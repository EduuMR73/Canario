"""Sonda de las marcas de dropped_iterations de k6 (E14 de docs/informe-pruebas.md).

E14 hace que una ventana de 10 s de L4 con algun descarte de k6 no cumpla el
criterio de recuperacion de F2: sin eso, una ventana podria parecer recuperada
justo porque las peticiones mas lentas no llegaron a enviarse. Esa regla
descansa en una propiedad de k6 que hay que COMPROBAR antes de medir, no
suponer: las marcas de dropped_iterations salen una por llegada descartada, en
su instante.

La comprobacion lanza un escenario constant-arrival-rate a 2/s con 1 VU contra
un endpoint que tarda 2 s. Las marcas tienen que cumplir las seis
condiciones de E16 (que sustituyen al criterio de E14, que habria parado la
sonda siempre). Si no, la ejecucion de L4 PARA y se revisa E14 (no se ajusta la
sonda). El CSV y un resumen JSON se guardan en la salida de la ejecucion como
evidencia, y entran en el anti-fuga.

Este modulo no importa lanzar.py (que lo carga a la hora de usarlo): recibe la
funcion ejecutar y las constantes del lanzador por parametro, para que
python lanzar.py y las pruebas usen una unica copia del estado. La parte pura
(evaluar_marcas) se prueba en test_lanzar.py con literales; la parte con Docker
(ejecutar_sonda) solo se puede probar ejecutandola, y NO se ha ejecutado."""

import csv
import json
import pathlib
import re
import shutil
import subprocess
import tempfile

# E16 (corrige E14): criterio de la sonda, seis condiciones con nombre. Con
# constant-arrival-rate cada llegada intenta lanzar su iteracion sin esperar; si
# el VU esta ocupado se descarta y deja una marca con la hora del descarte (k6
# v2.3.0, lib/executor/constant_arrival_rate.go, lineas 328-347). Con 2/s, 1 VU
# y 2 s por peticion, la primera marca cae hacia los 0,5 s y tras cada llegada
# lanzada hay un hueco de 1,0 s entre marcas.
TASA_LLEGADAS = 2            # llegadas por segundo
DURACION_ESCENARIO_S = 12    # tiene que coincidir con duration de sonda_descartes.js
PASO_S = 1 / TASA_LLEGADAS   # 0,5 s entre llegadas programadas
MARCAS_MINIMAS = 5           # condicion 1
TOLERANCIA_MARCA_S = 0.2     # condicion 2 (menor que 0,25 s: el k nunca es ambiguo)
K_PRIMERA_PERMITIDOS = (0, 1)  # condicion 4: k = 0 si la llegada de 0 s se descarta por la carrera de arranque (TryRunIteration)
K_MINIMO = 0                 # condicion 2
SALTOS_K_PERMITIDOS = (1, 2)  # condicion 5
TOLERANCIA_CONCILIACION = 1  # condicion 6
LLEGADAS_PROGRAMADAS = TASA_LLEGADAS * DURACION_ESCENARIO_S  # 24; pueden ser 25 (la de 12,0 s compite con el fin del plazo): lo cubre el +-1
PATRON_T0 = re.compile(r"T0_MS=(\d+)")

# Etiqueta de TODO lo que crea la sonda (network create, run -d y run --rm). La
# limpieza decide por postcondicion: lista por esta etiqueta lo que queda. Si una
# creacion perdiera la etiqueta, el listado no la veria y todo parecera limpio
# (un falso "limpio"): lo cubre la prueba P1 de test_lanzar.py.
ETIQUETA_SONDA = "canario.estres=sonda"

# Servidor lento: responde a todo con 200 vacio tras 2 s. Sin comillas dobles ni
# barras invertidas: va por lista de argumentos con python -c. ThreadingHTTPServer
# para que el cierre de una conexion no bloquee a la siguiente.
CODIGO_SERVIDOR = (
    "import http.server, time\n"
    "class H(http.server.BaseHTTPRequestHandler):\n"
    "    def do_GET(self):\n"
    "        time.sleep(2)\n"
    "        self.send_response(200)\n"
    "        self.send_header('Content-Length', '0')\n"
    "        self.end_headers()\n"
    "    def log_message(self, *args):\n"
    "        pass\n"
    "http.server.ThreadingHTTPServer(('0.0.0.0', 8080), H).serve_forever()\n"
)


def nombre_servidor(prefijo):
    """Nombre del contenedor del servidor lento. Es la única fuente: lo usan
    ejecutar_sonda para crearlo y el control C5 de lanzar.py para reconocer su
    die (el k6 de la sonda lleva la misma etiqueta y no vale para C5)."""
    return f"{prefijo}sonda_lento"


def indice_k(marca, inicio):
    """k = redondeo((marca - T0) / 0,5): a que llegada programada corresponde la marca."""
    return round((marca - inicio) / PASO_S)


def condicion_1_minimo(marcas):
    return len(marcas) >= MARCAS_MINIMAS


def condicion_2_instantes(marcas, inicio):
    """Cada marca a +-0,2 s de T0 + 0,5 k, con k >= 0."""
    return all(indice_k(m, inicio) >= K_MINIMO and abs(m - (inicio + PASO_S * indice_k(m, inicio))) <= TOLERANCIA_MARCA_S
               for m in marcas)


def condicion_3_sin_repetidos(ks):
    return len(set(ks)) == len(ks)


def condicion_4_primera(ks):
    return bool(ks) and ks[0] in K_PRIMERA_PERMITIDOS


def condicion_5_saltos(ks):
    return all(b - a in SALTOS_K_PERMITIDOS for a, b in zip(ks, ks[1:], strict=False))


def condicion_6_conciliacion(n_marcas, n_iteraciones):
    """Marcas + iteraciones lanzadas (filas iterations del CSV) = llegadas programadas +-1."""
    return abs(n_marcas + n_iteraciones - LLEGADAS_PROGRAMADAS) <= TOLERANCIA_CONCILIACION


def evaluar_marcas(marcas, inicio, iteraciones):
    """(veredicto, texto) de la sonda de E14 con las seis condiciones de E16.
    marcas: dropped_iterations (segundos desde 1970); inicio: T0, el fin de
    setup(); iteraciones: numero de filas iterations del CSV. "PASA" o "PARADA":
    sin esta propiedad la regla de E14 no vale. Una sonda sin marcas no prueba
    nada y es PARADA con su motivo (condicion 1)."""
    if inicio is None:
        return "PARADA", "sin T0 de la sonda: no se sabe donde empieza el escenario"
    marcas = sorted(marcas)
    ks = [indice_k(m, inicio) for m in marcas]
    fallos = []
    if not condicion_1_minimo(marcas):
        fallos.append(f"(1) {len(marcas)} marcas y se necesitan al menos {MARCAS_MINIMAS}")
    if not condicion_2_instantes(marcas, inicio):
        fallos.append(f"(2) alguna marca no esta a +-{TOLERANCIA_MARCA_S} s de T0 + 0,5 k con k >= {K_MINIMO} (k: {ks})")
    if not condicion_3_sin_repetidos(ks):
        fallos.append(f"(3) hay marcas con el mismo k ({ks})")
    if not condicion_4_primera(ks):
        fallos.append(f"(4) la primera marca tiene k = {ks[0] if ks else None} y debe ser una de {K_PRIMERA_PERMITIDOS}")
    if not condicion_5_saltos(ks):
        fallos.append(f"(5) algun salto de k no es de 1 ni de 2 ({ks})")
    if not condicion_6_conciliacion(len(marcas), iteraciones):
        fallos.append(f"(6) {len(marcas)} marcas + {iteraciones} iteraciones no suman {LLEGADAS_PROGRAMADAS} +-"
                      f"{TOLERANCIA_CONCILIACION}")
    if fallos:
        return "PARADA", "; ".join(fallos)
    return "PASA", f"{len(marcas)} marcas con k {ks} y {iteraciones} iteraciones lanzadas: las seis condiciones de E16"


def leer_marcas(ruta_csv):
    """(marcas de dropped_iterations en segundos desde 1970, numero de filas
    iterations) del CSV de k6 (tiempo en unix_milli). Una fila ilegible o una
    ultima linea sin salto final es un error visible (ValueError): no se salta."""
    marcas, iteraciones = [], 0
    with open(ruta_csv, encoding="utf-8", newline="") as fichero:
        contenido = fichero.read()
    if contenido and not contenido.endswith("\n"):
        raise ValueError("el CSV de la sonda acaba sin salto de linea: ultima fila posiblemente cortada")
    try:
        for fila in csv.DictReader(contenido.splitlines()):
            if fila.get("metric_name") == "dropped_iterations":
                marcas.append(int(fila["timestamp"]) / 1000)
            elif fila.get("metric_name") == "iterations":
                iteraciones += 1
    except csv.Error as error:
        raise ValueError(f"CSV de la sonda ilegible: {error}") from error
    return marcas, iteraciones


def ejecutar_sonda(ejecutar, imagen_api, imagen_k6, cpus_k6, dir_estres, constantes, salida=None, *, avisar):
    """Arranca el servidor lento (contenedor de la imagen de la API, solo con su
    Python) y k6 en una red interna temporal, y devuelve (marcas, iteraciones,
    T0 o None, motivo o None). No decide: eso es de evaluar_marcas. constantes:
    {"prefijo", "usuario_api", "usuario_k6", "memoria_k6"} del lanzador. Los
    contenedores llevan el prefijo (limpiar_efimeros los borra) y los dos van en
    el cpuset de k6, no en el de Canario. limpiar_efimeros NO borra la red: la
    red de la sonda se borra explicitamente en el finally de esta funcion. Con
    salida (la carpeta de la ejecucion) se copian el CSV y el resumen JSON. Un
    TimeoutExpired es un motivo, no una excepcion.

    avisar es un argumento con nombre y OBLIGATORIO: se le llama una vez por
    cada problema de limpieza (un recurso que sigue, un listado que falla, el
    temporal sin borrar, un segundo Ctrl+C), con el texto ya hecho. Va por
    callback y no en el valor devuelto para que los avisos salgan tambien cuando
    la medida propaga una excepcion (Ctrl+C incluido). Por que no basta con
    ignorar el resultado del borrado: una red o un contenedor huerfano con el
    prefijo contaminaria la siguiente ejecucion sin dar la cara.

    La limpieza decide por POSTCONDICION (lo que listan los comandos por
    etiqueta), nunca por el texto del stderr de los borrados. Presupuesto en el
    peor caso: medir 120 + 300 + 300 = 720 s, limpiar 3 x 120 + 2 x 60 = 480 s,
    total 1200 s. Solo afecta a --pico en la repeticion 1 y no entra en la
    estimacion impresa. NO se ha ejecutado."""
    prefijo = constantes["prefijo"]
    red, servidor, k6 = f"{prefijo}sonda_red", nombre_servidor(prefijo), f"{prefijo}sonda_k6"
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="canario_estres_sonda_"))
    # El resultado se calcula en una variable y se devuelve DESPUES del finally:
    # un return dentro del finally se tragaria cualquier excepcion (un Ctrl+C
    # incluido). La excepcion de la medida no se captura: el finally limpia y
    # la excepcion sigue su camino. `medida_fallo` solo le dice a la limpieza si
    # hay una excepcion original en curso, para que un fallo de `avisar` no la
    # tape (si no hay ninguna, ese fallo se relanza al final y es visible).
    medida_fallo = True
    try:
        resultado = _medir_sonda(ejecutar, imagen_api, imagen_k6, cpus_k6, dir_estres, constantes, salida,
                                 (red, servidor, k6), tmp)
        medida_fallo = False
    finally:
        _limpiar_sonda(ejecutar, (servidor, k6), red, tmp, avisar, medida_fallo)
    return resultado


def _detalle_borrado(ejecutar, argumentos, orden):
    """Lanza un borrado y devuelve el texto de lo que ocurrio, GUARDADO para el
    aviso. Nunca decide el veredicto: eso lo hace el listado por etiqueta.
    Un KeyboardInterrupt no se captura aqui."""
    try:
        r = ejecutar(argumentos, timeout=120)
    except subprocess.TimeoutExpired:
        return f"{orden}: no responde en 120 s"
    except OSError as error:
        return f"{orden}: no se puede lanzar docker ({type(error).__name__}: {error})"
    mensaje = r.err.strip()[-200:]
    if r.rc != 0 or mensaje:
        return f"{orden}: codigo {r.rc}: {mensaje!r}"
    return f"{orden}: codigo 0"


def _listar_por_etiqueta(ejecutar, argumentos, orden, que_comprueba):
    """(nombres, aviso): nombres es el conjunto de lineas de stdout (con strip y
    sin lineas vacias) o None si el listado fallo, y entonces `aviso` dice por
    que no se pudo comprobar. Se lee solo r.out: lo que salga por stderr es
    ruido y nunca cuenta como un recurso. Un KeyboardInterrupt no se captura."""
    prefijo_aviso = f"no se puede comprobar {que_comprueba}: "
    try:
        r = ejecutar(argumentos, timeout=60)
    except subprocess.TimeoutExpired:
        return None, prefijo_aviso + f"{orden} no responde en 60 s"
    except OSError as error:
        return None, prefijo_aviso + f"no se puede lanzar docker ({type(error).__name__}: {error})"
    if r.rc != 0:
        return None, prefijo_aviso + f"{orden} codigo {r.rc}: {r.err.strip()[-200:]!r}"
    return {linea.strip() for linea in r.out.splitlines() if linea.strip()}, None


def _limpiar_sonda(ejecutar, contenedores, red, tmp, avisar, excepcion_en_curso):
    """Borra los contenedores y la red de la sonda y avisa de lo que no se pudo
    dejar limpio. Pasos, siempre en este orden: rm -f del servidor, rm -f de k6,
    network rm, docker ps -a y docker network ls (los dos por etiqueta) y
    rmtree del temporal.

    El veredicto es la POSTCONDICION: un recurso es un fallo de limpieza si y
    solo si su nombre aparece (igual, tras strip) en el listado por etiqueta. Lo
    que dijeron los borrados (rc, stderr, plazo, OSError) solo se guarda para el
    texto del aviso. Asi no se depende del texto de Docker, que cambia entre
    versiones. Procedencia de las medidas (Docker 29.5.3, 24/11/2026,
    PowerShell 5): docker rm -f de un contenedor inexistente da rc 0 con "No such
    container" en stderr; docker network rm de una red inexistente da rc 1 con
    "network ... not found"; los listados por etiqueta salen por stdout con rc 0
    y quedan vacios cuando el recurso no existe. NO se midio un contenedor en
    marcha que pase por "removing" ni un borrado ya en curso.

    Cada borrado va en su propio try: que el primero venza su plazo no puede
    dejar sin borrar la red. Los dos listados son independientes: si falla el
    primero el segundo se ejecuta igual. Los avisos se ACUMULAN y se emiten al
    final, en el orden servidor, k6, red, listados y temporal; el de Ctrl+C va el
    ultimo. Carrera con --rm aceptada: si k6 vence su plazo, su autoborrado puede
    seguir en el daemon y el listado verlo, dando un aviso de "sigue" que puede
    ser falso pero visible; nunca un falso limpio. Un recurso que el daemon cree
    DESPUES del listado queda para recursos_previos al final de main.

    Segundo Ctrl+C: si un paso de Docker recibe KeyboardInterrupt no se lanzan
    mas pasos de Docker, pero el rmtree se intenta igual (es local y no espera a
    nadie). Se emiten los avisos y se relanza el KeyboardInterrupt. Si `avisar`
    lanza una excepcion con un aviso se siguen emitiendo los demas; al final se
    relanza la primera, salvo que haya una excepcion original en curso
    (`excepcion_en_curso`), que es la que sigue su camino."""
    servidor, k6 = contenedores
    que = {servidor: f"contenedor {servidor}", k6: f"contenedor {k6}", red: f"red {red}"}
    detalles = {}
    nombres_contenedores = nombres_red = None
    aviso_ps = aviso_red = None
    interrupcion = None
    try:
        detalles[servidor] = _detalle_borrado(ejecutar, ["docker", "rm", "-f", servidor], "docker rm -f")
        detalles[k6] = _detalle_borrado(ejecutar, ["docker", "rm", "-f", k6], "docker rm -f")
        detalles[red] = _detalle_borrado(ejecutar, ["docker", "network", "rm", red], "docker network rm")
        nombres_contenedores, aviso_ps = _listar_por_etiqueta(
            ejecutar, ["docker", "ps", "-a", "--filter", f"label={ETIQUETA_SONDA}", "--format", "{{.Names}}"],
            "docker ps", "si quedan contenedores de la sonda")
        nombres_red, aviso_red = _listar_por_etiqueta(
            ejecutar, ["docker", "network", "ls", "--filter", f"label={ETIQUETA_SONDA}", "--format", "{{.Name}}"],
            "docker network ls", "si queda la red de la sonda")
    except KeyboardInterrupt as error:
        # Sin mas pasos de Docker: un segundo Ctrl+C dice que no se quiere esperar.
        interrupcion = error
    aviso_temporal = None
    try:
        # Sin ignore_errors: un temporal que no se borra tiene que verse.
        shutil.rmtree(tmp)
    except OSError as error:
        aviso_temporal = f"no se borra el temporal {tmp}: {type(error).__name__}: {error}"
    except KeyboardInterrupt as error:
        if interrupcion is None:
            interrupcion = error
    # Un recurso esta CONFIRMADO ausente solo si su listado funciono y no lo ve.
    confirmados = set()
    sigue = []
    for lista, recursos in ((nombres_contenedores, (servidor, k6)), (nombres_red, (red,))):
        if lista is None:
            continue
        for recurso in recursos:
            if recurso in lista:
                sigue.append(f"{que[recurso]} sigue existiendo tras el borrado ({detalles[recurso]})")
            else:
                confirmados.add(recurso)
    # Orden de los pasos: servidor, k6 y red, luego los listados y el temporal.
    avisos = list(sigue)
    avisos.extend(a for a in (aviso_ps, aviso_red, aviso_temporal) if a is not None)
    if interrupcion is not None:
        pendientes = [que[r] for r in (servidor, k6, red) if r not in confirmados]
        if pendientes:
            texto = "limpieza interrumpida con Ctrl+C: pueden quedar " + ", ".join(pendientes)
            if red not in confirmados:
                texto += f"; la red se borra a mano con: docker network rm {red}"
            avisos.append(texto)
    primer_error = None
    for texto in avisos:
        try:
            avisar(texto)
        except Exception as error:  # noqa: BLE001 - se siguen emitiendo los demas y se relanza el primero
            if primer_error is None:
                primer_error = error
    if interrupcion is not None:
        raise interrupcion
    if primer_error is not None and not excepcion_en_curso:
        raise primer_error


def _medir_sonda(ejecutar, imagen_api, imagen_k6, cpus_k6, dir_estres, constantes, salida, nombres, tmp):
    """El trabajo de ejecutar_sonda sin la limpieza: (marcas, iteraciones, T0 o
    None, motivo o None). Separado para que la limpieza, que va en el finally de
    quien la llama, no comparta bloque con los return de cada fallo."""
    red, servidor, k6 = nombres
    try:
        r = ejecutar(["docker", "network", "create", "--internal", "--label", ETIQUETA_SONDA, red], timeout=120)
        if r.rc != 0:
            return [], 0, None, f"no se crea la red de la sonda: {r.err.strip()[-200:]!r}"
        r = ejecutar(["docker", "run", "-d", "--name", servidor, "--label", ETIQUETA_SONDA, "--network", red,
                      "--network-alias", "lento", "--read-only", "--cap-drop", "ALL", "--security-opt",
                      "no-new-privileges", "--pids-limit", "64", "--memory", "64m", "--cpuset-cpus", cpus_k6,
                      "--user", constantes["usuario_api"], "--entrypoint", "python", imagen_api, "-I", "-c",
                      CODIGO_SERVIDOR], timeout=300)
        if r.rc != 0:
            return [], 0, None, f"no arranca el servidor lento: {r.err.strip()[-200:]!r}"
        r = ejecutar(["docker", "run", "--rm", "--name", k6, "--label", ETIQUETA_SONDA, "--network", red,
                      "--user", constantes["usuario_k6"], "--read-only", "--cap-drop", "ALL", "--security-opt",
                      "no-new-privileges", "--pids-limit", "1024", "--memory", constantes["memoria_k6"],
                      "--cpuset-cpus", cpus_k6, "--tmpfs", "/tmp:size=64m", "-e", "HOME=/tmp",
                      "-e", "K6_NO_USAGE_REPORT=true", "-e", "K6_CSV_TIME_FORMAT=unix_milli",
                      "--mount", f"type=bind,src={dir_estres},dst=/prueba,readonly",
                      "--mount", f"type=bind,src={tmp},dst=/salida",
                      imagen_k6, "run", "--no-usage-report", "--out", "csv=/salida/sonda.csv",
                      "/prueba/sonda_descartes.js"], timeout=300)
        if r.rc != 0:
            return [], 0, None, f"k6 termina con codigo {r.rc}: {r.todo.strip()[-300:]!r}"
        t0 = [int(x) for x in PATRON_T0.findall(r.todo)]
        if len(t0) != 1:
            return [], 0, None, f"la salida de k6 trae {len(t0)} lineas T0_MS y debe traer una"
        marcas, iteraciones = leer_marcas(tmp / "sonda.csv")
        if salida is not None:
            shutil.copyfile(tmp / "sonda.csv", pathlib.Path(salida) / "sonda_descartes.csv")
            (pathlib.Path(salida) / "sonda_descartes.json").write_text(
                resumen_json(marcas, t0[0] / 1000, iteraciones), encoding="utf-8", newline="\n")
        return marcas, iteraciones, t0[0] / 1000, None
    except subprocess.TimeoutExpired as error:
        return [], 0, None, f"la sonda supera el plazo de {error.timeout} s: {error.cmd[:3]}"
    except (OSError, ValueError, KeyError) as error:
        return [], 0, None, f"la sonda no se pudo leer: {type(error).__name__}: {error}"


def resumen_json(marcas, inicio, iteraciones):
    """Resumen de la sonda para la evidencia: marcas relativas a T0 y su k."""
    ordenadas = sorted(marcas)
    return json.dumps({"inicio": inicio, "iteraciones": iteraciones,
                       "marcas_relativas": [round(m - inicio, 3) for m in ordenadas],
                       "k": [indice_k(m, inicio) for m in ordenadas]})
