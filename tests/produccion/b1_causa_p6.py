#!/usr/bin/env python3
"""B1 del bloque 1: causa de las 2 aceptadas (404) ambiguas de A en P6.

Lee peticiones.csv y resumen.json de la carpeta de salida de P6 que se le
pasa como argumento (no la elige ni la busca: así nadie la abre antes de
tiempo y el resultado depende solo de lo que Eduardo le pase). Por cada
aceptada ambigua responde:

* (a) Deriva: ¿seguiría ambigua con el A1 inicial? Si no, la deriva entre el
  A1 inicial y el final es necesaria. Lado: inicio si la hora de inicio en el
  servidor cambia de ventana al pasar de d_min_inicial a d_min_envolvente
  (exige d_min_final < d_min_inicial); fin si la de fin cambia al pasar de
  d_max_inicial a d_max_envolvente (exige d_max_final > d_max_inicial).
* (b) Despachador: ¿la guarda de 4ec7d90 (permite_guarda tal cual), con el A1
  inicial y evaluada en el inicio local de la petición, la habría rechazado?
  Si sí, que la guarda solo se mire en el despachador es necesario. La hora
  planeada es la cota inferior de la hora a la que miró el despachador; se
  imprime como información.
* Resultado: solo (a), solo (b), las dos o ninguna. "Ninguna" es PARADA de P6.

Controles previos (si falla uno, SIN CONCLUSION y no se publica ninguna causa):
* identidad: resumen["head"] empieza por 4ec7d90 y resumen["sha256_lanzar"]
  es el SHA-256 de `git show 4ec7d90:tests/produccion/lanzar.py`;
* reconstrucción de los instantes locales a partir de los del servidor, con
  tres comprobaciones de literales fijos (brief de la tanda 2, v2.1, §1).

Solo biblioteca estándar, sin importar tests/produccion/lanzar.py: las
funciones que hacen falta están copiadas literalmente de 4ec7d90, para que un
cambio posterior del lanzador no cambie lo que este script mide.

Uso (PowerShell 5, desde la raíz del repo):

    python tests\\produccion\\b1_causa_p6.py "<carpeta de salida de P6>"

Código de salida: 0 HECHO, 1 PARADA, 2 SIN CONCLUSION.
"""
import argparse
import csv
import hashlib
import json
import math
import pathlib
import statistics
import subprocess
import sys

RAIZ = pathlib.Path(__file__).resolve().parent.parent.parent

HECHO, PARADA, SIN_CONCLUSION = "HECHO", "PARADA", "SIN CONCLUSION"

# Commit con el que corrió P6 (25/11, 22:03 UTC) y fichero cuya huella se
# compara. Literales: no se leen del entorno ni del propio resumen.
COMMIT_P6 = "4ec7d90"
FICHERO_LANZADOR = "tests/produccion/lanzar.py"

# Control de reconstrucción (brief de la tanda 2, v2.1, §1). Literales
# escritos aquí, no derivados de los datos:
# * TOLERANCIA_ANTES_DE_REAL_S: ninguna fila puede empezar antes de su `real`,
#   porque `real` se toma antes que `inicio` en el trabajador (lanzar.py de
#   4ec7d90, :2065 y :1358). Cero sería un error: `inicio_servidor` va
#   redondeado al µs y `real` se escribe con %.6f (:1468), así que la
#   diferencia sale negativa en una cuarta parte de las filas (QA midió un
#   26 %). El error teórico es de ±0,5 µs por redondeo más varias ulp del
#   double cerca de 1,76e9 (unos 2,4e-7 s cada una); -1e-5 deja un margen de
#   unas 7 veces y sigue detectando lo que el control busca (una envolvente
#   equivocada o una fila desalineada desplazan milisegundos o más).
# * TOLERANCIA_DURACION_S: `ms` se escribe con %.3f (:1470), 1 µs de
#   resolución; la duración reconstruida tiene que coincidir con esa holgura.
# * HUECO_MAXIMO_S: entre `real` y el inicio no hay más que la llamada a
#   peticion(); 10 ms solo se exige a las ambiguas y a la mediana, porque un
#   cambio de GIL de 5 ms puede pasar de 10 ms en alguna de las ~1800 filas y
#   eso no dice nada de las dos que importan.
TOLERANCIA_ANTES_DE_REAL_S = -1e-5
TOLERANCIA_DURACION_S = 1e-5
HUECO_MAXIMO_S = 0.01

# La línea del veredicto de P6 (vista en consola el 25/11 y citada en el
# plan) dice 2 aceptadas ambiguas. Si el CSV trae otro número, la carpeta no
# es la de esa ejecución o se lee mal: SIN CONCLUSION.
AMBIGUAS_ESPERADAS = 2

# Columnas de peticiones.csv: copia de COLUMNAS_CSV, lanzar.py de 4ec7d90,
# :1437-1438 (escritas con csv.DictWriter en :1476-1479). Las filas de A de
# P6 se escriben en :2297 con prueba "p6", red "A" y ruta RUTA_SEGUIMIENTO
# (:149); las omitidas y los descartes (:2300-2303) van con la misma red y
# ruta pero sin `real` ni hora del servidor.
COLUMNAS_CSV = ("prueba", "red", "ruta", "planeada", "real", "inicio_servidor", "fin_servidor", "estado", "ms",
                "retry_after", "ambigua", "nota")
RUTA_SEGUIMIENTO = "/v1/seguimiento"

# ===========================================================================
# Copiado literalmente de tests/produccion/lanzar.py en 4ec7d90 (blob
# aaa6f16c215d8c242da3d31443a87f9ac9a21d6e). No se importa: un cambio del
# lanzador después de P6 no debe cambiar lo que mide este script.
#   GUARDA_DURACION_S, GUARDA_MARGEN_S ....... :103-104
#   VENTANA_SEGUIMIENTO_S .................... :124
#   ventana_de_peticion ...................... :203-209
#   combinar_a1 .............................. :496-502
#   intervalo_servidor ....................... :505-509
#   clasificar ............................... :512-514
#   permite_guarda ........................... :570-578
# ===========================================================================
GUARDA_DURACION_S = 1.0
GUARDA_MARGEN_S = 0.001
VENTANA_SEGUIMIENTO_S = 60


def ventana_de_peticion(inicio_s, fin_s, ventana_s):
    """Copia de tests/estres/lanzar.py:3413-3420. (índice de ventana por la
    hora de INICIO, ambigua). Una petición es ambigua si el intervalo
    [inicio, fin] cruza una frontera de ventana: no se sabe en qué contador
    cayó."""
    a, b = math.floor(inicio_s / ventana_s), math.floor(fin_s / ventana_s)
    return a, a != b


def combinar_a1(inicio, fin):
    """A1 al principio y al final. Si no se solapan, None (SIN CONCLUSION). Si
    se solapan, la envolvente: es la cota conservadora (más ambiguas, nunca
    menos) si el desfase derivó algo entre las dos medidas."""
    if inicio is None or fin is None or max(inicio[0], fin[0]) > min(inicio[1], fin[1]):
        return None
    return min(inicio[0], fin[0]), max(inicio[1], fin[1])


def intervalo_servidor(inicio, fin, d_min, d_max):
    """[t_inicio + d_min, t_fin + d_max] (A2), redondeado al microsegundo: la
    coma flotante no debe decidir si 119,99999999999999 cruza la frontera de
    las 120 (ningún reloj de aquí resuelve por debajo del microsegundo)."""
    return round(inicio + d_min, 6), round(fin + d_max, 6)


def clasificar(inicio, fin, d_min, d_max, ventana):
    """(ventana del servidor, ambigua) de una petición con tiempos locales (A2)."""
    return ventana_de_peticion(*intervalo_servidor(inicio, fin, d_min, d_max), ventana)


def permite_guarda(t, d_min, d_max, ventana=VENTANA_SEGUIMIENTO_S):
    """D10 (Q-1, N3, QA6). Se lanza en el instante local t solo si
    t + d_min >= F_anterior y t + d_max + 1,0 s + 0,001 s <= F_siguiente, con
    F las fronteras de minuto del servidor. F_anterior es la frontera de la
    ventana en la que cae t + d_min."""
    temprano = round(t + d_min, 6)
    f_anterior = math.floor(temprano / ventana) * ventana
    f_siguiente = f_anterior + ventana
    return temprano >= f_anterior and round(t + d_max + GUARDA_DURACION_S + GUARDA_MARGEN_S, 6) <= f_siguiente


# ===========================================================================
# Fin de lo copiado
# ===========================================================================


class SinConclusion(Exception):
    """Un control previo no se cumple: no se publica ninguna causa."""


# --- E/S ----------------------------------------------------------------------
def leer_carpeta(carpeta):
    """(filas del CSV como dicts de texto, resumen). Si falta cualquiera de los
    dos ficheros o no se pueden leer, SIN CONCLUSION: el plan (§3, B1) dice
    que sin las salidas no hay conclusión, no que se supongan."""
    carpeta = pathlib.Path(carpeta)
    ruta_csv, ruta_json = carpeta / "peticiones.csv", carpeta / "resumen.json"
    faltan = [r.name for r in (ruta_csv, ruta_json) if not r.is_file()]
    if faltan:
        raise SinConclusion(f"faltan las salidas de P6: {', '.join(faltan)}")
    try:
        with open(ruta_csv, encoding="utf-8", newline="") as fichero:
            lector = csv.DictReader(fichero)
            cabecera = tuple(lector.fieldnames or ())
            filas = list(lector)
        resumen = json.loads(ruta_json.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, csv.Error, json.JSONDecodeError) as error:
        raise SinConclusion(f"no se pueden leer las salidas: {type(error).__name__}") from error
    # Las columnas se comparan con la copia literal: si no coinciden, el CSV
    # no viene de 4ec7d90 y los nombres que usa este script no valen.
    if cabecera != COLUMNAS_CSV:
        raise SinConclusion(f"las columnas de peticiones.csv no son las de {COMMIT_P6}: {list(cabecera)}")
    if not isinstance(resumen, dict):
        raise SinConclusion("resumen.json no es un objeto")
    return filas, resumen


def sha256_lanzador_git(raiz=RAIZ):
    """SHA-256 de `git show 4ec7d90:tests/produccion/lanzar.py`, o None si git
    falla o no devuelve nada. subprocess con lista de argumentos (sin shell:
    PowerShell 5 pierde las comillas dobles internas). `git show rev:ruta`
    da el blob tal cual, sin filtros de fin de línea, y el lanzador hace
    sha256 de los bytes de su fichero (:2495-2496, :2528); el repo fuerza LF
    en la copia de trabajo (.gitattributes), así que son los mismos bytes."""
    r = subprocess.run(["git", "-C", str(raiz), "show", f"{COMMIT_P6}:{FICHERO_LANZADOR}"],
                       capture_output=True, timeout=60, check=False)
    # Una salida vacía en `git show` es fallo, no un fichero vacío.
    if r.returncode != 0 or not r.stdout:
        return None
    return hashlib.sha256(r.stdout).hexdigest()


# --- controles ----------------------------------------------------------------
def control_identidad(resumen, sha_esperado):
    """La carpeta tiene que venir de una ejecución con HEAD en 4ec7d90 y con el
    lanzador de ese commit sin tocar. Sin esto, las copias de arriba podrían
    no ser el código que clasificó las filas. Claves escritas en :2527-2528
    (salida.resumen.update(... head=head_git(), ... sha256_lanzar=...))."""
    head = resumen.get("head")
    if not isinstance(head, str) or not head.startswith(COMMIT_P6):
        raise SinConclusion(f"identidad: resumen['head'] = {head!r} no empieza por {COMMIT_P6}")
    if sha_esperado is None:
        raise SinConclusion(f"identidad: git show {COMMIT_P6}:{FICHERO_LANZADOR} ha fallado")
    if resumen.get("sha256_lanzar") != sha_esperado:
        raise SinConclusion(f"identidad: resumen['sha256_lanzar'] no es el SHA-256 de {FICHERO_LANZADOR} en {COMMIT_P6}")
    return f"identidad: head {head[:12]} y sha256_lanzar igual al de {COMMIT_P6}"


def par_numerico(valor, nombre):
    if (not isinstance(valor, (list, tuple)) or len(valor) != 2
            or not all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in valor)):
        raise SinConclusion(f"resumen['a1']['p6']['{nombre}'] no es un par de numeros: {valor!r}")
    return float(valor[0]), float(valor[1])


def leer_a1(resumen):
    """(inicial, final, envolvente) de resumen["a1"]["p6"], escrito en :1644.
    La envolvente se comprueba con combinar_a1 (la misma copia que la
    calculó): si no cuadra, el resumen no es coherente."""
    try:
        a1 = resumen["a1"]["p6"]
        inicial = par_numerico(a1["inicial"], "inicial")
        final = par_numerico(a1["final"], "final")
        envolvente = par_numerico(a1["envolvente"], "envolvente")
    except (KeyError, TypeError) as error:
        raise SinConclusion(f"falta resumen['a1']['p6'] completo ({type(error).__name__}: {error})") from error
    if combinar_a1(inicial, final) != envolvente:
        raise SinConclusion(f"la envolvente {envolvente} no es combinar_a1({inicial}, {final})")
    return inicial, final, envolvente


def numero(texto, columna, i):
    try:
        return float(texto)
    except (TypeError, ValueError) as error:
        raise SinConclusion(f"linea {i} del CSV: '{columna}' = {texto!r} no es un numero") from error


def filas_de_a(filas):
    """Las peticiones de A que se enviaron en P6, con números. Una fila
    enviada tiene `real` y hora del servidor; una omitida o un descarte, ni lo
    uno ni lo otro (:2300-2303). Una fila con solo uno de los dos es
    incoherente y da SIN CONCLUSION: no se descarta en silencio."""
    enviadas = []
    for i, f in enumerate(filas, start=2):     # la línea 1 del CSV es la cabecera
        if f["prueba"] != "p6" or f["red"] != "A" or f["ruta"] != RUTA_SEGUIMIENTO:
            continue
        con_real, con_servidor = f["real"] != "", f["inicio_servidor"] != "" and f["fin_servidor"] != ""
        if con_real != con_servidor:
            raise SinConclusion(f"linea {i} del CSV: fila de A con real={f['real']!r} e inicio_servidor="
                                f"{f['inicio_servidor']!r}")
        if not con_real:
            continue
        if f["ambigua"] not in ("0", "1"):
            raise SinConclusion(f"linea {i} del CSV: ambigua = {f['ambigua']!r}")
        try:
            estado = int(f["estado"])
        except (TypeError, ValueError) as error:
            raise SinConclusion(f"linea {i} del CSV: estado = {f['estado']!r}") from error
        enviadas.append({"linea": i, "planeada": numero(f["planeada"], "planeada", i),
                         "real": numero(f["real"], "real", i),
                         "inicio_servidor": numero(f["inicio_servidor"], "inicio_servidor", i),
                         "fin_servidor": numero(f["fin_servidor"], "fin_servidor", i),
                         "estado": estado, "ms": numero(f["ms"], "ms", i), "ambigua": f["ambigua"] == "1"})
    if not enviadas:
        raise SinConclusion("ninguna peticion de A enviada en peticiones.csv")
    return enviadas


def reconstruir(enviadas, envolvente):
    """inicio_local = inicio_servidor - d_min_env y fin_local = fin_servidor -
    d_max_env: P6 escribió la hora del servidor con la envolvente (:2297 con
    la d de cerrar_prueba, :1639). Añade a cada fila inicio_local, fin_local y
    hueco = inicio_local - real."""
    d_min, d_max = envolvente
    for f in enviadas:
        f["inicio_local"] = f["inicio_servidor"] - d_min
        f["fin_local"] = f["fin_servidor"] - d_max
        f["hueco"] = f["inicio_local"] - f["real"]
    return enviadas


def control_reconstruccion(enviadas, ambiguas):
    """Las tres comprobaciones con literales. Devuelve las líneas de
    información (máximo, mediana y filas con hueco negativo, que se publican
    siempre) o lanza SinConclusion con ellas dentro."""
    huecos = [f["hueco"] for f in enviadas]
    maximo, mediana = max(huecos), statistics.median(huecos)
    negativas = sum(1 for h in huecos if h < 0)
    info = (f"reconstruccion: {len(enviadas)} filas de A; hueco inicio_local - real: maximo {maximo * 1e3:.6f} ms, "
            f"mediana {mediana * 1e3:.6f} ms, {negativas} filas con hueco negativo")
    fallos = []
    antes = [f for f in enviadas if f["hueco"] < TOLERANCIA_ANTES_DE_REAL_S]
    if antes:
        peor = min(antes, key=lambda f: f["hueco"])
        fallos.append(f"{len(antes)} filas empiezan antes de su real (peor: linea {peor['linea']}, "
                      f"{peor['hueco'] * 1e6:.3f} us; limite {TOLERANCIA_ANTES_DE_REAL_S * 1e6:.0f} us)")
    duracion = [f for f in enviadas
                if abs((f["fin_local"] - f["inicio_local"]) - f["ms"] / 1000) > TOLERANCIA_DURACION_S]
    if duracion:
        fallos.append(f"{len(duracion)} filas con fin - inicio distinto de ms (primera: linea {duracion[0]['linea']}; "
                      f"limite {TOLERANCIA_DURACION_S * 1e6:.0f} us)")
    for f in ambiguas:
        if f["hueco"] > HUECO_MAXIMO_S:
            fallos.append(f"ambigua de la linea {f['linea']}: hueco {f['hueco'] * 1e3:.3f} ms, mas de "
                          f"{HUECO_MAXIMO_S * 1e3:.0f} ms")
    if mediana > HUECO_MAXIMO_S:
        fallos.append(f"mediana del hueco {mediana * 1e3:.3f} ms, mas de {HUECO_MAXIMO_S * 1e3:.0f} ms")
    if fallos:
        raise SinConclusion(info + "; " + "; ".join(fallos))
    return info


# --- causa de cada ambigua ----------------------------------------------------
def causa_ambigua(f, inicial):
    """(a), su lado, (b) y el resultado de una aceptada ambigua, con sus
    instantes locales ya reconstruidos. Las ventanas con la envolvente salen
    de la hora del servidor tal como la escribió P6; las del A1 inicial, de
    intervalo_servidor sobre los instantes locales (la misma cuenta que hizo
    P6, con la otra d)."""
    ini, fin = f["inicio_local"], f["fin_local"]
    w_ini_env = math.floor(f["inicio_servidor"] / VENTANA_SEGUIMIENTO_S)
    w_fin_env = math.floor(f["fin_servidor"] / VENTANA_SEGUIMIENTO_S)
    srv_ini, srv_fin = intervalo_servidor(ini, fin, inicial[0], inicial[1])
    w_ini_ini = math.floor(srv_ini / VENTANA_SEGUIMIENTO_S)
    w_fin_ini = math.floor(srv_fin / VENTANA_SEGUIMIENTO_S)
    ambigua_inicial = clasificar(ini, fin, inicial[0], inicial[1], VENTANA_SEGUIMIENTO_S)[1]
    deriva = not ambigua_inicial
    lados = []
    if w_ini_env != w_ini_ini:
        lados.append("inicio")
    if w_fin_env != w_fin_ini:
        lados.append("fin")
    # Si (a) es sí, la envolvente tiene que haber movido al menos un extremo
    # de ventana; si no, las cuentas no cuadran y no se publica nada.
    if deriva and not lados:
        raise SinConclusion(f"linea {f['linea']}: (a) si sin ningun lado; los datos no cuadran")
    if not w_ini_env <= w_ini_ini or not w_fin_env >= w_fin_ini:
        raise SinConclusion(f"linea {f['linea']}: la envolvente estrecha el intervalo del A1 inicial")
    despachador = not permite_guarda(ini, inicial[0], inicial[1])
    resultado = {(True, False): "solo (a)", (False, True): "solo (b)", (True, True): "las dos",
                 (False, False): "ninguna"}[(deriva, despachador)]
    return {"linea": f["linea"], "deriva": deriva, "lados": lados, "despachador": despachador,
            "resultado": resultado, "inicio_local": ini, "fin_local": fin,
            "guarda_en_planeada": permite_guarda(f["planeada"], inicial[0], inicial[1]),
            "guarda_en_real": permite_guarda(f["real"], inicial[0], inicial[1])}


def texto_causa(c, inicial, final):
    if c["deriva"]:
        partes = []
        if "inicio" in c["lados"]:
            partes.append(f"inicio (d_min_final {final[0]:.6f} < d_min_inicial {inicial[0]:.6f})")
        if "fin" in c["lados"]:
            partes.append(f"fin (d_max_final {final[1]:.6f} > d_max_inicial {inicial[1]:.6f})")
        a = "si, lado " + " y ".join(partes)
    else:
        a = "no (tambien ambigua con el A1 inicial)"
    b = "si (la guarda de hoy la rechaza en su inicio)" if c["despachador"] else "no (la guarda de hoy la deja pasar)"
    return (f"ambigua de la linea {c['linea']}: local [{c['inicio_local']:.6f}; {c['fin_local']:.6f}], "
            f"duracion {(c['fin_local'] - c['inicio_local']) * 1e3:.3f} ms; (a) deriva: {a}; (b) despachador: {b} "
            f"[informacion: guarda en planeada {c['guarda_en_planeada']}, en real {c['guarda_en_real']}]; "
            f"resultado: {c['resultado']}")


# --- análisis completo (puro) -------------------------------------------------
def analizar(filas, resumen, sha_esperado):
    """(veredicto, líneas). HECHO si todas las ambiguas tienen causa; PARADA
    si alguna sale "ninguna"; SIN CONCLUSION si falla un control."""
    lineas = []
    try:
        lineas.append(control_identidad(resumen, sha_esperado))
        inicial, final, envolvente = leer_a1(resumen)
        lineas.append(f"A1 inicial {list(inicial)}, final {list(final)}, envolvente {list(envolvente)}")
        enviadas = reconstruir(filas_de_a(filas), envolvente)
        # Coherencia de la columna `ambigua` con la hora del servidor de la
        # misma fila (:1463-1465): si no cuadra, el CSV no se lee como se cree.
        for f in enviadas:
            if ventana_de_peticion(f["inicio_servidor"], f["fin_servidor"], VENTANA_SEGUIMIENTO_S)[1] != f["ambigua"]:
                raise SinConclusion(f"linea {f['linea']}: la columna ambigua no cuadra con la hora del servidor")
        ambiguas = [f for f in enviadas if f["ambigua"] and f["estado"] == 404]
        if len(ambiguas) != AMBIGUAS_ESPERADAS:
            raise SinConclusion(f"{len(ambiguas)} aceptadas (404) ambiguas en el CSV; P6 publico "
                                f"{AMBIGUAS_ESPERADAS}")
        lineas.append(control_reconstruccion(enviadas, ambiguas))
        causas = [causa_ambigua(f, inicial) for f in ambiguas]
    except SinConclusion as motivo:
        lineas.append(f"{SIN_CONCLUSION}: {motivo}")
        return SIN_CONCLUSION, lineas
    lineas.extend(texto_causa(c, inicial, final) for c in causas)
    ningunas = [c["linea"] for c in causas if c["resultado"] == "ninguna"]
    if ningunas:
        lineas.append(f"{PARADA}: ninguna de las dos causas explica la ambigua de las lineas {ningunas}; P6 queda en PARADA")
        return PARADA, lineas
    lineas.append(f"{HECHO}: " + "; ".join(f"linea {c['linea']}: {c['resultado']}" for c in causas))
    return HECHO, lineas


CODIGOS = {HECHO: 0, PARADA: 1, SIN_CONCLUSION: 2}


def main(argv=None):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
    analizador = argparse.ArgumentParser(description="B1: causa de las aceptadas ambiguas de A en P6")
    analizador.add_argument("carpeta", help="carpeta de salida de P6 (con peticiones.csv y resumen.json)")
    args = analizador.parse_args(argv)
    try:
        filas, resumen = leer_carpeta(args.carpeta)
    except SinConclusion as motivo:
        print(f"B1 {SIN_CONCLUSION}: {motivo}")
        return CODIGOS[SIN_CONCLUSION]
    veredicto, lineas = analizar(filas, resumen, sha256_lanzador_git())
    for linea in lineas:
        print(f"   {linea}")
    print(f"B1 {veredicto}")
    return CODIGOS[veredicto]


if __name__ == "__main__":
    sys.exit(main())
