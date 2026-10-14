#!/usr/bin/env python3
"""Batería de pruebas de seguridad de la conexión a PostgreSQL y del arranque
verificado de la API (app/bd.py, app/verificacion_arranque.py y
app/principal.py).

Qué prueba: que la API arranca y verifica la base de datos; que la contraseña
llega solo como Docker secret (ni en el entorno ni en la línea de comandos) y
no aparece en los logs aunque la autenticación falle; que la API se niega a
arrancar ante cada desviación de la base de datos (atributos del rol,
pertenencia a otros roles, propiedad de objetos, CREATE o TEMP, tablas nuevas,
RLS, permisos de tabla y de columna, funciones, dueño de las funciones de
definidor, políticas y search_path) y vuelve a arrancar al revertirla; que el
contexto de empresa aísla las filas, no se arrastra entre transacciones de la
misma conexión, no admite valores sin validar, y que el pool descarta una
conexión devuelta con contexto; y que la API aguanta una ráfaga concurrente
dentro de su pids_limit. Cada prueba negativa lleva su control positivo: si el
control falla, el resultado es SIN CONCLUSION, nunca PASA. Los oráculos son
literales.

Cómo se ejecuta (desde la raíz del repositorio, en PowerShell, con Docker en
marcha y los secretos generados con scripts/generar_secretos.py):

    python tests/security/verificar_arranque.py

Usa un proyecto de Docker propio (canario_arranque) y solo levanta postgres,
redis y api (la API depende de Redis para arrancar; las comprobaciones de
arranque del limitador se prueban en verificar_denuncia.py, r). Necesita que
el proyecto canario esté parado (las subredes de app y edge
son fijas). Al terminar lo borra todo (down -v y las imágenes construidas).
No lee ningún secreto real: los cambios en la base de datos se hacen como
superusuario por el socket del contenedor (peer), y las pruebas de
credenciales usan una contraseña falsa generada aquí.

Los ficheros auxiliares se escriben en un directorio temporal del sistema y se
borran al terminar. La salida completa se guarda en verificacion_arranque.txt
dentro del directorio temporal del sistema. El código de salida es 0 solo si
el resultado global es OK.

Solo usa la biblioteca estándar.
"""
import json
import pathlib
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import traceback

RAIZ = pathlib.Path.cwd()
PROYECTO = "canario_arranque"
SALIDA = pathlib.Path(tempfile.gettempdir()) / "verificacion_arranque.txt"
BASE = ["docker", "compose", "-p", PROYECTO, "-f", "docker-compose.yml"]

lineas_salida = []
estado = {"falla": False, "sin_conclusion": False}

# ---------------------------------------------------------------------------
# Oráculos literales
# ---------------------------------------------------------------------------
SUBREDES_FIJAS = {"10.88.0.0/28", "10.88.1.0/28"}
EMPRESA_A = "a0000000-0000-4000-8000-000000000001"
EMPRESA_B = "b0000000-0000-4000-8000-000000000002"
DEN_A = "a0000000-0000-4000-8000-0000000000d1"
DEN_B = "b0000000-0000-4000-8000-0000000000d1"

TEXTO_VERIFICADO = "ARRANQUE VERIFICADO"
TEXTO_BLOQUEADO = "ARRANQUE BLOQUEADO: "
TEXTO_AUTENTICACION = 'password authentication failed for user "aplicacion"'
TEXTO_ARRASTRE = "conexion devuelta al pool con contexto de empresa"
# Límites de sesión tal como los muestra PostgreSQL, y su mensaje al cortar
# una transacción inactiva.
TIEMPOS_SESION = ["5s", "2s", "10s"]
TEXTO_INACTIVA = "idle-in-transaction timeout"

# Variables de entorno permitidas en el contenedor de la API: las de la imagen
# base de Python y las del Dockerfile. Ninguna con credenciales.
ENTORNO_PERMITIDO = {"PATH", "LANG", "GPG_KEY", "PYTHON_VERSION", "PYTHON_SHA256",
                     "PYTHONDONTWRITEBYTECODE", "PYTHONUNBUFFERED"}
SECRETO_API = "/run/secrets/contrasena_aplicacion"

# Desviaciones de la base de datos: identificador de la comprobación que debe
# bloquear el arranque, SQL que la provoca y SQL que la revierte.
DESVIACIONES = [
    ("rol_atributos", "ALTER ROLE aplicacion BYPASSRLS;", "ALTER ROLE aplicacion NOBYPASSRLS;"),
    ("pertenencia", "GRANT pg_read_all_data TO aplicacion;", "REVOKE pg_read_all_data FROM aplicacion;"),
    # Un esquema propio y no el cambio de dueño de una tabla existente: al
    # devolver la tabla, PostgreSQL no restauraría los permisos que aplicacion
    # tenía sobre ella y la reversión no sería exacta.
    ("propiedad", "CREATE SCHEMA prueba_propiedad AUTHORIZATION aplicacion;", "DROP SCHEMA prueba_propiedad;"),
    ("esquema_bd", "GRANT TEMPORARY ON DATABASE canario TO aplicacion;",
     "REVOKE TEMPORARY ON DATABASE canario FROM aplicacion;"),
    ("tablas", "CREATE TABLE canal.prueba_nueva (x integer);", "DROP TABLE canal.prueba_nueva;"),
    ("rls", "ALTER TABLE canal.denuncia NO FORCE ROW LEVEL SECURITY;",
     "ALTER TABLE canal.denuncia FORCE ROW LEVEL SECURITY;"),
    ("privilegios_tabla", "GRANT DELETE ON canal.denuncia TO aplicacion;",
     "REVOKE DELETE ON canal.denuncia FROM aplicacion;"),
    ("privilegios_columna", "GRANT UPDATE (contenido_cifrado) ON canal.denuncia TO aplicacion;",
     "REVOKE UPDATE (contenido_cifrado) ON canal.denuncia FROM aplicacion;"),
    ("funciones", "GRANT EXECUTE ON FUNCTION canal.alta_empresa(text, text) TO aplicacion;",
     "REVOKE EXECUTE ON FUNCTION canal.alta_empresa(text, text) FROM aplicacion;"),
    ("funciones_definidor", "ALTER FUNCTION canal.resolver_empresa(text) OWNER TO migrador;",
     "ALTER FUNCTION canal.resolver_empresa(text) OWNER TO propietario_funciones;"),
    ("propietario_funciones", "ALTER ROLE propietario_funciones BYPASSRLS;",
     "ALTER ROLE propietario_funciones NOBYPASSRLS;"),
    ("propietario_supresion", "ALTER ROLE propietario_supresion BYPASSRLS;",
     "ALTER ROLE propietario_supresion NOBYPASSRLS;"),
    ("propietario_redaccion", "ALTER ROLE propietario_redaccion BYPASSRLS;",
     "ALTER ROLE propietario_redaccion NOBYPASSRLS;"),
    ("politicas", "CREATE POLICY prueba_permisiva ON canal.denuncia FOR SELECT TO aplicacion USING (true);",
     "DROP POLICY prueba_permisiva ON canal.denuncia;"),
    ("search_path", "ALTER ROLE aplicacion IN DATABASE canario SET search_path = canal, pg_catalog;",
     "ALTER ROLE aplicacion IN DATABASE canario SET search_path = pg_catalog, canal;"),
]

DATOS_PRUEBA = f"""
insert into canal.empresa (id, nombre) values ('{EMPRESA_A}', 'Empresa A'), ('{EMPRESA_B}', 'Empresa B');
insert into canal.clave_empresa (empresa_id, version, clave_envuelta)
    values ('{EMPRESA_A}', 1, '\\x01'), ('{EMPRESA_B}', 1, '\\x01');
insert into canal.denuncia (empresa_id, id, contenido_cifrado, version_clave)
    values ('{EMPRESA_A}', '{DEN_A}', '\\x01', 1), ('{EMPRESA_B}', '{DEN_B}', '\\x01', 1);
"""

# Se ejecuta dentro del contenedor de la API con el código real de app/bd.py.
# Pool de tamaño 1: todas las transacciones usan la misma conexión mientras el
# pool no la descarte.
PRUEBA_CONTEXTO = f"""
import json, time, uuid
from app import bd
A = uuid.UUID("{EMPRESA_A}")
B = uuid.UUID("{EMPRESA_B}")
pool = bd.crear_pool(tamano_maximo=1)
pool.open(wait=True, timeout=15)
res = {{}}

def ids(empresa):
    with bd.transaccion_empresa(pool, empresa) as c:
        filas = c.execute("select id from canal.denuncia").fetchall()
        return sorted(str(f[0]) for f in filas), c.info.backend_pid

res["a"], p1 = ids(A)
res["b"], p2 = ids(B)
res["a_otra_vez"], p3 = ids(A)
res["misma_conexion"] = p1 == p2 == p3
with bd.transaccion_sin_contexto(pool) as c:
    res["contexto_tras_transaccion"] = c.execute("select current_setting('app.empresa_id', true)").fetchone()[0]
    res["filas_sin_contexto"] = c.execute("select count(*) from canal.denuncia").fetchone()[0]
for etiqueta, valor in (("inyeccion", "' OR 1=1 --"), ("texto_uuid", "{EMPRESA_A}")):
    try:
        with bd.transaccion_empresa(pool, valor):
            pass
        res[etiqueta] = "aceptado"
    except TypeError:
        res[etiqueta] = "TypeError"
# Arrastre simulado: contexto de sesión (no local), que sobrevive a la
# transacción. El pool debe descartar la conexión al devolverla.
with pool.connection() as c:
    pid_arrastre = c.info.backend_pid
    c.execute("select set_config('app.empresa_id', %s, false)", [str(A)])
with pool.connection() as c:
    res["arrastre_descartado"] = c.info.backend_pid != pid_arrastre
    res["contexto_tras_arrastre"] = c.execute("select current_setting('app.empresa_id', true)").fetchone()[0]
# Límites de tiempo de la sesión: valores y efecto real.
with bd.transaccion_sin_contexto(pool) as c:
    res["tiempos"] = [c.execute("select current_setting(%s)", [n]).fetchone()[0]
                      for n in ("statement_timeout", "lock_timeout", "idle_in_transaction_session_timeout")]
for etiqueta, segundos in (("consulta_corta", 1), ("consulta_larga", 7)):
    try:
        with bd.transaccion_sin_contexto(pool) as c:
            c.execute("select pg_sleep(%s)", [segundos])
        res[etiqueta] = "completada"
    except Exception as error:
        res[etiqueta] = type(error).__name__
# Transacción abierta e inactiva: 3 s (control, sigue viva) y 12 s (el
# servidor corta la sesión a los 10 s).
for etiqueta, segundos in (("inactiva_3s", 3), ("inactiva_12s", 12)):
    try:
        with pool.connection() as c:
            c.execute("select 1")
            time.sleep(segundos)
            c.execute("select 1")
        res[etiqueta] = "sigue abierta"
    except Exception as error:
        res[etiqueta] = str(error)
pool.close()
# lock_timeout: dos conexiones a la vez (pool de tamaño 2). La primera retiene
# el bloqueo consultivo 1 dentro de su transacción. La segunda pide primero el
# 2 (control: libre, sin esperar) y después el 1 (ocupado): debe fallar con
# LockNotAvailable hacia los 2 s, antes del statement_timeout de 5 s.
pool2 = bd.crear_pool(tamano_maximo=2)
pool2.open(wait=True, timeout=15)
with pool2.connection() as c1, pool2.connection() as c2:
    c1.execute("select pg_advisory_xact_lock(1)")
    for etiqueta, sql in (("bloqueo_libre", "select pg_advisory_xact_lock(2)"),
                          ("bloqueo_ocupado", "select pg_advisory_xact_lock(1)")):
        inicio = time.monotonic()
        try:
            c2.execute(sql)
            resultado = "obtenido"
        except Exception as error:
            resultado = type(error).__name__
        res[etiqueta] = [resultado, round(time.monotonic() - inicio, 2)]
        c2.rollback()
    c1.rollback()
pool2.close()
print(json.dumps(res, sort_keys=True))
"""

# Ráfaga concurrente contra la API desde otro contenedor de la red app.
RAFAGA = """
import concurrent.futures, http.client, json
def pedir(_):
    c = http.client.HTTPConnection("api", 8000, timeout=20)
    c.request("GET", "/salud")
    r = c.getresponse()
    r.read()
    return r.status
with concurrent.futures.ThreadPoolExecutor(max_workers=60) as ex:
    codigos = list(ex.map(pedir, range(300)))
print(json.dumps({"total": len(codigos), "ok": codigos.count(200)}))
"""


# ---------------------------------------------------------------------------
# Utilidades de ejecución y de informe
# ---------------------------------------------------------------------------
class R:
    def __init__(self, rc, out, err):
        self.rc, self.out, self.err = rc, out, err

    @property
    def todo(self):
        return self.out + self.err


class Parada(Exception):
    pass


def p(texto=""):
    print(texto, flush=True)
    lineas_salida.append(texto)


def ejecutar(args, entrada=None, timeout=900):
    # check=False explícito: el código de salida se comprueba en cada llamada.
    r = subprocess.run(args, input=entrada, capture_output=True, timeout=timeout, check=False)
    return R(r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace"))


def dc(*args, entrada=None):
    return ejecutar(BASE + list(args), entrada=entrada)


def sup(sql):
    """SQL como superusuario por el socket del contenedor (peer)."""
    return dc("exec", "-T", "postgres", "psql", "-U", "postgres", "-d", "canario", "-X", "-q",
              "-A", "-t", "-v", "ON_ERROR_STOP=1", "-f", "-", entrada=sql.encode("utf-8"))


def pasa(cond, texto):
    p(("PASA  " if cond else "FALLA ") + texto)
    if not cond:
        estado["falla"] = True


def sinc(texto):
    p("SIN CONCLUSION " + texto)
    estado["sin_conclusion"] = True


def negativo(nombre, cond, control_ok, detalle=""):
    if not control_ok:
        sinc(f"{nombre}: el control positivo fallo {detalle}".rstrip())
        return
    pasa(cond, nombre)
    if not cond and detalle:
        p(f"   {detalle}")


def contenedor(servicio):
    cid = dc("ps", "-a", "-q", servicio).out.strip()
    if not cid:
        raise Parada(f"no hay contenedor para el servicio {servicio}")
    return cid


def salud(cid):
    return ejecutar(["docker", "inspect", "--format", "{{json .State.Health.Status}}", cid]).out.strip().strip('"')


def esperar(condicion, maximo):
    """Espera hasta que condicion() sea verdadera o pasen maximo segundos."""
    limite = time.monotonic() + maximo
    while time.monotonic() < limite:
        if condicion():
            return True
        time.sleep(1)
    return condicion()


def logs_api():
    return dc("logs", "--no-color", "--no-log-prefix", "api").todo


TEMPORAL = None
IMAGEN_API = ""


# ---------------------------------------------------------------------------
# Comprobaciones
# ---------------------------------------------------------------------------
def seccion_a():
    global IMAGEN_API
    p("=== a) arranque verificado")
    r = dc("up", "-d", "--build", "--wait", "postgres", "api")
    p(f"up -d --build --wait postgres api -> codigo {r.rc}")
    if r.rc != 0:
        p(r.todo.strip()[-1500:])
        raise Parada("no arranca la API")
    IMAGEN_API = ejecutar(["docker", "inspect", "--format", "{{.Config.Image}}", contenedor("api")]).out.strip()
    registro = logs_api()
    pasa(TEXTO_VERIFICADO in registro, f"a) el log de la API contiene {TEXTO_VERIFICADO!r}")
    pasa(TEXTO_BLOQUEADO not in registro, "a) el log de la API no contiene ningun bloqueo")
    pasa(salud(contenedor("api")) == "healthy", "a) la API esta healthy")


def seccion_b():
    p("=== b) la contrasena solo llega como secreto")
    cid = contenedor("api")
    entorno = json.loads(ejecutar(["docker", "inspect", "--format", "{{json .Config.Env}}", cid]).out)
    nombres = {e.split("=", 1)[0] for e in entorno}
    pasa(nombres == ENTORNO_PERMITIDO, f"b) variables de entorno = {sorted(nombres)}")
    linea = dc("exec", "-T", "api", "cat", "/proc/1/cmdline").out.replace("\x00", " ")
    pasa(linea.strip() != "" and "password" not in linea.lower() and "contrasena" not in linea.lower(),
         f"b) la linea de comandos del proceso no lleva credenciales ({linea.strip()[:120]!r})")
    r = dc("exec", "-T", "api", "test", "-f", SECRETO_API)
    pasa(r.rc == 0, f"b) {SECRETO_API} existe como fichero dentro del contenedor (sin leerlo)")

    # Contraseña falsa con el formato correcto: la autenticación falla, la API
    # no arranca y la contraseña no aparece en los logs. Control: el log
    # muestra el fallo de autenticación (la API sí llegó a PostgreSQL).
    falsa = secrets.token_urlsafe(48)
    (TEMPORAL / "falsa").mkdir()
    (TEMPORAL / "falsa" / "contrasena").write_text(falsa, encoding="ascii", newline="")
    registro = arrancar_api_temporal("falsa", TEMPORAL / "falsa" / "contrasena")
    negativo(f"b) con contrasena falsa la API no arranca ({TEXTO_BLOQUEADO}conexion)",
             f"{TEXTO_BLOQUEADO}conexion" in registro and TEXTO_VERIFICADO not in registro,
             TEXTO_AUTENTICACION in registro, f"log: {registro.strip()[-300:]!r}")
    negativo("b) la contrasena falsa no aparece en los logs", falsa not in registro,
             TEXTO_AUTENTICACION in registro)

    # Secreto con un salto de línea final: formato inválido, no se corrige en
    # silencio.
    (TEMPORAL / "mal").mkdir()
    (TEMPORAL / "mal" / "contrasena").write_text(falsa + "\n", encoding="ascii", newline="")
    registro = arrancar_api_temporal("mal", TEMPORAL / "mal" / "contrasena")
    pasa(f"{TEXTO_BLOQUEADO}secreto" in registro and falsa not in registro,
         f"b) con un secreto mal formado la API no arranca ({TEXTO_BLOQUEADO}secreto) y no lo muestra")


def claves_falsas():
    """Claves de cifrado y contraseña de Redis falsas con el formato correcto,
    generadas aquí.

    La API comprueba sus claves y el secreto de Redis antes de conectar: sin
    ellos se bloquearía como "claves" o "secreto_redis" y nunca llegaría a la
    conexión que estas pruebas quieren observar. Nunca se usan los reales.
    """
    directorio = TEMPORAL / "claves_falsas"
    if not directorio.is_dir():
        directorio.mkdir()
        for nombre in ("clave_maestra", "clave_hmac_codigos"):
            (directorio / nombre).write_text(secrets.token_hex(32), encoding="ascii", newline="")
        (directorio / "contrasena_redis").write_text(secrets.token_urlsafe(48), encoding="ascii", newline="")
    return [arg for nombre in ("clave_maestra", "clave_hmac_codigos", "contrasena_redis")
            for arg in ("--mount", f"type=bind,src={directorio / nombre},dst=/run/secrets/{nombre},readonly")]


def arrancar_api_temporal(etiqueta, fichero):
    """Arranca la imagen de la API con otro secreto y devuelve su log."""
    nombre = f"{PROYECTO}_api_{etiqueta}"
    ejecutar(["docker", "run", "-d", "--name", nombre, "--network", f"{PROYECTO}_data",
              "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
              "--mount", f"type=bind,src={fichero},dst={SECRETO_API},readonly", *claves_falsas(),
              IMAGEN_API])
    try:
        esperar(lambda: ejecutar(["docker", "inspect", "--format", "{{.State.Running}}", nombre]).out.strip()
                == "false", 60)
        return ejecutar(["docker", "logs", nombre]).todo
    finally:
        ejecutar(["docker", "rm", "-f", nombre])


def seccion_c():
    p("=== c) contexto de empresa (codigo real de app/bd.py)")
    r = sup(DATOS_PRUEBA)
    if r.rc != 0:
        raise Parada(f"no se pudieron insertar los datos de prueba: {r.err.strip()[:300]}")
    r = dc("exec", "-T", "api", "python", "-c", PRUEBA_CONTEXTO)
    try:
        res = json.loads(r.out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        sinc(f"c) no se pudo ejecutar la prueba de contexto: {r.err.strip()[-400:]!r}")
        return
    p(f"   resultado: {res}")
    control = res.get("misma_conexion") is True
    pasa(control, "c) control: las transacciones normales reutilizan la misma conexion")
    pasa(res.get("a") == [DEN_A], f"c) con contexto A solo se ve la denuncia de A ({res.get('a')})")
    pasa(res.get("b") == [DEN_B], f"c) con contexto B solo se ve la denuncia de B ({res.get('b')})")
    negativo(f"c) A, B y A en la misma conexion no se mezclan ({res.get('a_otra_vez')})",
             res.get("a_otra_vez") == [DEN_A], control)
    negativo(f"c) tras la transaccion el contexto queda vacio ({res.get('contexto_tras_transaccion')!r})",
             res.get("contexto_tras_transaccion") == "", control)
    negativo(f"c) sin contexto se ven 0 filas ({res.get('filas_sin_contexto')})",
             res.get("filas_sin_contexto") == 0, res.get("a") == [DEN_A])
    pasa(res.get("inyeccion") == "TypeError", f"c) un texto con SQL se rechaza antes del SQL ({res.get('inyeccion')})")
    pasa(res.get("texto_uuid") == "TypeError",
         f"c) un uuid en texto sin validar tambien se rechaza ({res.get('texto_uuid')})")
    negativo("c) una conexion devuelta con contexto de sesion se descarta",
             res.get("arrastre_descartado") is True and res.get("contexto_tras_arrastre") in ("", None),
             control, f"resultado: {res}")
    negativo("c) el descarte queda registrado en el log", TEXTO_ARRASTRE in r.err,
             res.get("arrastre_descartado") is True, f"stderr: {r.err.strip()[-300:]!r}")
    for linea in r.err.splitlines():
        if TEXTO_ARRASTRE in linea:
            p(f"   log de descarte literal: {linea!r}")
    pasa(res.get("tiempos") == TIEMPOS_SESION,
         f"c) limites de la sesion (statement, lock, idle in transaction) = {res.get('tiempos')}")
    # Control: una consulta de 1 s termina, así que la de 7 s se corta por el
    # límite y no porque pg_sleep falle.
    negativo(f"c) una consulta de 7 s se cancela por statement_timeout ({res.get('consulta_larga')})",
             res.get("consulta_larga") == "QueryCanceled", res.get("consulta_corta") == "completada",
             f"consulta de 1 s: {res.get('consulta_corta')}")
    # Control: una transacción inactiva 3 s sigue viva, así que el corte de la
    # de 12 s se debe al límite de 10 s y no a otra cosa.
    corta = res.get("inactiva_3s", "")
    larga = res.get("inactiva_12s", "")
    negativo(f"c) una transaccion inactiva 12 s se corta ({larga.strip()[:120]!r})",
             TEXTO_INACTIVA in larga, corta == "sigue abierta", f"transaccion de 3 s: {corta!r}")
    # lock_timeout. Control: un bloqueo libre se obtiene sin esperar, así que el
    # fallo con el ocupado se debe a la espera y no a la llamada.
    libre = res.get("bloqueo_libre") or ["", -1]
    ocupado = res.get("bloqueo_ocupado") or ["", -1]
    negativo(f"c) esperar un bloqueo ocupado falla por lock_timeout ({ocupado[0]} a los {ocupado[1]} s)",
             ocupado[0] == "LockNotAvailable" and 1.5 <= ocupado[1] < 4.5,
             libre[0] == "obtenido" and libre[1] < 1, f"bloqueo libre: {libre}")


def seccion_d():
    p("=== d) el arranque se bloquea ante cada desviacion de la base de datos")
    for identificador, provocar, revertir in DESVIACIONES:
        cid = contenedor("api")
        control_antes = salud(cid) == "healthy"
        mensaje = f"{TEXTO_BLOQUEADO}{identificador}:"
        previas = logs_api().count(mensaje)
        r = sup(provocar)
        if r.rc != 0:
            sinc(f"d) {identificador}: no se pudo provocar la desviacion: {r.err.strip()[:200]}")
            continue
        dc("restart", "api")
        # Valores de esta vuelta, enlazados de forma explícita (esperar los usa
        # dentro de la misma vuelta, pero así no depende de cuándo se llame).
        bloqueado = esperar(lambda mensaje=mensaje, previas=previas: logs_api().count(mensaje) > previas, 60)
        no_sana = salud(cid) != "healthy"
        r = sup(revertir)
        dc("restart", "api")
        control_despues = r.rc == 0 and esperar(lambda cid=cid: salud(cid) == "healthy", 90)
        negativo(f"d) {identificador}: la API no arranca y registra {mensaje!r}", bloqueado and no_sana,
                 control_antes and control_despues,
                 f"healthy antes {control_antes}, healthy tras revertir {control_despues}")
        if not control_despues:
            raise Parada(f"la API no vuelve a estar healthy tras revertir {identificador}")


def seccion_e():
    p("=== e) rafaga concurrente dentro de pids_limit")
    nombre = f"{PROYECTO}_rafaga"
    ejecutar(["docker", "run", "-d", "--name", nombre, "--network", f"{PROYECTO}_app",
              "--entrypoint", "python", IMAGEN_API, "-c", RAFAGA])
    hilos = []
    try:
        def terminado():
            hilo = dc("exec", "-T", "api", "sh", "-c", "grep '^Threads' /proc/1/status").out.split()
            if len(hilo) == 2:
                hilos.append(int(hilo[1]))
            return ejecutar(["docker", "inspect", "--format", "{{.State.Running}}", nombre]).out.strip() == "false"
        esperar(terminado, 120)
        salida = ejecutar(["docker", "logs", nombre]).out.strip().splitlines()
    finally:
        ejecutar(["docker", "rm", "-f", nombre])
    try:
        res = json.loads(salida[-1])
    except (ValueError, IndexError):
        sinc("e) la rafaga no devolvio resultado")
        return
    p(f"   rafaga: {res}, hilos maximos observados en la API: {max(hilos) if hilos else 'sin datos'}")
    pasa(res == {"total": 300, "ok": 300}, "e) las 300 peticiones concurrentes reciben 200")
    pasa(salud(contenedor("api")) == "healthy", "e) la API sigue healthy tras la rafaga")


def seccion_s():
    p("=== s) limpieza")
    r = dc("down", "-v", "--rmi", "local")
    p(f"down -v --rmi local -> codigo {r.rc}")
    for etiqueta, orden in [
        ("contenedor", ["docker", "ps", "-a", "--format", "{{.Names}}"]),
        ("red", ["docker", "network", "ls", "--format", "{{.Name}}"]),
        ("volumen", ["docker", "volume", "ls", "--format", "{{.Name}}"]),
        ("imagen", ["docker", "image", "ls", "--format", "{{.Repository}}"]),
    ]:
        restos = [n for n in ejecutar(orden).out.split() if n.startswith(PROYECTO)]
        pasa(not restos, f"s) ningun {etiqueta} con prefijo {PROYECTO} {restos if restos else ''}".strip())
    final = estado_git()
    if ESTADO_GIT_ARRANQUE is None or final is None:
        sinc("s) no se pudo comparar el estado de Git")
    else:
        pasa(final == ESTADO_GIT_ARRANQUE, "s) la bateria no ha modificado el repo (git status igual al del arranque)")


def terminar():
    resultado = "NO OK (hay FALLA o SIN CONCLUSION)" if estado["falla"] or estado["sin_conclusion"] else "OK"
    p("RESULTADO GLOBAL: " + resultado)
    SALIDA.write_text("\n".join(lineas_salida) + "\n", encoding="utf-8", newline="\n")
    sys.exit(0 if resultado == "OK" else 1)


def terminar_con_parada():
    p("RESULTADO GLOBAL: NO OK (PARADA)")
    SALIDA.write_text("\n".join(lineas_salida) + "\n", encoding="utf-8", newline="\n")
    sys.exit(1)


def estado_git():
    try:
        r = ejecutar(["git", "status", "--short", "-uall"], timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    return [l.rstrip() for l in r.out.splitlines() if l.strip()] if r.rc == 0 else None


def recursos_previos():
    previos = []
    for orden in (["docker", "ps", "-a", "--format", "{{.Names}}"],
                  ["docker", "network", "ls", "--format", "{{.Name}}"],
                  ["docker", "volume", "ls", "--format", "{{.Name}}"]):
        previos += [n for n in ejecutar(orden).out.split() if n.startswith(PROYECTO)]
    return previos


def subredes_ocupadas():
    ocupadas = []
    for red in ejecutar(["docker", "network", "ls", "-q"]).out.split():
        partes = ejecutar(["docker", "network", "inspect", "--format",
                           "{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}", red]).out.split()
        if partes and set(partes[1:]) & SUBREDES_FIJAS:
            ocupadas.append(partes[0])
    return ocupadas


ESTADO_GIT_ARRANQUE = None


def main():
    global ESTADO_GIT_ARRANQUE, TEMPORAL
    ESTADO_GIT_ARRANQUE = estado_git()
    # Precondiciones: si fallan, no se limpia nada (podrían ser recursos ajenos).
    if ejecutar(["docker", "info", "--format", "{{.ServerVersion}}"]).rc != 0:
        p("PARADA: docker info falla")
        terminar_con_parada()
    previos = recursos_previos()
    if previos:
        p(f"PARADA: ya existen recursos con prefijo {PROYECTO}: {previos}")
        terminar_con_parada()
    ocupadas = subredes_ocupadas()
    if ocupadas:
        p(f"PARADA: las subredes fijas ya estan en uso por {ocupadas} (pare el proyecto canario)")
        terminar_con_parada()
    # Solo se comprueba que existen (is_file), nunca se leen. Los de Redis
    # hacen falta porque la API depende de Redis para arrancar.
    for fichero in ("contrasena_aplicacion.txt", "clave_maestra.txt", "clave_hmac_codigos.txt",
                    "contrasena_redis.txt", "redis_acl.conf"):
        if not (RAIZ / "secrets" / fichero).is_file():
            p(f"PARADA: secrets/{fichero} no existe (scripts/generar_secretos.py)")
            terminar_con_parada()
    TEMPORAL = pathlib.Path(tempfile.mkdtemp(prefix="canario_arranque_"))
    parada = None
    try:
        for seccion in (seccion_a, seccion_b, seccion_c, seccion_d, seccion_e):
            seccion()
    except Parada as e:
        parada = str(e)
        p(f"PARADA: {parada}")
    except Exception:  # noqa: BLE001 - error inesperado del propio test: se informa y se limpia
        parada = "error inesperado en el test"
        p("ERROR INESPERADO:\n" + traceback.format_exc())
    finally:
        for nombre in ("api_falsa", "api_mal", "rafaga"):
            ejecutar(["docker", "rm", "-f", f"{PROYECTO}_{nombre}"])
        if parada is not None:
            dc("down", "-v", "--rmi", "local")
        else:
            seccion_s()
        shutil.rmtree(TEMPORAL, ignore_errors=True)
    if parada is not None:
        estado["falla"] = True
    terminar()


if __name__ == "__main__":
    main()
