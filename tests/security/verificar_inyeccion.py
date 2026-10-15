#!/usr/bin/env python3
"""Batería de inyección SQL y de robustez de la frontera de entrada.

Código probado: todo el SQL de app/ (consultas parametrizadas), las funciones
de db/init/, los modelos de entrada de app/rutas_denuncias.py y
app/rutas_personal.py, y los argumentos de app/gestion.py
(docs/threat-model.md, tabla 7, fila "Inyección SQL"). Sigue el SQL
Injection Prevention Cheat Sheet de OWASP (consultas parametrizadas como
defensa principal, lista cerrada para lo que no se puede parametrizar y
mínimo privilegio como red) y la guía de pruebas WSTG-INPV-05.

Un payload que no llega al SQL no prueba nada. Por eso hay cinco capas y
cada negativo tiene su control positivo:

* a) Estática (AST, sin ejecutar el código): cada llamada a execute de app/
  recibe un literal o una constante de módulo que es un literal puro (de
  ese módulo o de otro de app/), o un parámetro cuyas llamadas reciben eso.
  Lo que no se puede resolver es FALLA (falla cerrado). Ni psycopg.sql ni
  ClientCursor (que enlaza los parámetros en el cliente). Control: un módulo
  sintético con f-string, concatenación, %, format, una variable sin
  resolver y una llamada con SQL compuesto da exactamente esos hallazgos, y
  uno correcto ninguno.
* c) Catálogo: ninguna función plpgsql de canal o public usa EXECUTE
  dinámico. Control: una función temporal con EXECUTE se detecta.
* d) Dinámica: payloads de error, booleanos, UNION, apilados, de tiempo
  (pg_sleep) y de codificación en cada entrada de texto que llega al SQL
  (empresa y email del login, identificador de la ruta de crear denuncia,
  código de seguimiento) y en las que se rechazan antes (estado, cursor,
  desde, ids de la ruta y del cuerpo). Oráculos: el estado y el cuerpo
  literales de la entrada; ningún payload con pg_sleep tarda (control:
  pg_sleep(3) tarda); las tablas no cambian de filas ni desaparecen; los
  contadores del login del admin no se mueven (un "' OR '1'='1" que
  encontrara su cuenta los movería; control: un fallo real los mueve); la
  cadena de auditoría sigue intacta; ni una línea de ERROR en el log de
  PostgreSQL (control: una consulta mal formada deja la suya). Control por
  entrada: un valor válido llega al SQL y responde 200/201/204.
* e) Frontera (app/validacion.py): cada campo de texto de cada modelo de
  entrada usa TextoLinea o TextoLibre, recorriendo los modelos con el código
  real (cerrado por construcción: un campo nuevo con un str sin más es
  FALLA; control: un modelo sintético con str se detecta). Un NUL o un
  surrogate suelto (JSON "\\ud800") en cualquiera de esos campos da el 422
  propio, nunca un 500 (psycopg no admite NUL en un texto y el UTF-8 no
  admite surrogates); objetos, listas, números, booleanos y null donde se
  espera un texto, 422. Control por campo: el mismo campo con un valor
  benigno no da 422. La regla en las dos direcciones: un texto libre con
  tabulador, saltos, VT, FF, ESC y NEL se guarda y vuelve tal cual, con los
  controles C0 escapados en el JSON (RFC 8259, 7); los mismos en un
  TextoLinea dan 422.
* f) Segundo orden: el nombre de una empresa y emails con SQL, dados de alta
  por gestion y por la API, se guardan y vuelven byte a byte, y la cuenta con
  ese email activa y entra (el valor guardado se usa en otras consultas).
  gestion valida el email igual que la API (ASCII imprimible, sin
  espacios) y rechaza un nombre de empresa con caracteres de control.
* g) Mínimo privilegio: como aplicacion, pg_read_file, COPY TO PROGRAM,
  lo_import, pg_authid, CREATE en public y canal, DROP, ALTER ROLE y CREATE
  EXTENSION dan 42501. Control: como superusuario funcionan (en una
  transacción que se deshace).

Cómo se ejecuta (desde la raíz del repositorio, en PowerShell, con Docker en
marcha y los secretos generados con scripts/generar_secretos.py):

    python tests/security/verificar_inyeccion.py

Usa un proyecto de Docker propio (canario_inyeccion) y levanta postgres,
redis, api y caddy, más ejecuciones sueltas de gestion. Necesita que el
proyecto canario y las otras baterías estén parados (las subredes de app y
edge son fijas). Al terminar lo borra todo (down -v y las imágenes
construidas). Claves de cifrado y secretos de Redis FALSOS, generados en
cada ejecución; de secrets/ solo se usan las contraseñas de los roles, sin
leerlas.

La salida completa se guarda en verificacion_inyeccion.txt dentro del
directorio temporal del sistema. El código de salida es 0 solo si el
resultado global es OK. Solo usa la biblioteca estándar.
"""
import ast
import base64
import hashlib
import hmac
import json
import pathlib
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.parse
import uuid

RAIZ = pathlib.Path.cwd()
PROYECTO = "canario_inyeccion"
SALIDA = pathlib.Path(tempfile.gettempdir()) / "verificacion_inyeccion.txt"
BASE = ["docker", "compose", "-p", PROYECTO, "-f", "docker-compose.yml"]
CONTRASENAS_REDIS = {}

lineas_salida = []
estado = {"falla": False, "sin_conclusion": False}

# ---------------------------------------------------------------------------
# Oráculos literales
# ---------------------------------------------------------------------------
SUBREDES_FIJAS = {"10.88.0.0/28", "10.88.1.0/28"}
TEXTO_VERIFICADO = "ARRANQUE VERIFICADO"
TEXTO_BLOQUEADO = "ARRANQUE BLOQUEADO: "
PERMISOS_ACL_APLICACION = ("resetkeys ~limite:* resetchannels -@all "
                           "+ping +multi +exec +incr +expire +ttl +client|setinfo")
PERMISOS_ACL_INSPECTOR = "resetkeys ~* resetchannels -@all +ping +scan +get +pttl +dbsize +client|setinfo"
LIMITES_PRUEBA = ("denuncia=1000/3600,seguimiento=1000/60,mensajes=1000/3600,acceso=1000/300,otras=1000/60,"
                  "cuenta=1000/60")
TEXTO_LIMITES_PRUEBA = ("LIMITES (configurados): acceso=1000/300 cuenta=1000/60 denuncia=1000/3600 mensajes=1000/3600 "
                        "otras=1000/60 seguimiento=1000/60")

PATRON_ALTA = re.compile(r"empresa creada: empresa_id=([0-9a-f-]{36}) identificador_publico=([0-9a-f]{32})")
PATRON_INVITACION_GESTION = re.compile(r"invitacion creada: empresa_id=([0-9a-f-]{36}) usuario_id=([0-9a-f-]{36})\n"
                                       r"token_invitacion=([0-9a-f]{32}\.[A-Za-z0-9_-]{43})\n")

# Respuestas, literales (app/frontera_http.py, app/rutas_denuncias.py y app/rutas_personal.py).
CUERPO_401_CREDENCIALES = '{"detalle": "credenciales no válidas"}'.encode()
CUERPO_404 = b'{"detalle": "recurso no encontrado"}'
CUERPO_404_CODIGO = '{"detalle": "código de seguimiento no válido"}'.encode()
CUERPO_422 = '{"detalle": "petición no válida"}'.encode()
CATEGORIA = "fraude"

# Topes de forma de app/rutas_personal.py: lo que pase de aquí es 422 sin
# llegar al SQL.
LONGITUD_MAXIMA_IDENTIFICADOR = 64
LONGITUD_MAXIMA_ID_CUERPO = 64

# Un payload con pg_sleep(3) que se ejecutara tardaría al menos 3 s.
SEGUNDOS_SLEEP = 3
MS_MAXIMO_SIN_SLEEP = 1500

# Corpus de WSTG-INPV-05: errores de sintaxis, booleanos, UNION, apilados,
# de tiempo, con dólar, con E'', codificados y con comillas de ancho
# completo (U+FF07), más uno que intenta fijar la variable de empresa.
PAYLOADS_SQL = [
    "'",
    '"',
    "\\",
    "')--",
    "' OR '1'='1",
    "' OR 1=1 --",
    '" OR ""="',
    "1 OR 1=1",
    "' UNION SELECT NULL, NULL --",
    "' UNION SELECT email FROM canal.usuario_personal --",
    "'; DROP TABLE canal.denuncia; --",
    "1; SELECT pg_sleep(3) --",
    "' || pg_sleep(3) || '",
    "'||(SELECT pg_sleep(3))||'",
    "$$; SELECT pg_sleep(3); $$",
    "E'\\x27 OR 1=1'",
    "%27%20OR%201%3D1",
    "＇ OR ＇1＇=＇1",
    "' AND 1=CAST((SELECT version()) AS int) --",
    "' OR set_config('canario.empresa_id', '00000000-0000-0000-0000-000000000000', false) IS NOT NULL --",
]

# Emails con SQL que la validación de la API acepta (ASCII, sin espacios y
# con '@' después del primer carácter): llegan al INSERT y se guardan.
EMAILS_SEGUNDO_ORDEN = [
    "a'or'1'='1@inyeccion.test",
    "b'--@inyeccion.test",
    "c';drop/**/table/**/canal.denuncia;--@inyeccion.test",
    "d'||pg_sleep(3)||'@inyeccion.test",
    "e'union/**/select/**/null--@inyeccion.test",
    "f\\'@inyeccion.test",
    "g$$;select/**/1;$$@inyeccion.test",
]
NOMBRE_EMPRESA_SQL = "Empresa '); DROP TABLE canal.denuncia; -- S.L."
EMAIL_GESTION_SQL = "admin'--@inyeccion.test"
EMAILS_GESTION_INVALIDOS = ["con espacio@inyeccion.test", "ñandu@inyeccion.test"]

NOMBRE_EMPRESA_CONTROL = "Empresa\x1b[2J S.L."

# Campos de texto de los modelos de entrada, literales: si aparece uno nuevo,
# la prueba lo señala hasta que se añada aquí con su tipo.
CAMPOS_TEXTO = {
    "NuevaDenuncia.texto", "ConsultaSeguimiento.codigo", "NuevoMensaje.codigo", "NuevoMensaje.texto",
    "Activacion.token", "Activacion.contrasena", "Confirmacion.token", "Confirmacion.codigo_totp",
    "Login.empresa", "Login.email", "Login.contrasena", "Login.codigo_totp", "Login.token_dispositivo",
    "Renovacion.token_renovacion",
    "CambioContrasena.contrasena_actual", "CambioContrasena.contrasena_nueva", "CambioContrasena.codigo_totp",
    "NuevoUsuario.email", "MensajePersonal.texto", "CambioEstado.mensaje", "Asignacion.usuario_id",
    "Tramo.texto",
}
CONTROL_MODELOS = {"Control.sin_tipo": False, "Control.con_tipo": True, "Control.opcional_sin_tipo": False}

# Se ejecuta dentro de la API con los modelos reales: para cada campo con
# algún str, si todos sus str llevan el validador de app/validacion.py.
MODELOS_DENTRO = """
import json, typing
from pydantic import AfterValidator, BaseModel
from app import rutas_denuncias, rutas_personal, rutas_web, validacion
VALIDADORES = {validacion.texto_linea, validacion.texto_libre}

def textos(tipo):
    if typing.get_origin(tipo) is typing.Annotated:
        base, *meta = typing.get_args(tipo)
        if base is str:
            return [any(isinstance(m, AfterValidator) and m.func in VALIDADORES for m in meta)]
        return textos(base)
    if tipo is str:
        return [False]
    return [v for arg in typing.get_args(tipo) for v in textos(arg)]

def campos(modelos):
    res = {}
    for modelo in modelos:
        for nombre, tipo in typing.get_type_hints(modelo, include_extras=True).items():
            valores = textos(tipo)
            if valores:
                res[f"{modelo.__name__}.{nombre}"] = all(valores)
    return res

class Control(BaseModel):
    sin_tipo: str
    con_tipo: validacion.TextoLinea
    opcional_sin_tipo: str | None = None

# rutas_web no define modelos (valida con los de rutas_denuncias), pero se
# recorre igual: uno que se añada allí queda revisado sin tocar esta prueba.
reales = [c for m in (rutas_denuncias, rutas_personal, rutas_web) for c in vars(m).values()
          if isinstance(c, type) and issubclass(c, BaseModel) and c.__module__ == m.__name__]
print(json.dumps({"reales": campos(reales), "control": campos([Control])}, sort_keys=True))
"""

# Tipos que no son texto donde se espera un texto.
TIPOS_NO_TEXTO = [{"$ne": None}, ["x"], 1, True, None]

# Mínimo privilegio: sentencias peligrosas tras una inyección y el SQLSTATE
# esperado como aplicacion (42501, insufficient_privilege).
SENTENCIAS_PRIVILEGIO = [
    ("pg_read_file", "select pg_read_file('/etc/hostname');"),
    ("copy_program", "copy (select 1) to program 'true';"),
    ("lo_import", "select lo_import('/etc/hostname');"),
    ("pg_authid", "select count(*) from pg_authid;"),
    ("create_public", "create table public.inyeccion (a int);"),
    ("create_canal", "create table canal.inyeccion (a int);"),
    # CASCADE: sin él, también el superusuario falla por las claves foráneas
    # y el control no probaría nada.
    ("drop_denuncia", "drop table canal.denuncia cascade;"),
    ("alter_role", "alter role aplicacion superuser;"),
    # Con esquema: sin él, aplicacion falla antes por no tener esquema donde
    # crearla (3F000) y no por el permiso.
    ("create_extension", "create extension dblink schema public;"),
]
SQLSTATE_PRIVILEGIO = "42501"

# Capa estática: métodos que ejecutan SQL y llamadas sin argumentos que no
# son SQL (el pipeline de Redis de app/limitador.py).
METODOS_SQL = {"execute", "executemany", "copy", "stream"}
SIN_ARGUMENTOS_NO_SQL = {("limitador.py", "tubo")}
# Hallazgos esperados en el módulo sintético del control: (función, motivo).
HALLAZGOS_SINTETICOS = {
    ("con_fstring", "no resoluble"),
    ("con_porcentaje", "no resoluble"),
    ("con_format", "no resoluble"),
    ("con_suma", "no resoluble"),
    ("sin_resolver", "no resoluble"),
    ("ejecuta_parametro", "no resoluble"),
    ("con_constante_compuesta", "no resoluble"),
    ("pipeline_desconocido", "sin argumentos"),
    ("<modulo>", "psycopg.sql"),
    ("<modulo>", "ClientCursor"),
}
MODULO_MALO = '''
import psycopg
from psycopg import sql
COMPUESTA = "select " + "1"
LITERAL = "select 1"

def con_fstring(c, v):
    c.execute(f"select {v}")

def con_porcentaje(c, v):
    c.execute("select %s" % v)

def con_format(c, v):
    c.execute("select {}".format(v))

def con_suma(c, v):
    c.execute("select " + v)

def sin_resolver(c):
    consulta = LITERAL
    c.execute(consulta)

def ejecuta_parametro(c, consulta):
    c.execute(consulta)

def llama_mal(c, v):
    ejecuta_parametro(c, "select " + v)

def llama_bien(c):
    ejecuta_parametro(c, LITERAL)

def con_constante_compuesta(c):
    c.execute(COMPUESTA)

def pipeline_desconocido(t):
    t.execute()

def cliente(conexion):
    return psycopg.ClientCursor(conexion)
'''
MODULO_BUENO = '''
from app import otro
LITERAL = "select 1"
IMPLICITA = ("select a "
             "from b where c = %s")

def directa(c):
    c.execute("select %s", [1])

def constante(c):
    c.execute(LITERAL)

def implicita(c):
    c.execute(IMPLICITA, [1])

def de_otro_modulo(c):
    c.execute(otro.SQL_OTRO)

def capa(c, sql):
    c.execute(sql)

def capa_doble(c, sql):
    return capa(c, sql)

def usa(c):
    capa_doble(c, LITERAL)
'''
MODULO_OTRO = 'SQL_OTRO = "select 2"\n'

# Cliente HTTP de prueba (como en tests/security/verificar_personal.py):
# corre con la imagen de la API, en la red app, y mide cada petición.
CLIENTE_HTTP = r'''
import base64, http.client, json, sys, time

def una(pt):
    conexion = None
    try:
        conexion = http.client.HTTPConnection(pt["host"], pt["puerto"], timeout=30)
        conexion.connect()
        cuerpo = base64.b64decode(pt["cuerpo"]) if pt.get("cuerpo") is not None else None
        inicio = time.perf_counter()
        conexion.request(pt["metodo"], pt["ruta"], body=cuerpo, headers=pt.get("cabeceras", {}))
        respuesta = conexion.getresponse()
        datos = respuesta.read()
        ms = (time.perf_counter() - inicio) * 1000
        return {"estado": respuesta.status, "cuerpo": base64.b64encode(datos).decode("ascii"), "ms": ms}
    except Exception as error:
        # Solo el tipo: el mensaje de algunas excepciones de http.client
        # puede llevar parte de la respuesta. El método y la ruta van aquí,
        # igual que en tests/security/verificar_personal.py.
        return {"error": type(error).__name__, "metodo": pt["metodo"], "ruta": pt["ruta"]}
    finally:
        if conexion is not None:
            conexion.close()

print(json.dumps([una(pt) for pt in json.load(sys.stdin)]))
'''


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
    # check=False explícito: el código de salida lo revisa cada prueba.
    r = subprocess.run(args, input=entrada, capture_output=True, timeout=timeout, check=False)
    return R(r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace"))


def dc(*args, entrada=None):
    return ejecutar(BASE + list(args), entrada=entrada)


def dc_con_gestion(*args):
    return ejecutar(BASE + ["--profile", "gestion"] + list(args))


def sup(sql):
    """SQL como superusuario por el socket del contenedor (peer)."""
    return dc("exec", "-T", "postgres", "psql", "-U", "postgres", "-d", "canario", "-X", "-q",
              "-A", "-t", "-v", "ON_ERROR_STOP=1", "-f", "-", entrada=sql.encode("utf-8"))


def valor(sql):
    r = sup(sql)
    if r.rc != 0:
        raise Parada(f"consulta como superusuario fallida: {r.err.strip()[:300]}")
    return r.out.strip()


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


def lineas_log(servicio):
    return dc("logs", "--no-color", "--no-log-prefix", servicio).todo.splitlines()


TEMPORAL = None
IMAGEN_API = ""


def texto_acl(aplicacion):
    hash_aplicacion = hashlib.sha256(CONTRASENAS_REDIS["aplicacion"].encode("ascii")).hexdigest()
    hash_inspector = hashlib.sha256(CONTRASENAS_REDIS["inspector"].encode("ascii")).hexdigest()
    return (f"user default off\nuser aplicacion on #{hash_aplicacion} {aplicacion}\n"
            f"user inspector on #{hash_inspector} {PERMISOS_ACL_INSPECTOR}\n")


def fichero_secreto(nombre, ruta):
    return [f"  {nombre}:", f"    file: \"{ruta.as_posix()}\""]


def preparar_secretos_falsos():
    """Claves de cifrado y secretos de Redis FALSOS y los límites de prueba
    (como tests/security/verificar_personal.py)."""
    directorio = TEMPORAL / "secretos_compose"
    directorio.mkdir()
    lineas = ["secrets:"]
    for nombre in ("clave_maestra", "clave_hmac_codigos", "clave_firma_tokens"):
        (directorio / nombre).write_text(secrets.token_hex(32), encoding="ascii", newline="")
        lineas += fichero_secreto(nombre, directorio / nombre)
    for usuario in ("aplicacion", "inspector"):
        CONTRASENAS_REDIS[usuario] = secrets.token_urlsafe(48)
    (directorio / "contrasena_redis").write_text(CONTRASENAS_REDIS["aplicacion"], encoding="ascii", newline="")
    (directorio / "redis_acl").write_text(texto_acl(PERMISOS_ACL_APLICACION), encoding="ascii", newline="\n")
    lineas += fichero_secreto("contrasena_redis", directorio / "contrasena_redis")
    lineas += fichero_secreto("redis_acl", directorio / "redis_acl")
    adicional = TEMPORAL / "secretos_falsos.yml"
    adicional.write_text("\n".join(lineas) + "\n", encoding="utf-8", newline="\n")
    BASE.extend(["-f", str(adicional)])
    limites = TEMPORAL / "limites_prueba.yml"
    limites.write_text(f"services:\n  api:\n    environment:\n      CANARIO_LIMITES: \"{LIMITES_PRUEBA}\"\n",
                       encoding="utf-8", newline="\n")
    BASE.extend(["-f", str(limites)])


def gestion(*args):
    return dc("run", "--rm", "-T", "gestion", *args)


# ---------------------------------------------------------------------------
# HTTP y TOTP de la batería
# ---------------------------------------------------------------------------
def http(peticiones):
    r = ejecutar(["docker", "run", "--rm", "-i", "--network", f"{PROYECTO}_app", "--read-only",
                  "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                  "--entrypoint", "python", IMAGEN_API, "-c", CLIENTE_HTTP],
                 entrada=json.dumps(peticiones).encode("utf-8"))
    try:
        respuestas = json.loads(r.out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise Parada(f"el cliente HTTP no devolvio resultado: {r.err.strip()[-400:]!r}") from None
    for respuesta in respuestas:
        # Diagnóstico: una petición sin respuesta deja un control SIN
        # CONCLUSION; se imprime el tipo de error para que la causa sea
        # visible en la salida y no haya que adivinarla. No cambia ningún
        # oráculo ni condición.
        if "error" in respuesta:
            p(f"  [cliente HTTP] {respuesta['error']} en {respuesta['metodo']} {respuesta['ruta']}")
        if "cuerpo" in respuesta:
            respuesta["cuerpo"] = base64.b64decode(respuesta["cuerpo"])
    return respuestas


def pt(metodo, ruta, datos=None, token=None):
    """Petición a la API. El JSON va con ensure_ascii=True: así un surrogate
    suelto viaja como el escape "\\ud800", que es JSON válido."""
    cabeceras = {"Content-Type": "application/json"}
    if token is not None:
        cabeceras["Authorization"] = f"Bearer {token}"
    peticion = {"host": "api", "puerto": 8000, "metodo": metodo, "ruta": ruta, "cabeceras": cabeceras}
    if datos is not None:
        crudo = json.dumps(datos, ensure_ascii=True).encode("ascii")
        peticion["cuerpo"] = base64.b64encode(crudo).decode("ascii")
    return peticion


def json_de(respuesta):
    try:
        return json.loads(respuesta["cuerpo"].decode("utf-8"))
    except (KeyError, ValueError, UnicodeDecodeError):
        return None


def una(peticion):
    return http([peticion])[0]


def en_ruta(texto):
    """Un payload dentro de un segmento de la ruta, codificado entero."""
    return urllib.parse.quote(texto, safe="")


def totp(secreto_texto, paso, digitos=6):
    """TOTP propio de la batería (RFC 6238), independiente de app/cripto.py;
    tests/security/verificar_personal.py lo comprueba con los vectores."""
    clave = base64.b32decode(secreto_texto + "=" * (-len(secreto_texto) % 8))
    mac = hmac.new(clave, paso.to_bytes(8, "big"), hashlib.sha1).digest()
    o = mac[-1] & 0x0F
    return f"{(int.from_bytes(mac[o:o + 4], 'big') & 0x7FFFFFFF) % 10 ** digitos:0{digitos}d}"


ULTIMO_PASO = {}


def codigo_libre(secreto):
    """Código del paso actual; si ya se usó, espera al siguiente (como en
    tests/security/verificar_personal.py)."""
    while True:
        actual = int(time.time()) // 30
        if actual > ULTIMO_PASO.get(secreto, -1):
            return totp(secreto, actual), actual
        time.sleep(30 - time.time() % 30 + 0.5)


class Cuenta:
    def __init__(self, etiqueta, identificador, email):
        self.etiqueta, self.identificador, self.email = etiqueta, identificador, email
        self.contrasena = secrets.token_urlsafe(18)
        self.secreto = None
        self.dispositivo = None
        self.invitacion = None
        self.usuario_id = None
        self.renovacion = None


def activar(cuenta):
    r1 = una(pt("POST", "/v1/personal/activacion", {"token": cuenta.invitacion, "contrasena": cuenta.contrasena}))
    cuenta.secreto = (json_de(r1) or {}).get("secreto_totp")
    if r1.get("estado") != 200 or not cuenta.secreto:
        raise Parada(f"no se pudo activar {cuenta.etiqueta}: paso 1 {r1.get('estado')}")
    codigo, paso = codigo_libre(cuenta.secreto)
    r2 = una(pt("POST", "/v1/personal/activacion/confirmar", {"token": cuenta.invitacion, "codigo_totp": codigo}))
    if r2.get("estado") != 200:
        raise Parada(f"no se pudo confirmar {cuenta.etiqueta}: {r2.get('estado')}")
    ULTIMO_PASO[cuenta.secreto] = paso
    cuenta.dispositivo = (json_de(r2) or {}).get("token_dispositivo")


def peticion_login(cuenta, codigo, **cambios):
    datos = {"empresa": cuenta.identificador, "email": cuenta.email, "contrasena": cuenta.contrasena,
             "codigo_totp": codigo, "token_dispositivo": cuenta.dispositivo}
    datos.update(cambios)
    return pt("POST", "/v1/personal/sesiones", datos)


def sesion_de(cuenta):
    codigo, paso = codigo_libre(cuenta.secreto)
    r = una(peticion_login(cuenta, codigo))
    if r.get("estado") != 201:
        raise Parada(f"no se pudo iniciar sesion con {cuenta.etiqueta}: {r.get('estado')}")
    ULTIMO_PASO[cuenta.secreto] = paso
    cuenta.renovacion = json_de(r)["token_renovacion"]
    return json_de(r)["token_acceso"]


def acceso_nuevo(cuenta):
    """JWT de acceso recién renovado. El acceso dura 5 minutos y la batería
    tarda más: cada sección pide el suyo con el token de renovación, que rota
    en cada uso (app/personal.py, renovar)."""
    r = una(pt("POST", "/v1/personal/sesiones/renovacion", {"token_renovacion": cuenta.renovacion}))
    if r.get("estado") != 200:
        raise Parada(f"no se pudo renovar la sesion de {cuenta.etiqueta}: {r.get('estado')}")
    cuenta.renovacion = json_de(r)["token_renovacion"]
    return json_de(r)["token_acceso"]


def alta_empresa(nombre):
    r = gestion("alta-empresa", "--nombre", nombre, "--zona", "Europe/Madrid")
    m = PATRON_ALTA.search(r.out)
    if r.rc != 0 or not m:
        raise Parada(f"alta-empresa fallo: {r.todo.strip()[-300:]!r}")
    return m.group(1), m.group(2)


def admin_por_gestion(etiqueta, identificador, email):
    cuenta = Cuenta(etiqueta, identificador, email)
    r = gestion("alta-admin", "--identificador", identificador, "--email", email)
    m = PATRON_INVITACION_GESTION.search(r.out)
    if r.rc != 0 or not m:
        raise Parada(f"alta-admin de {etiqueta} fallo: {r.todo.strip()[-300:]!r}")
    cuenta.usuario_id, cuenta.invitacion = m.group(2), m.group(3)
    activar(cuenta)
    return cuenta


def hex_de(tabla, columna, fila_id):
    """Bytes guardados de un texto, en hexadecimal: se comparan sin tener que
    escribir el payload dentro de otra consulta."""
    return valor(f"select encode(convert_to({columna}, 'UTF8'), 'hex') from canal.{tabla} "
                 f"where id = '{uuid.UUID(fila_id)}';")


def filas_por_tabla():
    """Filas de cada tabla de canal (y cuántas tablas hay), como superusuario."""
    return valor("select string_agg(c.relname || '=' || (xpath('/row/n/text()', query_to_xml("
                 "format('select count(*) as n from canal.%I', c.relname), false, true, '')))[1]::text, ','"
                 " order by c.relname) from pg_class c join pg_namespace s on s.oid = c.relnamespace "
                 "where s.nspname = 'canal' and c.relkind in ('r', 'p');")


def errores_postgres():
    return [l for l in lineas_log("postgres") if "ERROR:" in l]


# ---------------------------------------------------------------------------
# a) Capa estática
# ---------------------------------------------------------------------------
def _es_literal(nodo):
    return isinstance(nodo, ast.Constant) and isinstance(nodo.value, str)


class Analisis:
    """Resuelve el primer argumento de cada execute de un directorio de
    módulos. Falla cerrado: lo que no sabe resolver es un hallazgo."""

    def __init__(self, directorio):
        # Recursivo: un módulo nuevo en una subcarpeta también se analiza.
        self.modulos = {f.relative_to(directorio).as_posix(): ast.parse(f.read_text(encoding="utf-8"), filename=f.name)
                        for f in sorted(directorio.rglob("*.py"))}
        self.constantes = {nombre: self._constantes(arbol) for nombre, arbol in self.modulos.items()}
        self.hallazgos = set()
        self.llamadas = 0

    @staticmethod
    def _constantes(arbol):
        """Nombres de módulo asignados una sola vez a un literal de texto."""
        asignaciones = {}
        for nodo in arbol.body:
            objetivos, valor_nodo = [], None
            if isinstance(nodo, ast.Assign):
                objetivos, valor_nodo = nodo.targets, nodo.value
            elif isinstance(nodo, ast.AnnAssign) and nodo.value is not None:
                objetivos, valor_nodo = [nodo.target], nodo.value
            for objetivo in objetivos:
                if isinstance(objetivo, ast.Name):
                    asignaciones.setdefault(objetivo.id, []).append(valor_nodo)
        return {n for n, valores in asignaciones.items() if len(valores) == 1 and _es_literal(valores[0])}

    @staticmethod
    def _funciones(arbol):
        return {n.name: n for n in ast.walk(arbol) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}

    def _alias_modulos(self, arbol):
        """Nombre local -> fichero, para 'from app import bd' y 'import app.bd as bd'."""
        alias = {}
        for nodo in ast.walk(arbol):
            if isinstance(nodo, ast.ImportFrom) and nodo.module in ("app", None):
                for nombre in nodo.names:
                    if f"{nombre.name}.py" in self.modulos:
                        alias[nombre.asname or nombre.name] = f"{nombre.name}.py"
        return alias

    def _resuelto(self, modulo, expresion, funcion, profundidad=0):
        if profundidad > 5:
            return False
        if _es_literal(expresion):
            return True
        if isinstance(expresion, ast.Name):
            if expresion.id in self.constantes[modulo] and not self._reasignado(funcion, expresion.id):
                return True
            return funcion is not None and self._parametro_resuelto(modulo, funcion, expresion.id, profundidad)
        if (isinstance(expresion, ast.Attribute) and isinstance(expresion.value, ast.Name)
                and expresion.value.id in self._alias_modulos(self.modulos[modulo])):
            otro = self._alias_modulos(self.modulos[modulo])[expresion.value.id]
            return expresion.attr in self.constantes[otro]
        return False

    @staticmethod
    def _reasignado(funcion, nombre):
        """Un nombre que la función asigna es una variable local, no la constante."""
        if funcion is None:
            return False
        return any(isinstance(n, ast.Name) and n.id == nombre and isinstance(n.ctx, ast.Store)
                   for n in ast.walk(funcion))

    def _parametro_resuelto(self, modulo, funcion, nombre, profundidad):
        parametros = [a.arg for a in funcion.args.posonlyargs + funcion.args.args]
        if nombre not in parametros or self._reasignado(funcion, nombre):
            return False
        posicion = parametros.index(nombre)
        llamadas = []
        for nodo in ast.walk(self.modulos[modulo]):
            if isinstance(nodo, ast.Call) and isinstance(nodo.func, ast.Name) and nodo.func.id == funcion.name:
                argumento = nodo.args[posicion] if posicion < len(nodo.args) else next(
                    (k.value for k in nodo.keywords if k.arg == nombre), None)
                llamadas.append((argumento, self._contenedora(modulo, nodo)))
        # Sin llamadas no hay de dónde resolverlo: falla cerrado.
        return bool(llamadas) and all(a is not None and self._resuelto(modulo, a, c, profundidad + 1)
                                      for a, c in llamadas)

    def _contenedora(self, modulo, objetivo):
        """La función más interna que contiene el nodo, o None."""
        mejor = None
        for funcion in self._funciones(self.modulos[modulo]).values():
            if any(n is objetivo for n in ast.walk(funcion)) and (
                    mejor is None or any(n is funcion for n in ast.walk(mejor))):
                mejor = funcion
        return mejor

    def ejecutar(self):
        for modulo, arbol in self.modulos.items():
            for nodo in ast.walk(arbol):
                if isinstance(nodo, ast.ImportFrom) and nodo.module and nodo.module.startswith("psycopg"):
                    nombres = {a.name for a in nodo.names}
                    if nodo.module == "psycopg.sql" or "sql" in nombres:
                        self.hallazgos.add((modulo, "<modulo>", "psycopg.sql"))
                    if nombres & {"ClientCursor", "AsyncClientCursor"}:
                        self.hallazgos.add((modulo, "<modulo>", "ClientCursor"))
                if isinstance(nodo, ast.Attribute) and nodo.attr in ("ClientCursor", "AsyncClientCursor"):
                    self.hallazgos.add((modulo, "<modulo>", "ClientCursor"))
                if not (isinstance(nodo, ast.Call) and isinstance(nodo.func, ast.Attribute)
                        and nodo.func.attr in METODOS_SQL):
                    continue
                self.llamadas += 1
                funcion = self._contenedora(modulo, nodo)
                nombre_funcion = funcion.name if funcion else "<modulo>"
                if not nodo.args:
                    receptor = nodo.func.value.id if isinstance(nodo.func.value, ast.Name) else None
                    if (modulo, receptor) not in SIN_ARGUMENTOS_NO_SQL:
                        self.hallazgos.add((modulo, nombre_funcion, "sin argumentos"))
                    continue
                if not self._resuelto(modulo, nodo.args[0], funcion):
                    self.hallazgos.add((modulo, nombre_funcion, "no resoluble"))
        return self


def seccion_a():
    p("=== a) capa estatica: todo el SQL de app/ es literal y va con parametros")
    sintetico = TEMPORAL / "sintetico"
    sintetico.mkdir()
    (sintetico / "malo.py").write_text(MODULO_MALO, encoding="utf-8", newline="\n")
    (sintetico / "bueno.py").write_text(MODULO_BUENO, encoding="utf-8", newline="\n")
    (sintetico / "otro.py").write_text(MODULO_OTRO, encoding="utf-8", newline="\n")
    control = Analisis(sintetico).ejecutar()
    malos = {(f, m) for modulo, f, m in control.hallazgos if modulo == "malo.py"}
    buenos = {h for h in control.hallazgos if h[0] != "malo.py"}
    control_ok = malos == HALLAZGOS_SINTETICOS and not buenos
    pasa(control_ok, "a) control: el modulo sintetico da exactamente sus 10 hallazgos y el correcto ninguno "
                     f"(faltan {sorted(HALLAZGOS_SINTETICOS - malos)}, sobran {sorted(malos - HALLAZGOS_SINTETICOS)}, "
                     f"en el correcto {sorted(buenos)})")
    real = Analisis(RAIZ / "app").ejecutar()
    p(f"   llamadas analizadas en app/: {real.llamadas} en {len(real.modulos)} modulos")
    negativo("a) ninguna llamada de app/ ejecuta SQL compuesto, sin resolver o con psycopg.sql o ClientCursor",
             not real.hallazgos and real.llamadas > 0, control_ok, f"hallazgos: {sorted(real.hallazgos)}")


# ---------------------------------------------------------------------------
# b) Arranque y preparación
# ---------------------------------------------------------------------------
ESTADO = {}


def seccion_b():
    global IMAGEN_API
    p("=== b) arranque y preparacion")
    r = dc("up", "-d", "--build", "--wait")
    p(f"up -d --build --wait -> codigo {r.rc}")
    if r.rc != 0:
        p(r.todo.strip()[-2000:])
        raise Parada("no arranca el proyecto")
    registro = "\n".join(lineas_log("api"))
    pasa(TEXTO_VERIFICADO in registro and TEXTO_BLOQUEADO not in registro, "b) la API arranca verificada")
    pasa(TEXTO_LIMITES_PRUEBA in registro, "b) las secciones usan los limites de prueba")
    IMAGEN_API = json.loads(ejecutar(["docker", "inspect", contenedor("api")]).out)[0]["Config"]["Image"]
    empresa_id, identificador = alta_empresa("Empresa Inyeccion S.L.")
    admin = admin_por_gestion("admin", identificador, "admin@inyeccion.test")
    token = sesion_de(admin)
    r = una(pt("POST", "/v1/personal/usuarios", {"email": "instructor@inyeccion.test", "rol": "instructor"},
               token=token))
    if r.get("estado") != 201:
        raise Parada(f"no se pudo invitar al instructor: {r.get('estado')}")
    instructor = Cuenta("instructor", identificador, "instructor@inyeccion.test")
    instructor.invitacion = json_de(r)["token_invitacion"]
    instructor.usuario_id = json_de(r)["usuario_id"]
    activar(instructor)
    r = una(pt("POST", f"/v1/empresas/{identificador}/denuncias", {"categoria": CATEGORIA, "texto": "denuncia"}))
    if r.get("estado") != 201:
        raise Parada(f"no se pudo crear la denuncia de control: {r.get('estado')}")
    sesion_de(instructor)
    ESTADO.update(empresa_id=empresa_id, identificador=identificador, admin=admin, instructor=instructor,
                  codigo=json_de(r)["codigo_seguimiento"], fecha=json_de(r)["fecha"],
                  denuncia_id=valor("select id from canal.denuncia;"))
    admin.usuario_id = valor("select id from canal.usuario_personal where email = 'admin@inyeccion.test';")


# ---------------------------------------------------------------------------
# c) Catálogo: sin EXECUTE dinámico en plpgsql
# ---------------------------------------------------------------------------
SQL_EXECUTE_DINAMICO = ("select coalesce(string_agg(n.nspname || '.' || p.proname, ',' order by p.proname), '') "
                        "from pg_proc p join pg_namespace n on n.oid = p.pronamespace "
                        "join pg_language l on l.oid = p.prolang "
                        "where n.nspname in ('canal', 'public') and l.lanname = 'plpgsql' "
                        "and p.prosrc ~* '\\mexecute\\M';")


def seccion_c():
    p("=== c) catalogo: ninguna funcion plpgsql usa EXECUTE dinamico")
    total = valor("select count(*) from pg_proc p join pg_namespace n on n.oid = p.pronamespace "
                  "join pg_language l on l.oid = p.prolang where n.nspname = 'canal' and l.lanname = 'plpgsql';")
    p(f"   funciones plpgsql en canal: {total}")
    # Control: una función con EXECUTE, creada y vista dentro de una
    # transacción que se deshace.
    control = valor("begin;\ncreate function canal.prueba_inyeccion() returns void language plpgsql as "
                    "$f$ begin execute 'select 1'; end $f$;\n" + SQL_EXECUTE_DINAMICO + "\nrollback;")
    control_ok = control == "canal.prueba_inyeccion"
    pasa(control_ok, f"c) control: una funcion temporal con EXECUTE se detecta ({control!r})")
    real = valor(SQL_EXECUTE_DINAMICO)
    negativo("c) ninguna funcion plpgsql de canal o public contiene EXECUTE", real == "" and int(total) > 0,
             control_ok, f"con EXECUTE: {real!r}")


# ---------------------------------------------------------------------------
# d) Payloads de inyección en cada entrada
# ---------------------------------------------------------------------------
def entradas():
    """(nombre, constructor de la petición con el payload, oráculo (estado,
    cuerpo) para un payload, petición de control, estados del control).

    Llegan al SQL como texto: login.empresa (se consulta siempre, también
    mal formada), login.email y seguimiento.codigo (como HMAC). Se rechazan
    antes del SQL: el identificador de la ruta (32 hex), estado (lista
    cerrada), cursor (fecha.uuid), desde (entero) y los ids (uuid)."""
    admin = ESTADO["admin"]
    token = acceso_nuevo(admin)
    denuncia = ESTADO["denuncia_id"]
    contrasena_mala = "equivocada-" + secrets.token_hex(6)

    def login_401(payload):
        if len(payload) > LONGITUD_MAXIMA_IDENTIFICADOR:
            return 422, CUERPO_422
        return 401, CUERPO_401_CREDENCIALES

    def id_cuerpo(payload):
        return (422, CUERPO_422) if len(payload) > LONGITUD_MAXIMA_ID_CUERPO else (404, CUERPO_404)

    return [
        ("login.empresa",
         lambda v: peticion_login(admin, "000000", empresa=v, contrasena=contrasena_mala),
         login_401, None, None),
        ("login.email",
         lambda v: peticion_login(admin, "000000", email=v, contrasena=contrasena_mala),
         lambda v: (401, CUERPO_401_CREDENCIALES), None, None),
        ("crear.identificador",
         lambda v: pt("POST", f"/v1/empresas/{en_ruta(v)}/denuncias", {"categoria": CATEGORIA, "texto": "t"}),
         lambda v: (404, CUERPO_404),
         pt("POST", f"/v1/empresas/{ESTADO['identificador']}/denuncias", {"categoria": CATEGORIA, "texto": "t"}),
         {201}),
        ("seguimiento.codigo",
         lambda v: pt("POST", "/v1/seguimiento", {"codigo": v}),
         lambda v: (404, CUERPO_404_CODIGO),
         pt("POST", "/v1/seguimiento", {"codigo": ESTADO["codigo"]}), {200}),
        ("listado.estado",
         lambda v: pt("GET", f"/v1/personal/denuncias?estado={en_ruta(v)}", token=token),
         lambda v: (422, CUERPO_422),
         pt("GET", "/v1/personal/denuncias?estado=nueva", token=token), {200}),
        ("listado.cursor",
         lambda v: pt("GET", f"/v1/personal/denuncias?cursor={en_ruta(v)}", token=token),
         lambda v: (422, CUERPO_422),
         pt("GET", f"/v1/personal/denuncias?cursor={ESTADO['fecha']}.{uuid.uuid4()}", token=token), {200}),
        ("auditoria.desde",
         lambda v: pt("GET", f"/v1/personal/auditoria?desde={en_ruta(v)}", token=token),
         lambda v: (422, CUERPO_422),
         pt("GET", "/v1/personal/auditoria?desde=1", token=token), {200}),
        ("lectura.denuncia_id",
         lambda v: pt("GET", f"/v1/personal/denuncias/{en_ruta(v)}", token=token),
         lambda v: (404, CUERPO_404),
         pt("GET", f"/v1/personal/denuncias/{denuncia}", token=token), {200}),
        ("asignacion.usuario_id",
         lambda v: pt("PUT", f"/v1/personal/denuncias/{denuncia}/asignacion", {"usuario_id": v}, token=token),
         id_cuerpo,
         pt("PUT", f"/v1/personal/denuncias/{denuncia}/asignacion", {"usuario_id": admin.usuario_id},
            token=token), {204}),
    ]


def contadores_admin():
    return valor(f"select intentos_fallidos || '|' || coalesce(bloqueado_hasta::text, '') "
                 f"from canal.usuario_personal where id = '{ESTADO['admin'].usuario_id}';") + "/" + valor(
        f"select coalesce(string_agg(intentos_fallidos::text, ',' order by id), '') from canal.dispositivo_personal "
        f"where usuario_id = '{ESTADO['admin'].usuario_id}';")


def seccion_d():
    p("=== d) payloads de inyeccion en cada entrada")
    admin = ESTADO["admin"]
    token = acceso_nuevo(admin)
    # El admin se asigna la denuncia: así su lectura es el control de la
    # entrada lectura.denuncia_id (sin asignación, el contenido no se lee).
    r = una(pt("PUT", f"/v1/personal/denuncias/{ESTADO['denuncia_id']}/asignacion",
               {"usuario_id": admin.usuario_id}, token=token))
    if r.get("estado") != 204:
        raise Parada(f"el admin no pudo asignarse la denuncia: {r.get('estado')}")

    # Controles por entrada: un valor válido llega al SQL y responde bien.
    controles = {}
    lista = entradas()
    for nombre, _, _, control, esperados in lista:
        if control is not None:
            respuesta = una(control)
            controles[nombre] = respuesta.get("estado") in esperados
            pasa(controles[nombre], f"d) control {nombre}: un valor valido responde {respuesta.get('estado')}")
    codigo, paso = codigo_libre(admin.secreto)
    respuesta = una(peticion_login(admin, codigo))
    if respuesta.get("estado") == 201:
        ULTIMO_PASO[admin.secreto] = paso
    controles["login.empresa"] = controles["login.email"] = respuesta.get("estado") == 201
    pasa(controles["login.email"], f"d) control login: credenciales validas responden {respuesta.get('estado')}")

    # Control de sensibilidad de los contadores: un fallo real los mueve.
    antes_fallo = contadores_admin()
    una(peticion_login(admin, "000000", contrasena="equivocada"))
    tras_fallo = contadores_admin()
    contadores_ok = tras_fallo != antes_fallo
    pasa(contadores_ok, f"d) control: un login fallido real mueve los contadores del admin ({antes_fallo} -> {tras_fallo})")
    valor(f"update canal.usuario_personal set intentos_fallidos = 0, bloqueado_hasta = null "
          f"where id = '{admin.usuario_id}'; update canal.dispositivo_personal set intentos_fallidos = 0, "
          f"bloqueado_hasta = null where usuario_id = '{admin.usuario_id}'; select 1;")

    tablas_antes = filas_por_tabla()
    contadores_antes = contadores_admin()
    errores_antes = len(errores_postgres())
    sleep_lentos = []
    for nombre, construir, oraculo, _, _ in lista:
        respuestas = http([construir(v) for v in PAYLOADS_SQL])
        fallidos = []
        for payload, respuesta in zip(PAYLOADS_SQL, respuestas):
            esperado = oraculo(payload)
            if (respuesta.get("estado"), respuesta.get("cuerpo")) != esperado:
                fallidos.append((payload, respuesta.get("estado"), respuesta.get("cuerpo", b"")[:80]))
            if "pg_sleep" in payload and respuesta.get("ms", 0) >= MS_MAXIMO_SIN_SLEEP:
                sleep_lentos.append((nombre, payload, round(respuesta.get("ms", 0))))
        negativo(f"d) {nombre}: los {len(PAYLOADS_SQL)} payloads dan su respuesta literal, sin 500",
                 not fallidos, controles.get(nombre, False), f"distintos: {fallidos}")
    errores_despues = errores_postgres()[errores_antes:]
    tablas_despues = filas_por_tabla()
    contadores_despues = contadores_admin()

    inicio = time.monotonic()
    sup(f"select pg_sleep({SEGUNDOS_SLEEP});")
    sleep_ok = time.monotonic() - inicio >= SEGUNDOS_SLEEP
    negativo(f"d) ningun payload con pg_sleep({SEGUNDOS_SLEEP}) tarda {MS_MAXIMO_SIN_SLEEP} ms o mas",
             not sleep_lentos, sleep_ok, f"lentos: {sleep_lentos}")
    negativo("d) ninguna tabla de canal desaparece ni cambia de filas", tablas_despues == tablas_antes,
             bool(tablas_antes), f"antes {tablas_antes}; despues {tablas_despues}")
    negativo("d) los contadores del login del admin no se mueven (ningun payload encontro su cuenta)",
             contadores_despues == contadores_antes, contadores_ok,
             f"{contadores_antes} -> {contadores_despues}")
    r = una(pt("GET", "/v1/personal/auditoria/verificacion", token=token))
    pasa(r.get("estado") == 200 and json_de(r) == {"cadena_intacta": True, "primera_rota": None},
         f"d) la cadena de auditoria sigue intacta ({json_de(r)})")
    # Control del log: una consulta mal formada a propósito deja su ERROR.
    antes_control = len(errores_postgres())
    sup("select from where;")
    control_log = len(errores_postgres()) > antes_control
    negativo("d) los payloads no dejan ninguna linea de ERROR en el log de PostgreSQL", not errores_despues,
             control_log, f"lineas: {errores_despues[:5]}")


# ---------------------------------------------------------------------------
# e) Frontera: NUL, surrogates y tipos que no son texto
# ---------------------------------------------------------------------------
def campos():
    """Cada campo de texto de cada modelo de entrada: (nombre, constructor de
    la petición con el valor, valor benigno, estados del benigno). El benigno
    es el control: con él, el campo no da 422."""
    token = acceso_nuevo(ESTADO["admin"])
    token_instructor = acceso_nuevo(ESTADO["instructor"])
    identificador, codigo, denuncia = ESTADO["identificador"], ESTADO["codigo"], ESTADO["denuncia_id"]
    sin_cuenta = secrets.token_hex(16)
    contador = iter(range(10_000))

    def login(**cambios):
        datos = {"empresa": identificador, "email": "nadie@inyeccion.test", "contrasena": "equivocada",
                 "codigo_totp": "000000", "token_dispositivo": None}
        datos.update(cambios)
        return pt("POST", "/v1/personal/sesiones", datos)

    def contrasena(**cambios):
        datos = {"contrasena_actual": "equivocada", "contrasena_nueva": "otra-contrasena-larga",
                 "codigo_totp": "000000"}
        datos.update(cambios)
        return pt("POST", "/v1/personal/contrasena", datos, token=token_instructor)

    return [
        ("crear.texto", lambda v: pt("POST", f"/v1/empresas/{identificador}/denuncias",
                                     {"categoria": CATEGORIA, "texto": v}), "texto benigno", {201}),
        ("seguimiento.codigo", lambda v: pt("POST", "/v1/seguimiento", {"codigo": v}), "AAAA", {404}),
        ("mensaje.codigo", lambda v: pt("POST", "/v1/seguimiento/mensajes", {"codigo": v, "texto": "hola"}),
         "AAAA", {404}),
        ("mensaje.texto", lambda v: pt("POST", "/v1/seguimiento/mensajes", {"codigo": codigo, "texto": v}),
         "texto benigno", {201}),
        ("activacion.token", lambda v: pt("POST", "/v1/personal/activacion",
                                          {"token": v, "contrasena": "contrasena-larga"}), "x", {401}),
        ("activacion.contrasena", lambda v: pt("POST", "/v1/personal/activacion",
                                               {"token": "x", "contrasena": v}), "contrasena-larga", {401}),
        ("confirmacion.token", lambda v: pt("POST", "/v1/personal/activacion/confirmar",
                                            {"token": v, "codigo_totp": "000000"}), "x", {401}),
        ("confirmacion.codigo_totp", lambda v: pt("POST", "/v1/personal/activacion/confirmar",
                                                  {"token": "x", "codigo_totp": v}), "000000", {401}),
        ("login.empresa", lambda v: login(empresa=v), sin_cuenta, {401}),
        ("login.email", lambda v: login(email=v), "nadie@inyeccion.test", {401}),
        ("login.contrasena", lambda v: login(contrasena=v), "equivocada", {401}),
        ("login.codigo_totp", lambda v: login(codigo_totp=v), "000000", {401}),
        ("login.token_dispositivo", lambda v: login(token_dispositivo=v), "x", {401}),
        ("renovacion.token", lambda v: pt("POST", "/v1/personal/sesiones/renovacion", {"token_renovacion": v}),
         "x", {401}),
        ("contrasena.actual", lambda v: contrasena(contrasena_actual=v), "equivocada", {401}),
        ("contrasena.nueva", lambda v: contrasena(contrasena_nueva=v), "otra-contrasena-larga", {401}),
        ("contrasena.codigo_totp", lambda v: contrasena(codigo_totp=v), "000000", {401}),
        ("usuarios.email", lambda v: pt("POST", "/v1/personal/usuarios", {"email": v, "rol": "instructor"},
                                        token=token),
         None, {201}),
        ("personal_mensaje.texto", lambda v: pt("POST", f"/v1/personal/denuncias/{denuncia}/mensajes",
                                                {"texto": v}, token=token), "texto benigno", {201}),
        ("estado.mensaje", lambda v: pt("POST", f"/v1/personal/denuncias/{denuncia}/estado",
                                        {"estado": "resuelta", "mensaje": v}, token=token), "texto benigno", {409}),
        ("asignacion.usuario_id", lambda v: pt("PUT", f"/v1/personal/denuncias/{denuncia}/asignacion",
                                               {"usuario_id": v}, token=token), "x", {404}),
        # El benigno no esta en la posicion 0 del texto: 409 sin escribir nada.
        ("redaccion.texto", lambda v: pt("POST", f"/v1/personal/denuncias/{denuncia}/redaccion",
                                         {"tramos": [{"desde": 0, "texto": v}]}, token=token),
         "texto benigno", {409}),
    ], (lambda: f"benigno{next(contador)}@inyeccion.test")


# TextoLibre solo rechaza NUL y surrogates: estos controles se guardan en una
# denuncia y se rechazan en un TextoLinea.
CONTROLES_LINEA = ["\t", "\n", "\x0b", "\x0c", "\x1b", "\x85"]
TEXTO_CON_CONTROLES = "a\tb\nc\r\nd\x0be\x0cf\x1b[31mg\x85h"
# C0 que lleva el texto y su escape JSON esperado (\r y \n pueden salir con
# su escape corto, así que solo se exige el \uXXXX de los que no lo tienen).
CONTROLES_C0 = [0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x1b]
CONTROLES_C0_ESCAPADOS = [0x0b, 0x1b]

# Campos donde además se prueban tipos que no son texto (los obligatorios
# que llegan al SQL o a un id).
CAMPOS_TIPOS = {"login.empresa", "login.email", "seguimiento.codigo", "usuarios.email", "asignacion.usuario_id",
                "crear.texto"}


def con_insercion(benigno, caracter):
    """El benigno con un carácter dentro: conserva su forma (un email sigue
    siendo un email), así solo cambia lo que se prueba."""
    return benigno[:1] + caracter + benigno[1:]


def seccion_e():
    p("=== e) frontera: NUL, surrogates y tipos que no son texto dan el 422 propio")
    r = dc("exec", "-T", "api", "python", "-c", MODELOS_DENTRO)
    try:
        modelos = json.loads(r.out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise Parada(f"no se pudieron recorrer los modelos dentro de la API: {r.err.strip()[-400:]!r}") from None
    control_ok = modelos["control"] == CONTROL_MODELOS
    pasa(control_ok, f"e) control: un modelo sintetico con str sin validar se detecta ({modelos['control']})")
    reales = modelos["reales"]
    negativo(f"e) los {len(CAMPOS_TEXTO)} campos de texto de los modelos de entrada son exactamente los esperados "
             "y todos usan TextoLinea o TextoLibre",
             set(reales) == CAMPOS_TEXTO and all(reales.values()), control_ok,
             f"sin validar {sorted(c for c, v in reales.items() if not v)}; "
             f"nuevos {sorted(set(reales) - CAMPOS_TEXTO)}; faltan {sorted(CAMPOS_TEXTO - set(reales))}")
    lista, email_benigno = campos()
    errores_api_antes = sum("ERROR INTERNO" in l for l in lineas_log("api"))
    for nombre, construir, benigno, esperados in lista:
        # benigno None: un email nuevo en cada uso (invitar dos veces el
        # mismo daría 409 y no probaría nada).
        # benigno enlazado de forma explícita: el de esta vuelta.
        def benigno_de(benigno=benigno):
            return benigno if benigno is not None else email_benigno()

        control = una(construir(benigno_de()))
        control_ok = control.get("estado") in esperados
        pasa(control_ok, f"e) control {nombre}: el valor benigno responde {control.get('estado')}")
        pruebas = {"NUL": con_insercion(benigno_de(), "\x00"), "surrogate": con_insercion(benigno_de(), "\ud800")}
        if nombre in CAMPOS_TIPOS:
            pruebas.update({f"tipo {json.dumps(t)}": t for t in TIPOS_NO_TEXTO})
        respuestas = http([construir(v) for v in pruebas.values()])
        distintos = [(etiqueta, r.get("estado")) for etiqueta, r in zip(pruebas, respuestas)
                     if (r.get("estado"), r.get("cuerpo")) != (422, CUERPO_422)]
        negativo(f"e) {nombre}: {', '.join(pruebas)} dan 422 con el cuerpo exacto", not distintos, control_ok,
                 f"distintos: {distintos}")
    nuevos = sum("ERROR INTERNO" in l for l in lineas_log("api")) - errores_api_antes
    pasa(nuevos == 0, f"e) ninguna de esas peticiones deja un ERROR INTERNO en el log de la API ({nuevos})")

    # La regla en las dos direcciones: los controles que un texto libre
    # guarda (es una prueba) son los que un TextoLinea rechaza.
    r = una(pt("POST", f"/v1/empresas/{ESTADO['identificador']}/denuncias",
               {"categoria": CATEGORIA, "texto": TEXTO_CON_CONTROLES}))
    creada = r.get("estado") == 201
    pasa(creada, f"e) un texto libre con tabulador, saltos, VT, FF, ESC y NEL se acepta ({r.get('estado')})")
    if creada:
        s = una(pt("POST", "/v1/seguimiento", {"codigo": json_de(r)["codigo_seguimiento"]}))
        pasa(s.get("estado") == 200 and (json_de(s) or {}).get("texto") == TEXTO_CON_CONTROLES,
             "e) y el seguimiento lo devuelve tal cual, caracter a caracter")
        # RFC 8259, 7: los controles C0 viajan escapados en el JSON, nunca
        # como bytes en crudo (la base de la regla, docs/threat-model.md 6.16).
        crudos = [hex(c) for c in CONTROLES_C0 if bytes([c]) in s.get("cuerpo", b"")]
        escapados = all(f"\\u{c:04x}".encode("ascii") in s.get("cuerpo", b"") for c in CONTROLES_C0_ESCAPADOS)
        pasa(not crudos and escapados,
             f"e) en el JSON de la respuesta los controles C0 van escapados y ninguno en crudo (crudos {crudos})")
    # El email del login es solo TextoLinea (sin validar_email, que también
    # los rechazaría): así el 422 es de la regla y no de otra validación.
    # Control: el mismo login sin el control da 401.
    def login_con(email):
        return pt("POST", "/v1/personal/sesiones", {"empresa": ESTADO["identificador"], "email": email,
                                                     "contrasena": "equivocada", "codigo_totp": "000000"})

    benigno, *respuestas = http([login_con("nadie@inyeccion.test")]
                                + [login_con(con_insercion("nadie@inyeccion.test", c)) for c in CONTROLES_LINEA])
    distintos = [(hex(ord(c)), r.get("estado")) for c, r in zip(CONTROLES_LINEA, respuestas)
                 if (r.get("estado"), r.get("cuerpo")) != (422, CUERPO_422)]
    negativo("e) esos mismos controles en un TextoLinea (el email del login) dan 422", not distintos,
             creada and benigno.get("estado") == 401, f"distintos: {distintos}; benigno {benigno.get('estado')}")


# ---------------------------------------------------------------------------
# f) Segundo orden: valores con SQL guardados y reutilizados
# ---------------------------------------------------------------------------
def seccion_f():
    p("=== f) segundo orden: lo guardado con SQL vuelve byte a byte y se reutiliza como dato")
    empresa_id, identificador = alta_empresa(NOMBRE_EMPRESA_SQL)
    pasa(valor(f"select encode(convert_to(nombre, 'UTF8'), 'hex') from canal.empresa where id = '{empresa_id}';")
         == NOMBRE_EMPRESA_SQL.encode("utf-8").hex(),
         "f) gestion guarda el nombre de empresa con SQL tal cual")
    admin = admin_por_gestion("admin_sql", identificador, EMAIL_GESTION_SQL)
    pasa(hex_de("usuario_personal", "email", admin.usuario_id) == EMAIL_GESTION_SQL.encode("utf-8").hex(),
         "f) gestion guarda el email con SQL tal cual")
    # Activar comprueba la contraseña contra el nombre y el email guardados,
    # y el login busca la cuenta por ese email: si se reinterpretaran como
    # SQL, la cuenta no activaría o no entraría.
    token = sesion_de(admin)
    r = una(pt("GET", "/v1/personal/yo", token=token))
    pasa(r.get("estado") == 200 and (json_de(r) or {}).get("email") == EMAIL_GESTION_SQL,
         "f) la cuenta con ese email activa, entra y /yo devuelve el email exacto")

    lentos, creados = [], {}
    respuestas = http([pt("POST", "/v1/personal/usuarios", {"email": e, "rol": "instructor"}, token=token)
                       for e in EMAILS_SEGUNDO_ORDEN])
    for email, respuesta in zip(EMAILS_SEGUNDO_ORDEN, respuestas):
        if respuesta.get("estado") == 201:
            creados[email] = json_de(respuesta)["usuario_id"]
        if respuesta.get("ms", 0) >= MS_MAXIMO_SIN_SLEEP:
            lentos.append((email, round(respuesta.get("ms", 0))))
    pasa(len(creados) == len(EMAILS_SEGUNDO_ORDEN),
         f"f) la API acepta los {len(EMAILS_SEGUNDO_ORDEN)} emails con SQL ({sorted(set(EMAILS_SEGUNDO_ORDEN) - set(creados))})")
    pasa(not lentos, f"f) ninguna invitacion tarda {MS_MAXIMO_SIN_SLEEP} ms o mas ({lentos})")
    distintos = [e for e, i in creados.items() if hex_de("usuario_personal", "email", i) != e.encode("utf-8").hex()]
    pasa(not distintos, f"f) cada email se guarda byte a byte ({distintos})")
    r = una(pt("GET", "/v1/personal/usuarios", token=token))
    listados = sorted(u["email"] for u in (json_de(r) or {}).get("usuarios", []))
    pasa(listados == sorted([EMAIL_GESTION_SQL, *EMAILS_SEGUNDO_ORDEN]),
         "f) la lista de cuentas devuelve exactamente esos emails, ni mas ni menos")
    r = una(pt("GET", "/v1/personal/auditoria/verificacion", token=token))
    pasa(json_de(r) == {"cadena_intacta": True, "primera_rota": None},
         f"f) la cadena de auditoria de esa empresa sigue intacta ({json_de(r)})")
    pasa(valor("select to_regclass('canal.denuncia') is not null;") == "t", "f) canal.denuncia sigue existiendo")

    # gestion valida el email como la API (app/rutas_personal.py, _email).
    _, identificador_c = alta_empresa("Empresa Validacion S.L.")
    rechazos = []
    for email in EMAILS_GESTION_INVALIDOS:
        r = gestion("alta-admin", "--identificador", identificador_c, "--email", email)
        creada = valor("select count(*) from canal.usuario_personal where email = lower("
                       f"convert_from(decode('{email.encode('utf-8').hex()}', 'hex'), 'UTF8'));")
        rechazos.append((email, r.rc, creada))
    r = gestion("alta-admin", "--identificador", identificador_c, "--email", "valido@inyeccion.test")
    negativo("f) gestion rechaza un email con espacios o no ASCII y no crea la cuenta",
             all(rc != 0 and creada == "0" for _, rc, creada in rechazos), r.rc == 0, f"{rechazos}")
    # El control es el alta con el nombre con SQL del principio de la
    # sección, que funcionó (si no, habría PARADA).
    empresas_antes = valor("select count(*) from canal.empresa;")
    r = gestion("alta-empresa", "--nombre", NOMBRE_EMPRESA_CONTROL, "--zona", "Europe/Madrid")
    pasa(r.rc != 0 and valor("select count(*) from canal.empresa;") == empresas_antes,
         f"f) gestion rechaza un nombre de empresa con caracteres de control y no la crea (codigo {r.rc})")


# ---------------------------------------------------------------------------
# g) Mínimo privilegio
# ---------------------------------------------------------------------------
def seccion_g():
    p("=== g) minimo privilegio: lo que haria una inyeccion, denegado a aplicacion")
    # Control: como superusuario todas funcionan, en una transacción que se
    # deshace (no deja nada).
    r = sup("begin;\n" + "\n".join(s for _, s in SENTENCIAS_PRIVILEGIO) + "\nrollback;")
    control_ok = r.rc == 0
    pasa(control_ok, f"g) control: como superusuario las {len(SENTENCIAS_PRIVILEGIO)} sentencias funcionan "
                     f"(codigo {r.rc} {r.err.strip()[-200:]!r})")
    for etiqueta, sentencia in SENTENCIAS_PRIVILEGIO:
        r = sup("\\set VERBOSITY sqlstate\nbegin;\nset local role aplicacion;\n" + sentencia + "\nrollback;")
        negativo(f"g) {etiqueta} como aplicacion: {SQLSTATE_PRIVILEGIO}",
                 r.rc != 0 and f"ERROR:  {SQLSTATE_PRIVILEGIO}" in r.err, control_ok,
                 f"codigo {r.rc}: {r.err.strip()[-200:]!r}")


# ---------------------------------------------------------------------------
# s) Limpieza y ejecución
# ---------------------------------------------------------------------------
def seccion_s():
    p("=== s) limpieza")
    r = dc_con_gestion("down", "-v", "--rmi", "local")
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


def terminar(parada=False):
    if parada:
        resultado = "NO OK (PARADA)"
    else:
        resultado = "NO OK (hay FALLA o SIN CONCLUSION)" if estado["falla"] or estado["sin_conclusion"] else "OK"
    p("RESULTADO GLOBAL: " + resultado)
    SALIDA.write_text("\n".join(lineas_salida) + "\n", encoding="utf-8", newline="\n")
    sys.exit(0 if resultado == "OK" else 1)


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
    if ejecutar(["docker", "info", "--format", "{{.ServerVersion}}"]).rc != 0:
        p("PARADA: docker info falla")
        terminar(parada=True)
    previos = recursos_previos()
    if previos:
        p(f"PARADA: ya existen recursos con prefijo {PROYECTO}: {previos}")
        terminar(parada=True)
    ocupadas = subredes_ocupadas()
    if ocupadas:
        p(f"PARADA: las subredes fijas ya estan en uso por {ocupadas} (pare el proyecto canario y las otras baterias)")
        terminar(parada=True)
    # Solo se comprueba que existen (is_file), nunca se leen.
    for fichero in ("contrasena_redis.txt", "redis_acl.conf", "contrasena_postgres_superusuario.txt",
                    "contrasena_migrador.txt", "contrasena_aplicacion.txt", "contrasena_plataforma.txt",
                    "clave_maestra.txt", "clave_hmac_codigos.txt", "clave_firma_tokens.txt"):
        if not (RAIZ / "secrets" / fichero).is_file():
            p(f"PARADA: secrets/{fichero} no existe (scripts/generar_secretos.py)")
            terminar(parada=True)
    TEMPORAL = pathlib.Path(tempfile.mkdtemp(prefix="canario_inyeccion_"))
    preparar_secretos_falsos()
    parada = None
    try:
        seccion_a()
        for seccion in (seccion_b, seccion_c, seccion_d, seccion_e, seccion_f, seccion_g):
            seccion()
    except Parada as e:
        parada = str(e)
        p(f"PARADA: {parada}")
    except Exception:  # noqa: BLE001 - error inesperado del propio test: se informa y se limpia
        parada = "error inesperado en el test"
        p("ERROR INESPERADO:\n" + traceback.format_exc())
    finally:
        if parada is not None:
            dc_con_gestion("down", "-v", "--rmi", "local")
        else:
            seccion_s()
        shutil.rmtree(TEMPORAL, ignore_errors=True)
    terminar(parada=parada is not None)


if __name__ == "__main__":
    main()
