#!/usr/bin/env python3
"""Batería de pruebas de seguridad de la identidad del personal (bloque 4a).

Código probado: app/personal.py, app/rutas_personal.py, app/cripto.py (TOTP y
tokens), app/gestion.py (alta-admin), la regla acceso de app/limitador.py y
las tablas del personal de db/init/02_esquema.sql (docs/threat-model.md, 6.3
y 6.9). Qué prueba:

* Alta del primer admin por gestion: solo sin admins activados, con una fila
  de auditoría de plataforma; después se niega.
* Activación: política de contraseñas, secreto TOTP con su URI, confirmación
  con un código, invitación de un solo uso, caducada o de otra empresa, y que
  en la base de datos solo hay Argon2id con los parámetros de OWASP, el
  secreto cifrado y el SHA-256 de cada token.
* Login: el mismo 401, byte a byte, para empresa inexistente o mal formada,
  email inexistente, contraseña o código erróneos, cuenta sin activar o dada
  de baja; tiempos comparables (con control de sensibilidad); un código TOTP
  solo vale una vez.
* Bloqueo sin denegación de servicio: los fallos sin dispositivo de confianza
  bloquean ese camino con esperas crecientes, y el titular sigue entrando con
  su dispositivo; los fallos con el dispositivo bloquean solo el dispositivo;
  20 lo retiran; 100 cierran el camino sin confianza hasta una reinvitación;
  un acierto con el dispositivo no reinicia el contador del otro camino;
  peticiones simultáneas no consiguen intentos extra.
* Sesiones: Bearer obligatorio, revocación al cerrar, 15 minutos sin uso, 8
  horas en total, baja de la cuenta, empresa inactiva y token de otra empresa.
* Administración: un instructor recibe 403; una cuenta de otra empresa da el
  mismo 404 que una inexistente; email duplicado 409; la baja del último
  admin 409; el cambio de contraseña revoca las demás sesiones y
  dispositivos; la auditoría registra cada acción y su cadena es válida.
* Regla acceso del limitador con los límites de producción, y 503 sin Redis
  sin contar ningún intento.
* Ni contraseñas, ni tokens, ni secretos TOTP en los logs ni en el volcado de
  la base de datos.

Cada prueba negativa lleva su control positivo: si el control falla, el
resultado es SIN CONCLUSION, nunca PASA. Los oráculos son literales; el TOTP
de la batería es una implementación propia, comprobada antes con los
vectores del RFC 6238 (apéndice B).

Cómo se ejecuta (desde la raíz del repositorio, en PowerShell, con Docker en
marcha y los secretos generados con scripts/generar_secretos.py):

    python tests/security/verificar_personal.py

Usa un proyecto de Docker propio (canario_personal) y levanta postgres, redis,
api y caddy, más ejecuciones sueltas de gestion. Necesita que el proyecto
canario y las otras baterías estén parados (las subredes de app y edge son
fijas). Al terminar lo borra todo (down -v y las imágenes construidas).
Claves de cifrado y secretos de Redis FALSOS, generados en cada ejecución,
como en tests/security/verificar_denuncia.py; de secrets/ solo se usan las
contraseñas de los roles, sin leerlas.

La salida completa se guarda en verificacion_personal.txt dentro del
directorio temporal del sistema. El código de salida es 0 solo si el
resultado global es OK. Solo usa la biblioteca estándar.
"""
import base64
import hashlib
import hmac
import json
import pathlib
import re
import secrets
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import traceback
import uuid

RAIZ = pathlib.Path.cwd()
PROYECTO = "canario_personal"
SALIDA = pathlib.Path(tempfile.gettempdir()) / "verificacion_personal.txt"
BASE = ["docker", "compose", "-p", PROYECTO, "-f", "docker-compose.yml"]
BASE_PRODUCCION = []
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
LIMITES_PRUEBA = "denuncia=1000/3600,seguimiento=1000/60,mensajes=1000/3600,acceso=1000/300,otras=1000/60"
TEXTO_LIMITES_PRUEBA = ("LIMITES (configurados): acceso=1000/300 denuncia=1000/3600 mensajes=1000/3600 "
                        "otras=1000/60 seguimiento=1000/60")
TEXTO_LIMITES_PRODUCCION = ("LIMITES (por defecto): acceso=10/300 denuncia=10/3600 mensajes=30/3600 otras=60/60 "
                            "seguimiento=60/60")
LIMITE_ACCESO = (10, 300)
IP_CLIENTE_A = "10.88.1.3"
IP_CLIENTE_B = "10.88.1.4"

PATRON_ALTA = re.compile(r"empresa creada: empresa_id=([0-9a-f-]{36}) identificador_publico=([0-9a-f]{32})")
PATRON_INVITACION_GESTION = re.compile(r"invitacion creada: empresa_id=([0-9a-f-]{36}) usuario_id=([0-9a-f-]{36})\n"
                                       r"token_invitacion=([0-9a-f]{32}\.[A-Za-z0-9_-]{43})\n")
TEXTO_YA_HAY_ADMIN = "ERROR: la empresa ya tiene un admin activo: las cuentas las gestionan sus admins"
# Un token del personal: identificador de empresa, punto y 256 bits en base64url.
PATRON_TOKEN_COMPUESTO = r"[0-9a-f]{32}\.[A-Za-z0-9_-]{43}"
PATRON_TOKEN = r"[A-Za-z0-9_-]{43}"
PATRON_SECRETO_TOTP = r"[A-Z2-7]{32}"

# Respuestas, literales (app/rutas_personal.py y app/frontera_http.py).
CUERPO_401_CREDENCIALES = '{"detalle": "credenciales no válidas"}'.encode("utf-8")
CUERPO_401_SESION = '{"detalle": "sesión no válida"}'.encode("utf-8")
CUERPO_401_INVITACION = '{"detalle": "invitación no válida"}'.encode("utf-8")
CUERPO_422_CODIGO = '{"detalle": "código no válido"}'.encode("utf-8")
CUERPO_422_CORTA = '{"detalle": "la contraseña debe tener entre 12 y 128 caracteres"}'.encode("utf-8")
CUERPO_422_CONTIENE = '{"detalle": "la contraseña no puede contener el email ni el nombre de la empresa"}'.encode(
    "utf-8")
CUERPO_422 = '{"detalle": "petición no válida"}'.encode("utf-8")
CUERPO_403 = '{"detalle": "permiso denegado"}'.encode("utf-8")
CUERPO_404 = '{"detalle": "recurso no encontrado"}'.encode("utf-8")
CUERPO_409_DUPLICADO = '{"detalle": "ya existe una cuenta con ese email"}'.encode("utf-8")
CUERPO_409_ULTIMO = '{"detalle": "la empresa se quedaría sin ningún admin activo"}'.encode("utf-8")
CUERPO_429 = '{"detalle": "demasiadas peticiones; inténtelo de nuevo más tarde"}'.encode("utf-8")
CUERPO_503_OCUPADO = '{"detalle": "servicio ocupado; inténtelo de nuevo en unos segundos"}'.encode("utf-8")
REINTENTAR_TRAS = "5"
CLAVES_ACTIVACION = ["secreto_totp", "uri_totp"]
CLAVES_LOGIN = ["token_dispositivo", "token_sesion"]
CLAVES_YO = ["email", "rol", "usuario_id"]
CLAVES_USUARIO = ["activado", "activo", "camino_sin_confianza_cerrado", "email", "en_espera", "rol", "usuario_id"]

# Argon2id con los parámetros de OWASP (m=19 MiB, t=2, p=1).
PREFIJO_ARGON2 = "$argon2id$v=19$m=19456,t=2,p=1$"
# Formato 1 + nonce 12 + secreto 20 + tag 16.
TAMANO_SECRETO_CIFRADO = 49
# Huellas de los tokens: SHA-256(etiqueta || 32 bytes) (docs/threat-model.md, 6.3).
ETIQUETAS = {"invitacion": b"canario/invitacion/v1", "dispositivo": b"canario/dispositivo/v1",
             "sesion": b"canario/sesion/v1"}
# Bloqueo (app/personal.py): esperas tras el fallo n (n >= 5) de 2^(n-5)
# minutos con tope de 60; tope de 20 fallos por dispositivo y 100 sin confianza.
ESPERA_TRAS = {5: 1, 6: 2, 8: 8, 10: 32, 11: 60, 30: 60}
TOPE_DISPOSITIVO = 20
TOPE_SIN_CONFIANZA = 100
EVENTOS = {"espera_sin_confianza": "EVENTO espera_sin_confianza: ",
           "cierre_sin_confianza": "EVENTO cierre_sin_confianza: ",
           "espera_dispositivo": "EVENTO espera_dispositivo: ",
           "retirada_dispositivo": "EVENTO retirada_dispositivo: "}
ACCIONES_AUDITADAS = {"invitacion_admin_plataforma", "activacion", "acceso", "invitacion", "baja",
                      "cambio_contrasena"}

# RFC 6238, apéndice B (SHA-1, 8 dígitos, secreto ASCII "12345678901234567890").
RFC6238_SECRETO = b"12345678901234567890"
RFC6238_VECTORES = {59: "94287082", 1111111109: "07081804", 1111111111: "14050471", 1234567890: "89005924",
                    2000000000: "69279037", 20000000000: "65353130"}

# Cliente HTTP de prueba: corre con la imagen de la API, directo a la API (red
# app) o a través de Caddy (red edge, TLS). Mide cada petición en
# milisegundos y puede lanzar copias simultáneas de una petición.
CLIENTE_HTTP = r'''
import base64, concurrent.futures, http.client, json, socket, ssl, sys, time

def una(pt):
    conexion = None
    try:
        if pt.get("tls"):
            contexto = ssl.create_default_context()
            contexto.check_hostname = False
            contexto.verify_mode = ssl.CERT_NONE
            crudo = socket.create_connection((pt["host"], pt["puerto"]), timeout=30)
            conexion = http.client.HTTPConnection("localhost", pt["puerto"], timeout=30)
            conexion.sock = contexto.wrap_socket(crudo, server_hostname="localhost")
        else:
            conexion = http.client.HTTPConnection(pt["host"], pt["puerto"], timeout=30)
            conexion.connect()
        cuerpo = base64.b64decode(pt["cuerpo"]) if pt.get("cuerpo") is not None else None
        inicio = time.perf_counter()
        conexion.request(pt["metodo"], pt["ruta"], body=cuerpo, headers=pt.get("cabeceras", {}))
        respuesta = conexion.getresponse()
        datos = respuesta.read()
        ms = (time.perf_counter() - inicio) * 1000
        return {"estado": respuesta.status, "cuerpo": base64.b64encode(datos).decode("ascii"),
                "cabeceras": {k.lower(): v for k, v in respuesta.getheaders()}, "ms": ms}
    except Exception as error:
        return {"error": type(error).__name__}
    finally:
        if conexion is not None:
            conexion.close()

salida = []
for pt in json.load(sys.stdin):
    if pt.get("paralelo"):
        with concurrent.futures.ThreadPoolExecutor(pt["paralelo"]) as grupo:
            salida.extend(grupo.map(una, [pt] * pt["paralelo"]))
    else:
        salida.append(una(pt))
print(json.dumps(salida))
'''

# Se ejecuta dentro de la API, con el código real: TOTP frente a los vectores
# de RFC 6238 y la lectura estricta de tokens.
CRIPTO_DENTRO = f"""
import json
from app import cripto
s = {RFC6238_SECRETO!r}
res = {{"rfc6238": {{str(t): cripto.codigo_totp(s, t // 30, 8) for t in {sorted(RFC6238_VECTORES)}}}}}
texto, crudo = cripto.generar_token()
# El último de 43 caracteres lleva 2 bits de datos y 4 de relleno: invertir su
# bit más bajo solo toca relleno y da otra forma del MISMO token.
alfabeto = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
otro = texto[:-1] + alfabeto[alfabeto.index(texto[-1]) ^ 1]
res["mismos_bytes"] = __import__("base64").urlsafe_b64decode(otro + "=") == crudo
res["token_ida_vuelta"] = cripto.leer_token(texto) == crudo
res["token_no_canonico"] = cripto.leer_token(otro)
res["token_corto"] = cripto.leer_token(texto[:-1])
res["token_no_ascii"] = cripto.leer_token("\\u00e1" + texto[1:])
res["etiquetas_distintas"] = len({{cripto.huella_token(e, crudo) for e in
                                   (cripto.ETIQUETA_INVITACION, cripto.ETIQUETA_DISPOSITIVO, cripto.ETIQUETA_SESION)}})
print(json.dumps(res, sort_keys=True))
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
    # check=False explícito: el código de salida lo revisa cada prueba.
    r = subprocess.run(args, input=entrada, capture_output=True, timeout=timeout, check=False)
    return R(r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace"))


def dc(*args, entrada=None):
    return ejecutar(BASE + list(args), entrada=entrada)


def dc_produccion(*args):
    return ejecutar(BASE_PRODUCCION + list(args))


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


def salud(cid):
    return ejecutar(["docker", "inspect", "--format", "{{json .State.Health.Status}}", cid]).out.strip().strip('"')


def esperar(condicion, maximo):
    limite = time.monotonic() + maximo
    while time.monotonic() < limite:
        if condicion():
            return True
        time.sleep(1)
    return condicion()


def lineas_log(servicio):
    return dc("logs", "--no-color", "--no-log-prefix", servicio).todo.splitlines()


TEMPORAL = None
IMAGEN_API = ""
salidas_gestion = []


def texto_acl(aplicacion):
    hash_aplicacion = hashlib.sha256(CONTRASENAS_REDIS["aplicacion"].encode("ascii")).hexdigest()
    hash_inspector = hashlib.sha256(CONTRASENAS_REDIS["inspector"].encode("ascii")).hexdigest()
    return (f"user default off\nuser aplicacion on #{hash_aplicacion} {aplicacion}\n"
            f"user inspector on #{hash_inspector} {PERMISOS_ACL_INSPECTOR}\n")


def fichero_secreto(nombre, ruta):
    return [f"  {nombre}:", f"    file: \"{ruta.as_posix()}\""]


def preparar_secretos_falsos():
    """Claves de cifrado y secretos de Redis FALSOS, y los límites de prueba
    (como tests/security/verificar_denuncia.py). BASE_PRODUCCION queda sin
    los límites de prueba."""
    directorio = TEMPORAL / "secretos_compose"
    directorio.mkdir()
    lineas = ["secrets:"]
    for nombre in ("clave_maestra", "clave_hmac_codigos"):
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
    BASE_PRODUCCION.extend(BASE)
    limites = TEMPORAL / "limites_prueba.yml"
    limites.write_text(f"services:\n  api:\n    environment:\n      CANARIO_LIMITES: \"{LIMITES_PRUEBA}\"\n",
                       encoding="utf-8", newline="\n")
    BASE.extend(["-f", str(limites)])


def gestion(*args):
    r = dc("run", "--rm", "-T", "gestion", *args)
    salidas_gestion.append(r.out + r.err)
    return r


# ---------------------------------------------------------------------------
# HTTP y TOTP de la batería
# ---------------------------------------------------------------------------
def http(peticiones, red="app", ip=None):
    fija = ["--ip", ip] if ip else []
    r = ejecutar(["docker", "run", "--rm", "-i", "--network", f"{PROYECTO}_{red}", *fija, "--read-only",
                  "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                  "--entrypoint", "python", IMAGEN_API, "-c", CLIENTE_HTTP],
                 entrada=json.dumps(peticiones).encode("utf-8"))
    try:
        respuestas = json.loads(r.out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise Parada(f"el cliente HTTP no devolvio resultado: {r.err.strip()[-400:]!r}") from None
    for respuesta in respuestas:
        if "cuerpo" in respuesta:
            respuesta["cuerpo"] = base64.b64decode(respuesta["cuerpo"])
    return respuestas


def pt(metodo, ruta, datos=None, token=None, crudo=None, **extra):
    cabeceras = {"Content-Type": "application/json"}
    if token is not None:
        cabeceras["Authorization"] = f"Bearer {token}"
    if crudo is None and datos is not None:
        crudo = json.dumps(datos, ensure_ascii=False).encode("utf-8")
    peticion = {"host": "api", "puerto": 8000, "metodo": metodo, "ruta": ruta, "cabeceras": cabeceras, **extra}
    if crudo is not None:
        peticion["cuerpo"] = base64.b64encode(crudo).decode("ascii")
    return peticion


def por_caddy(peticion):
    return {**peticion, "host": "caddy", "puerto": 8443, "tls": True}


def json_de(respuesta):
    try:
        return json.loads(respuesta["cuerpo"].decode("utf-8"))
    except (KeyError, ValueError, UnicodeDecodeError):
        return None


def una(peticion):
    return http([peticion])[0]


def totp(secreto_texto, paso, digitos=6):
    """TOTP propio de la batería (RFC 6238 sobre RFC 4226), independiente de
    app/cripto.py; se comprueba con los vectores del RFC antes de usarlo."""
    clave = base64.b32decode(secreto_texto + "=" * (-len(secreto_texto) % 8)) \
        if isinstance(secreto_texto, str) else secreto_texto
    mac = hmac.new(clave, paso.to_bytes(8, "big"), hashlib.sha1).digest()
    o = mac[-1] & 0x0F
    return f"{(int.from_bytes(mac[o:o + 4], 'big') & 0x7FFFFFFF) % 10 ** digitos:0{digitos}d}"


# Último paso TOTP aceptado por secreto: un código solo vale una vez.
ULTIMO_PASO = {}


def codigo_libre(secreto):
    """(código, paso) del primer paso aceptable: posterior al último usado y
    dentro de la ventana de ±1. Si no lo hay, espera al paso siguiente."""
    while True:
        actual = int(time.time()) // 30
        paso = max(actual - 1, ULTIMO_PASO.get(secreto, -1) + 1)
        if paso <= actual + 1:
            return totp(secreto, paso), paso
        time.sleep(30 - time.time() % 30 + 0.5)


def codigo_erroneo(secreto):
    """Un código de 6 dígitos que no vale en ningún paso de la ventana."""
    actual = int(time.time()) // 30
    validos = {totp(secreto, actual + d) for d in (-2, -1, 0, 1, 2)}
    while True:
        codigo = f"{secrets.randbelow(10 ** 6):06d}"
        if codigo not in validos:
            return codigo


class Cuenta:
    def __init__(self, etiqueta, empresa, email):
        self.etiqueta, self.empresa, self.email = etiqueta, empresa, email
        self.contrasena = secrets.token_urlsafe(18)
        self.secreto = None
        self.dispositivo = None
        self.usuario_id = None
        self.invitacion = None


def login(cuenta, contrasena=None, codigo=None, dispositivo="propio", empresa=None, email=None):
    """Petición de login. dispositivo: "propio" (el de la cuenta), None (sin
    dispositivo) u otro texto."""
    if dispositivo == "propio":
        dispositivo = cuenta.dispositivo
    datos = {"empresa": empresa if empresa is not None else EMPRESAS[cuenta.empresa][1],
             "email": email if email is not None else cuenta.email,
             "contrasena": contrasena if contrasena is not None else cuenta.contrasena,
             "codigo_totp": codigo if codigo is not None else codigo_erroneo(cuenta.secreto or "A" * 32)}
    if dispositivo is not None:
        datos["token_dispositivo"] = dispositivo
    return pt("POST", "/v1/personal/sesiones", datos)


def login_correcto(cuenta, dispositivo="propio"):
    """Login con las credenciales buenas y un código libre. Devuelve la
    respuesta; si es 201, anota el paso usado."""
    codigo, paso = codigo_libre(cuenta.secreto)
    respuesta = una(login(cuenta, codigo=codigo, dispositivo=dispositivo))
    if respuesta.get("estado") == 201:
        ULTIMO_PASO[cuenta.secreto] = paso
    return respuesta


def fallo(cuenta, dispositivo="propio", veces=1):
    """Logins con la contraseña equivocada."""
    return http([login(cuenta, contrasena="equivocada-" + secrets.token_hex(6), dispositivo=dispositivo)] * veces)


def sesion_de(cuenta, dispositivo="propio"):
    respuesta = login_correcto(cuenta, dispositivo)
    datos = json_de(respuesta)
    if respuesta.get("estado") != 201 or not datos:
        raise Parada(f"no se pudo iniciar sesion con {cuenta.etiqueta}: {respuesta}")
    return datos["token_sesion"]


def yo(token):
    return pt("GET", "/v1/personal/yo", token=token)


def activar(cuenta):
    """Activa la cuenta con su invitación. Devuelve las dos respuestas."""
    r1 = una(pt("POST", "/v1/personal/activacion", {"token": cuenta.invitacion, "contrasena": cuenta.contrasena}))
    datos = json_de(r1) or {}
    cuenta.secreto = datos.get("secreto_totp")
    if r1.get("estado") != 200 or not cuenta.secreto:
        return r1, None
    codigo, paso = codigo_libre(cuenta.secreto)
    r2 = una(pt("POST", "/v1/personal/activacion/confirmar", {"token": cuenta.invitacion, "codigo_totp": codigo}))
    if r2.get("estado") == 200:
        ULTIMO_PASO[cuenta.secreto] = paso
        cuenta.dispositivo = (json_de(r2) or {}).get("token_dispositivo")
    return r1, r2


def usuario_de(cuenta):
    empresa_id = EMPRESAS[cuenta.empresa][0]
    return valor(f"select id from canal.usuario_personal where empresa_id = '{empresa_id}' "
                 f"and email = '{cuenta.email}';")


def contadores(cuenta):
    """(intentos, segundos de espera restantes) del camino sin confianza."""
    fila = valor(f"select intentos_fallidos || '|' || coalesce(round(extract(epoch from bloqueado_hasta - now()))::text, '') "
                 f"from canal.usuario_personal where id = '{cuenta.usuario_id}';")
    intentos, espera = fila.split("|")
    return int(intentos), (int(espera) if espera else None)


def contadores_dispositivo(cuenta):
    huella = hashlib.sha256(ETIQUETAS["dispositivo"] + leer_token(cuenta.dispositivo)).hexdigest()
    fila = valor(f"select intentos_fallidos || '|' || coalesce(round(extract(epoch from bloqueado_hasta - now()))::text, '') "
                 f"|| '|' || revocado from canal.dispositivo_personal where token_sha256 = '\\x{huella}';")
    intentos, espera, revocado = fila.split("|")
    # Concatenado con texto, el booleano sale como true/false.
    return int(intentos), (int(espera) if espera else None), revocado == "true"


def leer_token(texto):
    return base64.urlsafe_b64decode(texto + "=")


def poner_sin_confianza(cuenta, intentos, bloqueado="null"):
    valor(f"update canal.usuario_personal set intentos_fallidos = {intentos}, bloqueado_hasta = {bloqueado} "
          f"where id = '{cuenta.usuario_id}'; select 1;")


def poner_dispositivo(cuenta, intentos, bloqueado="null"):
    huella = hashlib.sha256(ETIQUETAS["dispositivo"] + leer_token(cuenta.dispositivo)).hexdigest()
    valor(f"update canal.dispositivo_personal set intentos_fallidos = {intentos}, bloqueado_hasta = {bloqueado} "
          f"where token_sha256 = '\\x{huella}'; select 1;")


def es_201_login(respuesta, con_dispositivo_nuevo):
    datos = json_de(respuesta)
    if respuesta.get("estado") != 201 or not isinstance(datos, dict) or sorted(datos) != CLAVES_LOGIN:
        return False
    sesion_ok = isinstance(datos["token_sesion"], str) and re.fullmatch(PATRON_TOKEN_COMPUESTO, datos["token_sesion"])
    nuevo = datos["token_dispositivo"]
    dispositivo_ok = (isinstance(nuevo, str) and re.fullmatch(PATRON_TOKEN, nuevo)) if con_dispositivo_nuevo \
        else nuevo is None
    return bool(sesion_ok and dispositivo_ok)


def es_401(respuesta, cuerpo=CUERPO_401_CREDENCIALES):
    return respuesta.get("estado") == 401 and respuesta.get("cuerpo") == cuerpo


# ---------------------------------------------------------------------------
# Secciones
# ---------------------------------------------------------------------------
EMPRESAS = {}
CUENTAS = {}


def seccion_a():
    global IMAGEN_API
    p("=== a) arranque y empresas")
    r = dc("up", "-d", "--build", "--wait")
    p(f"up -d --build --wait -> codigo {r.rc}")
    if r.rc != 0:
        p(r.todo.strip()[-2000:])
        raise Parada("no arranca el proyecto")
    registro = "\n".join(lineas_log("api"))
    pasa(TEXTO_VERIFICADO in registro and TEXTO_BLOQUEADO not in registro, "a) la API arranca verificada")
    pasa(TEXTO_LIMITES_PRUEBA in registro, f"a) las secciones funcionales usan los limites de prueba ({TEXTO_LIMITES_PRUEBA!r})")
    IMAGEN_API = json.loads(ejecutar(["docker", "inspect", contenedor("api")]).out)[0]["Config"]["Image"]
    for etiqueta, nombre in (("A", "Empresa Alfa S.L."), ("B", "Empresa Beta S.L.")):
        r = gestion("alta-empresa", "--nombre", nombre, "--zona", "Europe/Madrid")
        m = PATRON_ALTA.search(r.out)
        if r.rc != 0 or not m:
            raise Parada(f"alta-empresa {etiqueta} fallo: {r.todo.strip()[-300:]!r}")
        EMPRESAS[etiqueta] = (m.group(1), m.group(2))
    r = dc("exec", "-T", "api", "python", "-c", CRIPTO_DENTRO)
    try:
        res = json.loads(r.out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise Parada(f"no se pudo ejecutar la prueba de cripto dentro de la API: {r.err.strip()[-400:]!r}") from None
    pasa(res["rfc6238"] == {str(t): c for t, c in RFC6238_VECTORES.items()},
         "a) cripto.codigo_totp coincide con los 6 vectores de RFC 6238 (apendice B)")
    pasa(all(totp(RFC6238_SECRETO, t // 30, 8) == c for t, c in RFC6238_VECTORES.items()),
         "a) el TOTP propio de la bateria coincide con los vectores de RFC 6238 (oraculo comprobado)")
    pasa(res["token_ida_vuelta"] is True and res["etiquetas_distintas"] == 3,
         "a) control: un token se lee de vuelta y cada tipo de token tiene su huella")
    # Control: la forma no canónica decodifica de verdad a los mismos bytes,
    # así que solo la comprobación de forma canónica la rechaza.
    negativo("a) leer_token rechaza la forma no canonica del mismo token, la corta y la no ASCII",
             res["token_no_canonico"] is None and res["token_corto"] is None and res["token_no_ascii"] is None,
             res["mismos_bytes"] is True, f"{res}")


def seccion_b():
    p("=== b) primer admin por gestion")
    admin = Cuenta("admin_a", "A", "admin@alfa.test")
    r1 = gestion("alta-admin", "--identificador", EMPRESAS["A"][1], "--email", admin.email)
    m1 = PATRON_INVITACION_GESTION.search(r1.out)
    pasa(r1.rc == 0 and m1 is not None, f"b) alta-admin emite la invitacion del primer admin (codigo {r1.rc})")
    if not m1:
        raise Parada(f"alta-admin no devolvio la invitacion: {r1.todo.strip()[-300:]!r}")
    # Repetirlo antes de activar sustituye la invitación: la anterior deja de valer.
    r2 = gestion("alta-admin", "--identificador", EMPRESAS["A"][1], "--email", admin.email)
    m2 = PATRON_INVITACION_GESTION.search(r2.out)
    pasa(r2.rc == 0 and m2 is not None and m2.group(2) == m1.group(2) and m2.group(3) != m1.group(3),
         "b) repetir alta-admin antes de activar reutiliza la cuenta y emite otra invitacion")
    admin.invitacion = m2.group(3)
    vieja = una(pt("POST", "/v1/personal/activacion", {"token": m1.group(3), "contrasena": admin.contrasena}))
    r_act, r_conf = activar(admin)
    control = r_act.get("estado") == 200 and r_conf is not None and r_conf.get("estado") == 200
    pasa(control, "b) control: el admin activa su cuenta con la invitacion vigente")
    negativo("b) la invitacion sustituida da 401 'invitación no válida'", es_401(vieja, CUERPO_401_INVITACION),
             control, f"respuesta: {vieja}")
    if not control:
        raise Parada("el primer admin no se pudo activar")
    admin.usuario_id = usuario_de(admin)
    CUENTAS["admin_a"] = admin
    filas_antes = valor("select count(*) from canal.invitacion_personal;")
    r3 = gestion("alta-admin", "--identificador", EMPRESAS["A"][1], "--email", "intruso@alfa.test")
    negativo("b) con un admin activado, alta-admin se niega, sale con 1 y no crea nada",
             r3.rc == 1 and TEXTO_YA_HAY_ADMIN in r3.err
             and valor("select count(*) from canal.invitacion_personal;") == filas_antes
             and valor("select count(*) from canal.usuario_personal where email = 'intruso@alfa.test';") == "0",
             r1.rc == 0, f"salida: {r3.todo.strip()[-300:]!r}")
    filas = valor(f"select actor || '|' || accion || '|' || objeto_id from canal.registro_auditoria "
                  f"where empresa_id = '{EMPRESAS['A'][0]}' and actor = 'plataforma' order by secuencia;").split()
    pasa(filas == [f"plataforma|invitacion_admin_plataforma|{admin.usuario_id}"] * 2,
         f"b) cada invitacion de plataforma deja su fila en la auditoria de la empresa ({filas})")
    # Admin de B, para las pruebas entre empresas.
    admin_b = Cuenta("admin_b", "B", "admin@beta.test")
    r = gestion("alta-admin", "--identificador", EMPRESAS["B"][1], "--email", admin_b.email)
    m = PATRON_INVITACION_GESTION.search(r.out)
    if not m:
        raise Parada("alta-admin de B fallo")
    admin_b.invitacion = m.group(3)
    _, r_conf = activar(admin_b)
    if not r_conf or r_conf.get("estado") != 200:
        raise Parada("el admin de B no se pudo activar")
    admin_b.usuario_id = usuario_de(admin_b)
    CUENTAS["admin_b"] = admin_b


def invitar(admin_token, etiqueta, email, rol="instructor", empresa="A"):
    r = una(pt("POST", "/v1/personal/usuarios", {"email": email, "rol": rol}, token=admin_token))
    datos = json_de(r)
    if r.get("estado") != 201 or not datos:
        raise Parada(f"no se pudo invitar a {email}: {r}")
    cuenta = Cuenta(etiqueta, empresa, email)
    cuenta.invitacion = datos["token_invitacion"]
    cuenta.usuario_id = datos["usuario_id"]
    CUENTAS[etiqueta] = cuenta
    return cuenta, r


def seccion_c():
    p("=== c) invitacion y activacion por la API")
    admin = CUENTAS["admin_a"]
    token_admin = sesion_de(admin)
    instr, r = invitar(token_admin, "instructor", "instructor@alfa.test")
    pasa(sorted(json_de(r)) == ["token_invitacion", "usuario_id"]
         and re.fullmatch(PATRON_TOKEN_COMPUESTO, instr.invitacion) is not None
         and instr.invitacion.startswith(EMPRESAS["A"][1] + "."),
         "c) invitar devuelve 201 solo con usuario_id y un token <identificador>.<256 bits>")
    ruta = "/v1/personal/activacion"
    corta = una(pt("POST", ruta, {"token": instr.invitacion, "contrasena": "corta"}))
    con_email = una(pt("POST", ruta, {"token": instr.invitacion, "contrasena": "xx" + instr.email + "xx"}))
    con_empresa = una(pt("POST", ruta, {"token": instr.invitacion, "contrasena": "mi EMPRESA ALFA S.L. 2026"}))
    larga = una(pt("POST", ruta, {"token": instr.invitacion, "contrasena": "a" * 129}))
    # NFKC: 12 ligaduras "ﬀ" son 24 caracteres normalizados; 11 caracteres
    # que no cambian se quedan en 11.
    pasa(corta.get("estado") == 422 and corta.get("cuerpo") == CUERPO_422_CORTA
         and larga.get("cuerpo") == CUERPO_422_CORTA,
         "c) contrasena de menos de 12 o mas de 128 caracteres: 422 con el motivo")
    pasa(con_email.get("cuerpo") == CUERPO_422_CONTIENE and con_empresa.get("cuerpo") == CUERPO_422_CONTIENE,
         "c) contrasena con el email o el nombre de la empresa (sin distinguir mayusculas): 422 con el motivo")
    r_act, r_conf_malo = None, None
    r_act = una(pt("POST", ruta, {"token": instr.invitacion, "contrasena": instr.contrasena}))
    datos = json_de(r_act) or {}
    instr.secreto = datos.get("secreto_totp")
    control = r_act.get("estado") == 200 and sorted(datos) == CLAVES_ACTIVACION
    pasa(control and re.fullmatch(PATRON_SECRETO_TOTP, instr.secreto or "") is not None,
         "c) activar devuelve 200 con el secreto TOTP (160 bits en base32) y su URI")
    uri = (f"otpauth://totp/Canario:instructor@alfa.test?secret={instr.secreto}&issuer=Canario"
           f"&algorithm=SHA1&digits=6&period=30")
    pasa(datos.get("uri_totp") == uri, f"c) la URI otpauth es la literal esperada ({datos.get('uri_totp')!r})")
    pendiente = valor(f"select totp_activo || '|' || (hash_contrasena is null) from canal.usuario_personal "
                      f"where id = '{instr.usuario_id}';")
    # Un booleano concatenado con texto sale como true/false (no t/f).
    pasa(pendiente == "false|true", f"c) antes de confirmar la cuenta sigue sin credenciales ({pendiente})")
    malo = una(pt("POST", "/v1/personal/activacion/confirmar",
                  {"token": instr.invitacion, "codigo_totp": codigo_erroneo(instr.secreto)}))
    codigo, paso = codigo_libre(instr.secreto)
    bueno = una(pt("POST", "/v1/personal/activacion/confirmar", {"token": instr.invitacion, "codigo_totp": codigo}))
    control = bueno.get("estado") == 200 and re.fullmatch(PATRON_TOKEN, (json_de(bueno) or {}).get(
        "token_dispositivo", "")) is not None
    if control:
        ULTIMO_PASO[instr.secreto] = paso
        instr.dispositivo = json_de(bueno)["token_dispositivo"]
    pasa(control, "c) confirmar con el codigo correcto devuelve 200 con el primer token de dispositivo")
    negativo("c) confirmar con un codigo erroneo da 422 'código no válido' y no consume la invitacion",
             malo.get("estado") == 422 and malo.get("cuerpo") == CUERPO_422_CODIGO, control, f"respuesta: {malo}")
    repetida = [una(pt("POST", ruta, {"token": instr.invitacion, "contrasena": instr.contrasena})),
                una(pt("POST", "/v1/personal/activacion/confirmar", {"token": instr.invitacion, "codigo_totp": "000000"}))]
    negativo("c) la invitacion usada da 401 'invitación no válida' en los dos pasos",
             all(es_401(x, CUERPO_401_INVITACION) for x in repetida), control, f"respuestas: {repetida}")
    otra_empresa = EMPRESAS["B"][1] + instr.invitacion[32:]
    malformadas = [instr.invitacion[:-1], "x" * 76, otra_empresa, EMPRESAS["A"][1] + "." + "A" * 43,
                   "0" * 32 + instr.invitacion[32:]]
    respuestas = http([pt("POST", ruta, {"token": t, "contrasena": "una contrasena valida"}) for t in malformadas])
    negativo("c) token mal formado, aleatorio, de otra empresa o de empresa inexistente: el mismo 401 byte a byte",
             all(es_401(x, CUERPO_401_INVITACION) for x in respuestas), control,
             f"estados: {[x.get('estado') for x in respuestas]}")
    # Base de datos: Argon2id con los parámetros de OWASP, secreto cifrado y
    # solo la huella de cada token.
    fila = valor(f"select hash_contrasena || '|' || octet_length(secreto_totp_cifrado) || '|' || "
                 f"encode(secreto_totp_cifrado, 'hex') from canal.usuario_personal where id = '{instr.usuario_id}';")
    hash_guardado, longitud, cifrado_hex = fila.split("|")
    crudo_secreto = base64.b32decode(instr.secreto).hex()
    pasa(hash_guardado.startswith(PREFIJO_ARGON2), f"c) la contrasena se guarda con Argon2id {PREFIJO_ARGON2}")
    pasa(int(longitud) == TAMANO_SECRETO_CIFRADO and crudo_secreto not in cifrado_hex and cifrado_hex[:2] == "01",
         f"c) el secreto TOTP se guarda cifrado (formato 1, {TAMANO_SECRETO_CIFRADO} bytes) y no en claro")
    huella = hashlib.sha256(ETIQUETAS["invitacion"] + leer_token(instr.invitacion.split(".")[1])).hexdigest()
    pasa(valor(f"select count(*) from canal.invitacion_personal where token_sha256 = '\\x{huella}' and cerrada;") == "1",
         "c) la invitacion se guarda como SHA-256(etiqueta || token) y queda cerrada")
    # Caducidad: control, una invitación nueva vale; la misma, caducada, no.
    caducar, _ = invitar(token_admin, "caducada", "caducada@alfa.test")
    huella = hashlib.sha256(ETIQUETAS["invitacion"] + leer_token(caducar.invitacion.split(".")[1])).hexdigest()
    control_cad = una(pt("POST", ruta, {"token": caducar.invitacion, "contrasena": caducar.contrasena})).get("estado")
    valor(f"update canal.invitacion_personal set caduca = now() - interval '1 second' "
          f"where token_sha256 = '\\x{huella}'; select 1;")
    caducada = una(pt("POST", ruta, {"token": caducar.invitacion, "contrasena": caducar.contrasena}))
    negativo("c) una invitacion caducada da 401 'invitación no válida'", es_401(caducada, CUERPO_401_INVITACION),
             control_cad == 200, f"respuesta: {caducada}")
    CUENTAS["token_admin_a"] = token_admin


def seccion_d():
    p("=== d) login: respuesta uniforme, tiempos y un solo uso del codigo")
    admin = CUENTAS["admin_a"]
    token_admin = CUENTAS["token_admin_a"]
    instr = CUENTAS["instructor"]
    control = login_correcto(instr)
    pasa(es_201_login(control, con_dispositivo_nuevo=False),
         "d) control: con su dispositivo, 201 con el token de sesion y sin dispositivo nuevo")
    sin = login_correcto(instr, dispositivo=None)
    pasa(es_201_login(sin, con_dispositivo_nuevo=True),
         "d) sin dispositivo de confianza, 201 con un dispositivo nuevo")
    pendiente, _ = invitar(token_admin, "pendiente", "pendiente@alfa.test")
    baja, _ = invitar(token_admin, "de_baja", "debaja@alfa.test")
    activar(baja)
    una(pt("POST", f"/v1/personal/usuarios/{baja.usuario_id}/baja", token=token_admin))
    codigo, _ = codigo_libre(instr.secreto)
    casos = {
        "empresa inexistente": login(instr, codigo=codigo, empresa="0123456789abcdef0123456789abcdef"),
        "empresa mal formada": login(instr, codigo=codigo, empresa="../" + "x" * 10),
        "empresa de otra cuenta (B)": login(instr, codigo=codigo, empresa=EMPRESAS["B"][1]),
        "email inexistente": login(instr, codigo=codigo, email="nadie@alfa.test"),
        "contrasena erronea": login(instr, contrasena="no es la buena 123", codigo=codigo),
        "codigo erroneo": login(instr),
        "codigo mal formado": login(instr, codigo="12a456"),
        "cuenta sin activar": login(pendiente, contrasena=pendiente.contrasena, dispositivo=None),
        "cuenta dada de baja": login(baja, codigo=codigo_libre(baja.secreto)[0]),
    }
    respuestas = dict(zip(casos, http(list(casos.values()))))
    distintos = {k: (v.get("estado"), v.get("cuerpo")) for k, v in respuestas.items() if not es_401(v)}
    pasa(not distintos, f"d) los 9 fallos responden el mismo 401 'credenciales no válidas' byte a byte {distintos or ''}")
    # El instructor solo ha fallado por el camino de su dispositivo: los
    # fallos cuentan ahí.
    poner_dispositivo(instr, 0)

    # Un código solo vale una vez: el mismo código, en dos logins seguidos.
    codigo, paso = codigo_libre(instr.secreto)
    primero, segundo = http([login(instr, codigo=codigo), login(instr, codigo=codigo)])
    if primero.get("estado") == 201:
        ULTIMO_PASO[instr.secreto] = paso
    negativo("d) el mismo codigo TOTP no vale dos veces (401 la segunda)", es_401(segundo),
             es_201_login(primero, False), f"respuestas: {primero.get('estado')}, {segundo.get('estado')}")
    poner_dispositivo(instr, 0)

    # Tiempos: email inexistente frente a cuenta real con la contraseña
    # equivocada y frente a cuenta en espera. Muestras intercaladas; los
    # contadores se reinician entre tandas para medir siempre la verificación
    # real. Control de sensibilidad: un 422 (sin Argon2) se distingue.
    tiempos = cuenta_tiempos(token_admin)
    muestras = {"inexistente": [], "erronea": [], "en_espera": [], "sin_hash": []}
    for _ in range(10):
        poner_sin_confianza(tiempos, 0)
        tanda = []
        for _ in range(4):
            tanda += [login(tiempos, email="nadie@alfa.test", dispositivo=None),
                      login(tiempos, dispositivo=None),
                      pt("POST", "/v1/personal/sesiones", {"empresa": EMPRESAS["A"][1]})]
        res = http(tanda)
        for i, nombre in enumerate(["inexistente", "erronea", "sin_hash"] * 4):
            if "ms" in res[i]:
                muestras[nombre].append(res[i]["ms"])
    poner_sin_confianza(tiempos, 10, "now() + interval '1 hour'")
    tanda = []
    for _ in range(40):
        tanda += [login(tiempos, email="nadie@alfa.test", dispositivo=None), login(tiempos, dispositivo=None)]
    res = http(tanda)
    en_espera_inexistente = [x["ms"] for x in res[0::2] if "ms" in x]
    muestras["en_espera"] = [x["ms"] for x in res[1::2] if "ms" in x]
    mediana = {k: statistics.median(v) for k, v in muestras.items() if v}
    mediana["inexistente_2"] = statistics.median(en_espera_inexistente)
    p("   medianas en ms: " + ", ".join(f"{k}={v:.1f}" for k, v in mediana.items()))
    control = mediana["inexistente"] - mediana["sin_hash"] >= 8
    negativo("d) tiempos: email inexistente y contrasena erronea de una cuenta real difieren menos de 3 ms",
             abs(mediana["inexistente"] - mediana["erronea"]) < 3, control,
             f"control: Argon2 no se distingue de un 422 ({mediana})")
    negativo("d) tiempos: email inexistente y cuenta en espera difieren menos de 3 ms",
             abs(mediana["inexistente_2"] - mediana["en_espera"]) < 3, control, f"{mediana}")
    poner_sin_confianza(tiempos, 0)


def cuenta_tiempos(token_admin):
    if "tiempos" not in CUENTAS:
        cuenta, _ = invitar(token_admin, "tiempos", "tiempos@alfa.test")
        activar(cuenta)
    return CUENTAS["tiempos"]


def seccion_e():
    p("=== e) bloqueo sin denegacion de servicio")
    token_admin = CUENTAS["token_admin_a"]
    victima, _ = invitar(token_admin, "victima", "victima@alfa.test")
    activar(victima)
    control = login_correcto(victima, dispositivo=None)
    pasa(es_201_login(control, True), "e) control: la victima entra sin dispositivo de confianza")
    # e1) Cinco fallos sin dispositivo bloquean ese camino 1 minuto.
    fallo(victima, dispositivo=None, veces=5)
    intentos, espera = contadores(victima)
    pasa(intentos == 5 and espera is not None and 50 <= espera <= 60,
         f"e1) 5 fallos sin dispositivo: intentos 5 y espera de 1 minuto ({intentos}, {espera} s)")
    sin = login_correcto(victima, dispositivo=None)
    con = login_correcto(victima)
    negativo("e1) con el camino sin confianza en espera, el titular ENTRA con su dispositivo (201)",
             es_201_login(con, False), es_401(sin), f"sin dispositivo: {sin.get('estado')}, con: {con}")
    negativo("e1) con el camino en espera, las credenciales buenas sin dispositivo dan 401 (no se verifican)",
             es_401(sin), es_201_login(con, False))
    pasa(contadores(victima)[0] == 5,
         "e1) ni el login en espera ni el acierto con el dispositivo cambian el contador sin confianza")
    eventos = "\n".join(lineas_log("api"))
    pasa(EVENTOS["espera_sin_confianza"] in eventos, "e1) el bloqueo deja EVENTO espera_sin_confianza en el log")
    # e2) Esperas crecientes con tope de 60 minutos.
    observadas = {}
    for n in sorted(ESPERA_TRAS):
        poner_sin_confianza(victima, n - 1)
        fallo(victima, dispositivo=None)
        observadas[n] = contadores(victima)
    pasa(all(o[0] == n and o[1] is not None and ESPERA_TRAS[n] * 60 - 10 <= o[1] <= ESPERA_TRAS[n] * 60
             for n, o in observadas.items()),
         f"e2) espera tras el fallo n: 2^(n-5) minutos con tope de 60 ({observadas})")
    # e3) Al acabar la espera, un acierto sin dispositivo entra y pone el contador a cero.
    poner_sin_confianza(victima, 7, "now() - interval '1 second'")
    r = login_correcto(victima, dispositivo=None)
    pasa(es_201_login(r, True) and contadores(victima) == (0, None),
         f"e3) terminada la espera, un acierto sin dispositivo entra y reinicia el contador ({contadores(victima)})")
    # e4) Un acierto con el dispositivo NO reinicia el contador del otro camino.
    fallo(victima, dispositivo=None, veces=3)
    r = login_correcto(victima)
    negativo("e4) tres fallos sin dispositivo y un acierto con el: el contador sin confianza sigue en 3",
             contadores(victima)[0] == 3, es_201_login(r, False), f"{contadores(victima)}")
    # e5) Un fallo de TOTP con la contraseña buena cuenta igual.
    poner_sin_confianza(victima, 0)
    una(login(victima, dispositivo=None))
    pasa(contadores(victima)[0] == 1, "e5) contrasena buena y codigo erroneo cuentan como fallo")
    # e6) 100 fallos cierran el camino sin confianza; el dispositivo sigue.
    poner_sin_confianza(victima, TOPE_SIN_CONFIANZA - 1)
    fallo(victima, dispositivo=None)
    poner_sin_confianza(victima, TOPE_SIN_CONFIANZA)
    cerrado = login_correcto(victima, dispositivo=None)
    con = login_correcto(victima)
    negativo("e6) con 100 fallos, el camino sin confianza queda cerrado aunque no haya espera (401)",
             es_401(cerrado), es_201_login(con, False), f"{cerrado.get('estado')}")
    negativo("e6) con el camino cerrado, el titular entra con su dispositivo (201)", es_201_login(con, False),
             es_401(cerrado))
    pasa(EVENTOS["cierre_sin_confianza"] in "\n".join(lineas_log("api")),
         "e6) el cierre deja EVENTO cierre_sin_confianza en el log")
    lista = json_de(una(pt("GET", "/v1/personal/usuarios", token=token_admin))) or {}
    fila = next((u for u in lista.get("usuarios", []) if u.get("email") == victima.email), {})
    pasa(fila.get("camino_sin_confianza_cerrado") is True and sorted(fila) == CLAVES_USUARIO,
         "e6) el admin ve el camino cerrado en la lista de cuentas (sin hashes ni contadores)")
    # e7) La reinvitación lo reabre.
    r = una(pt("POST", f"/v1/personal/usuarios/{victima.usuario_id}/invitacion", token=token_admin))
    victima.invitacion = (json_de(r) or {}).get("token_invitacion")
    activar(victima)
    r = login_correcto(victima, dispositivo=None)
    pasa(es_201_login(r, True) and contadores(victima)[0] == 0,
         "e7) tras reinvitar y activar, el camino sin confianza vuelve a funcionar desde cero")
    # e8) Fallos con el dispositivo: bloquean solo el dispositivo; un acierto
    # con él va entonces por el camino sin confianza (dispositivo nuevo).
    fallo(victima, veces=5)
    intentos, espera, _ = contadores_dispositivo(victima)
    pasa(intentos == 5 and espera is not None and 50 <= espera <= 60 and contadores(victima)[0] == 0,
         f"e8) 5 fallos con el dispositivo: cuentan en el dispositivo ({intentos}, {espera} s) y no en la cuenta")
    r = login_correcto(victima)
    pasa(es_201_login(r, True), "e8) con el dispositivo en espera, un acierto entra por el camino sin confianza "
                                "y recibe un dispositivo nuevo")
    pasa(EVENTOS["espera_dispositivo"] in "\n".join(lineas_log("api")), "e8) EVENTO espera_dispositivo en el log")
    # e9) 20 fallos retiran el dispositivo.
    poner_dispositivo(victima, TOPE_DISPOSITIVO - 1)
    fallo(victima)
    poner_sin_confianza(victima, 0)
    r = login_correcto(victima)
    pasa(contadores_dispositivo(victima)[0] == TOPE_DISPOSITIVO and es_201_login(r, True),
         "e9) con 20 fallos el dispositivo deja de ser de confianza (el acierto va por el otro camino)")
    pasa(EVENTOS["retirada_dispositivo"] in "\n".join(lineas_log("api")), "e9) EVENTO retirada_dispositivo en el log")
    victima.dispositivo = (json_de(r) or {}).get("token_dispositivo")
    # e10) El dispositivo de otra cuenta no da confianza ni cuenta en él.
    instr = CUENTAS["instructor"]
    antes = contadores_dispositivo(instr)[0]
    poner_sin_confianza(victima, 0)
    r = login_correcto(victima, dispositivo=instr.dispositivo)
    pasa(es_201_login(r, True) and contadores_dispositivo(instr)[0] == antes,
         "e10) con el dispositivo de otra cuenta, el login va por el camino sin confianza y no toca ese dispositivo")
    victima.dispositivo = (json_de(r) or {}).get("token_dispositivo")
    # e11) Peticiones simultáneas no consiguen intentos extra: 15 fallos a
    # la vez, solo 5 se verifican.
    poner_sin_confianza(victima, 0)
    paralelo = login(victima, contrasena="equivocada simultanea", dispositivo=None)
    respuestas = http([{**paralelo, "paralelo": 15}])
    pasa(all(es_401(x) for x in respuestas) and contadores(victima)[0] == 5,
         f"e11) 15 fallos simultaneos: todos 401 y el contador queda exactamente en 5 ({contadores(victima)[0]})")
    poner_sin_confianza(victima, 0)


def seccion_f():
    p("=== f) sesiones")
    instr = CUENTAS["instructor"]
    token = sesion_de(instr)
    control = una(yo(token))
    datos = json_de(control) or {}
    pasa(control.get("estado") == 200 and sorted(datos) == CLAVES_YO and datos.get("email") == instr.email
         and datos.get("rol") == "instructor", "f) control: /yo con el token Bearer responde la cuenta")
    identificador, secreto_token = token.split(".")
    malos = {
        "sin cabecera": pt("GET", "/v1/personal/yo"),
        "esquema Basic": {**yo(token), "cabeceras": {"Authorization": f"Basic {token}"}},
        "token mal formado": yo(token[:-1]),
        "token aleatorio": yo(f"{identificador}.{'A' * 43}"),
        "token con el identificador de B": yo(f"{EMPRESAS['B'][1]}.{secreto_token}"),
        "token de dispositivo como sesion": yo(f"{identificador}.{instr.dispositivo}"),
    }
    respuestas = dict(zip(malos, http(list(malos.values()))))
    distintos = {k: v.get("estado") for k, v in respuestas.items()
                 if not (es_401(v, CUERPO_401_SESION) and v.get("cabeceras", {}).get("www-authenticate") == "Bearer")}
    negativo(f"f) sin sesion valida: 401 'sesión no válida' con WWW-Authenticate: Bearer {distintos or ''}".strip(),
             not distintos, control.get("estado") == 200)
    huella = hashlib.sha256(ETIQUETAS["sesion"] + leer_token(secreto_token)).hexdigest()
    pasa(valor(f"select count(*) from canal.sesion_personal where token_sha256 = '\\x{huella}';") == "1",
         "f) la sesion se guarda como SHA-256(etiqueta || token)")

    def sesion_sql(cambio):
        valor(f"update canal.sesion_personal set {cambio} where token_sha256 = '\\x{huella}'; select 1;")
    sesion_sql("ultimo_uso = now() - interval '14 minutes'")
    casi = una(yo(token)).get("estado")
    sesion_sql("ultimo_uso = now() - interval '16 minutes'")
    inactiva = una(yo(token))
    negativo("f) 16 minutos sin uso: 401 (control: con 14 minutos responde 200 y renueva)",
             es_401(inactiva, CUERPO_401_SESION), casi == 200)
    sesion_sql("ultimo_uso = now()")
    sesion_sql("caduca = now() - interval '1 second'")
    caducada = una(yo(token))
    negativo("f) pasadas las 8 horas: 401 aunque se haya usado", es_401(caducada, CUERPO_401_SESION), casi == 200)
    token = sesion_de(instr)
    antes = una(yo(token)).get("estado")
    cierre = una(pt("DELETE", "/v1/personal/sesiones/actual", token=token))
    despues = una(yo(token))
    negativo("f) tras cerrar la sesion (204), el token da 401", cierre.get("estado") == 204
             and es_401(despues, CUERPO_401_SESION), antes == 200)
    token = sesion_de(instr)
    valor(f"update canal.empresa set activa = false where id = '{EMPRESAS['A'][0]}'; select 1;")
    inactiva = una(yo(token))
    valor(f"update canal.empresa set activa = true where id = '{EMPRESAS['A'][0]}'; select 1;")
    vuelta = una(yo(token)).get("estado")
    negativo("f) con la empresa inactiva, sus sesiones dan 401 (control: al reactivarla, 200)",
             es_401(inactiva, CUERPO_401_SESION), vuelta == 200)


def seccion_g():
    p("=== g) administracion de cuentas y auditoria")
    admin, admin_b = CUENTAS["admin_a"], CUENTAS["admin_b"]
    token_admin = sesion_de(admin)
    token_b = sesion_de(admin_b)
    instr = CUENTAS["instructor"]
    token_instr = sesion_de(instr)
    ctl_lista = una(pt("GET", "/v1/personal/usuarios", token=token_admin))
    prohibidas = http([pt("GET", "/v1/personal/usuarios", token=token_instr),
                       pt("POST", "/v1/personal/usuarios", {"email": "x@alfa.test", "rol": "admin"}, token=token_instr),
                       pt("POST", f"/v1/personal/usuarios/{admin.usuario_id}/invitacion", token=token_instr),
                       pt("POST", f"/v1/personal/usuarios/{admin.usuario_id}/baja", token=token_instr)])
    negativo("g) un instructor recibe 403 en las 4 rutas de administracion",
             all(x.get("estado") == 403 and x.get("cuerpo") == CUERPO_403 for x in prohibidas),
             ctl_lista.get("estado") == 200, f"estados: {[x.get('estado') for x in prohibidas]}")
    pasa(valor("select count(*) from canal.usuario_personal where email = 'x@alfa.test';") == "0",
         "g) el instructor no ha creado ninguna cuenta")
    ajeno = admin_b.usuario_id
    control = una(pt("POST", f"/v1/personal/usuarios/{instr.usuario_id}/invitacion", token=token_admin))
    instr_inv = (json_de(control) or {}).get("token_invitacion")
    respuestas = http([pt("POST", f"/v1/personal/usuarios/{ajeno}/invitacion", token=token_admin),
                       pt("POST", f"/v1/personal/usuarios/{ajeno}/baja", token=token_admin),
                       pt("POST", f"/v1/personal/usuarios/{uuid.uuid4()}/baja", token=token_admin),
                       pt("POST", "/v1/personal/usuarios/no-es-un-uuid/baja", token=token_admin)])
    negativo("g) una cuenta de otra empresa, una inexistente y un id mal formado dan el mismo 404",
             all(x.get("estado") == 404 and x.get("cuerpo") == CUERPO_404 for x in respuestas),
             control.get("estado") == 201, f"estados: {[x.get('estado') for x in respuestas]}")
    pasa(una(yo(token_b)).get("estado") == 200 and
         valor(f"select activo from canal.usuario_personal where id = '{ajeno}';") == "t",
         "g) el admin de B sigue activo y con sesion")
    # La reinvitación del control no cambia la cuenta hasta confirmarse.
    pasa(una(yo(token_instr)).get("estado") == 200, "g) reinvitar no desactiva la cuenta ni sus sesiones")
    valor(f"update canal.invitacion_personal set cerrada = true where cerrada = false "
          f"and usuario_id = '{instr.usuario_id}'; select 1;")
    del instr_inv
    duplicado = una(pt("POST", "/v1/personal/usuarios", {"email": instr.email, "rol": "instructor"}, token=token_admin))
    mayusculas = una(pt("POST", "/v1/personal/usuarios", {"email": instr.email.upper(), "rol": "admin"},
                        token=token_admin))
    invalidos = http([pt("POST", "/v1/personal/usuarios", {"email": e, "rol": "instructor"}, token=token_admin)
                      for e in ("sin-arroba", "@alfa.test", "con espacio@alfa.test", "ñ@alfa.test")]
                     + [pt("POST", "/v1/personal/usuarios", {"email": "rol@alfa.test", "rol": "superadmin"},
                           token=token_admin)])
    pasa(duplicado.get("estado") == 409 and duplicado.get("cuerpo") == CUERPO_409_DUPLICADO
         and mayusculas.get("cuerpo") == CUERPO_409_DUPLICADO,
         "g) un email ya usado en la empresa (tambien en mayusculas) da 409")
    pasa(all(x.get("estado") == 422 and x.get("cuerpo") == CUERPO_422 for x in invalidos),
         "g) emails mal formados o no ASCII y un rol desconocido dan 422 sin eco")
    # La baja del último admin activado se rechaza; con otro admin, se acepta.
    ultimo = una(pt("POST", f"/v1/personal/usuarios/{admin.usuario_id}/baja", token=token_admin))
    pasa(ultimo.get("estado") == 409 and ultimo.get("cuerpo") == CUERPO_409_ULTIMO,
         "g) la baja del unico admin activado da 409")
    admin2, _ = invitar(token_admin, "admin2", "admin2@alfa.test", rol="admin")
    activar(admin2)
    token_admin2 = sesion_de(admin2)
    baja = una(pt("POST", f"/v1/personal/usuarios/{admin.usuario_id}/baja", token=token_admin2))
    tras = http([yo(token_admin), login(admin, codigo=codigo_libre(admin.secreto)[0])])
    negativo("g) con otro admin activado, la baja se acepta (204), revoca sus sesiones y el login da 401",
             es_401(tras[0], CUERPO_401_SESION) and es_401(tras[1]), baja.get("estado") == 204,
             f"baja: {baja.get('estado')}, tras: {[x.get('estado') for x in tras]}")
    # Reactivar = reinvitar y activar.
    r = una(pt("POST", f"/v1/personal/usuarios/{admin.usuario_id}/invitacion", token=token_admin2))
    admin.invitacion = (json_de(r) or {}).get("token_invitacion")
    activar(admin)
    pasa(es_201_login(login_correcto(admin), False),
         "g) tras reinvitar y activar, la cuenta dada de baja vuelve a entrar con su dispositivo nuevo")
    # Cambio de contraseña.
    token_instr = sesion_de(instr)
    otra_sesion = sesion_de(instr, dispositivo=None)
    # login_correcto anota el paso TOTP usado: el cambio de contraseña
    # necesita uno posterior.
    otro_dispositivo = json_de(login_correcto(instr, dispositivo=None)) or {}
    ruta = "/v1/personal/contrasena"
    nueva = secrets.token_urlsafe(18)
    poner_dispositivo(instr, 0)
    debil = una(pt("POST", ruta, {"contrasena_actual": instr.contrasena, "contrasena_nueva": "corta",
                                  "codigo_totp": codigo_libre(instr.secreto)[0]}, token=token_instr))
    pasa(debil.get("cuerpo") == CUERPO_422_CORTA and contadores_dispositivo(instr)[0] == 0,
         "g) una contrasena nueva debil da 422 sin gastar un intento")
    mala = una(pt("POST", ruta, {"contrasena_actual": "no es la actual 1", "contrasena_nueva": nueva,
                                 "codigo_totp": codigo_libre(instr.secreto)[0]}, token=token_instr))
    pasa(es_401(mala) and contadores_dispositivo(instr)[0] == 1,
         "g) con la contrasena actual equivocada: 401 y el fallo cuenta en el dispositivo de la sesion")
    codigo, paso = codigo_libre(instr.secreto)
    cambio = una(pt("POST", ruta, {"contrasena_actual": instr.contrasena, "contrasena_nueva": nueva,
                                   "codigo_totp": codigo}, token=token_instr))
    if cambio.get("estado") == 204:
        ULTIMO_PASO[instr.secreto] = paso
    vieja = instr.contrasena
    instr.contrasena = nueva
    tras = http([yo(token_instr), yo(otra_sesion),
                 login(instr, contrasena=vieja, codigo=codigo_libre(instr.secreto)[0])])
    negativo("g) cambio de contrasena (204): la sesion actual sigue, la otra se revoca y la contrasena vieja da 401",
             tras[0].get("estado") == 200 and es_401(tras[1], CUERPO_401_SESION) and es_401(tras[2]),
             cambio.get("estado") == 204, f"cambio: {cambio.get('estado')}, tras: {[x.get('estado') for x in tras]}")
    dispositivo_viejo = otro_dispositivo.get("token_dispositivo")
    if dispositivo_viejo:
        huella = hashlib.sha256(ETIQUETAS["dispositivo"] + leer_token(dispositivo_viejo)).hexdigest()
        pasa(valor(f"select revocado from canal.dispositivo_personal where token_sha256 = '\\x{huella}';") == "t",
             "g) el cambio de contrasena revoca los demas dispositivos de la cuenta")
    pasa(es_201_login(login_correcto(instr), False), "g) la contrasena nueva entra con el dispositivo de la sesion")
    # Auditoría: cada acción con su actor, y la cadena es válida.
    filas = valor(f"select distinct accion from canal.registro_auditoria where empresa_id = '{EMPRESAS['A'][0]}';").split()
    pasa(ACCIONES_AUDITADAS <= set(filas), f"g) la auditoria registra {sorted(ACCIONES_AUDITADAS)} ({sorted(filas)})")
    actores = valor(f"select count(*) from canal.registro_auditoria where empresa_id = '{EMPRESAS['A'][0]}' "
                    f"and actor !~ '^(plataforma|personal:[0-9a-f-]{{36}})$';")
    pasa(actores == "0", "g) cada fila de auditoria del personal tiene como actor plataforma o personal:<uuid>")
    cadena = valor(f"begin; set local role aplicacion; select set_config('app.empresa_id', '{EMPRESAS['A'][0]}', true); "
                   f"select coalesce(canal.verificar_cadena_auditoria()::text, 'intacta'); commit;").split()[-1]
    pasa(cadena == "intacta", f"g) la cadena de auditoria de la empresa sigue intacta ({cadena})")
    CUENTAS["token_admin_a"] = token_admin2


def seccion_h():
    p("=== h) regla acceso del limitador (limites de produccion)")
    r = dc_produccion("up", "-d", "--wait", "api")
    if r.rc != 0:
        raise Parada(f"no arranca la API con los limites de produccion: {r.todo.strip()[-500:]}")
    pasa(TEXTO_LIMITES_PRODUCCION in "\n".join(lineas_log("api")),
         f"h) la API arranca con los limites de produccion ({TEXTO_LIMITES_PRODUCCION!r})")
    maximo, ventana = LIMITE_ACCESO
    resto = ventana - int(time.time()) % ventana
    if resto < 60:
        p(f"   espera de {resto + 3} s a la ventana siguiente")
        time.sleep(resto + 3)
    victima = CUENTAS["victima"]
    poner_sin_confianza(victima, 0)
    peticion = por_caddy(login(victima, contrasena="rafaga equivocada", dispositivo=None,
                               empresa="0123456789abcdef0123456789abcdef"))
    respuestas = http([peticion] * (maximo + 1), red="edge", ip=IP_CLIENTE_A)
    control = all(es_401(x) for x in respuestas[:-1])
    pasa(control, f"h) las {maximo} primeras peticiones de login del cliente A responden 401")
    ultima = respuestas[-1]
    tras = ultima.get("cabeceras", {}).get("retry-after", "")
    negativo(f"h) la peticion {maximo + 1} es 429 con Retry-After entre 1 y {ventana}",
             ultima.get("estado") == 429 and ultima.get("cuerpo") == CUERPO_429 and tras.isdigit()
             and 1 <= int(tras) <= ventana, control, f"respuesta: {ultima}")
    otro = http([peticion], red="edge", ip=IP_CLIENTE_B)[0]
    negativo("h) el cliente B no comparte el contador de A", es_401(otro), control)
    # Sin Redis: 503 sin llegar a contar ningún intento en la base de datos.
    antes = contadores(victima)[0]
    dc("stop", "redis")
    try:
        sin_redis = http([por_caddy(login(victima, contrasena="sin redis", dispositivo=None)),
                          por_caddy(pt("GET", "/salud"))], red="edge", ip=IP_CLIENTE_B)
    finally:
        dc("start", "redis")
    negativo("h) con Redis parado, el login da 503 con Retry-After 5 y no cuenta ningun intento",
             sin_redis[0].get("estado") == 503 and sin_redis[0].get("cuerpo") == CUERPO_503_OCUPADO
             and sin_redis[0].get("cabeceras", {}).get("retry-after") == REINTENTAR_TRAS
             and contadores(victima)[0] == antes, sin_redis[1].get("estado") == 200, f"{sin_redis}")
    esperar(lambda: salud(contenedor("redis")) == "healthy", 60)


def seccion_i():
    p("=== i) nada sensible en logs ni en el volcado")
    sensibles = {}
    for cuenta in CUENTAS.values():
        if not isinstance(cuenta, Cuenta):
            continue
        for nombre, v in (("contrasena", cuenta.contrasena), ("secreto_totp", cuenta.secreto),
                          ("dispositivo", cuenta.dispositivo), ("invitacion", cuenta.invitacion)):
            if v:
                sensibles[f"{nombre} de {cuenta.etiqueta}"] = v
        if cuenta.secreto:
            sensibles[f"secreto_hex de {cuenta.etiqueta}"] = base64.b32decode(cuenta.secreto).hex()
    textos = {s: dc("logs", "--no-color", "--no-log-prefix", s).todo for s in ("api", "postgres", "caddy", "redis")}
    volcado = dc("exec", "-T", "postgres", "pg_dump", "-U", "postgres", "-d", "canario", "--data-only",
                 "-n", "canal").out
    control = "usuario_personal" in volcado and "$argon2id$" in volcado and len(sensibles) > 10
    fugas = sorted({f"{n} en {s}" for s, t in {**textos, "volcado": volcado}.items()
                    for n, v in sensibles.items() if v in t})
    negativo(f"i) ni contrasenas, ni secretos TOTP, ni tokens aparecen en los logs ni en el volcado "
             f"({len(sensibles)} valores) {fugas if fugas else ''}".strip(), not fugas, control)
    ips = [s for s, t in textos.items() if IP_CLIENTE_A in t or IP_CLIENTE_B in t]
    pasa(not ips, f"i) ninguna IP de cliente en los logs {ips if ips else ''}".strip())
    salida = "\n".join(salidas_gestion)
    pasa(all(c.contrasena not in salida for c in CUENTAS.values() if isinstance(c, Cuenta)),
         "i) gestion nunca imprime contrasenas")


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
    if ejecutar(["docker", "info", "--format", "{{.ServerVersion}}"]).rc != 0:
        p("PARADA: docker info falla")
        terminar_con_parada()
    previos = recursos_previos()
    if previos:
        p(f"PARADA: ya existen recursos con prefijo {PROYECTO}: {previos}")
        terminar_con_parada()
    ocupadas = subredes_ocupadas()
    if ocupadas:
        p(f"PARADA: las subredes fijas ya estan en uso por {ocupadas} (pare el proyecto canario y las otras baterias)")
        terminar_con_parada()
    # Solo se comprueba que existen (is_file), nunca se leen.
    for fichero in ("contrasena_redis.txt", "redis_acl.conf", "contrasena_postgres_superusuario.txt",
                    "contrasena_migrador.txt", "contrasena_aplicacion.txt", "contrasena_plataforma.txt",
                    "clave_maestra.txt", "clave_hmac_codigos.txt"):
        if not (RAIZ / "secrets" / fichero).is_file():
            p(f"PARADA: secrets/{fichero} no existe (scripts/generar_secretos.py)")
            terminar_con_parada()
    TEMPORAL = pathlib.Path(tempfile.mkdtemp(prefix="canario_personal_"))
    preparar_secretos_falsos()
    parada = None
    try:
        for seccion in (seccion_a, seccion_b, seccion_c, seccion_d, seccion_e, seccion_f, seccion_g, seccion_i,
                        seccion_h):
            seccion()
    except Parada as e:
        parada = str(e)
        p(f"PARADA: {parada}")
    except Exception:  # error inesperado del propio test: se informa y se limpia
        parada = "error inesperado en el test"
        p("ERROR INESPERADO:\n" + traceback.format_exc())
    finally:
        dc("start", "redis")
        if parada is not None:
            dc_con_gestion("down", "-v", "--rmi", "local")
        else:
            seccion_s()
        shutil.rmtree(TEMPORAL, ignore_errors=True)
    if parada is not None:
        estado["falla"] = True
    terminar()


if __name__ == "__main__":
    main()
