#!/usr/bin/env python3
"""Batería de pruebas de seguridad del registro del personal, "primero el
email" (app/solicitudes.py, app/correo.py y las rutas de app/rutas_personal.py),
con la pila real: API, PostgreSQL, Redis, el cartero (app/cartero.py, que
entrega el correo) y Mailpit (el SMTP de desarrollo, con TLS).

Qué prueba:

* a) el arranque: la API registra el origen de la SPA del personal; Mailpit
  corre sin root, de solo lectura, sin capacidades, con sus límites, solo en
  la red interna correo y sin puertos publicados, y desde esa red no se sale a
  internet; el cartero corre de solo lectura, sin capacidades, en las redes
  correo (con su IP fija) y salida, y con la CA de la batería como único
  almacén de confianza;
* c) el control positivo de extremo a extremo: solicitud, correo con el
  enlace (token en el fragmento), verificación, la solicitud aparece al admin,
  aprobación con un rol (sin token en la respuesta), correo de invitación,
  activación con TOTP, login con el rol aprobado y la fila de auditoría; el
  aviso de la activación llega al admin de la empresa, sin tokens, y no a la
  cuenta activada ni a otra empresa (en b, la del primer admin, sin nadie a
  quien avisar, deja EVENTO aviso_sin_destinatario);
* d) enumeración: la misma respuesta byte a byte para una empresa que no
  existe, un email con cuenta y uno nuevo; lo que cambia es el correo, que
  solo lee el dueño del buzón (aviso sin enlace, o nada); y el tiempo
  (medianas): cada camino tarda como un 422, sin base de datos antes de
  responder, y los tres lo mismo entre sí, con un control de sensibilidad
  (una consulta a la base de datos se distingue del 422) mayor que la
  tolerancia;
* e) la verificación: un token usado, desconocido, mal formado, caducado o de
  otro tipo (una invitación) da el mismo 401; un token de verificación no
  sirve como invitación;
* f) el admin: lo no verificado no se ve, un rol en el cuerpo del registro es
  un 422, la aprobación entre empresas es un 404 con su evento, un instructor
  recibe 403, un email que ya tiene cuenta da 409, el rechazo cierra y se
  audita, una solicitud verificada no se sustituye (sale un aviso), y se
  puede aprobar con el rol auditor. Las aprobaciones y las altas de admin
  llevan el codigo_totp de la cuenta de la sesión (step-up);
* m) el step-up TOTP de la aprobación: sin codigo_totp es un 422, con un
  código malo o ya usado es un 401 sin WWW-Authenticate, y en los tres la
  solicitud sigue abierta, sin cuenta nueva ni correo de invitación; el
  control positivo, con un código bueno: 201, la cuenta existe y llega el
  correo;
* g) CR, LF y NUL en el email: 422 sin crear nada ni enviar correo;
* h) el límite por destinatario con su valor de producción (3 en 15
  minutos): el cuarto es 429 con Retry-After y otro email sigue pasando; un
  solo evento con su regla, sin el email. Y el diario (configurado en 2): el
  tercero es 429 con el Retry-After hasta las 00:00 UTC, y su propio evento;
* i) sin el cartero, la respuesta no cambia y el fallo queda en el log de la
  API (EVENTO correo_fallido) sin el email; sin Mailpit, tampoco, y el fallo
  queda en el log del cartero (EVENTO correo_aplazado, con reintento); ni
  emails, ni tokens, ni enlaces en los logs de la API, el cartero, PostgreSQL
  y Redis (el del cartero, con un control: sí registra las entregas);
* j) sin CANARIO_ORIGEN_PERSONAL, o mal formado, la API no arranca;
* k) con PostgreSQL parado, el registro responde el mismo 202 al momento (la
  base de datos va después de responder) y el fallo queda en el log, como
  EVENTO registro_fallido, sin el email;
* l) (tras h y antes de i) la herramienta del buzón de desarrollo (scripts/buzon.py)
  enseña un correo de verificación con su asunto, su destinatario y el
  enlace entero, el mismo que lee el lector propio de la batería; con --texto,
  además, el texto del correo (control: sin --texto no sale); su limpieza
  cambia por "?" cada carácter de control (ESC, \r suelto, U+202E, tabulador
  y C1) y deja el resto igual, salto de línea incluido; con Mailpit
  parado (la red correo sigue, como al arrancar sin el perfil desarrollo) sale
  con código 1 y un error, sin enlaces ni traza (control: con Mailpit sale
  con 0). Va después de las secciones que leen correos anteriores, porque
  parar Mailpit borra su buzón (tmpfs), y antes de k, que deja la API
  reconectando con PostgreSQL;
* n) lo que fija el cartero en todo correo que llega a Mailpit: el remitente
  "Canario <no-responder@canario.invalid>", X-Mailjet-TrackClick: 0,
  X-Mailjet-TrackOpen: 0, el Message-ID con el dominio del remitente y el pie
  ("Canario nunca le pedirá por correo su contraseña ni su código de
  verificación."). Se leen las cabeceras con la API de Mailpit
  (/message/{ID}/headers) y el cuerpo del mensaje en crudo (/message/{ID}/raw);
* o) el cartero solo atiende a la IP de la API: un POST /correos desde otro
  contenedor de la red correo es un 403, deja EVENTO cartero_cliente_rechazado
  (sin la IP ni el destinatario) y no sale correo; control: GET /salud desde
  ese mismo contenedor da 200, así que la red llega y lo que rechaza es la IP;
* q) TLS verificado: con el cartero confiando en una CA ajena (otro override
  que cambia el montaje de /usr/lib/ssl/cert.pem), el correo no llega a
  Mailpit, el log del cartero tiene EVENTO correo_fallido con
  motivo=certificado y no hay reintento (es definitivo); control: con la CA
  buena (antes y después, tras volver a crear el cartero) el correo sí llega.

Cada prueba negativa lleva su control positivo: si el control falla, el
resultado es SIN CONCLUSION, nunca PASA. Los oráculos son literales.

Cómo se ejecuta (desde la raíz del repositorio, en PowerShell, con Docker en
marcha y los secretos generados con scripts/generar_secretos.py):

    python tests/security/verificar_registro.py

Usa un proyecto de Docker propio (canario_registro) con los perfiles
desarrollo (Mailpit) y gestion. No levanta Caddy: habla con la API por la red
app. Necesita que el proyecto canario y las demás baterías estén parados: las
subredes 10.88.0.0/28 y 10.88.4.0/28 son fijas (si están en uso, PARADA). Al
terminar lo borra todo (down -v y las imágenes construidas). No lee ningún
secreto: la API y gestion los reciben de secrets/ como Docker secrets, las
APIs temporales de j) usan secretos falsos, y el correo usa los suyos, FALSOS
y generados en cada ejecución en el directorio temporal: las credenciales SMTP
(los dos marcadores, con los que el cartero entrega sin autenticarse) y dos CA
(la buena y una ajena) con el certificado de Mailpit (nombre mailpit) firmado
por la buena, que salen de la función generar() de
scripts/generar_tls_desarrollo.py ejecutada en la imagen de la API. Un override
monta la CA buena en el cartero como su único almacén de confianza y el
certificado y la clave en Mailpit. Los ficheros auxiliares van a un directorio temporal
del sistema, nunca al repositorio. La salida completa se guarda en
verificacion_registro.txt dentro del directorio temporal del sistema. El
código de salida es 0 solo si el resultado global es OK.

Solo usa la biblioteca estándar.
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
from email import message_from_bytes
from email import policy as politica_email

RAIZ = pathlib.Path.cwd()
PROYECTO = "canario_registro"
SALIDA = pathlib.Path(tempfile.gettempdir()) / "verificacion_registro.txt"
BASE = ["docker", "compose", "-p", PROYECTO, "-f", "docker-compose.yml", "--profile", "desarrollo",
        "--profile", "gestion"]

lineas_salida = []
estado = {"falla": False, "sin_conclusion": False}

# ---------------------------------------------------------------------------
# Oráculos literales
# ---------------------------------------------------------------------------
SUBRED_APP = "10.88.0.0/28"
SUBRED_CORREO = "10.88.4.0/28"
# docker-compose.yml: IP fija del cartero y de la API en la red correo.
IP_CARTERO = "10.88.4.3"
IP_API_CORREO = "10.88.4.4"
MONTAJE_CA = "/usr/lib/ssl/cert.pem"
MARCADOR_SMTP_USUARIO = "sin-configurar:usuario"
MARCADOR_SMTP_CONTRASENA = "sin-configurar:contrasena"
ORIGEN_PERSONAL = "https://localhost:8445"
TEXTO_ORIGEN = "ORIGEN PERSONAL: https://localhost:8445"
TEXTO_BLOQUEADO = "ARRANQUE BLOQUEADO: "
LIMITES_PRUEBA = ("denuncia=1000/3600,seguimiento=1000/60,mensajes=1000/3600,acceso=1000/300,otras=1000/60,"
                  "cuenta=1000/60,registro=1000/3600,destinatario=1000/900,destinatario_dia=1000/86400")
# h) El de producción para destinatario (3 cada 15 minutos); el resto, altos.
LIMITES_DESTINATARIO = ("denuncia=1000/3600,seguimiento=1000/60,mensajes=1000/3600,acceso=1000/300,otras=1000/60,"
                        "cuenta=1000/60,registro=1000/3600,destinatario=3/900,destinatario_dia=1000/86400")
VENTANA_DESTINATARIO = 900
# h) Solo la regla del día, baja (2): con el de producción (10) habría que
# esperar a que la de 15 minutos se vaciara varias veces.
LIMITES_DESTINATARIO_DIA = ("denuncia=1000/3600,seguimiento=1000/60,mensajes=1000/3600,acceso=1000/300,"
                            "otras=1000/60,cuenta=1000/60,registro=1000/3600,destinatario=1000/900,"
                            "destinatario_dia=2/86400")
SEGUNDOS_DIA = 86400

# d) Tiempos (medianas, en ms). La tolerancia es menor que el efecto que
# demuestra el control: si no, aceptaría una fuga del tamaño de lo que dice
# ver. Medidos antes de fijarlos (informe del bloque 5a-bis).
TOLERANCIA_TIEMPO_MS = 1.0
CONTROL_TIEMPO_MS = 2.0
PAUSA_TIEMPOS = 0.2  # segundos antes de cada petición medida

# k) Con PostgreSQL parado, un registro que esperase a la base de datos
# tardaría lo que el pool tarda en rendirse (10 s, app/bd.py).
MAXIMO_SIN_BD_MS = 1000

# Mailpit (docker-compose.yml)
USUARIO_MAILPIT = "10003:10003"
MEMORIA_MAILPIT = 134217728  # 128m
PIDS = 64

# Respuestas (app/rutas_personal.py y app/frontera_http.py)
CUERPO_202 = ('{"mensaje":"si los datos son correctos, recibirá un correo de Canario en unos minutos; '
              'si no le llega, mire en la carpeta de spam y, si tampoco está, vuelva a solicitarlo más tarde"}'
              ).encode()
CUERPO_401 = '{"detalle": "solicitud no válida"}'.encode()
CUERPO_401_INVITACION = '{"detalle": "invitación no válida"}'.encode()
CUERPO_401_CREDENCIALES = '{"detalle": "credenciales no válidas"}'.encode()
CUERPO_404 = b'{"detalle": "recurso no encontrado"}'
CUERPO_409 = b'{"detalle": "ya existe una cuenta con ese email"}'
CUERPO_422 = '{"detalle": "petición no válida"}'.encode()
CUERPO_429 = '{"detalle": "demasiadas peticiones; inténtelo de nuevo más tarde"}'.encode()
TIPO_JSON = "application/json"

# Correos (app/solicitudes.py)
REMITENTE = "no-responder@canario.invalid"
# n) Lo que fija el cartero (app/cartero.py): el remitente completo y el pie.
DE_CORREO = "Canario <no-responder@canario.invalid>"
PIE_CORREO = "\n\n-- \nCanario nunca le pedirá por correo su contraseña ni su código de verificación.\n"
FIN_MESSAGE_ID = "@canario.invalid>"
# Eventos del log del cartero (app/cartero.py).
TEXTO_CARTERO_ENTREGADO = "EVENTO correo_entregado: tipo=verificacion"
TEXTO_CARTERO_APLAZADO = "EVENTO correo_aplazado: tipo=verificacion motivo="
TEXTO_CARTERO_CERTIFICADO = "EVENTO correo_fallido: tipo=verificacion motivo=certificado"
TEXTO_CARTERO_RECHAZADO = "EVENTO cartero_cliente_rechazado: ruta=/correos"
CUERPO_CARTERO_PROHIBIDO = {"detalle": "prohibido"}
CUERPO_CARTERO_SALUD = {"estado": "ok"}
ASUNTO_VERIFICACION = "Confirme su email para registrarse en Canario"
ASUNTO_AVISO_CUENTA = "Intento de registro con su email en Canario"
ASUNTO_AVISO_PENDIENTE = "Su solicitud de registro en Canario sigue pendiente"
ASUNTO_INVITACION = "Active su cuenta del personal en Canario"
ASUNTO_ACTIVACION = "Aviso de Canario: se ha activado una cuenta del personal"
TEXTO_SIN_DESTINATARIO = "EVENTO aviso_sin_destinatario: tipo=aviso_activacion empresa="

# l) La herramienta del buzón (scripts/buzon.py): su primera línea de error y
# un límite que alcanza a todos los correos de la batería.
ERROR_BUZON = "ERROR: no se pudo leer el buzon de Mailpit: "
LIMITE_BUZON = 100
# Una línea del texto del correo de verificación (app/solicitudes.py). Sin
# tildes a propósito: por una tubería, Python en Windows escribe en cp1252 y
# la batería lee UTF-8, así que una tilde no se compararía bien.
LINEA_TEXTO_VERIFICACION = "Si no lo ha pedido usted, ignore este correo: sin confirmar, la solicitud caduca sola."
# limpiar() de scripts/buzon.py, cargada sin ejecutar main(). Las entradas
# llegan en JSON por la entrada estándar y la salida va en JSON con escapes
# ASCII: ningún carácter de control pasa por la línea de órdenes ni por la
# consola.
PRUEBA_LIMPIEZA = """
import json, runpy, sys
limpiar = runpy.run_path(sys.argv[1])["limpiar"]
print(json.dumps([limpiar(t) for t in json.load(sys.stdin)]))
"""
CON_CONTROL = "a\x1b[31mb\rc\N{RIGHT-TO-LEFT OVERRIDE}d\te\x85f"
LIMPIO = "a?[31mb?c?d?e?f"
SIN_CONTROL = "linea 1\nlinea 2 con tilde: camión"
PATRON_VERIFICACION = re.compile(r"https://localhost:8445/registro/verificacion#([0-9a-f]{32}\.[A-Za-z0-9_-]{43})")
PATRON_ACTIVACION = re.compile(r"https://localhost:8445/activacion#([0-9a-f]{32}\.[A-Za-z0-9_-]{43})")
ACCION_APROBACION = "aprobacion_registro"
ACCION_RECHAZO = "rechazo_registro"
# Se comparan con el final de la línea: "regla=destinatario" es también el
# principio de "regla=destinatario_dia".
EVENTO_DESTINATARIO = "EVENTO limite_destinatario: regla=destinatario"
EVENTO_DESTINATARIO_DIA = "EVENTO limite_destinatario: regla=destinatario_dia"
TEXTO_EVENTO_REGISTRO_FALLIDO = "EVENTO registro_fallido: error="
TEXTO_EVENTO_CORREO = "EVENTO correo_fallido: tipo=verificacion error="
TEXTO_EVENTO_DENEGADO = "EVENTO acceso_denegado: "
CLAVES_APROBACION = ["usuario_id"]
CLAVES_LISTADO = ["hay_mas", "solicitudes"]
CLAVES_SOLICITUD = ["email", "solicitud_id"]

PATRON_ALTA = re.compile(r"empresa creada: empresa_id=([0-9a-f-]{36}) identificador_publico=([0-9a-f]{32})")
PATRON_INVITACION_GESTION = re.compile(r"token_invitacion=([0-9a-f]{32}\.[A-Za-z0-9_-]{43})\n")
EMPRESA_INEXISTENTE = "0" * 32

# Cliente HTTP: corre con la imagen de la API en la red app, directo a la
# API. Mide cada petición en milisegundos.
CLIENTE_HTTP = r'''
import base64, http.client, json, sys, time

def una(pt):
    conexion = None
    # La pausa va antes de conectar y fuera de la medida.
    time.sleep(pt.get("pausa", 0))
    try:
        conexion = http.client.HTTPConnection("api", 8000, timeout=30)
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
        return {"error": type(error).__name__, "metodo": pt["metodo"], "ruta": pt["ruta"]}
    finally:
        if conexion is not None:
            conexion.close()

print(json.dumps([una(pt) for pt in json.load(sys.stdin)]))
'''

# Lector del buzón de Mailpit por su API HTTP, desde la red correo (la única
# donde está). "borrar" vacía el buzón.
LECTOR_CORREO = r'''
import json, sys, urllib.request
orden = json.load(sys.stdin)
base = "http://mailpit:8025/api/v1"
if orden == "borrar":
    urllib.request.urlopen(urllib.request.Request(base + "/messages", method="DELETE"), timeout=10).read()
    print(json.dumps("borrado"))
    sys.exit()
lista = json.load(urllib.request.urlopen(base + "/messages?limit=1000", timeout=10))
salida = []
for m in lista.get("messages") or []:
    d = json.load(urllib.request.urlopen(base + "/message/" + m["ID"], timeout=10))
    salida.append({"para": [a["Address"] for a in d.get("To") or []], "de": (d.get("From") or {}).get("Address"),
                   "asunto": d.get("Subject"), "texto": d.get("Text")})
print(json.dumps(salida))
'''

# Cabeceras y cuerpo en crudo de cada correo del buzón, por la API de Mailpit:
# GET /message/{ID}/headers (un objeto cabecera -> lista de valores; las
# claves salen con la mayúscula canónica de net/mail, así que se comparan en
# minúsculas) y GET /message/{ID}/raw (el mensaje tal cual lo recibió).
LECTOR_CABECERAS = r'''
import base64, json, urllib.request
base = "http://mailpit:8025/api/v1"
lista = json.load(urllib.request.urlopen(base + "/messages?limit=1000", timeout=10))
salida = []
for m in lista.get("messages") or []:
    cabeceras = json.load(urllib.request.urlopen(base + "/message/" + m["ID"] + "/headers", timeout=10))
    crudo = urllib.request.urlopen(base + "/message/" + m["ID"] + "/raw", timeout=10).read()
    salida.append({"asunto": m.get("Subject"), "cabeceras": cabeceras,
                   "crudo": base64.b64encode(crudo).decode("ascii")})
print(json.dumps(salida))
'''

# o) Un cliente que no es la API, en la red correo: un POST /correos con un
# correo bien formado (así lo que lo rechaza es la IP, no el formato) y un
# GET /salud (el control: la red llega).
CLIENTE_CARTERO = r'''
import http.client, json, sys


def peticion(metodo, ruta, cuerpo=None):
    conexion = http.client.HTTPConnection("cartero", 8000, timeout=15)
    try:
        cabeceras = {"Content-Type": "application/json"} if cuerpo is not None else {}
        conexion.request(metodo, ruta, body=cuerpo, headers=cabeceras)
        respuesta = conexion.getresponse()
        return {"estado": respuesta.status, "cuerpo": respuesta.read().decode("utf-8", "replace")}
    except Exception as error:
        return {"error": type(error).__name__}
    finally:
        conexion.close()


correo = json.dumps({"tipo": "verificacion", "destinatario": sys.argv[1], "asunto": "prueba de la bateria",
                     "cuerpo": "cuerpo de prueba"}).encode("ascii")
print(json.dumps({"salud": peticion("GET", "/salud"), "correos": peticion("POST", "/correos", correo)}))
'''

# Las dos CA y el certificado de Mailpit, con la función generar() del propio
# script de desarrollo (se monta en la imagen de la API, que trae cryptography).
# Se generan dos juegos: el primero es el bueno, del segundo solo se usa su CA
# (la ajena). Imprime PEM, nunca claves en el log: la salida la lee la batería.
GENERADOR_TLS = r'''
import json, runpy, sys
generar = runpy.run_path(sys.argv[1])["generar"]
print(json.dumps([[parte.decode("ascii") for parte in generar()] for _ in range(2)]))
'''

PRUEBA_SALIDA = ("import socket\n"
                 "try:\n"
                 "    socket.create_connection(('1.1.1.1', 443), timeout=5).close(); print('CONECTA')\n"
                 "except OSError as e:\n"
                 "    print('SIN_SALIDA', type(e).__name__)\n")


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
    """Prueba negativa con control: si el control falla, SIN CONCLUSION."""
    if not control_ok:
        sinc(f"{nombre}: el control positivo fallo {detalle}".rstrip())
        return
    pasa(cond, nombre)
    if not cond and detalle:
        p(f"   {detalle}")


def esperar(condicion, maximo):
    limite = time.monotonic() + maximo
    while time.monotonic() < limite:
        if condicion():
            return True
        time.sleep(1)
    return condicion()


def contenedor(servicio):
    cid = dc("ps", "-q", servicio).out.strip()
    if not cid:
        raise Parada(f"no hay contenedor para el servicio {servicio}")
    return cid


def inspeccionar(objeto, formato="{{json .}}"):
    r = ejecutar(["docker", "inspect", "--format", formato, objeto])
    if r.rc != 0:
        raise Parada(f"docker inspect {objeto} fallo: {r.err.strip()[:200]}")
    return json.loads(r.out)


def log_de(servicio):
    return dc("logs", "--no-color", "--no-log-prefix", servicio).todo


def log_cartero():
    """El log del cartero entero, incluido el de los contenedores que q) ya
    reemplazó."""
    return "\n".join(LOGS_CARTERO_PREVIOS + [log_de("cartero")])


def eventos_que_acaban(texto):
    """Líneas del log de la API que terminan exactamente en texto."""
    return [l for l in log_de("api").splitlines() if l.rstrip().endswith(texto)]


TEMPORAL = None
PRUEBA = None
CA_AJENA_YML = None
# Logs del cartero de contenedores que q) ya ha reemplazado: sin ellos, i) no
# vería lo que se registró antes.
LOGS_CARTERO_PREVIOS = []
IMAGEN_API = ""
ESTADO_GIT_ARRANQUE = None
# Lo que no debe aparecer en ningún log: emails y tokens de la batería.
SENSIBLES = set()


# ---------------------------------------------------------------------------
# HTTP, correo y TOTP de la batería
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
        if "error" in respuesta:
            p(f"  [cliente HTTP] {respuesta['error']} en {respuesta['metodo']} {respuesta['ruta']}")
        if "cuerpo" in respuesta:
            respuesta["cuerpo"] = base64.b64decode(respuesta["cuerpo"])
    return respuestas


def una(peticion):
    return http([peticion])[0]


def pt(metodo, ruta, datos=None, token=None, crudo=None):
    cabeceras = {"Content-Type": "application/json"}
    if isinstance(token, Sesion):
        token = token.vigente()
    if token is not None:
        cabeceras["Authorization"] = f"Bearer {token}"
    if crudo is None and datos is not None:
        crudo = json.dumps(datos, ensure_ascii=False).encode("utf-8")
    peticion = {"metodo": metodo, "ruta": ruta, "cabeceras": cabeceras}
    if crudo is not None:
        peticion["cuerpo"] = base64.b64encode(crudo).decode("ascii")
    return peticion


def json_de(respuesta):
    try:
        return json.loads(respuesta["cuerpo"].decode("utf-8"))
    except (KeyError, ValueError, UnicodeDecodeError):
        return None


def es(respuesta, codigo, cuerpo):
    return (respuesta.get("estado") == codigo and respuesta.get("cuerpo") == cuerpo
            and respuesta.get("cabeceras", {}).get("content-type") == TIPO_JSON)


def registro(empresa, email):
    SENSIBLES.add(email)
    return pt("POST", "/v1/personal/registro", {"empresa": empresa, "email": email})


def verificacion(token):
    return pt("POST", "/v1/personal/registro/verificacion", {"token": token})


def buzon(orden="leer"):
    r = ejecutar(["docker", "run", "--rm", "-i", "--network", f"{PROYECTO}_correo", "--read-only",
                  "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                  "--entrypoint", "python", IMAGEN_API, "-c", LECTOR_CORREO],
                 entrada=json.dumps(orden).encode("utf-8"))
    try:
        return json.loads(r.out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise Parada(f"no se pudo leer el buzon de Mailpit: {r.err.strip()[-400:]!r}") from None


def correos_para(email):
    return [c for c in buzon() if c["para"] == [email]]


def esperar_correos(email, cuantos, maximo=30):
    """Los correos de email cuando haya al menos cuantos, o los que haya."""
    encontrados = []

    def hay():
        encontrados[:] = correos_para(email)
        return len(encontrados) >= cuantos
    esperar(hay, maximo)
    return list(encontrados)


def token_de(correo_recibido, patron):
    encaje = patron.search(correo_recibido.get("texto") or "")
    if encaje:
        SENSIBLES.add(encaje.group(1))
    return encaje.group(1) if encaje else None


def totp(secreto_texto, paso, digitos=6):
    """TOTP propio de la batería (RFC 6238 sobre RFC 4226), independiente de
    app/cripto.py."""
    clave = base64.b32decode(secreto_texto + "=" * (-len(secreto_texto) % 8))
    mac = hmac.new(clave, paso.to_bytes(8, "big"), hashlib.sha1).digest()
    o = mac[-1] & 0x0F
    return f"{(int.from_bytes(mac[o:o + 4], 'big') & 0x7FFFFFFF) % 10 ** digitos:0{digitos}d}"


ULTIMO_PASO = {}


def codigo_libre(secreto):
    """Código del paso actual sin usar; si ya se usó, espera al siguiente
    (como tests/security/verificar_personal.py)."""
    while True:
        actual = int(time.time()) // 30
        if actual > ULTIMO_PASO.get(secreto, -1):
            return totp(secreto, actual), actual
        time.sleep(30 - time.time() % 30 + 0.5)


class Cuenta:
    def __init__(self, empresa, email):
        self.empresa, self.email = empresa, email
        self.contrasena = secrets.token_urlsafe(18)
        self.secreto = None
        self.dispositivo = None
        SENSIBLES.add(email)


def activar(cuenta, token):
    """Activa la cuenta con el token de su invitación. Cierto si termina."""
    SENSIBLES.add(token)
    r1 = una(pt("POST", "/v1/personal/activacion", {"token": token, "contrasena": cuenta.contrasena}))
    cuenta.secreto = (json_de(r1) or {}).get("secreto_totp")
    if r1.get("estado") != 200 or not cuenta.secreto:
        return False
    codigo, paso = codigo_libre(cuenta.secreto)
    r2 = una(pt("POST", "/v1/personal/activacion/confirmar", {"token": token, "codigo_totp": codigo}))
    if r2.get("estado") != 200:
        return False
    ULTIMO_PASO[cuenta.secreto] = paso
    cuenta.dispositivo = (json_de(r2) or {}).get("token_dispositivo")
    SENSIBLES.add(cuenta.dispositivo)
    return True


class Sesion:
    """Acceso y renovación; renueva el acceso pasados 4 minutos."""

    def __init__(self, datos):
        self.jwt, self.renovacion = datos["token_acceso"], datos["token_renovacion"]
        self.desde = time.monotonic()

    def vigente(self):
        if time.monotonic() - self.desde > 240:
            r = una(pt("POST", "/v1/personal/sesiones/renovacion", {"token_renovacion": self.renovacion}))
            datos = json_de(r) or {}
            if r.get("estado") == 200:
                self.jwt, self.renovacion = datos["token_acceso"], datos["token_renovacion"]
                self.desde = time.monotonic()
        return self.jwt


def iniciar_sesion(cuenta):
    codigo, paso = codigo_libre(cuenta.secreto)
    r = una(pt("POST", "/v1/personal/sesiones", {
        "empresa": cuenta.empresa, "email": cuenta.email, "contrasena": cuenta.contrasena, "codigo_totp": codigo,
        "token_dispositivo": cuenta.dispositivo}))
    if r.get("estado") != 201:
        return None
    ULTIMO_PASO[cuenta.secreto] = paso
    return Sesion(json_de(r))


def con_totp(cuenta, datos=None):
    """Cuerpo con el codigo_totp de ESA cuenta (el step-up de las operaciones de
    admin pide el TOTP de la cuenta de la sesión) y el paso que usa. El paso
    solo se anota con gastar() cuando la API lo consume: si la operación se
    rechaza por negocio (404, 409) o por el rol (422, 403), el código queda
    sin gastar."""
    codigo, paso = codigo_libre(cuenta.secreto)
    return dict(datos or {}, codigo_totp=codigo), paso


def gastar(cuenta, paso):
    ULTIMO_PASO[cuenta.secreto] = paso


def listado(sesion):
    return json_de(una(pt("GET", "/v1/personal/solicitudes", token=sesion))) or {}


def id_de(sesion, email):
    """El id de la solicitud de ese email en el listado del admin, o None."""
    return next((s["solicitud_id"] for s in listado(sesion).get("solicitudes", []) if s["email"] == email), None)


def gestion(*args):
    return dc("run", "--rm", "-T", "gestion", *args)


def con_limites(limites):
    """Recrea la API con esos límites (CANARIO_LIMITES en un compose adicional)."""
    fichero = TEMPORAL / f"limites_{secrets.token_hex(4)}.yml"
    fichero.write_text(f"services:\n  api:\n    environment:\n      CANARIO_LIMITES: \"{limites}\"\n",
                       encoding="utf-8", newline="\n")
    r = ejecutar(BASE + ["-f", str(fichero), "up", "-d", "--wait", "api"])
    if r.rc != 0:
        p(r.todo.strip()[-1500:])
        raise Parada("la API no arranca con los limites pedidos")
    return fichero


def fichero_secreto(nombre, ruta):
    return [f"  {nombre}:", f"    file: \"{ruta.as_posix()}\""]


def escribir_auxiliares():
    """Secretos falsos del correo (credenciales SMTP con los dos marcadores,
    certificado y clave de Mailpit) y la CA de prueba en el cartero, en
    ficheros de compose adicionales, como verificar_login_externo.py. Los PEM
    se escriben vacíos y a) los rellena: compose necesita que existan antes
    de cualquier config. Además, el override que cambia la CA por la ajena
    (q)."""
    global PRUEBA, CA_AJENA_YML
    PRUEBA = TEMPORAL / "prueba"
    secretos = TEMPORAL / "secretos_compose"
    PRUEBA.mkdir()
    secretos.mkdir()
    for fichero in ("correo_ca.pem", "ca_ajena.pem", "mailpit_certificado.pem", "mailpit_clave.pem"):
        (PRUEBA / fichero).write_bytes(b"")
    (secretos / "smtp_usuario").write_bytes(MARCADOR_SMTP_USUARIO.encode("ascii"))
    (secretos / "smtp_contrasena").write_bytes(MARCADOR_SMTP_CONTRASENA.encode("ascii"))
    lineas = ["secrets:"]
    for nombre in ("smtp_usuario", "smtp_contrasena"):
        lineas += fichero_secreto(nombre, secretos / nombre)
    for nombre in ("mailpit_certificado", "mailpit_clave"):
        lineas += fichero_secreto(nombre, PRUEBA / f"{nombre}.pem")
    adicional = TEMPORAL / "secretos_correo.yml"
    adicional.write_text("\n".join(lineas) + "\n", encoding="utf-8", newline="\n")

    def montaje(fichero):
        # compose fusiona volumes por target y sustituye el montaje del repo
        # (./secrets/correo_ca.pem): la CA de la batería es el único almacén de
        # confianza del cartero.
        return ("services:\n  cartero:\n    volumes:\n      - type: bind\n"
                f"        source: \"{(PRUEBA / fichero).as_posix()}\"\n"
                f"        target: {MONTAJE_CA}\n        read_only: true\n")
    override = TEMPORAL / "ca_buena.yml"
    override.write_text(montaje("correo_ca.pem"), encoding="utf-8", newline="\n")
    CA_AJENA_YML = TEMPORAL / "ca_ajena.yml"
    CA_AJENA_YML.write_text(montaje("ca_ajena.pem"), encoding="utf-8", newline="\n")
    BASE.extend(["-f", str(adicional), "-f", str(override)])


def generar_tls_prueba():
    """Escribe en PRUEBA la CA buena, el certificado y la clave de Mailpit
    (firmado por ella) y una CA ajena, generados con generar() de
    scripts/generar_tls_desarrollo.py en la imagen de la API (sin red)."""
    guion = RAIZ / "scripts" / "generar_tls_desarrollo.py"
    r = ejecutar(["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
                  "--security-opt", "no-new-privileges:true", "--mount",
                  f"type=bind,src={guion},dst=/prueba/generar_tls_desarrollo.py,readonly",
                  "--entrypoint", "python", IMAGEN_API, "-I", "-c", GENERADOR_TLS,
                  "/prueba/generar_tls_desarrollo.py"])
    try:
        buena, ajena = json.loads(r.out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise Parada(f"no se generan los certificados de prueba: {r.err.strip()[-400:]!r}") from None
    ca, certificado, clave = buena
    for nombre, contenido in (("correo_ca.pem", ca), ("mailpit_certificado.pem", certificado),
                              ("mailpit_clave.pem", clave), ("ca_ajena.pem", ajena[0])):
        (PRUEBA / nombre).write_bytes(contenido.encode("ascii"))
    pasa(ca.startswith("-----BEGIN CERTIFICATE-----") and certificado.startswith("-----BEGIN CERTIFICATE-----")
         and clave.startswith("-----BEGIN PRIVATE KEY-----") and ajena[0].startswith("-----BEGIN CERTIFICATE-----")
         and ca != ajena[0], "a) control: se generan la CA buena, el certificado y la clave de Mailpit y una CA ajena distinta")


def montaje_ca(servicio):
    """[(origen, escritura)] de lo montado en /usr/lib/ssl/cert.pem del
    contenedor del servicio, según docker inspect."""
    montajes = inspeccionar(contenedor(servicio), "{{json .Mounts}}")
    return [(m.get("Source", ""), m.get("RW")) for m in montajes if m.get("Destination") == MONTAJE_CA]


def correos_completos():
    """Cada correo del buzón con sus cabeceras (claves en minúsculas, valores
    en lista) y el cuerpo de texto decodificado por la biblioteca estándar a
    partir del mensaje en crudo, con LF."""
    r = ejecutar(["docker", "run", "--rm", "--network", f"{PROYECTO}_correo", "--read-only", "--cap-drop", "ALL",
                  "--security-opt", "no-new-privileges:true", "--entrypoint", "python", IMAGEN_API, "-c",
                  LECTOR_CABECERAS])
    try:
        lista = json.loads(r.out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise Parada(f"no se pudieron leer las cabeceras del buzon: {r.err.strip()[-400:]!r}") from None
    for c in lista:
        c["cabeceras"] = {k.lower(): v for k, v in c["cabeceras"].items()}
        mensaje = message_from_bytes(base64.b64decode(c.pop("crudo")), policy=politica_email.default)
        parte = mensaje.get_body(preferencelist=("plain",))
        c["cuerpo"] = parte.get_content().replace("\r\n", "\n") if parte is not None else None
    return lista


# ---------------------------------------------------------------------------
# Secciones
# ---------------------------------------------------------------------------
EMPRESAS = {}
ADMINS = {}
SESIONES = {}
LIMITES_ACTUALES = None


def seccion_a():
    global IMAGEN_API, LIMITES_ACTUALES
    p("=== a) arranque: API con su origen y Mailpit endurecido en una red interna")
    LIMITES_ACTUALES = TEMPORAL / "limites.yml"
    LIMITES_ACTUALES.write_text(f"services:\n  api:\n    environment:\n      CANARIO_LIMITES: \"{LIMITES_PRUEBA}\"\n",
                                encoding="utf-8", newline="\n")
    # Primero la imagen: los certificados de prueba se generan con ella, y la
    # pila los necesita ya escritos al arrancar.
    r = dc("build", "api")
    p(f"build api -> codigo {r.rc}")
    if r.rc != 0:
        p(r.todo.strip()[-1500:])
        raise Parada("no se construye la imagen de la API")
    IMAGEN_API = f"{PROYECTO}-api"
    if ejecutar(["docker", "image", "inspect", IMAGEN_API]).rc != 0:
        raise Parada(f"no existe la imagen {IMAGEN_API} tras construirla")
    generar_tls_prueba()
    r = ejecutar(BASE + ["-f", str(LIMITES_ACTUALES), "up", "-d", "--build", "--wait", "api", "mailpit", "cartero"])
    p(f"up -d --build --wait api mailpit cartero -> codigo {r.rc}")
    if r.rc != 0:
        p(r.todo.strip()[-1500:])
        raise Parada("no arranca la pila con el cartero y Mailpit")
    IMAGEN_API = inspeccionar(contenedor("api"), "{{json .Config.Image}}")
    pasa(TEXTO_ORIGEN in log_de("api"), f"a) la API registra el origen de la SPA ({TEXTO_ORIGEN!r})")
    i = inspeccionar(contenedor("mailpit"))
    hc = i["HostConfig"]
    pasa(i["Config"]["User"] == USUARIO_MAILPIT, f"a) mailpit: User = {i['Config']['User']!r}")
    pasa(hc["ReadonlyRootfs"] is True, f"a) mailpit: ReadonlyRootfs = {hc['ReadonlyRootfs']}")
    pasa(hc["CapDrop"] == ["ALL"] and not hc["CapAdd"], f"a) mailpit: CapDrop = {hc['CapDrop']}, CapAdd = {hc['CapAdd']}")
    pasa(hc["SecurityOpt"] == ["no-new-privileges:true"], f"a) mailpit: SecurityOpt = {hc['SecurityOpt']}")
    pasa(hc["Memory"] == MEMORIA_MAILPIT and hc["PidsLimit"] == PIDS,
         f"a) mailpit: Memory = {hc['Memory']}, PidsLimit = {hc['PidsLimit']}")
    redes = sorted(i["NetworkSettings"]["Networks"])
    pasa(redes == [f"{PROYECTO}_correo"], f"a) mailpit: solo en la red correo ({redes})")
    publicados = {k: v for k, v in (i["NetworkSettings"]["Ports"] or {}).items() if v}
    pasa(not publicados and not hc["PortBindings"], f"a) mailpit: sin puertos publicados ({publicados})")
    estado_salud = inspeccionar(contenedor("mailpit"), "{{json .State.Health.Status}}")
    pasa(estado_salud == "healthy", f"a) mailpit: healthy con su healthcheck ({estado_salud})")
    # El cartero: endurecido como el resto, en correo (IP fija) y salida, con la
    # CA de la batería como su único almacén de confianza.
    i = inspeccionar(contenedor("cartero"))
    hc = i["HostConfig"]
    pasa(hc["ReadonlyRootfs"] is True and hc["CapDrop"] == ["ALL"] and not hc["CapAdd"]
         and hc["SecurityOpt"] == ["no-new-privileges:true"],
         f"a) cartero: de solo lectura, sin capacidades y sin ganar privilegios ({hc['ReadonlyRootfs']}, "
         f"{hc['CapDrop']}, {hc['SecurityOpt']})")
    redes = sorted(i["NetworkSettings"]["Networks"])
    pasa(redes == [f"{PROYECTO}_correo", f"{PROYECTO}_salida"]
         and i["NetworkSettings"]["Networks"][f"{PROYECTO}_correo"]["IPAddress"] == IP_CARTERO,
         f"a) cartero: en las redes correo (con la IP {IP_CARTERO}) y salida ({redes})")
    ip_api = inspeccionar(contenedor("api"), "{{json .NetworkSettings.Networks}}")[f"{PROYECTO}_correo"]["IPAddress"]
    pasa(ip_api == IP_API_CORREO, f"a) la API tiene en la red correo la IP {IP_API_CORREO} que espera el cartero ({ip_api})")
    montaje = montaje_ca("cartero")
    pasa(len(montaje) == 1 and montaje[0][0].endswith("correo_ca.pem") and montaje[0][1] is False,
         f"a) cartero: {MONTAJE_CA} es la CA de la bateria, de solo lectura ({montaje})")
    estado_salud = inspeccionar(contenedor("cartero"), "{{json .State.Health.Status}}")
    pasa(estado_salud == "healthy", f"a) cartero: healthy con su healthcheck ({estado_salud})")
    red = inspeccionar(f"{PROYECTO}_correo")
    pasa(red["Internal"] is True, f"a) la red correo es interna ({red['Internal']})")
    control = ejecutar(["docker", "run", "--rm", "--network", "bridge", "--entrypoint", "python", IMAGEN_API,
                        "-c", PRUEBA_SALIDA])
    desde_correo = ejecutar(["docker", "run", "--rm", "--network", f"{PROYECTO}_correo", "--entrypoint", "python",
                             IMAGEN_API, "-c", PRUEBA_SALIDA])
    negativo(f"a) desde la red correo no se llega a 1.1.1.1:443 ({desde_correo.out.strip()})",
             desde_correo.out.startswith("SIN_SALIDA"), control.out.strip() == "CONECTA",
             f"control en la red bridge: {control.out.strip()!r}")


def seccion_b():
    p("=== b) preparacion: dos empresas con su admin activado")
    for clave in ("A", "B"):
        r = gestion("alta-empresa", "--nombre", f"Empresa Registro {clave}", "--zona", "Europe/Madrid")
        alta = PATRON_ALTA.search(r.out)
        if r.rc != 0 or alta is None:
            raise Parada(f"no se pudo dar de alta la empresa {clave}: {r.err.strip()[-300:]!r}")
        EMPRESAS[clave] = (alta.group(1), alta.group(2))
        admin = Cuenta(alta.group(2), f"admin.{clave.lower()}@registro.test")
        r = gestion("alta-admin", "--identificador", alta.group(2), "--email", admin.email)
        invitacion = PATRON_INVITACION_GESTION.search(r.out)
        if r.rc != 0 or invitacion is None or not activar(admin, invitacion.group(1)):
            raise Parada(f"no se pudo activar el admin de {clave}: {r.err.strip()[-300:]!r}")
        ADMINS[clave] = admin
        SESIONES[clave] = iniciar_sesion(admin)
        if SESIONES[clave] is None:
            raise Parada(f"no se pudo iniciar sesion con el admin de {clave}")
    pasa(True, f"b) empresas A y B con su admin activado y en sesion ({EMPRESAS['A'][1]}, {EMPRESAS['B'][1]})")
    # El primer admin de cada empresa no tiene a quién avisar de su
    # activación (app/avisos.py): el aviso que no llega a nadie se ve en el log.
    sin_destino = [l for l in log_de("api").splitlines() if TEXTO_SIN_DESTINATARIO in l]
    pasa(sorted(l[l.index("empresa=") + len("empresa="):] for l in sin_destino)
         == sorted(EMPRESAS[c][0] for c in ("A", "B")),
         f"b) la activacion de cada primer admin, sin nadie a quien avisar, deja EVENTO aviso_sin_destinatario "
         f"({len(sin_destino)})")
    buzon("borrar")


def seccion_c():
    p("=== c) control de extremo a extremo: registro, verificacion, aprobacion, activacion y login")
    ident = EMPRESAS["A"][1]
    email = "nueva.persona@registro.test"
    r = una(registro(ident, email))
    pasa(es(r, 202, CUERPO_202), f"c) POST /registro -> 202 con el cuerpo fijo ({r.get('estado')}, {r.get('cuerpo')!r})")
    correos = esperar_correos(email, 1)
    correo = correos[0] if correos else {}
    token = token_de(correo, PATRON_VERIFICACION)
    pasa(len(correos) == 1 and correo.get("asunto") == ASUNTO_VERIFICACION and correo.get("de") == REMITENTE
         and token is not None and token.startswith(ident + "."),
         f"c) llega un correo de verificacion con el enlace a la SPA y el token en el fragmento "
         f"({len(correos)}, {correo.get('asunto')!r})")
    if token is None:
        raise Parada("sin el correo de verificacion no se puede seguir")
    pasa(token not in (correo.get("asunto") or ""), "c) el token no va en el asunto")
    # Sin verificar, el admin no la ve.
    antes = listado(SESIONES["A"])
    pasa(sorted(antes) == CLAVES_LISTADO and antes.get("solicitudes") == [] and antes.get("hay_mas") is False,
         f"c) sin verificar, el admin no ve la solicitud ({antes})")
    r = una(verificacion(token))
    pasa(r.get("estado") == 204 and r.get("cuerpo") == b"", f"c) POST /registro/verificacion -> 204 ({r.get('estado')})")
    despues = listado(SESIONES["A"])
    filas = despues.get("solicitudes") or []
    pasa(len(filas) == 1 and sorted(filas[0]) == CLAVES_SOLICITUD and filas[0]["email"] == email,
         f"c) verificada, aparece en el listado del admin con solo id y email ({despues})")
    solicitud = filas[0]["solicitud_id"] if filas else "x"
    cuerpo, paso = con_totp(ADMINS["A"], {"rol": "instructor"})
    r = una(pt("POST", f"/v1/personal/solicitudes/{solicitud}/aprobacion", cuerpo, token=SESIONES["A"]))
    if r.get("estado") == 201:
        gastar(ADMINS["A"], paso)
    datos = json_de(r) or {}
    pasa(r.get("estado") == 201 and sorted(datos) == CLAVES_APROBACION,
         f"c) aprobacion -> 201 con solo el id de la cuenta, sin token de invitacion ({r.get('estado')}, {sorted(datos)})")
    invitaciones = [c for c in esperar_correos(email, 2) if c["asunto"] == ASUNTO_INVITACION]
    token_invitacion = token_de(invitaciones[0], PATRON_ACTIVACION) if invitaciones else None
    pasa(len(invitaciones) == 1 and token_invitacion is not None,
         f"c) la invitacion llega solo al email verificado, con el enlace de activacion ({len(invitaciones)})")
    persona = Cuenta(ident, email)
    activada = token_invitacion is not None and activar(persona, token_invitacion)
    pasa(activada, "c) la persona activa su cuenta con el enlace del correo (contrasena y TOTP)")
    # Aviso de activación (app/avisos.py): una cuenta más que puede leer
    # denuncias, y quien vigila la empresa lo sabe. Control: le llega al admin
    # de A, con la cuenta y el rol. Ni a la propia cuenta ni a otra empresa.
    avisos = [c for c in esperar_correos(ADMINS["A"].email, 1) if c["asunto"] == ASUNTO_ACTIVACION]
    control = (activada and len(avisos) == 1 and avisos[0].get("de") == REMITENTE
               and f"La cuenta {email} de Empresa Registro A se ha activado en Canario con el rol instructor"
               in (avisos[0].get("texto") or ""))
    pasa(control, f"c) control: el admin de A recibe el aviso de la activacion, con la cuenta y el rol ({len(avisos)})")
    negativo("c) el aviso no lleva el token de invitacion ni el de dispositivo",
             control and token_invitacion not in avisos[0]["texto"]
             and (persona.dispositivo or "-") not in avisos[0]["texto"], control)
    negativo("c) la cuenta activada no recibe su propio aviso, ni el admin de otra empresa",
             not any(c["asunto"] == ASUNTO_ACTIVACION for c in correos_para(email) + correos_para(ADMINS["B"].email)),
             control)
    sesion = iniciar_sesion(persona) if activada else None
    yo = json_de(una(pt("GET", "/v1/personal/yo", token=sesion))) if sesion else {}
    pasa(bool(yo) and yo.get("rol") == "instructor" and yo.get("email") == email,
         f"c) y entra con el rol que eligio el admin ({(yo or {}).get('rol')})")
    filas = (json_de(una(pt("GET", "/v1/personal/auditoria", token=SESIONES["A"]))) or {}).get("filas", [])
    aprobaciones = [f for f in filas if f["accion"] == ACCION_APROBACION]
    pasa(len(aprobaciones) == 1 and aprobaciones[0]["objeto_id"] == datos.get("usuario_id")
         and aprobaciones[0]["actor"].startswith("personal:"),
         f"c) la aprobacion queda en la auditoria con el admin y la cuenta creada ({aprobaciones})")
    r = una(verificacion(token))
    pasa(es(r, 401, CUERPO_401), f"c) el enlace de verificacion ya usado da 401 ({r.get('estado')})")
    estado["c_ok"] = activada and sesion is not None


def seccion_d():
    p("=== d) enumeracion: misma respuesta, el correo solo lo lee el dueno, y el mismo tiempo")
    buzon("borrar")
    ident = EMPRESAS["A"][1]
    casos = {"empresa inexistente": registro(EMPRESA_INEXISTENTE, "inexistente@registro.test"),
             "email con cuenta": registro(ident, ADMINS["A"].email),
             "email nuevo": registro(ident, "otra.nueva@registro.test")}
    respuestas = dict(zip(casos, http(list(casos.values()))))
    # Todo menos la fecha, que cambia de una respuesta a otra.
    huellas = {k: (v.get("estado"), v.get("cuerpo"),
                   sorted((c, x) for c, x in (v.get("cabeceras") or {}).items() if c != "date"))
               for k, v in respuestas.items()}
    pasa(all(es(v, 202, CUERPO_202) for v in respuestas.values()) and len({repr(h) for h in huellas.values()}) == 1,
         f"d) las tres responden 202 con el mismo cuerpo y las mismas cabeceras ({[v.get('estado') for v in respuestas.values()]})")
    nuevo = esperar_correos("otra.nueva@registro.test", 1)
    aviso = esperar_correos(ADMINS["A"].email, 1)
    control = len(nuevo) == 1 and nuevo[0]["asunto"] == ASUNTO_VERIFICACION
    pasa(control, f"d) control: el email nuevo recibe su enlace de verificacion ({len(nuevo)})")
    negativo("d) el email con cuenta recibe un aviso, sin enlace",
             len(aviso) == 1 and aviso[0]["asunto"] == ASUNTO_AVISO_CUENTA and "https://" not in aviso[0]["texto"],
             control, f"correos: {aviso}")

    # Tiempos. La propiedad: la respuesta sale antes de tocar la base de
    # datos (app/solicitudes.py, procesar). Se afirma con dos comparaciones:
    # cada camino del registro tarda como un 422 (que no llega a la ruta) y
    # los tres caminos tardan lo mismo entre sí. Control de sensibilidad: una
    # verificación con un token desconocido de una empresa real, que SÍ
    # consulta la base de datos antes de responder, se distingue del 422 en
    # al menos CONTROL_TIEMPO_MS. La tolerancia es menor que ese efecto: si
    # no, la prueba aceptaría una fuga del tamaño de lo que dice ver.
    # Muestras intercaladas, cada email nuevo distinto (cada uno crea su
    # solicitud), y una pausa antes de cada petición para que la tarea de la
    # anterior haya terminado: lo que se mide es la respuesta de cada camino,
    # no la competencia con el trabajo de otro (ese residual queda
    # documentado en docs/threat-model.md, 8).
    caminos = ["inexistente", "cuenta", "nuevo", "sin_bd", "verificacion"]
    muestras = {k: [] for k in caminos}
    desconocido = f"{ident}.{'A' * 43}"
    for vuelta in range(10):
        tanda = []
        for i in range(4):
            tanda += [registro(EMPRESA_INEXISTENTE, "tiempos@registro.test"),
                      registro(ident, ADMINS["A"].email),
                      registro(ident, f"tiempo.{vuelta}.{i}@registro.test"),
                      pt("POST", "/v1/personal/registro", {"empresa": ident}),
                      verificacion(desconocido)]
        for peticion in tanda:
            peticion["pausa"] = PAUSA_TIEMPOS
        res = http(tanda)
        for j, nombre in enumerate(caminos * 4):
            if "ms" in res[j]:
                muestras[nombre].append(res[j]["ms"])
    # La empresa inexistente no deja ni correo ni fila. Se mira aquí, tras
    # las muestras de tiempo (decenas de segundos): su tarea se hace después
    # de responder, y mirarlo antes podría dar 0 solo porque aún no ha
    # terminado.
    negativo("d) para una empresa que no existe no sale ningun correo",
             correos_para("inexistente@registro.test") == [], control)
    filas = valor("select count(*) from canal.solicitud_registro where email = 'inexistente@registro.test';")
    negativo(f"d) ni se guarda nada ({filas} filas)", filas == "0", control)
    mediana = {k: statistics.median(v) for k, v in muestras.items() if v}
    p("   medianas en ms: " + ", ".join(f"{k}={v:.2f}" for k, v in mediana.items()))
    if len(mediana) != len(caminos):
        sinc("d) faltan muestras de tiempo")
        return
    control = mediana["verificacion"] - mediana["sin_bd"] >= CONTROL_TIEMPO_MS
    detalle = f"control: una consulta a la base de datos no se distingue de un 422 ({mediana})"
    for camino in ("inexistente", "cuenta", "nuevo"):
        negativo(f"d) tiempos: el registro ({camino}) tarda como un 422, sin base de datos antes de responder "
                 f"(menos de {TOLERANCIA_TIEMPO_MS} ms)",
                 mediana[camino] - mediana["sin_bd"] < TOLERANCIA_TIEMPO_MS, control, detalle)
    for a, b in (("inexistente", "cuenta"), ("inexistente", "nuevo"), ("cuenta", "nuevo")):
        negativo(f"d) tiempos: {a} y {b} difieren menos de {TOLERANCIA_TIEMPO_MS} ms",
                 abs(mediana[a] - mediana[b]) < TOLERANCIA_TIEMPO_MS, control, detalle)


def seccion_e():
    p("=== e) verificacion: el mismo 401 para todo lo que no vale")
    buzon("borrar")
    ident_a, ident_b = EMPRESAS["A"][1], EMPRESAS["B"][1]
    http([registro(ident_a, "e.uno@registro.test"), registro(ident_a, "e.dos@registro.test"),
          registro(ident_b, "e.tres@registro.test")])
    tokens = {}
    for email in ("e.uno@registro.test", "e.dos@registro.test", "e.tres@registro.test"):
        correos = esperar_correos(email, 1)
        tokens[email] = token_de(correos[0], PATRON_VERIFICACION) if correos else None
    if None in tokens.values():
        sinc(f"e) no llegaron los tres correos de verificacion ({tokens})")
        return
    uno, dos, tres = tokens.values()
    # Un token de verificación no sirve como invitación (etiquetas distintas).
    r = una(pt("POST", "/v1/personal/activacion", {"token": uno, "contrasena": "una-contrasena-larga"}))
    pasa(es(r, 401, CUERPO_401_INVITACION), f"e) el token de verificacion no vale como invitacion ({r.get('estado')})")
    # El token con el identificador de otra empresa: la huella no existe en ella.
    cruzado = ident_b + "." + uno.split(".")[1]
    # Caducado: se adelanta su caducidad como superusuario con el trigger
    # desactivado solo en esa transacción.
    sup("BEGIN;\nALTER TABLE canal.solicitud_registro DISABLE TRIGGER solicitud_registro_transicion;\n"
        "UPDATE canal.solicitud_registro SET caduca = now() - interval '1 second' WHERE email = 'e.dos@registro.test';\n"
        "ALTER TABLE canal.solicitud_registro ENABLE TRIGGER solicitud_registro_transicion;\nCOMMIT;\n")
    malos = {"desconocido": f"{ident_a}.{'A' * 43}", "mal formado": "no-es-un-token",
             "empresa inexistente": f"{EMPRESA_INEXISTENTE}.{uno.split('.')[1]}",
             "de otra empresa": cruzado, "caducado": dos, "vacio": ""}
    respuestas = dict(zip(malos, http([verificacion(t) for t in malos.values()])))
    control = una(verificacion(uno))
    control_ok = control.get("estado") == 204
    pasa(control_ok, f"e) control: el token bueno verifica despues de todos los malos ({control.get('estado')})")
    for nombre, r in respuestas.items():
        negativo(f"e) token {nombre} -> 401 con el mismo cuerpo ({r.get('estado')})", es(r, 401, CUERPO_401), control_ok)
    r = una(verificacion(tres))
    pasa(r.get("estado") == 204, f"e) el de la empresa B verifica en B ({r.get('estado')})")


def seccion_f():
    p("=== f) administracion de solicitudes")
    buzon("borrar")
    ident = EMPRESAS["A"][1]
    # Un rol (o una contraseña) en el cuerpo: 422 y nada creado.
    con_rol = pt("POST", "/v1/personal/registro", {"empresa": ident, "email": "f.rol@registro.test", "rol": "admin"})
    con_contrasena = pt("POST", "/v1/personal/registro",
                        {"empresa": ident, "email": "f.rol@registro.test", "contrasena": "x" * 20})
    r1, r2 = http([con_rol, con_contrasena])
    filas = valor("select count(*) from canal.solicitud_registro where email = 'f.rol@registro.test';")
    pasa(es(r1, 422, CUERPO_422) and es(r2, 422, CUERPO_422) and filas == "0",
         f"f) un rol o una contrasena en el cuerpo del registro -> 422 sin crear nada ({r1.get('estado')}, "
         f"{r2.get('estado')}, {filas} filas)")
    # Dos solicitudes verificadas en A.
    emails = ["f.cruzada@registro.test", "f.rechazada@registro.test", "f.duplicada@registro.test"]
    http([registro(ident, e) for e in emails])
    for e in emails:
        correos = esperar_correos(e, 1)
        token = token_de(correos[0], PATRON_VERIFICACION) if correos else None
        if token is None or una(verificacion(token)).get("estado") != 204:
            sinc(f"f) no se pudo preparar la solicitud verificada de {e}")
            return
    ids = {e: id_de(SESIONES["A"], e) for e in emails}
    control = all(ids.values())
    pasa(control, "f) control: las tres solicitudes verificadas aparecen al admin de A")
    # B no ve las de A, y aprobar una de A desde B es el 404 de lo inexistente.
    visto_b = [s["email"] for s in listado(SESIONES["B"]).get("solicitudes", [])]
    negativo(f"f) el admin de B no ve las solicitudes de A ({visto_b})", not set(visto_b) & set(emails), control)
    eventos_antes = log_de("api").count(TEXTO_EVENTO_DENEGADO)
    cuerpo, _ = con_totp(ADMINS["B"], {"rol": "admin"})  # el código es bueno: el 404 no lo gasta
    r = una(pt("POST", f"/v1/personal/solicitudes/{ids[emails[0]]}/aprobacion", cuerpo, token=SESIONES["B"]))
    negativo(f"f) aprobar desde B una solicitud de A -> 404 ({r.get('estado')})", es(r, 404, CUERPO_404), control)
    negativo("f) y deja EVENTO acceso_denegado", log_de("api").count(TEXTO_EVENTO_DENEGADO) > eventos_antes, control)
    sigue = id_de(SESIONES["A"], emails[0]) is not None
    negativo("f) la solicitud sigue pendiente en A", sigue, control)
    # Un instructor no administra solicitudes.
    instructor = Cuenta(ident, "f.instructor@registro.test")
    cuerpo, paso = con_totp(ADMINS["A"], {"email": instructor.email, "rol": "instructor"})
    r = una(pt("POST", "/v1/personal/usuarios", cuerpo, token=SESIONES["A"]))
    if r.get("estado") == 201:
        gastar(ADMINS["A"], paso)
    token_inv = (json_de(r) or {}).get("token_invitacion")
    sesion_instr = iniciar_sesion(instructor) if token_inv and activar(instructor, token_inv) else None
    if sesion_instr is None:
        sinc("f) no se pudo preparar la cuenta del instructor")
    else:
        lista = una(pt("GET", "/v1/personal/solicitudes", token=sesion_instr))
        # Con un código bueno de la propia cuenta: el 403 llega antes de mirarlo.
        cuerpo, _ = con_totp(instructor, {"rol": "admin"})
        aprueba = una(pt("POST", f"/v1/personal/solicitudes/{ids[emails[0]]}/aprobacion", cuerpo,
                         token=sesion_instr))
        rechaza = una(pt("DELETE", f"/v1/personal/solicitudes/{ids[emails[0]]}", token=sesion_instr))
        pasa(all(x.get("estado") == 403 for x in (lista, aprueba, rechaza)),
             f"f) un instructor recibe 403 al listar, aprobar y rechazar ({lista.get('estado')}, "
             f"{aprueba.get('estado')}, {rechaza.get('estado')})")
    # Rechazo: 204, se audita, y después ni aprobar ni rechazar (404).
    r = una(pt("DELETE", f"/v1/personal/solicitudes/{ids[emails[1]]}", token=SESIONES["A"]))
    pasa(r.get("estado") == 204, f"f) rechazar -> 204 ({r.get('estado')})")
    cuerpo, _ = con_totp(ADMINS["A"], {"rol": "instructor"})  # el 404 no gasta el código
    otra = una(pt("POST", f"/v1/personal/solicitudes/{ids[emails[1]]}/aprobacion", cuerpo, token=SESIONES["A"]))
    negativo(f"f) una rechazada ya no se aprueba (404, {otra.get('estado')})", es(otra, 404, CUERPO_404),
             r.get("estado") == 204)
    filas = (json_de(una(pt("GET", "/v1/personal/auditoria", token=SESIONES["A"]))) or {}).get("filas", [])
    pasa(any(f["accion"] == ACCION_RECHAZO and f["objeto_id"] == ids[emails[1]] for f in filas),
         "f) el rechazo queda en la auditoria con el id de la solicitud")
    pasa(correos_para(emails[1]) and all(c["asunto"] == ASUNTO_VERIFICACION for c in correos_para(emails[1])),
         "f) el rechazo no envia correo (solo esta el de verificacion)")
    # Un email que ya tiene cuenta: 409 y la solicitud sigue.
    cuerpo, paso = con_totp(ADMINS["A"], {"email": emails[2], "rol": "instructor"})
    r = una(pt("POST", "/v1/personal/usuarios", cuerpo, token=SESIONES["A"]))
    if r.get("estado") == 201:
        gastar(ADMINS["A"], paso)
    cuerpo, _ = con_totp(ADMINS["A"], {"rol": "instructor"})  # el 409 no gasta el código
    duplicada = una(pt("POST", f"/v1/personal/solicitudes/{ids[emails[2]]}/aprobacion", cuerpo,
                       token=SESIONES["A"]))
    negativo(f"f) aprobar un email que ya tiene cuenta -> 409 ({duplicada.get('estado')})",
             es(duplicada, 409, CUERPO_409), r.get("estado") == 201)
    # Una verificada no se sustituye: el nuevo registro da el mismo 202 y un aviso.
    buzon("borrar")
    r = una(registro(ident, emails[0]))
    avisos = esperar_correos(emails[0], 1)
    negativo("f) repetir el registro de una solicitud verificada: 202, aviso de pendiente y la solicitud sigue",
             es(r, 202, CUERPO_202) and len(avisos) == 1 and avisos[0]["asunto"] == ASUNTO_AVISO_PENDIENTE
             and "https://" not in avisos[0]["texto"] and id_de(SESIONES["A"], emails[0]) == ids[emails[0]],
             control, f"respuesta {r.get('estado')}, correos {avisos}")
    # Una sin verificar sí se sustituye: el enlace anterior deja de valer y el nuevo vale.
    http([registro(ident, "f.repetida@registro.test")])
    primero = esperar_correos("f.repetida@registro.test", 1)
    http([registro(ident, "f.repetida@registro.test")])
    ambos = esperar_correos("f.repetida@registro.test", 2)
    viejo = token_de(primero[0], PATRON_VERIFICACION) if primero else None
    nuevos = [token_de(c, PATRON_VERIFICACION) for c in ambos]
    nuevo = next((t for t in nuevos if t and t != viejo), None)
    if viejo is None or nuevo is None:
        sinc(f"f) no llegaron los dos enlaces de la solicitud repetida ({len(ambos)})")
    else:
        r_viejo, r_nuevo = una(verificacion(viejo)), una(verificacion(nuevo))
        negativo(f"f) repetir una sin verificar invalida el enlace anterior ({r_viejo.get('estado')})",
                 es(r_viejo, 401, CUERPO_401), r_nuevo.get("estado") == 204, f"nuevo: {r_nuevo.get('estado')}")
    # Aprobación con un rol que no existe: 422.
    cuerpo, _ = con_totp(ADMINS["A"], {"rol": "superadmin"})  # el 422 llega antes del código
    r = una(pt("POST", f"/v1/personal/solicitudes/{ids[emails[0]]}/aprobacion", cuerpo, token=SESIONES["A"]))
    pasa(es(r, 422, CUERPO_422), f"f) aprobar con un rol que no existe -> 422 ({r.get('estado')})")
    # El tercer rol, auditor, tambien se aprueba: la cuenta nace con ese rol.
    cuerpo, paso = con_totp(ADMINS["A"], {"rol": "auditor"})
    r = una(pt("POST", f"/v1/personal/solicitudes/{ids[emails[0]]}/aprobacion", cuerpo, token=SESIONES["A"]))
    if r.get("estado") == 201:
        gastar(ADMINS["A"], paso)
    rol = valor(f"select rol from canal.usuario_personal where email = '{emails[0]}';")
    pasa(r.get("estado") == 201 and rol == "auditor",
         f"f) aprobar con el rol auditor -> 201 y la cuenta nace con ese rol ({r.get('estado')}, {rol!r})")


def seccion_m():
    p("=== m) step-up TOTP de la aprobacion: sin codigo, con codigo malo y con codigo repetido no se aprueba")
    buzon("borrar")
    ident = EMPRESAS["A"][1]
    email = "m.stepup@registro.test"
    http([registro(ident, email)])
    correos = esperar_correos(email, 1)
    token = token_de(correos[0], PATRON_VERIFICACION) if correos else None
    if token is None or una(verificacion(token)).get("estado") != 204:
        sinc("m) no se pudo preparar la solicitud verificada")
        return
    solicitud = id_de(SESIONES["A"], email)
    control = solicitud is not None
    pasa(control, "m) control: la solicitud verificada aparece al admin de A")
    if not control:
        return
    ruta = f"/v1/personal/solicitudes/{solicitud}/aprobacion"

    def sin_efecto(nombre, r, estado_http, cuerpo_http):
        """El código HTTP y el cuerpo esperados, y que nada cambió: la solicitud
        sigue abierta, no hay cuenta nueva y no ha salido correo de invitación."""
        abiertas = id_de(SESIONES["A"], email) == solicitud
        cuentas = valor(f"select count(*) from canal.usuario_personal where email = '{email}';")
        invitaciones = [c for c in correos_para(email) if c["asunto"] == ASUNTO_INVITACION]
        negativo(f"m) {nombre} -> {estado_http} ({r.get('estado')})", es(r, estado_http, cuerpo_http), control)
        negativo(f"m) {nombre}: la solicitud sigue abierta, sin cuenta nueva ni correo de invitacion "
                 f"({abiertas}, {cuentas} cuentas, {len(invitaciones)} correos)",
                 abiertas and cuentas == "0" and not invitaciones, control)

    # Sin codigo_totp: 422 (falta un campo del cuerpo).
    r = una(pt("POST", ruta, {"rol": "instructor"}, token=SESIONES["A"]))
    sin_efecto("aprobar sin codigo_totp", r, 422, CUERPO_422)
    # Código malo: se elige uno que no sea el del paso anterior, el actual ni el siguiente.
    validos = {totp(ADMINS["A"].secreto, int(time.time()) // 30 + d) for d in (-1, 0, 1)}
    malo = next(c for c in ("000000", "111111", "222222") if c not in validos)
    r = una(pt("POST", ruta, {"rol": "instructor", "codigo_totp": malo}, token=SESIONES["A"]))
    sin_efecto("aprobar con un codigo_totp malo", r, 401, CUERPO_401_CREDENCIALES)
    negativo("m) el 401 del codigo malo no lleva WWW-Authenticate",
             "www-authenticate" not in (r.get("cabeceras") or {}), control and r.get("estado") == 401,
             f"cabeceras {sorted(r.get('cabeceras') or {})}")
    # Control positivo: con un código bueno se aprueba (201), la cuenta existe y llega la invitación.
    cuerpo, paso = con_totp(ADMINS["A"], {"rol": "instructor"})
    bueno = una(pt("POST", ruta, cuerpo, token=SESIONES["A"]))
    if bueno.get("estado") == 201:
        gastar(ADMINS["A"], paso)
    cuentas = valor(f"select count(*) from canal.usuario_personal where email = '{email}';")
    invitaciones = [c for c in esperar_correos(email, 2) if c["asunto"] == ASUNTO_INVITACION]
    control_repetido = bueno.get("estado") == 201 and cuentas == "1" and len(invitaciones) == 1
    pasa(control_repetido,
         f"m) control: con un codigo bueno se aprueba (201), la cuenta existe y llega la invitacion "
         f"({bueno.get('estado')}, {cuentas} cuentas, {len(invitaciones)} correos)")
    # Código repetido: el que acaba de gastarse, sobre otra solicitud verificada.
    otro = "m.repetido@registro.test"
    http([registro(ident, otro)])
    correos = esperar_correos(otro, 1)
    token = token_de(correos[0], PATRON_VERIFICACION) if correos else None
    otra = id_de(SESIONES["A"], otro) if token and una(verificacion(token)).get("estado") == 204 else None
    if otra is None:
        sinc("m) no se pudo preparar la segunda solicitud para el codigo repetido")
        return
    repetido = una(pt("POST", f"/v1/personal/solicitudes/{otra}/aprobacion", cuerpo, token=SESIONES["A"]))
    cuentas = valor(f"select count(*) from canal.usuario_personal where email = '{otro}';")
    invitaciones = [c for c in correos_para(otro) if c["asunto"] == ASUNTO_INVITACION]
    abierta = id_de(SESIONES["A"], otro) == otra
    negativo(f"m) aprobar con un codigo ya usado -> 401 sin WWW-Authenticate ({repetido.get('estado')})",
             es(repetido, 401, CUERPO_401_CREDENCIALES) and "www-authenticate" not in (repetido.get("cabeceras") or {}),
             control_repetido)
    negativo(f"m) el codigo repetido no aprueba: la solicitud sigue abierta, sin cuenta ni correo "
             f"({abierta}, {cuentas} cuentas, {len(invitaciones)} correos)",
             abierta and cuentas == "0" and not invitaciones, control_repetido)


def seccion_g():
    p("=== g) CR, LF y NUL en el email: 422 sin crear nada ni enviar correo")
    buzon("borrar")
    ident = EMPRESAS["A"][1]
    malos = ["g@registro.test\r\nBcc: otro@registro.test", "g@registro.test\nBcc: otro@registro.test",
             "g@registro.test\x00", "g\x00@registro.test", "g@registro.test\r"]
    respuestas = http([pt("POST", "/v1/personal/registro", {"empresa": ident, "email": m}) for m in malos])
    control = una(registro(ident, "g@registro.test"))
    control_ok = es(control, 202, CUERPO_202)
    for m, r in zip(malos, respuestas):
        negativo(f"g) email {m!r} -> 422 ({r.get('estado')})", es(r, 422, CUERPO_422), control_ok)
    llegados = esperar_correos("g@registro.test", 1)
    otros = [c for c in buzon() if c["para"] != ["g@registro.test"]]
    filas = valor("select count(*) from canal.solicitud_registro where email like 'g@%' or email like 'g%otro%';")
    negativo(f"g) solo existe la solicitud y el correo del control ({filas} filas, {len(otros)} correos ajenos)",
             filas == "1" and not otros and len(llegados) == 1, control_ok)


def seccion_h():
    p("=== h) limite por destinatario con el valor de produccion (3 cada 15 minutos)")
    con_limites(LIMITES_DESTINATARIO)
    ident = EMPRESAS["A"][1]
    # Las cuatro, dentro de la misma ventana de 15 minutos.
    while VENTANA_DESTINATARIO - int(time.time()) % VENTANA_DESTINATARIO < 120:
        time.sleep(10)
    antes = len(eventos_que_acaban(EVENTO_DESTINATARIO))
    res = http([registro(ident, "h.buzon@registro.test") for _ in range(4)]
               + [registro(EMPRESA_INEXISTENTE, "h.buzon@registro.test"), registro(ident, "h.otro@registro.test")])
    control = all(es(r, 202, CUERPO_202) for r in res[:3]) and es(res[5], 202, CUERPO_202)
    pasa(control, f"h) control: tres registros al mismo email y uno a otro pasan ({[r.get('estado') for r in res]})")
    for etiqueta, r in (("el cuarto", res[3]), ("el quinto, con otra empresa", res[4])):
        espera = (r.get("cabeceras") or {}).get("retry-after", "")
        negativo(f"h) {etiqueta} al mismo email -> 429 con Retry-After ({r.get('estado')}, {espera!r})",
                 es(r, 429, CUERPO_429) and espera.isdigit() and 1 <= int(espera) <= VENTANA_DESTINATARIO, control)
    eventos = eventos_que_acaban(EVENTO_DESTINATARIO)
    negativo(f"h) un solo EVENTO limite_destinatario con regla=destinatario, sin el email ({len(eventos) - antes})",
             len(eventos) - antes == 1 and not any("@" in l for l in eventos), control)

    p("=== h) limite diario por destinatario (configurado en 2 al dia)")
    con_limites(LIMITES_DESTINATARIO_DIA)
    # Lejos de las 00:00 UTC: el tercero cae en el mismo día y lo que falta
    # para medianoche supera los 15 minutos de la otra regla (si no, los dos
    # Retry-After no se distinguirían).
    while SEGUNDOS_DIA - int(time.time()) % SEGUNDOS_DIA < VENTANA_DESTINATARIO + 100:
        time.sleep(10)
    antes = len(eventos_que_acaban(EVENTO_DESTINATARIO_DIA))
    res = http([registro(ident, "h.dia@registro.test") for _ in range(3)] + [registro(ident, "h.dia.otro@registro.test")])
    hasta_medianoche = SEGUNDOS_DIA - int(time.time()) % SEGUNDOS_DIA
    control = all(es(r, 202, CUERPO_202) for r in res[:2]) and es(res[3], 202, CUERPO_202)
    pasa(control, f"h) control: dos registros al mismo email y uno a otro pasan ({[r.get('estado') for r in res]})")
    espera = (res[2].get("cabeceras") or {}).get("retry-after", "")
    # El Retry-After es lo que falta para las 00:00 UTC (la ventana del día),
    # no los 15 minutos de la otra regla: con un margen por el reloj.
    negativo(f"h) el tercero -> 429 con Retry-After hasta las 00:00 UTC ({res[2].get('estado')}, {espera!r}, "
             f"faltan {hasta_medianoche} s)",
             es(res[2], 429, CUERPO_429) and espera.isdigit()
             and abs(int(espera) - hasta_medianoche) <= 30 and int(espera) > VENTANA_DESTINATARIO, control)
    eventos = eventos_que_acaban(EVENTO_DESTINATARIO_DIA)
    negativo(f"h) un solo EVENTO limite_destinatario con regla=destinatario_dia, sin el email ({len(eventos) - antes})",
             len(eventos) - antes == 1 and not any("@" in l for l in eventos), control)
    con_limites(LIMITES_PRUEBA)


def seccion_i():
    p("=== i) sin el cartero o sin Mailpit la respuesta no cambia y el fallo queda en el log, sin datos")
    ident = EMPRESAS["A"][1]
    # Sin el cartero: el fallo queda en el log de la API (no puede hablar con
    # el cartero). El contenedor parado deja de resolverse por su nombre.
    dc("stop", "cartero")
    try:
        antes = log_de("api").count(TEXTO_EVENTO_CORREO)
        r = una(registro(ident, "i.sin.cartero@registro.test"))
        aparece = esperar(lambda: log_de("api").count(TEXTO_EVENTO_CORREO) > antes, 30)
    finally:
        arranca = ejecutar(BASE + ["up", "-d", "--wait", "cartero"])
    pasa(arranca.rc == 0, f"i) el cartero vuelve a arrancar (codigo {arranca.rc})")
    pasa(es(r, 202, CUERPO_202), f"i) con el cartero parado, el registro responde el mismo 202 ({r.get('estado')})")
    eventos = [l for l in log_de("api").splitlines() if TEXTO_EVENTO_CORREO in l]
    pasa(aparece and not any("@" in l for l in eventos),
         f"i) el fallo deja EVENTO correo_fallido con el tipo y la clase del error, sin el email ({eventos[-1:]})")
    # Sin Mailpit: la API entrega al cartero sin problema (202 del cartero); el
    # fallo es del cartero, que aplaza el correo (temporal) y lo registra.
    # Mailpit al volver recibe el reintento a los 60 s: no afecta a j ni k.
    antes = log_cartero().count(TEXTO_CARTERO_APLAZADO)
    dc("stop", "mailpit")
    try:
        r = una(registro(ident, "i.sin.correo@registro.test"))
        aplazado = esperar(lambda: log_cartero().count(TEXTO_CARTERO_APLAZADO) > antes, 30)
    finally:
        dc("start", "mailpit")
    pasa(es(r, 202, CUERPO_202), f"i) con Mailpit parado, el registro responde el mismo 202 ({r.get('estado')})")
    eventos = [l for l in log_cartero().splitlines() if TEXTO_CARTERO_APLAZADO in l]
    pasa(aplazado and not any("@" in l for l in eventos),
         f"i) el cartero deja EVENTO correo_aplazado con el tipo y el motivo, sin el email ({eventos[-1:]})")
    textos = {s: log_de(s) for s in ("api", "postgres", "redis", "mailpit")}
    textos["cartero"] = log_cartero()
    control = bool(SENSIBLES) and estado.get("c_ok", False)
    fugas = sorted({f"{s}" for s, t in textos.items() for v in SENSIBLES if v and v in t
                    and s not in ("mailpit", "cartero")})
    negativo(f"i) ningun email, token ni enlace de la bateria aparece en los logs de api, postgres y redis {fugas}",
             not fugas, control)
    negativo("i) los logs de la API no llevan la ruta de la SPA con un token",
             "#" + ident not in textos["api"], estado.get("c_ok", False))
    # El cartero. Control: su log SI registra las entregas (si no registrara
    # nada, que no haya rastro no diría nada) y la batería tiene datos.
    control_cartero = control and TEXTO_CARTERO_ENTREGADO in textos["cartero"]
    fugas_cartero = sum(1 for v in SENSIBLES if v and v in textos["cartero"])
    negativo(f"i) ningun email, token ni enlace de la bateria aparece en el log del cartero ({fugas_cartero} coincidencias)",
             fugas_cartero == 0 and "https://" not in textos["cartero"], control_cartero,
             "control: el log del cartero no tiene EVENTO correo_entregado")


def seccion_j():
    p("=== j) sin CANARIO_ORIGEN_PERSONAL, o mal formado, la API no arranca")
    d = TEMPORAL / "falsos"
    d.mkdir()
    ficheros = {"contrasena_aplicacion": secrets.token_urlsafe(48), "clave_maestra": secrets.token_hex(32),
                "clave_hmac_codigos": secrets.token_hex(32), "clave_firma_tokens": secrets.token_hex(32),
                "clave_hmac_identidades": secrets.token_hex(32), "clave_flujo_externo": secrets.token_hex(32),
                "contrasena_redis": secrets.token_urlsafe(48)}
    montajes = []
    for nombre, contenido in ficheros.items():
        (d / nombre).write_text(contenido, encoding="ascii", newline="")
        montajes += ["--mount", f"type=bind,src={d / nombre},dst=/run/secrets/{nombre},readonly"]

    def arrancar(etiqueta, entorno):
        nombre = f"{PROYECTO}_api_{etiqueta}"
        variables = [a for k, v in entorno.items() for a in ("-e", f"{k}={v}")]
        ejecutar(["docker", "run", "-d", "--name", nombre, "--network", f"{PROYECTO}_data", "--read-only",
                  "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", *montajes, *variables, IMAGEN_API])
        try:
            esperar(lambda: ejecutar(["docker", "inspect", "--format", "{{.State.Running}}", nombre]).out.strip()
                    == "false", 60)
            return ejecutar(["docker", "logs", nombre]).todo
        finally:
            ejecutar(["docker", "rm", "-f", nombre])
    control = arrancar("control", {"CANARIO_ORIGEN_PERSONAL": ORIGEN_PERSONAL})
    control_ok = TEXTO_ORIGEN in control and f"{TEXTO_BLOQUEADO}conexion" in control
    pasa(control_ok, "j) control: con el origen bien formado la API lo registra y llega a la conexion "
                     "(que falla por la contrasena falsa)")
    casos = {
        "sin variable": ({}, "origen_personal: CANARIO_ORIGEN_PERSONAL: obligatoria (origen https de la SPA del personal)"),
        "http": ({"CANARIO_ORIGEN_PERSONAL": "http://localhost:8445"},
                 "origen_personal: CANARIO_ORIGEN_PERSONAL: se espera https://host o https://host:puerto, en minusculas"),
        "con ruta": ({"CANARIO_ORIGEN_PERSONAL": "https://localhost:8445/"},
                     "origen_personal: CANARIO_ORIGEN_PERSONAL: se espera https://host o https://host:puerto, en minusculas"),
        "puerto 443": ({"CANARIO_ORIGEN_PERSONAL": "https://localhost:443"},
                       "origen_personal: CANARIO_ORIGEN_PERSONAL: puerto no valido (el 443 se omite)"),
    }
    for etiqueta, (entorno, motivo) in casos.items():
        log = arrancar(etiqueta.replace(" ", "_"), entorno)
        negativo(f"j) {etiqueta}: la API no arranca y registra {TEXTO_BLOQUEADO + motivo!r}",
                 TEXTO_BLOQUEADO + motivo in log and f"{TEXTO_BLOQUEADO}conexion" not in log, control_ok,
                 f"log: {log.strip()[-300:]!r}")


def seccion_k():
    p("=== k) con PostgreSQL parado, el registro responde el mismo 202 al momento y el fallo queda en el log")
    # La última sección: deja PostgreSQL parado unos segundos y la API con
    # su pool reconectando.
    ident = EMPRESAS["A"][1]
    control = una(registro(ident, "k.control@registro.test"))
    control_ok = es(control, 202, CUERPO_202) and len(esperar_correos("k.control@registro.test", 1)) == 1
    pasa(control_ok, f"k) control: con PostgreSQL en marcha, 202 y llega el correo ({control.get('estado')})")
    antes = log_de("api").count(TEXTO_EVENTO_REGISTRO_FALLIDO)
    dc("stop", "postgres")
    try:
        r = una(registro(ident, "k.sin.bd@registro.test"))
        # El pool se rinde a los 10 s (app/bd.py); el evento sale después.
        aparece = esperar(lambda: log_de("api").count(TEXTO_EVENTO_REGISTRO_FALLIDO) > antes, 60)
    finally:
        arranca = ejecutar(BASE + ["up", "-d", "--wait", "postgres"])
    ms = r.get("ms", float("inf"))
    negativo(f"k) sin PostgreSQL: el mismo 202, en menos de {MAXIMO_SIN_BD_MS} ms ({r.get('estado')}, {ms:.0f} ms)",
             es(r, 202, CUERPO_202) and ms < MAXIMO_SIN_BD_MS, control_ok)
    eventos = [l for l in log_de("api").splitlines() if TEXTO_EVENTO_REGISTRO_FALLIDO in l]
    negativo(f"k) el fallo deja EVENTO registro_fallido con la clase del error, sin el email ({eventos[-1:]})",
             aparece and not any("@" in l for l in eventos), control_ok)
    negativo("k) y no sale ningun correo", correos_para("k.sin.bd@registro.test") == [], control_ok)
    # Ni en el evento ni en ninguna otra línea (un traceback de uvicorn con
    # el texto del error, por ejemplo).
    negativo("k) el email no aparece en ninguna linea del log de la API",
             "k.sin.bd@registro.test" not in log_de("api"), control_ok)
    pasa(arranca.rc == 0, f"k) PostgreSQL vuelve a arrancar (codigo {arranca.rc})")


def seccion_n():
    p("=== n) el cartero fija el remitente, desactiva el seguimiento y pone el pie en todo correo")
    ident = EMPRESAS["A"][1]
    buzon("borrar")
    # Dos tipos de correo distintos: verificacion y aviso_cuenta.
    http([registro(ident, "n.nuevo@registro.test"), registro(ident, ADMINS["A"].email)])
    esperar_correos("n.nuevo@registro.test", 1)
    esperar_correos(ADMINS["A"].email, 1)
    completos = correos_completos()
    asuntos = {c["asunto"] for c in completos}
    # Control: llegaron los dos y la API de cabeceras de Mailpit responde de
    # verdad (cada mensaje trae su Subject). Sin esto, "todos cumplen" podría
    # ser sobre una lista vacia o sobre cabeceras que no se leyeron.
    control = {ASUNTO_VERIFICACION, ASUNTO_AVISO_CUENTA} <= asuntos and all(
        c["cabeceras"].get("subject") for c in completos)
    if not control:
        sinc(f"n) no llegaron los dos correos o no se leen las cabeceras ({sorted(asuntos)})")
        return
    pasa(True, f"n) control: llegan los correos de verificacion y de aviso y sus cabeceras se leen ({len(completos)} correos)")

    def todos(cabecera, esperado):
        return all(c["cabeceras"].get(cabecera) == esperado for c in completos)
    pasa(todos("from", [DE_CORREO]),
         f"n) todos llevan From {DE_CORREO!r} ({[c['cabeceras'].get('from') for c in completos]})")
    pasa(todos("x-mailjet-trackclick", ["0"]),
         f"n) todos llevan X-Mailjet-TrackClick: 0 ({[c['cabeceras'].get('x-mailjet-trackclick') for c in completos]})")
    pasa(todos("x-mailjet-trackopen", ["0"]),
         f"n) todos llevan X-Mailjet-TrackOpen: 0 ({[c['cabeceras'].get('x-mailjet-trackopen') for c in completos]})")
    ids = [c["cabeceras"].get("message-id") or [""] for c in completos]
    pasa(all(len(i) == 1 and i[0].endswith(FIN_MESSAGE_ID) for i in ids),
         f"n) todos llevan un Message-ID con el dominio del remitente ({ids})")
    pasa(all((c["cuerpo"] or "").endswith(PIE_CORREO) for c in completos),
         f"n) todos terminan con el pie de Canario ({[(c['cuerpo'] or '')[-60:] for c in completos]!a})")


def seccion_o():
    p("=== o) el cartero solo atiende a la IP de la API")
    destinatario = "o.intruso@registro.test"
    SENSIBLES.add(destinatario)
    buzon("borrar")
    antes = log_cartero().count(TEXTO_CARTERO_RECHAZADO)
    r = ejecutar(["docker", "run", "--rm", "--network", f"{PROYECTO}_correo", "--read-only", "--cap-drop", "ALL",
                  "--security-opt", "no-new-privileges:true", "--entrypoint", "python", IMAGEN_API, "-c",
                  CLIENTE_CARTERO, destinatario])
    try:
        res = json.loads(r.out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise Parada(f"el cliente del cartero no devolvio resultado: {r.err.strip()[-400:]!r}") from None
    salud, correos_http = res["salud"], res["correos"]

    def cuerpo_json(respuesta):
        try:
            return json.loads(respuesta.get("cuerpo", ""))
        except ValueError:
            return None
    # Control: desde el mismo contenedor, /salud llega y da 200. Así la red
    # funciona y el 403 de /correos es por la IP, no por no llegar.
    control = salud.get("estado") == 200 and cuerpo_json(salud) == CUERPO_CARTERO_SALUD
    pasa(control, f"o) control: GET /salud desde otro contenedor de la red correo da 200 ({salud})")
    negativo(f"o) POST /correos desde otro contenedor de la red correo -> 403 ({correos_http.get('estado')})",
             correos_http.get("estado") == 403 and cuerpo_json(correos_http) == CUERPO_CARTERO_PROHIBIDO, control,
             f"respuesta: {correos_http}")
    esperar(lambda: log_cartero().count(TEXTO_CARTERO_RECHAZADO) > antes, 15)
    lineas = [l for l in log_cartero().splitlines() if TEXTO_CARTERO_RECHAZADO in l]
    negativo(f"o) y deja EVENTO cartero_cliente_rechazado con la ruta, sin la IP ni el destinatario "
             f"({len(lineas) - antes} nuevo)",
             len(lineas) - antes == 1 and not any("@" in l or "10.88." in l for l in lineas), control)
    # El rechazo es síncrono (middleware, antes de leer el cuerpo), pero la
    # entrega, si se hubiera aceptado, tardaría unos instantes: se espera un
    # poco antes de afirmar que no llegó.
    time.sleep(5)
    negativo("o) y no sale ningun correo", correos_para(destinatario) == [], control)


def seccion_q():
    p("=== q) TLS del cartero: con una CA ajena el correo no sale y el motivo es el certificado")
    ident = EMPRESAS["A"][1]
    buzon("borrar")
    antes_ok, ajeno, despues_ok = "q.antes@registro.test", "q.ajena@registro.test", "q.despues@registro.test"
    r = una(registro(ident, antes_ok))
    llega_antes = es(r, 202, CUERPO_202) and len(esperar_correos(antes_ok, 1)) == 1
    pasa(llega_antes, "q) control: con la CA buena, el correo llega a Mailpit (verificado por TLS)")
    LOGS_CARTERO_PREVIOS.append(log_de("cartero"))
    recreado = montado = aparece = False
    log_ajena = ""
    montaje = []
    try:
        arranque = ejecutar(BASE + ["-f", str(CA_AJENA_YML), "up", "-d", "--force-recreate", "--wait", "cartero"])
        recreado = arranque.rc == 0
        montaje = montaje_ca("cartero") if recreado else []
        montado = len(montaje) == 1 and montaje[0][0].endswith("ca_ajena.pem")
        if recreado and montado:
            una(registro(ident, ajeno))
            aparece = esperar(lambda: TEXTO_CARTERO_CERTIFICADO in log_de("cartero"), 60)
            log_ajena = log_de("cartero")
    finally:
        # Siempre se vuelve a la CA buena, pase lo que pase en la prueba.
        LOGS_CARTERO_PREVIOS.append(log_de("cartero"))
        restaurado = ejecutar(BASE + ["up", "-d", "--force-recreate", "--wait", "cartero"])
    montaje_buena = montaje_ca("cartero")
    r = una(registro(ident, despues_ok))
    llega_despues = es(r, 202, CUERPO_202) and len(esperar_correos(despues_ok, 1)) == 1
    # El control de los tres negativos: el cartero confiaba de verdad en la CA
    # ajena (montaje comprobado) y, con la buena, antes y despues, el correo
    # llega.
    control = (llega_antes and llega_despues and restaurado.rc == 0 and recreado and montado
               and len(montaje_buena) == 1 and montaje_buena[0][0].endswith("correo_ca.pem"))
    pasa(control, f"q) control: el cartero se vuelve a crear con la CA ajena ({montaje}) y despues con la buena; "
                  f"con la buena llega el correo ({llega_antes}, {llega_despues}, {restaurado.rc})")
    negativo("q) con una CA ajena, el correo no llega a Mailpit", aparece and correos_para(ajeno) == [], control,
             f"evento certificado: {aparece}")
    lineas = [l for l in log_ajena.splitlines() if TEXTO_CARTERO_CERTIFICADO in l]
    negativo(f"q) el log del cartero tiene EVENTO correo_fallido con motivo=certificado, sin el email ({lineas[-1:]})",
             len(lineas) == 1 and "@" not in lineas[0], control)
    negativo("q) y es definitivo: ningun EVENTO correo_aplazado (no hay reintento)",
             "EVENTO correo_aplazado" not in log_ajena, control and aparece)


def buzon_herramienta(proyecto, *extra):
    """scripts/buzon.py tal cual lo usa una persona, con el proyecto dado."""
    return ejecutar([sys.executable, str(RAIZ / "scripts" / "buzon.py"), "--proyecto", proyecto,
                     "--limite", str(LIMITE_BUZON), *extra], timeout=120)


def seccion_l():
    p("=== l) la herramienta del buzon de desarrollo ensena el correo con su enlace, o falla de forma visible")
    ident = EMPRESAS["A"][1]
    email = "l.buzon@registro.test"
    r = una(registro(ident, email))
    correos = esperar_correos(email, 1)
    token = token_de(correos[0], PATRON_VERIFICACION) if correos else None
    if r.get("estado") != 202 or token is None:
        sinc(f"l) sin un correo de verificacion no hay oraculo ({r.get('estado')}, {len(correos)} correos)")
        return
    # Oráculo: el enlace entero, con el origen literal y el token que leyó el
    # lector propio de la batería (LECTOR_CORREO), no la herramienta.
    enlace = f"{ORIGEN_PERSONAL}/registro/verificacion#{token}"
    r = buzon_herramienta(PROYECTO)
    lineas = [linea.strip() for linea in r.out.splitlines()]
    control = r.rc == 0 and enlace in lineas
    # Sin volcar la salida: lleva tokens.
    pasa(control, f"l) control: con Mailpit, la herramienta sale con 0 y muestra el enlace entero en su linea "
                  f"(codigo {r.rc}, {len(lineas)} lineas)")
    pasa(control and f"Asunto: {ASUNTO_VERIFICACION}" in lineas and f"Para:   {email}" in lineas,
         "l) y el asunto y el destinatario del correo de verificacion")
    # --texto. Control: sin --texto, la línea del texto no sale, así que si
    # sale es por la opción.
    con_texto = buzon_herramienta(PROYECTO, "--texto")
    lineas_texto = [linea.strip() for linea in con_texto.out.splitlines()]
    negativo("l) con --texto ensena tambien el texto del correo, con el enlace en su linea",
             con_texto.rc == 0 and LINEA_TEXTO_VERIFICACION in lineas_texto and enlace in lineas_texto,
             control and LINEA_TEXTO_VERIFICACION not in lineas,
             f"(codigo {con_texto.rc}, {len(lineas_texto)} lineas)")
    # limpiar(). Control: un texto sin caracteres de control sale igual.
    # Entrada en JSON con escapes ASCII: por una tubería, Python en Windows
    # lee la entrada estándar en cp1252.
    r = ejecutar([sys.executable, "-I", "-c", PRUEBA_LIMPIEZA, str(RAIZ / "scripts" / "buzon.py")],
                 entrada=json.dumps([CON_CONTROL, SIN_CONTROL]).encode("ascii"), timeout=60)
    try:
        limpios = json.loads(r.out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        limpios = [None, None]
    negativo(f"l) la limpieza cambia por ? cada caracter de control ({limpios[0]!a})",
             limpios[0] == LIMPIO, limpios[1] == SIN_CONTROL,
             f"sin control: {limpios[1]!a}, error: {r.err.strip()[-200:]!r}")
    # Mailpit parado con la red correo en pie (la API sigue en ella): lo que
    # pasa al arrancar la pila sin el perfil desarrollo.
    dc("stop", "mailpit")
    try:
        sin = buzon_herramienta(PROYECTO)
    finally:
        dc("start", "mailpit")
    negativo("l) con Mailpit parado sale con 1 y un error claro, sin enlaces ni traza",
             sin.rc == 1 and sin.err.startswith(ERROR_BUZON) and "https://" not in sin.out
             and "Traceback" not in sin.todo, control,
             f"(codigo {sin.rc}, {sin.err.strip()[:200]!r})")


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
        iguales = final == ESTADO_GIT_ARRANQUE
        pasa(iguales, "s) la bateria no ha modificado el repo (git status igual al del arranque)")
        if not iguales:
            p(f"   al arrancar: {ESTADO_GIT_ARRANQUE}")
            p(f"   al terminar: {final}")


# ---------------------------------------------------------------------------
# Arranque y cierre
# ---------------------------------------------------------------------------
def terminar():
    if estado["falla"] or estado["sin_conclusion"]:
        resultado = "NO OK (hay FALLA o SIN CONCLUSION)"
    else:
        resultado = "OK"
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
    if r.rc != 0:
        return None
    return [l.rstrip() for l in r.out.splitlines() if l.strip()]


def recursos_previos():
    previos = []
    for orden in (["docker", "ps", "-a", "--format", "{{.Names}}"],
                  ["docker", "network", "ls", "--format", "{{.Name}}"],
                  ["docker", "volume", "ls", "--format", "{{.Name}}"]):
        previos += [n for n in ejecutar(orden).out.split() if n.startswith(PROYECTO)]
    return previos


def subred_ocupada():
    for red in ejecutar(["docker", "network", "ls", "-q"]).out.split():
        r = ejecutar(["docker", "network", "inspect", "--format",
                      "{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}", red])
        partes = r.out.split()
        if partes and {SUBRED_APP, SUBRED_CORREO} & set(partes[1:]):
            return partes[0]
    return None


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
    ocupada = subred_ocupada()
    if ocupada:
        p(f"PARADA: la subred {SUBRED_APP} o la {SUBRED_CORREO} ya esta en uso por {ocupada} "
          f"(pare el proyecto canario)")
        terminar_con_parada()
    TEMPORAL = pathlib.Path(tempfile.mkdtemp(prefix="canario_registro_"))
    escribir_auxiliares()
    r = dc("config", "--quiet")
    if r.rc != 0:
        p(f"PARADA: docker compose config falla (genere los secretos con scripts/generar_secretos.py): "
          f"{r.err.strip()[:300]}")
        shutil.rmtree(TEMPORAL, ignore_errors=True)
        terminar_con_parada()
    parada = None
    try:
        # l va antes de i: necesita la API y PostgreSQL sanos (k, la última,
        # deja el pool reconectando) y para Mailpit, que borra su buzón; i
        # también lo para (y el cartero) y no depende de correos anteriores.
        # n, o y q (el correo del cartero) van tras h y antes de l: q vuelve a
        # crear el cartero (se pierde su log, por eso LOGS_CARTERO_PREVIOS) y
        # deja el cupo diario de correo en cero, y l borra el buzon.
        for seccion in (seccion_a, seccion_b, seccion_c, seccion_d, seccion_e, seccion_f, seccion_m, seccion_g, seccion_h,
                        seccion_n, seccion_o, seccion_q, seccion_l, seccion_i, seccion_j, seccion_k):
            seccion()
    except Parada as e:
        parada = str(e)
        p(f"PARADA: {parada}")
    except Exception:  # noqa: BLE001 - error inesperado del propio test: se informa y se limpia
        parada = "error inesperado en el test"
        p("ERROR INESPERADO:\n" + traceback.format_exc())
    finally:
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
