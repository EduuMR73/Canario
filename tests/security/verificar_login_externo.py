#!/usr/bin/env python3
"""Batería de seguridad del login con Google y de los vínculos, de punta a
punta (app/rutas_externo.py, app/externo.py, el login externo y los vínculos
de app/personal.py, app/cliente_broker.py y app/avisos.py;
docs/threat-model.md, 6.19).

La pila entera (PostgreSQL, Redis, API, Caddy, el broker y Mailpit) con un
Google falso, y la batería haciendo de navegador por el 8445: guarda las
cookies como un navegador (una Set-Cookie con Max-Age=0 la borra; en una
navegación desde otro sitio solo viajan las SameSite=Lax) y manda Fetch
Metadata y Origin. También hace de servidor de autorización de Google: lee
la URL de autorización, comprueba que es la exacta y fabrica el code.

El Google falso es el token endpoint, con el nombre real por alias de red y
un certificado de una CA de prueba, como en verificar_externo.py. Comprueba
PKCE de verdad: el code lleva el code_challenge de la URL, y solo devuelve
un id_token si el SHA-256 del code_verifier que le envía el broker es ese
challenge. Así un login bueno demuestra que la API manda el verifier de ese
mismo flujo (control en a: con otro challenge, el canje se rechaza). Apunta
cada canje: los rechazos de la vuelta se comprueban contando que no llegó
ninguno.

Qué prueba:
a) Arranque, tres cuentas (un admin y dos instructores) y, de punta a punta,
   la vinculación de una cuenta de Google y el login con ella: la URL de
   autorización exacta, las cookies del flujo y del ticket con sus atributos
   exactos, el formulario exacto del canje, la sesión con las mismas cookies
   que el login con contraseña y sin dispositivo nuevo. El login confirma con
   el vínculo bloqueado FOR SHARE (supuesto 1 de A1-b2: sin 500).
b) El dispositivo de confianza: el inicio sin él es un 409 sin URL ni cookie.
   Sin vínculo, con el dispositivo de otra cuenta o sin dispositivo, la
   reserva no casa y no cuenta ningún intento (supuesto 3). Control: con la
   cuenta vinculada y su dispositivo, un código malo sí lo cuenta.
c) La vuelta: sin la cookie del flujo, con el state de otro flujo, sin iss o
   con otro, cancelada en Google, otro error, sin navegación de nivel
   superior, con Authorization, con la cookie o un parámetro repetidos, sin
   code y con el flujo repetido: 303 a la lista cerrada, su EVENTO
   vuelta_rechazada y CERO canjes. La vinculación tiene sus propios destinos.
   El canje que Google rechaza llega a Google y da fallido.
d) El ticket: repetido (supuesto 6), uno de vinculación para entrar, el de
   otra sesión de la misma cuenta (R2), y el vínculo revocado entre la vuelta
   y el código: 401 sin WWW-Authenticate. Una cuenta sin vincular y un código
   malo dan el mismo 401, byte a byte.
e) Los avisos de vincular y de revocar, en Mailpit: al titular y a quien
   vigila (los admins), y a nadie más. La identidad ya vinculada a otra
   cuenta y la cuenta que ya tiene una dan su 409 con su texto (supuesto 2);
   revocar sin vínculo, 404.
f) Dos vinculaciones a la vez con la misma cuenta de Google: una 204 y otra
   409 (supuesto 4, prueba mínima: no demuestra que se solaparan).
g) Redis y el broker. Con una ACL que no deja gastar el ticket (el resto del
   limitador sigue contando): 503 y nada escrito; el mismo ticket vale
   después (supuesto 7). Con una que no deja gastar el flujo: 303
   no_disponible y ningún canje. Redis reiniciado: el ticket repetido con el
   mismo código da 401 (ultimo_paso_totp), y con un código nuevo se acepta
   (límite documentado, docs/threat-model.md, 8). Redis parado, el broker
   parado y Google caído: 503 en las rutas JSON y 303 no_disponible en la
   vuelta.
i) Entradas maliciosas: en la vuelta (controles, saltos de línea, unicode,
   bytes que no son UTF-8, textos largos, HTML y SQL en state, code, iss y
   error), siempre 303 a fallido, sin 500 ni canje; en las rutas JSON, 422
   con el mismo cuerpo; un cliente que no es el navegador, 403.
h) Lo que queda: /yo solo da el proveedor y la fecha de cada vínculo; la
   auditoría tiene una fila por cada acceso, vinculación y revocación de la
   batería (acceso_externo, vinculacion_externa, revocacion_externa) con la
   cuenta afectada; cada EVENTO vuelta_rechazada lleva un motivo de la lista
   cerrada; los logs de la API, el broker, Caddy, PostgreSQL y Redis no
   llevan ningún code, state, nonce, verifier, ticket, flujo, sub, token ni
   el client_secret; el volcado de la base de datos no lleva ningún sub.
s) Limpieza y repositorio intacto.

Orden: a, b, c, d, e, f, g, i y h. La h va la última porque revisa lo que
han dejado todas las demás.

Lo que no prueba: un navegador real (lo hará la batería de la SPA en el paso
3), el Google real (paso 5) y que dos vinculaciones simultáneas se solapen de
verdad en PostgreSQL.

Cada prueba negativa lleva su control positivo: si el control falla, el
resultado es SIN CONCLUSION, nunca PASA. Los oráculos son literales.

Cómo se ejecuta (desde la raíz del repositorio, en PowerShell, con Docker en
marcha y los secretos generados con scripts/generar_secretos.py):

    python tests/security/verificar_login_externo.py

Usa un proyecto de Docker propio (canario_loginext) con el perfil desarrollo
(Mailpit). Necesita que el proyecto canario y las demás baterías estén
parados: las subredes 10.88.0.0/28, 10.88.1.0/28 y 10.88.2.0/28 y los puertos
127.0.0.1:8443, 8444 y 8445 son fijos (si están en uso, PARADA). Claves de
cifrado, secretos de Redis y configuración de Google FALSOS, generados en
cada ejecución, como en verificar_personal.py y verificar_externo.py; de
secrets/ solo se usan las contraseñas de los roles de PostgreSQL, sin
leerlas. En el override la red salida es interna: la batería no sale a
internet. Tarda unos minutos: cada código TOTP vale una vez, y a veces hay
que esperar al siguiente paso de 30 segundos.

Los ficheros auxiliares van a un directorio temporal del sistema, nunca al
repositorio, y se borran al terminar; al final se borra todo (down -v y las
imágenes construidas). La salida completa se guarda en
verificacion_login_externo.txt dentro del directorio temporal del sistema.
El código de salida es 0 solo si el resultado global es OK.

Solo usa la biblioteca estándar.
"""
import base64
import concurrent.futures
import hashlib
import hmac
import http.client
import json
import pathlib
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.parse

RAIZ = pathlib.Path.cwd()
PROYECTO = "canario_loginext"
SALIDA = pathlib.Path(tempfile.gettempdir()) / "verificacion_login_externo.txt"
BASE = ["docker", "compose", "-p", PROYECTO, "-f", "docker-compose.yml", "--profile", "desarrollo"]

lineas_salida = []
estado = {"falla": False, "sin_conclusion": False}

# ---------------------------------------------------------------------------
# Oráculos literales
# ---------------------------------------------------------------------------
PUERTO_API = 8443
PUERTO_WEB = 8444
PUERTO_SPA = 8445
SUBREDES = ("10.88.0.0/28", "10.88.1.0/28", "10.88.2.0/28")
RAIZ_CA = "/data/caddy/pki/authorities/local/root.crt"
ORIGEN_SPA = "https://localhost:8445"
ORIGEN_WEB = "https://localhost:8444"
SERVICIOS = ["postgres", "redis", "api", "caddy", "broker", "mailpit"]
LIMITES_PRUEBA = ("denuncia=1000/3600,seguimiento=1000/60,mensajes=1000/3600,acceso=1000/300,otras=1000/60,"
                  "cuenta=1000/60,registro=1000/3600,destinatario=1000/900,destinatario_dia=1000/86400")
RED_SALIDA = f"{PROYECTO}_salida"
RED_CORREO = f"{PROYECTO}_correo"
IMAGEN_API = f"{PROYECTO}-api"
IMAGEN_BROKER = f"{PROYECTO}-broker"
GOOGLE = f"{PROYECTO}_google"

# Lo que manda la SPA: un GET no lleva Origin (MDN, Origin), un POST sí. La
# vuelta es una navegación de nivel superior desde Google, otro sitio.
LECTURA = {"Sec-Fetch-Site": "same-origin"}
ESCRITURA = {"Sec-Fetch-Site": "same-origin", "Origin": ORIGEN_SPA, "Content-Type": "application/json"}
NAVEGACION = {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document",
              "Sec-Fetch-User": "?1"}

# Cookies (app/rutas_personal.py y app/rutas_externo.py) y sus atributos
# exactos, como los escribe Starlette 1.7.0 (orden alfabético).
ACCESO = "__Host-canario_acceso"
RENOVACION = "__Host-canario_renovacion"
DISPOSITIVO = "__Host-canario_dispositivo"
FLUJO = "__Host-canario_flujo"
TICKET = "__Host-canario_ticket"
ATRIBUTOS = {ACCESO: "HttpOnly; Max-Age=300; Path=/; SameSite=strict; Secure",
             RENOVACION: "HttpOnly; Max-Age=28800; Path=/; SameSite=strict; Secure",
             DISPOSITIVO: "HttpOnly; Max-Age=7776000; Path=/; SameSite=strict; Secure",
             FLUJO: "HttpOnly; Max-Age=600; Path=/; SameSite=lax; Secure",
             TICKET: "HttpOnly; Max-Age=300; Path=/; SameSite=strict; Secure"}
BORRADO = re.compile(r'(__Host-canario_[a-z]+)=""; expires=[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} '
                     r"\d{2}:\d{2}:\d{2} GMT; HttpOnly; Max-Age=0; Path=/; SameSite=(lax|strict); Secure")
PATRON_SELLADO = re.compile(r"[A-Za-z0-9_-]{100,400}")

# Rutas (app/rutas_externo.py) y destinos de la vuelta, literales.
RUTA_PROVEEDORES = "/v1/personal/externo/proveedores"
RUTA_INICIO = "/v1/personal/externo/google/inicio"
RUTA_VUELTA = "/v1/personal/externo/google/vuelta"
RUTA_SESION_EXTERNA = "/v1/personal/sesiones/externa"
RUTA_VINCULO_INICIO = "/v1/personal/externo/google/vinculo/inicio"
RUTA_VINCULO = "/v1/personal/externo/google/vinculo"
DESTINO_ACCESO = "/entrar/codigo"
DESTINO_VINCULO = "/cuenta?vinculo=pendiente"
FALLIDO_ACCESO = "/entrar?externo=fallido"
CANCELADO_ACCESO = "/entrar?externo=cancelado"
NO_DISPONIBLE_ACCESO = "/entrar?externo=no_disponible"
FALLIDO_VINCULO = "/cuenta?vinculo=fallido"
CANCELADO_VINCULO = "/cuenta?vinculo=cancelado"

CUERPO_401 = '{"detalle": "credenciales no válidas"}'.encode()
CUERPO_403 = b'{"detalle": "permiso denegado"}'
CUERPO_404 = b'{"detalle": "recurso no encontrado"}'
CUERPO_409_SIN_DISPOSITIVO = ('{"detalle": "este navegador no es de confianza para esa empresa; '
                              'la primera vez entre con su contraseña y su código"}').encode()
CUERPO_409_IDENTIDAD = '{"detalle": "esa cuenta externa ya está vinculada a otra cuenta de la empresa"}'.encode()
CUERPO_409_CUENTA = '{"detalle": "su cuenta ya tiene vinculada una cuenta de ese proveedor"}'.encode()
CUERPO_422 = '{"detalle": "petición no válida"}'.encode()
CUERPO_503 = '{"detalle": "servicio ocupado; inténtelo de nuevo en unos segundos"}'.encode()
REINTENTAR_TRAS = "5"

EVENTO_VUELTA = "EVENTO vuelta_rechazada: proveedor=google motivo="
MOTIVOS_VUELTA = ("transporte", "cookie", "flujo", "parametros", "proveedor", "state", "iss", "code", "repetida",
                  "canje", "no_configurado", "error_proveedor")
PATRON_EVENTO_VUELTA = re.compile(r".*EVENTO vuelta_rechazada: proveedor=google motivo=(" + "|".join(MOTIVOS_VUELTA)
                                  + r")")
EVENTO_LIMITADOR = "EVENTO limitador_no_disponible: "
EVENTO_BROKER_AUTORIZAR = "EVENTO broker_no_disponible: operacion=autorizar motivo="
EVENTO_BROKER_CANJEAR = "EVENTO broker_no_disponible: operacion=canjear motivo="
EVENTO_ORIGEN_INICIO = "EVENTO origen_rechazado: metodo=POST ruta=/v1/personal/externo/google/inicio sitio=-"

# Google: valores inventados (nunca los de secrets/), los mismos que
# verificar_externo.py y por el mismo motivo (sin la forma de un secreto real).
CLIENT_ID = "123456789012-bateria.apps.googleusercontent.com"
CLIENT_SECRET = "secreto-falso-de-la-bateria"
REDIRECT = "https://localhost:8445/v1/personal/externo/google/vuelta"
EMISOR = "https://accounts.google.com"
PREFIJO_CODE = "4/0Bateria-"
FORMULARIO_CANJE = ["client_id", "client_secret", "code", "code_verifier", "grant_type", "redirect_uri"]
# La URL de autorización exacta (app/proveedores_externos.py): solo cambian
# state, code_challenge y nonce, que genera la API en cada flujo.
PATRON_URL_AUTORIZACION = re.compile(
    re.escape("https://accounts.google.com/o/oauth2/v2/auth?client_id=123456789012-bateria.apps.googleusercontent.com"
              "&redirect_uri=https%3A%2F%2Flocalhost%3A8445%2Fv1%2Fpersonal%2Fexterno%2Fgoogle%2Fvuelta"
              "&response_type=code&scope=openid&state=")
    + r"(?P<state>[A-Za-z0-9_-]{43})" + re.escape("&code_challenge=") + r"(?P<reto>[A-Za-z0-9_-]{43})"
    + re.escape("&code_challenge_method=S256&nonce=") + r"(?P<nonce>[A-Za-z0-9_-]{43})")
# Las cuentas de Google de la batería (su sub).
SUB_B = "108765432109876543210"
SUB_C = "109999999999999999990"
SUB_LIBRE = "100000000000000000001"
SUB_CARRERA = "107777777777777777777"
SUBS = (SUB_B, SUB_C, SUB_LIBRE, SUB_CARRERA)

# Cuentas y correos (app/avisos.py).
NOMBRE_EMPRESA = "Empresa Login Externo"
PATRON_ALTA = re.compile(r"empresa creada: empresa_id=([0-9a-f-]{36}) identificador_publico=([0-9a-f]{32})")
PATRON_INVITACION = re.compile(r"invitacion creada: empresa_id=([0-9a-f-]{36}) usuario_id=([0-9a-f-]{36})\n"
                               r"token_invitacion=([0-9a-f]{32}\.[A-Za-z0-9_-]{43})\n")
PATRON_SECRETO_TOTP = re.compile(r"[A-Z2-7]{32}")
PATRON_FECHA = re.compile(r"\d{4}-\d{2}-\d{2}")
ASUNTO_VINCULADO = "Aviso de Canario: se ha vinculado una cuenta de Google"
ASUNTO_DESVINCULADO = "Aviso de Canario: se ha desvinculado la cuenta de Google"
TEXTO_TITULAR = "En su cuenta {email} de Empresa Login Externo en Canario se ha {hecho}"
TEXTO_VIGILANTE = "En la cuenta {email} de Empresa Login Externo en Canario se ha {hecho}"
HECHO_VINCULADO = "vinculado una cuenta de Google."
HECHO_DESVINCULADO = "desvinculado la cuenta de Google."
ACCIONES_EXTERNAS = ("acceso_externo", "vinculacion_externa", "revocacion_externa")

# Redis: la ACL de producción del usuario aplicacion (scripts/generar_secretos.py)
# y, para g, la misma con las claves por espacio en lugar de limite:*, menos
# una. Los espacios son las reglas del limitador (app/limitador.py, más el
# contador del arranque) y los dos de un solo uso.
PERMISOS_ACL_APLICACION = ("resetkeys ~limite:* resetchannels -@all "
                           "+ping +multi +exec +incr +expire +ttl +client|setinfo")
PERMISOS_ACL_INSPECTOR = "resetkeys ~* resetchannels -@all +ping +scan +get +pttl +dbsize +client|setinfo"
ESPACIOS_REDIS = ("denuncia", "seguimiento", "mensajes", "acceso", "otras", "cuenta", "registro", "destinatario",
                  "destinatario_dia", "arranque", "ticket", "flujo")


def permisos_sin(espacio):
    claves = " ".join(f"~limite:{e}:*" for e in ESPACIOS_REDIS if e != espacio)
    return f"resetkeys {claves} resetchannels -@all +ping +multi +exec +incr +expire +ttl +client|setinfo"


# ---------------------------------------------------------------------------
# Ficheros auxiliares (se escriben en el directorio temporal)
# ---------------------------------------------------------------------------
# CA de la batería y el certificado de oauth2.googleapis.com firmado por ella
# (como verificar_externo.py). Corre en la imagen del broker, sin red.
CERTIFICADOS = r'''
import datetime, pathlib, sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

destino = pathlib.Path(sys.argv[1])
ahora = datetime.datetime.now(datetime.timezone.utc)
NOMBRE = "oauth2.googleapis.com"


def nombre(texto):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, texto)])


clave_ca = ec.generate_private_key(ec.SECP256R1())
cert_ca = (x509.CertificateBuilder().subject_name(nombre("Canario bateria CA")).issuer_name(nombre("Canario bateria CA"))
           .public_key(clave_ca.public_key()).serial_number(x509.random_serial_number())
           .not_valid_before(ahora - datetime.timedelta(minutes=5)).not_valid_after(ahora + datetime.timedelta(days=1))
           .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
           .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                        data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                        crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
           .add_extension(x509.SubjectKeyIdentifier.from_public_key(clave_ca.public_key()), critical=False)
           .sign(clave_ca, hashes.SHA256()))
clave = ec.generate_private_key(ec.SECP256R1())
cert = (x509.CertificateBuilder().subject_name(nombre(NOMBRE)).issuer_name(cert_ca.subject)
        .public_key(clave.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(ahora - datetime.timedelta(minutes=5)).not_valid_after(ahora + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(NOMBRE)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(clave_ca.public_key()), critical=False)
        .sign(clave_ca, hashes.SHA256()))
pem_ca = cert_ca.public_bytes(serialization.Encoding.PEM)
(destino / "ca_bateria.pem").write_bytes(pem_ca)
(destino / "google.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM) + pem_ca)
(destino / "google.key").write_bytes(clave.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                         serialization.NoEncryption()))
print("CERTIFICADOS")
'''

# Google falso: el token endpoint por HTTPS en el 443. El code lo fabrica la
# batería: PREFIJO, el escenario, un punto y, en base64url, el sub, el nonce
# y el code_challenge de la URL de autorización. Comprueba el formulario del
# broker y PKCE (S256 del code_verifier igual al challenge, RFC 7636, 4.6), y
# solo entonces responde según el escenario. Imprime cada petición recibida,
# con el resultado de PKCE, para que la batería cuente los canjes.
FALSO = r'''
import base64, hashlib, http.server, json, ssl, sys, time, urllib.parse

CERT, CLAVE = sys.argv[1], sys.argv[2]
ESPERADO = json.loads(sys.argv[3])
PREFIJO = ESPERADO.pop("prefijo")
CLIENT_ID = ESPERADO["client_id"]


def b64(datos):
    return base64.urlsafe_b64encode(datos).rstrip(b"=").decode("ascii")


def id_token(sub, nonce):
    ahora = int(time.time())
    claims = {"iss": "https://accounts.google.com", "aud": CLIENT_ID, "exp": ahora + 300, "iat": ahora,
              "nonce": nonce, "sub": sub}
    return b64(b'{"alg":"RS256","kid":"bateria"}') + "." + b64(json.dumps(claims).encode()) + ".firma-bateria"


def leer_code(code):
    if not code.startswith(PREFIJO):
        return None
    escenario, _, resto = code[len(PREFIJO):].partition(".")
    try:
        datos = json.loads(base64.urlsafe_b64decode(resto + "=" * (-len(resto) % 4)))
    except ValueError:
        return None
    return (escenario, datos) if isinstance(datos, dict) else None


class Manejador(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def enviar(self, codigo, cuerpo):
        self.send_response(codigo)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(cuerpo)))
        self.end_headers()
        self.wfile.write(cuerpo)

    def do_GET(self):
        print(json.dumps({"metodo": "GET", "ruta": self.path}), flush=True)
        self.enviar(404, b"{}")

    def do_POST(self):
        datos = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode("ascii", "replace")
        formulario = dict(urllib.parse.parse_qsl(datos))
        leido = leer_code(formulario.get("code", ""))
        verifier = formulario.get("code_verifier", "").encode("ascii", "replace")
        pkce = leido is not None and b64(hashlib.sha256(verifier).digest()) == leido[1].get("reto")
        print(json.dumps({"metodo": "POST", "ruta": self.path, "formulario": formulario, "pkce": pkce}), flush=True)
        if self.path != "/token":
            return self.enviar(404, b"{}")
        if leido is None or not pkce or any(formulario.get(k) != v for k, v in ESPERADO.items()):
            return self.enviar(400, b'{"error":"invalid_grant"}')
        escenario, valores = leido
        if escenario == "bueno":
            cuerpo = json.dumps({"id_token": id_token(valores.get("sub"), valores.get("nonce")),
                                 "access_token": "token-falso-de-la-bateria", "token_type": "Bearer",
                                 "expires_in": 3599, "scope": "openid"}).encode()
            return self.enviar(200, cuerpo)
        if escenario == "caido":
            return self.enviar(500, b"{}")
        return self.enviar(400, b'{"error":"invalid_grant"}')


servidor = http.server.ThreadingHTTPServer(("0.0.0.0", 443), Manejador)
contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
contexto.load_cert_chain(CERT, CLAVE)
servidor.socket = contexto.wrap_socket(servidor.socket, server_side=True)
print("LISTO", flush=True)
servidor.serve_forever()
'''

# Lector del buzón de Mailpit por su API HTTP, desde la red correo (como
# verificar_registro.py).
LECTOR_CORREO = r'''
import json, urllib.request
base = "http://mailpit:8025/api/v1"
lista = json.load(urllib.request.urlopen(base + "/messages?limit=1000", timeout=10))
salida = []
for m in lista.get("messages") or []:
    d = json.load(urllib.request.urlopen(base + "/message/" + m["ID"], timeout=10))
    salida.append({"para": [a["Address"] for a in d.get("To") or []], "asunto": d.get("Subject"),
                   "texto": d.get("Text")})
print(json.dumps(salida))
'''


# ---------------------------------------------------------------------------
# Utilidades de ejecución y de informe
# ---------------------------------------------------------------------------
class R:
    """Resultado de un comando: código, stdout y stderr por separado."""

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


def ejecutar(args, timeout=900, entrada=None):
    # check=False explícito: el código de salida se comprueba en cada llamada.
    r = subprocess.run(args, capture_output=True, timeout=timeout, check=False, input=entrada)
    return R(r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace"))


def dc(*args, entrada=None):
    return ejecutar(BASE + list(args), entrada=entrada)


def dc_con_gestion(*args):
    """compose con el perfil gestion. down solo actúa sobre los servicios de
    los perfiles activos: sin él, la imagen de gestion quedaría sin borrar."""
    return ejecutar(BASE + ["--profile", "gestion"] + list(args))


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


def sup(sql):
    """SQL como superusuario por el socket del contenedor (peer)."""
    return dc("exec", "-T", "postgres", "psql", "-U", "postgres", "-d", "canario", "-X", "-q",
              "-A", "-t", "-v", "ON_ERROR_STOP=1", "-f", "-", entrada=sql.encode("utf-8"))


def valor(sql):
    r = sup(sql)
    if r.rc != 0:
        raise Parada(f"consulta como superusuario fallida: {r.err.strip()[:300]}")
    return r.out.strip()


def lineas_log(servicio):
    return dc("logs", "--no-color", "--no-log-prefix", servicio).todo.splitlines()


def marca():
    """Cuántas líneas tiene ya el log de la API: nuevas() da las de después."""
    return len(lineas_log("api"))


def nuevas(desde):
    # El log de Docker se escribe de forma asíncrona: un instante de margen.
    time.sleep(0.5)
    return lineas_log("api")[desde:]


def motivos_en(lineas):
    return [linea.rstrip().rpartition("motivo=")[2] for linea in lineas if EVENTO_VUELTA in linea]


TEMPORAL = None
PRUEBA = None
SECRETOS = None
CA_LOCAL = None
# Todo valor sensible que ha pasado por la batería: h) comprueba que ninguno
# está en los logs.
VISTOS = set()


# ---------------------------------------------------------------------------
# HTTP: el navegador de la batería
# ---------------------------------------------------------------------------
def peticion(metodo, ruta, puerto=PUERTO_SPA, cabeceras=None, datos=None, crudo=None):
    """Petición al proxy publicado en 127.0.0.1 con SNI localhost y TLS
    validado (como verificar_sesion.py). datos: un objeto que se envía como
    JSON; crudo: los bytes tal cual. Devuelve (estado, {cabecera en
    minúsculas: [valores]}, cuerpo). La ruta se envía tal cual."""
    if crudo is not None:
        cuerpo = crudo
    else:
        cuerpo = b"" if datos is None else json.dumps(datos, ensure_ascii=False).encode("utf-8")
    contexto = ssl.create_default_context(cafile=str(CA_LOCAL))
    s = socket.create_connection(("127.0.0.1", puerto), timeout=60)
    c = http.client.HTTPConnection("localhost", puerto, timeout=60)
    c.sock = contexto.wrap_socket(s, server_hostname="localhost")
    c.putrequest(metodo, ruta, skip_host=True, skip_accept_encoding=True)
    c.putheader("Host", f"localhost:{puerto}")
    c.putheader("Content-Length", str(len(cuerpo)))
    for nombre, valor_cabecera in (cabeceras or {}).items():
        c.putheader(nombre, valor_cabecera)
    c.endheaders()
    if cuerpo:
        c.send(cuerpo)
    r = c.getresponse()
    leido = r.read()
    valores = {}
    for nombre, valor_cabecera in r.getheaders():
        valores.setdefault(nombre.lower(), []).append(valor_cabecera)
    c.close()
    return r.status, valores, leido


def una(cabeceras, nombre):
    """El valor de una cabecera que debe aparecer una sola vez, o None."""
    lista = cabeceras.get(nombre) or []
    return lista[0] if len(lista) == 1 else None


def json_de(cuerpo):
    try:
        return json.loads(cuerpo.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None


def puestas(cabeceras):
    """Las cookies que pone una respuesta (no las que borra): {nombre:
    (valor, atributos)}. Una repetida cuenta como None."""
    resultado = {}
    for linea in cabeceras.get("set-cookie") or []:
        if BORRADO.fullmatch(linea):
            continue
        par, _, atributos = linea.partition("; ")
        nombre, _, valor_cookie = par.partition("=")
        resultado[nombre] = None if nombre in resultado else (valor_cookie, atributos)
    return resultado


def borradas(cabeceras):
    """Las cookies que borra una respuesta, con su SameSite: [(nombre, samesite)]."""
    encajes = (BORRADO.fullmatch(linea) for linea in cabeceras.get("set-cookie") or [])
    return sorted((m.group(1), m.group(2)) for m in encajes if m)


def nombres(cabeceras):
    """Los nombres de las cookies de una respuesta, para la salida: los
    valores son tokens y no se escriben."""
    return [linea.partition("=")[0] for linea in cabeceras.get("set-cookie") or []]


def cookie_puesta(cabeceras, nombre):
    """El valor de la cookie si la respuesta la pone una vez, con sus
    atributos exactos y la forma de un valor sellado; si no, None."""
    puesta = puestas(cabeceras).get(nombre)
    if puesta is None or puesta[1] != ATRIBUTOS[nombre]:
        return None
    return puesta[0]


class Navegador:
    """Las cookies de un navegador para localhost:8445, guardadas y enviadas
    como lo hace uno de verdad: una Set-Cookie con Max-Age=0 la borra, y en
    una navegación desde otro sitio solo viajan las SameSite=Lax (MDN,
    Set-Cookie, SameSite). Es un modelo: el navegador real lo prueba la
    batería de la SPA."""

    def __init__(self, etiqueta):
        self.etiqueta = etiqueta
        self.cookies = {}
        self.acceso_desde = None

    def copia(self, etiqueta):
        otro = Navegador(etiqueta)
        otro.cookies = dict(self.cookies)
        otro.acceso_desde = self.acceso_desde
        return otro

    def guardar(self, cabeceras):
        for linea in cabeceras.get("set-cookie") or []:
            par, _, atributos = linea.partition("; ")
            nombre, _, valor_cookie = par.partition("=")
            partes = atributos.split("; ")
            if "Max-Age=0" in partes:
                self.cookies.pop(nombre, None)
                continue
            samesite = next((a.partition("=")[2].lower() for a in partes if a.startswith("SameSite=")), "lax")
            self.cookies[nombre] = (valor_cookie, samesite)
            VISTOS.add(valor_cookie)
            if nombre == ACCESO:
                self.acceso_desde = time.monotonic()

    def valor(self, nombre):
        return (self.cookies.get(nombre) or (None, None))[0]

    def poner(self, nombre, valor_cookie, samesite):
        self.cookies[nombre] = (valor_cookie, samesite)

    def cabecera(self, navegacion, sin=()):
        return "; ".join(f"{n}={v}" for n, (v, s) in self.cookies.items()
                         if n not in sin and (not navegacion or s == "lax"))


def pedir(nav, metodo, ruta, datos=None, navegacion=False, sin=(), extra=None, crudo=None, guardar=True,
          puerto=PUERTO_SPA):
    """Una petición de la SPA (o la navegación de la vuelta) con las cookies
    de nav. extra cambia cabeceras (None quita una). Si guardar, nav se
    queda con las cookies de la respuesta."""
    if navegacion:
        cabeceras = dict(NAVEGACION)
    else:
        cabeceras = dict(LECTURA if metodo == "GET" else ESCRITURA)
    if nav is not None:
        cookie = nav.cabecera(navegacion, sin)
        if cookie:
            cabeceras["Cookie"] = cookie
    for nombre, valor_cabecera in (extra or {}).items():
        if valor_cabecera is None:
            cabeceras.pop(nombre, None)
        else:
            cabeceras[nombre] = valor_cabecera
    respuesta = peticion(metodo, ruta, puerto=puerto, cabeceras=cabeceras, datos=datos, crudo=crudo)
    if nav is not None and guardar:
        nav.guardar(respuesta[1])
    return respuesta


# ---------------------------------------------------------------------------
# TOTP de la batería (RFC 6238 sobre RFC 4226), independiente de app/cripto.py
# ---------------------------------------------------------------------------
def totp(clave, paso, digitos=6):
    mac = hmac.new(clave, paso.to_bytes(8, "big"), hashlib.sha1).digest()
    o = mac[-1] & 0x0F
    return f"{(int.from_bytes(mac[o:o + 4], 'big') & 0x7FFFFFFF) % 10 ** digitos:0{digitos}d}"


# Último paso aceptado por secreto: un código solo vale una vez.
ULTIMO_PASO = {}


def codigo_libre(cuenta):
    """(código, paso) del paso actual, como lo usaría una persona con su
    aplicación; si ese paso ya se usó, espera al siguiente. Nunca el anterior
    ni el siguiente (como verificar_personal.py, codigo_libre)."""
    while True:
        actual = int(time.time()) // 30
        if actual > ULTIMO_PASO.get(cuenta.secreto, -1):
            return totp(base64.b32decode(cuenta.secreto), actual), actual
        time.sleep(30 - time.time() % 30 + 0.5)


def gastado(cuenta, paso):
    ULTIMO_PASO[cuenta.secreto] = max(ULTIMO_PASO.get(cuenta.secreto, -1), paso)


def codigo_erroneo(cuenta):
    """Un código de 6 dígitos que no vale en ningún paso de la ventana."""
    actual = int(time.time()) // 30
    validos = {totp(base64.b32decode(cuenta.secreto), actual + d) for d in (-2, -1, 0, 1, 2)}
    while True:
        codigo = f"{secrets.randbelow(10 ** 6):06d}"
        if codigo not in validos:
            return codigo


def esperar_inicio_de_paso():
    """Espera al principio de un paso de 30 s: un código de ese paso vale
    entonces casi un minuto (el paso y el siguiente)."""
    resto = time.time() % 30
    if resto > 2:
        time.sleep(30 - resto + 0.3)


# ---------------------------------------------------------------------------
# Cuentas, flujos y Google
# ---------------------------------------------------------------------------
class Cuenta:
    def __init__(self, etiqueta, email):
        self.etiqueta, self.email = etiqueta, email
        self.contrasena = secrets.token_urlsafe(18)
        self.secreto = None
        self.usuario_id = None
        self.nav = Navegador(etiqueta)
        VISTOS.add(self.contrasena)


IDENTIFICADOR = ""
EMPRESA_ID = ""
A = Cuenta("A (admin)", "admin@loginext.test")
B = Cuenta("B (instructor)", "instructor.b@loginext.test")
C = Cuenta("C (instructor)", "instructor.c@loginext.test")
# Lo que la batería ha hecho con éxito, por acción de auditoría: la cuenta
# afectada de cada fila que tiene que haber (h).
EXITOS = {accion: [] for accion in ACCIONES_EXTERNAS}
# Respuestas que d) compara entre sí.
RESPUESTAS = {}


def activar(cuenta, invitacion):
    """Activación por el 8445: el dispositivo queda en la cookie de su navegador."""
    VISTOS.add(invitacion)
    codigo, _, cuerpo = pedir(cuenta.nav, "POST", "/v1/personal/activacion",
                              {"token": invitacion, "contrasena": cuenta.contrasena})
    secreto = (json_de(cuerpo) or {}).get("secreto_totp", "")
    if codigo != 200 or not PATRON_SECRETO_TOTP.fullmatch(secreto):
        raise Parada(f"no se pudo activar la cuenta {cuenta.etiqueta} (paso 1: {codigo})")
    cuenta.secreto = secreto
    VISTOS.add(secreto)
    totp_codigo, paso = codigo_libre(cuenta)
    codigo, _, _ = pedir(cuenta.nav, "POST", "/v1/personal/activacion/confirmar",
                         {"token": invitacion, "codigo_totp": totp_codigo})
    if codigo != 200 or cuenta.nav.valor(DISPOSITIVO) is None:
        raise Parada(f"no se pudo confirmar la activacion de {cuenta.etiqueta} ({codigo})")
    gastado(cuenta, paso)


def login(cuenta):
    """Login con contraseña desde su navegador (con su dispositivo)."""
    totp_codigo, paso = codigo_libre(cuenta)
    codigo, _, _ = pedir(cuenta.nav, "POST", "/v1/personal/sesiones", {
        "empresa": IDENTIFICADOR, "email": cuenta.email, "contrasena": cuenta.contrasena,
        "codigo_totp": totp_codigo})
    if codigo != 201 or cuenta.nav.valor(ACCESO) is None:
        raise Parada(f"no se pudo iniciar sesion con {cuenta.etiqueta} ({codigo})")
    gastado(cuenta, paso)


def asegurar_sesion(cuenta):
    """Renueva el acceso si tiene más de 4 minutos (dura 5). Una sesión con
    más de 15 minutos sin renovar ya no se renueva (app/personal.py): entonces
    entra otra vez con contraseña, como haría la persona, y lo dice."""
    nav = cuenta.nav
    if nav.acceso_desde is None or time.monotonic() - nav.acceso_desde < 240:
        return
    codigo, _, _ = pedir(nav, "POST", "/v1/personal/sesiones/renovacion", {})
    if codigo != 200:
        p(f"  [sesion] la de {cuenta.etiqueta} no se renueva ({codigo}): entra otra vez con contrasena")
        login(cuenta)


def invitar(cuenta):
    asegurar_sesion(A)
    codigo, _, cuerpo = pedir(A.nav, "POST", "/v1/personal/usuarios", {"email": cuenta.email, "rol": "instructor"})
    datos = json_de(cuerpo) or {}
    if codigo != 201 or not isinstance(datos.get("token_invitacion"), str):
        raise Parada(f"el admin no pudo invitar a {cuenta.etiqueta} ({codigo})")
    cuenta.usuario_id = datos["usuario_id"]
    return datos["token_invitacion"]


def leer_url(cuerpo):
    """(state, reto, nonce) de la URL de autorización si es la exacta; si no, None."""
    url = (json_de(cuerpo) or {}).get("url")
    encaje = PATRON_URL_AUTORIZACION.fullmatch(url) if isinstance(url, str) else None
    if encaje is None:
        return None
    VISTOS.update((encaje["state"], encaje["nonce"]))
    return encaje["state"], encaje["reto"], encaje["nonce"]


def iniciar(nav, ruta=RUTA_INICIO, datos=None):
    """El inicio de un flujo: (respuesta, (state, reto, nonce) o None)."""
    respuesta = pedir(nav, "POST", ruta, datos if datos is not None else {"empresa": IDENTIFICADOR})
    return respuesta, (leer_url(respuesta[2]) if respuesta[0] == 200 else None)


def iniciar_vinculo(cuenta):
    """El inicio de una vinculación, con un código recién escrito."""
    asegurar_sesion(cuenta)
    totp_codigo, paso = codigo_libre(cuenta)
    respuesta, leidos = iniciar(cuenta.nav, RUTA_VINCULO_INICIO, {"codigo_totp": totp_codigo})
    if respuesta[0] == 200:
        gastado(cuenta, paso)
    return respuesta, leidos


def code_para(escenario, sub, nonce, reto):
    """El code que daría Google a esta cuenta en este flujo (ver FALSO)."""
    datos = json.dumps({"sub": sub, "nonce": nonce, "reto": reto}, separators=(",", ":")).encode("ascii")
    code = PREFIJO_CODE + escenario + "." + base64.urlsafe_b64encode(datos).decode("ascii").rstrip("=")
    VISTOS.add(code)
    return code


def consulta(*pares):
    """La ruta de la vuelta con esos parámetros, en ese orden, codificados
    como lo hace Google (también la barra del code: 4%2F0...)."""
    return RUTA_VUELTA + "?" + "&".join(f"{k}={urllib.parse.quote(v, safe='')}" for k, v in pares)


def de_google(leidos, sub, escenario="bueno", reto=None):
    """La vuelta con la que Google devuelve el navegador: los parámetros y el
    orden de una vuelta real, con iss (RFC 9207)."""
    state, reto_url, nonce = leidos
    return consulta(("state", state), ("iss", EMISOR), ("code", code_para(escenario, sub, nonce, reto or reto_url)),
                    ("scope", "openid"), ("authuser", "0"), ("prompt", "none"))


def volver(nav, ruta, guardar=True, sin=(), extra=None):
    return pedir(nav, "GET", ruta, navegacion=True, guardar=guardar, sin=sin, extra=extra)


def hasta_ticket(nav, sub, destino=DESTINO_ACCESO, inicio=None):
    """Inicio (o el que se pase) y vuelta buena: el ticket queda en nav. Si
    algo no va como debe, PARADA: es preparación, no la prueba."""
    respuesta, leidos = inicio if inicio is not None else iniciar(nav)
    if leidos is None:
        raise Parada(f"el inicio de {nav.etiqueta} no devolvio la URL de autorizacion ({respuesta[0]})")
    vuelta = volver(nav, de_google(leidos, sub))
    # El ticket de esta respuesta: uno anterior en el navegador no vale.
    if vuelta[0] != 303 or una(vuelta[1], "location") != destino or cookie_puesta(vuelta[1], TICKET) is None:
        raise Parada(f"la vuelta de {nav.etiqueta} no dejo el ticket ({vuelta[0]}, {una(vuelta[1], 'location')!r})")
    return leidos, vuelta


def entrar(cuenta, nav=None):
    """POST de la sesión externa con un código bueno; anota el éxito."""
    nav = nav or cuenta.nav
    totp_codigo, paso = codigo_libre(cuenta)
    respuesta = pedir(nav, "POST", RUTA_SESION_EXTERNA, {"codigo_totp": totp_codigo})
    if respuesta[0] == 201:
        gastado(cuenta, paso)
        EXITOS["acceso_externo"].append(cuenta.usuario_id)
    return respuesta


def completar(cuenta, nav=None):
    nav = nav or cuenta.nav
    respuesta = pedir(nav, "POST", RUTA_VINCULO, {})
    if respuesta[0] == 204:
        EXITOS["vinculacion_externa"].append(cuenta.usuario_id)
    return respuesta


def revocar(cuenta):
    asegurar_sesion(cuenta)
    totp_codigo, paso = codigo_libre(cuenta)
    respuesta = pedir(cuenta.nav, "DELETE", RUTA_VINCULO, {"codigo_totp": totp_codigo})
    if respuesta[0] == 204:
        gastado(cuenta, paso)
        EXITOS["revocacion_externa"].append(cuenta.usuario_id)
    return respuesta


def peticiones_falso():
    """Lo que ha recibido el Google falso, en orden."""
    salida = ejecutar(["docker", "logs", GOOGLE]).out
    return [json.loads(linea) for linea in salida.splitlines() if linea.startswith("{")]


def canjes():
    return [x for x in peticiones_falso() if x.get("ruta") == "/token"]


def falso():
    """Arranca el Google falso con el alias oauth2.googleapis.com en salida."""
    esperado = {"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "redirect_uri": REDIRECT,
                "grant_type": "authorization_code", "prefijo": PREFIJO_CODE}
    r = ejecutar(["docker", "run", "-d", "--name", GOOGLE, "--network", RED_SALIDA,
                  "--network-alias", "oauth2.googleapis.com", "--read-only", "--cap-drop", "ALL",
                  "--security-opt", "no-new-privileges:true",
                  # Sin capacidades, un usuario no root solo puede escuchar en
                  # el 443 si el espacio de red lo permite.
                  "--sysctl", "net.ipv4.ip_unprivileged_port_start=0",
                  "--mount", f"type=bind,src={PRUEBA},dst=/prueba,readonly",
                  "--entrypoint", "python", IMAGEN_BROKER, "-I", "/prueba/falso.py",
                  "/prueba/google.pem", "/prueba/google.key", json.dumps(esperado)])
    if r.rc != 0:
        raise Parada(f"no arranca el Google falso: {r.err.strip()[-300:]!r}")
    if not esperar(lambda: "LISTO" in ejecutar(["docker", "logs", GOOGLE]).out, 30):
        raise Parada("el Google falso no llega a escuchar")


def buzon():
    r = ejecutar(["docker", "run", "--rm", "--network", RED_CORREO, "--read-only", "--cap-drop", "ALL",
                  "--security-opt", "no-new-privileges:true", "--entrypoint", "python", IMAGEN_API,
                  "-c", LECTOR_CORREO])
    try:
        return json.loads(r.out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise Parada(f"no se pudo leer el buzon de Mailpit: {r.err.strip()[-400:]!r}") from None


def correos(email, asunto, cuantos, maximo=30):
    """Los correos a email con ese asunto cuando haya al menos cuantos, o los
    que haya al cumplirse el plazo (los avisos salen después de responder)."""
    encontrados = []

    def hay():
        encontrados[:] = [c for c in buzon() if c["para"] == [email] and c["asunto"] == asunto]
        return len(encontrados) >= cuantos
    esperar(hay, maximo)
    return list(encontrados)


def intentos():
    """(intentos de todos los dispositivos, intentos sin confianza de todas
    las cuentas) de la empresa: una reserva que cuenta cambia uno de los dos."""
    fila = valor(f"select (select coalesce(sum(intentos_fallidos), 0) from canal.dispositivo_personal "
                 f"where empresa_id = '{EMPRESA_ID}') || '|' || (select coalesce(sum(intentos_fallidos), 0) "
                 f"from canal.usuario_personal where empresa_id = '{EMPRESA_ID}');")
    dispositivos, cuentas = fila.split("|")
    return int(dispositivos), int(cuentas)


def n_sesiones(cuenta):
    return int(valor(f"select count(*) from canal.sesion_personal where usuario_id = '{cuenta.usuario_id}';"))


def paso_de(cuenta):
    return valor(f"select coalesce(ultimo_paso_totp::text, '-') from canal.usuario_personal "
                 f"where id = '{cuenta.usuario_id}';")


def escrito(cuenta):
    """Lo que escribe un login: sesiones de la cuenta, filas acceso_externo y
    el último paso TOTP. La reserva del intento no cuenta: va antes y queda
    también con un código malo (app/personal.py)."""
    return (n_sesiones(cuenta), valor(f"select count(*) from canal.registro_auditoria where empresa_id = "
                                      f"'{EMPRESA_ID}' and accion = 'acceso_externo';"), paso_de(cuenta))


def proveedores_ok():
    codigo, _, cuerpo = pedir(Navegador("sonda"), "GET", RUTA_PROVEEDORES)
    return codigo == 200 and json_de(cuerpo) == {"proveedores": ["google"]}


def poner_acl(permisos):
    """Recrea Redis con esta ACL para el usuario aplicacion. La API vuelve a
    conectar sola (app/limitador.py, un reintento ante un error de conexión);
    Redis no persiste nada, así que se vacía."""
    (SECRETOS / "redis_acl").write_text(texto_acl(permisos), encoding="ascii", newline="\n")
    r = dc("up", "-d", "--force-recreate", "--wait", "--wait-timeout", "60", "redis")
    if r.rc != 0:
        raise Parada(f"Redis no arranca con la ACL pedida: {r.todo.strip()[-400:]}")
    if not esperar(proveedores_ok, 30):
        raise Parada("la API no vuelve a responder tras recrear Redis")


def reiniciar_redis():
    """Reinicia Redis con la misma ACL: sin persistencia, vuelve vacío."""
    r = dc("restart", "redis")
    if r.rc != 0 or not esperar(proveedores_ok, 60):
        raise Parada("Redis no vuelve tras reiniciarlo")


CONTRASENAS_REDIS = {}


def texto_acl(aplicacion):
    hash_aplicacion = hashlib.sha256(CONTRASENAS_REDIS["aplicacion"].encode("ascii")).hexdigest()
    hash_inspector = hashlib.sha256(CONTRASENAS_REDIS["inspector"].encode("ascii")).hexdigest()
    return (f"user default off\nuser aplicacion on #{hash_aplicacion} {aplicacion}\n"
            f"user inspector on #{hash_inspector} {PERMISOS_ACL_INSPECTOR}\n")


# ---------------------------------------------------------------------------
# Secciones
# ---------------------------------------------------------------------------
def seccion_a():
    global CA_LOCAL, IDENTIFICADOR, EMPRESA_ID
    p("=== a) arranque, cuentas y login con Google de punta a punta")
    # Verificación del TOTP propio con el vector de RFC 6238 (SHA-1, T=59).
    pasa(totp(b"12345678901234567890", 59 // 30, 8) == "94287082", "a) el TOTP de la bateria cumple RFC 6238")
    r = dc("build")
    p(f"build -> codigo {r.rc}")
    if r.rc != 0:
        p(r.todo.strip()[-1500:])
        raise Parada("no se construyen las imagenes")
    (PRUEBA / "certificados.py").write_text(CERTIFICADOS, encoding="utf-8", newline="\n")
    r = ejecutar(["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
                  "--security-opt", "no-new-privileges:true", "--mount", f"type=bind,src={PRUEBA},dst=/salida",
                  "--entrypoint", "python", IMAGEN_BROKER, "-I", "/salida/certificados.py", "/salida"])
    if "CERTIFICADOS" not in r.out:
        raise Parada(f"no se generan los certificados de prueba: {r.err.strip()[-400:]!r}")
    r = dc("up", "-d", "--wait", *SERVICIOS)
    p(f"up -d --wait {' '.join(SERVICIOS)} -> codigo {r.rc}")
    if r.rc != 0:
        p(r.todo.strip()[-1500:])
        raise Parada("no arranca la pila")
    config = json_de(dc("config", "--format", "json").out.encode()) or {}
    montaje = [v.get("target") for v in config.get("services", {}).get("broker", {}).get("volumes", [])]
    pasa(montaje == ["/usr/lib/ssl/cert.pem"] and config.get("networks", {}).get("salida", {}).get("internal") is True,
         f"a) control: el override monta la CA de prueba en el broker y deja salida interna ({montaje})")
    CA_LOCAL = TEMPORAL / "root.crt"
    r = dc("cp", f"caddy:{RAIZ_CA}", str(CA_LOCAL))
    if r.rc != 0 or not CA_LOCAL.is_file():
        raise Parada(f"no se pudo copiar el certificado raiz del CA de Caddy: {r.err.strip()[:200]}")
    falso()
    r = dc("run", "--rm", "-T", "gestion", "alta-empresa", "--nombre", NOMBRE_EMPRESA, "--zona", "Europe/Madrid")
    alta = PATRON_ALTA.search(r.out)
    if r.rc != 0 or alta is None:
        raise Parada(f"no se pudo dar de alta la empresa de prueba: {r.rc} {r.err.strip()[-300:]!r}")
    EMPRESA_ID, IDENTIFICADOR = alta.group(1), alta.group(2)
    r = dc("run", "--rm", "-T", "gestion", "alta-admin", "--identificador", IDENTIFICADOR, "--email", A.email)
    invitacion = PATRON_INVITACION.search(r.out)
    if r.rc != 0 or invitacion is None:
        raise Parada(f"no se pudo emitir la invitacion del admin: {r.rc} {r.err.strip()[-300:]!r}")
    A.usuario_id = invitacion.group(2)
    activar(A, invitacion.group(3))
    login(A)
    for cuenta in (B, C):
        activar(cuenta, invitar(cuenta))
        login(cuenta)
    p(f"   empresa de prueba: {IDENTIFICADOR}; cuentas activadas: A (admin), B y C (instructores)")
    pasa(proveedores_ok(), "a) GET /externo/proveedores por el 8445: {\"proveedores\": [\"google\"]}")

    # Control del Google falso: con un challenge que no es el del flujo,
    # rechaza el canje. Sin esto, que el canje bueno pase no diría nada del
    # verifier que envía la API.
    _, leidos = iniciar(B.nav)
    if leidos is None:
        raise Parada("el inicio de B no devolvio la URL de autorizacion")
    antes = len(canjes())
    otro_reto = base64.urlsafe_b64encode(hashlib.sha256(b"otro-verifier").digest()).decode().rstrip("=")
    v = volver(B.nav, de_google(leidos, SUB_B, reto=otro_reto))
    nuevos = canjes()[antes:]
    control_pkce = (v[0] == 303 and una(v[1], "location") == FALLIDO_ACCESO and len(nuevos) == 1
                    and nuevos[0].get("pkce") is False)
    pasa(control_pkce, f"a) control del Google falso: con otro code_challenge rechaza el canje (PKCE) "
                       f"({v[0]}, {una(v[1], 'location')!r}, {[x.get('pkce') for x in nuevos]})")

    # B vincula su cuenta de Google.
    antes = len(canjes())
    r, leidos_vinculo = iniciar_vinculo(B)
    pasa(r[0] == 200 and leidos_vinculo is not None,
         f"a) el inicio de la vinculacion devuelve la URL de autorizacion exacta ({r[0]})")
    flujo = cookie_puesta(r[1], FLUJO)
    pasa(flujo is not None and PATRON_SELLADO.fullmatch(flujo) is not None and list(puestas(r[1])) == [FLUJO],
         f"a) el flujo va solo en su cookie, con {ATRIBUTOS[FLUJO]!r} ({nombres(r[1])})")
    if leidos_vinculo is None:
        raise Parada("sin URL de autorizacion no se puede seguir")
    v = volver(B.nav, de_google(leidos_vinculo, SUB_B))
    ticket = cookie_puesta(v[1], TICKET)
    pasa(v[0] == 303 and una(v[1], "location") == DESTINO_VINCULO and v[2] == b"",
         f"a) la vuelta de la vinculacion: 303 a {DESTINO_VINCULO} ({v[0]}, {una(v[1], 'location')!r})")
    pasa(ticket is not None and PATRON_SELLADO.fullmatch(ticket) is not None and borradas(v[1]) == [(FLUJO, "lax")],
         f"a) el ticket en su cookie, con {ATRIBUTOS[TICKET]!r}, y el flujo borrado ({nombres(v[1])})")
    nuevos = canjes()[antes:]
    formulario = nuevos[0].get("formulario", {}) if len(nuevos) == 1 else {}
    VISTOS.add(formulario.get("code_verifier", ""))
    pasa(len(nuevos) == 1 and nuevos[0].get("pkce") is True,
         f"a) un canje, con el verifier de ese flujo (PKCE) ({[x.get('pkce') for x in nuevos]})")
    pasa(sorted(formulario) == FORMULARIO_CANJE and formulario.get("client_id") == CLIENT_ID
         and formulario.get("client_secret") == CLIENT_SECRET and formulario.get("redirect_uri") == REDIRECT
         and formulario.get("grant_type") == "authorization_code",
         f"a) el broker envia exactamente el formulario del token endpoint ({sorted(formulario)})")
    c = completar(B)
    pasa(c[0] == 204 and borradas(c[1]) == [(TICKET, "strict")],
         f"a) completar la vinculacion: 204 y el ticket borrado ({c[0]}, {nombres(c[1])})")
    if c[0] != 204:
        raise Parada("sin vinculo no se puede probar el login")

    # Login de B con Google, de punta a punta, desde un navegador sin sesión.
    asegurar_sesion(B)
    cierre = pedir(B.nav, "DELETE", "/v1/personal/sesiones/actual")
    if cierre[0] != 204 or B.nav.valor(ACCESO) is not None:
        raise Parada(f"no se pudo cerrar la sesion de B ({cierre[0]})")
    antes = len(canjes())
    r, leidos = iniciar(B.nav)
    flujo = cookie_puesta(r[1], FLUJO)
    pasa(r[0] == 200 and leidos is not None and flujo is not None,
         f"a) el inicio del login: 200 con la URL exacta y la cookie del flujo ({r[0]}, {nombres(r[1])})")
    if leidos is None:
        raise Parada("sin URL de autorizacion no se puede seguir")
    pasa(all(x != y for x, y in zip(leidos, leidos_vinculo)),
         "a) cada flujo tiene su propio state, code_challenge y nonce")
    v = volver(B.nav, de_google(leidos, SUB_B))
    nuevos = canjes()[antes:]
    pasa(v[0] == 303 and una(v[1], "location") == DESTINO_ACCESO and cookie_puesta(v[1], TICKET) is not None
         and borradas(v[1]) == [(FLUJO, "lax")] and len(nuevos) == 1 and nuevos[0].get("pkce") is True,
         f"a) la vuelta: 303 a {DESTINO_ACCESO}, el ticket y un canje con PKCE ({v[0]}, {una(v[1], 'location')!r})")
    desde = marca()
    s = entrar(B)
    cookies = puestas(s[1])
    pasa(s[0] == 201 and json_de(s[2]) == {"expira_en": 300},
         f"a) la sesion externa: 201 con solo expira_en ({s[0]}, {s[2][:80]!r})")
    pasa(sorted(cookies) == sorted([ACCESO, RENOVACION]) and None not in cookies.values()
         and cookies[ACCESO][1] == ATRIBUTOS[ACCESO] and cookies[RENOVACION][1] == ATRIBUTOS[RENOVACION]
         and borradas(s[1]) == [(TICKET, "strict")],
         f"a) acceso y renovacion con sus atributos exactos, sin dispositivo nuevo y el ticket borrado ({nombres(s[1])})")
    yo = pedir(B.nav, "GET", "/v1/personal/yo")
    pasa(yo[0] == 200 and (json_de(yo[2]) or {}).get("email") == B.email,
         f"a) con esa sesion, /yo es el de B ({yo[0]})")
    lineas = nuevas(desde)
    pasa(not any("Traceback" in linea or "error interno" in linea for linea in lineas) and s[0] == 201,
         "a) el login confirma con el vinculo bloqueado FOR SHARE sin ningun error interno (supuesto 1)")
    if s[0] != 201:
        raise Parada("sin login externo no se puede seguir")


def seccion_b():
    p("=== b) el dispositivo de confianza: el inicio sin el y las reservas que no cuentan")
    r, leidos = iniciar(B.nav)
    control = r[0] == 200 and leidos is not None
    pasa(control, f"b) control: con su dispositivo, el inicio da 200 con la URL ({r[0]})")
    casos = [("sin dispositivo", Navegador("sin cookies"), {"empresa": IDENTIFICADOR}),
             ("con un dispositivo y una empresa que no existe", B.nav.copia("B"), {"empresa": "0" * 32})]
    for nombre, nav, datos in casos:
        codigo, cab, cuerpo = pedir(nav, "POST", RUTA_INICIO, datos)
        negativo(f"b) inicio {nombre}: 409 con su texto, sin URL ni cookie del flujo ({codigo}, {nombres(cab)})",
                 codigo == 409 and cuerpo == CUERPO_409_SIN_DISPOSITIVO and "set-cookie" not in cab, control,
                 f"cuerpo: {cuerpo[:120]!r}")

    # Control: con la cuenta vinculada y su dispositivo, la reserva casa y un
    # código malo cuenta un intento en el dispositivo.
    hasta_ticket(B.nav, SUB_B, inicio=(r, leidos))
    antes = intentos()
    malo = pedir(B.nav, "POST", RUTA_SESION_EXTERNA, {"codigo_totp": codigo_erroneo(B)})
    despues = intentos()
    RESPUESTAS["codigo_malo"] = malo
    control_reserva = malo[0] == 401 and despues == (antes[0] + 1, antes[1])
    pasa(control_reserva, f"b) control: vinculada, con su dispositivo y un codigo malo, 401 y un intento contado "
                          f"({malo[0]}, intentos {antes} -> {despues})")
    # Sin vínculo: la cuenta de Google no es de nadie. Con un código bueno.
    hasta_ticket(C.nav, SUB_LIBRE)
    antes = intentos()
    sin_vinculo = pedir(C.nav, "POST", RUTA_SESION_EXTERNA, {"codigo_totp": codigo_libre(C)[0]})
    despues = intentos()
    RESPUESTAS["sin_vinculo"] = sin_vinculo
    negativo(f"b) sin vinculo: 401 y ningun intento contado ({sin_vinculo[0]}, {antes} -> {despues})",
             sin_vinculo[0] == 401 and sin_vinculo[2] == CUERPO_401 and antes == despues, control_reserva)
    # Con el dispositivo de otra cuenta: la de Google es de B y el navegador, de C.
    hasta_ticket(C.nav, SUB_B)
    antes = intentos()
    otra = pedir(C.nav, "POST", RUTA_SESION_EXTERNA, {"codigo_totp": codigo_libre(B)[0]})
    despues = intentos()
    negativo(f"b) con el dispositivo de otra cuenta: 401 y ningun intento contado ({otra[0]}, {antes} -> {despues})",
             otra[0] == 401 and otra[2] == CUERPO_401 and antes == despues, control_reserva)
    # Sin dispositivo: el ticket de B sin su cookie de dispositivo.
    hasta_ticket(B.nav, SUB_B)
    antes = intentos()
    sin = pedir(B.nav, "POST", RUTA_SESION_EXTERNA, {"codigo_totp": codigo_libre(B)[0]}, sin=(DISPOSITIVO,))
    despues = intentos()
    negativo(f"b) con el ticket y sin dispositivo: 401 y ningun intento contado ({sin[0]}, {antes} -> {despues})",
             sin[0] == 401 and sin[2] == CUERPO_401 and antes == despues, control_reserva)


def caso_vuelta(nombre, hacer, motivo, destino=FALLIDO_ACCESO, control=True, canjes_esperados=0):
    """hacer() hace la vuelta. Comprueba el 303, su destino, que no deja
    ticket, el EVENTO (o ninguno si motivo es None) y los canjes."""
    antes = len(canjes())
    desde = marca()
    r = hacer()
    motivos = motivos_en(nuevas(desde))
    nuevos = len(canjes()) - antes
    ok = (r[0] == 303 and una(r[1], "location") == destino and TICKET not in puestas(r[1])
          and motivos == ([] if motivo is None else [motivo]) and nuevos == canjes_esperados)
    evento = f"EVENTO motivo={motivo}" if motivo else "sin EVENTO"
    negativo(f"c) {nombre}: 303 a {destino}, {evento} y {canjes_esperados} canjes "
             f"({r[0]}, {una(r[1], 'location')!r}, motivos {motivos}, canjes {nuevos})", ok, control)


def seccion_c():
    p("=== c) la vuelta: cada rechazo sin ningun canje")
    antes = len(canjes())
    hasta_ticket(B.nav, SUB_B)
    control = len(canjes()) == antes + 1
    pasa(control, "c) control: una vuelta buena canjea una vez y lleva a /entrar/codigo")

    def con_flujo(construir, nav=None, **opciones):
        """Un flujo nuevo de B y la vuelta que construir(leidos) arma con él."""
        def hacer():
            navegador = nav or B.nav
            _, leidos = iniciar(navegador)
            if leidos is None:
                raise Parada("el inicio no devolvio la URL de autorizacion")
            return volver(navegador, construir(leidos), **opciones)
        return hacer

    def sin_cookie():
        _, leidos = iniciar(B.nav)
        return volver(Navegador("sin cookie del flujo"), de_google(leidos, SUB_B))

    def state_ajeno():
        _, ajeno = iniciar(C.nav)
        _, propio = iniciar(B.nav)
        return volver(B.nav, de_google((ajeno[0], propio[1], propio[2]), SUB_B))

    def code_de(leidos):
        return code_para("bueno", SUB_B, leidos[2], leidos[1])

    def cookie_repetida():
        _, leidos = iniciar(B.nav)
        flujo = B.nav.valor(FLUJO)
        return volver(None, de_google(leidos, SUB_B), extra={"Cookie": f"{FLUJO}={flujo}; {FLUJO}={flujo}"})

    caso_vuelta("sin la cookie del flujo", sin_cookie, "flujo", control=control)
    caso_vuelta("con el state de otro flujo", state_ajeno, "state", control=control)
    caso_vuelta("sin iss", con_flujo(lambda l: consulta(("state", l[0]), ("code", code_de(l)))), "iss",
                control=control)
    caso_vuelta("con otro iss", con_flujo(lambda l: consulta(("state", l[0]), ("iss", "https://evil.example"),
                                                             ("code", code_de(l)))), "iss", control=control)
    caso_vuelta("con el iss sin esquema", con_flujo(lambda l: consulta(("state", l[0]), ("iss", "accounts.google.com"),
                                                                       ("code", code_de(l)))), "iss", control=control)
    caso_vuelta("cancelada en Google (access_denied)",
                con_flujo(lambda l: consulta(("error", "access_denied"), ("state", l[0]), ("iss", EMISOR))),
                None, CANCELADO_ACCESO, control)
    caso_vuelta("con otro error de Google",
                con_flujo(lambda l: consulta(("error", "server_error"), ("state", l[0]), ("iss", EMISOR))),
                "error_proveedor", control=control)
    caso_vuelta("desde un fetch de otro sitio (Sec-Fetch-Mode cors)",
                con_flujo(lambda l: de_google(l, SUB_B), extra={"Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty"}),
                "transporte", control=control)
    caso_vuelta("desde una imagen de otro sitio (Sec-Fetch-Dest image)",
                con_flujo(lambda l: de_google(l, SUB_B), extra={"Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "image"}),
                "transporte", control=control)
    caso_vuelta("sin Fetch Metadata",
                con_flujo(lambda l: de_google(l, SUB_B), extra={"Sec-Fetch-Site": None, "Sec-Fetch-Mode": None,
                                                                "Sec-Fetch-Dest": None, "Sec-Fetch-User": None}),
                "transporte", control=control)
    caso_vuelta("con Authorization", con_flujo(lambda l: de_google(l, SUB_B), extra={"Authorization": "Bearer x"}),
                "transporte", control=control)
    caso_vuelta("con la cookie del flujo repetida", cookie_repetida, "cookie", control=control)
    caso_vuelta("con el state repetido",
                con_flujo(lambda l: consulta(("state", l[0]), ("state", l[0]), ("iss", EMISOR), ("code", code_de(l)))),
                "parametros", control=control)
    caso_vuelta("sin code", con_flujo(lambda l: consulta(("state", l[0]), ("iss", EMISOR))), "code", control=control)

    # El flujo repetido: la vuelta buena (canjea una vez) y, con la cookie
    # guardada, la misma vuelta otra vez.
    _, leidos = iniciar(B.nav)
    guardada = B.nav.valor(FLUJO)
    ruta = de_google(leidos, SUB_B)
    antes = len(canjes())
    primera = volver(B.nav, ruta)
    control_repetida = (primera[0] == 303 and una(primera[1], "location") == DESTINO_ACCESO
                        and len(canjes()) == antes + 1)
    pasa(control_repetida, f"c) control: la primera vuelta del flujo canjea ({primera[0]})")
    copia = Navegador("flujo guardado")
    copia.poner(FLUJO, guardada, "lax")
    caso_vuelta("con el flujo repetido", lambda: volver(copia, ruta), "repetida", control=control_repetida)

    # El canje que Google rechaza: llega a Google y la vuelta da fallido.
    caso_vuelta("con un code que Google rechaza", con_flujo(lambda l: de_google(l, SUB_B, "rechazado")), "canje",
                control=control, canjes_esperados=1)

    # La vinculación tiene sus propios destinos.
    def vinculo(construir):
        def hacer():
            _, leidos = iniciar_vinculo(C)
            if leidos is None:
                raise Parada("el inicio de la vinculacion de C no devolvio la URL")
            return volver(C.nav, construir(leidos))
        return hacer
    caso_vuelta("de una vinculacion con otro state",
                vinculo(lambda l: de_google(("x" * 43, l[1], l[2]), SUB_C)), "state", FALLIDO_VINCULO, control)
    caso_vuelta("de una vinculacion cancelada en Google",
                vinculo(lambda l: consulta(("error", "access_denied"), ("state", l[0]), ("iss", EMISOR))),
                None, CANCELADO_VINCULO, control)


def seccion_d():
    p("=== d) el ticket")
    # Repetido (supuesto 6): el ticket ya gastado, aun con un código nuevo.
    hasta_ticket(B.nav, SUB_B)
    ticket = B.nav.valor(TICKET)
    bien = entrar(B)
    control = bien[0] == 201
    pasa(control, f"d) control: el ticket con un codigo bueno abre la sesion ({bien[0]})")
    sesiones = n_sesiones(B)
    atacante = B.nav.copia("ticket repetido")
    atacante.poner(TICKET, ticket, "strict")
    repetido = pedir(atacante, "POST", RUTA_SESION_EXTERNA, {"codigo_totp": codigo_libre(B)[0]}, guardar=False)
    negativo(f"d) el ticket repetido, aun con un codigo nuevo: 401 sin WWW-Authenticate y sin sesion nueva "
             f"({repetido[0]})", repetido[0] == 401 and repetido[2] == CUERPO_401
             and "www-authenticate" not in repetido[1] and n_sesiones(B) == sesiones, control)

    # Un ticket de vinculación no sirve para entrar.
    r, leidos = iniciar_vinculo(C)
    hasta_ticket(C.nav, SUB_C, DESTINO_VINCULO, inicio=(r, leidos))
    sesion_1 = C.nav.copia("C, sesion 1")
    para_entrar = pedir(C.nav, "POST", RUTA_SESION_EXTERNA, {"codigo_totp": codigo_libre(C)[0]})
    negativo(f"d) un ticket de vinculacion para entrar: 401 sin WWW-Authenticate ({para_entrar[0]})",
             para_entrar[0] == 401 and para_entrar[2] == CUERPO_401 and "www-authenticate" not in para_entrar[1],
             control)

    # Una cuenta sin vincular y un código malo: el mismo 401, byte a byte.
    sin_vinculo, malo = RESPUESTAS.get("sin_vinculo"), RESPUESTAS.get("codigo_malo")
    pasa(sin_vinculo is not None and malo is not None and (sin_vinculo[0], sin_vinculo[2]) == (malo[0], malo[2])
         == (401, CUERPO_401) and "www-authenticate" not in sin_vinculo[1] and "www-authenticate" not in malo[1],
         "d) cuenta sin vincular y codigo malo: el mismo 401, byte a byte, sin WWW-Authenticate")

    # El ticket de otra sesión de la misma cuenta (R2): C vuelve a entrar con
    # contraseña y usa con esa sesión el ticket que pidió la anterior.
    login(C)
    otra_sesion = completar(C)
    vinculo = completar(C, sesion_1)
    control_vinculo = vinculo[0] == 204
    pasa(control_vinculo, f"d) control: el ticket de vinculacion con su propia sesion vincula ({vinculo[0]})")
    negativo(f"d) el ticket de vinculacion con otra sesion de la misma cuenta: 401 sin WWW-Authenticate "
             f"({otra_sesion[0]})", otra_sesion[0] == 401 and otra_sesion[2] == CUERPO_401
             and "www-authenticate" not in otra_sesion[1], control_vinculo)
    C.nav.cookies.pop(TICKET, None)
    RESPUESTAS["vinculo_c"] = vinculo

    # El vínculo revocado entre la vuelta y el código.
    hasta_ticket(C.nav, SUB_C)
    entra = entrar(C)
    control_c = entra[0] == 201
    pasa(control_c, f"d) control: C entra con su cuenta de Google ({entra[0]})")
    hasta_ticket(C.nav, SUB_C)
    revocado = revocar(C)
    RESPUESTAS["revocacion_c"] = revocado
    pasa(revocado[0] == 204, f"d) C desvincula su cuenta de Google con un codigo ({revocado[0]})")
    tarde = pedir(C.nav, "POST", RUTA_SESION_EXTERNA, {"codigo_totp": codigo_libre(C)[0]})
    negativo(f"d) con el vinculo revocado entre la vuelta y el codigo: 401 ({tarde[0]})",
             tarde[0] == 401 and tarde[2] == CUERPO_401, control_c and revocado[0] == 204)


def seccion_e():
    p("=== e) vincular y revocar: avisos y los 409")
    # Vinculaciones: B (en a) y C (en d). Revocación: C (en d). El titular y
    # el admin reciben cada aviso; el otro instructor, ninguno.
    def con_texto(lista, texto):
        return len(lista) == 1 and texto in (lista[0]["texto"] or "")

    def tienen(lista, textos):
        return len(lista) == len(textos) and all(any(t in (c["texto"] or "") for c in lista) for t in textos)

    titular_b = correos(B.email, ASUNTO_VINCULADO, 1)
    titular_c = correos(C.email, ASUNTO_VINCULADO, 1)
    admin = correos(A.email, ASUNTO_VINCULADO, 2)
    titular_revocacion = correos(C.email, ASUNTO_DESVINCULADO, 1)
    admin_revocacion = correos(A.email, ASUNTO_DESVINCULADO, 1)
    # Después de esperar a todos: así el buzón ya tiene los que tenían que llegar.
    avisos = [c for c in buzon() if c["asunto"] in (ASUNTO_VINCULADO, ASUNTO_DESVINCULADO)]
    control = con_texto(titular_b, TEXTO_TITULAR.format(email=B.email, hecho=HECHO_VINCULADO))
    pasa(control, f"e) el titular recibe el aviso de su vinculacion ({len(titular_b)} correos)")
    pasa(con_texto(titular_c, TEXTO_TITULAR.format(email=C.email, hecho=HECHO_VINCULADO)),
         f"e) tambien el titular de la vinculacion de C ({len(titular_c)} correos)")
    pasa(tienen(admin, [TEXTO_VIGILANTE.format(email=e, hecho=HECHO_VINCULADO) for e in (B.email, C.email)]),
         f"e) el admin recibe un aviso por cada vinculacion, con la cuenta ({len(admin)} correos)")
    pasa(con_texto(titular_revocacion, TEXTO_TITULAR.format(email=C.email, hecho=HECHO_DESVINCULADO))
         and con_texto(admin_revocacion, TEXTO_VIGILANTE.format(email=C.email, hecho=HECHO_DESVINCULADO)),
         f"e) la revocacion avisa al titular y al admin ({len(titular_revocacion)} y {len(admin_revocacion)} correos)")
    # Quien no vigila (un instructor) no recibe el de otra cuenta: en total,
    # justo los de arriba.
    negativo(f"e) nadie mas recibe estos avisos ({len(avisos)} correos de vinculos en el buzon)",
             len(avisos) == 6 and not any(c["para"] == [C.email] and B.email in (c["texto"] or "") for c in avisos),
             control)
    filtrados = sorted({v[:12] for v in VISTOS | set(SUBS) for c in avisos if len(v) >= 8 and v in (c["texto"] or "")})
    negativo("e) los avisos no llevan ningun sub, ticket, flujo ni token", not filtrados, bool(avisos),
             f"encontrados: {filtrados}")

    # La identidad ya vinculada a otra cuenta: C con la cuenta de Google de B.
    r, leidos = iniciar_vinculo(C)
    hasta_ticket(C.nav, SUB_B, DESTINO_VINCULO, inicio=(r, leidos))
    duplicada = completar(C)
    control_vinculo = (RESPUESTAS.get("vinculo_c") or (0,))[0] == 204
    negativo(f"e) la cuenta de Google de otra cuenta: 409 con su texto ({duplicada[0]}, {duplicada[2][:90]!r})",
             duplicada[0] == 409 and duplicada[2] == CUERPO_409_IDENTIDAD, control_vinculo)
    C.nav.cookies.pop(TICKET, None)
    # La cuenta que ya tiene una: B. Se dice antes de gastar el código.
    paso = paso_de(B)
    ya = iniciar_vinculo(B)[0]
    negativo(f"e) la cuenta que ya tiene una de Google: 409 con su texto, sin flujo y sin gastar el codigo "
             f"({ya[0]}, {ya[2][:90]!r})", ya[0] == 409 and ya[2] == CUERPO_409_CUENTA and "set-cookie" not in ya[1]
             and paso_de(B) == paso, control_vinculo)
    # Revocar sin vínculo: C ya no tiene.
    sin = revocar(C)
    negativo(f"e) revocar sin vinculo: 404 ({sin[0]})", sin[0] == 404 and sin[2] == CUERPO_404,
             (RESPUESTAS.get("revocacion_c") or (0,))[0] == 204)


def seccion_f():
    p("=== f) dos vinculaciones a la vez con la misma cuenta de Google")
    for cuenta in (A, C):
        r, leidos = iniciar_vinculo(cuenta)
        hasta_ticket(cuenta.nav, SUB_CARRERA, DESTINO_VINCULO, inicio=(r, leidos))
        asegurar_sesion(cuenta)
    with concurrent.futures.ThreadPoolExecutor(2) as grupo:
        respuestas = list(grupo.map(completar, (A, C)))
    estados = sorted(r[0] for r in respuestas)
    cuerpo_409 = next((r[2] for r in respuestas if r[0] == 409), None)
    pasa(estados == [204, 409] and cuerpo_409 == CUERPO_409_IDENTIDAD,
         f"f) una vinculacion 204 y la otra 409 con su texto ({estados})")
    vigentes = valor(f"select count(*) from canal.identidad_externa where usuario_id in ('{A.usuario_id}', "
                     f"'{C.usuario_id}') and not revocada;")
    pasa(vigentes == "1", f"f) queda un solo vinculo vigente entre las dos cuentas ({vigentes})")
    p("   prueba minima: no demuestra que las dos transacciones se solaparan en PostgreSQL")


def seccion_g():
    p("=== g) Redis y el broker")
    # Sin poder gastar el ticket (supuesto 7): el resto del limitador cuenta.
    hasta_ticket(B.nav, SUB_B)
    antes = escrito(B)
    desde = marca()
    poner_acl(permisos_sin("ticket"))
    control_contador = proveedores_ok()
    sin_gastar = pedir(B.nav, "POST", RUTA_SESION_EXTERNA, {"codigo_totp": codigo_libre(B)[0]})
    despues = escrito(B)
    lineas = nuevas(desde)
    poner_acl(PERMISOS_ACL_APLICACION)
    # Control: el ticket no se gastó (la cookie sigue en el navegador: un
    # error no la borra), así que ahora abre la sesión.
    bien = entrar(B)
    control = bien[0] == 201 and control_contador
    pasa(control_contador, "g) control: con la ACL sin limite:ticket:*, el limitador sigue contando (200)")
    pasa(bien[0] == 201, f"g) control: con la ACL de produccion, el mismo ticket abre la sesion ({bien[0]})")
    negativo(f"g) sin poder gastar el ticket: 503 con Retry-After y EVENTO limitador_no_disponible ({sin_gastar[0]})",
             sin_gastar[0] == 503 and sin_gastar[2] == CUERPO_503 and una(sin_gastar[1], "retry-after") == REINTENTAR_TRAS
             and any(EVENTO_LIMITADOR in linea for linea in lineas), control)
    negativo(f"g) y nada escrito: ni sesion, ni auditoria, ni el paso del codigo ({antes} -> {despues})",
             antes == despues, control)

    # Sin poder gastar el flujo: ningún canje.
    _, leidos = iniciar(B.nav)
    guardada = B.nav.valor(FLUJO)
    ruta = de_google(leidos, SUB_B)
    poner_acl(permisos_sin("flujo"))
    control_contador = proveedores_ok()
    antes = len(canjes())
    desde = marca()
    v = volver(B.nav, ruta)
    lineas = nuevas(desde)
    nuevos = len(canjes()) - antes
    poner_acl(PERMISOS_ACL_APLICACION)
    copia = B.nav.copia("flujo guardado")
    copia.poner(FLUJO, guardada, "lax")
    antes = len(canjes())
    otra = volver(copia, ruta)
    control = (control_contador and otra[0] == 303 and una(otra[1], "location") == DESTINO_ACCESO
               and len(canjes()) == antes + 1)
    pasa(control, "g) control: con la ACL de produccion, el mismo flujo canjea (no se habia gastado)")
    negativo(f"g) sin poder gastar el flujo: 303 a {NO_DISPONIBLE_ACCESO}, EVENTO limitador_no_disponible y ningun "
             f"canje ({v[0]}, {una(v[1], 'location')!r}, canjes {nuevos})",
             v[0] == 303 and una(v[1], "location") == NO_DISPONIBLE_ACCESO and nuevos == 0
             and any(EVENTO_LIMITADOR in linea for linea in lineas), control)

    # Redis reiniciado: se olvida de los tickets gastados.
    hasta_ticket(B.nav, SUB_B)
    ticket = B.nav.valor(TICKET)
    esperar_inicio_de_paso()
    codigo, paso = codigo_libre(B)
    primera = pedir(B.nav, "POST", RUTA_SESION_EXTERNA, {"codigo_totp": codigo})
    if primera[0] == 201:
        gastado(B, paso)
        EXITOS["acceso_externo"].append(B.usuario_id)
    pasa(primera[0] == 201, f"g) control: el ticket abre la sesion antes de reiniciar Redis ({primera[0]})")
    reiniciar_redis()
    copia = B.nav.copia("ticket guardado")
    copia.poner(TICKET, ticket, "strict")
    # El código vale su paso y el siguiente: si ya ha caducado, el 401 no
    # diría por qué.
    a_tiempo = time.time() < (paso + 2) * 30 - 2
    mismo = pedir(copia, "POST", RUTA_SESION_EXTERNA, {"codigo_totp": codigo}, guardar=False)
    if not a_tiempo:
        sinc("g) Redis reiniciado, el ticket repetido con el mismo codigo: el codigo ya habia caducado")
    else:
        negativo(f"g) Redis reiniciado: el ticket repetido con el mismo codigo da 401 por ultimo_paso_totp ({mismo[0]})",
                 mismo[0] == 401 and mismo[2] == CUERPO_401, primera[0] == 201)
    # Ese intento ha vuelto a gastar el jti en el Redis vacío (el ticket se
    # gasta antes de confirmar el paso): para ver el límite hace falta otro
    # reinicio.
    reiniciar_redis()
    nuevo = entrar(B, copia)
    pasa(nuevo[0] == 201, "g) limite documentado (docs/threat-model.md, 8): con Redis reiniciado y un codigo nuevo, "
                          f"el ticket repetido abre otra sesion ({nuevo[0]})")

    # Redis parado: el limitador falla cerrado antes de llegar a la ruta.
    hasta_ticket(B.nav, SUB_B)
    _, leidos = iniciar(B.nav)
    guardada = B.nav.valor(FLUJO)
    ruta = de_google(leidos, SUB_B)
    dc("stop", "redis")
    antes = len(canjes())
    v = volver(B.nav, ruta)
    s = pedir(B.nav, "POST", RUTA_SESION_EXTERNA, {"codigo_totp": codigo_libre(B)[0]})
    nuevos = len(canjes()) - antes
    dc("start", "redis")
    if not esperar(proveedores_ok, 60):
        raise Parada("Redis no vuelve tras arrancarlo")
    copia = B.nav.copia("flujo guardado")
    copia.poner(FLUJO, guardada, "lax")
    otra = volver(copia, ruta)
    control = otra[0] == 303 and una(otra[1], "location") == DESTINO_ACCESO
    pasa(control, f"g) control: con Redis de vuelta, la misma vuelta llega a /entrar/codigo ({otra[0]})")
    negativo(f"g) Redis parado: la vuelta, 303 a {NO_DISPONIBLE_ACCESO} sin canje ({v[0]}, {una(v[1], 'location')!r})",
             v[0] == 303 and una(v[1], "location") == NO_DISPONIBLE_ACCESO and nuevos == 0, control)
    negativo(f"g) Redis parado: la sesion externa, 503 con Retry-After ({s[0]})",
             s[0] == 503 and s[2] == CUERPO_503 and una(s[1], "retry-after") == REINTENTAR_TRAS, control)

    # El broker parado: la API no tiene a quién pedir la URL ni el canje.
    _, leidos = iniciar(B.nav)
    ruta = de_google(leidos, SUB_B)
    dc("stop", "broker")
    desde = marca()
    sin_broker = pedir(B.nav.copia("B"), "POST", RUTA_INICIO, {"empresa": IDENTIFICADOR})
    v = volver(B.nav, ruta)
    lineas = nuevas(desde)
    r = dc("up", "-d", "--wait", "--wait-timeout", "60", "broker")
    if r.rc != 0:
        raise Parada(f"el broker no vuelve a arrancar: {r.todo.strip()[-300:]}")
    control = iniciar(B.nav)[1] is not None
    pasa(control, "g) control: con el broker de vuelta, el inicio da la URL")
    negativo(f"g) broker parado: el inicio, 503 con Retry-After, sin cookie del flujo y su EVENTO ({sin_broker[0]})",
             sin_broker[0] == 503 and sin_broker[2] == CUERPO_503
             and una(sin_broker[1], "retry-after") == REINTENTAR_TRAS and "set-cookie" not in sin_broker[1]
             and any(EVENTO_BROKER_AUTORIZAR in linea for linea in lineas), control)
    negativo(f"g) broker parado: la vuelta, 303 a {NO_DISPONIBLE_ACCESO} y su EVENTO ({v[0]}, {una(v[1], 'location')!r})",
             v[0] == 303 and una(v[1], "location") == NO_DISPONIBLE_ACCESO
             and any(EVENTO_BROKER_CANJEAR in linea for linea in lineas), control)

    # Google caído (responde 500): el broker da 503 y la vuelta, no_disponible.
    _, leidos = iniciar(B.nav)
    antes = len(canjes())
    desde = marca()
    v = volver(B.nav, de_google(leidos, SUB_B, "caido"))
    lineas = nuevas(desde)
    negativo(f"g) Google caido: 303 a {NO_DISPONIBLE_ACCESO} y EVENTO broker_no_disponible motivo=estado "
             f"({v[0]}, {una(v[1], 'location')!r})",
             v[0] == 303 and una(v[1], "location") == NO_DISPONIBLE_ACCESO and len(canjes()) == antes + 1
             and any(EVENTO_BROKER_CANJEAR + "estado" in linea for linea in lineas), control)


def seccion_i():
    p("=== i) entradas maliciosas en las rutas del login externo")
    antes = len(canjes())
    hasta_ticket(B.nav, SUB_B)
    control = len(canjes()) == antes + 1
    pasa(control, "i) control: la vuelta buena canjea y lleva a /entrar/codigo")
    # En la vuelta. Cada valor ya codificado como iría en la URL.
    malos = {
        "salto de linea": "%0D%0ASet-Cookie:%20x=y",
        "NUL": "a%00b",
        "unicode": "%C3%B1" * 43,
        "bytes que no son UTF-8": "%FF%FE%FD",
        "8000 caracteres": "a" * 8000,
        "HTML": "%3Cscript%3Ealert(1)%3C/script%3E",
        "SQL": "%27%20or%201=1--",
        "espacio": "a%20b",
    }
    motivos = {"state": "state", "code": "code", "iss": "iss", "error": "error_proveedor"}
    # El HTML del code es ASCII imprimible sin espacios: tiene la forma de un
    # code (PATRON_CODE), llega a Google y Google lo rechaza.
    especiales = {("code", "HTML"): ("canje", 1)}
    for parametro, motivo_parametro in motivos.items():
        for nombre, malo in malos.items():
            motivo, esperados = especiales.get((parametro, nombre), (motivo_parametro, 0))
            _, leidos = iniciar(B.nav)
            if leidos is None:
                raise Parada("el inicio no devolvio la URL de autorizacion")
            bueno = {"state": leidos[0], "iss": urllib.parse.quote(EMISOR, safe=""),
                     "code": urllib.parse.quote(code_para("bueno", SUB_B, leidos[2], leidos[1]), safe="")}
            bueno[parametro] = malo
            orden = ["error", "state", "iss", "code"] if parametro == "error" else ["state", "iss", "code"]
            antes = len(canjes())
            desde = marca()
            r = volver(B.nav, RUTA_VUELTA + "?" + "&".join(f"{k}={bueno[k]}" for k in orden))
            lineas = nuevas(desde)
            nuevos = len(canjes()) - antes
            ok = (r[0] == 303 and una(r[1], "location") == FALLIDO_ACCESO and TICKET not in puestas(r[1])
                  and nuevos == esperados and motivos_en(lineas) == [motivo]
                  and not any("Traceback" in linea or "error interno" in linea for linea in lineas))
            negativo(f"i) {parametro} con {nombre}: 303 a {FALLIDO_ACCESO}, motivo={motivo}, sin 500 y {esperados} "
                     f"canjes ({r[0]}, {una(r[1], 'location')!r}, {motivos_en(lineas)}, canjes {nuevos})", ok, control)

    # En las rutas JSON: el mismo 422, antes de la lógica.
    asegurar_sesion(B)
    r, leidos = iniciar(B.nav)
    control_json = r[0] == 200 and leidos is not None
    pasa(control_json, f"i) control: el inicio valido da 200 ({r[0]})")
    casos = [
        (RUTA_INICIO, "POST", {"empresa": "a\u0000b"}, None),
        (RUTA_INICIO, "POST", {"empresa": "a\nb"}, None),
        (RUTA_INICIO, "POST", {"empresa": 5}, None),
        (RUTA_INICIO, "POST", {"empresa": "a" * 65}, None),
        (RUTA_INICIO, "POST", {"empresa": IDENTIFICADOR, "otro": 1}, None),
        (RUTA_INICIO, "POST", None, b"no es json"),
        (RUTA_SESION_EXTERNA, "POST", {"codigo_totp": "1" * 17}, None),
        (RUTA_SESION_EXTERNA, "POST", {"codigo_totp": "12345\u001b"}, None),
        (RUTA_SESION_EXTERNA, "POST", {"codigo_totp": 123456}, None),
        (RUTA_VINCULO_INICIO, "POST", {"codigo_totp": "\u001b[31m"}, None),
        (RUTA_VINCULO_INICIO, "POST", {}, None),
        (RUTA_VINCULO, "DELETE", {"codigo_totp": None}, None),
    ]
    for ruta, metodo, datos, crudo in casos:
        codigo, _, cuerpo = pedir(B.nav.copia("B"), metodo, ruta, datos, crudo=crudo, guardar=False)
        etiqueta = repr(datos)[:40] if crudo is None else repr(crudo)
        negativo(f"i) {metodo} {ruta} con {etiqueta}: 422 con el cuerpo fijo ({codigo})",
                 codigo == 422 and cuerpo == CUERPO_422, control_json, f"cuerpo: {cuerpo[:100]!r}")
    # Quien no es el navegador de la SPA no usa estas rutas.
    desde = marca()
    cliente = pedir(None, "POST", RUTA_INICIO, {"empresa": IDENTIFICADOR}, extra={"Sec-Fetch-Site": None,
                                                                                    "Origin": None},
                    puerto=PUERTO_API)
    lineas = nuevas(desde)
    negativo(f"i) un cliente sin cookies ni Sec-Fetch-Site (por el 8443): 403 y EVENTO origen_rechazado ({cliente[0]})",
             cliente[0] == 403 and cliente[2] == CUERPO_403 and any(EVENTO_ORIGEN_INICIO in l for l in lineas),
             control_json)
    otro_puerto = pedir(B.nav.copia("B"), "POST", RUTA_INICIO, {"empresa": IDENTIFICADOR},
                        extra={"Sec-Fetch-Site": "same-site", "Origin": ORIGEN_WEB}, guardar=False)
    negativo(f"i) desde el 8444 (same-site): 403 sin cookie del flujo ({otro_puerto[0]})",
             otro_puerto[0] == 403 and otro_puerto[2] == CUERPO_403 and "set-cookie" not in otro_puerto[1],
             control_json)


def seccion_h():
    p("=== h) /yo, auditoria, eventos, logs y volcado")
    asegurar_sesion(B)
    codigo, _, cuerpo = pedir(B.nav, "GET", "/v1/personal/yo")
    vinculos = (json_de(cuerpo) or {}).get("vinculos")
    pasa(codigo == 200 and isinstance(vinculos, list) and len(vinculos) == 1
         and sorted(vinculos[0]) == ["creada", "proveedor"] and vinculos[0]["proveedor"] == "google"
         and PATRON_FECHA.fullmatch(str(vinculos[0]["creada"])) is not None,
         f"h) /yo de B: un vinculo, solo con el proveedor y el dia ({codigo}, {vinculos})")
    pasa(not any(sub.encode() in cuerpo for sub in SUBS), "h) /yo no lleva ningun sub")

    # Auditoría: una fila por cada éxito de la batería, con la cuenta afectada.
    filas = valor(f"select accion || '|' || objeto_id from canal.registro_auditoria where empresa_id = '{EMPRESA_ID}' "
                  f"and accion in ('acceso_externo', 'vinculacion_externa', 'revocacion_externa') order by secuencia;")
    leidas = {accion: [] for accion in ACCIONES_EXTERNAS}
    for fila in filter(None, filas.splitlines()):
        accion, _, objeto = fila.partition("|")
        leidas[accion].append(objeto)
    for accion in ACCIONES_EXTERNAS:
        pasa(sorted(leidas[accion]) == sorted(EXITOS[accion]) and EXITOS[accion],
             f"h) auditoria: {len(EXITOS[accion])} filas {accion}, una por exito, con la cuenta afectada "
             f"({len(leidas[accion])})")

    # Cada EVENTO vuelta_rechazada, con un motivo de la lista cerrada.
    eventos = [l.rstrip() for l in lineas_log("api") if EVENTO_VUELTA in l]
    raros = [l[-80:] for l in eventos if not PATRON_EVENTO_VUELTA.fullmatch(l)]
    pasa(eventos and not raros, f"h) {len(eventos)} EVENTO vuelta_rechazada, todos con un motivo de la lista cerrada "
                                f"{raros if raros else ''}".rstrip())

    # Los logs: nada de lo que ha pasado por la batería.
    for x in peticiones_falso():
        VISTOS.update(v for k, v in x.get("formulario", {}).items() if k in ("code_verifier", "code", "client_secret"))
    sensibles = {v for v in VISTOS | set(SUBS) | {CLIENT_SECRET, PREFIJO_CODE} if v and len(v) >= 8}
    control = len(sensibles) >= 50
    pasa(control, f"h) control: {len(sensibles)} valores sensibles vistos en la bateria")
    for servicio in ("api", "broker", "caddy", "postgres", "redis"):
        texto = "\n".join(lineas_log(servicio))
        encontrados = sorted({v[:12] for v in sensibles if v in texto})
        negativo(f"h) el log de {servicio} no lleva ningun code, state, nonce, verifier, ticket, flujo, sub, token "
                 f"ni el client_secret", not encontrados and bool(texto), control, f"encontrados: {encontrados}")

    # El volcado: del sub solo queda su HMAC.
    r = dc("exec", "-T", "postgres", "pg_dump", "-U", "postgres", "-d", "canario", "--data-only")
    control_volcado = r.rc == 0 and B.email in r.out
    pasa(control_volcado, f"h) control: el volcado de la base de datos tiene datos (el email de B) ({r.rc})")
    negativo("h) el volcado no lleva ningun sub de Google", not any(sub in r.out for sub in SUBS), control_volcado)


# ---------------------------------------------------------------------------
# Limpieza, precondiciones y arranque
# ---------------------------------------------------------------------------
def seccion_s():
    p("=== s) limpieza")
    ejecutar(["docker", "rm", "-f", GOOGLE])
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
        sinc("s) no se pudo comparar el estado de Git (git no disponible, fallo o el directorio no es un repositorio)")
    else:
        iguales = final == ESTADO_GIT_ARRANQUE
        pasa(iguales, "s) la bateria no ha modificado el repo (git status igual al del arranque)")
        if not iguales:
            p(f"   al arrancar: {ESTADO_GIT_ARRANQUE}")
            p(f"   al terminar: {final}")


def fichero_secreto(nombre, ruta):
    return [f"  {nombre}:", f"    file: \"{ruta.as_posix()}\""]


def escribir_auxiliares():
    """Secretos falsos, configuración de Google falsa, la CA de prueba en el
    broker, salida interna y los límites de prueba, en ficheros de compose
    adicionales (como verificar_personal.py y verificar_externo.py)."""
    global PRUEBA, SECRETOS
    PRUEBA = TEMPORAL / "prueba"
    SECRETOS = TEMPORAL / "secretos_compose"
    PRUEBA.mkdir()
    SECRETOS.mkdir()
    (PRUEBA / "falso.py").write_text(FALSO, encoding="utf-8", newline="\n")
    # El override necesita que exista antes de cualquier config; a) la escribe.
    (PRUEBA / "ca_bateria.pem").write_bytes(b"")
    lineas = ["secrets:"]
    for nombre in ("clave_maestra", "clave_hmac_codigos", "clave_firma_tokens", "clave_hmac_identidades",
                   "clave_flujo_externo"):
        (SECRETOS / nombre).write_text(secrets.token_hex(32), encoding="ascii", newline="")
        lineas += fichero_secreto(nombre, SECRETOS / nombre)
    for usuario in ("aplicacion", "inspector"):
        CONTRASENAS_REDIS[usuario] = secrets.token_urlsafe(48)
    (SECRETOS / "contrasena_redis").write_text(CONTRASENAS_REDIS["aplicacion"], encoding="ascii", newline="")
    (SECRETOS / "redis_acl").write_text(texto_acl(PERMISOS_ACL_APLICACION), encoding="ascii", newline="\n")
    (SECRETOS / "google_client_id").write_bytes(CLIENT_ID.encode("ascii"))
    (SECRETOS / "google_client_secret").write_bytes(CLIENT_SECRET.encode("ascii"))
    for nombre in ("contrasena_redis", "redis_acl", "google_client_id", "google_client_secret"):
        lineas += fichero_secreto(nombre, SECRETOS / nombre)
    adicional = TEMPORAL / "secretos_falsos.yml"
    adicional.write_text("\n".join(lineas) + "\n", encoding="utf-8", newline="\n")
    override = TEMPORAL / "override.yml"
    override.write_text(
        "services:\n"
        "  api:\n"
        "    environment:\n"
        f"      CANARIO_LIMITES: \"{LIMITES_PRUEBA}\"\n"
        "  broker:\n"
        "    volumes:\n"
        "      - type: bind\n"
        f"        source: \"{(PRUEBA / 'ca_bateria.pem').as_posix()}\"\n"
        "        target: /usr/lib/ssl/cert.pem\n"
        "        read_only: true\n"
        "networks:\n"
        "  salida:\n"
        "    internal: true\n",
        encoding="utf-8", newline="\n")
    BASE.extend(["-f", str(adicional), "-f", str(override)])


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
    """Líneas de "git status --short -uall", o None si git no está disponible o falla."""
    try:
        r = ejecutar(["git", "status", "--short", "-uall"], timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.rc != 0:
        return None
    return [linea.rstrip() for linea in r.out.splitlines() if linea.strip()]


def recursos_previos():
    previos = []
    for orden in (["docker", "ps", "-a", "--format", "{{.Names}}"],
                  ["docker", "network", "ls", "--format", "{{.Name}}"],
                  ["docker", "volume", "ls", "--format", "{{.Name}}"]):
        previos += [n for n in ejecutar(orden).out.split() if n.startswith(PROYECTO)]
    return previos


def subredes_ocupadas():
    """Redes ajenas que ya usan alguna de las subredes fijas del compose."""
    ocupadas = []
    for red in ejecutar(["docker", "network", "ls", "-q"]).out.split():
        r = ejecutar(["docker", "network", "inspect", "--format",
                      "{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}", red])
        partes = r.out.split()
        if partes and set(partes[1:]) & set(SUBREDES):
            ocupadas.append(partes[0])
    return ocupadas


def puertos_ocupados():
    ocupados = []
    for puerto in (PUERTO_API, PUERTO_WEB, PUERTO_SPA):
        s = socket.socket()
        s.settimeout(2)
        try:
            if s.connect_ex(("127.0.0.1", puerto)) == 0:
                ocupados.append(puerto)
        finally:
            s.close()
    return ocupados


ESTADO_GIT_ARRANQUE = None


def main():
    global ESTADO_GIT_ARRANQUE, TEMPORAL
    # Estado de Git al arrancar, antes de levantar Docker: s) lo compara con el final.
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
        p(f"PARADA: las subredes {', '.join(SUBREDES)} ya estan en uso por {ocupadas} (pare el proyecto canario)")
        terminar_con_parada()
    ocupados = puertos_ocupados()
    if ocupados:
        p(f"PARADA: 127.0.0.1:{ocupados} ya esta en uso (pare el proyecto canario)")
        terminar_con_parada()
    # Solo se comprueba que existen (is_file), nunca se leen: son las
    # contraseñas de los roles de PostgreSQL, las únicas de secrets/ que usa.
    for fichero in ("contrasena_postgres_superusuario.txt", "contrasena_migrador.txt", "contrasena_aplicacion.txt",
                    "contrasena_plataforma.txt"):
        if not (RAIZ / "secrets" / fichero).is_file():
            p(f"PARADA: secrets/{fichero} no existe (ejecute scripts/generar_secretos.py)")
            terminar_con_parada()
    TEMPORAL = pathlib.Path(tempfile.mkdtemp(prefix="canario_loginext_"))
    escribir_auxiliares()
    r = dc("config", "--quiet")
    if r.rc != 0:
        p(f"PARADA: docker compose config falla (genere los secretos con scripts/generar_secretos.py): {r.err.strip()[:300]}")
        shutil.rmtree(TEMPORAL, ignore_errors=True)
        terminar_con_parada()
    parada = None
    try:
        for seccion in (seccion_a, seccion_b, seccion_c, seccion_d, seccion_e, seccion_f, seccion_g, seccion_i,
                        seccion_h):
            seccion()
    except Parada as e:
        parada = str(e)
        p(f"PARADA: {parada}")
    except Exception:  # noqa: BLE001 - error inesperado del propio test: se informa y se limpia
        parada = "error inesperado en el test"
        p("ERROR INESPERADO:\n" + traceback.format_exc())
    finally:
        if parada is not None:
            ejecutar(["docker", "rm", "-f", GOOGLE])
            dc_con_gestion("down", "-v", "--rmi", "local")
        else:
            seccion_s()
        shutil.rmtree(TEMPORAL, ignore_errors=True)
    if parada is not None:
        estado["falla"] = True
    terminar()


if __name__ == "__main__":
    main()
