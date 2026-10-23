#!/usr/bin/env python3
"""Batería de seguridad del broker de canje (app/broker.py y
app/proveedores_externos.py): el único contenedor con salida a internet y el
único que habla con Google (docs/threat-model.md, 6.19).

Qué prueba:
a) La definición del compose real, con oráculos literales: punto de entrada,
   --host, redes (canje interna con su subred, salida con internet y solo
   para el broker; la API nunca en salida), secretos (solo los dos de
   Google), entorno (el origen es el mismo valor que el de la API) y ningún
   montaje. La CA de prueba solo existe en el override de esta batería.
b) El contenedor: usuario no root, solo lectura, sin capacidades, sin nuevos
   privilegios, límites y sano.
c) Quién le habla: escucha solo en su IP de canje (desde salida, rechazo) y
   solo atiende a la IP de la API (otra IP de canje, 403; /salud abierta).
d) La URL de autorización exacta, con S256 y solo el scope openid.
e) El canje contra un Google falso con el nombre real (alias de red
   oauth2.googleapis.com) y un certificado de una CA de prueba: el canje
   bueno devuelve solo el sub, y cada fallo del id_token o de la respuesta
   da 401 o 503 con su EVENTO. Una redirección no se sigue.
f) TLS: el mismo nombre con un certificado de otra CA da 503 (tls).
g) Saturación: con cinco canjes lentos a la vez, el quinto recibe 503 en el
   acto; los cuatro primeros se cortan a los 10 s.
h) Entradas mal formadas: 422 con el mismo cuerpo, sin repetir lo recibido.
i) El log del broker no lleva el client_secret, el verifier, el code, el sub
   ni ningún token.
j) Configuración: sin configurar, Google desactivado y visible en el log; a
   medias, el broker no arranca.
s) Limpieza y repositorio intacto.
Cada prueba negativa lleva su control positivo: si el control falla, el
resultado es SIN CONCLUSION, nunca PASA. Los oráculos son literales.

Cómo se ejecuta (desde la raíz del repositorio, en PowerShell, con Docker en
marcha y los secretos generados con scripts/generar_secretos.py):

    python tests/security/verificar_externo.py

Usa un proyecto de Docker propio (canario_externo) y solo levanta el broker;
el Google falso y los clientes son contenedores desechables con la imagen del
broker. La subred de canje (10.88.2.0/28) es fija: si está en uso (el
proyecto canario en marcha), PARADA. No lee ningún secreto: el override
sustituye los dos ficheros de Google por valores inventados en un directorio
temporal, y el resto solo tiene que existir para que docker compose valide la
configuración. En el override, la red salida es interna: la batería no sale a
internet.

Los ficheros auxiliares (CA y certificados de prueba, el Google falso, el
cliente y el override) se escriben en un directorio temporal del sistema,
nunca dentro del repositorio, y se borran al terminar. La salida completa se
guarda en verificacion_externo.txt dentro del directorio temporal del
sistema. El código de salida es 0 solo si el resultado global es OK.

Solo usa la biblioteca estándar.
"""
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.parse

RAIZ = pathlib.Path.cwd()
PROYECTO = "canario_externo"
SALIDA = pathlib.Path(tempfile.gettempdir()) / "verificacion_externo.txt"
BASE = ["docker", "compose", "-p", PROYECTO, "-f", "docker-compose.yml"]

lineas_salida = []
estado = {"falla": False, "sin_conclusion": False}

# ---------------------------------------------------------------------------
# Oráculos literales
# ---------------------------------------------------------------------------
SUBRED_CANJE = "10.88.2.0/28"
RANGO_CANJE = "10.88.2.8/29"
IP_BROKER = "10.88.2.3"
IP_API = "10.88.2.4"
IP_OTRA = "10.88.2.5"  # en canje, pero no es la API
RED_CANJE = f"{PROYECTO}_canje"
RED_SALIDA = f"{PROYECTO}_salida"
ENTRYPOINT_BROKER = ["uvicorn", "app.broker:aplicacion", "--port", "8000", "--no-access-log", "--no-server-header"]
COMANDO_BROKER = ["--host", IP_BROKER]
SECRETOS_BROKER = ["google_client_id", "google_client_secret"]
MEMORIA = 134217728  # 128m
PIDS = 32
USUARIO = "10001:10001"

# Valores inventados de la batería (nunca los de secrets/). Sin imitar el
# formato de los secretos reales de Google (como el prefijo GOCSPX- o ya29.):
# un valor con forma de credencial lo marca gitleaks (verificar_escaneos.py,
# b) y obligaría a silenciarlo.
CLIENT_ID = "123456789012-bateria.apps.googleusercontent.com"
CLIENT_SECRET = "secreto-falso-de-la-bateria"
MARCADOR_ID = "sin-configurar:client-id"
MARCADOR_SECRETO = "sin-configurar:client-secret"
ORIGEN = "https://localhost:8445"
REDIRECT = "https://localhost:8445/v1/personal/externo/google/vuelta"
STATE = "stateBateria" + "s" * 31
RETO = "retoBateria0" + "c" * 31
NONCE = "nonceBateria" + "n" * 31
VERIFIER = "verifierDeLaBateria-" + "v" * 30
SUB = "108765432109876543210"
PREFIJO_CODE = "4/0Bateria-"
TOKEN_ACCESO = "token-falso-de-la-bateria"

URL_AUTORIZACION = (
    "https://accounts.google.com/o/oauth2/v2/auth"
    "?client_id=123456789012-bateria.apps.googleusercontent.com"
    "&redirect_uri=https%3A%2F%2Flocalhost%3A8445%2Fv1%2Fpersonal%2Fexterno%2Fgoogle%2Fvuelta"
    "&response_type=code&scope=openid"
    f"&state={STATE}&code_challenge={RETO}&code_challenge_method=S256&nonce={NONCE}")

CUERPO_FORMATO = '{"detalle":"formato no valido"}'
CUERPO_PROHIBIDO = '{"detalle":"prohibido"}'
CUERPO_NO_CONFIGURADO = '{"detalle":"proveedor no configurado"}'
CUERPO_FALLIDO = '{"detalle":"canje fallido"}'
CUERPO_NO_DISPONIBLE = '{"detalle":"proveedor no disponible"}'
CUERPO_SALUD = '{"estado":"ok"}'
CUERPO_BUENO = json.dumps({"proveedor": "google", "sub": SUB}, separators=(",", ":"))

LOG_DESACTIVADO = "EVENTO proveedor_desactivado: proveedor=google"
LOG_A_MEDIAS = "ARRANQUE BLOQUEADO: google configurado a medias: google_client_secret conserva su marcador"

# Escenario del Google falso (el code) -> (estado del broker, cuerpo, EVENTO del log o None).
ESCENARIOS = {
    "bueno": (200, CUERPO_BUENO, None),
    "iss_sin_esquema": (200, CUERPO_BUENO, None),
    "aud_ajena": (401, CUERPO_FALLIDO, "EVENTO canje_fallido: proveedor=google motivo=aud"),
    "aud_lista": (401, CUERPO_FALLIDO, "EVENTO canje_fallido: proveedor=google motivo=aud"),
    "azp_ajeno": (401, CUERPO_FALLIDO, "EVENTO canje_fallido: proveedor=google motivo=azp"),
    "iss_falso": (401, CUERPO_FALLIDO, "EVENTO canje_fallido: proveedor=google motivo=iss"),
    "caducado": (401, CUERPO_FALLIDO, "EVENTO canje_fallido: proveedor=google motivo=exp"),
    "nonce_otro": (401, CUERPO_FALLIDO, "EVENTO canje_fallido: proveedor=google motivo=nonce"),
    "sin_sub": (401, CUERPO_FALLIDO, "EVENTO canje_fallido: proveedor=google motivo=sub"),
    "sub_largo": (401, CUERPO_FALLIDO, "EVENTO canje_fallido: proveedor=google motivo=sub"),
    "rechazado": (401, CUERPO_FALLIDO, "EVENTO canje_fallido: proveedor=google motivo=rechazado"),
    "json_roto": (401, CUERPO_FALLIDO, "EVENTO canje_fallido: proveedor=google motivo=json"),
    "grande": (401, CUERPO_FALLIDO, "EVENTO canje_fallido: proveedor=google motivo=respuesta_grande"),
    "error_500": (503, CUERPO_NO_DISPONIBLE, "EVENTO proveedor_no_disponible: proveedor=google motivo=estado"),
    "redireccion": (503, CUERPO_NO_DISPONIBLE, "EVENTO proveedor_no_disponible: proveedor=google motivo=estado"),
    "lento": (503, CUERPO_NO_DISPONIBLE, "EVENTO proveedor_no_disponible: proveedor=google motivo=plazo"),
}

# ---------------------------------------------------------------------------
# Ficheros auxiliares (se escriben en el directorio temporal)
# ---------------------------------------------------------------------------
# CA de la batería y dos certificados para oauth2.googleapis.com: uno firmado
# por ella (el bueno) y otro por una CA ajena (f). Corre en la imagen del
# broker, sin red, con cryptography de requirements.txt.
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


def ca(texto):
    clave = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(nombre(texto)).issuer_name(nombre(texto))
            .public_key(clave.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(ahora - datetime.timedelta(minutes=5)).not_valid_after(ahora + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                         crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(clave.public_key()), critical=False)
            .sign(clave, hashes.SHA256()))
    return clave, cert


def servidor(clave_ca, cert_ca):
    clave = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(nombre(NOMBRE)).issuer_name(cert_ca.subject)
            .public_key(clave.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(ahora - datetime.timedelta(minutes=5)).not_valid_after(ahora + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(NOMBRE)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(clave_ca.public_key()), critical=False)
            .sign(clave_ca, hashes.SHA256()))
    return clave, cert


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def pem_clave(clave):
    return clave.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                               serialization.NoEncryption())


clave_ca, cert_ca = ca("Canario bateria CA")
clave_ajena, cert_ajena = ca("CA ajena")
(destino / "ca_bateria.pem").write_bytes(pem(cert_ca))
for prefijo, (clave_emisor, cert_emisor) in (("google", (clave_ca, cert_ca)), ("ajena", (clave_ajena, cert_ajena))):
    clave, cert = servidor(clave_emisor, cert_emisor)
    (destino / f"{prefijo}.pem").write_bytes(pem(cert) + pem(cert_emisor))
    (destino / f"{prefijo}.key").write_bytes(pem_clave(clave))
print("CERTIFICADOS")
'''

# Google falso: el token endpoint por HTTPS en el 443, con el comportamiento
# que pide el code. Imprime cada petición recibida (ruta y formulario) para
# que la batería compruebe qué envió el broker.
FALSO = r'''
import base64, http.server, json, ssl, sys, time, urllib.parse

CERT, CLAVE = sys.argv[1], sys.argv[2]
ESPERADO = json.loads(sys.argv[3])
NONCE, SUB, PREFIJO, CLIENT_ID, TOKEN_ACCESO = (ESPERADO.pop(k) for k in
                                                ("nonce", "sub", "prefijo", "client_id_aud", "token_acceso"))


def b64(datos):
    return base64.urlsafe_b64encode(datos).rstrip(b"=").decode("ascii")


def id_token(ahora, **cambios):
    claims = {"iss": "https://accounts.google.com", "aud": CLIENT_ID, "exp": ahora + 300, "iat": ahora,
              "nonce": NONCE, "sub": SUB}
    for nombre, valor in cambios.items():
        if valor is None:
            claims.pop(nombre)
        else:
            claims[nombre] = valor
    return b64(b'{"alg":"RS256","kid":"bateria"}') + "." + b64(json.dumps(claims).encode()) + ".firma-bateria"


class Manejador(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def enviar(self, codigo, cuerpo, cabeceras=()):
        self.send_response(codigo)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(cuerpo)))
        for nombre, valor in cabeceras:
            self.send_header(nombre, valor)
        self.end_headers()
        self.wfile.write(cuerpo)

    def do_GET(self):
        print(json.dumps({"metodo": "GET", "ruta": self.path}), flush=True)
        self.enviar(404, b"{}")

    def do_POST(self):
        datos = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode("ascii", "replace")
        formulario = dict(urllib.parse.parse_qsl(datos))
        print(json.dumps({"metodo": "POST", "ruta": self.path, "formulario": formulario}), flush=True)
        if self.path != "/token":
            return self.enviar(404, b"{}")
        if any(formulario.get(k) != v for k, v in ESPERADO.items()):
            return self.enviar(400, b'{"error":"invalid_grant"}')
        escenario = formulario["code"][len(PREFIJO):]
        ahora = int(time.time())
        claims = {"bueno": {}, "iss_sin_esquema": {"iss": "accounts.google.com"}, "aud_ajena": {"aud": "otro"},
                  "aud_lista": {"aud": [CLIENT_ID, "otro"]}, "azp_ajeno": {"azp": "otro"},
                  "iss_falso": {"iss": "https://evil.example"}, "caducado": {"exp": ahora - 10},
                  "nonce_otro": {"nonce": "x" * 43}, "sin_sub": {"sub": None}, "sub_largo": {"sub": "1" * 256}}
        if escenario in claims:
            cuerpo = json.dumps({"id_token": id_token(ahora, **claims[escenario]), "access_token": TOKEN_ACCESO,
                                 "token_type": "Bearer", "expires_in": 3599, "scope": "openid"}).encode()
            return self.enviar(200, cuerpo)
        if escenario == "json_roto":
            return self.enviar(200, b"esto no es json")
        if escenario == "grande":
            return self.enviar(200, b'{"relleno":"' + b"a" * 70000 + b'"}')
        if escenario == "error_500":
            return self.enviar(500, b"{}")
        if escenario == "redireccion":
            return self.enviar(302, b"", [("Location", "https://oauth2.googleapis.com/otra")])
        if escenario == "lento":
            # Cabeceras enseguida y el cuerpo, un byte cada medio segundo
            # durante 20 s: cada lectura cumple el plazo de la conexión, solo
            # el plazo total del broker lo corta.
            self.send_response(200)
            self.send_header("Content-Length", "40")
            self.end_headers()
            try:
                for _ in range(40):
                    self.wfile.write(b"a")
                    self.wfile.flush()
                    time.sleep(0.5)
            except OSError:
                pass
            return None
        return self.enviar(400, b'{"error":"invalid_grant"}')


servidor = http.server.ThreadingHTTPServer(("0.0.0.0", 443), Manejador)
contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
contexto.load_cert_chain(CERT, CLAVE)
servidor.socket = contexto.wrap_socket(servidor.socket, server_side=True)
print("LISTO", flush=True)
servidor.serve_forever()
'''

# Cliente del broker: corre en canje con la IP que se le dé. Lee una lista de
# peticiones por la entrada estándar; con "paralelo" en todas, las lanza a la
# vez. Devuelve estado, cuerpo y segundos de cada una.
CLIENTE = r'''
import concurrent.futures, http.client, json, sys, time

peticiones = json.load(sys.stdin)


def una(p):
    inicio = time.monotonic()
    c = http.client.HTTPConnection(p.get("host", "10.88.2.3"), 8000, timeout=40)
    try:
        cuerpo = p.get("crudo")
        if cuerpo is None and "json" in p:
            cuerpo = json.dumps(p["json"])
        cabeceras = {"Content-Type": "application/json"} if cuerpo is not None else {}
        c.request(p["metodo"], p["ruta"], body=None if cuerpo is None else cuerpo.encode("utf-8"), headers=cabeceras)
        r = c.getresponse()
        datos = r.read().decode("utf-8", "replace")
        return {"estado": r.status, "cuerpo": datos, "segundos": round(time.monotonic() - inicio, 1)}
    except (OSError, http.client.HTTPException) as error:
        return {"error": type(error).__name__, "segundos": round(time.monotonic() - inicio, 1)}
    finally:
        c.close()


if peticiones and all(p.get("paralelo") for p in peticiones):
    with concurrent.futures.ThreadPoolExecutor(len(peticiones)) as grupo:
        respuestas = list(grupo.map(una, peticiones))
else:
    respuestas = [una(p) for p in peticiones]
print(json.dumps(respuestas))
'''

# Conexión a /salud en el 8000 de una dirección (la misma prueba que
# verificar_esqueleto.py, o). RECHAZA solo con ConnectionRefusedError.
PRUEBA_ESCUCHA = ("import http.client, sys\n"
                  "c = http.client.HTTPConnection(sys.argv[1], 8000, timeout=5)\n"
                  "try:\n"
                  "    c.request('GET', '/salud'); r = c.getresponse(); print('RESPONDE', r.status, r.read().decode())\n"
                  "except ConnectionRefusedError:\n"
                  "    print('RECHAZA')\n"
                  "except (OSError, http.client.HTTPException) as e:\n"
                  "    print('OTRO', type(e).__name__)\n")


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


def dc(*args, override=True):
    base = BASE + (["-f", str(TEMPORAL / "override.yml")] if override else [])
    return ejecutar(base + list(args))


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


def inspeccionar(objeto, formato="{{json .}}"):
    r = ejecutar(["docker", "inspect", "--format", formato, objeto])
    if r.rc != 0:
        raise Parada(f"docker inspect {objeto} fallo: {r.err.strip()[:200]}")
    return json.loads(r.out)


def contenedor(servicio):
    cid = dc("ps", "-q", servicio).out.strip()
    if not cid:
        raise Parada(f"no hay contenedor para el servicio {servicio}")
    return cid


def docker_run(*args, timeout=300, entrada=None):
    """docker run --rm: contenedor desechable que se borra al terminar."""
    return ejecutar(["docker", "run", "--rm", *args], timeout=timeout, entrada=entrada)


TEMPORAL = None
IMAGEN = f"{PROYECTO}-broker"


def cliente(peticiones, ip=IP_API):
    """Peticiones al broker desde un contenedor de canje con la IP dada."""
    r = docker_run("--network", RED_CANJE, "--ip", ip, "-i", "--read-only", "--cap-drop", "ALL",
                   "--security-opt", "no-new-privileges:true",
                   "--mount", f"type=bind,src={TEMPORAL},dst=/prueba,readonly",
                   "--entrypoint", "python", IMAGEN, "-I", "/prueba/cliente.py",
                   entrada=json.dumps(peticiones).encode("utf-8"), timeout=120)
    try:
        return json.loads(r.out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise Parada(f"el cliente no devolvio resultado: {r.err.strip()[-400:]!r}") from None


def autorizar(**cambios):
    datos = {"proveedor": "google", "state": STATE, "code_challenge": RETO, "nonce": NONCE}
    datos.update(cambios)
    return {"metodo": "POST", "ruta": "/autorizar", "json": datos}


def canjear(escenario=None, **cambios):
    datos = {"proveedor": "google", "code": PREFIJO_CODE + (escenario or "bueno"), "verifier": VERIFIER,
             "nonce": NONCE}
    datos.update(cambios)
    return {"metodo": "POST", "ruta": "/canjear", "json": datos}


def logs_broker():
    return dc("logs", "--no-color", "broker").out


def falso(nombre_cert):
    """Arranca el Google falso con el alias oauth2.googleapis.com en salida."""
    nombre = f"{PROYECTO}_google"
    ejecutar(["docker", "rm", "-f", nombre])
    esperado = {"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "redirect_uri": REDIRECT,
                "grant_type": "authorization_code", "code_verifier": VERIFIER, "nonce": NONCE, "sub": SUB,
                "prefijo": PREFIJO_CODE, "client_id_aud": CLIENT_ID, "token_acceso": TOKEN_ACCESO}
    r = ejecutar(["docker", "run", "-d", "--name", nombre, "--network", RED_SALIDA,
                  "--network-alias", "oauth2.googleapis.com", "--read-only", "--cap-drop", "ALL",
                  "--security-opt", "no-new-privileges:true",
                  # Sin capacidades, un usuario no root solo puede escuchar en
                  # el 443 si el espacio de red lo permite.
                  "--sysctl", "net.ipv4.ip_unprivileged_port_start=0",
                  "--mount", f"type=bind,src={TEMPORAL},dst=/prueba,readonly",
                  "--entrypoint", "python", IMAGEN, "-I", "/prueba/falso.py",
                  f"/prueba/{nombre_cert}.pem", f"/prueba/{nombre_cert}.key", json.dumps(esperado)])
    if r.rc != 0:
        raise Parada(f"no arranca el Google falso: {r.err.strip()[-300:]!r}")
    for _ in range(30):
        if "LISTO" in ejecutar(["docker", "logs", nombre]).out:
            return
        time.sleep(1)
    raise Parada("el Google falso no llega a escuchar")


def peticiones_falso():
    """Lo que ha recibido el Google falso, en orden."""
    salida = ejecutar(["docker", "logs", f"{PROYECTO}_google"]).out
    return [json.loads(linea) for linea in salida.splitlines() if linea.startswith("{")]


def escribir_configuracion(client_id, client_secret):
    (TEMPORAL / "client_id").write_bytes(client_id.encode("ascii"))
    (TEMPORAL / "client_secret").write_bytes(client_secret.encode("ascii"))


def recrear_broker():
    return dc("up", "-d", "--force-recreate", "--wait", "--wait-timeout", "60", "broker")


# ---------------------------------------------------------------------------
# Comprobaciones
# ---------------------------------------------------------------------------
def seccion_a():
    p("=== a) el compose real")
    r = dc("config", "--format", "json", override=False)
    try:
        config = json.loads(r.out)
    except ValueError:
        raise Parada(f"docker compose config no devuelve JSON: {r.err.strip()[:300]}") from None
    servicios, redes = config["services"], config["networks"]
    broker = servicios["broker"]
    pasa(broker.get("entrypoint") == ENTRYPOINT_BROKER, f"a) entrypoint del broker ({broker.get('entrypoint')})")
    pasa(broker.get("command") == COMANDO_BROKER, f"a) command del broker ({broker.get('command')})")
    pasa(broker.get("build") == servicios["api"].get("build"),
         "a) el broker se construye exactamente como la API (una sola imagen que escanear)")
    pasa(set(broker.get("networks", {})) == {"canje", "salida"}, f"a) redes del broker ({sorted(broker['networks'])})")
    pasa((broker["networks"].get("canje") or {}).get("ipv4_address") == IP_BROKER, "a) el broker tiene la IP fija .3 en canje")
    secretos = sorted(s["source"] for s in broker.get("secrets", []))
    pasa(secretos == SECRETOS_BROKER, f"a) secretos del broker: solo los de Google ({secretos})")
    pasa(not broker.get("volumes"), f"a) el broker no monta nada ({broker.get('volumes')})")
    pasa(broker.get("environment") == {"CANARIO_ORIGEN_PERSONAL": ORIGEN, "CANARIO_IP_API": IP_API},
         f"a) entorno del broker ({broker.get('environment')})")
    pasa(servicios["api"].get("environment", {}).get("CANARIO_ORIGEN_PERSONAL") == ORIGEN,
         "a) el origen del broker es el mismo valor que el de la API")
    pasa(broker.get("read_only") is True and broker.get("cap_drop") == ["ALL"]
         and broker.get("security_opt") == ["no-new-privileges:true"], "a) broker: read_only, cap_drop y no-new-privileges")
    canje = redes.get("canje", {})
    config_canje = [(c.get("subnet"), c.get("ip_range")) for c in (canje.get("ipam") or {}).get("config", [])]
    pasa(canje.get("internal") is True and config_canje == [(SUBRED_CANJE, RANGO_CANJE)],
         f"a) canje: interna, {SUBRED_CANJE} y rango automatico {RANGO_CANJE} ({canje.get('internal')}, {config_canje})")
    pasa(not redes.get("salida", {}).get("internal"), "a) salida no es interna (la salida a internet del broker)")
    en_salida = sorted(n for n, s in servicios.items() if "salida" in (s.get("networks") or {}))
    pasa(en_salida == ["broker"], f"a) en salida solo esta el broker ({en_salida})")
    pasa("broker" not in [n for n, s in servicios.items() if "app" in (s.get("networks") or {})],
         "a) el broker no esta en la red app")
    # La API es la única otra pieza de canje, con la IP a la que atiende el
    # broker: si la tuviera otra, el broker serviría a quien no debe.
    en_canje = sorted(n for n, s in servicios.items() if "canje" in (s.get("networks") or {}))
    pasa(en_canje == ["api", "broker"], f"a) en canje solo estan la API y el broker ({en_canje})")
    ip_api = ((servicios["api"].get("networks") or {}).get("canje") or {}).get("ipv4_address")
    pasa(ip_api == IP_API, f"a) la API tiene en canje la IP fija {IP_API}, la que atiende el broker ({ip_api})")
    # Control: el override de la batería sí cambia lo que dice.
    r = dc("config", "--format", "json")
    try:
        prueba = json.loads(r.out)
    except ValueError:
        raise Parada(f"docker compose config con el override no devuelve JSON: {r.err.strip()[:300]}") from None
    montaje = [v.get("target") for v in prueba["services"]["broker"].get("volumes", [])]
    pasa(montaje == ["/usr/lib/ssl/cert.pem"] and prueba["networks"]["salida"].get("internal") is True,
         f"a) control: el override monta la CA de prueba y deja salida interna ({montaje})")


def preparar():
    p("=== preparacion: imagen, certificados, broker y Google falso")
    r = dc("build", "broker")
    if r.rc != 0:
        raise Parada(f"no se construye la imagen del broker: {r.todo.strip()[-500:]}")
    (TEMPORAL / "certificados.py").write_text(CERTIFICADOS, encoding="utf-8", newline="\n")
    r = docker_run("--network", "none", "--read-only", "--cap-drop", "ALL",
                   "--mount", f"type=bind,src={TEMPORAL},dst=/salida",
                   "--entrypoint", "python", IMAGEN, "-I", "/salida/certificados.py", "/salida")
    if "CERTIFICADOS" not in r.out:
        raise Parada(f"no se generan los certificados de prueba: {r.err.strip()[-400:]!r}")
    escribir_configuracion(CLIENT_ID, CLIENT_SECRET)
    r = recrear_broker()
    p(f"up del broker configurado -> codigo {r.rc}")
    if r.rc != 0:
        raise Parada(f"no arranca el broker: {r.todo.strip()[-500:]} {logs_broker()[-500:]}")
    falso("google")


def seccion_b():
    p("=== b) el contenedor del broker")
    i = inspeccionar(contenedor("broker"))
    hc = i["HostConfig"]
    pasa(i["Config"]["User"] == USUARIO, f"b) User = {i['Config']['User']!r}")
    pasa(hc["ReadonlyRootfs"] is True, f"b) ReadonlyRootfs = {hc['ReadonlyRootfs']}")
    pasa(hc["CapDrop"] == ["ALL"] and not hc["CapAdd"], f"b) CapDrop = {hc['CapDrop']}, CapAdd = {hc['CapAdd']}")
    pasa(hc["SecurityOpt"] == ["no-new-privileges:true"], f"b) SecurityOpt = {hc['SecurityOpt']}")
    pasa(hc["Memory"] == MEMORIA and hc["PidsLimit"] == PIDS, f"b) Memory = {hc['Memory']}, PidsLimit = {hc['PidsLimit']}")
    pasa(not hc["Privileged"], "b) no privilegiado")
    salud = i["State"].get("Health", {}).get("Status")
    pasa(salud == "healthy", f"b) sano ({salud})")
    redes = i["NetworkSettings"]["Networks"]
    pasa(set(redes) == {RED_CANJE, RED_SALIDA}, f"b) redes = {sorted(redes)}")
    pasa(redes[RED_CANJE]["IPAddress"] == IP_BROKER, f"b) IP en canje = {redes[RED_CANJE]['IPAddress']}")


def seccion_c():
    p("=== c) quien le habla al broker")
    ip_salida = inspeccionar(contenedor("broker"))["NetworkSettings"]["Networks"][RED_SALIDA]["IPAddress"]
    control = docker_run("--network", RED_CANJE, "--ip", IP_OTRA, "--read-only", "--cap-drop", "ALL",
                         "--entrypoint", "python", IMAGEN, "-c", PRUEBA_ESCUCHA, IP_BROKER).out.strip()
    control_ok = control == "RESPONDE 200 " + CUERPO_SALUD
    pasa(control_ok, f"c) control: desde canje, {IP_BROKER}:8000/salud responde ({control!r})")
    r = docker_run("--network", RED_SALIDA, "--read-only", "--cap-drop", "ALL",
                   "--entrypoint", "python", IMAGEN, "-c", PRUEBA_ESCUCHA, ip_salida).out.strip()
    negativo(f"c) desde salida, el broker en {ip_salida}:8000 rechaza la conexion ({r!r})", r == "RECHAZA",
             control_ok, f"control: {control!r}")
    desde_api = cliente([{"metodo": "GET", "ruta": "/proveedores"}])[0]
    control_api = desde_api.get("estado") == 200 and desde_api.get("cuerpo") == '{"proveedores":["google"]}'
    pasa(control_api, f"c) control: desde la IP de la API, /proveedores = {desde_api}")
    otra = cliente([{"metodo": "GET", "ruta": "/proveedores"}, canjear(), autorizar()], ip=IP_OTRA)
    negativo("c) desde otra IP de canje, /proveedores, /canjear y /autorizar dan 403 con el cuerpo fijo",
             all(o.get("estado") == 403 and o.get("cuerpo") == CUERPO_PROHIBIDO for o in otra), control_api,
             f"respuestas: {otra}")
    salud_otra = cliente([{"metodo": "GET", "ruta": "/salud"}], ip=IP_OTRA)[0]
    pasa(salud_otra.get("estado") == 200 and salud_otra.get("cuerpo") == CUERPO_SALUD,
         f"c) /salud queda abierta a cualquier IP de canje (el healthcheck) ({salud_otra})")
    pasa("EVENTO broker_cliente_rechazado: ruta=/canjear" in logs_broker(), "c) el rechazo deja su EVENTO")


def seccion_d():
    p("=== d) URL de autorizacion")
    r = cliente([autorizar()])[0]
    url = json.loads(r.get("cuerpo", "{}")).get("url") if r.get("estado") == 200 else None
    pasa(url == URL_AUTORIZACION, f"d) la URL de autorizacion es la exacta ({url})")
    if url:
        consulta = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
        pasa(consulta.get("scope") == "openid" and consulta.get("code_challenge_method") == "S256"
             and consulta.get("redirect_uri") == REDIRECT, "d) solo el scope openid, S256 y la redirect_uri del origen")


def seccion_e():
    p("=== e) canje contra el Google falso")
    nombres = list(ESCENARIOS)
    respuestas = dict(zip(nombres, cliente([canjear(n) for n in nombres])))
    bueno = respuestas["bueno"]
    control = bueno.get("estado") == 200 and bueno.get("cuerpo") == CUERPO_BUENO
    pasa(control, f"e) control: el canje bueno devuelve solo proveedor y sub ({bueno})")
    log = logs_broker()
    for nombre, (codigo, cuerpo, evento) in ESCENARIOS.items():
        if nombre == "bueno":
            continue
        r = respuestas[nombre]
        ok = r.get("estado") == codigo and r.get("cuerpo") == cuerpo and (evento is None or evento in log)
        negativo(f"e) {nombre}: {codigo} {cuerpo}" + (f" y {evento}" if evento else ""), ok, control,
                 f"respuesta: {r}")
    lento = respuestas["lento"]
    negativo(f"e) lento: cortado por el plazo total de 10 s ({lento.get('segundos')} s)",
             9 <= (lento.get("segundos") or 0) < 15, control, f"respuesta: {lento}")
    recibido = peticiones_falso()
    tokens = [x for x in recibido if x.get("ruta") == "/token"]
    pasa(len(tokens) == len(ESCENARIOS), f"e) el Google falso recibio un POST /token por escenario ({len(tokens)})")
    negativo("e) la redireccion no se sigue: nadie pidio /otra",
             not any(x.get("ruta") == "/otra" for x in recibido),
             any(x.get("formulario", {}).get("code") == PREFIJO_CODE + "redireccion" for x in tokens),
             "el Google falso no recibio el canje de la redireccion")
    primero = tokens[0]["formulario"] if tokens else {}
    pasa(primero == {"code": PREFIJO_CODE + "bueno", "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET,
                     "redirect_uri": REDIRECT, "grant_type": "authorization_code", "code_verifier": VERIFIER},
         "e) el broker envio exactamente el formulario del token endpoint")
    # verifier distinto del del flujo: Google responde invalid_grant.
    otro = cliente([canjear(verifier="otroVerifier-" + "o" * 40)])[0]
    negativo("e) un verifier que no es el del flujo da 401", otro.get("estado") == 401 and otro.get("cuerpo") == CUERPO_FALLIDO,
             control, f"respuesta: {otro}")


def seccion_f():
    p("=== f) TLS: el mismo nombre con un certificado de otra CA")
    falso("ajena")
    r = cliente([canjear()])[0]
    tls_ok = r.get("estado") == 503 and r.get("cuerpo") == CUERPO_NO_DISPONIBLE
    falso("google")
    control = cliente([canjear()])[0]
    negativo("f) con el certificado de otra CA, 503 y EVENTO motivo=tls",
             tls_ok and "EVENTO proveedor_no_disponible: proveedor=google motivo=tls" in logs_broker(),
             control.get("estado") == 200 and control.get("cuerpo") == CUERPO_BUENO,
             f"con la CA ajena: {r}; control con la de la bateria: {control}")


def seccion_g():
    p("=== g) saturacion: cinco canjes lentos a la vez")
    lentos = [{**canjear("lento"), "paralelo": True} for _ in range(5)]
    respuestas = cliente(lentos)
    # get con valor por defecto y no "or": una respuesta en 0.0 s es falsa.
    rapidas = [r for r in respuestas if r.get("segundos", 99) < 3]
    cortadas = [r for r in respuestas if 9 <= r.get("segundos", 0) < 15]
    pasa(all(r.get("estado") == 503 and r.get("cuerpo") == CUERPO_NO_DISPONIBLE for r in respuestas),
         "g) los cinco dan 503 con el cuerpo fijo")
    negativo(f"g) el quinto se rechaza en el acto ({[r.get('segundos') for r in respuestas]})",
             len(rapidas) == 1 and "EVENTO broker_saturado: proveedor=google" in logs_broker(),
             len(cortadas) == 4, f"respuestas: {respuestas}")
    despues = cliente([canjear()])[0]
    pasa(despues.get("estado") == 200, f"g) al terminar, el semaforo se libera: el canje bueno pasa ({despues})")


def seccion_h():
    p("=== h) entradas mal formadas")
    control = cliente([autorizar(), canjear()])
    control_ok = all(c.get("estado") == 200 for c in control)
    pasa(control_ok, f"h) control: autorizar y canjear validos dan 200 ({[c.get('estado') for c in control]})")
    casos = {
        "proveedor desconocido (autorizar)": autorizar(proveedor="facebook"),
        "proveedor en mayusculas (canjear)": canjear(proveedor="GOOGLE"),
        "state de 42 caracteres": autorizar(state=STATE[:-1]),
        "code_challenge con =": autorizar(code_challenge=RETO[:-1] + "="),
        "nonce de 44 caracteres": autorizar(nonce=NONCE + "n"),
        "campo de mas": autorizar(otro="x"),
        "falta el nonce": {"metodo": "POST", "ruta": "/autorizar",
                           "json": {"proveedor": "google", "state": STATE, "code_challenge": RETO}},
        "verifier de 42 caracteres": canjear(verifier=VERIFIER[:42]),
        "verifier con +": canjear(verifier=VERIFIER[:-1] + "+"),
        "code con espacio": canjear(code="4/0 espacio"),
        "code de 513 caracteres": canjear(code="a" * 513),
        "code numerico": canjear(code=12345),
        "nonce con =": canjear(nonce=NONCE[:-1] + "="),
        "cuerpo que no es JSON": {"metodo": "POST", "ruta": "/canjear", "crudo": "no es json"},
        "cuerpo de 5000 bytes": canjear(code="a" * 10, relleno="x" * 5000),
    }
    respuestas = dict(zip(casos, cliente(list(casos.values()))))
    for nombre, r in respuestas.items():
        negativo(f"h) {nombre}: 422 con el cuerpo fijo", r.get("estado") == 422 and r.get("cuerpo") == CUERPO_FORMATO,
                 control_ok, f"respuesta: {r}")


def seccion_i():
    p("=== i) el log del broker no lleva datos sensibles")
    log = logs_broker()
    enviado = any(x.get("formulario", {}).get("client_secret") == CLIENT_SECRET for x in peticiones_falso())
    control = enviado and "EVENTO canje_fallido: proveedor=google motivo=aud" in log
    prohibidos = {"client_secret": CLIENT_SECRET, "verifier": VERIFIER, "code": PREFIJO_CODE, "sub": SUB,
                  "access_token": TOKEN_ACCESO, "id_token (cabecera)": "eyJ", "nonce": NONCE, "state": STATE}
    for nombre, literal in prohibidos.items():
        negativo(f"i) el log no contiene el {nombre}", literal not in log, control,
                 "control: el broker envio el client_secret y su log tiene los EVENTO de los canjes")


def seccion_j():
    p("=== j) configuracion: sin configurar y a medias")
    escribir_configuracion(MARCADOR_ID, MARCADOR_SECRETO)
    r = recrear_broker()
    p(f"up del broker sin configurar -> codigo {r.rc}")
    # Control del caso a medias: con la misma orden, el broker sí arranca.
    arranca_sin_configurar = r.rc == 0
    if r.rc != 0:
        sinc(f"j) el broker sin configurar no arranca: {logs_broker()[-400:]!r}")
    else:
        lista, aut = cliente([{"metodo": "GET", "ruta": "/proveedores"}, autorizar()])
        pasa(lista.get("cuerpo") == '{"proveedores":[]}', f"j) sin configurar, /proveedores vacio ({lista})")
        pasa(aut.get("estado") == 404 and aut.get("cuerpo") == CUERPO_NO_CONFIGURADO,
             f"j) sin configurar, autorizar da 404 ({aut})")
        pasa(LOG_DESACTIVADO in logs_broker(), "j) sin configurar, el log lo dice (EVENTO proveedor_desactivado)")
    escribir_configuracion(CLIENT_ID, MARCADOR_SECRETO)
    r = recrear_broker()
    p(f"up del broker a medias -> codigo {r.rc}")
    log = logs_broker()
    salud = inspeccionar(contenedor("broker"), "{{json .State.Health}}") or {}
    negativo("j) a medias, el broker no arranca y el log dice por que",
             r.rc != 0 and LOG_A_MEDIAS in log and salud.get("Status") != "healthy", arranca_sin_configurar,
             f"codigo {r.rc}, salud {salud.get('Status')}, log: {log[-400:]!r}")


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
        sinc("s) no se pudo comparar el estado de Git (git no disponible, fallo o el directorio no es un repositorio)")
    else:
        iguales = final == ESTADO_GIT_ARRANQUE
        pasa(iguales, "s) la bateria no ha modificado el repo (git status igual al del arranque)")
        if not iguales:
            p(f"   al arrancar: {ESTADO_GIT_ARRANQUE}")
            p(f"   al terminar: {final}")


# ---------------------------------------------------------------------------
# Arranque, precondiciones y cierre
# ---------------------------------------------------------------------------
def escribir_auxiliares():
    (TEMPORAL / "falso.py").write_text(FALSO, encoding="utf-8", newline="\n")
    (TEMPORAL / "cliente.py").write_text(CLIENTE, encoding="utf-8", newline="\n")
    raiz = TEMPORAL.as_posix()
    (TEMPORAL / "override.yml").write_text(
        "services:\n"
        "  broker:\n"
        "    volumes:\n"
        "      - type: bind\n"
        f"        source: \"{raiz}/ca_bateria.pem\"\n"
        "        target: /usr/lib/ssl/cert.pem\n"
        "        read_only: true\n"
        "networks:\n"
        "  salida:\n"
        "    internal: true\n"
        "secrets:\n"
        "  google_client_id:\n"
        f"    file: \"{raiz}/client_id\"\n"
        "  google_client_secret:\n"
        f"    file: \"{raiz}/client_secret\"\n",
        encoding="utf-8", newline="\n")
    # El override necesita que existan antes de cualquier config o up.
    escribir_configuracion(CLIENT_ID, CLIENT_SECRET)
    (TEMPORAL / "ca_bateria.pem").write_bytes(b"")


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


def subred_ocupada():
    """Redes ajenas que ya usan la subred fija de canje."""
    ocupadas = []
    for red in ejecutar(["docker", "network", "ls", "-q"]).out.split():
        r = ejecutar(["docker", "network", "inspect", "--format",
                      "{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}", red])
        partes = r.out.split()
        if partes and SUBRED_CANJE in partes[1:]:
            ocupadas.append(partes[0])
    return ocupadas


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
    ocupadas = subred_ocupada()
    if ocupadas:
        p(f"PARADA: la subred {SUBRED_CANJE} ya esta en uso por {ocupadas} (pare el proyecto canario)")
        terminar_con_parada()
    # Solo se comprueba que existen (is_file), nunca se leen: docker compose
    # valida que estén todos los ficheros de secretos del compose.
    # Las dos claves del login externo de la API, las últimas en llegar: sin
    # ellas, compose falla antes de levantar nada y el motivo se ve peor.
    for fichero in ("google_client_id.txt", "google_client_secret.txt",
                    "clave_hmac_identidades.txt", "clave_flujo_externo.txt"):
        if not (RAIZ / "secrets" / fichero).is_file():
            p(f"PARADA: secrets/{fichero} no existe (ejecute scripts/generar_secretos.py)")
            terminar_con_parada()
    TEMPORAL = pathlib.Path(tempfile.mkdtemp(prefix="canario_externo_"))
    escribir_auxiliares()
    r = dc("config", "--quiet")
    if r.rc != 0:
        p(f"PARADA: docker compose config falla (genere los secretos con scripts/generar_secretos.py): {r.err.strip()[:300]}")
        shutil.rmtree(TEMPORAL, ignore_errors=True)
        terminar_con_parada()
    parada = None
    try:
        seccion_a()
        preparar()
        for seccion in (seccion_b, seccion_c, seccion_d, seccion_e, seccion_f, seccion_g, seccion_h, seccion_i,
                        seccion_j):
            seccion()
    except Parada as e:
        parada = str(e)
        p(f"PARADA: {parada}")
    except Exception:  # noqa: BLE001 - error inesperado del propio test: se informa y se limpia
        parada = "error inesperado en el test"
        p("ERROR INESPERADO:\n" + traceback.format_exc())
    finally:
        ejecutar(["docker", "rm", "-f", f"{PROYECTO}_google"])
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
