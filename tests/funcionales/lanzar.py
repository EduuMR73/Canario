#!/usr/bin/env python3
"""Lanzador de las pruebas funcionales (tests/funcionales/, F1, F2 y F3 de
docs/informe-pruebas.md). Se ejecuta en el host, desde la raíz del repo:

    python tests\\funcionales\\lanzar.py [--conservar]

Qué hace, en orden:
* comprobaciones previas: Docker en marcha, ningún recurso con el prefijo
  canario_funcionales, las subredes fijas del compose libres, los puertos
  8443 a 8445 libres y docker compose config sin errores. Si algo falla,
  PARADA sin tocar nada (podrían ser recursos ajenos);
* levanta su propia pila (proyecto canario_funcionales) con los overrides de
  verificar_spa.py en un directorio temporal: límites relajados, Google sin
  configurar y el correo con una CA de la prueba (nunca los ficheros de
  secrets/, que la pila monta como en las baterías y que aquí no se leen), y
  comprueba la línea entera de límites del log de la API;
* lee la hoja que Caddy sirve en 8444 y 8445 con un handshake TLS desde el
  host (validez y CN: datos públicos, van por argv). Es el control de
  identidad de Firefox y WebKit, que no tienen el SPKI de Chromium;
* ejecuta pytest una vez por motor (chromium, firefox, webkit), cada uno con
  su empresa, su contenedor de Playwright y su salida. Solo chromium y firefox
  corren F1 y dan de alta un admin con gestion: webkit corre F2 y F3 y no deja
  ningún token vivo. El token de invitación del admin no se imprime nunca: va
  a datos.json, en otro temporal montado de solo lectura en el contenedor (ni
  por argv ni por -e, donde lo vería docker inspect). El contenedor está
  endurecido como en verificar_spa.py y, mientras corre, se comprueba que
  docker inspect no contiene ningún token (con un marcador público como
  control). Antes de las pruebas, cada motor pasa un humo (humo.json): si
  falla, PARADA, y nunca se relaja el endurecimiento;
* al terminar todos los motores, el escáner anti-fuga busca en el informe HTML
  y en la salida de CADA motor los secretos de TODAS las ejecuciones (y sus
  formas escapadas), con un centinela por motor como control positivo, y
  genera el informe publicable;
* interpreta el resultado de cada motor (código de salida y resumen.json, con
  3, 3 y 2 pruebas esperadas) y termina con RESULTADO GLOBAL: OK o NO OK, con
  código 0 solo si es OK;
* limpia en finally: down -v --rmi local, restos con el prefijo, git status
  igual al del arranque y los temporales, salvo el de salida (informe y
  trazas), cuya ruta imprime.

--conservar deja la pila y los temporales para desarrollar: imprime la orden
exacta para borrarlos. La evidencia sale de una ejecución limpia, sin él.

Solo biblioteca estándar, salvo cryptography para la CA del correo (la misma
función que verificar_spa.py, con su misma PARADA si falta).
"""
import argparse
import base64
import hashlib
import html
import json
import pathlib
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import traceback
import urllib.parse

RAIZ = pathlib.Path(__file__).resolve().parent.parent.parent
DIR_PRUEBAS = RAIZ / "tests" / "funcionales"
PROYECTO = "canario_funcionales"
SALIDA_TEXTO = pathlib.Path(tempfile.gettempdir()) / "verificacion_funcionales.txt"
# Con los perfiles gestion (alta de la empresa y del admin) y desarrollo
# (Mailpit y el cartero). down solo actúa sobre los servicios de los perfiles
# activos: con los dos, no queda nada.
BASE = ["docker", "compose", "-p", PROYECTO, "-f", str(RAIZ / "docker-compose.yml"), "--profile", "gestion",
        "--profile", "desarrollo"]

lineas_salida = []
estado = {"falla": False, "sin_conclusion": False}

# Límites relajados: todo sale de la misma IP y un circuito hace más de 10
# accesos en 5 minutos. Los mismos que tests/security/verificar_spa.py, y la
# línea entera con la que la API los anuncia al arrancar (app/principal.py).
LIMITES_PRUEBA = ("denuncia=1000/3600,seguimiento=1000/60,mensajes=1000/3600,acceso=1000/300,otras=1000/60,"
                  "cuenta=1000/60,registro=1000/3600,destinatario=1000/900,destinatario_dia=1000/86400")
TEXTO_LIMITES_PRUEBA = ("LIMITES (configurados): acceso=1000/300 cuenta=1000/60 denuncia=1000/3600 "
                        "destinatario=1000/900 destinatario_dia=1000/86400 mensajes=1000/3600 otras=1000/60 "
                        "registro=1000/3600 seguimiento=1000/60")

PUERTOS = (8443, 8444, 8445)
SUBREDES = ("10.88.0.0/28", "10.88.1.0/28", "10.88.2.0/28")
# Los marcadores de Google y de la credencial SMTP sin configurar
# (scripts/generar_secretos.py), como en verificar_spa.py.
SECRETOS_GOOGLE = ("google_client_id", "google_client_secret")
MARCADORES_GOOGLE = ("sin-configurar:client-id", "sin-configurar:client-secret")
MARCADOR_SMTP_USUARIO = "sin-configurar:usuario"
MARCADOR_SMTP_CONTRASENA = "sin-configurar:contrasena"
INTERMEDIA_CA = "/data/caddy/pki/authorities/local/intermediate.crt"

# Playwright 1.63.0, fijada por digest (la de verificar_spa.py). Trae Python
# y los navegadores; los paquetes van en requisitos.txt, con sus hashes.
IMG_PLAYWRIGHT = ("mcr.microsoft.com/playwright/python:v1.63.0-noble"
                  "@sha256:72bd171a9ffc2b4b59532aaa6210e21014d07093120dc25528870c0b840da1f0")
USUARIO_PLAYWRIGHT = "1001:1001"  # pwuser

PATRON_ALTA = re.compile(r"empresa creada: empresa_id=([0-9a-f-]{36}) identificador_publico=([0-9a-f]{32})")
PATRON_INVITACION = re.compile(r"token_invitacion=([0-9a-f]{32}\.[A-Za-z0-9_-]{43})\n")
# El mismo literal que EMAIL_ADMIN de conftest.py.
EMAIL_ADMIN = "admin@funcionales.test"

# Oráculos del resultado: el número de pruebas que deben pasar en cada motor,
# escrito a mano (si una prueba no se recogiera, no pasaría en silencio).
# chromium: F1, F2 y F3; firefox: F1, F2 y F3; webkit: F2 y F3.
MOTORES = ("chromium", "firefox", "webkit")
PRUEBAS_ESPERADAS = {"chromium": 3, "firefox": 3, "webkit": 2}
# El alta del admin solo en los motores que corren F1: en webkit sería un token
# vivo que nadie usa.
MOTORES_CON_ADMIN = ("chromium", "firefox")
PUERTOS_HOJA = (8444, 8445)
INFORME_BRUTO = "informe_bruto.html"
INFORME_PUBLICABLE = "informe.html"
# El elemento con el que conftest.py escribe el centinela en el informe.
FORMATO_CENTINELA = '<p id="centinela-antifuga">{}</p>'
# Adjuntos de pytest-html que van en base64 dentro del HTML autocontenido: el
# escáner no los decodifica, así que no puede haber ninguno.
ADJUNTOS_BASE64 = ("data:text/plain;", "data:application/json;")

# La orden que corre en el contenedor. pip instala con versiones exactas y
# hashes en /tmp/pw (tmpfs). PYTHONPATH mete /tmp/pw en sys.path (por eso no
# va -I, que lo ignoraría). Sin autocarga de plugins: solo los dos que se
# piden con -p. pytest sin caché ni bytecode (el montaje es de solo lectura),
# sin reescritura de asserts (--assert=plain: los mensajes son los literales
# de las pruebas, sin valores introspectados), con trazas cortas, sin la
# salida capturada en la terminal y sin -rA, -v ni --showlocals, que
# llevarían datos de la ejecución a la salida.
ORDEN_PRUEBAS = (
    "pip install -q --disable-pip-version-check --no-cache-dir --no-deps --only-binary :all: --require-hashes "
    "--target /tmp/pw -r /pruebas/requisitos.txt && PYTHONPATH=/tmp/pw exec python3 -m pytest /pruebas "
    "-p no:cacheprovider -p pytest_metadata.plugin -p pytest_html.plugin -o xfail_strict=true "
    "--assert=plain --tb=short --show-capture=no --color=no "
    f"--html=/salida/{INFORME_BRUTO} --self-contained-html --spki \"$1\" --motor \"$2\" --hojas \"$3\""
)


# ---------------------------------------------------------------------------
# Utilidades de ejecución y de informe (duplicadas por batería, como en
# tests/security/)
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


def ejecutar(args, timeout=900):
    # check=False explícito: el código de salida se comprueba en cada llamada.
    r = subprocess.run(args, capture_output=True, timeout=timeout, check=False)
    return R(r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace"))


def dc(*args, timeout=900):
    return ejecutar(BASE + list(args), timeout=timeout)


def pasa(cond, texto):
    p(("PASA  " if cond else "FALLA ") + texto)
    if not cond:
        estado["falla"] = True


def sinc(texto):
    p("SIN CONCLUSION " + texto)
    estado["sin_conclusion"] = True


def negativo(nombre, cond, control_ok):
    """Prueba negativa con control: si el control falla, SIN CONCLUSION."""
    if not control_ok:
        sinc(f"{nombre}: el control positivo fallo")
        return
    pasa(cond, nombre)


def terminar():
    if estado["falla"] or estado["sin_conclusion"]:
        resultado = "NO OK (hay FALLA o SIN CONCLUSION)"
    else:
        resultado = "OK"
    p("RESULTADO GLOBAL: " + resultado)
    SALIDA_TEXTO.write_text("\n".join(lineas_salida) + "\n", encoding="utf-8", newline="\n")
    sys.exit(0 if resultado == "OK" else 1)


def terminar_con_parada():
    p("RESULTADO GLOBAL: NO OK (PARADA)")
    SALIDA_TEXTO.write_text("\n".join(lineas_salida) + "\n", encoding="utf-8", newline="\n")
    sys.exit(1)


def estado_git():
    """Líneas de "git status --short -uall", o None si git no está disponible o falla."""
    try:
        r = ejecutar(["git", "-C", str(RAIZ), "status", "--short", "-uall"], timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.rc != 0:
        return None
    return [linea.rstrip() for linea in r.out.splitlines() if linea.strip()]


def recursos_previos():
    previos = []
    for orden in (["docker", "ps", "-a", "--format", "{{.Names}}"],
                  ["docker", "network", "ls", "--format", "{{.Name}}"],
                  ["docker", "volume", "ls", "--format", "{{.Name}}"],
                  ["docker", "image", "ls", "--format", "{{.Repository}}"]):
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
    for puerto in PUERTOS:
        s = socket.socket()
        s.settimeout(2)
        try:
            if s.connect_ex(("127.0.0.1", puerto)) == 0:
                ocupados.append(puerto)
        finally:
            s.close()
    return ocupados


def spki_de(pem):
    """SHA-256 en base64 del SubjectPublicKeyInfo de un certificado PEM, el
    formato de --ignore-certificate-errors-spki-list (verificar_spa.py).
    Recorre el DER a mano: Certificate > tbsCertificate > [version], serial,
    firma, emisor, validez, sujeto y, después, la clave pública."""
    der = base64.b64decode("".join(linea for linea in pem.splitlines() if linea and not linea.startswith("-----")))

    def elemento(i):
        longitud = der[i + 1]
        i += 2
        if longitud & 0x80:
            octetos = longitud & 0x7F
            longitud = int.from_bytes(der[i:i + octetos], "big")
            i += octetos
        return i, i + longitud

    i, _ = elemento(0)
    i, _ = elemento(i)
    if der[i] == 0xA0:
        i = elemento(i)[1]
    for _ in range(5):
        i = elemento(i)[1]
    fin = elemento(i)[1]
    return base64.b64encode(hashlib.sha256(der[i:fin]).digest()).decode()


def certificados_correo(destino):
    """Escribe en destino la CA de la prueba (ca_correo.pem), el certificado
    de Mailpit (nombre mailpit, firmado por esa CA) y su clave, como
    verificar_spa.py: nunca se usan los ficheros de secrets/, el cartero solo
    confía en esta CA y la clave de la CA se descarta al firmar."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    def nombre(texto):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, texto)])

    ahora = datetime.datetime.now(datetime.UTC)
    desde, hasta = ahora - datetime.timedelta(minutes=5), ahora + datetime.timedelta(days=1)
    clave_ca = ec.generate_private_key(ec.SECP256R1())
    ca = (x509.CertificateBuilder().subject_name(nombre("Canario funcionales CA del correo"))
          .issuer_name(nombre("Canario funcionales CA del correo"))
          .public_key(clave_ca.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(desde).not_valid_after(hasta)
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                       data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                       crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(clave_ca.public_key()), critical=False)
          .sign(clave_ca, hashes.SHA256()))
    clave = ec.generate_private_key(ec.SECP256R1())
    certificado = (x509.CertificateBuilder().subject_name(nombre("mailpit")).issuer_name(ca.subject)
                   .public_key(clave.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(desde).not_valid_after(hasta)
                   .add_extension(x509.SubjectAlternativeName([x509.DNSName("mailpit")]), critical=False)
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                   .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(clave_ca.public_key()),
                                  critical=False)
                   .sign(clave_ca, hashes.SHA256()))
    (destino / "ca_correo.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (destino / "mailpit_certificado.pem").write_bytes(certificado.public_bytes(serialization.Encoding.PEM))
    (destino / "mailpit_clave.pem").write_bytes(clave.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


def preparar_overrides(temporal):
    """Los ficheros de compose adicionales, en el directorio temporal: el
    docker-compose.yml del repo no cambia."""
    limites = temporal / "limites_prueba.yml"
    limites.write_text(f"services:\n  api:\n    environment:\n      CANARIO_LIMITES: \"{LIMITES_PRUEBA}\"\n",
                       encoding="utf-8", newline="\n")
    # Google sin configurar, sea cual sea secrets/: las credenciales reales no
    # llegan a una pila de pruebas. Sin salto final: el broker exige ASCII
    # imprimible.
    secretos_google = temporal / "secretos_google"
    secretos_google.mkdir()
    lineas = ["secrets:"]
    for nombre, valor in zip(SECRETOS_GOOGLE, MARCADORES_GOOGLE, strict=True):
        (secretos_google / nombre).write_bytes(valor.encode("ascii"))
        lineas += [f"  {nombre}:", f"    file: \"{(secretos_google / nombre).as_posix()}\""]
    marcadores = temporal / "secretos_google.yml"
    marcadores.write_text("\n".join(lineas) + "\n", encoding="utf-8", newline="\n")
    # El correo: una CA y un certificado de Mailpit de la prueba y la
    # credencial SMTP falsa (los marcadores). El override monta la CA en el
    # cartero sobre su único almacén de confianza.
    correo = temporal / "correo"
    correo.mkdir()
    certificados_correo(correo)
    (correo / "smtp_usuario").write_bytes(MARCADOR_SMTP_USUARIO.encode("ascii"))
    (correo / "smtp_contrasena").write_bytes(MARCADOR_SMTP_CONTRASENA.encode("ascii"))
    lineas = ["secrets:"]
    for nombre, fichero in (("smtp_usuario", "smtp_usuario"), ("smtp_contrasena", "smtp_contrasena"),
                            ("mailpit_certificado", "mailpit_certificado.pem"),
                            ("mailpit_clave", "mailpit_clave.pem")):
        lineas += [f"  {nombre}:", f"    file: \"{(correo / fichero).as_posix()}\""]
    secretos_correo = temporal / "secretos_correo.yml"
    secretos_correo.write_text("\n".join(lineas) + "\n", encoding="utf-8", newline="\n")
    ca_cartero = temporal / "ca_cartero.yml"
    ca_cartero.write_text(
        "services:\n"
        "  cartero:\n"
        "    volumes:\n"
        "      - type: bind\n"
        f"        source: \"{(correo / 'ca_correo.pem').as_posix()}\"\n"
        "        target: /usr/lib/ssl/cert.pem\n"
        "        read_only: true\n",
        encoding="utf-8", newline="\n")
    return [limites, marcadores, secretos_correo, ca_cartero]


# ---------------------------------------------------------------------------
# Pasos
# ---------------------------------------------------------------------------
def contenedor_de(motor):
    return f"{PROYECTO}_playwright_{motor}"


def hoja_servida(puerto):
    """Validez y CN de la hoja que Caddy sirve en 127.0.0.1:<puerto>, leída
    con un handshake TLS desde el host (ssl de la biblioteca estándar), no de
    un fichero de /data. Son datos públicos y viajan por argv. La verificación
    se desactiva solo para este handshake: lo que se quiere es leer la hoja,
    no confiar en ella (la confianza de Firefox y WebKit se comprueba después,
    en conftest.py, contra estos valores). Docker publica los puertos solo en
    127.0.0.1."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    contexto.check_hostname = False
    contexto.verify_mode = ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", puerto), timeout=10) as conexion:
        with contexto.wrap_socket(conexion, server_hostname="localhost") as tls:
            der = tls.getpeercert(binary_form=True)
    if not der:
        raise Parada(f"Caddy no envía certificado en 127.0.0.1:{puerto}")
    hoja = x509.load_der_x509_certificate(der)
    nombres = hoja.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return {"desde": int(hoja.not_valid_before_utc.timestamp()), "hasta": int(hoja.not_valid_after_utc.timestamp()),
            "cn": nombres[0].value if nombres else None}


def arrancar(temporal):
    """Levanta la pila (una vez para todos los motores) y devuelve el SPKI de
    la CA intermedia y las hojas servidas (JSON en base64)."""
    p("=== arranque de la pila")
    # Antes de arrancar: los secretos de Google salen del directorio temporal
    # y no de secrets/. Solo se imprimen los dos nombres, nunca la
    # configuración entera.
    r = dc("config", "--format", "json")
    try:
        definidos = json.loads(r.out)["secrets"]
        rutas = {nombre: definidos[nombre]["file"] for nombre in SECRETOS_GOOGLE}
    except (ValueError, KeyError, TypeError):
        raise Parada("docker compose config no da los secretos de Google") from None
    if not all(pathlib.Path(ruta).resolve() == (temporal / "secretos_google" / nombre).resolve()
               for nombre, ruta in rutas.items()):
        raise Parada("los secretos de Google no salen del directorio temporal")
    pasa(True, f"la pila monta los marcadores de Google del directorio temporal ({sorted(rutas)})")
    r = dc("up", "-d", "--build", "--wait", "api", "caddy", "mailpit", "cartero", "broker", timeout=1800)
    p(f"up -d --build --wait api caddy mailpit cartero broker -> codigo {r.rc}")
    if r.rc != 0:
        p(r.todo.strip()[-1500:])
        raise Parada("no arranca la pila")
    registro = dc("logs", "--no-color", "--no-log-prefix", "api").todo
    limites_ok = TEXTO_LIMITES_PRUEBA in registro
    pasa(limites_ok, f"la API usa los limites relajados y el log lo dice ({TEXTO_LIMITES_PRUEBA!r})")
    if not limites_ok:
        raise Parada("la API no anuncia los limites relajados: el circuito no seria valido")
    pem = dc("exec", "-T", "caddy", "cat", INTERMEDIA_CA).out
    if "BEGIN CERTIFICATE" not in pem:
        raise Parada("no se pudo leer el certificado de la CA intermedia de Caddy")
    try:
        hojas = {str(puerto): hoja_servida(puerto) for puerto in PUERTOS_HOJA}
    except OSError as error:
        raise Parada(f"no se pudo leer la hoja que sirve Caddy ({type(error).__name__})") from None
    p("   hojas servidas por Caddy (validez y CN, datos publicos): " + json.dumps(hojas, sort_keys=True))
    hojas_b64 = base64.b64encode(json.dumps(hojas, sort_keys=True).encode("ascii")).decode("ascii")
    return spki_de(pem), hojas_b64


def alta_empresa(motor):
    """Da de alta una empresa para el motor y, si corre F1, su admin. Devuelve
    (identificador, token del admin o None)."""
    r = dc("run", "--rm", "-T", "gestion", "alta-empresa", "--nombre", f"Empresa funcionales {motor}", "--zona",
           "Europe/Madrid")
    alta = PATRON_ALTA.search(r.out)
    if r.rc != 0 or alta is None:
        raise Parada(f"no se pudo dar de alta la empresa de prueba de {motor}: {r.err.strip()[-300:]!r}")
    identificador = alta.group(2)
    p(f"   {motor}: empresa de prueba {identificador}")
    if motor not in MOTORES_CON_ADMIN:
        return identificador, None
    # La salida de alta-admin lleva el token: no se imprime nunca, ni stdout
    # ni stderr, tampoco en la PARADA.
    r = dc("run", "--rm", "-T", "gestion", "alta-admin", "--identificador", identificador, "--email", EMAIL_ADMIN)
    invitacion = PATRON_INVITACION.search(r.out)
    if r.rc != 0 or invitacion is None:
        raise Parada(f"no se pudo emitir la invitacion del admin de {motor} (codigo {r.rc})")
    return identificador, invitacion.group(1)


def ejecutar_pruebas(motor, datos, salida, temporal, spki, hojas_b64, tokens):
    """Ejecuta pytest de un motor en su contenedor de Playwright y devuelve
    (código de pytest o None, salida del contenedor). tokens: los tokens de
    admin de este motor y de los anteriores."""
    p(f"=== pruebas en {motor} (contenedor de Playwright)")
    contenedor = contenedor_de(motor)
    caddy = dc("ps", "-q", "caddy").out.strip()
    if not caddy:
        raise Parada("no se encuentra el contenedor de Caddy")
    # El navegador comparte la red del contenedor de Caddy: localhost:8444 y
    # :8445 son Caddy, con el mismo Host y el mismo SNI que desde el host. En
    # esos puertos de localhost solo puede estar Caddy, y por eso el control de
    # identidad de Firefox y WebKit (que no es criptográfico) basta.
    # Mínimo privilegio, igual para los tres motores: pwuser, raíz de solo
    # lectura, sin capacidades y sin nuevos privilegios. NO se relaja para que
    # un motor arranque (nada de --ipc=host, SYS_ADMIN, seccomp=unconfined ni
    # root): si no arranca, el humo da PARADA. La red la usa pip. Sin --rm:
    # docker inspect y docker logs se leen antes de borrarlo (en finally).
    r = ejecutar(["docker", "run", "-d", "--name", contenedor, "--network", f"container:{caddy}",
                  "--user", USUARIO_PLAYWRIGHT, "--read-only", "--cap-drop", "ALL",
                  "--security-opt", "no-new-privileges", "--shm-size", "512m", "--tmpfs", "/tmp:size=600m,exec",
                  "-e", "HOME=/tmp", "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1",
                  "--mount", f"type=bind,src={DIR_PRUEBAS},dst=/pruebas,readonly",
                  "--mount", f"type=bind,src={datos},dst=/datos,readonly",
                  "--mount", f"type=bind,src={salida},dst=/salida",
                  "-w", "/pruebas", "--entrypoint", "sh", IMG_PLAYWRIGHT, "-c", ORDEN_PRUEBAS, "funcionales", spki,
                  motor, hojas_b64],
                 timeout=900)
    if r.rc != 0:
        raise Parada(f"no arranca el contenedor de Playwright de {motor}: {r.err.strip()[-500:]!r}")

    # Mientras corre: la configuración del contenedor (órdenes, entorno y
    # montajes) no lleva ningún token de admin. Control: sí lleva el SPKI, que
    # va por argv en todos los motores aunque Firefox y WebKit no lo usen, así
    # que se está leyendo la configuración de verdad.
    r = ejecutar(["docker", "inspect", contenedor])
    if r.rc != 0 or not r.out.strip():
        sinc(f"docker inspect del contenedor de {motor} no se pudo leer: no se sabe si lleva algun token")
    else:
        negativo(f"docker inspect del contenedor de {motor} no contiene ningun token de admin",
                 not any(token in r.out for token in tokens), spki in r.out)

    try:
        r = ejecutar(["docker", "wait", contenedor], timeout=1800)
        codigo = int(r.out.strip()) if r.rc == 0 and r.out.strip().lstrip("-").isdigit() else None
    except subprocess.TimeoutExpired:
        ejecutar(["docker", "kill", contenedor])
        codigo = None
        p("   el contenedor de pruebas supera 30 minutos: se detiene")
    r = ejecutar(["docker", "logs", contenedor])
    texto = r.out + r.err
    # La salida se guarda en el temporal y no se imprime entera: con un
    # fallo, las trazas de pytest podrían llevar datos.
    (temporal / f"salida_contenedor_{motor}.txt").write_text(texto, encoding="utf-8", newline="\n")
    p(f"   pytest termina con codigo {codigo}; salida guardada en {temporal / f'salida_contenedor_{motor}.txt'}")
    return codigo, texto


def leer_json(ruta):
    try:
        return json.loads(ruta.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def comprobar_humo(motor, salida):
    """Lee humo.json del motor. PARADA si el humo falló o no terminó; un
    SIN CONCLUSION (por ejemplo, el literal del error de certificado sin
    fijar) no para: las pruebas ya lo reflejan, y aquí se imprime lo observado
    para fijarlo."""
    humo = leer_json(salida / "humo.json")
    if not isinstance(humo, dict):
        raise Parada(f"{motor}: el humo no dejo humo.json")
    p(f"   humo de {motor}: {json.dumps(humo, ensure_ascii=False, sort_keys=True)}")
    if humo.get("estado") == "parada":
        raise Parada(f"{motor}: {humo.get('motivo')}")
    if humo.get("estado") == "sin_conclusion":
        sinc(f"el humo de {motor} no concluye: {humo.get('motivo')}")
    elif humo.get("estado") != "ok":
        raise Parada(f"{motor}: el humo no termino (estado {humo.get('estado')!r})")


def formas(valor):
    """Las formas en que un secreto puede aparecer en el informe o en la
    salida: tal cual, escapado en HTML (con y sin comillas), escapado en JSON
    (pytest-html mete los registros en un JSON dentro de un atributo), las
    dos cosas a la vez y en una URL."""
    en_json = json.dumps(valor)[1:-1]
    return {valor, html.escape(valor), html.escape(valor, quote=False), en_json, html.escape(en_json),
            urllib.parse.quote(valor, safe="")}


def fugas(secretos, textos):
    """Nombres de los secretos que aparecen, en alguna forma, en algún texto.
    Nunca devuelve el valor."""
    vistos = []
    for nombre, valores in secretos.items():
        for valor in valores:
            if any(forma in texto for forma in formas(valor) for texto in textos):
                vistos.append(nombre)
                break
    return vistos


def antifuga(motor, salida, secretos, centinelas, texto_contenedor):
    """Escáner anti-fuga sobre el informe real y la salida guardada de un
    motor, contra los secretos de TODAS las ejecuciones (un secreto de un motor
    en la salida de otro también es una fuga), con el centinela del motor como
    control positivo. Si todo está limpio, genera el informe publicable sin el
    centinela y borra el bruto. Devuelve True solo si el control funcionó y no
    apareció ningún secreto."""
    p(f"=== anti-fuga ({motor}): secretos de todas las ejecuciones en el informe y en la salida del contenedor")
    bruto = salida / INFORME_BRUTO
    contenido = bruto.read_text(encoding="utf-8") if bruto.is_file() else ""
    pasa(bool(contenido.strip()), f"{motor}: el informe HTML existe y no esta vacio")
    if not contenido.strip():
        return False
    # El HTML tal cual y desescapado (atributos y entidades).
    textos = [contenido, html.unescape(contenido), texto_contenedor]
    elemento = FORMATO_CENTINELA.format(centinelas[0]) if len(centinelas) == 1 else None
    control = elemento is not None and contenido.count(elemento) == 1
    if not control:
        sinc(f"{motor}: el centinela no aparece una vez en el informe: el escaner no demuestra nada")
    adjuntos = [a for a in ADJUNTOS_BASE64 if a in contenido]
    pasa(not adjuntos, f"{motor}: el informe no lleva adjuntos en base64, que el escaner no lee ({adjuntos})")
    vistos = fugas(secretos, textos)
    negativo(f"{motor}: ningun secreto de las ejecuciones aparece en el informe ni en la salida (revisados: "
             f"{sorted(secretos)}; vistos: {vistos})", not vistos, control)
    if not control or vistos or adjuntos:
        p(f"   NO PUBLICAR {bruto}: puede llevar secretos de esta ejecucion")
        return False
    # El informe publicable se escribe de nuevo, sin el elemento del
    # centinela, en vez de editar el bruto en su sitio: nunca hay un fichero
    # publicable a medias. Se comprueba otra vez antes de borrar el bruto.
    publicable = contenido.replace(elemento, "", 1)
    limpio = centinelas[0] not in publicable and not fugas(secretos, [publicable, html.unescape(publicable)])
    pasa(limpio, f"{motor}: el informe publicable no lleva el centinela ni ningun secreto")
    if limpio:
        (salida / INFORME_PUBLICABLE).write_text(publicable, encoding="utf-8", newline="\n")
        bruto.unlink()
    return True


def interpretar(motor, codigo, resumen):
    p(f"=== resultado de pytest ({motor})")
    esperadas = PRUEBAS_ESPERADAS[motor]
    if resumen is None:
        pasa(False, f"{motor}: conftest.py no dejo resumen.json")
        return
    p(f"   {json.dumps(resumen, ensure_ascii=False)}")
    if resumen.get("sin_conclusion", 0):
        sinc(f"{motor}: {resumen['sin_conclusion']} prueba(s) SIN CONCLUSION: un control positivo fallo")
    pasa(resumen.get("fallidas") == 0 and resumen.get("errores_coleccion") == 0,
         f"{motor}: ninguna prueba falla ni hay errores de recogida ({resumen.get('fallidas')}, "
         f"{resumen.get('errores_coleccion')})")
    pasa(resumen.get("saltadas") == 0 and resumen.get("xfail") == 0 and resumen.get("xpass") == 0,
         f"{motor}: ninguna prueba saltada ni fallo esperado ({resumen.get('saltadas')}, {resumen.get('xfail')}, "
         f"{resumen.get('xpass')})")
    pasa(resumen.get("recogidas") == esperadas and resumen.get("pasadas") == esperadas,
         f"{motor}: pasan las {esperadas} pruebas esperadas ({resumen.get('pasadas')} de {resumen.get('recogidas')})")
    pasa(codigo == 0 and resumen.get("codigo_salida") == 0,
         f"{motor}: pytest termina con codigo 0 ({codigo}, {resumen.get('codigo_salida')})")


def orden_powershell(args):
    return " ".join(f'"{a}"' if " " in a or "\\" in a else a for a in args)


def main():
    analizador = argparse.ArgumentParser(description="Pruebas funcionales de Canario (F1, F2 y F3; Chromium, "
                                                     "Firefox y WebKit)")
    analizador.add_argument("--conservar", action="store_true",
                            help="no borra la pila ni los temporales (solo para desarrollar)")
    conservar = analizador.parse_args().conservar

    git_arranque = estado_git()
    # Precondiciones: si fallan, no se limpia nada (podrían ser recursos ajenos).
    if ejecutar(["docker", "info", "--format", "{{.ServerVersion}}"]).rc != 0:
        p("PARADA: docker info falla")
        terminar_con_parada()
    previos = recursos_previos()
    if previos:
        p(f"PARADA: ya existen recursos con prefijo {PROYECTO}: {previos} (restos de una ejecucion anterior)")
        terminar_con_parada()
    ocupadas = subredes_ocupadas()
    if ocupadas:
        p(f"PARADA: las subredes {', '.join(SUBREDES)} ya estan en uso por {ocupadas} "
          "(pare el proyecto canario: docker compose -p canario down, sin -v)")
        terminar_con_parada()
    ocupados = puertos_ocupados()
    if ocupados:
        p(f"PARADA: 127.0.0.1:{ocupados} ya esta en uso (pare el proyecto canario)")
        terminar_con_parada()
    r = dc("config", "--quiet")
    if r.rc != 0:
        p(f"PARADA: docker compose config falla (genere los secretos con scripts/generar_secretos.py): "
          f"{r.err.strip()[:300]}")
        terminar_con_parada()

    temporal = pathlib.Path(tempfile.mkdtemp(prefix="canario_funcionales_"))
    datos_raiz = pathlib.Path(tempfile.mkdtemp(prefix="canario_funcionales_datos_"))
    salida_raiz = pathlib.Path(tempfile.mkdtemp(prefix="canario_funcionales_salida_"))
    try:
        overrides = preparar_overrides(temporal)
    except ImportError:
        p("PARADA: falta cryptography en el Python que ejecuta las pruebas (pip install -r requirements.txt)")
        for directorio in (temporal, datos_raiz, salida_raiz):
            shutil.rmtree(directorio, ignore_errors=True)
        terminar_con_parada()
    for fichero in overrides:
        BASE.extend(["-f", str(fichero)])

    parada = None
    try:
        spki, hojas_b64 = arrancar(temporal)
        # Por motor: su salida (/salida/<motor> en el host), su empresa y su
        # fichero de datos, que el contenedor monta de solo lectura.
        salidas, resultados, tokens = {}, {}, []
        secretos_todos, centinelas = {}, {}
        for motor in MOTORES:
            salida = salidas[motor] = salida_raiz / motor
            salida.mkdir()
            datos = datos_raiz / motor
            datos.mkdir()
            identificador, token = alta_empresa(motor)
            if token is not None:
                tokens.append(token)
            (datos / "datos.json").write_text(json.dumps({"identificador": identificador, "token_admin": token}),
                                              encoding="utf-8", newline="\n")
            codigo, texto = ejecutar_pruebas(motor, datos, salida, temporal, spki, hojas_b64, tokens)
            # secretos.json se lee, se usa y se borra: nunca se publica. El
            # token del admin lo conoce el host; el resto lo registra
            # conftest.py. Cada token entra en el escáner.
            secretos = leer_json(salida / "secretos.json")
            (salida / "secretos.json").unlink(missing_ok=True)
            if not isinstance(secretos, dict):
                sinc(f"{motor}: conftest.py no dejo secretos.json: el escaner no sabe que buscar")
                secretos = {}
            centinelas[motor] = secretos.pop("centinela", [])
            if token is not None:
                secretos.setdefault("token_admin", []).append(token)
            for nombre, valores in secretos.items():
                secretos_todos.setdefault(nombre, []).extend(valores)
            resultados[motor] = (codigo, texto)
            # Si el humo falla, PARADA: no se sigue con los demás motores.
            comprobar_humo(motor, salida)
        # El escáner, con los secretos de TODAS las ejecuciones contra la
        # salida de cada motor.
        for motor in MOTORES:
            codigo, texto = resultados[motor]
            if antifuga(motor, salidas[motor], secretos_todos, centinelas[motor], texto):
                # Solo con el escáner limpio y su control en verde se enseña el
                # final de la salida de pytest (el resumen de la terminal).
                p(f"   final de la salida del contenedor de {motor}:")
                for linea in texto.strip().splitlines()[-15:]:
                    p(f"   | {linea}")
            interpretar(motor, codigo, leer_json(salidas[motor] / "resumen.json"))
    except Parada as e:
        parada = str(e)
        p(f"PARADA: {parada}")
    except Exception:  # noqa: BLE001 - error inesperado del propio lanzador: se informa y se limpia
        parada = "error inesperado en el lanzador"
        p("ERROR INESPERADO:\n" + traceback.format_exc())
    finally:
        for motor in MOTORES:
            (salida_raiz / motor / "secretos.json").unlink(missing_ok=True)
            ejecutar(["docker", "rm", "-f", contenedor_de(motor)])
        if conservar:
            p("=== --conservar: la pila y los temporales siguen ahi")
            p("AVISO: las credenciales de esta ejecucion siguen vivas en la pila, y datos.json guarda el token "
              "del admin de cada motor. Borre todo en cuanto termine.")
            p("   Para borrarlo (PowerShell, desde cualquier directorio):")
            p("   " + orden_powershell([*BASE, "down", "-v", "--rmi", "local"]))
            for directorio in (temporal, datos_raiz):
                p(f"   Remove-Item -Recurse -Force \"{directorio}\"")
        else:
            p("=== limpieza")
            r = dc("down", "-v", "--rmi", "local")
            p(f"down -v --rmi local -> codigo {r.rc}")
            restos = recursos_previos()
            pasa(not restos, f"ningun contenedor, red, volumen ni imagen con prefijo {PROYECTO} {restos or ''}".strip())
            shutil.rmtree(temporal, ignore_errors=True)
            shutil.rmtree(datos_raiz, ignore_errors=True)
            pasa(not datos_raiz.exists(), "datos.json (con los tokens de los admin) se ha borrado")
        git_final = estado_git()
        if git_arranque is None or git_final is None:
            sinc("no se pudo comparar el estado de Git")
        else:
            iguales = git_final == git_arranque
            pasa(iguales, "las pruebas no han modificado el repo (git status igual al del arranque)")
            if not iguales:
                p(f"   al arrancar: {git_arranque}")
                p(f"   al terminar: {git_final}")
        p(f"Informe y trazas (si hubo fallo), una carpeta por motor: {salida_raiz}")
        p("   Las trazas llevan codigos, contrasenas y textos de la ejecucion: no se publican y se borran al "
          "terminar de revisarlas.")
    if parada is not None:
        estado["falla"] = True
    terminar()


if __name__ == "__main__":
    main()
