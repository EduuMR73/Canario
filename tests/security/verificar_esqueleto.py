#!/usr/bin/env python3
"""Batería de pruebas de seguridad del esqueleto vertical: proxy Caddy delante
de la API (docker-compose.yml, Dockerfile, proxy/Dockerfile, proxy/Caddyfile y
app/).

Qué prueba: que la API no tiene salida a internet ni resuelve nombres
externos; que la API solo escucha en su IP fija de la red app (no desde data,
cache ni correo, ni en su propio 127.0.0.1); que los únicos puertos
publicados son los tres del proxy (8443, la API; 8444, el sitio del
denunciante; 8445, la SPA del personal) y solo en 127.0.0.1; que solo /salud responde; las cabeceras de
seguridad con valores literales y sin Server; que un Host que no coincide con
el SNI recibe 421; que el sitio del denunciante sirve sus estáticos con sus
cabeceras y sin rangos, y que desde él no se alcanza la API fuera de /web (n;
el reenvío a /web lo prueba verificar_web.py); que la IP del cliente no queda en los logs de
Caddy ni de la API ni en el volumen de Caddy tras una ráfaga de peticiones; que
un X-Forwarded-For falsificado no llega a la API tal cual y que uvicorn solo
confía en las cabeceras de reenvío del proxy; usuario no root, solo lectura,
capacidades y límites; el healthcheck sano y roto; la imagen y el estado de
Caddy (sin file capability, /data/caddy cerrado, /config de solo lectura, sin
volúmenes anónimos, sin autosave ni HTTP/3); que el CA de Caddy sobrevive a
reinicios; y que Caddy funciona sin internet (en una red interna, con un
volumen vacío, crea su CA y sirve con TLS validado sin intentar ACME ni OCSP). Cada prueba negativa lleva su control positivo: si el control falla,
el resultado es SIN CONCLUSION, nunca PASA. Los oráculos son literales.

Cómo se ejecuta (desde la raíz del repositorio, en PowerShell, con Docker en
marcha):

    python tests/security/verificar_esqueleto.py

Usa un proyecto de Docker propio (canario_esqueleto) y levanta los servicios
api y caddy (y postgres y redis, de los que depende la API para su arranque
verificado).
Nunca toca el proyecto canario, pero necesita que esté
parado: las subredes 10.88.0.0/28 y 10.88.1.0/28 y los puertos 127.0.0.1:8443,
127.0.0.1:8444 y 127.0.0.1:8445 son fijos y no pueden estar en uso por otro proyecto (si lo
están, PARADA). Al
terminar lo borra todo (down -v y las imágenes construidas). No lee ningún
secreto: docker compose solo necesita que los ficheros de secrets/ existan.

Los ficheros auxiliares (cliente de pruebas, aplicación de eco, Caddyfile de
control y override de Compose) se escriben en un directorio temporal del
sistema, nunca dentro del repositorio, y se borran al terminar. La salida
completa se guarda en verificacion_esqueleto.txt dentro del directorio temporal
del sistema. El código de salida es 0 solo si el resultado global es OK.

Solo usa la biblioteca estándar.
"""
import http.client
import json
import pathlib
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import traceback

RAIZ = pathlib.Path.cwd()
PROYECTO = "canario_esqueleto"
SALIDA = pathlib.Path(tempfile.gettempdir()) / "verificacion_esqueleto.txt"
BASE = ["docker", "compose", "-p", PROYECTO, "-f", "docker-compose.yml"]

lineas_salida = []
estado = {"falla": False, "sin_conclusion": False}

# ---------------------------------------------------------------------------
# Oráculos literales
# ---------------------------------------------------------------------------
PUERTO = 8443
PUERTO_DENUNCIANTE = 8444
PUERTO_SPA = 8445
SUBRED_APP = "10.88.0.0/28"
SUBRED_EDGE = "10.88.1.0/28"
IP_PROXY = "10.88.0.2"
RANGO_APP = "10.88.0.8/29"  # IPs automáticas; de .2 a .7 quedan para IPs fijas
RANGO_EDGE = "10.88.1.8/29"
IP_CLIENTE = "10.88.1.3"  # cliente de pruebas en la red edge (fuera del rango automático)
IP_DIRECTO = "10.88.0.3"  # cliente de pruebas en la red app, sin pasar por el proxy
IP_API = "10.88.0.4"  # IP fija de la API en app: la única en la que escucha uvicorn
SUBRED_CANJE = "10.88.2.0/28"
RANGO_CANJE = "10.88.2.8/29"
IP_API_CANJE = "10.88.2.4"  # IP fija de la API en canje, la única a la que atiende el broker
IP_FALSA = "6.6.6.6"  # valor falsificado de X-Forwarded-For
# ENTRYPOINT de la imagen de la API, sin --host (uvicorn escucha entonces en
# 127.0.0.1), y command del compose, que lo añade.
ENTRYPOINT_API = ["uvicorn", "app.principal:aplicacion", "--port", "8000", "--no-access-log", "--no-server-header"]
COMANDO_API = ["--host", IP_API, "--proxy-headers", "--forwarded-allow-ips", IP_PROXY]

CUERPO_SALUD = b'{"estado":"ok"}'
CABECERAS = {
    "strict-transport-security": "max-age=63072000",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    "cache-control": "no-store",
}
RUTAS_404 = ["/", "/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect", "/salud/", "/SALUD", "/no-existe"]

# Sitio del denunciante (8444): cabeceras de las páginas HTML y de sus estáticos.
CABECERAS_HTML = {
    "strict-transport-security": "max-age=63072000",
    "x-content-type-options": "nosniff",
    "referrer-policy": "same-origin",
    "content-security-policy": ("default-src 'none'; style-src 'self'; form-action 'self'; "
                                "frame-ancestors 'none'; base-uri 'none'"),
    "cache-control": "no-store",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
}
RUTA_CSS = "/estatico/canario.css"
TIPO_CSS = "text/css; charset=utf-8"
TIPO_HTML = "text/html; charset=utf-8"
METODOS_ESTATICOS = "GET, HEAD"
RANGO_DOBLE = "bytes=0-1,3-4"
TIPO_RANGOS = "multipart/byteranges"
# Rutas que no son un estático existente ni una página: la API fuera de /web
# (el 8444 las reenvía como /web/salud, /web/v1/denuncias..., que no existen),
# un directorio sin index (no debe listarse), un fichero que no existe y cuatro
# intentos de salir de /srv con "../" literal y codificado. "/" es la página de
# inicio (app/rutas_web.py); las páginas las prueba verificar_web.py.
RUTAS_404_DENUNCIANTE = ["/salud", "/v1/denuncias", "/docs", "/estatico/", "/estatico/no-existe.css",
                         "/estatico/../etc/caddy/Caddyfile", "/estatico/%2e%2e/%2e%2e/etc/passwd",
                         "/estatico/..%2f..%2fetc/passwd", "/estatico/%2e%2e%2f%2e%2e%2fetc%2fcaddy%2fCaddyfile"]

USUARIO = {"api": "10001:10001", "caddy": "10002:10002"}
UID = {"api": "10001", "caddy": "10002"}
MEMORIA = {"api": 268435456, "caddy": 134217728}  # 256m y 128m
PIDS = 64
CAP_CERO = "0000000000000000"
PUERTOS_CADDY = {"8443/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8443"}],
                 "8444/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8444"}],
                 "8445/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8445"}]}
# La API está en app (con el proxy), en data (con PostgreSQL), en cache (con
# Redis, el del limitador), en correo (con el SMTP de desarrollo) y en canje
# (con el broker del login externo), nunca en edge.
REDES = {"api": {f"{PROYECTO}_app", f"{PROYECTO}_data", f"{PROYECTO}_cache", f"{PROYECTO}_correo",
                 f"{PROYECTO}_canje"},
         "caddy": {f"{PROYECTO}_app", f"{PROYECTO}_edge"}}
# Únicos montajes de la API: sus siete Docker secrets (contraseña de la base
# de datos, clave maestra, clave del HMAC de los códigos, clave de firma de
# los JWT, clave del HMAC de las identidades externas, clave de las cookies
# del login externo y contraseña de Redis), ordenados por destino porque
# docker inspect no garantiza el orden. Nunca contrasena_plataforma ni los
# client_secret de los proveedores, que son solo del broker.
MONTAJES_API = [("bind", "", "/run/secrets/clave_firma_tokens"),
                ("bind", "", "/run/secrets/clave_flujo_externo"),
                ("bind", "", "/run/secrets/clave_hmac_codigos"),
                ("bind", "", "/run/secrets/clave_hmac_identidades"),
                ("bind", "", "/run/secrets/clave_maestra"),
                ("bind", "", "/run/secrets/contrasena_aplicacion"),
                ("bind", "", "/run/secrets/contrasena_redis")]

IMAGEN_CADDY_OFICIAL = ("caddy:2.11.7-alpine@sha256:"
                        "d8542f48d34a9cf4e4c11a478865229840e87e4c96ea3f439101f31a5d35f75f")
CAP_OFICIAL = "cap_net_bind_service=ep"
RAIZ_CA = "/data/caddy/pki/authorities/local/root.crt"

# Literales del código de Caddy (caddy.go) y de su log de arranque
TEXTO_AUTOSAVE = "unable to autosave config"
TEXTO_HTTP3 = "enabling HTTP/3 listener"

# ---------------------------------------------------------------------------
# Ficheros auxiliares (se escriben en el directorio temporal)
# ---------------------------------------------------------------------------
# Cliente que corre DENTRO de un contenedor con IP fija. Solo genera tráfico:
# no valida el certificado (la validación TLS se prueba desde el host en f).
CLIENTE = r'''
import http.client, json, socket, ssl, sys

modo, destino = sys.argv[1], sys.argv[2]
SIN_VERIFICAR = ssl.create_default_context()
SIN_VERIFICAR.check_hostname = False
SIN_VERIFICAR.verify_mode = ssl.CERT_NONE


def https(ruta, cabeceras=None, host="localhost:8443", sni="localhost"):
    s = socket.create_connection((destino, 8443), timeout=10)
    t = SIN_VERIFICAR.wrap_socket(s, server_hostname=sni)
    c = http.client.HTTPConnection("localhost", 8443, timeout=10)
    c.sock = t
    c.putrequest("GET", ruta, skip_host=True)
    c.putheader("Host", host)
    for k, v in (cabeceras or {}).items():
        c.putheader(k, v)
    c.endheaders()
    r = c.getresponse()
    cuerpo = r.read()
    c.close()
    return r.status, cuerpo


def http_directo(ruta, cabeceras):
    c = http.client.HTTPConnection(destino, 8000, timeout=10)
    c.request("GET", ruta, headers=cabeceras)
    r = c.getresponse()
    return r.status, r.read()


falsa = {"X-Forwarded-For": "6.6.6.6", "X-Real-IP": "6.6.6.6", "Forwarded": "for=6.6.6.6"}
res = {}
if modo == "rafaga":
    res["salud200"] = sum(https("/salud", falsa)[0] == 200 for _ in range(20))
    res["noexiste404"] = sum(https("/no-existe", falsa)[0] == 404 for _ in range(10))
    res["host421"] = sum(https("/salud", host="otro.ejemplo")[0] == 421 for _ in range(3))
    planos = 0
    for _ in range(5):  # HTTP en claro contra el puerto TLS
        s = socket.create_connection((destino, 8443), timeout=10)
        s.sendall(b"GET /salud HTTP/1.1\r\nHost: localhost\r\n\r\n")
        planos += bool(s.recv(4096))
        s.close()
    res["plano_respondido"] = planos
    fallos_sni = 0
    for sni in ["desconocido.ejemplo"] * 3 + [None] * 3:  # SNI sin certificado y sin SNI
        try:
            https("/salud", sni=sni)
        except (ssl.SSLError, OSError):
            fallos_sni += 1
    res["tls_fallido"] = fallos_sni
elif modo == "control":
    res["salud200"] = sum(https("/salud", falsa)[0] == 200 for _ in range(5))
elif modo == "eco_proxy":
    estado, cuerpo = https("/eco", {"X-Forwarded-For": "6.6.6.6", "X-Prueba": "canario"})
    res = {"codigo": estado, **json.loads(cuerpo)}
elif modo == "eco_directo":
    estado, cuerpo = http_directo("/eco", {"X-Forwarded-For": "6.6.6.6", "X-Prueba": "canario"})
    res = {"codigo": estado, **json.loads(cuerpo)}
elif modo.startswith("cabecera_lenta_"):
    # Envía la línea de petición y una cabecera, espera N segundos y termina
    # las cabeceras. Con N mayor que read_header, Caddy debe cortar.
    import time
    pausa = int(modo.rsplit("_", 1)[1])
    s = SIN_VERIFICAR.wrap_socket(socket.create_connection((destino, 8443), timeout=pausa + 20),
                                  server_hostname="localhost")
    inicio = time.monotonic()
    try:
        s.sendall(b"GET /salud HTTP/1.1\r\nHost: localhost:8443\r\n")
        time.sleep(pausa)
        s.sendall(b"Connection: close\r\n\r\n")
        datos = b""
        while True:
            trozo = s.recv(4096)
            if not trozo:
                break
            datos += trozo
        linea = datos.split(b"\r\n", 1)[0].split()
        res = {"estado": int(linea[1]) if len(linea) > 1 and linea[1].isdigit() else None}
    except OSError as error:
        res = {"error": type(error).__name__}
    res["segundos"] = round(time.monotonic() - inicio, 1)
print(json.dumps(res, sort_keys=True))
'''

# Aplicación ASGI de eco, sin dependencias, que sustituye a la API en j). Se
# sirve con el mismo uvicorn y las mismas opciones de reenvío (el command del
# compose). Responde en /salud como la API para que el healthcheck siga sano.
ECO = r'''
import json


async def aplicacion(scope, receive, send):
    if scope["type"] == "lifespan":
        while True:
            mensaje = await receive()
            if mensaje["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif mensaje["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return
    if scope["path"] == "/salud":
        cuerpo = b'{"estado":"ok"}'
    else:
        cab = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        cuerpo = json.dumps({
            "cliente": scope["client"][0] if scope.get("client") else None,
            "xff": cab.get("x-forwarded-for"),
            "prueba": cab.get("x-prueba"),
        }).encode()
    await send({"type": "http.response.start", "status": 200,
                "headers": [(b"content-type", b"application/json")]})
    await send({"type": "http.response.body", "body": cuerpo})
'''

# Ejecuta app.comprobar_salud contra servidores locales que responden bien,
# con otro cuerpo, con 500, y contra un puerto cerrado.
SALUD_ROTA = r'''
import http.server, json, socket, subprocess, threading

def servidor(codigo, cuerpo):
    class Manejador(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(codigo)
            self.send_header("Content-Length", str(len(cuerpo)))
            self.end_headers()
            self.wfile.write(cuerpo)
        def log_message(self, *a):
            pass
    s = http.server.HTTPServer(("127.0.0.1", 0), Manejador)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s.server_address[1]

def comprobar(puerto):
    return subprocess.run(["python", "-m", "app.comprobar_salud", "127.0.0.1", str(puerto)],
                          cwd="/srv", capture_output=True).returncode

libre = socket.socket(); libre.bind(("127.0.0.1", 0)); cerrado = libre.getsockname()[1]; libre.close()
print(json.dumps({
    "correcto": comprobar(servidor(200, b'{"estado":"ok"}')),
    "otro_cuerpo": comprobar(servidor(200, b'{"estado":"mal"}')),
    "cuerpo_largo": comprobar(servidor(200, b'{"estado":"ok"} ')),
    "codigo_500": comprobar(servidor(500, b'{"estado":"ok"}')),
    "cerrado": comprobar(cerrado),
}, sort_keys=True))
'''

# Caddy de control para i): igual que el real en lo básico, pero CON la
# directiva log. Debe dejar la IP del cliente en su log.
CADDYFILE_CONTROL_LOG = """{
	admin off
	persist_config off
	auto_https disable_redirects
	skip_install_trust
}

https://localhost:8443 {
	tls internal
	log
	respond "ok" 200
}
"""

# Caddy de control para g): SIN persist_config off y con los protocolos por
# defecto. Debe registrar el fallo de autosave y el listener de HTTP/3.
CADDYFILE_CONTROL_AUTOSAVE = """{
	admin off
	auto_https disable_redirects
	skip_install_trust
}

https://localhost:8443 {
	tls internal
	respond "ok" 200
}
"""


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


def ejecutar(args, timeout=900):
    # check=False explícito: el código de salida se comprueba en cada llamada.
    r = subprocess.run(args, capture_output=True, timeout=timeout, check=False)
    return R(r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace"))


def dc(*args, override=None):
    base = BASE + (["-f", str(override)] if override else [])
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


def exec_(servicio, *orden):
    return dc("exec", "-T", servicio, *orden)


def docker_run(*args, timeout=300):
    """docker run --rm: contenedor desechable que se borra al terminar."""
    return ejecutar(["docker", "run", "--rm", *args], timeout=timeout)


# ---------------------------------------------------------------------------
# Cliente HTTPS desde el host, validando el certificado contra el CA de Caddy
# ---------------------------------------------------------------------------
TEMPORAL = None
CA_LOCAL = None
IMAGEN_API = ""
IMAGEN_PROXY = ""


def peticion(metodo, ruta, host=None, puerto=PUERTO, cabeceras=None):
    """Petición al proxy publicado en 127.0.0.1 con SNI localhost y TLS validado.

    La ruta se envía tal cual (http.client no la normaliza), así que sirve para
    probar "../" literal.
    """
    contexto = ssl.create_default_context(cafile=str(CA_LOCAL))
    s = socket.create_connection(("127.0.0.1", puerto), timeout=10)
    t = contexto.wrap_socket(s, server_hostname="localhost")
    c = http.client.HTTPConnection("localhost", puerto, timeout=10)
    c.sock = t
    c.putrequest(metodo, ruta, skip_host=True)
    c.putheader("Host", host or f"localhost:{puerto}")
    c.putheader("Content-Length", "0")
    for nombre, valor in (cabeceras or {}).items():
        c.putheader(nombre, valor)
    c.endheaders()
    r = c.getresponse()
    cuerpo = r.read()
    cabeceras = r.getheaders()
    c.close()
    return r.status, cabeceras, cuerpo


def cliente_red(red, ip, modo, destino):
    """Ejecuta el cliente de pruebas en un contenedor de IP fija y devuelve su JSON."""
    r = docker_run("--name", f"{PROYECTO}_cliente", "--network", red, "--ip", ip,
                   "--mount", f"type=bind,src={TEMPORAL},dst=/prueba,readonly",
                   "--entrypoint", "python", IMAGEN_API, "-I", "/prueba/cliente.py", modo, destino)
    if r.rc != 0:
        p(f"   cliente {modo}: codigo {r.rc} {r.err.strip()[-300:]!r}")
        return None
    return json.loads(r.out.strip().splitlines()[-1])


# ---------------------------------------------------------------------------
# Comprobaciones
# ---------------------------------------------------------------------------
def seccion_a():
    global IMAGEN_API, IMAGEN_PROXY, CA_LOCAL
    p("=== a) arranque")
    r = dc("up", "-d", "--build", "--wait", "api", "caddy")
    p(f"up -d --build --wait api caddy -> codigo {r.rc}")
    if r.rc != 0:
        p(r.todo.strip()[-1500:])
        raise Parada("no arranca el esqueleto")
    IMAGEN_API = inspeccionar(contenedor("api"), "{{json .Config.Image}}")
    IMAGEN_PROXY = inspeccionar(contenedor("caddy"), "{{json .Config.Image}}")
    p(f"imagenes: {IMAGEN_API}, {IMAGEN_PROXY}")
    CA_LOCAL = TEMPORAL / "root.crt"
    r = dc("cp", f"caddy:{RAIZ_CA}", str(CA_LOCAL))
    if r.rc != 0 or not CA_LOCAL.is_file():
        raise Parada(f"no se pudo copiar el certificado raiz del CA de Caddy: {r.err.strip()[:200]}")


def seccion_b():
    p("=== b) imagenes")
    for nombre, imagen in (("api", IMAGEN_API), ("caddy", IMAGEN_PROXY), ("caddy oficial", IMAGEN_CADDY_OFICIAL)):
        volumenes = inspeccionar(imagen, "{{json .Config.Volumes}}")
        pasa(volumenes is None, f"b) la imagen {nombre} no declara VOLUME (Config.Volumes = {volumenes})")
    for servicio, imagen in (("api", IMAGEN_API), ("caddy", IMAGEN_PROXY)):
        usuario = inspeccionar(imagen, "{{json .Config.User}}")
        pasa(usuario == USUARIO[servicio], f"b) la imagen {servicio} declara USER {USUARIO[servicio]} ({usuario!r})")
    r = docker_run("--entrypoint", "python", IMAGEN_API, "-c", "import pip")
    pasa(r.rc != 0 and "No module named 'pip'" in r.err, "b) la imagen de la API no tiene pip")
    entrypoint = inspeccionar(IMAGEN_API, "{{json .Config.Entrypoint}}")
    pasa(entrypoint == ENTRYPOINT_API, f"b) el ENTRYPOINT de la imagen de la API no fija --host ({entrypoint})")


def seccion_c():
    p("=== c) contenedores: usuario, solo lectura, capacidades y limites")
    for servicio in ("api", "caddy"):
        cid = contenedor(servicio)
        i = inspeccionar(cid)
        hc = i["HostConfig"]
        pasa(i["Config"]["User"] == USUARIO[servicio], f"c) {servicio}: User = {i['Config']['User']!r}")
        pasa(hc["ReadonlyRootfs"] is True, f"c) {servicio}: ReadonlyRootfs = {hc['ReadonlyRootfs']}")
        pasa(hc["CapDrop"] == ["ALL"], f"c) {servicio}: CapDrop = {hc['CapDrop']}")
        pasa(not hc["CapAdd"], f"c) {servicio}: CapAdd vacio ({hc['CapAdd']})")
        pasa(hc["SecurityOpt"] == ["no-new-privileges:true"], f"c) {servicio}: SecurityOpt = {hc['SecurityOpt']}")
        pasa(hc["Memory"] == MEMORIA[servicio], f"c) {servicio}: Memory = {hc['Memory']}")
        pasa(hc["PidsLimit"] == PIDS, f"c) {servicio}: PidsLimit = {hc['PidsLimit']}")
        pasa(not hc["Privileged"], f"c) {servicio}: no privilegiado")
        uid = exec_(servicio, "id", "-u").out.strip()
        pasa(uid == UID[servicio], f"c) {servicio}: id -u dentro del contenedor = {uid!r}")
        estado_proc = exec_(servicio, "cat", "/proc/1/status").out
        campos = dict(l.split(":\t", 1) for l in estado_proc.splitlines() if ":\t" in l)
        for cap in ("CapPrm", "CapEff", "CapBnd"):
            pasa(campos.get(cap, "").strip() == CAP_CERO, f"c) {servicio}: {cap} del proceso 1 = {campos.get(cap, '').strip()}")
        pasa(campos.get("NoNewPrivs", "").strip() == "1", f"c) {servicio}: NoNewPrivs = {campos.get('NoNewPrivs', '').strip()}")
    # Control: la misma imagen sin cap_drop tiene capacidades en el conjunto límite.
    r = docker_run("--entrypoint", "cat", IMAGEN_API, "/proc/1/status")
    bnd = [l.split(":\t", 1)[1].strip() for l in r.out.splitlines() if l.startswith("CapBnd:")]
    if not bnd or bnd[0] == CAP_CERO:
        sinc(f"c) control: sin cap_drop el conjunto limite deberia no ser cero ({bnd})")
    else:
        pasa(True, f"c) control: sin cap_drop CapBnd = {bnd[0]} (la comprobacion distingue)")


def seccion_d():
    p("=== d) redes y puertos publicados")
    for servicio in ("api", "caddy"):
        i = inspeccionar(contenedor(servicio))
        redes = set(i["NetworkSettings"]["Networks"])
        pasa(redes == REDES[servicio], f"d) {servicio}: redes = {sorted(redes)}")
        publicados = {k: v for k, v in (i["NetworkSettings"]["Ports"] or {}).items() if v}
        esperado = PUERTOS_CADDY if servicio == "caddy" else {}
        pasa(publicados == esperado, f"d) {servicio}: puertos publicados = {publicados}")
        pasa((i["HostConfig"]["PortBindings"] or {}) == esperado,
             f"d) {servicio}: PortBindings = {i['HostConfig']['PortBindings']}")
    ip = inspeccionar(contenedor("caddy"))["NetworkSettings"]["Networks"][f"{PROYECTO}_app"]["IPAddress"]
    pasa(ip == IP_PROXY, f"d) caddy tiene la IP fija {IP_PROXY} en app ({ip})")
    ip = inspeccionar(contenedor("api"))["NetworkSettings"]["Networks"][f"{PROYECTO}_app"]["IPAddress"]
    pasa(ip == IP_API, f"d) la API tiene la IP fija {IP_API} en app ({ip})")
    ip = inspeccionar(contenedor("api"))["NetworkSettings"]["Networks"][f"{PROYECTO}_canje"]["IPAddress"]
    pasa(ip == IP_API_CANJE, f"d) la API tiene la IP fija {IP_API_CANJE} en canje ({ip})")
    for red, subred, rango, interna in ((f"{PROYECTO}_app", SUBRED_APP, RANGO_APP, True),
                                        (f"{PROYECTO}_edge", SUBRED_EDGE, RANGO_EDGE, False),
                                        (f"{PROYECTO}_canje", SUBRED_CANJE, RANGO_CANJE, True)):
        i = inspeccionar(red)
        config = [(c["Subnet"], c.get("IPRange")) for c in i["IPAM"]["Config"]]
        pasa(config == [(subred, rango)], f"d) {red}: subred y rango automatico = {config}")
        pasa(i["Internal"] is interna, f"d) {red}: internal = {i['Internal']}")
    # La red del correo, interna: la API no gana salida a internet por ella
    # (la e) lo comprueba con una conexión real).
    interna = inspeccionar(f"{PROYECTO}_correo")["Internal"]
    pasa(interna is True, f"d) {PROYECTO}_correo: internal = {interna}")


PRUEBA_SALIDA = ("import socket\n"
                 "try:\n"
                 "    socket.create_connection(('1.1.1.1', 443), timeout=5).close(); print('CONECTA')\n"
                 "except OSError as e:\n"
                 "    print('SIN_SALIDA', type(e).__name__)\n")


# Resolución de un nombre externo. Sin DNS hacia fuera no hay exfiltración por
# consultas DNS (ATT&CK T1071.004). github.com y no example.com: con el DNS del
# anfitrión de Windows, example.com no resolvía ni desde la red bridge
# (comprobado), y un control que falla por eso deja la prueba sin conclusión.
PRUEBA_DNS = ("import socket\n"
              "try:\n"
              "    socket.getaddrinfo('github.com', 443, socket.AF_INET); print('RESUELVE')\n"
              "except OSError as e:\n"
              "    print('SIN_DNS', type(e).__name__)\n")


# Ruta por defecto (destino 00000000 en /proc/net/route). Sin ella, el tráfico
# hacia fuera no tiene por dónde salir aunque un vecino de una red interna
# (el broker, en canje) tenga internet: la API no puede añadirse una ruta, porque
# no tiene CAP_NET_ADMIN (cap_drop ALL).
PRUEBA_RUTA = ("rutas = open('/proc/net/route').read().splitlines()[1:]\n"
               "print('CON_RUTA' if any(l.split()[1] == '00000000' for l in rutas) else 'SIN_RUTA')\n")


def seccion_e():
    p("=== e) la API no tiene salida a internet")
    control = docker_run("--network", "bridge", "--entrypoint", "python", IMAGEN_API, "-c", PRUEBA_RUTA)
    r = exec_("api", "python", "-c", PRUEBA_RUTA)
    negativo(f"e) la API no tiene ruta por defecto ({r.out.strip()})",
             r.out.strip() == "SIN_RUTA", control.out.strip() == "CON_RUTA",
             f"control en la red bridge: {control.out.strip()!r}")
    control = docker_run("--network", "bridge", "--entrypoint", "python", IMAGEN_API, "-c", PRUEBA_SALIDA)
    r = exec_("api", "python", "-c", PRUEBA_SALIDA)
    negativo(f"e) desde la API no se llega a 1.1.1.1:443 ({r.out.strip()})",
             r.out.startswith("SIN_SALIDA"), control.out.strip() == "CONECTA",
             f"control en la red bridge: {control.out.strip()!r}")
    control = docker_run("--network", "bridge", "--entrypoint", "python", IMAGEN_API, "-c", PRUEBA_DNS)
    r = exec_("api", "python", "-c", PRUEBA_DNS)
    negativo(f"e) desde la API no se resuelve github.com ({r.out.strip()})",
             r.out.startswith("SIN_DNS"), control.out.strip() == "RESUELVE",
             f"control en la red bridge: {control.out.strip()!r}")


# Conexión a /salud en el puerto 8000 de una dirección. RECHAZA solo con
# ConnectionRefusedError: nadie escucha en esa dirección. Un tiempo agotado
# u otro error no demuestra eso y sale como OTRO.
PRUEBA_ESCUCHA = ("import http.client, sys\n"
                  "c = http.client.HTTPConnection(sys.argv[1], 8000, timeout=5)\n"
                  "try:\n"
                  "    c.request('GET', '/salud'); r = c.getresponse(); print('RESPONDE', r.status, r.read().decode())\n"
                  "except ConnectionRefusedError:\n"
                  "    print('RECHAZA')\n"
                  "except (OSError, http.client.HTTPException) as e:\n"
                  "    print('OTRO', type(e).__name__)\n")
RESPUESTA_SALUD = 'RESPONDE 200 {"estado":"ok"}'


def seccion_o():
    p("=== o) la API solo escucha en su IP de la red app")
    redes = inspeccionar(contenedor("api"))["NetworkSettings"]["Networks"]
    # Control: un cliente de la red app (sin pasar por el proxy) sí llega.
    control = docker_run("--network", f"{PROYECTO}_app", "--ip", IP_DIRECTO, "--read-only", "--cap-drop", "ALL",
                         "--entrypoint", "python", IMAGEN_API, "-c", PRUEBA_ESCUCHA, IP_API).out.strip()
    control_ok = control == RESPUESTA_SALUD
    pasa(control_ok, f"o) control: desde app, {IP_API}:8000 responde ({control!r})")
    # canje incluida: si el broker, el único vecino con salida a internet,
    # cayera, tampoco podría hablarle a la API.
    for red in ("data", "cache", "correo", "canje"):
        ip = redes[f"{PROYECTO}_{red}"]["IPAddress"]
        r = docker_run("--network", f"{PROYECTO}_{red}", "--read-only", "--cap-drop", "ALL",
                       "--entrypoint", "python", IMAGEN_API, "-c", PRUEBA_ESCUCHA, ip).out.strip()
        negativo(f"o) desde {red}, la API en {ip}:8000 rechaza la conexion ({r!r})", r == "RECHAZA",
                 control_ok, f"control: {control!r}")
    # Dentro del propio contenedor: 127.0.0.1 ya no es la dirección de escucha
    # (el healthcheck usa la IP de app). Control: la IP de app sí responde.
    dentro = exec_("api", "python", "-c", PRUEBA_ESCUCHA, IP_API).out.strip()
    local = exec_("api", "python", "-c", PRUEBA_ESCUCHA, "127.0.0.1").out.strip()
    negativo(f"o) dentro de la API, 127.0.0.1:8000 rechaza la conexion ({local!r})", local == "RECHAZA",
             dentro == RESPUESTA_SALUD, f"control dentro, {IP_API}: {dentro!r}")


def seccion_f():
    p("=== f) rutas, cabeceras y Host")
    estado_salud, cabeceras, cuerpo = peticion("GET", "/salud")
    control = estado_salud == 200 and cuerpo == CUERPO_SALUD
    pasa(control, f"f) GET /salud -> {estado_salud} {cuerpo!r} (control)")
    for ruta in RUTAS_404:
        codigo = peticion("GET", ruta)[0]
        negativo(f"f) GET {ruta} -> 404 ({codigo})", codigo == 404, control)
    codigo = peticion("POST", "/salud")[0]
    negativo(f"f) POST /salud -> 405 ({codigo})", codigo == 405, control)
    for etiqueta, (codigo, cab, _) in (("/salud", (estado_salud, cabeceras, cuerpo)),
                                       ("/no-existe", peticion("GET", "/no-existe"))):
        nombres = [k.lower() for k, _ in cab]
        valores = {k.lower(): v for k, v in cab}
        for nombre, valor in CABECERAS.items():
            pasa(nombres.count(nombre) == 1 and valores.get(nombre) == valor,
                 f"f) {etiqueta}: {nombre}: {valores.get(nombre)!r}")
        pasa("server" not in nombres, f"f) {etiqueta}: sin cabecera Server")
    codigo = peticion("GET", "/salud", host="otro.ejemplo")[0]
    negativo(f"f) Host distinto del SNI -> 421 ({codigo})", codigo == 421, control)


# Cliente para n): pide el CSS sin Range y con dos rangos a cada destino (el
# Caddy del proyecto y el de control) desde la red edge, y devuelve el código,
# el Content-Type y el Accept-Ranges. Reintenta mientras el de control arranca.
CLIENTE_RANGOS = r'''
import http.client, json, socket, ssl, sys, time

SIN_VERIFICAR = ssl.create_default_context()
SIN_VERIFICAR.check_hostname = False
SIN_VERIFICAR.verify_mode = ssl.CERT_NONE


def pedir(destino, cabeceras):
    for _ in range(30):
        try:
            s = SIN_VERIFICAR.wrap_socket(socket.create_connection((destino, 8444), timeout=10),
                                          server_hostname="localhost")
            break
        except OSError:
            time.sleep(1)
    else:
        return None
    c = http.client.HTTPConnection("localhost", 8444, timeout=10)
    c.sock = s
    c.request("GET", "/estatico/canario.css", headers={"Host": "localhost:8444", **cabeceras})
    r = c.getresponse()
    r.read()
    c.close()
    return [r.status, r.getheader("Content-Type"), r.getheader("Accept-Ranges")]


res = {}
for destino in sys.argv[2:]:
    res[destino] = {"sin_rango": pedir(destino, {}), "dos_rangos": pedir(destino, {"Range": sys.argv[1]})}
print(json.dumps(res, sort_keys=True))
'''
# Cambios que convierten el Caddyfile del proyecto en el de control de n): el
# sitio del denunciante sin la quita de Range y sin quitar Accept-Ranges. Se
# construye desde el fichero real para que el control solo difiera en eso.
CAMBIOS_CONTROL_RANGOS = [("\timport sin_range\n\timport cabeceras_html\n", "\timport cabeceras_html\n"),
                          ("\t\theader -Accept-Ranges\n", "")]
# Lo que carga el Caddyfile local: él y los ficheros que importa
# (proxy/Caddyfile). El control se construye sobre una copia de todos.
FICHEROS_CADDY = ("Caddyfile", "global.caddy", "servidor.caddy", "comun.caddy")


def caddyfile_control_rangos(destino):
    """Copia en destino la configuración local de Caddy con los cambios del
    control de n). Cada texto debe aparecer una sola vez en el conjunto de
    ficheros: si no, el control no se puede construir y se ve."""
    textos = {nombre: (RAIZ / "proxy" / nombre).read_text(encoding="utf-8") for nombre in FICHEROS_CADDY}
    for viejo, nuevo in CAMBIOS_CONTROL_RANGOS:
        if sum(texto.count(viejo) for texto in textos.values()) != 1:
            raise Parada(f"proxy/ no contiene una sola vez {viejo.strip()!r}: el control de n) no se puede construir")
        textos = {nombre: texto.replace(viejo, nuevo) for nombre, texto in textos.items()}
    for nombre, texto in textos.items():
        (destino / nombre).write_text(texto, encoding="utf-8", newline="\n")


def cabeceras_exactas(etiqueta, cab, esperadas):
    nombres = [k.lower() for k, _ in cab]
    valores = {k.lower(): v for k, v in cab}
    for nombre, valor in esperadas.items():
        pasa(nombres.count(nombre) == 1 and valores.get(nombre) == valor,
             f"{etiqueta}: {nombre}: {valores.get(nombre)!r}")
    pasa("server" not in nombres, f"{etiqueta}: sin cabecera Server")


def seccion_n():
    p("=== n) sitio del denunciante (8444): estaticos, cabeceras, rangos y errores")
    # Control de todo n): el CSS se sirve, con su tipo y el contenido del repo.
    codigo, cab, cuerpo = peticion("GET", RUTA_CSS, puerto=PUERTO_DENUNCIANTE)
    valores = {k.lower(): v for k, v in cab}
    esperado = (RAIZ / "proxy" / "estatico" / "canario.css").read_bytes()
    control = codigo == 200 and cuerpo == esperado
    pasa(control, f"n) GET {RUTA_CSS} -> {codigo}, {len(cuerpo)} bytes iguales al fichero del repo (control)")
    pasa(valores.get("content-type") == TIPO_CSS, f"n) {RUTA_CSS}: content-type: {valores.get('content-type')!r}")
    cabeceras_exactas(f"n) {RUTA_CSS}", cab, CABECERAS_HTML)

    # Rangos y Accept-Ranges: el Caddy del proyecto frente a uno de control con
    # la misma imagen y el sitio del denunciante sin la quita de Range ni la de
    # Accept-Ranges. El de control debe responder 206 y anunciar bytes; si no,
    # la comprobación no distinguiría nada.
    (TEMPORAL / "control_rangos").mkdir()
    caddyfile_control_rangos(TEMPORAL / "control_rangos")
    (TEMPORAL / "rangos.py").write_text(CLIENTE_RANGOS, encoding="utf-8", newline="\n")
    nombre = f"{PROYECTO}_control_rangos"
    ejecutar(["docker", "run", "-d", "--name", nombre, "--network", f"{PROYECTO}_edge",
              "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
              "--mount", "type=volume,dst=/data",
              # El directorio entero: el Caddyfile importa sus vecinos.
              "--mount", f"type=bind,src={TEMPORAL / 'control_rangos'},dst=/etc/caddy,readonly",
              IMAGEN_PROXY])
    try:
        r = docker_run("--network", f"{PROYECTO}_edge",
                       "--mount", f"type=bind,src={TEMPORAL},dst=/prueba,readonly",
                       "--entrypoint", "python", IMAGEN_API, "-I", "/prueba/rangos.py", RANGO_DOBLE, "caddy", nombre,
                       timeout=120)
    finally:
        ejecutar(["docker", "rm", "-f", "-v", nombre])
    try:
        res = json.loads(r.out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        sinc(f"n) no se pudo ejecutar el cliente de rangos: {r.err.strip()[-300:]!r}")
        return
    real, ctl = res.get("caddy") or {}, res.get(nombre) or {}
    p(f"   rangos: proyecto {real}; control {ctl}")
    ctl_dos, ctl_sin = ctl.get("dos_rangos") or [None] * 3, ctl.get("sin_rango") or [None] * 3
    real_dos, real_sin = real.get("dos_rangos") or [None] * 3, real.get("sin_rango") or [None] * 3
    negativo(f"n) dos rangos -> 200 con el CSS entero, no 206 (CVE-2026-78667) ({real_dos[0]})",
             real_dos[0] == 200 and real_dos[1] == TIPO_CSS,
             ctl_dos[0] == 206 and str(ctl_dos[1]).startswith(TIPO_RANGOS), f"control: {ctl_dos}")
    negativo(f"n) sin Accept-Ranges ({real_sin[2]!r})", real_sin[0] == 200 and real_sin[2] is None,
             ctl_sin[0] == 200 and ctl_sin[2] == "bytes", f"control: {ctl_sin}")

    # Lo que no es un estático existente da 404 en HTML, con las cabeceras del
    # sitio. /salud además demuestra que desde el 8444 no se alcanza la API
    # fuera de /web: en el 8443 la misma ruta responde la API.
    salud_api = peticion("GET", "/salud")
    control_api = control and salud_api[0] == 200 and salud_api[2] == CUERPO_SALUD
    for ruta in RUTAS_404_DENUNCIANTE:
        codigo, cab, _ = peticion("GET", ruta, puerto=PUERTO_DENUNCIANTE)
        tipo = {k.lower(): v for k, v in cab}.get("content-type")
        negativo(f"n) GET {ruta} -> 404 en HTML ({codigo}, {tipo!r})", codigo == 404 and tipo == TIPO_HTML,
                 control_api if ruta == "/salud" else control,
                 f"control: CSS {control}, /salud en {PUERTO} -> {salud_api[0]}")
    codigo, cab, _ = peticion("GET", "/no-existe", puerto=PUERTO_DENUNCIANTE)
    cabeceras_exactas("n) error 404", cab, CABECERAS_HTML)

    codigo, cab, _ = peticion("POST", RUTA_CSS, puerto=PUERTO_DENUNCIANTE)
    valores = {k.lower(): v for k, v in cab}
    negativo(f"n) POST {RUTA_CSS} -> 405 en HTML con Allow {METODOS_ESTATICOS} ({codigo}, {valores.get('allow')!r})",
             codigo == 405 and valores.get("allow") == METODOS_ESTATICOS and valores.get("content-type") == TIPO_HTML,
             control)
    codigo = peticion("GET", RUTA_CSS, host="otro.ejemplo", puerto=PUERTO_DENUNCIANTE)[0]
    negativo(f"n) Host distinto del SNI en {PUERTO_DENUNCIANTE} -> 421 ({codigo})", codigo == 421, control)


def seccion_g():
    p("=== g) imagen y estado de Caddy")
    r = exec_("caddy", "getcap", "/usr/bin/caddy")
    control = docker_run("--entrypoint", "getcap", IMAGEN_CADDY_OFICIAL, "/usr/bin/caddy")
    negativo(f"g) /usr/bin/caddy sin file capability ({r.out.strip()!r})",
             r.rc == 0 and r.out.strip() == "", CAP_OFICIAL in control.out, f"control: {control.out.strip()!r}")
    r = exec_("caddy", "stat", "-c", "%u %g %a", "/data/caddy")
    pasa(r.out.strip() == "10002 10002 700", f"g) /data/caddy: dueno, grupo y modo = {r.out.strip()!r}")
    control = exec_("caddy", "sh", "-c", "touch /data/caddy/prueba_escritura && rm /data/caddy/prueba_escritura")
    r = exec_("caddy", "touch", "/config/caddy/prueba_escritura")
    negativo("g) /config no es escribible", r.rc != 0, control.rc == 0, f"control /data: {control.err.strip()!r}")

    # Montajes: solo el volumen caddy_datos en /data, sin volúmenes anónimos ni tmpfs.
    def montajes(cid):
        i = inspeccionar(cid)
        lista = [(m["Type"], m.get("Name", ""), m["Destination"]) for m in i["Mounts"]]
        return lista, i["HostConfig"].get("Tmpfs")

    control_cid = ejecutar(["docker", "run", "-d", "--name", f"{PROYECTO}_control_volumen",
                            "--mount", "type=volume,dst=/config", "--entrypoint", "sleep",
                            IMAGEN_PROXY, "60"]).out.strip()
    try:
        lista_control = montajes(control_cid)[0] if control_cid else []
    finally:
        ejecutar(["docker", "rm", "-f", "-v", f"{PROYECTO}_control_volumen"])
    control = any(t == "volume" and d == "/config" and len(n) == 64 for t, n, d in lista_control)
    lista, tmpfs = montajes(contenedor("caddy"))
    negativo(f"g) caddy: Mounts = {lista}, Tmpfs = {tmpfs}",
             lista == [("volume", f"{PROYECTO}_caddy_datos", "/data")] and not tmpfs,
             control, f"control con volumen anonimo: {lista_control}")
    lista, tmpfs = montajes(contenedor("api"))
    pasa(sorted(lista) == MONTAJES_API and not tmpfs,
         f"g) api: solo sus secretos montados ({sorted(lista)}, Tmpfs = {tmpfs})")

    # Logs de arranque: sin autosave ni HTTP/3. Control: Caddy sin persist_config
    # off y con protocolos por defecto los registra.
    (TEMPORAL / "control_autosave").mkdir()
    (TEMPORAL / "control_autosave" / "Caddyfile").write_text(CADDYFILE_CONTROL_AUTOSAVE, encoding="utf-8", newline="\n")
    nombre = f"{PROYECTO}_control_autosave"
    ejecutar(["docker", "run", "-d", "--name", nombre, "--read-only", "--cap-drop", "ALL",
              "--security-opt", "no-new-privileges:true", "--mount", "type=volume,dst=/data",
              "--mount", f"type=bind,src={TEMPORAL / 'control_autosave' / 'Caddyfile'},dst=/etc/caddy/Caddyfile,readonly",
              IMAGEN_PROXY])
    try:
        time.sleep(5)
        control_log = ejecutar(["docker", "logs", nombre]).todo
    finally:
        ejecutar(["docker", "rm", "-f", "-v", nombre])
    log = dc("logs", "--no-color", "caddy").todo
    negativo("g) el log de caddy no contiene 'autosave'", "autosave" not in log.lower(),
             TEXTO_AUTOSAVE in control_log, "control sin persist_config off")
    negativo("g) el log de caddy no contiene el listener HTTP/3", TEXTO_HTTP3 not in log,
             TEXTO_HTTP3 in control_log, "control con protocolos por defecto")


def seccion_h():
    p("=== h) healthcheck")
    salud = inspeccionar(contenedor("api"), "{{json .State.Health.Status}}")
    pasa(salud == "healthy", f"h) la API esta healthy ({salud})")
    (TEMPORAL / "salud_rota.py").write_text(SALUD_ROTA, encoding="utf-8", newline="\n")
    r = docker_run("--network", "none", "--read-only", "--cap-drop", "ALL",
                   "--mount", f"type=bind,src={TEMPORAL},dst=/prueba,readonly",
                   "--entrypoint", "python", IMAGEN_API, "-I", "/prueba/salud_rota.py")
    try:
        res = json.loads(r.out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        sinc(f"h) no se pudo ejecutar el healthcheck aislado: {r.err.strip()[-300:]!r}")
        return
    control = res.get("correcto") == 0
    for caso in ("otro_cuerpo", "cuerpo_largo", "codigo_500", "cerrado"):
        negativo(f"h) healthcheck con {caso} sale con 1 ({res.get(caso)})", res.get(caso) == 1, control,
                 f"correcto = {res.get('correcto')}")


def seccion_i():
    p("=== i) la IP del cliente no queda en logs ni en el volumen")
    (TEMPORAL / "cliente.py").write_text(CLIENTE, encoding="utf-8", newline="\n")
    # Control: un Caddy temporal CON la directiva log deja la IP en su log.
    (TEMPORAL / "control_log").mkdir()
    (TEMPORAL / "control_log" / "Caddyfile").write_text(CADDYFILE_CONTROL_LOG, encoding="utf-8", newline="\n")
    nombre = f"{PROYECTO}_control_log"
    ejecutar(["docker", "run", "-d", "--name", nombre, "--network", f"{PROYECTO}_edge",
              "--mount", "type=volume,dst=/data",
              "--mount", f"type=bind,src={TEMPORAL / 'control_log' / 'Caddyfile'},dst=/etc/caddy/Caddyfile,readonly",
              IMAGEN_PROXY])
    try:
        time.sleep(3)
        res_control = cliente_red(f"{PROYECTO}_edge", IP_CLIENTE, "control", nombre)
        time.sleep(2)
        log_control = ejecutar(["docker", "logs", nombre]).todo
    finally:
        ejecutar(["docker", "rm", "-f", "-v", nombre])
    control = bool(res_control) and res_control.get("salud200") == 5 and IP_CLIENTE in log_control

    # La ráfaga mezcla peticiones válidas, rutas inexistentes, Host distinto del
    # SNI, HTTP en claro contra el puerto TLS y handshakes sin certificado o sin
    # SNI, para provocar también los logs de error. El control es que las 20
    # peticiones válidas llegan; el resto de contadores solo se informa (los
    # códigos se prueban en f).
    res = cliente_red(f"{PROYECTO}_edge", IP_CLIENTE, "rafaga", "caddy")
    rafaga_ok = bool(res) and res.get("salud200") == 20
    p(f"   rafaga: {res}")
    if not rafaga_ok:
        sinc("i) control: las 20 peticiones validas de la rafaga no llegaron")
    # Un SNI sin certificado (3) o sin SNI (3) no completa el TLS: solo hay
    # certificado para localhost. Control: las 20 peticiones con SNI
    # localhost sí llegan.
    negativo(f"i) un SNI desconocido o ausente no completa el TLS ({res.get('tls_fallido') if res else None} de 6)",
             bool(res) and res.get("tls_fallido") == 6, rafaga_ok)
    time.sleep(3)
    log = dc("logs", "--no-color", "caddy", "api").todo
    negativo(f"i) {IP_CLIENTE} no aparece en los logs de caddy ni de api", IP_CLIENTE not in log,
             control and rafaga_ok, f"control con directiva log: {res_control}, IP en su log: {IP_CLIENTE in log_control}")
    # Control propio: el Caddy con directiva log también debe dejar el valor
    # falso en su log. Si no lo deja, esta prueba no demostraría nada.
    negativo(f"i) {IP_FALSA} (X-Forwarded-For falso) no aparece en los logs", IP_FALSA not in log,
             control and rafaga_ok and IP_FALSA in log_control,
             f"control con directiva log: {IP_FALSA} en su log: {IP_FALSA in log_control}")
    # Volumen de Caddy. Control: el mismo grep encuentra la IP en un fichero plantado.
    r = exec_("caddy", "grep", "-r", "-l", "-F", IP_CLIENTE, "/data")
    plantado = docker_run("--entrypoint", "sh", IMAGEN_PROXY, "-c",
                          f"mkdir -p /tmp/v && echo {IP_CLIENTE} > /tmp/v/x && grep -r -l -F {IP_CLIENTE} /tmp/v")
    negativo(f"i) {IP_CLIENTE} no aparece en el volumen de caddy (grep codigo {r.rc})", r.rc == 1,
             plantado.rc == 0 and rafaga_ok, f"control grep: {plantado.rc}")


def seccion_j():
    p("=== j) X-Forwarded-For y --forwarded-allow-ips (API sustituida por una app de eco)")
    (TEMPORAL / "eco").mkdir()
    (TEMPORAL / "eco" / "eco.py").write_text(ECO, encoding="utf-8", newline="\n")
    override = TEMPORAL / "override.yml"
    override.write_text(
        "services:\n"
        "  api:\n"
        "    entrypoint: [\"uvicorn\", \"eco:aplicacion\", \"--app-dir\", \"/eco\",\n"
        "                 \"--port\", \"8000\", \"--no-access-log\", \"--no-server-header\"]\n"
        "    volumes:\n"
        "      - type: bind\n"
        f"        source: \"{(TEMPORAL / 'eco').as_posix()}\"\n"
        "        target: /eco\n"
        "        read_only: true\n",
        encoding="utf-8", newline="\n")
    r = dc("up", "-d", "--wait", "api", override=override)
    p(f"up con la app de eco -> codigo {r.rc}")
    if r.rc != 0:
        sinc(f"j) no arranca la app de eco: {r.todo.strip()[-400:]!r}")
    else:
        comando = inspeccionar(contenedor("api"), "{{json .Config.Cmd}}")
        pasa(comando == COMANDO_API, f"j) el eco corre con el command del compose ({comando})")
        via_proxy = cliente_red(f"{PROYECTO}_edge", IP_CLIENTE, "eco_proxy", "caddy") or {}
        control = via_proxy.get("codigo") == 200 and via_proxy.get("prueba") == "canario"
        negativo(f"j) via proxy, X-Forwarded-For que llega = {via_proxy.get('xff')!r}",
                 via_proxy.get("xff") == IP_CLIENTE, control, f"respuesta: {via_proxy}")
        negativo(f"j) via proxy, uvicorn ve como cliente {via_proxy.get('cliente')!r}",
                 via_proxy.get("cliente") == IP_CLIENTE, control, f"respuesta: {via_proxy}")
        directo = cliente_red(f"{PROYECTO}_app", IP_DIRECTO, "eco_directo", "api") or {}
        control_directo = control and via_proxy.get("cliente") == IP_CLIENTE and directo.get("prueba") == "canario"
        negativo(f"j) directo a la API con X-Forwarded-For falso, uvicorn ve {directo.get('cliente')!r}",
                 directo.get("cliente") == IP_DIRECTO, control_directo, f"respuesta: {directo}")
    r = dc("up", "-d", "--wait", "api")
    p(f"up de la API real de nuevo -> codigo {r.rc}")
    if r.rc != 0:
        raise Parada("no vuelve a arrancar la API real")
    codigo, _, cuerpo = peticion("GET", "/salud")
    pasa(codigo == 200 and cuerpo == CUERPO_SALUD, f"j) la API real vuelve a responder ({codigo} {cuerpo!r})")


def huella_ca():
    r = exec_("caddy", "sha256sum", RAIZ_CA)
    return r.out.split()[0] if r.rc == 0 and r.out.strip() else ""


# Caddy de control para l): API de administración y servidor de redirección
# por defecto (este en 8080, porque el usuario 10002 no puede usar el 80).
CADDYFILE_CONTROL_ESCUCHA = """{
	http_port 8080
	skip_install_trust
}

https://localhost:8443 {
	tls internal
	respond "ok"
}
"""
# Plazos del Caddyfile en la configuración que carga Caddy (nanosegundos).
PLAZOS_CADDY = {"read_header_timeout": 10_000_000_000, "read_timeout": 30_000_000_000,
                "write_timeout": 30_000_000_000, "idle_timeout": 120_000_000_000}


# Sockets del proceso 1 y tabla TCP del espacio de red. Solo se cuentan los
# sockets del proceso de Caddy: en una red definida por el usuario, el DNS
# embebido de Docker escucha en 127.0.0.11 con un puerto aleatorio dentro del
# mismo espacio de red (comprobado con un contenedor que solo ejecuta cat).
ORDEN_ESCUCHA = ["sh", "-c", "ls -l /proc/1/fd; cat /proc/net/tcp /proc/net/tcp6"]


def puertos_escuchando(texto):
    """Puertos TCP en LISTEN (estado 0A) cuyos sockets son del proceso 1."""
    inodos = set(re.findall(r"socket:\[(\d+)\]", texto))
    puertos = set()
    for linea in texto.splitlines():
        partes = linea.split()
        if len(partes) > 9 and partes[3] == "0A" and ":" in partes[1] and partes[9] in inodos:
            puertos.add(int(partes[1].rsplit(":", 1)[1], 16))
    return puertos


def seccion_l():
    p("=== l) Caddy: que escucha, cabeceras lentas y plazos")
    # Sin API de administración (2019) ni servidor de redirección: solo 8443
    # (la API), 8444 (el sitio del denunciante) y 8445 (la SPA del personal).
    # Control: un Caddy con los valores por defecto escucha también en 2019 y
    # en su puerto HTTP.
    (TEMPORAL / "control_escucha").mkdir()
    (TEMPORAL / "control_escucha" / "Caddyfile").write_text(CADDYFILE_CONTROL_ESCUCHA, encoding="utf-8", newline="\n")
    nombre = f"{PROYECTO}_control_escucha"
    ejecutar(["docker", "run", "-d", "--name", nombre,
              "--mount", f"type=bind,src={TEMPORAL / 'control_escucha' / 'Caddyfile'},dst=/etc/caddy/Caddyfile,readonly",
              IMAGEN_PROXY])
    try:
        time.sleep(4)
        control = puertos_escuchando(ejecutar(["docker", "exec", nombre, *ORDEN_ESCUCHA]).out)
    finally:
        ejecutar(["docker", "rm", "-f", nombre])
    real = puertos_escuchando(exec_("caddy", *ORDEN_ESCUCHA).out)
    negativo(f"l) Caddy solo escucha en 8443, 8444 y 8445: sin API de administracion (2019) ni redireccion HTTP "
             f"({sorted(real)})", real == {8443, 8444, 8445}, {2019, 8080, 8443} <= control, f"control: {sorted(control)}")

    # read_header: cabeceras a medias más de 10 s se cortan. Control: con 2 s
    # de pausa la petición llega.
    corta = cliente_red(f"{PROYECTO}_edge", IP_CLIENTE, "cabecera_lenta_2", "caddy") or {}
    larga = cliente_red(f"{PROYECTO}_edge", IP_CLIENTE, "cabecera_lenta_15", "caddy") or {}
    p(f"   cabeceras lentas: 2 s -> {corta}; 15 s -> {larga}")
    negativo("l) unas cabeceras paradas mas de read_header (10 s) no llegan a la API",
             larga.get("estado") != 200, corta.get("estado") == 200, f"control: {corta}")

    # write e idle no se prueban por comportamiento (exigirían respuestas de
    # más de 30 s o esperas de 2 minutos): se comprueba la configuración que
    # Caddy carga de verdad (caddy adapt del Caddyfile de la imagen).
    r = exec_("caddy", "caddy", "adapt", "--config", "/etc/caddy/Caddyfile")
    try:
        servidores = json.loads(r.out)["apps"]["http"]["servers"]
    except (ValueError, KeyError):
        sinc(f"l) no se pudo leer la configuracion efectiva de Caddy: {r.err.strip()[-200:]!r}")
        return
    reales = {n: {k: s.get(k) for k in PLAZOS_CADDY} for n, s in servidores.items()}
    pasa(bool(reales) and all(v == PLAZOS_CADDY for v in reales.values()),
         f"l) configuracion efectiva: read_header 10s, read_body 30s, write 30s e idle 2m en todos los servidores ({reales})")


# m) Caddy funciona sin internet. Nombres propios (con el prefijo del
# proyecto, así s) detecta cualquier resto) y cliente que valida el TLS contra
# la raíz que el propio Caddy acaba de crear en su volumen vacío.
RED_SIN_INTERNET = f"{PROYECTO}_sin_internet"
VOLUMEN_SIN_INTERNET = f"{PROYECTO}_datos_sin_internet"
CADDY_SIN_INTERNET = f"{PROYECTO}_caddy_sin_internet"
API_FALSA = f"{PROYECTO}_api_falsa"
# Términos que delatarían que Caddy intenta salir: ACME, OCSP o una conexión
# saliente fallida ("dial"). Comprobado: el log de Caddy en una red interna
# no contiene ninguno (solo el aviso de la API de administración desactivada).
TERMINOS_SALIDA = ("acme", "ocsp", "dial")
CLIENTE_TLS_VALIDADO = r'''
import http.client, json, socket, ssl
contexto = ssl.create_default_context(cafile="/prueba/raiz_sin_internet.crt")
s = contexto.wrap_socket(socket.create_connection(("proxy", 8443), timeout=10), server_hostname="localhost")
c = http.client.HTTPConnection("localhost", 8443, timeout=10)
c.sock = s
c.request("GET", "/salud", headers={"Host": "localhost:8443"})
r = c.getresponse()
print(json.dumps({"estado": r.status, "cuerpo": r.read().decode("latin-1")}))
'''


def seccion_m():
    p("=== m) Caddy funciona sin internet (red interna, volumen vacio)")
    # Precondición: la red interna de verdad no tiene salida, y desde una red
    # normal sí la hay (si no, no se puede concluir nada sobre "sin internet").
    r = ejecutar(["docker", "network", "create", "--internal", RED_SIN_INTERNET])
    if r.rc != 0:
        raise Parada(f"no se pudo crear la red interna de m): {r.err.strip()[:200]}")
    control = docker_run("--network", "bridge", "--entrypoint", "python", IMAGEN_API, "-c", PRUEBA_SALIDA)
    sin_salida = docker_run("--network", RED_SIN_INTERNET, "--entrypoint", "python", IMAGEN_API, "-c", PRUEBA_SALIDA)
    p(f"   salida a 1.1.1.1:443: red interna -> {sin_salida.out.strip()!r}; red bridge -> {control.out.strip()!r}")
    if control.out.strip() != "CONECTA" or not sin_salida.out.startswith("SIN_SALIDA"):
        sinc("m) la red de la prueba no es una red sin internet comprobada (control: bridge CONECTA, interna "
             "SIN_SALIDA): no se puede concluir")
        return

    # API falsa con el alias api: sirve /salud desde un fichero, sin la API real.
    (TEMPORAL / "api_falsa").mkdir()
    (TEMPORAL / "api_falsa" / "salud").write_bytes(CUERPO_SALUD)
    (TEMPORAL / "cliente_tls.py").write_text(CLIENTE_TLS_VALIDADO, encoding="utf-8", newline="\n")
    ejecutar(["docker", "run", "-d", "--name", API_FALSA, "--network", RED_SIN_INTERNET, "--network-alias", "api",
              "--mount", f"type=bind,src={TEMPORAL / 'api_falsa'},dst=/web,readonly",
              "--entrypoint", "python", IMAGEN_API, "-m", "http.server", "8000", "--directory", "/web"])
    # La imagen construida del proyecto con el mismo endurecimiento que el
    # compose y un volumen nuevo, vacío: tiene que crear su CA sin red.
    ejecutar(["docker", "volume", "create", VOLUMEN_SIN_INTERNET])
    ejecutar(["docker", "run", "-d", "--name", CADDY_SIN_INTERNET, "--network", RED_SIN_INTERNET,
              "--network-alias", "proxy", "--read-only", "--cap-drop", "ALL",
              "--security-opt", "no-new-privileges:true",
              "--mount", f"type=volume,src={VOLUMEN_SIN_INTERNET},dst=/data", IMAGEN_PROXY])
    raiz = TEMPORAL / "raiz_sin_internet.crt"
    copiada = esperar_raiz(raiz)
    respuesta = {}
    if copiada:
        r = docker_run("--network", RED_SIN_INTERNET,
                       "--mount", f"type=bind,src={TEMPORAL},dst=/prueba,readonly",
                       "--entrypoint", "python", IMAGEN_API, "-I", "/prueba/cliente_tls.py")
        try:
            respuesta = json.loads(r.out.strip().splitlines()[-1])
        except (ValueError, IndexError):
            p(f"   cliente TLS: codigo {r.rc} {r.err.strip()[-300:]!r}")
    pasa(copiada and respuesta == {"estado": 200, "cuerpo": CUERPO_SALUD.decode("latin-1")},
         f"m) sin internet y con el volumen vacio, Caddy crea su CA y sirve /salud con TLS validado contra esa "
         f"raiz y SNI localhost ({respuesta})")
    registro = ejecutar(["docker", "logs", CADDY_SIN_INTERNET]).todo
    delatoras = [l for l in registro.splitlines() if any(t in l.lower() for t in TERMINOS_SALIDA)]
    pasa(bool(registro.strip()) and not delatoras,
         f"m) el log de Caddy no menciona {', '.join(TERMINOS_SALIDA)} ({len(delatoras)} lineas)")
    for l in delatoras[:5]:
        p(f"   {l[:300]}")


def esperar_raiz(destino, maximo=30):
    """Copia la raíz del CA del Caddy de m) en cuanto existe."""
    limite = time.monotonic() + maximo
    while time.monotonic() < limite:
        if ejecutar(["docker", "cp", f"{CADDY_SIN_INTERNET}:{RAIZ_CA}", str(destino)]).rc == 0 and destino.is_file():
            # Un margen para que el servidor TLS termine de arrancar tras crear el CA.
            time.sleep(2)
            return True
        time.sleep(1)
    return False


def limpiar_sin_internet():
    for nombre in (CADDY_SIN_INTERNET, API_FALSA):
        ejecutar(["docker", "rm", "-f", "-v", nombre])
    ejecutar(["docker", "volume", "rm", VOLUMEN_SIN_INTERNET])
    ejecutar(["docker", "network", "rm", RED_SIN_INTERNET])


def seccion_k():
    p("=== k) el CA de Caddy sobrevive a reinicios")
    inicial = huella_ca()
    pasa(len(inicial) == 64, f"k) huella inicial del CA: {inicial[:16]}...")
    r = dc("restart", "caddy")
    tras_restart = huella_ca()
    pasa(r.rc == 0 and tras_restart == inicial, f"k) igual tras restart ({tras_restart[:16]}...)")
    dc("down")
    r = dc("up", "-d", "--wait", "api", "caddy")
    tras_down = huella_ca()
    pasa(r.rc == 0 and tras_down == inicial, f"k) igual tras down (sin -v) y up ({tras_down[:16]}...)")
    # Control: con el volumen borrado el CA cambia, así que la comparación detecta un CA nuevo.
    dc("down", "-v")
    r = dc("up", "-d", "--wait", "api", "caddy")
    nuevo = huella_ca()
    if r.rc != 0 or len(nuevo) != 64 or nuevo == inicial:
        sinc(f"k) control: tras down -v el CA deberia ser otro ({nuevo[:16]}...)")
    else:
        pasa(True, f"k) control: tras down -v el CA es otro ({nuevo[:16]}...)")


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


def terminar():
    if estado["falla"] or estado["sin_conclusion"]:
        resultado = "NO OK (hay FALLA o SIN CONCLUSION)"
    else:
        resultado = "OK"
    p("RESULTADO GLOBAL: " + resultado)
    SALIDA.write_text("\n".join(lineas_salida) + "\n", encoding="utf-8", newline="\n")
    sys.exit(0 if resultado == "OK" else 1)


def estado_git():
    """Líneas de "git status --short -uall", o None si git no está disponible o falla."""
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


def subredes_ocupadas():
    """Redes ajenas que ya usan alguna de las subredes fijas del esqueleto."""
    ocupadas = []
    for red in ejecutar(["docker", "network", "ls", "-q"]).out.split():
        r = ejecutar(["docker", "network", "inspect", "--format",
                      "{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}", red])
        partes = r.out.split()
        if partes and set(partes[1:]) & {SUBRED_APP, SUBRED_EDGE}:
            ocupadas.append(partes[0])
    return ocupadas


def puertos_ocupados():
    ocupados = []
    for puerto in (PUERTO, PUERTO_DENUNCIANTE, PUERTO_SPA):
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
    # Precondiciones: si fallan, no se limpia nada (podrian ser recursos ajenos).
    if ejecutar(["docker", "info", "--format", "{{.ServerVersion}}"]).rc != 0:
        p("PARADA: docker info falla")
        terminar_con_parada()
    previos = recursos_previos()
    if previos:
        p(f"PARADA: ya existen recursos con prefijo {PROYECTO}: {previos}")
        terminar_con_parada()
    ocupadas = subredes_ocupadas()
    if ocupadas:
        p(f"PARADA: las subredes {SUBRED_APP} o {SUBRED_EDGE} ya estan en uso por {ocupadas} (pare el proyecto canario)")
        terminar_con_parada()
    ocupados = puertos_ocupados()
    if ocupados:
        p(f"PARADA: 127.0.0.1:{ocupados} ya esta en uso (pare el proyecto canario)")
        terminar_con_parada()
    r = dc("config", "--quiet")
    if r.rc != 0:
        p(f"PARADA: docker compose config falla (genere los secretos con scripts/generar_secretos.py): {r.err.strip()[:300]}")
        terminar_con_parada()
    if ejecutar(["docker", "image", "inspect", IMAGEN_CADDY_OFICIAL]).rc != 0 and \
            ejecutar(["docker", "pull", IMAGEN_CADDY_OFICIAL]).rc != 0:
        p("PARADA: no se puede obtener la imagen oficial de Caddy para los controles")
        terminar_con_parada()
    TEMPORAL = pathlib.Path(tempfile.mkdtemp(prefix="canario_esqueleto_"))
    parada = None
    try:
        seccion_a()
        for seccion in (seccion_b, seccion_c, seccion_d, seccion_e, seccion_o, seccion_f, seccion_n, seccion_g,
                        seccion_h, seccion_i, seccion_j, seccion_k, seccion_l, seccion_m):
            seccion()
    except Parada as e:
        parada = str(e)
        p(f"PARADA: {parada}")
    except Exception:  # noqa: BLE001 - error inesperado del propio test: se informa y se limpia
        parada = "error inesperado en el test"
        p("ERROR INESPERADO:\n" + traceback.format_exc())
    finally:
        for nombre in ("cliente", "control_volumen", "control_autosave", "control_log", "control_rangos"):
            ejecutar(["docker", "rm", "-f", "-v", f"{PROYECTO}_{nombre}"])
        limpiar_sin_internet()
        if parada is not None:
            dc("down", "-v", "--rmi", "local")
        else:
            seccion_s()
        shutil.rmtree(TEMPORAL, ignore_errors=True)
    if parada is not None:
        estado["falla"] = True
    terminar()


def terminar_con_parada():
    p("RESULTADO GLOBAL: NO OK (PARADA)")
    SALIDA.write_text("\n".join(lineas_salida) + "\n", encoding="utf-8", newline="\n")
    sys.exit(1)


if __name__ == "__main__":
    main()
