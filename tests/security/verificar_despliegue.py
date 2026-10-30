#!/usr/bin/env python3
"""Batería de pruebas de seguridad del despliegue de producción: Canario
detrás del Traefik de Dokploy (compose.produccion.yaml,
proxy/Caddyfile.produccion y despliegue/traefik/canario.yml; docs/operacion.md
y docs/threat-model.md).

La pila con el compose de producción encima del de siempre y, delante, un
Traefik de la misma versión que el de Dokploy cargando el mismo
despliegue/traefik/canario.yml que se copia al VPS. Los clientes son
contenedores con IP fija en una red propia, como los navegadores de internet
frente al Traefik real. Prueba:

* a) arranque: el compose de producción sin construir nada (las imágenes se
  construyen antes con el compose de siempre, como en el PC), Caddy con el
  Caddyfile de producción, sin puertos publicados y la red edge interna;
* b) el enrutado por Traefik: cada nombre llega a su sitio por HTTPS, con una
  sola cabecera HSTS (la de Caddy), y HTTP redirige a HTTPS (301 a un GET,
  308 a un POST, que conserva el método);
* c) la IP del cliente a través de Traefik: un cliente agota su límite y otro
  no se ve afectado (las IP se distinguen), y el primero no se libra
  falsificando X-Forwarded-For (ni con una IP inventada ni con la del otro);
* d) que Caddy solo atiende a Traefik: lo que llega a Caddy por otra IP de la
  red edge recibe 403 en cada tipo de ruta (API, estáticos, páginas del
  denunciante, la SPA y la API del personal), y un Host ajeno, 421;
* e) los orígenes de producción: la API del personal acepta el de
  canario-personal y rechaza el de localhost, el de otra aplicación del mismo
  dominio (same-site) y un Sec-Fetch-Site same-site; los formularios del
  denunciante aceptan el de canario y rechazan el de localhost.

Lo que no prueba: el Traefik real del VPS, Let's Encrypt (aquí el resolver no
tiene salida y Traefik sirve su certificado por defecto) ni la persistencia de
la conexión de Traefik a la red edge cuando Dokploy lo recrea. Eso se
comprueba en el VPS con las órdenes de docs/operacion.md.

Cada prueba negativa lleva su control positivo: si el control falla, el
resultado es SIN CONCLUSION, nunca PASA. Los oráculos son literales.

Cómo se ejecuta (desde la raíz del repositorio, en PowerShell, con Docker en
marcha y los secretos generados con scripts/generar_secretos.py):

    python tests/security/verificar_despliegue.py

Usa un proyecto de Docker propio (canario_despliegue). Necesita que el
proyecto canario y las demás baterías estén parados: las subredes
10.88.0.0/28, 10.88.1.0/28, 10.88.2.0/28 y la de los clientes, 10.88.3.0/28,
son fijas (si están en uso, PARADA). Al terminar lo borra todo (down -v y las
imágenes construidas). No lee ningún secreto. Los ficheros auxiliares van a un
directorio temporal del sistema, nunca al repositorio. La salida completa se
guarda en verificacion_despliegue.txt dentro del directorio temporal del
sistema. El código de salida es 0 solo si el resultado global es OK.

Solo usa la biblioteca estándar.
"""
import base64
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import traceback

RAIZ = pathlib.Path.cwd()
PROYECTO = "canario_despliegue"
SALIDA = pathlib.Path(tempfile.gettempdir()) / "verificacion_despliegue.txt"
# El compose de siempre, con el que se construyen las imágenes (como en el PC).
BASE = ["docker", "compose", "-p", PROYECTO, "-f", "docker-compose.yml"]
# El de producción encima, más el de la prueba (se añade en a).
PRODUCCION = BASE + ["-f", "compose.produccion.yaml"]

lineas_salida = []
estado = {"falla": False, "sin_conclusion": False}

# ---------------------------------------------------------------------------
# Oráculos literales
# ---------------------------------------------------------------------------
SERVICIOS_CONSTRUIDOS = ("postgres", "api", "broker", "caddy")
SUBREDES = ("10.88.0.0/28", "10.88.1.0/28", "10.88.2.0/28", "10.88.3.0/28")
# La misma versión que el Traefik de Dokploy v0.30.10 (TRAEFIK_VERSION en
# packages/server/src/setup/traefik-setup.ts), fijada por digest (índice
# multiarquitectura). Si el VPS lleva otra, se cambia aquí.
IMG_TRAEFIK = "traefik:v3.6.25@sha256:31267173a15b4944e797a76ffd9c419707c8d8b32fe5b610f80cd0cfa05f372d"
IP_TRAEFIK_EDGE = "10.88.1.2"      # la única en la que confía Caddy
IP_TRAEFIK_PUBLICA = "10.88.3.2"
IP_CLIENTE = "10.88.3.3"           # cliente de b) y e)
IP_CLIENTE_A = "10.88.3.5"         # c): agota su límite
IP_CLIENTE_B = "10.88.3.6"         # c): no debe verse afectado
IP_INTRUSO_EDGE = "10.88.1.3"      # d): en la red edge, pero no es Traefik
PUERTO_WEB_TRAEFIK = 8000          # entrypoint web de la prueba (80 en Dokploy)
PUERTO_TLS_TRAEFIK = 8443          # entrypoint websecure de la prueba (443 en Dokploy)
PUERTO_CADDY = 8080
HOST_API = "canario-api.eduumr.dev"
HOST_WEB = "canario.eduumr.dev"
HOST_SPA = "canario-personal.eduumr.dev"
ORIGEN_SPA = "https://canario-personal.eduumr.dev"
ORIGEN_WEB = "https://canario.eduumr.dev"
ORIGEN_SPA_LOCAL = "https://localhost:8445"
ORIGEN_WEB_LOCAL = "https://localhost:8444"
ORIGEN_HERMANO = "https://titoenglish.eduumr.dev"
CADDYFILE_PRODUCCION = "/etc/caddy/Caddyfile.produccion"
# El límite de "acceso" de la prueba: 3 logins por cliente. El resto, altos.
LIMITE_ACCESO = 3
LIMITES_PRUEBA = (f"denuncia=1000/3600,seguimiento=1000/60,mensajes=1000/3600,acceso={LIMITE_ACCESO}/300,"
                  "otras=1000/60,cuenta=1000/60,registro=1000/3600,destinatario=1000/900,destinatario_dia=1000/86400")
HSTS = "max-age=63072000"
RUTA_CSS = "/estatico/canario.css"
CUERPO_SALUD = b'{"estado":"ok"}'
CUERPO_403_API = b'{"detalle": "permiso denegado"}'
CUERPO_403_CADDY = '{"detalle": "petición no válida"}'.encode()
CUERPO_421 = '{"detalle": "host no válido"}'.encode()
# Un login con la forma correcta y datos que no existen: 401 si pasa todo lo
# demás (app/rutas_personal.py, Login).
LOGIN_FALSO = json.dumps({"empresa": "0" * 32, "email": "nadie@despliegue.test", "contrasena": "x" * 12,
                          "codigo_totp": "000000"})

# Cliente que se ejecuta en un contenedor: hace las peticiones que recibe en
# JSON y devuelve, por cada una, el estado, las cabeceras y el cuerpo.
CLIENTE = r'''
import base64, http.client, json, ssl, sys
contexto = ssl.create_default_context()
# El Traefik de la prueba sirve su certificado por defecto: lo que se prueba
# es el enrutado y las cabeceras, no la cadena (eso es Let's Encrypt en el VPS).
contexto.check_hostname = False
contexto.verify_mode = ssl.CERT_NONE
res = {}
for pet in json.loads(sys.argv[1]):
    try:
        if pet["tls"]:
            c = http.client.HTTPSConnection(pet["destino"], pet["puerto"], timeout=15, context=contexto)
        else:
            c = http.client.HTTPConnection(pet["destino"], pet["puerto"], timeout=15)
        c.putrequest(pet["metodo"], pet["ruta"], skip_host=True, skip_accept_encoding=True)
        c.putheader("Host", pet["host"])
        cuerpo = pet["cuerpo"].encode() if pet["cuerpo"] is not None else None
        for k, v in pet["cabeceras"].items():
            c.putheader(k, v)
        if cuerpo is not None:
            c.putheader("Content-Length", str(len(cuerpo)))
        c.endheaders(cuerpo)
        r = c.getresponse()
        res[pet["id"]] = [r.status, r.getheaders(), base64.b64encode(r.read()).decode()]
    except Exception as e:
        res[pet["id"]] = [0, [], base64.b64encode(repr(e).encode()).decode()]
print(json.dumps(res))
'''

# El compose de la prueba, encima del de producción: las imágenes de este
# proyecto, los límites de la prueba, el Traefik y la red de los clientes.
COMPOSE_PRUEBA = f"""services:
  postgres:
    image: {PROYECTO}-postgres
  api:
    image: {PROYECTO}-api
    environment:
      CANARIO_LIMITES: "{LIMITES_PRUEBA}"
  broker:
    image: {PROYECTO}-broker
  caddy:
    image: {PROYECTO}-caddy
  traefik:
    image: {IMG_TRAEFIK}
    user: "65534:65534"
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp
    depends_on:
      caddy:
        condition: service_started
    command:
      - --global.checknewversion=false
      - --global.sendanonymoususage=false
      - --entrypoints.web.address=:{PUERTO_WEB_TRAEFIK}
      - --entrypoints.websecure.address=:{PUERTO_TLS_TRAEFIK}
      - --providers.file.filename=/conf/canario.yml
      # El mismo nombre de resolver que en Dokploy. Sin salida: no consigue
      # certificado y Traefik sirve el suyo por defecto.
      - --certificatesresolvers.letsencrypt.acme.tlschallenge=true
      - --certificatesresolvers.letsencrypt.acme.caserver=https://acme.canario.invalid/directory
      - --certificatesresolvers.letsencrypt.acme.email=pruebas@canario.invalid
      - --certificatesresolvers.letsencrypt.acme.storage=/tmp/acme.json
    volumes:
      - type: bind
        # Entre comillas: la ruta del proyecto puede llevar espacios.
        source: {json.dumps((RAIZ / "despliegue" / "traefik" / "canario.yml").as_posix())}
        target: /conf/canario.yml
        read_only: true
    networks:
      edge:
        ipv4_address: {IP_TRAEFIK_EDGE}
      publica:
        ipv4_address: {IP_TRAEFIK_PUBLICA}

networks:
  publica:
    internal: true
    ipam:
      config:
        - subnet: 10.88.3.0/28
          ip_range: 10.88.3.8/29
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


def ejecutar(args, timeout=900, entrada=None):
    # check=False explícito: el código de salida se comprueba en cada llamada.
    r = subprocess.run(args, capture_output=True, timeout=timeout, check=False, input=entrada)
    return R(r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace"))


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


TEMPORAL = None


def pet(ident, host, ruta, metodo="GET", cabeceras=None, cuerpo=None, tls=True, destino=None, puerto=None):
    """Una petición para el cliente. Por defecto, por HTTPS al Traefik."""
    return {"id": ident, "host": host, "ruta": ruta, "metodo": metodo, "cabeceras": cabeceras or {},
            "cuerpo": cuerpo, "tls": tls,
            "destino": destino or (host if tls else "traefik"),
            "puerto": puerto or (PUERTO_TLS_TRAEFIK if tls else PUERTO_WEB_TRAEFIK)}


def cliente(peticiones, red, ip):
    """Ejecuta las peticiones desde un contenedor con IP fija en esa red, en
    orden, y devuelve {id: (estado, cabeceras, cuerpo)}."""
    # Los nombres de producción apuntan al Traefik de la prueba, como el DNS
    # real apunta al VPS.
    hosts = [x for h in (HOST_API, HOST_WEB, HOST_SPA) for x in ("--add-host", f"{h}:{IP_TRAEFIK_PUBLICA}")]
    hosts += ["--add-host", f"traefik:{IP_TRAEFIK_PUBLICA}"]
    r = ejecutar(["docker", "run", "--rm", "--network", f"{PROYECTO}_{red}", "--ip", ip, *hosts,
                  "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "65534:65534",
                  "--mount", f"type=bind,src={TEMPORAL},dst=/prueba,readonly",
                  "--entrypoint", "python", f"{PROYECTO}-api", "-I", "/prueba/cliente.py", json.dumps(peticiones)],
                 timeout=300)
    try:
        crudo = json.loads(r.out)
    except ValueError:
        raise Parada(f"el cliente no devuelve JSON: {r.todo.strip()[-300:]}") from None
    return {k: (v[0], v[1], base64.b64decode(v[2])) for k, v in crudo.items()}


def cabecera(respuesta, nombre):
    """Todos los valores de una cabecera, en minúsculas el nombre."""
    return [v for k, v in respuesta[1] if k.lower() == nombre]


# ---------------------------------------------------------------------------
# Secciones
# ---------------------------------------------------------------------------
def seccion_a():
    p("=== a) arranque con el compose de produccion y un Traefik delante")
    r = ejecutar(BASE + ["build", *SERVICIOS_CONSTRUIDOS], timeout=1800)
    p(f"build {' '.join(SERVICIOS_CONSTRUIDOS)} (compose de siempre) -> codigo {r.rc}")
    if r.rc != 0:
        p(r.todo.strip()[-1500:])
        raise Parada("no se construyen las imagenes")
    prueba = TEMPORAL / "compose.prueba.yaml"
    prueba.write_text(COMPOSE_PRUEBA, encoding="utf-8", newline="\n")
    (TEMPORAL / "cliente.py").write_text(CLIENTE, encoding="utf-8", newline="\n")
    PRODUCCION.extend(["-f", str(prueba)])
    # Sin --build: el compose de producción anula build, así que si faltara
    # una imagen "up" fallaría en vez de construirla.
    r = ejecutar(PRODUCCION + ["up", "-d", "--wait", "api", "caddy", "traefik"], timeout=600)
    p(f"up -d --wait api caddy traefik (compose de produccion) -> codigo {r.rc}")
    if r.rc != 0:
        p(r.todo.strip()[-1500:])
        raise Parada("no arranca la pila de produccion")

    caddy = f"{PROYECTO}-caddy-1"
    orden = json.loads(ejecutar(["docker", "inspect", "--format", "{{json .Config.Cmd}}", caddy]).out or "null")
    pasa(orden == ["caddy", "run", "--config", CADDYFILE_PRODUCCION, "--adapter", "caddyfile"],
         f"a) Caddy carga {CADDYFILE_PRODUCCION}: {orden}")
    puertos = ejecutar(["docker", "port", caddy]).out.strip()
    pasa(puertos == "", f"a) Caddy sin puertos publicados en el anfitrion {puertos!r}")
    interna = ejecutar(["docker", "network", "inspect", "--format", "{{.Internal}}", f"{PROYECTO}_edge"]).out.strip()
    pasa(interna == "true", f"a) la red edge es interna (Caddy sin salida a internet): {interna}")

    # Traefik carga el fichero dinámico al arrancar; se espera a que enrute.
    for _ in range(30):
        res = cliente([pet("salud", HOST_API, "/salud")], "publica", IP_CLIENTE)
        if res["salud"][0] == 200:
            break
        time.sleep(1)
    else:
        p(ejecutar(PRODUCCION + ["logs", "--no-color", "traefik"]).todo.strip()[-1500:])
        raise Parada(f"Traefik no enruta a Caddy en 30 s (ultimo estado {res['salud'][0]})")


def seccion_b():
    global RUTAS_TRAEFIK_OK
    p("=== b) enrutado por Traefik y cabeceras")
    css = (RAIZ / "proxy" / "estatico" / "canario.css").read_bytes()
    res = cliente([pet("api", HOST_API, "/salud"),
                   pet("css", HOST_WEB, RUTA_CSS),
                   pet("spa", HOST_SPA, "/"),
                   pet("http", HOST_WEB, "/", tls=False),
                   pet("http_post", HOST_WEB, "/seguimiento/consulta", "POST", tls=False, cuerpo="")],
                  "publica", IP_CLIENTE)
    api, estilo, spa, http = res["api"], res["css"], res["spa"], res["http"]
    pasa(api[0] == 200 and api[2] == CUERPO_SALUD, f"b) {HOST_API}/salud -> {api[0]} {api[2][:40]!r}")
    pasa(estilo[0] == 200 and estilo[2] == css, f"b) {HOST_WEB}{RUTA_CSS} -> {estilo[0]}, igual al fichero del repo")
    pasa(spa[0] == 200 and b'<app-root' in spa[2], f"b) {HOST_SPA}/ -> {spa[0]}, la pagina de la SPA")
    RUTAS_TRAEFIK_OK = api[0] == 200 and estilo[0] == 200 and spa[0] == 200
    for nombre, r in (("api", api), ("css", estilo), ("spa", spa)):
        valores = cabecera(r, "strict-transport-security")
        pasa(valores == [HSTS], f"b) {nombre}: una sola Strict-Transport-Security {valores}")
    # Traefik redirige un GET con 301 y cualquier otro método con 308, que
    # conserva el método (pkg/middlewares/redirect/redirect.go de Traefik v3.6).
    ubicacion = cabecera(http, "location")
    pasa(http[0] == 301 and ubicacion == [f"https://{HOST_WEB}/"],
         f"b) GET http://{HOST_WEB}/ -> {http[0]} {ubicacion}")
    post, ubicacion_post = res["http_post"], cabecera(res["http_post"], "location")
    pasa(post[0] == 308 and ubicacion_post == [f"https://{HOST_WEB}/seguimiento/consulta"],
         f"b) POST http://{HOST_WEB}/seguimiento/consulta -> {post[0]} {ubicacion_post}")


RUTAS_TRAEFIK_OK = False


def seccion_c():
    p("=== c) la IP del cliente a traves de Traefik (limitador)")
    login = {"Content-Type": "application/json"}

    def intento(ident, extra=None):
        return pet(ident, HOST_API, "/v1/personal/sesiones", "POST", {**login, **(extra or {})}, LOGIN_FALSO)

    # A agota su límite: los LIMITE_ACCESO primeros dan 401, el siguiente 429.
    res_a = cliente([intento(f"a{i}") for i in range(LIMITE_ACCESO + 1)], "publica", IP_CLIENTE_A)
    estados_a = [res_a[f"a{i}"][0] for i in range(LIMITE_ACCESO + 1)]
    control = estados_a == [401] * LIMITE_ACCESO + [429]
    pasa(control, f"c) control: el cliente A agota su limite de acceso {estados_a}")
    # B, otra IP: si Caddy o uvicorn vieran a todos como Traefik, compartiría
    # el contador de A y daría 429.
    res_b = cliente([intento("b")], "publica", IP_CLIENTE_B)
    negativo(f"c) el cliente B no comparte el contador de A (las IP se distinguen): {res_b['b'][0]}",
             res_b["b"][0] == 401, control, f"A: {estados_a}")
    # A falsifica X-Forwarded-For: si Caddy lo leyera de izquierda a derecha,
    # se haría pasar por otro cliente con el contador a cero.
    res_f = cliente([intento("inventada", {"X-Forwarded-For": "203.0.113.9"}),
                     intento("otra_ip", {"X-Forwarded-For": IP_CLIENTE_B})], "publica", IP_CLIENTE_A)
    for ident, texto in (("inventada", "203.0.113.9"), ("otra_ip", IP_CLIENTE_B)):
        negativo(f"c) A no se libra falsificando X-Forwarded-For: {texto} -> {res_f[ident][0]}",
                 res_f[ident][0] == 429, control and res_b["b"][0] == 401)


def seccion_d():
    p("=== d) Caddy solo atiende a Traefik")
    directo = {"destino": "canario-caddy", "puerto": PUERTO_CADDY, "tls": False}
    rutas = [("api", HOST_API, "/salud"), ("css", HOST_WEB, RUTA_CSS), ("web", HOST_WEB, "/seguimiento"),
             ("spa", HOST_SPA, "/"), ("personal", HOST_SPA, "/v1/personal/yo")]
    res = cliente([{**pet(i, h, r), **directo} for i, h, r in rutas]
                  + [{**pet("ajeno", "otro.canario.invalid", "/"), **directo}], "edge", IP_INTRUSO_EDGE)
    for ident, host, ruta in rutas:
        negativo(f"d) {host}{ruta} desde {IP_INTRUSO_EDGE} (edge, no Traefik) -> {res[ident][0]}",
                 res[ident][0] == 403, RUTAS_TRAEFIK_OK)
    pasa(res["api"][2] == CUERPO_403_CADDY, f"d) el 403 de la API sale con el cuerpo de Caddy {res['api'][2][:60]!r}")
    pasa(cabecera(res["api"], "strict-transport-security") == [HSTS], "d) el 403 lleva las cabeceras del sitio")
    ajeno = res["ajeno"]
    pasa(ajeno[0] == 421 and ajeno[2] == CUERPO_421, f"d) Host ajeno -> {ajeno[0]} {ajeno[2][:40]!r}")


def seccion_e():
    p("=== e) origenes de produccion")
    # La renovación del navegador: con Sec-Fetch-Site pasa por la comprobación
    # de origen antes de buscar la cookie (sin cookie, 401).
    def renovacion(ident, origen, sitio="same-origin"):
        return pet(ident, HOST_SPA, "/v1/personal/sesiones/renovacion", "POST",
                   {"Content-Type": "application/json", "Origin": origen, "Sec-Fetch-Site": sitio}, "{}")

    # La consulta del seguimiento: primero el origen y después el cuerpo
    # (app/rutas_web.py, formulario). Con un código que no existe, el 404 solo
    # sale si el origen y el cuerpo han pasado.
    def formulario(ident, origen):
        return pet(ident, HOST_WEB, "/seguimiento/consulta", "POST",
                   {"Content-Type": "application/x-www-form-urlencoded", "Origin": origen}, "codigo=x")

    res = cliente([renovacion("spa_ok", ORIGEN_SPA), renovacion("spa_local", ORIGEN_SPA_LOCAL),
                   renovacion("spa_hermano", ORIGEN_HERMANO, "same-site"),
                   renovacion("spa_sitio", ORIGEN_SPA, "same-site"),
                   formulario("web_ok", ORIGEN_WEB), formulario("web_local", ORIGEN_WEB_LOCAL)],
                  "publica", IP_CLIENTE)
    control_spa = res["spa_ok"][0] == 401
    pasa(control_spa, f"e) control: Origin {ORIGEN_SPA} pasa la comprobacion de origen -> {res['spa_ok'][0]}")
    for ident, texto in (("spa_local", f"Origin {ORIGEN_SPA_LOCAL}"),
                         ("spa_hermano", f"Origin {ORIGEN_HERMANO} (same-site)"),
                         ("spa_sitio", "Sec-Fetch-Site same-site")):
        negativo(f"e) la API del personal rechaza {texto} -> {res[ident][0]}",
                 res[ident][0] == 403 and res[ident][2] == CUERPO_403_API, control_spa,
                 f"{res[ident][2][:60]!r}")
    control_web = res["web_ok"][0] == 404
    pasa(control_web, f"e) control: el formulario con Origin {ORIGEN_WEB} pasa la comprobacion -> {res['web_ok'][0]}")
    negativo(f"e) el formulario rechaza Origin {ORIGEN_WEB_LOCAL} -> {res['web_local'][0]}",
             res["web_local"][0] == 403, control_web)


def imagenes():
    return [f"{PROYECTO}-{s}" for s in SERVICIOS_CONSTRUIDOS]


def limpiar():
    r = ejecutar(PRODUCCION + ["down", "-v"], timeout=600)
    ejecutar(["docker", "image", "rm", *imagenes()])
    return r


def seccion_s():
    p("=== s) limpieza")
    r = limpiar()
    p(f"down -v y las imagenes construidas -> codigo {r.rc}")
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
                  ["docker", "volume", "ls", "--format", "{{.Name}}"],
                  ["docker", "image", "ls", "--format", "{{.Repository}}"]):
        previos += [n for n in ejecutar(orden).out.split() if n.startswith(PROYECTO)]
    return previos


def subredes_ocupadas():
    """Redes ajenas que ya usan alguna de las subredes fijas."""
    ocupadas = []
    for red in ejecutar(["docker", "network", "ls", "-q"]).out.split():
        r = ejecutar(["docker", "network", "inspect", "--format",
                      "{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}", red])
        partes = r.out.split()
        if partes and set(partes[1:]) & set(SUBREDES):
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
    ocupadas = subredes_ocupadas()
    if ocupadas:
        p(f"PARADA: las subredes {SUBREDES} ya estan en uso por {ocupadas} (pare el proyecto canario)")
        terminar_con_parada()
    r = ejecutar(PRODUCCION + ["config", "--quiet"])
    if r.rc != 0:
        p(f"PARADA: docker compose config falla (genere los secretos con scripts/generar_secretos.py): {r.err.strip()[:300]}")
        terminar_con_parada()
    TEMPORAL = pathlib.Path(tempfile.mkdtemp(prefix="canario_despliegue_"))
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
        if parada is not None:
            limpiar()
        else:
            seccion_s()
        shutil.rmtree(TEMPORAL, ignore_errors=True)
    if parada is not None:
        estado["falla"] = True
    terminar()


if __name__ == "__main__":
    main()
