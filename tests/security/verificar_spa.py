#!/usr/bin/env python3
"""Batería de pruebas de seguridad de la SPA del personal servida por Caddy en
el 8445 (spa/, proxy/Dockerfile y proxy/Caddyfile, docs/threat-model.md, 6.11).

La pila entera con la imagen real del proxy, que compila la SPA en su primera
etapa. Prueba:

* a) arranque de la pila;
* b) las cabeceras exactas de la página, del script, de la hoja de estilos y de
  un error, con su tipo de contenido;
* c) que index.html no lleva nada en línea (ni <script> sin src, ni <style>,
  ni atributos on* o style), que es lo que permite la CSP sin 'unsafe-inline',
  y que declara lang="es". Control: la etapa de compilación con un mutante
  (inlineCritical activado y una regla de CSS) sí lo lleva;
* d) que la imagen final no lleva Node ni npm (control: la imagen base de la
  compilación sí), y que /srv/spa solo contiene index.html, un main-*.js y un
  styles-*.css, de root y sin escritura para nadie más (control: /data/caddy,
  que es del usuario de Caddy, sale con su dueño);
* e) que el contexto de compilación está aislado: unos ficheros centinela
  puestos en una copia de spa/ (en node_modules/, en dist/ y en la raíz) no
  llegan a la etapa de compilación (control: package.json sí llega);
* f) el recorrido de rutas del 8445 (ficheros, rutas de la SPA, ficheros que
  no existen, intentos de salir de /srv, métodos y rangos), que el 8444 no
  sirve la SPA (control: sirve su CSS) y que el 8443 tampoco;
* g) la SPA en un Chromium real (imagen de Playwright fijada por digest): carga
  "/" y una ruta profunda en recarga directa sin ninguna violación de la CSP,
  y Trusted Types bloquea un innerHTML con texto y la política
  'angular#unsafe-bypass' (control: en about:blank el mismo innerHTML se
  permite). Chromium confía en el certificado de Caddy por el SPKI de la CA
  intermedia, que es lo que Caddy envía (control: con el SPKI de la raíz, que
  no envía, la carga falla con ERR_CERT_AUTHORITY_INVALID). Solo se leen los
  certificados públicos, nunca una clave.

Lo que no prueba: Trusted Types en Firefox y Safari, que no lo aplican de la
misma forma (docs/threat-model.md, 8); el login y las cookies en el
navegador (bloque 6b-2).

Cada prueba negativa lleva su control positivo: si el control falla, el
resultado es SIN CONCLUSION, nunca PASA. Los oráculos son literales.

Cómo se ejecuta (desde la raíz del repositorio, en PowerShell, con Docker en
marcha, conexión a internet y los secretos generados con
scripts/generar_secretos.py):

    python tests/security/verificar_spa.py

Necesita red para compilar la SPA (npm ci y npm audit signatures), para
descargar la imagen de Playwright y para instalar el paquete playwright con
pip (versiones exactas y hashes de PyPI). La imagen de Playwright es para
linux/amd64.

Usa un proyecto de Docker propio (canario_spa). Necesita que el proyecto
canario y las demás baterías estén parados: las subredes 10.88.0.0/28 y
10.88.1.0/28 y los puertos 127.0.0.1:8443, 127.0.0.1:8444 y 127.0.0.1:8445 son
fijos (si están en uso, PARADA). Al terminar lo borra todo (down -v, las
imágenes construidas y la del mutante). No lee ningún secreto. Los ficheros
auxiliares van a un directorio temporal del sistema, nunca al repositorio. La
salida completa se guarda en verificacion_spa.txt dentro del directorio
temporal del sistema. El código de salida es 0 solo si el resultado global es
OK.

Solo usa la biblioteca estándar.
"""
import base64
import hashlib
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
import traceback

RAIZ = pathlib.Path.cwd()
PROYECTO = "canario_spa"
SALIDA = pathlib.Path(tempfile.gettempdir()) / "verificacion_spa.txt"
BASE = ["docker", "compose", "-p", PROYECTO, "-f", "docker-compose.yml"]

lineas_salida = []
estado = {"falla": False, "sin_conclusion": False}

# ---------------------------------------------------------------------------
# Oráculos literales
# ---------------------------------------------------------------------------
PUERTO_API = 8443
PUERTO_WEB = 8444
PUERTO_SPA = 8445
SUBRED_APP = "10.88.0.0/28"
SUBRED_EDGE = "10.88.1.0/28"
RAIZ_CA = "/data/caddy/pki/authorities/local/root.crt"
INTERMEDIA_CA = "/data/caddy/pki/authorities/local/intermediate.crt"

# La imagen base de la etapa de compilación (proxy/Dockerfile).
IMG_NODE = "node:24.20.0-alpine3.23@sha256:0388af2af070cd4736a1567cfed02469ba117848845b4165d87a333edb53d2ca"
# Playwright 1.63.0 (15 de septiembre de 2026). La imagen trae Python y los
# navegadores, pero no el paquete playwright (comprobado): se instala con pip,
# con versiones exactas y los hashes de los ficheros de PyPI. playwright exige
# pyee<14.
IMG_PLAYWRIGHT = ("mcr.microsoft.com/playwright/python:v1.63.0-noble"
                  "@sha256:72bd171a9ffc2b4b59532aaa6210e21014d07093120dc25528870c0b840da1f0")
USUARIO_PLAYWRIGHT = "1001:1001"  # pwuser
REQUISITOS_PLAYWRIGHT = (
    "playwright==1.63.0 --hash=sha256:ad21bc07516b187965a7521c5cf0df0bd657b17482eaad74335272d35a2b07de\n"
    "pyee==13.0.1 --hash=sha256:af2f8fede4171ef667dfded53f96e2ed0d6e6bd7ee3bb46437f77e3b57689228\n"
    "greenlet==3.5.6 --hash=sha256:975736b002ed080d124cf81a79cb7e05cb26d6b3f5c7a7b651c0fcce70353aa1\n"
    "typing-extensions==4.16.0 --hash=sha256:481caa481374e813c1b176ada14e97f1f67a4539ce9cfeb3f350d78d6370c2e8\n"
)

CSP_SPA = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
           "require-trusted-types-for 'script'; trusted-types angular; base-uri 'self'; "
           "form-action 'none'; frame-ancestors 'none'")
CABECERAS_SPA = {
    "strict-transport-security": "max-age=63072000",
    "x-content-type-options": "nosniff",
    "referrer-policy": "same-origin",
    "content-security-policy": CSP_SPA,
    "cache-control": "no-store",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
}
TIPO_HTML = "text/html; charset=utf-8"
TIPO_JS = "text/javascript; charset=utf-8"
TIPO_CSS = "text/css; charset=utf-8"
TIPO_JSON = "application/json"
CUERPO_404 = b'{"detalle": "recurso no encontrado"}'
CUERPO_405 = '{"detalle": "petición no válida"}'.encode()

# Lo que tiene que haber en index.html (spa/src/index.html y el build).
FRAGMENTO_SPA = b"<app-root><p>Cargando...</p></app-root>"
LANG_ES = b'<html lang="es">'
BASE_HREF = b'<base href="/">'
PATRON_MAIN = re.compile(rb'<script src="(main-[A-Z0-9]{8}\.js)" type="module"></script>')
PATRON_ESTILOS = re.compile(rb'<link rel="stylesheet" href="(styles-[A-Z0-9]{8}\.css)">')
# d) Los únicos ficheros de /srv/spa.
PATRON_FICHERO_SPA = re.compile(r"(index\.html|main-[A-Z0-9]{8}\.js|styles-[A-Z0-9]{8}\.css)")

# c) Lo que delata algo en línea en un HTML.
EN_LINEA = {
    "script sin src": re.compile(rb"<script\b(?![^>]*\ssrc=)[^>]*>", re.IGNORECASE),
    "style": re.compile(rb"<style\b", re.IGNORECASE),
    "atributo on*": re.compile(rb"\son[a-z]+\s*=", re.IGNORECASE),
    "atributo style": re.compile(rb"\sstyle\s*=", re.IGNORECASE),
    "javascript:": re.compile(rb"javascript:", re.IGNORECASE),
}
# Mutante de c): beasties solo pone algo en línea si hay CSS que inlinar.
CSS_MUTANTE = "body { margin: 0; }\n"
CENTINELAS = ("node_modules/centinela_spa.txt", "dist/centinela_spa.txt", "centinela_spa.txt")

# f) Recorrido de rutas del 8445: (método, ruta, estado, tipo, qué cuerpo).
# "spa" es la página de la SPA (FRAGMENTO_SPA); "404" y "405", los errores de
# Caddy en JSON.
RUTAS_SPA = [
    ("GET", "/", 200, TIPO_HTML, "spa"),
    ("GET", "/index.html", 200, TIPO_HTML, "spa"),
    ("GET", "/denuncias/abc", 200, TIPO_HTML, "spa"),
    ("GET", "/a/b/c/d", 200, TIPO_HTML, "spa"),
    ("GET", "/main-NOEXISTE.js", 404, TIPO_JSON, "404"),
    ("GET", "/favicon.ico", 404, TIPO_JSON, "404"),
    ("GET", "/3rdpartylicenses.txt", 404, TIPO_JSON, "404"),
    ("GET", "/package.json", 404, TIPO_JSON, "404"),
    ("GET", "/../etc/passwd", 200, TIPO_HTML, "spa"),
    ("GET", "/..%2f..%2fetc/passwd", 200, TIPO_HTML, "spa"),
    ("GET", "/%2e%2e/%2e%2e/etc/caddy/Caddyfile", 200, TIPO_HTML, "spa"),
    ("GET", "/%2e%2e/estatico/canario.css", 404, TIPO_JSON, "404"),
    ("POST", "/", 405, TIPO_JSON, "405"),
    ("DELETE", "/index.html", 405, TIPO_JSON, "405"),
]
# El 8444 no sirve la SPA aunque /srv/spa esté al lado de /srv/estatico.
RUTAS_SPA_DESDE_8444 = ["/spa/index.html", "/estatico/../spa/index.html", "/estatico/%2e%2e/spa/index.html",
                        "/estatico/..%2fspa/index.html"]
RUTA_CSS_8444 = "/estatico/canario.css"

# g) Lo que pinta la SPA (spa/src/app).
H1_INICIO = "Canario"
TITULO_INICIO = "Canario"
H1_NO_ENCONTRADA = "Página no encontrada"
TITULO_NO_ENCONTRADA = "Página no encontrada - Canario"
RUTA_PROFUNDA = "/denuncias/abc/def"
ERROR_TLS = "net::ERR_CERT_AUTHORITY_INVALID"
ERROR_TRUSTED_HTML = "This document requires 'TrustedHTML' assignment"
ERROR_POLITICA = "Policy \"angular#unsafe-bypass\" disallowed"

# Script del navegador (se escribe en el directorio temporal). Recibe los dos
# SPKI y escribe un JSON con lo que ve.
NAVEGADOR = r'''
import json, sys
sys.path.insert(0, "/tmp/pw")
from playwright.sync_api import Error, sync_playwright

spki_intermedia, spki_raiz = sys.argv[1], sys.argv[2]
ORIGEN = "https://localhost:8445"
res = {}


def intento(pagina, js):
    try:
        pagina.evaluate(js)
        return "permitido"
    except Error as e:
        return "bloqueado: " + str(e)


def visitar(pagina, ruta, recargar=False):
    pagina.goto(ORIGEN + ruta, wait_until="load")
    if recargar:
        pagina.reload(wait_until="load")
    pagina.wait_for_selector("main h1", timeout=15000)
    return {"h1": pagina.inner_text("main h1"), "titulo": pagina.title(),
            "lang": pagina.evaluate("document.documentElement.lang"),
            "cargando": pagina.evaluate("document.body.innerText.includes('Cargando...')")}


with sync_playwright() as pw:
    navegador = pw.chromium.launch(args=[f"--ignore-certificate-errors-spki-list={spki_intermedia}"])
    pagina = navegador.new_page()
    consola, errores = [], []
    pagina.on("console", lambda m: consola.append(f"{m.type}: {m.text}"))
    pagina.on("pageerror", lambda e: errores.append(str(e)))
    res["inicio"] = visitar(pagina, "/")
    res["profunda"] = visitar(pagina, sys.argv[3], recargar=True)
    res["consola"], res["errores"] = list(consola), list(errores)
    res["innerHTML"] = intento(pagina, "document.body.innerHTML = '<b>x</b>'")
    res["politica"] = intento(pagina, "trustedTypes.createPolicy('angular#unsafe-bypass', {createHTML: s => s})")
    pagina.goto("about:blank")
    res["control_innerHTML"] = intento(pagina, "document.body.innerHTML = '<b>x</b>'")
    navegador.close()

    navegador = pw.chromium.launch(args=[f"--ignore-certificate-errors-spki-list={spki_raiz}"])
    pagina = navegador.new_page()
    try:
        pagina.goto(ORIGEN + "/", wait_until="load")
        res["con_spki_raiz"] = "cargada"
    except Error as e:
        res["con_spki_raiz"] = "error: " + str(e)
    navegador.close()
print(json.dumps(res, ensure_ascii=False))
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


def dc(*args, timeout=900):
    return ejecutar(BASE + list(args), timeout=timeout)


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


def montaje(origen, destino):
    return ["--mount", f"type=bind,src={origen},dst={destino},readonly"]


TEMPORAL = None
CA_LOCAL = None
IMAGEN_PROXY = ""
IMAGEN_MUTANTE = f"{PROYECTO}_mutante"


def peticion(metodo, ruta, puerto=PUERTO_SPA, cabeceras=None):
    """Petición al proxy publicado en 127.0.0.1 con SNI localhost y TLS
    validado contra la raíz de Caddy. Devuelve (estado, {cabecera en
    minúsculas: [valores]}, cuerpo). La ruta se envía tal cual."""
    contexto = ssl.create_default_context(cafile=str(CA_LOCAL))
    s = socket.create_connection(("127.0.0.1", puerto), timeout=30)
    c = http.client.HTTPConnection("localhost", puerto, timeout=30)
    c.sock = contexto.wrap_socket(s, server_hostname="localhost")
    c.putrequest(metodo, ruta, skip_host=True, skip_accept_encoding=True)
    c.putheader("Host", f"localhost:{puerto}")
    c.putheader("Content-Length", "0")
    for nombre, valor in (cabeceras or {}).items():
        c.putheader(nombre, valor)
    c.endheaders()
    r = c.getresponse()
    leido = r.read()
    valores = {}
    for nombre, valor in r.getheaders():
        valores.setdefault(nombre.lower(), []).append(valor)
    c.close()
    return r.status, valores, leido


def una(cabeceras, nombre):
    """El valor de una cabecera que debe aparecer una sola vez, o None."""
    lista = cabeceras.get(nombre) or []
    return lista[0] if len(lista) == 1 else None


def en_linea(html):
    """Lo que hay en línea en un HTML: [(qué, cuántas veces)]."""
    return [(nombre, len(patron.findall(html))) for nombre, patron in EN_LINEA.items() if patron.search(html)]


def spki_de(pem):
    """SHA-256 en base64 del SubjectPublicKeyInfo de un certificado PEM, el
    formato de --ignore-certificate-errors-spki-list. Recorre el DER a mano:
    Certificate > tbsCertificate > [version], serial, firma, emisor, validez,
    sujeto y, después, la clave pública."""
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


def en_imagen(imagen, orden, timeout=120):
    """Una orden de shell en un contenedor desechable de la imagen, sin red y
    con la raíz de solo lectura."""
    return ejecutar(["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
                     "--security-opt", "no-new-privileges", "--entrypoint", "sh", imagen, "-c", orden], timeout=timeout)


# ---------------------------------------------------------------------------
# Secciones
# ---------------------------------------------------------------------------
INDICE = b""
MAIN = ""
ESTILOS = ""


def seccion_a():
    global CA_LOCAL, IMAGEN_PROXY
    p("=== a) arranque de la pila (la imagen del proxy compila la SPA)")
    r = dc("up", "-d", "--build", "--wait", "api", "caddy", timeout=1800)
    p(f"up -d --build --wait api caddy -> codigo {r.rc}")
    if r.rc != 0:
        p(r.todo.strip()[-1500:])
        raise Parada("no arranca la pila")
    IMAGEN_PROXY = ejecutar(["docker", "inspect", "--format", "{{.Config.Image}}",
                             dc("ps", "-q", "caddy").out.strip()]).out.strip()
    p(f"imagen del proxy: {IMAGEN_PROXY}")
    CA_LOCAL = TEMPORAL / "root.crt"
    r = dc("cp", f"caddy:{RAIZ_CA}", str(CA_LOCAL))
    if r.rc != 0 or not CA_LOCAL.is_file():
        raise Parada(f"no se pudo copiar el certificado raiz del CA de Caddy: {r.err.strip()[:200]}")


def seccion_b():
    global INDICE, MAIN, ESTILOS
    p("=== b) cabeceras y tipos del 8445")
    codigo, cab, INDICE = peticion("GET", "/")
    main, estilos = PATRON_MAIN.search(INDICE), PATRON_ESTILOS.search(INDICE)
    if codigo != 200 or main is None or estilos is None:
        raise Parada(f"GET / no devuelve el index.html del build ({codigo}, {INDICE[:200]!r})")
    MAIN, ESTILOS = main.group(1).decode(), estilos.group(1).decode()
    p(f"   index.html carga {MAIN} y {ESTILOS}")
    for etiqueta, ruta, tipo in (("pagina", "/", TIPO_HTML), ("script", f"/{MAIN}", TIPO_JS),
                                 ("estilos", f"/{ESTILOS}", TIPO_CSS), ("error 404", "/main-NOEXISTE.js", TIPO_JSON)):
        _, cab, _ = peticion("GET", ruta)
        pasa(una(cab, "content-type") == tipo, f"b) {etiqueta}: content-type: {cab.get('content-type')!r}")
        for nombre, valor in CABECERAS_SPA.items():
            pasa(una(cab, nombre) == valor, f"b) {etiqueta}: {nombre}: {cab.get(nombre)!r}")
        pasa("server" not in cab and "accept-ranges" not in cab, f"b) {etiqueta}: sin Server ni Accept-Ranges")


def seccion_c_e():
    p("=== c) index.html sin nada en linea y e) contexto de compilacion aislado")
    pasa(LANG_ES in INDICE and BASE_HREF in INDICE and FRAGMENTO_SPA in INDICE,
         "c) index.html declara lang=\"es\", <base href=\"/\"> y el aviso de carga dentro de app-root")

    # Mutante y centinelas en una copia de spa/ sin lo que genera un build
    # local. La etapa de compilación se construye con esa copia como contexto
    # spa: el repositorio no se toca.
    copia = TEMPORAL / "spa"
    shutil.copytree(RAIZ / "spa", copia, ignore=shutil.ignore_patterns("node_modules", "dist", ".angular"))
    angular = json.loads((copia / "angular.json").read_text(encoding="utf-8"))
    optimizacion = angular["projects"]["canario-spa"]["architect"]["build"]["configurations"]["production"]["optimization"]
    if optimizacion["styles"].get("inlineCritical") is not False:
        raise Parada("spa/angular.json no tiene inlineCritical en false: el mutante no se puede construir")
    optimizacion["styles"]["inlineCritical"] = True
    (copia / "angular.json").write_text(json.dumps(angular, indent=2), encoding="utf-8", newline="\n")
    with (copia / "src" / "styles.css").open("a", encoding="utf-8", newline="\n") as f:
        f.write(CSS_MUTANTE)
    for centinela in CENTINELAS:
        (copia / centinela).parent.mkdir(parents=True, exist_ok=True)
        (copia / centinela).write_text("centinela\n", encoding="utf-8", newline="\n")
    r = ejecutar(["docker", "build", "-q", "--target", "compilacion", "--build-context", f"spa={copia}",
                  "-f", str(RAIZ / "proxy" / "Dockerfile"), "-t", IMAGEN_MUTANTE, str(RAIZ / "proxy")], timeout=1800)
    if r.rc != 0:
        raise Parada(f"no se pudo construir la etapa de compilacion del mutante: {r.err.strip()[-500:]}")
    mutante = en_imagen(IMAGEN_MUTANTE, "cat /spa/dist/canario-spa/browser/index.html").out.encode("utf-8")
    real = en_linea(INDICE)
    control = en_linea(mutante)
    p(f"   mutante: {control}")
    negativo(f"c) index.html servido: nada en linea {real}", not real, bool(control),
             f"control: el mutante no tiene nada en linea ({mutante[:200]!r})")

    r = en_imagen(IMAGEN_MUTANTE, "find /spa -name 'centinela*'; test -f /spa/package.json && echo PACKAGE_JSON")
    hallados = [linea for linea in r.out.splitlines() if "centinela" in linea]
    negativo(f"e) ningun centinela de la copia de spa/ llega a la compilacion {hallados}", not hallados,
             r.rc == 0 and "PACKAGE_JSON" in r.out, f"control: {r.todo.strip()[-200:]!r}")


def seccion_d():
    p("=== d) la imagen final: sin Node y /srv/spa solo con el build, de root")
    orden = "command -v node npm npx corepack; true"
    final, control = en_imagen(IMAGEN_PROXY, orden), en_imagen(IMG_NODE, orden)
    negativo(f"d) sin node, npm, npx ni corepack en la imagen final ({final.out.split()})", not final.out.split(),
             "/usr/local/bin/node" in control.out, f"control: {control.out.split()}")

    r = en_imagen(IMAGEN_PROXY, "find /srv/spa /data/caddy -maxdepth 1 -exec stat -c '%u:%g %a %n' {} +")
    filas = [linea.split(" ", 2) for linea in r.out.splitlines() if linea.count(" ") >= 2]
    datos = {nombre: (dueno, int(modo, 8)) for dueno, modo, nombre in filas}
    control = datos.get("/data/caddy", ("", 0))[0] == "10002:10002" and "/srv/spa/index.html" in datos
    spa = {nombre: v for nombre, v in datos.items() if nombre.startswith("/srv/spa/")}
    nombres = sorted(n.removeprefix("/srv/spa/") for n in spa)
    negativo(f"d) /srv/spa solo contiene index.html, un main-*.js y un styles-*.css ({nombres})",
             len(nombres) == 3 and all(PATRON_FICHERO_SPA.fullmatch(n) for n in nombres), control,
             f"control: {r.todo.strip()[-300:]!r}")
    de_otro = sorted(n for n, (dueno, modo) in {**spa, "/srv/spa": datos.get("/srv/spa", ("", 0))}.items()
                     if dueno != "0:0" or modo & 0o022)
    negativo(f"d) /srv/spa y sus ficheros son de root y solo root escribe {de_otro}", not de_otro, control,
             "; ".join(f"{n}: {spa.get(n, datos.get(n, ('?', 0)))[0]} {spa.get(n, datos.get(n, ('?', 0)))[1]:o}"
                       for n in de_otro))


def seccion_f():
    p("=== f) recorrido de rutas del 8445; el 8444 y el 8443 no sirven la SPA")
    codigo, _, cuerpo = peticion("GET", f"/{MAIN}")
    control = codigo == 200 and len(cuerpo) > 1000
    pasa(control, f"f) control: GET /{MAIN} -> {codigo}, {len(cuerpo)} bytes")
    esperados = {"spa": FRAGMENTO_SPA, "404": CUERPO_404, "405": CUERPO_405}
    for metodo, ruta, estado_esperado, tipo, cuerpo_esperado in RUTAS_SPA:
        codigo, cab, cuerpo = peticion(metodo, ruta)
        ok = (codigo == estado_esperado and una(cab, "content-type") == tipo
              and (esperados[cuerpo_esperado] in cuerpo if cuerpo_esperado == "spa"
                   else cuerpo == esperados[cuerpo_esperado])
              and b"root:" not in cuerpo and "via" not in cab)
        negativo(f"f) {metodo} {ruta} -> {estado_esperado} {cuerpo_esperado} ({codigo}, {una(cab, 'content-type')!r})",
                 ok, control, f"{cuerpo[:120]!r}")
    codigo, cab, cuerpo = peticion("GET", f"/{MAIN}", cabeceras={"Range": "bytes=0-1,3-4"})
    negativo(f"f) dos rangos sobre /{MAIN} -> 200 con el fichero entero ({codigo}, {len(cuerpo)} bytes)",
             codigo == 200 and una(cab, "content-type") == TIPO_JS and len(cuerpo) > 1000
             and "accept-ranges" not in cab, control)

    codigo, _, _ = peticion("GET", RUTA_CSS_8444, puerto=PUERTO_WEB)
    control_web = codigo == 200
    pasa(control_web, f"f) control: el 8444 sirve {RUTA_CSS_8444} ({codigo})")
    for ruta in RUTAS_SPA_DESDE_8444:
        codigo, cab, cuerpo = peticion("GET", ruta, puerto=PUERTO_WEB)
        negativo(f"f) 8444 GET {ruta} -> 404, sin la SPA ({codigo})",
                 codigo == 404 and una(cab, "content-type") == TIPO_HTML and FRAGMENTO_SPA not in cuerpo, control_web)
    codigo, cab, cuerpo = peticion("GET", "/index.html", puerto=PUERTO_API)
    negativo(f"f) 8443 GET /index.html -> 404 de la API, sin la SPA ({codigo})",
             codigo == 404 and cuerpo == CUERPO_404 and FRAGMENTO_SPA not in cuerpo, control)


def seccion_g():
    p("=== g) la SPA en Chromium: CSP sin violaciones y Trusted Types")
    pem_intermedia = dc("exec", "-T", "caddy", "cat", INTERMEDIA_CA).out
    pem_raiz = CA_LOCAL.read_text(encoding="utf-8")
    if "BEGIN CERTIFICATE" not in pem_intermedia:
        raise Parada("no se pudo leer el certificado de la CA intermedia de Caddy")
    spki_intermedia, spki_raiz = spki_de(pem_intermedia), spki_de(pem_raiz)
    directorio = TEMPORAL / "navegador"
    directorio.mkdir()
    (directorio / "navegador.py").write_text(NAVEGADOR, encoding="utf-8", newline="\n")
    (directorio / "requisitos.txt").write_text(REQUISITOS_PLAYWRIGHT, encoding="utf-8", newline="\n")
    caddy = dc("ps", "-q", "caddy").out.strip()
    # El navegador comparte la red del contenedor de Caddy: localhost:8445 es
    # Caddy, con el mismo Host y el mismo SNI que desde el host. Mínimo
    # privilegio: pwuser, raíz de solo lectura y sin capacidades (Playwright
    # lanza Chromium sin su sandbox por defecto). La red la usa pip.
    r = ejecutar(["docker", "run", "--rm", "--network", f"container:{caddy}", "--user", USUARIO_PLAYWRIGHT,
                  "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--shm-size", "512m",
                  "--tmpfs", "/tmp:size=600m,exec", "-e", "HOME=/tmp", *montaje(directorio, "/prueba"),
                  "--entrypoint", "sh", IMG_PLAYWRIGHT, "-c",
                  ("pip install -q --disable-pip-version-check --no-deps --only-binary :all: --require-hashes "
                   "--target /tmp/pw -r /prueba/requisitos.txt && python3 -I /prueba/navegador.py \"$0\" \"$1\" \"$2\""),
                  spki_intermedia, spki_raiz, RUTA_PROFUNDA], timeout=900)
    try:
        res = json.loads(r.out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        sinc(f"g) no se pudo ejecutar el navegador: {r.todo.strip()[-800:]!r}")
        return
    inicio, profunda = res.get("inicio") or {}, res.get("profunda") or {}
    p(f"   inicio {inicio}; profunda {profunda}")
    control = inicio.get("h1") == H1_INICIO
    pasa(control, f"g) control: Chromium carga / y Angular pinta la pagina ({inicio.get('h1')!r})")
    negativo(f"g) Chromium sin el SPKI de la intermedia no acepta el certificado ({res.get('con_spki_raiz', '')[:80]!r})",
             ERROR_TLS in res.get("con_spki_raiz", ""), control)
    pasa(inicio.get("titulo") == TITULO_INICIO and inicio.get("lang") == "es" and inicio.get("cargando") is False,
         f"g) /: titulo {inicio.get('titulo')!r}, lang {inicio.get('lang')!r} y sin el aviso de carga")
    pasa(profunda.get("h1") == H1_NO_ENCONTRADA and profunda.get("titulo") == TITULO_NO_ENCONTRADA,
         f"g) {RUTA_PROFUNDA} en recarga directa: {profunda.get('h1')!r}, titulo {profunda.get('titulo')!r}")
    consola, errores = res.get("consola") or [], res.get("errores") or []
    negativo(f"g) ningun mensaje de consola ni error de JavaScript al cargar ({len(consola)}, {len(errores)})",
             not consola and not errores, control, f"consola {consola}; errores {errores}")
    control_tt = res.get("control_innerHTML") == "permitido"
    pasa(control_tt, f"g) control: en about:blank un innerHTML con texto se permite ({res.get('control_innerHTML')!r})")
    negativo("g) Trusted Types bloquea un innerHTML con texto en la SPA", ERROR_TRUSTED_HTML in res.get("innerHTML", ""),
             control_tt, res.get("innerHTML", "")[:200])
    negativo("g) Trusted Types no deja crear la politica 'angular#unsafe-bypass'",
             ERROR_POLITICA in res.get("politica", ""), control_tt, res.get("politica", "")[:200])


# ---------------------------------------------------------------------------
# Limpieza, precondiciones y arranque
# ---------------------------------------------------------------------------
def limpiar():
    ejecutar(["docker", "image", "rm", "-f", IMAGEN_MUTANTE])
    return dc_con_gestion("down", "-v", "--rmi", "local")


def seccion_s():
    p("=== s) limpieza")
    r = limpiar()
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
    """Redes ajenas que ya usan alguna de las subredes fijas del compose."""
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
    TEMPORAL = pathlib.Path(tempfile.mkdtemp(prefix="canario_spa_"))
    parada = None
    try:
        for seccion in (seccion_a, seccion_b, seccion_c_e, seccion_d, seccion_f, seccion_g):
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
