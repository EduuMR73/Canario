#!/usr/bin/env python3
"""Batería de pruebas de seguridad del sitio del denunciante (8444) delante de
las páginas HTML de la API (proxy/Caddyfile).

Parte A, el proxy: la API se sustituye por una aplicación de eco servida con
el mismo uvicorn y las mismas opciones (el command del compose), que devuelve
lo que le llega. Así se ve qué reenvía Caddy de verdad, sin depender de lo que
haga la API. Prueba:

* b) que el 8444 reenvía bajo /web, con la ruta tal cual (oráculos observados
  con la imagen fijada);
* c) que las rutas que tras el rewrite saldrían de /web se rechazan en Caddy
  sin llegar a la API;
* d) que las cookies solo viajan por el 8445 (la SPA del personal): la
  cabecera Cookie no llega a la API desde el 8444 ni desde el 8443, y un
  Set-Cookie de la API no sale por ellos (por el 8445 sí, en los dos
  sentidos: control de que el eco las vería);
* e) que del backend solo pasa HTML: JSON, texto o sin tipo se convierten en
  la página de error del sitio, con su estado, Retry-After y Allow;
* f) las cabeceras de seguridad de las páginas reenviadas y de los errores;
* g) que /web no es alcanzable desde el 8443, con el mismo 404 que la API;
* h) el límite de cuerpo en el 8444.

Parte B, la pila entera: la API real (app/rutas_web.py) con PostgreSQL y
Redis, una empresa dada de alta con gestion y peticiones como las de un
navegador. Prueba:

* i) que la API arranca con el origen del sitio en el log;
* j) la página de inicio, con las cabeceras del sitio;
* k) el formulario de una empresa, y el mismo 404 para una empresa que no
  existe que para una ruta que no existe;
* l) que una denuncia por formulario se crea, que el código sale una sola vez
  y que se guarda lo mismo que guardaría la API JSON (CRLF -> LF), leyéndola
  por /v1 en el 8443;
* m) la consulta: todo escapado, el código en el cuerpo y el mismo 404 para
  un código que no existe, sin repetirlo;
* n) los mensajes, y que un texto vacío vuelve con el formulario;
* o) que un formulario de otro origen (o sin Origin, o same-site) se rechaza
  sin crear nada;
* p) que el cuerpo se lee de forma estricta (tipo, campos repetidos o de más);
* q) que /v1 no se alcanza desde el 8444 y que ninguna respuesta del 8444 es
  JSON;
* r) que un NUL (%00) en un formulario se rechaza en la validación sin
  guardar nada: 422 con lo escrito en la denuncia y el mensaje, y el mismo
  404 que un código inexistente en la consulta;
* t) que el camino anónimo por /web (de j a r: páginas, denuncias, consultas,
  mensajes, 400, 403, 404, 415 y 422) no deja ninguna línea en el log de la
  API, y que ni los textos, ni el código, ni el identificador de la empresa
  aparecen en los logs de la API, PostgreSQL y Caddy.

Cada prueba negativa lleva su control positivo: si el control falla, el
resultado es SIN CONCLUSION, nunca PASA. Los oráculos son literales. Que una
respuesta haya pasado por la API se sabe por la cabecera Via que añade Caddy
al reenviar (y por la cabecera X-Eco del eco); un error que genera Caddy no
lleva ninguna de las dos.

Cómo se ejecuta (desde la raíz del repositorio, en PowerShell, con Docker en
marcha y los secretos generados con scripts/generar_secretos.py):

    python tests/security/verificar_web.py

Usa un proyecto de Docker propio (canario_web). Necesita que el proyecto
canario y las demás baterías estén parados: las subredes 10.88.0.0/28 y
10.88.1.0/28 y los puertos 127.0.0.1:8443, 127.0.0.1:8444 y 127.0.0.1:8445 son
fijos (si están en uso, PARADA). Al terminar lo borra todo (down -v y las imágenes
construidas, también la de gestion). No lee ningún secreto: la API y gestion
los reciben de secrets/ como Docker secrets. Los ficheros auxiliares van a un
directorio temporal del sistema, nunca al repositorio. La salida completa se
guarda en verificacion_web.txt dentro del directorio temporal del sistema. El
código de salida es 0 solo si el resultado global es OK.

Solo usa la biblioteca estándar.
"""
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

RAIZ = pathlib.Path.cwd()
PROYECTO = "canario_web"
SALIDA = pathlib.Path(tempfile.gettempdir()) / "verificacion_web.txt"
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
IP_PROXY = "10.88.0.2"
RAIZ_CA = "/data/caddy/pki/authorities/local/root.crt"
LIMITE_CUERPO = 128 * 1024

# b) Lo que ve la API (ruta cruda y consulta) para lo que pide el navegador.
# Observado con caddy:2.11.7-alpine el 15 de octubre de 2026: el rewrite no
# normaliza, y un %2F se decodifica.
REENVIADAS = {
    "/": "/web/",
    "/seguimiento": "/web/seguimiento",
    "/seguimiento?x=1": "/web/seguimiento?x=1",
    "//v1/denuncias": "/web//v1/denuncias",
    "/./v1": "/web/./v1",
    "/estatico/../v1": "/web/estatico/../v1",
    "/web/../v1": "/web/web/../v1",
    "/%2fv1": "/web//v1",
    "/x?a=/../v1": "/web/x?a=/../v1",
}
# c) Rutas que, limpias tras el rewrite, quedan fuera de /web: Caddy las
# rechaza con su 404 sin llegar a la API. La última es absolute-form.
RECHAZADAS = ["/../v1/denuncias", "/%2e%2e/v1/denuncias", "/%2E%2E%2Fv1/denuncias", "/..%2fv1/denuncias",
              "/a/../../v1", "/../salud", "https://localhost:8444/../v1"]

# e) Respuestas fijas del eco y lo que debe salir por el 8444: estado, cabecera
# que debe conservarse (o None) y el título de la página.
INTERCEPTADAS = {
    "/prueba/json429": (429, ("retry-after", "7"), "Demasiadas peticiones"),
    "/prueba/json405": (405, ("allow", "POST"), "Petición no válida"),
    "/prueba/json200": (500, None, "Servicio no disponible"),
    "/prueba/texto500": (500, None, "Servicio no disponible"),
    "/prueba/sintipo404": (404, None, "Página no encontrada"),
}
TIPO_HTML = "text/html; charset=utf-8"
# d) La cookie que pone el eco en sus rutas /prueba/cookie.
COOKIE_ECO = "__Host-canario_acceso=inyectada; Path=/; Secure"

# f) Cabeceras de las páginas del 8444 (proxy/Caddyfile, cabeceras_html).
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

# g) /web en el 8443: el mismo cuerpo que el 404 de la API (app/frontera_http.py).
CUERPO_404_API = b'{"detalle": "recurso no encontrado"}'
WEB_EN_API = ["/web", "/web/", "/web/seguimiento", "//web/seguimiento", "/./web/seguimiento", "/WEB/seguimiento",
              "/web%2Fseguimiento", "/web/empresas/%2e%2e"]

# Parte B. Límites altos para que las pruebas funcionales no choquen con los
# de producción; el 429 y su página los prueba e) y la regla de cada ruta,
# tests/unit/test_limitador.py y verificar_denuncia.py (r7).
LIMITES_PRUEBA = ("denuncia=1000/3600,seguimiento=1000/60,mensajes=1000/3600,acceso=1000/300,otras=1000/60,"
                  "cuenta=1000/60,registro=1000/3600,destinatario=1000/900,destinatario_dia=1000/86400")
TEXTO_ORIGEN = "ORIGEN WEB (por defecto): https://localhost:8444"
ORIGEN_WEB = "https://localhost:8444"
FORMULARIO = "application/x-www-form-urlencoded"
# Lo que manda un navegador en un POST de formulario del mismo origen.
CABECERAS_NAVEGADOR = {"Origin": ORIGEN_WEB, "Sec-Fetch-Site": "same-origin", "Content-Type": FORMULARIO}
PATRON_ALTA = re.compile(r"empresa creada: empresa_id=([0-9a-f-]{36}) identificador_publico=([0-9a-f]{32})")
PATRON_CODIGO = re.compile(rb'<p class="codigo"><code>([^<]+)</code></p>')
# Un texto con HTML y un salto de línea, enviado como lo codifica un navegador
# (el salto, como CRLF: %0D%0A).
TEXTO_HTML = "<script>alert(1)</script> & \"comillas\""
CUERPO_DENUNCIA = ("categoria=fraude&texto=%3Cscript%3Ealert%281%29%3C%2Fscript%3E+%26+%22comillas%22"
                   "%0D%0Asegunda+l%C3%ADnea").encode("ascii")
TEXTO_GUARDADO = TEXTO_HTML + "\nsegunda línea"
MENSAJE_CODIGO = "código de seguimiento no válido"
# r) El mensaje fijo del campo de texto (app/rutas_web.py, ERROR_TEXTO).
ERROR_TEXTO = "Escriba el texto. No puede estar vacío ni superar los 10000 caracteres."
EMPRESA_INEXISTENTE = "0" * 32

# ---------------------------------------------------------------------------
# Aplicación de eco que sustituye a la API (se escribe en el directorio temporal)
# ---------------------------------------------------------------------------
ECO = r'''
import json

COOKIE = b"__Host-canario_acceso=inyectada; Path=/; Secure"

# Respuestas fijas para e): estado, tipo (None: sin Content-Type) y cabeceras.
CASOS = {
    "/web/prueba/json429": (429, b"application/json", [(b"retry-after", b"7")]),
    "/web/prueba/json405": (405, b"application/json", [(b"allow", b"POST")]),
    "/web/prueba/json200": (200, b"application/json", []),
    "/web/prueba/texto500": (500, b"text/plain; charset=utf-8", []),
    "/web/prueba/sintipo404": (404, None, []),
    "/web/prueba/html422": (422, b"text/html; charset=utf-8", []),
    # Para d): una respuesta que pone una cookie, por cada puerto.
    "/web/prueba/cookie": (200, b"text/html; charset=utf-8", [(b"set-cookie", COOKIE)]),
    "/prueba/cookie": (200, b"application/json", [(b"set-cookie", COOKIE)]),
    "/v1/personal/prueba/cookie": (200, b"application/json", [(b"set-cookie", COOKIE)]),
}


async def aplicacion(scope, receive, send):
    if scope["type"] == "lifespan":
        while True:
            mensaje = await receive()
            if mensaje["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif mensaje["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return
    recibidos = 0
    while True:
        mensaje = await receive()
        recibidos += len(mensaje.get("body", b""))
        if not mensaje.get("more_body", False):
            break
    if scope["path"] == "/salud":
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": b'{"estado":"ok"}'})
        return
    cab = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
    consulta = scope["query_string"].decode("latin-1")
    cuerpo = json.dumps({
        "metodo": scope["method"],
        "ruta": scope["raw_path"].decode("latin-1") + ("?" + consulta if consulta else ""),
        "cookie": cab.get("cookie"),
        "prueba": cab.get("x-prueba"),
        "bytes": recibidos,
    }).encode()
    estado, tipo, extra = CASOS.get(scope["path"], (200, b"text/html; charset=utf-8", []))
    cabeceras = [(b"x-eco", b"si"), *extra] + ([(b"content-type", tipo)] if tipo else [])
    await send({"type": "http.response.start", "status": estado, "headers": cabeceras})
    await send({"type": "http.response.body", "body": cuerpo})
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


def dc(*args, override=None, entrada=None):
    base = BASE + (["-f", str(override)] if override else [])
    return ejecutar(base + list(args), entrada=entrada)


def dc_con_gestion(*args):
    """compose con el perfil gestion. down solo actúa sobre los servicios de
    los perfiles activos: sin él, la imagen de gestion quedaría sin borrar."""
    return ejecutar(BASE + ["--profile", "gestion"] + list(args))


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
    """Prueba negativa con control: si el control falla, SIN CONCLUSION."""
    if not control_ok:
        sinc(f"{nombre}: el control positivo fallo {detalle}".rstrip())
        return
    pasa(cond, nombre)
    if not cond and detalle:
        p(f"   {detalle}")


TEMPORAL = None
CA_LOCAL = None


def esperar(condicion, maximo):
    """Espera hasta que condicion() sea verdadera o pasen maximo segundos."""
    limite = time.monotonic() + maximo
    while time.monotonic() < limite:
        if condicion():
            return True
        time.sleep(1)
    return condicion()


def log_de(servicio):
    return dc("logs", "--no-color", "--no-log-prefix", servicio).todo


def peticion(metodo, ruta, puerto=PUERTO_WEB, cabeceras=None, cuerpo=b""):
    """Petición al proxy publicado en 127.0.0.1 con SNI localhost y TLS validado.

    Devuelve (estado, {cabecera en minúsculas: [valores]}, cuerpo). La ruta se
    envía tal cual (http.client no la normaliza). Si Caddy corta mientras se
    envía el cuerpo (413), se lee igualmente su respuesta.
    """
    contexto = ssl.create_default_context(cafile=str(CA_LOCAL))
    s = socket.create_connection(("127.0.0.1", puerto), timeout=30)
    c = http.client.HTTPConnection("localhost", puerto, timeout=30)
    c.sock = contexto.wrap_socket(s, server_hostname="localhost")
    c.putrequest(metodo, ruta, skip_host=True, skip_accept_encoding=True)
    c.putheader("Host", f"localhost:{puerto}")
    c.putheader("Content-Length", str(len(cuerpo)))
    for nombre, valor in (cabeceras or {}).items():
        c.putheader(nombre, valor)
    c.endheaders()
    try:
        if cuerpo:
            c.send(cuerpo)
    except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
        pass
    r = c.getresponse()
    datos = r.read()
    valores = {}
    for nombre, valor in r.getheaders():
        valores.setdefault(nombre.lower(), []).append(valor)
    c.close()
    return r.status, valores, datos


def una(cabeceras, nombre):
    """El valor de una cabecera que debe aparecer una sola vez, o None."""
    lista = cabeceras.get(nombre) or []
    return lista[0] if len(lista) == 1 else None


def eco_de(respuesta):
    """El JSON del eco si la respuesta pasó por la API (Via y X-Eco), o None."""
    codigo, cab, cuerpo = respuesta
    if codigo != 200 or "via" not in cab or una(cab, "x-eco") != "si":
        return None
    try:
        return json.loads(cuerpo)
    except ValueError:
        return None


def generada_por_caddy(respuesta, codigo, titulo):
    """Página de error del sitio: su estado, HTML, su título y sin pasar por la API."""
    estado_r, cab, cuerpo = respuesta
    return (estado_r == codigo and una(cab, "content-type") == TIPO_HTML and "via" not in cab
            and "x-eco" not in cab and f"<h1>{titulo}</h1>".encode() in cuerpo)


def cabeceras_exactas(etiqueta, cab, esperadas):
    for nombre, valor in esperadas.items():
        pasa(una(cab, nombre) == valor, f"{etiqueta}: {nombre}: {cab.get(nombre)!r}")
    pasa("server" not in cab, f"{etiqueta}: sin cabecera Server")


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


# ---------------------------------------------------------------------------
# Parte A: el proxy, con la API sustituida por el eco
# ---------------------------------------------------------------------------
def seccion_a():
    global CA_LOCAL
    p("=== a) arranque con la API sustituida por la aplicacion de eco")
    (TEMPORAL / "eco").mkdir()
    (TEMPORAL / "eco" / "eco.py").write_text(ECO, encoding="utf-8", newline="\n")
    override = TEMPORAL / "override.yml"
    override.write_text(
        "services:\n"
        "  api:\n"
        "    entrypoint: [\"uvicorn\", \"eco:aplicacion\", \"--app-dir\", \"/eco\", \"--host\", \"0.0.0.0\",\n"
        "                 \"--port\", \"8000\", \"--no-access-log\", \"--no-server-header\"]\n"
        "    volumes:\n"
        "      - type: bind\n"
        f"        source: \"{(TEMPORAL / 'eco').as_posix()}\"\n"
        "        target: /eco\n"
        "        read_only: true\n",
        encoding="utf-8", newline="\n")
    r = dc("up", "-d", "--build", "--wait", "api", "caddy", override=override)
    p(f"up -d --build --wait api caddy (con el eco) -> codigo {r.rc}")
    if r.rc != 0:
        p(r.todo.strip()[-1500:])
        raise Parada("no arranca el proxy con la aplicacion de eco")
    comando = inspeccionar(contenedor("api"), "{{json .Config.Cmd}}")
    pasa(comando == ["--proxy-headers", "--forwarded-allow-ips", IP_PROXY],
         f"a) el eco corre con el command del compose ({comando})")
    CA_LOCAL = TEMPORAL / "root.crt"
    r = dc("cp", f"caddy:{RAIZ_CA}", str(CA_LOCAL))
    if r.rc != 0 or not CA_LOCAL.is_file():
        raise Parada(f"no se pudo copiar el certificado raiz del CA de Caddy: {r.err.strip()[:200]}")


def seccion_b():
    p("=== b) el 8444 reenvia bajo /web, con la ruta tal cual")
    for pedida, esperada in REENVIADAS.items():
        eco = eco_de(peticion("GET", pedida))
        pasa(eco is not None and eco.get("ruta") == esperada,
             f"b) GET {pedida} -> la API recibe {(eco or {}).get('ruta')!r} (se espera {esperada!r})")


def seccion_c():
    p("=== c) lo que saldria de /web se rechaza en Caddy, sin llegar a la API")
    # Control: una ruta normal llega al eco, así que la ausencia de Via en los
    # rechazos significa que no llegaron.
    control = eco_de(peticion("GET", "/seguimiento")) is not None
    pasa(control, "c) control: GET /seguimiento llega a la API (Via y X-Eco)")
    for ruta in RECHAZADAS:
        respuesta = peticion("GET", ruta)
        negativo(f"c) GET {ruta} -> 404 del sitio, sin llegar a la API ({respuesta[0]})",
                 generada_por_caddy(respuesta, 404, "Página no encontrada"), control)


def seccion_d():
    p("=== d) las cookies solo viajan por el 8445")
    cabeceras = {"Cookie": "sesion=canario", "X-Prueba": "canario"}
    desde_spa = eco_de(peticion("GET", "/v1/personal/eco", puerto=PUERTO_SPA, cabeceras=cabeceras)) or {}
    desde_api = eco_de(peticion("GET", "/eco", puerto=PUERTO_API, cabeceras=cabeceras)) or {}
    desde_web = eco_de(peticion("GET", "/seguimiento", cabeceras=cabeceras)) or {}
    # Control: el eco ve la Cookie cuando llega (por el 8445), y por el 8443 y
    # el 8444 la petición llega con el resto de cabeceras (X-Prueba).
    control = (desde_spa.get("cookie") == "sesion=canario" and desde_api.get("prueba") == "canario"
               and desde_web.get("prueba") == "canario")
    detalle = f"8445: {desde_spa}; 8443: {desde_api}; 8444: {desde_web}"
    negativo(f"d) por el 8444 la API no recibe Cookie ({desde_web.get('cookie')!r})",
             desde_web.get("cookie") is None, control, detalle)
    negativo(f"d) por el 8443 la API no recibe Cookie ({desde_api.get('cookie')!r})",
             desde_api.get("cookie") is None, control, detalle)
    # Set-Cookie: una cookie puesta en el 8443 o el 8444 valdría en el 8445
    # (no se aíslan por puerto). Control: por el 8445 sale tal cual.
    codigo, cab, _ = peticion("GET", "/v1/personal/prueba/cookie", puerto=PUERTO_SPA)
    control = codigo == 200 and "via" in cab and una(cab, "set-cookie") == COOKIE_ECO
    pasa(control, f"d) control: un Set-Cookie de la API sale por el 8445 ({codigo}, {cab.get('set-cookie')})")
    for puerto in (PUERTO_API, PUERTO_WEB):
        codigo, cab, _ = peticion("GET", "/prueba/cookie", puerto=puerto)
        negativo(f"d) por el {puerto} no sale el Set-Cookie de la API ({codigo}, {cab.get('set-cookie')})",
                 codigo == 200 and "via" in cab and "set-cookie" not in cab, control)


def seccion_e():
    p("=== e) del backend solo pasa HTML")
    # Control: el HTML del backend pasa con su estado, su cuerpo y por la API.
    codigo, cab, cuerpo = peticion("GET", "/prueba/html422")
    control = codigo == 422 and una(cab, "content-type") == TIPO_HTML and "via" in cab and b'"metodo"' in cuerpo
    pasa(control, f"e) control: un 422 en HTML de la API pasa tal cual ({codigo}, {cab.get('content-type')})")
    for ruta, (codigo, conservada, titulo) in INTERCEPTADAS.items():
        respuesta = peticion("GET", ruta)
        cab = respuesta[1]
        bien = generada_por_caddy(respuesta, codigo, titulo)
        if conservada:
            bien = bien and una(cab, conservada[0]) == conservada[1]
        negativo(f"e) GET {ruta} -> {codigo} con la pagina \"{titulo}\""
                 + (f" y {conservada[0]}: {conservada[1]}" if conservada else "")
                 + f" ({respuesta[0]}, {cab.get('content-type')}, {conservada and cab.get(conservada[0])})",
                 bien, control, f"cabeceras: {cab}")


def seccion_f():
    p("=== f) cabeceras de las paginas reenviadas y de los errores")
    codigo, cab, _ = peticion("GET", "/seguimiento")
    pasa(codigo == 200 and "via" in cab, f"f) control: GET /seguimiento pasa por la API ({codigo})")
    cabeceras_exactas("f) pagina reenviada", cab, CABECERAS_HTML)
    pasa("x-eco" in cab, "f) la pagina reenviada conserva las cabeceras propias de la API (X-Eco)")
    _, cab, _ = peticion("GET", "/prueba/json429")
    cabeceras_exactas("f) error interceptado", cab, CABECERAS_HTML)
    _, cab, _ = peticion("GET", RECHAZADAS[0])
    cabeceras_exactas("f) rechazo de la guarda", cab, CABECERAS_HTML)


def seccion_g():
    p("=== g) /web no es alcanzable desde el 8443")
    # Control: el 8443 reenvía a la API lo que no es /web.
    control = eco_de(peticion("GET", "/eco", puerto=PUERTO_API)) is not None
    pasa(control, "g) control: GET /eco en el 8443 llega a la API")
    for ruta in WEB_EN_API:
        codigo, cab, cuerpo = peticion("GET", ruta, puerto=PUERTO_API)
        negativo(f"g) 8443 GET {ruta} -> 404 con el cuerpo de la API, sin llegar a ella ({codigo}, {cuerpo[:60]!r})",
                 codigo == 404 and cuerpo == CUERPO_404_API and "via" not in cab
                 and una(cab, "content-type") == "application/json", control)


def seccion_h():
    p("=== h) limite de cuerpo en el 8444")
    cabeceras = {"Content-Type": "application/x-www-form-urlencoded"}
    justo = peticion("POST", "/seguimiento", cabeceras=cabeceras, cuerpo=b"a" * LIMITE_CUERPO)
    eco = eco_de(justo) or {}
    control = eco.get("bytes") == LIMITE_CUERPO
    pasa(control, f"h) control: un cuerpo de 128 KiB llega entero a la API ({eco.get('bytes')} bytes)")
    encima = peticion("POST", "/seguimiento", cabeceras=cabeceras, cuerpo=b"a" * (LIMITE_CUERPO + 1))
    negativo(f"h) un byte por encima -> 413 del sitio, sin llegar a la API ({encima[0]})",
             generada_por_caddy(encima, 413, "Texto demasiado largo"), control)


# ---------------------------------------------------------------------------
# Parte B: la pila entera, con la API real
# ---------------------------------------------------------------------------
IDENTIFICADOR = ""
# Líneas del log de la API al terminar i): t) cuenta las que aparecen después.
LINEAS_API = None


def pagina_api(respuesta, codigo):
    """Página HTML generada por la API (pasa por ella: Via), con ese estado."""
    estado_r, cab, _ = respuesta
    return estado_r == codigo and una(cab, "content-type") == TIPO_HTML and "via" in cab


def enviar(ruta, cuerpo, cabeceras=None):
    """POST de formulario como el de un navegador, salvo lo que se cambie."""
    return peticion("POST", ruta, cabeceras={**CABECERAS_NAVEGADOR, **(cabeceras or {})}, cuerpo=cuerpo)


def sin(cabecera):
    """Las cabeceras del navegador sin una de ellas."""
    return {k: v for k, v in CABECERAS_NAVEGADOR.items() if k != cabecera}


def contar(tabla):
    r = sup(f"select count(*) from canal.{tabla};")
    return int(r.out.strip()) if r.rc == 0 and r.out.strip().isdigit() else None


def contar_denuncias():
    return contar("denuncia")


def seccion_i():
    global IDENTIFICADOR, LINEAS_API
    p("=== i) arranque de la API real (con PostgreSQL y Redis) y alta de una empresa")
    limites = TEMPORAL / "limites.yml"
    limites.write_text(f"services:\n  api:\n    environment:\n      CANARIO_LIMITES: \"{LIMITES_PRUEBA}\"\n",
                       encoding="utf-8", newline="\n")
    BASE.extend(["-f", str(limites)])
    r = dc("up", "-d", "--wait", "api", "caddy")
    p(f"up -d --wait api caddy (API real) -> codigo {r.rc}")
    if r.rc != 0:
        p(r.todo.strip()[-1500:])
        raise Parada("no arranca la API real")
    registro = dc("logs", "--no-color", "--no-log-prefix", "api").todo
    pasa(TEXTO_ORIGEN in registro, f"i) la API registra el origen del sitio ({TEXTO_ORIGEN!r})")
    r = dc("run", "--rm", "-T", "gestion", "alta-empresa", "--nombre", "Empresa Web", "--zona", "Europe/Madrid")
    alta = PATRON_ALTA.search(r.out)
    if r.rc != 0 or alta is None:
        p(f"   gestion: codigo {r.rc} {r.err.strip()[-300:]!r}")
        raise Parada("no se pudo dar de alta la empresa de prueba")
    IDENTIFICADOR = alta.group(2)
    p(f"   empresa de prueba: {IDENTIFICADOR}")
    LINEAS_API = len(log_de("api").splitlines())


def seccion_j():
    p("=== j) pagina de inicio")
    respuesta = peticion("GET", "/")
    pasa(pagina_api(respuesta, 200) and "<h1>Canal de denuncias anónimo</h1>".encode() in respuesta[2],
         f"j) GET / -> 200, la pagina de inicio de la API ({respuesta[0]})")
    cabeceras_exactas("j) pagina de inicio", respuesta[1], CABECERAS_HTML)


def seccion_k():
    p("=== k) formulario de una empresa y 404 uniforme")
    respuesta = peticion("GET", f"/empresas/{IDENTIFICADOR}")
    accion = f'action="/empresas/{IDENTIFICADOR}/denuncias"'.encode()
    control = pagina_api(respuesta, 200) and accion in respuesta[2]
    pasa(control, f"k) GET /empresas/<empresa> -> 200 con el formulario que envia a su ruta ({respuesta[0]})")
    no_existe = peticion("GET", "/no-existe")
    for ruta in (f"/empresas/{EMPRESA_INEXISTENTE}", f"/empresas/{IDENTIFICADOR.upper()}", "/empresas/x"):
        otra = peticion("GET", ruta)
        negativo(f"k) GET {ruta} -> el mismo 404 que una ruta inexistente ({otra[0]})",
                 generada_por_caddy(otra, 404, "Página no encontrada") and otra[2] == no_existe[2], control)


CODIGO = ""


def seccion_l():
    global CODIGO
    p("=== l) denuncia por formulario")
    antes = contar_denuncias()
    respuesta = enviar(f"/empresas/{IDENTIFICADOR}/denuncias", CUERPO_DENUNCIA)
    encontrado = PATRON_CODIGO.findall(respuesta[2])
    pasa(pagina_api(respuesta, 201) and len(encontrado) == 1,
         f"l) POST de la denuncia -> 201 con el codigo una sola vez ({respuesta[0]}, {len(encontrado)})")
    pasa(antes is not None and contar_denuncias() == antes + 1, "l) se crea exactamente una denuncia")
    if len(encontrado) != 1:
        raise Parada("sin codigo de seguimiento no se puede seguir")
    CODIGO = encontrado[0].decode("ascii")
    # Lo guardado, leído por la API JSON: el mismo texto que escribió la
    # persona, con LF y no con el CRLF del envío.
    cuerpo = json.dumps({"codigo": CODIGO}).encode()
    codigo, _, datos = peticion("POST", "/v1/seguimiento", puerto=PUERTO_API,
                                cabeceras={"Content-Type": "application/json"}, cuerpo=cuerpo)
    leido = json.loads(datos) if codigo == 200 else {}
    pasa(leido.get("texto") == TEXTO_GUARDADO and leido.get("categoria") == "fraude",
         f"l) por /v1 se lee el mismo texto, con LF ({codigo}, {leido.get('texto')!r})")


def seccion_m():
    p("=== m) consulta por formulario")
    respuesta = enviar("/seguimiento/consulta", f"codigo={CODIGO}".encode("ascii"))
    html = respuesta[2]
    control = pagina_api(respuesta, 200) and "segunda línea".encode() in html
    pasa(control, f"m) POST de la consulta -> 200 con la denuncia ({respuesta[0]})")
    negativo("m) el texto de la denuncia sale escapado (sin <script>)",
             b"<script>" not in html and b"&lt;script&gt;alert(1)&lt;/script&gt; &amp; &#34;comillas&#34;" in html, control)
    pasa(f'<input type="hidden" name="codigo" value="{CODIGO}">'.encode() in html,
         "m) el codigo va oculto en el formulario de mensajes (cuerpo del POST, nunca en la URL)")
    for codigo in ("Z" * len(CODIGO), "x"):
        respuesta = enviar("/seguimiento/consulta", f"codigo={codigo}".encode("ascii"))
        negativo(f"m) un codigo que no existe ({len(codigo)} caracteres) -> 404 con el formulario, sin repetirlo",
                 pagina_api(respuesta, 404) and MENSAJE_CODIGO.encode() in respuesta[2]
                 and f'value="{codigo}"'.encode() not in respuesta[2], control, f"{respuesta[0]}")


def seccion_n():
    p("=== n) mensajes por formulario")
    respuesta = enviar("/seguimiento/mensajes", f"codigo={CODIGO}&texto=hola+desde+la+web".encode("ascii"))
    control = pagina_api(respuesta, 201) and b"Mensaje enviado." in respuesta[2] and b"hola desde la web" in respuesta[2]
    pasa(control, f"n) POST de un mensaje -> 201 con el expediente y el mensaje ({respuesta[0]})")
    respuesta = enviar("/seguimiento/mensajes", f"codigo={CODIGO}&texto=+++".encode("ascii"))
    negativo("n) un mensaje solo de espacios -> 422 con el formulario y lo escrito",
             pagina_api(respuesta, 422) and b'aria-invalid="true"' in respuesta[2]
             and b">\n   </textarea>" in respuesta[2], control, f"{respuesta[0]}")


def seccion_o():
    p("=== o) formularios de otro origen")
    cuerpo = b"categoria=acoso&texto=denuncia+enviada+desde+otro+sitio"
    ruta = f"/empresas/{IDENTIFICADOR}/denuncias"
    antes = contar_denuncias()
    casos = {
        "sin Origin": sin("Origin"),
        "Origin de otro sitio": {**sin("Sec-Fetch-Site"), "Origin": "https://atacante.ejemplo"},
        "Origin del 8443 (mismo sitio)": {**sin("Sec-Fetch-Site"), "Origin": "https://localhost:8443"},
        "Origin null": {**sin("Sec-Fetch-Site"), "Origin": "null"},
        "Sec-Fetch-Site cross-site": {**CABECERAS_NAVEGADOR, "Sec-Fetch-Site": "cross-site"},
        "Sec-Fetch-Site same-site": {**CABECERAS_NAVEGADOR, "Sec-Fetch-Site": "same-site"},
    }
    resultados = {nombre: peticion("POST", ruta, cabeceras=cab, cuerpo=cuerpo) for nombre, cab in casos.items()}
    despues = contar_denuncias()
    # Control: con las cabeceras de un navegador del mismo origen, sí se crea.
    aceptada = enviar(ruta, cuerpo)
    control = pagina_api(aceptada, 201) and despues is not None and contar_denuncias() == despues + 1
    pasa(control, f"o) control: el mismo envio desde el sitio crea la denuncia ({aceptada[0]})")
    for nombre, respuesta in resultados.items():
        negativo(f"o) {nombre} -> 403 con la pagina del sitio ({respuesta[0]})",
                 generada_por_caddy(respuesta, 403, "Petición no válida"), control)
    negativo(f"o) ninguno de los envios rechazados crea una denuncia ({antes} -> {despues})",
             antes is not None and despues == antes, control)


def seccion_p():
    p("=== p) lectura estricta del cuerpo")
    ruta = "/seguimiento/consulta"
    control = pagina_api(enviar(ruta, f"codigo={CODIGO}".encode("ascii")), 200)
    pasa(control, "p) control: el cuerpo de un navegador se acepta")
    casos = {
        "JSON en vez de formulario": ({"Content-Type": "application/json"}, json.dumps({"codigo": CODIGO}).encode(), 415),
        "multipart": ({"Content-Type": "multipart/form-data; boundary=x"}, b"--x--", 415),
        "campo repetido": ({}, f"codigo={CODIGO}&codigo={CODIGO}".encode("ascii"), 400),
        "campo de mas": ({}, f"codigo={CODIGO}&otro=1".encode("ascii"), 400),
        "% suelto": ({}, b"codigo=100%", 400),
        "UTF-8 no valido": ({}, b"codigo=%FF", 400),
    }
    for nombre, (cabeceras, cuerpo, codigo) in casos.items():
        respuesta = enviar(ruta, cuerpo, cabeceras)
        negativo(f"p) {nombre} -> {codigo} con la pagina del sitio ({respuesta[0]})",
                 generada_por_caddy(respuesta, codigo, "Petición no válida"), control)


def seccion_q():
    p("=== q) /v1 no se alcanza desde el 8444 y el 8444 nunca responde JSON")
    control = pagina_api(enviar("/seguimiento/consulta", f"codigo={CODIGO}".encode("ascii")), 200)
    cuerpo = json.dumps({"codigo": CODIGO}).encode()
    for ruta in ("/v1/seguimiento", "/v1/empresas/" + IDENTIFICADOR + "/denuncias"):
        respuesta = peticion("POST", ruta, cabeceras={"Content-Type": "application/json"}, cuerpo=cuerpo)
        negativo(f"q) POST {ruta} en el 8444 -> 404 del sitio ({respuesta[0]})",
                 generada_por_caddy(respuesta, 404, "Página no encontrada"), control)
    # Una muestra de todo lo que puede responder el 8444: páginas, errores de la
    # API y errores de Caddy. Ninguna puede ser JSON.
    muestras = [peticion("GET", "/"), peticion("GET", f"/empresas/{IDENTIFICADOR}"), peticion("GET", "/seguimiento"),
                peticion("GET", "/no-existe"), peticion("DELETE", "/seguimiento"), peticion("GET", "/seguimiento/consulta"),
                enviar("/seguimiento/consulta", b"codigo=x"), enviar("/seguimiento/consulta", b"codigo=%FF"),
                peticion("POST", "/seguimiento/consulta", cuerpo=b"codigo=x")]
    tipos = sorted({str(m[1].get("content-type")) for m in muestras})
    negativo(f"q) las {len(muestras)} respuestas de muestra son HTML ({tipos})",
             all(una(m[1], "content-type") == TIPO_HTML for m in muestras), control)


def seccion_r():
    # %00 es UTF-8 válido: pasa la lectura del formulario (p) y lo rechaza la
    # validación (TextoLibre y TextoLinea, app/validacion.py). Un surrogate o
    # un UTF-8 mal formado no llegan ahí: los rechaza la lectura con 400
    # (tests/unit/test_web.py, Formulario.test_rechazos).
    # Decisión fijada aquí: el 422 devuelve lo escrito, NUL incluido, para que
    # la persona no pierda su texto en ningún 422. Va escapado y solo a quien lo
    # envió (el origen se comprueba antes); el navegador muestra el NUL como
    # U+FFFD. El mensaje es el genérico del campo, aunque no nombre el NUL: un
    # navegador no lo envía desde el formulario. Si esto cambia, falla aquí.
    p("=== r) NUL en los formularios: rechazado sin guardar nada")
    ruta = f"/empresas/{IDENTIFICADOR}/denuncias"
    antes = contar("denuncia")
    respuesta = enviar(ruta, b"categoria=acoso&texto=con%00nul")
    despues = contar("denuncia")
    control = pagina_api(enviar(ruta, b"categoria=acoso&texto=sin+nul"), 201) and contar("denuncia") == despues + 1
    pasa(control, "r) control: la misma denuncia sin el NUL se crea (201)")
    negativo(f"r) denuncia con NUL en el texto -> 422 con el mensaje del campo y lo escrito ({respuesta[0]})",
             pagina_api(respuesta, 422) and b'aria-invalid="true"' in respuesta[2]
             and ERROR_TEXTO.encode() in respuesta[2] and b">\ncon\x00nul</textarea>" in respuesta[2], control)
    negativo(f"r) la denuncia con NUL no se guarda ({antes} -> {despues})", antes is not None and despues == antes, control)

    inexistente = enviar("/seguimiento/consulta", f"codigo={'Z' * len(CODIGO)}".encode("ascii"))
    control = pagina_api(enviar("/seguimiento/consulta", f"codigo={CODIGO}".encode("ascii")), 200)
    pasa(control and pagina_api(inexistente, 404), "r) control: el codigo bueno da 200 y uno inexistente 404")
    respuesta = enviar("/seguimiento/consulta", f"codigo={CODIGO}%00".encode("ascii"))
    negativo(f"r) consulta con NUL en el codigo -> el mismo 404 que un codigo inexistente ({respuesta[0]})",
             pagina_api(respuesta, 404) and respuesta[2] == inexistente[2], control)

    antes = contar("mensaje")
    respuesta = enviar("/seguimiento/mensajes", f"codigo={CODIGO}&texto=con%00nul".encode("ascii"))
    despues = contar("mensaje")
    control = (pagina_api(enviar("/seguimiento/mensajes", f"codigo={CODIGO}&texto=sin+nul".encode("ascii")), 201)
               and contar("mensaje") == despues + 1)
    pasa(control, "r) control: el mismo mensaje sin el NUL se guarda (201)")
    negativo(f"r) mensaje con NUL en el texto -> 422 con el expediente, el mensaje del campo y lo escrito ({respuesta[0]})",
             pagina_api(respuesta, 422) and b'aria-invalid="true"' in respuesta[2]
             and ERROR_TEXTO.encode() in respuesta[2] and b">\ncon\x00nul</textarea>" in respuesta[2], control)
    negativo(f"r) el mensaje con NUL no se guarda ({antes} -> {despues})", antes is not None and despues == antes, control)


def seccion_t():
    # El mismo criterio que el camino anónimo de /v1 (docs/threat-model.md, 6.5,
    # y verificar_denuncia.py, l): cada línea de log lleva la hora, y la hora
    # junto a una denuncia desharía la fecha redondeada al día. De j) a r) solo
    # hay uso normal y rechazos sin fallo del servidor: no debe quedar ninguna.
    p("=== t) logs del camino anonimo por /web")
    if LINEAS_API is None or not CODIGO:
        sinc("t) faltan la cuenta de lineas de i) o el codigo de l)")
        return
    nuevas = log_de("api").splitlines()[LINEAS_API:]
    buscadas = {
        "el texto de la denuncia": TEXTO_HTML,
        "el texto del mensaje": "hola desde la web",
        "el texto del envio de otro sitio": "denuncia enviada desde otro sitio",
        "el codigo": CODIGO,
        "el codigo sin guiones": CODIGO.replace("-", ""),
        "el identificador de la empresa": IDENTIFICADOR,
    }

    def encontradas():
        logs = {s: log_de(s) for s in ("api", "postgres", "caddy")}
        return sorted({f"{n} en {s}" for n, v in buscadas.items() for s, t in logs.items() if v in t})
    halladas = encontradas()
    # Control: una línea testigo escrita en el log de la API aparece como línea
    # nueva y se encuentra al buscar. Demuestra que la cuenta y la búsqueda
    # leen el log de verdad y ven lo que se añade.
    testigo = f"testigo-{secrets.token_hex(8)}"
    buscadas["testigo"] = testigo
    dc("exec", "-T", "api", "sh", "-c", f"echo {testigo} > /proc/1/fd/1")
    control = esperar(lambda: "testigo en api" in encontradas()
                      and testigo in log_de("api").splitlines()[LINEAS_API + len(nuevas):], 10)
    pasa(control, "t) control: una linea testigo en el log de la API se ve como nueva y se encuentra")
    negativo(f"t) de j) a r) el camino /web no deja ninguna linea en el log de la API ({len(nuevas)} nuevas)",
             nuevas == [], control, f"lineas nuevas: {nuevas}")
    negativo(f"t) ni los textos, ni el codigo, ni el identificador aparecen en los logs de la API, PostgreSQL y "
             f"Caddy {halladas if halladas else ''}".strip(), not halladas, control)


# ---------------------------------------------------------------------------
# Limpieza, precondiciones y arranque
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
    return [l.rstrip() for l in r.out.splitlines() if l.strip()]


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
    TEMPORAL = pathlib.Path(tempfile.mkdtemp(prefix="canario_web_"))
    parada = None
    try:
        seccion_a()
        for seccion in (seccion_b, seccion_c, seccion_d, seccion_e, seccion_f, seccion_g, seccion_h,
                        seccion_i, seccion_j, seccion_k, seccion_l, seccion_m, seccion_n, seccion_o, seccion_p,
                        seccion_q, seccion_r, seccion_t):
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
    if parada is not None:
        estado["falla"] = True
    terminar()


if __name__ == "__main__":
    main()
