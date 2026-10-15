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
* d) que la cabecera Cookie no llega a la API desde el 8444 (y sí desde el
  8443: control de que el eco la vería);
* e) que del backend solo pasa HTML: JSON, texto o sin tipo se convierten en
  la página de error del sitio, con su estado, Retry-After y Allow;
* f) las cabeceras de seguridad de las páginas reenviadas y de los errores;
* g) que /web no es alcanzable desde el 8443, con el mismo 404 que la API;
* h) el límite de cuerpo en el 8444.

La parte B (la pila entera con las páginas reales) llega con el adaptador HTML
de la API (app/rutas_web.py).

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
10.88.1.0/28 y los puertos 127.0.0.1:8443 y 127.0.0.1:8444 son fijos (si están
en uso, PARADA). Al terminar lo borra todo (down -v y las imágenes
construidas). No lee ningún secreto. Los ficheros auxiliares van a un
directorio temporal del sistema, nunca al repositorio. La salida completa se
guarda en verificacion_web.txt dentro del directorio temporal del sistema. El
código de salida es 0 solo si el resultado global es OK.

Solo usa la biblioteca estándar.
"""
import http.client
import json
import pathlib
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
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

# ---------------------------------------------------------------------------
# Aplicación de eco que sustituye a la API (se escribe en el directorio temporal)
# ---------------------------------------------------------------------------
ECO = r'''
import json

# Respuestas fijas para e): estado, tipo (None: sin Content-Type) y cabeceras.
CASOS = {
    "/web/prueba/json429": (429, b"application/json", [(b"retry-after", b"7")]),
    "/web/prueba/json405": (405, b"application/json", [(b"allow", b"POST")]),
    "/web/prueba/json200": (200, b"application/json", []),
    "/web/prueba/texto500": (500, b"text/plain; charset=utf-8", []),
    "/web/prueba/sintipo404": (404, None, []),
    "/web/prueba/html422": (422, b"text/html; charset=utf-8", []),
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


TEMPORAL = None
CA_LOCAL = None


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
    p("=== d) la cabecera Cookie no llega a la API desde el 8444")
    cabeceras = {"Cookie": "sesion=canario", "X-Prueba": "canario"}
    desde_api = eco_de(peticion("GET", "/eco", puerto=PUERTO_API, cabeceras=cabeceras)) or {}
    desde_web = eco_de(peticion("GET", "/seguimiento", cabeceras=cabeceras)) or {}
    # Control: el eco ve la Cookie cuando llega (por el 8443), y por el 8444 la
    # petición llega con el resto de cabeceras (X-Prueba).
    control = desde_api.get("cookie") == "sesion=canario" and desde_web.get("prueba") == "canario"
    negativo(f"d) por el 8444 la API no recibe Cookie ({desde_web.get('cookie')!r})",
             desde_web.get("cookie") is None, control, f"8443: {desde_api}; 8444: {desde_web}")


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
# Limpieza, precondiciones y arranque
# ---------------------------------------------------------------------------
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
    for puerto in (PUERTO_API, PUERTO_WEB):
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
        for seccion in (seccion_b, seccion_c, seccion_d, seccion_e, seccion_f, seccion_g, seccion_h):
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
