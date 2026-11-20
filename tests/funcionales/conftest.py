"""Fixtures y hooks de las pruebas funcionales. Se ejecuta DENTRO del
contenedor de Playwright que lanza tests/funcionales/lanzar.py; no en el host.

Lo que hay en el contenedor (lanzar.py):
* /pruebas: este directorio, de solo lectura;
* /datos/datos.json, de solo lectura: el identificador público de la empresa
  y el token de invitación de su admin. El token va en un fichero montado, y
  nunca en la línea de órdenes ni en variables de entorno, donde lo vería
  docker inspect;
* /salida, con escritura: el informe HTML, resumen.json, secretos.json y las
  trazas si algo falla.

Con la API síncrona de Playwright y fixtures propias (sin pytest-playwright).
"""
import json
import os
import pathlib
import re
import secrets
import urllib.parse

import pytest
from paginas import (
    ORIGENES_PERMITIDOS,
    SPA,
    PersonalSpa,
    SinConclusion,
    paso,
    totp,
)
from playwright.sync_api import Error as ErrorPlaywright
from playwright.sync_api import sync_playwright

DATOS = pathlib.Path("/datos/datos.json")
SALIDA = pathlib.Path("/salida")
SECRETOS = SALIDA / "secretos.json"
RESUMEN = SALIDA / "resumen.json"
TRAZAS = SALIDA / "trazas"

# El mismo literal que EMAIL_ADMIN de lanzar.py, que da de alta al admin con
# gestion. No es un secreto: si no coincidieran, el login fallaría a la vista.
EMAIL_ADMIN = "admin@funcionales.test"
EMAIL_INSTRUCTORA = "instructora@funcionales.test"
PATRON_ENLACE = re.compile(r"https://localhost:8445/activacion#[0-9a-f]{32}\.[A-Za-z0-9_-]{43}")
# Vector de RFC 6238 (apéndice B, SHA-1, T = 59 s): la clave ASCII
# "12345678901234567890" en base32 y el código de 8 cifras.
VECTOR_RFC6238 = ("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59 // 30, "94287082")
# La petición del control del filtro de orígenes: .invalid no se resuelve
# nunca (RFC 6761), así que aunque el filtro fallara no saldría nada.
URL_CONTROL_FILTRO = "https://ejemplo.invalid/control-del-filtro"
# El centinela del control positivo del escáner anti-fuga de lanzar.py: un
# valor aleatorio que se registra como secreto y se escribe a propósito en el
# informe. Si el escáner no lo encuentra, no habría encontrado un secreto de
# verdad: SIN CONCLUSION.
CENTINELA = "centinela-" + secrets.token_hex(16)
ELEMENTO_CENTINELA = f'<p id="centinela-antifuga">{CENTINELA}</p>'

_secretos = {}
_resultados = {"pasadas": set(), "fallidas": set(), "sin_conclusion": set(), "saltadas": set(),
               "xfail": set(), "xpass": set(), "errores_coleccion": 0, "recogidas": 0}


def _escribir_json(ruta, contenido):
    # Escritura atómica: lanzar.py nunca lee un fichero a medias.
    temporal = ruta.with_name(ruta.name + ".tmp")
    temporal.write_text(json.dumps(contenido, ensure_ascii=False), encoding="utf-8")
    os.replace(temporal, ruta)


def registrar(nombre, *valores):
    """Anota en /salida/secretos.json cada secreto de la ejecución, en todas
    las formas en que puede aparecer, en cuanto existe y antes de usarlo: si
    la prueba se corta después, el escáner de lanzar.py lo busca igual. El
    host lo lee, lo usa y lo borra; nunca se publica."""
    lista = _secretos.setdefault(nombre, [])
    for valor in valores:
        if valor and valor not in lista:
            lista.append(valor)
    _escribir_json(SECRETOS, _secretos)


def formas_totp(mostrado):
    """El secreto TOTP tal como se muestra, sin espacios y agrupado de cuatro
    en cuatro."""
    limpio = "".join(mostrado.split())
    agrupado = " ".join(limpio[i:i + 4] for i in range(0, len(limpio), 4))
    return [mostrado.strip(), limpio, agrupado]


# ---------------------------------------------------------------------------
# Opciones, informe HTML y resumen
# ---------------------------------------------------------------------------
def pytest_addoption(parser):
    # El SPKI de la CA intermedia de Caddy: público, va por argv.
    parser.addoption("--spki", action="store", required=True,
                     help="SHA-256 en base64 del SPKI de la CA intermedia de Caddy")


def pytest_configure(config):
    registrar("centinela", CENTINELA)


def pytest_html_report_title(report):
    report.title = "Canario: pruebas funcionales (F1, Chromium)"


def pytest_html_results_summary(prefix, summary, postfix, session):
    # pytest-html 4.2.0 pinta cada elemento de postfix tal cual
    # (resources/index.jinja2: {{ p|safe }}), así que el centinela queda
    # literal en el HTML. lanzar.py lo busca y genera el informe publicable
    # sin este elemento.
    postfix.append(ELEMENTO_CENTINELA)


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item, call):
    informe = yield
    # SIN CONCLUSION no es un skip (que devuelve 0) ni un fallo corriente: se
    # marca como fallo, para que pytest nunca lo dé por bueno, y se cuenta
    # aparte. El texto es el de la excepción, que es literal.
    if call.excinfo is not None and call.excinfo.errisinstance(SinConclusion):
        informe.outcome = "failed"
        informe.longrepr = f"SIN CONCLUSION: {call.excinfo.value}"
        informe.user_properties.append(("sin_conclusion", True))
    return informe


def pytest_collectreport(report):
    if report.failed:
        _resultados["errores_coleccion"] += 1


def pytest_collection_finish(session):
    _resultados["recogidas"] = len(session.items)


def pytest_runtest_logreport(report):
    nodo = report.nodeid
    if report.failed:
        if ("sin_conclusion", True) in report.user_properties:
            _resultados["sin_conclusion"].add(nodo)
        else:
            _resultados["fallidas"].add(nodo)
    elif report.skipped:
        _resultados["xfail" if hasattr(report, "wasxfail") else "saltadas"].add(nodo)
    elif report.when == "call":
        _resultados["xpass" if hasattr(report, "wasxfail") else "pasadas"].add(nodo)


def pytest_sessionfinish(session, exitstatus):
    """Escribe /salida/resumen.json. Un skip, un xfail o un SIN CONCLUSION
    impiden el OK: pytest devuelve 0 con un skip y con un xfail, así que aquí
    se fuerza el código 1."""
    r = _resultados
    no_concluyentes = r["sin_conclusion"] | r["fallidas"]
    resumen = {
        "recogidas": r["recogidas"],
        "pasadas": len(r["pasadas"] - no_concluyentes),
        "fallidas": len(r["fallidas"]),
        "sin_conclusion": len(r["sin_conclusion"] - r["fallidas"]),
        "saltadas": len(r["saltadas"]),
        "xfail": len(r["xfail"]),
        "xpass": len(r["xpass"]),
        "errores_coleccion": r["errores_coleccion"],
    }
    impiden = resumen["sin_conclusion"] + resumen["saltadas"] + resumen["xfail"] + resumen["xpass"]
    if impiden and session.exitstatus == 0:
        session.exitstatus = 1
    resumen["codigo_salida"] = int(session.exitstatus)
    _escribir_json(RESUMEN, resumen)


# ---------------------------------------------------------------------------
# Navegador y contextos
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def datos():
    contenido = json.loads(DATOS.read_text(encoding="utf-8"))
    return {"identificador": contenido["identificador"], "token_admin": contenido["token_admin"]}


@pytest.fixture(scope="session")
def navegador(pytestconfig):
    # Chromium confía en el certificado de Caddy por el SPKI de su CA
    # intermedia, que es lo que Caddy envía (verificar_spa.py, g): no se
    # desactiva la verificación TLS entera.
    spki = pytestconfig.getoption("spki")
    with sync_playwright() as pw:
        chromium = pw.chromium.launch(args=[f"--ignore-certificate-errors-spki-list={spki}"])
        yield chromium
        chromium.close()


def _origen(url):
    partes = urllib.parse.urlsplit(url)
    return f"{partes.scheme}://{partes.netloc}".lower()


@pytest.fixture(scope="session")
def nuevo_contexto(navegador, request):
    """Fábrica única de contextos: todos pasan por aquí. Cada contexto:
    * aborta toda petición que no vaya a https://localhost:8444 o :8445, con
      un control positivo al crearlo (una petición a otro origen debe pasar
      por el filtro y abortarse; si no, SIN CONCLUSION). Así ningún dato de la
      prueba sale de la pila aunque una página lo intentara;
    * graba una traza de Playwright que solo se guarda si algo falla, en
      /salida/trazas (lleva códigos, contraseñas y textos: no se publica)."""
    creados = []

    def crear(nombre, javascript=True):
        contexto = navegador.new_context(java_script_enabled=javascript)
        abortadas = []

        def filtrar(ruta):
            url = ruta.request.url
            if _origen(url) in ORIGENES_PERMITIDOS:
                ruta.continue_()
            else:
                abortadas.append(url)
                ruta.abort()

        contexto.route("**/*", filtrar)
        pagina = contexto.new_page()
        try:
            pagina.goto(URL_CONTROL_FILTRO)
            cargada = True
        except ErrorPlaywright:
            cargada = False
        pagina.close()
        # La petición tiene que haber pasado por el filtro y haberse
        # abortado: que solo falle la carga no basta (.invalid falla igual).
        if cargada or abortadas != [URL_CONTROL_FILTRO]:
            contexto.close()
            raise SinConclusion("el filtro de orígenes del contexto no abortó la petición de control")
        contexto.tracing.start(screenshots=True, snapshots=True)
        creados.append((nombre, contexto))
        return contexto

    yield crear

    # Al cerrar la sesión, después de la última prueba: con algún fallo (o un
    # SIN CONCLUSION, que cuenta como fallo), cada contexto guarda su traza.
    fallo = request.session.testsfailed > 0
    for nombre, contexto in creados:
        try:
            if fallo:
                TRAZAS.mkdir(exist_ok=True)
                contexto.tracing.stop(path=str(TRAZAS / f"{nombre}.zip"))
            else:
                contexto.tracing.stop()
        finally:
            contexto.close()


@pytest.fixture(scope="session")
def registrar_secreto():
    return registrar


@pytest.fixture(scope="session")
def cuentas(datos, nuevo_contexto):
    """Prepara las cuentas dentro del contenedor: activa al admin con su
    token, le pone contraseña, entra, invita a una instructora (enlace leído
    del DOM, #cuentas-enlace) y la activa y la hace entrar en otro contexto.
    Cada secreto se registra antes de usarlo."""
    ok = totp(VECTOR_RFC6238[0], VECTOR_RFC6238[1], 8) == VECTOR_RFC6238[2]
    if not ok:
        raise SinConclusion("el TOTP de la prueba no cumple el vector de RFC 6238")
    identificador = datos["identificador"]
    registrar("token_admin", datos["token_admin"], f"{SPA}/activacion#{datos['token_admin']}")

    # Contraseñas aleatorias de cada ejecución (token_urlsafe: solo
    # [A-Za-z0-9_-], que ningún escapado HTML ni JSON cambia).
    contrasena_admin = secrets.token_urlsafe(18)
    registrar("contrasena_admin", contrasena_admin)
    admin = PersonalSpa(nuevo_contexto("admin").new_page())
    with paso("el admin abre su enlace de activación y elige contraseña"):
        mostrado = admin.activar_hasta_secreto(f"{SPA}/activacion#{datos['token_admin']}", contrasena_admin)
    registrar("totp_admin", *formas_totp(mostrado))
    secreto_admin = "".join(mostrado.split())
    with paso("el admin termina la activación con su código TOTP"):
        admin.terminar_activacion(secreto_admin)
    with paso("el admin entra con contraseña y TOTP"):
        admin.entrar(identificador, EMAIL_ADMIN, contrasena_admin, secreto_admin)
    with paso("el admin invita a la instructora"):
        admin.ir_por_menu("Cuentas")
        enlace = admin.invitar(EMAIL_INSTRUCTORA, "instructor", secreto_admin)
    registrar("enlace_instructora", enlace, enlace.split("#", 1)[-1])
    ok = PATRON_ENLACE.fullmatch(enlace) is not None
    assert ok, "el enlace de activación de la instructora no tiene la forma esperada"

    contrasena_instructora = secrets.token_urlsafe(18)
    registrar("contrasena_instructora", contrasena_instructora)
    instructora = PersonalSpa(nuevo_contexto("instructora").new_page())
    with paso("la instructora abre su enlace de activación y elige contraseña"):
        mostrado = instructora.activar_hasta_secreto(enlace, contrasena_instructora)
    registrar("totp_instructora", *formas_totp(mostrado))
    secreto_instructora = "".join(mostrado.split())
    with paso("la instructora termina la activación con su código TOTP"):
        instructora.terminar_activacion(secreto_instructora)
    with paso("la instructora entra con contraseña y TOTP"):
        instructora.entrar(identificador, EMAIL_INSTRUCTORA, contrasena_instructora, secreto_instructora)
    return {"identificador": identificador, "admin": admin, "instructora": instructora,
            "email_instructora": EMAIL_INSTRUCTORA}
