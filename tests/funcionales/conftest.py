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

El motor (chromium, firefox o webkit) lo elige --motor: lanzar.py lanza pytest
una vez por motor, cada uno en su contenedor y con su propia salida.
"""
import base64
import json
import os
import pathlib
import re
import secrets
import shutil
import urllib.parse

import pytest
from paginas import (
    ORIGENES_PERMITIDOS,
    SPA,
    WEB,
    PersonalSpa,
    SinConclusion,
    paso,
    totp,
)
from playwright.sync_api import Error as ErrorPlaywright
from playwright.sync_api import TimeoutError as ErrorTiempo
from playwright.sync_api import sync_playwright

DATOS = pathlib.Path("/datos/datos.json")
SALIDA = pathlib.Path("/salida")
SECRETOS = SALIDA / "secretos.json"
RESUMEN = SALIDA / "resumen.json"
TRAZAS = SALIDA / "trazas"
# El humo de cada motor (lo que pasó antes de las pruebas y lo observado). No
# lleva secretos: solo datos públicos del certificado de Caddy y del motor.
HUMO = SALIDA / "humo.json"

MOTORES = ("chromium", "firefox", "webkit")
# Chromium confía en Caddy por el SPKI de su CA intermedia (argumento de
# lanzamiento, que solo existe en Chromium). Firefox y WebKit no tienen un
# mecanismo equivalente: ahí se usa ignore_https_errors, con los controles de
# identidad y el control negativo de más abajo.
ORIGEN_Y_PUERTO = {WEB: 8444, SPA: 8445}
# Direcciones con las que Playwright puede describir el servidor de localhost
# (server_addr()): cualquier otra es un FALLA visible, no se acepta en silencio.
DIRECCIONES_SERVIDOR = frozenset({"127.0.0.1", "[::1]", "::1"})
# El literal del error de certificado de cada motor sin ignore_https_errors. Lo
# observa el humo (humo.json, error_tls_observado) y se FIJA aquí a mano tras la
# primera ejecución. Mientras valga el marcador, el resultado es SIN CONCLUSION:
# no se inventa un literal que no se ha visto.
PENDIENTE_FIJAR = "PENDIENTE-FIJAR-TRAS-LA-PRIMERA-EJECUCION"
# Fijados el 22/11 con lo observado en la primera ejecución (humo.json de
# canario_funcionales_salida_42nw253m): son los errores de emisor desconocido
# de cada motor, no de plazo ni de conexión.
ERROR_TLS_ESPERADO = {"firefox": "SEC_ERROR_UNKNOWN_ISSUER", "webkit": "Unacceptable TLS certificate"}
# Preferencias de usuario de Firefox contra la actividad propia del navegador
# (telemetría, actualizaciones y portal cautivo). Se SUMAN a las que ya trae
# Playwright y no sustituyen ninguna. Lista literal: lo que no esté aquí no se
# toca. No evitan toda salida del contenedor (README, "Límites aceptados").
PREFS_FIREFOX = {
    "datareporting.healthreport.uploadEnabled": False,
    "datareporting.policy.dataSubmissionEnabled": False,
    "toolkit.telemetry.enabled": False,
    "toolkit.telemetry.unified": False,
    "toolkit.telemetry.archive.enabled": False,
    "app.update.enabled": False,
    "app.update.auto": False,
    "network.captive-portal-service.enabled": False,
    "network.connectivity-service.enabled": False,
}
# El tmpfs de /tmp mide 600m (lanzar.py): con el perfil del navegador y /tmp/pw
# ya escritos, no puede estar usado más de la mitad, para dejar sitio a las
# trazas (capturas y DOM de cada contexto) y al propio informe.
MARGEN_TMP = 2

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
_humo = {}
_estado = {"motor": "?"}
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


def _anotar_humo(clave, valor):
    """Añade un dato al humo y lo escribe en el acto: si la sesión se corta
    después, lanzar.py lo lee igual."""
    _humo[clave] = valor
    _escribir_json(HUMO, _humo)


def _parada_humo(motivo):
    """El humo falla: PARADA. No se ejecuta ninguna prueba (un navegador que no
    arranca en el contenedor endurecido no se arregla relajando el
    endurecimiento) y lanzar.py lo lee de humo.json. El motivo es un texto
    literal."""
    _anotar_humo("estado", "parada")
    _anotar_humo("motivo", motivo)
    pytest.exit(f"PARADA del humo: {motivo}", returncode=3)


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
    parser.addoption("--motor", action="store", required=True, choices=MOTORES,
                     help="motor del navegador: chromium, firefox o webkit")
    # Los datos públicos de la hoja que sirve Caddy en 8444 y 8445 (fechas y,
    # si lo lleva, el CN), leídos por lanzar.py con un handshake TLS desde el
    # host. JSON en base64 para que viaje por argv sin comillas.
    parser.addoption("--hojas", action="store", required=True,
                     help="JSON en base64 con validez y CN de la hoja de cada origen")


def pytest_configure(config):
    registrar("centinela", CENTINELA)
    _estado["motor"] = config.getoption("motor")
    _humo["motor"] = _estado["motor"]
    _humo["estado"] = "iniciado"
    _escribir_json(HUMO, _humo)
    config.addinivalue_line("markers", "motores(*nombres): motores en los que corre la prueba")


def pytest_collection_modifyitems(config, items):
    """Elige las pruebas del motor DESELECCIONANDO las demás, no con skip: un
    skip impide el OK (pytest_sessionfinish) y haría que ningún motor lo diera.
    Una prueba sin su marca motores es un error visible, no una prueba que
    nunca corre."""
    motor = config.getoption("motor")
    elegidas, descartadas = [], []
    for item in items:
        marca = item.get_closest_marker("motores")
        if marca is None or not marca.args or not set(marca.args) <= set(MOTORES):
            raise pytest.UsageError(f"{item.nodeid}: falta @pytest.mark.motores con motores válidos")
        (elegidas if motor in marca.args else descartadas).append(item)
    if descartadas:
        config.hook.pytest_deselected(items=descartadas)
    items[:] = elegidas


def pytest_html_report_title(report):
    report.title = f"Canario: pruebas funcionales (F1, F2 y F3, {_estado['motor']})"


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
    # token_admin es None en los motores que no corren F1 (webkit): no se da
    # de alta ningún admin que nadie vaya a usar, para no dejar un token vivo.
    return {"identificador": contenido["identificador"], "token_admin": contenido.get("token_admin")}


@pytest.fixture(scope="session")
def hojas(pytestconfig):
    """Validez y CN de la hoja que Caddy sirve en 8444 y 8445, por puerto."""
    try:
        valores = json.loads(base64.b64decode(pytestconfig.getoption("hojas"), validate=True))
        for puerto in ("8444", "8445"):
            hoja = valores[puerto]
            if not (isinstance(hoja["desde"], int) and isinstance(hoja["hasta"], int)
                    and (hoja["cn"] is None or isinstance(hoja["cn"], str))):
                raise ValueError("tipo")
    except (ValueError, KeyError, TypeError):
        raise pytest.UsageError("--hojas no es el JSON en base64 esperado") from None
    return valores


@pytest.fixture(scope="session")
def navegador(pytestconfig):
    """El navegador del motor, con su humo de arranque: launch, new_page y
    about:blank dentro del contenedor endurecido tal como está (sin
    --ipc=host, SYS_ADMIN, seccomp=unconfined ni root: relajarlo para que un
    motor arranque está prohibido). Si falla, PARADA."""
    motor = pytestconfig.getoption("motor")
    with sync_playwright() as pw:
        try:
            if motor == "chromium":
                # Chromium confía en el certificado de Caddy por el SPKI de su
                # CA intermedia, que es lo que Caddy envía (verificar_spa.py,
                # g): no se desactiva la verificación TLS entera.
                spki = pytestconfig.getoption("spki")
                lanzado = pw.chromium.launch(args=[f"--ignore-certificate-errors-spki-list={spki}"])
            elif motor == "firefox":
                lanzado = pw.firefox.launch(firefox_user_prefs=PREFS_FIREFOX)
            else:
                lanzado = pw.webkit.launch()
            # Fuera de la fábrica a propósito: about:blank no hace ninguna
            # petición de red, así que no hay nada que filtrar.
            contexto = lanzado.new_context()
            contexto.new_page().goto("about:blank")
            contexto.close()
        except ErrorPlaywright as error:
            _parada_humo(f"el motor {motor} no arranca en el contenedor endurecido ({type(error).__name__})")
        # Con el perfil ya creado y /tmp/pw instalado: lo usado en el tmpfs.
        uso = shutil.disk_usage("/tmp")
        _anotar_humo("tmp_usado_mb", uso.used // 2 ** 20)
        _anotar_humo("tmp_total_mb", uso.total // 2 ** 20)
        if uso.used * MARGEN_TMP > uso.total:
            _parada_humo("el perfil del navegador y /tmp/pw ocupan más de la mitad del tmpfs de /tmp")
        yield lanzado
        lanzado.close()


def _origen(url):
    partes = urllib.parse.urlsplit(url)
    return f"{partes.scheme}://{partes.netloc}".lower()


@pytest.fixture(scope="session")
def nuevo_contexto(navegador, hojas, pytestconfig, request):
    """Fábrica única de contextos: todos pasan por aquí. Cada contexto:
    * aborta toda petición que no vaya a https://localhost:8444 o :8445, con
      un control positivo al crearlo (una petición a otro origen debe pasar
      por el filtro y abortarse; si no, SIN CONCLUSION). Así ningún dato de la
      prueba sale de la pila aunque una página lo intentara;
    * bloquea los service workers: un service worker haría peticiones por su
      cuenta, fuera del page.route y del filtro de este contexto;
    * en Firefox y WebKit lleva ignore_https_errors, porque no tienen el SPKI
      de Chromium. Eso apaga la verificación TLS de ese contexto, así que la
      primera respuesta de cada origen se comprueba contra la hoja que sirve
      Caddy (comprobar_identidad) y el humo demuestra con un contexto sin el
      flag que, sin él, el motor sí rechaza el certificado;
    * graba una traza de Playwright que solo se guarda si algo falla, en
      /salida/trazas (lleva códigos, contraseñas y textos: no se publica).

    La función expone abortadas (por nombre de contexto) y
    comprobar_identidad."""
    motor = pytestconfig.getoption("motor")
    creados = []
    abortadas_por_contexto = {}
    pendientes = []  # (origen, respuesta): la primera de cada origen y contexto

    def crear(nombre, javascript=True, confiar_certificado=True):
        if nombre in abortadas_por_contexto:
            raise SinConclusion("dos contextos con el mismo nombre: sus peticiones abortadas se mezclarían")
        ignorar = motor != "chromium" and confiar_certificado
        contexto = navegador.new_context(java_script_enabled=javascript, service_workers="block",
                                         ignore_https_errors=ignorar)
        abortadas = []
        abortadas_por_contexto[nombre] = abortadas

        def filtrar(ruta):
            url = ruta.request.url
            if _origen(url) in ORIGENES_PERMITIDOS:
                ruta.continue_()
            else:
                abortadas.append(url)
                ruta.abort()

        contexto.route("**/*", filtrar)
        if ignorar:
            vistos = set()

            def observar(respuesta):
                # Solo se guarda la respuesta: security_details() y
                # server_addr() son llamadas al navegador y se hacen después,
                # fuera del manejador del evento.
                origen = _origen(respuesta.url)
                if origen in ORIGEN_Y_PUERTO and origen not in vistos:
                    vistos.add(origen)
                    pendientes.append((origen, respuesta))

            contexto.on("response", observar)
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

    def comprobar_identidad():
        """Control de identidad de los contextos con ignore_https_errors: la
        primera respuesta de cada origen trae la hoja que Caddy sirve (validez
        exacta y CN si la lleva) y viene de localhost en el puerto esperado.
        No se compara el emisor: WebKit en Linux no lo da (Playwright,
        har.spec.ts). Límite: el control no es criptográfico (README). Sin
        security_details() o sin dirección, SIN CONCLUSION; con otra hoja u
        otra dirección, FALLA."""
        sin_datos, fallos = False, False
        while pendientes:
            origen, respuesta = pendientes.pop(0)
            puerto = ORIGEN_Y_PUERTO[origen]
            hoja = hojas[str(puerto)]
            try:
                detalles = respuesta.security_details()
                direccion = respuesta.server_addr()
            except ErrorPlaywright:
                sin_datos = True
                continue
            _anotar_humo(f"identidad_observada_{puerto}", {"security_details": detalles, "server_addr": direccion})
            if not detalles or not direccion or detalles.get("validFrom") is None or detalles.get("validTo") is None:
                sin_datos = True
                continue
            if int(detalles["validFrom"]) != hoja["desde"] or int(detalles["validTo"]) != hoja["hasta"]:
                fallos = True
            if hoja["cn"] is not None and detalles.get("subjectName") != hoja["cn"]:
                fallos = True
            if direccion.get("ipAddress") not in DIRECCIONES_SERVIDOR or direccion.get("port") != puerto:
                fallos = True
        if sin_datos:
            raise SinConclusion("security_details() o server_addr() no devolvieron datos: no se pudo comprobar "
                                "la identidad de la hoja")
        assert not fallos, ("la hoja o la dirección del servidor no son las de Caddy en localhost "
                            "(valores observados en humo.json)")

    crear.abortadas = abortadas_por_contexto
    crear.comprobar_identidad = comprobar_identidad
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


@pytest.fixture(scope="session", autouse=True)
def humo(navegador, nuevo_contexto, pytestconfig):
    """Humo del motor antes de las pruebas (autouse: va primero). Con un
    contexto de la fábrica carga el 8444 y comprueba que security_details()
    funciona aunque haya un filtro por medio. Si no, PARADA. En Firefox y
    WebKit, además, el control negativo de la confianza TLS: la misma URL, en
    un contexto de la fábrica SIN ignore_https_errors, tiene que fallar con el
    error de certificado fijado en ERROR_TLS_ESPERADO. Un fallo por otra causa
    (plazo, conexión rechazada o aborto del filtro) o un literal sin fijar es
    SIN CONCLUSION."""
    motor = pytestconfig.getoption("motor")
    url = f"{WEB}/"
    con_bandera = nuevo_contexto("humo_con_bandera")
    pagina = con_bandera.new_page()
    try:
        respuesta = pagina.goto(url)
        estado = -1 if respuesta is None else respuesta.status
        detalles = None if respuesta is None else respuesta.security_details()
    except ErrorPlaywright as error:
        _parada_humo(f"el humo no carga {url} en {motor} ({type(error).__name__})")
    # La respuesta del humo queda en las pendientes del control de identidad
    # (en Firefox y WebKit el contexto lleva ignore_https_errors). Se comprueba
    # aquí, con la página viva: con la página ya cerrada, security_details()
    # no devuelve datos y la primera prueba del motor daba SIN CONCLUSION en su
    # teardown. Así además la hoja del humo se compara de verdad con la de Caddy.
    nuevo_contexto.comprobar_identidad()
    pagina.close()
    # Este es también el control positivo del negativo: la misma URL, con el
    # flag (o el SPKI en Chromium), carga.
    if estado != 200:
        _parada_humo("el humo no carga el 8444 con la confianza TLS del motor (se esperaba 200)")
    if detalles is None:
        _parada_humo("security_details() devuelve None con el filtro de la fábrica: el control de identidad "
                     "no se puede hacer")
    _anotar_humo("security_details_ok", True)
    if motor == "chromium":
        _anotar_humo("estado", "ok")
        return

    sin_bandera = nuevo_contexto("humo_sin_bandera", confiar_certificado=False)
    # La fábrica ya dejó en la lista la URL de su control positivo del filtro
    # (siempre está). Solo cuentan las abortadas DESPUÉS de este punto: si no,
    # el control negativo de TLS daría SIN CONCLUSION en todas las ejecuciones
    # y nunca llegaría a comparar el error de certificado.
    abortadas_antes = len(nuevo_contexto.abortadas["humo_sin_bandera"])
    pagina = sin_bandera.new_page()
    try:
        pagina.goto(url)
        error = None
    except ErrorTiempo:
        error = "plazo"
    except ErrorPlaywright as e:
        error = str(e)
    pagina.close()
    observado = " | ".join(error.splitlines()[:3])[:400] if error else "carga sin error"
    _anotar_humo("error_tls_observado", observado)
    motivo = None
    if error is None:
        motivo = "sin ignore_https_errors el 8444 carga: no se demuestra que la verificación TLS esté activa"
    elif nuevo_contexto.abortadas["humo_sin_bandera"][abortadas_antes:]:
        motivo = "el filtro abortó la petición del control negativo de TLS: el fallo no es del certificado"
    elif ERROR_TLS_ESPERADO[motor] == PENDIENTE_FIJAR:
        motivo = (f"el literal del error de certificado de {motor} está pendiente de fijar "
                  "(error_tls_observado en humo.json)")
    elif error == "plazo" or ERROR_TLS_ESPERADO[motor] not in error:
        motivo = f"{motor} falla sin ignore_https_errors, pero no con el error de certificado fijado"
    if motivo is not None:
        _anotar_humo("estado", "sin_conclusion")
        _anotar_humo("motivo", motivo)
        raise SinConclusion(motivo)
    _anotar_humo("estado", "ok")


@pytest.fixture(autouse=True)
def identidad_tls(nuevo_contexto):
    """Después de cada prueba, comprueba la primera respuesta de cada origen
    de los contextos con ignore_https_errors (en Chromium no hay ninguna)."""
    yield
    nuevo_contexto.comprobar_identidad()


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
    if not datos["token_admin"]:
        raise SinConclusion("este motor no tiene admin dado de alta y la prueba pide cuentas del personal")
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
