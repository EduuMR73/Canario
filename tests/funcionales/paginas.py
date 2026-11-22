"""Objetos de página de las pruebas funcionales (F1), sin jerarquía.

Denunciante8444 es el sitio sin JavaScript del denunciante (app/plantillas/);
PersonalSpa, la SPA del personal en el 8445 (spa/src/app/). Los selectores son
los reales, los mismos que usa tests/security/verificar_spa.py.

Las comprobaciones devuelven bool y las pruebas las afirman con un mensaje
literal (ok = ...; assert ok, "..."): un mensaje de fallo nunca lleva datos de
la ejecución (códigos, contraseñas, enlaces ni textos), porque acaba en el
informe HTML.

Aquí viven también, porque las usan conftest.py y las pruebas a la vez, el
TOTP de la prueba con su memoria de pasos, la excepción SinConclusion, concluir()
(la regla "control fallido: SIN CONCLUSION") y paso(), que traduce los errores
de Playwright.
"""
import base64
import contextlib
import hashlib
import hmac
import time

from playwright.sync_api import Error as ErrorPlaywright

WEB = "https://localhost:8444"
SPA = "https://localhost:8445"
# Los únicos orígenes a los que puede ir un contexto (conftest.py): todo lo
# demás se aborta.
ORIGENES_PERMITIDOS = frozenset({WEB, SPA})

CODIGO = "Código de autenticación"
CLAVE_OCULTA = "¿No puede escanear el código QR?"
PASO_CODIGO = "Paso 2 de 2: configure la aplicación de autenticación"


class SinConclusion(Exception):
    """Un control positivo ha fallado: la prueba no demuestra nada. Distinta
    de un skip: conftest.py la traduce a SIN CONCLUSION, la cuenta aparte e
    impide el OK."""


class FalloPaso(AssertionError):
    """Un paso del circuito no se pudo completar en el navegador."""


def concluir(control_ok, resultado_ok, mensaje):
    """Prueba negativa con control positivo: si el control falla, la prueba no
    demuestra nada y es SIN CONCLUSION (aunque el resultado también falle);
    solo con el control en verde cuenta el resultado. El mensaje es un literal,
    sin datos de la ejecución."""
    if not control_ok:
        raise SinConclusion(f"{mensaje}: el control positivo falló")
    assert resultado_ok, mensaje


@contextlib.contextmanager
def paso(descripcion):
    """Traduce un error de Playwright a un fallo con un texto literal. El
    mensaje de Playwright puede llevar la URL (con el token de activación en
    el fragmento) o lo que había en la página, y acabaría en el informe HTML.
    from None: tampoco se muestra la excepción original. El diagnóstico está
    en las trazas, que no se publican."""
    try:
        yield
    except ErrorPlaywright as error:
        raise FalloPaso(f"falla el paso: {descripcion} ({type(error).__name__})") from None


# ---------------------------------------------------------------------------
# TOTP propio de la prueba (RFC 6238 sobre RFC 4226), independiente de
# app/cripto.py, con memoria del último paso usado por cada secreto: un código
# vale una sola vez, así que login, invitación y logins posteriores nunca
# repiten paso. La memoria es del proceso: conftest.py y las pruebas importan
# este mismo módulo.
# ---------------------------------------------------------------------------
_usados = {}


def totp(secreto, paso_tiempo, digitos=6):
    mac = hmac.new(base64.b32decode(secreto), paso_tiempo.to_bytes(8, "big"), hashlib.sha1).digest()
    o = mac[-1] & 0x0F
    return f"{(int.from_bytes(mac[o:o + 4], 'big') & 0x7FFFFFFF) % 10 ** digitos:0{digitos}d}"


def codigo_de(secreto):
    while True:
        actual = int(time.time()) // 30
        if actual > _usados.get(secreto, -1):
            _usados[secreto] = actual
            return totp(secreto, actual)
        time.sleep(30 - time.time() % 30 + 0.5)


def normalizado(texto):
    """Espacios en blanco seguidos como uno solo, sin los de los extremos."""
    return " ".join((texto or "").split())


class Denunciante8444:
    """El denunciante en el 8444, en un contexto sin JavaScript: los
    formularios se envían de forma nativa y cada envío es una navegación."""

    def __init__(self, pagina):
        self.pagina = pagina
        # La última respuesta de navegación, para comparar su cuerpo (F2).
        self.respuesta = None

    def _enviar(self):
        # El estado HTTP de la respuesta que pinta la página nueva.
        with self.pagina.expect_navigation() as navegacion:
            self.pagina.click("main form button[type=submit]")
        self.respuesta = navegacion.value
        return -1 if self.respuesta is None else self.respuesta.status

    def abrir_formulario(self, identificador):
        respuesta = self.pagina.goto(f"{WEB}/empresas/{identificador}")
        return -1 if respuesta is None else respuesta.status

    def presentar(self, categoria, texto):
        self.pagina.select_option("#categoria", categoria)
        self.pagina.fill("#texto", texto)
        return self._enviar()

    def elegir_categoria(self, categoria):
        self.pagina.select_option("#categoria", categoria)

    def escribir_texto(self, texto):
        self.pagina.fill("#texto", texto)

    def pulsar_enviar(self):
        """Pulsa "Enviar" sin esperar una navegación: si la validación del
        navegador bloquea el envío, no hay ninguna."""
        self.pagina.click("main form button[type=submit]")

    def url(self):
        return self.pagina.url

    def campo_invalido(self, campo):
        """Exactamente un elemento con ese id y aria-invalid="true"."""
        return self.pagina.locator(f'#{campo}[aria-invalid="true"]').count() == 1

    def alerta_visible(self):
        """Exactamente un role="alert" en el contenido principal, y visible."""
        alertas = self.pagina.locator("main [role=alert]")
        return alertas.count() == 1 and alertas.first.is_visible()

    def alerta_contiene(self, literal):
        return literal in normalizado(self.pagina.locator("main [role=alert]").first.text_content())

    def error_codigo_es(self, literal):
        """El mensaje unido al campo del código (#error-codigo), entero."""
        error = self.pagina.locator("#error-codigo")
        return error.count() == 1 and normalizado(error.text_content()) == literal

    def cuerpo_ultima_respuesta(self):
        return self.respuesta.body()

    def h1_es(self, literal):
        return normalizado(self.pagina.locator("main h1").text_content()) == literal

    def codigo_mostrado(self):
        return self.pagina.locator(".codigo code").text_content().strip()

    def consultar(self, codigo):
        self.pagina.goto(f"{WEB}/seguimiento")
        self.pagina.fill("#codigo", codigo)
        return self._enviar()

    def estado_es(self, literal):
        # El <dd> que sigue al <dt> "Estado" de la ficha
        # (app/plantillas/expediente.html), no "aparece en la página".
        terminos = [normalizado(t) for t in self.pagina.locator("dl.ficha > dt").all_text_contents()]
        valores = [normalizado(v) for v in self.pagina.locator("dl.ficha > dd").all_text_contents()]
        if terminos.count("Estado") != 1 or len(terminos) != len(valores):
            return False
        return valores[terminos.index("Estado")] == literal

    def tiene_mensaje(self, autor, texto):
        # Un <li> de ol.mensajes con ese autor en su cabecera y ese texto,
        # entero, en su bloque de texto.
        for elemento in self.pagina.locator("ol.mensajes > li").all():
            quien = normalizado(elemento.locator("p.mensaje-cabecera strong").text_content())
            if quien == autor and elemento.locator("div.texto").text_content() == texto:
                return True
        return False

    def escribir(self, texto):
        self.pagina.fill("#texto", texto)
        return self._enviar()

    def aviso_es(self, literal):
        avisos = [normalizado(a) for a in self.pagina.locator("main p.aviso[role=status]").all_text_contents()]
        return avisos == [literal]

    def campo_mensaje_vacio(self):
        return self.pagina.locator("#texto").input_value() == ""


class PersonalSpa:
    """Una cuenta del personal en la SPA del 8445, en su propio contexto (con
    sus cookies)."""

    def __init__(self, pagina):
        self.pagina = pagina

    def activar_hasta_secreto(self, enlace, contrasena):
        """Primer paso de la activación: la contraseña. Devuelve el secreto
        TOTP tal como se muestra (agrupado), para registrarlo antes de seguir."""
        self.pagina.goto(enlace)
        self.pagina.get_by_label("Contraseña", exact=True).fill(contrasena)
        self.pagina.get_by_label("Repita la contraseña").fill(contrasena)
        self.pagina.get_by_role("button", name="Continuar", exact=True).click()
        self.pagina.get_by_role("heading", name=PASO_CODIGO).wait_for()
        self.pagina.get_by_text(CLAVE_OCULTA, exact=True).click()
        return self.pagina.locator("#activacion-secreto").inner_text()

    def terminar_activacion(self, secreto):
        self.pagina.get_by_label(CODIGO).fill(codigo_de(secreto))
        self.pagina.get_by_role("button", name="Activar la cuenta", exact=True).click()
        self.pagina.get_by_role("heading", name="Cuenta activada").wait_for()

    def entrar(self, identificador, email, contrasena, secreto):
        self.pagina.goto(f"{SPA}/entrar")
        self.pagina.get_by_label("Empresa").fill(identificador)
        self.pagina.get_by_label("Email").fill(email)
        self.pagina.get_by_label("Contraseña", exact=True).fill(contrasena)
        self.pagina.get_by_label(CODIGO).fill(codigo_de(secreto))
        self.pagina.get_by_role("button", name="Entrar", exact=True).click()
        self.pagina.wait_for_url(f"{SPA}/inicio")
        self.pagina.locator(".quien-email").wait_for()

    def ir_por_menu(self, texto):
        # Espera al h1 de la página pedida (en Denuncias y Cuentas es el
        # texto del menú) y no a cualquier h1: el de la página anterior
        # seguiría a la vista y la tabla leída sería la de antes.
        self.pagina.get_by_role("navigation", name="Principal").get_by_role("link", name=texto, exact=True).click()
        self.pagina.locator("main").get_by_role("heading", level=1, name=texto, exact=True).wait_for()

    def invitar(self, email, rol, secreto):
        """Invita una cuenta desde Cuentas y devuelve el enlace de activación
        que muestra la página (#cuentas-enlace)."""
        self.pagina.get_by_label("Email").fill(email)
        self.pagina.get_by_label("Rol", exact=True).select_option(rol)
        # Por su id: con una confirmación abierta en la tabla habría dos
        # campos "Código de autenticación".
        self.pagina.locator("#cuentas-invitar-codigo").fill(codigo_de(secreto))
        self.pagina.get_by_role("button", name="Invitar", exact=True).click()
        self.pagina.get_by_role("heading", name="Enlace de activación para " + email).wait_for()
        return self.pagina.locator("#cuentas-enlace").inner_text().strip()

    def ids_del_listado(self):
        self.pagina.locator("tbody th[scope=row]").first.wait_for()
        return [normalizado(t) for t in self.pagina.locator("tbody th[scope=row]").all_inner_texts()]

    def asignar(self, denuncia_id, email):
        """Asigna desde el listado y devuelve el aviso #denuncias-hecho."""
        self.pagina.get_by_label("Asignar la denuncia " + denuncia_id + " a", exact=True).select_option(label=email)
        self.pagina.get_by_role("button", name="Asignar la denuncia " + denuncia_id, exact=True).click()
        aviso = self.pagina.locator("#denuncias-hecho")
        aviso.wait_for()
        return normalizado(aviso.inner_text())

    def abrir_expediente(self, denuncia_id):
        """Desde el listado: el enlace de la denuncia y "Abrir el expediente",
        que es lo que la lee (la página sola no lee nada)."""
        enlace = self.pagina.get_by_role("link", name="Ir a la denuncia " + denuncia_id, exact=True)
        enlace.wait_for()
        enlace.click()
        self.pagina.get_by_role("button", name="Abrir el expediente", exact=True).click()
        self.pagina.locator("#expediente-texto").wait_for()

    def texto_denuncia_es(self, literal):
        return self.pagina.locator("#expediente-texto").text_content() == literal

    def enviar_mensaje(self, texto):
        """Devuelve el aviso #expediente-hecho tras el envío."""
        self.pagina.get_by_label("Mensaje para el denunciante", exact=True).fill(texto)
        self.pagina.get_by_role("button", name="Enviar el mensaje", exact=True).click()
        aviso = self.pagina.locator("#expediente-hecho")
        aviso.wait_for()
        return normalizado(aviso.inner_text())

    def cambiar_estado(self, destino, aviso_anterior):
        """Cambia el estado y devuelve el aviso nuevo: el de la acción
        anterior sigue a la vista hasta que llega el siguiente."""
        self.pagina.get_by_label("Estado nuevo", exact=True).select_option(destino)
        self.pagina.get_by_role("button", name="Cambiar el estado", exact=True).click()
        self.pagina.wait_for_function(
            "([s, a]) => { const e = document.querySelector(s); return e !== null && e.textContent.trim() !== a; }",
            arg=["#expediente-hecho", aviso_anterior])
        return normalizado(self.pagina.locator("#expediente-hecho").inner_text())

    def estado_es(self, literal):
        return normalizado(self.pagina.locator("#expediente-estado").inner_text()) == literal

    def tiene_mensaje(self, autor, texto):
        # Un <li> de .mensajes con "· autor ·" en su cabecera
        # (spa/src/app/denuncias/contenido.ts) y ese texto, entero, en su
        # bloque de texto libre.
        for elemento in self.pagina.locator(".mensajes > li").all():
            cabecera = normalizado(elemento.locator("p.mensaje-cabecera").inner_text())
            if f" · {autor} · " in cabecera and elemento.locator("p.texto-libre").text_content() == texto:
                return True
        return False
