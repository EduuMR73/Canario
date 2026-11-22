"""F3: JavaScript desactivado de verdad en el contexto del denunciante, en
Chromium, Firefox y WebKit (docs/informe-pruebas.md, 2).

F1 y F2 usan un contexto con java_script_enabled=False, pero nada demuestra
que la opción haga lo que dice en cada motor. Aquí se prueba, en el MISMO
contexto que después usa el 8444, con una página de control servida por
page.route desde un host .invalid (sin CSP, que es lo que podría parar el
script por otra causa): lleva un marcador estático y un <script> en línea y
síncrono que añade un segundo marcador.

* Oráculo: en el contexto sin JavaScript está el marcador estático y NO el del
  script.
* Controles (si fallan, SIN CONCLUSION): el mismo script añade su marcador en
  un contexto con JavaScript; el marcador estático está en el contexto sin
  JavaScript (la página cargó); y cualquier otra petición de esa página sigue
  abortada por el filtro del contexto (el page.route solo sirve la URL exacta).
* Después, en ese mismo contexto, el denunciante presenta una denuncia y
  consulta con su código: sin JavaScript el sitio funciona.
"""
import re
import secrets

import pytest
from paginas import Denunciante8444, concluir, paso
from playwright.sync_api import Error as ErrorPlaywright

# Hosts .invalid: no se resuelven nunca (RFC 6761), así que aunque el filtro o
# el page.route fallaran, no saldría nada de la pila.
URL_CONTROL = "https://pagina-de-control.invalid/f3"
URL_OTRA = "https://pagina-de-control.invalid/otra-peticion"
MARCADOR_ESTATICO = "marcador-estatico"
MARCADOR_SCRIPT = "marcador-script"
# document.write en un script síncrono: el marcador existe en cuanto termina la
# carga si, y solo si, el script se ejecuta.
HTML_CONTROL = (
    '<!doctype html><html lang="es"><head><meta charset="utf-8"><title>control</title></head><body>'
    f'<p id="{MARCADOR_ESTATICO}">estatico</p>'
    f"<script>document.write('<p id=\"{MARCADOR_SCRIPT}\">script</p>');</script>"
    "</body></html>"
)

CATEGORIA = "fraude"
H1_CREADA = "Denuncia enviada"
H1_EXPEDIENTE_WEB = "Su denuncia"
ESTADO_WEB_RECIBIDA = "Recibida"
PATRON_CODIGO = re.compile(r"([A-Z2-7]{4}-){7}[A-Z2-7]{4}")


def servir_control(pagina):
    """Sirve la página de control con page.route (que va antes que el filtro
    del contexto) solo para la URL exacta."""
    pagina.route(URL_CONTROL, lambda ruta: ruta.fulfill(status=200, content_type="text/html; charset=utf-8",
                                                         body=HTML_CONTROL))


def marcadores(pagina):
    """(hay marcador estático, hay marcador del script), tras la carga."""
    return (pagina.locator(f"#{MARCADOR_ESTATICO}").count() == 1,
            pagina.locator(f"#{MARCADOR_SCRIPT}").count() == 1)


@pytest.mark.motores("chromium", "firefox", "webkit")
def test_f3_javascript_desactivado_de_verdad(datos, nuevo_contexto, registrar_secreto):
    identificador = datos["identificador"]

    # Control positivo: con JavaScript, el script añade su marcador.
    pagina_con_js = nuevo_contexto("f3_con_js", javascript=True).new_page()
    servir_control(pagina_con_js)
    with paso("carga la página de control en un contexto con JavaScript"):
        pagina_con_js.goto(URL_CONTROL)
        estatico_con_js, script_con_js = marcadores(pagina_con_js)

    # Dado el contexto del denunciante, sin JavaScript,
    contexto = nuevo_contexto("denunciante_f3", javascript=False)
    pagina = contexto.new_page()
    servir_control(pagina)
    with paso("carga la página de control en el contexto sin JavaScript"):
        pagina.goto(URL_CONTROL)
        estatico, script = marcadores(pagina)
    # Control del filtro: otra petición de esa misma página (otra URL, que el
    # page.route no sirve) sigue abortada, y la de control no se abortó.
    with paso("pide otra URL desde la página de control"):
        try:
            pagina.goto(URL_OTRA)
            cargo_otra = True
        except ErrorPlaywright:
            cargo_otra = False
    abortadas = nuevo_contexto.abortadas["denunciante_f3"]
    filtro_ok = (not cargo_otra and URL_OTRA in abortadas and URL_CONTROL not in abortadas)
    # entonces el marcador estático está y el del script no.
    concluir(estatico_con_js and script_con_js and estatico and filtro_ok, not script,
             "con JavaScript desactivado el script en línea añade su marcador")

    # Y en ese mismo contexto el denunciante usa el sitio: presenta y consulta.
    denunciante = Denunciante8444(contexto.new_page())
    with paso("el denunciante abre el formulario y presenta una denuncia"):
        denunciante.abrir_formulario(identificador)
        estado_http = denunciante.presentar(CATEGORIA, f"Denuncia de la prueba sin JavaScript {secrets.token_hex(8)}.")
        creada = estado_http == 201 and denunciante.h1_es(H1_CREADA)
        codigo = denunciante.codigo_mostrado() if creada else ""
    # el código se registra antes de usarlo.
    registrar_secreto("codigo_seguimiento_f3", codigo, codigo.replace("-", ""))
    assert creada, "el 8444 no acepta la denuncia sin JavaScript (se esperaba 201 y 'Denuncia enviada')"
    ok = PATRON_CODIGO.fullmatch(codigo) is not None
    assert ok, "el código de seguimiento no tiene la forma esperada"
    with paso("el denunciante consulta su denuncia con el código"):
        estado_http = denunciante.consultar(codigo)
        ok = (estado_http == 200 and denunciante.h1_es(H1_EXPEDIENTE_WEB)
              and denunciante.estado_es(ESTADO_WEB_RECIBIDA))
    assert ok, "la consulta con el código no abre la denuncia sin JavaScript"
