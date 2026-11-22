"""F2: los errores del 8444 en Chromium, Firefox y WebKit (docs/informe-pruebas.md,
2). Sin JavaScript, como lo usa de verdad el denunciante y como dice el informe:
la CSP del 8444 ya prohíbe los scripts, así que lo que se prueba es el
navegador con el HTML, no una ayuda de JavaScript.

Tres bloques en una sola prueba, cada uno con su control positivo en la misma
página o el mismo formulario. Si el control falla, SIN CONCLUSION (concluir):

(a) texto solo de espacios con una categoría válida: pasa el required del
    navegador y lo rechaza el servidor (422, aria-invalid y role="alert").
    Control: el mismo formulario con texto válido da 201 y "Denuncia enviada";
(b) sin categoría el navegador no envía nada. Control: con categoría, sí;
(c) un código de seguimiento mal formado, inexistente, no ASCII o demasiado
    largo da el mismo 404, con el mismo cuerpo byte a byte, sin revelar si el
    código existe. Control: el código real abre su expediente, también en
    minúsculas.

Los oráculos son literales escritos aquí. Todo código de seguimiento se
registra en el escáner anti-fuga (con todas sus variantes) en cuanto aparece y
antes de usarlo; los mensajes de fallo no llevan datos de la ejecución.
"""
import re
import secrets

import pytest
from paginas import Denunciante8444, concluir, paso

CATEGORIA = "fraude"
# Solo espacios: un campo lleno, así que el required del navegador lo deja
# pasar, y vacío para el servidor (strip), que lo rechaza.
TEXTO_EN_BLANCO = "     "
TEXTO_VALIDO = f"Denuncia de la prueba de errores {secrets.token_hex(8)}: texto válido."

# Oráculos literales (plantillas de app/plantillas/ y mensaje de la API).
H1_FORMULARIO = "Nueva denuncia"
H1_CREADA = "Denuncia enviada"
H1_CONSULTA = "Consultar una denuncia"
H1_EXPEDIENTE_WEB = "Su denuncia"
ESTADO_WEB_RECIBIDA = "Recibida"
MENSAJE_CODIGO = "código de seguimiento no válido"
PATRON_CODIGO = re.compile(r"([A-Z2-7]{4}-){7}[A-Z2-7]{4}")
# El alfabeto base32 del código, escrito a mano (no importado de la app).
ALFABETO_BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
LONGITUD_CODIGO_BASE32 = 32
# "Observación sin envío": se espera un tiempo fijo después del clic y se mira
# lo que el listener de peticiones vio. Un valor literal, no un wait implícito.
VENTANA_MS = 1500

CODIGO_MAL_FORMADO = "esto-no-es-un-codigo"
# 30 caracteres del alfabeto, "45" y una ligadura: en mayúsculas, "ﬀ" pasa a
# ser "FF" y el resultado tendría 32 letras válidas; solo isascii() lo frena.
CODIGO_NO_ASCII = "ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ23-45ﬀ"
# Uno más que el máximo de entrada (64).
CODIGO_DEMASIADO_LARGO = "A" * 65


def codigo_inexistente(real):
    """Un código bien formado generado al azar, NO derivado del real, con la
    longitud exacta. Si coincidiera con el real, se genera otro."""
    real_limpio = real.replace("-", "")
    while True:
        crudo = "".join(secrets.choice(ALFABETO_BASE32) for _ in range(LONGITUD_CODIGO_BASE32))
        if crudo != real_limpio:
            return "-".join(crudo[i:i + 4] for i in range(0, LONGITUD_CODIGO_BASE32, 4))


@pytest.mark.motores("chromium", "firefox", "webkit")
def test_f2_errores_del_8444(datos, nuevo_contexto, registrar_secreto):
    identificador = datos["identificador"]
    pagina = nuevo_contexto("denunciante_f2", javascript=False).new_page()
    denunciante = Denunciante8444(pagina)
    envios = []

    def mirar(peticion):
        # Los POST a /denuncias que salen del navegador, sea cual sea su origen.
        if peticion.method == "POST" and peticion.url.endswith("/denuncias"):
            envios.append(peticion.url)

    pagina.on("request", mirar)

    def anotar(codigo):
        # En cuanto aparece un código, con todas sus formas: tal cual, sin
        # guiones y esas dos en minúsculas (las que se usarán después).
        registrar_secreto("codigo_seguimiento_f2", codigo, codigo.replace("-", ""), codigo.lower(),
                          codigo.lower().replace("-", ""))

    # (a) Dado el formulario de la empresa,
    with paso("abre el formulario de su empresa"):
        estado_http = denunciante.abrir_formulario(identificador)
        ok = estado_http == 200 and denunciante.h1_es(H1_FORMULARIO)
    assert ok, "el formulario de la empresa en el 8444 no se abre"
    # cuando envía una categoría válida y un texto solo de espacios,
    with paso("envía un texto solo de espacios"):
        estado_blanco = denunciante.presentar(CATEGORIA, TEXTO_EN_BLANCO)
        rechazado = (estado_blanco == 422 and denunciante.campo_invalido("texto")
                     and not denunciante.campo_invalido("categoria") and denunciante.alerta_visible())
    # entonces el servidor lo rechaza: 422, el campo texto con aria-invalid y un
    # role="alert" visible. Control: el mismo formulario, con texto válido, se
    # acepta con 201 y "Denuncia enviada".
    with paso("envía el mismo formulario con un texto válido"):
        denunciante.abrir_formulario(identificador)
        estado_valido = denunciante.presentar(CATEGORIA, TEXTO_VALIDO)
        creada = estado_valido == 201 and denunciante.h1_es(H1_CREADA)
        codigo = denunciante.codigo_mostrado() if creada else ""
    anotar(codigo)
    control = creada and PATRON_CODIGO.fullmatch(codigo) is not None
    concluir(control, rechazado, "el texto solo de espacios no da 422 con aria-invalid y role=alert")

    # (b) Dado el formulario con texto y sin categoría,
    with paso("pulsa Enviar sin categoría"):
        denunciante.abrir_formulario(identificador)
        denunciante.escribir_texto(TEXTO_VALIDO)
        url_antes, envios_antes = denunciante.url(), len(envios)
        denunciante.pulsar_enviar()
        pagina.wait_for_timeout(VENTANA_MS)
        sin_envio = (len(envios) == envios_antes and denunciante.url() == url_antes
                     and denunciante.h1_es(H1_FORMULARIO))
    # entonces el navegador no envía nada (ningún POST a /denuncias y la URL no
    # cambia). Control, con el mismo listener y la misma ventana: con categoría,
    # el envío sale.
    with paso("pulsa Enviar con categoría"):
        denunciante.elegir_categoria(CATEGORIA)
        envios_antes = len(envios)
        with pagina.expect_navigation():
            denunciante.pulsar_enviar()
        pagina.wait_for_timeout(VENTANA_MS)
        sale = len(envios) == envios_antes + 1 and denunciante.h1_es(H1_CREADA)
        codigo_b = denunciante.codigo_mostrado() if sale else ""
    anotar(codigo_b)
    concluir(sale, sin_envio, "sin categoría el navegador envía el formulario")

    # (c) Dados cuatro códigos que no abren ninguna denuncia,
    inexistente = codigo_inexistente(codigo)
    registrar_secreto("codigo_inexistente_f2", inexistente, inexistente.replace("-", ""))
    casos = (CODIGO_MAL_FORMADO, inexistente, CODIGO_NO_ASCII, CODIGO_DEMASIADO_LARGO)
    cuerpos, todos_404 = [], True
    for caso in casos:
        with paso("consulta un código que no abre ninguna denuncia"):
            estado_http = denunciante.consultar(caso)
            todos_404 = todos_404 and (
                estado_http == 404 and denunciante.h1_es(H1_CONSULTA) and denunciante.alerta_visible()
                and denunciante.alerta_contiene(MENSAJE_CODIGO) and denunciante.error_codigo_es(MENSAJE_CODIGO)
                and denunciante.campo_invalido("codigo"))
            cuerpos.append(denunciante.cuerpo_ultima_respuesta())
    # entonces todos dan 404 con "código de seguimiento no válido" en el
    # role="alert" y en #error-codigo, el campo con aria-invalid, y el cuerpo
    # es el mismo byte a byte (no revela si el código existe).
    iguales = len(cuerpos) == len(casos) and len(set(cuerpos)) == 1 and len(cuerpos[0]) > 0
    # Control: el código real abre su expediente, tal cual y normalizado
    # (minúsculas, con guiones).
    abre = []
    for variante in (codigo, codigo.lower()):
        with paso("consulta el código real"):
            estado_http = denunciante.consultar(variante)
            abre.append(estado_http == 200 and denunciante.h1_es(H1_EXPEDIENTE_WEB)
                        and denunciante.estado_es(ESTADO_WEB_RECIBIDA))
    concluir(all(abre), todos_404 and iguales,
             "un código mal formado, inexistente, no ASCII o demasiado largo no da el mismo 404")
