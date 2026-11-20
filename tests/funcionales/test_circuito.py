"""F1: el circuito entre actores en Chromium (docs/informe-pruebas.md, 2).

El denunciante presenta en el 8444 sin JavaScript; el admin asigna la
denuncia a la instructora; la instructora la abre, responde y cambia el
estado en el 8445; el denunciante consulta con su código, ve el estado y la
respuesta y escribe; la instructora ve su mensaje. Cada texto sembrado lleva
un nonce de esta ejecución, así que lo que se encuentra no puede venir de otra.

Los oráculos son literales escritos aquí, acotados a su elemento (el <dd> del
estado, un <li> de los mensajes, el aviso de la acción), nunca "aparece en la
página". Control positivo: es el propio camino feliz, cada paso comprueba el
anterior (el texto de un actor tiene que llegar al otro).
"""
import re
import secrets

from paginas import Denunciante8444, paso

# Un nonce por ejecución en cada texto sembrado.
NONCE = secrets.token_hex(8)
TEXTO_DENUNCIA = f"Denuncia de la prueba funcional {NONCE}: el responsable de compras acepta regalos."
TEXTO_PERSONAL = f"Respuesta de la instructora {NONCE}: ¿puede indicar las fechas aproximadas?"
TEXTO_DENUNCIANTE = f"Respuesta del denunciante {NONCE}: ocurrió en marzo y en abril."
CATEGORIA = "fraude"

# Oráculos literales: las plantillas del 8444 (app/plantillas/), la etiqueta
# del estado (app/rutas_web.py, ESTADOS) y los textos de la SPA.
H1_FORMULARIO = "Nueva denuncia"
H1_CREADA = "Denuncia enviada"
H1_EXPEDIENTE_WEB = "Su denuncia"
ESTADO_WEB_RECIBIDA = "Recibida"
ESTADO_WEB_EN_INSTRUCCION = "En instrucción"
AUTOR_WEB_PERSONAL = "Personal de la empresa"
AUTOR_WEB_DENUNCIANTE = "Usted"
AVISO_WEB_MENSAJE = "Mensaje enviado."
AVISO_SPA_MENSAJE = "Mensaje enviado."
AVISO_SPA_EN_INSTRUCCION = "Estado cambiado a En instrucción."
ESTADO_SPA_EN_INSTRUCCION = "En instrucción"
AUTOR_SPA_PROPIO = "Usted"
AUTOR_SPA_DENUNCIANTE = "Denunciante"
PATRON_CODIGO = re.compile(r"([A-Z2-7]{4}-){7}[A-Z2-7]{4}")
PATRON_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def test_f1_circuito_entre_actores_chromium(cuentas, nuevo_contexto, registrar_secreto):
    identificador = cuentas["identificador"]
    admin, instructora = cuentas["admin"], cuentas["instructora"]

    # (a) Dado el formulario de la empresa en el 8444, en un contexto sin
    # JavaScript (como lo usa de verdad el denunciante),
    denunciante = Denunciante8444(nuevo_contexto("denunciante", javascript=False).new_page())
    with paso("el denunciante abre el formulario de su empresa"):
        estado_http = denunciante.abrir_formulario(identificador)
        ok = estado_http == 200 and denunciante.h1_es(H1_FORMULARIO)
    assert ok, "el formulario de la empresa en el 8444 no se abre"
    # cuando presenta una denuncia con el texto sembrado,
    with paso("el denunciante presenta la denuncia"):
        estado_http = denunciante.presentar(CATEGORIA, TEXTO_DENUNCIA)
        creada = estado_http == 201 and denunciante.h1_es(H1_CREADA)
        codigo = denunciante.codigo_mostrado() if creada else ""
    # el código se registra antes de cualquier comprobación: es un secreto.
    registrar_secreto("codigo_seguimiento", codigo, codigo.replace("-", ""))
    # entonces la denuncia se acepta (201) y recibe su código de seguimiento.
    assert creada, "el 8444 no acepta la denuncia (se esperaba 201 y 'Denuncia enviada')"
    ok = PATRON_CODIGO.fullmatch(codigo) is not None
    assert ok, "el código de seguimiento no tiene la forma esperada"

    # (b) Dado el admin en el listado de Denuncias de una empresa nueva,
    with paso("el admin abre el listado de denuncias"):
        admin.ir_por_menu("Denuncias")
        ids = admin.ids_del_listado()
    ok = len(ids) == 1 and PATRON_UUID.fullmatch(ids[0]) is not None
    assert ok, "el listado del admin no tiene exactamente la denuncia recién presentada"
    denuncia_id = ids[0]
    # cuando la asigna a la instructora,
    with paso("el admin asigna la denuncia a la instructora"):
        aviso = admin.asignar(denuncia_id, cuentas["email_instructora"])
    # entonces el aviso confirma la asignación a esa cuenta.
    ok = aviso == f"La denuncia {denuncia_id} está asignada a {cuentas['email_instructora']}."
    assert ok, "el aviso de la asignación no es el esperado"

    # (c) Dada la instructora con la denuncia asignada,
    with paso("la instructora abre la denuncia y pulsa 'Abrir el expediente'"):
        instructora.ir_por_menu("Denuncias")
        instructora.abrir_expediente(denuncia_id)
        ok = instructora.texto_denuncia_es(TEXTO_DENUNCIA)
    # entonces ve, literal, el texto que escribió el denunciante;
    assert ok, "el expediente de la instructora no muestra el texto de la denuncia"
    # cuando envía un mensaje,
    with paso("la instructora envía un mensaje al denunciante"):
        aviso_mensaje = instructora.enviar_mensaje(TEXTO_PERSONAL)
        ok = aviso_mensaje == AVISO_SPA_MENSAJE and instructora.tiene_mensaje(AUTOR_SPA_PROPIO, TEXTO_PERSONAL)
    # entonces se acepta y aparece en su lista de mensajes;
    assert ok, "el mensaje de la instructora no se acepta o no aparece en el expediente"
    # cuando cambia el estado a en_instruccion,
    with paso("la instructora cambia el estado a en_instruccion"):
        aviso_estado = instructora.cambiar_estado("en_instruccion", aviso_mensaje)
        ok = aviso_estado == AVISO_SPA_EN_INSTRUCCION and instructora.estado_es(ESTADO_SPA_EN_INSTRUCCION)
    # entonces el aviso y la ficha dicen "En instrucción".
    assert ok, "el cambio de estado a En instrucción no se acepta o no se ve"

    # (d) Dado el denunciante con su código,
    with paso("el denunciante consulta su denuncia con el código"):
        estado_http = denunciante.consultar(codigo)
        ok = estado_http == 200 and denunciante.h1_es(H1_EXPEDIENTE_WEB)
    assert ok, "la consulta con el código no abre la denuncia en el 8444"
    # entonces el <dd> del estado dice literalmente "En instrucción" (y no
    # "Recibida", el de una denuncia sin tocar),
    with paso("el denunciante lee el estado"):
        ok = (denunciante.estado_es(ESTADO_WEB_EN_INSTRUCCION)
              and not denunciante.estado_es(ESTADO_WEB_RECIBIDA))
    assert ok, "el 8444 no muestra el estado 'En instrucción'"
    # y el mensaje de la instructora está en ol.mensajes > li, como del
    # personal;
    with paso("el denunciante lee el mensaje de la instructora"):
        ok = denunciante.tiene_mensaje(AUTOR_WEB_PERSONAL, TEXTO_PERSONAL)
    assert ok, "el 8444 no muestra el mensaje de la instructora"
    # cuando escribe un mensaje,
    with paso("el denunciante escribe un mensaje"):
        estado_http = denunciante.escribir(TEXTO_DENUNCIANTE)
        ok = (estado_http == 201 and denunciante.aviso_es(AVISO_WEB_MENSAJE)
              and denunciante.campo_mensaje_vacio()
              and denunciante.tiene_mensaje(AUTOR_WEB_DENUNCIANTE, TEXTO_DENUNCIANTE))
    # entonces se acepta (201, "Mensaje enviado."), el textarea queda vacío y
    # el mensaje sale en su lista como suyo.
    assert ok, "el mensaje del denunciante no se acepta como se esperaba (201, aviso, campo vacío y en la lista)"

    # (e) Dada la instructora, cuando vuelve a abrir el expediente (una
    # lectura nueva),
    with paso("la instructora vuelve a abrir el expediente"):
        instructora.ir_por_menu("Denuncias")
        instructora.abrir_expediente(denuncia_id)
        ok = instructora.tiene_mensaje(AUTOR_SPA_DENUNCIANTE, TEXTO_DENUNCIANTE)
    # entonces ve el mensaje del denunciante en .mensajes > li.
    assert ok, "la instructora no ve el mensaje del denunciante"
