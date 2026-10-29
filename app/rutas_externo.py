"""Rutas del login con un proveedor externo y de los vínculos
(docs/threat-model.md, 6.19). Hoy solo Google.

* GET /v1/personal/externo/proveedores: los proveedores configurados en el
  broker. La SPA solo pinta el botón de los que estén aquí.
* POST /v1/personal/externo/google/inicio (empresa): si este navegador tiene
  un dispositivo de confianza vigente de esa empresa, abre un flujo, lo deja
  en su cookie y devuelve {url} para ir a Google. Si no, 409: la primera vez
  se entra con contraseña, porque Google nunca crea la confianza (6.19).
* GET /v1/personal/externo/google/vuelta: adonde vuelve el navegador desde
  Google. Comprueba la vuelta contra el flujo de su cookie, gasta el flujo,
  canjea el code por medio del broker y deja el ticket en su cookie.
  Siempre responde 303 a una página fija de la SPA.
* POST /v1/personal/sesiones/externa (codigo_totp): con el ticket, el
  dispositivo de confianza y un código, abre la sesión, con las mismas
  cookies que el login con contraseña (app/rutas_personal.py).
* POST /v1/personal/externo/google/vinculo/inicio (codigo_totp), con sesión:
  abre un flujo de vinculación y devuelve {url}.
* POST /v1/personal/externo/google/vinculo, con sesión: guarda el vínculo del
  ticket de la vuelta. DELETE en la misma ruta (codigo_totp): lo revoca. Los
  dos avisan por correo al titular y a quienes vigilan.

Este módulo es el único que conoce las cookies del flujo y del ticket, sus
atributos y las respuestas de la vuelta. La lógica (app/externo.py,
app/personal.py) no sabe que existen, y sus nombres están en
rutas_personal.COOKIES solo para que el filtro de cookies las reconozca.

Solo navegador. Todo el flujo vive en cookies que un cliente con Bearer no
tiene, así que estas rutas no le sirven de nada: una petición sin cookies ni
Sec-Fetch-Site es un 403 con EVENTO origen_rechazado, como cualquier otra que
no venga de la SPA. El resto del transporte es el de rutas_personal: mismo
origen y, si cambia algo, el Origin de la SPA.

La vuelta es distinta: llega desde Google, es una navegación de otro sitio
(Sec-Fetch-Site cross-site) y no puede pasar por ese transporte. Lo que la
protege es el flujo: el state de la URL tiene que ser el de la cookie
__Host- de este navegador, y la cookie solo la pone el inicio, que exige el
mismo origen. Además, solo se acepta una navegación de nivel superior
(Sec-Fetch-Mode navigate y Sec-Fetch-Dest document, especificación Fetch
Metadata), sin Authorization. Sea cual sea el fallo, la respuesta es un 303
a una lista cerrada de destinos (nunca un JSON que el navegador enseñe en
crudo, nunca una redirección abierta) y deja EVENTO vuelta_rechazada con un
motivo fijo, nunca un valor recibido. Lo que llega de Google (code, state)
no se escribe en ningún log: ni uvicorn (--no-access-log) ni Caddy registran
las peticiones.

Respuestas: un ticket que no vale, un vínculo que no vale y unas
credenciales que no valen dan el mismo 401, con el mismo cuerpo que el login
y sin WWW-Authenticate. Esa cabecera es la de una sesión caducada: con ella,
la SPA renovaría la sesión y acabaría en la página de entrada
(spa/src/app/nucleo/renovacion.ts).

Las rutas son síncronas (def), como las del personal: la base de datos y el
broker son síncronos. Gastar el flujo o el ticket es asíncrono (Redis): se
llama desde el hilo con anyio.from_thread, que lo ejecuta en el bucle de
eventos de la aplicación.
"""
import logging

import anyio.from_thread
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, ConfigDict, Field
from starlette.background import BackgroundTask

from app import cliente_broker, correo, externo, limitador, personal, proveedores_externos, rutas_personal
from app.frontera_http import REINTENTAR_TRAS, cuerpo_error
from app.validacion import TextoLinea

registro = logging.getLogger("canario.externo")

PROVEEDOR_GOOGLE = proveedores_externos.PROVEEDOR_GOOGLE

# Cuánto guarda el navegador cada cookie: lo que vale cada una (app/externo.py).
DURACION_COOKIE_FLUJO = externo.DURACION_FLUJO
DURACION_COOKIE_TICKET = externo.DURACION_TICKET
# El flujo es Lax: la vuelta es una navegación desde Google, otro sitio, y una
# cookie Strict no viajaría en ella. Lax solo viaja desde otro sitio en una
# navegación de nivel superior con un método seguro (GET), así que un
# formulario de otro sitio no la lleva (MDN, Set-Cookie, SameSite). El ticket
# es Strict: se pone en esa misma respuesta y solo se lee en un fetch de la
# SPA, del mismo origen. Que el navegador guarde una Strict puesta en una
# respuesta a una navegación de otro sitio se comprobó en Chromium 153 el 23
# de octubre de 2026.
SAMESITE_FLUJO = "lax"
SAMESITE_TICKET = "strict"

# Resultados de la vuelta para la SPA: lista cerrada, y ningún valor de la
# petición llega a la URL de destino.
CANCELADO = "cancelado"
NO_DISPONIBLE = "no_disponible"
FALLIDO = "fallido"
RESULTADOS = (CANCELADO, NO_DISPONIBLE, FALLIDO)
# Destino de cada propósito si todo va bien y prefijo del destino si falla.
# Mientras no se ha abierto el flujo no se sabe el propósito: se toma el
# acceso. Rutas de la SPA sin punto (proxy/Caddyfile trata las rutas con
# extensión como ficheros).
DESTINOS = {
    externo.PROPOSITO_ACCESO: ("/entrar/codigo", "/entrar?externo="),
    externo.PROPOSITO_VINCULO: ("/cuenta?vinculo=pendiente", "/cuenta?vinculo="),
}
# Error de la vuelta (RFC 6749, 4.1.2.1) cuando la persona cancela en el
# proveedor: tiene su propio mensaje en la SPA. Cualquier otro es un fallo.
ERROR_CANCELADO = "access_denied"

# Un solo texto para las tres causas de personal.SinDispositivo (sin cookie,
# empresa que no existe y dispositivo no vigente): si fueran distintos, el 409
# diría qué identificadores son de una empresa. Por eso nombra las dos salidas:
# revisar la empresa y, la primera vez, entrar con contraseña.
MENSAJE_SIN_DISPOSITIVO = ("no se puede entrar con ese proveedor en esa empresa desde este navegador; "
                           "revise la empresa o, la primera vez, entre con su contraseña y su código")
MENSAJE_NO_CONFIGURADO = "el acceso con ese proveedor no está disponible"
# Un texto fijo por motivo (personal.VinculoDuplicado): la SPA elige el texto
# por el código de estado, y los dos son 409.
MENSAJES_DUPLICADO = {
    "identidad": "esa cuenta externa ya está vinculada a otra cuenta de la empresa",
    "cuenta": "su cuenta ya tiene vinculada una cuenta de ese proveedor",
}


class InicioExterno(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    empresa: TextoLinea = Field(max_length=rutas_personal.LONGITUD_MAXIMA_IDENTIFICADOR)


# El mismo modelo que reinvitar y dar de baja: un solo sitio para el código.
CodigoTotp = rutas_personal.CodigoTotp


async def _solo_navegador(peticion: Request):
    """Dependencia del router: el transporte del personal y, además, solo el
    navegador (ver la cabecera)."""
    await rutas_personal.transporte(peticion)
    if not peticion.state.navegador:
        raise rutas_personal.OrigenNoPermitido(None)


router = APIRouter(prefix="/v1/personal", dependencies=[Depends(_solo_navegador)])
# Sin dependencias: la vuelta comprueba su propio transporte y nunca responde
# con un error en JSON (ver la cabecera).
router_vuelta = APIRouter()


def _poner_cookie(respuesta, nombre, valor, segundos, samesite):
    respuesta.set_cookie(nombre, valor, max_age=segundos, path="/", secure=True, httponly=True, samesite=samesite)


def _borrar_cookie(respuesta, nombre, samesite):
    # Con los mismos atributos con que se puso: el navegador ignora el borrado
    # de una cookie __Host- sin Secure (app/rutas_personal.py, _borrar_cookie).
    respuesta.delete_cookie(nombre, path="/", secure=True, httponly=True, samesite=samesite)


def _gastador(estado, espacio, jti, valor):
    """Función sin argumentos que gasta jti en Redis desde el hilo de la ruta:
    True solo la primera vez (app/limitador.py, consumir_una_vez). Los
    segundos se calculan al llamarla, con lo que le quede a valor."""
    def gastar():
        return anyio.from_thread.run(estado.limitador.consumir_una_vez, espacio, jti.hex(),
                                     valor.segundos_restantes())
    return gastar


def _ir_al_proveedor(estado, flujo):
    """{url} del proveedor para este flujo, con el flujo en su cookie. Si el
    broker falla, no se pone la cookie."""
    url = cliente_broker.autorizar(flujo.proveedor, flujo.state, flujo.code_challenge, flujo.nonce)
    respuesta = JSONResponse(content={"url": url})
    _poner_cookie(respuesta, rutas_personal.COOKIE_FLUJO, externo.sellar_flujo(estado.claves.flujo_externo, flujo),
                  DURACION_COOKIE_FLUJO, SAMESITE_FLUJO)
    return respuesta


def _con_avisos(cambio):
    # Los avisos, después de responder: la respuesta no depende de ellos.
    return Response(status_code=204, background=BackgroundTask(correo.enviar_todos, cambio.correos))


# ---------------------------------------------------------------------------
# Rutas
# ---------------------------------------------------------------------------

@router.get("/externo/proveedores")
def listar_proveedores():
    return JSONResponse(content={"proveedores": list(cliente_broker.proveedores())})


@router.post("/externo/google/inicio")
def iniciar_google(datos: InicioExterno, peticion: Request):
    estado = peticion.app.state
    # Antes de ir a Google: sin dispositivo de confianza, el login externo
    # fallaría siempre, y el fallo se ve aquí sin gastar ningún intento.
    empresa_id = personal.empresa_con_dispositivo(estado.pool, datos.empresa,
                                                  peticion.state.cookies.get(rutas_personal.COOKIE_DISPOSITIVO) or None)
    flujo = externo.nuevo_flujo(PROVEEDOR_GOOGLE, externo.PROPOSITO_ACCESO, empresa_id, datos.empresa)
    return _ir_al_proveedor(estado, flujo)


@router.post("/sesiones/externa", status_code=201)
def iniciar_sesion_externa(datos: CodigoTotp, peticion: Request):
    estado = peticion.app.state
    cookies = peticion.state.cookies
    ticket = externo.abrir_ticket(estado.claves.flujo_externo, cookies.get(rutas_personal.COOKIE_TICKET),
                                  externo.PROPOSITO_ACCESO)
    acceso = personal.iniciar_sesion_externa(estado.pool, estado.claves, ticket, datos.codigo_totp,
                                             cookies.get(rutas_personal.COOKIE_DISPOSITIVO) or None,
                                             _gastador(estado, "ticket", ticket.jti, ticket))
    respuesta = rutas_personal.respuesta_con_tokens(peticion, acceso, 201)
    # Gastado: ya no sirve. Si el código falla, el ticket sigue sin gastar y
    # la cookie se queda para otro intento mientras viva.
    _borrar_cookie(respuesta, rutas_personal.COOKIE_TICKET, SAMESITE_TICKET)
    return respuesta


@router.post("/externo/google/vinculo/inicio")
def iniciar_vinculo_google(datos: CodigoTotp, peticion: Request, sesion: rutas_personal.SesionPersonal):
    estado = peticion.app.state
    # Un código recién escrito antes de ir a Google: la sesión sola (un token
    # robado) no basta para vincular una cuenta externa.
    personal.iniciar_vinculo(estado.pool, estado.claves, sesion, PROVEEDOR_GOOGLE, datos.codigo_totp)
    flujo = externo.nuevo_flujo(PROVEEDOR_GOOGLE, externo.PROPOSITO_VINCULO, sesion.empresa_id, sesion.identificador,
                                sesion.sesion_id)
    return _ir_al_proveedor(estado, flujo)


@router.post("/externo/google/vinculo", status_code=204)
def completar_vinculo_google(peticion: Request, sesion: rutas_personal.SesionPersonal):
    estado = peticion.app.state
    ticket = externo.abrir_ticket(estado.claves.flujo_externo, peticion.state.cookies.get(rutas_personal.COOKIE_TICKET),
                                  externo.PROPOSITO_VINCULO)
    if ticket.proveedor != PROVEEDOR_GOOGLE:
        raise externo.TicketNoValido
    cambio = personal.completar_vinculo(estado.pool, estado.claves, sesion, ticket,
                                        _gastador(estado, "ticket", ticket.jti, ticket))
    respuesta = _con_avisos(cambio)
    _borrar_cookie(respuesta, rutas_personal.COOKIE_TICKET, SAMESITE_TICKET)
    return respuesta


@router.delete("/externo/google/vinculo", status_code=204)
def revocar_vinculo_google(datos: CodigoTotp, peticion: Request, sesion: rutas_personal.SesionPersonal):
    estado = peticion.app.state
    return _con_avisos(personal.revocar_vinculo(estado.pool, estado.claves, sesion, PROVEEDOR_GOOGLE,
                                                datos.codigo_totp))


# ---------------------------------------------------------------------------
# La vuelta
# ---------------------------------------------------------------------------

class _Fallo(Exception):
    """Fallo de la vuelta: el resultado para la SPA y el motivo para el log
    (None si no se registra: cancelar no es un incidente)."""

    def __init__(self, resultado, motivo):
        super().__init__(resultado)
        self.resultado = resultado
        self.motivo = motivo


def es_navegacion(cabeceras):
    """True solo si es la navegación de nivel superior de un navegador. Una
    petición de un script, una imagen o un iframe de otro sitio, o un cliente
    que no manda Fetch Metadata, no es una vuelta del proveedor. El sitio no
    se mira: desde Google es cross-site, y quien lo protege es el flujo."""
    return (cabeceras.get("sec-fetch-mode") == "navigate" and cabeceras.get("sec-fetch-dest") == "document"
            and "authorization" not in cabeceras)


def _parametro(consulta, nombre):
    """El valor de un parámetro de la URL, o None si no viene. Repetido es un
    fallo: con dos valores no se sabe cuál es el del proveedor."""
    valores = consulta.getlist(nombre)
    if len(valores) > 1:
        raise _Fallo(FALLIDO, "parametros")
    return valores[0] if valores else None


def _redirigir(proposito, resultado=None):
    correcto, prefijo = DESTINOS[proposito]
    return RedirectResponse(correcto if resultado is None else prefijo + resultado, status_code=303)


def _canjear(peticion, proveedor):
    """El flujo y el texto del ticket de una vuelta válida, o _Fallo. El
    orden importa: nada llega al broker sin un flujo de este navegador con
    el mismo state y el mismo iss, y sin haberlo gastado."""
    estado = peticion.app.state
    if not es_navegacion(peticion.headers):
        raise _Fallo(FALLIDO, "transporte")
    try:
        cookies = rutas_personal.cookies_canario(peticion.headers.getlist("cookie"))
    except personal.SesionNoValida:
        raise _Fallo(FALLIDO, "cookie") from None
    try:
        flujo = externo.abrir_flujo(estado.claves.flujo_externo, cookies.get(rutas_personal.COOKIE_FLUJO))
    except externo.FlujoNoValido:
        raise _Fallo(FALLIDO, "flujo") from None
    # Desde aquí se sabe el propósito: el destino de un fallo es el suyo.
    peticion.state.proposito_externo = flujo.proposito
    consulta = peticion.query_params
    error = _parametro(consulta, "error")
    if error is not None:
        # El proveedor no ha dado ningún code: no hay nada que canjear ni que
        # comprobar, y cancelar es lo normal.
        raise _Fallo(CANCELADO, None) if error == ERROR_CANCELADO else _Fallo(FALLIDO, "error_proveedor")
    try:
        externo.comprobar_vuelta(flujo, proveedor, _parametro(consulta, "state"), _parametro(consulta, "iss"))
    except externo.VueltaNoValida as fallo:
        raise _Fallo(FALLIDO, fallo.motivo) from None
    code = _parametro(consulta, "code")
    if code is None or not proveedores_externos.PATRON_CODE.fullmatch(code):
        raise _Fallo(FALLIDO, "code")
    try:
        if not _gastador(estado, "flujo", flujo.jti, flujo)():
            raise _Fallo(FALLIDO, "repetida")
    except limitador.NoDisponible as error_redis:
        registro.error("EVENTO limitador_no_disponible: %s", error_redis.clase)
        raise _Fallo(NO_DISPONIBLE, None) from None
    try:
        sub = cliente_broker.canjear(proveedor, code, flujo.verifier, flujo.nonce)
    except cliente_broker.CanjeRechazado:
        raise _Fallo(FALLIDO, "canje") from None
    except cliente_broker.NoConfigurado:
        raise _Fallo(NO_DISPONIBLE, "no_configurado") from None
    except cliente_broker.BrokerNoDisponible:
        # cliente_broker ya deja su EVENTO broker_no_disponible.
        raise _Fallo(NO_DISPONIBLE, None) from None
    return flujo, externo.emitir_ticket(estado.claves.flujo_externo, estado.claves.hmac_identidades, flujo, sub)


@router_vuelta.get(proveedores_externos.RUTA_VUELTA_GOOGLE)
def vuelta_google(peticion: Request):
    return _vuelta(peticion, PROVEEDOR_GOOGLE)


def _vuelta(peticion, proveedor):
    peticion.state.proposito_externo = externo.PROPOSITO_ACCESO
    try:
        flujo, ticket = _canjear(peticion, proveedor)
    except _Fallo as fallo:
        if fallo.motivo is not None:
            registro.warning("EVENTO vuelta_rechazada: proveedor=%s motivo=%s", proveedor, fallo.motivo)
        respuesta = _redirigir(peticion.state.proposito_externo, fallo.resultado)
    else:
        respuesta = _redirigir(flujo.proposito)
        _poner_cookie(respuesta, rutas_personal.COOKIE_TICKET, ticket, DURACION_COOKIE_TICKET, SAMESITE_TICKET)
    # El flujo no sirve para nada más, haya ido bien o mal. Que sea de un
    # solo uso no depende de este borrado (lo garantiza su jti en Redis).
    _borrar_cookie(respuesta, rutas_personal.COOKIE_FLUJO, SAMESITE_FLUJO)
    return respuesta


# ---------------------------------------------------------------------------
# Errores
# ---------------------------------------------------------------------------

def _manejador(codigo, mensaje=None, cabeceras=None):
    async def manejar(_peticion, _error_capturado):
        return Response(cuerpo_error(codigo, mensaje), status_code=codigo, media_type="application/json",
                        headers=cabeceras)
    return manejar


async def _vinculo_duplicado(_peticion, error):
    return Response(cuerpo_error(409, MENSAJES_DUPLICADO[error.motivo]), status_code=409,
                    media_type="application/json")


def instalar_errores(aplicacion):
    # El mismo 401 que unas credenciales que no valen (rutas_personal), sin
    # WWW-Authenticate: ver la cabecera.
    no_valido = _manejador(401, rutas_personal.MENSAJE_CREDENCIALES)
    aplicacion.add_exception_handler(externo.TicketNoValido, no_valido)
    aplicacion.add_exception_handler(personal.VinculoNoValido, no_valido)
    aplicacion.add_exception_handler(personal.SinDispositivo, _manejador(409, MENSAJE_SIN_DISPOSITIVO))
    aplicacion.add_exception_handler(personal.VinculoDuplicado, _vinculo_duplicado)
    aplicacion.add_exception_handler(cliente_broker.NoConfigurado, _manejador(404, MENSAJE_NO_CONFIGURADO))
    # cliente_broker ya deja su EVENTO broker_no_disponible.
    aplicacion.add_exception_handler(cliente_broker.BrokerNoDisponible,
                                     _manejador(503, None, {"Retry-After": REINTENTAR_TRAS}))
