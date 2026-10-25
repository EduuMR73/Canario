"""Rutas del personal (docs/threat-model.md, 6.3).

* POST /v1/personal/activacion: con el token de invitación, fija la
  contraseña y devuelve el secreto TOTP (texto y URI otpauth para el QR).
* POST /v1/personal/activacion/confirmar: con el token y un código, activa la
  cuenta y devuelve el primer token de dispositivo de confianza.
* POST /v1/personal/sesiones: login (empresa, email, contraseña, código y,
  si lo tiene, el token de dispositivo). Devuelve el JWT de acceso, el token
  de renovación, los segundos que dura el acceso y, si el login fue sin
  dispositivo de confianza, un token de dispositivo nuevo.
* POST /v1/personal/sesiones/renovacion: con el token de renovación,
  devuelve un acceso y una renovación nuevos (app/personal.py, renovar).
* DELETE /v1/personal/sesiones/actual: cierra la sesión.
* GET /v1/personal/yo: cuenta de la sesión, con invitacion_pendiente (el
  aviso de una reinvitación de esa cuenta) y sus cuentas externas vinculadas
  (proveedor y día).
* El login externo y los vínculos tienen sus rutas en app/rutas_externo.py.
* POST /v1/personal/contrasena: cambia la contraseña (actual, nueva y código)
  y devuelve los tokens de una sesión nueva: la anterior queda revocada.
* GET y POST /v1/personal/usuarios, POST y DELETE .../{usuario_id}/invitacion
  (reinvitar y anular la invitación abierta) y POST .../{usuario_id}/baja:
  administración de cuentas, solo admin.
* Registro "primero el email" (app/solicitudes.py): POST /v1/personal/registro
  (empresa y email; siempre el mismo 202) y POST .../registro/verificacion
  (el token del enlace), sin sesión. GET /v1/personal/solicitudes (las
  verificadas), POST .../{solicitud_id}/aprobacion (con el rol) y DELETE
  .../{solicitud_id} (rechazo): solo admin. Los correos salen después de
  responder (BackgroundTask, app/correo.py); en el registro, también todo el
  trabajo con la base de datos (solicitudes.procesar). La aprobación NO
  devuelve el token de invitación: va solo al email verificado.
* Instrucción (app/instruccion.py): GET /v1/personal/denuncias (listado sin
  contenido), GET .../{denuncia_id} (contenido y mensajes, solo quien la
  tiene asignada), POST .../{denuncia_id}/mensajes, POST .../{denuncia_id}/estado
  y PUT .../{denuncia_id}/asignacion (solo admin). POST .../{denuncia_id}/redaccion
  y POST .../{denuncia_id}/mensajes/{secuencia}/redaccion (tachar parte del
  texto, art. 32.2; solo admin con la denuncia asignada).
  GET /v1/personal/auditoria (desde el principio, con desde),
  GET .../auditoria/recientes (desde lo más reciente, con antes) y
  GET .../auditoria/verificacion: admin y auditor.

Este módulo es el único que sabe cómo viajan los tokens, y hay dos
transportes (docs/threat-model.md, 6.3), que decide la dependencia
transporte en todas las rutas:

* Cliente (las baterías, cualquier cliente que no sea un navegador): el JWT
  de acceso en la cabecera Authorization (Bearer), y los de renovación y
  dispositivo en el cuerpo de sus peticiones. Sin cookies no hay CSRF: este
  cliente nunca envía credenciales por su cuenta.
* Navegador (la SPA del personal, en CANARIO_ORIGEN_PERSONAL): los tres
  tokens en cookies __Host- con HttpOnly, Secure y SameSite=Strict. Ningún
  script de la página los lee, así que un XSS no puede llevárselos (ATT&CK
  T1539); el cuerpo de las respuestas solo dice cuánto dura el acceso. Con
  cookies sí hay CSRF, porque el navegador las añade solo (OWASP, Cross-Site
  Request Forgery Prevention Cheat Sheet). La defensa es la que ese documento
  llama la señal principal, Fetch Metadata, con el origen como respaldo
  obligatorio: toda petición con cookies o con Sec-Fetch-Site debe traer
  Sec-Fetch-Site same-origin y, si cambia algo (todo lo que no es GET ni
  HEAD), Origin igual al de la SPA. SameSite=Strict no basta: se mide por
  sitio y no por origen, y el 8443 y el 8444 son el mismo sitio que la SPA.
  Las dos cabeceras las pone el navegador y una página no puede cambiarlas.
  Un rechazo da 403 y deja EVENTO origen_rechazado.

Bearer y cookie a la vez, o una cookie de Canario repetida, son un 401: con
dos credenciales no se sabe cuál vale, y el analizador de Starlette se
quedaría con la última sin avisar. Las cookies no se aíslan por puerto en
ningún sentido (RFC 6265, 8.5): el proxy quita Cookie de las peticiones y
Set-Cookie de las respuestas en el 8443 y el 8444 (proxy/Caddyfile), así que
solo el 8445 las recibe y solo él las pone. app/personal.py no sabe nada del
transporte.

Respuestas: cualquier fallo del login da el mismo 401, con el mismo cuerpo
(app/personal.py explica por qué el tiempo también es el mismo). Un JWT de
acceso o un token de renovación que no vale da otro 401 con
WWW-Authenticate: Bearer, sin decir por qué (firma, caducidad, sesión
revocada o reutilización dan la misma respuesta). Una cuenta de
otra empresa es invisible (RLS) y da el 404 genérico, igual que una
inexistente. Un rol insuficiente da 403. Una denuncia que no es de quien la
pide da el mismo 404 que una inexistente o de otra empresa.

Límite por cuenta (docs/threat-model.md, 6.9): toda ruta con sesión la
obtiene de la dependencia _sesion, que autentica y después consume la regla
"cuenta" del limitador con la identidad autenticada. Es la única forma de
obtener una sesión en este módulo, así que ninguna ruta con sesión queda sin
ese límite (cerrado por construcción, como la regla "otras" del middleware).
Comprobado en la versión fijada de FastAPI: la dependencia se ejecuta aunque
el cuerpo no valide (un 422 autenticado también cuenta), salvo con un JSON
que ni siquiera se puede analizar, que se rechaza antes de autenticar.

Accesos denegados (docs/threat-model.md, 6.7): cada 403 y cada 404 de una
petición con sesión deja EVENTO acceso_denegado en el log, con empresa,
cuenta, código, método, la plantilla de la ruta y los ids de la ruta. Es lo
que pide OWASP ASVS 5.0.0, 16.3.2 ("failed authorization attempts are
logged"): sin esto, una cuenta que prueba ids de denuncias ajenas no deja
rastro. El 404 entra porque aquí es la forma de denegar sin revelar si el
recurso existe. Lo escriben los manejadores de las dos excepciones, no cada
ruta, así que una ruta nueva queda cubierta sin hacer nada. La sesión la
deja _sesion en peticion.state: en las versiones fijadas (FastAPI 0.143.0 y
Starlette 1.7.0, fastapi/routing.py) la dependencia y el manejador reciben
el mismo objeto Request.

Las rutas son síncronas (def): FastAPI las ejecuta en su pool de hilos, y
tanto la base de datos como Argon2 son síncronos. La dependencia _sesion es
asíncrona porque el limitador lo es; la autenticación, que es síncrona, la
envía al pool de hilos.
"""
import logging
import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Path, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from starlette.background import BackgroundTask

from app import correo, cripto, denuncias, instruccion, limitador, personal, solicitudes, tokens
from app.frontera_http import REINTENTAR_TRAS, cuerpo_error
from app.rutas_denuncias import LONGITUD_MAXIMA_TEXTO
from app.validacion import TextoLibre, TextoLinea, validar_email

registro = logging.getLogger("canario.personal")

MENSAJE_CREDENCIALES = "credenciales no válidas"
MENSAJE_SESION = "sesión no válida"
MENSAJE_INVITACION = "invitación no válida"
MENSAJE_CODIGO = "código no válido"
MENSAJE_PROHIBIDO = "permiso denegado"
MENSAJE_DUPLICADO = "ya existe una cuenta con ese email"
MENSAJE_ULTIMO_ADMIN = "la empresa se quedaría sin ningún admin activo"
MENSAJE_SIN_CLAVE = "el canal de esta empresa no está disponible; inténtelo más tarde"
MENSAJE_TRANSICION = "la denuncia no puede pasar a ese estado desde el actual"
MENSAJE_CERRADA = "la denuncia está cerrada"
MENSAJE_LIMITE = "la denuncia ha alcanzado el máximo de mensajes"
MENSAJE_DESTINO = "la cuenta de destino no está activa o no instruye denuncias"
MENSAJE_FINAL = "cerrar una denuncia exige un mensaje final para el denunciante"
MENSAJE_NO_VERAZ = "declarar una denuncia no veraz no admite mensaje"
MENSAJE_FRAGMENTO = "el texto indicado no está en esa posición"
# Propio y no el 429 genérico: quien lo recibe tiene que saber qué ha pasado
# y que puede seguir con lo que ya abrió (el tope no es un secreto para quien
# llega a él).
MENSAJE_LECTURAS = (f"ha abierto hoy el máximo de {instruccion.LECTURAS_TOPE} denuncias distintas; "
                    "puede seguir con las que ya abrió y abrir otras mañana")
# Siempre el mismo, pase lo que pase con la solicitud (app/solicitudes.py).
# Si la tarea de después de responder falla, el 202 ya ha salido: el mensaje
# dice qué hacer si el correo no llega (app/solicitudes.py, cabecera).
MENSAJE_REGISTRO = ("si los datos son correctos, recibirá un correo en unos minutos; "
                    "si no le llega, vuelva a solicitarlo más tarde")
MENSAJE_SOLICITUD = "solicitud no válida"

# Topes de forma de la petición, holgados respecto a lo válido: lo que pase
# de aquí es un 422, sin llegar a la lógica. La política de contraseñas
# (12 a 128 caracteres tras NFKC) la aplica app/personal.py.
LONGITUD_MAXIMA_CONTRASENA = 512
LONGITUD_MAXIMA_TOKEN = 128
LONGITUD_MAXIMA_CODIGO = 16
LONGITUD_MAXIMA_EMAIL = 254
LONGITUD_MAXIMA_IDENTIFICADOR = 64
# Tramos por redacción: acota el trabajo de una petición. Más tramos, en
# otra petición.
MAXIMO_TRAMOS = 50
# Una secuencia de mensaje fuera de 1..200 (el tope de canal.preparar_mensaje,
# db/init/02_esquema.sql) no puede existir: 422 sin consultar.
MAXIMO_MENSAJES = 200


# ---------------------------------------------------------------------------
# Transporte: cliente con Bearer o navegador con cookies (ver la cabecera)
# ---------------------------------------------------------------------------
# __Host-: el navegador solo las acepta con Secure, Path=/ y sin Domain, así
# que quedan atadas a este host y nadie las cambia desde otra ruta o
# subdominio (MDN, Cookies, "Cookie prefixes").
COOKIE_ACCESO = "__Host-canario_acceso"
COOKIE_RENOVACION = "__Host-canario_renovacion"
COOKIE_DISPOSITIVO = "__Host-canario_dispositivo"
# Las del login externo: el flujo hacia el proveedor y el ticket de la vuelta.
# Sus atributos, su duración y cuándo se ponen y se borran solo los conoce
# app/rutas_externo.py; aquí van sus nombres porque este es el filtro de todas
# las cookies de Canario: una repetida o demasiado larga no vale ninguna.
COOKIE_FLUJO = "__Host-canario_flujo"
COOKIE_TICKET = "__Host-canario_ticket"
COOKIES = (COOKIE_ACCESO, COOKIE_RENOVACION, COOKIE_DISPOSITIVO, COOKIE_FLUJO, COOKIE_TICKET)
# Cuánto las guarda el navegador. Quien decide si un token vale es siempre la
# base de datos o la firma; esto solo evita que el navegador guarde de más.
# La sesión caduca a las 8 horas y el dispositivo a los 90 días
# (db/init/02_esquema.sql); el acceso, a los 5 minutos (app/tokens.py).
DURACION_RENOVACION = 8 * 3600
DURACION_DISPOSITIVO = 90 * 86400
# Tope de forma de una cookie, holgado respecto al JWT (377 caracteres) y a
# los tokens (76): lo que pase de aquí no es nuestro.
LONGITUD_MAXIMA_COOKIE = 512
# Los únicos métodos que no cambian nada; el resto exige Origin.
METODOS_SEGUROS = ("GET", "HEAD")
# Valores de Sec-Fetch-Site (especificación Fetch Metadata). En el log va el
# valor solo si es uno de estos: lo demás lo ha escrito alguien a mano.
SITIOS_FETCH = ("same-origin", "same-site", "cross-site", "none")


class OrigenNoPermitido(Exception):
    """Una petición del navegador que no viene de la SPA: 403."""

    def __init__(self, sitio):
        super().__init__(sitio)
        if sitio is None:
            self.sitio = "-"
        else:
            self.sitio = sitio if sitio in SITIOS_FETCH else "otro"


def cookies_canario(cabeceras_cookie):
    """Las cookies de Canario de las cabeceras Cookie, por nombre. Una
    repetida o demasiado larga es SesionNoValida: no se elige ninguna. Las
    demás cookies se ignoran."""
    encontradas = {}
    for cabecera in cabeceras_cookie:
        for trozo in cabecera.split(";"):
            nombre, _, valor = trozo.strip().partition("=")
            if nombre not in COOKIES:
                continue
            if nombre in encontradas or len(valor) > LONGITUD_MAXIMA_COOKIE:
                raise personal.SesionNoValida
            encontradas[nombre] = valor.strip()
    return encontradas


def es_navegador(metodo, cabeceras, hay_cookies, origen_personal):
    """True si la petición es de la SPA (cookies), False si es de un cliente
    con Bearer. OrigenNoPermitido si es de un navegador pero no de la SPA, y
    SesionNoValida si trae las dos credenciales.

    Sin Sec-Fetch-Site ni cookies no es un navegador moderno (todos la envían
    a un origen HTTPS desde marzo de 2023, MDN): es un cliente con Bearer,
    que no corre riesgo de CSRF. Con cualquiera de las dos, se exige el mismo
    origen. Un GET del mismo origen no lleva Origin (MDN, Origin), así que en
    GET y HEAD basta Sec-Fetch-Site."""
    sitio = cabeceras.get("sec-fetch-site")
    if sitio is None and not hay_cookies:
        return False
    if sitio != "same-origin":
        raise OrigenNoPermitido(sitio)
    if metodo not in METODOS_SEGUROS and cabeceras.get("origin") != origen_personal:
        raise OrigenNoPermitido(sitio)
    if "authorization" in cabeceras:
        raise personal.SesionNoValida
    return True


async def transporte(peticion: Request):
    """Dependencia de todas las rutas del router (cerrado por construcción:
    una ruta nueva queda cubierta sin hacer nada). Deja en peticion.state el
    transporte y las cookies de Canario. La usa también el router del login
    externo (app/rutas_externo.py), que además exige el navegador."""
    cookies = cookies_canario(peticion.headers.getlist("cookie"))
    # La aplicación siempre lo tiene: sin él no arranca (app/principal.py).
    # Si faltara, ningún Origin es igual a None y todo POST del navegador se
    # rechaza: falla cerrado.
    origen = getattr(peticion.app.state, "origen_personal", None)
    peticion.state.navegador = es_navegador(peticion.method, peticion.headers, bool(cookies), origen)
    peticion.state.cookies = cookies


def _poner_cookie(respuesta, nombre, valor, segundos):
    respuesta.set_cookie(nombre, valor, max_age=segundos, path="/", secure=True, httponly=True, samesite="strict")


def _borrar_cookie(respuesta, nombre):
    # Con los mismos atributos: el navegador ignora un borrado de una cookie
    # __Host- sin Secure, y delete_cookie de Starlette pone secure=False por
    # defecto (comprobado en la versión fijada, 1.7.0).
    respuesta.delete_cookie(nombre, path="/", secure=True, httponly=True, samesite="strict")


router = APIRouter(prefix="/v1/personal", dependencies=[Depends(transporte)])


# extra="forbid" y strict=True, como en app/rutas_denuncias.py. Cada campo de
# texto es TextoLinea o TextoLibre (app/validacion.py): sin NUL, surrogates
# ni caracteres de control.
class Activacion(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    token: TextoLinea = Field(max_length=LONGITUD_MAXIMA_TOKEN)
    contrasena: TextoLinea = Field(min_length=1, max_length=LONGITUD_MAXIMA_CONTRASENA)


class Confirmacion(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    token: TextoLinea = Field(max_length=LONGITUD_MAXIMA_TOKEN)
    codigo_totp: TextoLinea = Field(max_length=LONGITUD_MAXIMA_CODIGO)


class Login(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    empresa: TextoLinea = Field(max_length=LONGITUD_MAXIMA_IDENTIFICADOR)
    email: TextoLinea = Field(max_length=LONGITUD_MAXIMA_EMAIL)
    contrasena: TextoLinea = Field(max_length=LONGITUD_MAXIMA_CONTRASENA)
    codigo_totp: TextoLinea = Field(max_length=LONGITUD_MAXIMA_CODIGO)
    token_dispositivo: TextoLinea | None = Field(default=None, max_length=LONGITUD_MAXIMA_TOKEN)


class Renovacion(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    # Obligatorio para el cliente con Bearer y prohibido en el navegador, que
    # manda {} y lo lleva en su cookie (renovar_sesion).
    token_renovacion: TextoLinea | None = Field(default=None, max_length=LONGITUD_MAXIMA_TOKEN)


class CambioContrasena(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    contrasena_actual: TextoLinea = Field(max_length=LONGITUD_MAXIMA_CONTRASENA)
    contrasena_nueva: TextoLinea = Field(min_length=1, max_length=LONGITUD_MAXIMA_CONTRASENA)
    codigo_totp: TextoLinea = Field(max_length=LONGITUD_MAXIMA_CODIGO)


class NuevoUsuario(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    email: TextoLinea
    rol: Literal[personal.ROLES]

    @field_validator("email")
    @classmethod
    def email_valido(cls, texto):
        return validar_email(texto)


class SolicitudRegistro(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    # Solo empresa y email: un rol o una contraseña en el cuerpo son un 422
    # (extra="forbid"). El rol lo elige el admin al aprobar.
    empresa: TextoLinea = Field(max_length=LONGITUD_MAXIMA_IDENTIFICADOR)
    email: TextoLinea

    @field_validator("email")
    @classmethod
    def email_valido(cls, texto):
        return validar_email(texto)


class VerificacionRegistro(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    token: TextoLinea = Field(max_length=LONGITUD_MAXIMA_TOKEN)


class AprobacionSolicitud(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    rol: Literal[personal.ROLES]


def _texto_no_vacio(texto):
    # Como en app/rutas_denuncias.py: se guarda tal cual, pero un texto solo
    # de espacios no es un mensaje.
    if not texto.strip():
        raise ValueError("texto vacio")
    return texto


class MensajePersonal(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    texto: TextoLibre = Field(min_length=1, max_length=LONGITUD_MAXIMA_TEXTO)

    @field_validator("texto")
    @classmethod
    def no_vacio(cls, texto):
        return _texto_no_vacio(texto)


class CambioEstado(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    estado: Literal[instruccion.ESTADOS_DESTINO]
    mensaje: TextoLibre | None = Field(default=None, min_length=1, max_length=LONGITUD_MAXIMA_TEXTO)

    @field_validator("mensaje")
    @classmethod
    def no_vacio(cls, texto):
        return None if texto is None else _texto_no_vacio(texto)


class Asignacion(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    # Texto y no uuid: un id mal formado es una cuenta que no existe (404),
    # como en la ruta (_uuid).
    usuario_id: TextoLinea = Field(max_length=64)


class Tramo(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    # Posición en caracteres (code points) y el texto exacto que se tacha: si
    # no coinciden, 409 sin escribir nada (app/instruccion.py, cabecera).
    desde: int = Field(ge=0, le=LONGITUD_MAXIMA_TEXTO)
    texto: TextoLibre = Field(min_length=1, max_length=LONGITUD_MAXIMA_TEXTO)


class Redaccion(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    tramos: list[Tramo] = Field(min_length=1, max_length=MAXIMO_TRAMOS)


def _error(codigo, mensaje=None, cabeceras=None):
    return Response(cuerpo_error(codigo, mensaje), status_code=codigo, media_type="application/json",
                    headers=cabeceras)


class LimiteCuentaSuperado(Exception):
    """La cuenta autenticada ha superado su regla "cuenta" en esta ventana, o
    un email su regla "destinatario" (mismo 429)."""

    def __init__(self, segundos):
        super().__init__(segundos)
        self.segundos = segundos


async def _sesion(peticion: Request):
    """Dependencia: sesión del JWT (de la cookie en el navegador, de la
    cabecera Bearer en el cliente), o SesionNoValida; después, la segunda
    capa del limitador, por cuenta. Un token que no vale no consume el
    contador de ninguna cuenta (no se sabe de quién es); lo frena la capa
    por IP del middleware.

    El primer exceso de cada ventana deja un evento con empresa y cuenta (es
    del personal, no del denunciante, y sin IP): es la señal de una sesión
    que se usa de forma anómala. Solo el primero, para que el log no se
    pueda inundar con 429."""
    if peticion.state.navegador:
        token = peticion.state.cookies.get(COOKIE_ACCESO)
    else:
        esquema, _, token = peticion.headers.get("authorization", "").partition(" ")
        if esquema != "Bearer":
            token = None
    if not token:
        raise personal.SesionNoValida
    estado = peticion.app.state
    sesion = await run_in_threadpool(personal.autenticar, estado.pool, estado.claves, token)
    permitida, segundos, primer_exceso = await estado.limitador.consumir_cuenta(
        sesion.empresa_id, sesion.usuario_id)
    if not permitida:
        if primer_exceso:
            registro.warning("EVENTO limite_cuenta: empresa=%s cuenta=%s", sesion.empresa_id, sesion.usuario_id)
        raise LimiteCuentaSuperado(segundos)
    # Para el evento de acceso denegado (ver la cabecera): solo una sesión que
    # la ruta llega a recibir.
    peticion.state.sesion_personal = sesion
    return sesion


# El único tipo con el que una ruta recibe la sesión.
SesionPersonal = Annotated[personal.Sesion, Depends(_sesion)]


def _uuid(texto):
    """Un id de la ruta que no es un uuid es una cuenta que no existe: 404."""
    try:
        return uuid.UUID(texto)
    except ValueError:
        raise personal.NoEncontrado from None


# ---------------------------------------------------------------------------
# Rutas
# ---------------------------------------------------------------------------

@router.post("/activacion")
def activar(datos: Activacion, peticion: Request):
    estado = peticion.app.state
    pendiente = personal.activar(estado.pool, estado.claves, datos.token, datos.contrasena)
    return JSONResponse(content={"secreto_totp": pendiente.secreto_totp, "uri_totp": pendiente.uri_totp})


@router.post("/activacion/confirmar")
def confirmar_activacion(datos: Confirmacion, peticion: Request):
    estado = peticion.app.state
    activacion = personal.confirmar_activacion(estado.pool, estado.claves, datos.token, datos.codigo_totp)
    if not activacion.correos:
        # La activación del primer admin de una empresa no tiene a quién
        # avisar; cualquier otra sin destinatarios es una empresa sin nadie
        # más que vigile (app/avisos.py).
        registro.warning("EVENTO aviso_sin_destinatario: tipo=aviso_activacion empresa=%s",
                         activacion.empresa_id)
    # Los avisos, después de responder: la respuesta no depende de ellos.
    avisar = BackgroundTask(correo.enviar_todos, activacion.correos) if activacion.correos else None
    if not peticion.state.navegador:
        return JSONResponse(content={"token_dispositivo": activacion.token_dispositivo}, background=avisar)
    respuesta = JSONResponse(content={}, background=avisar)
    _poner_cookie(respuesta, COOKIE_DISPOSITIVO, activacion.token_dispositivo, DURACION_DISPOSITIVO)
    return respuesta


def respuesta_con_tokens(peticion, acceso, codigo=200):
    """Respuesta con los tokens de una sesión. expira_en: segundos que dura
    el acceso, para que el cliente renueve antes de que caduque. En el
    navegador, los tokens van en sus cookies y el cuerpo solo lleva
    expira_en: ningún script de la página los ve. La usa también el login
    externo (app/rutas_externo.py): una sesión es la misma venga de donde
    venga."""
    if not peticion.state.navegador:
        contenido = {"token_acceso": acceso.token_acceso, "token_renovacion": acceso.token_renovacion,
                     "expira_en": tokens.DURACION_ACCESO}
        if codigo == 201:
            contenido["token_dispositivo"] = acceso.token_dispositivo
        return JSONResponse(status_code=codigo, content=contenido)
    respuesta = JSONResponse(status_code=codigo, content={"expira_en": tokens.DURACION_ACCESO})
    _poner_cookie(respuesta, COOKIE_ACCESO, acceso.token_acceso, tokens.DURACION_ACCESO)
    _poner_cookie(respuesta, COOKIE_RENOVACION, acceso.token_renovacion, DURACION_RENOVACION)
    # Solo el login entrega dispositivo, y solo si entró sin uno de confianza.
    if codigo == 201 and acceso.token_dispositivo is not None:
        _poner_cookie(respuesta, COOKIE_DISPOSITIVO, acceso.token_dispositivo, DURACION_DISPOSITIVO)
    return respuesta


@router.post("/sesiones", status_code=201)
def iniciar_sesion(datos: Login, peticion: Request):
    estado = peticion.app.state
    dispositivo = datos.token_dispositivo
    if peticion.state.navegador:
        # En el navegador el dispositivo viaja en su cookie; en el cuerpo
        # sería un segundo sitio del que leerlo.
        if dispositivo is not None:
            return _error(422)
        dispositivo = peticion.state.cookies.get(COOKIE_DISPOSITIVO) or None
    acceso = personal.iniciar_sesion(estado.pool, estado.claves, datos.empresa, datos.email, datos.contrasena,
                                     datos.codigo_totp, dispositivo)
    return respuesta_con_tokens(peticion, acceso, 201)


@router.post("/sesiones/renovacion")
def renovar_sesion(datos: Renovacion, peticion: Request):
    estado = peticion.app.state
    if peticion.state.navegador:
        if datos.token_renovacion is not None:
            return _error(422)
        token = peticion.state.cookies.get(COOKIE_RENOVACION)
        if not token:
            raise personal.SesionNoValida
    else:
        if datos.token_renovacion is None:
            return _error(422)
        token = datos.token_renovacion
    return respuesta_con_tokens(peticion, personal.renovar(estado.pool, estado.claves, token))


@router.delete("/sesiones/actual", status_code=204)
def cerrar_sesion(peticion: Request, sesion: SesionPersonal):
    personal.cerrar_sesion(peticion.app.state.pool, sesion)
    respuesta = Response(status_code=204)
    if peticion.state.navegador:
        # La del dispositivo se queda: el equipo sigue siendo de confianza.
        # Un 401 no borra ninguna: con el acceso caducado, la SPA necesita la
        # renovación, y una cookie que ya no vale no abre nada.
        _borrar_cookie(respuesta, COOKIE_ACCESO)
        _borrar_cookie(respuesta, COOKIE_RENOVACION)
    return respuesta


@router.get("/yo")
def yo(peticion: Request, sesion: SesionPersonal):
    pendiente = personal.invitacion_pendiente(peticion.app.state.pool, sesion)
    # El enlace del canal de la empresa, para todo el personal y no solo para
    # el admin: la ley obliga a la empresa a publicarlo (art. 25 de la Ley
    # 2/2023), y así ninguna persona sola es la única que lo conoce. Lo arma
    # la API porque la SPA no conoce el origen del sitio del denunciante: un
    # origen escrito a mano en el cliente se desincronizaría con
    # CANARIO_ORIGEN_WEB, que se valida al arrancar. No es secreto: es el
    # enlace que la empresa debe publicar.
    enlace_canal = f"{peticion.app.state.origen_web}/empresas/{sesion.identificador}"
    # Las cuentas externas vinculadas (app/rutas_externo.py): solo el
    # proveedor y el día, nada que identifique la cuenta externa. /yo es la
    # única fuente de la SPA para pintarlas.
    vinculados = [{"proveedor": v.proveedor, "creada": v.creada.isoformat()}
                  for v in personal.vinculos(peticion.app.state.pool, sesion)]
    return JSONResponse(content={"usuario_id": str(sesion.usuario_id), "email": sesion.email, "rol": sesion.rol,
                                 "invitacion_pendiente": pendiente, "enlace_canal": enlace_canal,
                                 "vinculos": vinculados})


@router.post("/contrasena")
def cambiar_contrasena(datos: CambioContrasena, peticion: Request, sesion: SesionPersonal):
    estado = peticion.app.state
    return respuesta_con_tokens(peticion, personal.cambiar_contrasena(
        estado.pool, estado.claves, sesion, datos.contrasena_actual, datos.contrasena_nueva, datos.codigo_totp))


@router.get("/usuarios")
def listar_usuarios(peticion: Request, sesion: SesionPersonal):
    usuarios = personal.listar_usuarios(peticion.app.state.pool, sesion)
    # Lista explícita de campos: lo que no está aquí no sale (nunca hashes,
    # secretos ni contadores).
    return JSONResponse(content={"usuarios": [{
        "usuario_id": str(u.usuario_id), "email": u.email, "rol": u.rol, "activo": u.activo,
        "activado": u.activado, "camino_sin_confianza_cerrado": u.camino_sin_confianza_cerrado,
        "en_espera": u.en_espera, "invitacion_pendiente": u.invitacion_pendiente,
    } for u in usuarios]})


@router.post("/usuarios", status_code=201)
def invitar(datos: NuevoUsuario, peticion: Request, sesion: SesionPersonal):
    try:
        invitacion = personal.invitar(peticion.app.state.pool, sesion, datos.email, datos.rol)
    except ValueError:
        return _error(422)
    return JSONResponse(status_code=201, content={"usuario_id": str(invitacion.usuario_id),
                                                  "token_invitacion": invitacion.token_invitacion})


@router.post("/usuarios/{usuario_id}/invitacion", status_code=201)
def reinvitar(usuario_id: str, peticion: Request, sesion: SesionPersonal):
    invitacion = personal.reinvitar(peticion.app.state.pool, sesion, _uuid(usuario_id))
    return JSONResponse(status_code=201, content={"usuario_id": str(invitacion.usuario_id),
                                                  "token_invitacion": invitacion.token_invitacion})


@router.delete("/usuarios/{usuario_id}/invitacion", status_code=204)
def anular_invitacion(usuario_id: str, peticion: Request, sesion: SesionPersonal):
    personal.anular_invitacion(peticion.app.state.pool, sesion, _uuid(usuario_id))
    return Response(status_code=204)


@router.post("/usuarios/{usuario_id}/baja", status_code=204)
def dar_de_baja(usuario_id: str, peticion: Request, sesion: SesionPersonal):
    personal.dar_de_baja(peticion.app.state.pool, sesion, _uuid(usuario_id))
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Registro (app/solicitudes.py)
# ---------------------------------------------------------------------------

def _con_correo(contenido, codigo, mensaje):
    """Respuesta JSON y, si hay correo, su envío después de responder. El
    cuerpo y las cabeceras no dependen de que haya correo."""
    return JSONResponse(status_code=codigo, content=contenido,
                        background=None if mensaje is None else BackgroundTask(correo.enviar, mensaje))


@router.post("/registro", status_code=202)
async def solicitar_registro(datos: SolicitudRegistro, peticion: Request):
    estado = peticion.app.state
    # Segunda capa del limitador, por email (app/limitador.py): la cuenta
    # igual exista o no la empresa. El primer exceso de cada regla en su
    # ventana deja un evento con la regla, sin el email.
    permitida, segundos, primeros = await estado.limitador.consumir_destinatario(datos.email)
    if not permitida:
        for regla in primeros:
            registro.warning("EVENTO limite_destinatario: regla=%s", regla)
        raise LimiteCuentaSuperado(segundos)
    # La base de datos y el correo, después de responder (app/solicitudes.py,
    # cabecera): lo que tarde cada camino no llega a la respuesta.
    return JSONResponse(status_code=202, content={"mensaje": MENSAJE_REGISTRO},
                        background=BackgroundTask(solicitudes.procesar, estado.pool, estado.origen_personal,
                                                  datos.empresa, datos.email))


@router.post("/registro/verificacion", status_code=204)
def verificar_registro(datos: VerificacionRegistro, peticion: Request):
    solicitudes.verificar(peticion.app.state.pool, datos.token)
    return Response(status_code=204)


@router.get("/solicitudes")
def listar_solicitudes(peticion: Request, sesion: SesionPersonal):
    listado = solicitudes.listar(peticion.app.state.pool, sesion)
    return JSONResponse(content={"solicitudes": [{"solicitud_id": str(s.solicitud_id), "email": s.email}
                                                 for s in listado.solicitudes],
                                 "hay_mas": listado.hay_mas})


@router.post("/solicitudes/{solicitud_id}/aprobacion", status_code=201)
def aprobar_solicitud(solicitud_id: str, datos: AprobacionSolicitud, peticion: Request, sesion: SesionPersonal):
    estado = peticion.app.state
    try:
        aprobacion = solicitudes.aprobar(estado.pool, sesion, estado.origen_personal, _uuid(solicitud_id),
                                         datos.rol)
    except ValueError:
        return _error(422)
    # Sin token_invitacion: solo lo recibe el email verificado.
    return _con_correo({"usuario_id": str(aprobacion.usuario_id)}, 201, aprobacion.correo)


@router.delete("/solicitudes/{solicitud_id}", status_code=204)
def rechazar_solicitud(solicitud_id: str, peticion: Request, sesion: SesionPersonal):
    solicitudes.rechazar(peticion.app.state.pool, sesion, _uuid(solicitud_id))
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Instrucción (app/instruccion.py)
# ---------------------------------------------------------------------------

def _opcional(valor):
    return None if valor is None else str(valor)


@router.get("/denuncias")
def listar_denuncias(peticion: Request, sesion: SesionPersonal,
                     estado: str | None = Query(default=None, max_length=32),
                     cursor: str | None = Query(default=None, max_length=64)):
    try:
        pagina = instruccion.listar_denuncias(peticion.app.state.pool, sesion, estado, cursor)
    except ValueError:
        return _error(422)
    # Lista explícita de campos: nunca contenido (ni la categoría).
    return JSONResponse(content={"denuncias": [{
        "denuncia_id": str(d.denuncia_id), "fecha": d.fecha.isoformat(), "estado": d.estado,
        "asignada_a": _opcional(d.asignada_a), "asignada_activa": d.asignada_activa,
    } for d in pagina.denuncias], "siguiente": pagina.siguiente})


@router.get("/denuncias/{denuncia_id}")
def leer_denuncia(denuncia_id: str, peticion: Request, sesion: SesionPersonal):
    estado = peticion.app.state
    lectura = instruccion.leer_denuncia(estado.pool, estado.claves, sesion, _uuid(denuncia_id))
    if lectura.umbral is not None:
        # La señal fuera de la base de datos (app/instruccion.py, cabecera),
        # una vez por umbral, cuenta y día. Sin ids de denuncias.
        registro.warning("EVENTO limite_lecturas_%s: empresa=%s cuenta=%s lecturas=%d destinatarios=%d",
                         lectura.umbral, sesion.empresa_id, sesion.usuario_id, lectura.lecturas_hoy,
                         len(lectura.correos))
        if not lectura.correos:
            registro.warning("EVENTO aviso_sin_destinatario: tipo=aviso_lecturas empresa=%s", sesion.empresa_id)
    expediente = lectura.expediente
    return JSONResponse(content={
        "denuncia_id": str(expediente.denuncia_id), "fecha": expediente.fecha.isoformat(),
        "estado": expediente.estado, "categoria": expediente.categoria, "texto": expediente.texto,
        # El personal sí ve quién del personal escribió cada mensaje.
        "mensajes": [{"secuencia": m.secuencia, "fecha": m.fecha.isoformat(), "autor": m.autor,
                      "autor_id": _opcional(m.autor_id), "texto": m.texto} for m in expediente.mensajes],
        # Para que la SPA avise antes de llegar al tope, no después.
        "lecturas": {"hoy": lectura.lecturas_hoy, "tope": instruccion.LECTURAS_TOPE},
    }, background=BackgroundTask(correo.enviar_todos, lectura.correos) if lectura.correos else None)


@router.post("/denuncias/{denuncia_id}/mensajes", status_code=201)
def enviar_mensaje(denuncia_id: str, datos: MensajePersonal, peticion: Request, sesion: SesionPersonal):
    estado = peticion.app.state
    enviado = instruccion.enviar_mensaje(estado.pool, estado.claves, sesion, _uuid(denuncia_id), datos.texto)
    return JSONResponse(status_code=201, content={"secuencia": enviado.secuencia,
                                                  "fecha": enviado.fecha.isoformat()})


@router.post("/denuncias/{denuncia_id}/estado", status_code=204)
def cambiar_estado(denuncia_id: str, datos: CambioEstado, peticion: Request, sesion: SesionPersonal):
    estado = peticion.app.state
    identificador = _uuid(denuncia_id)
    instruccion.cambiar_estado(estado.pool, estado.claves, sesion, identificador, datos.estado, datos.mensaje)
    # Solo tras confirmar (cambiar_estado ya ha vuelto sin error). Ids ya
    # validados como uuid, nunca el texto de la ruta ni contenido. Ver la
    # cabecera de app/instruccion.py.
    if datos.estado == instruccion.ESTADO_NO_VERAZ:
        registro.warning("EVENTO declaracion_no_veraz: empresa=%s cuenta=%s denuncia=%s",
                         sesion.empresa_id, sesion.usuario_id, identificador)
    return Response(status_code=204)


def _registrar_redaccion(sesion, denuncia_id, secuencia, tramos):
    # Solo tras confirmar. Posiciones y longitudes, nunca el texto tachado:
    # con ellas, quien restaure una copia anterior sabe qué volver a tachar
    # (docs/threat-model.md, 8). Ver la cabecera de app/instruccion.py.
    registro.warning("EVENTO redaccion: empresa=%s cuenta=%s denuncia=%s mensaje=%s tramos=%s",
                     sesion.empresa_id, sesion.usuario_id, denuncia_id, "-" if secuencia is None else secuencia,
                     ",".join(f"{t.desde}+{len(t.texto)}" for t in tramos))


@router.post("/denuncias/{denuncia_id}/redaccion", status_code=204)
def redactar_denuncia(denuncia_id: str, datos: Redaccion, peticion: Request, sesion: SesionPersonal):
    estado = peticion.app.state
    identificador = _uuid(denuncia_id)
    if instruccion.redactar_denuncia(estado.pool, estado.claves, sesion, identificador,
                                     [(t.desde, t.texto) for t in datos.tramos]):
        _registrar_redaccion(sesion, identificador, None, datos.tramos)
    return Response(status_code=204)


@router.post("/denuncias/{denuncia_id}/mensajes/{secuencia}/redaccion", status_code=204)
def redactar_mensaje(denuncia_id: str, datos: Redaccion, peticion: Request, sesion: SesionPersonal,
                     secuencia: int = Path(ge=1, le=MAXIMO_MENSAJES)):
    estado = peticion.app.state
    identificador = _uuid(denuncia_id)
    if instruccion.redactar_mensaje(estado.pool, estado.claves, sesion, identificador, secuencia,
                                    [(t.desde, t.texto) for t in datos.tramos]):
        _registrar_redaccion(sesion, identificador, secuencia, datos.tramos)
    return Response(status_code=204)


@router.put("/denuncias/{denuncia_id}/asignacion", status_code=204)
def asignar(denuncia_id: str, datos: Asignacion, peticion: Request, sesion: SesionPersonal):
    instruccion.asignar(peticion.app.state.pool, sesion, _uuid(denuncia_id), _uuid(datos.usuario_id))
    return Response(status_code=204)


def _fila_auditoria(fila):
    return {"secuencia": fila.secuencia, "fecha": fila.fecha.isoformat(), "actor": fila.actor,
            "actor_email": fila.actor_email, "accion": fila.accion, "objeto_id": _opcional(fila.objeto_id),
            "destino_id": _opcional(fila.destino_id), "cuenta_email": fila.cuenta_email}


@router.get("/auditoria")
def listar_auditoria(peticion: Request, sesion: SesionPersonal, desde: int = Query(default=1, ge=1, le=2 ** 62)):
    pagina = instruccion.listar_auditoria(peticion.app.state.pool, sesion, desde)
    return JSONResponse(content={"filas": [_fila_auditoria(f) for f in pagina.filas], "siguiente": pagina.siguiente})


# antes empieza en 2: por debajo de 1 no hay secuencias, así que antes=1 solo
# puede venir de un cliente que se ha equivocado, y se le dice (422) en vez
# de darle una página vacía.
@router.get("/auditoria/recientes")
def listar_auditoria_reciente(peticion: Request, sesion: SesionPersonal,
                              antes: int | None = Query(default=None, ge=2, le=2 ** 62)):
    pagina = instruccion.listar_auditoria_reciente(peticion.app.state.pool, sesion, antes)
    return JSONResponse(content={"filas": [_fila_auditoria(f) for f in pagina.filas], "anterior": pagina.anterior})


@router.get("/auditoria/verificacion")
def verificar_auditoria(peticion: Request, sesion: SesionPersonal):
    primera_rota = instruccion.verificar_auditoria(peticion.app.state.pool, sesion)
    return JSONResponse(content={"cadena_intacta": primera_rota is None, "primera_rota": primera_rota})


# ---------------------------------------------------------------------------
# Errores: una traducción por excepción, igual en todas las rutas
# ---------------------------------------------------------------------------

def _manejador(codigo, mensaje=None, cabeceras=None):
    async def manejar(_peticion, _error_capturado):
        return _error(codigo, mensaje, cabeceras)
    return manejar


# Parámetros de ruta que identifican el recurso denegado. La secuencia de un
# mensaje no hace falta: el recurso es la denuncia.
IDS_EN_RUTA = ("denuncia_id", "usuario_id", "solicitud_id")


def _id_para_registro(texto):
    # Nunca el texto de la ruta: llega decodificado (la especificación ASGI
    # convierte %0A en un salto de línea), y escribirlo permitiría inyectar
    # líneas falsas en el log. Solo un uuid válido, en su forma canónica.
    try:
        return str(uuid.UUID(texto))
    except ValueError:
        return "invalido"


def _registrar_acceso_denegado(peticion, codigo):
    # Sin sesión no se registra nada: el camino anónimo no deja ninguna línea
    # (docs/threat-model.md, 6.5), y estas excepciones solo se lanzan tras
    # autenticar, así que una sin sesión no es una denegación del personal.
    sesion = getattr(peticion.state, "sesion_personal", None)
    if sesion is None:
        return
    # La plantilla de la ruta es un texto fijo del código, no lo que envió el
    # cliente.
    ruta = peticion.scope.get("route")
    ids = ",".join(f"{nombre}={_id_para_registro(valor)}" for nombre, valor in sorted(peticion.path_params.items())
                   if nombre in IDS_EN_RUTA)
    registro.warning("EVENTO acceso_denegado: empresa=%s cuenta=%s codigo=%d metodo=%s ruta=%s ids=%s",
                     sesion.empresa_id, sesion.usuario_id, codigo, peticion.method,
                     "-" if ruta is None else ruta.path, ids or "-")


def _denegado(codigo, mensaje=None):
    async def manejar(peticion, _error_capturado):
        _registrar_acceso_denegado(peticion, codigo)
        return _error(codigo, mensaje)
    return manejar


async def _origen_no_permitido(peticion, error):
    # Sin cuenta (todavía no se ha autenticado) y sin IP. El método lo valida
    # el servidor HTTP, la ruta es la plantilla fija del código y el sitio
    # está normalizado (OrigenNoPermitido): nada de lo escrito por el cliente
    # llega al log tal cual.
    ruta = peticion.scope.get("route")
    registro.warning("EVENTO origen_rechazado: metodo=%s ruta=%s sitio=%s", peticion.method,
                     "-" if ruta is None else ruta.path, error.sitio)
    return _error(403, MENSAJE_PROHIBIDO)


async def _contrasena_no_valida(_peticion, error):
    # El motivo es un texto fijo de app/personal.py: nunca la contraseña.
    return _error(422, str(error))


async def _sin_clave(_peticion, _error_capturado):
    registro.error("EVENTO empresa_sin_clave: una empresa activa no tiene clave de cifrado")
    return _error(503, MENSAJE_SIN_CLAVE)


async def _limite_cuenta(_peticion, error):
    # Mismo cuerpo y misma cabecera que el 429 del middleware.
    return _error(429, None, {"Retry-After": str(error.segundos)})


async def _limite_lecturas(_peticion, error):
    # Sin evento: el del tope ya salió con la lectura que llegó a él, y uno
    # por rechazo dejaría inundar el log.
    return _error(429, MENSAJE_LECTURAS, {"Retry-After": str(error.segundos)})


async def _limitador_no_disponible(_peticion, error):
    # Falla cerrado, como el middleware (app/limitador.py).
    registro.error("EVENTO limitador_no_disponible: %s", error.clase)
    return _error(503, None, {"Retry-After": REINTENTAR_TRAS})


async def _integridad(_peticion, _error_capturado):
    registro.error("INTEGRIDAD: un secreto o una clave del personal no se puede descifrar en su sitio")
    return _error(500)


def instalar_errores(aplicacion):
    aplicacion.add_exception_handler(personal.CredencialesNoValidas, _manejador(401, MENSAJE_CREDENCIALES))
    aplicacion.add_exception_handler(personal.SesionNoValida,
                                     _manejador(401, MENSAJE_SESION, {"WWW-Authenticate": "Bearer"}))
    aplicacion.add_exception_handler(personal.InvitacionNoValida, _manejador(401, MENSAJE_INVITACION))
    aplicacion.add_exception_handler(solicitudes.SolicitudNoValida, _manejador(401, MENSAJE_SOLICITUD))
    aplicacion.add_exception_handler(personal.CodigoNoValido, _manejador(422, MENSAJE_CODIGO))
    aplicacion.add_exception_handler(personal.ContrasenaNoValida, _contrasena_no_valida)
    aplicacion.add_exception_handler(personal.Saturado, _manejador(503, None, {"Retry-After": REINTENTAR_TRAS}))
    aplicacion.add_exception_handler(OrigenNoPermitido, _origen_no_permitido)
    aplicacion.add_exception_handler(personal.Prohibido, _denegado(403, MENSAJE_PROHIBIDO))
    aplicacion.add_exception_handler(personal.NoEncontrado, _denegado(404))
    aplicacion.add_exception_handler(personal.EmailDuplicado, _manejador(409, MENSAJE_DUPLICADO))
    aplicacion.add_exception_handler(personal.UltimoAdmin, _manejador(409, MENSAJE_ULTIMO_ADMIN))
    aplicacion.add_exception_handler(personal.EmpresaSinClave, _sin_clave)
    aplicacion.add_exception_handler(cripto.ErrorIntegridad, _integridad)
    aplicacion.add_exception_handler(LimiteCuentaSuperado, _limite_cuenta)
    aplicacion.add_exception_handler(limitador.NoDisponible, _limitador_no_disponible)
    # Instrucción. La de la clave es la de app/denuncias.py: el mensaje del
    # personal se cifra con la misma pieza que el del denunciante.
    aplicacion.add_exception_handler(denuncias.EmpresaSinClave, _sin_clave)
    aplicacion.add_exception_handler(instruccion.TransicionNoValida, _manejador(409, MENSAJE_TRANSICION))
    aplicacion.add_exception_handler(instruccion.DenunciaCerrada, _manejador(409, MENSAJE_CERRADA))
    aplicacion.add_exception_handler(instruccion.LimiteMensajes, _manejador(409, MENSAJE_LIMITE))
    aplicacion.add_exception_handler(instruccion.DestinoNoValido, _manejador(409, MENSAJE_DESTINO))
    aplicacion.add_exception_handler(instruccion.MensajeFinalObligatorio, _manejador(422, MENSAJE_FINAL))
    aplicacion.add_exception_handler(instruccion.MensajeNoPermitido, _manejador(422, MENSAJE_NO_VERAZ))
    aplicacion.add_exception_handler(instruccion.LimiteLecturas, _limite_lecturas)
    aplicacion.add_exception_handler(instruccion.FragmentoNoCoincide, _manejador(409, MENSAJE_FRAGMENTO))
