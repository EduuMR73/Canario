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
  aviso de una reinvitación de esa cuenta).
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
  GET /v1/personal/auditoria y GET /v1/personal/auditoria/verificacion (solo
  admin).

Este módulo es el único que sabe cómo viajan los tokens: el JWT de acceso en
la cabecera Authorization (Bearer), y los de renovación y dispositivo en el
cuerpo de sus peticiones. Sin cookies no hay CSRF: el navegador nunca envía
estas credenciales por su cuenta (OWASP, Cross-Site Request Forgery
Prevention Cheat Sheet: el ataque funciona porque el navegador añade las
cookies solo). Un frontend web cambiaría solo esta capa (cookies __Host-
HttpOnly, Secure y SameSite=Strict, más defensa CSRF), no app/personal.py.

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

router = APIRouter(prefix="/v1/personal")

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
MENSAJE_DESTINO = "la cuenta de destino no está activa"
MENSAJE_FINAL = "cerrar una denuncia exige un mensaje final para el denunciante"
MENSAJE_NO_VERAZ = "declarar una denuncia no veraz no admite mensaje"
MENSAJE_FRAGMENTO = "el texto indicado no está en esa posición"
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

    token_renovacion: TextoLinea = Field(max_length=LONGITUD_MAXIMA_TOKEN)


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
    """Dependencia: sesión del JWT Bearer, o SesionNoValida; después, la
    segunda capa del limitador, por cuenta. Un token que no vale no consume
    el contador de ninguna cuenta (no se sabe de quién es); lo frena la capa
    por IP del middleware.

    El primer exceso de cada ventana deja un evento con empresa y cuenta (es
    del personal, no del denunciante, y sin IP): es la señal de una sesión
    que se usa de forma anómala. Solo el primero, para que el log no se
    pueda inundar con 429."""
    esquema, _, token = peticion.headers.get("authorization", "").partition(" ")
    if esquema != "Bearer" or not token:
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
    token = personal.confirmar_activacion(estado.pool, estado.claves, datos.token, datos.codigo_totp)
    return JSONResponse(content={"token_dispositivo": token})


def _tokens(acceso, codigo=200):
    """Respuesta con los tokens de una sesión. expira_en: segundos que dura
    el acceso, para que el cliente renueve antes de que caduque."""
    contenido = {"token_acceso": acceso.token_acceso, "token_renovacion": acceso.token_renovacion,
                 "expira_en": tokens.DURACION_ACCESO}
    if codigo == 201:
        contenido["token_dispositivo"] = acceso.token_dispositivo
    return JSONResponse(status_code=codigo, content=contenido)


@router.post("/sesiones", status_code=201)
def iniciar_sesion(datos: Login, peticion: Request):
    estado = peticion.app.state
    acceso = personal.iniciar_sesion(estado.pool, estado.claves, datos.empresa, datos.email, datos.contrasena,
                                     datos.codigo_totp, datos.token_dispositivo)
    return _tokens(acceso, 201)


@router.post("/sesiones/renovacion")
def renovar_sesion(datos: Renovacion, peticion: Request):
    estado = peticion.app.state
    return _tokens(personal.renovar(estado.pool, estado.claves, datos.token_renovacion))


@router.delete("/sesiones/actual", status_code=204)
def cerrar_sesion(peticion: Request, sesion: SesionPersonal):
    personal.cerrar_sesion(peticion.app.state.pool, sesion)
    return Response(status_code=204)


@router.get("/yo")
def yo(peticion: Request, sesion: SesionPersonal):
    pendiente = personal.invitacion_pendiente(peticion.app.state.pool, sesion)
    return JSONResponse(content={"usuario_id": str(sesion.usuario_id), "email": sesion.email, "rol": sesion.rol,
                                 "invitacion_pendiente": pendiente})


@router.post("/contrasena")
def cambiar_contrasena(datos: CambioContrasena, peticion: Request, sesion: SesionPersonal):
    estado = peticion.app.state
    return _tokens(personal.cambiar_contrasena(estado.pool, estado.claves, sesion, datos.contrasena_actual,
                                               datos.contrasena_nueva, datos.codigo_totp))


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
    expediente = instruccion.leer_denuncia(estado.pool, estado.claves, sesion, _uuid(denuncia_id))
    return JSONResponse(content={
        "denuncia_id": str(expediente.denuncia_id), "fecha": expediente.fecha.isoformat(),
        "estado": expediente.estado, "categoria": expediente.categoria, "texto": expediente.texto,
        # El personal sí ve quién del personal escribió cada mensaje.
        "mensajes": [{"secuencia": m.secuencia, "fecha": m.fecha.isoformat(), "autor": m.autor,
                      "autor_id": _opcional(m.autor_id), "texto": m.texto} for m in expediente.mensajes],
    })


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


@router.get("/auditoria")
def listar_auditoria(peticion: Request, sesion: SesionPersonal, desde: int = Query(default=1, ge=1, le=2 ** 62)):
    pagina = instruccion.listar_auditoria(peticion.app.state.pool, sesion, desde)
    return JSONResponse(content={
        "filas": [{"secuencia": f.secuencia, "fecha": f.fecha.isoformat(), "actor": f.actor, "accion": f.accion,
                   "objeto_id": _opcional(f.objeto_id), "destino_id": _opcional(f.destino_id)}
                  for f in pagina.filas],
        "siguiente": pagina.siguiente,
    })


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


async def _contrasena_no_valida(_peticion, error):
    # El motivo es un texto fijo de app/personal.py: nunca la contraseña.
    return _error(422, str(error))


async def _sin_clave(_peticion, _error_capturado):
    registro.error("EVENTO empresa_sin_clave: una empresa activa no tiene clave de cifrado")
    return _error(503, MENSAJE_SIN_CLAVE)


async def _limite_cuenta(_peticion, error):
    # Mismo cuerpo y misma cabecera que el 429 del middleware.
    return _error(429, None, {"Retry-After": str(error.segundos)})


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
    aplicacion.add_exception_handler(instruccion.FragmentoNoCoincide, _manejador(409, MENSAJE_FRAGMENTO))
