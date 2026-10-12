"""Rutas del personal (docs/threat-model.md, 6.3).

* POST /v1/personal/activacion: con el token de invitación, fija la
  contraseña y devuelve el secreto TOTP (texto y URI otpauth para el QR).
* POST /v1/personal/activacion/confirmar: con el token y un código, activa la
  cuenta y devuelve el primer token de dispositivo de confianza.
* POST /v1/personal/sesiones: login (empresa, email, contraseña, código y,
  si lo tiene, el token de dispositivo). Devuelve el token de sesión y, si
  el login fue sin dispositivo de confianza, uno nuevo.
* DELETE /v1/personal/sesiones/actual: cierra la sesión.
* GET /v1/personal/yo: cuenta de la sesión.
* POST /v1/personal/contrasena: cambia la contraseña (actual, nueva y código).
* GET y POST /v1/personal/usuarios, POST .../{usuario_id}/invitacion y
  .../{usuario_id}/baja: administración de cuentas, solo admin.

Este módulo es el único que sabe cómo viajan los tokens: el de sesión en la
cabecera Authorization (Bearer) y el de dispositivo en el cuerpo del login.
Sin cookies no hay CSRF: el navegador nunca envía estas credenciales por su
cuenta. Un frontend web cambiaría solo esta capa (cookies __Host- HttpOnly,
Secure y SameSite=Strict, más defensa CSRF), no app/personal.py.

Respuestas: cualquier fallo del login da el mismo 401, con el mismo cuerpo
(app/personal.py explica por qué el tiempo también es el mismo). Un token
de sesión que no vale da otro 401 con WWW-Authenticate: Bearer. Una cuenta de
otra empresa es invisible (RLS) y da el 404 genérico, igual que una
inexistente. Un rol insuficiente da 403.

Las funciones son síncronas (def): FastAPI las ejecuta en su pool de hilos,
y tanto la base de datos como Argon2 son síncronos.
"""
import logging
import uuid
from typing import Literal

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app import cripto, personal
from app.frontera_http import REINTENTAR_TRAS, cuerpo_error

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

# Topes de forma de la petición, holgados respecto a lo válido: lo que pase
# de aquí es un 422, sin llegar a la lógica. La política de contraseñas
# (12 a 128 caracteres tras NFKC) la aplica app/personal.py.
LONGITUD_MAXIMA_CONTRASENA = 512
LONGITUD_MAXIMA_TOKEN = 128
LONGITUD_MAXIMA_CODIGO = 16
LONGITUD_MAXIMA_EMAIL = 254
LONGITUD_MAXIMA_IDENTIFICADOR = 64


def _email(texto):
    """ASCII, sin espacios y con '@' después del primer carácter. En
    minúsculas, como exige el CHECK de la tabla. Solo ASCII: lower() de
    Python y de PostgreSQL coinciden en ASCII, no siempre fuera de él."""
    if (not texto.isascii() or any(c.isspace() for c in texto)
            or not 3 <= len(texto) <= LONGITUD_MAXIMA_EMAIL or texto.find("@") < 1):
        raise ValueError("email no valido")
    return texto.lower()


# extra="forbid" y strict=True, como en app/rutas_denuncias.py.
class Activacion(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    token: str = Field(max_length=LONGITUD_MAXIMA_TOKEN)
    contrasena: str = Field(min_length=1, max_length=LONGITUD_MAXIMA_CONTRASENA)


class Confirmacion(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    token: str = Field(max_length=LONGITUD_MAXIMA_TOKEN)
    codigo_totp: str = Field(max_length=LONGITUD_MAXIMA_CODIGO)


class Login(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    empresa: str = Field(max_length=LONGITUD_MAXIMA_IDENTIFICADOR)
    email: str = Field(max_length=LONGITUD_MAXIMA_EMAIL)
    contrasena: str = Field(max_length=LONGITUD_MAXIMA_CONTRASENA)
    codigo_totp: str = Field(max_length=LONGITUD_MAXIMA_CODIGO)
    token_dispositivo: str | None = Field(default=None, max_length=LONGITUD_MAXIMA_TOKEN)


class CambioContrasena(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    contrasena_actual: str = Field(max_length=LONGITUD_MAXIMA_CONTRASENA)
    contrasena_nueva: str = Field(min_length=1, max_length=LONGITUD_MAXIMA_CONTRASENA)
    codigo_totp: str = Field(max_length=LONGITUD_MAXIMA_CODIGO)


class NuevoUsuario(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    email: str
    rol: Literal[personal.ROLES]

    @field_validator("email")
    @classmethod
    def email_valido(cls, texto):
        return _email(texto)


def _error(codigo, mensaje=None, cabeceras=None):
    return Response(cuerpo_error(codigo, mensaje), status_code=codigo, media_type="application/json",
                    headers=cabeceras)


def _sesion(peticion):
    """Sesión del token Bearer, o SesionNoValida."""
    esquema, _, token = peticion.headers.get("authorization", "").partition(" ")
    if esquema != "Bearer" or not token:
        raise personal.SesionNoValida
    return personal.autenticar(peticion.app.state.pool, token)


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


@router.post("/sesiones", status_code=201)
def iniciar_sesion(datos: Login, peticion: Request):
    estado = peticion.app.state
    acceso = personal.iniciar_sesion(estado.pool, estado.claves, datos.empresa, datos.email, datos.contrasena,
                                     datos.codigo_totp, datos.token_dispositivo)
    return JSONResponse(status_code=201, content={"token_sesion": acceso.token_sesion,
                                                  "token_dispositivo": acceso.token_dispositivo})


@router.delete("/sesiones/actual", status_code=204)
def cerrar_sesion(peticion: Request):
    personal.cerrar_sesion(peticion.app.state.pool, _sesion(peticion))
    return Response(status_code=204)


@router.get("/yo")
def yo(peticion: Request):
    sesion = _sesion(peticion)
    return JSONResponse(content={"usuario_id": str(sesion.usuario_id), "email": sesion.email, "rol": sesion.rol})


@router.post("/contrasena", status_code=204)
def cambiar_contrasena(datos: CambioContrasena, peticion: Request):
    estado = peticion.app.state
    personal.cambiar_contrasena(estado.pool, estado.claves, _sesion(peticion), datos.contrasena_actual,
                                datos.contrasena_nueva, datos.codigo_totp)
    return Response(status_code=204)


@router.get("/usuarios")
def listar_usuarios(peticion: Request):
    usuarios = personal.listar_usuarios(peticion.app.state.pool, _sesion(peticion))
    # Lista explícita de campos: lo que no está aquí no sale (nunca hashes,
    # secretos ni contadores).
    return JSONResponse(content={"usuarios": [{
        "usuario_id": str(u.usuario_id), "email": u.email, "rol": u.rol, "activo": u.activo,
        "activado": u.activado, "camino_sin_confianza_cerrado": u.camino_sin_confianza_cerrado,
        "en_espera": u.en_espera,
    } for u in usuarios]})


@router.post("/usuarios", status_code=201)
def invitar(datos: NuevoUsuario, peticion: Request):
    try:
        invitacion = personal.invitar(peticion.app.state.pool, _sesion(peticion), datos.email, datos.rol)
    except ValueError:
        return _error(422)
    return JSONResponse(status_code=201, content={"usuario_id": str(invitacion.usuario_id),
                                                  "token_invitacion": invitacion.token_invitacion})


@router.post("/usuarios/{usuario_id}/invitacion", status_code=201)
def reinvitar(usuario_id: str, peticion: Request):
    sesion = _sesion(peticion)
    invitacion = personal.reinvitar(peticion.app.state.pool, sesion, _uuid(usuario_id))
    return JSONResponse(status_code=201, content={"usuario_id": str(invitacion.usuario_id),
                                                  "token_invitacion": invitacion.token_invitacion})


@router.post("/usuarios/{usuario_id}/baja", status_code=204)
def dar_de_baja(usuario_id: str, peticion: Request):
    sesion = _sesion(peticion)
    personal.dar_de_baja(peticion.app.state.pool, sesion, _uuid(usuario_id))
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Errores: una traducción por excepción, igual en todas las rutas
# ---------------------------------------------------------------------------

def _manejador(codigo, mensaje=None, cabeceras=None):
    async def manejar(_peticion, _error_capturado):
        return _error(codigo, mensaje, cabeceras)
    return manejar


async def _contrasena_no_valida(_peticion, error):
    # El motivo es un texto fijo de app/personal.py: nunca la contraseña.
    return _error(422, str(error))


async def _sin_clave(_peticion, _error_capturado):
    registro.error("EVENTO empresa_sin_clave: una empresa activa no tiene clave de cifrado")
    return _error(503, MENSAJE_SIN_CLAVE)


async def _integridad(_peticion, _error_capturado):
    registro.error("INTEGRIDAD: un secreto o una clave del personal no se puede descifrar en su sitio")
    return _error(500)


def instalar_errores(aplicacion):
    aplicacion.add_exception_handler(personal.CredencialesNoValidas, _manejador(401, MENSAJE_CREDENCIALES))
    aplicacion.add_exception_handler(personal.SesionNoValida,
                                     _manejador(401, MENSAJE_SESION, {"WWW-Authenticate": "Bearer"}))
    aplicacion.add_exception_handler(personal.InvitacionNoValida, _manejador(401, MENSAJE_INVITACION))
    aplicacion.add_exception_handler(personal.CodigoNoValido, _manejador(422, MENSAJE_CODIGO))
    aplicacion.add_exception_handler(personal.ContrasenaNoValida, _contrasena_no_valida)
    aplicacion.add_exception_handler(personal.Saturado, _manejador(503, None, {"Retry-After": REINTENTAR_TRAS}))
    aplicacion.add_exception_handler(personal.Prohibido, _manejador(403, MENSAJE_PROHIBIDO))
    aplicacion.add_exception_handler(personal.NoEncontrado, _manejador(404))
    aplicacion.add_exception_handler(personal.EmailDuplicado, _manejador(409, MENSAJE_DUPLICADO))
    aplicacion.add_exception_handler(personal.UltimoAdmin, _manejador(409, MENSAJE_ULTIMO_ADMIN))
    aplicacion.add_exception_handler(personal.EmpresaSinClave, _sin_clave)
    aplicacion.add_exception_handler(cripto.ErrorIntegridad, _integridad)
