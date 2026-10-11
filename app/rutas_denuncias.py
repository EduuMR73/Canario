"""Rutas del denunciante anónimo (docs/threat-model.md, 6.1, 6.5 y 6.11).

* POST /v1/empresas/{identificador}/denuncias: crea una denuncia y devuelve,
  una sola vez, su código de seguimiento y su fecha.
* POST /v1/seguimiento: estado, contenido y mensajes de la denuncia de un
  código.
* POST /v1/seguimiento/mensajes: añade un mensaje del denunciante a la
  denuncia de un código.

El código va siempre en el cuerpo y nunca en la URL: así no queda en
historiales, en la cabecera Referer ni en ningún registro de rutas.

Respuestas uniformes: una empresa desconocida, mal formada o inactiva da
exactamente el mismo 404 que cualquier ruta inexistente, así que no se puede
distinguir "esa empresa no existe" de "esa URL no existe" (un identificador
con "%2F" ni siquiera llega a esta ruta). Un código mal formado o inexistente
da siempre el mismo 404 del seguimiento, también al enviar un mensaje. Ni el
id interno de la denuncia ni el de un mensaje salen de la API, y de un
mensaje del personal solo se dice que es del personal, nunca de quién.

Registro: solo fallos, con el tipo de evento y sin empresa, denuncia ni
código (app/denuncias.py explica por qué). Una denuncia cerrada o llena
(409) es una respuesta normal del flujo y no se registra.

Las funciones son síncronas (def): FastAPI las ejecuta en su pool de hilos y
el acceso a la base de datos es síncrono (docs/threat-model.md, 6.10).
"""
import logging
from typing import Literal

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app import cripto, denuncias
from app.frontera_http import cuerpo_error

registro = logging.getLogger("canario.denuncias")

router = APIRouter(prefix="/v1")

# Para la denuncia y para cada mensaje. Con el peor escapado JSON cabe en el
# límite de cuerpo (app/frontera_http.py, LIMITE_CUERPO).
LONGITUD_MAXIMA_TEXTO = 10_000

MENSAJE_CODIGO = "código de seguimiento no válido"
MENSAJE_SIN_CLAVE = "el canal de esta empresa no está disponible; inténtelo más tarde"
MENSAJE_CERRADA = "la denuncia está cerrada y no admite mensajes"
MENSAJE_LIMITE = "la denuncia ha alcanzado el máximo de mensajes"


def _texto_no_vacio(texto):
    # Se guarda tal cual llega (es una prueba y no se modifica), pero un texto
    # solo de espacios no es una denuncia ni un mensaje.
    if not texto.strip():
        raise ValueError("texto vacio")
    return texto


# extra="forbid": un campo desconocido es un error, no se ignora.
# strict=True: sin conversiones implícitas (un número no pasa por texto).
class NuevaDenuncia(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    categoria: Literal[denuncias.CATEGORIAS]
    texto: str = Field(min_length=1, max_length=LONGITUD_MAXIMA_TEXTO)

    @field_validator("texto")
    @classmethod
    def no_vacio(cls, texto):
        return _texto_no_vacio(texto)


class ConsultaSeguimiento(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    # Sin límite de longitud aquí: un código demasiado largo es un código mal
    # formado y debe dar el mismo 404 que uno inexistente, no un 422. El
    # cuerpo ya está acotado por LimiteCuerpo y cripto.leer_codigo descarta
    # lo que pase de su longitud máxima antes de procesarlo.
    codigo: str


class NuevoMensaje(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    # Como en ConsultaSeguimiento: sin límite propio.
    codigo: str
    texto: str = Field(min_length=1, max_length=LONGITUD_MAXIMA_TEXTO)

    @field_validator("texto")
    @classmethod
    def no_vacio(cls, texto):
        return _texto_no_vacio(texto)


def _error(codigo, mensaje):
    """Mismo formato que el resto de errores de la API (app/frontera_http.py)."""
    return Response(cuerpo_error(codigo, mensaje), status_code=codigo, media_type="application/json")


@router.post("/empresas/{identificador}/denuncias", status_code=201)
def crear_denuncia(identificador: str, datos: NuevaDenuncia, peticion: Request):
    estado = peticion.app.state
    try:
        creada = denuncias.crear(estado.pool, estado.claves, identificador, datos.categoria, datos.texto)
    except denuncias.EmpresaNoEncontrada:
        # El 404 genérico de la API (app/frontera_http.py), sin mensaje propio.
        return _error(404, None)
    except denuncias.EmpresaSinClave:
        registro.error("EVENTO empresa_sin_clave: una empresa activa no tiene clave de cifrado")
        return _error(503, MENSAJE_SIN_CLAVE)
    except cripto.ErrorIntegridad:
        registro.error("INTEGRIDAD: una clave de empresa no se puede desenvolver")
        return _error(500, None)
    return JSONResponse(status_code=201, content={
        "codigo_seguimiento": creada.codigo_seguimiento,
        "fecha": creada.fecha.isoformat(),
    })


@router.post("/seguimiento")
def consultar_seguimiento(datos: ConsultaSeguimiento, peticion: Request):
    estado = peticion.app.state
    try:
        denuncia = denuncias.consultar(estado.pool, estado.claves, datos.codigo)
    except denuncias.CodigoNoEncontrado:
        return _error(404, MENSAJE_CODIGO)
    except cripto.ErrorIntegridad:
        registro.error("INTEGRIDAD: un contenido cifrado no se puede descifrar en su sitio")
        return _error(500, None)
    return JSONResponse(content={
        "estado": denuncia.estado,
        "fecha": denuncia.fecha.isoformat(),
        "categoria": denuncia.categoria,
        "texto": denuncia.texto,
        # Lista explícita de campos: lo que no está aquí no sale.
        "mensajes": [{
            "secuencia": mensaje.secuencia,
            "fecha": mensaje.fecha.isoformat(),
            "autor": mensaje.autor,
            "texto": mensaje.texto,
        } for mensaje in denuncia.mensajes],
    })


@router.post("/seguimiento/mensajes", status_code=201)
def enviar_mensaje(datos: NuevoMensaje, peticion: Request):
    estado = peticion.app.state
    try:
        enviado = denuncias.enviar_mensaje(estado.pool, estado.claves, datos.codigo, datos.texto)
    except denuncias.CodigoNoEncontrado:
        return _error(404, MENSAJE_CODIGO)
    except denuncias.DenunciaCerrada:
        return _error(409, MENSAJE_CERRADA)
    except denuncias.LimiteMensajes:
        return _error(409, MENSAJE_LIMITE)
    except denuncias.EmpresaSinClave:
        registro.error("EVENTO empresa_sin_clave: una empresa activa no tiene clave de cifrado")
        return _error(503, MENSAJE_SIN_CLAVE)
    except cripto.ErrorIntegridad:
        registro.error("INTEGRIDAD: una clave de empresa no se puede desenvolver")
        return _error(500, None)
    return JSONResponse(status_code=201, content={
        "secuencia": enviado.secuencia,
        "fecha": enviado.fecha.isoformat(),
    })
