"""Frontera HTTP de la API (docs/threat-model.md, 6.11).

Tres piezas que no dependen de ninguna ruta concreta:

* LimiteCuerpo: ninguna petición pasa de LIMITE_CUERPO bytes. Caddy aplica el
  mismo límite, y este es la segunda capa: si la API quedara expuesta sin
  proxy, uvicorn no tiene límite propio. Lee el cuerpo entero aquí, con la
  memoria acotada por el límite, y se lo entrega ya leído a la aplicación:
  así cuenta los bytes reales aunque Content-Length mienta o no exista, y no
  depende de cómo FastAPI lea el cuerpo (FastAPI convierte en 400 cualquier
  excepción que salte al leerlo, salvo HTTPException; comprobado en
  fastapi/routing.py de la versión fijada).
* ErroresInternos: un error no previsto responde 500 genérico y solo registra
  la clase del error y su SQLSTATE. Hace falta como middleware propio porque el
  ServerErrorMiddleware de Starlette, aunque haya un manejador de 500, siempre
  vuelve a lanzar la excepción, y uvicorn volcaría el traceback con el
  mensaje, que puede llevar valores de la fila (comprobado en
  starlette/middleware/errors.py de la versión fijada).
* Respuestas de error uniformes y en castellano. El 422 nunca devuelve lo que
  envió el cliente: el de FastAPI incluye el campo "input" con su valor.
* Saturación: si una consulta agota lock_timeout (55P03) o statement_timeout
  (57014) de app/bd.py, la respuesta es 503 con Retry-After, no 500. No es un
  error del servidor sino contención pasajera (por ejemplo, un mensaje que
  espera a que el personal termine de cambiar el estado de su denuncia), y el
  cliente debe saber que puede reintentar. Se registra solo la clase y el
  SQLSTATE, como el resto de errores.
"""
import json
import logging

from fastapi.exceptions import RequestValidationError
from fastapi.responses import Response
from psycopg import errors as errores_bd
from starlette.exceptions import HTTPException

registro = logging.getLogger("canario.api")

# 128 KiB. El texto de una denuncia admite 10 000 caracteres: en el peor caso
# de escapado JSON (caracteres fuera del plano básico, 12 bytes cada uno) son
# 120 000 bytes más el resto del cuerpo. proxy/Caddyfile usa el mismo valor.
LIMITE_CUERPO = 128 * 1024

MENSAJES = {
    400: "petición no válida",
    404: "recurso no encontrado",
    405: "método no permitido",
    413: "cuerpo de la petición demasiado grande",
    422: "petición no válida",
    500: "error interno",
    503: "servicio ocupado; inténtelo de nuevo en unos segundos",
}

# Segundos que se sugieren al cliente antes de reintentar tras una saturación.
# Del orden de lock_timeout (2 s, app/bd.py) con margen.
REINTENTAR_TRAS = "5"


def cuerpo_error(codigo, mensaje=None):
    return json.dumps({"detalle": mensaje or MENSAJES.get(codigo, "error")},
                      ensure_ascii=False).encode("utf-8")


async def _responder(send, codigo, cabeceras=(), mensaje=None):
    cuerpo = cuerpo_error(codigo, mensaje)
    await send({"type": "http.response.start", "status": codigo,
                "headers": [(b"content-type", b"application/json"),
                            (b"content-length", str(len(cuerpo)).encode("ascii")),
                            *cabeceras]})
    await send({"type": "http.response.body", "body": cuerpo})


def describir_error(error):
    """Clase y SQLSTATE: nunca el mensaje, que puede incluir valores."""
    sqlstate = getattr(error, "sqlstate", None)
    return f"{type(error).__name__} {sqlstate}" if sqlstate else type(error).__name__


class LimiteCuerpo:
    def __init__(self, app, maximo=LIMITE_CUERPO):
        self.app = app
        self.maximo = maximo

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declarada = dict(scope["headers"]).get(b"content-length")
        if declarada is not None:
            if not declarada.isdigit():
                await _responder(send, 400)
                return
            # Se rechaza antes de leer nada.
            if int(declarada) > self.maximo:
                await _responder(send, 413, [(b"connection", b"close")])
                return
        partes = []
        recibidos = 0
        while True:
            mensaje = await receive()
            if mensaje["type"] == "http.disconnect":
                return
            trozo = mensaje.get("body", b"")
            recibidos += len(trozo)
            # Cuenta lo que llega de verdad: cubre un Content-Length falso y
            # el envío por trozos sin Content-Length.
            if recibidos > self.maximo:
                await _responder(send, 413, [(b"connection", b"close")])
                return
            partes.append(trozo)
            if not mensaje.get("more_body", False):
                break
        cuerpo = b"".join(partes)
        entregado = False

        async def recibir():
            nonlocal entregado
            if not entregado:
                entregado = True
                return {"type": "http.request", "body": cuerpo, "more_body": False}
            return await receive()

        await self.app(scope, recibir, send)


class ErroresInternos:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        iniciada = False

        async def enviar(mensaje):
            nonlocal iniciada
            if mensaje["type"] == "http.response.start":
                iniciada = True
            await send(mensaje)

        try:
            await self.app(scope, receive, enviar)
        except Exception as error:  # noqa: BLE001 - es justo su función: ningún error sale de aquí
            registro.error("ERROR INTERNO: %s", describir_error(error))
            # Si la respuesta ya había empezado no se puede enviar otra: la
            # conexión se cierra incompleta y el cliente lo ve.
            if not iniciada:
                await _responder(send, 500)


async def _http_exception(_peticion, error):
    # Conserva las cabeceras del error (por ejemplo Allow en un 405).
    return Response(cuerpo_error(error.status_code), status_code=error.status_code,
                    media_type="application/json", headers=getattr(error, "headers", None))


async def _validacion(_peticion, _error):
    return Response(cuerpo_error(422), status_code=422, media_type="application/json")


async def _saturacion(_peticion, error):
    registro.warning("SATURACION: %s", describir_error(error))
    return Response(cuerpo_error(503), status_code=503, media_type="application/json",
                    headers={"Retry-After": REINTENTAR_TRAS})


def instalar(aplicacion):
    """Middlewares y manejadores. ErroresInternos se añade el último para
    quedar por fuera de LimiteCuerpo: Starlette pone el último añadido en la
    posición más externa."""
    aplicacion.add_exception_handler(HTTPException, _http_exception)
    aplicacion.add_exception_handler(RequestValidationError, _validacion)
    # Solo estas dos clases: cualquier otro error de la base de datos sigue
    # siendo un 500 de ErroresInternos.
    aplicacion.add_exception_handler(errores_bd.LockNotAvailable, _saturacion)
    aplicacion.add_exception_handler(errores_bd.QueryCanceled, _saturacion)
    aplicacion.add_middleware(LimiteCuerpo)
    aplicacion.add_middleware(ErroresInternos)
