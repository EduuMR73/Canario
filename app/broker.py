"""Broker de canje: con el cartero del correo (app/cartero.py), el único
contenedor de Canario con salida a internet.

La API guarda en memoria la clave maestra y la de firma de los JWT, y no
tiene salida a internet: así, si la comprometen, no tiene por dónde sacarlas
(docs/threat-model.md, 6.11). El login con un proveedor externo necesita
hablar con ese proveedor, y eso lo hace este proceso aparte, que no tiene
ninguna clave de Canario ni acceso a la base de datos. Es la separación de
privilegios de docs/threat-model.md, 6.19: si cae el broker, el atacante
tiene los client_secret de los proveedores, no los datos de las denuncias.

Quién le habla: solo la API, por la red interna canje. uvicorn escucha solo en
la IP del broker en esa red (--host en docker-compose.yml) y, además, toda
ruta salvo /salud exige que la conexión venga de la IP fija de la API
(CANARIO_IP_API). Lo segundo no sustituye a lo primero: es defensa en
profundidad por si alguien conectara otro servicio a canje.

Qué hace, y nada más:
* GET /salud: vivacidad (el healthcheck, desde el propio contenedor).
* GET /proveedores: qué proveedores están configurados.
* POST /autorizar: la URL de autorización del proveedor, con el state, el
  code_challenge y el nonce que genera la API.
* POST /canjear: canjea un code y devuelve solo (proveedor, sub). Ningún token
  sale de aquí.
La API no elige adónde se envía nada: endpoints y redirect_uri están fijos en
app/proveedores_externos.py. Lo que manda se valida por formato antes de
usarlo, así que una API comprometida tampoco puede usar el broker como canal
hacia fuera.

Respuestas: 422 con el mismo cuerpo para cualquier entrada que no vale (sin
repetir lo recibido), 401 si el proveedor rechaza el canje, 503 si no se
puede hablar con él o el broker está ocupado, 403 a otra IP. Los EVENTO del
log llevan el proveedor y un motivo fijo, nunca el code, el verifier, un
token, el client_secret ni el sub.
"""
import ipaddress
import logging
import os
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from app import proveedores_externos as externos

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
registro = logging.getLogger("canario.broker")

VARIABLE_IP_API = "CANARIO_IP_API"
# Las peticiones de la API son unos pocos cientos de bytes. Se exige
# Content-Length y un tope antes de leer el cuerpo.
TAMANO_MAXIMO_PETICION = 4096
# Canjes simultáneos: cada uno puede tardar hasta PLAZO_TOTAL_SEGUNDOS. Si no
# hay hueco, 503 en el acto en vez de encolar hilos.
CANJES_SIMULTANEOS = 4

CUERPO_FORMATO = {"detalle": "formato no valido"}
CUERPO_PROHIBIDO = {"detalle": "prohibido"}
CUERPO_NO_CONFIGURADO = {"detalle": "proveedor no configurado"}
CUERPO_FALLIDO = {"detalle": "canje fallido"}
CUERPO_NO_DISPONIBLE = {"detalle": "proveedor no disponible"}


class ArranqueBloqueado(Exception):
    """La configuración no es válida: el broker no arranca y el motivo queda
    en el log."""


def cargar_ip_api(entorno=None):
    entorno = os.environ if entorno is None else entorno
    texto = entorno.get(VARIABLE_IP_API)
    try:
        return str(ipaddress.IPv4Address(texto or ""))
    except ValueError:
        raise ArranqueBloqueado(f"{VARIABLE_IP_API}: obligatoria, una IPv4") from None


@asynccontextmanager
async def ciclo_de_vida(app):
    try:
        app.state.ip_api = cargar_ip_api()
        origen = externos.cargar_origen()
        google = externos.cargar_google(origen)
    except externos.ErrorConfiguracion as error:
        registro.error("ARRANQUE BLOQUEADO: %s", error)
        raise ArranqueBloqueado(str(error)) from None
    except ArranqueBloqueado as error:
        registro.error("ARRANQUE BLOQUEADO: %s", error)
        raise
    app.state.proveedores = {}
    if google is None:
        # Visible en cada arranque: sin configurar, el login con Google no
        # aparece en la SPA y quien opera lo ve aquí.
        registro.warning("EVENTO proveedor_desactivado: proveedor=google")
    else:
        app.state.proveedores[externos.PROVEEDOR_GOOGLE] = google
        registro.info("PROVEEDOR ACTIVADO: proveedor=google redirect_uri=%s", google.redirect_uri)
    app.state.canjes = threading.BoundedSemaphore(CANJES_SIMULTANEOS)
    yield


# Sin /docs, /redoc ni /openapi.json, y sin redirecciones implícitas, como la
# API (app/principal.py).
aplicacion = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, redirect_slashes=False,
                     lifespan=ciclo_de_vida)


@aplicacion.exception_handler(RequestValidationError)
async def _formato_no_valido(_peticion, _error):
    # El 422 de FastAPI repite la entrada recibida ("input"): aquí podría ser
    # un code o un verifier. Siempre el mismo cuerpo.
    return JSONResponse(CUERPO_FORMATO, status_code=422)


@aplicacion.middleware("http")
async def _frontera(peticion: Request, siguiente):
    # /salud queda abierta a propósito: la llama el healthcheck desde dentro
    # del propio contenedor y no dice nada.
    if peticion.url.path != "/salud":
        cliente = peticion.client.host if peticion.client else None
        if cliente != peticion.app.state.ip_api:
            # Sin la IP en el log, como en el resto de Canario.
            registro.warning("EVENTO broker_cliente_rechazado: ruta=%s", peticion.url.path)
            return JSONResponse(CUERPO_PROHIBIDO, status_code=403)
    if peticion.method == "POST":
        longitud = peticion.headers.get("content-length")
        if longitud is None or not longitud.isdigit() or int(longitud) > TAMANO_MAXIMO_PETICION:
            return JSONResponse(CUERPO_FORMATO, status_code=422)
    return await siguiente(peticion)


class Autorizacion(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    proveedor: str
    state: str
    code_challenge: str
    nonce: str


class Canje(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    proveedor: str
    code: str
    verifier: str
    nonce: str


def _configurado(peticion, proveedor):
    """Configuración del proveedor; None si no está configurado. Un nombre
    que el broker no conoce no llega aquí: es un 422."""
    return peticion.app.state.proveedores.get(proveedor)


@aplicacion.get("/salud")
def salud():
    return {"estado": "ok"}


@aplicacion.get("/proveedores")
def proveedores(peticion: Request):
    return {"proveedores": sorted(peticion.app.state.proveedores)}


@aplicacion.post("/autorizar")
def autorizar(datos: Autorizacion, peticion: Request):
    if datos.proveedor not in externos.PROVEEDORES or not all(
            externos.PATRON_VALOR_API.fullmatch(v) for v in (datos.state, datos.code_challenge, datos.nonce)):
        return JSONResponse(CUERPO_FORMATO, status_code=422)
    config = _configurado(peticion, datos.proveedor)
    if config is None:
        return JSONResponse(CUERPO_NO_CONFIGURADO, status_code=404)
    return {"url": externos.url_autorizacion_google(config, datos.state, datos.code_challenge, datos.nonce)}


@aplicacion.post("/canjear")
def canjear(datos: Canje, peticion: Request):
    if not (datos.proveedor in externos.PROVEEDORES and externos.PATRON_CODE.fullmatch(datos.code)
            and externos.PATRON_VERIFIER.fullmatch(datos.verifier) and externos.PATRON_VALOR_API.fullmatch(datos.nonce)):
        return JSONResponse(CUERPO_FORMATO, status_code=422)
    config = _configurado(peticion, datos.proveedor)
    if config is None:
        return JSONResponse(CUERPO_NO_CONFIGURADO, status_code=404)
    canjes = peticion.app.state.canjes
    if not canjes.acquire(blocking=False):
        registro.warning("EVENTO broker_saturado: proveedor=%s", datos.proveedor)
        return JSONResponse(CUERPO_NO_DISPONIBLE, status_code=503)
    try:
        sub = externos.canjear_google(config, datos.code, datos.verifier, datos.nonce)
    except externos.CanjeFallido as error:
        registro.warning("EVENTO canje_fallido: proveedor=%s motivo=%s", datos.proveedor, error.motivo)
        return JSONResponse(CUERPO_FALLIDO, status_code=401)
    except externos.ProveedorNoDisponible as error:
        registro.warning("EVENTO proveedor_no_disponible: proveedor=%s motivo=%s", datos.proveedor, error.motivo)
        return JSONResponse(CUERPO_NO_DISPONIBLE, status_code=503)
    finally:
        canjes.release()
    return {"proveedor": datos.proveedor, "sub": sub}
