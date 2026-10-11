"""Aplicación FastAPI de Canario (esqueleto vertical).

Por ahora solo expone GET /salud, una comprobación de vivacidad.
"""
from fastapi import FastAPI

# Sin /docs, /redoc ni /openapi.json: en producción solo darían a un atacante
# el mapa completo de la API.
# redirect_slashes=False: sin esto, /salud/ respondería 307 hacia /salud. Toda
# ruta que no coincida exactamente debe dar 404, sin redirecciones implícitas.
aplicacion = FastAPI(
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    redirect_slashes=False,
)


@aplicacion.get("/salud")
def salud():
    """Vivacidad: el proceso responde.

    No consulta la base de datos ni Redis a propósito: si lo hiciera, una caída
    de una dependencia haría que Docker reiniciara la API sin motivo.
    """
    return {"estado": "ok"}
