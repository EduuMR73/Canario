"""Aplicación FastAPI de Canario.

Expone GET /salud (vivacidad) y las rutas del denunciante anónimo
(app/rutas_denuncias.py), detrás de la frontera HTTP (app/frontera_http.py):
límite de cuerpo, errores internos sin detalles y respuestas de error
uniformes. Al arrancar comprueba los secretos (contraseña y claves de
cifrado), abre el pool de conexiones a PostgreSQL y verifica la base de datos;
si algo no es lo esperado, la API no arranca (docs/threat-model.md, 6.10).
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from psycopg_pool import PoolTimeout

from app import bd, claves, frontera_http, rutas_denuncias, verificacion_arranque

# Logs propios y del pool de conexiones por la salida de error. Nunca llevan
# IPs de clientes ni la contraseña: solo nombres de comprobaciones, clases de
# error y mensajes del servidor. El log de acceso de uvicorn sigue desactivado
# (--no-access-log en el Dockerfile).
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
registro = logging.getLogger("canario.arranque")

# Tiempo máximo para abrir la primera conexión. Si se agota, la API no arranca
# y Docker la reinicia: el fallo queda visible como contenedor no sano.
ESPERA_CONEXION_SEGUNDOS = 15


@asynccontextmanager
async def ciclo_de_vida(app):
    """Abre el pool, verifica la base de datos y lo cierra al parar.

    Bloquea el bucle de eventos mientras arranca, a propósito: hasta que la
    verificación termina no se sirve ninguna petición.
    """
    try:
        bd.comprobar_secreto()
    except bd.ErrorConfiguracion as error:
        registro.error("ARRANQUE BLOQUEADO: secreto: %s", error)
        raise verificacion_arranque.ArranqueBloqueado("secreto") from None
    # Las claves de cifrado se comprueban antes de conectar, igual que la
    # contraseña: sin ellas la API no podría ni crear ni leer una denuncia, y
    # el fallo debe verse al arrancar, no en la primera petición.
    try:
        claves_servidor = claves.cargar()
    except claves.ErrorClaves as error:
        registro.error("ARRANQUE BLOQUEADO: claves: %s", error)
        raise verificacion_arranque.ArranqueBloqueado("claves") from None
    pool = bd.crear_pool()
    try:
        try:
            pool.open(wait=True, timeout=ESPERA_CONEXION_SEGUNDOS)
        except PoolTimeout:
            # El motivo concreto (por ejemplo, autenticación fallida) lo ha
            # registrado ya el pool en cada intento.
            registro.error(
                "ARRANQUE BLOQUEADO: conexion: sin conexion a la base de datos en %s s",
                ESPERA_CONEXION_SEGUNDOS,
            )
            raise verificacion_arranque.ArranqueBloqueado("conexion") from None
        verificacion_arranque.verificar(pool)
        app.state.pool = pool
        app.state.claves = claves_servidor
        yield
    finally:
        pool.close()


# Sin /docs, /redoc ni /openapi.json: en producción solo darían a un atacante
# el mapa completo de la API.
# redirect_slashes=False: sin esto, /salud/ respondería 307 hacia /salud. Toda
# ruta que no coincida exactamente debe dar 404, sin redirecciones implícitas.
aplicacion = FastAPI(
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    redirect_slashes=False,
    lifespan=ciclo_de_vida,
)
frontera_http.instalar(aplicacion)
aplicacion.include_router(rutas_denuncias.router)


@aplicacion.get("/salud")
def salud():
    """Vivacidad: el proceso responde.

    No consulta la base de datos ni Redis a propósito: si lo hiciera, una caída
    de una dependencia haría que Docker reiniciara la API sin motivo.
    """
    return {"estado": "ok"}
