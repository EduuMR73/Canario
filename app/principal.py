"""Aplicación FastAPI de Canario.

Expone GET /salud (vivacidad), las rutas del denunciante anónimo
(app/rutas_denuncias.py), sus páginas HTML (app/rutas_web.py, que Caddy sirve
en el 8444) y las del personal (app/rutas_personal.py, y su login externo en
app/rutas_externo.py), detrás
de la frontera HTTP (app/frontera_http.py):
límite de cuerpo, limitador de peticiones con Redis (app/limitador.py),
errores internos sin detalles y respuestas de error uniformes. Al arrancar
comprueba los secretos (contraseña, claves de cifrado y contraseña de Redis)
y los límites, abre el pool de conexiones a PostgreSQL, verifica la base de
datos y después Redis; si algo no es lo esperado, la API no arranca
(docs/threat-model.md, 6.10).
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from psycopg_pool import PoolTimeout

from app import (
    bd,
    claves,
    frontera_http,
    limitador,
    rutas_denuncias,
    rutas_externo,
    rutas_personal,
    rutas_web,
    solicitudes,
    verificacion_arranque,
)

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
    # Los límites y el secreto de Redis también antes de conectar: un límite
    # mal configurado o un secreto que falta son errores de despliegue y deben
    # verse al arrancar, no como un 503 en cada petición.
    try:
        limites, origen = limitador.cargar_limites()
    except limitador.ErrorConfiguracion as error:
        registro.error("ARRANQUE BLOQUEADO: limites: %s", error)
        raise verificacion_arranque.ArranqueBloqueado("limites") from None
    try:
        limitador.leer_contrasena()
    except limitador.ErrorConfiguracion as error:
        registro.error("ARRANQUE BLOQUEADO: secreto_redis: %s", error)
        raise verificacion_arranque.ArranqueBloqueado("secreto_redis") from None
    # Visible en cada arranque: un límite relajado no pasa desapercibido.
    registro.info("LIMITES (%s): %s", origen, limitador.describir_limites(limites))
    # El origen del sitio del denunciante, contra el que se comprueban sus
    # formularios (app/rutas_web.py). Uno mal escrito haría que se rechazaran
    # todos: se ve al arrancar, y el valor efectivo queda en el log.
    try:
        origen_web, procedencia_origen = rutas_web.cargar_origen()
    except rutas_web.ErrorConfiguracion as error:
        registro.error("ARRANQUE BLOQUEADO: origen_web: %s", error)
        raise verificacion_arranque.ArranqueBloqueado("origen_web") from None
    registro.info("ORIGEN WEB (%s): %s", procedencia_origen, origen_web)
    # El origen de la SPA del personal, al que apuntan los enlaces de los
    # correos del registro (app/solicitudes.py). Obligatorio: sin él, o mal
    # escrito, la API no arranca.
    try:
        origen_personal = solicitudes.cargar_origen()
    except rutas_web.ErrorConfiguracion as error:
        registro.error("ARRANQUE BLOQUEADO: origen_personal: %s", error)
        raise verificacion_arranque.ArranqueBloqueado("origen_personal") from None
    registro.info("ORIGEN PERSONAL: %s", origen_personal)
    pool = bd.crear_pool()
    limitador_api = None
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
        limitador_api = limitador.Limitador(limites)
        fallos = await limitador_api.verificar()
        for detalle in fallos:
            registro.error("ARRANQUE BLOQUEADO: limitador: %s", detalle)
        if fallos:
            raise verificacion_arranque.ArranqueBloqueado("limitador")
        registro.info("LIMITADOR VERIFICADO")
        app.state.pool = pool
        app.state.claves = claves_servidor
        app.state.limitador = limitador_api
        app.state.origen_web = origen_web
        app.state.origen_personal = origen_personal
        yield
    finally:
        if limitador_api is not None:
            await limitador_api.cerrar()
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
frontera_http.instalar(aplicacion, limitador.FronteraLimitador)
rutas_personal.instalar_errores(aplicacion)
rutas_externo.instalar_errores(aplicacion)
aplicacion.include_router(rutas_denuncias.router)
aplicacion.include_router(rutas_personal.router)
aplicacion.include_router(rutas_externo.router)
aplicacion.include_router(rutas_externo.router_vuelta)
aplicacion.include_router(rutas_web.router)


@aplicacion.get("/salud")
def salud():
    """Vivacidad: el proceso responde.

    No consulta la base de datos ni Redis a propósito: si lo hiciera, una caída
    de una dependencia haría que Docker reiniciara la API sin motivo.
    """
    return {"estado": "ok"}
