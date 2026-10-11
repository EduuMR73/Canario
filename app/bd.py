"""Acceso a PostgreSQL de la API de Canario.

Único camino de la API a la base de datos. La API se conecta siempre con el
rol aplicacion (sin superusuario ni BYPASSRLS) y el aislamiento entre
empresas lo aplica la RLS con el contexto que fija transaccion_empresa().

Reglas:
* El contexto de empresa se fija con set_config(..., true), local a la
  transacción: al terminar desaparece y la conexión vuelve limpia al pool.
  Nunca con SET ni con set_config(..., false), que durarían toda la sesión y
  pasarían a la siguiente petición que use la conexión.
* El valor va siempre como parámetro enlazado. psycopg 3 envía consulta y
  parámetros por separado en SELECT, pero no en SET: por eso se usa
  "select set_config" y no "SET".
* Al devolver una conexión al pool se comprueba que no lleva contexto. Si lo
  lleva, el pool la cierra y lo registra: un arrastre de contexto entre
  peticiones nunca pasa en silencio.
"""
import pathlib
import uuid
from contextlib import contextmanager

import psycopg
from psycopg_pool import ConnectionPool

# Docker secrets montados como fichero: nunca en variables de entorno. La API
# solo tiene el de aplicacion; el de plataforma solo existe en el servicio de
# gestión (app/gestion.py).
FICHERO_CONTRASENA = pathlib.Path("/run/secrets/contrasena_aplicacion")
FICHERO_CONTRASENA_PLATAFORMA = pathlib.Path("/run/secrets/contrasena_plataforma")

# Tiempos máximos de cada sesión, en milisegundos:
# * statement_timeout: una consulta colgada no retiene una conexión del pool.
# * lock_timeout: no se espera indefinidamente por un bloqueo.
# * idle_in_transaction_session_timeout: una transacción abandonada se corta.
#   Importa porque los triggers de auditoría y de mensajes toman bloqueos
#   consultivos por empresa: una transacción colgada bloquearía a toda la
#   empresa.
OPCIONES_SESION = (
    "-c statement_timeout=5000 "
    "-c lock_timeout=2000 "
    "-c idle_in_transaction_session_timeout=10000"
)

PARAMETROS_CONEXION = {
    "host": "postgres",
    "port": 5432,
    "dbname": "canario",
    "user": "aplicacion",
    "application_name": "canario-api",
    "connect_timeout": 5,
    # Límite asumido (docker-compose.yml): la red data es interna y el
    # servidor tiene ssl=off; el contenido sensible ya va cifrado por la API.
    "sslmode": "disable",
    "options": OPCIONES_SESION,
}

# true = local a la transacción. El valor siempre como parámetro enlazado.
SQL_FIJAR_CONTEXTO = "select set_config('app.empresa_id', %s, true)"
SQL_LEER_CONTEXTO = "select current_setting('app.empresa_id', true)"

# Por debajo del CONNECTION LIMIT 10 del rol aplicacion: deja margen para que
# dos procesos de la API convivan durante un reinicio.
TAMANO_MAXIMO_POOL = 5


class ErrorConfiguracion(Exception):
    """La API no tiene lo necesario para conectarse (por ejemplo, el secreto)."""


class ContextoArrastrado(psycopg.ProgrammingError):
    """Una conexión volvió al pool con contexto de empresa.

    Hereda de psycopg.Error para que el pool la capture y cierre la conexión
    en vez de devolverla.
    """


def _parametros_con_contrasena(usuario="aplicacion", fichero=FICHERO_CONTRASENA):
    """Parámetros de conexión con la contraseña leída del secreto.

    El pool la llama sin argumentos (rol aplicacion) en cada intento de
    conexión: si la contraseña se rota, las conexiones nuevas usan la nueva
    sin reiniciar la API. El contenido no se recorta ni se corrige: un fichero
    con espacios o saltos de línea es un error de configuración y debe verse.
    """
    try:
        contrasena = fichero.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError) as error:
        raise ErrorConfiguracion(
            f"no se puede leer el secreto de la base de datos ({type(error).__name__})"
        ) from None
    if not contrasena or any(c.isspace() for c in contrasena):
        raise ErrorConfiguracion(
            "el secreto de la base de datos tiene un formato inesperado"
        )
    return {**PARAMETROS_CONEXION, "user": usuario, "password": contrasena}


def comprobar_secreto():
    """Comprueba al arrancar que el secreto existe y tiene un formato válido.

    Lanza ErrorConfiguracion con un motivo que no incluye la contraseña. Así
    el fallo se ve con un mensaje claro, y no como un error del hilo que abre
    las conexiones.
    """
    _parametros_con_contrasena()


def _comprobar_sin_contexto(conexion):
    """Callback reset del pool: la conexión no debe volver con contexto."""
    valor = conexion.execute(SQL_LEER_CONTEXTO).fetchone()[0]
    conexion.rollback()
    if valor not in (None, ""):
        raise ContextoArrastrado(
            "conexion devuelta al pool con contexto de empresa: se descarta"
        )


def crear_pool(tamano_maximo=TAMANO_MAXIMO_POOL):
    """Crea el pool sin abrirlo. Se abre en el arranque de la API."""
    return ConnectionPool(
        kwargs=_parametros_con_contrasena,
        min_size=1,
        max_size=tamano_maximo,
        open=False,
        reset=_comprobar_sin_contexto,
        name="canario",
        timeout=10,
    )


def conectar(usuario, fichero):
    """Conexión suelta, sin pool, para el servicio de gestión.

    Mismas opciones de sesión (tiempos máximos) que las del pool de la API.
    """
    return psycopg.connect(**_parametros_con_contrasena(usuario, fichero))


def fijar_contexto(conexion, empresa_id):
    """Fija el contexto de empresa, local a la transacción en curso.

    Único punto donde se fija el contexto. empresa_id debe ser un uuid.UUID,
    no un texto: lo que venga de una petición se convierte y valida antes de
    llegar aquí, y nada sin validar llega al SQL.
    """
    if not isinstance(empresa_id, uuid.UUID):
        raise TypeError("empresa_id debe ser uuid.UUID")
    conexion.execute(SQL_FIJAR_CONTEXTO, [str(empresa_id)])


@contextmanager
def transaccion_empresa(pool, empresa_id, solo_lectura=False):
    """Transacción con el contexto de una empresa fijado.

    solo_lectura: para los caminos que solo consultan (el seguimiento del
    denunciante). Un error del código no puede escribir nada.
    """
    # Se valida antes de pedir una conexión al pool: un valor inválido no
    # llega a ocupar ninguna.
    if not isinstance(empresa_id, uuid.UUID):
        raise TypeError("empresa_id debe ser uuid.UUID")
    with pool.connection() as conexion, conexion.transaction():
        # Tiene que ser la primera sentencia de la transacción.
        if solo_lectura:
            conexion.execute("set transaction read only")
        fijar_contexto(conexion, empresa_id)
        yield conexion


@contextmanager
def transaccion_sin_contexto(pool, solo_lectura=False):
    """Transacción sin contexto de empresa.

    Las tablas con RLS devuelven cero filas. Sirve para las funciones de
    definidor (resolver_empresa, buscar_codigo) y para la verificación de
    arranque, que va en solo lectura.
    """
    with pool.connection() as conexion, conexion.transaction():
        if solo_lectura:
            conexion.execute("set transaction read only")
        yield conexion
