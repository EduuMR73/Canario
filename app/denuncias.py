"""Denuncia anónima: alta, seguimiento y mensajes (docs/threat-model.md, 6.1,
6.4 y 6.5).

Lógica sin HTTP: las rutas (app/rutas_denuncias.py) traducen las excepciones
de aquí a respuestas.

Alta:
1. El identificador público de la empresa se resuelve con
   canal.resolver_empresa(), que no distingue entre desconocido, mal formado o
   empresa inactiva.
2. En una sola transacción con el contexto de la empresa: se toma su clave de
   la versión más alta, se desenvuelve, se cifra {v, categoria, texto} con el
   AAD de la denuncia, se inserta y se registra el HMAC del código. O se
   guardan la denuncia y su código, o nada.
3. El código se devuelve una sola vez. La fecha la pone la base de datos, en
   la zona horaria de la empresa; la API nunca la elige.

Seguimiento: HMAC del código, canal.buscar_codigo() y, con el contexto de esa
empresa y en solo lectura (una sola foto de los datos, app/bd.py), la
denuncia y sus mensajes. Se descifra fuera de la transacción, para no
retener la conexión. Cada mensaje se descifra con la versión de clave con la
que se cifró: tras una rotación conviven varias.

Mensajes del denunciante: el código identifica la denuncia igual que en el
seguimiento. El id del mensaje lo genera la API, porque forma parte del AAD y
hace falta antes de cifrar; se cifra {v, texto} con la clave de la versión más
alta. Las reglas que dependen del estado de la base de datos (denuncia
abierta, tope de mensajes, número y fecha) las impone el trigger
canal.preparar_mensaje() en el mismo INSERT, no una comprobación previa
aquí: entre comprobar e insertar el personal podría cerrar la denuncia. Sus
SQLSTATE propios se traducen a excepciones de este módulo.

Registro (logs): por diseño, aquí no se registra nada. Una línea de log lleva
la hora, y anotar que alguien denunció, consultó o escribió a las 10:32
desharía la fecha redondeada al día. Las rutas solo registran fallos, con el
tipo de evento y sin empresa, denuncia ni código.
"""
import json
import re
import uuid
from dataclasses import dataclass

import psycopg

from app import bd, cripto

# Lista cerrada. Va dentro del contenido cifrado, así que se puede cambiar sin
# migrar la base de datos; las denuncias antiguas conservan la suya.
CATEGORIAS = ("acoso", "fraude", "corrupcion", "seguridad_laboral",
              "proteccion_datos", "medio_ambiente", "otros")

# Versión del formato del contenido cifrado: permite cambiarlo en el futuro
# sin ambigüedad sobre cómo leer lo antiguo.
VERSION_CONTENIDO = 1

# Formato del identificador público (canal.directorio_empresas). Lo que no
# encaja no se consulta: no puede ser una empresa.
PATRON_IDENTIFICADOR = re.compile(r"[0-9a-f]{32}")

# SQLSTATE propios de canal.preparar_mensaje() (db/init/02_esquema.sql).
SQLSTATE_DENUNCIA_CERRADA = "CN001"
SQLSTATE_LIMITE_MENSAJES = "CN002"
# foreign_key_violation: preparar_mensaje lo lanza cuando la denuncia no es
# visible. Con un código resuelto, solo pasa si la denuncia se ha suprimido
# entre resolver el código e insertar (db/init/04_supresion.sql): la clave de
# cifrado se acaba de leer en la misma transacción y nunca se borra.
SQLSTATE_DENUNCIA_NO_VISIBLE = "23503"

SQL_RESOLVER = "select canal.resolver_empresa(%s)"
SQL_CLAVE_ACTUAL = (
    "select version, clave_envuelta from canal.clave_empresa order by version desc limit 1"
)
SQL_CLAVES = "select version, clave_envuelta from canal.clave_empresa where version = any(%s)"
SQL_INSERTAR = (
    "insert into canal.denuncia (empresa_id, id, contenido_cifrado, version_clave) "
    "values (%s, %s, %s, %s) returning fecha"
)
SQL_REGISTRAR_CODIGO = "select canal.registrar_codigo(%s, %s)"
SQL_BUSCAR_CODIGO = "select empresa_id, denuncia_id from canal.buscar_codigo(%s)"
SQL_DENUNCIA = (
    "select fecha, estado, contenido_cifrado, version_clave from canal.denuncia where id = %s"
)
# El denunciante nunca tiene autor_id (CHECK de canal.mensaje).
SQL_INSERTAR_MENSAJE = (
    "insert into canal.mensaje (empresa_id, denuncia_id, id, autor, contenido_cifrado, version_clave) "
    "values (%s, %s, %s, 'denunciante', %s, %s) returning secuencia, fecha"
)
SQL_MENSAJES = (
    "select secuencia, fecha, id, autor, autor_id, contenido_cifrado, version_clave "
    "from canal.mensaje where denuncia_id = %s order by secuencia"
)


class EmpresaNoEncontrada(Exception):
    """Identificador desconocido, mal formado o de una empresa inactiva."""


class EmpresaSinClave(Exception):
    """La empresa existe pero no tiene clave de cifrado: alta a medias
    (app/gestion.py, nueva-clave). No acepta denuncias."""


class CodigoNoEncontrado(Exception):
    """Código mal formado o que no corresponde a ninguna denuncia."""


class DenunciaCerrada(Exception):
    """La denuncia está resuelta o archivada: no admite mensajes."""


class LimiteMensajes(Exception):
    """La denuncia ya tiene el máximo de mensajes."""


@dataclass(frozen=True)
class DenunciaCreada:
    codigo_seguimiento: str
    fecha: object


@dataclass(frozen=True)
class MensajeEnviado:
    secuencia: int
    fecha: object


@dataclass(frozen=True)
class Mensaje:
    """Lo que el denunciante puede ver de un mensaje. Sin id ni autor_id: el
    id es interno y autor_id identificaría a la persona del personal."""
    secuencia: int
    fecha: object
    autor: str
    texto: str


@dataclass(frozen=True)
class EstadoDenuncia:
    estado: str
    fecha: object
    categoria: str
    texto: str
    mensajes: tuple


@dataclass(frozen=True)
class MensajeCompleto:
    """Un mensaje descifrado con autor_id, solo para el personal
    (app/instruccion.py). Nunca sale hacia el denunciante."""
    secuencia: int
    fecha: object
    autor: str
    autor_id: object
    texto: str


# ---------------------------------------------------------------------------
# Piezas compartidas con app/instruccion.py: el personal lee y escribe la
# misma denuncia con el mismo formato y los mismos AAD.
# ---------------------------------------------------------------------------

def serializar(**campos):
    contenido = {"v": VERSION_CONTENIDO, **campos}
    return json.dumps(contenido, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def deserializar(datos, campos):
    """Inverso estricto de serializar(): exige exactamente {v, *campos}, con
    textos. Los datos ya están autenticados por GCM: una desviación indicaría
    un error propio, no un ataque, y se trata como fallo de integridad."""
    try:
        contenido = json.loads(datos.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise cripto.ErrorIntegridad("contenido descifrado con formato invalido") from None
    if (not isinstance(contenido, dict)
            or set(contenido) != {"v", *campos}
            or contenido["v"] != VERSION_CONTENIDO
            or not all(isinstance(contenido[c], str) for c in campos)):
        raise cripto.ErrorIntegridad("contenido descifrado con formato desconocido")
    return contenido


def clave_actual(conexion, claves, empresa_id):
    """Versión más alta de la clave de la empresa del contexto, desenvuelta."""
    fila = conexion.execute(SQL_CLAVE_ACTUAL).fetchone()
    if fila is None:
        raise EmpresaSinClave
    version, envuelta = fila
    return version, cripto.desenvolver_clave(claves.maestra, bytes(envuelta), empresa_id, version)


def leer_mensajes_y_claves(conexion, denuncia_id, version_denuncia):
    """Mensajes de una denuncia y las claves envueltas de todas las versiones
    que hacen falta para leerla, dentro de la transacción de quien llama."""
    filas = conexion.execute(SQL_MENSAJES, [denuncia_id]).fetchall()
    versiones = sorted({version_denuncia} | {fila[6] for fila in filas})
    envueltas = dict(conexion.execute(SQL_CLAVES, [versiones]).fetchall())
    return filas, envueltas


def descifrar_expediente(claves, empresa_id, denuncia_id, cifrado, version, filas, envueltas):
    """Contenido de la denuncia y sus mensajes en claro. Se llama fuera de la
    transacción, para no retener la conexión. Cada versión de clave se
    desenvuelve una sola vez; la clave foránea de version_clave garantiza que
    todas existen. Devuelve los mensajes con autor_id: quien llama decide qué
    sale de la API."""
    claves_empresa = {v: cripto.desenvolver_clave(claves.maestra, bytes(envuelta), empresa_id, v)
                      for v, envuelta in envueltas.items()}
    datos = cripto.descifrar_contenido(claves_empresa[version], bytes(cifrado),
                                       cripto.aad_denuncia(empresa_id, denuncia_id))
    contenido = deserializar(datos, ("categoria", "texto"))
    mensajes = []
    for secuencia, fecha_mensaje, mensaje_id, autor, autor_id, cifrado_mensaje, version_mensaje in filas:
        # El AAD lleva el id, el autor y autor_id: un mensaje movido de fila o
        # con el autor cambiado no se descifra.
        aad = cripto.aad_mensaje(empresa_id, denuncia_id, mensaje_id, autor, autor_id)
        texto = deserializar(cripto.descifrar_contenido(claves_empresa[version_mensaje],
                                                        bytes(cifrado_mensaje), aad), ("texto",))["texto"]
        mensajes.append(MensajeCompleto(secuencia=secuencia, fecha=fecha_mensaje, autor=autor, autor_id=autor_id,
                                        texto=texto))
    return contenido, mensajes


# ---------------------------------------------------------------------------
# Denunciante
# ---------------------------------------------------------------------------

def _resolver_codigo(pool, claves, codigo):
    """Empresa y denuncia de un código de seguimiento, o CodigoNoEncontrado."""
    crudo = cripto.leer_codigo(codigo)
    if crudo is None:
        raise CodigoNoEncontrado
    with bd.transaccion_sin_contexto(pool, solo_lectura=True) as conexion:
        fila = conexion.execute(SQL_BUSCAR_CODIGO, [cripto.hmac_codigo(claves.hmac_codigos, crudo)]).fetchone()
    if fila is None:
        raise CodigoNoEncontrado
    return fila


def crear(pool, claves, identificador, categoria, texto):
    """Crea una denuncia y devuelve su código de seguimiento y su fecha."""
    if categoria not in CATEGORIAS:
        raise ValueError("categoria desconocida")
    if not isinstance(identificador, str) or not PATRON_IDENTIFICADOR.fullmatch(identificador):
        raise EmpresaNoEncontrada
    with bd.transaccion_sin_contexto(pool, solo_lectura=True) as conexion:
        empresa_id = conexion.execute(SQL_RESOLVER, [identificador]).fetchone()[0]
    if empresa_id is None:
        raise EmpresaNoEncontrada

    denuncia_id = uuid.uuid4()
    codigo, crudo = cripto.generar_codigo()
    with bd.transaccion_empresa(pool, empresa_id) as conexion:
        version, clave = clave_actual(conexion, claves, empresa_id)
        cifrado = cripto.cifrar_contenido(clave, serializar(categoria=categoria, texto=texto),
                                          cripto.aad_denuncia(empresa_id, denuncia_id))
        fecha = conexion.execute(SQL_INSERTAR, [empresa_id, denuncia_id, cifrado, version]).fetchone()[0]
        conexion.execute(SQL_REGISTRAR_CODIGO, [cripto.hmac_codigo(claves.hmac_codigos, crudo), denuncia_id])
    return DenunciaCreada(codigo_seguimiento=codigo, fecha=fecha)


def consultar(pool, claves, codigo):
    """Estado, contenido y mensajes de la denuncia de un código de seguimiento."""
    empresa_id, denuncia_id = _resolver_codigo(pool, claves, codigo)

    with bd.transaccion_empresa(pool, empresa_id, solo_lectura=True) as conexion:
        denuncia = conexion.execute(SQL_DENUNCIA, [denuncia_id]).fetchone()
        # Suprimida entre resolver el código y leerla
        # (db/init/04_supresion.sql): el código ya no existe, mismo 404.
        if denuncia is None:
            raise CodigoNoEncontrado
        fecha, estado, cifrado, version = denuncia
        filas, envueltas = leer_mensajes_y_claves(conexion, denuncia_id, version)

    contenido, mensajes = descifrar_expediente(claves, empresa_id, denuncia_id, cifrado, version, filas, envueltas)
    # Sin autor_id: identificaría a la persona del personal.
    return EstadoDenuncia(estado=estado, fecha=fecha, categoria=contenido["categoria"], texto=contenido["texto"],
                          mensajes=tuple(Mensaje(secuencia=m.secuencia, fecha=m.fecha, autor=m.autor, texto=m.texto)
                                         for m in mensajes))


def enviar_mensaje(pool, claves, codigo, texto):
    """Añade un mensaje del denunciante a la denuncia de un código."""
    empresa_id, denuncia_id = _resolver_codigo(pool, claves, codigo)
    mensaje_id = uuid.uuid4()
    try:
        with bd.transaccion_empresa(pool, empresa_id) as conexion:
            version, clave = clave_actual(conexion, claves, empresa_id)
            cifrado = cripto.cifrar_contenido(
                clave, serializar(texto=texto),
                cripto.aad_mensaje(empresa_id, denuncia_id, mensaje_id, "denunciante", None))
            secuencia, fecha = conexion.execute(
                SQL_INSERTAR_MENSAJE, [empresa_id, denuncia_id, mensaje_id, cifrado, version]).fetchone()
    except psycopg.Error as error:
        # Solo los casos previstos; cualquier otro error sigue su camino.
        if error.sqlstate == SQLSTATE_DENUNCIA_CERRADA:
            raise DenunciaCerrada from None
        if error.sqlstate == SQLSTATE_LIMITE_MENSAJES:
            raise LimiteMensajes from None
        # Denuncia suprimida en carrera: el código ya no existe, mismo 404.
        if error.sqlstate == SQLSTATE_DENUNCIA_NO_VISIBLE:
            raise CodigoNoEncontrado from None
        raise
    return MensajeEnviado(secuencia=secuencia, fecha=fecha)
