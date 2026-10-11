"""Denuncia anónima: alta y seguimiento (docs/threat-model.md, 6.1, 6.4 y 6.5).

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
empresa y en solo lectura, la denuncia. Se descifra fuera de la transacción,
para no retener la conexión.

Registro (logs): por diseño, aquí no se registra nada. Una línea de log lleva
la hora, y anotar que alguien denunció o consultó a las 10:32 desharía la
fecha redondeada al día. Las rutas solo registran fallos, con el tipo de
evento y sin empresa, denuncia ni código.
"""
import json
import re
import uuid
from dataclasses import dataclass

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

SQL_RESOLVER = "select canal.resolver_empresa(%s)"
SQL_CLAVE_ACTUAL = (
    "select version, clave_envuelta from canal.clave_empresa order by version desc limit 1"
)
SQL_CLAVE = "select clave_envuelta from canal.clave_empresa where version = %s"
SQL_INSERTAR = (
    "insert into canal.denuncia (empresa_id, id, contenido_cifrado, version_clave) "
    "values (%s, %s, %s, %s) returning fecha"
)
SQL_REGISTRAR_CODIGO = "select canal.registrar_codigo(%s, %s)"
SQL_BUSCAR_CODIGO = "select empresa_id, denuncia_id from canal.buscar_codigo(%s)"
SQL_DENUNCIA = (
    "select fecha, estado, contenido_cifrado, version_clave from canal.denuncia where id = %s"
)


class EmpresaNoEncontrada(Exception):
    """Identificador desconocido, mal formado o de una empresa inactiva."""


class EmpresaSinClave(Exception):
    """La empresa existe pero no tiene clave de cifrado: alta a medias
    (app/gestion.py, nueva-clave). No acepta denuncias."""


class CodigoNoEncontrado(Exception):
    """Código mal formado o que no corresponde a ninguna denuncia."""


@dataclass(frozen=True)
class DenunciaCreada:
    codigo_seguimiento: str
    fecha: object


@dataclass(frozen=True)
class EstadoDenuncia:
    estado: str
    fecha: object
    categoria: str
    texto: str


def _serializar(categoria, texto):
    contenido = {"v": VERSION_CONTENIDO, "categoria": categoria, "texto": texto}
    return json.dumps(contenido, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _deserializar(datos):
    """Inverso estricto de _serializar(). Los datos ya están autenticados por
    GCM: una desviación indicaría un error propio, no un ataque, y se trata
    como fallo de integridad."""
    try:
        contenido = json.loads(datos.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise cripto.ErrorIntegridad("contenido descifrado con formato invalido") from None
    if (not isinstance(contenido, dict)
            or set(contenido) != {"v", "categoria", "texto"}
            or contenido["v"] != VERSION_CONTENIDO
            or not isinstance(contenido["categoria"], str)
            or not isinstance(contenido["texto"], str)):
        raise cripto.ErrorIntegridad("contenido descifrado con formato desconocido")
    return contenido["categoria"], contenido["texto"]


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
        fila = conexion.execute(SQL_CLAVE_ACTUAL).fetchone()
        if fila is None:
            raise EmpresaSinClave
        version, envuelta = fila
        clave = cripto.desenvolver_clave(claves.maestra, bytes(envuelta), empresa_id, version)
        cifrado = cripto.cifrar_contenido(clave, _serializar(categoria, texto),
                                          cripto.aad_denuncia(empresa_id, denuncia_id))
        fecha = conexion.execute(SQL_INSERTAR, [empresa_id, denuncia_id, cifrado, version]).fetchone()[0]
        conexion.execute(SQL_REGISTRAR_CODIGO, [cripto.hmac_codigo(claves.hmac_codigos, crudo), denuncia_id])
    return DenunciaCreada(codigo_seguimiento=codigo, fecha=fecha)


def consultar(pool, claves, codigo):
    """Estado y contenido de la denuncia de un código de seguimiento."""
    crudo = cripto.leer_codigo(codigo)
    if crudo is None:
        raise CodigoNoEncontrado
    with bd.transaccion_sin_contexto(pool, solo_lectura=True) as conexion:
        fila = conexion.execute(SQL_BUSCAR_CODIGO, [cripto.hmac_codigo(claves.hmac_codigos, crudo)]).fetchone()
    if fila is None:
        raise CodigoNoEncontrado
    empresa_id, denuncia_id = fila

    with bd.transaccion_empresa(pool, empresa_id, solo_lectura=True) as conexion:
        fecha, estado, cifrado, version = conexion.execute(SQL_DENUNCIA, [denuncia_id]).fetchone()
        envuelta = conexion.execute(SQL_CLAVE, [version]).fetchone()[0]
    clave = cripto.desenvolver_clave(claves.maestra, bytes(envuelta), empresa_id, version)
    datos = cripto.descifrar_contenido(clave, bytes(cifrado), cripto.aad_denuncia(empresa_id, denuncia_id))
    categoria, texto = _deserializar(datos)
    return EstadoDenuncia(estado=estado, fecha=fecha, categoria=categoria, texto=texto)
