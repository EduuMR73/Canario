"""Criptografía de Canario (docs/threat-model.md, 6.1 y 6.4).

Lógica pura: sin ficheros, sin red y sin base de datos. Las claves llegan
como parámetros (app/claves.py las carga).

Envelope encryption:
* Cada empresa tiene su propia clave de datos (32 bytes) por versión. En la
  base de datos solo está envuelta (cifrada) con la clave maestra, que nunca
  entra en la base de datos. Quien tenga un volcado no tiene ninguna clave.
* Rotar la clave de una empresa es crear la versión siguiente: lo nuevo se
  cifra con ella y lo antiguo se sigue leyendo con la suya.

AES-256-GCM con datos asociados (AAD). El AAD no se cifra, pero se autentica:
ata cada cifrado a su sitio (empresa, fila y tipo de dato), de modo que
copiarlo a otra fila, a otra empresa o a otra tabla hace fallar el
descifrado (recomendación de Google Tink para cifrado por celda). Cada AAD
empieza por una etiqueta distinta por tipo y versión, y el resto son campos
binarios de longitud fija: dos AAD distintos nunca pueden coincidir.

Formato de todo lo cifrado: versión del formato (1 byte) || nonce (12 bytes)
|| cifrado || tag (16 bytes). La versión permite cambiar de algoritmo en el
futuro sin ambigüedad sobre cómo leer lo antiguo.

Nonce aleatorio de 96 bits por cifrado. Con nonces aleatorios (construcción
RBG), NIST SP 800-38D, sección 8.3, exige que una misma clave no cifre más de
2^32 veces. El código no lleva esa cuenta: el volumen de una empresa está
muy por debajo, y la rotación (versión nueva de clave, app/gestion.py) da
una clave nueva con su propia cuenta.
"""
import base64
import hashlib
import hmac
import re
import secrets
import uuid

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FORMATO_V1 = b"\x01"
LONGITUD_CLAVE = 32
LONGITUD_NONCE = 12
LONGITUD_TAG = 16
# version_clave es integer en PostgreSQL.
VERSION_MAXIMA = 2**31 - 1

# Relleno: el tamaño del cifrado solo revela en qué tramo de 256 bytes cae el
# texto, no su longitud exacta.
BLOQUE_RELLENO = 256
LONGITUD_CABECERA_RELLENO = 4

ETIQUETA_CLAVE_EMPRESA = b"canario/clave_empresa/v1"
ETIQUETA_DENUNCIA = b"canario/denuncia/v1"
ETIQUETA_MENSAJE = b"canario/mensaje/v1"
ETIQUETA_SEGUIMIENTO = b"canario/seguimiento/v1"

# Mismos valores que el CHECK de canal.mensaje.autor.
AUTORES = {"denunciante": b"D", "personal": b"P"}

# Código de seguimiento: 160 bits aleatorios, que en base32 (RFC 4648) son 32
# caracteres exactos, sin relleno ni bits sobrantes. Se muestra en 8 grupos
# de 4 separados por guiones.
LONGITUD_CODIGO = 20
GRUPO_CODIGO = 4
PATRON_CODIGO = re.compile(r"[A-Z2-7]{32}")
# 32 caracteres, 7 guiones y holgura para espacios. Lo que pase de aquí no
# es un código y no se procesa.
LONGITUD_MAXIMA_ENTRADA_CODIGO = 64


class ErrorIntegridad(Exception):
    """Un cifrado no se puede descifrar: está alterado, se ha movido de sitio o
    la clave no es la suya. Nunca lleva datos ni claves."""


def _exigir_uuid(*valores):
    for valor in valores:
        if not isinstance(valor, uuid.UUID):
            raise TypeError("se esperaba uuid.UUID")


def _exigir_version(version):
    # bool es subclase de int: se excluye a propósito.
    if isinstance(version, bool) or not isinstance(version, int) or not 1 <= version <= VERSION_MAXIMA:
        raise ValueError("version de clave fuera de rango")


def _aead(clave):
    if not isinstance(clave, bytes) or len(clave) != LONGITUD_CLAVE:
        raise ValueError("la clave debe tener 32 bytes")
    return AESGCM(clave)


# ---------------------------------------------------------------------------
# Cifrado autenticado
# ---------------------------------------------------------------------------

def cifrar(clave, datos, aad):
    """AES-256-GCM con nonce aleatorio. Devuelve formato || nonce || cifrado || tag."""
    nonce = secrets.token_bytes(LONGITUD_NONCE)
    return FORMATO_V1 + nonce + _aead(clave).encrypt(nonce, datos, aad)


def descifrar(clave, cifrado, aad):
    """Inverso de cifrar(). Cualquier fallo es ErrorIntegridad, sin detalles."""
    aead = _aead(clave)
    if (not isinstance(cifrado, bytes)
            or len(cifrado) < 1 + LONGITUD_NONCE + LONGITUD_TAG
            or cifrado[:1] != FORMATO_V1):
        raise ErrorIntegridad("formato de cifrado desconocido")
    nonce = cifrado[1:1 + LONGITUD_NONCE]
    try:
        return aead.decrypt(nonce, cifrado[1 + LONGITUD_NONCE:], aad)
    except InvalidTag:
        raise ErrorIntegridad("el cifrado no es autentico para este contexto") from None


# ---------------------------------------------------------------------------
# Datos asociados (AAD)
# ---------------------------------------------------------------------------

def aad_clave_empresa(empresa_id, version):
    _exigir_uuid(empresa_id)
    _exigir_version(version)
    return ETIQUETA_CLAVE_EMPRESA + empresa_id.bytes + version.to_bytes(4, "big")


def aad_denuncia(empresa_id, denuncia_id):
    _exigir_uuid(empresa_id, denuncia_id)
    return ETIQUETA_DENUNCIA + empresa_id.bytes + denuncia_id.bytes


def aad_mensaje(empresa_id, denuncia_id, mensaje_id, autor, autor_id):
    """Incluye el id del mensaje: sin él, un mensaje se podría duplicar en otra
    fila o intercambiar con otro de la misma denuncia sin que GCM lo notara.
    Incluye el autor: un mensaje del denunciante no puede pasar por uno del
    personal ni al revés."""
    _exigir_uuid(empresa_id, denuncia_id, mensaje_id)
    if autor not in AUTORES:
        raise ValueError("autor desconocido")
    # La misma regla que el CHECK de la tabla: el personal siempre tiene
    # autor_id y el denunciante nunca.
    if (autor == "personal") != (autor_id is not None):
        raise ValueError("autor_id incoherente con el autor")
    if autor_id is not None:
        _exigir_uuid(autor_id)
    return (ETIQUETA_MENSAJE + empresa_id.bytes + denuncia_id.bytes + mensaje_id.bytes
            + AUTORES[autor] + (autor_id.bytes if autor_id is not None else bytes(16)))


# ---------------------------------------------------------------------------
# Claves de empresa (envelope encryption)
# ---------------------------------------------------------------------------

def nueva_clave_empresa():
    return secrets.token_bytes(LONGITUD_CLAVE)


def envolver_clave(maestra, clave_empresa, empresa_id, version):
    if not isinstance(clave_empresa, bytes) or len(clave_empresa) != LONGITUD_CLAVE:
        raise ValueError("la clave de empresa debe tener 32 bytes")
    return cifrar(maestra, clave_empresa, aad_clave_empresa(empresa_id, version))


def desenvolver_clave(maestra, envuelta, empresa_id, version):
    clave = descifrar(maestra, envuelta, aad_clave_empresa(empresa_id, version))
    if len(clave) != LONGITUD_CLAVE:
        raise ErrorIntegridad("la clave desenvuelta no tiene 32 bytes")
    return clave


# ---------------------------------------------------------------------------
# Contenido con relleno
# ---------------------------------------------------------------------------

def rellenar(datos):
    """Longitud (4 bytes) || datos || ceros hasta un múltiplo de BLOQUE_RELLENO."""
    if len(datos) >= 2**32:
        raise ValueError("contenido demasiado grande")
    total = LONGITUD_CABECERA_RELLENO + len(datos)
    tamano = -(-total // BLOQUE_RELLENO) * BLOQUE_RELLENO
    return len(datos).to_bytes(4, "big") + datos + bytes(tamano - total)


def quitar_relleno(rellenado):
    """Inverso estricto de rellenar(): cualquier desviación es ErrorIntegridad.

    Solo se llama sobre datos ya autenticados por GCM, así que una desviación
    no la puede provocar un atacante sin la clave: indicaría un error propio.
    """
    if len(rellenado) < BLOQUE_RELLENO or len(rellenado) % BLOQUE_RELLENO:
        raise ErrorIntegridad("relleno con tamano invalido")
    longitud = int.from_bytes(rellenado[:LONGITUD_CABECERA_RELLENO], "big")
    fin = LONGITUD_CABECERA_RELLENO + longitud
    if fin > len(rellenado) or any(rellenado[fin:]):
        raise ErrorIntegridad("relleno invalido")
    if len(rellenado) - fin >= BLOQUE_RELLENO:
        raise ErrorIntegridad("relleno mas largo de lo necesario")
    return rellenado[LONGITUD_CABECERA_RELLENO:fin]


def cifrar_contenido(clave_empresa, datos, aad):
    return cifrar(clave_empresa, rellenar(datos), aad)


def descifrar_contenido(clave_empresa, cifrado, aad):
    return quitar_relleno(descifrar(clave_empresa, cifrado, aad))


# ---------------------------------------------------------------------------
# Código de seguimiento
# ---------------------------------------------------------------------------

def generar_codigo():
    """Devuelve (código para mostrar, bytes del código).

    El código para mostrar se entrega una sola vez al denunciante. De los
    bytes solo se guarda su HMAC.
    """
    crudo = secrets.token_bytes(LONGITUD_CODIGO)
    texto = base64.b32encode(crudo).decode("ascii")
    return "-".join(texto[i:i + GRUPO_CODIGO] for i in range(0, len(texto), GRUPO_CODIGO)), crudo


def leer_codigo(texto):
    """Bytes del código, o None si no es un código válido.

    Admite minúsculas, guiones y espacios, que es como una persona lo copia o
    lo dicta. Todo lo demás se rechaza sin distinguir el motivo. isascii()
    antes de upper(): sin esa comprobación, caracteres como la ligadura "ﬀ"
    se convertirían en letras válidas.
    """
    if not isinstance(texto, str) or len(texto) > LONGITUD_MAXIMA_ENTRADA_CODIGO or not texto.isascii():
        return None
    limpio = texto.replace("-", "").replace(" ", "").upper()
    if not PATRON_CODIGO.fullmatch(limpio):
        return None
    return base64.b32decode(limpio)


def hmac_codigo(clave_hmac, crudo):
    """HMAC-SHA256 del código: 32 bytes, lo único que se guarda.

    Con 160 bits de entropía no hace falta un hash lento (a diferencia de una
    contraseña): la fuerza bruta es inviable. La clave del servidor impide
    además comprobar códigos con un volcado de la base de datos y sin ella.
    """
    if not isinstance(crudo, bytes) or len(crudo) != LONGITUD_CODIGO:
        raise ValueError("el codigo debe tener 20 bytes")
    return hmac.new(clave_hmac, ETIQUETA_SEGUIMIENTO + crudo, hashlib.sha256).digest()
