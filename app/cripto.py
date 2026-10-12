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
import urllib.parse
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
ETIQUETA_TOTP = b"canario/totp/v1"
# Una etiqueta por tipo de token del personal: el mismo valor no sirve como
# otro tipo de token aunque alguien lo presente en otro sitio.
ETIQUETA_INVITACION = b"canario/invitacion/v1"
ETIQUETA_DISPOSITIVO = b"canario/dispositivo/v1"
ETIQUETA_SESION = b"canario/sesion/v1"

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


# ---------------------------------------------------------------------------
# TOTP del personal (RFC 6238 sobre HOTP, RFC 4226)
# ---------------------------------------------------------------------------

# Los parámetros que entienden todas las aplicaciones de autenticación: SHA-1,
# 6 dígitos y pasos de 30 s. SHA-1 aquí es HMAC-SHA-1, que sigue siendo seguro
# como PRF (RFC 4226, apéndice A.2); no se usa como hash resistente a
# colisiones. 160 bits de secreto, lo que recomienda RFC 4226 (sección 4).
LONGITUD_SECRETO_TOTP = 20
DIGITOS_TOTP = 6
PERIODO_TOTP = 30
# Pasos de desfase admitidos a cada lado: el reloj del móvil puede ir unos
# segundos desviado (RFC 6238, sección 5.2). Uno a cada lado: 3 códigos
# válidos a la vez, y cada uno solo se acepta una vez (ultimo_paso_totp).
DESFASE_TOTP = 1
EMISOR_TOTP = "Canario"
PATRON_CODIGO_TOTP = re.compile(r"[0-9]{6}")


def aad_totp(empresa_id, usuario_id):
    """Ata el secreto TOTP cifrado a su cuenta: copiado a otra fila no se
    descifra. Es el mismo en la invitación y en la cuenta, así que al
    confirmar se mueve sin volver a cifrar."""
    _exigir_uuid(empresa_id, usuario_id)
    return ETIQUETA_TOTP + empresa_id.bytes + usuario_id.bytes


def generar_secreto_totp():
    return secrets.token_bytes(LONGITUD_SECRETO_TOTP)


def paso_totp(instante):
    return int(instante) // PERIODO_TOTP


def codigo_totp(secreto, paso, digitos=DIGITOS_TOTP):
    """HOTP(secreto, paso) con el truncado dinámico de RFC 4226, sección 5.3.

    digitos solo es parámetro para comprobar los vectores de RFC 6238
    (apéndice B), que usan 8.
    """
    mac = hmac.new(secreto, paso.to_bytes(8, "big"), hashlib.sha1).digest()
    desplazamiento = mac[-1] & 0x0F
    binario = int.from_bytes(mac[desplazamiento:desplazamiento + 4], "big") & 0x7FFFFFFF
    return f"{binario % 10 ** digitos:0{digitos}d}"


def verificar_totp(secreto, codigo, instante):
    """Paso que corresponde al código, o None si no vale.

    Calcula y compara siempre los tres pasos, sin salir antes y en tiempo
    constante: el tiempo de respuesta no dice si el código casi valía. Un
    código mal formado también recorre los tres, contra un valor que nunca
    coincide.
    """
    bien_formado = isinstance(codigo, str) and PATRON_CODIGO_TOTP.fullmatch(codigo) is not None
    recibido = (codigo if bien_formado else "x" * DIGITOS_TOTP).encode("ascii")
    actual = paso_totp(instante)
    aceptado = None
    for paso in range(actual - DESFASE_TOTP, actual + DESFASE_TOTP + 1):
        if hmac.compare_digest(codigo_totp(secreto, paso).encode("ascii"), recibido) and bien_formado:
            aceptado = paso
    return aceptado


def secreto_totp_texto(secreto):
    """Secreto en base32 sin relleno, como lo teclea una persona."""
    return base64.b32encode(secreto).decode("ascii").rstrip("=")


def uri_totp(secreto, email):
    """URI otpauth:// (Key Uri Format de Google Authenticator) para el QR.

    El separador entre emisor y cuenta va como ':' literal, y el email se
    codifica aparte: un ':' dentro del email sale como %3A y la etiqueta no
    es ambigua."""
    etiqueta = f"{urllib.parse.quote(EMISOR_TOTP, safe='')}:{urllib.parse.quote(email, safe='@')}"
    return (f"otpauth://totp/{etiqueta}?secret={secreto_totp_texto(secreto)}&issuer={EMISOR_TOTP}"
            f"&algorithm=SHA1&digits={DIGITOS_TOTP}&period={PERIODO_TOTP}")


# ---------------------------------------------------------------------------
# Tokens del personal (invitación, dispositivo y sesión)
# ---------------------------------------------------------------------------

# 256 bits aleatorios en base64url sin relleno: 43 caracteres. Con esa
# entropía basta un SHA-256 para guardarlos (como el HMAC de los códigos, no
# hace falta un hash lento), y la etiqueta de cada tipo impide usar uno por
# otro.
LONGITUD_TOKEN = 32
PATRON_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")


def generar_token():
    """Devuelve (texto para el cliente, bytes). Solo se guarda la huella."""
    crudo = secrets.token_bytes(LONGITUD_TOKEN)
    return base64.urlsafe_b64encode(crudo).decode("ascii").rstrip("="), crudo


def leer_token(texto):
    """Bytes del token, o None si no tiene la forma exacta.

    Solo la forma canónica: el último carácter de 43 lleva 4 bits sobrantes,
    y sin esta comprobación varios textos distintos darían el mismo token.
    """
    if not isinstance(texto, str) or not PATRON_TOKEN.fullmatch(texto):
        return None
    crudo = base64.urlsafe_b64decode(texto + "=")
    if base64.urlsafe_b64encode(crudo).decode("ascii").rstrip("=") != texto:
        return None
    return crudo


def huella_token(etiqueta, crudo):
    if etiqueta not in (ETIQUETA_INVITACION, ETIQUETA_DISPOSITIVO, ETIQUETA_SESION):
        raise ValueError("etiqueta de token desconocida")
    if not isinstance(crudo, bytes) or len(crudo) != LONGITUD_TOKEN:
        raise ValueError("el token debe tener 32 bytes")
    return hashlib.sha256(etiqueta + crudo).digest()
