"""Login con un proveedor externo: el flujo hacia el proveedor y el ticket de
vuelta (docs/threat-model.md, 6.19).

Lógica sin HTTP, como app/personal.py: sella y abre los textos que
app/rutas_externo.py guarda en cookies y nunca sabe que lo son. Los nombres,
los atributos (__Host-, SameSite, Max-Age) y las respuestas viven solo allí.

Dos valores, cifrados con clave_flujo_externo (AES-256-GCM, app/cripto.py)
y cada uno con su etiqueta como AAD, así que uno no se abre como el otro:

* Flujo: lo que la API necesita al volver del proveedor sin guardar estado
  en el servidor: el state, el nonce y el verifier de PKCE, la empresa, el
  propósito (entrar o vincular) y, al vincular, la sesión que lo pidió.
  Caduca a los 10 minutos. Cifrado y no solo firmado: el verifier y el nonce
  solo los debe conocer el cliente que los generó (RFC 7636, 4.1; OIDC Core
  1.0, 3.1.2.1), y el navegador no los necesita.
* Ticket: el resultado de la vuelta. Lleva la empresa, el propósito, la
  sesión si es una vinculación y la huella de la cuenta externa
  (cripto.hmac_identidad), nunca el sub. Caduca a los 5 minutos y vale una
  vez: su jti se consume en Redis (app/limitador.py, consumir_una_vez).
  La vuelta no consulta la base de datos ni sabe si esa cuenta está
  vinculada: el paso siguiente busca la cuenta vinculada a esa huella en la
  misma sentencia que reserva el intento, y una cuenta sin vincular son cero
  filas, el mismo fallo que un código malo (app/personal.py).

Formato del texto en claro: campos binarios de longitud fija, sin longitudes
ni separadores que analizar. La etiqueta (con su versión) dice cómo se lee.
El texto para la cookie es el cifrado en base64url sin relleno, y solo se
acepta su forma canónica: dos textos distintos nunca abren el mismo valor.

Fallos: FlujoNoValido, TicketNoValido y VueltaNoValida no dicen nada a quien
llama más allá de su clase. VueltaNoValida lleva un motivo fijo para el log
(proveedor, state o iss), nunca un valor recibido.
"""
import base64
import dataclasses
import hashlib
import hmac
import re
import secrets
import time
import uuid

from app import cripto

# Duraciones en segundos. El flujo cubre el tiempo en la página del
# proveedor (elegir cuenta, su propio segundo factor); el ticket, el de
# escribir el código TOTP.
DURACION_FLUJO = 600
DURACION_TICKET = 300

PROPOSITO_ACCESO = "acceso"
PROPOSITO_VINCULO = "vinculo"

# Códigos de un byte. Listas cerradas: un proveedor o un propósito que no
# esté aquí no se puede sellar ni abrir. Añadir uno (GitHub, bloque A2) es
# añadir su entrada aquí y en EMISORES_AUTORIZACION.
CODIGOS_PROVEEDOR = {"google": 1}
CODIGOS_PROPOSITO = {PROPOSITO_ACCESO: 1, PROPOSITO_VINCULO: 2}

# Emisor que el proveedor devuelve en el parámetro iss de la vuelta (RFC
# 9207). Google lo anuncia en su documento de descubrimiento
# (authorization_response_iss_parameter_supported: true, issuer
# https://accounts.google.com; comprobado el 25 de octubre de 2026). Se
# exige siempre: con un solo proveedor no hay mezcla posible, pero con dos
# (A2) es la defensa contra el mix-up (RFC 9700, 4.4.2).
EMISORES_AUTORIZACION = {"google": "https://accounts.google.com"}

# state, nonce y verifier: 32 bytes aleatorios, que en base64url sin relleno
# son 43 caracteres (lo que exige el broker, PATRON_VALOR_API y
# PATRON_VERIFIER de app/proveedores_externos.py).
LONGITUD_ALEATORIO = 32
LONGITUD_JTI = 16

_UUID_NULO = bytes(16)
_LONGITUD_IDENTIFICADOR = 16
# proveedor(1) propósito(1) caduca(8) empresa(16) identificador(16) sesión(16)
# state(32) nonce(32) verifier(32)
_LONGITUD_FLUJO = 1 + 1 + 8 + 16 + _LONGITUD_IDENTIFICADOR + 16 + 3 * LONGITUD_ALEATORIO
# proveedor(1) propósito(1) caduca(8) jti(16) empresa(16) identificador(16)
# sesión(16) huella(32)
_LONGITUD_TICKET = 1 + 1 + 8 + LONGITUD_JTI + 16 + _LONGITUD_IDENTIFICADOR + 16 + 32
_PATRON_SELLADO = re.compile(r"[A-Za-z0-9_-]+")
# El identificador público de una empresa (app/denuncias.py,
# PATRON_IDENTIFICADOR): 16 bytes en hexadecimal en minúscula.
_PATRON_IDENTIFICADOR = re.compile(r"[0-9a-f]{32}")


class FlujoNoValido(Exception):
    """El texto del flujo no se abre: alterado, de otra clave o etiqueta,
    caducado o con un campo fuera de su lista."""


class TicketNoValido(Exception):
    """El texto del ticket no se abre, por los mismos motivos que el flujo."""


class VueltaNoValida(Exception):
    """La vuelta del proveedor no corresponde a este flujo."""

    def __init__(self, motivo):
        super().__init__(motivo)
        self.motivo = motivo


def _texto(crudo):
    return base64.urlsafe_b64encode(crudo).decode("ascii").rstrip("=")


def _crudo(texto, longitud):
    """Bytes de un texto base64url sin relleno de exactamente esa longitud
    descodificada, o None. Solo la forma canónica."""
    if not isinstance(texto, str) or not _PATRON_SELLADO.fullmatch(texto):
        return None
    try:
        crudo = base64.urlsafe_b64decode(texto + "=" * (-len(texto) % 4))
    except ValueError:
        return None
    if len(crudo) != longitud or _texto(crudo) != texto:
        return None
    return crudo


def _codigo_de(codigos, nombre):
    if nombre not in codigos:
        raise ValueError("valor fuera de la lista")
    return codigos[nombre].to_bytes(1, "big")


def _nombre_de(codigos, codigo):
    for nombre, valor in codigos.items():
        if valor == codigo:
            return nombre
    return None


def _identificador_crudo(identificador):
    if not isinstance(identificador, str) or not _PATRON_IDENTIFICADOR.fullmatch(identificador):
        raise ValueError("identificador de empresa mal formado")
    return bytes.fromhex(identificador)


def _sesion_coherente(proposito, sesion_id):
    """Una vinculación siempre la pide una sesión; un acceso nunca."""
    if proposito == PROPOSITO_VINCULO:
        return isinstance(sesion_id, uuid.UUID) and sesion_id.bytes != _UUID_NULO
    return sesion_id is None


@dataclasses.dataclass(frozen=True)
class Flujo:
    proveedor: str
    proposito: str
    caduca: int
    empresa_id: uuid.UUID
    identificador: str
    sesion_id: uuid.UUID | None
    # Fuera del repr: un log o una traza con el flujo no los enseña.
    state_crudo: bytes = dataclasses.field(repr=False)
    nonce_crudo: bytes = dataclasses.field(repr=False)
    verifier_crudo: bytes = dataclasses.field(repr=False)

    @property
    def state(self):
        return _texto(self.state_crudo)

    @property
    def nonce(self):
        return _texto(self.nonce_crudo)

    @property
    def verifier(self):
        return _texto(self.verifier_crudo)

    @property
    def code_challenge(self):
        """S256 (RFC 7636, 4.2): base64url sin relleno del SHA-256 del verifier
        en ASCII."""
        return _texto(hashlib.sha256(self.verifier.encode("ascii")).digest())


@dataclasses.dataclass(frozen=True)
class Ticket:
    proveedor: str
    proposito: str
    caduca: int
    jti: bytes
    empresa_id: uuid.UUID
    identificador: str
    sesion_id: uuid.UUID | None
    sub_hmac: bytes = dataclasses.field(repr=False)

    def segundos_restantes(self, ahora=None):
        """Vida que le queda, al menos 1: es el TTL de su jti en Redis."""
        ahora = int(time.time() if ahora is None else ahora)
        return max(1, self.caduca - ahora)


# ---------------------------------------------------------------------------
# Flujo
# ---------------------------------------------------------------------------

def nuevo_flujo(proveedor, proposito, empresa_id, identificador, sesion_id=None, ahora=None):
    """Flujo con state, nonce y verifier nuevos. ValueError si un campo no
    es de su lista o la sesión no corresponde al propósito."""
    ahora = int(time.time() if ahora is None else ahora)
    _codigo_de(CODIGOS_PROVEEDOR, proveedor)
    _codigo_de(CODIGOS_PROPOSITO, proposito)
    _identificador_crudo(identificador)
    if not isinstance(empresa_id, uuid.UUID) or not _sesion_coherente(proposito, sesion_id):
        raise ValueError("empresa o sesion incoherentes con el proposito")
    return Flujo(proveedor=proveedor, proposito=proposito, caduca=ahora + DURACION_FLUJO, empresa_id=empresa_id,
                 identificador=identificador, sesion_id=sesion_id,
                 state_crudo=secrets.token_bytes(LONGITUD_ALEATORIO),
                 nonce_crudo=secrets.token_bytes(LONGITUD_ALEATORIO),
                 verifier_crudo=secrets.token_bytes(LONGITUD_ALEATORIO))


def sellar_flujo(clave, flujo):
    claro = (_codigo_de(CODIGOS_PROVEEDOR, flujo.proveedor) + _codigo_de(CODIGOS_PROPOSITO, flujo.proposito)
             + flujo.caduca.to_bytes(8, "big") + flujo.empresa_id.bytes + _identificador_crudo(flujo.identificador)
             + (flujo.sesion_id.bytes if flujo.sesion_id is not None else _UUID_NULO)
             + flujo.state_crudo + flujo.nonce_crudo + flujo.verifier_crudo)
    return _texto(cripto.cifrar(clave, claro, cripto.ETIQUETA_FLUJO_EXTERNO))


def abrir_flujo(clave, texto, ahora=None):
    """Flujo de un texto sellado y vigente, o FlujoNoValido."""
    ahora = int(time.time() if ahora is None else ahora)
    sellado = _crudo(texto, 1 + cripto.LONGITUD_NONCE + _LONGITUD_FLUJO + cripto.LONGITUD_TAG)
    if sellado is None:
        raise FlujoNoValido
    try:
        claro = cripto.descifrar(clave, sellado, cripto.ETIQUETA_FLUJO_EXTERNO)
    except cripto.ErrorIntegridad:
        raise FlujoNoValido from None
    proveedor = _nombre_de(CODIGOS_PROVEEDOR, claro[0])
    proposito = _nombre_de(CODIGOS_PROPOSITO, claro[1])
    caduca = int.from_bytes(claro[2:10], "big")
    sesion = claro[42:58]
    sesion_id = None if sesion == _UUID_NULO else uuid.UUID(bytes=sesion)
    # Vigente y sin más vida de la que se le da al emitirlo.
    if (proveedor is None or proposito is None or not ahora < caduca <= ahora + DURACION_FLUJO
            or not _sesion_coherente(proposito, sesion_id)):
        raise FlujoNoValido
    return Flujo(proveedor=proveedor, proposito=proposito, caduca=caduca, empresa_id=uuid.UUID(bytes=claro[10:26]),
                 identificador=claro[26:42].hex(), sesion_id=sesion_id, state_crudo=claro[58:90],
                 nonce_crudo=claro[90:122], verifier_crudo=claro[122:154])


def comprobar_vuelta(flujo, proveedor, state, iss):
    """La vuelta es de este flujo: el mismo proveedor que la ruta, el mismo
    state (en tiempo constante) y el iss exacto de ese proveedor. Si no,
    VueltaNoValida con su motivo. Va ANTES de llamar al broker: una vuelta
    que no es de este navegador no gasta un canje (docs/threat-model.md,
    6.19)."""
    if proveedor != flujo.proveedor:
        raise VueltaNoValida("proveedor")
    if not isinstance(state, str) or not hmac.compare_digest(state.encode("utf-8"), flujo.state.encode("ascii")):
        raise VueltaNoValida("state")
    if iss != EMISORES_AUTORIZACION[flujo.proveedor]:
        raise VueltaNoValida("iss")


# ---------------------------------------------------------------------------
# Ticket
# ---------------------------------------------------------------------------

def emitir_ticket(clave_flujo, clave_identidades, flujo, sub, ahora=None):
    """Texto sellado del ticket de una vuelta válida. Del sub solo queda su
    huella con la empresa del flujo."""
    ahora = int(time.time() if ahora is None else ahora)
    huella = cripto.hmac_identidad(clave_identidades, flujo.empresa_id, flujo.proveedor, sub)
    claro = (_codigo_de(CODIGOS_PROVEEDOR, flujo.proveedor) + _codigo_de(CODIGOS_PROPOSITO, flujo.proposito)
             + (ahora + DURACION_TICKET).to_bytes(8, "big") + secrets.token_bytes(LONGITUD_JTI)
             + flujo.empresa_id.bytes + _identificador_crudo(flujo.identificador)
             + (flujo.sesion_id.bytes if flujo.sesion_id is not None else _UUID_NULO) + huella)
    return _texto(cripto.cifrar(clave_flujo, claro, cripto.ETIQUETA_TICKET_EXTERNO))


def abrir_ticket(clave, texto, proposito, ahora=None):
    """Ticket de un texto sellado, vigente y del propósito pedido, o
    TicketNoValido. Abrirlo no lo gasta: eso lo hace consumir_una_vez con
    su jti."""
    ahora = int(time.time() if ahora is None else ahora)
    sellado = _crudo(texto, 1 + cripto.LONGITUD_NONCE + _LONGITUD_TICKET + cripto.LONGITUD_TAG)
    if sellado is None:
        raise TicketNoValido
    try:
        claro = cripto.descifrar(clave, sellado, cripto.ETIQUETA_TICKET_EXTERNO)
    except cripto.ErrorIntegridad:
        raise TicketNoValido from None
    proveedor = _nombre_de(CODIGOS_PROVEEDOR, claro[0])
    leido = _nombre_de(CODIGOS_PROPOSITO, claro[1])
    caduca = int.from_bytes(claro[2:10], "big")
    sesion = claro[58:74]
    sesion_id = None if sesion == _UUID_NULO else uuid.UUID(bytes=sesion)
    if (proveedor is None or leido is None or leido != proposito or not ahora < caduca <= ahora + DURACION_TICKET
            or not _sesion_coherente(leido, sesion_id)):
        raise TicketNoValido
    return Ticket(proveedor=proveedor, proposito=leido, caduca=caduca, jti=claro[10:26],
                  empresa_id=uuid.UUID(bytes=claro[26:42]), identificador=claro[42:58].hex(), sesion_id=sesion_id,
                  sub_hmac=claro[74:106])
