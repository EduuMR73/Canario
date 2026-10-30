"""Proveedores de identidad externos del personal: el adaptador de Google.

Lo usa el broker (app/broker.py), que con el cartero del correo es el único
contenedor con salida a internet (docs/threat-model.md, 6.19). La API no habla con Google: le pasa al broker
lo que necesita y recibe una identidad (proveedor, sub). Así ni el
client_secret ni ningún token de Google llegan a la API ni al navegador
(OWASP ASVS 5.0.0, 10.1.1). La API solo importa de aquí las constantes y
los formatos (app/cliente_broker.py), para validar lo que le devuelve el
broker con los mismos valores; nunca llama a publicar ni a canjear_google,
y sin internet no podría.

Google (OpenID Connect, flujo de código de autorización):
* La URL de autorización la construye el broker con valores fijos (scope
  openid, response_type code, PKCE S256) y los tres que genera la API: state,
  code_challenge y nonce. La redirect_uri sale de CANARIO_ORIGEN_PERSONAL,
  nunca de una petición.
* El canje es un POST al token endpoint de Google, autenticado con el
  client_secret. El id_token que devuelve no se verifica por firma: OIDC Core
  1.0, 3.1.3.7, paso 6, permite validar el emisor por TLS cuando el token
  llega directo del token endpoint, y la guía de Google lo dice igual ("since
  you are communicating directly with Google over an intermediary-free HTTPS
  channel and using your client secret..."). Así el broker no necesita la
  JWKS ni salida a www.googleapis.com. Sí se validan, uno a uno, iss (sus dos
  valores), aud, azp si viene, exp, nonce y sub. Ese id_token no sale del
  broker: si lo pasara a otro componente, ese tendría que verificar la firma.
* TLS con el almacén de certificados del sistema (ssl.create_default_context):
  no hay ningún interruptor para desactivarlo ni para cambiar la CA desde la
  configuración. Las pruebas montan su CA sobre el almacén de la imagen.
* Sin redirecciones: http.client no las sigue nunca. Una respuesta 3xx del
  token endpoint es un proveedor que no responde como debe.
* Plazo total (un vigilante corta la conexión en cualquier fase) y tamaño
  máximo de cada respuesta: un proveedor lento o enorme no retiene el broker.

Errores: CanjeFallido (el proveedor rechaza el canje o responde algo que no
vale; 401) y ProveedorNoDisponible (red, TLS, plazo, 5xx o 3xx; 503). Los dos
llevan un motivo corto y fijo para el log, nunca un valor recibido.
"""
import base64
import binascii
import dataclasses
import hmac
import http.client
import json
import os
import pathlib
import re
import socket
import ssl
import threading
import time
import urllib.parse

# ---------------------------------------------------------------------------
# Formatos de entrada (los valida el broker antes de usarlos)
# ---------------------------------------------------------------------------
# state, nonce y code_challenge los genera la API: 32 bytes aleatorios en
# base64url sin relleno (43 caracteres), o el SHA-256 del verifier codificado
# igual (RFC 7636, 4.2).
PATRON_VALOR_API = re.compile(r"[A-Za-z0-9_-]{43}")
# code_verifier: RFC 7636, 4.1 (de 43 a 128 caracteres "unreserved").
PATRON_VERIFIER = re.compile(r"[A-Za-z0-9._~-]{43,128}")
# El code lo emite Google y su formato no está documentado: ASCII imprimible
# sin espacios y con un tope, para no enviar cualquier cosa al token endpoint.
PATRON_CODE = re.compile(r"[\x21-\x7e]{1,512}")
# sub de Google: "Maximum length of 255 case-sensitive ASCII characters"
# (guía de OpenID Connect de Google). Sin espacios ni controles.
PATRON_SUB = re.compile(r"[\x21-\x7e]{1,255}")

# ---------------------------------------------------------------------------
# Google
# ---------------------------------------------------------------------------
PROVEEDOR_GOOGLE = "google"
# Los proveedores que el broker sabe tratar. Un nombre fuera de la lista es
# una entrada mal formada (422); uno de la lista sin configurar, un 404.
PROVEEDORES = (PROVEEDOR_GOOGLE,)
# Documento de descubrimiento de Google (accounts.google.com/.well-known/
# openid-configuration): authorization_endpoint y token_endpoint. Fijos en el
# código: ni la API ni la configuración pueden cambiar adónde se envía el code.
URL_AUTORIZACION_GOOGLE = "https://accounts.google.com/o/oauth2/v2/auth"
HOST_TOKEN_GOOGLE = "oauth2.googleapis.com"
RUTA_TOKEN_GOOGLE = "/token"
# "Always https://accounts.google.com or accounts.google.com for Google ID
# tokens" (guía de OpenID Connect de Google).
EMISORES_GOOGLE = ("https://accounts.google.com", "accounts.google.com")
RUTA_VUELTA_GOOGLE = "/v1/personal/externo/google/vuelta"

# Configuración: dos ficheros de secrets/ montados como Docker secrets. Los
# crea scripts/generar_secretos.py con un marcador; quien opera pone en ellos
# los valores de la consola de Google Cloud. El client_id no es secreto, pero
# vive junto al secreto para que el repositorio no lleve nada de un despliegue.
FICHERO_CLIENT_ID_GOOGLE = pathlib.Path("/run/secrets/google_client_id")
FICHERO_CLIENT_SECRET_GOOGLE = pathlib.Path("/run/secrets/google_client_secret")
MARCADOR_CLIENT_ID = "sin-configurar:client-id"
MARCADOR_CLIENT_SECRET = "sin-configurar:client-secret"
PATRON_CONFIGURACION = re.compile(r"[\x21-\x7e]{1,255}")

VARIABLE_ORIGEN_PERSONAL = "CANARIO_ORIGEN_PERSONAL"
# Como lo serializa un navegador en la cabecera Origin (la misma regla que
# app/rutas_web.py, que no se importa para no traer al broker el código de la
# API).
PATRON_ORIGEN = re.compile(r"https://([a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?)(?::([1-9][0-9]{0,4}))?")

# ---------------------------------------------------------------------------
# Límites de la conexión con el proveedor
# ---------------------------------------------------------------------------
PLAZO_CONEXION_SEGUNDOS = 5
PLAZO_TOTAL_SEGUNDOS = 10
# Una respuesta del token endpoint con un id_token cabe de sobra en 64 KiB.
TAMANO_MAXIMO_RESPUESTA = 64 * 1024
TROZO_LECTURA = 8192


class ErrorConfiguracion(Exception):
    """La configuración del proveedor no es válida: el broker no arranca. El
    mensaje nunca lleva el valor de un secreto."""


class CanjeFallido(Exception):
    """El proveedor rechaza el canje o su respuesta no vale."""

    def __init__(self, motivo):
        super().__init__(motivo)
        self.motivo = motivo


class ProveedorNoDisponible(Exception):
    """No se pudo hablar con el proveedor como se espera."""

    def __init__(self, motivo):
        super().__init__(motivo)
        self.motivo = motivo


@dataclasses.dataclass(frozen=True)
class ConfigGoogle:
    client_id: str
    # Fuera del repr: un log o una traza con la configuración no lo enseña.
    client_secret: str = dataclasses.field(repr=False)
    redirect_uri: str


# ---------------------------------------------------------------------------
# Carga de la configuración
# ---------------------------------------------------------------------------
def _leer_configuracion(fichero, nombre):
    try:
        texto = fichero.read_bytes().decode("ascii")
    except FileNotFoundError:
        raise ErrorConfiguracion(f"{nombre}: falta el fichero (scripts/generar_secretos.py)") from None
    except (OSError, UnicodeDecodeError):
        raise ErrorConfiguracion(f"{nombre}: no se puede leer como ASCII") from None
    if not PATRON_CONFIGURACION.fullmatch(texto):
        raise ErrorConfiguracion(f"{nombre}: formato no valido (ASCII imprimible, sin espacios ni salto final)")
    return texto


def cargar_origen(entorno=None):
    """CANARIO_ORIGEN_PERSONAL, obligatorio y con la forma exacta de un
    Origin: de él sale la redirect_uri, que Google compara carácter a
    carácter con la registrada."""
    entorno = os.environ if entorno is None else entorno
    texto = entorno.get(VARIABLE_ORIGEN_PERSONAL)
    if texto is None:
        raise ErrorConfiguracion(f"{VARIABLE_ORIGEN_PERSONAL}: obligatoria")
    encaje = PATRON_ORIGEN.fullmatch(texto)
    puerto = encaje.group(2) if encaje else None
    if not encaje or (puerto is not None and (int(puerto) > 65535 or puerto == "443")):
        raise ErrorConfiguracion(f"{VARIABLE_ORIGEN_PERSONAL}: se espera https://host o https://host:puerto")
    return texto


def cargar_google(origen, fichero_id=FICHERO_CLIENT_ID_GOOGLE, fichero_secreto=FICHERO_CLIENT_SECRET_GOOGLE):
    """ConfigGoogle, o None si Google no está configurado (los dos ficheros
    con su marcador). Uno configurado y el otro no es un error de quien
    opera: ErrorConfiguracion, y el broker no arranca."""
    client_id = _leer_configuracion(fichero_id, "google_client_id")
    client_secret = _leer_configuracion(fichero_secreto, "google_client_secret")
    sin_id = client_id == MARCADOR_CLIENT_ID
    sin_secreto = client_secret == MARCADOR_CLIENT_SECRET
    if sin_id and sin_secreto:
        return None
    if sin_id or sin_secreto:
        falta = "google_client_id" if sin_id else "google_client_secret"
        raise ErrorConfiguracion(f"google configurado a medias: {falta} conserva su marcador")
    return ConfigGoogle(client_id=client_id, client_secret=client_secret,
                        redirect_uri=origen + RUTA_VUELTA_GOOGLE)


# ---------------------------------------------------------------------------
# Autorización
# ---------------------------------------------------------------------------
def url_autorizacion_google(config, state, code_challenge, nonce):
    """URL a la que la SPA manda al navegador. Solo el scope openid: Canario
    no necesita el email ni el perfil (minimización, RGPD art. 5.1.c)."""
    parametros = {
        "client_id": config.client_id,
        "redirect_uri": config.redirect_uri,
        "response_type": "code",
        "scope": "openid",
        "state": state,
        "code_challenge": code_challenge,
        # Explícito: si falta, RFC 7636 (4.3) toma "plain".
        "code_challenge_method": "S256",
        "nonce": nonce,
    }
    return URL_AUTORIZACION_GOOGLE + "?" + urllib.parse.urlencode(parametros)


# ---------------------------------------------------------------------------
# Canje
# ---------------------------------------------------------------------------
def _contexto_tls():
    # Verificación de certificado y de nombre, con el almacén del sistema.
    return ssl.create_default_context()


def _cortar(conexion, cortada):
    """La llama el vigilante al cumplirse el plazo total: shutdown despierta
    una lectura bloqueada en otro hilo (close no lo garantiza)."""
    cortada.set()
    sock = conexion.sock
    if sock is not None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


def publicar(host, ruta, cuerpo, plazo=PLAZO_TOTAL_SEGUNDOS):
    """POST HTTPS. Devuelve (estado, cuerpo) o lanza una de las excepciones
    del módulo.

    Dos plazos: el de la conexión vale por operación de red, y un vigilante
    corta la conexión al cumplirse el total, en cualquier fase (TLS,
    cabeceras o cuerpo). Sin él, un servidor que envía un byte cada pocos
    segundos alargaría la respuesta sin límite: cada operación cumpliría su
    plazo. read1 devuelve lo que haya llegado, sin esperar a llenar el trozo.
    """
    conexion = http.client.HTTPSConnection(host, timeout=PLAZO_CONEXION_SEGUNDOS, context=_contexto_tls())
    cortada = threading.Event()
    vigilante = threading.Timer(plazo, _cortar, args=(conexion, cortada))
    vigilante.start()
    try:
        conexion.request("POST", ruta, body=cuerpo, headers={
            "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
        respuesta = conexion.getresponse()
        leido = b""
        while len(leido) <= TAMANO_MAXIMO_RESPUESTA:
            trozo = respuesta.read1(TROZO_LECTURA)
            if not trozo:
                break
            leido += trozo
        # Tras un corte, lo leído puede estar a medias: no vale.
        if cortada.is_set():
            raise ProveedorNoDisponible("plazo")
        if len(leido) > TAMANO_MAXIMO_RESPUESTA:
            raise CanjeFallido("respuesta_grande")
        return respuesta.status, leido
    except (OSError, http.client.HTTPException) as error:
        if cortada.is_set():
            raise ProveedorNoDisponible("plazo") from None
        # ssl.SSLError y TimeoutError son OSError: van antes que "red".
        if isinstance(error, ssl.SSLError):
            raise ProveedorNoDisponible("tls") from None
        if isinstance(error, TimeoutError):
            raise ProveedorNoDisponible("plazo") from None
        raise ProveedorNoDisponible("red") from None
    finally:
        vigilante.cancel()
        conexion.close()


def _parte_jwt(texto):
    try:
        datos = base64.urlsafe_b64decode(texto + "=" * (-len(texto) % 4))
        return json.loads(datos)
    # RecursionError: un JSON anidado miles de niveles no es un ValueError.
    except (binascii.Error, ValueError, RecursionError):
        raise CanjeFallido("id_token_formato") from None


def validar_id_token_google(id_token, client_id, nonce, ahora=time.time):
    """sub del id_token, o CanjeFallido. Cada comprobación, con su motivo."""
    if not isinstance(id_token, str) or id_token.count(".") != 2:
        raise CanjeFallido("id_token_formato")
    claims = _parte_jwt(id_token.split(".")[1])
    if not isinstance(claims, dict):
        raise CanjeFallido("id_token_formato")
    if claims.get("iss") not in EMISORES_GOOGLE:
        raise CanjeFallido("iss")
    # aud como cadena y exacta: una lista con nuestro client_id y otro sería
    # un token emitido también para otra aplicación.
    if claims.get("aud") != client_id:
        raise CanjeFallido("aud")
    if "azp" in claims and claims["azp"] != client_id:
        raise CanjeFallido("azp")
    exp = claims.get("exp")
    # bool es un int en Python: True no puede pasar por una fecha.
    if type(exp) is not int or ahora() >= exp:
        raise CanjeFallido("exp")
    recibido = claims.get("nonce")
    if not isinstance(recibido, str) or not hmac.compare_digest(recibido.encode(), nonce.encode()):
        raise CanjeFallido("nonce")
    sub = claims.get("sub")
    if not isinstance(sub, str) or not PATRON_SUB.fullmatch(sub):
        raise CanjeFallido("sub")
    return sub


def canjear_google(config, code, verifier, nonce, enviar=publicar, ahora=time.time):
    """sub de la cuenta de Google que autorizó el code, o una de las dos
    excepciones del módulo."""
    cuerpo = urllib.parse.urlencode({
        "code": code,
        "client_id": config.client_id,
        "client_secret": config.client_secret,
        "redirect_uri": config.redirect_uri,
        "grant_type": "authorization_code",
        "code_verifier": verifier,
    }).encode("ascii")
    estado, datos = enviar(HOST_TOKEN_GOOGLE, RUTA_TOKEN_GOOGLE, cuerpo)
    # 400 y 401: el code, el verifier o el cliente no valen (RFC 6749, 5.2).
    if estado in (400, 401):
        raise CanjeFallido("rechazado")
    if estado != 200:
        raise ProveedorNoDisponible("estado")
    try:
        respuesta = json.loads(datos)
    except (ValueError, RecursionError):
        raise CanjeFallido("json") from None
    if not isinstance(respuesta, dict):
        raise CanjeFallido("json")
    return validar_id_token_google(respuesta.get("id_token"), config.client_id, nonce, ahora)
