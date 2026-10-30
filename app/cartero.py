"""Cartero: el único contenedor de Canario que entrega correo fuera
(docs/threat-model.md, 6.3).

La API no tiene salida a internet ni credenciales de correo (6.11). Le pasa
cada correo a este proceso por la red interna correo (app/correo.py), y él lo
compone y lo entrega al proveedor (Mailjet en producción, Mailpit en
desarrollo). Es la misma separación que el broker (app/broker.py, 6.19): si
cae el cartero, el atacante tiene la credencial SMTP, no las claves de
Canario ni la base de datos, a la que el cartero no llega.

Quién le habla: solo la API. uvicorn escucha solo en la IP del cartero en la
red correo (--host en docker-compose.yml) y, además, toda ruta salvo /salud
exige que la conexión venga de la IP fija de la API (CANARIO_IP_API).

Qué hace, y nada más:
* GET /salud: vivacidad (el healthcheck, desde el propio contenedor).
* POST /correos: valida un correo, lo pone en la cola y responde 202 en el
  acto. Entregarlo es cosa de un hilo aparte (abajo).

Por qué así:
* La API no elige el remitente ni las cabeceras: los fija el cartero. Una API
  comprometida solo puede pedir correos de un tipo conocido, a un email con
  forma de email, con un asunto de una línea; lo demás es un 422.
* TLS siempre, con el certificado verificado: ssl.create_default_context()
  explícito. smtplib, si no se le pasa un contexto, usa
  ssl._create_stdlib_context(), que NO verifica el certificado (comprobado en
  el código de Python 3.12). Puerto de TLS implícito (465), no STARTTLS: con
  STARTTLS, quien está en medio puede quitar el anuncio y la sesión seguiría
  en claro (RFC 8314, 3). No hay modo sin TLS: en desarrollo Mailpit también
  habla TLS, con un certificado de una CA local (scripts/generar_tls_desarrollo.py).
* Sin seguimiento: X-Mailjet-TrackClick y X-Mailjet-TrackOpen a 0. Con el
  seguimiento, el proveedor reescribe cada enlace por uno suyo que lleva el
  original entero, y el token, que va en el fragmento (#) precisamente para
  no llegar a ningún servidor, acabaría en sus registros. Mailjet documenta
  que estas cabeceras mandan sobre la configuración de la cuenta.
* Cola en memoria, acotada, con reintentos: un proveedor caído un rato no
  pierde el correo. No se guarda en disco a propósito: los correos llevan
  enlaces con tokens, y la base de datos solo guarda su HMAC. Si el cartero
  se para con correos pendientes, quedan en EVENTO correo_perdido y se
  recuperan con lo que ya existe: reinvitar desde Cuentas o volver a pedir
  el registro.
* Cupo diario por categoría: el proveedor tiene un tope diario (Mailjet
  gratis: 200). Los avisos de seguridad (6.15) tienen su propia parte: una
  avalancha de registros no puede agotarlo y silenciarlos.

Los EVENTO del log llevan el tipo de correo y un motivo fijo, nunca el
destinatario, el asunto, el cuerpo ni la credencial.
"""
import dataclasses
import datetime
import heapq
import ipaddress
import itertools
import logging
import os
import pathlib
import re
import smtplib
import ssl
import threading
import time
from contextlib import asynccontextmanager
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from app import correo, validacion

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
registro = logging.getLogger("canario.cartero")

VARIABLE_IP_API = "CANARIO_IP_API"
VARIABLE_SERVIDOR = "CANARIO_SMTP_SERVIDOR"
VARIABLE_PUERTO = "CANARIO_SMTP_PUERTO"
VARIABLE_REMITENTE = "CANARIO_CORREO_REMITENTE"

# Credenciales SMTP: dos ficheros de secrets/ montados como Docker secrets. Los
# crea scripts/generar_secretos.py con un marcador; quien opera pone los de la
# cuenta del proveedor. Con los dos marcadores el cartero entrega sin
# autenticarse (Mailpit, en desarrollo, no lo pide); con uno solo no arranca.
FICHERO_USUARIO = pathlib.Path("/run/secrets/smtp_usuario")
FICHERO_CONTRASENA = pathlib.Path("/run/secrets/smtp_contrasena")
MARCADOR_USUARIO = "sin-configurar:usuario"
MARCADOR_CONTRASENA = "sin-configurar:contrasena"
PATRON_CONFIGURACION = re.compile(r"[\x21-\x7e]{1,255}")
# Nombre de host: minúsculas, cifras, puntos y guiones (RFC 1123).
PATRON_SERVIDOR = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?")
NOMBRE_REMITENTE = "Canario"
# Pie de todos los correos, puesto aquí para que ninguno salga sin él. Un
# correo falso de "invitación" busca justo eso (ATT&CK T1566.002): que alguien
# escriba su contraseña o su código en una página que no es Canario. Se
# separa con la línea "-- " de la convención de firmas (RFC 3676, 4.3).
PIE = "-- \nCanario nunca le pedirá por correo su contraseña ni su código de verificación."

# Las peticiones de la API son de unos pocos KiB (el cuerpo más largo es el
# aviso de lecturas). Se exige Content-Length y un tope antes de leer.
TAMANO_MAXIMO_PETICION = 16 * 1024
LONGITUD_MAXIMA_ASUNTO = 200
LONGITUD_MAXIMA_CUERPO = 8000

# Segundos para conectar y para cada respuesta del proveedor: un servidor
# colgado no retiene el hilo de entrega para siempre.
PLAZO = 10
# Correos pendientes como mucho. Llena, la API recibe un 503 y lo registra:
# la memoria del cartero no crece sin límite.
COLA_MAXIMA = 50
# Segundos de espera antes de cada reintento. Cuatro intentos en unos 20
# minutos: más allá, el enlace del correo sigue valiendo (24 o 72 horas),
# pero un proveedor caído tanto tiempo es una incidencia que tiene que
# verse en el log, no esconderse detrás de reintentos.
ESPERAS_REINTENTO = (60, 300, 900)

# Cupo diario (día UTC) por categoría. La suma es el tope del plan gratuito
# de Mailjet (200 al día, mailjet.com/pricing): pasarlo solo serviría para
# que el proveedor los aplace al día siguiente.
CATEGORIAS = {
    "verificacion": "registro", "aviso_cuenta": "registro", "aviso_pendiente": "registro",
    "invitacion": "registro",
    "aviso_lecturas": "avisos", "aviso_activacion": "avisos", "aviso_vinculo": "avisos",
}
CUPO_DIARIO = {"registro": 150, "avisos": 50}

CUERPO_FORMATO = {"detalle": "formato no valido"}
CUERPO_PROHIBIDO = {"detalle": "prohibido"}
CUERPO_CUPO = {"detalle": "cupo diario agotado"}
CUERPO_COLA = {"detalle": "cola llena"}
CUERPO_ACEPTADO = {"estado": "en_cola"}


class ArranqueBloqueado(Exception):
    """La configuración no es válida: el cartero no arranca y el motivo
    queda en el log. El mensaje nunca lleva el valor de un secreto."""


@dataclasses.dataclass(frozen=True)
class Config:
    ip_api: str
    servidor: str
    puerto: int
    remitente: str
    usuario: str | None
    # Fuera del repr: un log o una traza con la configuración no la enseña.
    contrasena: str | None = dataclasses.field(repr=False)


# ---------------------------------------------------------------------------
# Configuración
# ---------------------------------------------------------------------------
def _leer_secreto(fichero, nombre):
    try:
        texto = fichero.read_bytes().decode("ascii")
    except FileNotFoundError:
        raise ArranqueBloqueado(f"{nombre}: falta el fichero (scripts/generar_secretos.py)") from None
    except (OSError, UnicodeDecodeError):
        raise ArranqueBloqueado(f"{nombre}: no se puede leer como ASCII") from None
    if not PATRON_CONFIGURACION.fullmatch(texto):
        raise ArranqueBloqueado(f"{nombre}: formato no valido (ASCII imprimible, sin espacios ni salto final)")
    return texto


def cargar_config(entorno=None, fichero_usuario=FICHERO_USUARIO, fichero_contrasena=FICHERO_CONTRASENA):
    """Toda la configuración es obligatoria y explícita, sin valores por
    defecto: un correo con un enlace secreto no sale hacia un servidor que
    nadie eligió."""
    entorno = os.environ if entorno is None else entorno
    try:
        ip_api = str(ipaddress.IPv4Address(entorno.get(VARIABLE_IP_API) or ""))
    except ValueError:
        raise ArranqueBloqueado(f"{VARIABLE_IP_API}: obligatoria, una IPv4") from None
    servidor = entorno.get(VARIABLE_SERVIDOR) or ""
    if not PATRON_SERVIDOR.fullmatch(servidor):
        raise ArranqueBloqueado(f"{VARIABLE_SERVIDOR}: obligatoria, un nombre de host")
    texto_puerto = entorno.get(VARIABLE_PUERTO) or ""
    if not (texto_puerto.isdigit() and 1 <= int(texto_puerto) <= 65535):
        raise ArranqueBloqueado(f"{VARIABLE_PUERTO}: obligatoria, de 1 a 65535")
    try:
        remitente = validacion.validar_email(entorno.get(VARIABLE_REMITENTE) or "")
    except ValueError:
        raise ArranqueBloqueado(f"{VARIABLE_REMITENTE}: obligatoria, un email") from None
    usuario = _leer_secreto(fichero_usuario, "smtp_usuario")
    contrasena = _leer_secreto(fichero_contrasena, "smtp_contrasena")
    sin_usuario = usuario == MARCADOR_USUARIO
    sin_contrasena = contrasena == MARCADOR_CONTRASENA
    if sin_usuario != sin_contrasena:
        falta = "smtp_usuario" if sin_usuario else "smtp_contrasena"
        raise ArranqueBloqueado(f"credenciales SMTP a medias: {falta} conserva su marcador")
    if sin_usuario:
        usuario = contrasena = None
    return Config(ip_api=ip_api, servidor=servidor, puerto=int(texto_puerto), remitente=remitente,
                  usuario=usuario, contrasena=contrasena)


# ---------------------------------------------------------------------------
# Composición y entrega
# ---------------------------------------------------------------------------
class EntregaFallida(Exception):
    """El correo no se entregó. definitiva: reintentar no cambiaría nada
    (el proveedor lo rechaza o el certificado no vale)."""

    def __init__(self, motivo, definitiva):
        super().__init__(motivo)
        self.motivo = motivo
        self.definitiva = definitiva


def componer(remitente, tipo, destinatario, asunto, cuerpo):
    """EmailMessage listo para entregar. ValueError si una cabecera lleva CR o
    LF: EmailMessage los rechaza (comprobado en Python 3.12.15, el de la
    imagen), y eso cierra la inyección de cabeceras (CWE-93) aunque una
    validación anterior fallara."""
    if tipo not in correo.TIPOS:
        raise ValueError("tipo de correo desconocido")
    mensaje = EmailMessage()
    mensaje["From"] = formataddr((NOMBRE_REMITENTE, remitente))
    mensaje["To"] = destinatario
    mensaje["Subject"] = asunto
    mensaje["Date"] = formatdate(usegmt=True)
    # Con el dominio del remitente: sin él, make_msgid usaría el nombre del
    # contenedor, que no dice nada a nadie y delata la infraestructura.
    mensaje["Message-ID"] = make_msgid(domain=remitente.split("@", 1)[1])
    # Ver la cabecera del módulo: sin ellas, el token del enlace llegaría al
    # proveedor dentro de su URL de seguimiento.
    mensaje["X-Mailjet-TrackClick"] = "0"
    mensaje["X-Mailjet-TrackOpen"] = "0"
    mensaje.set_content(f"{cuerpo}\n\n{PIE}\n")
    return mensaje


def contexto_tls():
    """Contexto TLS que verifica el certificado y el nombre del servidor con
    el almacén de la imagen. Las baterías montan ahí su CA de prueba, como en
    el broker: el código no tiene un modo sin verificar."""
    return ssl.create_default_context()


def _codigo_definitivo(codigo):
    # SMTP: 4xx es temporal y 5xx definitivo (RFC 5321, 4.2.1).
    return codigo >= 500


def entregar(config, mensaje, smtp=smtplib.SMTP_SSL):
    """Entrega un correo. EntregaFallida con un motivo fijo si no sale."""
    try:
        with smtp(config.servidor, config.puerto, timeout=PLAZO, context=contexto_tls()) as servidor:
            if config.usuario is not None:
                servidor.login(config.usuario, config.contrasena)
            servidor.send_message(mensaje)
    except ssl.SSLCertVerificationError:
        # Antes que OSError, del que deriva: reintentar con el mismo
        # certificado no lo arregla, y es lo que se vería si alguien se
        # hiciera pasar por el proveedor.
        raise EntregaFallida("certificado", definitiva=True) from None
    except smtplib.SMTPRecipientsRefused as error:
        codigos = [codigo for codigo, _texto in error.recipients.values()]
        raise EntregaFallida("destinatario_rechazado", definitiva=any(map(_codigo_definitivo, codigos))) from None
    except smtplib.SMTPAuthenticationError:
        raise EntregaFallida("autenticacion", definitiva=True) from None
    except smtplib.SMTPResponseException as error:
        raise EntregaFallida(f"smtp_{error.smtp_code}", definitiva=_codigo_definitivo(error.smtp_code)) from None
    except (smtplib.SMTPException, OSError) as error:
        # Red, plazo, desconexión o TLS que no se negocia: temporal.
        raise EntregaFallida(type(error).__name__, definitiva=False) from None


# ---------------------------------------------------------------------------
# Cola y cupo
# ---------------------------------------------------------------------------
@dataclasses.dataclass
class Pendiente:
    tipo: str
    mensaje: EmailMessage
    intento: int = 0


class Cola:
    """Correos pendientes, ordenados por el momento en que toca intentarlos,
    y el cupo del día. Un solo hilo los entrega: el volumen es de decenas al
    día y así el orden y el cupo no tienen carreras."""

    def __init__(self, reloj=time.monotonic, hoy=lambda: datetime.datetime.now(datetime.UTC).date()):
        self._reloj = reloj
        self._hoy = hoy
        self._condicion = threading.Condition()
        self._monton = []
        self._secuencia = itertools.count()
        self._dia = None
        self._usados = {}
        self._cerrada = False

    def admitir(self, pendiente):
        """None si entra en la cola, o el motivo por el que no entra."""
        categoria = CATEGORIAS[pendiente.tipo]
        with self._condicion:
            if self._cerrada:
                return "cerrada"
            if len(self._monton) >= COLA_MAXIMA:
                return "cola_llena"
            hoy = self._hoy()
            if hoy != self._dia:
                self._dia, self._usados = hoy, {}
            if self._usados.get(categoria, 0) >= CUPO_DIARIO[categoria]:
                return "cupo_diario"
            self._usados[categoria] = self._usados.get(categoria, 0) + 1
            self._poner(pendiente, self._reloj())
            return None

    def _poner(self, pendiente, cuando):
        heapq.heappush(self._monton, (cuando, next(self._secuencia), pendiente))
        self._condicion.notify()

    def reintentar(self, pendiente, espera):
        with self._condicion:
            if not self._cerrada:
                self._poner(pendiente, self._reloj() + espera)
                return True
            return False

    def siguiente(self):
        """El siguiente pendiente cuando le toque, o None si la cola se cerró."""
        with self._condicion:
            while not self._cerrada:
                if self._monton:
                    espera = self._monton[0][0] - self._reloj()
                    if espera <= 0:
                        return heapq.heappop(self._monton)[2]
                    self._condicion.wait(espera)
                else:
                    self._condicion.wait()
            return None

    def cerrar(self):
        """Cierra la cola y devuelve los pendientes que se quedan sin enviar."""
        with self._condicion:
            self._cerrada = True
            pendientes = [elemento[2] for elemento in self._monton]
            self._monton = []
            self._condicion.notify_all()
            return pendientes


def repartir(cola, config, entregar_uno=entregar):
    """Bucle del hilo de entrega: hasta que se cierre la cola."""
    while (pendiente := cola.siguiente()) is not None:
        try:
            entregar_uno(config, pendiente.mensaje)
        except EntregaFallida as error:
            if not error.definitiva and pendiente.intento < len(ESPERAS_REINTENTO):
                espera = ESPERAS_REINTENTO[pendiente.intento]
                pendiente.intento += 1
                registro.warning("EVENTO correo_aplazado: tipo=%s motivo=%s intento=%d",
                                 pendiente.tipo, error.motivo, pendiente.intento)
                if cola.reintentar(pendiente, espera):
                    continue
            registro.error("EVENTO correo_fallido: tipo=%s motivo=%s", pendiente.tipo, error.motivo)
        # Exception y no una lista cerrada: el hilo de entrega no puede morir
        # por un fallo imprevisto, o la cola se llenaría sin que nada saliera.
        # Queda solo la clase, nunca el texto (puede llevar el destinatario).
        except Exception as error:  # noqa: BLE001 - el hilo de entrega no puede morir en silencio
            registro.error("EVENTO correo_fallido: tipo=%s motivo=%s", pendiente.tipo, type(error).__name__)
        else:
            registro.info("EVENTO correo_entregado: tipo=%s", pendiente.tipo)


# ---------------------------------------------------------------------------
# Aplicación
# ---------------------------------------------------------------------------
@asynccontextmanager
async def ciclo_de_vida(app):
    try:
        config = cargar_config()
    except ArranqueBloqueado as error:
        registro.error("ARRANQUE BLOQUEADO: %s", error)
        raise
    if config.usuario is None:
        # Visible en cada arranque: en producción, sin credenciales, el
        # proveedor rechazará cada correo (y cada uno dejará su evento).
        registro.warning("EVENTO correo_sin_credenciales: se entrega sin autenticarse")
    registro.info("CARTERO LISTO: servidor=%s puerto=%d remitente=%s", config.servidor, config.puerto,
                  config.remitente)
    app.state.config = config
    app.state.cola = Cola()
    hilo = threading.Thread(target=repartir, args=(app.state.cola, config), name="reparto", daemon=True)
    hilo.start()
    yield
    perdidos = app.state.cola.cerrar()
    if perdidos:
        registro.error("EVENTO correo_perdido: pendientes=%d", len(perdidos))
    hilo.join(PLAZO * 2)


# Sin /docs, /redoc ni /openapi.json, y sin redirecciones implícitas, como la
# API (app/principal.py).
aplicacion = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, redirect_slashes=False,
                     lifespan=ciclo_de_vida)


@aplicacion.exception_handler(RequestValidationError)
async def _formato_no_valido(_peticion, _error):
    # El 422 de FastAPI repite la entrada recibida ("input"): aquí sería el
    # destinatario o el cuerpo con su enlace. Siempre el mismo cuerpo.
    return JSONResponse(CUERPO_FORMATO, status_code=422)


@aplicacion.middleware("http")
async def _frontera(peticion: Request, siguiente):
    # /salud queda abierta a propósito: la llama el healthcheck desde dentro
    # del propio contenedor y no dice nada.
    if peticion.url.path != "/salud":
        cliente = peticion.client.host if peticion.client else None
        if cliente != peticion.app.state.config.ip_api:
            # Sin la IP en el log, como en el resto de Canario.
            registro.warning("EVENTO cartero_cliente_rechazado: ruta=%s", peticion.url.path)
            return JSONResponse(CUERPO_PROHIBIDO, status_code=403)
    if peticion.method == "POST":
        longitud = peticion.headers.get("content-length")
        if longitud is None or not longitud.isdigit() or int(longitud) > TAMANO_MAXIMO_PETICION:
            return JSONResponse(CUERPO_FORMATO, status_code=422)
    return await siguiente(peticion)


class PeticionCorreo(BaseModel):
    # Los mismos tipos de texto que los modelos de la API (app/validacion.py).
    model_config = ConfigDict(extra="forbid", strict=True)
    tipo: validacion.TextoLinea
    destinatario: validacion.TextoLinea
    asunto: validacion.TextoLinea
    cuerpo: validacion.TextoLibre


@aplicacion.get("/salud")
def salud():
    return {"estado": "ok"}


@aplicacion.post("/correos", status_code=202)
def correos(datos: PeticionCorreo, peticion: Request):
    try:
        if datos.tipo not in correo.TIPOS or not (
                1 <= len(datos.asunto) <= LONGITUD_MAXIMA_ASUNTO and 1 <= len(datos.cuerpo) <= LONGITUD_MAXIMA_CUERPO):
            raise ValueError
        destinatario = validacion.validar_email(datos.destinatario)
        mensaje = componer(peticion.app.state.config.remitente, datos.tipo, destinatario, datos.asunto, datos.cuerpo)
    except ValueError:
        return JSONResponse(CUERPO_FORMATO, status_code=422)
    motivo = peticion.app.state.cola.admitir(Pendiente(tipo=datos.tipo, mensaje=mensaje))
    if motivo is None:
        return CUERPO_ACEPTADO
    registro.error("EVENTO correo_descartado: tipo=%s motivo=%s", datos.tipo, motivo)
    if motivo == "cupo_diario":
        return JSONResponse(CUERPO_CUPO, status_code=429)
    return JSONResponse(CUERPO_COLA, status_code=503)
