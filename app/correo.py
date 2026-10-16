"""Correo saliente del registro del personal (docs/threat-model.md, 6.3).

Lo envía app/solicitudes.py: el enlace de verificación de una solicitud, los
avisos al titular de un email y la invitación de una solicitud aprobada.

Por qué así:
* Se envía DESPUÉS de responder (BackgroundTask de Starlette: en la versión
  fijada, Response.__call__ envía el cuerpo y solo después espera a la
  tarea). El tiempo de la respuesta no depende de si hubo correo, de a quién
  ni de lo que tarde el servidor SMTP: no es un canal para saber si un email
  tiene cuenta.
* La tarea en segundo plano de una función síncrona ocupa un hilo del pool
  de la API, el mismo que usan todas las rutas síncronas (starlette 1.7.0,
  background.py: run_in_threadpool). Un servidor SMTP lento retendría un hilo
  por correo hasta PLAZO segundos y podría dejar a la API sin hilos. Por eso
  hay como mucho CORREOS_SIMULTANEOS envíos a la vez, y si no hay hueco el
  correo se descarta al momento (EVENTO correo_descartado) en vez de esperar:
  el daño de un SMTP colgado queda acotado a esos hilos.
* Un fallo de envío no tiene a quién devolverse (la respuesta ya salió), así
  que se registra: EVENTO correo_fallido con el tipo de correo y la clase del
  error, nunca el email, el enlace ni el token. Nada se traga en silencio.
* El destinatario llega validado (app/validacion.py: ASCII imprimible, sin
  espacios). Además, EmailMessage rechaza CR y LF en las cabeceras
  (comprobado en Python 3.12.15, el de la imagen fijada): una inyección de
  cabeceras (CWE-93) daría ValueError, que acaba en el mismo evento.
* El token solo va en el fragmento del enlace (#...): el navegador no lo
  envía al servidor, así que no queda en logs, en Referer ni en proxies. La
  página lo manda por POST (app/solicitudes.py).

Destino: en desarrollo, Mailpit (docker-compose.yml, perfil desarrollo, red
interna correo sin salida a internet). Sin texto plano en tránsito fuera de
esa red interna, porque no sale de ella. La salida SMTP de producción
(relay, TLS, SPF, DKIM y DMARC) no está decidida: es un punto abierto del
modelo de amenazas, y sin ella el registro no entrega correos (cada intento
deja su evento).
"""
import logging
import smtplib
import threading
from dataclasses import dataclass
from email.message import EmailMessage

registro = logging.getLogger("canario.correo")

HOST = "mailpit"
PUERTO = 1025
# Segundos para conectar y para cada respuesta del servidor: un SMTP colgado
# no retiene para siempre un hilo del pool.
PLAZO = 5
CORREOS_SIMULTANEOS = 4
# .invalid está reservado (RFC 2606 y RFC 6761): nadie puede responder a
# este remitente ni suplantar un dominio real con él.
REMITENTE = "Canario <no-responder@canario.invalid>"

TIPOS = ("verificacion", "aviso_cuenta", "aviso_pendiente", "invitacion")

_semaforo = threading.BoundedSemaphore(CORREOS_SIMULTANEOS)


@dataclass(frozen=True)
class Correo:
    tipo: str
    destinatario: str
    asunto: str
    cuerpo: str


def componer(correo):
    """EmailMessage del correo. ValueError si una cabecera lleva CR o LF o el
    tipo no es uno de TIPOS."""
    if correo.tipo not in TIPOS:
        raise ValueError("tipo de correo desconocido")
    mensaje = EmailMessage()
    mensaje["From"] = REMITENTE
    mensaje["To"] = correo.destinatario
    mensaje["Subject"] = correo.asunto
    mensaje.set_content(correo.cuerpo)
    return mensaje


def enviar(correo):
    """Envía el correo. Pensada para una BackgroundTask: nunca lanza; un
    fallo queda en el log (ver la cabecera)."""
    tipo = correo.tipo if correo.tipo in TIPOS else "desconocido"
    if not _semaforo.acquire(blocking=False):
        registro.error("EVENTO correo_descartado: tipo=%s motivo=envios_simultaneos", tipo)
        return
    try:
        mensaje = componer(correo)
        with smtplib.SMTP(HOST, PUERTO, timeout=PLAZO) as servidor:
            servidor.send_message(mensaje)
    # Exception y no una lista cerrada: tras responder, cualquier excepción
    # solo llegaría a uvicorn, que volcaría el traceback (con el texto del
    # error, que en smtplib puede incluir el destinatario). Aquí queda solo
    # el tipo y la clase.
    except Exception as error:  # noqa: BLE001 - tras responder, el log es el único destino del error
        registro.error("EVENTO correo_fallido: tipo=%s error=%s", tipo, type(error).__name__)
    finally:
        _semaforo.release()
