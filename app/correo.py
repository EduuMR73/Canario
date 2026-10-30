"""Correo saliente del personal (docs/threat-model.md, 6.3 y 6.15).

Lo envía app/solicitudes.py: el enlace de verificación de una solicitud, los
avisos al titular de un email y la invitación de una solicitud aprobada. Y
app/rutas_personal.py, los avisos de seguridad de app/avisos.py (lecturas,
activaciones y vínculos) a los admins y auditores.

Es el adaptador de salida de la API hacia el cartero (app/cartero.py), como
app/cliente_broker.py lo es hacia el broker: la API no habla SMTP, no tiene
credenciales de correo ni salida a internet. Le pasa cada correo al cartero
por la red interna correo, y él lo compone, lo pone en su cola y lo entrega.

Por qué así:
* Se envía DESPUÉS de responder (BackgroundTask de Starlette: en la versión
  fijada, Response.__call__ envía el cuerpo y solo después espera a la
  tarea). El tiempo de la respuesta no depende de si hubo correo, de a quién
  ni de lo que tarde el cartero: no es un canal para saber si un email tiene
  cuenta.
* La tarea en segundo plano de una función síncrona ocupa un hilo del pool
  de la API, el mismo que usan todas las rutas síncronas (starlette 1.7.0,
  background.py: run_in_threadpool). El cartero responde en el acto (solo
  encola), pero si se colgara retendría un hilo por correo hasta PLAZO
  segundos. Por eso hay como mucho CORREOS_SIMULTANEOS envíos a la vez, y si
  no hay hueco el correo se descarta al momento (EVENTO correo_descartado)
  en vez de esperar.
* Un fallo no tiene a quién devolverse (la respuesta ya salió), así que se
  registra: EVENTO correo_fallido o correo_descartado con el tipo de correo
  y un motivo fijo, nunca el email, el enlace ni el token. Nada se traga en
  silencio. Lo que pase después de encolarlo (entregado, aplazado o fallido)
  queda en el log del cartero.
* El token solo va en el fragmento del enlace (#...): el navegador no lo
  envía al servidor, así que no queda en logs, en Referer ni en proxies. La
  página lo manda por POST (app/solicitudes.py). Para que tampoco lo vea el
  proveedor de correo más allá de entregarlo, el cartero desactiva su
  seguimiento de enlaces.
"""
import http.client
import json
import logging
import threading
from dataclasses import dataclass

registro = logging.getLogger("canario.correo")

# El cartero en la red correo (docker-compose.yml): solo atiende a la IP fija
# de la API en esa red.
HOST = "cartero"
PUERTO = 8000
# Segundos para conectar y para la respuesta: un cartero colgado no retiene
# para siempre un hilo del pool.
PLAZO = 5
CORREOS_SIMULTANEOS = 4

TIPOS = ("verificacion", "aviso_cuenta", "aviso_pendiente", "invitacion", "aviso_lecturas", "aviso_activacion",
         "aviso_vinculo")

# Respuesta del cartero -> motivo del evento. 429 y 503 son descartes que el
# cartero ya decidió (cupo del día, cola llena); el resto, un fallo.
DESCARTES = {429: "cupo_diario", 503: "cola_llena"}

_semaforo = threading.BoundedSemaphore(CORREOS_SIMULTANEOS)


@dataclass(frozen=True)
class Correo:
    tipo: str
    destinatario: str
    asunto: str
    cuerpo: str


def _publicar(cuerpo):
    """Código de estado de POST /correos al cartero. OSError o HTTPException
    si no se puede hablar con él."""
    conexion = http.client.HTTPConnection(HOST, PUERTO, timeout=PLAZO)
    try:
        conexion.request("POST", "/correos", body=cuerpo,
                         headers={"Content-Type": "application/json", "Accept": "application/json"})
        respuesta = conexion.getresponse()
        # El cuerpo no se usa: el estado dice todo. Se lee acotado para
        # cerrar bien la conexión.
        respuesta.read(1024)
        return respuesta.status
    finally:
        conexion.close()


def enviar(correo):
    """Pasa el correo al cartero. Pensada para una BackgroundTask: nunca
    lanza; un fallo queda en el log (ver la cabecera)."""
    tipo = correo.tipo if correo.tipo in TIPOS else "desconocido"
    if not _semaforo.acquire(blocking=False):
        registro.error("EVENTO correo_descartado: tipo=%s motivo=envios_simultaneos", tipo)
        return
    try:
        if tipo == "desconocido":
            raise ValueError("tipo de correo desconocido")
        cuerpo = json.dumps({"tipo": correo.tipo, "destinatario": correo.destinatario, "asunto": correo.asunto,
                             "cuerpo": correo.cuerpo}, ensure_ascii=True).encode("ascii")
        estado = _publicar(cuerpo)
        if estado in DESCARTES:
            registro.error("EVENTO correo_descartado: tipo=%s motivo=%s", tipo, DESCARTES[estado])
        elif estado != 202:
            registro.error("EVENTO correo_fallido: tipo=%s error=estado_%d", tipo, estado)
    # Exception y no una lista cerrada: tras responder, cualquier excepción
    # solo llegaría a uvicorn, que volcaría el traceback (con el texto del
    # error). Aquí queda solo el tipo y la clase.
    except Exception as error:  # noqa: BLE001 - tras responder, el log es el único destino del error
        registro.error("EVENTO correo_fallido: tipo=%s error=%s", tipo, type(error).__name__)
    finally:
        _semaforo.release()


def enviar_todos(correos):
    """Envía varios correos uno detrás de otro, en la misma tarea: un aviso
    a varias personas ocupa un solo hilo del pool. Cada uno pasa por enviar,
    con su hueco y su evento si falla: un fallo no impide los siguientes."""
    for uno in correos:
        enviar(uno)
