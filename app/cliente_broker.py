"""Cliente del broker de canje (app/broker.py, docs/threat-model.md, 6.19).

El adaptador de salida de la API hacia el broker, como app/correo.py lo es
hacia el SMTP: es la única pieza de la API que le habla, por la red interna
canje. La lógica (app/externo.py, app/personal.py) no sabe que hay HTTP
detrás.

Por qué así:
* La API no tiene salida a internet (6.11): todo lo que necesita del
  proveedor lo pide aquí. El broker solo atiende a la IP fija de la API.
* Un broker lento o colgado no retiene hilos del pool sin límite: como
  mucho SIMULTANEAS peticiones a la vez (la siguiente es BrokerNoDisponible
  en el acto, sin esperar), y cada una con un plazo total que corta la
  conexión en cualquier fase, como app/proveedores_externos.py (publicar):
  el plazo por operación no basta contra quien envía un byte cada pocos
  segundos. El plazo total cubre el del broker con Google (10 s) y algo
  más, para que el 503 del broker llegue antes que el corte.
* Lo que devuelve el broker se valida antes de usarlo, aunque sea nuestro:
  un broker comprometido no puede mandar al navegador a otro sitio (la URL
  tiene que empezar por el endpoint de autorización del proveedor) ni colar
  un sub que no tenga la forma de uno.

Errores: CanjeRechazado (el proveedor no acepta el code: el broker responde
401), NoConfigurado (el proveedor no está configurado en el broker: 404) y
BrokerNoDisponible (red, plazo, saturación, cualquier otra respuesta o una
que no tiene la forma esperada). Este último deja EVENTO
broker_no_disponible con la operación y un motivo fijo, nunca un valor.
"""
import http.client
import json
import logging
import re
import socket
import threading

from app import proveedores_externos

registro = logging.getLogger("canario.cliente_broker")

HOST = "broker"
PUERTO = 8000
PLAZO_CONEXION_SEGUNDOS = 2
PLAZO_TOTAL_SEGUNDOS = proveedores_externos.PLAZO_TOTAL_SEGUNDOS + 2
# Las respuestas del broker son unos cientos de bytes (la URL de
# autorización es la más larga).
TAMANO_MAXIMO_RESPUESTA = 8192
TROZO_LECTURA = 2048
# Las mismas que canjes admite el broker a la vez (app/broker.py,
# CANJES_SIMULTANEOS): más no servirían de nada.
SIMULTANEAS = 4

# Endpoint de autorización de cada proveedor, literal: la URL que devuelve el
# broker tiene que empezar exactamente por él y su "?".
ENDPOINTS_AUTORIZACION = {proveedores_externos.PROVEEDOR_GOOGLE: proveedores_externos.URL_AUTORIZACION_GOOGLE}
# La URL de autorización: ASCII imprimible sin espacios y con un tope.
PATRON_URL = re.compile(r"[\x21-\x7e]{1,2048}")

_semaforo = threading.BoundedSemaphore(SIMULTANEAS)


class BrokerNoDisponible(Exception):
    def __init__(self, motivo):
        super().__init__(motivo)
        self.motivo = motivo


class CanjeRechazado(Exception):
    """El proveedor no acepta el code (o el broker no le reconoce el canje)."""


class NoConfigurado(Exception):
    """El proveedor no está configurado en el broker."""


def _cortar(conexion, cortada):
    cortada.set()
    sock = conexion.sock
    if sock is not None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


def _enviar(metodo, ruta, cuerpo):
    """(estado, cuerpo) de una petición al broker, o BrokerNoDisponible."""
    conexion = http.client.HTTPConnection(HOST, PUERTO, timeout=PLAZO_CONEXION_SEGUNDOS)
    cortada = threading.Event()
    vigilante = threading.Timer(PLAZO_TOTAL_SEGUNDOS, _cortar, args=(conexion, cortada))
    vigilante.start()
    try:
        cabeceras = {"Accept": "application/json"}
        if cuerpo is not None:
            cabeceras["Content-Type"] = "application/json"
        conexion.request(metodo, ruta, body=cuerpo, headers=cabeceras)
        respuesta = conexion.getresponse()
        leido = b""
        while len(leido) <= TAMANO_MAXIMO_RESPUESTA:
            trozo = respuesta.read1(TROZO_LECTURA)
            if not trozo:
                break
            leido += trozo
        if cortada.is_set():
            raise BrokerNoDisponible("plazo")
        if len(leido) > TAMANO_MAXIMO_RESPUESTA:
            raise BrokerNoDisponible("respuesta_grande")
        return respuesta.status, leido
    except (OSError, http.client.HTTPException):
        raise BrokerNoDisponible("plazo" if cortada.is_set() else "red") from None
    finally:
        vigilante.cancel()
        conexion.close()


def _pedir(operacion, metodo, ruta, datos, enviar):
    """Cuerpo JSON (un dict) de una respuesta 200 del broker. Traduce el
    resto a las excepciones del módulo."""
    if not _semaforo.acquire(blocking=False):
        registro.warning("EVENTO broker_no_disponible: operacion=%s motivo=saturado", operacion)
        raise BrokerNoDisponible("saturado")
    try:
        cuerpo = None if datos is None else json.dumps(datos, separators=(",", ":")).encode("ascii")
        estado, leido = enviar(metodo, ruta, cuerpo)
        if estado == 401:
            raise CanjeRechazado
        if estado == 404:
            raise NoConfigurado
        if estado != 200:
            raise BrokerNoDisponible("estado")
        try:
            respuesta = json.loads(leido)
        except (ValueError, RecursionError):
            raise BrokerNoDisponible("json") from None
        if not isinstance(respuesta, dict):
            raise BrokerNoDisponible("json")
        return respuesta
    except BrokerNoDisponible as error:
        registro.warning("EVENTO broker_no_disponible: operacion=%s motivo=%s", operacion, error.motivo)
        raise
    finally:
        _semaforo.release()


def _fallo_de_forma(operacion):
    registro.warning("EVENTO broker_no_disponible: operacion=%s motivo=forma", operacion)
    return BrokerNoDisponible("forma")


def proveedores(enviar=_enviar):
    """Proveedores configurados en el broker, ordenados. Un nombre que la API
    no conoce es un broker que no responde como debe."""
    respuesta = _pedir("proveedores", "GET", "/proveedores", None, enviar)
    lista = respuesta.get("proveedores")
    if (set(respuesta) != {"proveedores"} or not isinstance(lista, list)
            or not all(isinstance(p, str) and p in ENDPOINTS_AUTORIZACION for p in lista)):
        raise _fallo_de_forma("proveedores")
    return tuple(sorted(set(lista)))


def autorizar(proveedor, state, code_challenge, nonce, enviar=_enviar):
    """URL de autorización del proveedor para este flujo."""
    respuesta = _pedir("autorizar", "POST", "/autorizar", {
        "proveedor": proveedor, "state": state, "code_challenge": code_challenge, "nonce": nonce}, enviar)
    url = respuesta.get("url")
    if (set(respuesta) != {"url"} or not isinstance(url, str) or not PATRON_URL.fullmatch(url)
            or not url.startswith(ENDPOINTS_AUTORIZACION[proveedor] + "?")):
        raise _fallo_de_forma("autorizar")
    return url


def canjear(proveedor, code, verifier, nonce, enviar=_enviar):
    """sub de la cuenta del proveedor que autorizó el code."""
    respuesta = _pedir("canjear", "POST", "/canjear", {
        "proveedor": proveedor, "code": code, "verifier": verifier, "nonce": nonce}, enviar)
    sub = respuesta.get("sub")
    if (set(respuesta) != {"proveedor", "sub"} or respuesta.get("proveedor") != proveedor
            or not isinstance(sub, str) or not proveedores_externos.PATRON_SUB.fullmatch(sub)):
        raise _fallo_de_forma("canjear")
    return sub
