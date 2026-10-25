"""Pruebas unitarias de app/cliente_broker.py: cómo trata cada respuesta del
broker, el tope de peticiones simultáneas y el plazo total.

Casi todas sustituyen el envío por una función de la prueba. La del plazo
usa un servidor de verdad en 127.0.0.1 (el contenedor de las pruebas no
tiene red, pero sí loopback) que responde un byte cada cierto tiempo: es el
caso que el plazo por operación no corta.
"""
import json
import socket
import threading
import time
import unittest
from unittest import mock

from app import cliente_broker

URL = ("https://accounts.google.com/o/oauth2/v2/auth?client_id=123-prueba.apps.googleusercontent.com"
       "&response_type=code&scope=openid")
SUB = "109876543210987654321"
CODE = "4/0AbCdEf-prueba"
VALOR = "v" * 43


def responde(estado, cuerpo, llamadas=None):
    """Envío falso que devuelve (estado, cuerpo) y apunta lo que recibe."""
    def enviar(metodo, ruta, datos):
        if llamadas is not None:
            llamadas.append((metodo, ruta, None if datos is None else json.loads(datos)))
        return estado, cuerpo if isinstance(cuerpo, bytes) else json.dumps(cuerpo).encode()
    return enviar


class Proveedores(unittest.TestCase):
    def test_valido(self):
        llamadas = []
        self.assertEqual(cliente_broker.proveedores(responde(200, {"proveedores": ["google"]}, llamadas)), ("google",))
        self.assertEqual(llamadas, [("GET", "/proveedores", None)])
        self.assertEqual(cliente_broker.proveedores(responde(200, {"proveedores": []})), ())

    def test_forma_no_valida(self):
        for cuerpo in ({"proveedores": ["google", "otro"]}, {"proveedores": "google"}, {"proveedores": [1]},
                       {"proveedores": ["google"], "mas": 1}, {}, ["google"]):
            with self.subTest(cuerpo=cuerpo):
                with self.assertRaises(cliente_broker.BrokerNoDisponible), self.assertLogs("canario.cliente_broker"):
                    cliente_broker.proveedores(responde(200, cuerpo))


class Autorizar(unittest.TestCase):
    def test_valido_y_lo_que_envia(self):
        llamadas = []
        url = cliente_broker.autorizar("google", "s" * 43, "c" * 43, "n" * 43, responde(200, {"url": URL}, llamadas))
        self.assertEqual(url, URL)
        self.assertEqual(llamadas, [("POST", "/autorizar", {
            "proveedor": "google", "state": "s" * 43, "code_challenge": "c" * 43, "nonce": "n" * 43})])

    def test_url_que_no_es_la_del_proveedor(self):
        # Un broker comprometido no puede mandar al navegador a otro sitio.
        for url in ("https://accounts.google.com.evil.example/o/oauth2/v2/auth?x=1",
                    "https://accounts.google.com/o/oauth2/v2/auth@evil.example/?x=1",
                    "https://accounts.google.com/o/oauth2/v2/authx?x=1",
                    "http://accounts.google.com/o/oauth2/v2/auth?x=1",
                    "https://accounts.google.com/o/oauth2/v2/auth?x=1\r\nSet-Cookie: a=b",
                    "https://accounts.google.com/o/oauth2/v2/auth?" + "x" * 2048,
                    "javascript:alert(1)"):
            with self.subTest(url=url):
                with self.assertRaises(cliente_broker.BrokerNoDisponible), self.assertLogs("canario.cliente_broker"):
                    cliente_broker.autorizar("google", VALOR, VALOR, VALOR, responde(200, {"url": url}))
        self.assertEqual(cliente_broker.autorizar("google", VALOR, VALOR, VALOR, responde(200, {"url": URL})),
                         URL)  # control

    def test_no_configurado(self):
        with self.assertRaises(cliente_broker.NoConfigurado):
            cliente_broker.autorizar("google", VALOR, VALOR, VALOR, responde(404, {"detalle": "proveedor no configurado"}))


class Canjear(unittest.TestCase):
    def test_valido_y_lo_que_envia(self):
        llamadas = []
        sub = cliente_broker.canjear("google", CODE, VALOR, VALOR,
                                     responde(200, {"proveedor": "google", "sub": SUB}, llamadas))
        self.assertEqual(sub, SUB)
        self.assertEqual(llamadas, [("POST", "/canjear", {
            "proveedor": "google", "code": CODE, "verifier": VALOR, "nonce": VALOR})])

    def test_cada_estado_su_error(self):
        casos = {401: cliente_broker.CanjeRechazado, 404: cliente_broker.NoConfigurado,
                 422: cliente_broker.BrokerNoDisponible, 403: cliente_broker.BrokerNoDisponible,
                 503: cliente_broker.BrokerNoDisponible, 500: cliente_broker.BrokerNoDisponible,
                 302: cliente_broker.BrokerNoDisponible}
        for estado, excepcion in casos.items():
            with self.subTest(estado=estado):
                with self.assertRaises(excepcion):
                    if excepcion is cliente_broker.BrokerNoDisponible:
                        # Un broker que no responde como debe deja su evento.
                        with self.assertLogs("canario.cliente_broker", "WARNING"):
                            cliente_broker.canjear("google", CODE, VALOR, VALOR, responde(estado, {"detalle": "x"}))
                    else:
                        cliente_broker.canjear("google", CODE, VALOR, VALOR, responde(estado, {"detalle": "x"}))

    def test_forma_no_valida(self):
        for cuerpo in ({"proveedor": "github", "sub": SUB}, {"proveedor": "google", "sub": "con espacio"},
                       {"proveedor": "google", "sub": "x" * 256}, {"proveedor": "google", "sub": 123},
                       {"proveedor": "google"}, {"proveedor": "google", "sub": SUB, "email": "a@b.c"},
                       b"no es json", b"[" * 100_000):
            with self.subTest(cuerpo=str(cuerpo)[:40]):
                with self.assertRaises(cliente_broker.BrokerNoDisponible), self.assertLogs("canario.cliente_broker"):
                    cliente_broker.canjear("google", CODE, VALOR, VALOR, responde(200, cuerpo))

    def test_el_log_no_lleva_valores(self):
        with self.assertRaises(cliente_broker.BrokerNoDisponible), \
                self.assertLogs("canario.cliente_broker", "WARNING") as registro:
            cliente_broker.canjear("google", CODE, VALOR, VALOR,
                                   responde(200, {"proveedor": "google", "sub": SUB + " x"}))
        self.assertEqual(registro.output,
                         ["WARNING:canario.cliente_broker:EVENTO broker_no_disponible: operacion=canjear motivo=forma"])


class Simultaneas(unittest.TestCase):
    def test_sin_hueco_falla_en_el_acto_sin_enviar(self):
        llamadas = []
        ocupados = 0
        try:
            for _ in range(cliente_broker.SIMULTANEAS):
                self.assertTrue(cliente_broker._semaforo.acquire(blocking=False))
                ocupados += 1
            inicio = time.monotonic()
            with self.assertRaises(cliente_broker.BrokerNoDisponible) as error, \
                    self.assertLogs("canario.cliente_broker", "WARNING"):
                cliente_broker.canjear("google", CODE, VALOR, VALOR,
                                       responde(200, {"proveedor": "google", "sub": SUB}, llamadas))
            self.assertLess(time.monotonic() - inicio, 0.5)
            self.assertEqual(error.exception.motivo, "saturado")
            self.assertEqual(llamadas, [])
        finally:
            for _ in range(ocupados):
                cliente_broker._semaforo.release()
        # Control: con hueco, la misma llamada llega al broker.
        self.assertEqual(cliente_broker.canjear("google", CODE, VALOR, VALOR,
                                                responde(200, {"proveedor": "google", "sub": SUB}, llamadas)), SUB)
        self.assertEqual(len(llamadas), 1)

    def test_el_hueco_se_devuelve_tras_un_error(self):
        for _ in range(cliente_broker.SIMULTANEAS + 2):
            with self.assertRaises(cliente_broker.CanjeRechazado):
                cliente_broker.canjear("google", CODE, VALOR, VALOR, responde(401, {"detalle": "canje fallido"}))
        self.assertEqual(cliente_broker.canjear("google", CODE, VALOR, VALOR,
                                                responde(200, {"proveedor": "google", "sub": SUB})), SUB)


class Servidor:
    """Servidor HTTP mínimo en 127.0.0.1: envía la respuesta byte a byte con
    una pausa entre bytes."""

    def __init__(self, respuesta, pausa):
        self.respuesta, self.pausa = respuesta, pausa
        self.escucha = socket.create_server(("127.0.0.1", 0))
        self.puerto = self.escucha.getsockname()[1]
        self.hilo = threading.Thread(target=self._atender, daemon=True)
        self.hilo.start()

    def _atender(self):
        try:
            conexion, _ = self.escucha.accept()
        except OSError:
            return
        with conexion:
            conexion.recv(65536)
            try:
                for byte in self.respuesta:
                    conexion.sendall(bytes([byte]))
                    time.sleep(self.pausa)
            except OSError:
                pass

    def cerrar(self):
        self.escucha.close()
        self.hilo.join(5)


class PlazoTotal(unittest.TestCase):
    CUERPO = b'{"proveedores":["google"]}'
    RESPUESTA = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 26\r\n"
                 b"Connection: close\r\n\r\n" + CUERPO)

    def pedir(self, pausa):
        servidor = Servidor(self.RESPUESTA, pausa)
        try:
            with mock.patch.object(cliente_broker, "HOST", "127.0.0.1"), \
                    mock.patch.object(cliente_broker, "PUERTO", servidor.puerto), \
                    mock.patch.object(cliente_broker, "PLAZO_TOTAL_SEGUNDOS", 1):
                inicio = time.monotonic()
                try:
                    return cliente_broker._enviar("GET", "/proveedores", None), time.monotonic() - inicio
                except cliente_broker.BrokerNoDisponible as error:
                    return error.motivo, time.monotonic() - inicio
        finally:
            servidor.cerrar()

    def test_un_byte_cada_poco_se_corta_en_el_plazo_total(self):
        # Control: rápido, la respuesta llega entera.
        self.assertEqual(len(self.CUERPO), 26)
        (estado, cuerpo), _ = self.pedir(0)
        self.assertEqual((estado, cuerpo), (200, self.CUERPO))
        # Cada byte llega antes del plazo de conexión (2 s), pero la respuesta
        # entera tardaría más de 10 s: el vigilante la corta al segundo.
        motivo, segundos = self.pedir(0.1)
        self.assertEqual(motivo, "plazo")
        self.assertLess(segundos, 3)


if __name__ == "__main__":
    unittest.main()
