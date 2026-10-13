"""Pruebas unitarias de app/frontera_http.py: el cuerpo de error uniforme, el
límite de tamaño del cuerpo y el 500 que no filtra el mensaje del error.

Los middlewares ASGI se prueban con un receive y un send falsos (sin red ni
servidor): el send guarda lo que se enviaría y la aplicación interior anota
si se le ha llamado y con qué cuerpo.
"""
import unittest

from psycopg import errors as errores_bd

from app import frontera_http

MAXIMO = 10
# Literales: no se leen de frontera_http.MENSAJES, que es lo que se prueba.
DETALLES = {400: "petición no válida", 413: "cuerpo de la petición demasiado grande"}


def peticion_http(cabeceras=()):
    return {"type": "http", "headers": list(cabeceras)}


def receptor(*trozos, desconectar=False):
    """receive() que entrega los trozos en orden, el último sin more_body."""
    mensajes = [{"type": "http.request", "body": t, "more_body": i < len(trozos) - 1} for i, t in enumerate(trozos)]
    if desconectar:
        mensajes = [{"type": "http.disconnect"}]
    llamadas = {"n": 0}

    async def receive():
        llamadas["n"] += 1
        return mensajes.pop(0)
    return receive, llamadas


class Destino:
    """Aplicación interior: lee el cuerpo como lo haría Starlette y responde 200."""

    def __init__(self):
        self.llamada = False
        self.cuerpo = None

    async def __call__(self, scope, receive, send):
        self.llamada = True
        mensaje = await receive()
        self.cuerpo = mensaje["body"]
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


def emisor():
    enviados = []

    async def send(mensaje):
        enviados.append(mensaje)
    return send, enviados


class CuerpoDeError(unittest.TestCase):
    def test_literales(self):
        self.assertEqual(frontera_http.cuerpo_error(404), b'{"detalle": "recurso no encontrado"}')
        self.assertEqual(frontera_http.cuerpo_error(413),
                         '{"detalle": "cuerpo de la petición demasiado grande"}'.encode())
        self.assertEqual(frontera_http.cuerpo_error(418), b'{"detalle": "error"}')
        self.assertEqual(frontera_http.cuerpo_error(409, "otro"), b'{"detalle": "otro"}')
        # Un mensaje vacío no deja el detalle vacío.
        self.assertEqual(frontera_http.cuerpo_error(400, ""), '{"detalle": "petición no válida"}'.encode())


class DescribirError(unittest.TestCase):
    def test_nunca_el_mensaje(self):
        self.assertEqual(frontera_http.describir_error(ValueError("dato secreto de la fila")), "ValueError")
        self.assertEqual(frontera_http.describir_error(errores_bd.UniqueViolation("dato secreto de la fila")),
                         "UniqueViolation 23505")


class LimiteDelCuerpo(unittest.IsolatedAsyncioTestCase):
    async def ejecutar(self, cabeceras, *trozos, desconectar=False):
        destino = Destino()
        receive, llamadas = receptor(*trozos, desconectar=desconectar)
        send, enviados = emisor()
        await frontera_http.LimiteCuerpo(destino, maximo=MAXIMO)(peticion_http(cabeceras), receive, send)
        return destino, llamadas, enviados

    def assertRespuesta(self, enviados, codigo, cabeceras_extra=()):
        esperado_cuerpo = ('{"detalle": "' + DETALLES[codigo] + '"}').encode()
        self.assertEqual(enviados, [
            {"type": "http.response.start", "status": codigo,
             "headers": [(b"content-type", b"application/json"),
                         (b"content-length", str(len(esperado_cuerpo)).encode()), *cabeceras_extra]},
            {"type": "http.response.body", "body": esperado_cuerpo},
        ])

    async def test_justo_en_el_limite_pasa_entero(self):
        destino, _, enviados = await self.ejecutar([(b"content-length", b"10")], b"12345", b"67890")
        self.assertTrue(destino.llamada)
        self.assertEqual(destino.cuerpo, b"1234567890")
        self.assertEqual(enviados[0]["status"], 200)

    async def test_cabecera_mayor_que_el_limite_sin_leer(self):
        destino, llamadas, enviados = await self.ejecutar([(b"content-length", b"11")], b"x")
        self.assertFalse(destino.llamada)
        self.assertEqual(llamadas["n"], 0)
        self.assertRespuesta(enviados, 413, [(b"connection", b"close")])

    async def test_cabecera_que_miente_cuenta_lo_real(self):
        destino, _, enviados = await self.ejecutar([(b"content-length", b"5")], b"123456", b"78901")
        self.assertFalse(destino.llamada)
        self.assertRespuesta(enviados, 413, [(b"connection", b"close")])

    async def test_sin_cabecera_por_trozos(self):
        destino, _, enviados = await self.ejecutar([], b"123456", b"78901")
        self.assertFalse(destino.llamada)
        self.assertRespuesta(enviados, 413, [(b"connection", b"close")])
        destino, _, _ = await self.ejecutar([], b"12345", b"67890")  # control
        self.assertEqual(destino.cuerpo, b"1234567890")

    async def test_cabecera_no_numerica(self):
        for valor in (b"abc", b"-1", b"1.5", b"", b" 5"):
            with self.subTest(valor=valor):
                destino, llamadas, enviados = await self.ejecutar([(b"content-length", valor)], b"x")
                self.assertFalse(destino.llamada)
                self.assertEqual(llamadas["n"], 0)
                self.assertRespuesta(enviados, 400)

    async def test_desconexion_sin_respuesta(self):
        destino, _, enviados = await self.ejecutar([], desconectar=True)
        self.assertFalse(destino.llamada)
        self.assertEqual(enviados, [])


class ErroresInternos(unittest.IsolatedAsyncioTestCase):
    async def test_500_generico_y_log_sin_el_mensaje(self):
        async def falla(scope, receive, send):
            raise ValueError("dato secreto de la fila")

        send, enviados = emisor()
        with self.assertLogs("canario.api", "ERROR") as registro:
            await frontera_http.ErroresInternos(falla)(peticion_http(), None, send)
        self.assertEqual(registro.output, ["ERROR:canario.api:ERROR INTERNO: ValueError"])
        self.assertEqual(enviados[0]["status"], 500)
        self.assertEqual(enviados[1]["body"], b'{"detalle": "error interno"}')
        self.assertNotIn("secreto", repr(enviados))

    async def test_respuesta_ya_empezada_no_envia_otra(self):
        async def falla_a_medias(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            raise ValueError("x")

        send, enviados = emisor()
        with self.assertLogs("canario.api", "ERROR"):
            await frontera_http.ErroresInternos(falla_a_medias)(peticion_http(), None, send)
        self.assertEqual([m["type"] for m in enviados], ["http.response.start"])
        self.assertEqual(enviados[0]["status"], 200)
