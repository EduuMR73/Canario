"""Pruebas unitarias del correo saliente de la API (app/correo.py): lo que
le pasa al cartero, fallos que quedan en el log sin datos personales y tope
de envíos simultáneos.

El cartero se sustituye por un doble (unittest.mock): aquí no hay red. La
composición y la entrega las prueban tests/unit/test_cartero.py y, de
extremo a extremo con Mailpit, tests/security/verificar_registro.py.
"""
import json
import unittest
from unittest import mock

from app import correo

EMAIL = "persona@empresa.es"


def un_correo(destinatario=EMAIL, tipo="verificacion"):
    return correo.Correo(tipo=tipo, destinatario=destinatario, asunto="Asunto",
                         cuerpo="Enlace: https://localhost:8445/registro/verificacion#secreto")


class Enviar(unittest.TestCase):
    def test_envio(self):
        with mock.patch.object(correo, "_publicar", return_value=202) as publicar, \
                self.assertNoLogs("canario.correo"):
            correo.enviar(un_correo())
        publicar.assert_called_once()
        enviado = json.loads(publicar.call_args.args[0])
        # Solo estos cuatro campos: el remitente y las cabeceras los pone el
        # cartero, no la API.
        self.assertEqual(enviado, {"tipo": "verificacion", "destinatario": EMAIL, "asunto": "Asunto",
                                   "cuerpo": "Enlace: https://localhost:8445/registro/verificacion#secreto"})

    def test_destino_fijo(self):
        # El cartero en la red interna correo, nunca otro sitio.
        self.assertEqual((correo.HOST, correo.PUERTO, correo.PLAZO), ("cartero", 8000, 5))

    def test_fallo_al_log_sin_datos(self):
        error = OSError(f"conexion rechazada para {EMAIL}")
        with mock.patch.object(correo, "_publicar", side_effect=error), \
                self.assertLogs("canario.correo", "ERROR") as registro:
            correo.enviar(un_correo())
        self.assertEqual(registro.output, ["ERROR:canario.correo:EVENTO correo_fallido: tipo=verificacion error=OSError"])
        # El texto del error lleva el email (control): el log no.
        self.assertIn(EMAIL, str(error))
        self.assertNotIn(EMAIL, "\n".join(registro.output))
        self.assertNotIn("secreto", "\n".join(registro.output))

    def test_respuestas_del_cartero(self):
        # 429 y 503 son descartes del cartero; cualquier otro estado, un fallo.
        casos = {
            429: "ERROR:canario.correo:EVENTO correo_descartado: tipo=invitacion motivo=cupo_diario",
            503: "ERROR:canario.correo:EVENTO correo_descartado: tipo=invitacion motivo=cola_llena",
            422: "ERROR:canario.correo:EVENTO correo_fallido: tipo=invitacion error=estado_422",
            403: "ERROR:canario.correo:EVENTO correo_fallido: tipo=invitacion error=estado_403",
            200: "ERROR:canario.correo:EVENTO correo_fallido: tipo=invitacion error=estado_200",
        }
        for estado, esperado in casos.items():
            with self.subTest(estado=estado), mock.patch.object(correo, "_publicar", return_value=estado), \
                    self.assertLogs("canario.correo", "ERROR") as registro:
                correo.enviar(un_correo(tipo="invitacion"))
            self.assertEqual(registro.output, [esperado])

    def test_tipo_desconocido_no_sale(self):
        with mock.patch.object(correo, "_publicar") as publicar, \
                self.assertLogs("canario.correo", "ERROR") as registro:
            correo.enviar(un_correo(tipo="otro"))
        publicar.assert_not_called()
        self.assertEqual(registro.output, ["ERROR:canario.correo:EVENTO correo_fallido: tipo=desconocido error=ValueError"])

    def test_enviar_todos_sigue_tras_un_fallo(self):
        # Un aviso a varias personas: el fallo con una no deja sin aviso a las demás.
        enviados = []

        def publicar(cuerpo):
            destinatario = json.loads(cuerpo)["destinatario"]
            if destinatario == "falla@empresa.es":
                raise OSError
            enviados.append(destinatario)
            return 202

        destinos = ("a@empresa.es", "falla@empresa.es", "b@empresa.es")
        with mock.patch.object(correo, "_publicar", side_effect=publicar), \
                self.assertLogs("canario.correo", "ERROR") as registro:
            correo.enviar_todos([un_correo(d, "aviso_lecturas") for d in destinos])
        self.assertEqual(enviados, ["a@empresa.es", "b@empresa.es"])
        self.assertEqual(registro.output, ["ERROR:canario.correo:EVENTO correo_fallido: tipo=aviso_lecturas error=OSError"])

    def test_sin_hueco_se_descarta_sin_esperar(self):
        ocupados = 0
        try:
            while correo._semaforo.acquire(blocking=False):
                ocupados += 1
            self.assertEqual(ocupados, 4)
            with mock.patch.object(correo, "_publicar") as publicar, \
                    self.assertLogs("canario.correo", "ERROR") as registro:
                correo.enviar(un_correo(tipo="invitacion"))
            publicar.assert_not_called()
            self.assertEqual(registro.output, [
                "ERROR:canario.correo:EVENTO correo_descartado: tipo=invitacion motivo=envios_simultaneos"])
        finally:
            for _ in range(ocupados):
                correo._semaforo.release()
        # Control: con huecos libres se envía, y los huecos quedan libres
        # también tras un fallo.
        with mock.patch.object(correo, "_publicar", side_effect=OSError), self.assertLogs("canario.correo", "ERROR"):
            correo.enviar(un_correo())
        with mock.patch.object(correo, "_publicar", return_value=202) as publicar:
            correo.enviar(un_correo())
        publicar.assert_called_once()
        libres = [correo._semaforo.acquire(blocking=False) for _ in range(4)]
        for _ in range(sum(libres)):
            correo._semaforo.release()
        self.assertEqual(libres, [True] * 4)
