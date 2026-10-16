"""Pruebas unitarias del correo saliente (app/correo.py): composición sin
inyección de cabeceras, fallos que quedan en el log sin datos personales y
tope de envíos simultáneos.

El servidor SMTP se sustituye por un doble (unittest.mock): aquí no hay red.
El envío real a Mailpit lo prueba tests/security/verificar_registro.py.
"""
import smtplib
import unittest
from unittest import mock

from app import correo

EMAIL = "persona@empresa.es"


def un_correo(destinatario=EMAIL, tipo="verificacion"):
    return correo.Correo(tipo=tipo, destinatario=destinatario, asunto="Asunto",
                         cuerpo="Enlace: https://localhost:8445/registro/verificacion#secreto")


class Componer(unittest.TestCase):
    def test_valido(self):
        mensaje = correo.componer(un_correo())
        self.assertEqual(mensaje["To"], EMAIL)
        self.assertEqual(mensaje["From"], "Canario <no-responder@canario.invalid>")
        self.assertEqual(mensaje["Subject"], "Asunto")
        self.assertIn("#secreto", mensaje.get_content())

    def test_cabeceras_sin_cr_ni_lf(self):
        # CWE-93: un salto de línea en el destinatario añadiría una cabecera
        # (un Bcc). Control: el mismo email sin salto pasa (test_valido).
        for malo in (EMAIL + "\r\nBcc: otro@x.es", EMAIL + "\nBcc: otro@x.es", EMAIL + "\rX: y"):
            with self.subTest(malo=malo), self.assertRaises(ValueError):
                correo.componer(un_correo(destinatario=malo))

    def test_tipo_desconocido(self):
        with self.assertRaises(ValueError):
            correo.componer(un_correo(tipo="otro"))


class Enviar(unittest.TestCase):
    def test_envio(self):
        with mock.patch.object(smtplib, "SMTP") as smtp:
            correo.enviar(un_correo())
        smtp.assert_called_once_with("mailpit", 1025, timeout=5)
        enviado = smtp.return_value.__enter__.return_value.send_message.call_args.args[0]
        self.assertEqual(enviado["To"], EMAIL)

    def test_fallo_al_log_sin_datos(self):
        error = smtplib.SMTPRecipientsRefused({EMAIL: (550, b"no")})
        with mock.patch.object(smtplib, "SMTP", side_effect=error), \
                self.assertLogs("canario.correo", "ERROR") as registro:
            correo.enviar(un_correo())
        self.assertEqual(registro.output,
                         ["ERROR:canario.correo:EVENTO correo_fallido: tipo=verificacion error=SMTPRecipientsRefused"])
        # El texto del error lleva el email (control): el log no.
        self.assertIn(EMAIL, str(error))
        self.assertNotIn(EMAIL, "\n".join(registro.output))
        self.assertNotIn("secreto", "\n".join(registro.output))

    def test_cabecera_inyectada_acaba_en_el_log(self):
        with mock.patch.object(smtplib, "SMTP") as smtp, self.assertLogs("canario.correo", "ERROR") as registro:
            correo.enviar(un_correo(destinatario=EMAIL + "\r\nBcc: otro@x.es"))
        smtp.assert_not_called()
        self.assertEqual(registro.output,
                         ["ERROR:canario.correo:EVENTO correo_fallido: tipo=verificacion error=ValueError"])

    def test_sin_hueco_se_descarta_sin_esperar(self):
        ocupados = 0
        try:
            while correo._semaforo.acquire(blocking=False):
                ocupados += 1
            self.assertEqual(ocupados, 4)
            with mock.patch.object(smtplib, "SMTP") as smtp, \
                    self.assertLogs("canario.correo", "ERROR") as registro:
                correo.enviar(un_correo(tipo="invitacion"))
            smtp.assert_not_called()
            self.assertEqual(registro.output, [
                "ERROR:canario.correo:EVENTO correo_descartado: tipo=invitacion motivo=envios_simultaneos"])
        finally:
            for _ in range(ocupados):
                correo._semaforo.release()
        # Control: con huecos libres se envía, y los huecos quedan libres
        # también tras un fallo.
        with mock.patch.object(smtplib, "SMTP", side_effect=OSError), self.assertLogs("canario.correo", "ERROR"):
            correo.enviar(un_correo())
        with mock.patch.object(smtplib, "SMTP") as smtp:
            correo.enviar(un_correo())
        smtp.assert_called_once()
        libres = [correo._semaforo.acquire(blocking=False) for _ in range(4)]
        for _ in range(sum(libres)):
            correo._semaforo.release()
        self.assertEqual(libres, [True] * 4)
