"""Pruebas unitarias del cartero (app/cartero.py): configuración obligatoria,
composición sin inyección de cabeceras ni seguimiento, TLS que verifica el
certificado, qué fallo se reintenta y cuál no, cola acotada y cupo diario.

Sin red: el servidor SMTP se sustituye por un doble (unittest.mock). La
entrega real por TLS a Mailpit, con un certificado de confianza y con uno
que no lo es, la prueba tests/security/verificar_registro.py, y también que
el cartero solo atiende a la IP de la API.
"""
import datetime
import pathlib
import smtplib
import ssl
import tempfile
import unittest
from unittest import mock

import pydantic

from app import cartero, correo

REMITENTE = "no-responder@canario.test"
EMAIL = "persona@empresa.es"
ENTORNO = {"CANARIO_IP_API": "10.88.4.4", "CANARIO_SMTP_SERVIDOR": "in-v3.mailjet.com",
           "CANARIO_SMTP_PUERTO": "465", "CANARIO_CORREO_REMITENTE": REMITENTE}


def mensaje(tipo="invitacion"):
    return cartero.componer(REMITENTE, tipo, EMAIL, "Asunto", "Enlace: https://localhost:8445/activacion#secreto")


class Config(unittest.TestCase):
    def setUp(self):
        directorio = tempfile.TemporaryDirectory()
        self.addCleanup(directorio.cleanup)
        self.usuario = pathlib.Path(directorio.name) / "smtp_usuario"
        self.contrasena = pathlib.Path(directorio.name) / "smtp_contrasena"

    def cargar(self, usuario, contrasena, entorno=ENTORNO):
        self.usuario.write_bytes(usuario)
        self.contrasena.write_bytes(contrasena)
        return cartero.cargar_config(entorno, self.usuario, self.contrasena)

    def test_valida(self):
        config = self.cargar(b"clave-api", b"clave-secreta")
        self.assertEqual((config.ip_api, config.servidor, config.puerto, config.remitente, config.usuario),
                         ("10.88.4.4", "in-v3.mailjet.com", 465, REMITENTE, "clave-api"))
        # La contraseña no sale en el repr (un log o una traza con la config).
        self.assertEqual(config.contrasena, "clave-secreta")
        self.assertNotIn("clave-secreta", repr(config))

    def test_marcadores(self):
        # Los dos marcadores: sin autenticarse (Mailpit, en desarrollo).
        config = self.cargar(b"sin-configurar:usuario", b"sin-configurar:contrasena")
        self.assertIsNone(config.usuario)
        self.assertIsNone(config.contrasena)
        # Uno solo es un error de quien opera: no arranca.
        for usuario, contrasena in ((b"sin-configurar:usuario", b"clave-secreta"),
                                    (b"clave-api", b"sin-configurar:contrasena")):
            with self.subTest(usuario=usuario), self.assertRaises(cartero.ArranqueBloqueado):
                self.cargar(usuario, contrasena)

    def test_obligatoria_y_sin_valores_por_defecto(self):
        malos = {
            "CANARIO_IP_API": ("", "cartero", "10.88.4"),
            "CANARIO_SMTP_SERVIDOR": ("", "In-V3.mailjet.com", "smtp://x", "-x"),
            "CANARIO_SMTP_PUERTO": ("", "0", "65536", "465 ", "-1"),
            "CANARIO_CORREO_REMITENTE": ("", "Canario <no@x.es>", "sin-arroba"),
        }
        for variable, valores in malos.items():
            for valor in valores:
                with self.subTest(variable=variable, valor=valor), self.assertRaises(cartero.ArranqueBloqueado):
                    self.cargar(b"u", b"c", {**ENTORNO, variable: valor})
            with self.subTest(variable=variable, valor=None), self.assertRaises(cartero.ArranqueBloqueado):
                self.cargar(b"u", b"c", {k: v for k, v in ENTORNO.items() if k != variable})
        # Un secreto con salto de línea final (un editor que lo añade) no vale.
        with self.assertRaises(cartero.ArranqueBloqueado):
            self.cargar(b"clave-api\n", b"clave-secreta")


class Componer(unittest.TestCase):
    def test_cabeceras(self):
        compuesto = mensaje()
        self.assertEqual(compuesto["From"], "Canario <no-responder@canario.test>")
        self.assertEqual(compuesto["To"], EMAIL)
        self.assertEqual(compuesto["Subject"], "Asunto")
        self.assertTrue(compuesto["Message-ID"].endswith("@canario.test>"))
        self.assertIsNotNone(compuesto["Date"])
        self.assertIn("#secreto", compuesto.get_content())
        # El pie antiphishing, literal, al final de todos los correos.
        self.assertTrue(compuesto.get_content().endswith(
            "\n\n-- \nCanario nunca le pedirá por correo su contraseña ni su código de verificación.\n"))

    def test_sin_seguimiento(self):
        # Con seguimiento, Mailjet reescribiría el enlace y el token llegaría
        # a sus registros. Literales de su documentación (custom headers).
        compuesto = mensaje()
        self.assertEqual(compuesto["X-Mailjet-TrackClick"], "0")
        self.assertEqual(compuesto["X-Mailjet-TrackOpen"], "0")

    def test_cabeceras_sin_cr_ni_lf(self):
        # CWE-93: un salto de línea añadiría una cabecera (un Bcc). Control:
        # los mismos valores sin salto pasan (test_cabeceras).
        for malo in (EMAIL + "\r\nBcc: otro@x.es", EMAIL + "\nBcc: otro@x.es", EMAIL + "\rX: y"):
            with self.subTest(malo=malo):
                with self.assertRaises(ValueError):
                    cartero.componer(REMITENTE, "invitacion", malo, "Asunto", "Cuerpo")
                with self.assertRaises(ValueError):
                    cartero.componer(REMITENTE, "invitacion", EMAIL, "Asunto" + malo[len(EMAIL):], "Cuerpo")

    def test_tipo_desconocido(self):
        self.assertEqual(set(cartero.CATEGORIAS), set(correo.TIPOS))
        with self.assertRaises(ValueError):
            cartero.componer(REMITENTE, "otro", EMAIL, "Asunto", "Cuerpo")

    def test_peticion_sin_controles(self):
        # La frontera del cartero usa los mismos tipos de texto que la API: el
        # asunto, de una línea; el cuerpo, libre salvo NUL.
        valido = {"tipo": "invitacion", "destinatario": EMAIL, "asunto": "Asunto", "cuerpo": "Uno\n\nDos"}
        cartero.PeticionCorreo(**valido)
        for campo, malo in (("asunto", "A\r\nBcc: x@x.es"), ("cuerpo", "con\x00nul"), ("destinatario", EMAIL + "\n")):
            with self.subTest(campo=campo), self.assertRaises(pydantic.ValidationError):
                cartero.PeticionCorreo(**{**valido, campo: malo})
        with self.assertRaises(pydantic.ValidationError):
            cartero.PeticionCorreo(**valido, remitente="otro@x.es")


class Tls(unittest.TestCase):
    def test_verifica_certificado_y_nombre(self):
        contexto = cartero.contexto_tls()
        self.assertEqual(contexto.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(contexto.check_hostname)
        self.assertGreaterEqual(contexto.minimum_version, ssl.TLSVersion.TLSv1_2)
        # Control: lo que smtplib usa si no se le pasa contexto no verifica
        # nada. Es la trampa que evita contexto_tls().
        self.assertEqual(ssl._create_stdlib_context().verify_mode, ssl.CERT_NONE)

    def test_entrega_con_el_contexto_y_tls_implicito(self):
        smtp = mock.MagicMock()
        config = cartero.Config("10.88.4.4", "in-v3.mailjet.com", 465, REMITENTE, "clave-api", "clave-secreta")
        compuesto = mensaje()
        cartero.entregar(config, compuesto, smtp=smtp)
        argumentos = smtp.call_args
        self.assertEqual(argumentos.args, ("in-v3.mailjet.com", 465))
        self.assertEqual(argumentos.kwargs["timeout"], cartero.PLAZO)
        self.assertEqual(argumentos.kwargs["context"].verify_mode, ssl.CERT_REQUIRED)
        servidor = smtp.return_value.__enter__.return_value
        servidor.login.assert_called_once_with("clave-api", "clave-secreta")
        servidor.send_message.assert_called_once_with(compuesto)
        # Sin credenciales (los marcadores) no se autentica.
        smtp.reset_mock()
        cartero.entregar(cartero.Config("10.88.4.4", "mailpit", 1025, REMITENTE, None, None), compuesto, smtp=smtp)
        smtp.return_value.__enter__.return_value.login.assert_not_called()
        # Es SMTP_SSL (TLS desde el primer byte), no SMTP con STARTTLS.
        self.assertIs(cartero.entregar.__defaults__[0], smtplib.SMTP_SSL)


class Fallos(unittest.TestCase):
    CONFIG = cartero.Config("10.88.4.4", "in-v3.mailjet.com", 465, REMITENTE, None, None)

    def fallo(self, error):
        with self.assertRaises(cartero.EntregaFallida) as contexto:
            cartero.entregar(self.CONFIG, mensaje(), smtp=mock.Mock(side_effect=error))
        return contexto.exception.motivo, contexto.exception.definitiva

    def test_que_se_reintenta(self):
        casos = (
            (ssl.SSLCertVerificationError("certificado"), ("certificado", True)),
            (smtplib.SMTPAuthenticationError(535, b"no"), ("autenticacion", True)),
            (smtplib.SMTPRecipientsRefused({EMAIL: (550, b"no")}), ("destinatario_rechazado", True)),
            (smtplib.SMTPRecipientsRefused({EMAIL: (450, b"luego")}), ("destinatario_rechazado", False)),
            (smtplib.SMTPSenderRefused(553, b"no", REMITENTE), ("smtp_553", True)),
            (smtplib.SMTPDataError(421, b"luego"), ("smtp_421", False)),
            (smtplib.SMTPServerDisconnected("cortado"), ("SMTPServerDisconnected", False)),
            (TimeoutError(), ("TimeoutError", False)),
            (ConnectionRefusedError(), ("ConnectionRefusedError", False)),
        )
        for error, esperado in casos:
            with self.subTest(error=type(error).__name__):
                self.assertEqual(self.fallo(error), esperado)

    def test_motivo_sin_datos(self):
        # El texto del error puede llevar el destinatario (control): el motivo no.
        error = smtplib.SMTPRecipientsRefused({EMAIL: (550, b"no existe " + EMAIL.encode())})
        self.assertIn(EMAIL, str(error))
        motivo, _ = self.fallo(error)
        self.assertNotIn(EMAIL, motivo)


class ColaYCupo(unittest.TestCase):
    def test_cupo_por_categoria_y_por_dia(self):
        dia = [datetime.date(2026, 10, 30)]
        cola = cartero.Cola(reloj=lambda: 0.0, hoy=lambda: dia[0])
        with mock.patch.object(cartero, "COLA_MAXIMA", 1000):
            admitidos = [cola.admitir(cartero.Pendiente("verificacion", mensaje())) for _ in range(150)]
            self.assertEqual(admitidos, [None] * 150)
            # El registro agota su parte...
            self.assertEqual(cola.admitir(cartero.Pendiente("invitacion", mensaje())), "cupo_diario")
            # ...y los avisos de seguridad siguen saliendo (control del anterior).
            self.assertIsNone(cola.admitir(cartero.Pendiente("aviso_activacion", mensaje())))
            # Día nuevo, cupo nuevo.
            dia[0] = datetime.date(2026, 10, 31)
            self.assertIsNone(cola.admitir(cartero.Pendiente("invitacion", mensaje())))
        self.assertEqual(sum(cartero.CUPO_DIARIO.values()), 200)

    def test_cola_acotada_y_ordenada(self):
        cola = cartero.Cola(reloj=lambda: 0.0, hoy=lambda: datetime.date(2026, 10, 30))
        for _ in range(cartero.COLA_MAXIMA):
            self.assertIsNone(cola.admitir(cartero.Pendiente("aviso_lecturas", mensaje())))
        self.assertEqual(cola.admitir(cartero.Pendiente("aviso_lecturas", mensaje())), "cola_llena")
        # Sale primero lo que toca antes; un reintento espera su turno.
        self.assertIsNotNone(cola.siguiente())
        pendientes = cola.cerrar()
        self.assertEqual(len(pendientes), cartero.COLA_MAXIMA - 1)
        self.assertIsNone(cola.siguiente())
        self.assertEqual(cola.admitir(cartero.Pendiente("aviso_lecturas", mensaje())), "cerrada")


class ColaFalsa:
    """Lo mínimo de Cola para repartir: una lista y los reintentos anotados."""

    def __init__(self, pendientes):
        self.pendientes = list(pendientes)
        self.esperas = []

    def siguiente(self):
        return self.pendientes.pop(0) if self.pendientes else None

    def reintentar(self, pendiente, espera):
        self.esperas.append(espera)
        self.pendientes.append(pendiente)
        return True


class Repartir(unittest.TestCase):
    def repartir(self, error):
        cola = ColaFalsa([cartero.Pendiente("invitacion", mensaje())])
        llamadas = []

        def entregar(_config, _mensaje):
            llamadas.append(1)
            if error is not None:
                raise error

        with self.assertLogs("canario.cartero", "INFO") as registro:
            cartero.repartir(cola, None, entregar_uno=entregar)
        return len(llamadas), cola.esperas, registro.output

    def test_entregado(self):
        llamadas, esperas, salida = self.repartir(None)
        self.assertEqual((llamadas, esperas), (1, []))
        self.assertEqual(salida, ["INFO:canario.cartero:EVENTO correo_entregado: tipo=invitacion"])

    def test_temporal_se_reintenta_y_acaba(self):
        llamadas, esperas, salida = self.repartir(cartero.EntregaFallida("TimeoutError", definitiva=False))
        self.assertEqual(llamadas, 4)
        self.assertEqual(esperas, [60, 300, 900])
        self.assertEqual(salida[-1], "ERROR:canario.cartero:EVENTO correo_fallido: tipo=invitacion motivo=TimeoutError")
        self.assertEqual(sum("correo_aplazado" in linea for linea in salida), 3)

    def test_definitivo_no_se_reintenta(self):
        llamadas, esperas, salida = self.repartir(cartero.EntregaFallida("certificado", definitiva=True))
        self.assertEqual((llamadas, esperas), (1, []))
        self.assertEqual(salida, ["ERROR:canario.cartero:EVENTO correo_fallido: tipo=invitacion motivo=certificado"])

    def test_imprevisto_no_mata_el_hilo(self):
        cola = ColaFalsa([cartero.Pendiente("invitacion", mensaje()), cartero.Pendiente("aviso_lecturas", mensaje())])
        errores = [RuntimeError("con " + EMAIL), None]

        def entregar(_config, _mensaje):
            error = errores.pop(0)
            if error is not None:
                raise error

        with self.assertLogs("canario.cartero", "INFO") as registro:
            cartero.repartir(cola, None, entregar_uno=entregar)
        self.assertEqual(registro.output, [
            "ERROR:canario.cartero:EVENTO correo_fallido: tipo=invitacion motivo=RuntimeError",
            "INFO:canario.cartero:EVENTO correo_entregado: tipo=aviso_lecturas"])
