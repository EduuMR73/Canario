"""Pruebas unitarias del núcleo del login del personal (app/personal.py,
_comprobar_factores): contraseña y TOTP, con el mismo trabajo haya cuenta o
no.

Uniformidad: un tiempo de respuesta distinto según exista la cuenta permite
enumerar cuentas. Medir tiempos en una prueba unitaria es frágil (lo mide la
batería tests/security/verificar_personal.py); aquí se comprueba la causa:
en todos los caminos se calcula un Argon2 y una verificación TOTP, con
unittest.mock en modo wraps (la función real se ejecuta y solo se cuentan
las llamadas).
"""
import unittest
import uuid
from unittest import mock

from app import claves, cripto, personal

MAESTRA = bytes(range(32))
CLAVE_EMPRESA = bytes([7]) * 32
EMPRESA = uuid.UUID(int=1)
USUARIO = uuid.UUID(int=2)
DISPOSITIVO = uuid.UUID(int=3)
# RFC 4226, apéndice D: con este secreto, el contador 5 da 254676. Instante
# 150 = paso 5.
SECRETO_RFC = b"12345678901234567890"
INSTANTE = 150
CODIGO = "254676"
CONTRASENA = "Contrasena-correcta-1"


def cuenta(contrasena=CONTRASENA, usuario_aad=USUARIO):
    """Fila reservada como la devuelve la base de datos (índices 1, 3, 4, 5)
    y la clave de empresa envuelta."""
    claves_reales = claves.Claves(maestra=MAESTRA, hmac_codigos=bytes(32))
    envuelta = cripto.envolver_clave(MAESTRA, CLAVE_EMPRESA, EMPRESA, 1)
    cifrado = cripto.cifrar(CLAVE_EMPRESA, SECRETO_RFC, cripto.aad_totp(EMPRESA, usuario_aad))
    reservada = (DISPOSITIVO, USUARIO, None, personal._hasher.hash(contrasena), cifrado, 1, 0)
    return claves_reales, reservada, (envuelta,)


def factores(reservada, envuelta, contrasena=CONTRASENA, codigo=CODIGO, claves_reales=None):
    claves_reales = claves_reales or claves.Claves(maestra=MAESTRA, hmac_codigos=bytes(32))
    return personal._comprobar_factores(claves_reales, EMPRESA, reservada, envuelta, contrasena, codigo, INSTANTE)


class ComprobarFactores(unittest.TestCase):
    def test_cuenta_valida(self):
        claves_reales, reservada, envuelta = cuenta()
        self.assertEqual(factores(reservada, envuelta, claves_reales=claves_reales), 5)

    def test_contrasena_incorrecta(self):
        _, reservada, envuelta = cuenta()
        self.assertIsNone(factores(reservada, envuelta, contrasena="Contrasena-mala-12"))

    def test_codigo_incorrecto(self):
        _, reservada, envuelta = cuenta()
        # 162583 es el código del paso 7: fuera de la ventana de 5 +- 1.
        self.assertIsNone(factores(reservada, envuelta, codigo="162583"))

    def test_sin_cuenta_nunca_acepta(self):
        self.assertIsNone(factores(None, None))

    def test_contrasena_normalizada_nfkc(self):
        # Guardada en NFKC; tecleada con 6 ligaduras fi (U+FB01).
        _, reservada, envuelta = cuenta(contrasena="fi" * 6 + "-segura")
        self.assertEqual(factores(reservada, envuelta, contrasena=chr(0xFB01) * 6 + "-segura"), 5)

    def test_secreto_de_otra_cuenta_falla_visible(self):
        # El AAD ata el secreto a su cuenta: copiado a otra fila no se descifra.
        _, reservada, envuelta = cuenta(usuario_aad=uuid.UUID(int=99))
        with self.assertRaises(cripto.ErrorIntegridad):
            factores(reservada, envuelta)

    def test_mismo_trabajo_en_todos_los_caminos(self):
        _, reservada, envuelta = cuenta()
        caminos = {
            "cuenta valida": (reservada, envuelta, CONTRASENA, 5),
            "contrasena mala": (reservada, envuelta, "Contrasena-mala-12", None),
            "sin cuenta": (None, None, CONTRASENA, None),
            "cuenta sin clave envuelta": (reservada, None, CONTRASENA, None),
        }
        for camino, (fila, clave, contrasena, esperado) in caminos.items():
            with self.subTest(camino=camino), \
                    mock.patch.object(personal, "_verificar_hash", wraps=personal._verificar_hash) as argon2, \
                    mock.patch.object(cripto, "verificar_totp", wraps=cripto.verificar_totp) as totp:
                self.assertEqual(factores(fila, clave, contrasena=contrasena), esperado)
                self.assertEqual(argon2.call_count, 1)
                self.assertEqual(totp.call_count, 1)
                # Sin cuenta, el Argon2 se hace contra el hash ficticio (None aquí).
                self.assertEqual(argon2.call_args.args[0], fila[3] if fila else None)

    def test_saturado_sin_calcular_el_hash(self):
        _, reservada, envuelta = cuenta()
        ocupados = 0
        try:
            # Ocupa los huecos de Argon2 (HASHES_SIMULTANEOS) como lo harían
            # otras peticiones en curso.
            while personal._semaforo.acquire(blocking=False):
                ocupados += 1
            self.assertEqual(ocupados, 2)
            with mock.patch.object(personal, "ESPERA_HASH", 0.05), \
                    mock.patch.object(personal, "_verificar_hash", wraps=personal._verificar_hash) as argon2, \
                    self.assertLogs("canario.personal", "WARNING") as registro, \
                    self.assertRaises(personal.Saturado):
                factores(reservada, envuelta)
            self.assertEqual(argon2.call_count, 0)
            self.assertEqual(registro.output, [
                "WARNING:canario.personal:EVENTO hashes_saturados: no hay hueco para calcular un hash de contrasena"])
        finally:
            for _ in range(ocupados):
                personal._semaforo.release()
        # Control: con los huecos libres, el mismo login funciona y los deja libres.
        self.assertEqual(factores(reservada, envuelta), 5)
        libres = [personal._semaforo.acquire(blocking=False) for _ in range(2)]
        for _ in range(sum(libres)):
            personal._semaforo.release()
        self.assertEqual(libres, [True, True])
