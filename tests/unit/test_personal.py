"""Pruebas unitarias de la lógica pura de app/personal.py: política de
contraseñas, parámetros de Argon2id y tokens compuestos.

Los parámetros de Argon2id son los mínimos del OWASP Password Storage Cheat
Sheet ("m=19456 (19 MiB), t=2, p=1"): el oráculo es esa cadena, no las
constantes del módulo.
"""
import unittest

from app import personal

MOTIVO_LONGITUD = "la contraseña debe tener entre 12 y 128 caracteres"
MOTIVO_PIEZAS = "la contraseña no puede contener el email ni el nombre de la empresa"
IDENTIFICADOR = "0123456789abcdef0123456789abcdef"


class PoliticaDeContrasenas(unittest.TestCase):
    def validar(self, texto, email="persona@empresa.es", empresa="Acme"):
        return personal.validar_contrasena(texto, email, empresa)

    def test_longitud(self):
        for texto in ("x" * 12, "x" * 128):
            with self.subTest(longitud=len(texto)):
                self.assertEqual(self.validar(texto), texto)
        for texto in ("x" * 11, "x" * 129, ""):
            with self.subTest(longitud=len(texto)):
                with self.assertRaises(personal.ContrasenaNoValida) as error:
                    self.validar(texto)
                self.assertEqual(str(error.exception), MOTIVO_LONGITUD)

    def test_nfkc_antes_de_medir(self):
        # 6 ligaduras fi (U+FB01) son 6 caracteres; en NFKC, "fi" x 6 = 12.
        self.assertEqual(self.validar(chr(0xFB01) * 6), "fi" * 6)
        # Letras de ancho completo: la misma contraseña que en ASCII.
        ancho_completo = "".join(chr(0xFF41 + i) for i in range(12))
        self.assertEqual(self.validar(ancho_completo), "abcdefghijkl")
        # 11 en NFKC, aunque escrita con 12 puntos de código: A + anillo combinante
        # (U+030A) se compone en un solo carácter (U+00C5).
        with self.assertRaises(personal.ContrasenaNoValida):
            self.validar("A" + chr(0x030A) + "x" * 10)

    def test_piezas_prohibidas_sin_distinguir_mayusculas(self):
        for texto in ("xxPERSONA@EMPRESA.ESxx", "xxxxPersonaxxxx", "xxxxxxxxACMExx"):
            with self.subTest(texto=texto):
                with self.assertRaises(personal.ContrasenaNoValida) as error:
                    self.validar(texto)
                self.assertEqual(str(error.exception), MOTIVO_PIEZAS)
        self.assertEqual(self.validar("xxxxotracosaxxxx"), "xxxxotracosaxxxx")  # control

    def test_piezas_de_menos_de_4_no_se_buscan(self):
        # Parte local "ana" y empresa "Iso": 3 caracteres, se ignoran.
        self.assertEqual(self.validar("xxanaxxisoxxx", email="ana@b.es", empresa="Iso"), "xxanaxxisoxxx")
        with self.assertRaises(personal.ContrasenaNoValida):
            self.validar("xxanaaxxxxxxx", email="anaa@b.es", empresa="Iso")  # control: con 4 sí


class Argon2(unittest.TestCase):
    def test_parametros_owasp(self):
        self.assertTrue(personal._hasher.hash("contraseña de prueba").startswith("$argon2id$v=19$m=19456,t=2,p=1$"))
        self.assertTrue(personal._HASH_FICTICIO.startswith("$argon2id$v=19$m=19456,t=2,p=1$"))

    def test_verificar(self):
        guardado = personal._hasher.hash("correcta-12345")
        self.assertTrue(personal._verificar_hash(guardado, "correcta-12345"))  # control
        self.assertFalse(personal._verificar_hash(guardado, "incorrecta-1234"))
        # Sin cuenta: verifica contra el hash ficticio y nunca acepta.
        self.assertFalse(personal._verificar_hash(None, "correcta-12345"))
        self.assertFalse(personal._verificar_hash("", "correcta-12345"))
        self.assertFalse(personal._verificar_hash("no es un hash", "correcta-12345"))


class TokenCompuesto(unittest.TestCase):
    TOKEN = "A" * 43  # forma canónica de 32 bytes cero

    def test_valido(self):
        self.assertEqual(personal.leer_compuesto(f"{IDENTIFICADOR}.{self.TOKEN}"), (IDENTIFICADOR, bytes(32)))
        self.assertEqual(personal.token_compuesto(IDENTIFICADOR, self.TOKEN), f"{IDENTIFICADOR}.{self.TOKEN}")

    def test_rechazados(self):
        rechazados = {
            "sin punto": IDENTIFICADOR + self.TOKEN,
            "dos puntos": f"{IDENTIFICADOR}.{self.TOKEN}.",
            "identificador en mayusculas": f"{IDENTIFICADOR.upper()}.{self.TOKEN}",
            "identificador de 31": f"{IDENTIFICADOR[1:]}.{self.TOKEN}",
            "identificador de 33": f"0{IDENTIFICADOR}.{self.TOKEN}",
            "token no canonico": f"{IDENTIFICADOR}.{'A' * 42}B",
            "no es str": None,
        }
        for motivo, texto in rechazados.items():
            with self.subTest(motivo=motivo):
                self.assertIsNone(personal.leer_compuesto(texto))
