"""Pruebas unitarias de app/claves.py: el formato exacto de las tres claves
del servidor, que sean distintas entre sí y que nunca salgan en un repr ni
en un mensaje de error.

Las claves de prueba se escriben en un directorio temporal propio de cada
prueba (los secretos reales nunca se leen aquí).
"""
import dataclasses
import pathlib
import tempfile
import unittest

from app import claves

MAESTRA = "0123456789abcdef" * 4
HMAC = "fedcba9876543210" * 4
FIRMA = "00112233445566778899aabbccddeeff" * 2


class Carga(unittest.TestCase):
    def setUp(self):
        self._directorio = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self._directorio.name)

    def tearDown(self):
        self._directorio.cleanup()

    def fichero(self, nombre, contenido):
        ruta = self.dir / nombre
        if isinstance(contenido, bytes):
            ruta.write_bytes(contenido)
        else:
            ruta.write_text(contenido, encoding="ascii", newline="")
        return ruta

    def cargar(self, maestra=MAESTRA, hmac_codigos=HMAC, firma=FIRMA):
        return claves.cargar(self.fichero("m", maestra), self.fichero("h", hmac_codigos), self.fichero("f", firma))

    def test_valida(self):
        cargadas = self.cargar()
        self.assertEqual(cargadas.maestra, bytes.fromhex(MAESTRA))
        self.assertEqual(cargadas.hmac_codigos, bytes.fromhex(HMAC))
        self.assertEqual(cargadas.firma_tokens, bytes.fromhex(FIRMA))

    def test_formatos_rechazados(self):
        malos = {
            "63 caracteres": MAESTRA[:-1],
            "65 caracteres": MAESTRA + "0",
            "mayusculas": MAESTRA.upper(),
            "salto final": MAESTRA + "\n",
            "espacio": " " + MAESTRA[1:],
            "no hexadecimal": "g" + MAESTRA[1:],
            "vacio": "",
        }
        for motivo, valor in malos.items():
            with self.subTest(motivo=motivo):
                with self.assertRaises(claves.ErrorClaves) as error:
                    self.cargar(maestra=valor)
                self.assertEqual(str(error.exception),
                                 "clave_maestra no tiene el formato esperado (64 hexadecimales en minuscula)")

    def test_la_maestra_se_comprueba_antes_que_la_hmac(self):
        with self.assertRaises(claves.ErrorClaves) as error:
            self.cargar(maestra="x", hmac_codigos="y")
        self.assertTrue(str(error.exception).startswith("clave_maestra "))
        with self.assertRaises(claves.ErrorClaves) as error:
            self.cargar(hmac_codigos="y")
        self.assertEqual(str(error.exception),
                         "clave_hmac_codigos no tiene el formato esperado (64 hexadecimales en minuscula)")
        with self.assertRaises(claves.ErrorClaves) as error:
            self.cargar(firma=FIRMA + "\n")
        self.assertEqual(str(error.exception),
                         "clave_firma_tokens no tiene el formato esperado (64 hexadecimales en minuscula)")

    def test_iguales(self):
        # Las tres parejas: cada clave tiene un único uso.
        casos = {
            "clave_maestra y clave_hmac_codigos son iguales": {"hmac_codigos": MAESTRA},
            "clave_maestra y clave_firma_tokens son iguales": {"firma": MAESTRA},
            "clave_hmac_codigos y clave_firma_tokens son iguales": {"firma": HMAC},
        }
        for mensaje, cambio in casos.items():
            with self.subTest(mensaje=mensaje):
                with self.assertRaises(claves.ErrorClaves) as error:
                    self.cargar(**cambio)
                self.assertEqual(str(error.exception), mensaje)

    def test_ilegibles_sin_valor_en_el_mensaje(self):
        with self.assertRaises(claves.ErrorClaves) as error:
            claves.cargar(self.dir / "no_existe", self.fichero("h", HMAC), self.fichero("f", FIRMA))
        self.assertEqual(str(error.exception), "no se puede leer clave_maestra (FileNotFoundError)")
        with self.assertRaises(claves.ErrorClaves) as error:
            claves.cargar_maestra(self.fichero("m", b"\xff" * 64))
        self.assertEqual(str(error.exception), "no se puede leer clave_maestra (UnicodeDecodeError)")

    def test_cargar_maestra(self):
        self.assertEqual(claves.cargar_maestra(self.fichero("m", MAESTRA)), bytes.fromhex(MAESTRA))


class ClavesOcultas(unittest.TestCase):
    def test_repr_sin_valores_e_inmutable(self):
        cargadas = claves.Claves(maestra=bytes.fromhex(MAESTRA), hmac_codigos=bytes.fromhex(HMAC),
                                 firma_tokens=bytes.fromhex(FIRMA))
        for texto in (repr(cargadas), str(cargadas), f"{cargadas}"):
            with self.subTest(texto=texto):
                self.assertEqual(texto, "Claves(<ocultas>)")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            cargadas.maestra = bytes(32)
