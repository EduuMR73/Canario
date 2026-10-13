"""Pruebas unitarias de app/validacion.py: los textos que admite la frontera.

Los bordes son los de cada rango, a un carácter de distancia por los dos
lados: lo que está justo dentro es el control de lo que está justo fuera.
"""
import unittest

import pydantic

from app import validacion

MOTIVO_TEXTO = "texto con caracteres no admitidos"


class TextoLinea(unittest.TestCase):
    def test_bordes_admitidos(self):
        for texto in ("", "a", "\x20", "\x7e", "\xa0", "\u2028", "\u2029", "\ud7ff", "\ue000", "ñ😀"):
            with self.subTest(texto=ascii(texto)):
                self.assertEqual(validacion.texto_linea(texto), texto)

    def test_bordes_rechazados(self):
        for texto in ("\x00", "\t", "\n", "\r", "\x1f", "\x7f", "\x80", "\x9f", "\ud800", "\udfff", "ok\x00"):
            with self.subTest(texto=ascii(texto)):
                with self.assertRaises(ValueError) as error:
                    validacion.texto_linea(texto)
                self.assertEqual(str(error.exception), MOTIVO_TEXTO)


class TextoLibre(unittest.TestCase):
    def test_controles_que_se_conservan(self):
        # Contenido de una prueba: se guarda tal cual (ver la cabecera del módulo).
        for texto in ("a\nb", "a\tb", "\x0c", "\x7f", "\x9f", "\x01"):
            with self.subTest(texto=ascii(texto)):
                self.assertEqual(validacion.texto_libre(texto), texto)

    def test_nul_y_surrogates(self):
        for texto in ("a\x00", "\ud800", "\udfff"):
            with self.subTest(texto=ascii(texto)):
                with self.assertRaises(ValueError) as error:
                    validacion.texto_libre(texto)
                self.assertEqual(str(error.exception), MOTIVO_TEXTO)


class Email(unittest.TestCase):
    def test_validos_y_en_minusculas(self):
        casos = {"a@b": "a@b", "A@B.ES": "a@b.es", "!@~": "!@~", "a@@": "a@@",
                 "a" * 250 + "@b.c": "a" * 250 + "@b.c"}
        for entrada, salida in casos.items():
            with self.subTest(entrada=entrada[:20]):
                self.assertEqual(validacion.validar_email(entrada), salida)

    def test_rechazados(self):
        rechazados = {
            "2 caracteres": "ab",
            "@ al principio": "@ab",
            "sin @": "abc",
            "255 caracteres": "a" * 251 + "@b.c",
            "espacio": "a b@c",
            "salto final": "a@b\n",
            "no ascii": "\xf1@x.es",
            "control": "a@b\x7f",
        }
        for motivo, texto in rechazados.items():
            with self.subTest(motivo=motivo):
                with self.assertRaises(ValueError) as error:
                    validacion.validar_email(texto)
                self.assertEqual(str(error.exception), "email no valido")


class TiposDePydantic(unittest.TestCase):
    """Los tipos anotados aplican la validación dentro de un modelo."""

    def test_texto_linea_en_un_modelo(self):
        adaptador = pydantic.TypeAdapter(validacion.TextoLinea)
        self.assertEqual(adaptador.validate_python("ok"), "ok")  # control
        with self.assertRaises(pydantic.ValidationError):
            adaptador.validate_python("o\x00k")

    def test_texto_libre_en_un_modelo(self):
        adaptador = pydantic.TypeAdapter(validacion.TextoLibre)
        self.assertEqual(adaptador.validate_python("a\nb"), "a\nb")  # control
        with self.assertRaises(pydantic.ValidationError):
            adaptador.validate_python("a\x00b")
