"""Validación de los textos de entrada en la frontera (docs/threat-model.md, 6.16).

Todo campo de texto de un modelo de entrada de la API usa uno de estos dos
tipos, y el email, además, validar_email. Lo comprueba la batería
tests/security/verificar_inyeccion.py recorriendo los modelos: un campo
nuevo con un str sin más la hace fallar (cerrado por construcción).

Por qué en la frontera y no en cada consumidor (OWASP Input Validation Cheat
Sheet: validar pronto, con una lista positiva):

* NUL: PostgreSQL no admite el carácter 0 en un texto y psycopg lo rechaza
  al enviar el parámetro. Sin esta validación, un NUL en el email del login
  o de una invitación era un 500 que cualquiera podía provocar, sin
  credenciales. En el resto de campos llegaba a la lógica (se cifraba y se
  guardaba, o se comparaba) sin que nadie lo hubiera decidido.
* Surrogates sueltos (U+D800 a U+DFFF): JSON permite escribirlos como
  "\\ud800", pero no son caracteres Unicode y no se pueden codificar en
  UTF-8 (RFC 8259, 8.2). Pydantic ya los rechazaba en los campos con límite
  de longitud y los dejaba pasar en los que no lo tienen: no era una
  garantía sino un efecto lateral, y aquí se hace explícito.
* Caracteres de control en TextoLinea: en un identificador, un email, una
  contraseña, un token o un código no tienen ningún uso legítimo.
* TextoLibre (denuncias y mensajes) rechaza solo lo que no es texto
  representable: el NUL y los surrogates. El resto es contenido de una
  prueba y se guarda tal cual, como hacen los canales de denuncia de
  referencia: un texto pegado desde un procesador de textos puede llevar un
  salto de página o un salto manual, y rechazarlo podría hacer perder una
  denuncia legítima. Lo que esos caracteres pudieran inyectar al mostrarse se
  resuelve en la salida (OWASP Cross Site Scripting Prevention Cheat Sheet):
  la API ya devuelve los controles C0 escapados en el JSON (RFC 8259, 7), y
  escapar al mostrar es tarea del cliente (docs/threat-model.md, 8).

El rechazo es el 422 genérico de la API (app/frontera_http.py), sin eco de
lo enviado.
"""
import re
from typing import Annotated

from pydantic import AfterValidator

# Cc (C0, DEL y C1) y surrogates.
_PROHIBIDOS_LINEA = re.compile("[\x00-\x1f\x7f-\x9f\ud800-\udfff]")
# NUL y surrogates: lo que no se puede guardar ni codificar.
_PROHIBIDOS_LIBRE = re.compile("[\x00\ud800-\udfff]")
# Email: ASCII imprimible sin espacio (de "!" a "~").
_EMAIL = re.compile("[\x21-\x7e]+")

LONGITUD_MAXIMA_EMAIL = 254


def texto_linea(texto):
    """Texto de una línea: sin caracteres de control ni surrogates."""
    if _PROHIBIDOS_LINEA.search(texto):
        raise ValueError("texto con caracteres no admitidos")
    return texto


def texto_libre(texto):
    """Texto libre: sin NUL ni surrogates; el resto se guarda tal cual."""
    if _PROHIBIDOS_LIBRE.search(texto):
        raise ValueError("texto con caracteres no admitidos")
    return texto


def validar_email(texto):
    """ASCII imprimible, sin espacios y con '@' después del primer carácter.
    Se devuelve en minúsculas, como exige el CHECK de la tabla. Solo ASCII:
    lower() de Python y el de PostgreSQL coinciden en ASCII, no siempre fuera
    de él. Es la única regla de email: la usan la API y gestion."""
    if not (3 <= len(texto) <= LONGITUD_MAXIMA_EMAIL and _EMAIL.fullmatch(texto) and texto.find("@") >= 1):
        raise ValueError("email no valido")
    return texto.lower()


TextoLinea = Annotated[str, AfterValidator(texto_linea)]
TextoLibre = Annotated[str, AfterValidator(texto_libre)]
