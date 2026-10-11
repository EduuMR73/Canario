"""Claves de cifrado de Canario (docs/threat-model.md, 6.1 y 6.4).

Dos claves del servidor, cada una en su Docker secret (nunca en variables de
entorno), generadas por scripts/generar_secretos.py como 64 caracteres
hexadecimales en minúscula (32 bytes):

* clave_maestra: envuelve la clave de cada empresa. No cifra datos.
* clave_hmac_codigos: calcula el HMAC de los códigos de seguimiento, que es lo
  único que se guarda de ellos.

Se leen una sola vez, al arrancar, y la API no arranca si alguna falta o no
tiene el formato exacto: un fichero con un salto de línea final o en
mayúsculas es un error de configuración y debe verse, no corregirse en
silencio. Cambiar la clave maestra exige volver a envolver las claves de
todas las empresas, así que no tiene sentido releerla en caliente.

Límite asumido: Python no permite borrar con garantías un valor de la
memoria. Las claves viven en el proceso de la API mientras está en marcha
(docs/threat-model.md, 8: servidor comprometido).
"""
import pathlib
import re
from dataclasses import dataclass

FICHERO_CLAVE_MAESTRA = pathlib.Path("/run/secrets/clave_maestra")
FICHERO_CLAVE_HMAC = pathlib.Path("/run/secrets/clave_hmac_codigos")

# fullmatch: un salto de línea final no encaja nunca (a diferencia de "$").
PATRON_CLAVE = re.compile(r"[0-9a-f]{64}")


class ErrorClaves(Exception):
    """Falta una clave o no tiene el formato esperado. Nunca lleva su valor."""


# repr propio: un traceback o un log que muestre el objeto no imprime las
# claves.
@dataclass(frozen=True, repr=False)
class Claves:
    maestra: bytes
    hmac_codigos: bytes

    def __repr__(self):
        return "Claves(<ocultas>)"


def _leer(fichero, nombre):
    try:
        texto = fichero.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError) as error:
        raise ErrorClaves(f"no se puede leer {nombre} ({type(error).__name__})") from None
    if not PATRON_CLAVE.fullmatch(texto):
        raise ErrorClaves(f"{nombre} no tiene el formato esperado (64 hexadecimales en minuscula)")
    return bytes.fromhex(texto)


def cargar(fichero_maestra=FICHERO_CLAVE_MAESTRA, fichero_hmac=FICHERO_CLAVE_HMAC):
    """Lee y valida las dos claves. Lanza ErrorClaves con un motivo sin valores."""
    maestra = _leer(fichero_maestra, "clave_maestra")
    hmac_codigos = _leer(fichero_hmac, "clave_hmac_codigos")
    # Cada clave tiene un único uso. Dos secretos iguales indican un error al
    # generarlos o al montarlos, y romperían esa separación.
    if maestra == hmac_codigos:
        raise ErrorClaves("clave_maestra y clave_hmac_codigos son iguales")
    return Claves(maestra=maestra, hmac_codigos=hmac_codigos)


def cargar_maestra(fichero=FICHERO_CLAVE_MAESTRA):
    """Solo la clave maestra: el servicio de gestión no necesita la de HMAC."""
    return _leer(fichero, "clave_maestra")
