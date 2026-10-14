"""Claves de cifrado de Canario (docs/threat-model.md, 6.1 y 6.4).

Tres claves del servidor, cada una en su Docker secret (nunca en variables de
entorno), generadas por scripts/generar_secretos.py como 64 caracteres
hexadecimales en minúscula (32 bytes):

* clave_maestra: envuelve la clave de cada empresa. No cifra datos.
* clave_hmac_codigos: calcula el HMAC de los códigos de seguimiento, que es lo
  único que se guarda de ellos.
* clave_firma_tokens: firma (HMAC-SHA256) los JWT de acceso del personal
  (app/tokens.py). 32 bytes aleatorios: RFC 7518, 3.2, pide al menos el
  tamaño del hash, y RFC 8725, 3.5, prohíbe usar una contraseña como clave.

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
FICHERO_CLAVE_FIRMA = pathlib.Path("/run/secrets/clave_firma_tokens")

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
    firma_tokens: bytes

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


def cargar(fichero_maestra=FICHERO_CLAVE_MAESTRA, fichero_hmac=FICHERO_CLAVE_HMAC,
           fichero_firma=FICHERO_CLAVE_FIRMA):
    """Lee y valida las tres claves. Lanza ErrorClaves con un motivo sin valores."""
    leidas = {"clave_maestra": _leer(fichero_maestra, "clave_maestra"),
              "clave_hmac_codigos": _leer(fichero_hmac, "clave_hmac_codigos"),
              "clave_firma_tokens": _leer(fichero_firma, "clave_firma_tokens")}
    # Cada clave tiene un único uso. Dos secretos iguales indican un error al
    # generarlos o al montarlos, y romperían esa separación.
    nombres = list(leidas)
    for i, primero in enumerate(nombres):
        for segundo in nombres[i + 1:]:
            if leidas[primero] == leidas[segundo]:
                raise ErrorClaves(f"{primero} y {segundo} son iguales")
    return Claves(maestra=leidas["clave_maestra"], hmac_codigos=leidas["clave_hmac_codigos"],
                  firma_tokens=leidas["clave_firma_tokens"])


def cargar_maestra(fichero=FICHERO_CLAVE_MAESTRA):
    """Solo la clave maestra: el servicio de gestión no necesita las otras."""
    return _leer(fichero, "clave_maestra")
