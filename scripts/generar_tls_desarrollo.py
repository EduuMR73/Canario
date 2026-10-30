#!/usr/bin/env python3
"""TLS del correo de DESARROLLO: una CA local y el certificado de Mailpit.

El cartero (app/cartero.py) solo entrega por TLS con el certificado
verificado, también en desarrollo: no tiene un modo sin TLS que pudiera
colarse en producción. Para eso, en desarrollo:

* secrets/correo_ca.pem: el certificado de una CA local. docker-compose.yml lo
  monta en el cartero como su ÚNICO almacén de confianza, así que desde un PC
  de desarrollo el cartero no puede entregar a ningún servidor real.
* secrets/mailpit_certificado.pem y secrets/mailpit_clave.pem: el
  certificado de Mailpit (nombre "mailpit"), firmado por esa CA, y su clave.

La clave privada de la CA no se guarda: se usa una vez para firmar y se
descarta, así que nadie puede emitir otro certificado en el que confíe el
cartero. Para renovar (caducan a los DIAS_VALIDEZ días), se borran los tres
ficheros y se vuelve a ejecutar el script.

Uso (desde la raíz del repositorio, en PowerShell):
    python scripts/generar_tls_desarrollo.py

Necesita cryptography (la versión de requirements.txt). Nunca sobrescribe un
fichero ni imprime una clave. No hace falta en producción: allí el cartero
confía en el almacén de certificados de la imagen.
"""
import datetime
import os
import pathlib
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

RAIZ_REPOSITORIO = pathlib.Path(__file__).resolve().parent.parent
DIRECTORIO = RAIZ_REPOSITORIO / "secrets"
FICHERO_CA = "correo_ca.pem"
FICHERO_CERTIFICADO = "mailpit_certificado.pem"
FICHERO_CLAVE = "mailpit_clave.pem"
NOMBRE_MAILPIT = "mailpit"
DIAS_VALIDEZ = 365
# Mismo modo que scripts/generar_secretos.py: el contenedor sin privilegios
# (Mailpit, 10003) tiene que poder leerlo por el bind mount.
MODO_FICHERO = 0o644


def _nombre(texto):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, texto)])


def generar():
    """(CA, certificado de Mailpit, clave de Mailpit) en PEM."""
    ahora = datetime.datetime.now(datetime.UTC)
    hasta = ahora + datetime.timedelta(days=DIAS_VALIDEZ)
    clave_ca = ec.generate_private_key(ec.SECP256R1())
    ca = (x509.CertificateBuilder().subject_name(_nombre("Canario CA de desarrollo del correo"))
          .issuer_name(_nombre("Canario CA de desarrollo del correo"))
          .public_key(clave_ca.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(ahora).not_valid_after(hasta)
          # path_length=0: solo firma certificados finales, nunca otra CA.
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                       data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                       crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
          # Solo el nombre mailpit: la CA no sirve para ningún otro nombre
          # aunque alguien consiguiera su clave (que tampoco se guarda).
          .add_extension(x509.NameConstraints(permitted_subtrees=[x509.DNSName(NOMBRE_MAILPIT)],
                                              excluded_subtrees=None), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(clave_ca.public_key()), critical=False)
          .sign(clave_ca, hashes.SHA256()))
    clave = ec.generate_private_key(ec.SECP256R1())
    certificado = (x509.CertificateBuilder().subject_name(_nombre(NOMBRE_MAILPIT)).issuer_name(ca.subject)
                   .public_key(clave.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(ahora).not_valid_after(hasta)
                   .add_extension(x509.SubjectAlternativeName([x509.DNSName(NOMBRE_MAILPIT)]), critical=False)
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                   .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(clave_ca.public_key()),
                                  critical=False)
                   .sign(clave_ca, hashes.SHA256()))
    return (ca.public_bytes(serialization.Encoding.PEM), certificado.public_bytes(serialization.Encoding.PEM),
            clave.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()))


def crear(ruta, contenido):
    # O_EXCL: falla si ya existe (nunca se sobrescribe). O_BINARY (solo
    # Windows): sin traducir saltos de línea.
    banderas = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(ruta, banderas, MODO_FICHERO)
    with os.fdopen(descriptor, "wb") as fichero:
        fichero.write(contenido)
    if os.name == "posix":
        os.chmod(ruta, MODO_FICHERO)
    print(f"  {ruta.name}: creado")


def main():
    if not DIRECTORIO.is_dir():
        print("ERROR: falta secrets/ (ejecute antes scripts/generar_secretos.py)")
        return 1
    rutas = [DIRECTORIO / nombre for nombre in (FICHERO_CA, FICHERO_CERTIFICADO, FICHERO_CLAVE)]
    existentes = [ruta.name for ruta in rutas if ruta.exists()]
    if len(existentes) == len(rutas):
        print("OK: ya existen los tres ficheros, no se toca nada")
        return 0
    if existentes:
        # A medias, la CA y el certificado no casarían: que decida quien lo
        # ejecuta, sin borrar nada por su cuenta.
        print(f"ERROR: solo existen {', '.join(existentes)}; borre los que haya y vuelva a ejecutar")
        return 1
    for ruta, contenido in zip(rutas, generar(), strict=True):
        crear(ruta, contenido)
    print(f"OK: CA y certificado de Mailpit validos {DIAS_VALIDEZ} dias")
    return 0


if __name__ == "__main__":
    sys.exit(main())
