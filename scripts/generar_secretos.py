#!/usr/bin/env python3
"""Generador de secretos de Canario.

Crea, si faltan, los secretos del directorio secrets/ y comprueba que todo
el conjunto es correcto. Solo usa la biblioteca estándar.

Uso:
    python scripts/generar_secretos.py                    crea lo que falte y comprueba
    python scripts/generar_secretos.py --comprobar        solo comprueba, no crea nada
    python scripts/generar_secretos.py --directorio RUTA  usa otro directorio (pruebas)

Reglas de seguridad:
- Nunca sobrescribe un fichero existente. No hay opción para forzarlo: una
  clave maestra regenerada dejaría ilegibles los datos ya cifrados.
- Nunca imprime el valor de un secreto ni el hash derivado, solo nombres de
  fichero y estados.
- Todo lo que se imprime es ASCII puro para evitar problemas de codificación
  en la consola de Windows.
"""

import argparse
import hashlib
import os
import pathlib
import re
import secrets
import subprocess
import sys

# Raíz del repositorio calculada desde la ubicación de este script, no desde
# el directorio de trabajo.
RAIZ_REPOSITORIO = pathlib.Path(__file__).resolve().parent.parent
DIRECTORIO_POR_DEFECTO = RAIZ_REPOSITORIO / "secrets"

MODO_DIRECTORIO = 0o700
MODO_FICHERO = 0o644
ES_POSIX = os.name == "posix"

# Patrones exactos. Se usa fullmatch, así que un salto de línea final no
# encaja nunca (a diferencia de "$", que lo tolera).
PATRON_URLSAFE = re.compile(rb"[A-Za-z0-9_-]{64}")
PATRON_HEXADECIMAL = re.compile(rb"[0-9a-f]{64}")
PATRON_ACL = re.compile(
    rb"user default off\n"
    rb"user aplicacion on #([0-9a-f]{64}) ~\* \+@all -@admin -@dangerous\n"
)

# nombre de fichero -> (generador, patrón que debe cumplir)
# token_urlsafe(48) da exactamente 64 caracteres; token_hex(32), también 64.
SECRETOS = {
    "contrasena_redis.txt": (lambda: secrets.token_urlsafe(48), PATRON_URLSAFE),
    "contrasena_postgres_superusuario.txt": (lambda: secrets.token_urlsafe(48), PATRON_URLSAFE),
    "contrasena_migrador.txt": (lambda: secrets.token_urlsafe(48), PATRON_URLSAFE),
    "contrasena_aplicacion.txt": (lambda: secrets.token_urlsafe(48), PATRON_URLSAFE),
    "contrasena_plataforma.txt": (lambda: secrets.token_urlsafe(48), PATRON_URLSAFE),
    "clave_hmac_codigos.txt": (lambda: secrets.token_hex(32), PATRON_HEXADECIMAL),
    "clave_maestra.txt": (lambda: secrets.token_hex(32), PATRON_HEXADECIMAL),
}
FICHERO_REDIS = "contrasena_redis.txt"
FICHERO_ACL = "redis_acl.conf"
FICHERO_CENTINELA_GIT = "clave_maestra.txt"

# Resultados de la guardia de Git
IGNORADO = "ignorado"
NO_IGNORADO = "no_ignorado"
INDETERMINADO = "indeterminado"


def texto_ascii(texto):
    """Devuelve el texto con todo carácter no ASCII escapado."""
    return str(texto).encode("ascii", "backslashreplace").decode("ascii")


def ancestro_existente(ruta):
    """Devuelve el ancestro existente más cercano de una ruta (o ella misma)."""
    actual = ruta
    while not actual.exists():
        if actual.parent == actual:
            break
        actual = actual.parent
    return actual


def guardia_git(directorio):
    """Comprueba con Git que el directorio de secretos está ignorado.

    El destino puede ser el directorio real o uno de pruebas, así que se
    ejecuta git desde el ancestro existente más cercano al destino, y se
    consulta la ruta absoluta del fichero centinela.

    Códigos de salida de "git check-ignore -q": 0 = ignorado, 1 = no
    ignorado. Cualquier otro resultado (git no instalado, directorio fuera
    de un repositorio, error o tiempo agotado) no permite concluir nada:
    se avisa y se continúa.
    """
    centinela = directorio.resolve() / FICHERO_CENTINELA_GIT
    try:
        resultado = subprocess.run(
            ["git", "check-ignore", "-q", "--", str(centinela)],
            cwd=str(ancestro_existente(directorio.resolve())),
            capture_output=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        print("AVISO: no se pudo comprobar la exclusion de Git")
        return INDETERMINADO

    if resultado.returncode == 0:
        return IGNORADO
    if resultado.returncode == 1:
        return NO_IGNORADO
    print("AVISO: no se pudo comprobar la exclusion de Git")
    return INDETERMINADO


def preparar_directorio(directorio):
    """Crea el directorio de secretos si falta y fija su modo en POSIX."""
    directorio.mkdir(parents=True, exist_ok=True)
    if ES_POSIX:
        # chmod explícito DESPUÉS de crear: el modo que se pasa a mkdir lo
        # recorta el umask del usuario. En Windows no se aplican modos; el
        # acceso lo controlan las ACL del sistema de ficheros.
        os.chmod(directorio, MODO_DIRECTORIO)


def crear_fichero(ruta, contenido):
    """Crea un fichero nuevo sin sobrescribir nunca. Devuelve True si lo creó."""
    # O_EXCL hace la creación atómica: falla si el fichero ya existe.
    # O_BINARY (solo Windows) evita que se traduzcan los saltos de línea.
    banderas = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(ruta, banderas, MODO_FICHERO)
    except FileExistsError:
        print(f"  {ruta.name}: ya existe, no se toca")
        return False

    try:
        with os.fdopen(descriptor, "wb") as fichero:
            fichero.write(contenido)
        if ES_POSIX:
            # chmod explícito DESPUÉS de crear: con umask 077 el 0o644 que se
            # pasa a os.open saldría 0o600 y un contenedor sin privilegios no
            # podría leer el fichero por el bind mount. El directorio cerrado
            # (0o700) protege frente a otros usuarios del host. En Windows no
            # se aplican modos.
            os.chmod(ruta, MODO_FICHERO)
    except OSError:
        # No dejar a medias un fichero que acabamos de crear nosotros.
        try:
            ruta.unlink()
        except OSError:
            pass
        raise
    print(f"  {ruta.name}: creado")
    return True


def contenido_acl(contrasena_en_disco):
    """Construye redis_acl.conf a partir de los bytes de contrasena_redis.txt."""
    hash_contrasena = hashlib.sha256(contrasena_en_disco).hexdigest()
    return (
        "user default off\n"
        f"user aplicacion on #{hash_contrasena} ~* +@all -@admin -@dangerous\n"
    ).encode("utf-8")


def crear_secretos(directorio):
    """Crea lo que falte. Devuelve True si no hubo errores."""
    print("Creando secretos que falten en: " + texto_ascii(directorio))
    sin_errores = True
    try:
        preparar_directorio(directorio)
        for nombre, (generador, _patron) in SECRETOS.items():
            crear_fichero(directorio / nombre, generador().encode("ascii"))

        ruta_acl = directorio / FICHERO_ACL
        ruta_redis = directorio / FICHERO_REDIS
        if ruta_acl.exists():
            print(f"  {FICHERO_ACL}: ya existe, no se toca")
        elif not ruta_redis.is_file():
            # Se deriva de la contraseña tal como exista en disco.
            print(f"ERROR: falta {FICHERO_REDIS}, no se puede crear {FICHERO_ACL}")
            sin_errores = False
        else:
            crear_fichero(ruta_acl, contenido_acl(ruta_redis.read_bytes()))
    except OSError as error:
        print("ERROR: fallo de entrada/salida: " + texto_ascii(type(error).__name__))
        sin_errores = False
    return sin_errores


def diagnosticar_txt(datos, patron):
    """Devuelve el motivo por el que un .txt no cumple su patrón, o None."""
    if patron.fullmatch(datos):
        return None
    if datos.startswith(b"\xef\xbb\xbf"):
        return "tiene BOM"
    if b"\r" in datos:
        return "contiene retornos de carro"
    if b"\n" in datos:
        return "contiene saltos de linea"
    if len(datos) != 64:
        return "longitud incorrecta"
    return "contiene caracteres no permitidos"


def comprobar_modo(ruta, esperado, problemas):
    """Anota un problema si el modo de la ruta no es exactamente el esperado."""
    modo = ruta.stat().st_mode & 0o777
    if modo != esperado:
        problemas.append(f"{ruta.name}: modo {modo:#o}, se esperaba {esperado:#o}")


def comprobar(directorio, estado_git):
    """Verifica el conjunto completo. Devuelve True solo si todo es correcto."""
    print("Comprobando secretos en: " + texto_ascii(directorio))
    problemas = []

    if estado_git == NO_IGNORADO:
        problemas.append("el directorio de secretos no esta ignorado por Git")

    if not directorio.is_dir():
        problemas.append("el directorio de secretos no existe")

    valores = {}
    for nombre, (_generador, patron) in SECRETOS.items():
        ruta = directorio / nombre
        if not ruta.is_file() or ruta.is_symlink():
            problemas.append(f"{nombre}: falta o no es un fichero regular")
            continue
        datos = ruta.read_bytes()
        motivo = diagnosticar_txt(datos, patron)
        if motivo:
            problemas.append(f"{nombre}: {motivo}")
        valores[nombre] = datos

    ruta_acl = directorio / FICHERO_ACL
    if not ruta_acl.is_file() or ruta_acl.is_symlink():
        problemas.append(f"{FICHERO_ACL}: falta o no es un fichero regular")
    else:
        datos_acl = ruta_acl.read_bytes()
        encaje = PATRON_ACL.fullmatch(datos_acl)
        if not encaje:
            problemas.append(f"{FICHERO_ACL}: formato incorrecto")
        elif FICHERO_REDIS not in valores:
            problemas.append(f"{FICHERO_ACL}: no se puede verificar el hash sin {FICHERO_REDIS}")
        else:
            esperado = hashlib.sha256(valores[FICHERO_REDIS]).hexdigest().encode("ascii")
            if encaje.group(1) != esperado:
                problemas.append(f"{FICHERO_ACL}: el hash no coincide con {FICHERO_REDIS}")

    nombres = list(valores)
    for i, primero in enumerate(nombres):
        for segundo in nombres[i + 1:]:
            if valores[primero] == valores[segundo]:
                problemas.append(f"{primero} y {segundo}: valores duplicados")

    if ES_POSIX:
        if directorio.is_dir():
            comprobar_modo(directorio, MODO_DIRECTORIO, problemas)
        for nombre in list(SECRETOS) + [FICHERO_ACL]:
            ruta = directorio / nombre
            if ruta.is_file():
                comprobar_modo(ruta, MODO_FICHERO, problemas)
    else:
        print("  Se omite la comprobacion de modos (solo aplica en POSIX)")

    if problemas:
        print(f"FALLO: {len(problemas)} problema(s):")
        for problema in problemas:
            print("  - " + texto_ascii(problema))
        return False
    print("OK: todos los secretos son correctos")
    return True


def construir_parser():
    parser = argparse.ArgumentParser(
        description="Genera y comprueba los secretos de Canario. Nunca sobrescribe ficheros existentes.",
    )
    parser.add_argument(
        "--comprobar",
        action="store_true",
        help="solo comprueba, no crea nada",
    )
    parser.add_argument(
        "--directorio",
        type=pathlib.Path,
        default=DIRECTORIO_POR_DEFECTO,
        help="directorio de secretos a usar (por defecto, secrets/ en la raiz del repositorio; util para pruebas)",
    )
    return parser


def main():
    args = construir_parser().parse_args()
    directorio = args.directorio

    estado_git = guardia_git(directorio)

    sin_errores = True
    if not args.comprobar:
        if estado_git == NO_IGNORADO:
            print("ERROR: el directorio de secretos no esta ignorado por Git, no se crea nada")
            return 1
        sin_errores = crear_secretos(directorio)

    todo_correcto = comprobar(directorio, estado_git)
    return 0 if (sin_errores and todo_correcto) else 1


if __name__ == "__main__":
    sys.exit(main())
