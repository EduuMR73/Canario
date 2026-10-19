#!/usr/bin/env python3
"""Buzón de desarrollo de Canario: los últimos correos de Mailpit con sus
enlaces.

En desarrollo, los correos del registro del personal (verificación del email,
invitación y avisos) van a Mailpit, que no los entrega a nadie. Esta
herramienta los enseña en la terminal: fecha, destinatario, asunto y cada
enlace en su propia línea, para abrirlo con Ctrl+clic.

Uso (desde la raíz del repositorio, con la pila arrancada con
--profile desarrollo):
    python scripts/buzon.py                       los 10 últimos correos
    python scripts/buzon.py --limite 30           los 30 últimos (de 1 a 100)
    python scripts/buzon.py --proyecto NOMBRE     otro proyecto de Docker (pruebas)

Por qué así y no con la interfaz web de Mailpit (docs/threat-model.md, 8):
- Mailpit está solo en la red interna correo, sin salida a internet, y una red
  interna no puede publicar puertos. Publicar su interfaz obligaría a sacarlo
  de ella, y que un correo de prueba no pueda llegar a un buzón real pasaría
  a depender de su configuración.
- Una interfaz en 127.0.0.1 la podría leer cualquier proceso del anfitrión o
  una página web abierta en el navegador (DNS rebinding). En el buzón están
  los enlaces de activación: quien lo lea antes que el titular elige la
  contraseña y el TOTP de una cuenta ya aprobada.
- Esta herramienta lee el buzón desde un contenedor en esa red, así que solo
  la puede usar quien controla Docker, que ya puede leerlo todo. No abre
  ningún acceso nuevo.

Reglas:
- No borra ni envía nada: solo consulta la API HTTP de Mailpit.
- El contenedor que lee es desechable y va endurecido: sistema de ficheros de
  solo lectura, sin capacidades, sin nuevos privilegios y sin descargar
  imágenes (usa la de la API ya construida).
- Si no puede leer el buzón (Docker parado, la pila sin el perfil desarrollo
  o la imagen sin construir), lo dice y sale con código 1. Nunca da un buzón
  vacío por bueno cuando no lo ha podido leer.
- Los enlaces llevan tokens de un solo uso: la salida es solo para la
  terminal de quien la pide, en desarrollo.

Solo usa la biblioteca estándar.
"""

import argparse
import json
import re
import subprocess
import sys

PROYECTO_POR_DEFECTO = "canario"
LIMITE_POR_DEFECTO = 10
LIMITE_MAXIMO = 100
# Código de salida de docker run cuando el error es del propio Docker y no
# del programa del contenedor.
CODIGO_ERROR_DOCKER = 125
# Nombres de proyecto de Docker Compose: minúsculas, cifras, "_" y "-".
PATRON_PROYECTO = re.compile(r"[a-z0-9][a-z0-9_-]*")
# Un enlace: hasta el primer espacio. Los tokens van en el fragmento (#...).
PATRON_ENLACE = re.compile(r"https://\S+")

# Lo que se ejecuta dentro del contenedor, en la red correo. Lee el límite de
# la entrada estándar (nada del anfitrión va en la línea de órdenes) y
# devuelve JSON. La lista de Mailpit viene ordenada de la más nueva a la más
# antigua (swagger de Mailpit v1.31.6, GET /api/v1/messages).
LECTOR = r'''
import json, sys, urllib.request
limite = json.load(sys.stdin)
base = "http://mailpit:8025/api/v1"
lista = json.load(urllib.request.urlopen(f"{base}/messages?limit={limite}", timeout=10))
salida = []
for m in lista.get("messages") or []:
    d = json.load(urllib.request.urlopen(f"{base}/message/{m['ID']}", timeout=10))
    salida.append({"fecha": m.get("Created"), "para": [a["Address"] for a in d.get("To") or []],
                   "asunto": d.get("Subject"), "texto": d.get("Text")})
print(json.dumps(salida))
'''


def limite_valido(texto):
    valor = int(texto)
    if not 1 <= valor <= LIMITE_MAXIMO:
        raise argparse.ArgumentTypeError(f"entre 1 y {LIMITE_MAXIMO}")
    return valor


def proyecto_valido(texto):
    if not PATRON_PROYECTO.fullmatch(texto):
        raise argparse.ArgumentTypeError("solo minusculas, cifras, '_' y '-'")
    return texto


def fallo(motivo, detalle=""):
    print(f"ERROR: no se pudo leer el buzon de Mailpit: {motivo}", file=sys.stderr)
    if detalle:
        print(f"  {detalle}", file=sys.stderr)
    print("  Arranque la pila con: docker compose --profile desarrollo up -d --build --wait", file=sys.stderr)
    sys.exit(1)


def leer(proyecto, limite):
    orden = ["docker", "run", "--rm", "-i", "--pull", "never",
             "--network", f"{proyecto}_correo", "--read-only",
             "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
             "--entrypoint", "python", f"{proyecto}-api", "-c", LECTOR]
    try:
        # check=False explícito: el código de salida se revisa aquí.
        r = subprocess.run(orden, input=json.dumps(limite).encode("utf-8"), capture_output=True,
                           timeout=60, check=False)
    except FileNotFoundError:
        fallo("no se encuentra la orden docker")
    except subprocess.TimeoutExpired:
        fallo("Docker no respondio en 60 segundos")
    lineas = r.stderr.decode("utf-8", "replace").strip().splitlines()
    if r.returncode != 0:
        # Una línea con la causa, sin volcar una traza entera. Con 125 falla
        # Docker (la red o la imagen no existen) y la causa es su primera
        # línea; con otro código falla el lector (Mailpit no responde) y es la
        # última, la de la excepción. El 125 es el de los errores del propio
        # Docker (referencia de docker run en docker-cli, "Exit status";
        # comprobado: con la red sin crear, 125 y la causa en la primera línea).
        causa = (lineas[0] if r.returncode == CODIGO_ERROR_DOCKER else lineas[-1]) if lineas else ""
        fallo(f"codigo {r.returncode}", causa)
    try:
        return json.loads(r.stdout.decode("utf-8").strip().splitlines()[-1])
    except (ValueError, IndexError, UnicodeDecodeError):
        fallo("respuesta inesperada del lector")


def main():
    parser = argparse.ArgumentParser(description="Los ultimos correos de Mailpit con sus enlaces.")
    parser.add_argument("--limite", type=limite_valido, default=LIMITE_POR_DEFECTO,
                        help=f"cuantos correos (de 1 a {LIMITE_MAXIMO}, por defecto {LIMITE_POR_DEFECTO})")
    parser.add_argument("--proyecto", type=proyecto_valido, default=PROYECTO_POR_DEFECTO,
                        help="proyecto de Docker Compose (por defecto canario)")
    args = parser.parse_args()
    # Un carácter que la consola de Windows no sepa escribir sale como "?" en
    # vez de cortar la salida a medias.
    sys.stdout.reconfigure(errors="replace")

    correos = leer(args.proyecto, args.limite)
    if not correos:
        print("El buzon esta vacio.")
        return
    print(f"{len(correos)} correo(s), del mas nuevo al mas antiguo:")
    for numero, correo in enumerate(correos, start=1):
        print()
        print(f"[{numero}] {correo.get('fecha') or '-'}")
        print(f"    Para:   {', '.join(correo.get('para') or []) or '-'}")
        print(f"    Asunto: {correo.get('asunto') or '-'}")
        enlaces = PATRON_ENLACE.findall(correo.get("texto") or "")
        for enlace in enlaces:
            print(f"    {enlace}")
        if not enlaces:
            print("    (sin enlaces)")


if __name__ == "__main__":
    main()
