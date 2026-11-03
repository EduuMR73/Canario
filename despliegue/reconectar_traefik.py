#!/usr/bin/env python3
"""Reconecta el Traefik de Dokploy a la red edge de Canario con su IP fija.

Por qué existe: Dokploy v0.30.10, cada vez que recrea su Traefik (al
actualizarse o al cambiar sus ajustes), lo borra y lo crea solo en
dokploy-network (initializeStandaloneTraefik, en
packages/server/src/setup/traefik-setup.ts), y no tiene ninguna opción para
añadir redes. Sin la conexión a canario_edge con 10.88.1.2, los tres nombres de
Canario dejan de funcionar. No hay forma declarativa de evitarlo, así que este
script compara el estado real con el deseado y lo corrige (docs/operacion.md,
docs/threat-model.md 6.20).

Compara estado y no escucha eventos (docker events): un evento perdido o un
arranque a mitad de una recreación no lo dejan mal, porque cada ejecución mira
cómo está todo ahora, sin depender de la historia.

Lo lanza cada minuto canario-reconectar-traefik.timer, como root, desde una
copia en /usr/local/sbin que solo root puede cambiar. Nunca desde el
repositorio: un fichero que un usuario puede editar y que root ejecuta es una
vía de escalada (ATT&CK T1543.002).

Qué hace:
* conectado con la IP correcta: nada, y no escribe nada (corre cada minuto);
* desconectado: lo conecta con la IP;
* conectado con otra IP: lo desconecta y lo vuelve a conectar, solo en esa red;
* la IP la tiene otro contenedor: no toca nada y lo dice, con su nombre;
* el contenedor no existe: no toca nada y lo dice (código 3).

Cada reconexión deja una línea RECONECTADO con prioridad warning en el journal:
que Traefik se recree es una señal que alguien tiene que poder ver, no algo que
se arregla en silencio. Cada fallo sale por stderr con prioridad err y un
código distinto de 0, así que la unidad queda fallida y se ve.

Códigos de salida: 0 bien (ya estaba o se reconectó), 1 error, 2 argumentos no
válidos, 3 el contenedor no existe.

Solo usa la biblioteca estándar. Las órdenes de docker van como lista de
argumentos, nunca por una shell.
"""
import argparse
import ipaddress
import json
import os
import subprocess
import sys

# Plazo de cada orden de docker: si el demonio no contesta, se falla de forma
# visible en vez de colgar la unidad.
PLAZO = 30

# Prioridades de syslog (sd-daemon(3)). systemd las lee del principio de cada
# línea si la salida va al journal, y las quita del texto.
AVISO = 4
ERROR = 3


class Fallo(Exception):
    """Un error que se informa y termina con el código indicado."""

    def __init__(self, mensaje, codigo=1):
        super().__init__(mensaje)
        self.codigo = codigo


def escribir(prioridad, texto, flujo):
    # JOURNAL_STREAM solo existe si systemd conecta la salida al journal: así,
    # ejecutado a mano, el texto sale sin el prefijo <N>.
    prefijo = f"<{prioridad}>" if os.environ.get("JOURNAL_STREAM") else ""
    print(prefijo + texto, file=flujo, flush=True)


def docker(*argumentos):
    try:
        r = subprocess.run(["docker", *argumentos], capture_output=True, text=True,
                           timeout=PLAZO, check=False)
    except FileNotFoundError:
        raise Fallo("no se encuentra la orden docker") from None
    except subprocess.TimeoutExpired:
        raise Fallo(f"docker {argumentos[0]} no responde en {PLAZO} s") from None
    return r


def inspeccionar_red(red):
    r = docker("network", "inspect", red)
    if r.returncode != 0:
        raise Fallo(f"no existe la red {red}: {r.stderr.strip()}")
    datos = json.loads(r.stdout)[0]
    subredes = [ipaddress.ip_network(c["Subnet"]) for c in (datos.get("IPAM") or {}).get("Config") or []
                if "Subnet" in c]
    # Quién tiene cada IP en esta red: nombre del contenedor e IP sin máscara.
    ocupantes = {}
    for ident, c in (datos.get("Containers") or {}).items():
        ip = (c.get("IPv4Address") or "").split("/")[0]
        if ip:
            ocupantes[ip] = (ident, c.get("Name", ident))
    return subredes, ocupantes


def ip_en_la_red(contenedor, red):
    """(id del contenedor, IP que tiene en la red o None si no está conectado)."""
    r = docker("container", "inspect", contenedor)
    if r.returncode != 0:
        raise Fallo(f"no existe el contenedor {contenedor}", codigo=3)
    datos = json.loads(r.stdout)[0]
    conexion = (datos.get("NetworkSettings") or {}).get("Networks", {}).get(red)
    if conexion is None:
        return datos["Id"], None
    return datos["Id"], conexion.get("IPAddress") or None


def conectar(contenedor, red, ip):
    r = docker("network", "connect", "--ip", ip, red, contenedor)
    if r.returncode != 0:
        raise Fallo(f"no se pudo conectar {contenedor} a {red} con {ip}: {r.stderr.strip()}")


def reconciliar(contenedor, red, ip):
    subredes, ocupantes = inspeccionar_red(red)
    # La IP tiene que caber en la red: si no, docker fallaría con un mensaje
    # menos claro, o la red no es la que se cree.
    if not any(ipaddress.ip_address(ip) in s for s in subredes):
        raise Fallo(f"la IP {ip} no está en la red {red} ({', '.join(map(str, subredes)) or 'sin subred'})")

    ident, actual = ip_en_la_red(contenedor, red)
    if actual == ip:
        return

    ocupante = ocupantes.get(ip)
    if ocupante is not None and ocupante[0] != ident:
        # No se desconecta a nadie: si otro contenedor tiene la IP de Traefik,
        # o es un error de configuración o alguien intenta hacerse pasar por
        # Traefik ante Caddy. Las dos cosas las tiene que ver una persona.
        raise Fallo(f"la IP {ip} de {red} la tiene el contenedor {ocupante[1]}: no se toca nada")

    if actual is None:
        antes = "desconectado"
    else:
        antes = f"otra_ip={actual}"
        r = docker("network", "disconnect", red, contenedor)
        if r.returncode != 0:
            raise Fallo(f"no se pudo desconectar {contenedor} de {red}: {r.stderr.strip()}")
    conectar(contenedor, red, ip)

    # Se comprueba el resultado en vez de suponerlo.
    _, despues = ip_en_la_red(contenedor, red)
    if despues != ip:
        raise Fallo(f"tras conectar, {contenedor} tiene {despues} en {red} en vez de {ip}")
    escribir(AVISO, f"RECONECTADO: contenedor={contenedor} red={red} ip={ip} antes={antes}", sys.stdout)


def ip_valida(texto):
    try:
        return str(ipaddress.IPv4Address(texto))
    except ValueError:
        raise argparse.ArgumentTypeError(f"no es una IPv4: {texto!r}") from None


def main():
    parser = argparse.ArgumentParser(description="Reconecta un contenedor a una red con una IP fija.")
    parser.add_argument("--contenedor", required=True)
    parser.add_argument("--red", required=True)
    parser.add_argument("--ip", required=True, type=ip_valida)
    args = parser.parse_args()
    try:
        reconciliar(args.contenedor, args.red, args.ip)
    except Fallo as e:
        escribir(ERROR, f"ERROR: {e}", sys.stderr)
        return e.codigo
    return 0


if __name__ == "__main__":
    sys.exit(main())
