#!/usr/bin/env python3
"""Pruebas de producción de Canario: P0, P1, P1b, P2, P3, P4, P5 y P6 de
docs/informe-pruebas.md (§2, "En producción"), según el plan v3
(plan-produccion-v3.md). Se ejecuta en el host, desde la raíz del repo, en
PowerShell 5. Los comandos exactos están en tests/produccion/README.md.

Reglas que el script impone por sí mismo:
* el destino por defecto es la pila local (https://localhost:8443 y 8444);
  producción solo con --destino produccion y --franja-autorizada HH:MM-HH:MM
  (UTC), y el script se niega fuera de esa franja;
* topes fijos dentro del script (TOPE_*): se niega a superarlos;
* nunca ejecuta sudo ni abre ssh hacia el VPS. Lo que necesita sudo (P4, la
  relectura de la API antes de P6 y Q-12) se hace en modo manual: el autor
  pega en su propia sesión el comando fijo del README y entrega el bloque con
  --p4-entrada o --q12-entrada. De "ssh -G ovh" (que solo lee la
  configuración local, sin conectar) se leen solo user y hostname, para el
  anti-fuga, y no se imprimen nunca;
* ninguna credencial: las peticiones son seguimiento con códigos inexistentes
  generados en memoria (nunca se escriben), una denuncia no válida contra una
  empresa inexistente, /salud, el CSS estático y lecturas;
* las IP completas solo van a %TEMP%\\canario_produccion_privado\\ips.txt; la
  salida publicable pasa por el anti-fuga con centinela;
* RESULTADO GLOBAL: OK solo si todas las pruebas pedidas dan PASA (o HECHO en
  P0), el anti-fuga da PASA y git status no ha cambiado. Código 0 solo si OK.

Solo biblioteca estándar. Las funciones puras están separadas de la E/S y
las prueba tests/produccion/test_lanzar.py, sin red ni Docker.
"""
import argparse
import ast
import base64
import collections
import csv
import datetime
import email.utils
import hashlib
import heapq
import hmac
import http.client
import ipaddress
import json
import math
import os
import pathlib
import queue
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

RAIZ = pathlib.Path(__file__).resolve().parent.parent.parent
TEMP = pathlib.Path(tempfile.gettempdir())
# Carpeta privada: IP completas, bloques pegados del VPS, sal de las vecinas.
# Nunca se publica nada de aquí (plan §5.5).
PRIVADO = TEMP / "canario_produccion_privado"

PASA, FALLA, SIN_CONCLUSION, PARADA, HECHO = "PASA", "FALLA", "SIN CONCLUSION", "PARADA", "HECHO"
VEREDICTOS_OK = (PASA, HECHO)


class Parada(Exception):
    """Algo impide medir con garantías: no hay veredicto y el resultado es NO OK."""


# ---------------------------------------------------------------------------
# Topes fijos (plan §4, punto 10, y tabla del §2). El script se niega a
# superarlos: nada de lo que se pase por argumentos los cambia.
# ---------------------------------------------------------------------------
TOPE_TASA_A = 20                 # peticiones por segundo de A en P6
TOPE_DURACION_S = 120            # duración de la carga de P6
TOPE_PETICIONES_A = 2400         # peticiones de A en P6
TOPE_EN_VUELO = 10               # conexiones de A en vuelo en P6
TOPE_TASA_B = 0.5                # peticiones por segundo de B (P5 y P6)
TOPE_PERIODO_SONDA_MIN_S = 1.0   # una sonda por vecina cada segundo como mucho
TOPE_P1_A, TOPE_P1_B = 70, 5
TOPE_P1B = 70
TOPE_P2 = 11
TOPE_P5_S = 600
LLEGADAS_P5 = 300                # 0,5/s durante 600 s
MINIMO_RESPUESTAS_P5 = 290       # de 300; con menos, SIN CONCLUSION (QA, punto 3)
TOPE_A1 = 10                     # peticiones de CSS por A1
PLAZO_SOCKET_S = 10
PLAZO_JOIN_S = 150

# Perfil de P6 (plan §4, punto 2).
TASA_INICIAL_A = 1
RAMPA_S = 60
PERIODO_B_S = 2.0
MUESTRAS_B_P6 = 60
PERIODO_SONDA_S = 2.0
LINEA_BASE_S = 300
POST_CARGA_S = 60
LENTA_S = 5.0
FACTOR_P95 = 3
ERRORES_SEGUIDOS_B = 3
ERRORES_SEGUIDOS_A = 10
# D10, guarda de frontera: duración máxima supuesta de una petición más 1 ms,
# para que una de 1,000 s lanzada en el último instante permitido termine
# antes de la frontera (QA6).
GUARDA_DURACION_S = 1.0
GUARDA_MARGEN_S = 0.001
# Q-13, retraso del planificador.
RETRASO_UMBRAL_S = 0.5
RETRASO_FRACCION_MAX = 0.01
RETRASO_MAXIMO_S = 2.0
# Franja de P6 en hora UTC del servidor (Q-8 y N7) y su duración estimada:
# 10,6 min de fases más 2 min de margen.
P6_INICIO_MIN_S = 22 * 3600
P6_INICIO_MAX_S = 22 * 3600 + 47 * 60
P6_DURACION_S = 12.6 * 60
# Duración estimada de cada prueba, para no empezar si no cabe en la franja.
DURACION_ESTIMADA_S = {"p0": 150, "p1": 160, "p1b": 230, "p2": 60, "p3": 60, "p5": TOPE_P5_S + 60}

# A1, reloj del servidor (Q-2).
SEPARACION_A1_S = 1.1
ANCHURA_A1_MAX_S = 1.5
# P2 y P3.
MARGEN_HORA_P2_S = 600
LIMITE_CUERPO = 131072           # 128 KiB, en la API y en Caddy
PLAZO_413_S = 0.5
VENTANA_SEGUIMIENTO_S = 60
VENTANA_DENUNCIA_S = 3600
LIMITE_SEGUIMIENTO = 60

# ---------------------------------------------------------------------------
# Congelación de P6 (plan §4, puntos 1 y 4). Las rellena Eduardo en el commit
# "congelación de P6", con push ANTES de medir (E3). Mientras alguna valga
# None, P6 da PARADA: un umbral sin congelar se podría ajustar después de ver
# los datos.
# ---------------------------------------------------------------------------
P5_P50_MS = 428.0
P5_P95_MS = 634.4
P5_MAX_MS = 961.7
P6_P50_B_MAX_MS = 856.0          # 2 x P5_P50_MS, escrito como literal
HMAC_VECINAS = "210d0bba62fb47aca06fded4221abf56685b24cf31f2c17c84740b040abd16d2"  # HMAC-SHA256(sal, bytes del fichero de vecinas), en hexadecimal

# ---------------------------------------------------------------------------
# Destinos. Producción solo con --destino produccion (plan §1).
# ---------------------------------------------------------------------------
DESTINOS = {
    "local": {"host_api": "localhost", "puerto_api": 8443, "host_web": "localhost", "puerto_web": 8444},
    "produccion": {"host_api": "canario-api.eduumr.dev", "puerto_api": 443,
                   "host_web": "canario.eduumr.dev", "puerto_web": 443},
}
RUTA_CSS = "/estatico/canario.css"   # file_server de Caddy (proxy/comun.caddy:252-255)
RUTA_SEGUIMIENTO = "/v1/seguimiento"
RUTA_DENUNCIA = "/v1/empresas/00000000000000000000000000000000/denuncias"
RUTA_SALUD = "/salud"
TIPO_JSON = ("Content-Type", "application/json")
# Comando del VPS (docs/operacion.md:90-91 y :185): la pila corre desde ~/apps/canario.
COMPOSE_VPS = "sudo docker compose -f docker-compose.yml -f compose.produccion.yaml"

# ---------------------------------------------------------------------------
# Literales (de las baterías, no de la app; plan §2, "Literales").
# ---------------------------------------------------------------------------
# tests/security/verificar_denuncia.py:317, 347 y 396.
CUERPO_404 = '{"detalle": "código de seguimiento no válido"}'.encode()
CUERPO_422 = '{"detalle": "petición no válida"}'.encode()
CUERPO_429 = '{"detalle": "demasiadas peticiones; inténtelo de nuevo más tarde"}'.encode()
# tests/security/verificar_despliegue.py:146 y :137.
CUERPO_413 = '{"detalle": "cuerpo de la petición demasiado grande"}'.encode()
CUERPO_SALUD = b'{"estado":"ok"}'
# tests/security/verificar_denuncia.py:324-330: las cabeceras de seguridad de
# Caddy que lleva también el 429 (es_429).
CABECERAS_SEGURIDAD = {
    "strict-transport-security": "max-age=63072000",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    "cache-control": "no-store",
}
# La línea de límites de producción: TEXTO_LIMITES_PRODUCCION de
# tests/security/verificar_denuncia.py:386-387 (plan, Discrepancias, Q-6).
TEXTO_LIMITES_PRODUCCION = ("LIMITES (por defecto): acceso=10/300 cuenta=60/60 denuncia=10/3600 destinatario=3/900 "
                            "destinatario_dia=10/86400 mensajes=30/3600 otras=60/60 registro=10/3600 seguimiento=60/60")
# Control de P4 en la pila local: límites relajados como
# tests/funcionales/lanzar.py:75-76 (y su override en :329), y la línea que la
# API escribe con ellos: TEXTO_LIMITES_PRUEBA de verificar_denuncia.py:383-385.
LIMITES_CONTROL_P4 = ("denuncia=1000/3600,seguimiento=1000/60,mensajes=1000/3600,acceso=1000/300,otras=1000/60,"
                      "cuenta=1000/60,registro=1000/3600,destinatario=1000/900,destinatario_dia=1000/86400")
TEXTO_LIMITES_CONTROL_P4 = ("LIMITES (configurados): acceso=1000/300 cuenta=1000/60 denuncia=1000/3600 "
                            "destinatario=1000/900 destinatario_dia=1000/86400 mensajes=1000/3600 otras=1000/60 "
                            "registro=1000/3600 seguimiento=1000/60")
# P1b: X-Forwarded-For de los tres rangos de documentación (informe l.94).
REDES_XFF = (ipaddress.ip_network("192.0.2.0/24"), ipaddress.ip_network("198.51.100.0/24"),
             ipaddress.ip_network("203.0.113.0/24"))
# Q-12: conjuntos cerrados del evento (app/limitador.py:216-229), escritos aquí
# como literales: solo sirven para rechazar una línea fuera de formato.
CAUSAS_EVENTO = ("pool_agotado", "permiso", "plazo", "conexion", "otra")
ESPERAS_EVENTO = ("<0.25", "0.25-0.5", ">0.5")
# Patrón de un código de seguimiento (tests/estres/lanzar.py:3322): el anti-fuga
# lo busca en toda la salida.
PATRON_CODIGO = re.compile(rb"(?i:[A-Z2-7]{4}(?:-[A-Z2-7]{4}){7})|[A-Z2-7]{32}")


# ===========================================================================
# Funciones copiadas (no importadas) de otras baterías, con sus mismos casos
# literales en las unitarias (plan §1).
# ===========================================================================
def ventana_de_peticion(inicio_s, fin_s, ventana_s):
    """Copia de tests/estres/lanzar.py:3506-3513. (índice de ventana por la
    hora de INICIO, ambigua). Una petición es ambigua si el intervalo
    [inicio, fin] cruza una frontera de ventana: no se sabe en qué contador
    cayó."""
    a, b = math.floor(inicio_s / ventana_s), math.floor(fin_s / ventana_s)
    return a, a != b


def contar_por_ip_ventana(filas, ventana_s, aceptado):
    """Copia de tests/estres/lanzar.py:3516-3554. Recuento por (IP, ventana).
    filas: dicts con ip, inicio, fin (segundos desde 1970) y estado. Solo
    cuenta el estado ACEPTADO; los 503 van aparte y todo lo demás en "otros".
    Cada par lleva sus peticiones ordenadas por inicio, para el control
    positivo, y las ambiguas que cruzan su frontera inicial. "hasta_ambiguas"
    (B1(ii)): la ventana de fin de cada aceptada ambigua que empieza en el
    par, para asignacion_factible."""
    pares = {}

    def par(clave):
        return pares.setdefault(clave, {"aceptadas": 0, "aceptadas_ambiguas": 0, "aceptadas_ambiguas_inicio": 0,
                                        "n429": 0, "n503": 0, "otros": 0, "ambiguas": 0, "ambiguas_inicio": 0,
                                        "peticiones": [], "hasta_ambiguas": []})

    for f in filas:
        ventana, ambigua = ventana_de_peticion(f["inicio"], f["fin"], ventana_s)
        p_ = par((f["ip"], ventana))
        p_["peticiones"].append((f["inicio"], f["estado"], ambigua))
        if ambigua:
            p_["ambiguas"] += 1
            siguiente = par((f["ip"], ventana + 1))
            siguiente["ambiguas_inicio"] += 1
            if f["estado"] == aceptado:
                siguiente["aceptadas_ambiguas_inicio"] += 1
                p_["hasta_ambiguas"].append(math.floor(f["fin"] / ventana_s))
        if f["estado"] == aceptado:
            p_["aceptadas_ambiguas" if ambigua else "aceptadas"] += 1
        elif f["estado"] == 429:
            p_["n429"] += 1
        elif f["estado"] == 503:
            p_["n503"] += 1
        else:
            p_["otros"] += 1
    for p_ in pares.values():
        p_["peticiones"].sort()
    return pares


def retry_after_valido(valor, ventana_s):
    """Copia de tests/estres/lanzar.py:3557-3561. Retry-After de un 429: un
    entero entre 1 y la ventana. El -1 que se anota cuando falta no vale."""
    return (isinstance(valor, (int, float)) and not isinstance(valor, bool) and float(valor).is_integer()
            and 1 <= valor <= ventana_s)


def asignacion_factible(no_ambiguas, ambiguas, limite):
    """Copia de tests/estres/lanzar.py:3570-3611. B1(ii): None si las aceptadas
    ambiguas ([(a, b)]) se pueden repartir entre los contadores de a a b sin
    que ninguno pase de `limite` junto con las no ambiguas ({ventana: n}); si
    no, la ventana del primer conflicto. EDF con montón."""
    ventanas = set(no_ambiguas) | {a for a, _ in ambiguas}
    if not ventanas:
        return None
    por_nacer = sorted(ambiguas)
    monton, i, w = [], 0, min(ventanas)
    while True:
        while i < len(por_nacer) and por_nacer[i][0] <= w:
            heapq.heappush(monton, por_nacer[i][1])
            i += 1
        # Capacidad negativa: las no ambiguas ya pasan del límite (conflicto).
        capacidad = limite - no_ambiguas.get(w, 0)
        if capacidad < 0:
            return w
        while monton and capacidad > 0:
            heapq.heappop(monton)
            capacidad -= 1
        if monton and monton[0] <= w:
            return w
        if monton:
            w += 1
            continue
        siguientes = [x for x in no_ambiguas if x > w]
        if i < len(por_nacer):
            siguientes.append(por_nacer[i][0])
        if not siguientes:
            return None
        w = min(siguientes)


def veredicto_l3(pares, limite, retry_invalidos=0):
    """Copia de tests/estres/lanzar.py:3614-3650. Oráculo por IP y ventana, C1
    en tres niveles (B1(ii)). FALLA: algún par con más de `limite` aceptadas
    NO ambiguas, ninguna asignación factible de las ambiguas de una IP, o
    algún 429 sin Retry-After válido. SIN CONCLUSION: una aceptada ambigua
    cruza dos fronteras, o solo se pasa de `limite` contando las ambiguas.
    PASA en otro caso."""
    pasan = sorted(((c, p_["aceptadas"]) for c, p_ in pares.items() if p_["aceptadas"] > limite))
    if pasan:
        return "FALLA", f"{len(pasan)} pares IP-ventana con mas de {limite} aceptadas no ambiguas (ejemplo {pasan[0]})"
    por_ip = {}
    for (ip, w), p_ in pares.items():
        no_ambiguas, ambiguas = por_ip.setdefault(ip, ({}, []))
        no_ambiguas[w] = p_["aceptadas"]
        ambiguas.extend((w, b) for b in p_["hasta_ambiguas"])
    for ip in sorted(por_ip, key=str):
        conflicto = asignacion_factible(*por_ip[ip], limite)
        if conflicto is not None:
            return "FALLA", f"ninguna asignacion factible de las ambiguas (IP {ip}, ventana {conflicto})"
    if retry_invalidos:
        return "FALLA", f"{retry_invalidos} respuestas 429 sin Retry-After valido"
    if any(b >= w + 2 for (_, w), p_ in pares.items() for b in p_["hasta_ambiguas"]):
        return "SIN CONCLUSION", "una aceptada cruza dos fronteras: la regla de PASA no la cubre"
    # Cuentan tambien las aceptadas ambiguas de la ventana anterior, que pudieron
    # caer en esta (H11), igual que control_l3 con ambiguas_inicio.
    dudosos = [c for c, p_ in pares.items()
               if p_["aceptadas"] + p_["aceptadas_ambiguas"] + p_["aceptadas_ambiguas_inicio"] > limite]
    if dudosos:
        return "SIN CONCLUSION", f"{len(dudosos)} pares solo pasan de {limite} contando peticiones ambiguas"
    return "PASA", f"ningun par IP-ventana pasa de {limite} aceptadas ({sum(1 for x in pares.values() if x['peticiones'])} pares con peticiones)"


def control_l3(pares, limite):
    """Copia de tests/estres/lanzar.py:3653-3670. Control positivo: en cada par
    no son 429 las primeras (limite - ambiguas al inicio del par - peticiones
    previas del par con estado 0 o 503) peticiones NO ambiguas. Devuelve
    (ok, motivos)."""
    motivos = []
    for clave, p_ in sorted(pares.items()):
        previas, j = 0, 0
        for _, estado, ambigua in p_["peticiones"]:
            if ambigua:
                continue
            if estado == 429 and j < limite - p_["ambiguas_inicio"] - previas:
                motivos.append(f"{clave}: 429 en la peticion no ambigua {j + 1} (protegidas "
                               f"{limite - p_['ambiguas_inicio'] - previas})")
                break
            if estado in (0, 503):
                previas += 1
            j += 1
    return not motivos, motivos[:5]


def maximo_deslizante(inicios_por_ip, tramo_s=60):
    """Copia de tests/estres/lanzar.py:3673-3686. Máximo de peticiones
    aceptadas por una IP en cualquier tramo de tramo_s segundos (el defecto de
    la ventana fija). Devuelve (máximo, ip)."""
    mejor = (0, None)
    for ip, inicios in inicios_por_ip.items():
        inicios = sorted(inicios)
        izquierda = 0
        for derecha, t in enumerate(inicios):
            while t - inicios[izquierda] >= tramo_s:
                izquierda += 1
            if derecha - izquierda + 1 > mejor[0]:
                mejor = (derecha - izquierda + 1, ip)
    return mejor


def percentil(ordenados, q):
    """Copia de tests/estres/lanzar.py:612-617. Percentil por rango más
    cercano sobre una lista ya ordenada."""
    if not ordenados:
        return None
    rango = max(1, math.ceil(q / 100 * len(ordenados)))
    return ordenados[rango - 1]


def formas_codificadas(valor):
    """Copia de tests/estres/lanzar.py:4250-4256. Un literal tal cual y en sus
    formas codificadas: URL y JSON escapado. Sin duplicados."""
    import urllib.parse
    formas = {valor, urllib.parse.quote(valor, safe=""), urllib.parse.quote_plus(valor),
              json.dumps(valor)[1:-1], json.dumps(valor, ensure_ascii=False)[1:-1]}
    return sorted(formas)


def buscar_en_bytes(contenido, literales, patrones=()):
    """Copia de tests/estres/lanzar.py:4259-4270. Literales (con sus formas
    codificadas) y patrones (regex de bytes) que aparecen en contenido.
    Devuelve los nombres encontrados, sin repetir."""
    encontrados = []
    for nombre, valor in literales.items():
        if any(forma.encode("utf-8") in contenido for forma in formas_codificadas(valor)):
            encontrados.append(nombre)
    for nombre, patron in patrones:
        if patron.search(contenido):
            encontrados.append(nombre)
    return encontrados


def escanear_fichero(ruta, literales, patrones=(), trozo=8 * 1024 * 1024, solape=512):
    """Copia de tests/estres/lanzar.py:4273-4286: buscar_en_bytes por trozos
    con solape."""
    encontrados = set()
    cola = b""
    with open(ruta, "rb") as fichero:
        while True:
            datos = fichero.read(trozo)
            if not datos:
                break
            bloque = cola + datos
            encontrados.update(buscar_en_bytes(bloque, literales, patrones))
            cola = bloque[-solape:]
    return sorted(encontrados)


def veredicto_fuga(hallazgos, centinela_visto):
    """Copia de tests/estres/lanzar.py:4313-4320. Si el escáner no encuentra
    su centinela, no es de fiar (SIN CONCLUSION); si encuentra algo, SIN
    CONCLUSION; si no, PASA."""
    if not centinela_visto:
        return "SIN CONCLUSION", "el escaner no encontro su centinela: no es de fiar"
    if hallazgos:
        return "SIN CONCLUSION", f"valores sembrados en ficheros guardados: {hallazgos}"
    return "PASA", "ningun valor sembrado en los ficheros guardados"


def codigo_inexistente():
    """Copia de tests/security/verificar_denuncia.py:2380-2382. Código con el
    formato válido que no existe. Vive solo en memoria: nunca se escribe en la
    salida (y el anti-fuga busca su patrón)."""
    aleatorio = base64.b32encode(secrets.token_bytes(20)).decode("ascii")
    return "-".join(aleatorio[i:i + 4] for i in range(0, 32, 4))


def es_429(respuesta, ventana):
    """Copia de tests/security/verificar_denuncia.py:2385-2392. 429 con el
    cuerpo exacto, las cabeceras de seguridad de Caddy y un Retry-After entre
    1 y la ventana. Un 429 de un rateLimit de Traefik no lo cumple (S2)."""
    cabeceras = respuesta.get("cabeceras", {})
    tras = cabeceras.get("retry-after", "")
    return (respuesta.get("estado") == 429 and respuesta.get("cuerpo") == CUERPO_429
            and tras.isdigit() and 1 <= int(tras) <= ventana
            and all(cabeceras.get(k) == v for k, v in CABECERAS_SEGURIDAD.items()))


def segundos_para_frontera(ahora_servidor, ventana):
    """Adaptación de esperar_ventana (tests/security/verificar_denuncia.py:2369-2377
    y tests/estres/lanzar.py:4642-4649): lo que queda hasta la frontera
    siguiente de la ventana, pero en hora del SERVIDOR (local + d, A1) y no
    con el reloj del anfitrión, que en producción no es el del VPS."""
    return ventana - ahora_servidor % ventana


# ===========================================================================
# Funciones puras propias
# ===========================================================================
# --- relojes (Q-3) -----------------------------------------------------------
class Reloj:
    """Un solo ancla por ejecución: el instante es ancla_time + (perf_counter -
    ancla_perf). time.time() se puede ajustar a saltos (NTP); perf_counter
    no, y es el que mide las duraciones."""

    def __init__(self):
        self.ancla_time = time.time()
        self.ancla_perf = time.perf_counter()

    def ahora(self):
        return self.ancla_time + (time.perf_counter() - self.ancla_perf)

    def dormir_hasta(self, instante, evento=None):
        """Duerme hasta el instante (en este reloj). False si el evento se
        activa antes."""
        while True:
            resto = instante - self.ahora()
            if resto <= 0:
                return True
            if evento is not None and evento.is_set():
                return False
            time.sleep(min(resto, 0.05))


def info_relojes():
    """Resolución e implementación de los dos relojes (Q-3), para la salida."""
    info = {}
    for nombre in ("perf_counter", "time"):
        c = time.get_clock_info(nombre)
        info[nombre] = {"implementacion": c.implementation, "resolucion": c.resolution,
                        "monotono": c.monotonic, "ajustable": c.adjustable}
    return info


# --- franjas (S3, Q-8 y N7) ---------------------------------------------------
def leer_franja(texto):
    """HH:MM-HH:MM en UTC -> (inicio, fin) en segundos del día. No cruza las
    00:00 UTC (el cambio de sal, docs/threat-model.md:196)."""
    encaje = re.fullmatch(r"(\d{2}):(\d{2})-(\d{2}):(\d{2})", texto or "")
    if encaje is None:
        raise Parada("--franja-autorizada tiene que ser HH:MM-HH:MM en UTC")
    h1, m1, h2, m2 = (int(x) for x in encaje.groups())
    if h1 > 23 or h2 > 23 or m1 > 59 or m2 > 59:
        raise Parada("--franja-autorizada fuera de rango")
    inicio, fin = h1 * 3600 + m1 * 60, h2 * 3600 + m2 * 60
    if inicio >= fin:
        raise Parada("--franja-autorizada tiene que empezar antes de acabar y no cruzar las 00:00 UTC")
    return inicio, fin


def comprobar_franja(franja, inicio_epoch, fin_epoch):
    """Parada si [inicio, fin] (hora UTC del servidor) no cabe en la franja
    autorizada del mismo día."""
    if math.floor(inicio_epoch / 86400) != math.floor(fin_epoch / 86400):
        raise Parada("la prueba cruzaria las 00:00 UTC")
    if not (franja[0] <= inicio_epoch % 86400 and fin_epoch % 86400 <= franja[1]):
        raise Parada("fuera de --franja-autorizada (inicio y fin estimado, hora UTC del servidor)")


def comprobar_franja_p6(ahora_local, d_min, d_max, franja):
    """P6 empieza entre las 22:00:00 y las 22:47:00 UTC del servidor y, además,
    todo P6 (inicio + 12,6 min) cabe en --franja-autorizada. Las dos
    condiciones; si falla una, Parada. Con d_min para el "no antes" y d_max
    para el "no después", que es lo conservador."""
    temprano, tardio = ahora_local + d_min, ahora_local + d_max
    if temprano % 86400 < P6_INICIO_MIN_S:
        raise Parada("P6 no empieza antes de las 22:00:00 UTC (hora del servidor)")
    if tardio % 86400 > P6_INICIO_MAX_S:
        raise Parada("P6 no empieza despues de las 22:47:00 UTC (hora del servidor)")
    comprobar_franja(franja, temprano, tardio + P6_DURACION_S)


# --- A1, A2 y A3 (Q-2) ---------------------------------------------------------
def intervalo_a1(muestras):
    """muestras: (t_inicio, t_fin, Date en segundos enteros). Cada una cumple
    Date - t_fin <= d <= Date + 1 - t_inicio (el Date es el segundo truncado
    de algún instante dentro de la petición). Devuelve la intersección
    (d_min, d_max) o None si queda vacía."""
    if not muestras:
        return None
    d_min = max(fecha - fin for _, fin, fecha in muestras)
    d_max = min(fecha + 1 - inicio for inicio, _, fecha in muestras)
    return (d_min, d_max) if d_min <= d_max else None


def evaluar_a1(muestras):
    """(veredicto, intervalo, texto). Vacía o más ancha de 1,5 s: SIN CONCLUSION."""
    intervalo = intervalo_a1(muestras)
    if intervalo is None:
        return SIN_CONCLUSION, None, f"A1: interseccion vacia con {len(muestras)} muestras"
    if intervalo[1] - intervalo[0] > ANCHURA_A1_MAX_S:
        return SIN_CONCLUSION, intervalo, f"A1: intervalo de {intervalo[1] - intervalo[0]:.3f} s, mas de {ANCHURA_A1_MAX_S} s"
    return PASA, intervalo, f"A1: d en [{intervalo[0]:.3f}; {intervalo[1]:.3f}] s con {len(muestras)} muestras"


def combinar_a1(inicio, fin):
    """A1 al principio y al final. Si no se solapan, None (SIN CONCLUSION). Si
    se solapan, la envolvente: es la cota conservadora (más ambiguas, nunca
    menos) si el desfase derivó algo entre las dos medidas."""
    if inicio is None or fin is None or max(inicio[0], fin[0]) > min(inicio[1], fin[1]):
        return None
    return min(inicio[0], fin[0]), max(inicio[1], fin[1])


def intervalo_servidor(inicio, fin, d_min, d_max):
    """[t_inicio + d_min, t_fin + d_max] (A2), redondeado al microsegundo: la
    coma flotante no debe decidir si 119,99999999999999 cruza la frontera de
    las 120 (ningún reloj de aquí resuelve por debajo del microsegundo)."""
    return round(inicio + d_min, 6), round(fin + d_max, 6)


def clasificar(inicio, fin, d_min, d_max, ventana):
    """(ventana del servidor, ambigua) de una petición con tiempos locales (A2)."""
    return ventana_de_peticion(*intervalo_servidor(inicio, fin, d_min, d_max), ventana)


def comprobar_a3(filas, d_min, d_max, ventana):
    """A3: todas las peticiones caen sin ambigüedad en la misma ventana."""
    vistas = set()
    for i, f in enumerate(filas):
        indice, ambigua = clasificar(f["inicio"], f["fin"], d_min, d_max, ventana)
        if ambigua:
            return False, f"A3: la peticion {i + 1} ({f.get('red', '?')}) es ambigua"
        vistas.add(indice)
    if len(vistas) != 1:
        return False, f"A3: las peticiones caen en {len(vistas)} ventanas"
    return True, "A3: todas en la misma ventana, sin ambiguedad"


# --- perfil de A, topes y guarda (P6) ------------------------------------------
def validar_topes(tasa, duracion, tope_peticiones, en_vuelo, tasa_b=TOPE_TASA_B, periodo_sonda=PERIODO_SONDA_S):
    """Parada si algún parámetro supera los topes fijos (plan §4, punto 10)."""
    if tasa > TOPE_TASA_A:
        raise Parada(f"tasa {tasa}/s por encima del tope de {TOPE_TASA_A}/s")
    if duracion > TOPE_DURACION_S:
        raise Parada(f"duracion {duracion} s por encima del tope de {TOPE_DURACION_S} s")
    if tope_peticiones > TOPE_PETICIONES_A:
        raise Parada(f"{tope_peticiones} peticiones por encima del tope de {TOPE_PETICIONES_A}")
    if en_vuelo > TOPE_EN_VUELO:
        raise Parada(f"{en_vuelo} en vuelo por encima del tope de {TOPE_EN_VUELO}")
    if tasa_b > TOPE_TASA_B:
        raise Parada(f"tasa de B {tasa_b}/s por encima del tope de {TOPE_TASA_B}/s")
    if periodo_sonda < TOPE_PERIODO_SONDA_MIN_S:
        raise Parada(f"sondas cada {periodo_sonda} s, por debajo del minimo de {TOPE_PERIODO_SONDA_MIN_S} s")


def tiempos_rampa(tasa_final=TOPE_TASA_A, duracion=TOPE_DURACION_S, rampa=RAMPA_S):
    """Llegadas de A: rampa lineal de 1 a tasa_final/s en `rampa` s y luego
    tasa constante hasta `duracion`. Con 20/s, 60 s y 120 s: k = 0..629 en
    t_k = (-1 + sqrt(1 + 4ak)) / 2a con a = 19/120, y k = 630..1829 en
    60 + (k - 630)/20 (1830 llegadas)."""
    a = (tasa_final - TASA_INICIAL_A) / (2 * rampa)
    llegadas_rampa = round(TASA_INICIAL_A * rampa + a * rampa * rampa)
    tiempos = [(-1 + math.sqrt(1 + 4 * a * k)) / (2 * a) for k in range(llegadas_rampa)]
    constantes = round(tasa_final * (duracion - rampa))
    tiempos += [rampa + j / tasa_final for j in range(constantes)]
    return tiempos


def construir_plan_a(tasa=TOPE_TASA_A, duracion=TOPE_DURACION_S, tope_peticiones=TOPE_PETICIONES_A,
                     en_vuelo=TOPE_EN_VUELO):
    """Valida los topes y devuelve las llegadas de A (segundos desde t0)."""
    validar_topes(tasa, duracion, tope_peticiones, en_vuelo)
    tiempos = tiempos_rampa(tasa, duracion)
    if len(tiempos) > tope_peticiones:
        raise Parada(f"el perfil tiene {len(tiempos)} llegadas, por encima de {tope_peticiones}")
    return tiempos


def permite_guarda(t, d_min, d_max, ventana=VENTANA_SEGUIMIENTO_S):
    """D10 con la guarda de B1(i) (plan bloque 1, §3). Se lanza en el instante
    local t, con [d_min, d_max] el A1 INICIAL, solo si el intervalo
    [t + d_min - 1,5 ; t + d_max + 1,5 + 1,0 + 0,001] cae entero en una
    ventana del servidor.

    Por qué el 1,5 a cada lado: el veredicto clasifica con la envolvente del
    A1 inicial y el final (combinar_a1). Cada A1 mide como mucho
    ANCHURA_A1_MAX_S = 1,5 s (evaluar_a1) y el final tiene que solapar con el
    inicial (si no, combinar_a1 da None y P6 queda SIN CONCLUSION). Así que la
    envolvente cae dentro de [d_min_ini - 1,5 ; d_max_ini + 1,5], y una
    petición de 1,0 s o menos lanzada con esta guarda no puede salir ambigua
    con ella. La guarda vieja (t + d_max + 1,001 <= F_siguiente, con una
    condición t + d_min >= F_anterior que era una tautología) usaba el A1
    inicial sin margen: si el desfase derivaba, la envolvente fabricaba
    ambiguas (las 2 de P6 del 25/11; B1 las atribuye a la deriva por el lado
    del inicio).

    Zona ciega: con d = [0; 0,3] se pierden 4,301 s por minuto, y con
    d = [0; 1,5], 5,501 s (antes, unos 1,3 s). A sigue dando mucho más de 60
    por ventana.

    Con b exactamente en la frontera, la guarda rechaza: floor(b / ventana) ya
    es la ventana siguiente, igual que en ventana_de_peticion. Los extremos se
    redondean al microsegundo, como en intervalo_servidor."""
    a = round(t + d_min - ANCHURA_A1_MAX_S, 6)
    b = round(t + d_max + ANCHURA_A1_MAX_S + GUARDA_DURACION_S + GUARDA_MARGEN_S, 6)
    return math.floor(a / ventana) == math.floor(b / ventana)


def planificar_guarda(tiempos, t0, d_min, d_max, guarda=True):
    """Separa las llegadas en lanzadas y omitidas por la guarda. Las omitidas
    no se reenvían (ni en ráfaga después de la pausa) y no son descartes.
    Devuelve (lanzadas, omitidas), listas de (k, instante local planeado).
    guarda=False solo existe para el control de las unitarias."""
    lanzadas, omitidas = [], []
    for k, t in enumerate(tiempos):
        plan = t0 + t
        (lanzadas if (not guarda or permite_guarda(plan, d_min, d_max)) else omitidas).append((k, plan))
    return lanzadas, omitidas


def control_retraso(retrasos):
    """Q-13: SIN CONCLUSION si más del 1 % de las llegadas lanzadas sale con
    más de 0,5 s de retraso, o alguna con más de 2 s: se habría medido el
    generador. Devuelve (ok, texto)."""
    if not retrasos:
        return True, "sin llegadas lanzadas"
    maximo = max(retrasos)
    lentas = sum(1 for r in retrasos if r > RETRASO_UMBRAL_S)
    if maximo > RETRASO_MAXIMO_S:
        return False, f"retraso maximo {maximo:.3f} s, mas de {RETRASO_MAXIMO_S} s"
    if lentas / len(retrasos) > RETRASO_FRACCION_MAX:
        return False, f"{lentas} de {len(retrasos)} llegadas con mas de {RETRASO_UMBRAL_S} s de retraso"
    return True, f"retraso maximo {maximo:.3f} s; {lentas} de {len(retrasos)} por encima de {RETRASO_UMBRAL_S} s"


# --- respuestas literales ------------------------------------------------------
def es_404_literal(r):
    return r.get("estado") == 404 and r.get("cuerpo") == CUERPO_404


def es_422_literal(r):
    return r.get("estado") == 422 and r.get("cuerpo") == CUERPO_422


def es_error(estado):
    """Error de B o de A: sin respuesta (0) o 5xx (informe l.100, "ningún error")."""
    return estado == 0 or 500 <= estado <= 599


def retry_after_entero(r):
    texto = r.get("cabeceras", {}).get("retry-after", "")
    return int(texto) if texto.isdigit() else -1


# --- P1, P1b, P2, P3 y P5 ------------------------------------------------------
def control_70(filas, ventana=VENTANA_SEGUIMIENTO_S):
    """60 x 404 literal y 10 x es_429: el control de A en P1 y P1b-c."""
    if len(filas) != TOPE_P1_A:
        return False, f"{len(filas)} peticiones de A en vez de {TOPE_P1_A}"
    for i, r in enumerate(filas[:LIMITE_SEGUIMIENTO]):
        if not es_404_literal(r):
            return False, f"peticion {i + 1} = {r.get('estado')} (se esperaba 404 literal)"
    for i, r in enumerate(filas[LIMITE_SEGUIMIENTO:], start=LIMITE_SEGUIMIENTO):
        if not es_429(r, ventana):
            return False, f"peticion {i + 1} = {r.get('estado')} (se esperaba es_429)"
    return True, "60 x 404 literal y 10 x es_429"


def veredicto_p1(filas_a, filas_b, d_min, d_max, consultar_ips):
    """P1. Control (A): 60 x 404 y 10 x es_429, y las 75 sin ambigüedad en la
    ventana de A (A3, S6, Q-9). Oráculo (B): las 5 son 404 literales. Un 429
    en B es FALLA solo si, al repetir la consulta de IP, A y B siguen siendo
    distintas (Q-14); si coinciden, SIN CONCLUSION."""
    ok, motivo = control_70(filas_a)
    if not ok:
        return SIN_CONCLUSION, f"control de A: {motivo}"
    if len(filas_b) != TOPE_P1_B:
        return SIN_CONCLUSION, f"{len(filas_b)} peticiones de B en vez de {TOPE_P1_B}"
    ok, motivo = comprobar_a3(list(filas_a) + list(filas_b), d_min, d_max, VENTANA_SEGUIMIENTO_S)
    if not ok:
        return SIN_CONCLUSION, motivo
    if all(es_404_literal(r) for r in filas_b):
        return PASA, "B: 5 x 404 literal en la ventana en la que A recibio 429"
    if any(r.get("estado") == 429 for r in filas_b):
        ip_a, ip_b = consultar_ips()
        if ip_a == ip_b:
            return SIN_CONCLUSION, "B recibio 429, pero al repetir la consulta A y B salen con la misma IP (Q-14)"
        return FALLA, "B recibio 429 con una IP publica distinta de la de A"
    return SIN_CONCLUSION, f"B: estados inesperados {[r.get('estado') for r in filas_b]}"


def veredicto_p1b_c(filas, d_min, d_max):
    """P1b-c, control de P1b: lo mismo que A en P1, sin X-Forwarded-For."""
    ok, motivo = control_70(filas)
    if not ok:
        return SIN_CONCLUSION, motivo
    ok, motivo = comprobar_a3(filas, d_min, d_max, VENTANA_SEGUIMIENTO_S)
    if not ok:
        return SIN_CONCLUSION, motivo
    return PASA, "60 x 404 literal y 10 x es_429 sin X-Forwarded-For"


def lista_xff():
    """Las 70 direcciones de P1b: 192.0.2.1-24, 198.51.100.1-23 y 203.0.113.1-23."""
    return ([f"192.0.2.{i}" for i in range(1, 25)] + [f"198.51.100.{i}" for i in range(1, 24)]
            + [f"203.0.113.{i}" for i in range(1, 24)])


def validar_xff(lista):
    """70 distintas y todas en los tres /24 de documentación: así no se gasta
    el cupo de IP reales de terceros si la cabecera se tuviera en cuenta."""
    try:
        ips = [ipaddress.ip_address(x) for x in lista]
    except ValueError:
        return False
    return (len(ips) == TOPE_P1B and len(set(ips)) == TOPE_P1B
            and all(any(ip in red for red in REDES_XFF) for ip in ips))


def veredicto_p1b(filas, control_pasa, d_min, d_max):
    """P1b. Control: P1b-c en PASA. Validez: las 60 primeras son 404
    literales (S2). Oráculo: de la 61.ª a la 70.ª, es_429 con cuerpo,
    cabeceras y Retry-After entre 1 y 60; un 429 de otro (Traefik) es FALLA."""
    if not control_pasa:
        return SIN_CONCLUSION, "control de P1b: P1b-c no dio PASA"
    if len(filas) != TOPE_P1B:
        return SIN_CONCLUSION, f"{len(filas)} peticiones en vez de {TOPE_P1B}"
    for i, r in enumerate(filas[:LIMITE_SEGUIMIENTO]):
        if not es_404_literal(r):
            return SIN_CONCLUSION, f"control de P1b, peticion {i + 1} = {r.get('estado')}"
    ok, motivo = comprobar_a3(filas, d_min, d_max, VENTANA_SEGUIMIENTO_S)
    if not ok:
        return SIN_CONCLUSION, motivo
    for i, r in enumerate(filas[LIMITE_SEGUIMIENTO:], start=LIMITE_SEGUIMIENTO):
        # Sin respuesta o un 5xx no es un fallo del límite ni del XFF: no se
        # sabe qué habría contestado el limitador (interpretación del
        # "FALLA si no" del plan, declarada en el README).
        if es_error(r.get("estado", 0)):
            return SIN_CONCLUSION, f"peticion {i + 1} = {r.get('estado')} (sin respuesta o 5xx)"
    for i, r in enumerate(filas[LIMITE_SEGUIMIENTO:], start=LIMITE_SEGUIMIENTO):
        if not es_429(r, VENTANA_SEGUIMIENTO_S):
            return FALLA, f"peticion {i + 1} = {r.get('estado')} sin el 429 literal de Caddy"
    return PASA, "de la 61.a a la 70.a, es_429 con X-Forwarded-For distintos: A no puede inventarse IP"


def segundos_restantes_hora(ahora_local, d_max):
    """Lo que queda de la hora UTC del servidor, con d_max (lo conservador)."""
    return VENTANA_DENUNCIA_S - (ahora_local + d_max) % VENTANA_DENUNCIA_S


def p2_puede_arrancar(restantes):
    return restantes > MARGEN_HORA_P2_S


def veredicto_p2(filas, d_min, d_max):
    """P2. Control: las 10 primeras, 422 literal, y nada cruza la hora (A3).
    Oráculo: la 11.ª, es_429 con Retry-After entre 1 y 3600."""
    if len(filas) != TOPE_P2:
        return SIN_CONCLUSION, f"{len(filas)} peticiones en vez de {TOPE_P2}"
    for i, r in enumerate(filas[:10]):
        if not es_422_literal(r):
            return SIN_CONCLUSION, f"control: peticion {i + 1} = {r.get('estado')} (se esperaba 422 literal)"
    ok, motivo = comprobar_a3(filas, d_min, d_max, VENTANA_DENUNCIA_S)
    if not ok:
        return SIN_CONCLUSION, motivo
    if es_error(filas[10].get("estado", 0)):
        # Igual que en P1b: sin respuesta o 5xx no dice nada del límite.
        return SIN_CONCLUSION, f"la 11.a = {filas[10].get('estado')} (sin respuesta o 5xx)"
    if not es_429(filas[10], VENTANA_DENUNCIA_S):
        return FALLA, (f"la 11.a = {filas[10].get('estado')} con Retry-After "
                       f"{filas[10].get('cabeceras', {}).get('retry-after')!r}, no es_429")
    return PASA, f"10 x 422 literal y la 11.a es_429 (Retry-After {filas[10]['cabeceras']['retry-after']})"


def veredicto_p3(justo, grande, segundos):
    """P3. Control: 128 KiB justos dan 405 con Via (llegan a la API). Oráculo:
    128 KiB + 1 da el 413 literal de Caddy, sin Via y en menos de 0,5 s.
    Connection se anota como información (D1: a través de Traefik
    probablemente no se observa). Devuelve (veredicto, texto, connection)."""
    conexion = grande.get("cabeceras", {}).get("connection", "")
    if not (justo.get("estado") == 405 and "via" in justo.get("cabeceras", {})):
        return SIN_CONCLUSION, f"control: 128 KiB justos -> {justo.get('estado')} sin Via", conexion
    nota = f"Connection del 413: {conexion!r} (D1, informacion)"
    if (grande.get("estado") == 413 and grande.get("cuerpo") == CUERPO_413
            and "via" not in grande.get("cabeceras", {}) and segundos is not None and segundos < PLAZO_413_S):
        return PASA, f"413 literal de Caddy sin Via en {segundos:.3f} s; {nota}", conexion
    return FALLA, (f"128 KiB + 1 -> {grande.get('estado')}, Via {'via' in grande.get('cabeceras', {})}, "
                   f"{segundos if segundos is None else round(segundos, 3)} s; {nota}"), conexion


def estadisticas_ms(valores):
    ordenados = sorted(valores)
    if not ordenados:
        return None
    return {"p50": percentil(ordenados, 50), "p95": percentil(ordenados, 95), "max": ordenados[-1],
            "n": len(ordenados)}


def minimo_respuestas_p5(previstas):
    """290 respuestas de 300 en producción; en el ensayo local corto, la misma
    proporción redondeada hacia arriba."""
    return math.ceil(previstas * MINIMO_RESPUESTAS_P5 / LLEGADAS_P5)


def veredicto_p5(filas, retraso_ok, retraso_texto, previstas=None):
    """P5. Control: ninguna 429 (si hay alguna, la línea base no es de fiar),
    todas las llegadas previstas lanzadas (300 en producción) y al menos 290
    con respuesta: con menos, el p50 que se congela no es de fiar.
    Resultado: p50, p95 y máximo de B (las respuestas recibidas), que se
    congelan para P6. Errores contados y publicados."""
    previstas = LLEGADAS_P5 if previstas is None else previstas
    n429 = sum(1 for f in filas if f["estado"] == 429)
    errores = sum(1 for f in filas if es_error(f["estado"]))
    if n429:
        return SIN_CONCLUSION, f"control: {n429} respuestas 429", None
    if not retraso_ok:
        return SIN_CONCLUSION, f"retraso del planificador: {retraso_texto}", None
    if len(filas) != previstas:
        return SIN_CONCLUSION, f"{len(filas)} llegadas lanzadas de {previstas}", None
    respuestas = sum(1 for f in filas if f["estado"] != 0)
    if respuestas < minimo_respuestas_p5(previstas):
        return SIN_CONCLUSION, f"{respuestas} respuestas, menos de {minimo_respuestas_p5(previstas)}", None
    stats = estadisticas_ms([f["ms"] for f in filas if f["estado"] != 0])
    if stats is None:
        return SIN_CONCLUSION, "ninguna respuesta", None
    stats["errores"] = errores
    return PASA, (f"p50 {stats['p50']:.1f} ms, p95 {stats['p95']:.1f} ms, max {stats['max']:.1f} ms, "
                  f"{stats['n']} respuestas, {errores} errores"), stats


# --- P4 (Q-6, Q-7, QA3) ----------------------------------------------------------
PATRON_MARCA = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z")
PATRON_LINEA_API = re.compile(r"API (\S+) (\d+) (sha256:[0-9a-f]{64})")
PATRON_LINEA_PRIMERA = re.compile(r"PRIMERA_MARCA (\S+)")
PATRON_LINEA_LIMITES = re.compile(r"(\S+) INFO canario\.arranque: (LIMITES \(.*)")
INICIO_P4, FIN_P4 = "CANARIO_P4_INICIO", "CANARIO_P4_FIN"
INICIO_Q12, FIN_Q12 = "CANARIO_Q12_INICIO", "CANARIO_Q12_FIN"


def leer_marca(texto):
    """Marca de docker (RFC 3339 con hasta 9 decimales y Z) -> (segundos
    enteros, nanosegundos), comparable sin perder precisión. None si no casa."""
    encaje = PATRON_MARCA.fullmatch(texto or "")
    if encaje is None:
        return None
    try:
        base = datetime.datetime.strptime(encaje.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.UTC)
    except ValueError:
        return None
    return int(base.timestamp()), int((encaje.group(2) or "0").ljust(9, "0"))


def lineas_del_bloque(texto, inicio, fin):
    """Quita los \\r (Q-7), exige ASCII imprimible sin '?' (QA3: Set-Content
    -Encoding ascii cambia lo que no es ASCII por '?', así que un '?' delata
    texto ajeno) y los delimitadores. Devuelve (lineas interiores, motivo)."""
    lineas = [linea[:-1] if linea.endswith("\r") else linea for linea in texto.split("\n")]
    for n, linea in enumerate(lineas, start=1):
        if "?" in linea or any(not (32 <= ord(c) <= 126) for c in linea):
            return None, f"linea {n}: caracteres fuera de ASCII imprimible o '?' (texto ajeno)"
    lineas = [linea for linea in lineas if linea != ""]
    if len(lineas) < 2 or lineas[0] != inicio or lineas[-1] != fin:
        return None, f"el bloque no empieza por {inicio} y acaba por {fin}"
    if lineas.count(inicio) != 1 or lineas.count(fin) != 1:
        return None, "delimitadores repetidos"
    return lineas[1:-1], ""


def analizar_bloque_p4(texto, literal=TEXTO_LIMITES_PRODUCCION):
    """P4. Todas las líneas LIMITES son exactamente el literal y la última
    tiene una marca >= StartedAt: PASA. FALLA si alguna difiere, o si no hay
    línea y el log empieza antes del arranque (o en él). SIN CONCLUSION si el
    log empieza después de StartedAt y la línea no está (rotación de
    3 x 10 MB), o si el bloque trae una línea fuera de formato (el aviso de
    sudo, "Sorry, try again", un '?'). Devuelve un dict con veredicto, motivo
    y lo analizado."""
    res = {"veredicto": SIN_CONCLUSION, "motivo": "", "started_at": None, "restart_count": None, "image": None,
           "primera_marca": None, "lineas": [], "formato_valido": False}
    interiores, motivo = lineas_del_bloque(texto, INICIO_P4, FIN_P4)
    if interiores is None:
        res["motivo"] = motivo
        return res
    if len(interiores) < 2:
        res["motivo"] = "faltan las lineas API y PRIMERA_MARCA"
        return res
    api, primera = PATRON_LINEA_API.fullmatch(interiores[0]), PATRON_LINEA_PRIMERA.fullmatch(interiores[1])
    if api is None or primera is None:
        res["motivo"] = "las lineas 2 y 3 no son API ... y PRIMERA_MARCA ..."
        return res
    arranque, primera_marca = leer_marca(api.group(1)), leer_marca(primera.group(1))
    if arranque is None or primera_marca is None:
        res["motivo"] = "StartedAt o la primera marca fuera de formato"
        return res
    lineas = []
    for n, linea in enumerate(interiores[2:], start=4):
        encaje = PATRON_LINEA_LIMITES.fullmatch(linea)
        marca = leer_marca(encaje.group(1)) if encaje else None
        if marca is None:
            res["motivo"] = f"linea {n} fuera de formato"
            return res
        lineas.append((marca, encaje.group(2)))
    res.update(started_at=api.group(1), restart_count=int(api.group(2)), image=api.group(3),
               primera_marca=primera.group(1), lineas=[t for _, t in lineas], formato_valido=True)
    distintas = [t for _, t in lineas if t != literal]
    if distintas:
        res.update(veredicto=FALLA, motivo=f"{len(distintas)} lineas LIMITES distintas del literal (ej. {distintas[0][:60]!r})")
    elif lineas and lineas[-1][0] >= arranque:
        res.update(veredicto=PASA, motivo=f"{len(lineas)} lineas LIMITES iguales al literal; la ultima, posterior al arranque")
    elif lineas:
        res.update(veredicto=FALLA, motivo="ninguna linea LIMITES desde el ultimo arranque y el log lo cubre")
    elif primera_marca > arranque:
        res.update(veredicto=SIN_CONCLUSION, motivo="sin linea LIMITES y el log empieza despues de StartedAt (rotacion)")
    else:
        res.update(veredicto=FALLA, motivo="sin linea LIMITES y el log empieza antes del arranque")
    return res


def control_p4_correcto(analisis):
    """Control de P4 en la pila local: el analizador RECHAZA la línea de
    límites relajados, y la línea es exactamente la configurada (así se sabe
    que la cadena leyó la línea correcta y no otra cosa)."""
    return (analisis["veredicto"] == FALLA and bool(analisis["lineas"])
            and all(t == TEXTO_LIMITES_CONTROL_P4 for t in analisis["lineas"]))


def comparar_relectura(anterior, nuevo):
    """Q-5: StartedAt, RestartCount e Image tienen que coincidir con los de P4.
    Si no, hay que repetir P4 entero. Devuelve (iguales, motivo)."""
    distintos = [c for c in ("started_at", "restart_count", "image") if anterior.get(c) != nuevo.get(c)]
    if distintos:
        return False, f"cambian {distintos}: hay que repetir P4"
    return True, "StartedAt, RestartCount e Image iguales a los de P4"


# --- Q-12 (N5) ---------------------------------------------------------------------
PATRON_MARCA_Q12 = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
# El mismo evento lo escriben tres loggers: canario.limitador (app/limitador.py:96,
# el middleware), canario.personal (app/rutas_personal.py:126, en :936) y
# canario.externo (app/rutas_externo.py:70, en :323). Literales leídos del código.
LOGGERS_EVENTO = ("canario.limitador", "canario.personal", "canario.externo")
PATRON_EVENTO = re.compile(r"(\S+) ERROR (?:" + "|".join(map(re.escape, LOGGERS_EVENTO))
                           + r"): EVENTO limitador_no_disponible: "
                           r"([A-Za-z_][A-Za-z0-9_]*) causa=(" + "|".join(map(re.escape, CAUSAS_EVENTO))
                           + r") espera=(" + "|".join(map(re.escape, ESPERAS_EVENTO)) + r")")


def validar_marca_q12(marca):
    """Antes de escribir una marca en un comando que el autor pegará en el VPS:
    exactamente AAAA-MM-DDTHH:MM:SSZ (fullmatch: ni un salto de línea ni un
    '; rm' pueden colarse). Si no casa, Parada."""
    if not isinstance(marca, str) or PATRON_MARCA_Q12.fullmatch(marca) is None:
        raise Parada("marca de Q-12 fuera de formato: no se construye el comando")
    return marca


def marca_q12(epoch):
    return validar_marca_q12(datetime.datetime.fromtimestamp(epoch, datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"))


def comando_q12(desde_servidor, hasta_servidor):
    """Segundo comando del modo manual: solo las líneas del evento del limitador
    entre dos marcas, con 5 s de margen a cada lado. El grep es fijo y lo único
    variable son las dos marcas validadas."""
    desde, hasta = marca_q12(math.floor(desde_servidor - 5)), marca_q12(math.ceil(hasta_servidor + 5))
    return (f"cd ~/apps/canario && c=$({COMPOSE_VPS} ps -q api) && echo {INICIO_Q12} && "
            f"sudo docker logs --timestamps --since {desde} --until {hasta} \"$c\" 2>&1 | "
            f"grep -F 'EVENTO limitador_no_disponible: '; echo {FIN_Q12}")


def analizar_q12(texto, ventanas):
    """Asigna cada evento a la prueba en cuya ventana (servidor) cae su marca.
    ventanas: {prueba: (desde, hasta)}. Devuelve (veredicto, texto, detalle)."""
    interiores, motivo = lineas_del_bloque(texto, INICIO_Q12, FIN_Q12)
    if interiores is None:
        return SIN_CONCLUSION, motivo, {}
    por_prueba, fuera = {p: 0 for p in ventanas}, 0
    for n, linea in enumerate(interiores, start=2):
        encaje = PATRON_EVENTO.fullmatch(linea)
        marca = leer_marca(encaje.group(1)) if encaje else None
        if marca is None:
            return SIN_CONCLUSION, f"linea {n} fuera de formato", {}
        instante = marca[0] + marca[1] / 1e9
        dentro = [p for p, (desde, hasta) in ventanas.items() if desde <= instante <= hasta]
        for p in dentro:
            por_prueba[p] += 1
        fuera += 0 if dentro else 1
    detalle = {"por_prueba": por_prueba, "en_el_margen": fuera}
    afectadas = sorted(p for p, n in por_prueba.items() if n)
    if afectadas:
        return SIN_CONCLUSION, f"el limitador no estuvo disponible durante {afectadas}", detalle
    return PASA, f"ningun evento limitador_no_disponible en las pruebas ({fuera} en el margen)", detalle


# --- P6: vecinas, sondas y veredicto -------------------------------------------------
PATRON_VECINA = re.compile(r"(https://([A-Za-z0-9.-]+)(?::(\d{1,5}))?(/\S*)) ([23]\d\d)")


def validar_bytes_vecinas(datos):
    """N4: UTF-8 sin BOM, con LF y sin CR. No se normaliza: el HMAC no debe
    depender de cómo se guardó el fichero. Si no cumple, Parada."""
    if datos.startswith(b"\xef\xbb\xbf"):
        raise Parada("el fichero de vecinas lleva BOM")
    if b"\r" in datos:
        raise Parada("el fichero de vecinas lleva CR (tiene que ser LF)")
    try:
        return datos.decode("utf-8")
    except UnicodeDecodeError:
        raise Parada("el fichero de vecinas no es UTF-8") from None


def leer_vecinas(texto):
    """Una vecina por línea: "<URL https> <estado esperado 2xx o 3xx>". Los
    alias vecina_1..n son lo único que se publica."""
    vecinas = []
    for linea in texto.split("\n"):
        if not linea:
            continue
        encaje = PATRON_VECINA.fullmatch(linea)
        if encaje is None:
            raise Parada(f"linea {len(vecinas) + 1} del fichero de vecinas fuera de formato")
        vecinas.append({"alias": f"vecina_{len(vecinas) + 1}", "url": encaje.group(1), "host": encaje.group(2),
                        "puerto": int(encaje.group(3) or 443), "ruta": encaje.group(4),
                        "esperado": int(encaje.group(5))})
    if not vecinas:
        raise Parada("el fichero de vecinas esta vacio")
    return vecinas


def hmac_vecinas(sal, datos):
    """HMAC-SHA256(sal, bytes del fichero), en hexadecimal (S9, N4). Con una
    sal secreta, un SHA-256 de URL conocidas no se puede adivinar."""
    return hmac.new(sal, datos, hashlib.sha256).hexdigest()


def sonda_mala(estado, segundos):
    return not (200 <= estado <= 399) or segundos > LENTA_S


def evaluar_sondas(historial, p95_base):
    """Parada automática de P6: dos sondas seguidas de una vecina con un estado
    que no es 2xx ni 3xx o de más de 5,0 s, o una sonda por encima de 3 x p95
    de su línea base. historial: [(estado, segundos)]. Motivo o None."""
    if len(historial) >= 2 and sonda_mala(*historial[-1]) and sonda_mala(*historial[-2]):
        return "dos sondas seguidas fallidas o de mas de 5 s"
    if p95_base is not None and historial and historial[-1][1] > FACTOR_P95 * p95_base:
        return f"sonda de {historial[-1][1]:.3f} s, mas de {FACTOR_P95} x p95 de su linea base ({p95_base:.3f} s)"
    return None


def valores_congelados():
    return {"P5_P50_MS": P5_P50_MS, "P5_P95_MS": P5_P95_MS, "P5_MAX_MS": P5_MAX_MS,
            "P6_P50_B_MAX_MS": P6_P50_B_MAX_MS, "HMAC_VECINAS": HMAC_VECINAS}


def comprobar_congelacion(valores=None):
    """P6 exige las constantes congeladas (plan §4, punto 1) y coherentes: las
    cifras con un decimal y P6_P50_B_MAX_MS exactamente 2 x P5_P50_MS (los dos
    a 0,1 ms, como los imprime texto_congelacion). valores, solo para las
    unitarias; por defecto, las constantes del módulo."""
    v = valores_congelados() if valores is None else valores
    faltan = [n for n, x in v.items() if x is None]
    if faltan:
        raise Parada(f"P6 sin congelar: {sorted(faltan)} valen None (commit de congelacion con push antes de medir)")
    for nombre in ("P5_P50_MS", "P5_P95_MS", "P5_MAX_MS", "P6_P50_B_MAX_MS"):
        x = v[nombre]
        if isinstance(x, bool) or not isinstance(x, (int, float)) or x <= 0 or round(x, 1) != x:
            raise Parada(f"{nombre} tiene que ser un numero positivo con un decimal como mucho")
    if round(2 * v["P5_P50_MS"], 1) != v["P6_P50_B_MAX_MS"]:
        raise Parada("P6_P50_B_MAX_MS no es 2 x P5_P50_MS")
    if not (v["P5_P50_MS"] <= v["P5_P95_MS"] <= v["P5_MAX_MS"]):
        raise Parada("las cifras de P5 no cumplen p50 <= p95 <= max")
    if not isinstance(v["HMAC_VECINAS"], str) or re.fullmatch(r"[0-9a-f]{64}", v["HMAC_VECINAS"]) is None:
        raise Parada("HMAC_VECINAS tiene que ser 64 hexadecimales en minusculas")
    return True


def verificar_congelacion(valores=None):
    """--prueba verificar-congelacion: (PASA o PARADA, texto)."""
    try:
        comprobar_congelacion(valores)
    except Parada as e:
        return PARADA, str(e)
    return PASA, "constantes de P6 congeladas y coherentes"


def texto_congelacion(stats):
    """Las constantes para el commit de congelación, ya coherentes: P6_P50_B_MAX_MS
    es 2 x (p50 redondeado a 0,1), no 2 x p50 sin redondear (41,26 -> 41,3 y 82,6)."""
    p50, p95, maximo = round(stats["p50"], 1), round(stats["p95"], 1), round(stats["max"], 1)
    return (f"P5_P50_MS = {p50:.1f}, P5_P95_MS = {p95:.1f}, P5_MAX_MS = {maximo:.1f}, "
            f"P6_P50_B_MAX_MS = {round(2 * p50, 1):.1f}")


def veredicto_p6(filas_a, filas_b, d_min, d_max, parada, descartes, retraso_ok, umbral_p50_ms,
                 muestras_b=MUESTRAS_B_P6):
    """Veredicto de P6 (plan §4, punto 7).
    filas_a: dicts con inicio, fin (locales), estado, es_429 y retry_after.
    filas_b: dicts con estado y ms. parada: None o {causa, motivo, instante}.
    Precedencia: un error de B es FALLA siempre (l.100, "ningún error"),
    aunque haya parada y los datos queden truncados. Una FALLA de A cuenta
    en cualquier ventana; su control, solo en las completas antes de la
    parada. El p50 de B es FALLA
    solo con las 60 muestras previstas. Sin ninguna FALLA, una parada por una
    vecina, un descarte, el retraso del generador o una ambigua aceptada dan
    SIN CONCLUSION. Devuelve (veredicto, motivos, info)."""
    fallas, dudas, info = [], [], {}
    errores_b = [f for f in filas_b if es_error(f["estado"])]
    if errores_b:
        fallas.append(f"B: {len(errores_b)} errores (estado 0 o 5xx); el oraculo es 'ningun error'")
    # A, con A2 sobre la hora del servidor.
    filas_srv = []
    for f in filas_a:
        inicio, fin = intervalo_servidor(f["inicio"], f["fin"], d_min, d_max)
        ventana, ambigua = ventana_de_peticion(inicio, fin, VENTANA_SEGUIMIENTO_S)
        filas_srv.append({"ip": "A", "inicio": inicio, "fin": fin, "estado": f["estado"], "ventana": ventana,
                          "ambigua": ambigua, "es_429": f.get("es_429", False), "retry_after": f.get("retry_after", -1)})
    # B1(i): con la guarda nueva, una aceptada de 1,0 s o menos no puede salir
    # ambigua; si sale, falla el instrumento (la guarda o el A1). Una de más
    # de 1,0 s sí puede, y es lo que D10 ya espera. Las dos son SIN
    # CONCLUSION, pero con su causa. La duración es la LOCAL (fin - inicio de
    # filas_a), sin el desfase.
    largas = cortas = 0
    for f, f_srv in zip(filas_a, filas_srv):
        if f_srv["ambigua"] and f_srv["estado"] == 404:
            if f["fin"] - f["inicio"] > GUARDA_DURACION_S:
                largas += 1
            else:
                cortas += 1
    if largas:
        dudas.append(f"A: {largas} aceptadas (404) ambiguas de mas de 1,0 s: esperadas por D10")
    if cortas:
        dudas.append(f"A: {cortas} aceptadas (404) ambiguas de 1,0 s o menos: fallo del instrumento")
    ventanas = sorted({f["ventana"] for f in filas_srv})
    if parada is not None:
        limite = round(parada["instante"] + d_min, 6)
        completas = {w for w in ventanas if (w + 1) * VENTANA_SEGUIMIENTO_S <= limite}
    else:
        completas = set(ventanas)
    info["ventanas_completas"] = len(completas)
    # Oráculo de A en TODAS las ventanas: más de 60 aceptadas no ambiguas (o
    # un 429 sin Retry-After válido) es FALLA aunque la parada corte la
    # ventana; contar menos peticiones de las que hubo no puede fabricar una
    # FALLA. El control positivo (control_l3 y un es_429 por ventana llena)
    # solo se exige en las ventanas completas.
    pares_todas = contar_por_ip_ventana(filas_srv, VENTANA_SEGUIMIENTO_S, 404)
    invalidos = sum(1 for f in filas_srv if f["estado"] == 429
                    and not retry_after_valido(f["retry_after"], VENTANA_SEGUIMIENTO_S))
    v_todas, texto_todas = veredicto_l3(pares_todas, LIMITE_SEGUIMIENTO, invalidos)
    info["a"] = texto_todas
    if v_todas == FALLA:
        fallas.append(f"A: {texto_todas}")
    filas_l3 = [f for f in filas_srv if f["ventana"] in completas]
    if not any(f["es_429"] for f in filas_a):
        dudas.append("control de A: ninguna 429 de A")
    elif not completas:
        dudas.append("A: ninguna ventana completa antes de la parada")
    else:
        pares = contar_por_ip_ventana(filas_l3, VENTANA_SEGUIMIENTO_S, 404)
        control_ok, motivos = control_l3(pares, LIMITE_SEGUIMIENTO)
        for w in completas:
            de_w = [f for f in filas_l3 if f["ventana"] == w]
            no_ambiguas = sum(1 for f in de_w if not f["ambigua"])
            if no_ambiguas > LIMITE_SEGUIMIENTO and not any(f["es_429"] for f in de_w):
                control_ok = False
                motivos.append(f"ventana {w}: {no_ambiguas} no ambiguas y ningun es_429")
        if not control_ok:
            dudas.append(f"control de A: {motivos[:3]}")
        elif v_todas == SIN_CONCLUSION:
            dudas.append(f"A: {texto_todas}")
    maximo, _ = maximo_deslizante({"A": [f["inicio"] for f in filas_srv if f["estado"] == 404]})
    info["maximo_deslizante"] = maximo
    # B, p50: un indicio, y solo con las 60 muestras previstas (QA2).
    if not errores_b:
        latencias = sorted(f["ms"] for f in filas_b)
        if len(latencias) < muestras_b:
            dudas.append(f"B: {len(latencias)} muestras de {muestras_b}: el p50 no concluye")
        else:
            p50 = percentil(latencias, 50)
            info["p50_b_ms"] = p50
            if p50 > umbral_p50_ms and retraso_ok:
                fallas.append(f"B: p50 {p50:.1f} ms por encima de {umbral_p50_ms} ms (indicio, no SLO)")
            elif p50 > umbral_p50_ms:
                dudas.append("B: p50 alto con el generador retrasado")
    if parada is not None:
        if parada["causa"] == "vecina":
            dudas.append(f"parada por una vecina (hallazgo): {parada['motivo']}")
        else:
            # errores_a, interrupcion o errores_b (este ya es FALLA por los
            # errores de B, que ganan).
            dudas.append(f"parada ({parada['causa']}): {parada['motivo']}")
    if descartes:
        dudas.append(f"{descartes} llegadas de A sin conexion libre (descartes)")
    if not retraso_ok:
        dudas.append("retraso del planificador (Q-13)")
    if fallas:
        return FALLA, fallas, info
    if dudas:
        return SIN_CONCLUSION, dudas, info
    return PASA, ["A como mucho 60 aceptadas por ventana, con 429; B sin errores y p50 dentro del umbral"], info


# --- P3: comprobación previa de P6 (plan bloque 1, §5, punto 2) -----------------
# No es la prueba P3 del 413. Antes de P6 se comprueba que, desde 5bd462a (el
# código con el que se midió lo anterior), el diff no toca nada que cambie lo
# que P6 mide salvo el mamparo de A2, y que app/principal.py solo añade esas
# sentencias. Mecanismo: lista permitida LITERAL. Si alguien retoca una de
# estas 9 sentencias, P3 da PARADA hasta que se actualice la lista: es
# justo lo que se quiere vigilar.
BASE_P3 = "5bd462a"
# Las 9 sentencias que A2 (42cbd20) añadió a ciclo_de_vida, como fuente. Se
# parsean dentro de un async def auxiliar (la 9 lleva await) y se comparan
# por ast.dump, sin posiciones. Su sitio también es literal (SITIO_MAMPARO).
MAMPARO_A2 = (
    "tarea_resumen = None",
    "semaforo_hash, limitador_hash = personal.crear_mamparo()",
    ("if fallo := personal.comprobar_mamparo(semaforo_hash, limitador_hash):\n"
     "    registro.error(\"ARRANQUE BLOQUEADO: mamparo_hashes: %s\", fallo)\n"
     "    raise verificacion_arranque.ArranqueBloqueado(\"mamparo_hashes\")"),
    "resumen_saturacion = personal.ResumenSaturacion()",
    "tarea_resumen = resumen_saturacion.lanzar_tarea()",
    "app.state.semaforo_hash = semaforo_hash",
    "app.state.limitador_hash = limitador_hash",
    "app.state.resumen_saturacion = resumen_saturacion",
    ("if tarea_resumen is not None:\n"
     "    await resumen_saturacion.parar_tarea(tarea_resumen)"),
)
# Sitio de cada huella: "cuerpo" (cuerpo de ciclo_de_vida, justo antes del
# Try contenedor), "body" o "finalbody" de ese Try (app/principal.py:116).
SITIO_MAMPARO = ("cuerpo", "body", "body", "body", "body", "body", "body", "body", "finalbody")
# Lo que P6 no puede ver cambiado (plan §5, punto 2). Además, cualquier A
# bajo app/ es PARADA: así se mecaniza "un módulo nuevo de log" (Q5).
FICHEROS_PROHIBIDOS_P3 = ("app/rutas_denuncias.py", "app/denuncias.py", "app/bd.py", "app/frontera_http.py",
                          "app/limitador.py", "app/validacion.py", "app/cripto.py", "Dockerfile",
                          "requirements.txt", "docker-compose.yml", "compose.produccion.yaml")
# Control positivo del comparador, en ejecución: un lifespan mínimo con las 9
# en su sitio (tiene que dar igual) y el mismo con un else colado en la
# sentencia 3 (el mutante de python-async, que tiene que dar distinto).
CONTROL_P3_VIEJO = """
async def ciclo_de_vida(app):
    pool = bd.crear_pool()
    limitador_api = None
    try:
        app.state.pool = pool
        yield
    finally:
        pool.close()
"""
CONTROL_P3_NUEVO = """
async def ciclo_de_vida(app):
    pool = bd.crear_pool()
    limitador_api = None
    tarea_resumen = None
    try:
        semaforo_hash, limitador_hash = personal.crear_mamparo()
        if fallo := personal.comprobar_mamparo(semaforo_hash, limitador_hash):
            registro.error("ARRANQUE BLOQUEADO: mamparo_hashes: %s", fallo)
            raise verificacion_arranque.ArranqueBloqueado("mamparo_hashes")
        resumen_saturacion = personal.ResumenSaturacion()
        tarea_resumen = resumen_saturacion.lanzar_tarea()
        app.state.pool = pool
        app.state.semaforo_hash = semaforo_hash
        app.state.limitador_hash = limitador_hash
        app.state.resumen_saturacion = resumen_saturacion
        yield
    finally:
        if tarea_resumen is not None:
            await resumen_saturacion.parar_tarea(tarea_resumen)
        pool.close()
"""
CONTROL_P3_ELSE = """
async def ciclo_de_vida(app):
    pool = bd.crear_pool()
    limitador_api = None
    tarea_resumen = None
    try:
        semaforo_hash, limitador_hash = personal.crear_mamparo()
        if fallo := personal.comprobar_mamparo(semaforo_hash, limitador_hash):
            registro.error("ARRANQUE BLOQUEADO: mamparo_hashes: %s", fallo)
            raise verificacion_arranque.ArranqueBloqueado("mamparo_hashes")
        else:
            pool.max_size = 1
        resumen_saturacion = personal.ResumenSaturacion()
        tarea_resumen = resumen_saturacion.lanzar_tarea()
        app.state.pool = pool
        app.state.semaforo_hash = semaforo_hash
        app.state.limitador_hash = limitador_hash
        app.state.resumen_saturacion = resumen_saturacion
        yield
    finally:
        if tarea_resumen is not None:
            await resumen_saturacion.parar_tarea(tarea_resumen)
        pool.close()
"""


def huellas_mamparo(sentencias=MAMPARO_A2):
    """ast.dump (sin posiciones) de cada sentencia de la lista, parseada
    dentro de un async def auxiliar para que el await de la 9 sea válido."""
    huellas = []
    for texto in sentencias:
        envoltorio = "async def _p3():\n" + "\n".join("    " + linea for linea in texto.split("\n")) + "\n"
        huellas.append(ast.dump(ast.parse(envoltorio).body[0].body[0]))
    return huellas


def _ciclo_de_vida(modulo):
    """La definición de ciclo_de_vida del nivel superior del módulo, o None si
    no hay exactamente una."""
    defs = [n for n in modulo.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            and n.name == "ciclo_de_vida"]
    return defs[0] if len(defs) == 1 else None


def quitar_mamparo(funcion, huellas):
    """Quita de la función (se modifica) las 9 huellas, exigiendo cada una
    exactamente una vez en toda la función y en su sitio (SITIO_MAMPARO):
    la 1 en el cuerpo, seguida del Try contenedor; de la 2 a la 8 en el body
    de ese Try, en orden; la 9 en su finalbody. Solo se quita una sentencia
    si su ast.dump está en la lista. Sin el sitio, mover una huella a otro
    bloque pasaba (python-async lo comprobó). Devuelve None si todo cuadra, o
    el motivo."""
    vistas = collections.Counter(ast.dump(n) for n in ast.walk(funcion) if isinstance(n, ast.stmt))
    for i, h in enumerate(huellas, 1):
        if vistas.get(h, 0) != 1:
            return f"la sentencia {i} del mamparo aparece {vistas.get(h, 0)} veces (se espera 1)"
    cuerpo = [ast.dump(n) for n in funcion.body]
    if huellas[0] not in cuerpo:
        return "la sentencia 1 del mamparo no esta en el cuerpo de ciclo_de_vida"
    i1 = cuerpo.index(huellas[0])
    if i1 + 1 >= len(funcion.body) or not isinstance(funcion.body[i1 + 1], ast.Try):
        return "la sentencia 1 del mamparo no va justo antes del try contenedor"
    contenedor = funcion.body[i1 + 1]
    en_body = [ast.dump(n) for n in contenedor.body]
    posiciones = []
    for i, (h, sitio) in enumerate(zip(huellas, SITIO_MAMPARO), 1):
        if sitio == "body":
            if h not in en_body:
                return f"la sentencia {i} del mamparo no esta en el body del try contenedor"
            posiciones.append(en_body.index(h))
        elif sitio == "finalbody" and h not in [ast.dump(n) for n in contenedor.finalbody]:
            return f"la sentencia {i} del mamparo no esta en el finally del try contenedor"
    if posiciones != sorted(posiciones):
        return "las sentencias 2 a 8 del mamparo no van en orden"
    conjunto = set(huellas)
    contenedor.body = [n for n in contenedor.body if ast.dump(n) not in conjunto]
    contenedor.finalbody = [n for n in contenedor.finalbody if ast.dump(n) not in conjunto]
    funcion.body = [n for n in funcion.body if ast.dump(n) not in conjunto]
    return None


def comparar_principal(viejo, nuevo, sentencias=MAMPARO_A2):
    """P3 sobre dos fuentes de app/principal.py. Devuelve (dentro, fuera,
    motivo): dentro es True si ciclo_de_vida del nuevo, sin las 9 sentencias
    del mamparo (en su sitio y una sola vez), es igual a la del viejo; fuera,
    si el módulo sin ciclo_de_vida es igual. Todo por ast.dump, sin
    posiciones (los comentarios no cuentan)."""
    try:
        m_viejo, m_nuevo = ast.parse(viejo), ast.parse(nuevo)
    except SyntaxError as error:
        return False, False, f"no se puede parsear: {type(error).__name__}"
    f_viejo, f_nuevo = _ciclo_de_vida(m_viejo), _ciclo_de_vida(m_nuevo)
    if f_viejo is None or f_nuevo is None:
        return False, False, "no hay exactamente una ciclo_de_vida en cada fuente"
    motivo = quitar_mamparo(f_nuevo, huellas_mamparo(sentencias))
    dentro = motivo is None and ast.dump(f_nuevo) == ast.dump(f_viejo)
    if motivo is None and not dentro:
        motivo = "ciclo_de_vida cambia ademas de las 9 sentencias del mamparo"
    m_viejo.body = [n for n in m_viejo.body if n is not f_viejo]
    m_nuevo.body = [n for n in m_nuevo.body if n is not f_nuevo]
    fuera = ast.dump(m_nuevo) == ast.dump(m_viejo)
    if not fuera:
        motivo = (motivo + "; " if motivo else "") + "el modulo cambia fuera de ciclo_de_vida"
    return dentro, fuera, motivo or "solo cambian las 9 sentencias del mamparo, en su sitio"


def ficheros_prohibidos(lineas):
    """Motivos de PARADA en la salida de git diff --name-status --no-renames
    (con --no-renames un renombrado sale como D + A, no hay R ni C). Lista
    vacía si no hay ninguno. Cualquier estado (A, M, D o T) sobre un fichero
    prohibido o bajo proxy/, cualquier A bajo app/ y cualquier línea con un
    estado desconocido."""
    motivos = []
    for linea in lineas:
        if not linea.strip():
            continue
        partes = linea.split("\t")
        if len(partes) != 2 or partes[0] not in ("A", "M", "D", "T"):
            motivos.append(f"linea de git diff con un estado desconocido: {linea!r}")
            continue
        estado, ruta = partes
        if ruta in FICHEROS_PROHIBIDOS_P3 or ruta.startswith("proxy/"):
            motivos.append(f"{estado} {ruta}: fichero que P6 no puede ver cambiado")
        elif estado == "A" and ruta.startswith("app/"):
            motivos.append(f"A {ruta}: modulo nuevo en app/")
    return motivos


# --- IP pública (S5), ssh -G (N6) y anti-fuga (§5.4) -----------------------------------
def extraer_ip_trace(texto):
    """De la respuesta de cdn-cgi/trace solo se lee la línea ip=; el resto se
    descarta sin escribirlo. Sin ip=, Parada."""
    for linea in texto.split("\n"):
        if linea.startswith("ip="):
            return linea[3:].strip()
    raise Parada("la respuesta de cdn-cgi/trace no trae ip=")


def validar_ip_publica(ip):
    try:
        direccion = ipaddress.ip_address(ip)
    except ValueError:
        raise Parada("la IP publica no es una direccion valida") from None
    if direccion.version != 4 or not direccion.is_global:
        raise Parada("la IP publica no es IPv4 global")
    return ip


def leer_ssh_g(texto):
    """De la salida de "ssh -G ovh" solo se leen user y hostname (N6). Nunca
    se imprimen ni se guardan fuera de la memoria."""
    usuario = servidor = None
    for linea in texto.splitlines():
        if linea.startswith("user "):
            usuario = linea[5:].strip()
        elif linea.startswith("hostname "):
            servidor = linea[9:].strip()
    return usuario, servidor


def patron_aislado(valor):
    """El valor como palabra entera (una IP no casa dentro de otra IP, ni un
    usuario corto dentro de un hash)."""
    return re.compile(rb"(?<![A-Za-z0-9_.-])" + re.escape(valor.encode("utf-8")) + rb"(?![A-Za-z0-9_-])")


def literales_carpeta_personal(carpeta):
    """La carpeta personal (lleva el usuario de Windows) con barras invertidas
    y con barras normales (C:/Users/...), como la escriben Python y git."""
    texto = str(carpeta)
    return {"carpeta_personal": texto, "carpeta_personal_barras": texto.replace("\\", "/")}


# Portapapeles (N1). Lo único documentado por Microsoft son las POLÍTICAS
# AllowClipboardHistory (Experience Policy CSP) y AllowCrossDeviceClipboard
# (Privacy Policy CSP): Computer Configuration, clave
# Software\Policies\Microsoft\Windows\System, 0 = no permitido, 1 = permitido
# (por defecto). El interruptor de usuario de Configuración no tiene clave
# documentada, así que no se lee: sin la política a 0, el script no puede
# confirmarlo y lo dice con un aviso visible; queda la declaración del autor.
CLAVE_POLITICA_PORTAPAPELES = r"Software\Policies\Microsoft\Windows\System"
VALORES_POLITICA_PORTAPAPELES = ("AllowClipboardHistory", "AllowCrossDeviceClipboard")


def evaluar_portapapeles(valores):
    """valores: {nombre: entero o None si no existe}. (confirmado, texto)."""
    if all(valores.get(n) == 0 for n in VALORES_POLITICA_PORTAPAPELES):
        return True, "historial y sincronizacion apagados por politica (AllowClipboardHistory = 0 y AllowCrossDeviceClipboard = 0)"
    estado = ", ".join(f"{n} = {'no existe' if valores.get(n) is None else valores.get(n)}"
                       for n in VALORES_POLITICA_PORTAPAPELES)
    return False, (f"el registro documentado no confirma que esten apagados ({estado}); "
                   "solo queda la declaracion del autor")


def leer_politica_portapapeles():
    """Lee las dos políticas de HKLM con winreg (solo lectura). Fuera de
    Windows o si no existen, None: nunca se dan por apagadas."""
    valores = {n: None for n in VALORES_POLITICA_PORTAPAPELES}
    try:
        import winreg
    except ImportError:
        return valores
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, CLAVE_POLITICA_PORTAPAPELES) as clave:
            for nombre in VALORES_POLITICA_PORTAPAPELES:
                try:
                    valor, tipo = winreg.QueryValueEx(clave, nombre)
                    valores[nombre] = valor if tipo == winreg.REG_DWORD else None
                except OSError:
                    pass
    except OSError:
        pass
    return valores


CARPETA_CENTINELA = "_control_antifuga"


def escanear_directorio(directorio, literales, patrones):
    hallazgos = {}
    for ruta in sorted(directorio.rglob("*")):
        if ruta.is_file():
            encontrados = escanear_fichero(ruta, literales, patrones)
            if encontrados:
                hallazgos[ruta.relative_to(directorio).as_posix()] = encontrados
    return hallazgos


def escanear_con_centinela(salida, literales, patrones):
    """Adaptación de escanear_con_centinela (tests/estres/lanzar.py:4148-4184):
    planta en la salida un literal con acento (tal cual y en JSON), un código
    con el formato y una IP, y recorre TODA la salida con el mismo escáner.
    Devuelve (hallazgos reales, ficheros del centinela no encontrados). La
    carpeta del centinela se borra al terminar."""
    valor = "Centinela ó " + secrets.token_hex(6)
    ip = f"192.0.2.{secrets.randbelow(200) + 30}"
    carpeta = salida / CARPETA_CENTINELA
    carpeta.mkdir(exist_ok=True)
    ficheros = {"centinela_literal.txt": ("centinela", valor),
                "centinela_json.txt": ("centinela", json.dumps({"t": valor})),
                "centinela_codigo.txt": ("codigo", "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH"),
                "centinela_ip.txt": ("ip_centinela", f"origen {ip}.")}
    for nombre, (_, contenido) in ficheros.items():
        (carpeta / nombre).write_text(contenido, encoding="utf-8", newline="\n")
    # El patrón de los códigos de seguimiento se busca SIEMPRE (§5.4), lo
    # pase o no quien llama.
    patrones = list(patrones)
    if not any(nombre == "codigo" for nombre, _ in patrones):
        patrones.append(("codigo", PATRON_CODIGO))
    try:
        todo = escanear_directorio(salida, {**literales, "centinela": valor},
                                   patrones + [("ip_centinela", patron_aislado(ip))])
    finally:
        shutil.rmtree(carpeta, ignore_errors=True)
    esperados = {f"{CARPETA_CENTINELA}/{n}": clave for n, (clave, _) in ficheros.items()}
    reales = {k: v for k, v in todo.items() if not k.startswith(CARPETA_CENTINELA + "/")}
    faltan = [f for f, clave in esperados.items() if clave not in todo.get(f, [])]
    return reales, faltan


def resultado_global(veredictos, fuga, git_igual):
    """OK solo si hay al menos una prueba, todas en PASA (o HECHO, P0), el
    anti-fuga en PASA y git status igual que al arrancar. (texto, código)."""
    if veredictos and all(v in VEREDICTOS_OK for v in veredictos.values()) and fuga == PASA and git_igual:
        return "OK", 0
    return "NO OK", 1


# ===========================================================================
# E/S: procesos, git, HTTP
# ===========================================================================
def ejecutar_proceso(args, timeout=120):
    """subprocess SIEMPRE con lista de argumentos (sin shell: PowerShell 5
    pierde las comillas dobles internas). check=False: el código se mira."""
    r = subprocess.run(args, capture_output=True, timeout=timeout, check=False)
    return r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace")


def git(*args):
    return ejecutar_proceso(["git", "-C", str(RAIZ), *args], timeout=120)


def estado_git():
    rc, out, _ = git("status", "--short", "-uall")
    return [linea.rstrip() for linea in out.splitlines() if linea.strip()] if rc == 0 else None


def head_git():
    rc, out, _ = git("rev-parse", "HEAD")
    return out.strip() if rc == 0 else None


def comprobar_push():
    """Q-11 y QA4: el árbol limpio y origin/main igual a HEAD (el push con
    fecha del servidor es lo que congela)."""
    rc, out, _ = git("status", "--porcelain")
    if rc != 0 or out.strip():
        raise Parada("git status --porcelain no esta vacio: el arbol tiene que estar limpio")
    head = head_git()
    rc, out, _ = git("ls-remote", "origin", "refs/heads/main")
    remoto = out.split()[0] if rc == 0 and out.split() else None
    if head is None or remoto != head:
        raise Parada("origin/main no es HEAD: falta el push")
    return head


def comprobar_diff_p6(git_=None):
    """P3 previa de P6 (plan bloque 1, §5, punto 2). Parada si el diff desde
    BASE_P3 toca lo prohibido o si app/principal.py cambia algo más que las
    9 sentencias del mamparo. Compara las versiones de HEAD (git show), no el
    árbol de trabajo: lo que se mide es lo commiteado. git() no lanza:
    devuelve (rc, out, err), así que cada rc se mira aquí. git_ solo existe
    para las unitarias. Devuelve el texto para la salida."""
    git_ = git_ or git
    # Control positivo en ejecución, antes de los reales: si el comparador no
    # distingue el par literal, no es de fiar.
    igual = comparar_principal(CONTROL_P3_VIEJO, CONTROL_P3_NUEVO)[:2]
    distinto = comparar_principal(CONTROL_P3_VIEJO, CONTROL_P3_ELSE)[:2]
    if igual != (True, True) or distinto == (True, True):
        raise Parada("SIN CONCLUSION del control de P3")

    def llamar(*args, vacio_es_fallo):
        rc, out, err = git_(*args)
        if rc != 0:
            raise Parada(f"P3: git {args[0]} devolvio {rc}: {err[-300:]}")
        # Una salida vacía solo es fallo en git show (el fichero tiene que
        # existir); en git diff significa que no hay cambios (C2).
        if vacio_es_fallo and not out.strip():
            raise Parada(f"P3: git {args[0]} sin salida")
        return out

    diff = llamar("diff", "--name-status", "--no-renames", BASE_P3, "HEAD", vacio_es_fallo=False)
    motivos = ficheros_prohibidos(diff.splitlines())
    if motivos:
        raise Parada(f"P3: el diff desde {BASE_P3} toca lo prohibido: {motivos[:5]}")
    viejo = llamar("show", f"{BASE_P3}:app/principal.py", vacio_es_fallo=True)
    nuevo = llamar("show", "HEAD:app/principal.py", vacio_es_fallo=True)
    dentro, fuera, motivo = comparar_principal(viejo, nuevo)
    if not (dentro and fuera):
        raise Parada(f"P3: app/principal.py: {motivo}")
    return f"P3 previa: diff desde {BASE_P3} sin ficheros prohibidos; app/principal.py: {motivo}"


class ConexionFijada(http.client.HTTPSConnection):
    """HTTPS/1.1 keep-alive contra una IP fijada (resuelta una vez con AF_INET)
    y desde un origen local fijo (source_address): así A y B salen cada una
    por su red, y un cambio de DNS a mitad no cambia el destino."""

    def __init__(self, host, ip, puerto, origen, contexto, plazo=PLAZO_SOCKET_S):
        super().__init__(host, puerto, timeout=plazo, source_address=(origen, 0) if origen else None,
                         context=contexto)
        self._ip = ip

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout, self.source_address)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def peticion(conexion, reloj, metodo, ruta, cuerpo=None, cabeceras=(), leer_max=1_048_576, inicio=None):
    """Una petición por la conexión. Sin User-Agent ni cookies, y sin el
    Accept-Encoding que añade http.client. Devuelve estado (0 si no hubo
    respuesta), cuerpo, cabeceras en minúsculas e instantes inicio y fin.
    inicio (B1(i)): el instante en el que el trabajador de P6 comprobó la
    guarda. Si se pasa, es el inicio de la petición: así la guarda y el
    veredicto miran el MISMO instante y no dos lecturas del reloj."""
    r = {"estado": 0, "cuerpo": b"", "cabeceras": {}, "inicio": reloj.ahora() if inicio is None else inicio,
         "fin": None, "error": ""}
    try:
        conexion.putrequest(metodo, ruta, skip_accept_encoding=True)
        for nombre, valor in cabeceras:
            conexion.putheader(nombre, valor)
        if cuerpo is not None:
            conexion.putheader("Content-Length", str(len(cuerpo)))
        conexion.endheaders(cuerpo)
        respuesta = conexion.getresponse()
        r["estado"] = respuesta.status
        for nombre, valor in respuesta.getheaders():
            clave = nombre.lower()
            r["cabeceras"][clave] = valor if clave not in r["cabeceras"] else r["cabeceras"][clave] + ", " + valor
        r["cuerpo"] = respuesta.read(leer_max)
        if not respuesta.isclosed():
            conexion.close()
    except (OSError, http.client.HTTPException) as error:
        r["error"] = type(error).__name__
        conexion.close()
    r["fin"] = reloj.ahora()
    r["ms"] = (r["fin"] - r["inicio"]) * 1000
    return r


def peticion_p3(conexion, reloj, cuerpo):
    """POST /salud con un cuerpo real. El tiempo va desde que se entrega el
    último byte al socket (o el envío falla con reset) hasta leer la línea
    de estado y las cabeceras."""
    r = {"estado": 0, "cuerpo": b"", "cabeceras": {}, "inicio": reloj.ahora(), "fin": None, "error": ""}
    entregado = None
    try:
        conexion.putrequest("POST", RUTA_SALUD, skip_accept_encoding=True)
        conexion.putheader("Content-Type", "application/octet-stream")
        conexion.putheader("Content-Length", str(len(cuerpo)))
        try:
            conexion.endheaders(cuerpo)
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as error:
            r["error"] = "envio: " + type(error).__name__
        entregado = reloj.ahora()
        respuesta = conexion.getresponse()
        estado_t = reloj.ahora()
        r["estado"] = respuesta.status
        r["cabeceras"] = {n.lower(): v for n, v in respuesta.getheaders()}
        r["cuerpo"] = respuesta.read(65536)
        r["segundos"] = estado_t - entregado
    except (OSError, http.client.HTTPException) as error:
        r["error"] = (r["error"] + "; " if r["error"] else "") + type(error).__name__
        r["segundos"] = None
    finally:
        conexion.close()
    r["fin"] = reloj.ahora()
    r["ms"] = (r["fin"] - r["inicio"]) * 1000
    return r


def fecha_de(r):
    try:
        return int(email.utils.parsedate_to_datetime(r["cabeceras"]["date"]).timestamp())
    except (KeyError, TypeError, ValueError, IndexError):
        return None


def resolver_ipv4(host):
    infos = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)
    if not infos:
        raise Parada(f"{host} no tiene registro A")
    return infos[0][4][0]


def tiene_aaaa(host):
    try:
        return bool(socket.getaddrinfo(host, 443, socket.AF_INET6, socket.SOCK_STREAM))
    except socket.gaierror:
        return False


# ===========================================================================
# Salida
# ===========================================================================
COLUMNAS_CSV = ("prueba", "red", "ruta", "planeada", "real", "inicio_servidor", "fin_servidor", "estado", "ms",
                "retry_after", "ambigua", "nota")


class Salida:
    """%TEMP%\\canario_produccion_salida_<UTC>_<prueba>\\ con salida.txt,
    peticiones.csv y resumen.json. Nunca se escriben IP, URL de vecinas ni
    códigos: las filas llevan la red (A, B, vecina_n) y la ruta."""

    def __init__(self, prueba):
        marca = datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ")
        self.dir = TEMP / f"canario_produccion_salida_{marca}_{prueba}"
        self.dir.mkdir(parents=True, exist_ok=False)
        self.lineas, self.filas, self.resumen, self.veredictos = [], [], {}, {}

    def p(self, texto):
        print(texto, flush=True)
        self.lineas.append(texto)

    def veredicto(self, prueba, v, texto):
        self.veredictos[prueba] = v
        self.p(f"{prueba} {v}: {texto}")

    def fila(self, prueba, red, ruta, r, d=None, ventana=None, planeada=None, real=None, nota=""):
        ini = fin = ambigua = ""
        if d is not None and r.get("inicio") is not None and r.get("fin") is not None:
            ini, fin = intervalo_servidor(r["inicio"], r["fin"], d[0], d[1])
            if ventana:
                ambigua = int(ventana_de_peticion(ini, fin, ventana)[1])
        self.filas.append({"prueba": prueba, "red": red, "ruta": ruta,
                           "planeada": "" if planeada is None else f"{planeada:.6f}",
                           "real": "" if real is None else f"{real:.6f}",
                           "inicio_servidor": ini, "fin_servidor": fin, "estado": r.get("estado", ""),
                           "ms": "" if r.get("ms") is None else f"{r['ms']:.3f}",
                           "retry_after": r.get("cabeceras", {}).get("retry-after", ""),
                           "ambigua": ambigua, "nota": nota})

    def escribir(self):
        (self.dir / "salida.txt").write_text("\n".join(self.lineas) + "\n", encoding="utf-8", newline="\n")
        with open(self.dir / "peticiones.csv", "w", encoding="utf-8", newline="") as fichero:
            escritor = csv.DictWriter(fichero, fieldnames=COLUMNAS_CSV, lineterminator="\n")
            escritor.writeheader()
            escritor.writerows(self.filas)
        (self.dir / "resumen.json").write_text(json.dumps(self.resumen, indent=2, sort_keys=True, ensure_ascii=False)
                                               + "\n", encoding="utf-8", newline="\n")


def guardar_privado(nombre, linea):
    """Añade una línea a un fichero de la carpeta privada (nunca se publica)."""
    PRIVADO.mkdir(parents=True, exist_ok=True)
    with open(PRIVADO / nombre, "a", encoding="utf-8", newline="\n") as fichero:
        fichero.write(linea + "\n")


# ===========================================================================
# Contexto de una ejecución
# ===========================================================================
class Contexto:
    def __init__(self, args, salida):
        self.args, self.salida, self.reloj = args, salida, Reloj()
        self.produccion = args.destino == "produccion"
        self.destino = dict(DESTINOS[args.destino])
        self.origen = {"A": args.origen_a, "B": args.origen_b}
        self.ips = {}                      # IP públicas: solo en memoria y en ips.txt
        # El anti-fuga busca también la carpeta personal (lleva el usuario de
        # Windows), que podría colarse en un mensaje de error.
        self.literales_fuga = literales_carpeta_personal(pathlib.Path.home())
        self.patrones_fuga = [("codigo", PATRON_CODIGO), ("sudo", re.compile(rb"\[sudo\]"))]
        self.franja = leer_franja(args.franja_autorizada) if self.produccion else None
        self._tls = None
        for red, origen in self.origen.items():
            if origen:
                self.patrones_fuga.append((f"origen_{red.lower()}", patron_aislado(origen)))

    @property
    def tls(self):
        """Contexto TLS, solo cuando hace falta (P4, Q-12 y --combinar no lo usan)."""
        if self._tls is None:
            if self.produccion:
                self._tls = ssl.create_default_context()
            else:
                if not self.args.ca_local or not pathlib.Path(self.args.ca_local).is_file():
                    raise Parada("destino local: falta --ca-local con la CA de Caddy (README, ensayo local)")
                # Se verifica contra la CA local de Caddy; nunca se desactiva
                # la verificación de certificados.
                self._tls = ssl.create_default_context(cafile=self.args.ca_local)
        return self._tls

    def resolver(self):
        """IP del destino, una vez y fijada. En producción, PARADA si la API
        tiene AAAA (informe l.259): dos IPv6 de la misma red compartirían
        contador. La IP del VPS no se imprime nunca y el anti-fuga la busca (N6)."""
        if self.produccion:
            if tiene_aaaa(self.destino["host_api"]):
                raise Parada("canario-api.eduumr.dev tiene AAAA")
            self.destino["ip_api"] = resolver_ipv4(self.destino["host_api"])
            self.destino["ip_web"] = resolver_ipv4(self.destino["host_web"])
            for clave in ("ip_api", "ip_web"):
                self.patrones_fuga.append((f"ip_vps_{clave}", patron_aislado(self.destino[clave])))
        else:
            self.destino["ip_api"] = self.destino["ip_web"] = "127.0.0.1"
        self.tls  # noqa: B018 - falla aquí, antes de medir, si falta la CA local

    def conexion(self, red, sitio="api"):
        return ConexionFijada(self.destino[f"host_{sitio}"], self.destino[f"ip_{sitio}"],
                              self.destino[f"puerto_{sitio}"], self.origen.get(red), self.tls)

    def anotar_ssh(self):
        """N6: user y hostname de ssh -G ovh, solo en memoria, para el anti-fuga."""
        try:
            rc, out, _ = ejecutar_proceso(["ssh", "-G", "ovh"], timeout=30)
        except (OSError, subprocess.SubprocessError):
            rc, out = 1, ""
        usuario, servidor = leer_ssh_g(out) if rc == 0 else (None, None)
        if not usuario or not servidor:
            raise Parada("ssh -G ovh no da user y hostname (el anti-fuga los necesita)")
        self.patrones_fuga += [("ssh_user", patron_aislado(usuario)), ("ssh_hostname", patron_aislado(servidor))]

    def consultar_ip(self, red):
        """S5: GET https://1.1.1.1/cdn-cgi/trace por TLS, atado al origen. Solo
        Host y Connection: close. Solo se lee ip=."""
        con = ConexionFijada("1.1.1.1", "1.1.1.1", 443, self.origen[red], ssl.create_default_context())
        try:
            con.putrequest("GET", "/cdn-cgi/trace", skip_accept_encoding=True)
            con.putheader("Connection", "close")
            con.endheaders()
            respuesta = con.getresponse()
            estado, texto = respuesta.status, respuesta.read(4096).decode("ascii", "replace")
        except (OSError, http.client.HTTPException) as error:
            raise Parada(f"consulta de IP de {red}: {type(error).__name__}") from None
        finally:
            con.close()
        if estado != 200:
            raise Parada(f"consulta de IP de {red}: estado {estado}")
        ip = validar_ip_publica(extraer_ip_trace(texto))
        del texto
        guardar_privado("ips.txt", f"{datetime.datetime.now(datetime.UTC).isoformat()} {self.args.prueba} {red} {ip}")
        self.patrones_fuga.append((f"ip_publica_{red.lower()}", patron_aislado(ip)))
        return ip


# ===========================================================================
# Piezas comunes de las pruebas de red
# ===========================================================================
def medir_a1(ctx, prueba, etiqueta):
    """A1: unas 10 peticiones del CSS (file_server de Caddy), separadas 1,1 s,
    por el origen de A (o el de B si solo corre B)."""
    red = "A" if ctx.origen.get("A") or not ctx.produccion else "B"
    con, muestras, inicio = ctx.conexion(red, "web"), [], ctx.reloj.ahora()
    try:
        for i in range(TOPE_A1):
            ctx.reloj.dormir_hasta(inicio + SEPARACION_A1_S * i)
            r = peticion(con, ctx.reloj, "GET", RUTA_CSS)
            ctx.salida.fila(prueba, red, RUTA_CSS, r, nota=f"A1 {etiqueta}")
            fecha = fecha_de(r)
            if r["estado"] != 200 or fecha is None:
                ctx.salida.p(f"   A1 {etiqueta}: muestra {i + 1} sin 200 o sin Date ({r['estado']} {r['error']})")
                return None
            muestras.append((r["inicio"], r["fin"], fecha))
    finally:
        con.close()
    v, intervalo, texto = evaluar_a1(muestras)
    ctx.salida.p(f"   {texto} ({etiqueta})")
    return intervalo if v == PASA else None


def redes_de(prueba, rol):
    """Redes que usa cada prueba (con --rol, solo la propia)."""
    necesita = {"p0": "AB", "p1": "AB", "p1b": "A", "p2": "A", "p3": "A", "p5": "B", "p6": "AB"}.get(prueba, "")
    if rol:
        necesita = "".join(r for r in necesita if r == rol.upper())
    return necesita


def abrir_prueba(ctx, prueba):
    """IP públicas (producción), A1 inicial y franja con la hora del servidor.
    Devuelve el estado de apertura o None (SIN CONCLUSION ya anotado)."""
    estado = {"ips": {}, "inicio_local": ctx.reloj.ahora()}
    if ctx.produccion:
        for red in redes_de(prueba, ctx.args.rol):
            estado["ips"][red] = ctx.consultar_ip(red)
        if len(estado["ips"]) == 2 and estado["ips"]["A"] == estado["ips"]["B"]:
            raise Parada("A y B salen con la misma IP publica")
    a1 = medir_a1(ctx, prueba, "inicial")
    if a1 is None:
        ctx.salida.veredicto(prueba.upper(), SIN_CONCLUSION, "A1 inicial sin intervalo valido")
        return None
    estado["a1"] = a1
    if ctx.produccion and prueba != "p6":
        ahora = ctx.reloj.ahora()
        comprobar_franja(ctx.franja, ahora + a1[0], ahora + a1[1] + DURACION_ESTIMADA_S[prueba])
    return estado


def cerrar_prueba(ctx, prueba, estado):
    """A1 final, IP repetidas (CGNAT) y ventana del servidor para Q-12.
    Devuelve (d envolvente o None, motivo)."""
    a1_fin = medir_a1(ctx, prueba, "final")
    if ctx.produccion:
        for red, ip in estado["ips"].items():
            if ctx.consultar_ip(red) != ip:
                return None, f"la IP publica de {red} ha cambiado durante la prueba (CGNAT)"
    d = combinar_a1(estado["a1"], a1_fin)
    if d is None:
        return None, "A1 inicial y final no se solapan (o el final no es valido)"
    ctx.salida.resumen.setdefault("ventanas_servidor", {})[prueba] = [estado["inicio_local"] + d[0],
                                                                       ctx.reloj.ahora() + d[1]]
    ctx.salida.resumen.setdefault("a1", {})[prueba] = {"inicial": estado["a1"], "final": a1_fin, "envolvente": d}
    return d, ""


def esperar_frontera(ctx, a1, mas_s=2.0, frontera_utc=None):
    """Espera a la frontera siguiente de minuto (hora del servidor) más mas_s,
    de modo que incluso con d_min el servidor ya ha pasado la frontera.
    Con frontera_utc (HH:MM, plan B con dos máquinas), esa frontera."""
    ahora = ctx.reloj.ahora()
    if frontera_utc:
        h, m = (int(x) for x in frontera_utc.split(":"))
        dia = math.floor((ahora + a1[0]) / 86400) * 86400
        frontera = dia + h * 3600 + m * 60
        if frontera - (ahora + a1[1]) < 5:
            raise Parada("--frontera-utc ya ha pasado o queda a menos de 5 s")
    else:
        frontera = ahora + a1[0] + segundos_para_frontera(ahora + a1[0], VENTANA_SEGUIMIENTO_S)
    objetivo = frontera + mas_s - a1[0]
    ctx.salida.p(f"   espera de {objetivo - ahora:.1f} s a la frontera mas {mas_s} s")
    ctx.reloj.dormir_hasta(objetivo)
    return frontera


def cuerpo_seguimiento():
    return json.dumps({"codigo": codigo_inexistente()}).encode("utf-8")


def enviar_seguimiento(con, reloj, inicio):
    """El envío de A en P6 (antes enviar_a, anidada en prueba_p6), a nivel de
    módulo para poder probarlo (B1(i)). inicio es el instante en el que el
    trabajador comprobó la guarda, y pasa a ser el inicio de la petición.
    Añade es_429 y retry_after, que piden veredicto_p6 y control_l3."""
    r = peticion(con, reloj, "POST", RUTA_SEGUIMIENTO, cuerpo_seguimiento(), [TIPO_JSON], inicio=inicio)
    r["es_429"], r["retry_after"] = es_429(r, VENTANA_SEGUIMIENTO_S), retry_after_entero(r)
    return r


def filas_para_combinar(filas, d):
    """Para --combinar: las filas con los tiempos ya pasados a hora del
    servidor (cada máquina con su A1) y sin cuerpos ni cabeceras salvo lo
    que piden los veredictos."""
    return [{"inicio": intervalo_servidor(f["inicio"], f["fin"], d[0], d[1])[0],
             "fin": intervalo_servidor(f["inicio"], f["fin"], d[0], d[1])[1],
             "estado": f["estado"], "es_404": es_404_literal(f), "es_429": es_429(f, VENTANA_SEGUIMIENTO_S),
             "retry_after": retry_after_entero(f), "ms": f.get("ms"), "red": f.get("red", "")}
            for f in filas]


# ===========================================================================
# Pruebas
# ===========================================================================
def prueba_p0(ctx):
    """P0: no es una prueba. IP públicas distintas y globales, /salud con el 200
    literal desde A y B, A1, y la revisión manual de Traefik (--p0-revisado)."""
    if not ctx.produccion:
        raise Parada("P0 solo tiene sentido contra produccion")
    estado = abrir_prueba(ctx, "p0")
    if estado is None:
        return
    for red in redes_de("p0", ctx.args.rol):
        con = ctx.conexion(red)
        try:
            r = peticion(con, ctx.reloj, "GET", RUTA_SALUD)
        finally:
            con.close()
        ctx.salida.fila("p0", red, RUTA_SALUD, r)
        if not (r["estado"] == 200 and r["cuerpo"] == CUERPO_SALUD):
            raise Parada(f"/salud desde {red} -> {r['estado']}, no el 200 literal")
    d, motivo = cerrar_prueba(ctx, "p0", estado)
    if d is None:
        ctx.salida.veredicto("P0", SIN_CONCLUSION, motivo)
        return
    if ctx.args.p0_nota:
        nota = re.sub(r"[^ -~]", "", ctx.args.p0_nota)[:300]
        ctx.salida.p(f"   Traefik, nota del autor: {nota}")
    if ctx.args.rol:
        ctx.salida.veredicto("P0", SIN_CONCLUSION, f"rol {ctx.args.rol}: A distinta de B sale de --combinar")
        return
    if not ctx.args.p0_revisado:
        ctx.salida.veredicto("P0", SIN_CONCLUSION, "falta la revision manual de Traefik (--p0-revisado)")
        return
    ctx.salida.veredicto("P0", HECHO, "IP distintas y globales, /salud 200 literal, A1 valido y Traefik revisado")


def rafaga(ctx, red, con, n, ruta, cuerpos, cabeceras_de=lambda i: ()):
    """n POST en serie por una conexión, con Content-Type: application/json (Q-10)."""
    filas = []
    for i in range(n):
        r = peticion(con, ctx.reloj, "POST", ruta, cuerpos(), [TIPO_JSON, *cabeceras_de(i)])
        r["red"] = red
        filas.append(r)
    return filas


def prueba_p1(ctx):
    estado = abrir_prueba(ctx, "p1")
    if estado is None:
        return
    a1, rol = estado["a1"], ctx.args.rol
    filas_a, filas_b = [], []
    con_a = ctx.conexion("A") if rol in (None, "a") else None
    con_b = ctx.conexion("B") if rol in (None, "b") else None
    try:
        ahora = ctx.reloj.ahora()
        frontera_prev = (ahora + a1[0]) + segundos_para_frontera(ahora + a1[0], VENTANA_SEGUIMIENTO_S)
        if con_b is not None and rol is None:
            # B abre su TLS antes de la frontera (Q-9), unos 3 s antes.
            ctx.reloj.dormir_hasta(frontera_prev - 3 - a1[1])
            r = peticion(con_b, ctx.reloj, "GET", RUTA_SALUD)
            ctx.salida.fila("p1", "B", RUTA_SALUD, r, nota="apertura TLS de B")
        frontera = esperar_frontera(ctx, a1, 2.0, ctx.args.frontera_utc)
        if rol is None:
            filas_a = rafaga(ctx, "A", con_a, 61, RUTA_SEGUIMIENTO, cuerpo_seguimiento)
            filas_b = rafaga(ctx, "B", con_b, TOPE_P1_B, RUTA_SEGUIMIENTO, cuerpo_seguimiento)
            filas_a += rafaga(ctx, "A", con_a, TOPE_P1_A - 61, RUTA_SEGUIMIENTO, cuerpo_seguimiento)
        elif rol == "a":
            filas_a = rafaga(ctx, "A", con_a, TOPE_P1_A, RUTA_SEGUIMIENTO, cuerpo_seguimiento)
        else:
            # Plan B (Q-15): B envía en la segunda mitad del minuto de A.
            r = peticion(con_b, ctx.reloj, "GET", RUTA_SALUD)
            ctx.salida.fila("p1", "B", RUTA_SALUD, r, nota="apertura TLS de B")
            ctx.reloj.dormir_hasta(frontera + 32 - a1[0])
            filas_b = rafaga(ctx, "B", con_b, TOPE_P1_B, RUTA_SEGUIMIENTO, cuerpo_seguimiento)
    finally:
        for con in (con_a, con_b):
            if con is not None:
                con.close()
    d, motivo = cerrar_prueba(ctx, "p1", estado)
    for f in filas_a + filas_b:
        ctx.salida.fila("p1", f["red"], RUTA_SEGUIMIENTO, f, d, VENTANA_SEGUIMIENTO_S)
    if d is None:
        ctx.salida.veredicto("P1", SIN_CONCLUSION, motivo)
        return
    if rol:
        ctx.salida.resumen["filas_combinar"] = filas_para_combinar(filas_a + filas_b, d)
        ctx.salida.veredicto("P1", SIN_CONCLUSION, f"rol {rol}: el veredicto sale de --combinar")
        return

    def consultar_ips():
        return ctx.consultar_ip("A"), ctx.consultar_ip("B")

    v, texto = veredicto_p1(filas_a, filas_b, d[0], d[1], consultar_ips)
    ctx.salida.veredicto("P1", v, texto)


def prueba_p1b(ctx):
    """P1b-c en una ventana y P1b en la siguiente, en la misma ejecución: el
    control de P1b es P1b-c en PASA."""
    xff = lista_xff()
    if not validar_xff(xff):
        raise Parada("la lista de X-Forwarded-For no son 70 direcciones de documentacion distintas")
    estado = abrir_prueba(ctx, "p1b")
    if estado is None:
        return
    a1 = estado["a1"]
    con = ctx.conexion("A")
    try:
        esperar_frontera(ctx, a1)
        filas_c = rafaga(ctx, "A", con, TOPE_P1B, RUTA_SEGUIMIENTO, cuerpo_seguimiento)
        esperar_frontera(ctx, a1)
        filas_x = rafaga(ctx, "A", con, TOPE_P1B, RUTA_SEGUIMIENTO, cuerpo_seguimiento,
                         lambda i: [("X-Forwarded-For", xff[i])])
    finally:
        con.close()
    d, motivo = cerrar_prueba(ctx, "p1b", estado)
    for etiqueta, filas in (("p1b-c", filas_c), ("p1b", filas_x)):
        for f in filas:
            ctx.salida.fila(etiqueta, "A", RUTA_SEGUIMIENTO, f, d, VENTANA_SEGUIMIENTO_S)
    if d is None:
        ctx.salida.veredicto("P1b-c", SIN_CONCLUSION, motivo)
        ctx.salida.veredicto("P1b", SIN_CONCLUSION, motivo)
        return
    v_c, texto_c = veredicto_p1b_c(filas_c, d[0], d[1])
    ctx.salida.veredicto("P1b-c", v_c, texto_c)
    v, texto = veredicto_p1b(filas_x, v_c == PASA, d[0], d[1])
    ctx.salida.veredicto("P1b", v, texto)


def prueba_p2(ctx):
    estado = abrir_prueba(ctx, "p2")
    if estado is None:
        return
    restantes = segundos_restantes_hora(ctx.reloj.ahora(), estado["a1"][1])
    if not p2_puede_arrancar(restantes):
        ctx.salida.veredicto("P2", SIN_CONCLUSION, f"quedan {restantes:.0f} s de la hora UTC; hacen falta mas de "
                                                   f"{MARGEN_HORA_P2_S} (no arranca)")
        return
    cuerpo = json.dumps({"categoria": "acoso"}).encode("utf-8")
    con = ctx.conexion("A")
    try:
        filas = rafaga(ctx, "A", con, TOPE_P2, RUTA_DENUNCIA, lambda: cuerpo)
    finally:
        con.close()
    d, motivo = cerrar_prueba(ctx, "p2", estado)
    for f in filas:
        ctx.salida.fila("p2", "A", "/v1/empresas/<cero>/denuncias", f, d, VENTANA_DENUNCIA_S)
    if d is None:
        ctx.salida.veredicto("P2", SIN_CONCLUSION, motivo)
        return
    v, texto = veredicto_p2(filas, d[0], d[1])
    ctx.salida.veredicto("P2", v, texto)


def prueba_p3(ctx):
    estado = abrir_prueba(ctx, "p3")
    if estado is None:
        return
    justo = peticion_p3(ctx.conexion("A"), ctx.reloj, b"x" * LIMITE_CUERPO)
    grande = peticion_p3(ctx.conexion("A"), ctx.reloj, b"x" * (LIMITE_CUERPO + 1))
    d, motivo = cerrar_prueba(ctx, "p3", estado)
    ctx.salida.fila("p3", "A", RUTA_SALUD, justo, d, nota="justo")
    ctx.salida.fila("p3", "A", RUTA_SALUD, grande, d, nota=f"grande; {grande.get('error', '')}")
    if d is None:
        ctx.salida.veredicto("P3", SIN_CONCLUSION, motivo)
        return
    v, texto, conexion = veredicto_p3(justo, grande, grande.get("segundos"))
    ctx.salida.resumen["p3_connection"] = conexion
    ctx.salida.veredicto("P3", v, texto)


def prueba_p5(ctx):
    duracion = ctx.args.duracion_p5
    if ctx.produccion and duracion != TOPE_P5_S:
        raise Parada(f"en produccion P5 dura {TOPE_P5_S} s (las cifras se congelan para P6)")
    if not 0 < duracion <= TOPE_P5_S:
        raise Parada(f"--duracion-p5 entre 1 y {TOPE_P5_S} s")
    validar_topes(TOPE_TASA_A, TOPE_DURACION_S, TOPE_PETICIONES_A, TOPE_EN_VUELO, tasa_b=1 / PERIODO_B_S)
    estado = abrir_prueba(ctx, "p5")
    if estado is None:
        return
    con, filas, retrasos = ctx.conexion("B"), [], []
    t0 = ctx.reloj.ahora() + 1
    try:
        for k in range(int(duracion / PERIODO_B_S)):
            plan = t0 + k * PERIODO_B_S       # reloj absoluto: un retraso no desplaza las siguientes
            ctx.reloj.dormir_hasta(plan)
            real = ctx.reloj.ahora()
            r = peticion(con, ctx.reloj, "POST", RUTA_SEGUIMIENTO, cuerpo_seguimiento(), [TIPO_JSON])
            r.update(planeada=plan, real=real)
            filas.append(r)
            retrasos.append(real - plan)
    finally:
        con.close()
    d, motivo = cerrar_prueba(ctx, "p5", estado)
    for f in filas:
        ctx.salida.fila("p5", "B", RUTA_SEGUIMIENTO, f, d, VENTANA_SEGUIMIENTO_S, f["planeada"], f["real"])
    if d is None:
        ctx.salida.veredicto("P5", SIN_CONCLUSION, motivo)
        return
    retraso_ok, retraso_texto = control_retraso(retrasos)
    ctx.salida.p(f"   retraso del planificador: {retraso_texto}")
    v, texto, stats = veredicto_p5(filas, retraso_ok, retraso_texto, int(duracion / PERIODO_B_S))
    ctx.salida.resumen["p5"] = stats
    ctx.salida.veredicto("P5", v, texto)
    if v == PASA:
        ctx.salida.p(f"   para el commit de congelacion: {texto_congelacion(stats)}")


def confirmar_portapapeles(ctx, leer=None):
    """N1: la declaración del autor es obligatoria; además se mira el registro
    documentado y, si no lo confirma, se avisa de forma visible en la salida."""
    if not ctx.args.portapapeles_sin_historial:
        raise Parada("falta --portapapeles-sin-historial (historial y sincronizacion del portapapeles apagados)")
    ctx.salida.p("   el autor confirma: historial (Win+V) y sincronizacion del portapapeles apagados")
    confirmado, texto = evaluar_portapapeles((leer or leer_politica_portapapeles)())
    ctx.salida.resumen["portapapeles_confirmado_por_registro"] = confirmado
    ctx.salida.p(("   portapapeles: " if confirmado else "   AVISO PORTAPAPELES: ") + texto)


def leer_bloque(ruta):
    """Lee un bloque pegado (bytes -> ASCII; lo que no lo sea queda como
    carácter no imprimible y el analizador lo rechaza)."""
    if not ruta or not pathlib.Path(ruta).is_file():
        raise Parada(f"no existe el fichero del bloque: {ruta}")
    return pathlib.Path(ruta).read_bytes().decode("ascii", "replace")


def publicar_bloque_p4(ctx, texto, analisis, etiqueta):
    """N2 y QA3: el bloque se publica tal cual SOLO si su formato es el exacto
    (marcas, StartedAt, RestartCount, Image y líneas LIMITES). Uno con texto
    ajeno (el aviso de sudo con el usuario, por ejemplo) no se publica."""
    if analisis["formato_valido"]:
        ctx.salida.p(f"   bloque {etiqueta}, pegado a mano por el autor desde su sesion SSH (tal cual):")
        for linea in texto.replace("\r", "").split("\n"):
            if linea:
                ctx.salida.p("   | " + linea)
    else:
        ctx.salida.p(f"   bloque {etiqueta} rechazado ({analisis['motivo']}): no se publica")


def prueba_p4(ctx):
    if not ctx.produccion:
        control_p4_local(ctx)
        return
    confirmar_portapapeles(ctx)
    control = leer_resumen(ctx.args.p4_control) if ctx.args.p4_control else {}
    texto = leer_bloque(ctx.args.p4_entrada)
    analisis = analizar_bloque_p4(texto)
    publicar_bloque_p4(ctx, texto, analisis, "de P4")
    ctx.salida.resumen["p4"] = {k: analisis[k] for k in ("veredicto", "motivo", "started_at", "restart_count",
                                                          "image", "primera_marca", "lineas")}
    # El control vale si lo hizo este mismo lanzar.py (el commit puede haber
    # cambiado por los documentos entre el ensayo local y P4).
    control_ok = (control.get("control_p4_ok") is True
                  and control.get("sha256_lanzar") == ctx.salida.resumen.get("sha256_lanzar"))
    if not control_ok:
        ctx.salida.veredicto("P4", SIN_CONCLUSION, "control: falta el control local de P4 en PASA hecho con este "
                                                   "mismo lanzar.py (--p4-control)")
        return
    ctx.salida.veredicto("P4", analisis["veredicto"], analisis["motivo"])


def control_p4_local(ctx):
    """Control de P4: la misma función sobre una pila local temporal
    (canario_produccion_p4, solo api y sus dependencias) con CANARIO_LIMITES
    relajado; tiene que RECHAZAR la línea. down -v al final."""
    proyecto = "canario_produccion_p4"
    base = ["docker", "compose", "-p", proyecto, "-f", str(RAIZ / "docker-compose.yml")]
    if ejecutar_proceso(["docker", "info", "--format", "{{.ServerVersion}}"])[0] != 0:
        raise Parada("docker info falla")
    for orden in (["docker", "ps", "-a", "--format", "{{.Names}}"], ["docker", "network", "ls", "--format", "{{.Name}}"],
                  ["docker", "volume", "ls", "--format", "{{.Name}}"]):
        if any(n.startswith(proyecto) for n in ejecutar_proceso(orden)[1].split()):
            raise Parada(f"ya existen recursos con el prefijo {proyecto} (restos de una ejecucion anterior)")
    subredes = {"10.88.0.0/28", "10.88.1.0/28", "10.88.2.0/28", "10.88.4.0/28"}
    for red in ejecutar_proceso(["docker", "network", "ls", "-q"])[1].split():
        partes = ejecutar_proceso(["docker", "network", "inspect", "--format",
                                   "{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}", red])[1].split()
        if partes and set(partes[1:]) & subredes:
            raise Parada(f"las subredes fijas del compose estan en uso por {partes[0]} (pare la pila canario)")
    temporal = pathlib.Path(tempfile.mkdtemp(prefix="canario_produccion_p4_"))
    override = temporal / "limites_control.yml"
    override.write_text(f"services:\n  api:\n    environment:\n      CANARIO_LIMITES: \"{LIMITES_CONTROL_P4}\"\n",
                        encoding="utf-8", newline="\n")
    base += ["-f", str(override)]
    try:
        rc, _, err = ejecutar_proceso(base + ["config", "--quiet"])
        if rc != 0:
            raise Parada(f"docker compose config falla (genere los secretos con scripts/generar_secretos.py): "
                         f"{err.strip()[:200]}")
        rc, _, err = ejecutar_proceso(base + ["up", "-d", "--build", "--wait", "api"], timeout=1800)
        ctx.salida.p(f"   up -d --build --wait api -> codigo {rc}")
        if rc != 0:
            raise Parada(f"la pila del control no arranca: {err.strip()[-300:]}")
        contenedor = ejecutar_proceso(base + ["ps", "-q", "api"])[1].strip()
        _, inspeccion, _ = ejecutar_proceso(["docker", "inspect", "--format",
                                              "{{.State.StartedAt}} {{.RestartCount}} {{.Image}}", contenedor])
        # docker logs separa stdout y stderr del contenedor; en el VPS van
        # juntos (2>&1). La primera marca es la menor de las dos primeras
        # líneas y las LIMITES se ordenan por marca: el mismo bloque.
        _, out, err = ejecutar_proceso(["docker", "logs", "--timestamps", contenedor])
        primeras = [linea.split(" ", 1)[0] for linea in (next((x for x in t.splitlines() if x.strip()), None)
                                                          for t in (out, err)) if linea]
        primeras = sorted((m for m in primeras if leer_marca(m)), key=leer_marca)
        limites = sorted((linea for linea in (out + "\n" + err).splitlines() if "canario.arranque: LIMITES (" in linea),
                         key=lambda linea: leer_marca(linea.split(" ", 1)[0]) or (0, 0))
        bloque = "\n".join([INICIO_P4, "API " + inspeccion.strip(), "PRIMERA_MARCA " + (primeras[0] if primeras else ""),
                            *limites, FIN_P4]) + "\n"
        analisis = analizar_bloque_p4(bloque)
        ok = control_p4_correcto(analisis)
        ctx.salida.resumen.update(control_p4_ok=ok, control_p4=analisis["motivo"])
        ctx.salida.veredicto("P4-control", PASA if ok else SIN_CONCLUSION,
                             f"el analizador {'rechaza' if ok else 'NO rechaza como se espera'} la linea configurada "
                             f"({analisis['veredicto']}: {analisis['motivo']})")
    finally:
        rc = ejecutar_proceso(base + ["down", "-v", "--remove-orphans", "--rmi", "local"], timeout=600)[0]
        ctx.salida.p(f"   down -v --remove-orphans --rmi local -> codigo {rc}")
        shutil.rmtree(temporal, ignore_errors=True)


# --- P6 ----------------------------------------------------------------------------
class EstadoParada:
    """La primera causa de parada gana. Cada hilo mira el evento y su propio
    plazo: nada depende de un hilo de parada (S7)."""

    def __init__(self):
        self.evento, self._candado = threading.Event(), threading.Lock()
        self.causa = self.motivo = self.instante = None

    def parar(self, causa, motivo, instante):
        with self._candado:
            if not self.evento.is_set():
                self.causa, self.motivo, self.instante = causa, motivo, instante
                self.evento.set()

    def como_dict(self):
        return None if not self.evento.is_set() else {"causa": self.causa, "motivo": self.motivo,
                                                      "instante": self.instante}


class Racha:
    """Errores seguidos (por orden de llegada de las respuestas)."""

    def __init__(self, maximo):
        self.maximo, self.n, self._candado = maximo, 0, threading.Lock()

    def anotar(self, error):
        with self._candado:
            self.n = self.n + 1 if error else 0
            return self.n >= self.maximo


def ejecutar_a(llegadas, t0, reloj, fabrica, enviar, parada, duracion, en_vuelo, tope, registro, conexiones,
               permite=None, racha=None):
    """Carga de A (S7). Un despachador y `en_vuelo` trabajadores, cada uno con
    su conexión. Cada uno calcula fin = monotonic_inicio + duracion y lo mira
    antes de cada envío. Una llegada sin conexión libre es un descarte; una
    que la guarda no deja lanzar se omite y no se reenvía. Devuelve
    (omitidas, descartes). conexiones recibe cada conexión creada; al salir
    se cierran todas aquí, haya terminado su hilo o no.

    La guarda (B1(i)) tiene la última palabra en el TRABAJADOR: toma
    real = reloj.ahora(), comprueba permite(real) y, si pasa, envía con
    enviar(con, reloj, real), de modo que ese mismo instante es el inicio de
    la petición. Así una llegada que el despachador vio permitida pero que el
    trabajador recoge tarde, ya dentro de la zona ciega, se omite en vez de
    lanzarse.

    La guarda del despachador se queda como prefiltro conservador, con la
    misma permite: sin ella, una llegada de la zona ciega que coincide con los
    `en_vuelo` trabajadores ocupados acabaría en descartes en vez de en
    omitidas, y veredicto_p6 convierte cualquier descarte en SIN CONCLUSION.
    El prefiltro solo puede omitir de más, nunca lanzar algo que el
    trabajador rechace. La lista omitidas mezcla las de los dos sitios."""
    fin_mono = time.monotonic() + duracion
    permite = permite or (lambda t: True)
    libres, trabajadores, omitidas, descartes, propias = queue.Queue(), [], [], [], []
    # Escriben en omitidas el despachador y varios trabajadores: candado
    # explícito, sin fiarse de que list.append sea atómico en CPython.
    candado_omitidas = threading.Lock()
    terminar = threading.Event()

    def trabajar(cola):
        con = fabrica()
        conexiones.append(con)
        propias.append(con)
        try:
            while True:
                try:
                    tarea = cola.get(timeout=0.05)
                except queue.Empty:
                    if terminar.is_set():
                        return
                    continue
                k, plan = tarea
                if time.monotonic() >= fin_mono or parada.evento.is_set():
                    libres.put(cola)
                    continue
                real = reloj.ahora()
                if not permite(real):
                    with candado_omitidas:
                        omitidas.append((k, plan))
                    libres.put(cola)
                    continue
                r = enviar(con, reloj, real)
                r.update(k=k, planeada=plan, real=real)
                registro.append(r)
                if racha is not None and racha.anotar(es_error(r["estado"])):
                    parada.parar("errores_a", f"{ERRORES_SEGUIDOS_A} errores seguidos de A", reloj.ahora())
                libres.put(cola)
        finally:
            con.close()

    for _ in range(en_vuelo):
        cola = queue.Queue(maxsize=1)
        hilo = threading.Thread(target=trabajar, args=(cola,), daemon=True)
        trabajadores.append((hilo, cola))
        hilo.start()
        libres.put(cola)
    enviadas = 0
    try:
        for k, t in enumerate(llegadas):
            plan = t0 + t
            while time.monotonic() < fin_mono and not parada.evento.is_set():
                resto = plan - reloj.ahora()
                if resto <= 0:
                    break
                time.sleep(min(resto, 0.05))
            if time.monotonic() >= fin_mono or parada.evento.is_set() or enviadas >= tope:
                break
            # Prefiltro del despachador (ver la docstring); el trabajador decide.
            if not (permite(plan) and permite(reloj.ahora())):
                with candado_omitidas:
                    omitidas.append((k, plan))
                continue
            try:
                cola = libres.get_nowait()
            except queue.Empty:
                descartes.append((k, plan))
                continue
            cola.put((k, plan))
            enviadas += 1
    finally:
        # Cada trabajador sale al ver la cola vacía con el aviso puesto; una
        # tarea pendiente la ve con el plazo vencido y no la envía.
        terminar.set()
        limite = max(fin_mono, time.monotonic()) + PLAZO_SOCKET_S + 1
        for hilo, _ in trabajadores:
            hilo.join(timeout=max(0.0, limite - time.monotonic()))
        for con in list(propias):
            try:
                con.close()
            except OSError:
                pass
    return omitidas, descartes


def ejecutar_b(t0, reloj, con, parada, duracion, registro, n_llegadas=MUESTRAS_B_P6):
    """B a 0,5/s por reloj absoluto, con su plazo propio y su tope."""
    fin_mono = time.monotonic() + duracion
    racha = Racha(ERRORES_SEGUIDOS_B)
    try:
        for k in range(n_llegadas):
            plan = t0 + k * PERIODO_B_S
            if not reloj.dormir_hasta(plan, parada.evento) or time.monotonic() >= fin_mono:
                break
            real = reloj.ahora()
            r = peticion(con, reloj, "POST", RUTA_SEGUIMIENTO, cuerpo_seguimiento(), [TIPO_JSON])
            r.update(k=k, planeada=plan, real=real)
            registro.append(r)
            if racha.anotar(es_error(r["estado"])):
                parada.parar("errores_b", f"{ERRORES_SEGUIDOS_B} errores seguidos de B", reloj.ahora())
    finally:
        con.close()


def ejecutar_sondas(vecina, ctx, inicio, duracion, fin_evento, parada, p95_ref, fase, registro):
    """Sondas GET a una vecina cada 2 s desde A, por una conexión propia, sin
    cookies ni User-Agent y sin seguir redirecciones (http.client no las
    sigue). Su plazo propio y su tope de peticiones."""
    fin_mono = time.monotonic() + duracion
    ip = resolver_ipv4(vecina["host"])
    con = ConexionFijada(vecina["host"], ip, vecina["puerto"], ctx.origen["A"], ssl.create_default_context())
    historial = []
    try:
        for k in range(int(duracion / PERIODO_SONDA_S) + 1):
            plan = inicio + k * PERIODO_SONDA_S
            if not ctx.reloj.dormir_hasta(plan, fin_evento) or time.monotonic() >= fin_mono:
                break
            real = ctx.reloj.ahora()
            r = peticion(con, ctx.reloj, "GET", vecina["ruta"], leer_max=262144)
            segundos = r["ms"] / 1000
            registro.append({"alias": vecina["alias"], "planeada": plan, "real": real, "estado": r["estado"],
                             "ms": r["ms"], "inicio": r["inicio"], "fin": r["fin"], "fase": fase["valor"]})
            historial.append((r["estado"], segundos))
            motivo = evaluar_sondas(historial, p95_ref.get(vecina["alias"]))
            if motivo and fase["valor"] != "post":
                parada.parar("vecina", f"{vecina['alias']}: {motivo}", real)
    finally:
        con.close()


def leer_sal():
    ruta = PRIVADO / "sal_vecinas.bin"
    if not ruta.is_file():
        raise Parada("no existe la sal de las vecinas en la carpeta privada (--prueba hmac-vecinas)")
    sal = ruta.read_bytes()
    if len(sal) != 32:
        raise Parada("la sal de las vecinas no tiene 32 bytes")
    return sal


def preparar_vecinas(ctx):
    """N4: el script comprueba el HMAC al arrancar P6, sobre los bytes del
    fichero, exigidos en UTF-8 sin BOM y con LF."""
    if not ctx.args.vecinas or not pathlib.Path(ctx.args.vecinas).is_file():
        raise Parada("falta --vecinas")
    datos = pathlib.Path(ctx.args.vecinas).read_bytes()
    vecinas = leer_vecinas(validar_bytes_vecinas(datos))
    sal = leer_sal()
    if not hmac.compare_digest(hmac_vecinas(sal, datos), HMAC_VECINAS):
        raise Parada("el HMAC del fichero de vecinas no es el congelado")
    ctx.literales_fuga["sal_hex"] = sal.hex()
    ctx.literales_fuga["sal_HEX"] = sal.hex().upper()
    for v in vecinas:
        ctx.literales_fuga[f"url_{v['alias']}"] = v["url"]
        ctx.patrones_fuga.append((f"host_{v['alias']}", patron_aislado(v["host"])))
    return vecinas


def relectura_api(ctx):
    """Q-5: la relectura manual de la API antes de P6 coincide con P4."""
    confirmar_portapapeles(ctx)
    anterior = analizar_bloque_p4(leer_bloque(ctx.args.p4_anterior))
    texto = leer_bloque(ctx.args.p4_entrada)
    nuevo = analizar_bloque_p4(texto)
    publicar_bloque_p4(ctx, texto, nuevo, "de la relectura antes de P6")
    if anterior["veredicto"] != PASA or nuevo["veredicto"] != PASA:
        raise Parada("la relectura de P4 o el P4 anterior no dan PASA: repetir P4")
    iguales, motivo = comparar_relectura(anterior, nuevo)
    if not iguales:
        raise Parada(motivo)
    ctx.salida.p(f"   Q-5: {motivo}")


def prueba_p6(ctx):
    if not ctx.produccion:
        raise Parada("P6 solo contra produccion (no tiene ensayo local con un solo origen)")
    comprobar_congelacion()
    ctx.salida.p(f"   {comprobar_diff_p6()}")
    llegadas = construir_plan_a()
    validar_topes(TOPE_TASA_A, TOPE_DURACION_S, TOPE_PETICIONES_A, TOPE_EN_VUELO, 1 / PERIODO_B_S, PERIODO_SONDA_S)
    rol = ctx.args.rol
    vecinas = preparar_vecinas(ctx) if rol in (None, "a") else []
    if rol in (None, "a"):
        relectura_api(ctx)
    estado = abrir_prueba(ctx, "p6")
    if estado is None:
        return
    a1 = estado["a1"]
    comprobar_franja_p6(ctx.reloj.ahora(), a1[0], a1[1], ctx.franja)
    parada, fase, p95_ref = EstadoParada(), {"valor": "base"}, {}
    fin_sondas = threading.Event()
    sondas, hilos_sondas, filas_a, filas_b, conexiones, hilos = [], [], [], [], [], []
    omitidas, descartes = [], []
    inicio_sondas = ctx.reloj.ahora() + 1
    duracion_sondas = LINEA_BASE_S + 65 + TOPE_DURACION_S + POST_CARGA_S + 5
    try:
        for v in vecinas:
            hilo = threading.Thread(target=ejecutar_sondas, daemon=True,
                                    args=(v, ctx, inicio_sondas, duracion_sondas, fin_sondas, parada, p95_ref, fase, sondas))
            hilos_sondas.append(hilo)
            hilo.start()
        if vecinas:
            ctx.reloj.dormir_hasta(inicio_sondas + LINEA_BASE_S)
            for v in vecinas:
                base = sorted(s["ms"] / 1000 for s in list(sondas) if s["alias"] == v["alias"] and s["fase"] == "base")
                primera = next((s for s in list(sondas) if s["alias"] == v["alias"]), None)
                if not base or primera is None or primera["estado"] != v["esperado"]:
                    raise Parada(f"{v['alias']}: la linea base no empieza con el estado esperado")
                p95_ref[v["alias"]] = percentil(base, 95)
            if parada.evento.is_set():
                raise Parada(f"una vecina ya falla en la linea base: {parada.motivo}")
        fase["valor"] = "espera"
        # Sin --frontera-utc, la siguiente; con ella (plan B), la acordada por
        # los dos roles, y PARADA si la línea base no ha acabado a tiempo.
        frontera = esperar_frontera(ctx, a1, 0.0, ctx.args.frontera_utc)
        # t0 tal que t0 + d_min ya es la frontera: la primera llegada cae en la ventana nueva.
        t0 = frontera - a1[0] + 0.01
        if parada.evento.is_set():
            raise Parada(f"parada antes de la carga: {parada.motivo}")
        fase["valor"] = "carga"
        if rol in (None, "a"):
            racha_a = Racha(ERRORES_SEGUIDOS_A)

            # La guarda sigue con el A1 INICIAL: el final aún no existe.
            def correr_a():
                o, d_ = ejecutar_a(llegadas, t0, ctx.reloj, lambda: ctx.conexion("A"), enviar_seguimiento, parada,
                                   TOPE_DURACION_S, TOPE_EN_VUELO, TOPE_PETICIONES_A, filas_a, conexiones,
                                   lambda t: permite_guarda(t, a1[0], a1[1]), racha_a)
                omitidas.extend(o)
                descartes.extend(d_)
            hilos.append(threading.Thread(target=correr_a, daemon=True))
        if rol in (None, "b"):
            con_b = ctx.conexion("B")
            conexiones.append(con_b)
            hilos.append(threading.Thread(target=ejecutar_b, daemon=True,
                                          args=(t0, ctx.reloj, con_b, parada, TOPE_DURACION_S, filas_b)))
        for hilo in hilos:
            hilo.start()
        limite_join = time.monotonic() + PLAZO_JOIN_S
        for hilo in hilos:
            hilo.join(timeout=max(0.0, limite_join - time.monotonic()))
        fin_carga = ctx.reloj.ahora()
        fase["valor"] = "post"
        # Las sondas siguen 60 s más (información), desde la parada o el fin.
        ctx.reloj.dormir_hasta(max(fin_carga, parada.instante or fin_carga) + POST_CARGA_S)
    finally:
        fin_sondas.set()
        # Si se sale por una excepción con la carga en marcha, A y B se paran
        # ya (además de sus plazos propios).
        if any(h.is_alive() for h in hilos):
            parada.parar("interrupcion", "salida del hilo principal con la carga en marcha", ctx.reloj.ahora())
        for con in conexiones:
            try:
                con.close()
            except OSError:
                pass
        for hilo in hilos_sondas:
            hilo.join(timeout=PLAZO_SOCKET_S + 2)
    d, motivo = cerrar_prueba(ctx, "p6", estado)
    for s in sondas:
        ctx.salida.fila("p6", s["alias"], "sonda", s, None, None, s["planeada"], s["real"], nota=s["fase"])
    for f in filas_a:
        ctx.salida.fila("p6", "A", RUTA_SEGUIMIENTO, f, d, VENTANA_SEGUIMIENTO_S, f["planeada"], f["real"])
    for f in filas_b:
        ctx.salida.fila("p6", "B", RUTA_SEGUIMIENTO, f, d, VENTANA_SEGUIMIENTO_S, f["planeada"], f["real"])
    for k, plan in omitidas:
        ctx.salida.fila("p6", "A", RUTA_SEGUIMIENTO, {}, planeada=plan, nota="omitida por la guarda (D10)")
    for k, plan in descartes:
        ctx.salida.fila("p6", "A", RUTA_SEGUIMIENTO, {}, planeada=plan, nota="descarte")
    retrasos = [f["real"] - f["planeada"] for f in filas_a + filas_b + sondas]
    retraso_ok, retraso_texto = control_retraso(retrasos)
    ctx.salida.p(f"   retraso del planificador: {retraso_texto}")
    ctx.salida.resumen["p6"] = {"lanzadas_a": len(filas_a), "omitidas_guarda": len(omitidas),
                                "descartes": len(descartes), "b": len(filas_b), "sondas": len(sondas),
                                "parada": parada.como_dict(), "retraso_ok": retraso_ok,
                                "p95_linea_base_s": p95_ref}
    if parada.evento.is_set():
        ctx.salida.p(f"   parada: {parada.causa}: {parada.motivo}")
    ctx.salida.p("   D10: la guarda evita a proposito el caso '120 si cruza la frontera' de l.100; "
                 "lo mide L3 en local (maximo_deslizante se da como informacion)")
    if d is None:
        ctx.salida.veredicto("P6", SIN_CONCLUSION, motivo)
        return
    if rol:
        ctx.salida.resumen["filas_combinar"] = filas_para_combinar(
            [dict(f, red="A") for f in filas_a] + [dict(f, red="B") for f in filas_b], d)
        ctx.salida.resumen["p6_rol"] = {"descartes": len(descartes), "retraso_ok": retraso_ok}
        ctx.salida.veredicto("P6", SIN_CONCLUSION, f"rol {rol}: el veredicto sale de --combinar")
        return
    v, motivos, info = veredicto_p6(filas_a, filas_b, d[0], d[1], parada.como_dict(), len(descartes), retraso_ok,
                                    P6_P50_B_MAX_MS)
    ctx.salida.resumen["p6"].update(info)
    ctx.salida.p(f"   maximo deslizante de A (informacion): {info.get('maximo_deslizante')}")
    ctx.salida.veredicto("P6", v, "; ".join(motivos))


# --- Q-12, combinar y HMAC de las vecinas --------------------------------------------
def leer_resumen(directorio):
    ruta = pathlib.Path(directorio) / "resumen.json"
    if not ruta.is_file():
        raise Parada(f"no existe {ruta}")
    return json.loads(ruta.read_text(encoding="utf-8"))


def prueba_q12(ctx):
    if not ctx.args.salidas:
        raise Parada("falta --salidas con las carpetas de salida de las pruebas del bloque")
    ventanas = {}
    for directorio in ctx.args.salidas:
        for prueba, (desde, hasta) in leer_resumen(directorio).get("ventanas_servidor", {}).items():
            # Con el nombre de la carpeta: dos ejecuciones de la misma prueba no se pisan.
            ventanas[f"{prueba}@{pathlib.Path(directorio).name}"] = (desde, hasta)
    if not ventanas:
        raise Parada("las salidas no traen ventanas del servidor")
    if not ctx.args.q12_entrada:
        comando = comando_q12(min(v[0] for v in ventanas.values()), max(v[1] for v in ventanas.values()))
        ctx.salida.p("   pegue en su sesion 'ssh ovh' (tras 'sudo -v'):")
        ctx.salida.p("   " + comando)
        ctx.salida.veredicto("Q12", SIN_CONCLUSION, "comando impreso; falta --q12-entrada con el bloque")
        return
    confirmar_portapapeles(ctx)
    v, texto, detalle = analizar_q12(leer_bloque(ctx.args.q12_entrada), ventanas)
    ctx.salida.resumen["q12"] = detalle
    ctx.salida.veredicto("Q12", v, texto)


def leer_ip_privada(ruta, red):
    """Última IP de la red en un ips.txt privado (plan B, --combinar)."""
    if not ruta or not pathlib.Path(ruta).is_file():
        raise Parada(f"falta el ips.txt privado de {red}")
    ips = [linea.split()[-1] for linea in pathlib.Path(ruta).read_text(encoding="utf-8").splitlines()
           if len(linea.split()) == 4 and linea.split()[2] == red]
    if not ips:
        raise Parada(f"el ips.txt de {red} no trae ninguna IP de {red}")
    return ips[-1]


def combinar(ctx):
    """Plan B con dos máquinas (Q-15): se niega si los commits difieren o algún
    árbol no estaba limpio; después aplica los mismos veredictos a las filas
    ya pasadas a hora del servidor (cada rol con su A1), con d = [0; 0]."""
    dir_a, dir_b = ctx.args.combinar
    ra, rb = leer_resumen(dir_a), leer_resumen(dir_b)
    if ra.get("head") is None or ra.get("head") != rb.get("head"):
        raise Parada("los dos roles no estan en el mismo commit")
    if not (ra.get("porcelana_vacia") and rb.get("porcelana_vacia")):
        raise Parada("algun rol no tenia el arbol limpio")
    if (ra.get("rol"), rb.get("rol")) != ("a", "b") or ra.get("prueba") != rb.get("prueba"):
        raise Parada("--combinar espera la salida del rol a y la del rol b de la misma prueba")
    prueba = ra["prueba"]
    ip_a, ip_b = leer_ip_privada(ctx.args.ips_a, "A"), leer_ip_privada(ctx.args.ips_b, "B")
    ctx.patrones_fuga += [("ip_publica_a", patron_aislado(ip_a)), ("ip_publica_b", patron_aislado(ip_b))]
    if ip_a == ip_b:
        raise Parada("A y B tienen la misma IP publica")
    filas_a = [f for f in ra.get("filas_combinar", []) if f["red"] == "A"]
    filas_b = [f for f in rb.get("filas_combinar", []) if f["red"] == "B"]
    for f in filas_a + filas_b:
        # Los veredictos miran el cuerpo literal a través de estas marcas.
        f["cuerpo"] = CUERPO_404 if f["es_404"] else (CUERPO_429 if f["es_429"] else b"")
        f["cabeceras"] = dict(CABECERAS_SEGURIDAD, **({"retry-after": str(f["retry_after"])}
                                                      if f["retry_after"] >= 0 else {})) if f["es_429"] else {}
    if prueba == "p0":
        ctx.salida.veredicto("P0", HECHO if ctx.args.p0_revisado else SIN_CONCLUSION,
                             "dos maquinas con IP distintas" + ("" if ctx.args.p0_revisado else "; falta --p0-revisado"))
    elif prueba == "p1":
        v, texto = veredicto_p1(filas_a, filas_b, 0.0, 0.0, lambda: (ip_a, ip_b))
        ctx.salida.veredicto("P1", v, texto + " (dos maquinas; B en la segunda mitad del minuto)")
    elif prueba == "p6":
        comprobar_congelacion()
        parada = ra.get("p6", {}).get("parada") or rb.get("p6", {}).get("parada")
        if parada is not None:
            # El instante de la parada se pasa también a hora del servidor.
            d_rol = (ra if ra.get("p6", {}).get("parada") else rb)["a1"]["p6"]["envolvente"]
            parada = dict(parada, instante=parada["instante"] + d_rol[0])
        retraso_ok = ra.get("p6_rol", {}).get("retraso_ok") and rb.get("p6_rol", {}).get("retraso_ok")
        v, motivos, _ = veredicto_p6(filas_a, filas_b, 0.0, 0.0, parada, ra.get("p6_rol", {}).get("descartes", 0),
                                     bool(retraso_ok), P6_P50_B_MAX_MS)
        ctx.salida.veredicto("P6", v, "; ".join(motivos) + " (dos maquinas)")
    else:
        raise Parada(f"--combinar no aplica a {prueba}")


def generar_hmac_vecinas(args):
    """Crea la sal (32 bytes, solo en la carpeta privada) si no existe e
    imprime el HMAC del fichero de vecinas para el commit de congelación."""
    if not args.vecinas or not pathlib.Path(args.vecinas).is_file():
        raise Parada("falta --vecinas")
    datos = pathlib.Path(args.vecinas).read_bytes()
    vecinas = leer_vecinas(validar_bytes_vecinas(datos))
    PRIVADO.mkdir(parents=True, exist_ok=True)
    ruta = PRIVADO / "sal_vecinas.bin"
    if not ruta.is_file():
        # O_EXCL: nunca se pisa una sal existente (el HMAC congelado dejaría de valer).
        descriptor = os.open(ruta, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(descriptor, "wb") as fichero:
            fichero.write(secrets.token_bytes(32))
    print(f"{len(vecinas)} vecinas (alias vecina_1..vecina_{len(vecinas)})")
    print(f'HMAC_VECINAS = "{hmac_vecinas(leer_sal(), datos)}"')


# ===========================================================================
# Principal
# ===========================================================================
PRUEBAS = {"p0": prueba_p0, "p1": prueba_p1, "p1b": prueba_p1b, "p2": prueba_p2, "p3": prueba_p3,
           "p4": prueba_p4, "p5": prueba_p5, "p6": prueba_p6, "q12": prueba_q12}
SOLO_LOCAL_PERMITIDAS = ("p2", "p3", "p4", "p5")


def analizar_argumentos(argv=None):
    a = argparse.ArgumentParser(description="Pruebas de produccion de Canario (plan v3). Destino local por defecto.")
    a.add_argument("--prueba", choices=[*PRUEBAS, "hmac-vecinas", "verificar-congelacion"])
    a.add_argument("--destino", choices=("local", "produccion"), default="local")
    a.add_argument("--franja-autorizada", help="HH:MM-HH:MM en UTC; obligatoria en produccion")
    a.add_argument("--origen-a", help="IP local de la red A (fibra)")
    a.add_argument("--origen-b", help="IP local de la red B (movil por USB)")
    a.add_argument("--rol", choices=("a", "b"), help="plan B con dos maquinas (Q-15)")
    a.add_argument("--frontera-utc", help="HH:MM: frontera comun de los dos roles (plan B)")
    a.add_argument("--combinar", nargs=2, metavar=("DIR_A", "DIR_B"))
    a.add_argument("--ips-a")
    a.add_argument("--ips-b")
    a.add_argument("--p0-revisado", action="store_true")
    a.add_argument("--p0-nota")
    a.add_argument("--p4-entrada")
    a.add_argument("--p4-anterior")
    a.add_argument("--p4-control")
    a.add_argument("--portapapeles-sin-historial", action="store_true")
    a.add_argument("--vecinas")
    a.add_argument("--duracion-p5", type=int, default=TOPE_P5_S)
    a.add_argument("--ca-local")
    a.add_argument("--salidas", nargs="+")
    a.add_argument("--q12-entrada")
    return a.parse_args(argv)


def validar_argumentos(args):
    """Destino local por defecto; producción solo explícita y con franja (S3)."""
    if args.combinar:
        args.prueba = args.prueba or "combinar"
        return
    if not args.prueba:
        raise Parada("falta --prueba")
    if args.destino == "produccion":
        leer_franja(args.franja_autorizada)
        if args.prueba not in ("p4", "q12"):
            for red in redes_de(args.prueba, args.rol):
                origen = getattr(args, f"origen_{red.lower()}")
                try:
                    ipaddress.IPv4Address(origen or "")
                except ValueError:
                    raise Parada(f"--origen-{red.lower()} tiene que ser la IPv4 local de la red {red}") from None
    elif args.prueba not in SOLO_LOCAL_PERMITIDAS + ("q12",):
        raise Parada(f"{args.prueba} no tiene ensayo local (un solo origen): use --destino produccion")
    if args.frontera_utc and re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", args.frontera_utc) is None:
        raise Parada("--frontera-utc tiene que ser HH:MM")
    if args.rol and args.prueba not in ("p0", "p1", "p6"):
        raise Parada("--rol solo vale para p0, p1 y p6")
    if args.rol and args.prueba in ("p1", "p6") and not args.frontera_utc:
        raise Parada("con --rol, p1 y p6 necesitan --frontera-utc (la frontera comun de los dos roles)")


def sha256_fichero(ruta):
    return hashlib.sha256(pathlib.Path(ruta).read_bytes()).hexdigest()


def main(argv=None):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
    args = analizar_argumentos(argv)
    if args.prueba == "hmac-vecinas":
        try:
            generar_hmac_vecinas(args)
        except Parada as e:
            print(f"PARADA: {e}")
            return 1
        return 0
    if args.prueba == "verificar-congelacion":
        # Sin red: comprueba las constantes del commit de congelación antes
        # de llegar a las 23:00 con una PARADA.
        v, texto = verificar_congelacion()
        print(f"CONGELACION {v}: {texto}")
        return 0 if v == PASA else 1
    git_arranque = estado_git()
    try:
        validar_argumentos(args)
    except Parada as e:
        print(f"PARADA: {e}")
        print("RESULTADO GLOBAL: NO OK")
        return 1
    salida = Salida(args.prueba)
    ctx = None
    salida.resumen.update(prueba=args.prueba, destino=args.destino, rol=args.rol, relojes=info_relojes(),
                          head=head_git(), git_status_arranque=git_arranque, sha256_lanzar=sha256_fichero(__file__))
    rc, out, _ = git("status", "--porcelain")
    salida.resumen["porcelana_vacia"] = rc == 0 and not out.strip()
    salida.p(f"Canario, pruebas de produccion: {args.prueba}, destino {args.destino}"
             + (f", rol {args.rol}" if args.rol else ""))
    try:
        ctx = Contexto(args, salida)
        if args.destino == "produccion" or args.combinar:
            if not args.combinar:
                comprobar_push()
                ctx.anotar_ssh()
                if args.prueba not in ("p4", "q12") and not args.p0_revisado and args.prueba != "p0":
                    raise Parada("falta --p0-revisado: Traefik sin revisar (S4)")
        if args.combinar:
            combinar(ctx)
        else:
            if args.prueba not in ("p4", "q12"):
                ctx.resolver()
                if ctx.produccion:
                    ahora = ctx.reloj.ahora()
                    comprobar_franja(ctx.franja, ahora, ahora + 1)
            PRUEBAS[args.prueba](ctx)
    except Parada as e:
        salida.veredicto(args.prueba.upper(), PARADA, str(e))
    except Exception as e:  # noqa: BLE001 - un fallo del script tiene que verse, no tragarse
        salida.veredicto(args.prueba.upper(), PARADA, f"error inesperado del script: {type(e).__name__}")
        raise
    finally:
        salida.escribir()
        literales = ctx.literales_fuga if ctx else {}
        patrones = ctx.patrones_fuga if ctx else [("codigo", PATRON_CODIGO)]
        reales, faltan = escanear_con_centinela(salida.dir, literales, patrones)
        fuga, texto = veredicto_fuga(reales, not faltan)
        salida.p(f"ANTIFUGA {fuga}: {texto if fuga == PASA or not reales else 'hallazgos en ' + str(sorted(reales))}")
        if fuga != PASA:
            salida.p("   NO PUBLICAR esta salida")
        git_igual = estado_git() == git_arranque and git_arranque is not None
        salida.p(f"git status {'igual' if git_igual else 'DISTINTO'} que al arrancar")
        texto_global, codigo = resultado_global(salida.veredictos, fuga, git_igual)
        salida.p(f"RESULTADO GLOBAL: {texto_global}")
        salida.escribir()
        # Solo por consola: la ruta de %TEMP% lleva el usuario de Windows.
        print(f"salida en {salida.dir}")
    return codigo


if __name__ == "__main__":
    sys.exit(main())
