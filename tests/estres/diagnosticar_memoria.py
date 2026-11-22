#!/usr/bin/env python3
"""Banco D1: diagnóstico de la memoria de la API bajo login (plan D1 v3).
Se ejecuta en el host, desde la raíz del repo:

    python tests\\estres\\diagnosticar_memoria.py

Pregunta: ¿por qué la API muere a los 14 s de login a 51/s en L1 (33
salidas con código 137)? La hipótesis principal (causa 1) es que cada hilo
de AnyIO que calcula un Argon2 de 19 MiB deja en su arena de glibc unos 19
MiB que no se devuelven, porque el import ya subió el umbral dinámico de
mmap a unos 19 MiB (malloc.c:3457-3462) y el top de un heap de hilo no se
recorta (malloc.c:5255). Las predicciones están escritas como literales
ANTES de medir (constantes de este fichero) y no se derivan de nada medido.

Qué hace:
* comprobaciones previas con PARADA: Docker, ningún recurso con el prefijo
  canario_diag, los parámetros de Argon2id y del semáforo de
  app/personal.py como literales;
* la CPU: el mismo cpuset de 2 CPU que lanzar.py da a Canario, leído con
  la imagen fijada de Redis del compose;
* construye la imagen de la API (docker build, etiqueta canario_diag_api)
  y, en un contenedor endurecido como el servicio api, la PARADA previa
  del plan: cgroup v2 (cgroup2fs), cada fichero y clave, glibc 2.41,
  usuario 10001, el import de app.personal sin secretos ni red y anyio
  4.15.1 con abandon_on_cancel=False y el limitador de 40;
* 3 rondas de 7 variantes (P, D, A, A2, E, B y C2) con el orden rotado, y
  A-t una vez: 22 ejecuciones, cada una en su contenedor (sin --rm ni
  política de reinicio), con docker events --filter event=oom desde fuera
  y un plazo de 360 s;
* el análisis (funciones puras, separadas de la recogida), una tabla por
  variante y un veredicto por oráculo con su motivo;
* limpieza en finally: contenedores, imagen y comprobación de que no queda
  nada con el prefijo, git status igual al del arranque y RESULTADO GLOBAL.

Diferencias declaradas con L1: sin healthcheck, sin HTTP, sin base de datos
ni Redis, sin uvicorn y sin red (--network none). La carga llama
directamente a _hueco_hash y _verificar_hash desde hilos de AnyIO con el
limitador por defecto, como la ruta def del login. Ese modo normal es el
diagnóstico de la API de antes del arreglo (commit c1eaa13): sobre la API
arreglada, _hueco_hash ya no existe y la PARADA previa lo detiene.

Modo --regresion (plan R1 v2), sobre la API arreglada:

    python tests\\estres\\diagnosticar_memoria.py --regresion

Reutiliza toda la infraestructura (imagen, contenedor endurecido,
supervisor, fases, análisis) con 4 variantes, 3 rondas de cada una:
* P, el control positivo de D1, sin cambios;
* D, la línea base de D1 (1 hilo) con su oráculo; como _hueco_hash ya no
  existe, el camino viejo se reconstruye (semáforo real y
  personal._hasher.verify en el hilo de AnyIO);
* V, el control del camino viejo con 40 hilos y 1 GiB (como A2): debe dar
  a >= 30 en F2, o todo queda SIN CONCLUSION; es además la referencia de
  tiempos de la sesión;
* R, el arreglo con 256 MiB, como producción: el ejecutor de la API creado
  con su misma iniciar_ejecutor_hashes() y _verificar_en_ejecutor, con los
  oráculos literales del plan (constantes "Oráculos de --regresion").
La salida va a verificacion_diag_memoria_regresion.txt, para no pisar la
de D1.

No modifica nada del repo ni toca secrets/. Solo biblioteca estándar.
"""
import collections
import json
import math
import pathlib
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import traceback

RAIZ = pathlib.Path(__file__).resolve().parent.parent.parent
DIR_ESTRES = RAIZ / "tests" / "estres"
COMPOSE = RAIZ / "docker-compose.yml"
PERSONAL = RAIZ / "app" / "personal.py"
PROGRAMA = DIR_ESTRES / "diag_memoria_contenedor.py"
PROGRAMA_DENTRO = "/diag/diag_memoria_contenedor.py"
PROYECTO = "canario_diag"
IMAGEN = "canario_diag_api"
SALIDA_TEXTO = pathlib.Path(tempfile.gettempdir()) / "verificacion_diag_memoria.txt"
SALIDA_TEXTO_REGRESION = pathlib.Path(tempfile.gettempdir()) / "verificacion_diag_memoria_regresion.txt"

lineas_salida = []
estado = {"falla": False, "sin_conclusion": False}
# Modo de la ejecución: el normal (D1) o --regresion (plan R1). Lo fija
# main() una vez, antes de cualquier otra cosa, y no cambia.
MODO = {"regresion": False}

MIB = 1024 * 1024

# ---------------------------------------------------------------------------
# Oráculos (literales del plan D1 v3, escritos antes de medir)
# ---------------------------------------------------------------------------
# Tamaño del bloque de Argon2 (m = 19456 KiB = 19 MiB, app/personal.py) y
# umbral dinámico de mmap tras el import (plan, Código; malloc.c:3457-3462).
UMBRAL_ARENA = 19 * MIB
# Umbral de recorte tras el import: 2 x mmap_threshold (malloc.c:3461).
UMBRAL_RECORTE = 38 * MIB
# Causa 1: |Retenido - a x 19 MiB| <= max(0,3 x a x 19 MiB, 10 MiB).
TOLERANCIA_RELATIVA = 0.3
TOLERANCIA_ABSOLUTA = 10 * MIB
# uordblks "sin pendiente": variación menor de 1 MiB entre fines de fase. La
# causa 3 (fuga) es la contraria en D: sube 1 MiB o más.
PENDIENTE_UORDBLKS = 1 * MIB
# En el reposo, el retenido no baja más de 19 MiB.
BAJADA_MAXIMA_REPOSO = 19 * MIB
# D (línea base): retenido <= 60 MiB en cada fin de fase.
RETENIDO_MAXIMO_D = 60 * MIB
# F1 con A: la meseta de L1, 9 x 19 MiB, o un oom_kill.
MESETA_L1 = 9 * UMBRAL_ARENA
# E se dispara con un retenido >= 4 x 19 MiB.
DISPARO_E = 4 * UMBRAL_ARENA
# B: como mucho 2 arenas en total, contando la principal (arena.c:97 y
# :852), y retenido <= 2 x 38 MiB.
ARENAS_MAXIMAS_B = 2
RETENIDO_MAXIMO_B = 2 * UMBRAL_RECORTE
# C2: retenido <= 2 x 19 MiB y ningún bloque libre de 19 MiB o más en los
# <size> de malloc_info, y tampoco en <unsorted> (malloc.c:6013-6017), que
# el plan no nombraba. Decisión de Eduardo (21/11): cuentan los dos, porque
# un bloque libre de 19 MiB es memoria retenida en cualquier bin; así el
# criterio es más estricto contra el arreglo, no más blando.
RETENIDO_MAXIMO_C2 = 2 * UMBRAL_ARENA
BLOQUE_LIBRE_MAXIMO_C2 = 19 * MIB
# Arreglo candidato: por debajo de 256 MiB - base - 64 MiB de margen, y p50
# y p95 de verify() <= 1,25 x los de A2 (tolerancia de ±25 % de H1).
LIMITE_MEMORIA_API = 256 * MIB
MARGEN_ARREGLO = 64 * MIB
FACTOR_TIEMPO_ARREGLO = 1.25
# Control positivo P: oom_kill >= 1, el evento oom de Docker y -9.
CODIGO_SIGKILL = -9
OOM_KILL_MINIMO = 1
# PENDIENTE DE DECISION: el plan pide "muestras subiendo hasta el kill" sin
# números. Se propone: al menos 3 muestras con el hijo vivo,
# ninguna bajada de más de 4 MiB (contabilidad del kernel al mover páginas
# a swap) y la última por encima de memory.max (el hijo pasó de la RAM del
# cgroup a la swap, es decir, siguió creciendo hasta el final).
MUESTRAS_MINIMAS_P = 3
BAJADA_TOLERADA_P = 4 * MIB
# Hitos con 0 hashes en curso y 0 pendientes (plan: las muestras de los
# oráculos son solo las de fin de fase, drenadas).
EN_CURSO_EN_HITO = 0
PENDIENTES_EN_HITO = 0

# PENDIENTE DE DECISION: el plan dice que la causa 2 (objetos de Python) se
# ve si "crece tracemalloc y fordblks no", sin un número. Se usa 1 MiB, el
# mismo umbral que la pendiente de uordblks, solo para el texto informativo
# de A-t; no cambia ningún veredicto.
CRECIMIENTO_CAUSA2 = 1 * MIB

# ---------------------------------------------------------------------------
# Protocolo (literales del plan)
# ---------------------------------------------------------------------------
# F1 60 s a 51/s, R1 15 s, F2 10 s a 150/s, R2 15 s; al final malloc_trim(0).
FASES = (("F1", 51, 60), ("R1", 0, 15), ("F2", 150, 10), ("R2", 0, 15))
FASES_CARGA = ("F1", "F2")
HITOS_FASE = tuple(f"fin_{nombre}" for nombre, _, _ in FASES)
REPOSOS = (("fin_F1", "fin_R1"), ("fin_F2", "fin_R2"))
TOPE_PENDIENTES = 3000
# Decisión de Eduardo (21/11), desviación del plan (240 s): D, con 1 hilo,
# acumula unas 1500 tareas pendientes por fase y se estima en unos 218 s; con
# 240 s, un plazo agotado en D dejaría todo en SIN CONCLUSION. El plazo es un
# tope de seguridad, no un oráculo: subirlo no hace pasar nada.
PLAZO_EJECUCION_S = 360
# Margen del host sobre el plazo del hijo: arranque del contenedor, import
# de la API y escritura del final. Supuesto.
MARGEN_CONTENEDOR_S = 30
# Estimación del plan: 22 ejecuciones de unos 150 s más la construcción,
# unos 60 min; tope global de 90 min con PARADA.
ESTIMACION_EJECUCION_S = 150
ESTIMACION_CONSTRUCCION_S = 300
TIEMPO_MAXIMO_S = 90 * 60
RONDAS = 3
OBJETIVO_E_S = 0.018
HILOS_POR_DEFECTO = 40
# P reserva memory.max + swap.max + 88 MiB en trozos de 16 MiB.
EXTRA_P_MIB = 88
TROZO_P_MIB = 16
PAUSA_P_S = 0.1

# Hechos verificados (plan, Hechos): si cambian, las predicciones ya no
# valen y el banco se detiene.
GLIBC = "glibc 2.41"
ANYIO = "4.15.1"
USUARIO_IMAGEN = "10001:10001"
UID_IMAGEN = 10001
MAGIA_CGROUP2 = 0x63677270
OOM_GROUP = "0"
# Límites que debe ver el contenedor por dentro, como texto de cgroup v2:
# con --memory 256m sin --memory-swap, swap.max = 256 MiB (hecho del plan);
# con --memory 1g --memory-swap 1g, swap.max = 0.
LIMITES_256M = {"memory.max": "268435456", "memory.swap.max": "268435456"}
LIMITES_1G = {"memory.max": "1073741824", "memory.swap.max": "0"}

# Variantes. memoria_swap solo en A2 y A-t; entorno solo llega al hijo.
VARIANTES = {
    "P": {"modo": "reserva", "memoria": "256m", "limites": LIMITES_256M},
    "D": {"modo": "carga", "memoria": "256m", "limites": LIMITES_256M, "hilos": 1},
    "A": {"modo": "carga", "memoria": "256m", "limites": LIMITES_256M, "hilos": HILOS_POR_DEFECTO},
    "A2": {"modo": "carga", "memoria": "1g", "memoria_swap": "1g", "limites": LIMITES_1G,
           "hilos": HILOS_POR_DEFECTO},
    "A-t": {"modo": "carga", "memoria": "1g", "memoria_swap": "1g", "limites": LIMITES_1G,
            "hilos": HILOS_POR_DEFECTO, "tracemalloc": True},
    "E": {"modo": "carga", "memoria": "256m", "limites": LIMITES_256M, "hilos": HILOS_POR_DEFECTO,
          "argon2_e": True},
    "B": {"modo": "carga", "memoria": "256m", "limites": LIMITES_256M, "hilos": HILOS_POR_DEFECTO,
          "entorno": ("MALLOC_ARENA_MAX=2",)},
    "C2": {"modo": "carga", "memoria": "256m", "limites": LIMITES_256M, "hilos": HILOS_POR_DEFECTO,
           "entorno": ("MALLOC_MMAP_THRESHOLD_=4194304",)},
}
ORDEN_BASE = ("P", "D", "A", "A2", "E", "B", "C2")
UNA_SOLA_VEZ = "A-t"

DIFERENCIAS_L1 = (
    "sin HTTP, uvicorn ni Caddy: la carga llama a _hueco_hash y _verificar_hash desde hilos de AnyIO",
    "sin base de datos, Redis ni secretos, y --network none",
    "sin healthcheck ni politica de reinicio: un OOM mata al hijo y el supervisor (PID 1) lo registra",
    "los mismos limites que el servicio api: 256 MiB sin memswap, pids 64, read_only, cap_drop ALL, "
    "no-new-privileges, usuario de la imagen y el cpuset de 2 CPU de L1",
)

# Argon2id y semáforo de app/personal.py, como literales sobre el texto: las
# predicciones (19 MiB por hash, 2 hashes simultáneos) dependen de ellos.
LITERALES_API = (
    re.compile(r"^MEMORIA_ARGON2_KIB = 19456$", re.M),
    re.compile(r"^ITERACIONES_ARGON2 = 2$", re.M),
    re.compile(r"^PARALELISMO_ARGON2 = 1$", re.M),
    re.compile(r"^HASHES_SIMULTANEOS = 2$", re.M),
    re.compile(r"^ESPERA_HASH = 2\.0$", re.M),
    re.compile(r"PasswordHasher\(time_cost=ITERACIONES_ARGON2, memory_cost=MEMORIA_ARGON2_KIB,\s*"
               r"parallelism=PARALELISMO_ARGON2, hash_len=32, salt_len=16, type=Type\.ID\)"),
)

# ---------------------------------------------------------------------------
# Modo --regresion (plan R1 v2): variantes y oráculos literales, fijados
# ANTES de ejecutar
# ---------------------------------------------------------------------------
VARIANTES_REGRESION = {
    "P": VARIANTES["P"],
    # D de D1 con el camino viejo reconstruido: _hueco_hash ya no existe.
    "D": {**VARIANTES["D"], "camino": "viejo"},
    # V: el camino viejo con 40 hilos y 1 GiB, como A2 (control y referencia).
    "V": {"modo": "carga", "memoria": "1g", "memoria_swap": "1g", "limites": LIMITES_1G,
          "hilos": HILOS_POR_DEFECTO, "camino": "viejo"},
    # R: el arreglo con los límites de producción (256 MiB más 256 de swap).
    "R": {"modo": "carga", "memoria": "256m", "limites": LIMITES_256M, "hilos": HILOS_POR_DEFECTO,
          "camino": "arreglo"},
}
ORDEN_REGRESION = ("P", "D", "V", "R")
# V debe reproducir D1: a >= 30 en fin_F2 (A2 dio 40), o todo queda SIN
# CONCLUSION.
ARENAS_MINIMAS_V = 30
# R. Precondición: hilos vivos >= 40 en F2 (threading.active_count del hijo,
# el mismo campo "hilos" de D1); si no, la ráfaga no ejercitó la concurrencia
# que rompía el camino viejo y R queda SIN CONCLUSION.
HILOS_MINIMOS_R = 40
# Memoria de R: sin oom_kill; a <= 2; cada arena de hilo crece como mucho
# 1,3 x 19 MiB; retenido <= 60 MiB en cada fin de fase y en el máximo de cada
# fase. Los 60 MiB salen de D: 25,9 MiB con 1 arena = 19 + unos 7; con 2
# arenas, unos 45, más 15 de margen.
ARENAS_MAXIMAS_R = 2
CRECIMIENTO_MAXIMO_ARENA_R = 1.3 * UMBRAL_ARENA
RETENIDO_MAXIMO_R = 60 * MIB
# Tiempos de R, medidos dentro del hilo argon2 (el intervalo de D1): p50 y
# p95 <= 1,25 x los de V de la misma ronda Y <= 1,25 x los de A2 en D1
# (mediana de las 3 rondas: 18,5 y 23,7 ms). Si las dos referencias
# discrepan, SIN CONCLUSION.
FACTOR_TIEMPO_R = 1.25
TIEMPOS_A2_D1 = {"p50": 0.0185, "p95": 0.0237}
# Los hilos del ejecutor de la API (app/personal.py, NOMBRES_HILOS_HASH),
# como literal: R solo vale si verify() corrió en ellos y en ningún otro.
NOMBRES_HILOS_ARGON2 = ("argon2_0", "argon2_1")
# Lo que el arreglo debe tener en app/personal.py, sobre el texto: si no, la
# imagen no es la del arreglo y el modo se detiene.
LITERALES_ARREGLO = (
    re.compile(r'^PREFIJO_HILOS_HASH = "argon2"$', re.M),
    re.compile(r"ThreadPoolExecutor\(max_workers=HASHES_SIMULTANEOS, thread_name_prefix=PREFIJO_HILOS_HASH\)"),
)
DIFERENCIAS_REGRESION = (
    "sin HTTP, uvicorn ni Caddy: D y V llaman al camino viejo reconstruido (semaforo real y "
    "personal._hasher.verify en el hilo de AnyIO) y R a personal._verificar_en_ejecutor, desde hilos de AnyIO",
    *DIFERENCIAS_L1[1:],
)

PATRON_REDIS = re.compile(r"^\s*image:\s*(redis:\S+@sha256:[0-9a-f]{64})\s*$", re.M)
PATRON_HERMANAS = re.compile(r"^/sys/devices/system/cpu/cpu(\d+)/topology/thread_siblings_list (\S+)$", re.M)
ORDEN_TOPOLOGIA = ("for f in /sys/devices/system/cpu/cpu[0-9]*/topology/thread_siblings_list; "
                   "do echo $f $(cat $f); done")


# ---------------------------------------------------------------------------
# Utilidades de ejecución y de informe (copiadas de tests/estres/lanzar.py,
# :227-292, con la misma forma: cada batería lleva las suyas)
# ---------------------------------------------------------------------------
class R:
    """Resultado de un comando: código, stdout y stderr por separado."""

    def __init__(self, rc, out, err):
        self.rc, self.out, self.err = rc, out, err

    @property
    def todo(self):
        return self.out + self.err


class Parada(Exception):
    pass


def p(texto=""):
    print(texto, flush=True)
    lineas_salida.append(texto)


def ejecutar(args, timeout=900):
    # check=False explícito: el código de salida se comprueba en cada llamada.
    r = subprocess.run(args, capture_output=True, timeout=timeout, check=False)
    return R(r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace"))


def pasa(cond, texto):
    p(("PASA  " if cond else "FALLA ") + texto)
    if not cond:
        estado["falla"] = True


def sinc(texto):
    p("SIN CONCLUSION " + texto)
    estado["sin_conclusion"] = True


def variantes():
    """La tabla de variantes del modo de esta ejecución."""
    return VARIANTES_REGRESION if MODO["regresion"] else VARIANTES


def salida_texto():
    return SALIDA_TEXTO_REGRESION if MODO["regresion"] else SALIDA_TEXTO


def terminar():
    if estado["falla"] or estado["sin_conclusion"]:
        resultado = "NO OK (hay FALLA o SIN CONCLUSION)"
    else:
        resultado = "OK"
    p("RESULTADO GLOBAL: " + resultado)
    salida_texto().write_text("\n".join(lineas_salida) + "\n", encoding="utf-8", newline="\n")
    sys.exit(0 if resultado == "OK" else 1)


def terminar_con_parada():
    p("RESULTADO GLOBAL: NO OK (PARADA)")
    salida_texto().write_text("\n".join(lineas_salida) + "\n", encoding="utf-8", newline="\n")
    sys.exit(1)


def estado_git():
    """Líneas de "git status --short -uall", o None si git no está disponible o falla."""
    try:
        r = ejecutar(["git", "-C", str(RAIZ), "status", "--short", "-uall"], timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.rc != 0:
        return None
    return [linea.rstrip() for linea in r.out.splitlines() if linea.strip()]


def recursos_previos():
    """Contenedores, redes, volúmenes e imágenes con el prefijo
    (lanzar.py:295)."""
    previos = []
    for orden in (["docker", "ps", "-a", "--format", "{{.Names}}"],
                  ["docker", "network", "ls", "--format", "{{.Name}}"],
                  ["docker", "volume", "ls", "--format", "{{.Name}}"],
                  ["docker", "image", "ls", "--format", "{{.Repository}}"]):
        previos += [n for n in ejecutar(orden).out.split() if n.startswith(PROYECTO)]
    return previos


def percentil(ordenados, q):
    """Percentil por rango más cercano sobre una lista ya ordenada (lanzar.py:345)."""
    if not ordenados:
        return None
    rango = max(1, math.ceil(q / 100 * len(ordenados)))
    return ordenados[rango - 1]


def mib(valor):
    return "-" if valor is None else f"{valor / MIB:.1f}"


def ms(valor):
    return "-" if valor is None else f"{valor * 1000:.1f}"


# ---------------------------------------------------------------------------
# Topología de CPU (lanzar.py:378-431)
# ---------------------------------------------------------------------------
def lista_cpus(texto):
    """Conjunto de CPU de una lista del kernel ("0-1,8-9" o "3")."""
    cpus = set()
    for parte in texto.split(","):
        if "-" in parte:
            desde, hasta = parte.split("-", 1)
            cpus.update(range(int(desde), int(hasta) + 1))
        else:
            cpus.add(int(parte))
    return frozenset(cpus)


def leer_topologia():
    """CPU de la VM de Docker y sus hermanas de hiperhilo, leídas en un
    contenedor efímero de la imagen de Redis ya fijada en el compose (sin
    red, de solo lectura, sin capacidades y sin root)."""
    encaje = PATRON_REDIS.search(COMPOSE.read_text(encoding="utf-8"))
    if encaje is None:
        raise Parada("no encuentro la imagen fijada de Redis en docker-compose.yml")
    r = ejecutar(["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
                  "--security-opt", "no-new-privileges", "--user", "65534:65534", "--entrypoint", "sh",
                  encaje.group(1), "-c", ORDEN_TOPOLOGIA], timeout=300)
    hermanas = {int(cpu): lista_cpus(lista) for cpu, lista in PATRON_HERMANAS.findall(r.out)}
    if r.rc != 0 or not hermanas:
        raise Parada(f"no se pudo leer la topologia de CPU de la VM de Docker (codigo {r.rc}): {r.err.strip()[-300:]!r}")
    return hermanas


def elegir_cpus_canario(hermanas):
    """La parte de Canario de elegir_cpus (lanzar.py:407): la primera CPU de
    dos núcleos distintos, sin el de la CPU 0. Es la misma regla, así que da
    el mismo cpuset que tuvo la API en L1; la parte de k6 no hace falta."""
    nucleos = sorted(set(hermanas.values()), key=min)
    candidatos = [n for n in nucleos if 0 not in n]
    if len(candidatos) < 2:
        raise Parada(f"la VM de Docker solo tiene {len(nucleos)} nucleos: hacen falta 2 fuera del de la CPU 0")
    canario = [min(n) for n in candidatos[:2]]
    return canario, f"nucleos de la VM: {[sorted(n) for n in nucleos]}; API en {canario}"


def comprobar_literales_api():
    """Argon2id y semáforo de app/personal.py sobre el texto (lanzar.py:474),
    antes de construir nada."""
    texto = PERSONAL.read_text(encoding="utf-8")
    faltan = [patron.pattern for patron in LITERALES_API if len(patron.findall(texto)) != 1]
    if faltan:
        raise Parada(f"app/personal.py no tiene los parametros esperados por las predicciones: {faltan}")
    pasa(True, "app/personal.py: Argon2id m=19456 KiB, t=2, p=1, 2 hashes simultaneos y 2 s de espera (literales)")
    if MODO["regresion"]:
        faltan = [patron.pattern for patron in LITERALES_ARREGLO if len(patron.findall(texto)) != 1]
        if faltan:
            raise Parada(f"app/personal.py no tiene el ejecutor de Argon2 del arreglo: {faltan}")
        pasa(True, "app/personal.py: ejecutor de Argon2 con max_workers=HASHES_SIMULTANEOS y prefijo argon2 "
                   "(literales)")


# ---------------------------------------------------------------------------
# Docker: imagen, contenedor endurecido, eventos
# ---------------------------------------------------------------------------
def construir_imagen():
    p(f"=== construccion de la imagen {IMAGEN} (Dockerfile de la raiz)")
    r = ejecutar(["docker", "build", "-t", IMAGEN, str(RAIZ)], timeout=1800)
    p(f"docker build -> codigo {r.rc}")
    if r.rc != 0:
        p(r.todo.strip()[-1500:])
        raise Parada("no se pudo construir la imagen de la API")
    usuario = ejecutar(["docker", "image", "inspect", "--format", "{{.Config.User}}", IMAGEN]).out.strip()
    if usuario != USUARIO_IMAGEN:
        raise Parada(f"la imagen declara el usuario {usuario!r} y se esperaba {USUARIO_IMAGEN}")
    pasa(True, f"la imagen {IMAGEN} declara USER {USUARIO_IMAGEN}")


def orden_contenedor(nombre, variante, cpus, programa_args):
    """docker run endurecido como el servicio api (docker-compose.yml:215-304):
    read_only, cap_drop ALL, no-new-privileges, pids 64, la memoria de la
    variante (sin --memory-swap salvo A2 y A-t, como mem_limit sin
    memswap_limit), el usuario de la imagen (sin --user) y además sin red.
    Sin --rm ni --restart: docker logs se lee antes de borrarlo y un OOM no
    reinicia nada. El programa se monta de solo lectura; no hay tmpfs."""
    v = variantes()[variante]
    args = ["docker", "run", "-d", "--name", nombre, "--memory", v["memoria"]]
    if "memoria_swap" in v:
        args += ["--memory-swap", v["memoria_swap"]]
    return args + ["--pids-limit", "64", "--cpuset-cpus", cpus, "--read-only", "--cap-drop", "ALL",
                   "--security-opt", "no-new-privileges", "--network", "none",
                   "--mount", f"type=bind,src={PROGRAMA},dst={PROGRAMA_DENTRO},readonly",
                   "--entrypoint", "python", IMAGEN, "-I", "-B", "-u", PROGRAMA_DENTRO, *programa_args]


def argumentos_hijo(variante):
    v = variantes()[variante]
    if v["modo"] == "reserva":
        return ["reserva", "--extra-mib", str(EXTRA_P_MIB), "--trozo-mib", str(TROZO_P_MIB), "--pausa", str(PAUSA_P_S)]
    args = ["carga", "--hilos", str(v["hilos"]), "--plazo", str(PLAZO_EJECUCION_S), "--tope", str(TOPE_PENDIENTES),
            "--fases", ",".join(f"{n}:{t}:{d}" for n, t, d in FASES)]
    if "camino" in v:
        args += ["--camino", v["camino"]]
    if v.get("tracemalloc"):
        args.append("--tracemalloc")
    if v.get("argon2_e"):
        args += ["--argon2-e", "--objetivo-e", str(OBJETIVO_E_S)]
    return args


def argumentos_supervisor(variante):
    entorno = [f"--entorno={a}" for a in variantes()[variante].get("entorno", ())]
    return ["supervisor", *entorno, "--", *argumentos_hijo(variante)]


class EventosOom:
    """docker events --filter event=oom del contenedor, desde antes de
    arrancarlo hasta después de que termine (plan: desde fuera)."""

    def __init__(self, nombre):
        self.eventos = []
        self.proceso = subprocess.Popen(["docker", "events", "--filter", "event=oom", "--filter",
                                         f"container={nombre}", "--format", "{{json .}}"],
                                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        self.hilo = threading.Thread(target=self._leer, daemon=True)
        self.hilo.start()
        # La suscripción del cliente no es instantánea: un segundo de
        # margen antes de arrancar el contenedor.
        time.sleep(1)

    def _leer(self):
        for linea in iter(self.proceso.stdout.readline, b""):
            try:
                self.eventos.append(json.loads(linea))
            except ValueError:
                continue

    def parar(self):
        # El evento llega por el socket del daemon con algo de retraso.
        time.sleep(2)
        self.proceso.terminate()
        try:
            self.proceso.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.proceso.kill()
        self.hilo.join(timeout=15)
        return sum(1 for e in self.eventos if e.get("Action") == "oom" or e.get("status") == "oom")


def lineas_json(texto):
    """(objetos, líneas que no son JSON) de la salida del contenedor."""
    objetos, ajenas = [], []
    for linea in texto.splitlines():
        if not linea.strip():
            continue
        try:
            objeto = json.loads(linea)
        except ValueError:
            ajenas.append(linea[:200])
            continue
        if isinstance(objeto, dict):
            objetos.append(objeto)
        else:
            ajenas.append(linea[:200])
    return objetos, ajenas


def comprobacion_previa(cpus):
    """PARADA previa del plan, en un contenedor con el mismo endurecimiento
    y 256 MiB."""
    p("=== PARADA previa dentro del contenedor (cgroup v2, ficheros, claves, glibc, usuario, import, anyio)")
    nombre = f"{PROYECTO}_comprobacion"
    # Los límites de A (256 MiB) son los de R en --regresion: la misma
    # comprobación vale para los dos modos.
    programa = ["comprobar", "--regresion"] if MODO["regresion"] else ["comprobar"]
    r = ejecutar(orden_contenedor(nombre, "R" if MODO["regresion"] else "A", cpus, programa), timeout=120)
    if r.rc != 0:
        raise Parada(f"no arranca el contenedor de comprobacion: {r.err.strip()[-500:]!r}")
    try:
        ejecutar(["docker", "wait", nombre], timeout=180)
        salida = ejecutar(["docker", "logs", nombre])
    finally:
        ejecutar(["docker", "rm", "-f", nombre])
    objetos, ajenas = lineas_json(salida.out)
    if len(objetos) != 1 or ajenas:
        raise Parada(f"la comprobacion no dio una linea JSON: {salida.todo.strip()[-800:]!r}")
    motivos = motivos_comprobacion(objetos[0], cpus)
    if motivos:
        raise Parada("la PARADA previa falla: " + "; ".join(motivos))
    c = objetos[0]
    pasa(True, f"cgroup v2 (magia {c['cgroup']['magia']:#x}, montaje {c['cgroup']['montaje']}), los 9 ficheros y "
               f"sus claves; memory.max {c['cgroup']['memory.max']}, swap.max {c['cgroup']['memory.swap.max']}, "
               f"oom.group {c['cgroup']['memory.oom.group']}")
    pasa(True, f"{c['entorno']['glibc']}, uid/gid {c['entorno']['uid']}/{c['entorno']['gid']}, afinidad "
               f"{c['entorno']['afinidad']}, THP {c['entorno']['thp']!r}")
    pasa(True, f"app.personal se importa sin secretos ni red y expone {sorted(c['api'])}; anyio {c['anyio']}, "
               f"abandon_on_cancel={c['abandon_on_cancel_por_defecto']} y limitador de {c['limitador_por_defecto']}")
    return c


def motivos_comprobacion(c, cpus):
    """Motivos de PARADA de la comprobación previa (función pura)."""
    if "error" in c:
        return [f"error dentro del contenedor: {c['error']}"]
    motivos = []
    cg, en = c["cgroup"], c["entorno"]
    if cg["magia"] != MAGIA_CGROUP2 or cg["montaje"] != "cgroup2":
        motivos.append(f"no es cgroup v2 ({cg['magia']:#x}, {cg['montaje']})")
    for clave, esperado in LIMITES_256M.items():
        if cg[clave] != esperado:
            motivos.append(f"{clave} = {cg[clave]} y se esperaba {esperado}")
    if cg["memory.oom.group"] != OOM_GROUP:
        motivos.append(f"memory.oom.group = {cg['memory.oom.group']}: un OOM mataria el contenedor entero")
    if en["glibc"] != GLIBC:
        motivos.append(f"{en['glibc']}: las predicciones citan la fuente de {GLIBC}")
    if (en["uid"], en["gid"]) != (UID_IMAGEN, UID_IMAGEN):
        motivos.append(f"uid/gid {en['uid']}/{en['gid']}")
    if ",".join(str(x) for x in en["afinidad"]) != cpus:
        motivos.append(f"afinidad {en['afinidad']} y se pidio {cpus}")
    if not all(c["api"].values()):
        motivos.append(f"faltan nombres en app.personal: {c['api']}")
    if c["anyio"] != ANYIO or c["abandon_on_cancel_por_defecto"] is not False:
        motivos.append(f"anyio {c['anyio']}, abandon_on_cancel por defecto {c['abandon_on_cancel_por_defecto']}")
    if c["limitador_por_defecto"] != HILOS_POR_DEFECTO:
        motivos.append(f"limitador por defecto de {c['limitador_por_defecto']} y no {HILOS_POR_DEFECTO}")
    return motivos


def lanzar_ejecucion(variante, ronda, cpus, salida):
    """Una ejecución: su contenedor, sus eventos oom y su salida cruda en
    disco. Devuelve los datos para analizar."""
    nombre = f"{PROYECTO}_{variante.replace('-', '').lower()}_r{ronda}"
    p(f"--- {variante}, ronda {ronda} ({nombre})")
    eventos = EventosOom(nombre)
    plazo_host = False
    try:
        r = ejecutar(orden_contenedor(nombre, variante, cpus, argumentos_supervisor(variante)), timeout=120)
        if r.rc != 0:
            raise Parada(f"no arranca el contenedor {nombre}: {r.err.strip()[-500:]!r}")
        try:
            r = ejecutar(["docker", "wait", nombre], timeout=PLAZO_EJECUCION_S + MARGEN_CONTENEDOR_S)
            codigo = int(r.out.strip()) if r.rc == 0 and r.out.strip().lstrip("-").isdigit() else None
        except subprocess.TimeoutExpired:
            ejecutar(["docker", "kill", nombre])
            codigo, plazo_host = None, True
    finally:
        oom_docker = eventos.parar()
    registro = ejecutar(["docker", "logs", nombre])
    (salida / f"{nombre}.jsonl").write_text(registro.out, encoding="utf-8", newline="\n")
    (salida / f"{nombre}_stderr.txt").write_text(registro.err, encoding="utf-8", newline="\n")
    ejecutar(["docker", "rm", "-f", nombre])
    objetos, ajenas = lineas_json(registro.out)
    errores_supervisor = [o for o in objetos if o.get("origen") == "supervisor" and o.get("tipo") == "error"]
    if errores_supervisor:
        raise Parada(f"{nombre}: el supervisor no supera la PARADA previa: {errores_supervisor[0]['motivo']}")
    return {"variante": variante, "ronda": ronda, "nombre": nombre, "codigo_contenedor": codigo,
            "plazo_host": plazo_host, "oom_docker": oom_docker, "objetos": objetos, "ajenas": ajenas,
            "stderr": registro.err.strip()[-600:]}


# ---------------------------------------------------------------------------
# Análisis: funciones puras sobre los objetos JSON (probables con datos
# sintéticos, sin Docker)
# ---------------------------------------------------------------------------
def separar(objetos):
    """Agrupa las líneas por origen y tipo."""
    d = {"inicio": None, "muestras": [], "fin_hijo": None, "entorno": None, "hitos": {}, "fases": {},
         "inicios_fase": {}, "tiempos": collections.defaultdict(list), "fin": None, "calibrado_e": None,
         "muestras_hijo": [], "reservas": [], "limitador": None,
         # Solo los da el camino arreglo de --regresion.
         "latencias": collections.defaultdict(list), "ejecutor": None, "hilos_argon2": None}
    for o in objetos:
        origen, tipo = o.get("origen"), o.get("tipo")
        if origen == "supervisor":
            if tipo == "inicio":
                d["inicio"] = o
            elif tipo == "muestra":
                d["muestras"].append(o)
            elif tipo == "fin_hijo":
                d["fin_hijo"] = o
        elif origen == "hijo":
            if tipo == "hito":
                d["hitos"][o["nombre"]] = o
            elif tipo == "fase":
                d["fases"][o["nombre"]] = o
            elif tipo == "inicio_fase":
                d["inicios_fase"][o["nombre"]] = o["t"]
            elif tipo == "tiempos":
                d["tiempos"][o["fase"]].extend(o["valores"])
            elif tipo == "latencias":
                d["latencias"][o["fase"]].extend(o["valores"])
            elif tipo == "muestra":
                d["muestras_hijo"].append(o)
            elif tipo == "reserva":
                d["reservas"].append(o)
            elif tipo in ("entorno", "fin", "calibrado_e", "limitador", "ejecutor", "hilos_argon2"):
                d[tipo] = o
    return d


def uso_hito(cg):
    """anon + swap.current - swapcached de un hito (plan: la fórmula del
    retenido, con swapcached restado porque está a la vez en RAM y swap)."""
    return cg["anon"] + cg["swap_current"] - cg["swapcached"]


def uso_muestra(m):
    return m["stat"]["anon"] + m["swap_current"] - m["stat"]["swapcached"]


def arenas_crecidas(arenas, base, incluir_principal):
    """a: arenas cuyo <system type="current"> crece >= 19 MiB respecto de la
    base. Una arena que no existía en la base partía de 0 bytes (por eso el
    0 no es un valor por defecto: es su tamaño real entonces)."""
    previas = {x["id"]: x["sistema"] for x in base}
    return sum(1 for x in arenas if (incluir_principal or x["id"] != 0)
               and x["sistema"] - previas.get(x["id"], 0) >= UMBRAL_ARENA)


def crecimiento_maximo_hilo(arenas, base):
    """Lo que más ha crecido una arena de hilo (no la principal) respecto de
    la base, con el mismo criterio que arenas_crecidas. malloc_info no dice
    de qué hilo es cada arena, así que el oráculo de R sobre "cada arena del
    ejecutor" se aplica a TODAS las arenas de hilo: es más estricto, nunca
    más blando (las de AnyIO ya no calculan Argon2 y apenas crecen)."""
    previas = {x["id"]: x["sistema"] for x in base}
    return max((x["sistema"] - previas.get(x["id"], 0) for x in arenas if x["id"] != 0), default=0)


def libres_grandes(arenas, umbral, incluir_desordenados):
    """Bloques libres de `umbral` o más en los <size> (y, si se pide, en el
    <unsorted>) de malloc_info."""
    total = 0
    for x in arenas:
        grupos = x["libres"] + (x["desordenados"] if incluir_desordenados else [])
        total += sum(cuenta for _, hasta, _, cuenta in grupos if hasta >= umbral and cuenta > 0)
    return total


def resumen_hito(h, base_abs, base_arenas, variante):
    mi = h["mallinfo2"]
    return {"retenido": uso_hito(h["cgroup"]) - base_abs,
            # La principal se excluye en A, A2, D y E, y en B se cuenta con
            # la base restada (plan, Predicción).
            "a": arenas_crecidas(h["arenas"], base_arenas, incluir_principal=(variante == "B")),
            "crecimiento_max_hilo": crecimiento_maximo_hilo(h["arenas"], base_arenas),
            "arenas_total": len(h["arenas"]), "uordblks": mi["uordblks"], "fordblks": mi["fordblks"],
            "arena": mi["arena"], "hblkhd": mi["hblkhd"], "mmap": h["mmap"],
            "libres_19": libres_grandes(h["arenas"], BLOQUE_LIBRE_MAXIMO_C2, incluir_desordenados=False),
            "libres_19_unsorted": libres_grandes(h["arenas"], BLOQUE_LIBRE_MAXIMO_C2, incluir_desordenados=True),
            "en_curso": h["en_curso"], "pendientes": h["pendientes"], "hilos": h["hilos"],
            "tracemalloc": h.get("tracemalloc"), "malloc_trim": h.get("malloc_trim")}


def ventanas(d):
    """[inicio, fin) de cada fase en el reloj monotónico del contenedor (el
    mismo para el supervisor y el hijo). La última acaba al morir el hijo."""
    nombres = [n for n, _, _ in FASES if n in d["inicios_fase"]]
    fin_hijo = d["fin_hijo"]["t"] if d["fin_hijo"] else math.inf
    resultado = {}
    for i, nombre in enumerate(nombres):
        siguiente = d["inicios_fase"][nombres[i + 1]] if i + 1 < len(nombres) else fin_hijo
        resultado[nombre] = (d["inicios_fase"][nombre], siguiente)
    return resultado


def maximo_en(muestras, desde, hasta, base_abs):
    valores = [uso_muestra(m) - base_abs for m in muestras if desde <= m["t"] < hasta]
    return max(valores) if valores else None


def fase_de_muerte(d, ventanas_):
    """Fase en la que murió el hijo por SIGKILL, o None."""
    fin = d["fin_hijo"]
    if fin is None or fin["codigo"] != CODIGO_SIGKILL:
        return None
    for nombre, (desde, hasta) in ventanas_.items():
        if desde <= fin["t"] <= hasta:
            return nombre
    return "antes de F1"


def tiempos_verify(d, clave="tiempos"):
    """n, p50 y p95 de las fases de carga: los tiempos de verify() o, con
    clave="latencias", la espera total del llamante (camino arreglo)."""
    valores = sorted(v for f in FASES_CARGA for v in d[clave].get(f, []))
    return {"n": len(valores), "p50": percentil(valores, 50), "p95": percentil(valores, 95)}


def hilos_maximos(d, ventanas_):
    """Hilos vivos máximos del hijo en cada fase (muestras del hijo)."""
    return {nombre: max((m["hilos"] for m in d["muestras_hijo"] if desde <= m["t"] < hasta), default=None)
            for nombre, (desde, hasta) in ventanas_.items()}


def oom_kill(d):
    if d["inicio"] is None or d["fin_hijo"] is None:
        return None
    return d["fin_hijo"]["eventos"]["oom_kill"] - d["inicio"]["eventos"]["oom_kill"]


def motivos_validez(ej, d):
    """Motivos de SIN CONCLUSION de una ejecución que no dependen de la
    variante."""
    motivos = []
    v = variantes()[ej["variante"]]
    if ej["plazo_host"]:
        motivos.append(f"el contenedor supera {PLAZO_EJECUCION_S + MARGEN_CONTENEDOR_S} s y se detiene")
    if ej["ajenas"]:
        motivos.append(f"{len(ej['ajenas'])} lineas de stdout que no son JSON (la primera: {ej['ajenas'][0]!r})")
    if d["inicio"] is None or d["fin_hijo"] is None:
        motivos.append(f"falta el inicio o el fin del supervisor (codigo del contenedor {ej['codigo_contenedor']})")
        return motivos
    limites = {k: d["inicio"]["limites"][k] for k in v["limites"]}
    if limites != v["limites"]:
        motivos.append(f"limites dentro {limites} y se esperaba {v['limites']}")
    if ej["codigo_contenedor"] != 0:
        motivos.append(f"el supervisor termina con codigo {ej['codigo_contenedor']}")
    if v["modo"] == "reserva":
        return motivos
    if d["fin"] is not None and d["fin"]["motivo"] == "plazo":
        motivos.append(f"el hijo agota el plazo de {PLAZO_EJECUCION_S} s")
    if d["fin"] is not None and d["fin"]["motivo"] == "tope":
        motivos.append(f"una fase supera el tope de {TOPE_PENDIENTES} tareas pendientes")
    for nombre, f in d["fases"].items():
        if f["otras"]:
            motivos.append(f"{nombre}: excepciones distintas de Saturado {f['otras']}")
    for nombre in HITOS_FASE:
        h = d["hitos"].get(nombre)
        if h is not None and (h["en_curso"], h["pendientes"]) != (EN_CURSO_EN_HITO, PENDIENTES_EN_HITO):
            motivos.append(f"{nombre} con {h['en_curso']} hashes en curso y {h['pendientes']} pendientes")
    if "base" not in d["hitos"]:
        motivos.append("no hay muestra base (el hijo no llego a cargar)")
    murio = d["fin_hijo"]["codigo"] == CODIGO_SIGKILL
    if d["fin"] is None and not murio:
        motivos.append(f"el hijo termina con codigo {d['fin_hijo']['codigo']} sin linea de fin: ver stderr")
    return motivos


def analizar_ejecucion(ej):
    """Datos de una ejecución, sin veredictos de variante."""
    d = separar(ej["objetos"])
    res = {"variante": ej["variante"], "ronda": ej["ronda"], "nombre": ej["nombre"],
           "sin_conclusion": motivos_validez(ej, d), "oom_docker": ej["oom_docker"], "oom_kill": oom_kill(d),
           "codigo_hijo": d["fin_hijo"]["codigo"] if d["fin_hijo"] else None, "stderr": ej["stderr"],
           "entorno": d["entorno"], "calibrado_e": d["calibrado_e"], "hitos": {}, "fases": d["fases"],
           "max_retenido": {}, "muestreo_max_s": None}
    if variantes()[ej["variante"]]["modo"] == "reserva":
        res["control_p"] = datos_control_p(d)
        return res
    base = d["hitos"].get("base")
    if base is None:
        return res
    base_abs = uso_hito(base["cgroup"])
    res["base_abs"] = base_abs
    for nombre, h in d["hitos"].items():
        if nombre != "base":
            res["hitos"][nombre] = resumen_hito(h, base_abs, base["arenas"], ej["variante"])
    v = ventanas(d)
    res["fase_muerte"] = fase_de_muerte(d, v)
    for nombre, (desde, hasta) in v.items():
        res["max_retenido"][nombre] = maximo_en(d["muestras"], desde, hasta, base_abs)
    res["max_retenido"]["total"] = maximo_en(d["muestras"], base["t"], math.inf, base_abs)
    res["tiempos"] = tiempos_verify(d)
    # Para --regresion; en el modo normal quedan vacíos (sin latencias ni
    # ejecutor) y no entran en ningún veredicto.
    res["latencias"] = tiempos_verify(d, "latencias")
    res["hilos_max"] = hilos_maximos(d, v)
    res["ejecutor"] = d["ejecutor"]["hilos"] if d["ejecutor"] else None
    res["nombres_argon2"] = d["hilos_argon2"]["nombres"] if d["hilos_argon2"] else None
    duraciones = [m["dur_malloc"] for m in d["muestras_hijo"]] + [m["dur"] for m in d["muestras"]]
    res["muestreo_max_s"] = max(duraciones) if duraciones else None
    res["base_tracemalloc"] = base.get("tracemalloc")
    return res


def datos_control_p(d):
    """Lo que pide el control positivo, sin decidir todavía."""
    if d["inicio"] is None or d["fin_hijo"] is None:
        return None
    memoria_max = int(d["inicio"]["limites"]["memory.max"])
    vivas = [uso_muestra(m) for m in d["muestras"] if m["hijo"] is not None]
    return {"codigo": d["fin_hijo"]["codigo"], "oom_kill": oom_kill(d), "memoria_max": memoria_max,
            "usos_vivos": vivas, "reservado": d["reservas"][-1]["reservado"] if d["reservas"] else 0}


# --- veredictos por ejecución ---------------------------------------------
def tolerancia(a):
    return max(TOLERANCIA_RELATIVA * a * UMBRAL_ARENA, TOLERANCIA_ABSOLUTA)


def uordblks_sin_pendiente(hitos):
    valores = [hitos[n]["uordblks"] for n in HITOS_FASE]
    return max(valores) - min(valores) < PENDIENTE_UORDBLKS


def faltan_hitos(res):
    return [n for n in HITOS_FASE if n not in res["hitos"]]


def evaluar_causa1(res):
    """(True/False/None, motivos): la predicción de la causa 1 en cada fin
    de fase."""
    faltan = faltan_hitos(res)
    if faltan:
        return None, [f"faltan los hitos {faltan}"]
    motivos = []
    for nombre in HITOS_FASE:
        h = res["hitos"][nombre]
        esperado = h["a"] * UMBRAL_ARENA
        if abs(h["retenido"] - esperado) > tolerancia(h["a"]):
            motivos.append(f"{nombre}: retenido {mib(h['retenido'])} MiB y a x 19 = {mib(esperado)} MiB "
                           f"(tolerancia {mib(tolerancia(h['a']))})")
        if h["fordblks"] < esperado - tolerancia(h["a"]):
            motivos.append(f"{nombre}: fordblks {mib(h['fordblks'])} MiB < {mib(esperado - tolerancia(h['a']))} MiB")
    if not uordblks_sin_pendiente(res["hitos"]):
        motivos.append("uordblks varia 1 MiB o mas entre fines de fase")
    for desde, hasta in REPOSOS:
        bajada = res["hitos"][desde]["retenido"] - res["hitos"][hasta]["retenido"]
        if bajada > BAJADA_MAXIMA_REPOSO:
            motivos.append(f"el retenido baja {mib(bajada)} MiB de {desde} a {hasta}")
    return not motivos, motivos


def evaluar_p(res):
    c = res.get("control_p")
    if c is None:
        return False, ["sin datos del supervisor"]
    motivos = []
    if c["codigo"] != CODIGO_SIGKILL:
        motivos.append(f"el hijo termina con {c['codigo']} y no con {CODIGO_SIGKILL}")
    if c["oom_kill"] is None or c["oom_kill"] < OOM_KILL_MINIMO:
        motivos.append(f"oom_kill = {c['oom_kill']}")
    if res["oom_docker"] < 1:
        motivos.append("docker events no da el evento oom")
    usos = c["usos_vivos"]
    if len(usos) < MUESTRAS_MINIMAS_P:
        motivos.append(f"solo {len(usos)} muestras con el hijo vivo")
    elif any(b < a - BAJADA_TOLERADA_P for a, b in zip(usos, usos[1:])) or usos[-1] <= c["memoria_max"]:
        motivos.append(f"las muestras no suben hasta el kill (ultima {mib(usos[-1])} MiB, memory.max "
                       f"{mib(c['memoria_max'])} MiB)")
    return not motivos, motivos


def evaluar_d(res):
    """Control de línea base y causa 3 (fuga)."""
    faltan = faltan_hitos(res)
    if faltan:
        return {"control": False, "motivos": [f"faltan los hitos {faltan} (codigo {res['codigo_hijo']})"],
                "causa3": None}
    motivos = [f"{n}: retenido {mib(res['hitos'][n]['retenido'])} MiB > {mib(RETENIDO_MAXIMO_D)} MiB"
               for n in HITOS_FASE if res["hitos"][n]["retenido"] > RETENIDO_MAXIMO_D]
    if not uordblks_sin_pendiente(res["hitos"]):
        motivos.append("uordblks varia 1 MiB o mas entre fines de fase")
    subida = res["hitos"][HITOS_FASE[-1]]["uordblks"] - res["hitos"][HITOS_FASE[0]]["uordblks"]
    return {"control": not motivos, "motivos": motivos, "causa3": subida >= PENDIENTE_UORDBLKS,
            "subida_uordblks": subida}


def disparo(res, fase, umbral):
    """Retenido máximo en la fase >= umbral, o el hijo muere por OOM en ella."""
    maximo = res["max_retenido"].get(fase)
    por_oom = res.get("fase_muerte") == fase and (res["oom_kill"] or 0) >= OOM_KILL_MINIMO
    return por_oom or (maximo is not None and maximo >= umbral)


def evaluar_a(res):
    return {"F1": disparo(res, "F1", MESETA_L1), "F2": disparo(res, "F2", MESETA_L1),
            "causa1": evaluar_causa1(res)}


def evaluar_e(res):
    """E se dispara: retenido >= 4 x 19 MiB en cualquier momento de la
    carga, o un OOM. PENDIENTE DE DECISION: el plan no dice si es el máximo
    de la ejecución o el de un fin de fase; se usa el máximo, el mismo
    criterio que "se dispara" en A (máximo de F1)."""
    maximo = res["max_retenido"].get("total")
    return (res["oom_kill"] or 0) >= OOM_KILL_MINIMO or (maximo is not None and maximo >= DISPARO_E)


def evaluar_arreglo(res, a2):
    """B o C2 frente a A2 de la misma ronda (referencia de tiempos).

    PENDIENTE DE DECISION, dos lecturas del plan:
    * "el retenido queda bajo su predicción": en cada fin de fase, que es
      donde se define el retenido; "por debajo de 256 MiB - base - 64 MiB":
      sobre el máximo de toda la ejecución, que es lo que decide un OOM.
    * Los tiempos se comparan con A2 de la MISMA ronda (emparejados, para
      que una deriva del host entre rondas no cuente), no con la mediana de
      A2; el veredicto exige además que las 3 rondas coincidan."""
    faltan = faltan_hitos(res)
    if (res["oom_kill"] or 0) >= OOM_KILL_MINIMO:
        return False, [f"oom_kill = {res['oom_kill']}"]
    if faltan:
        return None, [f"faltan los hitos {faltan}"]
    motivos = []
    prediccion = RETENIDO_MAXIMO_B if res["variante"] == "B" else RETENIDO_MAXIMO_C2
    for nombre in HITOS_FASE:
        h = res["hitos"][nombre]
        if h["retenido"] > prediccion:
            motivos.append(f"{nombre}: retenido {mib(h['retenido'])} MiB > prediccion {mib(prediccion)} MiB")
        if res["variante"] == "B" and h["arenas_total"] > ARENAS_MAXIMAS_B:
            motivos.append(f"{nombre}: {h['arenas_total']} arenas > {ARENAS_MAXIMAS_B}")
        if res["variante"] == "C2" and h["libres_19_unsorted"] > 0:
            motivos.append(f"{nombre}: {h['libres_19_unsorted']} bloques libres de 19 MiB o mas (<size> y <unsorted>)")
    margen = LIMITE_MEMORIA_API - res["base_abs"] - MARGEN_ARREGLO
    if res["max_retenido"]["total"] is None or res["max_retenido"]["total"] > margen:
        motivos.append(f"retenido maximo {mib(res['max_retenido']['total'])} MiB > 256 - base - 64 = {mib(margen)} MiB")
    if a2 is None or a2.get("tiempos", {}).get("p50") is None:
        return None, motivos + ["sin A2 valida en la misma ronda para comparar tiempos"]
    for q in ("p50", "p95"):
        if res["tiempos"][q] is None or res["tiempos"][q] > FACTOR_TIEMPO_ARREGLO * a2["tiempos"][q]:
            motivos.append(f"{q} de verify {ms(res['tiempos'][q])} ms > 1,25 x {ms(a2['tiempos'][q])} ms de A2")
    return not motivos, motivos


# --- veredictos de --regresion ---------------------------------------------
def evaluar_v(res):
    """Control V: el camino viejo reproduce en esta sesión lo que midió D1
    (a >= 30 en fin_F2)."""
    h = res["hitos"].get("fin_F2")
    if h is None:
        return False, [f"falta el hito fin_F2 (codigo {res['codigo_hijo']})"]
    if h["a"] < ARENAS_MINIMAS_V:
        return False, [f"fin_F2: a = {h['a']} < {ARENAS_MINIMAS_V}"]
    return True, []


def precondicion_r(res):
    """Motivos por los que R no puede concluir nada (SIN CONCLUSION)."""
    motivos = []
    hilos = res["hilos_max"].get("F2")
    if hilos is None or hilos < HILOS_MINIMOS_R:
        motivos.append(f"hilos vivos maximos en F2 {hilos} < {HILOS_MINIMOS_R}: la rafaga no ejercita la concurrencia")
    if res["ejecutor"] != list(NOMBRES_HILOS_ARGON2):
        motivos.append(f"el ejecutor arranca con {res['ejecutor']} y no {list(NOMBRES_HILOS_ARGON2)}")
    if not res["nombres_argon2"] or not set(res["nombres_argon2"]) <= set(NOMBRES_HILOS_ARGON2):
        motivos.append(f"verify() corre en {res['nombres_argon2']}, no solo en {list(NOMBRES_HILOS_ARGON2)}")
    faltan = faltan_hitos(res)
    if faltan:
        motivos.append(f"faltan los hitos {faltan}")
    return motivos


def memoria_r(res):
    """Oráculos de memoria de R, sobre una ejecución que cumple la
    precondición: (motivos de fallo)."""
    motivos = []
    for nombre in HITOS_FASE:
        h = res["hitos"][nombre]
        if h["a"] > ARENAS_MAXIMAS_R:
            motivos.append(f"{nombre}: a = {h['a']} > {ARENAS_MAXIMAS_R}")
        if h["crecimiento_max_hilo"] > CRECIMIENTO_MAXIMO_ARENA_R:
            motivos.append(f"{nombre}: una arena de hilo crece {mib(h['crecimiento_max_hilo'])} MiB > 1,3 x 19 = "
                           f"{mib(CRECIMIENTO_MAXIMO_ARENA_R)} MiB")
        if h["retenido"] > RETENIDO_MAXIMO_R:
            motivos.append(f"{nombre}: retenido {mib(h['retenido'])} MiB > {mib(RETENIDO_MAXIMO_R)} MiB")
    for nombre, _, _ in FASES:
        maximo = res["max_retenido"].get(nombre)
        if maximo is None or maximo > RETENIDO_MAXIMO_R:
            motivos.append(f"maximo de {nombre}: retenido {mib(maximo)} MiB > {mib(RETENIDO_MAXIMO_R)} MiB")
    return motivos


def tiempos_r(res, v):
    """Oráculo doble de tiempos de R: (True/False/None, motivos). None si
    falta una referencia o si las dos referencias discrepan."""
    t = res.get("tiempos") or {}
    tv = (v or {}).get("tiempos") or {}
    if t.get("p50") is None:
        return None, ["R sin tiempos de verify()"]
    if v is None or v["sin_conclusion"] or tv.get("p50") is None:
        return None, ["sin V valida en la misma ronda para comparar tiempos"]
    contra_v = [f"{q} {ms(t[q])} ms > 1,25 x {ms(tv[q])} ms de V" for q in ("p50", "p95")
                if t[q] > FACTOR_TIEMPO_R * tv[q]]
    contra_a2 = [f"{q} {ms(t[q])} ms > 1,25 x {ms(TIEMPOS_A2_D1[q])} ms de A2 en D1" for q in ("p50", "p95")
                 if t[q] > FACTOR_TIEMPO_R * TIEMPOS_A2_D1[q]]
    if bool(contra_v) != bool(contra_a2):
        return None, ["las dos referencias discrepan: " + "; ".join(contra_v + contra_a2)]
    return not contra_v, contra_v + contra_a2


def evaluar_r(res, v):
    """R: {"memoria": (valor, motivos), "tiempos": (valor, motivos)}, con
    valor True/False/None. Un oom_kill es NO PASA de memoria aunque falte
    todo lo demás: es justo lo que el arreglo debe impedir."""
    if (res["oom_kill"] or 0) >= OOM_KILL_MINIMO:
        return {"memoria": (False, [f"oom_kill = {res['oom_kill']}"]),
                "tiempos": (None, ["el hijo muere por OOM"])}
    motivos = precondicion_r(res)
    if motivos:
        return {"memoria": (None, motivos), "tiempos": (None, motivos)}
    fallos = memoria_r(res)
    return {"memoria": (not fallos, fallos), "tiempos": tiempos_r(res, v)}


def veredicto_ejecucion(res, referencia_de_ronda):
    """Veredicto propio de la variante; None si la ejecución no es válida.
    La referencia es A2 de la misma ronda (B y C2) o V (R, en --regresion)."""
    if res["sin_conclusion"]:
        return None
    variante = res["variante"]
    if variante == "P":
        return evaluar_p(res)
    if variante == "D":
        return evaluar_d(res)
    if variante == "A":
        return evaluar_a(res)
    if variante == "A2":
        return evaluar_causa1(res)
    if variante == "E":
        return evaluar_e(res)
    if variante in ("B", "C2"):
        return evaluar_arreglo(res, referencia_de_ronda)
    if variante == "V":
        return evaluar_v(res)
    if variante == "R":
        return evaluar_r(res, referencia_de_ronda)
    return None


# --- agregación por variante ------------------------------------------------
def acordar(valores):
    """El veredicto de las 3 rondas si coinciden; None (SIN CONCLUSION) si
    alguno falta o no coinciden (plan, Orden y plazos)."""
    if not valores or any(v is None for v in valores):
        return None
    return valores[0] if all(v == valores[0] for v in valores) else None


def acordar_memoria(valores):
    """Para la memoria de R (--regresion): un solo NO PASA en cualquier ronda
    basta, aunque otra no concluya; PASA solo si pasan las 3. Más estricto
    que acordar: un OOM no se esconde tras una ronda sin conclusión."""
    if any(v is False for v in valores):
        return False
    return True if valores and all(v is True for v in valores) else None


def mediana(valores):
    validos = [v for v in valores if v is not None]
    return statistics.median(validos) if validos else None


# ---------------------------------------------------------------------------
# Informe
# ---------------------------------------------------------------------------
def tabla_variante(variante, resultados):
    filas = [r for r in resultados if r["variante"] == variante]
    p(f"--- {variante}")
    entorno = next((r["entorno"] for r in filas if r.get("entorno")), None)
    if entorno:
        p(f"   {entorno['glibc']}, CPU {entorno['afinidad']} (cpu_count {entorno['cpu_count']}), THP "
          f"{entorno['thp']!r}, malloc {entorno['malloc']}")
    for r in filas:
        if variante == "P":
            c = r.get("control_p") or {}
            p(f"   r{r['ronda']}: codigo hijo {c.get('codigo')}, oom_kill {c.get('oom_kill')}, evento docker "
              f"{r['oom_docker']}, reservado {mib(c.get('reservado'))} MiB, muestras vivas "
              f"{[round(u / MIB) for u in c.get('usos_vivos', [])]} MiB")
            continue
        hitos = r["hitos"]
        a_txt = "/".join(str(hitos[n]["a"]) if n in hitos else "-" for n in HITOS_FASE)
        ret = "/".join(mib(hitos[n]["retenido"]) if n in hitos else "-" for n in HITOS_FASE)
        uord = "/".join(mib(hitos[n]["uordblks"]) if n in hitos else "-" for n in HITOS_FASE)
        ford = "/".join(mib(hitos[n]["fordblks"]) if n in hitos else "-" for n in HITOS_FASE)
        arenas = "/".join(str(hitos[n]["arenas_total"]) if n in hitos else "-" for n in HITOS_FASE)
        t = r.get("tiempos") or {}
        fases = r["fases"]
        p(f"   r{r['ronda']}: codigo hijo {r['codigo_hijo']}, oom_kill {r['oom_kill']}, evento docker "
          f"{r['oom_docker']}, muerte en {r.get('fase_muerte')}, base {mib(r.get('base_abs'))} MiB")
        p(f"      a (F1/R1/F2/R2) {a_txt}; arenas totales {arenas}")
        p(f"      retenido MiB {ret}; maximo F1 {mib(r['max_retenido'].get('F1'))}, F2 "
          f"{mib(r['max_retenido'].get('F2'))}, total {mib(r['max_retenido'].get('total'))}")
        p(f"      mallinfo2 MiB: uordblks {uord}; fordblks {ford}")
        p(f"      verify: n={t.get('n')} p50={ms(t.get('p50'))} ms p95={ms(t.get('p95'))} ms; "
          + "; ".join(f"{n}: correctos {f['correctos']} Saturado {f['saturados']} otras {f['otras']} pendientes max "
                      f"{f['pendientes_max']} retraso max {f['retraso_max'] * 1000:.0f} ms" for n, f in fases.items()
                      if f["tasa"] > 0))
        trim = hitos.get("tras_trim")
        if trim:
            p(f"      malloc_trim(0) = {trim['malloc_trim']}: retenido {mib(hitos.get('fin_R2', {}).get('retenido'))} "
              f"-> {mib(trim['retenido'])} MiB (informativo)")
        if r.get("calibrado_e"):
            c = r["calibrado_e"]
            p(f"      E: m=64 KiB, t={c['pasadas']} pasadas, verify {c['verify_s'] * 1000:.1f} ms "
              f"(objetivo {c['objetivo_s'] * 1000:.0f} ms)")
        if MODO["regresion"]:
            tabla_regresion(r)
        p(f"      muestreo mas lento {ms(r['muestreo_max_s'])} ms")
        for motivo in r["sin_conclusion"]:
            p(f"      SIN CONCLUSION: {motivo}")
    if variante != "P":
        p(f"   mediana: retenido fin_F1 {mib(mediana([r['hitos'].get('fin_F1', {}).get('retenido') for r in filas]))}"
          f" MiB, maximo total {mib(mediana([r['max_retenido'].get('total') for r in filas]))} MiB, p50 "
          f"{ms(mediana([(r.get('tiempos') or {}).get('p50') for r in filas]))} ms, p95 "
          f"{ms(mediana([(r.get('tiempos') or {}).get('p95') for r in filas]))} ms")


def tabla_regresion(r):
    """Las líneas que añade --regresion a la tabla de una ejecución."""
    hitos = r["hitos"]
    crecimiento = "/".join(mib(hitos[n]["crecimiento_max_hilo"]) if n in hitos else "-" for n in HITOS_FASE)
    p(f"      arena de hilo que mas crece MiB (F1/R1/F2/R2) {crecimiento}; hilos vivos max F1 "
      f"{r['hilos_max'].get('F1')}, F2 {r['hilos_max'].get('F2')}")
    if r["ejecutor"] is not None or r["nombres_argon2"] is not None:
        lat = r.get("latencias") or {}
        p(f"      ejecutor {r['ejecutor']}; verify() corrio en {r['nombres_argon2']}; latencia del llamante "
          f"(informativa) p50={ms(lat.get('p50'))} ms p95={ms(lat.get('p95'))} ms")


def por_ronda(resultados, variante):
    return {r["ronda"]: r for r in resultados if r["variante"] == variante}


def veredictos(resultados):
    """Un veredicto por oráculo, con su motivo. Devuelve un diccionario
    para resultados.json."""
    p("=== veredictos por oraculo (los hallazgos no cambian el RESULTADO GLOBAL; un control fallido si)")
    a2 = por_ronda(resultados, "A2")
    for r in resultados:
        r["veredicto"] = veredicto_ejecucion(r, a2.get(r["ronda"]))
    controles, salida = veredictos_controles(resultados)
    salida.update(veredictos_causas(resultados, controles))
    return salida


def veredictos_controles(resultados):
    """Controles P y D (y la causa 3, informativa), los mismos en los dos
    modos. Devuelve (los dos controles pasan, diccionario)."""
    salida = {}
    control_p = acordar([(r["veredicto"] or (None,))[0] for r in resultados if r["variante"] == "P"])
    motivos_p = [f"r{r['ronda']}: {m}" for r in resultados if r["variante"] == "P"
                 for m in (r["veredicto"] or (None, []))[1]]
    filas_d = [r for r in resultados if r["variante"] == "D"]
    d_rondas = [r["veredicto"] for r in filas_d]
    control_d = acordar([v["control"] if v else None for v in d_rondas])
    salida["control_p"], salida["control_d"] = control_p, control_d
    if control_p:
        pasa(True, "control positivo P: oom_kill, evento oom de Docker y -9 con muestras subiendo, en las 3 rondas")
    else:
        sinc(f"control positivo P: no se cumple en las 3 rondas ({'; '.join(motivos_p) or 'ejecucion no valida'}): "
             "TODO es SIN CONCLUSION")
    if control_d:
        pasa(True, "control de linea base D: retenido <= 60 MiB y uordblks sin pendiente en las 3 rondas")
    else:
        motivos_d = [f"r{r['ronda']}: {m}" for r in filas_d if r["veredicto"] for m in r["veredicto"]["motivos"]]
        sinc(f"control de linea base D ({'; '.join(motivos_d) or 'ejecucion no valida'}): TODO es SIN CONCLUSION")
    causa3 = acordar([v["causa3"] if v else None for v in d_rondas])
    p(f"   causa 3 (fuga, uordblks sube >= 1 MiB en D): {texto_si_no(causa3)} (hallazgo, informativo)")
    salida["causa3"] = causa3
    return bool(control_p and control_d), salida


def veredictos_regresion(resultados):
    """--regresion: controles P, D y V, y los oráculos de R. A diferencia de
    los arreglos candidatos de D1 (hallazgos), R es la prueba del arreglo de
    la API: un NO PASA es FALLA y cambia el RESULTADO GLOBAL."""
    p("=== veredictos de la regresion (plan R1 v2; oraculos literales fijados antes de ejecutar)")
    v_por_ronda = por_ronda(resultados, "V")
    for r in resultados:
        r["veredicto"] = veredicto_ejecucion(r, v_por_ronda.get(r["ronda"]))
    controles, salida = veredictos_controles(resultados)
    filas_v = [r for r in resultados if r["variante"] == "V"]
    control_v = acordar([(r["veredicto"] or (None,))[0] for r in filas_v])
    motivos_v = [f"r{r['ronda']}: {m}" for r in filas_v if r["veredicto"] for m in r["veredicto"][1]]
    if control_v:
        pasa(True, f"control V (camino viejo, 40 hilos, 1 GiB): a >= {ARENAS_MINIMAS_V} en fin_F2 en las 3 rondas")
    else:
        sinc(f"control V (camino viejo): no se cumple en las 3 rondas ({'; '.join(motivos_v) or 'ejecucion no valida'})"
             ": TODO es SIN CONCLUSION")
    controles = controles and bool(control_v)
    salida["control_v"] = control_v
    filas_r = [r for r in resultados if r["variante"] == "R"]
    for oraculo, agregar, texto in (
            ("memoria", acordar_memoria, f"sin oom_kill, a <= {ARENAS_MAXIMAS_R}, cada arena de hilo <= 1,3 x 19 MiB y "
                                         f"retenido <= {mib(RETENIDO_MAXIMO_R)} MiB en cada fin y maximo de fase"),
            ("tiempos", acordar, "p50 y p95 de verify() en el hilo argon2 <= 1,25 x V de la ronda y <= 1,25 x A2 "
                                 "de D1")):
        valor = agregar([r["veredicto"][oraculo][0] if r["veredicto"] else None for r in filas_r])
        motivos = [f"r{r['ronda']}: {m}" for r in filas_r if r["veredicto"] for m in r["veredicto"][oraculo][1]]
        if not controles:
            valor = None
        detalle = f" ({'; '.join(motivos)})" if motivos else ""
        if valor is None:
            sinc(f"R {oraculo} ({texto}): las 3 rondas no concluyen, alguna no es valida o un control falla{detalle}")
        else:
            pasa(valor, f"R {oraculo}: {texto}, en las 3 rondas{detalle}")
        salida[f"R_{oraculo}"] = valor
    # Un NO PASA en cualquiera de los dos basta; PASA exige los dos.
    memoria, tiempos = salida["R_memoria"], salida["R_tiempos"]
    if memoria is False or tiempos is False:
        arreglo = False
    else:
        arreglo = True if memoria and tiempos else None
    p(f"   ARREGLO R1 EN EL BANCO: {'SIN CONCLUSION' if arreglo is None else ('PASA' if arreglo else 'NO PASA')}")
    if arreglo:
        # Plan R1, Despliegue y redacción: nunca "arreglado" antes de L1.
        p("   Redaccion hasta que L1 cumpla su prediccion: mitigacion de la causa 1 demostrada en el banco, "
          "pendiente de L1")
    salida["arreglo_R1"] = arreglo
    return salida


def texto_si_no(valor):
    return "SIN CONCLUSION" if valor is None else ("SI" if valor else "NO")


def veredictos_causas(resultados, controles):
    salida = {}
    va = [r["veredicto"] for r in resultados if r["variante"] == "A"]
    f1 = acordar([v["F1"] if v else None for v in va])
    f2 = acordar([v["F2"] if v else None for v in va])
    causa1_a2 = acordar([v[0] if v else None for v in (r["veredicto"] for r in resultados if r["variante"] == "A2")])
    motivos_a2 = [f"r{r['ronda']}: {m}" for r in resultados if r["variante"] == "A2" and r["veredicto"]
                  for m in r["veredicto"][1]]
    if not controles:
        f1 = f2 = causa1_a2 = None
    p(f"   F1 (reproduccion de L1) con A: {texto_si_no(f1)} (retenido maximo en F1 >= 9 x 19 MiB o un oom_kill)")
    if f1 is False and f2:
        p("   HALLAZGO: F1 no llega a la meseta de L1 pero F2 si: la causa 1 no basta para explicar L1")
    if f1 is None:
        sinc("F1 con A: las 3 rondas no coinciden o alguna no es valida")
    p(f"   prediccion de la causa 1 en A2 (cada fin de fase): {texto_si_no(causa1_a2)}"
      + (f" ({'; '.join(motivos_a2)})" if motivos_a2 else ""))
    if causa1_a2 is None:
        sinc("prediccion de la causa 1 en A2: las 3 rondas no coinciden o alguna no es valida")
    if causa1_a2 is None or f1 is None:
        causa1 = None
    else:
        causa1 = causa1_a2 and f1
    p(f"   CAUSA 1: {'SIN CONCLUSION' if causa1 is None else ('CONFIRMADA' if causa1 else 'NO CONFIRMADA')}")
    salida.update({"F1": f1, "F2": f2, "causa1_A2": causa1_a2, "causa1": causa1})
    salida["E"] = informe_e(resultados, controles)
    salida["causa2"] = informe_causa2(resultados)
    for variante in ("B", "C2"):
        filas = [r for r in resultados if r["variante"] == variante]
        valor = acordar([r["veredicto"][0] if r["veredicto"] else None for r in filas]) if controles else None
        motivos = [f"r{r['ronda']}: {m}" for r in filas if r["veredicto"] for m in r["veredicto"][1]]
        p(f"   ARREGLO {variante}: {'SIN CONCLUSION' if valor is None else ('PASA' if valor else 'NO PASA')}"
          + (f" ({'; '.join(motivos)})" if motivos else ""))
        if valor is None:
            sinc(f"arreglo {variante}: las 3 rondas no coinciden, alguna no es valida o un control falla")
        salida[f"arreglo_{variante}"] = valor
    return salida


def informe_e(resultados, controles):
    """E solo informa si A se dispara en la misma ronda (plan)."""
    a, e = por_ronda(resultados, "A"), por_ronda(resultados, "E")
    textos = {}
    for ronda in sorted(e):
        va, ve = a.get(ronda, {}).get("veredicto"), e[ronda].get("veredicto")
        if not controles or va is None or ve is None:
            textos[ronda] = "SIN CONCLUSION"
        elif not va["F1"]:
            textos[ronda] = "no informa (A no se dispara en esta ronda)"
        else:
            textos[ronda] = ("E tambien se dispara: la causa 1 no es la unica" if ve
                             else "E no se dispara: compatible con la causa 1")
        p(f"   E, ronda {ronda} (informativo): {textos[ronda]}")
    return textos


def informe_causa2(resultados):
    """A-t, una sola ejecución: informativo, no un veredicto (plan)."""
    filas = [r for r in resultados if r["variante"] == "A-t"]
    if not filas or filas[0]["sin_conclusion"] or "fin_R2" not in filas[0]["hitos"]:
        p("   causa 2 (A-t, informativo): sin datos validos")
        return None
    r = filas[0]
    base, fin = r["base_tracemalloc"], r["hitos"]["fin_R2"]["tracemalloc"]
    if base is None or fin is None:
        p("   causa 2 (A-t, informativo): sin datos de tracemalloc")
        return None
    # Objetos de Python: lo trazado. El coste propio de tracemalloc
    # (get_tracemalloc_memory) se resta de uordblks, que lo incluye.
    objetos = fin["actual"] - base["actual"]
    ford = r["hitos"]["fin_R2"]["fordblks"]
    uord_sin_tm = r["hitos"]["fin_R2"]["uordblks"] - fin["propia"]
    crece = objetos >= CRECIMIENTO_CAUSA2
    p(f"   causa 2 (A-t, informativo): objetos de Python +{mib(objetos)} MiB, uordblks sin tracemalloc "
      f"{mib(uord_sin_tm)} MiB, fordblks {mib(ford)} MiB: "
      + ("crece tracemalloc" if crece else "tracemalloc no crece"))
    return {"objetos": objetos, "uordblks_sin_tracemalloc": uord_sin_tm, "fordblks": ford}


# ---------------------------------------------------------------------------
# Orden de las ejecuciones
# ---------------------------------------------------------------------------
def orden_ejecuciones(orden_base=ORDEN_BASE, una_sola_vez=UNA_SOLA_VEZ):
    """3 rondas con el orden rotado (len // 3 posiciones por ronda: 2 en D1 y
    1 en --regresion, para que cada variante caiga en un sitio distinto) y,
    si la hay, la variante de una sola vez al final de la primera ronda."""
    plan = []
    paso = len(orden_base) // RONDAS
    for ronda in range(1, RONDAS + 1):
        desplazamiento = (ronda - 1) * paso
        orden = orden_base[desplazamiento:] + orden_base[:desplazamiento]
        plan += [(v, ronda) for v in orden]
        if ronda == 1 and una_sola_vez is not None:
            plan.append((una_sola_vez, 1))
    return plan


# ---------------------------------------------------------------------------
# Principal
# ---------------------------------------------------------------------------
def comprobaciones_previas():
    if ejecutar(["docker", "info", "--format", "{{.ServerVersion}}"]).rc != 0:
        p("PARADA: docker info falla")
        terminar_con_parada()
    previos = recursos_previos()
    if previos:
        p(f"PARADA: ya existen recursos con prefijo {PROYECTO}: {previos} (restos de una ejecucion anterior)")
        terminar_con_parada()
    if not PROGRAMA.is_file():
        p(f"PARADA: no encuentro {PROGRAMA}")
        terminar_con_parada()


def medir(cpus, salida, inicio):
    plan = orden_ejecuciones(ORDEN_REGRESION, None) if MODO["regresion"] else orden_ejecuciones()
    estimado = len(plan) * ESTIMACION_EJECUCION_S + ESTIMACION_CONSTRUCCION_S
    p(f"=== plan: {len(plan)} ejecuciones ({', '.join(f'{v}/r{r}' for v, r in plan)})")
    p(f"   estimacion {estimado / 60:.0f} min; tope {TIEMPO_MAXIMO_S // 60} min")
    if estimado > TIEMPO_MAXIMO_S:
        raise Parada(f"la estimacion ({estimado / 60:.0f} min) supera el tope de {TIEMPO_MAXIMO_S // 60} min")
    resultados = []
    for variante, ronda in plan:
        # El tope global se comprueba antes de cada ejecución: como mucho se
        # pasa en una ejecución (el plazo más el margen).
        if time.monotonic() - inicio > TIEMPO_MAXIMO_S:
            raise Parada(f"se superan los {TIEMPO_MAXIMO_S // 60} min del plan")
        ejecucion = lanzar_ejecucion(variante, ronda, cpus, salida)
        res = analizar_ejecucion(ejecucion)
        p(f"   codigo hijo {res['codigo_hijo']}, oom_kill {res['oom_kill']}, evento oom {res['oom_docker']}, "
          f"retenido maximo {mib(res['max_retenido'].get('total'))} MiB"
          + (f"; SIN CONCLUSION: {'; '.join(res['sin_conclusion'])}" if res["sin_conclusion"] else ""))
        resultados.append(res)
    return resultados


def informe(resultados, salida):
    p("=== tabla por variante (retenido = anon + swap.current - swapcached - base; a = arenas de hilo que crecen "
      ">= 19 MiB)")
    regresion = MODO["regresion"]
    for variante in (ORDEN_REGRESION if regresion else (*ORDEN_BASE, UNA_SOLA_VEZ)):
        tabla_variante(variante, resultados)
    p("=== diferencias con L1 (declaradas)")
    for diferencia in (DIFERENCIAS_REGRESION if regresion else DIFERENCIAS_L1):
        p(f"   - {diferencia}")
    globales = veredictos_regresion(resultados) if regresion else veredictos(resultados)
    (salida / "resultados.json").write_text(json.dumps({"ejecuciones": resultados, "veredictos": globales},
                                                       indent=1, default=str), encoding="utf-8", newline="\n")
    p(f"   resultados: {salida / 'resultados.json'}")


def limpiar():
    p("=== limpieza")
    for nombre in [n for n in ejecutar(["docker", "ps", "-a", "--format", "{{.Names}}"]).out.split()
                   if n.startswith(PROYECTO)]:
        ejecutar(["docker", "rm", "-f", nombre])
    r = ejecutar(["docker", "image", "rm", IMAGEN])
    p(f"docker image rm {IMAGEN} -> codigo {r.rc}")
    restos = recursos_previos()
    pasa(not restos, f"ningun contenedor, red, volumen ni imagen con prefijo {PROYECTO} {restos or ''}".strip())


def leer_modo(argumentos):
    """Sin argumentos, D1; con --regresion, la regresión del arreglo R1.
    Cualquier otra cosa es un error visible, no un modo por defecto."""
    if argumentos not in ([], ["--regresion"]):
        print("uso: python tests\\estres\\diagnosticar_memoria.py [--regresion]", flush=True)
        sys.exit(2)
    return argumentos == ["--regresion"]


def main():
    MODO["regresion"] = leer_modo(sys.argv[1:])
    inicio = time.monotonic()
    git_arranque = estado_git()
    # Precondiciones: si fallan, no se limpia nada (podrían ser recursos ajenos).
    comprobaciones_previas()
    try:
        comprobar_literales_api()
        canario, texto = elegir_cpus_canario(leer_topologia())
    except Parada as e:
        p(f"PARADA: {e}")
        terminar_con_parada()
    cpus = ",".join(str(c) for c in canario)
    p(f"=== CPU: {texto}")
    salida = pathlib.Path(tempfile.mkdtemp(prefix="canario_diag_salida_"))
    parada = None
    try:
        construir_imagen()
        comprobacion_previa(cpus)
        resultados = medir(cpus, salida, inicio)
        informe(resultados, salida)
    except Parada as e:
        parada = str(e)
        p(f"PARADA: {parada}")
    except Exception:  # noqa: BLE001 - error inesperado del propio banco: se informa y se limpia
        parada = "error inesperado en el banco"
        p("ERROR INESPERADO:\n" + traceback.format_exc())
    finally:
        limpiar()
        git_final = estado_git()
        if git_arranque is None or git_final is None:
            sinc("no se pudo comparar el estado de Git")
        else:
            iguales = git_final == git_arranque
            pasa(iguales, "el banco no ha modificado el repo (git status igual al del arranque)")
            if not iguales:
                p(f"   al arrancar: {git_arranque}")
                p(f"   al terminar: {git_final}")
        p(f"Salida (JSON de cada ejecucion, stderr y resultados.json): {salida}")
        p(f"Duracion total: {(time.monotonic() - inicio) / 60:.1f} min")
    if parada is not None:
        estado["falla"] = True
    terminar()


if __name__ == "__main__":
    main()
