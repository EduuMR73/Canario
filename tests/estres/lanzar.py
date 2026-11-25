#!/usr/bin/env python3
"""Lanzador de la prueba de estrés L1 (capacidad y codo, docs/informe-pruebas.md,
secciones 2 y 3). Se ejecuta en el host, desde la raíz del repo, con la pila
local parada:

    python tests\\estres\\lanzar.py --hash [--conservar]
    python tests\\estres\\lanzar.py --l1 --t <segundos> [--conservar]
    python tests\\estres\\lanzar.py --l2|--pico|--l3|--l3b|--l7 --t 0.0196 [--repeticiones N] [--conservar]
    python tests\\estres\\lanzar.py --l5 [--repeticiones N] [--conservar]
    python tests\\estres\\lanzar.py --l6 [--humo] [--conservar]

--l5 (IP compartida), --l6 (agotar el limitador; --humo es la sonda B del
plan v3.2) y --l7 (inundacion de /salud) usan los limites de produccion y el
arnes de L3; sus funciones puras estan en la seccion "L5, L6 y L7".

--l2 (aislamiento: inundacion del login y tres victimas), --pico (L4: pico de
10 veces y recuperacion), --l3 (200 IPs con los limites de produccion) y
--l3b (el coste del ataque de L2 con esos limites) usan k6 con fases.js o
l3.js, tres repeticiones y las cifras de la segunda congelacion (docs/
informe-pruebas.md): por eso --t debe ser 0.0196. Sus oraculos, controles de
validez y el escaner anti-fuga estan en las funciones puras de la seccion "L2,
L3, L3b y L4", con sus pruebas en tests/estres/test_lanzar.py.

Las modalidades de L1 comparten:
* comprobaciones previas: Docker en marcha, ningún recurso con el prefijo
  canario_estres, las subredes fijas del compose libres, los puertos 8443 a
  8445 libres y docker compose config sin errores. Si algo falla, PARADA sin
  tocar nada (podrían ser recursos ajenos);
* la topología de CPU de la VM de Docker, leída con la imagen de Redis ya
  fijada en docker-compose.yml: elige 2 CPU lógicas de núcleos distintos para
  TODOS los servicios de Canario (override cpuset) y 4 para k6, que no son
  esas ni sus hermanas de hiperhilo. mem_limit no se toca;
* su propia pila (proyecto canario_estres), con los overrides en un
  directorio temporal: límites de estrés (las 9 reglas a 1 000 000 por su
  misma ventana) y el cpuset, comprobados con la línea entera de límites del
  log de la API y con docker inspect;
* limpieza en finally: down -v --rmi local, restos con el prefijo, git status
  igual al del arranque y los temporales, salvo el de salida, cuya ruta
  imprime. Termina con RESULTADO GLOBAL: OK o NO OK (código 0 solo si OK).

--hash mide, dentro del contenedor de la API, un hash y la mediana de 20
verify() de Argon2id en serie con los parámetros de app/personal.py
(comprobados antes como literales sobre el texto del fichero, sin
importarlo). Imprime t y 2/t, el dato de H1 para la primera congelación. No
toca la base de datos ni los secretos.

--l1 da de alta una empresa con gestion y lanza k6 (tests/estres/l1.js) una
vez por escalón, endurecido y en el espacio de red de Caddy. Mientras corre,
guarda en streaming los logs de la API, Redis y PostgreSQL y docker stats
continuo. Analiza el CSV de k6 con la biblioteca estándar: por escalón y
ruta, p50/p95/p99, errores (sección 3), códigos de estado, error_code de k6,
saturación del generador y de Canario, CPU de cada contenedor, BlockIO de
PostgreSQL y las señales del log por marca de tiempo. Decide el codo y el
corte de la escalera y deja una tabla en texto y resultados.json/csv.

--l1 repite la ejecución completa (--repeticiones, 3 por defecto) y añade:
* un detector de muertes desde fuera (docker events en streaming, clasificado
  por etiquetas), un lector de cgroup a 4 Hz de los 4 servicios y de su
  cgroup padre, y un control positivo en sándwich (un contenedor que muere
  por OOM a propósito, al principio y al final) que demuestra que el
  detector ve una muerte; sin ese control, la ejecución es SIN CONCLUSION;
* la puerta de R1: 0 reinicios de Canario en toda la ejecución y memoria
  (anon + swap - swapcached, muestreada a 4 Hz) de 160 MiB como mucho en los
  escalones de login cubiertos y en su calentamiento;
* la agregación entre repeticiones: la puerta toma el peor caso; la latencia,
  mediana, mínimo y máximo del p95 por escalón.
El análisis puro (veredictos, ventanas, cgroups) está en funciones sin Docker,
con sus pruebas en tests/estres/test_lanzar.py.

--conservar deja la pila y los temporales para desarrollar e imprime la
orden exacta para borrarlos. La evidencia sale de una ejecución sin él.

Solo biblioteca estándar.
"""
import argparse
import base64
import bisect
import collections
import contextlib
import csv
import datetime
import heapq
import itertools
import json
import math
import pathlib
import re
import secrets
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.parse

RAIZ = pathlib.Path(__file__).resolve().parent.parent.parent
DIR_ESTRES = RAIZ / "tests" / "estres"
COMPOSE = RAIZ / "docker-compose.yml"
PERSONAL = RAIZ / "app" / "personal.py"
PROYECTO = "canario_estres"
SALIDA_TEXTO = pathlib.Path(tempfile.gettempdir()) / "verificacion_estres.txt"
# Con el perfil gestion (alta de la empresa): down solo actúa sobre los
# servicios de los perfiles activos, y así también borra su imagen.
BASE = ["docker", "compose", "-p", PROYECTO, "-f", str(COMPOSE), "--profile", "gestion"]

lineas_salida = []
estado = {"falla": False, "sin_conclusion": False}

# Límites de estrés: las 9 reglas exactas de LIMITES_POR_DEFECTO
# (app/limitador.py), cada una a 1 000 000 (LIMITE_MAXIMO, el tope que admite
# CANARIO_LIMITES) por su misma ventana, que ya divide el día. Toda la carga
# sale de una sola IP (k6 dentro del espacio de red de Caddy): con los
# límites de producción, el limitador respondería 429 a partir de la
# petición 11 y se mediría el limitador, no la capacidad. La línea entera con
# la que la API los anuncia al arrancar (app/principal.py), en orden
# alfabético.
LIMITES_ESTRES = ("denuncia=1000000/3600,seguimiento=1000000/60,mensajes=1000000/3600,acceso=1000000/300,"
                  "registro=1000000/3600,otras=1000000/60,cuenta=1000000/60,destinatario=1000000/900,"
                  "destinatario_dia=1000000/86400")
LINEA_LIMITES = ("INFO canario.arranque: LIMITES (configurados): acceso=1000000/300 cuenta=1000000/60 "
                 "denuncia=1000000/3600 destinatario=1000000/900 destinatario_dia=1000000/86400 "
                 "mensajes=1000000/3600 otras=1000000/60 registro=1000000/3600 seguimiento=1000000/60")

# Limites de PRODUCCION (L3 y L3b): LIMITES_POR_DEFECTO de app/limitador.py. La
# linea es TEXTO_LIMITES_PRODUCCION de tests/security/verificar_denuncia.py:386
# con el prefijo con el que la API la registra (app/principal.py:94, origen
# "por defecto" al no haber CANARIO_LIMITES).
LINEA_LIMITES_PRODUCCION = ("INFO canario.arranque: LIMITES (por defecto): acceso=10/300 cuenta=60/60 "
                            "denuncia=10/3600 destinatario=3/900 destinatario_dia=10/86400 mensajes=30/3600 "
                            "otras=60/60 registro=10/3600 seguimiento=60/60")
# Override de Caddy de produccion (compose.produccion.yaml:75-96). Sin
# build/image/pull_policy: la imagen es la que construye el compose local.
YAML_CADDY_PRODUCCION = (
    "services:\n"
    "  caddy:\n"
    '    command: ["caddy", "run", "--config", "/etc/caddy/Caddyfile.produccion", "--adapter", "caddyfile"]\n'
    "    ports: !reset []\n"
    "networks:\n"
    "  edge:\n"
    "    internal: true\n")

PUERTOS = (8443, 8444, 8445)
# Las subredes fijas de las redes que crean los servicios que se levantan
# (app, edge, canje y correo: la API se conecta a las dos últimas).
SUBREDES = ("10.88.0.0/28", "10.88.1.0/28", "10.88.2.0/28", "10.88.4.0/28")
# Todos los servicios de Canario llevan el mismo cpuset, también los que esta
# prueba no levanta: si mañana se levantan, no quedan fuera del modelo.
SERVICIOS = ("redis", "postgres", "api", "broker", "cartero", "gestion", "mailpit", "caddy")
SERVICIOS_PILA = ("api", "caddy", "postgres", "redis")

# k6 v2.3.0 fijada por digest (índice; amd64
# sha256:7637f6a2c358cf1decd8b1f339649da429f5e91901ecee19bfc0486c9edb5b13).
# Usuario k6 de la imagen (Dockerfile de k6 v2.3.0: adduser -u 12345).
IMG_K6 = "grafana/k6:2.3.0@sha256:2dd4756ec6e14e62778916e1eb850108e4b499304c02df56760fa0bdb0fba0b8"
USUARIO_K6 = "12345:12345"
# Memoria de k6: 4 GiB de los 8 GB de Docker Desktop. La pila de Canario
# tiene topes que suman 1 GiB (redis 128m, postgres 512m, api 256m, caddy
# 128m); el resto queda para la VM y dockerd.
MEMORIA_K6 = "4g"
# Tope de VUs por escenario. Supuesto sin medir: unos 5 MiB por VU para un
# script de una petición sin cuerpos (discardResponseBodies), el extremo alto
# de lo que la documentación de k6 da para scripts sencillos. 600 VUs son
# unos 3 GiB, dentro de MEMORIA_K6 con margen para las sondas y el CSV.
# Si k6 se queda sin memoria, docker inspect da OOMKilled y el escalón es
# SIN CONCLUSION.
TOPE_VUS = 600
# maxVUs = min(tasa x 15, TOPE_VUS): 15 s es el plazo de cada petición en
# l1.js, así que por debajo del tope los VUs bastan aunque todas las
# peticiones agoten el plazo.
SEGUNDOS_PLAZO = 15
VUS_SONDA = 15
# gracefulStop de todos los escenarios de k6 (l1.js, fases.js, l3.js) y
# segundos que se conceden a k6 para inicializar los VUs (J13; el plazo de
# lanzar_escalon ya incluia los 300).
GRACEFUL_STOP_S = 20
INICIALIZACION_S = 300

# Protocolo que debe negociar k6 con Caddy (proxy/servidor.caddy: protocols
# h1). Literal: si apareciera otro, se estaría midiendo otra pila.
PROTOCOLO = "HTTP/1.1"

# SLO de L1 (docs/informe-pruebas.md, sección 3), en milisegundos, y el
# umbral de errores. Literales, no derivados de nada que se mida.
SLO_MS = {"login_email": 1500, "login_empresa": 1500, "denuncia": 1000, "seguimiento": 500, "sonda_web": 300}
UMBRAL_ERRORES = 0.01
# Oráculo de estado: proporción mínima del estado esperado entre las
# respuestas que no son error.
UMBRAL_ESPERADO = 0.99
ESPERADO = {"login_email": 401, "login_empresa": 401, "seguimiento": 404, "denuncia": 201,
            "sonda_salud": 405, "sonda_web": 200}
# Generador saturado: CPU de k6 por encima del 80 % de su cpuset (4 CPU,
# docker stats da el porcentaje sobre una CPU: 320 %).
CPUS_K6 = 4
UMBRAL_CPU_K6 = 0.80 * CPUS_K6 * 100

# Escaleras (docs/informe-pruebas.md, L1). El primer escalón de cada ruta es
# el control: la tasa más baja, que debe cumplir el SLO.
FACTORES_LOGIN_EMAIL = (0.5, 0.75, 1.0, 1.25, 1.5)
FACTORES_LOGIN_EMPRESA = (0.5, 1.0, 1.25)
TASAS_SEGUIMIENTO = (25, 50, 100, 200, 300, 400)
TASAS_DENUNCIA = (10, 25, 50, 100, 150, 200)
ORDEN_RUTAS = ("login_email", "login_empresa", "seguimiento", "denuncia")
CALENTAMIENTO_S = 30
REPOSO_S = 30
DURACION_MINIMA_S = 60
MUESTRAS_MINIMAS = 600
# Escalones seguidos fuera del SLO tras los que se corta la escalera.
CORTE = 2
# Sobrecoste estimado de cada ejecución de k6 (arranque del contenedor,
# inicialización de VUs, gracefulStop y lectura de resultados). Supuesto.
SOBRECOSTE_S = 15
TIEMPO_MAXIMO_S = 45 * 60
REPETICIONES_POR_DEFECTO = 3
# Sobrecoste por repetición (down -v, up --wait, alta de la empresa y
# recreación de la API entre rutas) y de los dos controles en sándwich. Solo la
# repetición 1 construye la imagen (up --build); las siguientes arrancan con
# --no-build sobre la misma imagen, y siguen siendo independientes (down -v,
# BD y Redis nuevos). Supuesto.
SOBRECOSTE_REPETICION_S = 4 * 60
SOBRECOSTE_CONTROLES_S = 4 * 60

# Puerta de R1 (plan lanzar v4, F). Todo literal, no derivado de nada que se
# mida ni del código que se prueba.
# Memoria máxima de la API en los escalones de login: 160 MiB, el máximo
# muestreado a 4 Hz de anon + swap.current - swapcached (la fórmula de
# diag_memoria_contenedor.py, la misma del banco D1/R1).
LIMITE_MEMORIA_B = 167772160
# Margen de coherencia cuando el muestreo puede no ver las reservas de Argon2:
# HASHES_SIMULTANEOS (2) x MEMORIA_ARGON2_KIB (19456) KiB, valores que
# comprobar_literales_argon2 verifica sobre app/personal.py al arrancar.
MARGEN_ARGON2_B = 2 * 19456 * 1024
MEMORIA_ARGON2_B = 19456 * 1024
# Cobertura de un escalón de login (QA E1): iteraciones lanzadas sobre las
# planificadas.
UMBRAL_COBERTURA = 0.95
# Límites de cgroup que debe ver el lector para saber que lee el cgroup que
# cree leer (memory.max, memory.swap.max): la API (mem_limit 256m, sin
# memswap_limit: swap = memoria, hecho de diagnosticar_memoria.py:193-197) y el
# control (--memory 64m --memory-swap 128m: swap = 64 MiB).
LIMITES_CGROUP = {"api": ("268435456", "268435456"), "control": ("67108864", "67108864")}
PERIODO_LECTOR_S = 0.25
# Un hueco del lector mayor que esto, fuera de una muerte registrada, es SIN
# CONCLUSION: la puerta no vio ese tramo.
HUECO_MAXIMO_S = 3.0
# Un reposo solo descarta el margen de Argon2 si el lector lo vio entero: su
# última muestra debe caer como pronto REPOSO_S - 0,5 s después del fin del
# escalón. 0,5 s son 2 periodos del lector: la última muestra puede quedar
# hasta un periodo antes del fin del reposo, más el retraso de planificación.
# Ningún camino del lanzador da un reposo real de menos de REPOSO_S (el sleep
# antes de cada escalón y el del final de la ruta), así que la tolerancia no
# lo relaja: si un reposo intermedio sale corto, se investiga, no se sube.
TOLERANCIA_REPOSO_S = 0.5
# Ventana en torno a un die para emparejar contadores de cgroup (solo ordena
# el incremento y el die, no atribuye por sí sola).
VENTANA_MUERTE_S = 5.0
CENTINELA_S = 10
# Trozo de reserva y pausa del control positivo (patrón de P en
# diagnosticar_memoria.py:180-183 con trozos de 4 MiB: 64 MiB de memoria y 64
# de swap se llenan en unos 3 s).
TROZO_CONTROL_MIB = 4
PAUSA_CONTROL_S = 0.1
USUARIO_API = "10001:10001"
PREFIJO_EFIMEROS = PROYECTO + "_"
EXTRAS_POSTGRES = ("log_checkpoints=on", "log_autovacuum_min_duration=0")

# Argon2id de app/personal.py, como literales: si el fichero cambia, la t
# medida ya no es la del login y la prueba se detiene.
LITERALES_ARGON2 = (
    re.compile(r"^MEMORIA_ARGON2_KIB = 19456$", re.M),
    re.compile(r"^HASHES_SIMULTANEOS = 2$", re.M),
    re.compile(r"^ITERACIONES_ARGON2 = 2$", re.M),
    re.compile(r"^PARALELISMO_ARGON2 = 1$", re.M),
    re.compile(r"PasswordHasher\(time_cost=ITERACIONES_ARGON2, memory_cost=MEMORIA_ARGON2_KIB,\s*"
               r"parallelism=PARALELISMO_ARGON2, hash_len=32, salt_len=16, type=Type\.ID\)"),
)
VERIFICACIONES = 20
# Se ejecuta en el contenedor de la API con python -I (sin variables
# PYTHON*, sin el directorio actual ni el site del usuario). La contraseña es
# aleatoria y no sale del contenedor. Sin comillas dobles: llegan intactas
# por la lista de argumentos, pero así no dependen de nada.
CODIGO_HASH = (
    "import json, secrets, time\n"
    "from argon2 import PasswordHasher, Type\n"
    "h = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1, hash_len=32, salt_len=16, type=Type.ID)\n"
    "c = secrets.token_urlsafe(24)\n"
    "i = time.perf_counter(); d = h.hash(c); th = time.perf_counter() - i\n"
    "v = []\n"
    f"for _ in range({VERIFICACIONES}):\n"
    "    i = time.perf_counter(); h.verify(d, c); v.append(time.perf_counter() - i)\n"
    "print(json.dumps(dict(hash=th, verify=v)))\n"
)
T_MINIMA, T_MAXIMA = 0.005, 2.0

# Lector de cgroup: corre en un contenedor efímero de la imagen de la API con
# --cgroupns host y SIN -v (el cgroup de la VM se ve como /sys/fs/cgroup). Sin
# comillas dobles (llegan por lista de argumentos, pero así no dependen del
# shell). Argumentos: segundos de espera a que aparezcan las rutas y pares
# nombre=id. Cada 0,25 s imprime una línea JSON con su hora (reloj de la VM,
# el mismo de docker events, k6 y StartedAt) y, de cada objetivo, los
# contadores de memory.stat, memory.swap.current, pids.current, memory.events
# y el inode del directorio (un inode nuevo = una encarnación nueva). Reabre
# los ficheros en cada lectura. Una ruta ausente en la muestra es None (el
# contenedor está parado): el lanzador lo registra como hueco. Además lee
# memory.events del cgroup padre y de cada hijo suyo (oom y oom_kill
# jerárquicos en cgroup v2) para atribuir una muerte sin depender del
# cgroup del hijo, que puede borrarse antes de la siguiente muestra.
CODIGO_LECTOR = (
    "import json, os, sys, time\n"
    "RAIZ = '/sys/fs/cgroup'\n"
    "espera = float(sys.argv[1])\n"
    "objetivos = dict(a.split('=', 1) for a in sys.argv[2:])\n"
    "def buscar(ident):\n"
    "    rutas = []\n"
    "    for d, sub, _ in os.walk(RAIZ):\n"
    "        rutas += [os.path.join(d, s) for s in sub if ident in s]\n"
    "        if d[len(RAIZ):].count('/') >= 3:\n"
    "            sub[:] = []\n"
    "    return rutas\n"
    "def leer(ruta, nombre):\n"
    "    with open(os.path.join(ruta, nombre), encoding='ascii') as f:\n"
    "        return f.read()\n"
    "def pares(texto):\n"
    "    return {k: int(v) for k, v in (l.split() for l in texto.splitlines() if l.strip())}\n"
    "def opcional(ruta, nombre):\n"
    "    try:\n"
    "        return int(leer(ruta, nombre).strip())\n"
    "    except (OSError, ValueError):\n"
    "        return None\n"
    "def muestra(ruta):\n"
    "    try:\n"
    "        st = pares(leer(ruta, 'memory.stat'))\n"
    "        ev = pares(leer(ruta, 'memory.events'))\n"
    "        return {'anon': st['anon'], 'swapcached': st['swapcached'], 'file': st['file'],\n"
    "                'kernel': st.get('kernel'), 'swap_current': int(leer(ruta, 'memory.swap.current').strip()),\n"
    "                'pids': int(leer(ruta, 'pids.current').strip()), 'oom': ev['oom'], 'oom_kill': ev['oom_kill'],\n"
    "                'inode': os.stat(ruta).st_ino, 'pico': opcional(ruta, 'memory.peak'),\n"
    "                'swap_pico': opcional(ruta, 'memory.swap.peak')}\n"
    "    except OSError:\n"
    "        return None\n"
    "def eventos(ruta):\n"
    "    try:\n"
    "        ev = pares(leer(ruta, 'memory.events'))\n"
    "        return [ev['oom'], ev['oom_kill']]\n"
    "    except OSError:\n"
    "        return None\n"
    "print(json.dumps({'tipo': 'listo', 't': time.time()}), flush=True)\n"
    "limite = time.time() + espera\n"
    "while True:\n"
    "    rutas = {n: buscar(i) for n, i in objetivos.items()}\n"
    "    if all(rutas.values()) or time.time() > limite:\n"
    "        break\n"
    "    time.sleep(0.2)\n"
    "padres = {n: os.path.dirname(r[0]) for n, r in rutas.items() if len(r) == 1}\n"
    "padre = next(iter(padres.values()), None)\n"
    # runc crea el directorio del cgroup antes de escribir sus límites: leerlos
    # en cuanto aparece el directorio puede dar 'max' (carrera vista el 22/11).
    # Se releen cada 0,05 s hasta que ninguno vale 'max', con un plazo de 2 s.
    # Si al vencer siguen en 'max', se informa 'max' y el oráculo literal falla
    # de forma visible (un contenedor sin límite no se da por bueno).
    "limites = {}\n"
    "for n, r in rutas.items():\n"
    "    if len(r) == 1:\n"
    "        fin_limites = time.time() + 2.0\n"
    "        while True:\n"
    "            limites[n] = {k: leer(r[0], k).strip() for k in ('memory.max', 'memory.swap.max')}\n"
    "            if 'max' not in limites[n].values() or time.time() > fin_limites:\n"
    "                break\n"
    "            time.sleep(0.05)\n"
    # Solo los subdirectorios son cgroups hijos (los ficheros cgroup.*, memory.*
    # son del propio padre). Para cada hijo, si tiene algún proceso en todo su
    # subárbol: un cgroup vacío (buildkit sin construir nada) no puede sumar un
    # OOM en los contadores del padre.
    "def con_procesos(raiz):\n"
    "    for d, _, _ in os.walk(raiz):\n"
    "        try:\n"
    "            with open(os.path.join(d, 'cgroup.procs')) as f:\n"
    "                if f.read().strip():\n"
    "                    return True\n"
    "        except OSError:\n"
    "            continue\n"
    "    return False\n"
    "hijos = sorted(h for h in os.listdir(padre) if os.path.isdir(os.path.join(padre, h))) if padre else []\n"
    "procesos = {h: con_procesos(os.path.join(padre, h)) for h in hijos}\n"
    "print(json.dumps({'tipo': 'inicio', 't': time.time(), 'rutas': rutas, 'padres': padres,\n"
    "                  'limites': limites, 'hijos': hijos, 'procesos': procesos}), flush=True)\n"
    "if not all(len(r) == 1 for r in rutas.values()):\n"
    "    sys.exit(3)\n"
    "while True:\n"
    "    t0 = time.time()\n"
    "    linea = {'tipo': 'muestra', 't': t0, 'c': {n: muestra(r[0]) for n, r in rutas.items()},\n"
    "             'padre': eventos(padre), 'hijos': {}}\n"
    "    try:\n"
    "        for h in os.listdir(padre):\n"
    "            e = eventos(os.path.join(padre, h))\n"
    "            if e is not None:\n"
    "                linea['hijos'][h] = e\n"
    "    except OSError:\n"
    "        pass\n"
    "    print(json.dumps(linea), flush=True)\n"
    "    time.sleep(max(0.0, 0.25 - (time.time() - t0)))\n"
)

# Control positivo: reserva memoria en trozos de 4 MiB con pausas de 0,1 s
# hasta que el OOM del cgroup lo mata. Se escribe en cada trozo para que las
# páginas se toquen de verdad.
CODIGO_CONTROL = (
    "import time\n"
    "trozos = []\n"
    "while True:\n"
    f"    trozos.append(bytearray(b'x') * ({TROZO_CONTROL_MIB} * 1024 * 1024))\n"
    f"    time.sleep({PAUSA_CONTROL_S})\n"
)

PATRON_ALTA = re.compile(r"empresa creada: empresa_id=([0-9a-f-]{36}) identificador_publico=([0-9a-f]{32})")
PATRON_REDIS = re.compile(r"^\s*image:\s*(redis:\S+@sha256:[0-9a-f]{64})\s*$", re.M)
PATRON_HERMANAS = re.compile(r"^/sys/devices/system/cpu/cpu(\d+)/topology/thread_siblings_list (\S+)$", re.M)
ORDEN_TOPOLOGIA = ("for f in /sys/devices/system/cpu/cpu[0-9]*/topology/thread_siblings_list; "
                   "do echo $f $(cat $f); done")
PATRON_MARCA = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?Z\s?(.*)$")
PATRON_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
PATRON_JSON = re.compile(r"\{[^{}]*\}")
PATRON_INSUFICIENTES = re.compile(r"Insufficient VUs.*?scenario=(\S+)")
# Líneas de PostgreSQL con log_checkpoints y log_autovacuum_min_duration=0.
PATRON_CHECKPOINT = re.compile(r"checkpoint starting")
PATRON_AUTOVACUUM = re.compile(r"automatic (?:vacuum|analyze) of table")

# Evento del limitador (app/limitador.py, texto_evento):
#   EVENTO limitador_no_disponible: <clase> causa=<causa> espera=<tramo>
# Los grupos 2 (causa) y 3 (espera) son OPCIONALES: una imagen anterior al
# cambio solo da la clase, y esa línea se cuenta como "sin_dato" (visible, no
# descartada). Es la única fuente del patrón: SENALES lo reutiliza.
# El grupo 4 es lo que queda de línea tras la espera. NO se ancla con $ tras el
# grupo 3: una línea con texto de más ("espera=<0.25 basura") dejaría de casar
# y saldría del total sin avisar. Se deja casar y parsear_limitador marca como
# anómalo cualquier sobrante no vacío.
PATRON_LIMITADOR = re.compile(r"EVENTO limitador_no_disponible: (\S+)(?: causa=(\S+))?(?: espera=(\S+))?(.*)$")
# Conjuntos cerrados del evento, escritos aquí como literales y NO importados
# de app/limitador.py: si la API cambiara sus conjuntos, un valor nuevo debe
# verse como "fuera_de_conjunto" y no colarse en silencio como válido.
CAUSAS_LIMITADOR = ("pool_agotado", "permiso", "plazo", "conexion", "otra")
ESPERAS_LIMITADOR = ("<0.25", "0.25-0.5", ">0.5")
SIN_DATO = "sin_dato"  # la línea no trae el campo (imagen anterior al evento con causa)
FUERA_DE_CONJUNTO = "fuera_de_conjunto"  # trae el campo con un valor que no es del conjunto cerrado
# Ventana tras un evento start de Redis, solo para SEPARAR los errores que
# siguen a un arranque de Redis de los demás (información; no los presenta
# como legítimos: en L1 el único start esperado es el de preparar_repeticion,
# antes del primer escalón, y un start dentro de la medida es un reinicio tras
# una muerte, o sea un incidente). Semiabierta [start, start + 10 s), como
# ventana_de.
VENTANA_ARRANQUE_REDIS_S = 10

# Señales del log de la API (app/frontera_http.py, app/personal.py y
# app/limitador.py). El grupo 1, si lo hay, es la clase del error.
SENALES = (
    ("sin_conexion_pooltimeout", re.compile(r"SIN CONEXION: PoolTimeout\b")),
    ("sin_conexion_otra", re.compile(r"SIN CONEXION: (?!PoolTimeout\b)(\S+)")),
    ("saturacion", re.compile(r"SATURACION: (\S+)")),
    ("hashes_saturados", re.compile(r"EVENTO hashes_saturados\b")),
    ("limitador_no_disponible", PATRON_LIMITADOR),
    ("error_interno", re.compile(r"ERROR INTERNO: (.+)$")),
    ("login_fallido", re.compile(r"EVENTO login_fallido\b")),
)

# error_code de k6 (documentación de k6, "Error codes", consultada el
# 21/11/2026 en su versión latest). Literales: el análisis no los deduce.
CODIGOS_K6 = {
    "1000": "error generico", "1010": "error de red no TCP", "1020": "URL no valida",
    "1050": "plazo de la peticion agotado", "1100": "error de DNS", "1101": "sin IP para el host",
    "1110": "IP en lista negra", "1111": "host bloqueado", "1200": "error TCP generico",
    "1201": "tuberia rota al escribir (el otro extremo cerro)", "1202": "error TCP del sistema",
    "1210": "error al conectar", "1211": "plazo de conexion agotado", "1212": "conexion rechazada",
    "1213": "error de conexion desconocido", "1220": "conexion reiniciada por el otro extremo",
    "1300": "error TLS generico", "1310": "emisor del certificado desconocido",
    "1311": "el certificado no casa con el host", "1600": "error HTTP/2 generico",
    "1701": "error de descompresion",
}


# ---------------------------------------------------------------------------
# Utilidades de ejecución y de informe (duplicadas por batería, como en
# tests/security/ y tests/funcionales/)
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


def dc(*args, timeout=900):
    return ejecutar(BASE + list(args), timeout=timeout)


def pasa(cond, texto):
    p(("PASA  " if cond else "FALLA ") + texto)
    if not cond:
        estado["falla"] = True


def sinc(texto):
    p("SIN CONCLUSION " + texto)
    estado["sin_conclusion"] = True


def terminar():
    if estado["falla"] or estado["sin_conclusion"]:
        resultado = "NO OK (hay FALLA o SIN CONCLUSION)"
    else:
        resultado = "OK"
    p("RESULTADO GLOBAL: " + resultado)
    SALIDA_TEXTO.write_text("\n".join(lineas_salida) + "\n", encoding="utf-8", newline="\n")
    sys.exit(0 if resultado == "OK" else 1)


def terminar_con_parada():
    p("RESULTADO GLOBAL: NO OK (PARADA)")
    SALIDA_TEXTO.write_text("\n".join(lineas_salida) + "\n", encoding="utf-8", newline="\n")
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
    previos = []
    for orden in (["docker", "ps", "-a", "--format", "{{.Names}}"],
                  ["docker", "network", "ls", "--format", "{{.Name}}"],
                  ["docker", "volume", "ls", "--format", "{{.Name}}"],
                  ["docker", "image", "ls", "--format", "{{.Repository}}"]):
        previos += [n for n in ejecutar(orden).out.split() if n.startswith(PROYECTO)]
    return previos


def subredes_ocupadas():
    """Redes ajenas que ya usan alguna de las subredes fijas del compose."""
    ocupadas = []
    for red in ejecutar(["docker", "network", "ls", "-q"]).out.split():
        r = ejecutar(["docker", "network", "inspect", "--format",
                      "{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}", red])
        partes = r.out.split()
        if partes and set(partes[1:]) & set(SUBREDES):
            ocupadas.append(partes[0])
    return ocupadas


def puertos_ocupados():
    ocupados = []
    for puerto in PUERTOS:
        s = socket.socket()
        s.settimeout(2)
        try:
            if s.connect_ex(("127.0.0.1", puerto)) == 0:
                ocupados.append(puerto)
        finally:
            s.close()
    return ocupados


def orden_powershell(args):
    return " ".join(f'"{a}"' if " " in a or "\\" in a else a for a in args)


def a_epoch(marca):
    """Segundos desde 1970 de una marca RFC 3339 en UTC con fracción de hasta
    nanosegundos (docker logs -t, docker inspect). None si no casa."""
    encaje = PATRON_MARCA.match(marca.strip())
    if encaje is None:
        return None
    base = datetime.datetime.strptime(encaje.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.UTC)
    fraccion = encaje.group(2)
    return base.timestamp() + (float("0." + fraccion) if fraccion else 0.0)


def percentil(ordenados, q):
    """Percentil por rango más cercano sobre una lista ya ordenada."""
    if not ordenados:
        return None
    rango = max(1, math.ceil(q / 100 * len(ordenados)))
    return ordenados[rango - 1]


def porcentaje(texto):
    try:
        return float(texto.strip().rstrip("%"))
    except (ValueError, AttributeError):
        return None


UNIDADES = {"b": 1, "kb": 1e3, "mb": 1e6, "gb": 1e9, "tb": 1e12, "kib": 1024, "mib": 1024 ** 2,
            "gib": 1024 ** 3, "tib": 1024 ** 4}


def bytes_de(texto):
    encaje = re.fullmatch(r"\s*([0-9.]+)\s*([A-Za-z]+)\s*", texto or "")
    if encaje is None or encaje.group(2).lower() not in UNIDADES:
        return None
    return float(encaje.group(1)) * UNIDADES[encaje.group(2).lower()]


def ms(valor):
    return "-" if valor is None else f"{valor:.0f}"


# ---------------------------------------------------------------------------
# Análisis puro, sin Docker (sus pruebas: tests/estres/test_lanzar.py). Todo lo
# que decide un veredicto de la puerta vive aquí, separado de la E/S, para
# poder probarlo con entradas escritas a mano.
# ---------------------------------------------------------------------------
PATRON_HORA_MOTOR = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?(Z|[+-]\d\d:\d\d)$")
PATRON_ID_LARGO = re.compile(r"[0-9a-f]{64}")
ORDEN_ESTADOS = {"PASA": 0, "SIN CONCLUSION": 1, "FALLA": 2}


def hora_motor(texto):
    """Segundos desde 1970 de la hora del motor (docker info --format
    {{.SystemTime}}), con sufijo Z o con un desfase explícito. Si no encaja,
    PARADA: nunca un 0 en silencio (con él, todas las ventanas saldrían
    movidas)."""
    encaje = PATRON_HORA_MOTOR.match((texto or "").strip())
    if encaje is None:
        raise Parada(f"la hora del motor no tiene un formato reconocible: {texto!r}")
    base = datetime.datetime.strptime(encaje.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.UTC)
    fraccion = encaje.group(2)
    epoch = base.timestamp() + (float("0." + fraccion) if fraccion else 0.0)
    sufijo = encaje.group(3)
    if sufijo != "Z":
        signo = 1 if sufijo[0] == "+" else -1
        epoch -= signo * (int(sufijo[1:3]) * 3600 + int(sufijo[4:6]) * 60)
    return epoch


def etiquetas_de(texto):
    """Etiquetas de docker ps --format {{.Labels}} ("a=b,c=d") como dict."""
    etiquetas = {}
    for parte in (texto or "").split(","):
        clave, igual, valor = parte.partition("=")
        if igual:
            etiquetas[clave] = valor
    return etiquetas


# Valores de la etiqueta canario.estres que pone el lanzador (k6, lector y
# control) y la sonda de descartes (sonda_descartes.ETIQUETA_SONDA).
CLASES_PROPIAS = ("k6", "lector", "control", "sonda")
# Clase de un contenedor con canario.estres y un valor que no está en
# CLASES_PROPIAS: es un instrumento nuestro que el lanzador no sabe tratar.
# Los filtros de muertes, starts y huecos lo ignorarían en silencio, así que
# instrumentos_desconocidos lo convierte en SIN CONCLUSION con su nombre.
CLASE_INSTRUMENTO = "instrumento_desconocido"


def clase_contenedor(atributos):
    """Qué es un contenedor por sus etiquetas. Si lleva la clave
    canario.estres, es un contenedor propio y NUNCA se clasifica por compose:
    los que salen de la imagen de la API (lector, control y el servidor de la
    sonda) heredan sus etiquetas de compose (M1-bis y M1-contenedor del plan
    v4.2, 25/11/2026), y por ellas pasarían por la API. Un valor de
    CLASES_PROPIAS da esa clase; uno desconocido, CLASE_INSTRUMENTO. Sin la
    clave: "canario" si es uno de los 4 servicios de la pila; "auxiliar" si es
    de compose pero de otro servicio (gestion); None si no es nuestro (se
    ignora)."""
    if "canario.estres" in atributos:
        propia = atributos["canario.estres"]
        return propia if propia in CLASES_PROPIAS else CLASE_INSTRUMENTO
    if atributos.get("com.docker.compose.project") == PROYECTO:
        return "canario" if atributos.get("com.docker.compose.service") in SERVICIOS_PILA else "auxiliar"
    return None


def parsear_evento(linea):
    """Evento de docker events (formato json) normalizado. ValueError si la
    línea no es JSON (se cuenta como ilegible: un fallo visible). None si no
    es un evento de contenedor. El reloj es timeNano, el de la VM."""
    bruto = json.loads(linea)
    if not isinstance(bruto, dict) or bruto.get("Type") != "container":
        return None
    actor = bruto.get("Actor") or {}
    atributos = actor.get("Attributes") or {}
    ident = actor.get("ID") or bruto.get("id")
    nano = bruto.get("timeNano")
    if not ident or not isinstance(nano, int):
        raise ValueError("evento sin id o sin timeNano")
    accion = (bruto.get("Action") or bruto.get("status") or "").split(":")[0].strip()
    return {"id": ident, "accion": accion, "t": nano / 1e9, "clase": clase_contenedor(atributos),
            "servicio": atributos.get("com.docker.compose.service") or atributos.get("name", ""),
            "nombre": atributos.get("name", ""), "codigo": atributos.get("exitCode")}


def ventana_de(t, ventanas):
    """La primera ventana que contiene t, semiabierta [desde, hasta): un
    evento justo en el borde final pertenece a la ventana siguiente. Las de
    mantenimiento van primero en la lista y mandan. None si ninguna."""
    for v in ventanas:
        if v["desde"] <= t < v["hasta"]:
            return v
    return None


def ventana_atribuida(t, ventanas):
    """Nombre de la ventana a la que se atribuye un evento: el escalón, el
    calentamiento o el mantenimiento; un reposo se atribuye al escalón
    anterior (lo que lo provocó está ahí)."""
    v = ventana_de(t, ventanas)
    if v is None:
        return None
    return v["anterior"] if v["tipo"] == "reposo" else v["nombre"]


def construir_ventanas(pasos, mantenimientos):
    """Ventanas sin solapes: las de mantenimiento primero y, por escalón,
    calentamiento (si hay), escalón y el reposo hasta el siguiente. pasos:
    {"nombre", "desde", "hasta", "cal_hasta"} en orden y con el reloj de la
    VM."""
    ventanas = [{"tipo": "mantenimiento", "nombre": m["motivo"], "desde": m["desde"],
                 "hasta": math.inf if m.get("hasta") is None else m["hasta"]} for m in mantenimientos]
    for i, paso in enumerate(pasos):
        cal = paso.get("cal_hasta")
        if cal is not None and paso["desde"] < cal < paso["hasta"]:
            ventanas.append({"tipo": "calentamiento", "nombre": paso["nombre"] + " (calentamiento)",
                             "desde": paso["desde"], "hasta": cal})
            ventanas.append({"tipo": "escalon", "nombre": paso["nombre"], "desde": cal, "hasta": paso["hasta"]})
        else:
            ventanas.append({"tipo": "escalon", "nombre": paso["nombre"], "desde": paso["desde"],
                             "hasta": paso["hasta"]})
        if i + 1 < len(pasos) and paso["hasta"] < pasos[i + 1]["desde"]:
            ventanas.append({"tipo": "reposo", "nombre": "reposo tras " + paso["nombre"], "anterior": paso["nombre"],
                             "desde": paso["hasta"], "hasta": pasos[i + 1]["desde"]})
    return ventanas


def encarnaciones_eventos(eventos):
    """Encarnaciones de UN contenedor (mismo id) a partir de sus eventos: lo
    que hay entre un start y su die. Con el reinicio por política el id es el
    mismo, así que se separan por start: dos start seguidos son dos
    encarnaciones. Devuelve [{"inicio", "fin", "codigo"}]."""
    encarnaciones = []
    for ev in sorted(eventos, key=lambda e: e["t"]):
        if ev["accion"] == "start":
            encarnaciones.append({"inicio": ev["t"], "fin": None, "codigo": None})
        elif ev["accion"] == "die" and encarnaciones and encarnaciones[-1]["fin"] is None:
            encarnaciones[-1]["fin"] = ev["t"]
            encarnaciones[-1]["codigo"] = ev["codigo"]
    return encarnaciones


def muertes_no_esperadas(eventos, mantenimientos):
    """die de los contenedores de Canario que el lanzador no provocó. Esperado
    = el id que el lanzador para a propósito (mantenimiento: sus ids, desde su
    instante y hasta el destroy de ese id). Un die de otro id en esa misma
    ventana (postgres en la recreación de la API) NO es esperado."""
    destruidos = set()
    muertes = []
    for ev in sorted(eventos, key=lambda e: e["t"]):
        if ev["clase"] != "canario":
            continue
        if ev["accion"] == "destroy":
            destruidos.add(ev["id"])
        elif ev["accion"] == "die":
            esperado = ev["id"] not in destruidos and any(
                ev["id"] in m["ids"] and ev["t"] >= m["desde"] for m in mantenimientos)
            if not esperado:
                muertes.append(ev)
    return muertes


def starts_no_esperados(eventos):
    """start de contenedores de Canario que no son el primero de su id: los
    reinicios por política, que deben coincidir con RestartCount. Los ids
    nuevos que crea el lanzador (up, --force-recreate) empiezan con un start
    que no cuenta."""
    vistos = collections.Counter(e["id"] for e in eventos if e["clase"] == "canario" and e["accion"] == "start")
    return sum(n - 1 for n in vistos.values())


def otro_murio(eventos, ident, desde, hasta, mantenimientos):
    """Si en la ventana murió otro contenedor de Canario, k6 o el lector con
    un código distinto de 0 y sin que el lanzador lo parara a propósito. El
    fin normal de k6 (código 0) no cuenta."""
    for ev in eventos:
        if (ev["clase"] in ("canario", "k6", "lector") and ev["accion"] == "die" and ev["id"] != ident
                and desde <= ev["t"] <= hasta and ev.get("codigo") not in (None, "0")
                and not any(ev["id"] in m["ids"] and ev["t"] >= m["desde"] for m in mantenimientos)):
            return True
    return False


def instrumentos_desconocidos(eventos):
    """Nombres (sin repetir y ordenados) de los contenedores con clase
    CLASE_INSTRUMENTO que aparecen en eventos, con cualquier acción. Los
    filtros de muertes, starts, huecos y conciliación solo miran la clase
    "canario" y lo ignorarían en silencio: quien llama lo convierte en SIN
    CONCLUSION. Sin nombre en el evento, se da el id corto."""
    return sorted({e["nombre"] or e["id"][:12] for e in eventos if e["clase"] == CLASE_INSTRUMENTO})


def muertes_por_clase(eventos):
    """Recuento de los die por clase de contenedor ("ajeno" si no es nuestro),
    para la salida."""
    return dict(sorted(collections.Counter(e["clase"] or "ajeno" for e in eventos if e["accion"] == "die").items()))


def control_c5(eventos):
    """Control C5 de L4 (plan v4.2, cambio 7), sobre los eventos de la
    repetición 1: el servidor de la sonda de descartes tiene que haber dejado
    un die clasificado como "sonda". Si no, la clasificación de la sonda no
    está demostrada y la repetición es SIN CONCLUSION. Se busca por el NOMBRE
    del servidor (sonda_descartes.nombre_servidor, la misma fuente que lo
    crea) y no solo por la clase: el k6 de la sonda también lleva
    canario.estres=sonda y muere con 0 al terminar. No se exige el código
    137: no está medido. Devuelve (ok, texto) con los die por clase."""
    # Carga perezosa, como en comprobar_sonda_descartes: solo --pico la necesita.
    import sonda_descartes
    servidor = sonda_descartes.nombre_servidor(PREFIJO_EFIMEROS)
    por_clase = muertes_por_clase(eventos)
    visto = any(e["accion"] == "die" and e["nombre"] == servidor and e["clase"] == "sonda" for e in eventos)
    if visto:
        return True, f"die por clase {por_clase}; el servidor de la sonda {servidor} muere clasificado como sonda"
    return False, (f"die por clase {por_clase}; no hay un die de {servidor} clasificado como sonda: la "
                   "clasificacion de la sonda no esta demostrada")


def delta_serie(serie, desde, hasta):
    """Incremento de un contador en [desde, hasta]. serie: [(t, valor)]
    ordenada. Valor inicial: el último muestreado a la hora desde o antes
    (o el primero de la serie si no lo hay); final: el último a hasta o
    antes. 0 si no hay muestras en ningún punto (el que llama lo anota)."""
    validas = [(t, v) for t, v in serie if v is not None]
    if not validas:
        return 0
    antes = [v for t, v in validas if t <= desde]
    inicial = antes[-1] if antes else validas[0][1]
    hasta_v = [v for t, v in validas if t <= hasta]
    final = hasta_v[-1] if hasta_v else inicial
    return max(0, final - inicial)


def veredicto_muerte(sube_oom, sube_oom_kill, otro_murio_, sube_oom_k6):
    """Veredicto de un die no esperado de Canario con los contadores del
    cgroup PADRE (no los del hijo, que a 4 Hz puede borrarse antes de verse).
    Todo es FALLA de la puerta (la puerta dice 0 reinicios), salvo el OOM
    global de la VM, donde la puerta no puede decidir: SIN CONCLUSION (las
    latencias de ese escalón, no el reinicio). El evento oom de Docker no es
    oráculo: no interviene."""
    if sube_oom and not otro_murio_:
        dudosa = " (atribucion dudosa: oom de k6 en la misma ventana)" if sube_oom_k6 else ""
        return "FALLA", "OOM por su propio limite" + dudosa
    if sube_oom_kill and not sube_oom:
        return "SIN CONCLUSION", "OOM global de la VM"
    if otro_murio_:
        return "FALLA", "no atribuible (murio otro contenedor en la misma ventana; no se lee como OOM ajeno)"
    return "FALLA", "no atribuible"


def etiquetar_cgroup(serie):
    """Encarnaciones de un cgroup a partir de su serie [(t, muestra|None)]. Una
    encarnación nueva empieza con un inode nuevo o con un contador (oom,
    oom_kill) que baja: el cgroup se recreó. Devuelve (muestras con "enc" y
    "t", encarnaciones [{"indice","desde","hasta","primera","ultima"}])."""
    muestras, encarnaciones, previa = [], [], None
    for t, m in serie:
        if m is None:
            continue
        nueva = (previa is None or m["inode"] != previa["inode"] or m["oom"] < previa["oom"]
                 or m["oom_kill"] < previa["oom_kill"])
        if nueva:
            encarnaciones.append({"indice": len(encarnaciones), "desde": t, "hasta": t, "primera": m, "ultima": m})
        enc = encarnaciones[-1]
        enc["hasta"], enc["ultima"] = t, m
        muestras.append({**m, "t": t, "enc": enc["indice"]})
        previa = m
    return muestras, encarnaciones


def huecos_de_serie(serie, umbral=HUECO_MAXIMO_S, desde=None, hasta=None):
    """Tramos de más de umbral segundos sin una muestra válida (ruta ausente o
    retraso del lector): [(desde, hasta)], con la hora de la última válida y
    de la siguiente (o de la última muestra de la serie, si el tramo llega
    hasta el final).

    desde y hasta acotan un tramo que debe estar cubierto entero (el reposo de
    un escalón): con desde, el hueco entre desde y la primera muestra válida
    también cuenta (un lector que tarda en ver el reposo no lo vio); con
    hasta, el cierre es hasta y no la última muestra (un lector que se corta
    antes del final deja hueco). Sin ellos, el comportamiento es el de
    siempre."""
    huecos, ultima = [], desde
    for t, m in serie:
        if m is None:
            continue
        if ultima is not None and t - ultima > umbral:
            huecos.append((ultima, t))
        ultima = t
    fin = hasta if hasta is not None else (serie[-1][0] if serie else None)
    if ultima is not None and fin is not None and fin - ultima > umbral:
        huecos.append((ultima, fin))
    return huecos


def huecos_no_explicados(huecos, tiempos_muerte, margen=1.0):
    """Huecos sin ninguna muerte registrada (ni esperada) en su interior o a
    margen segundos: la puerta no vio ese tramo y no sabe por qué."""
    return [(a, b) for a, b in huecos if not any(a - margen <= t <= b + margen for t in tiempos_muerte)]


def acumulado_contadores(encarnaciones):
    """oom y oom_kill acumulados de las encarnaciones de un cgroup. La
    primera: último menos primero visto (el lector puede llegar tarde); las
    siguientes: su último valor, porque un cgroup nuevo parte de 0."""
    total = {"oom": 0, "oom_kill": 0}
    for enc in encarnaciones:
        for clave in total:
            total[clave] += enc["ultima"][clave] - (enc["primera"][clave] if enc["indice"] == 0 else 0)
    return total


def memoria_puerta(m):
    """La fórmula de R1 (diag_memoria_contenedor.py:210-215): lo que el
    contenedor tiene de verdad, sin la caché de swap. file y kernel no entran:
    son información."""
    return m["anon"] + m["swap_current"] - m["swapcached"]


def maximo_memoria(muestras, desde, hasta):
    """(máximo, encarnación, hora) de memoria_puerta en [desde, hasta], o None
    si no hay muestras en la ventana."""
    mejor = None
    for m in muestras:
        if desde <= m["t"] <= hasta:
            valor = memoria_puerta(m)
            if mejor is None or valor > mejor[0]:
                mejor = (valor, m["enc"], m["t"])
    return mejor


def minimo_reposo(muestras, desde, hasta, enc):
    """Mínimo de memoria_puerta en el reposo [desde, hasta) y en la MISMA
    encarnación que el máximo; None si no hay muestras (muerte, corte, último
    escalón sin reposo muestreado)."""
    valores = [memoria_puerta(m) for m in muestras if desde <= m["t"] < hasta and m["enc"] == enc]
    return min(valores) if valores else None


def hay_indicio_picos(maximo_escalon, minimo_reposo_):
    """Hay indicio de reservas de Argon2 que el muestreo a 4 Hz no ve si lo
    retenido en el reposo queda más de 19456 KiB por debajo del máximo del
    escalón (la memoria se devuelve). Si lo retenido se mantiene (las arenas
    de glibc retienen los bloques), los buffers ya están en la muestra. Sin
    reposo que mirar, el margen se aplica por defecto."""
    if minimo_reposo_ is None:
        return True
    return maximo_escalon - minimo_reposo_ > MEMORIA_ARGON2_B


def veredicto_memoria(maximo, con_margen):
    """Veredicto de la memoria de un escalón (o de su calentamiento): el
    máximo muestreado, como mucho 160 MiB. Con margen (hay indicio de picos no
    muestreados, o no hay reposo que lo descarte), el máximo más 2 x 19456 KiB
    también debe caber; si no, SIN CONCLUSION: no se presenta como garantía."""
    if maximo is None:
        return "SIN CONCLUSION", "sin muestras del lector en la ventana"
    if maximo > LIMITE_MEMORIA_B:
        return "FALLA", f"maximo {maximo} B supera {LIMITE_MEMORIA_B} B"
    if con_margen and maximo + MARGEN_ARGON2_B > LIMITE_MEMORIA_B:
        return "SIN CONCLUSION", (f"maximo {maximo} B cabe, pero con 2 x 19456 KiB de reservas de Argon2 no "
                                  f"muestreadas ({maximo + MARGEN_ARGON2_B} B) no cabe en {LIMITE_MEMORIA_B} B")
    return "PASA", f"maximo {maximo} B <= {LIMITE_MEMORIA_B} B"


def siguiente_lanzado(resultados, i):
    """El siguiente escalón de la MISMA ruta en el que k6 llegó a correr, o
    None. Se decide por la presencia de la clave k6_id, que lanzar_escalon
    solo pone cuando el contenedor de k6 arrancó; el resultado sintético de un
    escalón "no se lanzo" no la tiene ni tuvo tráfico, así que se salta (su
    reposo sigue hasta el siguiente lanzado). No se decide por inicio_vm (un
    inspect fallido no quita que k6 corriera) ni por el texto del motivo."""
    ruta = resultados[i]["ruta"]
    for siguiente in resultados[i + 1:]:
        if siguiente["ruta"] != ruta:
            return None
        if "k6_id" in siguiente:
            return siguiente
    return None


def reposo_de_escalon(muestras, res, siguiente, fin_ruta, enc):
    """Mínimo de memoria_puerta en el reposo de un escalón y en la MISMA
    encarnación que su máximo: (mínimo, None) si el reposo es válido, o
    (None, motivo) si no lo es y el margen de Argon2 debe aplicarse.

    El reposo empieza en res["fin_vm"] y acaba en el inicio del siguiente
    escalón lanzado de la ruta (siguiente) o, si no lo hay, en el fin del
    reposo final de la ruta (fin_ruta["fin_reposo_vm"], con el lector vivo).
    La ventana es cerrada en los dos extremos: la muestra justo en el fin
    cuenta. Solo vale si el lector lo vio entero: última muestra como pronto
    REPOSO_S - TOLERANCIA_REPOSO_S después del fin del escalón y sin huecos de
    más de HUECO_MAXIMO_S, contando el inicial y el del cierre. Un mínimo de un
    reposo truncado podría descartar el margen sin haber visto lo retenido."""
    if siguiente is not None:
        if siguiente.get("inicio_vm") is None:
            # k6 corrió pero no se sabe cuándo empezó: el tráfico del siguiente
            # escalón podría estar dentro de la ventana.
            return None, "siguiente escalon sin hora"
        hasta = siguiente["inicio_vm"]
    else:
        if not fin_ruta.get("lector_vivo_al_final"):
            # Un lector muerto no vio el final del reposo, aunque sus
            # muestras anteriores parezcan cubrirlo.
            return None, "lector muerto en el reposo final"
        hasta = fin_ruta["fin_reposo_vm"]
    desde = res.get("fin_vm")
    if desde is None:
        # Sin la hora de fin de k6 no se sabe dónde empieza el reposo; se
        # dice, en lugar de comparar con None.
        return None, "escalon sin hora de fin"
    propias = [m for m in muestras if desde <= m["t"] <= hasta and m["enc"] == enc]
    if not propias or max(m["t"] for m in propias) < desde + REPOSO_S - TOLERANCIA_REPOSO_S:
        return None, "reposo corto"
    if huecos_de_serie([(m["t"], m) for m in propias], desde=desde, hasta=hasta):
        return None, "hueco en el reposo"
    return min(memoria_puerta(m) for m in propias), None


def veredicto_escalon_memoria(maximo, minimo, motivo):
    """(veredicto, texto, nota) de la memoria de un escalón o de su
    calentamiento a partir del máximo, del mínimo del reposo (None si no hay
    reposo válido) y del motivo de que no lo haya. El margen se aplica si hay
    indicio de picos no muestreados o no hay reposo válido; la nota dice cuál
    de los dos casos es."""
    con_margen = maximo is not None and hay_indicio_picos(maximo, minimo)
    veredicto, texto = veredicto_memoria(maximo, con_margen)
    if minimo is not None and not con_margen:
        nota = "retenido estable: sin margen"
    elif minimo is not None:
        nota = "con margen de 2 x 19456 KiB"
    else:
        nota = f"con margen de 2 x 19456 KiB (sin reposo valido: {motivo})"
    return veredicto, texto, nota


def escalon_cubierto(peticiones, tasa, duracion_s, descartadas, con_aviso, cpu_k6_alta):
    """Un escalón de login cubre la puerta si las iteraciones lanzadas
    (incluidas las que agotan el plazo) son al menos el 95 % de las
    planificadas, o si sus descartes llevan el aviso Insufficient VUs (la API
    recibió toda la concurrencia que da el generador); y en los dos casos sin
    descartes sin el aviso y con la CPU de k6 bajo el umbral (None = no
    medida: no cubierto). Devuelve (cubierto, motivo)."""
    if cpu_k6_alta is None:
        return False, "CPU de k6 no medida: no se sabe si el generador se saturo"
    if cpu_k6_alta:
        return False, "generador saturado (CPU de k6 sobre el umbral)"
    if descartadas > 0 and not con_aviso:
        return False, f"{descartadas} descartes sin el aviso de VUs insuficientes (generador)"
    if descartadas > 0:
        return True, f"{descartadas} descartes con Insufficient VUs: la API recibio toda la concurrencia del generador"
    planificadas = tasa * duracion_s
    if peticiones >= UMBRAL_COBERTURA * planificadas:
        return True, f"{peticiones} de {planificadas:.0f} iteraciones planificadas"
    return False, f"solo {peticiones} de {planificadas:.0f} iteraciones planificadas (menos del 95 %)"


def evaluar_protocolo(protocolos):
    """Control de protocolo sobre las filas con estado distinto de 0 (las de
    estado 0 siguen contando como error, pero no tienen protocolo). Si no hay
    ninguna respuesta con protocolo, no se puede comprobar: SIN CONCLUSION."""
    if sum(protocolos.values()) == 0:
        return "SIN CONCLUSION", "ninguna respuesta con protocolo: no se puede comprobar HTTP/1.1"
    otros = {k: v for k, v in protocolos.items() if k != PROTOCOLO}
    if otros:
        return "SIN CONCLUSION", f"protocolos distintos de {PROTOCOLO}: {otros}"
    return "PASA", f"todas las respuestas usan {PROTOCOLO}"


def peor_estado(estados):
    """El peor de una lista de estados: FALLA, luego SIN CONCLUSION, luego PASA."""
    return max(estados, key=ORDEN_ESTADOS.__getitem__, default="PASA")


def peor_caso(valores):
    """Máximo entre repeticiones, ignorando lo no medido. La puerta toma el
    peor caso, nunca la mediana: una repetición mala no se diluye."""
    medidos = [v for v in valores if v is not None]
    return max(medidos) if medidos else None


def resumen_latencias(valores):
    """Mediana, mínimo y máximo de los p95 de un escalón en las repeticiones;
    None si no hay ninguno."""
    medidos = [v for v in valores if v is not None]
    if not medidos:
        return None
    return {"mediana": statistics.median(medidos), "minimo": min(medidos), "maximo": max(medidos)}


def primera_repeticion_distinta(p95_por_repeticion):
    """Si la repetición 1 sale sistemáticamente distinta: p95_por_repeticion es
    {escalón: [p95 de la rep 1, de la 2, ...]}. Una repetición 1 es "distinta"
    en un escalón si cae fuera del rango de las demás; es sistemática si lo
    es en al menos el 75 % de los escalones comparables y siempre hacia el
    mismo lado. Devuelve (distinta, texto)."""
    arriba = abajo = comparables = 0
    for valores in p95_por_repeticion.values():
        primera, otras = valores[0], [v for v in valores[1:] if v is not None]
        if primera is None or len(otras) < 2:
            continue
        comparables += 1
        if primera > max(otras):
            arriba += 1
        elif primera < min(otras):
            abajo += 1
    if comparables == 0:
        return False, "sin escalones comparables (hacen falta 3 repeticiones)"
    lado = max(arriba, abajo)
    sistematica = lado >= 0.75 * comparables and (arriba == 0 or abajo == 0)
    sentido = "por encima" if arriba >= abajo else "por debajo"
    return sistematica, (f"{lado} de {comparables} escalones con la repeticion 1 fuera del rango de las demas "
                         f"({sentido}): {'sistematica' if sistematica else 'no sistematica'}")


def conciliar(n_eventos_oom, incremento_oom_cgroup, starts_inesperados, reinicios_inspect):
    """Conciliación final del detector: los eventos oom de Docker no pueden
    ser menos que los incrementos de oom vistos en los cgroups, y los start no
    esperados deben coincidir con RestartCount. Devuelve los desacuerdos."""
    problemas = []
    if n_eventos_oom < incremento_oom_cgroup:
        problemas.append(f"hay {incremento_oom_cgroup} incrementos de oom en los cgroups y solo {n_eventos_oom} "
                         "eventos oom en el stream")
    if starts_inesperados != reinicios_inspect:
        problemas.append(f"{starts_inesperados} start no esperados en el stream y RestartCount suma "
                         f"{reinicios_inspect}")
    return problemas


def desfase_valido(inicio, fin, tolerancia=1.0):
    """Desfase host-VM de un escalón a partir de las dos medidas (inicio y
    fin). Devuelve (desfase, motivo): sin medida o con las dos diferentes en
    más de la tolerancia, desfase None y el motivo (la CPU del escalón queda
    SIN CONCLUSION; nunca se fuerza a 0)."""
    if inicio is None or fin is None:
        return None, "no se pudo medir el desfase entre el reloj del host y el de la VM"
    if abs(inicio - fin) > tolerancia:
        return None, f"el desfase host-VM cambio de {inicio:.2f} s a {fin:.2f} s durante el escalon"
    return (inicio + fin) / 2, None


def comando_con_extras(original):
    """El command de PostgreSQL de docker compose config más los dos -c de
    estres que falten (log_checkpoints, log_autovacuum_min_duration). Se
    añaden al final: en PostgreSQL, el último -c de un parámetro gana."""
    lista = list(original)
    for extra in EXTRAS_POSTGRES:
        if extra not in lista:
            lista += ["-c", extra]
    return lista


def diferencias_comando(original, nuevo):
    """Diferencias entre el command que resuelve compose con el override y el
    original más los dos -c: vacío si solo difieren en esos dos parámetros."""
    esperado = comando_con_extras(original)
    if list(nuevo) == esperado:
        return []
    return [f"esperado {esperado}", f"resuelto {list(nuevo)}"]


def yaml_comando(comando):
    """Override de compose con el command entero de PostgreSQL. Cada
    elemento va como cadena JSON (válida en YAML) y con $ duplicado: compose
    interpola $ en los ficheros, pero config ya lo había resuelto."""
    lineas = ["services:", "  postgres:", "    command:"]
    lineas += [f"      - {json.dumps(a.replace('$', '$$'))}" for a in comando]
    return "\n".join(lineas) + "\n"


def args_incluyen(args, parametros):
    """Si los pares -c <parametro> están, en ese orden, en los Args de
    docker inspect del contenedor de PostgreSQL."""
    for parametro in parametros:
        if not any(args[i] == "-c" and args[i + 1] == parametro for i in range(len(args) - 1)):
            return False
    return True


def hijos_ajenos(nombres_hijos, contenedores, procesos=None):
    """Hijos del cgroup padre que no son del proyecto ni llevan
    canario.estres. contenedores: {id: {"nombre", "etiquetas"}}. Un hijo cuyo
    id no se conoce también es ajeno (se da su nombre de cgroup), salvo que
    procesos diga que no tiene ningún proceso en su subárbol: un cgroup vacío
    (por ejemplo, el de buildkit sin construir) no puede sumar un OOM al padre.
    Sin el dato de procesos, se trata como ajeno (fallo visible). Un contenedor
    con un valor desconocido de canario.estres (CLASE_INSTRUMENTO) también es
    ajeno (enmienda v4.3, punto 4): el lanzador no sabe qué es ni quién lo
    lanzó, y antes del cambio 3 de la v4.2 daba PARADA."""
    procesos = procesos or {}
    ajenos = []
    for nombre in nombres_hijos:
        encaje = PATRON_ID_LARGO.search(nombre)
        conocido = contenedores.get(encaje.group(0)) if encaje else None
        if conocido is None:
            if procesos.get(nombre, True):
                ajenos.append(nombre)
        elif clase_contenedor(conocido["etiquetas"]) in (None, CLASE_INSTRUMENTO):
            ajenos.append(conocido["nombre"])
    return ajenos


def problemas_inicio(inicio, nombres):
    """Problemas de la línea de inicio del lector: exactamente una ruta por
    objetivo, los literales de memory.max y memory.swap.max (que demuestran
    que es el cgroup de la API o del control) y un único padre común."""
    problemas = []
    for nombre in nombres:
        rutas = inicio.get("rutas", {}).get(nombre, [])
        if len(rutas) != 1:
            problemas.append(f"{nombre}: {len(rutas)} rutas de cgroup con su id ({rutas}), debe haber exactamente 1")
            continue
        esperado = LIMITES_CGROUP.get(nombre)
        visto = inicio.get("limites", {}).get(nombre, {})
        if esperado is not None and (visto.get("memory.max"), visto.get("memory.swap.max")) != esperado:
            problemas.append(f"{nombre}: memory.max/memory.swap.max = {visto.get('memory.max')}/"
                             f"{visto.get('memory.swap.max')}, esperado {esperado[0]}/{esperado[1]}")
    if len(set(inicio.get("padres", {}).values())) > 1:
        problemas.append(f"los objetivos no comparten cgroup padre: {inicio.get('padres')}")
    return problemas


def muestras_crecientes(muestras):
    """Cuántas muestras consecutivas de una encarnación superan a la anterior
    en memoria_puerta."""
    return sum(1 for a, b in itertools.pairwise(muestras) if memoria_puerta(b) > memoria_puerta(a))


def evaluar_control(encarnaciones, muestras, eventos, limites, subidas_padre):
    """Control positivo: lista de (ok, texto). Debe verse: los literales del
    cgroup del control; el lector arrancado antes, con al menos 5 muestras
    crecientes y swap_current > 0; el die 137 dos veces y el start dos veces
    (el reinicio, mismo id); la segunda encarnación con el cgroup recreado
    (inode nuevo, contadores a 0); y el OOM, con la MISMA fuente que la puerta:
    el contador oom del memory.events del cgroup PADRE (jerárquico, sobrevive
    a que el cgroup del hijo se borre), que debe subir al menos 2 durante el
    control (subidas_padre, medido por el lector entre su primera muestra y la
    última). El oom_kill del hijo y los eventos oom de Docker son solo
    información: no deciden."""
    r = []
    r.append((limites == {"memory.max": LIMITES_CGROUP["control"][0], "memory.swap.max": LIMITES_CGROUP["control"][1]},
              f"limites del cgroup del control {limites}, esperados {LIMITES_CGROUP['control']}"))
    primera = [m for m in muestras if m["enc"] == 0]
    crecientes = muestras_crecientes(primera)
    r.append((crecientes >= 5, f"{crecientes} muestras crecientes en la primera encarnacion (minimo 5)"))
    swap = max((m["swap_current"] for m in muestras), default=0)
    r.append((swap > 0, f"swap.current maximo {swap} B (debe ser mayor que 0)"))
    muertes_137 = [e for e in eventos if e["accion"] == "die" and e.get("codigo") == "137"]
    r.append((len(muertes_137) == 2, f"{len(muertes_137)} die con codigo 137 (esperados 2)"))
    arranques = [e for e in eventos if e["accion"] == "start"]
    r.append((len(arranques) == 2, f"{len(arranques)} start (esperados 2: el inicial y el reinicio)"))
    segunda = len(encarnaciones) >= 2
    r.append((segunda, f"{len(encarnaciones)} encarnaciones de cgroup (minimo 2)"))
    if segunda:
        a, b = encarnaciones[0], encarnaciones[1]
        r.append((a["primera"]["inode"] != b["primera"]["inode"] and b["primera"]["oom"] == 0
                  and b["primera"]["oom_kill"] == 0,
                  "la segunda encarnacion tiene inode nuevo y los contadores a 0"))
    n_oom_eventos = sum(1 for e in eventos if e["accion"] == "oom")
    vistos = [enc["ultima"]["oom_kill"] >= 1 for enc in encarnaciones]
    r.append((subidas_padre >= 2,
              f"el contador oom del cgroup padre sube {subidas_padre} veces durante el control (minimo 2). "
              f"Informacion, no oraculo: oom_kill del hijo visto por encarnacion {vistos}; {n_oom_eventos} "
              "eventos oom de Docker"))
    return r



# ---------------------------------------------------------------------------
# Topología de CPU y overrides
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
    red, de solo lectura, sin capacidades y sin root). /sys es la vista del
    kernel de la VM, que es el que reparte los cpuset."""
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


def elegir_cpus(hermanas):
    """(cpus de Canario, cpus de k6, texto). Canario: la primera CPU de dos
    núcleos distintos; k6: cuatro CPU de otros núcleos, una por núcleo
    mientras se pueda. Se evita el núcleo de la CPU 0, donde suelen caer las
    interrupciones y el trabajo del propio sistema de la VM."""
    nucleos = sorted(set(hermanas.values()), key=min)
    candidatos = [n for n in nucleos if 0 not in n]
    if len(candidatos) < 3:
        raise Parada(f"la VM de Docker solo tiene {len(nucleos)} nucleos: hacen falta 2 para Canario y otros "
                     "para k6, sin compartir hermanas")
    canario = [min(n) for n in candidatos[:2]]
    resto = candidatos[2:]
    k6 = [min(n) for n in resto][:CPUS_K6]
    if len(k6) < CPUS_K6:
        # Menos núcleos libres que CPU de k6: se completan con hermanas de
        # los núcleos de k6, nunca con las de Canario.
        k6 += sorted(c for n in resto for c in n if c not in k6)[:CPUS_K6 - len(k6)]
    if len(k6) < CPUS_K6:
        raise Parada(f"no quedan {CPUS_K6} CPU para k6 fuera de las de Canario y sus hermanas")
    sin_smt = all(len(n) == 1 for n in nucleos)
    texto = (f"nucleos de la VM: {[sorted(n) for n in nucleos]}; Canario en {canario} (nucleos "
             f"{[sorted(n) for n in candidatos[:2]]}); k6 en {sorted(k6)}")
    return canario, sorted(k6), texto, sin_smt


def preparar_overrides(temporal, cpus_canario, limites=LIMITES_ESTRES, caddy_produccion=False):
    """Los ficheros de compose adicionales, en el directorio temporal: el
    docker-compose.yml del repo no cambia.

    limites: la cadena de CANARIO_LIMITES (por defecto, los de estres). Con
    None NO se escribe el override: CANARIO_LIMITES se OMITE del entorno y la
    API usa LIMITES_POR_DEFECTO (los de produccion). Una cadena vacia no
    serviria: "" es un ErrorConfiguracion (app/limitador.py, cargar_limites).
    caddy_produccion: Caddy con proxy/Caddyfile.produccion, como en
    compose.produccion.yaml, pero SIN usar ese fichero entero (exige imagenes
    canario-api con pull_policy never)."""
    ficheros = []
    if limites is not None:
        fichero_limites = temporal / "limites_estres.yml"
        fichero_limites.write_text(f"services:\n  api:\n    environment:\n      CANARIO_LIMITES: \"{limites}\"\n",
                                   encoding="utf-8", newline="\n")
        ficheros.append(fichero_limites)
    # cpuset y no cpus: con cpus (cuota de CFS) el planificador reparte la
    # pila por las 16 CPU de la VM y solo limita el tiempo total; con cpuset
    # todos los servicios compiten por los mismos 2 núcleos, como en el VPS.
    lista = ",".join(str(c) for c in cpus_canario)
    lineas = ["services:"]
    for servicio in SERVICIOS:
        lineas += [f"  {servicio}:", f"    cpuset: \"{lista}\""]
    cpuset = temporal / "cpuset_estres.yml"
    cpuset.write_text("\n".join(lineas) + "\n", encoding="utf-8", newline="\n")
    ficheros.append(cpuset)
    if caddy_produccion:
        # Los mismos tres cambios de compose.produccion.yaml sobre caddy: la
        # orden con el Caddyfile de produccion, sin puertos publicados y la
        # red edge interna (C5). Una red interna no puede publicar puertos, y
        # en produccion Traefik llega a Caddy por esa red.
        fichero_caddy = temporal / "caddy_produccion.yml"
        fichero_caddy.write_text(YAML_CADDY_PRODUCCION, encoding="utf-8", newline="\n")
        ficheros.append(fichero_caddy)
    return ficheros


def comando_postgres_resuelto():
    """El command de PostgreSQL tal como lo resuelve docker compose con los
    ficheros de BASE (lista de cadenas)."""
    r = dc("config", "--format", "json", timeout=120)
    try:
        comando = json.loads(r.out)["services"]["postgres"]["command"]
    except (ValueError, KeyError, TypeError):
        raise Parada(f"docker compose config --format json no da el command de postgres (codigo {r.rc}): "
                     f"{r.err.strip()[-300:]!r}") from None
    if not isinstance(comando, list) or not all(isinstance(a, str) for a in comando):
        raise Parada(f"el command de postgres no es una lista de cadenas: {comando!r}")
    return comando


def preparar_override_postgres(temporal):
    """Activa log_checkpoints y log_autovacuum_min_duration=0 SOLO en el
    override de estres, sin docker exec ni tocar el compose del repo: son la
    explicación candidata de una denuncia no monótona (un checkpoint o un
    autovacuum en la ventana). compose sustituye el command entero, así que el
    override lleva el original más los dos -c. Antes de arrancar se compara con
    lo que resuelve compose: si difiere en algo más que esos dos -c, PARADA."""
    original = comando_postgres_resuelto()
    fichero = temporal / "postgres_estres.yml"
    fichero.write_text(yaml_comando(comando_con_extras(original)), encoding="utf-8", newline="\n")
    BASE.extend(["-f", str(fichero)])
    diferencias = diferencias_comando(original, comando_postgres_resuelto())
    if diferencias:
        raise Parada(f"el override de PostgreSQL cambia mas que los dos -c de logging: {diferencias}")
    p("   PostgreSQL con log_checkpoints=on y log_autovacuum_min_duration=0 (solo en el override de estres): "
      "cambia el logging del sistema medido; sus lineas entran en la tabla por ventana")


def comando_servicio_resuelto(servicio):
    """El command de `servicio` tal como lo resuelve docker compose con los
    ficheros de BASE (lista de cadenas), como comando_postgres_resuelto."""
    r = dc("config", "--format", "json", timeout=120)
    try:
        comando = json.loads(r.out)["services"][servicio]["command"]
    except (ValueError, KeyError, TypeError):
        raise Parada(f"docker compose config --format json no da el command de {servicio} (codigo {r.rc}): "
                     f"{r.err.strip()[-300:]!r}") from None
    if not isinstance(comando, list) or not all(isinstance(a, str) for a in comando):
        raise Parada(f"el command de {servicio} no es una lista de cadenas: {comando!r}")
    return comando


def comando_con_maxmemory(original, maxmemory):
    """El command de Redis con el valor de --maxmemory cambiado. Exige
    exactamente un --maxmemory con valor: si no lo hay, PARADA (el override no
    sabría qué cambiar)."""
    posiciones = [i for i, a in enumerate(original) if a == "--maxmemory"]
    if len(posiciones) != 1 or posiciones[0] + 1 >= len(original):
        raise Parada(f"el command de redis no tiene exactamente un --maxmemory con valor: {original!r}")
    nuevo = list(original)
    nuevo[posiciones[0] + 1] = maxmemory
    return nuevo


def yaml_comando_servicio(servicio, comando):
    """Override de compose con el command entero de `servicio` (como
    yaml_comando: cada elemento como cadena JSON y con $ duplicado)."""
    lineas = ["services:", f"  {servicio}:", "    command:"]
    lineas += [f"      - {json.dumps(a.replace('$', '$$'))}" for a in comando]
    return "\n".join(lineas) + "\n"


def preparar_override_redis(temporal, maxmemory=None):
    """Solo en el humo de L6 (§5.2): Redis con --maxmemory <M del humo> para que
    se llene en unos 120 s y no en una hora. Como preparar_override_postgres:
    el override lleva el command original con ese único cambio y, antes de
    arrancar, se compara con lo que resuelve compose; si difiere en algo más,
    PARADA. Sin maxmemory, el literal MAXMEMORY_HUMO."""
    maxmemory = MAXMEMORY_HUMO if maxmemory is None else maxmemory
    original = comando_servicio_resuelto("redis")
    esperado = comando_con_maxmemory(original, maxmemory)
    fichero = temporal / "redis_humo.yml"
    fichero.write_text(yaml_comando_servicio("redis", esperado), encoding="utf-8", newline="\n")
    BASE.extend(["-f", str(fichero)])
    resuelto = comando_servicio_resuelto("redis")
    if resuelto != esperado:
        raise Parada(f"el override de Redis del humo cambia mas que --maxmemory: esperado {esperado}, resuelto {resuelto}")
    p(f"   Redis con --maxmemory {maxmemory} (solo en el humo de L6)")


def comprobaciones_previas():
    if ejecutar(["docker", "info", "--format", "{{.ServerVersion}}"]).rc != 0:
        p("PARADA: docker info falla")
        terminar_con_parada()
    previos = recursos_previos()
    if previos:
        p(f"PARADA: ya existen recursos con prefijo {PROYECTO}: {previos} (restos de una ejecucion anterior)")
        terminar_con_parada()
    ocupadas = subredes_ocupadas()
    if ocupadas:
        p(f"PARADA: las subredes {', '.join(SUBREDES)} ya estan en uso por {ocupadas} "
          "(pare el proyecto canario: docker compose -p canario down, sin -v)")
        terminar_con_parada()
    ocupados = puertos_ocupados()
    if ocupados:
        p(f"PARADA: 127.0.0.1:{ocupados} ya esta en uso (pare el proyecto canario)")
        terminar_con_parada()
    r = dc("config", "--quiet")
    if r.rc != 0:
        p(f"PARADA: docker compose config falla (genere los secretos con scripts/generar_secretos.py): "
          f"{r.err.strip()[:300]}")
        terminar_con_parada()


def comprobar_literales_argon2():
    """Los parámetros de Argon2id de app/personal.py, sobre el texto (sin
    importar el módulo, que arrastraría la aplicación entera)."""
    texto = PERSONAL.read_text(encoding="utf-8")
    faltan = [patron.pattern for patron in LITERALES_ARGON2 if len(patron.findall(texto)) != 1]
    if faltan:
        raise Parada(f"app/personal.py no tiene los parametros de Argon2id esperados: {faltan}")
    pasa(True, "app/personal.py usa Argon2id m=19456 KiB, t=2, p=1, hash_len=32, salt_len=16 y "
               "HASHES_SIMULTANEOS = 2 (literales)")


def comprobar_limites_api(ident, linea=LINEA_LIMITES):
    """La línea entera de límites (por defecto, la de estrés) en el log de ESTA
    API (por id: la API se recrea entre rutas) y RestartCount 0 recién
    arrancada. L3 y L3b pasan la de producción."""
    registro = ejecutar(["docker", "logs", ident]).todo
    limites_ok = linea in [linea_log.rstrip("\r") for linea_log in registro.splitlines()]
    pasa(limites_ok, f"la API usa los limites esperados y el log lo dice con la linea entera ({linea!r})")
    if not limites_ok:
        raise Parada("la API no anuncia los limites esperados: se mediria otra configuracion")
    reinicios = ejecutar(["docker", "inspect", "--format", "{{.RestartCount}}", ident]).out.strip()
    pasa(reinicios == "0", f"la API recien arrancada tiene RestartCount 0 (vale {reinicios!r})")


def argumentos_arranque(rep, servicios=("api", "caddy")):
    """Argumentos de `docker compose` para levantar la pila de la repetición
    `rep`. Solo la repetición 1 construye. ¿Por qué? Con el almacén containerd
    de Docker Desktop, cada `up --build`, aunque salga entero de la caché,
    produce otro id de imagen (el attestation de provenance cambia el manifest
    list), y la imagen de la repetición anterior deja de estar donde la buscan
    el lector y el control (el 23/11: "No such image" al empezar la repetición
    2). Con --no-build las repeticiones 2 y siguientes reutilizan la imagen de
    la 1, y siguen siendo independientes: down -v, BD y Redis nuevos."""
    construccion = "--build" if rep == 1 else "--no-build"
    return ["up", "-d", construccion, "--wait", *servicios]


def arrancar(servicios, cpus_canario, linea=LINEA_LIMITES, rep=1):
    p(f"=== arranque de la pila ({', '.join(servicios)})")
    argumentos = argumentos_arranque(rep, servicios)
    r = dc(*argumentos, timeout=1800)
    p(f"{' '.join(argumentos)} -> codigo {r.rc}")
    if r.rc != 0:
        p(r.todo.strip()[-1500:])
        raise Parada("no arranca la pila")
    comprobar_limites_api(dc("ps", "-q", "api").out.strip(), linea)
    esperado = ",".join(str(c) for c in cpus_canario)
    vistos = {}
    # postgres y redis arrancan siempre (dependencias de la API); caddy, solo
    # si se ha pedido.
    for servicio in [s for s in SERVICIOS_PILA if s in servicios or s in ("postgres", "redis")]:
        ident = dc("ps", "-q", servicio).out.strip()
        vistos[servicio] = ejecutar(["docker", "inspect", "--format", "{{.HostConfig.CpusetCpus}}", ident]).out.strip()
    cpuset_ok = all(v == esperado for v in vistos.values())
    pasa(cpuset_ok, f"todos los contenedores de Canario estan en el cpuset {esperado} ({vistos})")
    if not cpuset_ok:
        raise Parada("el cpuset no se aplico: la medida no seria la del modelo de 2 nucleos")


# ---------------------------------------------------------------------------
# --hash
# ---------------------------------------------------------------------------
def medir_hash(salida):
    p("=== Argon2id en el contenedor de la API (un hash y 20 verify en serie)")
    r = dc("exec", "-T", "api", "python", "-I", "-c", CODIGO_HASH, timeout=600)
    try:
        datos = json.loads(r.out.strip().splitlines()[-1])
        th, verificaciones = float(datos["hash"]), [float(v) for v in datos["verify"]]
    except (ValueError, KeyError, IndexError, TypeError):
        raise Parada(f"la medida de Argon2 no dio un resultado legible (codigo {r.rc}): {r.err.strip()[-300:]!r}") \
            from None
    if len(verificaciones) != VERIFICACIONES:
        raise Parada(f"se esperaban {VERIFICACIONES} verificaciones y hay {len(verificaciones)}")
    t = statistics.median(verificaciones)
    p(f"   hash(): {th * 1000:.1f} ms")
    p(f"   verify(), {VERIFICACIONES} en serie: mediana {t * 1000:.1f} ms, minimo {min(verificaciones) * 1000:.1f} ms, "
      f"maximo {max(verificaciones) * 1000:.1f} ms")
    if not T_MINIMA <= t <= T_MAXIMA:
        sinc(f"t = {t:.4f} s fuera de lo plausible ({T_MINIMA} a {T_MAXIMA} s): revise la medida")
    p(f"   t = {t:.4f} s; 2/t = {2 / t:.2f} logins por segundo (H1, con 2 hashes simultaneos)")
    p("   escalones de login que saldrian con esta t:")
    for ruta, factores in (("login_email", FACTORES_LOGIN_EMAIL), ("login_empresa", FACTORES_LOGIN_EMPRESA)):
        p(f"   {ruta}: " + ", ".join(f"{f} x 2/t = {round(f * 2 / t, 2)}/s" for f in factores))
    p(f"   Para L1: python tests\\estres\\lanzar.py --l1 --t {t:.4f}")
    (salida / "hash.json").write_text(json.dumps({"hash_s": th, "verify_s": verificaciones, "t_s": t,
                                                  "logins_por_segundo": 2 / t}, indent=1),
                                      encoding="utf-8", newline="\n")


# ---------------------------------------------------------------------------
# --l1: escaleras y tiempo
# ---------------------------------------------------------------------------
def tramo(tasa, duracion, inicio, vus):
    """Tasa como entero por unidad de tiempo, que es lo que admite
    constant-arrival-rate (k6 reparte las iteraciones a intervalos iguales):
    una tasa con decimales va por 100 s."""
    if float(tasa).is_integer():
        rate, unidad = int(tasa), 1
    else:
        rate, unidad = round(tasa * 100), 100
    return {"rate": rate, "time_unit_s": unidad, "duracion_s": int(duracion), "inicio_s": int(inicio), "vus": int(vus)}


def escaleras(t):
    """Escalones de cada ruta: (escalón, etiqueta, tasa, duración, maxVUs)."""
    tasas = {
        "login_email": [(f"{f} x 2/t", round(f * 2 / t, 2)) for f in FACTORES_LOGIN_EMAIL],
        "login_empresa": [(f"{f} x 2/t", round(f * 2 / t, 2)) for f in FACTORES_LOGIN_EMPRESA],
        "seguimiento": [(f"{x}/s", float(x)) for x in TASAS_SEGUIMIENTO],
        "denuncia": [(f"{x}/s", float(x)) for x in TASAS_DENUNCIA],
    }
    resultado = {}
    for ruta in ORDEN_RUTAS:
        resultado[ruta] = []
        for i, (etiqueta, tasa) in enumerate(tasas[ruta], start=1):
            # Al menos 600 muestras por escalón y nunca menos de 60 s.
            duracion = max(DURACION_MINIMA_S, math.ceil(MUESTRAS_MINIMAS / tasa))
            vus = max(1, min(math.ceil(tasa * SEGUNDOS_PLAZO), TOPE_VUS))
            resultado[ruta].append({"escalon": f"e{i}", "etiqueta": etiqueta, "tasa": tasa, "duracion_s": duracion,
                                    "vus": vus})
    return resultado


def estimar_segundos(escalera):
    total = 0
    for ruta in ORDEN_RUTAS:
        pasos = escalera[ruta]
        total += CALENTAMIENTO_S + sum(e["duracion_s"] for e in pasos) + REPOSO_S * (len(pasos) - 1)
        total += SOBRECOSTE_S * len(pasos)
    return total + REPOSO_S * (len(ORDEN_RUTAS) - 1)


# ---------------------------------------------------------------------------
# --l1: captura en streaming
# ---------------------------------------------------------------------------
# Los streamers van en su propio grupo de procesos para poder pararlos con
# CTRL_BREAK sin que el Ctrl+C del lanzador los mate a medias.
CREACION = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0


def parar_proceso(proceso, plazo=10):
    """Para un proceso hijo: CTRL_BREAK (terminate fuera de Windows), espera
    con plazo y, si no basta, taskkill /T /F (el árbol entero; argumentos en
    lista). Si ni así muere, un aviso visible."""
    if proceso.poll() is not None:
        return
    try:
        if sys.platform == "win32":
            proceso.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            proceso.terminate()
        proceso.wait(timeout=plazo)
        return
    except (subprocess.TimeoutExpired, OSError, ValueError):
        pass
    if sys.platform == "win32":
        ejecutar(["taskkill", "/T", "/F", "/PID", str(proceso.pid)], timeout=60)
    else:
        proceso.kill()
    try:
        proceso.wait(timeout=plazo)
    except subprocess.TimeoutExpired:
        p(f"AVISO: el proceso {proceso.pid} no muere ni con taskkill: revise a mano")


def streamer_vivo(s):
    """Un streamer vive si su proceso no ha terminado (poll() is None) y su
    hilo lector, si lo tiene, sigue vivo."""
    return s.proceso.poll() is None and (getattr(s, "hilo", None) is None or s.hilo.is_alive())


def comprobar_vida(streamers, cuando):
    """Nombres de los streamers muertos. Que muera uno deja SIN CONCLUSION el
    tramo en que no se vigiló; se avisa en el momento."""
    muertos = [s.nombre for s in streamers if not streamer_vivo(s)]
    if muertos:
        p(f"   AVISO ({cuando}): streamers muertos: {muertos}")
    return muertos


class Registro:
    """docker compose logs -f -t de un servicio a un fichero, en streaming:
    la rotación (3 x 10 MB) y las líneas de login_fallido de una inundación
    podrían echar fuera las señales si se leyera al final. Se relanza con la
    API nueva tras cada recreación."""

    def __init__(self, servicio, destino):
        self.nombre = f"log_{servicio}"
        self.destino = destino
        self.hilo = None
        self.fichero = open(destino, "wb")  # noqa: SIM115 - se cierra en parar()
        self.proceso = subprocess.Popen(BASE + ["logs", "-f", "-t", "--no-color", "--no-log-prefix", servicio],
                                        stdout=self.fichero, stderr=subprocess.STDOUT, creationflags=CREACION)

    def parar(self):
        parar_proceso(self.proceso, 15)
        self.fichero.close()


class Estadisticas:
    """docker stats en modo continuo (no --no-stream en bucle, que mide una
    ventana distinta en cada llamada y deja huecos) a un fichero: cada línea,
    la hora del host y el JSON de un contenedor."""

    def __init__(self, contenedores, destino):
        self.nombre = "docker_stats"
        self.fichero = open(destino, "w", encoding="utf-8", newline="\n")  # noqa: SIM115 - se cierra en parar()
        self.proceso = subprocess.Popen(["docker", "stats", "--format", "{{json .}}", *contenedores],
                                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, creationflags=CREACION)
        self.hilo = threading.Thread(target=self._leer, daemon=True)
        self.hilo.start()

    def _leer(self):
        for linea in iter(self.proceso.stdout.readline, b""):
            ahora = time.time()
            # docker stats puede redibujar con secuencias de borrado de
            # pantalla: se quitan y se guarda cada objeto JSON.
            texto = PATRON_ANSI.sub("", linea.decode("utf-8", "replace"))
            for objeto in PATRON_JSON.findall(texto):
                self.fichero.write(f"{ahora:.3f}\t{objeto}\n")
            self.fichero.flush()

    def parar(self):
        parar_proceso(self.proceso, 15)
        self.hilo.join(timeout=15)
        self.fichero.close()


class EventosDocker:
    """docker events en streaming desde antes del primer control hasta después
    del último. Sin filtrar por id (cambia al recrear) ni combinar claves de
    filtro distintas (se combinan con AND): solo type=container, y se clasifica
    en Python por etiquetas. Reloj: timeNano, el de la VM. Su stderr va a un
    fichero; las líneas ilegibles se cuentan y dejan SIN CONCLUSION."""

    def __init__(self, desde, destino_err):
        self.nombre = "docker_events"
        self.eventos = []
        self.ilegibles = 0
        self.cerrojo = threading.Lock()
        self.err = open(destino_err, "wb")  # noqa: SIM115 - se cierra en parar()
        self.proceso = subprocess.Popen(["docker", "events", "--since", f"{desde:.3f}", "--filter", "type=container",
                                         "--format", "{{json .}}"],
                                        stdout=subprocess.PIPE, stderr=self.err, creationflags=CREACION)
        self.hilo = threading.Thread(target=self._leer, daemon=True)
        self.hilo.start()

    def _leer(self):
        for linea in iter(self.proceso.stdout.readline, b""):
            texto = linea.decode("utf-8", "replace").strip()
            if not texto:
                continue
            try:
                ev = parsear_evento(texto)
            except ValueError:
                with self.cerrojo:
                    self.ilegibles += 1
                continue
            if ev is not None:
                with self.cerrojo:
                    self.eventos.append(ev)

    def copia(self):
        with self.cerrojo:
            return list(self.eventos)

    def esperar(self, predicado, plazo):
        """True si en el plazo aparece un evento que cumple el predicado."""
        limite = time.time() + plazo
        while time.time() < limite:
            if any(predicado(e) for e in self.copia()):
                return True
            time.sleep(0.2)
        return any(predicado(e) for e in self.copia())

    def parar(self):
        parar_proceso(self.proceso, 15)
        self.hilo.join(timeout=15)
        self.err.close()


def guardar_eventos(destino, eventos):
    """Deja en la salida los eventos parseados de una repetición (plan v4.2,
    cambio 4): con ellos se puede saber después qué contenedor murió, con su
    nombre, su clase y su hora, cosa que la consola de L4 del 24/11 no
    permitía. Solo llevan id, acción, hora, clase, servicio, nombre y código
    (ninguna etiqueta ni variable de entorno). Si no se puede escribir, SIN
    CONCLUSION visible: la evidencia faltaría.

    No lanza nunca (enmienda v4.3, punto 2): se llama desde el finally de cada
    repetición, y una excepción aquí taparía la original (una PARADA, por
    ejemplo). Por eso captura también TypeError y ValueError, los de json.dumps."""
    try:
        destino.write_text(json.dumps(eventos, indent=1), encoding="utf-8", newline="\n")
    except (OSError, TypeError, ValueError) as e:
        sinc(f"no se pudieron guardar los eventos de docker en {destino}: {type(e).__name__}: {e}")


ENDURECIDO = ["--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--network", "none",
              "--pids-limit", "64", "--user", USUARIO_API]
numeracion_lectores = itertools.count(1)


class Lector:
    """Lector de cgroup a 4 Hz en un contenedor efímero de la imagen de la
    API (--cgroupns host, sin -v, endurecido como el control). Se relanza con
    los ids nuevos tras cada recreación de la API. Guarda las líneas que
    imprime; su stderr va a un fichero."""

    def __init__(self, imagen, objetivos, cpus, espera, destino_err):
        self.nombre = f"{PREFIJO_EFIMEROS}lector_{next(numeracion_lectores)}"
        self.objetivos = list(objetivos)
        self.inicio = None
        self.listo = False
        self.ticks = []
        self.cerrojo = threading.Lock()
        self.ruta_err = destino_err
        self.err = open(destino_err, "wb")  # noqa: SIM115 - se cierra en parar()
        pares = [f"{n}={i}" for n, i in objetivos.items()]
        self.proceso = subprocess.Popen(
            ["docker", "run", "--name", self.nombre, "--label", "canario.estres=lector", "--cgroupns", "host",
             *ENDURECIDO, "--memory", "64m", "--cpuset-cpus", cpus, "--entrypoint", "python", imagen,
             "-I", "-u", "-c", CODIGO_LECTOR, str(espera), *pares],
            stdout=subprocess.PIPE, stderr=self.err, creationflags=CREACION)
        self.hilo = threading.Thread(target=self._leer, daemon=True)
        self.hilo.start()

    def _leer(self):
        for linea in iter(self.proceso.stdout.readline, b""):
            try:
                dato = json.loads(linea)
            except ValueError:
                continue
            with self.cerrojo:
                if dato.get("tipo") == "listo":
                    self.listo = True
                elif dato.get("tipo") == "inicio":
                    self.inicio = dato
                elif dato.get("tipo") == "muestra":
                    self.ticks.append(dato)

    def esperar(self, atributo, plazo):
        limite = time.time() + plazo
        while time.time() < limite:
            with self.cerrojo:
                if getattr(self, atributo):
                    return True
            if self.proceso.poll() is not None:
                if atributo != "inicio":
                    break
                # Para "inicio", un proceso ya terminado no dará nada más:
                # esperar los 60 s enteros solo retrasa la PARADA y esconde la
                # causa. Antes de rendirse se deja que el hilo lector vacíe el
                # pipe (la línea puede estar escrita y aún sin leer).
                self.hilo.join(timeout=5)
                break
            time.sleep(0.1)
        with self.cerrojo:
            return bool(getattr(self, atributo))

    def cola_err(self, maximo=300):
        """Los últimos `maximo` caracteres del .err del lector (la causa de que
        no arranque: p. ej. "No such image"). Vacío si no se puede leer."""
        try:
            with open(self.ruta_err, "rb") as f:
                return f.read().decode("utf-8", "replace").strip()[-maximo:]
        except OSError:
            return ""

    def copia_ticks(self):
        with self.cerrojo:
            return list(self.ticks)

    def serie(self, objetivo):
        """[(t, muestra|None)] del objetivo."""
        return [(t["t"], t["c"].get(objetivo)) for t in self.copia_ticks()]

    def parar(self):
        parar_proceso(self.proceso, 15)
        self.hilo.join(timeout=15)
        self.err.close()
        ejecutar(["docker", "rm", "-f", self.nombre], timeout=120)


def leer_estadisticas(ruta):
    muestras = []
    try:
        lineas = ruta.read_text(encoding="utf-8").splitlines()
    except OSError:
        return muestras
    for linea in lineas:
        marca, _, objeto = linea.partition("\t")
        try:
            muestras.append((float(marca), json.loads(objeto)))
        except ValueError:
            continue
    return muestras


# ---------------------------------------------------------------------------
# --l1: análisis del CSV de k6
# ---------------------------------------------------------------------------
def nuevo_escenario():
    return {"peticiones": 0, "duraciones": [], "estados": collections.Counter(), "codigos_error": collections.Counter(),
            "textos_error": collections.Counter(), "protocolos": collections.Counter(), "errores": 0,
            "desde_ms": None, "hasta_ms": None, "descartadas": 0}


def analizar_csv(ruta):
    """Por escenario: peticiones (http_reqs), duraciones (http_req_duration),
    estados, errores según la sección 3 (5xx o estado 0: conexión cortada,
    fin de fichero inesperado o plazo) agrupados por error_code, protocolo,
    ventana de tiempo y descartes; y los VUs máximos (vus)."""
    escenarios = collections.defaultdict(nuevo_escenario)
    vus_maximos = 0.0
    with open(ruta, encoding="utf-8", newline="") as fichero:
        for fila in csv.DictReader(fichero):
            metrica = fila.get("metric_name")
            nombre = fila.get("scenario") or ""
            if metrica == "vus":
                vus_maximos = max(vus_maximos, float(fila["metric_value"]))
                continue
            if metrica == "dropped_iterations":
                escenarios[nombre]["descartadas"] += int(float(fila["metric_value"]))
                continue
            if metrica not in ("http_reqs", "http_req_duration"):
                continue
            e = escenarios[nombre]
            if metrica == "http_req_duration":
                e["duraciones"].append(float(fila["metric_value"]))
                continue
            marca = int(fila["timestamp"])
            e["desde_ms"] = marca if e["desde_ms"] is None else min(e["desde_ms"], marca)
            e["hasta_ms"] = marca if e["hasta_ms"] is None else max(e["hasta_ms"], marca)
            e["peticiones"] += 1
            estado_http = int(fila.get("status") or 0)
            e["estados"][estado_http] += 1
            # Las filas de estado 0 (conexión cortada, plazo) no tienen
            # protocolo: no entran en el control de protocolo y siguen
            # contando como error.
            if estado_http != 0:
                e["protocolos"][fila.get("proto") or ""] += 1
            if estado_http == 0 or 500 <= estado_http <= 599:
                e["errores"] += 1
                e["codigos_error"][fila.get("error_code") or ""] += 1
                e["textos_error"][(fila.get("error") or "")[:80]] += 1
    return escenarios, vus_maximos


def resumen_escenario(e, ruta):
    duraciones = sorted(e["duraciones"])
    no_error = e["peticiones"] - e["errores"]
    esperado = e["estados"].get(ESPERADO[ruta], 0)
    return {
        "peticiones": e["peticiones"],
        "p50_ms": percentil(duraciones, 50), "p95_ms": percentil(duraciones, 95), "p99_ms": percentil(duraciones, 99),
        "errores": e["errores"],
        "tasa_errores": e["errores"] / e["peticiones"] if e["peticiones"] else None,
        "estados": {str(k): v for k, v in sorted(e["estados"].items())},
        "proporcion_esperado": esperado / no_error if no_error else None,
        "respuestas_429": e["estados"].get(429, 0),
        "codigos_error": dict(e["codigos_error"]),
        "textos_error": dict(e["textos_error"].most_common(5)),
        "protocolos": dict(e["protocolos"]),
        "descartadas": e["descartadas"],
        "latencia_media_s": statistics.fmean(duraciones) / 1000 if duraciones else None,
        "ventana_ms": [e["desde_ms"], e["hasta_ms"]],
    }


# ---------------------------------------------------------------------------
# --l1: un escalón
# ---------------------------------------------------------------------------
def lanzar_escalon(ruta, paso, primero, control_tasa, identificador, contexto):
    """Una ejecución de k6 para un escalón. Devuelve el resultado o None si
    no se lanzó."""
    nombre = f"{ruta}__{paso['escalon']}"
    p(f"--- {nombre}: {paso['etiqueta']} = {paso['tasa']}/s durante {paso['duracion_s']} s, maxVUs {paso['vus']}")
    # La saturación de Canario (llegar a maxVUs) solo es válida si maxVUs
    # VUs dan para sostener la tasa con latencias por encima del SLO: si no,
    # se agotarían los VUs antes de que la latencia pasara del SLO y se
    # culparía a Canario de un tope del generador.
    holgura = paso["vus"] / paso["tasa"]
    if holgura <= SLO_MS[ruta] / 1000:
        sinc(f"{nombre}: maxVUs/tasa = {holgura:.2f} s no supera el p95 del SLO ({SLO_MS[ruta]} ms): no se lanza")
        return None
    inicio = CALENTAMIENTO_S if primero else 0
    datos = {
        "ruta": ruta, "escalon": paso["escalon"], "identificador": identificador, "t_s": contexto["t"],
        "calentamiento": tramo(control_tasa, CALENTAMIENTO_S, 0, max(1, min(math.ceil(control_tasa * SEGUNDOS_PLAZO),
                                                                            TOPE_VUS))) if primero else None,
        "principal": tramo(paso["tasa"], paso["duracion_s"], inicio, paso["vus"]),
        "sonda": tramo(1, paso["duracion_s"], inicio, VUS_SONDA),
        "escalones": contexto["escalera"][ruta],
    }
    (contexto["datos"] / "ejecucion.json").write_text(json.dumps(datos, indent=1), encoding="utf-8", newline="\n")
    salida = contexto["salida"] / nombre
    salida.mkdir()
    # En el espacio de red de Caddy: localhost:8443 y :8444 son Caddy, con el
    # mismo Host y SNI que desde el host, sin pasar por el proxy de puertos de
    # Docker Desktop (que se mediría también).
    k6 = ejecutar_k6(contexto, nombre, "l1.js", ["--network", f"container:{contexto['caddy']}"],
                     inicio + paso["duracion_s"], salida)
    res = analizar_escalon(ruta, paso, salida, k6["codigo"], k6["oom"], k6["registro"], k6["desfase"],
                           contexto["stats_ruta"], k6["motivo_desfase"])
    res["k6_id"] = k6["k6_id"]
    res["inicio_vm"], res["fin_vm"] = k6["inicio_vm"], k6["fin_vm"]
    # Los SIN CONCLUSION de la ejecución de k6 (A4) se fusionan en el resultado.
    res["sin_conclusion"].extend(k6["sin_conclusion"])
    return res


def ejecutar_k6(contexto, nombre, script, args_red, duracion_s, salida):
    """Una ejecución de k6 endurecida (A4). script: fichero de tests/estres
    (montado de solo lectura en /prueba); args_red: los argumentos de red de
    docker run (el espacio de red de Caddy en L1, L2 y L4; la red edge con IP
    fija en L3 y L3b); duracion_s: lo que dura el escenario más largo contando
    sus arranques con startTime; salida: carpeta de la ejecución.

    El plazo de docker wait es duracion_s + GRACEFUL_STOP_S + INICIALIZACION_S
    (J13). Devuelve un dict con el resultado de la ejecución y la LISTA de sus
    SIN CONCLUSION ("sin_conclusion"): el start y el die de k6 que no llegan al
    stream de eventos, los streamers muertos y la falta de StartedAt o
    FinishedAt. Quien llama los fusiona en su resultado."""
    contenedor = f"{PREFIJO_EFIMEROS}k6_{nombre}"
    sin_conclusion = []
    muertos_antes = comprobar_vida(contexto["vigilados"](), f"antes de {nombre}")
    desfase_inicio = medir_desfase()
    # Endurecido como el contenedor de Playwright de las funcionales: usuario
    # de la imagen, raíz de solo lectura, sin capacidades ni nuevos
    # privilegios, el script y los datos de solo lectura y solo /salida con
    # escritura. cpuset aparte del de Canario. Sin --rm: docker inspect y
    # docker logs se leen antes de borrarlo.
    r = ejecutar(["docker", "run", "-d", "--name", contenedor, "--label", "canario.estres=k6",
                  *args_red,
                  "--user", USUARIO_K6, "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                  "--pids-limit", "1024", "--memory", MEMORIA_K6, "--cpuset-cpus", contexto["cpus_k6"],
                  "--tmpfs", "/tmp:size=64m", "-e", "HOME=/tmp", "-e", "K6_NO_USAGE_REPORT=true",
                  "-e", "K6_CSV_TIME_FORMAT=unix_milli", "-e", "K6_WEB_DASHBOARD=true",
                  "-e", "K6_WEB_DASHBOARD_PORT=-1", "-e", "K6_WEB_DASHBOARD_EXPORT=/salida/panel.html",
                  "--mount", f"type=bind,src={DIR_ESTRES},dst=/prueba,readonly",
                  "--mount", f"type=bind,src={contexto['datos']},dst=/datos,readonly",
                  "--mount", f"type=bind,src={salida},dst=/salida",
                  IMG_K6, "run", "--no-usage-report", "--out", "csv=/salida/k6.csv", f"/prueba/{script}"],
                 timeout=900)
    if r.rc != 0:
        raise Parada(f"no arranca el contenedor de k6: {r.err.strip()[-500:]!r}")
    k6_id = r.out.strip()
    # docker stats usa la hora del host y k6, docker events y el lector la de
    # la VM: el desfase se mide al inicio y al final. Si no se puede medir o
    # difiere en más de 1 s, la CPU es SIN CONCLUSION (nunca se fuerza a 0).
    estadisticas = Estadisticas([contenedor], salida / "stats.txt")
    plazo = duracion_s + GRACEFUL_STOP_S + INICIALIZACION_S
    try:
        r = ejecutar(["docker", "wait", contenedor], timeout=plazo)
        codigo = int(r.out.strip()) if r.rc == 0 and r.out.strip().lstrip("-").isdigit() else None
    except subprocess.TimeoutExpired:
        ejecutar(["docker", "kill", contenedor])
        codigo = None
        p(f"   k6 supera {plazo} s: se detiene")
    finally:
        estadisticas.parar()
    desfase, motivo_desfase = desfase_valido(desfase_inicio, medir_desfase())
    registro_k6 = ejecutar(["docker", "logs", contenedor]).todo
    (salida / "k6_salida.txt").write_text(registro_k6, encoding="utf-8", newline="\n")
    estado_k6 = {}
    with contextlib.suppress(ValueError):
        estado_k6 = json.loads(ejecutar(["docker", "inspect", "--format", "{{json .State}}", contenedor]).out)
    ejecutar(["docker", "rm", "-f", contenedor])
    inicio_vm, fin_vm = a_epoch(estado_k6.get("StartedAt", "")), a_epoch(estado_k6.get("FinishedAt", ""))
    if inicio_vm is None or fin_vm is None:
        sin_conclusion.append("no se pudo leer StartedAt/FinishedAt de k6: no hay ventana del escalon")
    # Vida del detector: el start y el die de k6 deben estar en el stream (un
    # control positivo gratuito en cada ejecución) y todos los streamers vivos.
    for accion in ("start", "die"):
        if not contexto["eventos"].esperar(lambda e, a=accion: e["id"] == k6_id and e["accion"] == a, CENTINELA_S):
            sin_conclusion.append(f"el stream de docker events no trajo el {accion} de k6: el detector no vio "
                                  "la ejecucion")
    muertos = muertos_antes + comprobar_vida(contexto["vigilados"](), f"despues de {nombre}")
    if muertos:
        sin_conclusion.append(f"streamers muertos durante la ejecucion: {sorted(set(muertos))}")
    return {"k6_id": k6_id, "codigo": codigo, "oom": bool(estado_k6.get("OOMKilled")), "registro": registro_k6,
            "desfase": desfase, "motivo_desfase": motivo_desfase, "inicio_vm": inicio_vm, "fin_vm": fin_vm,
            "sin_conclusion": sin_conclusion}


def analizar_escalon(ruta, paso, salida, codigo, oom, registro_k6, desfase, stats_ruta=None, motivo_desfase=None):
    nombre = f"{ruta}__{paso['escalon']}"
    res = {"ruta": ruta, "escalon": paso["escalon"], "etiqueta": paso["etiqueta"], "tasa": paso["tasa"],
           "duracion_s": paso["duracion_s"], "max_vus": paso["vus"], "salida": str(salida), "codigo_k6": codigo,
           "k6_oom": oom, "desfase_host_vm_s": None if desfase is None else round(desfase, 3),
           "sin_conclusion": [], "cubierto": False, "motivo_cobertura": "sin analizar", "solo_memoria": False,
           "no_evaluable": False}
    if codigo != 0 or oom:
        res["sin_conclusion"].append(f"k6 termina con codigo {codigo} (OOMKilled {oom}): ver {salida / 'k6_salida.txt'}")
    csv_k6 = salida / "k6.csv"
    if not csv_k6.is_file():
        res["sin_conclusion"].append("k6 no dejo el CSV")
        res["motivos_fuera"] = ["sin CSV de k6"]
        res["fuera"] = True
        return res
    escenarios, vus_maximos = analizar_csv(csv_k6)
    res["vus_maximos_gauge"] = vus_maximos
    insuficientes = set(PATRON_INSUFICIENTES.findall(registro_k6))
    res["principal"] = resumen_escenario(escenarios[nombre], ruta)
    res["sondas"] = {s: resumen_escenario(escenarios[f"{s}__{nombre}"], s) for s in ("sonda_salud", "sonda_web")}
    pr = res["principal"]
    # VUs en uso estimados (ley de Little): tasa servida x latencia media.
    # Con preAllocatedVUs = maxVUs el gauge vus vale maxVUs desde el
    # principio y no dice cuántos se usan.
    pr["vus_en_uso_little"] = (pr["peticiones"] / paso["duracion_s"] * pr["latencia_media_s"]
                               if pr["latencia_media_s"] is not None else None)
    # Saturación de Canario: descartes con el aviso "Insufficient VUs" de
    # ese escenario (todos los VUs ocupados). Descartes sin el aviso: k6 no
    # pudo lanzar a tiempo por sí mismo, se habría medido el generador.
    res["saturado"] = pr["descartadas"] > 0 and nombre in insuficientes
    for nombre_escenario, datos in (("principal", pr), *res["sondas"].items()):
        clave = nombre if nombre_escenario == "principal" else f"{nombre_escenario}__{nombre}"
        if datos["descartadas"] > 0 and clave not in insuficientes:
            res["sin_conclusion"].append(f"{clave}: {datos['descartadas']} iteraciones descartadas sin el aviso "
                                         "de VUs insuficientes (generador)")
    # Oráculo de estado, en la ruta y en las sondas: entre las respuestas
    # que no son error, al menos el 99 % con el estado esperado, y ningún
    # 429 (se estaría midiendo el limitador).
    for nombre_escenario, datos in (("principal", pr), *res["sondas"].items()):
        clave = ruta if nombre_escenario == "principal" else nombre_escenario
        if datos["peticiones"] == 0:
            res["sin_conclusion"].append(f"{clave}: ninguna peticion en el CSV")
            continue
        if datos["proporcion_esperado"] is None:
            res["sin_conclusion"].append(f"{clave}: todas las respuestas son error, el oraculo de estado no se "
                                         "puede evaluar")
        elif datos["proporcion_esperado"] < UMBRAL_ESPERADO:
            res["sin_conclusion"].append(f"{clave}: solo el {datos['proporcion_esperado']:.2%} de las respuestas que no "
                                         f"son error tiene el estado {ESPERADO[clave]} ({datos['estados']})")
        if datos["respuestas_429"]:
            res["sin_conclusion"].append(f"{clave}: {datos['respuestas_429']} respuestas 429")
        veredicto_protocolo, texto_protocolo = evaluar_protocolo(collections.Counter(datos["protocolos"]))
        if veredicto_protocolo != "PASA":
            res["sin_conclusion"].append(f"{clave}: {texto_protocolo}")
    # Ventanas de k6 (reloj de la VM) sacadas del CSV de cada escenario: la
    # principal y, en el primer escalón de la ruta, el calentamiento.
    desde, hasta = pr["ventana_ms"]
    cal = escenarios.get(f"calentamiento__{ruta}")
    res["ventana_principal_s"] = None if desde is None else [desde / 1000, hasta / 1000]
    res["ventana_cal_s"] = (None if cal is None or cal["desde_ms"] is None
                            else [cal["desde_ms"] / 1000, cal["hasta_ms"] / 1000])
    # CPU de cada contenedor en la ventana del escalón (reloj del host).
    res["cpu"], res["blockio_postgres"] = {}, None
    if desfase is None:
        res["sin_conclusion"].append(f"CPU del escalon sin evaluar: {motivo_desfase}")
    if desde is not None and desfase is not None:
        a, b = desde / 1000 + desfase, hasta / 1000 + desfase
        por_contenedor = collections.defaultdict(list)
        bloques = []
        muestras_cpu = leer_estadisticas(salida / "stats.txt")
        if stats_ruta is not None:
            muestras_cpu += leer_estadisticas(stats_ruta)
        for marca, objeto in muestras_cpu:
            if a <= marca <= b:
                nombre_c = objeto.get("Name", "")
                valor = porcentaje(objeto.get("CPUPerc", ""))
                if valor is not None:
                    por_contenedor[nombre_c].append(valor)
                if nombre_c.endswith("-postgres-1"):
                    lectura, _, escritura = (objeto.get("BlockIO") or "").partition("/")
                    bloques.append((bytes_de(lectura), bytes_de(escritura)))
        for nombre_c, valores in por_contenedor.items():
            corto = "k6" if f"{PREFIJO_EFIMEROS}k6_" in nombre_c else nombre_c.removeprefix(f"{PROYECTO}-").removesuffix("-1")
            res["cpu"][corto] = {"media": statistics.fmean(valores), "maxima": max(valores), "muestras": len(valores)}
        validos = [x for x in bloques if None not in x]
        if len(validos) >= 2:
            res["blockio_postgres"] = {"lectura_mb": (validos[-1][0] - validos[0][0]) / 1e6,
                                       "escritura_mb": (validos[-1][1] - validos[0][1]) / 1e6}
    k6 = res["cpu"].get("k6")
    if k6 is None:
        if desfase is not None:
            res["sin_conclusion"].append("sin muestras de docker stats de k6 en la ventana: no se sabe si el "
                                         "generador se saturo")
    elif k6["maxima"] > UMBRAL_CPU_K6:
        res["sin_conclusion"].append(f"CPU de k6 {k6['maxima']:.0f} % supera el {UMBRAL_CPU_K6:.0f} % "
                                     f"(80 % de {CPUS_K6} CPU): generador saturado")
    if desfase is not None and abs(desfase) > 2:
        p(f"   AVISO: el reloj de la VM y el del host difieren {desfase:.1f} s (se corrige en la CPU por escalon)")
    # Cobertura de la puerta (QA E1): la salida dice lo que demuestra.
    res["cubierto"], res["motivo_cobertura"] = escalon_cubierto(
        pr["peticiones"], paso["tasa"], paso["duracion_s"], pr["descartadas"], nombre in insuficientes,
        None if k6 is None else k6["maxima"] > UMBRAL_CPU_K6)
    # Fuera del SLO: p95 por encima, 1 % o más de errores, o Canario saturado.
    p95, tasa_err = pr["p95_ms"], pr["tasa_errores"]
    res["motivos_fuera"] = [m for m, c in (
        (f"p95 {ms(p95)} ms > {SLO_MS[ruta]} ms", p95 is not None and p95 > SLO_MS[ruta]),
        (f"errores {tasa_err:.2%}" if tasa_err is not None else "errores", tasa_err is not None
         and tasa_err >= UMBRAL_ERRORES),
        ("saturacion (maxVUs alcanzados)", res["saturado"])) if c]
    res["fuera"] = bool(res["motivos_fuera"])
    p(f"   {pr['peticiones']} peticiones, p50/p95/p99 {ms(pr['p50_ms'])}/{ms(p95)}/{ms(pr['p99_ms'])} ms, "
      f"errores {pr['errores']}, estados {pr['estados']}, saturado {res['saturado']}, "
      f"{'FUERA: ' + '; '.join(res['motivos_fuera']) if res['fuera'] else 'dentro del SLO'}")
    for motivo in res["sin_conclusion"]:
        p(f"   motivo de SIN CONCLUSION: {motivo}")
    return res


# ---------------------------------------------------------------------------
# --l1: señales del log y tabla
# ---------------------------------------------------------------------------
def leer_log(ruta):
    """(epoch, mensaje) de cada línea de docker compose logs -t."""
    lineas = []
    try:
        texto = ruta.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return lineas
    for linea in texto.splitlines():
        encaje = PATRON_MARCA.match(linea)
        if encaje is not None:
            marca = a_epoch(f"{encaje.group(1)}.{encaje.group(2) or '0'}Z")
            lineas.append((marca, encaje.group(3)))
    return lineas


def _campo_limitador(valor, conjunto):
    """Valor de un campo del evento: SIN_DATO si la línea no lo trae, el valor
    si es del conjunto cerrado y FUERA_DE_CONJUNTO si no. Un valor ajeno o
    ausente tiene columna y dispara el AVISO del resumen (lineas_limitador)."""
    if valor is None:
        return SIN_DATO
    return valor if valor in conjunto else FUERA_DE_CONJUNTO


def parsear_limitador(mensaje):
    """(clase, causa, espera, causa_cruda, espera_cruda) de una línea del
    evento limitador_no_disponible, o None si la línea no es ese evento. Causa
    y espera ya normalizadas (conjunto cerrado, SIN_DATO o FUERA_DE_CONJUNTO);
    las crudas son lo escrito en el log (None si falta), solo para avisar."""
    encaje = PATRON_LIMITADOR.search(mensaje)
    if encaje is None:
        return None
    clase, causa, espera, sobrante = encaje.groups()
    espera_normal = _campo_limitador(espera, ESPERAS_LIMITADOR)
    if sobrante.strip():
        # Texto de más tras los campos: la línea no es la que escribe la API.
        espera_normal = FUERA_DE_CONJUNTO
        espera = f"{espera or ''}{sobrante}".strip()
    return (clase, _campo_limitador(causa, CAUSAS_LIMITADOR), espera_normal, causa, espera)


def resumir_limitador(lineas, arranques_redis):
    """Mezcla de causas del limitador en un escalón. INFORMACIÓN: no decide
    ningún veredicto (el criterio de H7 se evalúa a mano, con docs/).

    lineas: [(marca, mensaje)] de la API ya acotadas a la ventana del escalón.
    arranques_redis: marcas (reloj de la VM) de los eventos start de Redis.
    Devuelve el recuento por causa, el de espera dentro de pool_agotado (la
    espera solo se interpreta con esa causa) y el de conexion y permiso dentro
    y fuera de los VENTANA_ARRANQUE_REDIS_S s siguientes a un start de Redis
    (información que los separa; no los da por legítimos). espera_anomala
    cuenta las esperas sin dato o ajenas al conjunto de CUALQUIER causa, sin
    mezclarlas en esperas_pool (contaminaría el reparto). campos_ajenos es el
    total de campos (causa o espera) fuera del conjunto; valores_ajenos, una
    muestra de hasta 5 valores distintos."""
    causas = {c: 0 for c in (*CAUSAS_LIMITADOR, SIN_DATO, FUERA_DE_CONJUNTO)}
    espera_anomala = 0
    campos_ajenos = 0
    esperas_pool = {e: 0 for e in (*ESPERAS_LIMITADOR, SIN_DATO, FUERA_DE_CONJUNTO)}
    arranque = {"conexion": {"dentro": 0, "fuera": 0}, "permiso": {"dentro": 0, "fuera": 0}}
    crudos = set()
    total = 0
    for marca, mensaje in lineas:
        evento = parsear_limitador(mensaje)
        if evento is None:
            continue
        _, causa, espera, causa_cruda, espera_cruda = evento
        total += 1
        causas[causa] += 1
        if espera in (SIN_DATO, FUERA_DE_CONJUNTO):
            espera_anomala += 1
        if causa == "pool_agotado":
            esperas_pool[espera] += 1
        if causa in arranque:
            dentro = any(s <= marca < s + VENTANA_ARRANQUE_REDIS_S for s in arranques_redis)
            arranque[causa]["dentro" if dentro else "fuera"] += 1
        # Los valores ajenos al conjunto se muestran acotados y con repr: son
        # texto del log, no se imprimen tal cual.
        for campo, cruda, normal in (("causa", causa_cruda, causa), ("espera", espera_cruda, espera)):
            if normal == FUERA_DE_CONJUNTO:
                campos_ajenos += 1
                crudos.add(f"{campo}={cruda[:40]!r}")
    return {"total": total, "causas": causas, "esperas_pool": esperas_pool, "arranque": arranque,
            "arranques_redis": len(arranques_redis), "espera_anomala": espera_anomala,
            "campos_ajenos": campos_ajenos, "valores_ajenos": sorted(crudos)[:5]}


def arranques_redis_desde(ej, t_ini):
    """Marcas (reloj de la VM) de los eventos start de Redis desde t_ini. La
    ventana de arranque del resumen del limitador cuenta desde ellas. Pura
    salvo por la lectura de ej.eventos."""
    return [e["t"] for e in ej.eventos.copia()
            if e["t"] >= t_ini and e["clase"] == "canario" and e["servicio"] == "redis"
            and e["accion"] == "start"]


def senales_escalon(lineas_api, otras, res, arranques_redis):
    """Señales de la API en la ventana del escalón (reloj de la VM, el mismo
    de k6 y de docker logs), con la primera aparición de cada una, y las
    líneas de PostgreSQL y Redis en esa ventana. arranques_redis: marcas de
    los eventos start de Redis (sin valor por defecto: olvidarlo contaría todo
    como fuera de la ventana de arranque)."""
    desde, hasta = res.get("principal", {}).get("ventana_ms", [None, None])
    if desde is None:
        return
    a, b = desde / 1000 - 1, hasta / 1000 + 1
    senales = {nombre: {"total": 0, "clases": collections.Counter(), "primera": None} for nombre, _ in SENALES}
    for marca, mensaje in lineas_api:
        if not a <= marca <= b:
            continue
        for nombre, patron in SENALES:
            encaje = patron.search(mensaje)
            if encaje is None:
                continue
            s = senales[nombre]
            s["total"] += 1
            if patron.groups:
                s["clases"][encaje.group(1)] += 1
            if s["primera"] is None:
                s["primera"] = marca
    res["senales"] = {n: {"total": s["total"], "clases": dict(s["clases"]),
                          "primera_s": None if s["primera"] is None else round(s["primera"] - a - 1, 1)}
                      for n, s in senales.items()}
    res["limitador"] = resumir_limitador([(m, t) for m, t in lineas_api if a <= m <= b], arranques_redis)
    res["lineas_log"] = {servicio: sum(1 for marca, _ in lineas if a <= marca <= b) for servicio, lineas in otras.items()}
    # Checkpoints y autovacuum de PostgreSQL en la ventana (activados solo en
    # el override de estres): explicación candidata de una denuncia no monótona.
    res["postgres_eventos"] = {
        "checkpoints": sum(1 for marca, m in otras.get("postgres", []) if a <= marca <= b
                           and PATRON_CHECKPOINT.search(m)),
        "autovacuum": sum(1 for marca, m in otras.get("postgres", []) if a <= marca <= b
                          and PATRON_AUTOVACUUM.search(m))}


def lineas_limitador(lim):
    """Líneas legibles del resumen del limitador de un escalón (informativas;
    la primera lleva el recuento y las siguientes solo salen si hay algo que
    avisar). No es un veredicto."""
    if lim["total"] == 0:
        return ["      limitador (causa): sin eventos"]
    c, e, a = lim["causas"], lim["esperas_pool"], lim["arranque"]
    n = VENTANA_ARRANQUE_REDIS_S
    lineas = [
        f"      limitador (causa, informacion): n={lim['total']} pool_agotado={c['pool_agotado']} "
        f"plazo={c['plazo']} conexion={c['conexion']} permiso={c['permiso']} otra={c['otra']} "
        f"sin_dato={c[SIN_DATO]} fuera_de_conjunto={c[FUERA_DE_CONJUNTO]} espera_anomala={lim['espera_anomala']}; "
        f"espera de pool_agotado: "
        f"<0.25={e['<0.25']} 0.25-0.5={e['0.25-0.5']} >0.5={e['>0.5']} sin_dato={e[SIN_DATO]} "
        f"fuera_de_conjunto={e[FUERA_DE_CONJUNTO]}; conexion fuera/dentro de los {n} s tras el arranque de Redis "
        f"{a['conexion']['fuera']}/{a['conexion']['dentro']}; permiso fuera/dentro "
        f"{a['permiso']['fuera']}/{a['permiso']['dentro']}; arranques de Redis vistos {lim['arranques_redis']}"]
    # Cualquier campo ausente o fuera de su conjunto, en cualquier causa. La
    # espera anomala incluye la de pool_agotado (e[SIN_DATO], e[FUERA...]).
    if c[SIN_DATO] or c[FUERA_DE_CONJUNTO] or lim["espera_anomala"] or e[SIN_DATO] or e[FUERA_DE_CONJUNTO]:
        lineas.append(f"      AVISO limitador: lineas sin causa ({c[SIN_DATO]}), causas fuera del conjunto "
                      f"({c[FUERA_DE_CONJUNTO]}), esperas sin dato o fuera del conjunto ({lim['espera_anomala']}); "
                      f"{lim['campos_ajenos']} campos con valor ajeno, muestra {lim['valores_ajenos']}: imagen "
                      f"distinta de la esperada o log alterado")
    return lineas


def tabla(resultados):
    p("=== tabla de L1 (por escalon; latencias en ms; CPU en % de una CPU, media/maxima)")
    for ruta in ORDEN_RUTAS:
        filas = [r for r in resultados if r["ruta"] == ruta]
        p(f"--- {ruta} (SLO p95 {SLO_MS[ruta]} ms, errores < 1 %)")
        for r in filas:
            pr = r.get("principal")
            if pr is None:
                p(f"   {r['escalon']} {r['etiqueta']}: sin datos ({'; '.join(r['sin_conclusion'])})")
                continue
            p(f"   {r['escalon']} {r['etiqueta']} = {r['tasa']}/s: n={pr['peticiones']} p50={ms(pr['p50_ms'])} "
              f"p95={ms(pr['p95_ms'])} p99={ms(pr['p99_ms'])} errores={pr['errores']} "
              f"({(pr['tasa_errores'] or 0):.2%}) estados={pr['estados']} 429={pr['respuestas_429']} "
              f"{'FUERA' if r['fuera'] else 'dentro'}")
            if pr["codigos_error"]:
                p("      error_code: " + ", ".join(f"{c or 'sin codigo'} ({CODIGOS_K6.get(c, describir_codigo(c))}) x{n}"
                                              for c, n in pr["codigos_error"].items()))
                p(f"      textos de error: {pr['textos_error']}")
            p(f"      k6: maxVUs {r['max_vus']}, VUs en uso (Little) "
              f"{'-' if pr['vus_en_uso_little'] is None else round(pr['vus_en_uso_little'], 1)}, descartadas "
              f"{pr['descartadas']}, saturado {r['saturado']}")
            p("      CPU: " + ", ".join(f"{n} {c['media']:.0f}/{c['maxima']:.0f}" for n, c in sorted(r["cpu"].items())))
            if r.get("blockio_postgres"):
                b = r["blockio_postgres"]
                p(f"      BlockIO de PostgreSQL en el escalon: lectura {b['lectura_mb']:.1f} MB, escritura "
                  f"{b['escritura_mb']:.1f} MB")
            senales = r.get("senales", {})
            p("      senales: " + ", ".join(
                f"{n}={s['total']}" + (f" {s['clases']}" if s["clases"] else "") +
                (f" (primera a {s['primera_s']} s)" if s["primera_s"] is not None else "")
                for n, s in senales.items()))
            if r.get("limitador") is not None:
                for linea in lineas_limitador(r["limitador"]):
                    p(linea)
            p(f"      lineas de log en el escalon: {r.get('lineas_log', {})}; PostgreSQL: {r.get('postgres_eventos')}")
            p(f"      cobertura de la puerta: {'cubierto' if r['cubierto'] else 'NO cubierto'} ({r['motivo_cobertura']})"
              + ("; SOLO MEMORIA (no cuenta para el codo ni para H1)" if r["solo_memoria"] else "")
              + ("; NO EVALUABLE (murio un contenedor de Canario)" if r["no_evaluable"] else ""))
            for s, d in r["sondas"].items():
                slo = f" (SLO {SLO_MS[s]} ms)" if s in SLO_MS else ""
                p(f"      {s}: n={d['peticiones']} p50={ms(d['p50_ms'])} p95={ms(d['p95_ms'])}{slo} "
                  f"errores={d['errores']} estados={d['estados']}")
            for motivo in r["sin_conclusion"]:
                p(f"      SIN CONCLUSION: {motivo}")


def describir_codigo(codigo):
    if codigo.isdigit() and 1400 <= int(codigo) <= 1499:
        return f"HTTP {int(codigo) - 1000}"
    if codigo.isdigit() and 1500 <= int(codigo) <= 1599:
        return f"HTTP {int(codigo) - 1000}"
    if codigo.isdigit() and 1600 <= int(codigo) <= 1699:
        return "error HTTP/2"
    return "sin descripcion en la documentacion"


def codo_de(filas):
    """Primer escalón fuera del SLO. Los escalones solo-memoria (lanzados
    tras cortar la escalera) y los que vieron una muerte no cuentan."""
    for r in filas:
        if r.get("fuera") and not r.get("solo_memoria") and not r.get("no_evaluable"):
            return r
    return None


def hipotesis(resultados, t, muerte_en_login=False):
    """H1 y H2 (sección 3), informativas: una hipótesis refutada es un
    hallazgo, no un fallo de la prueba."""
    p("=== hipotesis (informativo: no cambia el RESULTADO GLOBAL)")
    filas = [r for r in resultados if r["ruta"] == "login_email" and "principal" in r and not r.get("solo_memoria")]
    codo = codo_de(filas)
    if muerte_en_login:
        p("   H1: NO EVALUABLE (murio un contenedor de Canario durante el login)")
    elif not filas or any(r["sin_conclusion"] or r.get("no_evaluable") for r in filas):
        p("   H1: NO EVALUABLE (falta algun escalon de login_email o alguno es SIN CONCLUSION)")
    else:
        # ±25 %: el codo cae en 1,0 o 1,25 x 2/t (se sostiene 0,75 y no 1,5).
        factor = None if codo is None else FACTORES_LOGIN_EMAIL[int(codo["escalon"][1:]) - 1]
        hashes = None if codo is None else codo.get("senales", {}).get("hashes_saturados", {}).get("total", 0)
        confirmada = factor in (1.0, 1.25) and bool(hashes)
        p(f"   H1: {'CONFIRMADA' if confirmada else 'REFUTADA'} (2/t = {2 / t:.2f}/s; codo en "
          f"{'ninguno' if codo is None else codo['etiqueta']}; EVENTO hashes_saturados en el codo: {hashes})")
    for ruta in ("seguimiento", "denuncia"):
        filas = [r for r in resultados if r["ruta"] == ruta and "principal" in r]
        codo = codo_de(filas)
        if codo is None or codo["sin_conclusion"]:
            p(f"   H2 ({ruta}): NO EVALUABLE (sin codo en la escalera o codo SIN CONCLUSION)")
            continue
        primeras = sorted((s["primera_s"], n) for n, s in codo.get("senales", {}).items()
                          if s["primera_s"] is not None and n != "login_fallido")
        primera = primeras[0][1] if primeras else None
        p(f"   H2 ({ruta}): {'CONFIRMADA' if primera == 'sin_conexion_pooltimeout' else 'REFUTADA'} (codo en "
          f"{codo['etiqueta']}; primera senal: {primera or 'ninguna en el log (cola de hilos o CPU)'}; "
          f"BlockIO de PostgreSQL: {codo.get('blockio_postgres')})")


# Columnas del CSV con la mezcla de causas del limitador (información, no
# oráculo). El orden de valores_limitador es el de esta lista.
COLUMNAS_LIMITADOR = (
    "limitador_pool_agotado", "limitador_permiso", "limitador_plazo", "limitador_conexion", "limitador_otra",
    "limitador_sin_dato", "limitador_fuera_de_conjunto", "limitador_espera_anomala",
    "pool_espera_menos_025", "pool_espera_025_a_05", "pool_espera_mas_05", "pool_espera_sin_dato",
    "pool_espera_fuera_de_conjunto",
    "conexion_fuera_arranque", "conexion_dentro_arranque", "permiso_fuera_arranque", "permiso_dentro_arranque",
    "arranques_redis_vistos")


def valores_limitador(lim):
    """Valores de COLUMNAS_LIMITADOR de un escalón; None en todas si el
    escalón no tiene resumen (res sin ventana_ms: no se lanzó), como el resto
    de columnas. Si la ventana existe pero el log no tiene eventos, salen
    ceros."""
    if lim is None:
        return [None] * len(COLUMNAS_LIMITADOR)
    c, e, a = lim["causas"], lim["esperas_pool"], lim["arranque"]
    return [c["pool_agotado"], c["permiso"], c["plazo"], c["conexion"], c["otra"], c[SIN_DATO],
            c[FUERA_DE_CONJUNTO], lim["espera_anomala"],
            e["<0.25"], e["0.25-0.5"], e[">0.5"], e[SIN_DATO], e[FUERA_DE_CONJUNTO],
            a["conexion"]["fuera"], a["conexion"]["dentro"], a["permiso"]["fuera"], a["permiso"]["dentro"],
            lim["arranques_redis"]]


def escribir_resultados(resultados, salida):
    (salida / "resultados.json").write_text(json.dumps(resultados, indent=1, default=str), encoding="utf-8",
                                            newline="\n")
    columnas = ["repeticion", "cubierto", "solo_memoria", "no_evaluable", "ruta", "escalon", "etiqueta", "tasa",
                "peticiones", "p50_ms", "p95_ms", "p99_ms", "errores",
                "tasa_errores", "respuestas_429", "saturado", "fuera", "sonda_salud_p95_ms", "sonda_web_p95_ms",
                "cpu_api_media", "cpu_postgres_media", "cpu_redis_media", "cpu_caddy_media", "cpu_k6_maxima",
                "pooltimeout", "saturacion", "hashes_saturados", "limitador_no_disponible", "error_interno",
                "login_fallido", *COLUMNAS_LIMITADOR, "sin_conclusion"]
    with open(salida / "resultados.csv", "w", encoding="utf-8", newline="") as fichero:
        escritor = csv.writer(fichero, lineterminator="\n")
        escritor.writerow(columnas)
        for r in resultados:
            pr, cpu, sen = r.get("principal", {}), r.get("cpu", {}), r.get("senales", {})
            escritor.writerow([
                r.get("repeticion"), r.get("cubierto"), r.get("solo_memoria"), r.get("no_evaluable"),
                r["ruta"], r["escalon"], r["etiqueta"], r["tasa"], pr.get("peticiones"), pr.get("p50_ms"),
                pr.get("p95_ms"), pr.get("p99_ms"), pr.get("errores"), pr.get("tasa_errores"),
                pr.get("respuestas_429"), r.get("saturado"), r.get("fuera"),
                r.get("sondas", {}).get("sonda_salud", {}).get("p95_ms"),
                r.get("sondas", {}).get("sonda_web", {}).get("p95_ms"),
                cpu.get("api", {}).get("media"), cpu.get("postgres", {}).get("media"),
                cpu.get("redis", {}).get("media"), cpu.get("caddy", {}).get("media"), cpu.get("k6", {}).get("maxima"),
                *(sen.get(n, {}).get("total") for n in ("sin_conexion_pooltimeout", "saturacion", "hashes_saturados",
                                                        "limitador_no_disponible", "error_interno", "login_fallido")),
                *valores_limitador(r.get("limitador")),
                " | ".join(r["sin_conclusion"])])


# ---------------------------------------------------------------------------
# --l1: E/S con Docker de la ejecución (controles, repeticiones y rutas). El
# análisis de lo que se recoge está en las funciones puras de arriba.
# ---------------------------------------------------------------------------
LOGIN = ("login_email", "login_empresa")


def emitir(veredicto, texto):
    """PASA, FALLA o SIN CONCLUSION con el mismo patrón que pasa y sinc."""
    if veredicto == "PASA":
        pasa(True, texto)
    elif veredicto == "FALLA":
        pasa(False, texto)
    else:
        sinc(texto)


def hora_motor_ahora():
    """Hora de la VM (docker info --format {{.SystemTime}}). Si falla o el
    formato no encaja, PARADA, nunca un 0."""
    r = ejecutar(["docker", "info", "--format", "{{.SystemTime}}"], timeout=60)
    if r.rc != 0:
        raise Parada(f"docker info no da la hora del motor (codigo {r.rc}): {r.err.strip()[-200:]!r}")
    return hora_motor(r.out)


def medir_desfase():
    """Desfase del reloj del host respecto al de la VM (el punto medio de la
    llamada menos la hora del motor), o None si no se puede medir."""
    antes = time.time()
    try:
        motor = hora_motor_ahora()
    except Parada:
        return None
    return (antes + time.time()) / 2 - motor


def ids_servicios():
    ids = {}
    for servicio in SERVICIOS_PILA:
        ident = dc("ps", "-q", servicio).out.strip()
        if not PATRON_ID_LARGO.fullmatch(ident):
            raise Parada(f"no se obtiene el id completo del contenedor de {servicio}: {ident!r}")
        ids[servicio] = ident
    return ids


PATRON_IMAGEN = re.compile(r"sha256:[0-9a-f]{64}")
SERVICIOS_IMAGEN = ("api", "caddy")


def comprobar_misma_imagen(referencia, actual, servicio, rep, *, etiqueta=None):
    """PARADA si la imagen de `servicio` en la repetición `rep` no es la de la
    repetición 1. Pura. ¿Por qué un control y no fiarse de --no-build? Porque
    todo lo que se mide (el lector, el control positivo, la API de cada ruta)
    asume que la pila es la misma en las tres repeticiones; si la imagen
    cambiara, las repeticiones no serían repeticiones. Un id vacío o que no
    sea sha256:<64 hex> (docker inspect falló) también es PARADA: un fallo
    visible, nunca una comparación de dos vacíos que daría PASA.

    Con `etiqueta`, la comparación es la de la API recreada para esa ruta o
    para ese sandwich de J5 (la `etiqueta` es el nombre de ruta o "J5"): el
    mensaje lo dice, para que la PARADA no se confunda con la del arranque de
    la repetición. El mismo `donde` sirve a los dos mensajes, y sin `etiqueta`
    son los de siempre."""
    donde = f"la repeticion {rep}" if etiqueta is None else f"la API recreada para {etiqueta} (repeticion {rep})"
    for ident in (referencia, actual):
        if not isinstance(ident, str) or not PATRON_IMAGEN.fullmatch(ident):
            raise Parada(f"no se obtiene un id de imagen sha256:<64 hex> de {servicio} en {donde}: "
                         f"{ident!r}")
    if actual != referencia:
        raise Parada(f"la imagen de {servicio} de {donde} no es la de la repeticion 1 "
                     f"({referencia} frente a {actual})")


def leer_imagen(ident, donde):
    """.Image del contenedor `ident`, o PARADA con la causa. ¿Por qué no basta
    con que comprobar_misma_imagen rechace un id vacío? Porque esa PARADA solo
    diría "id mal formado" y escondería por qué falló docker inspect: el
    código y la cola del stderr la hacen visible. El plazo de 60 s es propio:
    con el de 900 s de ejecutar, un motor colgado tendría la ejecución parada
    un cuarto de hora sin decir nada. El formato del id lo valida
    comprobar_misma_imagen, no esta función."""
    try:
        r = ejecutar(["docker", "inspect", "--format", "{{.Image}}", ident], timeout=60)
    except subprocess.TimeoutExpired:
        raise Parada(f"docker inspect de {donde} no responde en 60 s") from None
    if r.rc != 0:
        raise Parada(f"docker inspect de {donde} falla (codigo {r.rc}): {r.err.strip()[-300:]!r}")
    return r.out.strip()


def comprobar_imagenes(ej, rep):
    """Lee el .Image de los contenedores de api y caddy. En la repetición 1 se
    guardan como referencia (ej.imagenes) y ej.imagen, la de la API que usan el
    lector, el control, el cliente de control y la sonda de descartes, se fija
    una sola vez. En las siguientes se comparan con la referencia, ANTES de
    lanzar ningún lector."""
    actuales = {s: leer_imagen(ej.ids[s], f"{s} en la repeticion {rep}") for s in SERVICIOS_IMAGEN}
    if rep == 1:
        for s in SERVICIOS_IMAGEN:
            # Con la propia lectura como referencia solo se valida el formato.
            comprobar_misma_imagen(actuales[s], actuales[s], s, rep)
        ej.imagenes = actuales
        ej.imagen = actuales["api"]
        p(f"   repeticion 1: imagenes de referencia, api {actuales['api']} y caddy {actuales['caddy']}")
        return
    if ej.imagenes is None:
        raise Parada(f"la repeticion {rep} empieza sin la imagen de referencia de la repeticion 1")
    for s in SERVICIOS_IMAGEN:
        comprobar_misma_imagen(ej.imagenes[s], actuales[s], s, rep)
    pasa(True, f"repeticion {rep}: misma imagen que la repeticion 1 en api ({actuales['api']}) y caddy "
               f"({actuales['caddy']})")


def preparar_repeticion(ej, rep):
    """Todo lo previo al alta de la empresa: down -v (desde la 2), arranque,
    ids, comprobación de imágenes y control positivo inicial. El control
    inicial se hace solo en la repetición 1 (rep == 1 explícito, no "ej.imagen
    es None"): la imagen es la misma en todas por la comprobación de imágenes.
    La usan ejecutar_repeticion (L1) y la rama de pila nueva de
    ejecutar_repeticion_fases (L2, pico y la repetición 1 de L3 y L3b)."""
    if rep > 1:
        bajar_pila(ej)
    arrancar(("api", "caddy"), ej.cpus_canario, ej.linea_limites, rep)
    ej.ids = ids_servicios()
    comprobar_imagenes(ej, rep)
    comprobar_postgres_args(ej)
    if rep == 1 and not ejecutar_control(ej, "inicial"):
        raise Parada("el control positivo inicial no se ve completo: el detector no es de fiar")


def contenedores_conocidos():
    """{id: {"nombre", "etiquetas"}} de todos los contenedores del motor."""
    r = ejecutar(["docker", "ps", "-a", "--no-trunc", "--format", "{{json .}}"], timeout=120)
    conocidos = {}
    for linea in r.out.splitlines():
        try:
            c = json.loads(linea)
            conocidos[c["ID"]] = {"nombre": c["Names"], "etiquetas": etiquetas_de(c.get("Labels", ""))}
        except (ValueError, KeyError):
            continue
    return conocidos


def limpiar_efimeros():
    """Borra los contenedores efímeros del lanzador (prefijo canario_estres_:
    k6, lectores y control). Los de compose llevan un guion, no un guion bajo."""
    for nombre in ejecutar(["docker", "ps", "-a", "--format", "{{.Names}}"]).out.split():
        if nombre.startswith(PREFIJO_EFIMEROS):
            ejecutar(["docker", "rm", "-f", nombre], timeout=120)


class Ejecucion:
    """Estado compartido de una ejecución de --l1."""

    def __init__(self, t, datos, salida, cpus_canario, cpus_k6, escalera, linea_limites=LINEA_LIMITES):
        self.t, self.datos, self.salida, self.escalera = t, datos, salida, escalera
        # La línea literal de límites vive aquí (A4): arrancar y recrear_api la usan.
        self.linea_limites = linea_limites
        self.cpus_canario = cpus_canario
        self.cpus_k6 = ",".join(str(c) for c in cpus_k6)
        self.eventos = None
        self.mantenimientos = []
        self.ids = {}
        self.imagen = None  # .Image de la API (la misma en todas las repeticiones)
        self.imagenes = None  # {servicio: .Image} de la repetición 1, para compararlas
        self.identificador = None
        self.reinicios = {}
        self.todos = []


def registrar_reinicios(ej):
    """RestartCount de los 4 contenedores actuales (para la conciliación)."""
    for ident in ej.ids.values():
        r = ejecutar(["docker", "inspect", "--format", "{{.RestartCount}}", ident]).out.strip()
        if not r.isdigit():
            raise Parada(f"no se lee RestartCount de {ident[:12]}: {r!r}")
        ej.reinicios[ident] = int(r)


def comprobar_postgres_args(ej):
    """Los dos -c de logging llegaron a PostgreSQL (un parámetro no válido
    impediría arrancar), vistos en docker inspect, sin docker exec."""
    r = ejecutar(["docker", "inspect", "--format", "{{json .Args}}", ej.ids["postgres"]])
    try:
        args = json.loads(r.out)
    except ValueError:
        raise Parada(f"no se leen los Args del contenedor de PostgreSQL: {r.out.strip()[:200]!r}") from None
    ok = args_incluyen(args, EXTRAS_POSTGRES)
    pasa(ok, f"PostgreSQL arranca con {' '.join(EXTRAS_POSTGRES)} (docker inspect, Args)")
    if not ok:
        raise Parada("el override de logging de PostgreSQL no llego al contenedor")


def bajar_pila(ej):
    """down -v de la repetición anterior: el mantenimiento esperado son todos
    los ids del proyecto, hasta su destroy."""
    ids = frozenset(ejecutar(["docker", "ps", "-a", "--no-trunc", "--filter",
                              f"label=com.docker.compose.project={PROYECTO}", "--format", "{{.ID}}"]).out.split())
    mantenimiento = {"ids": ids, "desde": hora_motor_ahora(), "hasta": None, "motivo": "down -v entre repeticiones"}
    ej.mantenimientos.append(mantenimiento)
    r = dc("down", "-v", timeout=900)
    mantenimiento["hasta"] = hora_motor_ahora()
    p(f"down -v entre repeticiones -> codigo {r.rc}")
    if r.rc != 0:
        raise Parada(f"down -v falla: {r.todo.strip()[-300:]!r}")


# Plazos de recrear_api. MARGEN_RECREAR_API_S es el del subprocess (lo que el
# lanzador espera a `docker compose up` entera) y ESPERA_SALUD_RECREAR_S es el
# --wait-timeout de compose. ¿Por qué 30 s de diferencia? --wait-timeout solo
# cronometra la espera de salud (compose v5.1.4, pkg/compose/start.go): no
# cubre el stop de la API vieja (10 s por defecto, sin stop_grace_period) ni el
# borrado de la vieja y la creación y arranque de la nueva (unos 20 s, que
# compose no cronometra). Sin esa holgura, el plazo del subprocess vencería
# antes que el de compose y la causa sería un TimeoutExpired mudo en vez de un
# error de compose con su texto. Las dos cifras salen de una estimación (de 15 a
# 25 s en total, sin medir): la línea `recrear_api:` que imprime la función las
# contrasta con la medida real.
MARGEN_RECREAR_API_S = 120
ESPERA_SALUD_RECREAR_S = 90


def argumentos_recreacion():
    """Argumentos de `docker compose` para recrear la API entre rutas. Pura.
    ¿Por qué --no-build? El servicio api tiene `build:` sin `image:` ni
    `pull_policy`, y sin --no-build compose construye si falta la imagen: la
    API de la ruta podría ser otra imagen que la medida en la repetición 1.
    Con --no-build, si falta, el up falla y hay PARADA visible. ¿Por qué
    --wait-timeout? Sin él, la espera de salud de compose no tiene más tope que
    el plazo del subprocess y un healthcheck que nunca llega daría un
    TimeoutExpired sin causa."""
    return ["up", "-d", "--force-recreate", "--no-deps", "--no-build", "--wait",
            "--wait-timeout", str(ESPERA_SALUD_RECREAR_S), "api"]


def recrear_api(ej, rep, *, etiqueta):
    """API nueva entre rutas o dentro del sandwich de J5 (cada ruta parte de
    una API recién arrancada). `etiqueta` es el nombre de la ruta o "J5": solo
    sirve para que los textos digan para qué se recrea, y va como argumento
    con nombre para que una llamada vieja con dos o tres posicionales falle en
    vez de mezclar los argumentos en silencio. El die del id viejo es esperado;
    PostgreSQL, Redis y Caddy no deben cambiar de id (k6 usa el espacio de red
    de Caddy por id). La imagen de la API recreada se compara con la de la
    repetición 1, antes de lanzar el lector de la ruta."""
    # Sin la referencia no hay con qué comparar: PARADA antes de abrir la
    # ventana de mantenimiento, para no dejar una ventana sin recreación.
    if ej.imagenes is None:
        raise Parada("la API se recrea sin la imagen de referencia de la repeticion 1")
    viejo = ej.ids["api"]
    mantenimiento = {"ids": frozenset([viejo]), "desde": hora_motor_ahora(), "hasta": None,
                     "motivo": "recreacion de la API"}
    ej.mantenimientos.append(mantenimiento)
    argumentos = argumentos_recreacion()
    # El try/finally envuelve SOLO a dc: la medida se imprime también si vence el
    # plazo o si el código no es 0, y antes de la PARADA, que imprime quien la
    # recoge. Dentro del finally no se llama a hora_motor_ahora (podría colgarse
    # y esconder la causa). Si vence el plazo, "hasta" queda en None: la
    # ejecución termina con PARADA y no hay veredicto que ese hueco pueda falsear.
    inicio = time.monotonic()
    try:
        r = dc(*argumentos, timeout=MARGEN_RECREAR_API_S)
    except subprocess.TimeoutExpired:
        raise Parada(f"la API no se recrea en {MARGEN_RECREAR_API_S} s (plazo del lanzador)") from None
    finally:
        p(f"recrear_api: {time.monotonic() - inicio:.1f} s (plazo {MARGEN_RECREAR_API_S} s, "
          f"espera de salud {ESPERA_SALUD_RECREAR_S} s)")
    mantenimiento["hasta"] = hora_motor_ahora()
    p(f"{' '.join(argumentos)} -> codigo {r.rc}")
    if r.rc != 0:
        raise Parada(f"no se recrea la API: {r.todo.strip()[-500:]!r}")
    nuevos = ids_servicios()
    for servicio in ("postgres", "redis", "caddy"):
        if nuevos[servicio] != ej.ids[servicio]:
            raise Parada(f"el id de {servicio} cambio al recrear la API: la medida ya no es de la misma pila")
    if nuevos["api"] == viejo:
        raise Parada("la API recreada conserva el id: no se recreo")
    # Antes de leer la imagen: si después hay PARADA, el estado refleja el
    # contenedor que existe de verdad, no el que ya se destruyó.
    ej.ids = nuevos
    # Siempre contra la referencia de la repetición 1, nunca contra la API
    # anterior: comparar en cadena dejaría pasar una deriva ya aceptada.
    actual = leer_imagen(nuevos["api"], f"la API recreada para {etiqueta} (repeticion {rep})")
    comprobar_misma_imagen(ej.imagenes["api"], actual, "api", rep, etiqueta=etiqueta)
    pasa(True, f"repeticion {rep}, {etiqueta}: la API recreada tiene la imagen de la repeticion 1 ({actual})")
    comprobar_limites_api(nuevos["api"], ej.linea_limites)


def mensaje_lector_sin_inicio(returncode, cola):
    """Texto de la PARADA cuando el lector no da su línea de inicio. Pura:
    `returncode` es el del proceso (None si sigue vivo) y `cola` el final de su
    .err."""
    estado = "el proceso sigue en marcha" if returncode is None else f"codigo de salida {returncode}"
    return f"el lector de cgroup no da su linea de inicio ({estado}; cola del .err: {cola!r})"


def iniciar_lector(ej, nombre):
    """Lector de los 4 servicios y del padre con los ids actuales."""
    objetivos = {s: ej.ids[s] for s in SERVICIOS_PILA}
    lector = Lector(ej.imagen, objetivos, ej.cpus_k6, 10, ej.salida / f"lector_{nombre}.err")
    try:
        if not lector.esperar("inicio", 60):
            # La PARADA da la causa: sin el código de salida ni el .err solo se
            # sabría "no arranca", y la imagen que falta pasó por 60 s de espera.
            raise Parada(mensaje_lector_sin_inicio(lector.proceso.poll(), lector.cola_err()))
        problemas = problemas_inicio(lector.inicio, list(objetivos))
        if problemas:
            raise Parada("el lector no ve lo que debe: " + "; ".join(problemas))
        ajenos = hijos_ajenos(lector.inicio["hijos"], contenedores_conocidos(), lector.inicio.get("procesos"))
        if ajenos:
            raise Parada(f"el cgroup padre tiene hijos que no son del proyecto ni de la prueba: {ajenos} (otro "
                         "contenedor del motor sumaria en sus contadores)")
        if not lector.esperar("ticks", 10):
            raise Parada("el lector no da muestras")
    except BaseException:
        lector.parar()
        raise
    p(f"   lector {lector.nombre}: cgroups {lector.inicio['rutas']}; limites de la API "
      f"{lector.inicio['limites'].get('api')}")
    base = lector.copia_ticks()[0]["c"].get("api")
    if base is not None:
        p(f"   memoria base de la API: {memoria_puerta(base) / 1048576:.1f} MiB (anon + swap - swapcached)")
    return lector


def ejecutar_control(ej, etapa):
    """Control positivo en sándwich: un contenedor de la imagen de la API que
    reserva memoria hasta morir por OOM, con reinicio on-failure:1. Debe verse
    por el detector (stream de eventos y lector de cgroup). True si se ve
    completo; si no, False y el que llama decide (PARADA al principio, SIN
    CONCLUSION al final). El centinela (su start en el stream) debe llegar en
    10 s, o PARADA."""
    p(f"=== control positivo {etapa}")
    nombre = f"{PREFIJO_EFIMEROS}control"
    ejecutar(["docker", "rm", "-f", nombre])
    r = ejecutar(["docker", "create", "--name", nombre, "--label", "canario.estres=control", "--restart",
                  "on-failure:1", "--memory", "64m", "--memory-swap", "128m", *ENDURECIDO, "--cpuset-cpus",
                  ej.cpus_k6, "--entrypoint", "python", ej.imagen, "-I", "-u", "-c", CODIGO_CONTROL])
    if r.rc != 0:
        raise Parada(f"no se crea el contenedor de control: {r.err.strip()[-300:]!r}")
    ident = r.out.strip()
    lector = Lector(ej.imagen, {"control": ident}, ej.cpus_k6, 10, ej.salida / f"lector_control_{etapa}.err")
    try:
        # El lector arranca ANTES: ve crecer la memoria desde el principio.
        if not lector.esperar("listo", 60):
            raise Parada("el lector del control no arranca")
        r = ejecutar(["docker", "start", ident])
        if r.rc != 0:
            raise Parada(f"no arranca el control: {r.err.strip()[-300:]!r}")
        if not ej.eventos.esperar(lambda e: e["id"] == ident and e["accion"] == "start", CENTINELA_S):
            raise Parada(f"el centinela (start del control) no llega al stream de eventos en {CENTINELA_S} s")
        terminado = False
        limite = time.time() + 120
        while time.time() < limite:
            estado_c = ejecutar(["docker", "inspect", "--format", "{{.State.Status}} {{.RestartCount}}",
                                 ident]).out.split()
            if estado_c == ["exited", "1"]:
                terminado = True
                break
            time.sleep(1)
        time.sleep(3)  # los eventos llegan por el socket con algo de retraso
    finally:
        lector.parar()
        ejecutar(["docker", "rm", "-f", nombre])
    if not terminado:
        p("   el control no llego a morir dos veces en 120 s")
        return False
    eventos = [e for e in ej.eventos.copia() if e["id"] == ident]
    muestras, encarnaciones = etiquetar_cgroup(lector.serie("control"))
    limites = (lector.inicio or {}).get("limites", {}).get("control", {})
    # El lector del control ya muestrea el padre en cada tick (su primera
    # muestra sale tras el docker start, pero antes del primer OOM: la
    # reserva tarda más de 1 s en llegar al límite).
    serie_padre = [(tk["t"], None if tk["padre"] is None else tk["padre"][0]) for tk in lector.copia_ticks()]
    validas = [t for t, v in serie_padre if v is not None]
    subidas_padre = delta_serie(serie_padre, validas[0], validas[-1]) if validas else 0
    comprobaciones = evaluar_control(encarnaciones, muestras, eventos, limites, subidas_padre)
    for ok, texto in comprobaciones:
        p(("   PASA  " if ok else "   FALLA ") + texto)
    return all(ok for ok, _ in comprobaciones)


def ejecutar_ruta(ej, rep, ruta, n_ruta, ultima, contexto_rep):
    """Una ruta: API recién arrancada, lector, stats y log de la API que cubren
    la ruta entera (calentamiento y reposos incluidos), y sus escalones."""
    pasos = ej.escalera[ruta]
    if n_ruta:
        recrear_api(ej, rep, etiqueta=ruta)
    p(f"=== repeticion {rep}, {ruta}")
    salida_rep = contexto_rep["salida"]
    with contextlib.ExitStack() as pila:
        lector = iniciar_lector(ej, f"rep{rep}_{ruta}")
        pila.callback(lector.parar)
        stats_ruta = salida_rep / f"stats_{ruta}.txt"
        estadisticas = Estadisticas(list(ej.ids.values()), stats_ruta)
        pila.callback(estadisticas.parar)
        registro_api = Registro("api", salida_rep / f"log_{ruta}_api.txt")
        pila.callback(registro_api.parar)
        contexto = {**contexto_rep, "stats_ruta": stats_ruta, "eventos": ej.eventos,
                    "vigilados": lambda: [ej.eventos, lector, estadisticas, registro_api, *contexto_rep["registros"]]}
        resultados, seguidos, corte = [], 0, False
        login = ruta in LOGIN
        for i, paso in enumerate(pasos):
            if i:
                time.sleep(REPOSO_S)
            res = lanzar_escalon(ruta, paso, i == 0, pasos[0]["tasa"], ej.identificador, contexto)
            if res is None:
                res = {"ruta": ruta, "escalon": paso["escalon"], "etiqueta": paso["etiqueta"], "tasa": paso["tasa"],
                       "fuera": False, "cubierto": False, "solo_memoria": corte, "no_evaluable": False,
                       "motivo_cobertura": "no se lanzo", "sin_conclusion": ["maxVUs/tasa no supera el p95 del "
                                                                              "SLO: no se lanzo"]}
            res["repeticion"] = rep
            resultados.append(res)
            ej.todos.append(res)
            if res.get("principal") is None or corte:
                res["solo_memoria"] = corte
                continue
            if i == 0 and (res["fuera"] or res["sin_conclusion"]):
                # Control positivo: la tasa más baja cumple el SLO. Si no, la
                # pila de prueba está mal y el resto no significa nada para
                # la latencia (en el login, los escalones que quedan se
                # lanzan igual, solo para la memoria de la puerta).
                res["sin_conclusion"].append("el escalon de control no cumple el SLO o no es valido")
                p(f"   el escalon de control de {ruta} falla: no se sigue con esta ruta")
                if not login:
                    break
                corte = True
                p("   los escalones que quedan se lanzan igual, marcados solo memoria")
                continue
            seguidos = seguidos + 1 if res["fuera"] else 0
            if seguidos >= CORTE and i + 1 < len(pasos):
                p(f"   {CORTE} escalones seguidos fuera del SLO: se corta la escalera de {ruta}")
                if not login:
                    break
                corte = True
                p("   los escalones que quedan se lanzan igual, marcados solo memoria")
        time.sleep(3)
        if not ultima:
            # Reposo del último escalón con el lector vivo (su mínimo decide
            # si hace falta el margen de Argon2).
            time.sleep(REPOSO_S)
        # Orden fijo: la hora del fin del reposo se toma justo tras el sleep
        # (es el fin de la ventana, no la última muestra, que podría ser de un
        # lector cortado); luego se comprueba que la vigilancia siguió viva
        # durante el reposo (si el lector murió, sus muestras no cubren el
        # final) y solo después se copian los ticks.
        fin_reposo_vm = hora_motor_ahora()
        muertos_al_final = comprobar_vida(contexto["vigilados"](), f"reposo final de {ruta}")
        lector_vivo_al_final = streamer_vivo(lector)
        registrar_reinicios(ej)
        ticks = lector.copia_ticks()
    return {"ruta": ruta, "resultados": resultados, "ticks": ticks, "fin_reposo_vm": fin_reposo_vm,
            "lector_vivo_al_final": lector_vivo_al_final, "muertos_al_final": muertos_al_final}


def evaluar_repeticion(ej, rep, rutas, t_ini, muerte_en_login):
    """Veredictos de una repetición. Devuelve {"max_memoria", "muertes"}."""
    p(f"=== puerta de R1, repeticion {rep}")
    eventos = [e for e in ej.eventos.copia() if e["t"] >= t_ini]
    ticks = sorted((tk for r in rutas for tk in r["ticks"]), key=lambda tk: tk["t"])
    resultados = [res for r in rutas for res in r["resultados"]]
    lanzados = [res for res in resultados if res.get("inicio_vm") and res.get("fin_vm")]
    pasos = [{"nombre": f"{res['ruta']}__{res['escalon']}", "desde": res["inicio_vm"], "hasta": res["fin_vm"],
              "cal_hasta": (res.get("ventana_cal_s") or [None, None])[1]} for res in lanzados]
    ventanas = construir_ventanas(pasos, [m for m in ej.mantenimientos if m["desde"] >= t_ini])
    por_nombre = {f"{res['ruta']}__{res['escalon']}": res for res in lanzados}
    # --- muertes: 0 reinicios en toda la repetición, no solo en los escalones
    muertes = muertes_no_esperadas(eventos, ej.mantenimientos)
    k6_ids = {res["k6_id"] for res in lanzados if res.get("k6_id")}
    if not muertes:
        pasa(True, f"repeticion {rep}: 0 die no esperados de contenedores de Canario en toda la repeticion")
    for ev in muertes:
        a, b = ev["t"] - VENTANA_MUERTE_S, ev["t"] + VENTANA_MUERTE_S
        d_oom = delta_serie([(tk["t"], None if tk["padre"] is None else tk["padre"][0]) for tk in ticks], a, b)
        d_kill = delta_serie([(tk["t"], None if tk["padre"] is None else tk["padre"][1]) for tk in ticks], a, b)
        sube_k6 = any(delta_serie([(tk["t"], next((v[0] for h, v in tk["hijos"].items() if k6 in h), None))
                                  for tk in ticks], a, b) > 0 for k6 in k6_ids)
        veredicto, causa = veredicto_muerte(d_oom > 0, d_kill > 0, otro_murio(eventos, ev["id"], a, b,
                                                                           ej.mantenimientos), sube_k6)
        ventana = ventana_atribuida(ev["t"], ventanas) or "fuera de toda ventana"
        # Nombre y clase en la línea (plan v4.2, cambio 4): el die de la consola de
        # L4 del 24/11 no permitía saber qué contenedor era.
        emitir(veredicto, f"repeticion {rep}: murio {ev['servicio']} ({ev['nombre']}, clase {ev['clase']}, "
                          f"{ev['id'][:12]}, codigo {ev['codigo']}) en {ventana}: {causa} (padre: oom +{d_oom}, "
                          f"oom_kill +{d_kill})")
        escalon = por_nombre.get(ventana.split(" (")[0])
        if escalon is not None:
            escalon["no_evaluable"] = True
            muerte_en_login = muerte_en_login or escalon["ruta"] in LOGIN
            p(f"   {ventana}: latencias y codo NO EVALUABLE por la muerte")
    # --- instrumentos propios con una clase que el lanzador no sabe tratar: los
    # filtros de arriba solo miran "canario" y los ignorarían en silencio.
    desconocidos = instrumentos_desconocidos(eventos)
    if desconocidos:
        sinc(f"repeticion {rep}: eventos de contenedores con un valor desconocido de canario.estres: {desconocidos}")
    # --- cgroups por servicio, encarnaciones y huecos
    series = {s: [(tk["t"], tk["c"].get(s)) for tk in ticks] for s in SERVICIOS_PILA}
    etiquetados = {s: etiquetar_cgroup(series[s]) for s in SERVICIOS_PILA}
    muestras_api = etiquetados["api"][0]
    huecos = []
    for r in rutas:
        for s in SERVICIOS_PILA:
            huecos += huecos_de_serie([(tk["t"], tk["c"].get(s)) for tk in r["ticks"]])
    sin_explicar = huecos_no_explicados(huecos, [e["t"] for e in eventos
                                                 if e["clase"] == "canario" and e["accion"] == "die"])
    if sin_explicar:
        sinc(f"repeticion {rep}: {len(sin_explicar)} huecos del lector de mas de {HUECO_MAXIMO_S} s fuera de una "
             f"muerte registrada: la puerta no vio ese tramo ({sin_explicar[:3]})")
    else:
        pasa(True, f"repeticion {rep}: el lector no tiene huecos de mas de {HUECO_MAXIMO_S} s sin explicar")
    # Un streamer muerto en el reposo final de una ruta deja ese tramo sin
    # vigilar (los escalones ya lo comprueban antes y después de k6; el reposo
    # final no tenía comprobación propia).
    for r in rutas:
        if r["muertos_al_final"]:
            sinc(f"repeticion {rep}, {r['ruta']}: streamers muertos en el reposo final: "
                 f"{sorted(set(r['muertos_al_final']))}")
    # --- memoria de los escalones de login cubiertos y de su calentamiento
    maximos = []
    p("   supuesto: lo unico que vive menos de 250 ms (el periodo del lector) son las reservas de 19 MiB de "
      "Argon2; por eso el margen de 2 x 19456 KiB, cuando aplica, no se presenta como garantia")
    for r in rutas:
        for i, res in enumerate(r["resultados"]):
            if res["ruta"] not in LOGIN or res.get("principal") is None or not res.get("inicio_vm"):
                continue
            nombre = f"{res['ruta']}__{res['escalon']}"
            if res["no_evaluable"]:
                p(f"   {nombre}: sin veredicto de memoria (murio un contenedor, ya es FALLA o SIN CONCLUSION arriba)")
                continue
            for etiqueta, ventana in (("calentamiento", res.get("ventana_cal_s")),
                                      ("escalon", res.get("ventana_principal_s"))):
                if ventana is None:
                    continue
                maximo = maximo_memoria(muestras_api, *ventana)
                if maximo is None:
                    minimo, motivo = None, "sin muestras del escalon"
                elif etiqueta == "calentamiento":
                    # Al calentamiento le sigue el escalón sin pausa: no tiene
                    # reposo y el margen se aplica por defecto.
                    minimo, motivo = None, "al calentamiento le sigue el escalon"
                else:
                    minimo, motivo = reposo_de_escalon(muestras_api, res, siguiente_lanzado(r["resultados"], i), r,
                                                       maximo[1])
                veredicto, texto, nota = veredicto_escalon_memoria(None if maximo is None else maximo[0], minimo,
                                                                   motivo)
                linea = f"repeticion {rep}, {nombre} ({etiqueta}): memoria {texto}; {nota}"
                if res["cubierto"]:
                    emitir(veredicto, linea)
                    if maximo is not None:
                        maximos.append(maximo[0])
                else:
                    p(f"   informativo (escalon no cubierto: {res['motivo_cobertura']}): {linea}")
    # --- cobertura de 1,5 x 2/t de login_email
    tope = [res for res in resultados if res["ruta"] == "login_email" and res["escalon"] == "e5"]
    if tope and tope[0]["cubierto"] and not tope[0]["no_evaluable"]:
        pasa(True, f"repeticion {rep}: la puerta cubre login_email 1,5 x 2/t ({tope[0]['motivo_cobertura']}): demuestra "
                   "hasta 600 peticiones de login en vuelo ofrecidas a 1,5 x 2/t, no que se sostenga esa tasa")
    else:
        sinc(f"repeticion {rep}: la puerta no cubre login_email 1,5 x 2/t ("
             f"{'no se lanzo' if not tope else tope[0]['motivo_cobertura']})")
    # --- información: memory.peak y memory.swap.peak por ruta (no son oráculo)
    for r in rutas:
        picos = [tk["c"]["api"] for tk in r["ticks"] if tk["c"].get("api")]
        pico = max((m["pico"] for m in picos if m["pico"] is not None), default=None)
        pico_swap = max((m["swap_pico"] for m in picos if m["swap_pico"] is not None), default=None)
        p(f"   {r['ruta']}: memory.peak {pico}, memory.swap.peak "
          f"{pico_swap if pico_swap is not None else 'no existe: sin cota medida'} (informacion: incluyen cache "
          "de paginas y kernel; tras un OOM solo cubren la ultima encarnacion). Veredicto: PASA por muestreo a 4 Hz")
    # --- conciliación del detector
    ids_rep = {e["id"] for e in eventos if e["clase"] == "canario" and e["accion"] == "start"}
    problemas = conciliar(sum(1 for e in eventos if e["clase"] == "canario" and e["accion"] == "oom"),
                          sum(acumulado_contadores(etiquetados[s][1])["oom"] for s in SERVICIOS_PILA),
                          starts_no_esperados(eventos), sum(ej.reinicios.get(i, 0) for i in ids_rep))
    if problemas:
        sinc(f"repeticion {rep}: el detector no concilia: {'; '.join(problemas)}")
    else:
        pasa(True, f"repeticion {rep}: el detector concilia (start no esperados = RestartCount; oom en el stream >= "
                   "incrementos de oom)")
    return {"max_memoria": peor_caso(maximos), "muertes": len(muertes), "muerte_en_login": muerte_en_login}


def ejecutar_repeticion(ej, rep, n_reps):
    # Enmienda v4.4: precondición explícita. El finally de abajo lee ej.eventos.copia();
    # si ej.eventos faltara (Ejecucion nace con None), el AttributeError taparía la
    # excepción original. Se comprueba aquí, antes de cualquier efecto (sin carpeta,
    # sin Docker y sin hora_motor_ahora), con un fallo visible que dice quién lo crea.
    if ej.eventos is None:
        raise RuntimeError("ejecutar_repeticion: ej.eventos sin iniciar: lo crean ejecutar_l1 y ejecutar_modo antes "
                           "de la primera repetición")
    salida_rep = ej.salida / f"rep{rep}"
    salida_rep.mkdir()
    t_ini = hora_motor_ahora()
    # Enmienda v4.3, punto 2: los eventos de la repetición se guardan en el finally,
    # también si una PARADA o una excepción corta la repetición antes del análisis
    # (es justo lo que se quiere diagnosticar). El try empieza después de la
    # primera t_ini: si empezara antes, una PARADA de hora_motor_ahora dejaría t_ini
    # sin definir y el NameError del finally la taparía. guardar_eventos no lanza.
    try:
        preparar_repeticion(ej, rep)
        r = dc("run", "--rm", "-T", "gestion", "alta-empresa", "--nombre", "Empresa estres", "--zona", "Europe/Madrid")
        alta = PATRON_ALTA.search(r.out)
        if r.rc != 0 or alta is None:
            raise Parada(f"no se pudo dar de alta la empresa de prueba: {r.err.strip()[-300:]!r}")
        ej.identificador = alta.group(2)
        p(f"   empresa de prueba de la repeticion {rep}: {ej.identificador}")
        rutas = []
        with contextlib.ExitStack() as pila:
            # Cada Registro entra en la pila justo al crearse (PY-8): si el segundo
            # falla al arrancar, el primero se para y no queda un docker logs huerfano.
            registros = []
            for servicio in ("redis", "postgres"):
                registro = Registro(servicio, salida_rep / f"log_{servicio}.txt")
                pila.callback(registro.parar)
                registros.append(registro)
            contexto = {"t": ej.t, "escalera": ej.escalera, "datos": ej.datos, "salida": salida_rep,
                        "caddy": ej.ids["caddy"], "cpus_k6": ej.cpus_k6, "registros": registros}
            for n_ruta, ruta in enumerate(ORDEN_RUTAS):
                rutas.append(ejecutar_ruta(ej, rep, ruta, n_ruta, n_ruta == len(ORDEN_RUTAS) - 1, contexto))
            time.sleep(3)
        otras = {s: leer_log(salida_rep / f"log_{s}.txt") for s in ("redis", "postgres")}
        # Arranques de Redis de esta repetición (mismo reloj de la VM que el log):
        # la ventana de arranque del resumen del limitador cuenta desde ellos.
        arranques_redis = arranques_redis_desde(ej, t_ini)
        for r_ruta in rutas:
            lineas_api = leer_log(salida_rep / f"log_{r_ruta['ruta']}_api.txt")
            for res in r_ruta["resultados"]:
                senales_escalon(lineas_api, otras, res, arranques_redis)
        datos_rep = evaluar_repeticion(ej, rep, rutas, t_ini, False)
        resultados = [res for r_ruta in rutas for res in r_ruta["resultados"]]
        p(f"=== repeticion {rep} de {n_reps}: reinicios y OOMKilled de los contenedores de Canario (docker inspect)")
        for ident in ej.ids.values():
            r = ejecutar(["docker", "inspect", "--format", "{{.Name}} reinicios={{.RestartCount}} "
                          "OOMKilled={{.State.OOMKilled}} estado={{.State.Status}}", ident])
            p(f"   {r.out.strip()}")
        tabla(resultados)
        for res in resultados:
            for motivo in res["sin_conclusion"]:
                sinc(f"repeticion {rep}, {res['ruta']}__{res['escalon']}: {motivo}")
            if res.get("principal") is not None:
                pasa((salida_rep / f"{res['ruta']}__{res['escalon']}" / "panel.html").is_file(),
                     f"repeticion {rep}, {res['ruta']}__{res['escalon']}: k6 exporto el panel HTML")
        p(f"=== codo por ruta, repeticion {rep} (primer escalon con p95 > SLO, >= 1 % de errores o maxVUs "
          "alcanzados)")
        for ruta in ORDEN_RUTAS:
            codo = codo_de([res for res in resultados if res["ruta"] == ruta])
            p(f"   {ruta}: " + ("sin codo en la escalera medida" if codo is None else
                                f"{codo['escalon']} {codo['etiqueta']} = {codo['tasa']}/s "
                                f"({'; '.join(codo['motivos_fuera'])})"))
        hipotesis(resultados, ej.t, datos_rep["muerte_en_login"])
        return {"resultados": resultados, **datos_rep}
    finally:
        # ej.eventos.copia() se evalúa aquí, fuera de guardar_eventos, a propósito:
        # que ej.eventos exista lo garantiza la comprobación del principio de esta
        # función (enmienda v4.4), que lanza RuntimeError antes del try si falta; y
        # copia() solo toma el cerrojo y hace list(). Meterla dentro de
        # guardar_eventos obligaría a un except Exception amplio que taparía fallos
        # reales.
        guardar_eventos(salida_rep / "eventos_docker.json", [e for e in ej.eventos.copia() if e["t"] >= t_ini])


def agregar(repeticiones):
    """Agregación entre repeticiones: la puerta toma el peor caso (nunca la
    mediana); la latencia, una tabla por repetición, mediana, mínimo y máximo
    del p95 por escalón y el codo de cada repetición sin promediar."""
    p("=== agregacion entre repeticiones")
    peor = peor_caso([r["max_memoria"] for r in repeticiones])
    p(f"   puerta: peor caso de la memoria de login entre repeticiones = {peor} B (limite {LIMITE_MEMORIA_B} B), "
      "PASA por muestreo a 4 Hz si ninguna repeticion dio FALLA o SIN CONCLUSION arriba")
    p(f"   puerta: muertes de Canario por repeticion {[r['muertes'] for r in repeticiones]} (peor caso "
      f"{peor_caso([r['muertes'] for r in repeticiones])})")
    p("   p95 (ms) por escalon y repeticion; mediana/minimo/maximo (escalones NO EVALUABLE o sin datos: -)")
    p95s = {}
    for ruta in ORDEN_RUTAS:
        for paso in repeticiones[0]["resultados"]:
            if paso["ruta"] != ruta:
                continue
            clave = f"{ruta}__{paso['escalon']}"
            valores = []
            for r in repeticiones:
                fila = next((x for x in r["resultados"] if x["ruta"] == ruta and x["escalon"] == paso["escalon"]), None)
                pr = None if fila is None else fila.get("principal")
                valores.append(None if pr is None or fila.get("no_evaluable") else pr["p95_ms"])
            p95s[clave] = valores
            resumen = resumen_latencias(valores)
            p(f"   {clave} {paso['etiqueta']}: " + " / ".join(ms(v) for v in valores) + (
                "" if resumen is None else f"  -> mediana {ms(resumen['mediana'])}, minimo {ms(resumen['minimo'])}, "
                                          f"maximo {ms(resumen['maximo'])}"))
    for n, r in enumerate(repeticiones, start=1):
        p(f"   codo de la repeticion {n}: " + ", ".join(
            f"{ruta} {('ninguno' if c is None else c['etiqueta'])}"
            for ruta in ORDEN_RUTAS for c in [codo_de([x for x in r["resultados"] if x["ruta"] == ruta])]))
    if len(repeticiones) >= 3:
        distinta, texto = primera_repeticion_distinta(p95s)
        p(f"   repeticion 1 frente al resto: {texto}")


def ejecutar_l1(t, datos, salida, cpus_canario, cpus_k6, repeticiones):
    escalera = escaleras(t)
    por_repeticion = estimar_segundos(escalera) + SOBRECOSTE_REPETICION_S
    total = por_repeticion * repeticiones + SOBRECOSTE_CONTROLES_S
    p("=== escaleras de L1")
    for ruta in ORDEN_RUTAS:
        p(f"   {ruta}: " + ", ".join(f"{e['escalon']} {e['etiqueta']}={e['tasa']}/s x {e['duracion_s']} s"
                                    for e in escalera[ruta]))
    p(f"   tiempo estimado: {por_repeticion / 60:.1f} min por repeticion (sin cortes), {repeticiones} repeticiones y "
      f"los dos controles: {total / 3600:.1f} h en total")
    if por_repeticion > TIEMPO_MAXIMO_S:
        raise Parada(f"la carga estimada ({por_repeticion / 60:.1f} min por repeticion) supera los "
                     f"{TIEMPO_MAXIMO_S // 60} min del plan (t demasiado grande): revise t antes de medir")
    comprobar_literales_argon2()
    ej = Ejecucion(t, datos, salida, cpus_canario, cpus_k6, escalera)
    repeticiones_hechas = []
    try:
        with contextlib.ExitStack() as pila:
            # Orden de cierre (LIFO): primero el stream de eventos, al final los
            # contenedores efímeros.
            pila.callback(limpiar_efimeros)
            ej.eventos = EventosDocker(hora_motor_ahora(), salida / "docker_events.err")
            pila.callback(ej.eventos.parar)
            for rep in range(1, repeticiones + 1):
                repeticiones_hechas.append(ejecutar_repeticion(ej, rep, repeticiones))
            if not ejecutar_control(ej, "final"):
                sinc("el control positivo final no se ve completo: toda la ejecucion queda SIN CONCLUSION")
            if ej.eventos.ilegibles:
                sinc(f"{ej.eventos.ilegibles} lineas ilegibles en el stream de docker events")
            if not streamer_vivo(ej.eventos):
                sinc("el stream de docker events murio durante la ejecucion")
            agregar(repeticiones_hechas)
    finally:
        # Lo medido hasta ese momento queda escrito, también con PARADA o Ctrl+C.
        escribir_resultados(ej.todos, salida)
        p(f"   resultados: {salida / 'resultados.json'} y {salida / 'resultados.csv'}")


# ---------------------------------------------------------------------------
# L2, L3, L3b y L4: cifras congeladas y análisis puro, sin Docker (sus
# pruebas: tests/estres/test_lanzar.py). Las cifras salen de la subsección
# "Segunda congelación (22/11/2026)" de docs/informe-pruebas.md y de sus
# erratas E1-E13. Todo veredicto vive aquí, separado de la E/S.
# ---------------------------------------------------------------------------
# t congelada: el valor que se pasa con --t. Con otra, las tasas ya no serían
# las congeladas y el lanzador se detiene (PARADA).
T_CONGELADA = 0.0196
# Víctimas a tasa constante, en peticiones por segundo (L2, L3b y L4 en la BASE).
TASA_VICTIMA = 5
# N de L3b congelado (ceil(102,04 x 300 / 9)): si la derivación de las tasas
# diera otro, PARADA. Es un literal, no se deriva del código que se prueba.
N_IPS_ATAQUE_CONGELADO = 3402
# 200 IPs de L3 a 1,5 peticiones por segundo cada una: 300/s.
IPS_L3 = 200
TASA_POR_IP_L3 = 1.5
IPS_CONTROL_L3B = 10
# Peticiones por IP y ventana de 300 s del ataque de L3b (límite de acceso: 10).
PETICIONES_POR_IP_L3B = 9
MARGEN_IPS = 1.5
# Ventanas y límites de producción de las reglas que miden L3 y L3b.
LIMITE_SEGUIMIENTO, VENTANA_SEGUIMIENTO_S = 60, 60
LIMITE_ACCESO, VENTANA_ACCESO_S = 10, 300
LIMITE_DENUNCIA, VENTANA_DENUNCIA_S = 10, 3600
# Cifras congeladas como LITERALES (informe-pruebas.md, segunda congelacion). El
# lanzador las deriva de t y de las reglas (tasas_de, n_ips_ataque,
# ips_necesarias) y al arrancar las compara con estas: si no coinciden, PARADA
# (comprobar_cifras_congeladas).
TASA_INUNDACION_CONGELADA = 153.06
TASA_LOGIN_PICO_CONGELADA = 102.04
TASA_LOGIN_BASE_CONGELADA = 10.20
IPS_DENUNCIA_CONGELADAS = 428
IPS_SEGUIMIENTO_CONGELADAS = 8
# Esquema de IPs simuladas: 198.18.0.0/15 (RFC 2544), sin las direcciones .0 y
# .255 de cada /24. Al final del espacio quedan reservadas, fuera de todos los
# rangos de L3 y L3b: 198.19.255.254 (control de strict, J6), 198.19.255.253
# (sonda de salud), 198.19.255.252 (la otra IP del 71.o del control de strict,
# S1) y el bloque con nombre "strict_falsas" de las 70 IPs falsas que rotan.
INDICE_IP_STRICT = 130047
INDICE_IP_SONDA = 130046
INDICE_IP_S1 = 130045
PETICIONES_STRICT = 70
INICIO_STRICT_FALSAS = INDICE_IP_S1 - PETICIONES_STRICT
IP_STRICT = "198.19.255.254"
TAM_BLOQUE_REPETICION = 4096
# Hosts de producción (proxy/Caddyfile.produccion). La API y el sitio del
# denunciante son dos nombres; la SPA no interviene.
HOST_API = "canario-api.eduumr.dev"
HOST_WEB = "canario.eduumr.dev"
IP_TRAEFIK = "10.88.1.2"
IP_AJENA_EDGE = "10.88.1.3"
RED_EDGE = PROYECTO + "_edge"
# El 403 de solo_traefik (proxy/Caddyfile.produccion:42-46): lo pinta el
# handle_errors de sitio_api (proxy/comun.caddy:221, el último respond) con el
# estado 403. Literales, copiados de ahí.
ESTADO_403 = 403
CUERPO_403 = '{"detalle": "petición no válida"}'
# Control de trusted_proxies_strict: 70 peticiones, las 60 primeras aceptadas
# (404, seguimiento inexistente) y las 10 últimas 429 (límite seguimiento 60/60).
# La 71.a (S1, diferencial) lleva "198.19.255.254, <otra IP reservada>": con
# strict cuenta para la otra IP y da 404; sin strict, las 71 dan 404 (cuentan
# para IPs distintas); sin confianza, todo cuenta para la IP de la conexion (429).
ESTADOS_STRICT = [404] * 60 + [429] * 10 + [404]
# Memoria de k6 por VU (L1, supuesto sin medir) y tope de MEMORIA_K6 (J12).
MIB_POR_VU = 5
# Cada VU de k6 interpreta /datos/ejecucion.json al inicializarse y guarda su
# copia: MiB extra por VU = FACTOR_COPIAS_JSON x tamano del fichero en MiB. SIN
# MEDIR; se fija con la sonda antes de L3b. Las listas de IPs van aparte, en
# ips.json y en SharedArray de k6/data, y no cuentan aqui.
FACTOR_COPIAS_JSON = 4
MEMORIA_K6_MIB = 4096
# Segundos que se descartan al principio de la RECUPERACIÓN (E11, B4):
# gracefulStop de 20 s y plazo de 15 s de las peticiones en vuelo.
EXCLUSION_RECUP_S = 20
# Recuperación de L4 (F2, F3, E9).
VENTANA_P95_S = 10
SOSTENIDO_S = 30
UMBRAL_RECUPERACION_S = 60
MINIMO_BASE_OK = 0.95
# Humo de L4: 120 s después del fin PROGRAMADO del pico (E10) y 10 s antes de
# que empiece (el humo previo, justo antes del pico).
HUMO_PREVIO_S, HUMO_POSTERIOR_S = 140, 300
# maxDuration y gracefulStop del humo (plan v4.2, cambio 2). UNA SOLA FUENTE:
# viajan en `humos` (humos_pico) y de ahí los leen fases.js, duracion_total
# (el plazo de docker wait) y estimar_repeticion_s; ninguno los repite.
# maxDuration: el humo encadena 4 peticiones con el plazo de 15 s de fases.js
# (PLAZO, el mismo SEGUNDOS_PLAZO de l1.js), así que una API lenta pero correcta
# puede tardar 4 x 15 = 60 s. Con los 60 s exactos de antes (fases.js:101 del
# commit c7791e6) cortaría el humo y daría una FALLA falsa: se deja un margen
# de dos plazos más (supuesto, sin medir): 90 s.
# gracefulStop: antes no se fijaba y k6 aplicaba su valor por defecto, 30 s
# (medido: "humo_previo: ... (maxDuration: 1m0s, ..., gracefulStop: 30s)", línea
# 24 de k6_salida.txt de la repetición 2 de L4, k6 v2.3.0, 24/11/2026). Ahora se
# fija al gracefulStop del resto de escenarios (GRACEFUL_STOP_S, fases.js:83). Por
# qué basta con 20 s: es mayor o igual que el PLAZO de 15 s de una petición, así
# que la que esté en vuelo al llegar a maxDuration termina (con éxito o por su
# plazo) antes de que k6 la corte, y nunca cuenta como un error falso.
HUMO_PASOS = 4
HUMO_PLAZOS_MARGEN = 2
HUMO_MAX_DURACION_S = (HUMO_PASOS + HUMO_PLAZOS_MARGEN) * SEGUNDOS_PLAZO
HUMO_GRACEFUL_STOP_S = GRACEFUL_STOP_S
SLO_VICTIMAS_MS = {"denuncia": 1000, "seguimiento": 500, "web_seguimiento": 300}
SLO_RUTAS_MS = {**SLO_VICTIMAS_MS, "login_email": 1500}
ESTADO_RUTAS = {"denuncia": 201, "seguimiento": 404, "web_seguimiento": 200, "login_email": 401,
                "sonda_salud": 405}
RUTAS_FASES = ("denuncia", "seguimiento", "web_seguimiento", "login_email")
# Todas las rutas con la misma función de k6 salvo estas.
FUNCION_K6 = {"denuncia": "denuncia", "seguimiento": "seguimiento", "web_seguimiento": "web_seguimiento",
              "login_email": "login_email", "sonda_salud": "sonda_salud"}
PATRON_T0 = re.compile(r"T0_MS=(\d+)")
PATRON_ALINEACION_PERDIDA = re.compile(r"ALINEACION_PERDIDA")
# Cualquier código de seguimiento: el escáner anti-fuga busca este patrón
# porque el código del humo solo existe dentro de k6. La API acepta
# minúsculas, guiones y espacios (app/cripto.py, leer_codigo): se buscan los
# 8 grupos de 4 separados por guiones en cualquier caso y los 32 caracteres
# seguidos en mayúsculas. No se busca la variante con espacios ni la de 32
# minúsculas seguidas: darian falsos positivos en logs en prosa y en
# identificadores hexadecimales, y ninguna herramienta de esta bateria las
# produce.
PATRON_CODIGO = re.compile(rb"(?i:[A-Z2-7]{4}(?:-[A-Z2-7]{4}){7})|[A-Z2-7]{32}")


def tasas_de(t):
    """Las tasas que salen de t (docs/informe-pruebas.md, regla de las tasas):
    la inundación de L2 (1,5 x 2/t), el login del pico de L4 y de L3b (2/t) y
    el de la base de L4 (0,1 x 2/t), con dos decimales."""
    return {"inundacion": round(1.5 * 2 / t, 2), "login_pico": round(2 / t, 2), "login_base": round(0.1 * 2 / t, 2)}


def n_ips_ataque(tasa_login):
    """IPs del ataque de L3b: 9 peticiones por IP en cada ventana de 300 s."""
    return math.ceil(tasa_login * VENTANA_ACCESO_S / PETICIONES_POR_IP_L3B)


def ips_necesarias(tasa, duracion_s, limite, ventana_s, margen=MARGEN_IPS):
    """IPs que necesita una víctima (E4): peticiones en la parte de su
    duración que cabe en una ventana, divididas entre el límite y por el
    margen, redondeando hacia arriba. Denuncia: 5/s x 570 s / 10 x 1,5 = 428.
    Seguimiento: 5/s x 60 s / 60 x 1,5 = 8."""
    return math.ceil(tasa * min(duracion_s, ventana_s) / limite * margen)


def ip_de_indice(i):
    """IPv4 simulada número i de 198.18.0.0/15, sin .0 ni .255 de cada /24."""
    if not 0 <= i <= INDICE_IP_STRICT:
        raise ValueError(f"indice de IP fuera de rango: {i}")
    bloque, resto = divmod(i, 254)
    return f"198.{18 + bloque // 256}.{bloque % 256}.{resto + 1}"


def bloques_ips(repeticion, roles):
    """Bloques de índices de IP de una repetición: {rol: (inicio, n)}, en el
    orden de roles ([(rol, n)]), consecutivos dentro del bloque de la
    repetición. Cada repetición usa otro bloque (defensa en profundidad, J5)."""
    base = (repeticion - 1) * TAM_BLOQUE_REPETICION
    bloques, cursor = {}, base
    for rol, n in roles:
        bloques[rol] = (cursor, n)
        cursor += n
    return bloques


def solapes_de_bloques(bloques):
    """Pares de bloques que se solapan o que se salen del espacio permitido
    (hasta el principio de las IPs reservadas, sin incluirlo). bloques:
    {clave: (inicio, n)}."""
    problemas = []
    claves = sorted(bloques, key=lambda k: bloques[k][0])
    for clave in claves:
        inicio, n = bloques[clave]
        if inicio < 0 or inicio + n > INDICE_IP_S1:
            problemas.append(f"{clave}: [{inicio}, {inicio + n}) se sale del espacio de IPs permitido")
    for a, b in itertools.pairwise(claves):
        if bloques[a][0] + bloques[a][1] > bloques[b][0]:
            problemas.append(f"{a} y {b} se solapan")
    return problemas


def plan_ips(modo, repeticiones, n_ataque=None):
    """Bloques de IPs de todas las repeticiones, comprobados (E4): si se
    solapan o no caben, PARADA. Devuelve {repeticion: {rol: [IPs]}}. L3: un
    rol "carga" de 200 IPs. L3b: ataque, control y las tres víctimas.

    L5: la IP de las 11 denuncias y la de la 12.ª, informativa. L6: el cliente
    legítimo, UNA IP fija de 198.18.0.0/15 que sale de bloques_ips y pasa por
    solapes_de_bloques (PY-IP): así nunca cae en las reservadas ni en
    strict_falsas (el índice 130044, que parecería libre, está dentro de
    strict_falsas), y queda fuera de 100.64.0.0/10, que es del relleno. L7:
    las víctimas de L2 con IPs por E4 sobre 390 s (293, 8 y 8) y la IP de la
    inundación de /salud."""
    if modo == "l3":
        roles = [("carga", IPS_L3)]
    elif modo == "l5":
        roles = [("l5", 1), ("l5_otra", 1)]
    elif modo == "l6":
        roles = [("legitimo_l6", 1)]
    elif modo == "l7":
        roles = [("denuncia", ips_necesarias(TASA_VICTIMA, 390, LIMITE_DENUNCIA, VENTANA_DENUNCIA_S)),
                 ("seguimiento", ips_necesarias(TASA_VICTIMA, 390, LIMITE_SEGUIMIENTO, VENTANA_SEGUIMIENTO_S)),
                 ("web_seguimiento", ips_necesarias(TASA_VICTIMA, 390, LIMITE_SEGUIMIENTO, VENTANA_SEGUIMIENTO_S)),
                 ("inundacion", 1)]
    else:
        roles = [("ataque", n_ataque), ("control", IPS_CONTROL_L3B),
                 ("denuncia", ips_necesarias(TASA_VICTIMA, 570, LIMITE_DENUNCIA, VENTANA_DENUNCIA_S)),
                 ("seguimiento", ips_necesarias(TASA_VICTIMA, 570, LIMITE_SEGUIMIENTO, VENTANA_SEGUIMIENTO_S)),
                 ("web_seguimiento", ips_necesarias(TASA_VICTIMA, 570, LIMITE_SEGUIMIENTO, VENTANA_SEGUIMIENTO_S))]
    if sum(n for _, n in roles) > TAM_BLOQUE_REPETICION:
        raise Parada(f"los rangos de IPs de una repeticion ({sum(n for _, n in roles)}) no caben en "
                     f"{TAM_BLOQUE_REPETICION}")
    # El bloque con nombre de las IPs falsas de strict (S9) es el mismo en todas
    # las repeticiones: entra una sola vez en la comprobacion de solapes.
    todos = {("global", "strict_falsas"): (INICIO_STRICT_FALSAS, PETICIONES_STRICT)}
    por_repeticion = {}
    for rep in range(1, repeticiones + 1):
        bloques = bloques_ips(rep, roles)
        por_repeticion[rep] = bloques
        todos.update({(rep, rol): b for rol, b in bloques.items()})
    problemas = solapes_de_bloques(todos)
    if problemas:
        raise Parada(f"los rangos de IPs se solapan o no caben: {problemas}")
    falsas = [ip_de_indice(i) for i in range(INICIO_STRICT_FALSAS, INICIO_STRICT_FALSAS + PETICIONES_STRICT)]
    return {rep: {**{rol: [ip_de_indice(i) for i in range(inicio, inicio + n)] for rol, (inicio, n) in bloques.items()},
                  "strict_falsas": list(falsas)}
            for rep, bloques in por_repeticion.items()}


# --- ventanas del limitador -------------------------------------------------
def ventana_de_peticion(inicio_s, fin_s, ventana_s):
    """(índice de ventana por la hora de INICIO, ambigua). Una petición es
    ambigua si el intervalo [inicio, fin] cruza una frontera de ventana (C1):
    no se sabe en qué contador cayó. El intervalo es [marca - duración, marca]
    de la fila http_req_duration; no incluye el tiempo de conexión (en HTTP
    con conexiones reutilizadas es despreciable)."""
    a, b = math.floor(inicio_s / ventana_s), math.floor(fin_s / ventana_s)
    return a, a != b


def contar_por_ip_ventana(filas, ventana_s, aceptado):
    """Recuento por (IP, ventana). filas: dicts con ip, inicio, fin (segundos
    desde 1970) y estado. Solo cuenta el estado ACEPTADO (J3: 404 en L3, 401 en
    L3b); los 503 van aparte y todo lo demás en "otros". Cada par lleva sus
    peticiones ordenadas por inicio, para el control positivo (J2), y las
    ambiguas que cruzan su frontera inicial ("ambiguas_inicio")."""
    pares = {}

    def par(clave):
        return pares.setdefault(clave, {"aceptadas": 0, "aceptadas_ambiguas": 0, "aceptadas_ambiguas_inicio": 0,
                                        "n429": 0, "n503": 0, "otros": 0, "ambiguas": 0, "ambiguas_inicio": 0,
                                        "peticiones": []})

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
    """Retry-After de un 429 (E7): un entero entre 1 y la ventana (60 en L3,
    300 en L3b). El -1 que anota l3.js cuando falta o no son dígitos no vale."""
    return (isinstance(valor, (int, float)) and not isinstance(valor, bool) and float(valor).is_integer()
            and 1 <= valor <= ventana_s)


def retry_after_invalidos(valores, n429, ventana_s):
    """Cuántos 429 no tienen un Retry-After válido: los valores fuera de rango
    más los 429 que no dejaron ninguna fila de la métrica retry_after_s."""
    return sum(1 for v in valores if not retry_after_valido(v, ventana_s)) + max(0, n429 - len(valores))


def veredicto_l3(pares, limite, retry_invalidos=0):
    """Oráculo por IP y ventana (C1, E7). Devuelve (veredicto, texto).
    FALLA: algún par con más de `limite` aceptadas NO ambiguas, o algún 429
    sin Retry-After válido. SIN CONCLUSION: solo se pasa de `limite` contando
    las ambiguas. PASA en otro caso."""
    pasan = sorted(((c, p_["aceptadas"]) for c, p_ in pares.items() if p_["aceptadas"] > limite))
    if pasan:
        return "FALLA", f"{len(pasan)} pares IP-ventana con mas de {limite} aceptadas no ambiguas (ejemplo {pasan[0]})"
    if retry_invalidos:
        return "FALLA", f"{retry_invalidos} respuestas 429 sin Retry-After valido"
    # Cuentan tambien las aceptadas ambiguas de la ventana anterior, que pudieron
    # caer en esta (H11), igual que control_l3 con ambiguas_inicio.
    dudosos = [c for c, p_ in pares.items()
               if p_["aceptadas"] + p_["aceptadas_ambiguas"] + p_["aceptadas_ambiguas_inicio"] > limite]
    if dudosos:
        return "SIN CONCLUSION", f"{len(dudosos)} pares solo pasan de {limite} contando peticiones ambiguas"
    return "PASA", f"ningun par IP-ventana pasa de {limite} aceptadas ({sum(1 for x in pares.values() if x["peticiones"])} pares con peticiones)"


def control_l3(pares, limite):
    """Control positivo de L3 y L3b (J2, validez, E5): en cada par no son 429
    las primeras (limite - ambiguas al inicio del par - peticiones previas del
    par con estado 0 o 503) peticiones NO ambiguas. Devuelve (ok, motivos)."""
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
    """Máximo de peticiones aceptadas por una IP en cualquier tramo de tramo_s
    segundos (el defecto de la ventana fija, l.695: se espera como mucho el
    doble del límite). inicios_por_ip: {ip: [inicio, ...]}. Devuelve (máximo, ip)."""
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


def evaluar_d3(por_ip, ventana_s=VENTANA_ACCESO_S, limite=LIMITE_ACCESO):
    """Control de que el límite está activo en L3b (D3, E6, validez). por_ip:
    {ip: [{"inicio","fin","estado"} x (limite + 1), en orden]}. Las 11
    peticiones deben caer en la misma ventana y ninguna ser ambigua; las 10
    primeras, 401; solo entonces la 11.ª debe ser 429. Cualquier otra cosa es
    SIN CONCLUSION (nunca FALLA). Devuelve (veredicto, motivos)."""
    motivos = []
    for ip, peticiones in sorted(por_ip.items()):
        if len(peticiones) != limite + 1:
            motivos.append(f"{ip}: {len(peticiones)} peticiones, se esperaban {limite + 1}")
            continue
        ventanas = [ventana_de_peticion(x["inicio"], x["fin"], ventana_s) for x in peticiones]
        if any(a for _, a in ventanas) or len({v for v, _ in ventanas}) != 1:
            motivos.append(f"{ip}: las peticiones no caen todas en la misma ventana o alguna es ambigua")
            continue
        if any(x["estado"] != 401 for x in peticiones[:limite]):
            motivos.append(f"{ip}: alguna de las {limite} primeras no es 401 ({[x['estado'] for x in peticiones]})")
            continue
        if peticiones[limite]["estado"] != 429:
            motivos.append(f"{ip}: la peticion {limite + 1} da {peticiones[limite]['estado']}, no 429")
    return ("SIN CONCLUSION", motivos) if motivos else ("PASA", [])


# --- relojes y fronteras ----------------------------------------------------
def proxima_frontera(ahora, periodo_s, margen_s):
    """Primer múltiplo de periodo_s (frontera de minuto o de 5 minutos UTC)
    que queda al menos margen_s después de ahora."""
    return math.ceil((ahora + margen_s) / periodo_s) * periodo_s


def cruza_frontera(inicio, fin, periodo_s):
    """Si el intervalo [inicio, fin] cruza una frontera de periodo_s segundos
    (minuto UTC en el control de strict, 00:00 UTC con 86400)."""
    return math.floor(inicio / periodo_s) != math.floor(fin / periodo_s)


def evaluar_control_strict(estados, cruza):
    """Control de trusted_proxies_strict (C2, J6, S1): 70 peticiones con
    X-Forwarded-For "<IP falsa que rota>, 198.19.255.254" deben contar todas
    para 198.19.255.254 (60 aceptadas y 10 429) y una 71.a con "198.19.255.254,
    <otra IP reservada>" debe dar 404: cuenta para la IP de la derecha, que no
    esta saturada. El diferencial distingue los tres fallos de configuracion:
    sin strict (Caddy toma la IP de la izquierda: las 70 cuentan para las IPs
    falsas, una vez cada una, y la 71.a, con 198.19.255.254 a la izquierda, cuenta
    para esa IP, que nunca se contó: las 71 dan 404), sin confianza en 10.88.1.2
    (todo cuenta para la IP de la conexion y la 71.a da 429) y strict activo. Si cruzan la
    frontera de minuto, SIN CONCLUSION; si el patron no es el esperado, PARADA."""
    if cruza:
        return "SIN CONCLUSION", "las 71 peticiones cruzan una frontera de minuto UTC"
    estados = list(estados)
    if estados == ESTADOS_STRICT:
        return "PASA", "60 aceptadas, 10 429 para 198.19.255.254 y la 71.a cuenta para la otra IP: strict lee de derecha a izquierda"
    if estados[:70] == [404] * 70:
        causa = "sin strict: Caddy toma la IP de la izquierda y ninguna cuenta para 198.19.255.254"
    elif estados[:60] == [404] * 60 and estados[60:] == [429] * (len(estados) - 60):
        causa = "sin confianza en 10.88.1.2: todo cuenta para la IP de la conexion"
    else:
        causa = "patron inesperado"
    return "PARADA", f"estados {estados} distintos de 60 x 404, 10 x 429 y 404 ({causa}): trusted_proxies_strict no actua"


def evaluar_control_403(estado, cuerpo):
    """El 403 de solo_traefik (C3, E11): el estado Y el cuerpo JSON literal del
    handle_errors. Con otro Host que el de produccion daria 421."""
    if estado == ESTADO_403 and cuerpo == CUERPO_403:
        return "PASA", "403 con el cuerpo literal de handle_errors"
    return "PARADA", f"estado {estado} y cuerpo {cuerpo!r}, se esperaba {ESTADO_403} y {CUERPO_403!r}"


def evaluar_control_421(estado):
    """Una petición con el Host de produccion desde 10.88.1.2 llega a la API
    (POST /salud da 405). Un 421 es el sitio por defecto: el Host no llega
    (E11: PARADA)."""
    if estado == 405:
        return "PASA", "el Host de produccion llega a la API (405)"
    return "PARADA", f"estado {estado} con el Host de produccion, se esperaba 405 (421 = sitio por defecto)"


# --- L2 y L3b: víctimas -----------------------------------------------------
def degradada(p95_base, p95_carga, slo):
    """Criterio de degradación (informe-pruebas.md, sección 3): el p95 supera
    max(2 x base, base + 100 ms), o supera el SLO de la ruta."""
    return p95_carga > max(2 * p95_base, p95_base + 100) or p95_carga > slo


def veredicto_victima(p95_base, carga, slo, descartes_con_aviso):
    """B1: una víctima en la inundación o el ataque. carga: {"peticiones",
    "p95_ms", "tasa_errores"} (error = estado distinto del esperado, plazos y
    conexiones cortadas incluidos). FALLA si está degradada, supera el SLO,
    tiene un 1 % o más de errores o tiene descartes con el aviso; una víctima
    sin respuestas (caída) es FALLA. Devuelve (veredicto, motivos)."""
    if not carga.get("peticiones") or carga.get("p95_ms") is None:
        return "FALLA", ["sin respuestas durante la carga (victima caida)"]
    motivos = []
    if degradada(p95_base, carga["p95_ms"], slo):
        motivos.append(f"p95 {carga['p95_ms']:.0f} ms degradado frente a {p95_base:.0f} ms o por encima del SLO de "
                       f"{slo} ms")
    if carga["tasa_errores"] >= 0.01:
        motivos.append(f"errores {carga['tasa_errores']:.2%}")
    if descartes_con_aviso > 0:
        motivos.append(f"{descartes_con_aviso} descartes con Insufficient VUs")
    return ("FALLA", motivos) if motivos else ("PASA", [])


def veredicto_l2(victimas):
    """El de la peor víctima (FALLA si alguna lo es). victimas:
    {ruta: (veredicto, motivos)}. El control de que el ataque existe (B2) no
    entra aquí: lo aplica veredicto_con_validez, que es el único sitio donde
    se combinan los controles con el resultado (J1)."""
    return peor_estado([v for v, _ in victimas.values()])


def es_error_login(estado):
    """Error del login en B2 (E8): conexión cortada (0) o 5xx que no sea 503.
    Los 503 del login inundado son el diseño y se informan aparte."""
    return estado == 0 or (500 <= estado <= 599 and estado != 503)


def ataque_efectivo(p95_ms, tasa_errores, descartes_con_aviso):
    """B2, control de que el ataque existe: solo métricas del login (p95 por
    encima de 1500 ms, 1 % o más de errores según es_error_login o descartes
    con el aviso). La CPU de la API y la tasa servida solo se informan."""
    return ((p95_ms is not None and p95_ms > 1500) or (tasa_errores is not None and tasa_errores >= 0.01)
            or descartes_con_aviso > 0)


def mediana_p95(valores):
    """Mediana de los p95 de las repeticiones (A1). Un p95 None (sin
    respuestas: la victima cayo) cuenta como infinito (H5): ignorarlo haria
    parecer sana a una ruta que no contesto. None si no hay ninguna repeticion."""
    return statistics.median(math.inf if v is None else v for v in valores) if valores else None


# Motivo con el que veredicto_con_validez da FALLA por la muerte de un servicio de
# Canario: linea_l3b_b lo usa para distinguir esa FALLA de la de las victimas.
MOTIVO_MUERTE = "murio un servicio de Canario"


def veredicto_con_validez(resultado, fallos_validez, control_ataque, muertes=()):
    """Combina el resultado de los oraculos con los controles (J1, E5, H2).

    resultado: "PASA", "FALLA" o "SIN CONCLUSION". fallos_validez: lista de
    {"motivo"}; la validez gana a FALLA (peor_estado NO se usa aqui: daria
    FALLA sobre SIN CONCLUSION). control_ataque: True, False o None (no
    aplica); es el UNICO control que solo rebaja un PASA, nunca una FALLA.
    muertes: lista de los veredictos de veredicto_muerte de cada servicio de
    Canario que murio. Si alguna es FALLA, el resultado es FALLA y no lo
    rebaja ningun fallo de validez (H10: la muerte gana a todo); solo si TODAS
    son el OOM global de la VM, SIN CONCLUSION, como en L1. Devuelve
    (veredicto, motivos)."""
    if muertes:
        if "FALLA" in muertes:
            return "FALLA", [MOTIVO_MUERTE] + [f["motivo"] for f in fallos_validez]
        return "SIN CONCLUSION", ["OOM global de la VM: la muerte de un servicio no se atribuye a Canario"]
    if fallos_validez:
        return "SIN CONCLUSION", [f["motivo"] for f in fallos_validez]
    if resultado == "SIN CONCLUSION":
        return "SIN CONCLUSION", ["los oraculos no concluyen"]
    if resultado == "PASA" and control_ataque is False:
        return "SIN CONCLUSION", ["el control de que el ataque existe no se cumple: no hubo ataque que aislar"]
    return resultado, []


def combinar_resultados(resultados):
    """Los resultados de los oraculos de las repeticiones se combinan con
    peor_estado (FALLA > SIN CONCLUSION > PASA, H3); la validez entra aparte,
    por fallos, en veredicto_con_validez. Asi L3 y L3b se combinan igual."""
    return peor_estado(resultados)


# --- estadística de filas de k6 ---------------------------------------------
def resumen_filas(filas, esperado, es_error=None):
    """Resumen de filas de una ruta y fase: peticiones, p50/p95/p99,
    recuento de estados, errores y su tasa. es_error: función estado -> bool;
    por defecto, estado distinto del esperado (B1)."""
    if es_error is None:
        def es_error(estado):
            return estado != esperado
    duraciones = sorted(f["dur"] for f in filas)
    errores = sum(1 for f in filas if es_error(f["estado"]))
    estados = collections.Counter(f["estado"] for f in filas)
    n = len(filas)
    return {"peticiones": n, "p50_ms": percentil(duraciones, 50), "p95_ms": percentil(duraciones, 95),
            "p99_ms": percentil(duraciones, 99), "errores": errores, "tasa_errores": errores / n if n else None,
            "estados": dict(sorted(estados.items())), "n503": estados.get(503, 0), "n429": estados.get(429, 0),
            "proporcion_esperado": estados.get(esperado, 0) / n if n else None}


def ventanas_p95(muestras, desde_s, hasta_s, ancho_s=VENTANA_P95_S, paso_s=1):
    """p95 en ventanas [s, s + ancho) que avanzan de paso_s en paso_s desde
    desde_s mientras s + ancho <= hasta_s (E9: cada petición cuenta en TODAS
    las ventanas que contienen su inicio). muestras: [(inicio_s, duracion_ms)].
    Devuelve [(s, p95 o None, n)]."""
    ordenadas = sorted(muestras)
    inicios = [m[0] for m in ordenadas]
    salida, s = [], desde_s
    while s + ancho_s <= hasta_s:
        lo, hi = bisect.bisect_left(inicios, s), bisect.bisect_left(inicios, s + ancho_s)
        duraciones = sorted(d for _, d in ordenadas[lo:hi])
        salida.append((s, percentil(duraciones, 95), len(duraciones)))
        s += paso_s
    return salida


def serie_cumple(ventanas, p95_base, slo, descartes, ancho_s=VENTANA_P95_S):
    """[(s, cumple)] de una ruta: la ventana cumple si tiene p95, no está
    degradada frente a su BASE (degradada incluye el SLO) y no contiene ningún
    descarte de k6 (un descarte es saturación: sin él, las peticiones perdidas
    harían ver la recuperación antes de tiempo). descartes: marcas en segundos."""
    return [(s, p95 is not None and not degradada(p95_base, p95, slo)
             and not any(s <= d < s + ancho_s for d in descartes)) for s, p95, _ in ventanas]


def segundos_hasta_recuperar(series_por_ruta, fin_pico_s, sostenido=SOSTENIDO_S):
    """Tiempo de recuperación (F2, E9): s0 menos el fin programado del pico,
    con s0 el primer inicio de ventana a partir del cual TODAS las rutas
    cumplen en `sostenido` ventanas consecutivas (inicios s0..s0+sostenido-1).
    Solo cuentan ventanas que empiezan después del fin del pico. None si no
    se recupera. series_por_ruta: {ruta: [(s, cumple)]} con paso de 1 s."""
    mapas = [dict(serie) for serie in series_por_ruta.values()]
    if not mapas:
        return None
    comunes = sorted(s for s in set.intersection(*(set(m) for m in mapas)) if s >= fin_pico_s)
    for s0 in comunes:
        if all(all(m.get(s0 + k) for m in mapas) for k in range(sostenido)):
            return s0 - fin_pico_s
    return None


def control_base_f2(series_por_ruta, sostenido=SOSTENIDO_S, minimo=MINIMO_BASE_OK):
    """Control de F2 sobre la propia BASE (E5, validez): el mismo cálculo debe
    encadenar `sostenido` ventanas seguidas dentro del criterio y al menos el
    95 % de sus ventanas debe cumplirlo. Devuelve (ok, fraccion, motivo)."""
    mapas = [dict(serie) for serie in series_por_ruta.values()]
    comunes = sorted(set.intersection(*(set(m) for m in mapas))) if mapas else []
    if not comunes:
        return False, 0.0, "la BASE no tiene ventanas"
    cumplen = [all(m[s] for m in mapas) for s in comunes]
    fraccion = sum(cumplen) / len(cumplen)
    encadena = segundos_hasta_recuperar(series_por_ruta, comunes[0], sostenido) is not None
    if not encadena:
        return False, fraccion, f"la BASE no encadena {sostenido} ventanas seguidas dentro del criterio"
    if fraccion < minimo:
        return False, fraccion, f"solo el {fraccion:.1%} de las ventanas de la BASE cumple (minimo {minimo:.0%})"
    return True, fraccion, f"el {fraccion:.1%} de las ventanas de la BASE cumple"


def mediana_recuperacion(tiempos):
    """Mediana de los tiempos de recuperación de las repeticiones; una que no
    se recupera (None) cuenta como infinito (E9)."""
    return statistics.median(math.inf if t is None else t for t in tiempos)


def veredicto_recuperacion(mediana, reinicios, humo_ok):
    """F3: PASA si la mediana es menor de 60 s, sin reinicios y con el humo
    posterior correcto; si no, FALLA (H6 refutada). El humo previo y el
    control de la BASE son de validez y no entran aquí."""
    motivos = []
    if not mediana < UMBRAL_RECUPERACION_S:
        motivos.append("no se recupera en los 180 s" if mediana == math.inf
                       else f"recuperacion en {mediana:.0f} s (60 s o mas)")
    if reinicios:
        motivos.append(f"{reinicios} reinicios de contenedores")
    if not humo_ok:
        motivos.append("el humo posterior falla")
    return ("FALLA", motivos) if motivos else ("PASA", [])


# --- presupuesto de memoria de k6 (J12) -------------------------------------
def presupuesto_k6_mib(escenarios, humos=0, bytes_json=0):
    """Memoria estimada de k6 por VUs preasignados: MIB_POR_VU por VU (el
    supuesto sin medir de L1) mas FACTOR_COPIAS_JSON veces el tamano de
    ejecucion.json por VU (PY-1; sin medir). Cada escenario reserva sus VUs al
    empezar, aunque su startTime sea posterior."""
    vus = sum(e["vus"] for e in escenarios) + humos
    return math.ceil(vus * (MIB_POR_VU + FACTOR_COPIAS_JSON * bytes_json / 1048576))


def comprobar_presupuesto(escenarios, humos=0, bytes_json=0):
    """J12: si la estimación pasa de 4 GiB (MEMORIA_K6), PARADA."""
    mib = presupuesto_k6_mib(escenarios, humos, bytes_json)
    if mib > MEMORIA_K6_MIB:
        raise Parada(f"k6 necesitaria unos {mib} MiB por {sum(e['vus'] for e in escenarios) + humos} VUs preasignados, "
                     f"mas de los {MEMORIA_K6_MIB} MiB de MEMORIA_K6 (J12)")
    return mib


def holgura_insuficiente(escenarios):
    """Escenarios cuyos VUs no superan, en segundos de tasa, el SLO de su ruta:
    un descarte con aviso no probaria que Canario se saturó sino que el
    generador se quedó corto (comprobación de lanzar_escalon). Devuelve nombres."""
    return [e["nombre"] for e in escenarios
            if e["ruta"] in SLO_RUTAS_MS and e["vus"] / (e["rate"] / e["time_unit_s"]) <= SLO_RUTAS_MS[e["ruta"]] / 1000]


# --- construcción de los escenarios (el lanzador calcula, k6 transcribe) -----
def fases_de(modo):
    """Fases de cada prueba como [{"nombre","desde_s","hasta_s"}]. "carga" es
    la inundación (L2 y L7), el pico (L4) o el ataque (L3b). L7 usa las fases
    de L2 a propósito: con las mismas víctimas y fases, solo cambia la ruta
    inundada (plan v3.2, §4)."""
    duraciones = {"l2": (30, 120, 120, 120), "pico": (30, 120, 30, 180), "l3b": (30, 120, 300, 120),
                  "l7": (30, 120, 120, 120)}[modo]
    nombres, desde, resultado = ("cal", "base", "carga", "recup"), 0, []
    for nombre, d in zip(nombres, duraciones, strict=True):
        resultado.append({"nombre": nombre, "desde_s": desde, "hasta_s": desde + d})
        desde += d
    return resultado


def fase_por_nombre(fases, nombre):
    return next(f for f in fases if f["nombre"] == nombre)


def escenarios_l2(tasas):
    """L2: una víctima por ruta durante toda la ejecución (50 VUs, 10 s de
    holgura a 5/s), la sonda de salud y la inundación del login contra la
    empresa A en su fase, con 600 VUs (TOPE_VUS)."""
    fases = fases_de("l2")
    total = fases[-1]["hasta_s"]
    carga = fase_por_nombre(fases, "carga")
    esc = [{"nombre": ruta, "funcion": FUNCION_K6[ruta], "ruta": ruta, **tramo(TASA_VICTIMA, total, 0, 50)}
           for ruta in SLO_VICTIMAS_MS]
    esc.append({"nombre": "sonda_salud", "funcion": "sonda_salud", "ruta": "sonda_salud",
                **tramo(1, total, 0, VUS_SONDA)})
    esc.append({"nombre": "login_email", "funcion": "login_email", "ruta": "login_email",
                **tramo(tasas["inundacion"], carga["hasta_s"] - carga["desde_s"], carga["desde_s"], TOPE_VUS)})
    return esc


# VUs de L4 por ruta y fase (J12): base (calentamiento, BASE y RECUPERACION) y
# pico. Suman 747 con la sonda y los dos humos (unos 3,6 GiB). Todos dan una
# holgura mayor que el SLO de su ruta (holgura_insuficiente lo comprueba).
VUS_PICO = {"base": {"denuncia": 16, "seguimiento": 16, "web_seguimiento": 16, "login_email": 32},
            "pico": {"denuncia": 80, "seguimiento": 80, "web_seguimiento": 80, "login_email": 250}}


def escenarios_pico(tasas):
    """L4 (F1): un escenario constant-arrival-rate por ruta y fase, con
    startTime, para atribuir los descartes a su ruta. Base: 5/s por víctima y
    el login a 0,1 x 2/t; pico, x 10 (el login, 2/t)."""
    fases = fases_de("pico")
    esc = []
    for ruta in RUTAS_FASES:
        base = tasas["login_base"] if ruta == "login_email" else TASA_VICTIMA
        for fase in fases:
            pico = fase["nombre"] == "carga"
            tasa = tasas["login_pico"] if pico and ruta == "login_email" else (base * 10 if pico else base)
            vus = VUS_PICO["pico" if pico else "base"][ruta]
            esc.append({"nombre": f"{ruta}__{fase['nombre']}", "funcion": FUNCION_K6[ruta], "ruta": ruta,
                        **tramo(tasa, fase["hasta_s"] - fase["desde_s"], fase["desde_s"], vus)})
    esc.append({"nombre": "sonda_salud", "funcion": "sonda_salud", "ruta": "sonda_salud",
                **tramo(1, fases[-1]["hasta_s"], 0, VUS_SONDA)})
    return esc


def escenarios_l3(ips):
    """L3: 200 IPs a 1,5/s cada una, 300 s, seguimiento inexistente, con 600
    VUs (2 s de holgura, mayor que el SLO de 0,5 s) y la sonda de salud."""
    return [{"nombre": "seguimiento_ips", "funcion": "seguimiento_ip", "ruta": "seguimiento", "ips": ips["carga"],
             "etiquetar_ip": True, **tramo(len(ips["carga"]) * TASA_POR_IP_L3, 300, 0, TOPE_VUS)},
            {"nombre": "sonda_salud", "funcion": "sonda_salud", "ruta": "sonda_salud",
             "ips": [ip_de_indice(INDICE_IP_SONDA)], "etiquetar_ip": False, **tramo(1, 300, 0, VUS_SONDA)}]


def escenarios_l3b(tasas, ips):
    """L3b: el ataque de L2 (login contra la empresa A, 2/t desde N IPs) con
    las víctimas de L2, cada una desde su propio rango de IPs, y la sonda."""
    fases = fases_de("l3b")
    total = fases[-1]["hasta_s"]
    carga = fase_por_nombre(fases, "carga")
    esc = [{"nombre": "login_ataque", "funcion": "login_ataque", "ruta": "login_email", "ips": ips["ataque"],
            "etiquetar_ip": True, **tramo(tasas["login_pico"], carga["hasta_s"] - carga["desde_s"], carga["desde_s"],
                                          TOPE_VUS)}]
    funciones = {"denuncia": "denuncia_ip", "seguimiento": "seguimiento_ip", "web_seguimiento": "web_ip"}
    for ruta in SLO_VICTIMAS_MS:
        esc.append({"nombre": ruta, "funcion": funciones[ruta], "ruta": ruta, "ips": ips[ruta], "etiquetar_ip": False,
                    **tramo(TASA_VICTIMA, total, 0, 50)})
    esc.append({"nombre": "sonda_salud", "funcion": "sonda_salud", "ruta": "sonda_salud",
                "ips": [ip_de_indice(INDICE_IP_SONDA)], "etiquetar_ip": False, **tramo(1, total, 0, VUS_SONDA)})
    return esc


def humos_pico():
    """Los dos humos de L4 tal como viajan en ejecucion.json: nombre, inicio,
    maxDuration y gracefulStop. Es la única fuente de esos valores para
    fases.js, duracion_total y estimar_repeticion_s (plan v4.2, cambio 2)."""
    return [{"nombre": nombre, "inicio_s": inicio, "max_duracion_s": HUMO_MAX_DURACION_S,
             "graceful_stop_s": HUMO_GRACEFUL_STOP_S}
            for nombre, inicio in (("humo_previo", HUMO_PREVIO_S), ("humo_posterior", HUMO_POSTERIOR_S))]


def fin_humo(humo):
    """Segundo en que k6 da por terminado un humo en el peor caso: su inicio,
    su maxDuration y su gracefulStop, los tres leídos del propio humo."""
    return humo["inicio_s"] + humo["max_duracion_s"] + humo["graceful_stop_s"]


def duracion_total(escenarios, humos=()):
    """Segundos hasta el fin del último escenario (con sus arranques) o del
    último humo (fin_humo, con los valores que viajan en humos)."""
    fines = [e["inicio_s"] + e["duracion_s"] for e in escenarios] + [fin_humo(h) for h in humos]
    return max(fines)


# --- lectura del CSV de k6 para las pruebas de fases --------------------------
def etiquetas_extra(texto):
    """Las etiquetas propias de la columna extra_tags del CSV de k6 (k=v&k=v)."""
    etiquetas = {}
    for par in (texto or "").split("&"):
        clave, igual, valor = par.partition("=")
        if igual:
            etiquetas[clave] = valor
    return etiquetas


# Columnas que necesita cada fila http_req_duration (plan v4.2, cambio 5). La
# PRESENCIA se exige sin valor por defecto: una columna que falta no puede leerse
# como estado 0 o nombre vacío (con status ausente, todo saldría estado 0 y una
# FALLA falsa).
COLUMNAS_HTTP = ("status", "name", "scenario", "proto", "error_code")
# Columnas de http_req_duration que k6 nunca deja vacías, según los literales
# medidos: la fila de estado 0 de L3b (M4-real, medidas_v4_25nov/
# fila_status0_l3b_rep1.csv, k6 v2.3.0, 25/11/2026), las 13072 filas de la
# repetición 1 de L4 (canario_estres_salida_px5x7po1, k6 v2.3.0, 24/11/2026) y el
# barrido de QA de la enmienda v4.3 sobre L1, L2, L3, L3b y L4. scenario NO está:
# las peticiones de setup() de l3.js no pertenecen a ningún escenario y salen con
# scenario vacío (medidas_v4_25nov/filas_setup_l3_l3b.csv, k6 v2.3.0, 25/11/2026).
# Su columna sigue siendo obligatoria (COLUMNAS_HTTP). Un literal medido con un
# script no vale para otro.
NO_VACIAS_HTTP = ("status", "name")


def motivo_ilegible_http(fila):
    """None si una fila http_req_duration trae lo que necesita; si no, el
    motivo, que dice la columna. Vacíos admitidos, según los literales medidos:
    proto vacío solo con estado 0 (M4-real: una petición fallida no tiene
    protocolo, como supone evaluar_protocolo); error_code vacío solo si la
    petición fue bien (estado entre 1 y 399): en L4 todas las filas 4xx y 5xx
    traen 1000 + estado (1401, 1404, 1405, 1502, 1503), el 429 de L3 trae 1429
    y la de estado 0, 1050; scenario vacío, en las peticiones de setup()."""
    for columna in COLUMNAS_HTTP:
        if fila.get(columna) is None:
            return f"http_req_duration sin la columna {columna}"
    for columna in NO_VACIAS_HTTP:
        if fila[columna] == "":
            return f"http_req_duration con {columna} vacio"
    try:
        estado = int(fila["status"])
    except ValueError:
        return "http_req_duration con status no numerico"
    if fila["proto"] == "" and estado != 0:
        return f"http_req_duration con proto vacio y estado {estado}"
    if fila["error_code"] == "" and not 0 < estado < 400:
        return f"http_req_duration con error_code vacio y estado {estado}"
    return None


def motivo_ilegible_check(fila):
    """None si una fila checks trae el nombre del check; si no, el motivo. La
    columna check solo existe con 'check' en systemTags (M2) y k6 nunca la deja
    vacía en una fila checks (M2 y M4, medidas_v4_25nov, k6 v2.3.0, 25/11/2026):
    sin ella no se sabe de qué etapa del humo es el check."""
    if fila.get("check") is None:
        return "checks sin la columna check"
    if fila["check"] == "":
        return "checks con check vacio"
    return None


def leer_csv_fases(ruta, desviar=None):
    """Lee el CSV de k6 una vez. Devuelve un dict con las peticiones
    ("filas", solo las filas http_req_duration, que traen estado, name, proto y
    etiquetas; inicio = marca - duración porque la marca es el FIN de la
    petición, H-k6d), los descartes por escenario con su marca, los Retry-After
    de los 429 (métrica retry_after_s), los resultados de los check, el
    número de filas ILEGIBLES ("ilegibles": columnas ausentes, vacíos que k6
    nunca deja o campos que no se pueden convertir; validez_generador lo
    convierte en fallo) y sus motivos ("motivos_ilegibles": {motivo: n}). Solo
    se capturan los errores de conversion de cada fila, nunca el analisis
    entero.

    Trae también "retry_503": [(marca, valor de la etiqueta ra)] de la métrica
    retry_after_503_s (los 503 del cliente legítimo de L6, con el Retry-After
    TAL CUAL como etiqueta, porque el oráculo compara el texto literal "5").

    desviar (L6): función que recibe cada fila ya validada y devuelve True si
    la consume (el agregador en streaming del relleno, unas 675 000 peticiones
    que no caben como dicts en memoria). Las filas consumidas no se guardan;
    un error de conversión dentro de desviar cuenta como fila ilegible, igual
    que en el resto."""
    filas, descartes, retry, checks = [], collections.defaultdict(list), [], []
    retry_503 = []
    ilegibles = 0
    motivos = collections.Counter()
    # Una ultima linea sin salto final puede estar cortada (k6 muerto a medias): cuenta
    # como ilegible, aunque se lea lo que haya.
    with open(ruta, "rb") as binario:
        binario.seek(0, 2)
        if binario.tell() > 0:
            binario.seek(-1, 2)
            if binario.read(1) != b"\n":
                ilegibles += 1
                motivos["ultima linea sin salto final"] += 1
    with open(ruta, encoding="utf-8", newline="") as fichero:
        lector = csv.DictReader(fichero)
        while True:
            try:
                fila = next(lector)
            except StopIteration:
                break
            except csv.Error:
                # PY-13: un CSV roto deja de leerse (no se sabe donde seguir) y cuenta
                # como fila ilegible: validez_generador da SIN CONCLUSION.
                ilegibles += 1
                motivos["CSV roto (csv.Error)"] += 1
                break
            metrica = fila.get("metric_name")
            # Presencia y vacíos de las columnas que la fila necesita: el motivo dice
            # cuál falta (plan v4.2, cambio 5).
            motivo = (motivo_ilegible_http(fila) if metrica == "http_req_duration"
                      else motivo_ilegible_check(fila) if metrica == "checks" else None)
            if motivo is not None:
                ilegibles += 1
                motivos[motivo] += 1
                continue
            try:
                if desviar is not None and desviar(fila):
                    continue
                if metrica == "http_req_duration":
                    fin, dur = int(fila["timestamp"]) / 1000, float(fila["metric_value"])
                    tags = etiquetas_extra(fila.get("extra_tags"))
                    filas.append({"inicio": fin - dur / 1000, "fin": fin, "dur": dur,
                                  "estado": int(fila["status"]), "nombre": fila["name"],
                                  "escenario": fila["scenario"], "proto": fila["proto"],
                                  "error_code": fila["error_code"], "ip": tags.get("ip"),
                                  "fase": tags.get("fase"), "etapa": tags.get("etapa")})
                elif metrica == "dropped_iterations":
                    descartes[fila.get("scenario") or ""].append(int(fila["timestamp"]) / 1000)
                elif metrica == "retry_after_s":
                    retry.append(float(fila["metric_value"]))
                elif metrica == "retry_after_503_s":
                    retry_503.append((int(fila["timestamp"]) / 1000, etiquetas_extra(fila.get("extra_tags")).get("ra")))
                elif metrica == "checks":
                    checks.append((fila["check"], float(fila["metric_value"])))
            except (ValueError, TypeError, KeyError):
                ilegibles += 1
                motivos[f"{metrica}: campo que no se puede convertir"] += 1
    return {"filas": filas, "descartes": dict(descartes), "retry": retry, "checks": checks, "ilegibles": ilegibles,
            "motivos_ilegibles": dict(motivos), "retry_503": retry_503}


def leer_t0(registro_k6):
    """Instante (segundos desde 1970) en que acabó setup() y empezaron las
    fases, de la línea T0_MS=... de la salida de k6. None si no hay exactamente
    una."""
    valores = PATRON_T0.findall(registro_k6)
    return int(valores[0]) / 1000 if len(valores) == 1 else None


# --- escáner anti-fuga (A3, J7) ---------------------------------------------
def formas_codificadas(valor):
    """Un literal sembrado tal cual y en sus formas codificadas (J7): URL
    (%XX y con + por espacio) y JSON escapado (\\uXXXX para lo que no es ASCII).
    Sin duplicados."""
    formas = {valor, urllib.parse.quote(valor, safe=""), urllib.parse.quote_plus(valor),
              json.dumps(valor)[1:-1], json.dumps(valor, ensure_ascii=False)[1:-1]}
    return sorted(formas)


def buscar_en_bytes(contenido, literales, patrones=()):
    """Literales (str, con sus formas codificadas) y patrones (regex de bytes)
    que aparecen en contenido (bytes). Devuelve la lista de nombres de lo que
    se ha encontrado, sin repetir. literales: {nombre: valor}."""
    encontrados = []
    for nombre, valor in literales.items():
        if any(forma.encode("utf-8") in contenido for forma in formas_codificadas(valor)):
            encontrados.append(nombre)
    for nombre, patron in patrones:
        if patron.search(contenido):
            encontrados.append(nombre)
    return encontrados


def escanear_fichero(ruta, literales, patrones=(), trozo=8 * 1024 * 1024, solape=512):
    """Como buscar_en_bytes sobre un fichero grande, por trozos con solape
    (los CSV de k6 pesan cientos de MB)."""
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


# Ficheros en los que NO debe aparecer el identificador de una empresa (no los
# necesitan: los logs de la API y de PostgreSQL sí los llevan, y k6_salida.txt
# puede citar una URL en un mensaje de error de Go).
FICHEROS_SIN_IDENTIFICADORES = ("k6.csv", "resumen.json", "resultados.json", "resultados.csv")


def escanear_directorio(directorio, literales, ids, patrones=()):
    """Busca los literales sembrados (contraseña sintética, texto del humo, ...)
    y el patrón de un código de seguimiento en TODOS los ficheros de
    directorio, y los identificadores de empresa solo en los que no los
    necesitan. Devuelve {ruta relativa: [nombres encontrados]} solo con los
    ficheros que tienen algo."""
    hallazgos = {}
    for ruta in sorted(directorio.rglob("*")):
        if not ruta.is_file():
            continue
        encontrados = set(escanear_fichero(ruta, literales, patrones))
        if ruta.name in FICHEROS_SIN_IDENTIFICADORES or ruta.name.startswith("stats"):
            encontrados.update(escanear_fichero(ruta, ids))
        if encontrados:
            hallazgos[str(ruta.relative_to(directorio))] = sorted(encontrados)
    return hallazgos


def veredicto_fuga(hallazgos, centinela_visto):
    """Control del escáner: si no encuentra su centinela, no es de fiar (SIN
    CONCLUSION); si encuentra algún literal, SIN CONCLUSION; si no, PASA."""
    if not centinela_visto:
        return "SIN CONCLUSION", "el escaner no encontro su centinela: no es de fiar"
    if hallazgos:
        return "SIN CONCLUSION", f"valores sembrados en ficheros guardados: {hallazgos}"
    return "PASA", "ningun valor sembrado en los ficheros guardados"


# Subcarpeta de la salida donde se planta el centinela (S6, PY-4, H13): el
# MISMO recorrido que escanea los artefactos reales tiene que encontrarlo.
CARPETA_CENTINELA = "_control_antifuga"


def plantar_centinela(salida):
    """Planta en salida/_control_antifuga los valores que el escaner DEBE
    encontrar: un literal con acento y espacios tal cual, en forma de URL y en
    JSON escapado; un codigo de seguimiento con el formato; y un identificador
    de empresa dentro de un fichero llamado k6.csv (donde el escaner busca
    identificadores). Devuelve (literales, ids, esperados) con
    esperados = {fichero: nombre que debe salir}."""
    valor = "Centinela ó " + secrets.token_hex(6)
    ident = secrets.token_hex(16)
    carpeta = salida / CARPETA_CENTINELA
    carpeta.mkdir(exist_ok=True)
    ficheros = {"centinela_literal.txt": ("centinela", valor),
                "centinela_url.txt": ("centinela", urllib.parse.quote(valor)),
                "centinela_json.txt": ("centinela", json.dumps({"t": valor})),
                "centinela_codigo.txt": ("codigo", "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH"),
                "k6.csv": ("centinela_id", "x " + ident)}
    for nombre, (_, contenido) in ficheros.items():
        (carpeta / nombre).write_text(contenido, encoding="utf-8", newline="\n")
    esperados = {f"{CARPETA_CENTINELA}/{nombre}": clave for nombre, (clave, _) in ficheros.items()}
    return {"centinela": valor}, {"centinela_id": ident}, esperados


def escanear_con_centinela(salida, literales, ids, patrones):
    """Planta el centinela, recorre TODA la salida con el mismo escaner y lo
    separa: devuelve (hallazgos reales, ficheros del centinela que el escaner
    NO encontro). El centinela se excluye de los hallazgos y la carpeta se
    borra al terminar."""
    lit_c, ids_c, esperados = plantar_centinela(salida)
    try:
        todo = escanear_directorio(salida, {**literales, **lit_c}, {**ids, **ids_c}, patrones)
    finally:
        shutil.rmtree(salida / CARPETA_CENTINELA, ignore_errors=True)
    claves = {pathlib.PurePath(k).as_posix(): v for k, v in todo.items()}
    reales = {k: v for k, v in claves.items() if not k.startswith(CARPETA_CENTINELA + "/")}
    faltan = [f for f, nombre in esperados.items() if nombre not in claves.get(f, [])]
    return reales, faltan


# --- controles de datos, de entorno y de relojes (puros) -----------------------
def validar_ips_vistas(filas, escenario, esperadas):
    """PY-3: de la ruta medida (las filas del escenario), ninguna fila sin ip y el
    conjunto de IPs vistas es EXACTAMENTE el del plan (200 en L3, 3402 en el
    ataque de L3b). Devuelve la lista de motivos (vacia si todo bien)."""
    propias = [f for f in filas if f["escenario"] == escenario]
    motivos = []
    sin_ip = sum(1 for f in propias if f["ip"] is None)
    if sin_ip:
        motivos.append(f"{sin_ip} filas de {escenario} sin etiqueta ip")
    vistas = {f["ip"] for f in propias if f["ip"] is not None}
    esperadas = set(esperadas)
    if vistas != esperadas:
        motivos.append(f"{escenario}: {len(vistas)} IPs vistas frente a las {len(esperadas)} del plan "
                       f"({len(esperadas - vistas)} sin ver, {len(vistas - esperadas)} de mas)")
    return motivos


def conciliar_503(intervalos_503, marcas_eventos, tolerancia_s=2.0):
    """H14 (informativo): empareja uno a uno cada 503 de k6 con una linea EVENTO
    del log de la API por hora. Un EVENTO se empareja con el primer 503 todavia
    libre cuyo intervalo [inicio, fin] lo contiene con tolerancia_s de margen.
    intervalos_503: [(inicio, fin)]. Devuelve {"emparejados", "sin_evento"
    (503 sin linea), "eventos_sin_503"}."""
    libres = sorted(intervalos_503)
    usados, emparejados = set(), 0
    for t in sorted(marcas_eventos):
        for i, (inicio, fin) in enumerate(libres):
            if i not in usados and inicio - tolerancia_s <= t <= fin + tolerancia_s:
                usados.add(i)
                emparejados += 1
                break
    return {"emparejados": emparejados, "sin_evento": len(libres) - len(usados),
            "eventos_sin_503": len(marcas_eventos) - emparejados}


def comprobar_cifras_congeladas(tasas, n_ataque, ips_denuncia, ips_seguimiento):
    """Las cifras derivadas de t y de las reglas coinciden con los literales de
    la segunda congelacion; si no, PARADA (README: todas las cifras son
    literales)."""
    problemas = [f"{nombre}: {visto} frente a {literal} congelado" for nombre, visto, literal in (
        ("inundacion de L2", tasas["inundacion"], TASA_INUNDACION_CONGELADA),
        ("login del pico", tasas["login_pico"], TASA_LOGIN_PICO_CONGELADA),
        ("login de la base", tasas["login_base"], TASA_LOGIN_BASE_CONGELADA),
        ("IPs del ataque de L3b", n_ataque, N_IPS_ATAQUE_CONGELADO),
        ("IPs de la victima denuncia", ips_denuncia, IPS_DENUNCIA_CONGELADAS),
        ("IPs de las victimas de seguimiento", ips_seguimiento, IPS_SEGUIMIENTO_CONGELADAS)) if visto != literal]
    if problemas:
        raise Parada("las cifras derivadas no son las congeladas: " + "; ".join(problemas))


def espera_por_medianoche(ahora, duracion_s, maximo_s=1800, margen_s=5):
    """PY-9: segundos que hay que esperar para que una repeticion de duracion_s
    no cruce las 00:00 UTC (la sal del limitador cambia y los contadores
    empiezan de cero). 0 si no cruza. Si hay que esperar mas de maximo_s,
    PARADA."""
    medianoche = (math.floor(ahora / 86400) + 1) * 86400
    if ahora + duracion_s < medianoche:
        return 0.0
    espera = medianoche - ahora + margen_s
    if espera > maximo_s:
        raise Parada(f"la repeticion ({duracion_s:.0f} s) cruzaria las 00:00 UTC y habria que esperar {espera:.0f} s "
                     f"(mas de {maximo_s} s)")
    return espera


def evaluar_j5(positivo, negativo, ventana_s, aceptado):
    """J5 como sandwich (H6, validez): justo antes de recrear la API, una IP
    saturada en una ventana TODAVIA VIVA tiene que dar 429 (control positivo);
    despues de recrearla (sal nueva), esa misma IP NO puede dar 429 y tiene que
    dar el estado aceptado. Los dos en la misma ventana: si la ventana expiro
    entre medias, el negativo no discrimina. positivo y negativo:
    {"estado","inicio","fin"}. Devuelve (veredicto, texto)."""
    if positivo["estado"] != 429:
        return "SIN CONCLUSION", f"la IP saturada da {positivo['estado']} y no 429: el control no discrimina"
    ventana_p, ambigua_p = ventana_de_peticion(positivo["inicio"], positivo["fin"], ventana_s)
    ventana_n, ambigua_n = ventana_de_peticion(negativo["inicio"], negativo["fin"], ventana_s)
    if ambigua_p or ambigua_n or ventana_p != ventana_n:
        return "SIN CONCLUSION", "la ventana expiro entre el positivo y el negativo: no discrimina"
    if negativo["estado"] == 429:
        return "SIN CONCLUSION", "429 tras recrear la API: el contador de la repeticion anterior sigue vivo"
    if negativo["estado"] != aceptado:
        return "SIN CONCLUSION", f"estado {negativo['estado']} tras recrear la API, se esperaba {aceptado}"
    return "PASA", f"429 antes de recrear y {negativo['estado']} despues, en la misma ventana"


def rutas_sucias(salida_git):
    """S8: lineas de git status --short -- proxy/ compose.produccion.yaml
    docker-compose.yml. Vacia si el montaje es el del commit."""
    return [linea.rstrip() for linea in (salida_git or "").splitlines() if linea.strip()]


def diferencias_caddy_produccion(produccion, nuestro):
    """S8: el command de caddy y networks.edge.internal del override de la
    bateria frente a lo que resuelve docker compose con
    docker-compose.yml + compose.produccion.yaml (los dos JSON de config).
    Devuelve las diferencias (vacia si coinciden)."""
    dif = []
    for nombre, ruta in (("command de caddy", lambda c: c["services"]["caddy"].get("command")),
                         ("ports de caddy", lambda c: c["services"]["caddy"].get("ports")),
                         ("networks.edge.internal", lambda c: c["networks"]["edge"].get("internal"))):
        try:
            esperado, visto = ruta(produccion), ruta(nuestro)
        except (KeyError, TypeError, AttributeError):
            dif.append(f"{nombre}: no se puede leer en uno de los JSON de config")
            continue
        if esperado != visto:
            dif.append(f"{nombre}: produccion {esperado!r}, override {visto!r}")
    return dif


def texto_cota_ataque(veredicto_b, control_ataque, n_ips):
    """E15: la cifra del coste del ataque se da SOLO si L3b-b es FALLA y B2 se
    cumple (el ataque existe): es una cota superior, no el minimo, a esta tasa y
    duracion, IPv4. Con PASA no se da ninguna cifra (la diferencia con L2 se
    explica en el informe y no cierra la amenaza); con SIN CONCLUSION, nada."""
    if veredicto_b == "FALLA" and control_ataque:
        return f"cota superior del coste a esta tasa y duracion, IPv4: {n_ips} IPs sostenidas"
    return ""


# ---------------------------------------------------------------------------
# L5, L6 y L7 (plan v3.2 del 25/11/2026, con la decisión D-8): cifras literales
# y análisis puro, sin Docker. Sus pruebas, con los IDs del plan (U-L5-*,
# U-L6-*, U-OOM-*, U-K6-*, U-PB-*, U-IP-*, U-PY3-*, U-D4-1, U-F2-1, U-HUMO-1,
# U-N4-1 y las de L7), están en tests/estres/test_lanzar.py.
# ---------------------------------------------------------------------------
# Modos con los límites de producción, Caddyfile.produccion y el arnés de L3
# (k6 o el cliente de control desde 10.88.1.2, la IP de Traefik, en la red edge).
MODOS_PRODUCCION = ("l3", "l3b", "l5", "l6", "l7")

# --- L5: IP compartida (Tor o NAT) --------------------------------------------
# 11 denuncias válidas en serie desde una IP: con el límite de producción
# (denuncia = 10 por hora) la 11.ª tiene que dar 429.
DENUNCIAS_L5 = LIMITE_DENUNCIA + 1
# Segundos que tienen que quedar de la hora UTC para empezar: las 11 deben caer
# en la misma ventana del limitador (ventana fija de 3600 s).
MARGEN_HORA_L5_S = 300
# Retry-After: solo dígitos ASCII. No vale str.isdigit() (acepta dígitos
# Unicode como "²") ni int() a secas (acepta " 5" y "+5"): la cabecera la manda
# el servidor y se comprueba como texto, sin normalizarla antes.
PATRON_RETRY_AFTER = re.compile(r"[0-9]+")
TEXTO_COSTE_L5 = "coste asumido, threat-model §8 l.706"


def retry_after_429_valido(valor, ventana_s):
    """Un Retry-After de 429 en texto: dígitos ASCII y entre 1 y la ventana."""
    return isinstance(valor, str) and PATRON_RETRY_AFTER.fullmatch(valor) is not None and 1 <= int(valor) <= ventana_s


def sin_cuerpos(resultados):
    """Los resultados de cliente_control sin el cuerpo (PY-L5): el de un 201 de
    denuncia lleva el código de seguimiento, y no debe llegar a ningún print,
    fichero ni resultados.json. Se quita nada más volver del cliente."""
    return [{k: v for k, v in r.items() if k != "cuerpo"} for r in resultados]


def evaluar_l5(resultados):
    """Oráculo de L5 sobre las 11 respuestas, en orden. Un único parámetro
    (V31-8): no recibe ni ruta ni carpeta, no imprime y no escribe; devuelve
    (veredicto, texto) y quien llama lo publica. Solo lee estado, retry_after,
    inicio y fin, aunque las entradas traigan otras claves (cuerpo).

    SIN CONCLUSION: no son 11, cruzan la hora UTC (no caen en la misma ventana),
    alguna de las 10 primeras no es 201 (control positivo) o la 11.ª es 503 o 0
    (el limitador no respondió). FALLA: la 11.ª no es 429, o es 429 con un
    Retry-After que no son dígitos ASCII entre 1 y 3600. PASA: el coste asumido
    de threat-model §8."""
    if len(resultados) != DENUNCIAS_L5:
        return "SIN CONCLUSION", f"{len(resultados)} respuestas, se esperaban {DENUNCIAS_L5}"
    if cruza_frontera(resultados[0]["inicio"], resultados[-1]["fin"], VENTANA_DENUNCIA_S):
        return "SIN CONCLUSION", "las 11 denuncias cruzan una frontera de hora UTC: no caen en la misma ventana"
    primeras = [r["estado"] for r in resultados[:-1]]
    if any(e != 201 for e in primeras):
        return "SIN CONCLUSION", f"control positivo: las 10 primeras deben dar 201 y dan {primeras}"
    ultima = resultados[-1]
    if ultima["estado"] in (0, 503):
        return "SIN CONCLUSION", f"la 11.a da {ultima['estado']}: el limitador no respondio y no hay oraculo"
    if ultima["estado"] != 429:
        return "FALLA", f"la 11.a da {ultima['estado']} y no 429: el limite de denuncia por IP no actua"
    if not retry_after_429_valido(ultima.get("retry_after"), VENTANA_DENUNCIA_S):
        return "FALLA", f"la 11.a da 429 con un Retry-After no valido ({ultima.get('retry_after')!r})"
    return "PASA", f"la 11.a da 429 con Retry-After {ultima['retry_after']}; {TEXTO_COSTE_L5}"


def peticion_denuncia(identificador, ip):
    """Una denuncia válida contra la empresa `identificador`, con la IP del
    cliente en X-Forwarded-For (la pone Traefik; strict la lee a la derecha)."""
    return peticion_control("POST", f"/v1/empresas/{identificador}/denuncias", HOST_API, ip,
                            json.dumps({"categoria": "otros",
                                        "texto": "Denuncia de la prueba de estres L5 " + secrets.token_hex(8)}))


# --- L6: agotar el limitador --------------------------------------------------
# Estimación de una repetición (V32-6), un margen fijo: ver estimar_repeticion_s.
ESTIMACION_L6_S = 6000
# Escenario de la fase 1 (§3.1): BASE de 60 s; relleno a 150/s con 600 VUs
# durante como mucho 4500 s (600 s en el humo); legítimo a 0,5/s con 15 VUs.
BASE_L6_S = 60
RELLENO_L6_S = 4500
RELLENO_HUMO_S = 600
TASA_RELLENO = 150
VUS_RELLENO = TOPE_VUS
TASA_LEGITIMO = 0.5
VUS_LEGITIMO = 15
ESCENARIO_RELLENO = "denuncia_relleno"
# Fase 2 (§3.2, V31-9): fin en inicio_relleno + 4290 s o más, con 300 s como
# mínimo; en el humo dura unos 30 s (QA-SB). Tiene que empezar antes de
# inicio_relleno + 3598 - 120 = 3478 s para vigilar 120 s antes del primer
# instante en que H5 admite la recuperación (N3).
FIN_FASE2_S = 4290
FASE2_MINIMA_S = 300
FASE2_HUMO_S = 30
PLAZO_ARRANQUE_FASE2_S = 3478
# H5 (§3.8): llenado antes de 3600 s y R entre 3598 y 4200 s, relativos al
# inicio del relleno; R es el inicio de 30 respuestas seguidas sin 503.
H5_LLENADO_S = 3600
H5_R_MINIMO_S = 3598
H5_R_MAXIMO_S = 4200
RACHA_R = 30
# Controles positivos (§3.6): al menos 25 respuestas del legítimo en la BASE,
# todas 404, y al menos el 99 % de 422 en el relleno hasta la primera OOM.
RESPUESTAS_BASE_L6 = 25
UMBRAL_422_RELLENO = 0.99
# Información: más de 120 s entre la primera línea OOM y el primer 503.
INFO_OOM_503_S = 120
# maxmemory de Redis: 64mb en docker-compose.yml (la medida real) y el literal
# del humo, que se fija con la sonda A ANTES del humo (§5.1: 4mb si la sonda da
# al menos 18 000 claves; si no, el M literal que salga de la regla). No se
# calcula en tiempo de ejecución.
MAXMEMORY_REAL_B = 67108864
MAXMEMORY_HUMO = "4mb"
MAXMEMORY_HUMO_B = 4194304
# IPs del relleno (D-L6-1): 100.64.0.0/10 sin .0 ni .255 de cada /24 (16384
# bloques de 254), un millón por repetición; 150 x 4500 = 675 000 índices.
IPS_RELLENO_POR_REPETICION = 1000000
IPS_RELLENO_TOTAL = 16384 * 254
INTERVALO_IP_MUESTRA = 10000
# Conciliación de las líneas OOM (§3.4): E0 son los error_code admitidos para
# un estado 0 (plazo agotado, CODIGOS_K6, y el literal medido de la fila de
# estado 0 de L3b); tolerancia de 2 s; ventana excluida de 30 s tras T_RP.
E0_OOM = frozenset({"1050"})
TOLERANCIA_OOM_S = 2.0
VENTANA_ABORTO_S = 30.0
# Humo (§5.2, V32-1): PARADA si la última petición del relleno termina más de
# 15 s después de T_RP; extrapolación a 675 000 peticiones; topes de 3 GB de
# CSV y 3 GiB de memoria de k6 (MEMORIA_K6 = 4g); al menos 5000 peticiones
# entre las dos muestras de memoria.
COTA_HUMO_S = 15.0
PETICIONES_RELLENO_EXTRAPOLAR = 675000
TOPE_CSV_HUMO_B = 3000000000
TOPE_MEMORIA_K6_HUMO_B = 3 * 1024 ** 3
MINIMO_PETICIONES_EXTRAPOLAR = 5000
# Línea OOM literal (formato de app/limitador.py, texto_evento; la clase y la
# causa las confirma la sonda A). Se busca al final de la línea: otra clase u
# otra causa no casan.
PATRON_OOM = re.compile(r"EVENTO limitador_no_disponible: OutOfMemoryError causa=otra "
                        r"espera=(?:<0\.25|0\.25-0\.5|>0\.5)$")
PATRON_RELLENO_PARADO = re.compile(r"RELLENO_PARADO t=(\d+)")
PATRON_IP_MUESTRA = re.compile(r"IP_MUESTRA i=(\d+) ip=([0-9.]+)")
# ra= puede ir vacío y, en la salida de k6, seguido de la comilla del msg="...".
PATRON_LEGITIMO = re.compile(r"LEGITIMO t=(\d+) estado=(\d+) ra=([^\s\"]*)")
# Estado de L6 que impide el OK sin ser FALLA ni SIN CONCLUSION (D-L6-4).
NO_SE_LLENO = "NO SE LLENO (H5 refutada)"
SUFIJO_L6 = "(1 de 3 repeticiones; J1 exige 3)"


def ip_relleno(i, repeticion):
    """IP número i del relleno de la repetición, en 100.64.0.0/10 sin .0 ni
    .255. ValueError fuera de rango (un fallo visible, nunca una IP repetida)."""
    if not 0 <= i < IPS_RELLENO_POR_REPETICION or repeticion < 1:
        raise ValueError(f"indice de IP del relleno fuera de rango: {i} (repeticion {repeticion})")
    g = (repeticion - 1) * IPS_RELLENO_POR_REPETICION + i
    if g >= IPS_RELLENO_TOTAL:
        raise ValueError(f"la repeticion {repeticion} no cabe en 100.64.0.0/10")
    bloque, resto = divmod(g, 254)
    return f"100.{64 + bloque // 256}.{bloque % 256}.{resto + 1}"


def comprobar_ip_muestras(registro, repeticion):
    """CONTROL_IP de setup() y las líneas IP_MUESTRA del relleno contra
    ip_relleno (D-L6-1): devuelve los motivos de fallo (vacía si todo cuadra).
    Sin ninguna IP_MUESTRA no se ha comprobado nada: también es un motivo."""
    motivos = []
    if "CONTROL_IP" in registro:
        motivos.append("CONTROL_IP: los vectores literales de ip_relleno no coinciden en l3.js")
    muestras = PATRON_IP_MUESTRA.findall(registro)
    if not muestras:
        motivos.append("ninguna linea IP_MUESTRA: no se comprueba la IP del relleno")
    for i, ip in muestras:
        try:
            esperada = ip_relleno(int(i), repeticion)
        except ValueError as e:
            motivos.append(f"IP_MUESTRA i={i}: {e}")
            continue
        if ip != esperada:
            motivos.append(f"IP_MUESTRA i={i} ip={ip}, se esperaba {esperada}")
    return motivos


def marcas_relleno_parado(registro):
    """Instantes (s, reloj de la VM) de las líneas RELLENO_PARADO, ordenados.
    Puede haber más de una: el aborto tarda en propagarse a todos los VUs."""
    return sorted(int(x) / 1000 for x in PATRON_RELLENO_PARADO.findall(registro))


def validez_codigo_fase1(codigo, marcas):
    """Código de salida de la fase 1 (N2, V31-7). Válidos: 0 sin ninguna
    RELLENO_PARADO (llegó al final) y 108 (ScriptAborted) con al menos una.
    Cualquier otro (108 sin parada, 0 con parada, 105, 137, 1 o None, el plazo
    vencido de ejecutar_k6) es SIN CONCLUSION. Devuelve (válido, T_RP o None,
    texto): T_RP es la primera, y se publica cuántas hubo."""
    t_rp = marcas[0] if marcas else None
    texto = f"codigo {codigo} con {len(marcas)} lineas RELLENO_PARADO"
    if t_rp is not None:
        texto += f" (cuenta la primera, T_RP = {t_rp:.3f}; desfase de la ultima {marcas[-1] - t_rp:.3f} s)"
    valido = (codigo == 0 and not marcas) or (codigo == 108 and bool(marcas))
    return valido, t_rp, texto


def validez_codigo_fase2(codigo):
    """La fase 2 solo vale con 0 (None, el plazo vencido, no vale)."""
    return codigo == 0, f"codigo {codigo}"


def fin_fase2(inicio_relleno, i2):
    """Fin de la fase 2 (V31-9): inicio_relleno + 4290 s o I2 + 300 s si es más tarde."""
    return max(inicio_relleno + FIN_FASE2_S, i2 + FASE2_MINIMA_S)


def mantenimiento_aborto(eventos, k6_id, t_rp, ahora):
    """Mantenimiento del aborto del relleno (PY-3): el die con 108 del k6 de la
    fase 1 deja de contar como "murió otro" desde T_RP. "hasta" es el instante
    del destroy de ese k6 (ejecutar_k6 hace docker rm -f), visto en el stream
    con CENTINELA_S de plazo, como el start y el die. Nunca None (construir_
    ventanas lo haría infinito): si el destroy no llega, SIN CONCLUSION y
    "hasta" toma ahora() tras el plazo. eventos: EventosDocker (esperar, copia).
    Devuelve (mantenimiento, fallos)."""
    fallos = []
    def es_destroy(e):
        return e["id"] == k6_id and e["accion"] == "destroy"
    if eventos.esperar(es_destroy, CENTINELA_S):
        hasta = min(e["t"] for e in eventos.copia() if es_destroy(e))
    else:
        hasta = ahora()
        fallos.append(fallo("el detector no vio el destroy del k6 de la fase 1"))
    return {"ids": frozenset([k6_id]), "desde": t_rp, "hasta": hasta,
            "motivo": "aborto del relleno (fase 1 de L6)"}, fallos


def conciliar_oom(intervalos_503, intervalos_0, grupos, tolerancia_s=TOLERANCIA_OOM_S):
    """Emparejamiento uno a uno de las líneas OOM con peticiones de k6 (§3.4,
    V31-2). Pura.

    intervalos_503: [(inicio, fin)]; intervalos_0: [(inicio, fin, error_code)],
    de los que solo cuentan los de E0. Los dos forman UN conjunto, cada
    intervalo con su tipo. grupos: lista ordenada de listas de marcas (C1, C2,
    C4a...), procesadas en ese orden sobre los mismos intervalos libres; si la
    última marca de un grupo es posterior a la primera del siguiente,
    ValueError (un orden silencioso escondería el error del llamante).

    Un solo paso por tiempo: cada marca t toma, entre los intervalos libres con
    inicio - tolerancia <= t <= fin + tolerancia, el de fin + tolerancia menor
    (a igualdad: inicio menor, "503" antes que "0" y el índice). Es el voraz
    clásico de puntos e intervalos y da el emparejamiento máximo; el de
    conciliar_503 (voraz por inicio) no. Las marcas de un grupo anterior se
    emparejan antes, así que uno posterior no les quita pareja (prioridad de
    C1 sobre C2).

    Devuelve {"grupos": [{"con_503": [(t, (inicio, fin))], "con_0": [(t,
    (inicio, fin, error_code))], "sin_pareja": [t]}], "intervalos_sin_usar": n}."""
    no_vacios = [sorted(g) for g in grupos if g]
    for a, b in itertools.pairwise(no_vacios):
        if a[-1] > b[0]:
            raise ValueError(f"grupos fuera de orden: un grupo acaba en {a[-1]} y el siguiente empieza en {b[0]}")
    intervalos = [(i, f, "503", None) for i, f in intervalos_503]
    intervalos += [(i, f, "0", c) for i, f, c in intervalos_0 if c in E0_OOM]
    orden_tipo = {"503": 0, "0": 1}
    por_inicio = sorted(range(len(intervalos)), key=lambda k: intervalos[k][0])
    monton, siguiente, usados = [], 0, 0
    resultado = []
    for g in grupos:
        res = {"con_503": [], "con_0": [], "sin_pareja": []}
        for t in sorted(g):
            # Entran los que ya pueden contener t por su inicio...
            while siguiente < len(por_inicio) and intervalos[por_inicio[siguiente]][0] - tolerancia_s <= t:
                k = por_inicio[siguiente]
                inicio, fin, tipo, _ = intervalos[k]
                heapq.heappush(monton, (fin + tolerancia_s, inicio, orden_tipo[tipo], k))
                siguiente += 1
            # ...y salen los que ya acabaron: no sirven a t ni a ninguna marca posterior.
            while monton and monton[0][0] < t:
                heapq.heappop(monton)
            if not monton:
                res["sin_pareja"].append(t)
                continue
            _, _, _, k = heapq.heappop(monton)
            usados += 1
            inicio, fin, tipo, codigo = intervalos[k]
            if tipo == "503":
                res["con_503"].append((t, (inicio, fin)))
            else:
                res["con_0"].append((t, (inicio, fin, codigo)))
        resultado.append(res)
    return {"grupos": resultado, "intervalos_sin_usar": len(intervalos) - usados}


def desglose(res):
    """Texto de un grupo conciliado: total, con 503, con estado 0 y sin pareja."""
    n = len(res["con_503"]) + len(res["con_0"]) + len(res["sin_pareja"])
    return f"{n} (con 503 {len(res['con_503'])}, con estado 0 {len(res['con_0'])}, sin pareja {len(res['sin_pareja'])})"


def conciliacion_l6(lineas, t_rp, f1, i2, fin_f2, fase1, fase2, n_parado=0, tolerancia_s=TOLERANCIA_OOM_S):
    """Reglas C1 a C6 de §3.4 sobre las líneas OOM (instantes, reloj de la VM).

    t_rp: primera RELLENO_PARADO o None; f1: die del k6 de la fase 1; i2 y
    fin_f2: start y die del k6 de la fase 2 (None si no hubo). fase1 y fase2:
    (intervalos_503, intervalos_0) de las peticiones que pasan por el limitador
    (relleno y legítimo); fase1 None es el plan B (sin CSV: C1 lo decide el
    recuento y C4a no se puede emparejar).

    Grupos: C1 (antes de T_RP - 2; sin T_RP, toda la fase 1), C2 ([T_RP - 2,
    min(F1, T_RP + 30)], información), C4a ((T_RP + 30, F1], sin pareja = SIN
    CONCLUSION), C4b ((F1, F1 + 2], información), C4c ((F1 + 2, I2), SIN
    CONCLUSION), C5 ([I2, fin de la fase 2], sin pareja = FALLA). Lo que el plan
    no cubre, las líneas posteriores a la fase 2, sigue la regla de C4b y C4c
    sobre el fin de la fase 2: hasta 2 s, información ("C5b"); después, SIN
    CONCLUSION. C3 es el recuento a +-2 s de T_RP. Devuelve {"falla",
    "sin_conclusion" (motivos), "grupos" ({nombre: desglose}), "c3",
    "f1_t_rp", "texto" (la línea de publicación obligatoria)}."""
    lineas = sorted(lineas)
    g = {k: [] for k in ("C1", "C2", "C4a", "C4b", "C4c", "C5", "C5b", "tras_f2")}
    for t in lineas:
        if (t_rp is not None and t < t_rp - tolerancia_s) or (t_rp is None and t <= f1):
            g["C1"].append(t)
        elif t_rp is not None and t <= min(f1, t_rp + VENTANA_ABORTO_S):
            g["C2"].append(t)
        elif t <= f1:
            g["C4a"].append(t)
        elif t <= f1 + tolerancia_s:
            g["C4b"].append(t)
        elif i2 is None or t < i2:
            g["C4c"].append(t)
        elif fin_f2 is None or t <= fin_f2:
            g["C5"].append(t)
        elif t <= fin_f2 + tolerancia_s:
            g["C5b"].append(t)
        else:
            g["tras_f2"].append(t)
    c3 = sum(1 for t in lineas if t_rp is not None and t_rp - tolerancia_s <= t <= t_rp + tolerancia_s)
    vacio = {"con_503": [], "con_0": [], "sin_pareja": []}
    res = {}
    if fase1 is not None:
        c = conciliar_oom(fase1[0], fase1[1], [g["C1"], g["C2"], g["C4a"], g["C4b"]], tolerancia_s)["grupos"]
        res.update(zip(("C1", "C2", "C4a", "C4b"), c, strict=True))
    else:
        # Plan B: sin filas no hay intervalos; las líneas solo se cuentan.
        res.update({k: {**vacio, "sin_pareja": list(g[k])} for k in ("C1", "C2", "C4a", "C4b")})
    if fase2 is not None:
        c = conciliar_oom(fase2[0], fase2[1], [g["C5"], g["C5b"]], tolerancia_s)["grupos"]
        res.update(zip(("C5", "C5b"), c, strict=True))
    else:
        res.update({k: {**vacio, "sin_pareja": list(g[k])} for k in ("C5", "C5b")})
    falla, sin_conclusion = [], []
    if fase1 is not None and res["C1"]["sin_pareja"]:
        falla.append(f"{len(res['C1']['sin_pareja'])} lineas OOM de C1 sin 503 ni estado 0 de E0 que las contenga "
                     f"(la primera en {res['C1']['sin_pareja'][0]:.3f})")
    if res["C4a"]["sin_pareja"]:
        sin_conclusion.append(f"{len(res['C4a']['sin_pareja'])} lineas OOM mas de 30 s despues de la parada sin "
                              "ninguna peticion que las explique (C4a)")
    if g["C4c"]:
        sin_conclusion.append(f"{len(g['C4c'])} lineas OOM sin ningun k6 en marcha (C4c, la primera en "
                              f"{g['C4c'][0]:.3f}): algo fuera del instrumento llega al limitador")
    if g["tras_f2"]:
        sin_conclusion.append(f"{len(g['tras_f2'])} lineas OOM mas de 2 s despues del fin de la fase 2, sin k6 en marcha")
    if g["C5"] and fase2 is None:
        sin_conclusion.append(f"{len(g['C5'])} lineas OOM en la fase 2 sin su CSV: no se pueden conciliar")
    elif res["C5"]["sin_pareja"]:
        falla.append(f"{len(res['C5']['sin_pareja'])} lineas OOM de la fase 2 sin 503 ni estado 0 de E0 (C5, la "
                     f"primera en {res['C5']['sin_pareja'][0]:.3f})")
    f1_t_rp = None if t_rp is None else round(f1 - t_rp, 3)
    texto = (f"lineas OOM {len(lineas)}; F1 - T_RP = {f1_t_rp}; C1 {desglose(res['C1'])}; C2 {desglose(res['C2'])}; "
             f"C3 {c3}; C4a {desglose(res['C4a'])}; C4b {desglose(res['C4b'])}; C4c {len(g['C4c'])}; "
             f"C5 {desglose(res['C5'])}; C5b {desglose(res['C5b'])}; tras la fase 2 {len(g['tras_f2'])}; "
             f"RELLENO_PARADO {n_parado}")
    return {"falla": falla, "sin_conclusion": sin_conclusion, "grupos": res, "c3": c3, "f1_t_rp": f1_t_rp,
            "texto": texto, "n": {k: len(v) for k, v in g.items()}}


def calcular_r(respuestas):
    """R (§3.3 f): inicio de la primera racha de 30 respuestas seguidas del
    legítimo que no son 503, después de su primer 503, con las dos fases unidas
    en orden de tiempo (la racha se cuenta en respuestas, no en segundos).
    respuestas: [(t, estado)]. None si no hay 503 o no hay racha."""
    ordenadas = sorted(respuestas)
    primero = next((i for i, (_, e) in enumerate(ordenadas) if e == 503), None)
    if primero is None:
        return None
    inicio_racha, seguidas = None, 0
    for t, e in ordenadas[primero + 1:]:
        if e == 503:
            inicio_racha, seguidas = None, 0
            continue
        if inicio_racha is None:
            inicio_racha = t
        seguidas += 1
        if seguidas == RACHA_R:
            return inicio_racha
    return None


def parsear_legitimo(linea):
    """NO CONECTADA (R3): el plan B no está implementado; ningún flujo la llama.
    (t en s, estado, Retry-After o None) de una línea LEGITIMO del plan B, o
    None si la línea no lo es. ra= vacío es una respuesta sin la cabecera."""
    encaje = PATRON_LEGITIMO.search(linea)
    if encaje is None:
        return None
    return int(encaje.group(1)) / 1000, int(encaje.group(2)), encaje.group(3) or None


def legitimo_completo(n_lineas, n_contador):
    """NO CONECTADA (R3): el plan B no está implementado; ningún flujo la llama.
    Control de completitud del plan B (V31-5): las líneas LEGITIMO de la fase
    1 tienen que ser exactamente el total del legítimo en los Counters de
    resumen.json. Si faltan o sobran, R no se puede situar en la fase 1."""
    return n_lineas == n_contador


def oraculo_recuento_plan_b(lineas_oom, t_rp, n503, estados0):
    """NO CONECTADA (R3): el plan B no está implementado; ningún flujo la llama.
    Oráculo por recuento del plan B (QA-PB), congelado: N_OOM son las líneas
    del dominio C1 (antes de T_RP - 2; las de la ventana C2 no entran); N_0,
    los estados 0 con error_code en E0. FALLA si N_OOM > N_503 + N_0. Es una
    condición necesaria, más débil que el emparejamiento: los Counters cubren
    toda la fase 1. Devuelve (falla, texto con los tres números)."""
    n_oom = sum(1 for t in lineas_oom if t_rp is None or t < t_rp - TOLERANCIA_OOM_S)
    n0 = sum(n for codigo, n in estados0.items() if codigo in E0_OOM)
    return n_oom > n503 + n0, f"N_OOM {n_oom}, N_503 {n503}, N_0 {n0}"


def instrumento_fase1(hay_csv, hay_resumen, humo, plan_b=False):
    """Lo que dejó la fase 1 (D-4, V31-6, H-CSV). Devuelve (acción, texto):
    None si es evaluable; "PARADA" en el humo (sin ninguno de los dos:
    rediseño; sin CSV con el plan de CSV: H-CSV falsa y plan B); "SIN
    CONCLUSION" en la medida real (sin ninguno: fallo del instrumento)."""
    if not hay_csv and not hay_resumen:
        texto = "fallo del instrumento: la fase 1 no dejo ni k6.csv ni resumen.json"
        return ("PARADA", texto + " (D-4: rediseño, sin plan B que valga)") if humo else ("SIN CONCLUSION", texto)
    if plan_b:
        if hay_resumen:
            return None, "plan B: resumen.json presente"
        texto = "plan B sin resumen.json: no hay Counters de la fase 1"
        return ("PARADA", texto) if humo else ("SIN CONCLUSION", texto)
    if not hay_csv:
        texto = "la fase 1 no dejo k6.csv"
        return ("PARADA", texto + " (H-CSV falsa: plan B)") if humo else ("SIN CONCLUSION", texto)
    return None, "k6.csv presente"


def regla_cota_humo(t_rp, fin_ultima_relleno, f1):
    """Regla de PARADA del humo y de B' (V32-1): si la última petición del
    relleno termina más de 15 s después de T_RP, la cota de 30 s de C2 se queda
    sin margen. F1 - T_RP no entra: incluye handleSummary y el volcado del CSV.
    Devuelve (motivo de PARADA o None, texto informativo)."""
    retraso = fin_ultima_relleno - t_rp
    info = (f"fin de la ultima peticion del relleno - T_RP = {retraso:.3f} s; "
            f"F1 - T_RP = {f1 - t_rp:.1f} s (informacion: incluye handleSummary y el volcado del CSV)")
    if retraso > COTA_HUMO_S:
        return (f"la ultima peticion del relleno termina {retraso:.3f} s despues de T_RP (mas de {COTA_HUMO_S:.0f} s): "
                "revisar la cota de 30 s antes de congelar"), info
    return None, info


def maximo_trend(resumen, nombre):
    """values.max de un Trend en el resumen JSON de handleSummary, o None."""
    try:
        valor = resumen["metrics"][nombre]["values"]["max"]
    except (KeyError, TypeError):
        return None
    return valor if isinstance(valor, (int, float)) and not isinstance(valor, bool) else None


# D-8 con R2: diferencia máxima admitida, en los dos sentidos, entre el max del
# Trend fin_relleno_ms y el fin máximo del relleno en el CSV. Date.now() va
# después de la marca del CSV (Trend por delante) y un aborto entre el post y el
# add puede dejar el Trend sin la última petición (Trend por detrás).
TOLERANCIA_D8_MS = 1000


def comparar_trend_fin(max_trend, max_fin_csv_ms):
    """D-8 (con R2): el max del Trend fin_relleno_ms (Date.now() justo al volver
    el http.post) frente al fin máximo del relleno en el CSV. Vale si la
    diferencia, en valor absoluto, es de 1000 ms o menos; se publica con su
    signo (Trend - CSV). Si el Trend falta, PARADA; si no vale, el instrumento
    de B' no vale. Devuelve (accion "PARADA" o None, valido, texto)."""
    if max_trend is None:
        return "PARADA", False, "el Trend fin_relleno_ms falta en resumen.json (D-8)"
    if max_fin_csv_ms is None:
        return None, False, "sin filas del relleno en el CSV: no se puede comparar el Trend fin_relleno_ms (D-8)"
    diferencia = int(round(max_trend)) - max_fin_csv_ms
    texto = (f"max del Trend fin_relleno_ms {max_trend:.0f} y fin maximo del CSV {max_fin_csv_ms}: diferencia "
             f"(Trend - CSV) {diferencia:+d} ms (tolerancia {TOLERANCIA_D8_MS} ms)")
    if abs(diferencia) <= TOLERANCIA_D8_MS:
        return None, True, "el instrumento D-8 vale: " + texto
    return None, False, "INSTRUMENTO D-8 NO VALE: " + texto


def hipotesis_hgs(o1, o2):
    """H-GS (V31-3, V32-3), información: O1 = estados 0 cortados con error_code
    fuera de E0; O2 = peticiones del relleno vivas en T_RP que terminaron con
    estado. Nunca es PARADA: ningún oráculo depende de ella."""
    if o1 > 0:
        return f"H-GS: el aborto CORTA peticiones en vuelo (O1 = {o1}, O2 = {o2})"
    if o2 > 0:
        return f"H-GS: el aborto RESPETA el gracefulStop (O1 = 0, O2 = {o2})"
    return "H-GS sin cerrar (O1 = 0, O2 = 0): informacion, no PARADA"


def sumar_cpu_por_instante(muestras):
    """CPU de k6 sumada de todos los contenedores de clase k6 por instante (J1,
    §3.7): muestras [(t, contenedor, cpu %)], agrupadas por segundo entero;
    dentro de un segundo, cada contenedor cuenta con su máximo (para no sumar
    dos muestras del mismo). Devuelve la suma máxima, o None sin muestras."""
    por_segundo = collections.defaultdict(dict)
    for t, contenedor, cpu in muestras:
        actual = por_segundo[math.floor(t)]
        actual[contenedor] = max(cpu, actual.get(contenedor, cpu))
    return max((sum(c.values()) for c in por_segundo.values()), default=None)


def extrapolar_memoria_k6(m1, n1, m2, n2, maxima, total=PETICIONES_RELLENO_EXTRAPOLAR):
    """Memoria de k6 extrapolada a `total` peticiones del relleno (QA-SB):
    pendiente = (M2 - M1) / (N2 - N1); extrapolada = M2 + pendiente x (total -
    N2); con pendiente negativa, la máxima medida. Si N2 - N1 < 5000, la
    extrapolación no vale. Devuelve (bytes o None, motivo de PARADA o None)."""
    if n2 - n1 < MINIMO_PETICIONES_EXTRAPOLAR:
        return None, (f"solo {n2 - n1} peticiones del relleno entre las dos muestras de memoria (minimo "
                      f"{MINIMO_PETICIONES_EXTRAPOLAR}): la extrapolacion no vale")
    pendiente = (m2 - m1) / (n2 - n1)
    if pendiente < 0:
        return maxima, None
    return m2 + pendiente * (total - n2), None


def texto_salud_l6(salud, hueco_s):
    """Línea salud_l6 (§3.8): "/salud 200 en N de N sondas" o las que no lo son,
    con su instante, y el hueco sin sondas entre fases. No cambia l6."""
    malas = [x for x in salud if x["estado"] != 200]
    hueco = "sin fase 2" if hueco_s is None else f"{hueco_s:.1f} s"
    if not malas:
        cabeza = f"/salud 200 en {len(salud)} de {len(salud)} sondas"
    else:
        cabeza = (f"/salud 200 en {len(salud) - len(malas)} de {len(salud)} sondas; no 200: "
                  + ", ".join(f"{x['estado']} en {x['t']:.3f} (fase {x['fase']})" for x in malas[:10]))
    return f"{cabeza}; hueco sin sondas entre fases de {hueco}"


def evaluar_h5(d, primera_oom, l503, salud_malas):
    """H5 (información, §3.8). Devuelve (estado, texto)."""
    inicio = d["inicio_relleno"]
    if primera_oom is None:
        return "REFUTADA", "no se lleno"
    if primera_oom - inicio >= H5_LLENADO_S:
        return "REFUTADA", f"se lleno a los {primera_oom - inicio:.0f} s (3600 s o mas)"
    if any(x["fase"] == 1 for x in salud_malas):
        return "REFUTADA", "/salud fallo en la fase 1"
    if d.get("i2") is not None and d["i2"] - inicio >= PLAZO_ARRANQUE_FASE2_S:
        return "SIN CONCLUSION", f"la fase 2 empezo a los {d['i2'] - inicio:.1f} s (3478 s o mas): vigilancia tarde"
    plan_b = d.get("plan_b")
    if plan_b and not plan_b["legitimo_completo"] and l503 and l503[0]["fase"] == 1:
        return "SIN CONCLUSION", "plan B: las lineas LEGITIMO no estan completas y el primer 503 esta en la fase 1"
    if salud_malas:
        return "REFUTADA", "/salud fallo en la fase 2"
    if not l503:
        return "SIN CONCLUSION", "el legitimo no recibio ningun 503: R no existe"
    r = calcular_r([(x["t"], x["estado"]) for x in d["legitimo"]])
    if r is None:
        fin = d.get("fin_vigilancia")
        if fin is not None and fin - inicio >= H5_R_MAXIMO_S + 2 * RACHA_R:
            return "REFUTADA", "ninguna racha de 30 respuestas sin 503 en la vigilancia (R > 4200 s)"
        return "SIN CONCLUSION", "sin racha de 30 respuestas sin 503 y la vigilancia acaba antes de poder verla"
    relativo = r - inicio
    if relativo < H5_R_MINIMO_S:
        return "SIN CONCLUSION", f"R = {relativo:.1f} s (menos de 3598 s)"
    if relativo > H5_R_MAXIMO_S:
        return "REFUTADA", f"R = {relativo:.1f} s (mas de 4200 s)"
    return "CONFIRMADA", f"llenado a los {primera_oom - inicio:.0f} s y R = {relativo:.1f} s"


def evaluar_l6(d):
    """Veredicto de L6 (§3.6 a §3.8) a partir de lo medido. Pura. d:

    inicio_relleno, t0 (T0 de la fase 1), t_rp, i2, fin_vigilancia;
    lineas_oom [t]; conciliacion (de conciliacion_l6: "falla" y
    "sin_conclusion"); legitimo [{"t", "estado", "ra", "fase"}] (ra: el
    Retry-After en texto o None); salud [{"t", "estado", "fase"}] (GET
    /salud); hueco_s; n500; relleno {"n422", "n"} hasta la primera OOM; plan_b
    None o {"falla_recuento": texto o None, "legitimo_completo": bool};
    validez [fallo]; muertes.

    Devuelve {"resultado", "validez", "falla" (motivos de FALLA), "oraculo"
    (motivos de un SIN CONCLUSION del oráculo), "muertes", "salud_l6", "h5",
    "info"}. veredicto_l6 añade la validez global y decide."""
    validez = list(d.get("validez", []))
    validez += [fallo(m) for m in d["conciliacion"]["sin_conclusion"]]
    falla, oraculo, info = list(d["conciliacion"]["falla"]), [], []
    lineas = sorted(d["lineas_oom"])
    primera_oom = lineas[0] if lineas else None
    legitimo = sorted(d["legitimo"], key=lambda x: x["t"])
    l503 = [x for x in legitimo if x["estado"] == 503]
    # Controles positivos (§3.6): si fallan, SIN CONCLUSION, nunca PASA.
    base = [x for x in legitimo if d["t0"] <= x["t"] < d["t0"] + BASE_L6_S]
    if len(base) < RESPUESTAS_BASE_L6 or any(x["estado"] != 404 for x in base):
        validez.append(fallo(f"control de la BASE: {len(base)} respuestas del legitimo (minimo "
                             f"{RESPUESTAS_BASE_L6}, todas 404): {sorted(collections.Counter(x['estado'] for x in base).items())}"))
    salud_base = [x for x in d["salud"] if d["t0"] <= x["t"] < d["t0"] + BASE_L6_S]
    if not salud_base or any(x["estado"] != 200 for x in salud_base):
        validez.append(fallo(f"control de la BASE: /salud en la BASE {[x['estado'] for x in salud_base][:10]} "
                             "(todas deben ser 200)"))
    rel = d["relleno"]
    if not rel["n"] or rel["n422"] / rel["n"] < UMBRAL_422_RELLENO:
        validez.append(fallo(f"control del relleno: {rel['n422']} de {rel['n']} respuestas 422 hasta la primera "
                             "linea OOM (minimo el 99 %)"))
    plan_b = d.get("plan_b")
    if plan_b and plan_b.get("falla_recuento"):
        falla.append("plan B, recuento: " + plan_b["falla_recuento"])
    if d["n500"]:
        falla.append(f"{d['n500']} respuestas 500")
    # R1: un 503 sin su fila de retry_after_503_s (ra None) es un fallo del
    # instrumento, no del servidor: SIN CONCLUSION de validez, nunca FALLA. La
    # FALLA es solo para un ra presente distinto de "5" ("ausente" incluido: la
    # fila está y dice que el servidor no mandó la cabecera).
    sin_fila = [x for x in l503 if x["ra"] is None]
    if sin_fila:
        validez.append(fallo(f"instrumento del Retry-After: {len(sin_fila)} respuestas 503 del legitimo sin su fila "
                             "de retry_after_503_s"))
    malos = [x for x in l503 if x["ra"] is not None and x["ra"] != "5"]
    if malos:
        falla.append(f"{len(malos)} respuestas 503 del legitimo sin Retry-After \"5\" (por ejemplo {malos[0]['ra']!r} "
                     f"en la fase {malos[0]['fase']})")
    if falla:
        resultado = "FALLA"
    elif l503 and primera_oom is None:
        resultado = "SIN CONCLUSION"
        oraculo.append("el legitimo recibe 503 y no hay ninguna linea OOM (Q3)")
    elif d.get("t_rp") is not None and primera_oom is None:
        resultado = "SIN CONCLUSION"
        oraculo.append("el relleno aborto sin ninguna linea OOM")
    elif primera_oom is None:
        resultado = NO_SE_LLENO
    elif not l503:
        resultado = "SIN CONCLUSION"
        oraculo.append("hay linea OOM y el legitimo no recibio ningun 503")
    else:
        resultado = "PASA"
    if primera_oom is not None and l503 and l503[0]["t"] - primera_oom > INFO_OOM_503_S:
        info.append(f"informacion: {l503[0]['t'] - primera_oom:.0f} s entre la primera linea OOM y el primer 503 del "
                    "legitimo (mas de 120 s)")
    salud_malas = [x for x in d["salud"] if x["estado"] != 200]
    return {"resultado": resultado, "validez": validez, "falla": falla, "oraculo": oraculo,
            "muertes": list(d.get("muertes", [])), "salud_l6": texto_salud_l6(d["salud"], d.get("hueco_s")),
            "h5": evaluar_h5(d, primera_oom, l503, salud_malas), "info": info}


def veredicto_l6(ev, globales=()):
    """(veredicto, motivos) de L6 con la validez global (anti-fuga, detector
    final): veredicto_con_validez decide, y aquí solo se recuperan los motivos
    de una FALLA del oráculo o de un SIN CONCLUSION del oráculo."""
    v, motivos = veredicto_con_validez(ev["resultado"], ev["validez"] + list(globales), None, ev["muertes"])
    if v == "FALLA" and not ev["muertes"]:
        motivos = ev["falla"]
    elif v == "SIN CONCLUSION" and motivos == ["los oraculos no concluyen"]:
        motivos = ev["oraculo"]
    return v, motivos


def linea_l6(veredicto, motivos):
    """La línea final de L6, siempre con el sufijo de las repeticiones (J1)."""
    return f"l6: {veredicto}" + (f" ({'; '.join(motivos)})" if motivos else "") + f" {SUFIJO_L6}"


def escenarios_l6_fase1(ips, humo=False):
    """Fase 1 de L6 (§3.1): legítimo (seguimiento inexistente a 0,5/s desde su
    IP fija), GET /salud y la sonda POST /salud a 1/s durante toda la fase, y
    el relleno desde t = 60 s. El relleno no lleva lista de IPs: l3.js las
    calcula (ip_relleno). En el humo, el relleno dura como mucho 600 s."""
    relleno_s = RELLENO_HUMO_S if humo else RELLENO_L6_S
    total = BASE_L6_S + relleno_s
    sonda = [ip_de_indice(INDICE_IP_SONDA)]
    return [{"nombre": "legitimo", "funcion": "legitimo", "ruta": "seguimiento", "ips": ips["legitimo_l6"],
             "etiquetar_ip": False, **tramo(TASA_LEGITIMO, total, 0, VUS_LEGITIMO)},
            {"nombre": "salud_get", "funcion": "salud_get", "ruta": "salud", "ips": sonda, "etiquetar_ip": False,
             **tramo(1, total, 0, VUS_SONDA)},
            {"nombre": "sonda_salud", "funcion": "sonda_salud", "ruta": "sonda_salud", "ips": sonda,
             "etiquetar_ip": False, **tramo(1, total, 0, VUS_SONDA)},
            {"nombre": ESCENARIO_RELLENO, "funcion": ESCENARIO_RELLENO, "ruta": "denuncia",
             **tramo(TASA_RELLENO, relleno_s, BASE_L6_S, VUS_RELLENO)}]


def escenarios_l6_fase2(ips, duracion_s, humo=False):
    """Fase 2 (§3.2): solo el vigía, con la misma IP del legítimo; en el humo,
    legítimo y GET /salud solos (QA-SB), sin la sonda POST /salud."""
    sonda = [ip_de_indice(INDICE_IP_SONDA)]
    esc = [{"nombre": "legitimo", "funcion": "legitimo", "ruta": "seguimiento", "ips": ips["legitimo_l6"],
            "etiquetar_ip": False, **tramo(TASA_LEGITIMO, duracion_s, 0, VUS_LEGITIMO)},
           {"nombre": "salud_get", "funcion": "salud_get", "ruta": "salud", "ips": sonda, "etiquetar_ip": False,
            **tramo(1, duracion_s, 0, VUS_SONDA)}]
    if not humo:
        esc.append({"nombre": "sonda_salud", "funcion": "sonda_salud", "ruta": "sonda_salud", "ips": sonda,
                    "etiquetar_ip": False, **tramo(1, duracion_s, 0, VUS_SONDA)})
    return esc


# --- L7: inundación de /salud ---------------------------------------------------
# Tasa de la inundación: 1,5 x 2/t, la misma de L2 por la regla de las tasas
# (no tiene sentido físico para /salud; así, con las mismas víctimas y fases,
# solo cambia la ruta inundada). Literal de la congelación.
TASA_SALUD_CONGELADA = 153.06
# Control de que la inundación existe (solo rebaja un PASA): 0,95 x 153,06 x
# 120 = 17 448,84, hacia arriba.
UMBRAL_INUNDACION_L7 = 17449
# H4: la API llega a un núcleo si su CPU media en la INUNDACIÓN es de al menos
# el 90 % de una CPU.
UMBRAL_H4_CPU = 90.0


def control_inundacion(respuestas_200):
    """Si la inundación existió: al menos 17 449 respuestas 200 de GET /salud."""
    return respuestas_200 >= UMBRAL_INUNDACION_L7


def evaluar_h4(degradacion, cpu_api_media):
    """H4 (información, §4): NO EVALUADA sin degradación y por debajo del 90 %;
    REFUTA con degradación por debajo o sin degradación por encima; CONFIRMA
    con degradación por encima. Sin CPU medida, SIN CONCLUSION."""
    if cpu_api_media is None:
        return "SIN CONCLUSION"
    llega = cpu_api_media >= UMBRAL_H4_CPU
    if llega:
        return "CONFIRMA" if degradacion else "REFUTA"
    return "REFUTA" if degradacion else "NO EVALUADA"


def escenarios_l7(tasas, ips):
    """L7: las víctimas de L2 a 5/s (50 VUs) durante 390 s, cada una desde su
    rango (E4 sobre 390 s), la sonda POST /salud a 1/s y la inundación de GET
    /salud a 1,5 x 2/t con 600 VUs desde una sola IP durante la INUNDACIÓN."""
    fases = fases_de("l7")
    total = fases[-1]["hasta_s"]
    carga = fase_por_nombre(fases, "carga")
    funciones = {"denuncia": "denuncia_ip", "seguimiento": "seguimiento_ip", "web_seguimiento": "web_ip"}
    esc = [{"nombre": ruta, "funcion": funciones[ruta], "ruta": ruta, "ips": ips[ruta], "etiquetar_ip": False,
            **tramo(TASA_VICTIMA, total, 0, 50)} for ruta in SLO_VICTIMAS_MS]
    esc.append({"nombre": "sonda_salud", "funcion": "sonda_salud", "ruta": "sonda_salud",
                "ips": [ip_de_indice(INDICE_IP_SONDA)], "etiquetar_ip": False, **tramo(1, total, 0, VUS_SONDA)})
    esc.append({"nombre": "inundacion_salud", "funcion": "salud_get", "ruta": "salud", "ips": ips["inundacion"],
                "etiquetar_ip": False, **tramo(tasas["inundacion"], carga["hasta_s"] - carga["desde_s"],
                                               carga["desde_s"], TOPE_VUS)})
    return esc


# ---------------------------------------------------------------------------
# L2, L3, L3b y L4: análisis de una repetición (funciones puras sobre las filas
# del CSV, sin Docker) y E/S con Docker de la ejecución
# ---------------------------------------------------------------------------
# Partes de cada prueba, cada una con su veredicto y su validez propia: L3b da
# dos, L3b-a (oraculo por IP y ventana) y L3b-b (victimas), nunca uno conjunto
# (H4, E15).
PARTES = {"l2": ("l2",), "pico": ("pico",), "l3": ("l3",), "l3b": ("l3b-a", "l3b-b"),
          "l5": ("l5",), "l6": ("l6", "salud_l6", "h5"), "l7": ("l7", "h4")}
# Partes que son INFORMACIÓN, no veredicto: se publican en su propia línea y
# nunca cambian el RESULTADO GLOBAL (salud_l6, h5 y h4, plan v3.2, §3.8 y §4).
PARTES_INFORMATIVAS = ("salud_l6", "h5", "h4")
# Lo que dice la salida cuando L3b-b da FALLA por el oraculo de las victimas (B1)
# (E15): cuenta para el RESULTADO GLOBAL como cualquier otra prueba, aunque el
# diseño la espere. Si la FALLA sale de la muerte de un servicio de Canario, el
# diseño NO la esperaba (E17): linea_l3b_b da otra linea.
LINEA_L3B_B_FALLA = "L3b-b: FALLA (esperada por el diseño; NO OK; misma amenaza que L2, threat-model §8, ABIERTA)"
# Con PASA y B2 cumplido (E17): literal, sin ninguna cifra de IPs para que no se
# lea como una cota del coste.
LINEA_L3B_B_PASA = ("L3b-b: PASA con B2 cumplido: en este montaje (IPv4, 102,04/s, 300 s) las víctimas no se degradaron; "
                    "no se da cifra de coste (E15); no cierra threat-model §8 l.760-764, que sigue ABIERTA; la "
                    "diferencia con L2 se explica en el informe")


def linea_l3b_b(veredicto, motivos, control_ataque):
    """Texto de la linea de L3b-b (E15, E17) o None si no hay linea propia:
    FALLA del oraculo de las victimas = literal de E15; FALLA por la muerte de un
    servicio de Canario = su propia linea con los motivos y sin cifra de coste;
    PASA con B2 cumplido = el literal de E17; con SIN CONCLUSION (o con PASA sin
    B2, que veredicto_con_validez ya rebaja) no se imprime ninguna linea propia."""
    if veredicto == "FALLA":
        if MOTIVO_MUERTE in motivos:
            return "L3b-b: FALLA (murió un servicio de Canario; NO OK); motivos: " + "; ".join(motivos)
        return LINEA_L3B_B_FALLA
    if veredicto == "PASA" and control_ataque is True:
        return LINEA_L3B_B_PASA
    return None
PATRON_EVENTO_503 = re.compile(r"EVENTO (?:limitador_no_disponible|hashes_saturados|limitador_cliente_invalido)")
# Estado de la ejecucion en curso, para el escaneo final de main (S7).
ACTUAL = {"ej": None}


def fallo(motivo):
    """Un fallo de VALIDEZ (J1): da SIN CONCLUSION y gana a FALLA."""
    return {"motivo": motivo}


def humo_ok(checks, etapa):
    """El humo de una etapa (humo_previo o humo_posterior) pasa si sus cuatro
    check (denuncia 201 con código, seguimiento 200 con el texto sembrado,
    formulario 200 y consulta web 200 con el texto) existen y valen todos 1.
    Un paso que falla corta el humo y deja menos de cuatro: también falla."""
    propios = [valor for nombre, valor in checks if nombre.startswith(etapa + ":")]
    return len(propios) == 4 and all(valor == 1 for valor in propios)


def veredicto_humo(checks, etapa):
    """Veredicto del humo de una etapa programada (plan v4.2, cambio 6): con 0
    check el humo no se ejecutó y no demuestra nada, ni bueno ni malo: SIN
    CONCLUSION. Con alguno, humo_ok decide: PASA o FALLA (un check a 0 sigue
    siendo FALLA)."""
    if not any(nombre.startswith(etapa + ":") for nombre, _ in checks):
        return "SIN CONCLUSION"
    return "PASA" if humo_ok(checks, etapa) else "FALLA"


def humo_previo_antes_del_pico(filas, inicio_carga):
    """Control de validez del humo previo (plan v4.2, cambio 2): su última
    petición tiene que terminar antes del inicio de la carga, porque un PASA
    medido bajo el pico no vale como humo previo. filas: TODAS las del CSV,
    antes del filtro que quita el humo; las del humo previo se reconocen por
    etapa=humo_previo (extra_tags). El reloj es el FIN de la petición (la marca
    del CSV) y inicio_carga es t0 + desde_s de la fase carga, el mismo de H15.
    Sin filas del humo previo no decide (ok): lo hace veredicto_humo. Devuelve
    (ok, texto)."""
    fines = [f["fin"] for f in filas if f["etapa"] == "humo_previo"]
    if not fines:
        return True, "sin peticiones del humo previo: decide su veredicto"
    margen = inicio_carga - max(fines)
    if margen < 0:
        return False, (f"la ultima peticion del humo previo termina {-margen:.2f} s despues del inicio de la carga: "
                       "un PASA medido bajo el pico no vale como humo previo")
    return True, f"la ultima peticion del humo previo termina {margen:.2f} s antes del inicio de la carga"


def evaluar_alineacion(primer_inicio, frontera_s, tolerancia_s=3.0):
    """Control de que la carga empezó donde debía (validez): el inicio de la
    primera petición cae entre el instante programado (una frontera de ventana
    en L3 y L3b; t0 más el inicio del escenario en L2 y L4, H15) y
    tolerancia_s después. -0,05 s de holgura por el redondeo al ms de la marca."""
    if primer_inicio is None:
        return False, "no hay peticiones de la carga"
    desfase = primer_inicio - frontera_s
    if -0.05 <= desfase <= tolerancia_s:
        return True, f"la carga empieza {desfase:.2f} s despues de lo programado"
    return False, f"la carga empieza {desfase:.2f} s respecto a lo programado (debe estar entre 0 y {tolerancia_s} s)"


def validez_generador(k6, t0, datos_csv, insuficientes, cpu, es_http=False, codigos_validos=(0,)):
    """Fallos de validez del generador y de la ejecución de k6 (J1, A1): código
    de k6 u OOM, los SIN CONCLUSION de ejecutar_k6, falta de T0 o alineación
    perdida, CPU de k6 sobre el umbral o sin medir, descartes sin el aviso
    Insufficient VUs, filas ilegibles del CSV (PY-2), protocolo distinto de
    HTTP/1.1 y respuestas 421.

    codigos_validos (con nombre, por defecto solo 0): la fase 1 de L6 aborta a
    propósito con exec.test.abort y k6 sale con 108; ahí se pasa (0, 108) y la
    regla de RELLENO_PARADO (validez_codigo_fase1) decide si ese 108 vale. Los
    llamantes de antes no cambian. None (plazo vencido, ejecutar_k6) nunca
    está en la tupla: un k6 que no terminó no es válido."""
    fallos = []
    if k6["codigo"] not in codigos_validos or k6["oom"]:
        fallos.append(fallo(f"k6 termina con codigo {k6['codigo']} (OOMKilled {k6['oom']})"))
    fallos += [fallo(m) for m in k6["sin_conclusion"]]
    if t0 is None:
        fallos.append(fallo("la salida de k6 no trae exactamente una linea T0_MS: no hay reloj de fases"))
    if PATRON_ALINEACION_PERDIDA.search(k6["registro"]):
        fallos.append(fallo("k6 llego tarde al instante de alineacion (ALINEACION_PERDIDA)"))
    if k6["desfase"] is None:
        fallos.append(fallo(f"CPU sin evaluar: {k6['motivo_desfase']}"))
    elif cpu.get("k6") is None:
        fallos.append(fallo("sin muestras de docker stats de k6: no se sabe si el generador se saturo"))
    elif cpu["k6"]["maxima"] > UMBRAL_CPU_K6:
        fallos.append(fallo(f"CPU de k6 {cpu['k6']['maxima']:.0f} % supera el {UMBRAL_CPU_K6:.0f} %: generador saturado"))
    for escenario, marcas in sorted(datos_csv["descartes"].items()):
        if marcas and escenario not in insuficientes:
            fallos.append(fallo(f"{escenario}: {len(marcas)} iteraciones descartadas sin el aviso de VUs insuficientes"))
    if datos_csv.get("ilegibles"):
        # El motivo lleva la columna que faltaba (plan v4.2, cambio 5): sin él, un
        # cambio de cabecera de k6 se vería solo como un número.
        detalle = datos_csv.get("motivos_ilegibles", {})
        fallos.append(fallo(f"{datos_csv['ilegibles']} filas ilegibles en el CSV de k6"
                            + (f" ({dict(sorted(detalle.items()))})" if detalle else "")))
    filas = datos_csv["filas"]
    if not filas:
        fallos.append(fallo("el CSV de k6 no tiene peticiones"))
    else:
        veredicto, texto = evaluar_protocolo(collections.Counter(f["proto"] for f in filas if f["estado"] != 0))
        if veredicto != "PASA":
            fallos.append(fallo(texto))
    if es_http and any(f["estado"] == 421 for f in filas):
        fallos.append(fallo("respuestas 421: el Host de produccion no llego al sitio (sitio por defecto)"))
    return fallos


def cpu_en_ventana(rutas_stats, desfase, desde, hasta):
    """CPU de cada contenedor en [desde, hasta] (reloj de la VM) a partir de los
    ficheros de docker stats (reloj del host, corregido con desfase)."""
    por_contenedor = collections.defaultdict(list)
    for ruta in rutas_stats:
        for marca, objeto in leer_estadisticas(ruta):
            if desde + desfase <= marca <= hasta + desfase:
                valor = porcentaje(objeto.get("CPUPerc", ""))
                if valor is not None:
                    nombre = objeto.get("Name", "")
                    corto = "k6" if f"{PREFIJO_EFIMEROS}k6_" in nombre else nombre.removeprefix(f"{PROYECTO}-").removesuffix("-1")
                    por_contenedor[corto].append(valor)
    return {n: {"media": statistics.fmean(v), "maxima": max(v), "muestras": len(v)} for n, v in por_contenedor.items()}


def analizar_victimas(filas, t0, fases, insuficientes, descartes):
    """Las tres víctimas de L2 y L3b por fase (BASE, carga y RECUPERACIÓN sin
    sus primeros 20 s). Devuelve ({ruta: {"base","carga","recup",
    "descartes_aviso"}}, fallos de validez de la BASE). La BASE es el control
    positivo: fuera del SLO, con un 1 % o más de errores, con menos del 99 %
    del estado esperado o con descartes, es SIN CONCLUSION (B1)."""
    base_f, carga_f, recup_f = (fase_por_nombre(fases, n) for n in ("base", "carga", "recup"))
    victimas, fallos = {}, []
    for ruta, slo in SLO_VICTIMAS_MS.items():
        esperado = ESTADO_RUTAS[ruta]
        propias = [f for f in filas if f["nombre"] == ruta]
        base = resumen_filas([f for f in propias if f["fase"] == "base"], esperado)
        carga = resumen_filas([f for f in propias if f["fase"] == "carga"], esperado)
        recup = resumen_filas([f for f in propias if f["fase"] == "recup"
                               and f["inicio"] >= t0 + recup_f["desde_s"] + EXCLUSION_RECUP_S], esperado)
        marcas = descartes.get(ruta, [])
        en_base = sum(1 for d in marcas if t0 + base_f["desde_s"] <= d < t0 + base_f["hasta_s"])
        con_aviso = sum(1 for d in marcas if t0 + carga_f["desde_s"] <= d < t0 + carga_f["hasta_s"]) \
            if ruta in insuficientes else 0
        if not base["peticiones"]:
            fallos.append(fallo(f"{ruta}: la BASE no tiene peticiones"))
        else:
            if base["p95_ms"] > slo:
                fallos.append(fallo(f"{ruta}: la BASE no cumple el SLO (p95 {base['p95_ms']:.0f} ms > {slo} ms)"))
            if base["tasa_errores"] >= UMBRAL_ERRORES:
                fallos.append(fallo(f"{ruta}: la BASE tiene {base['tasa_errores']:.2%} de errores"))
            if base["proporcion_esperado"] < UMBRAL_ESPERADO:
                fallos.append(fallo(f"{ruta}: la BASE tiene solo el {base['proporcion_esperado']:.2%} con el estado "
                                    f"esperado {esperado} ({base['estados']})"))
        if en_base:
            fallos.append(fallo(f"{ruta}: {en_base} descartes en la BASE"))
        victimas[ruta] = {"base": base, "carga": carga, "recup": recup, "descartes_aviso": con_aviso}
    return victimas, fallos


def veredictos_victimas(victimas):
    """{ruta: (veredicto, motivos)} con B1. Sin p95 de BASE no hay con qué
    comparar: SIN CONCLUSION (la BASE ya figura como fallo de validez)."""
    resultado = {}
    for ruta, v in victimas.items():
        if v["base"]["p95_ms"] is None:
            resultado[ruta] = ("SIN CONCLUSION", ["sin BASE"])
        else:
            resultado[ruta] = veredicto_victima(v["base"]["p95_ms"], v["carga"], SLO_VICTIMAS_MS[ruta],
                                                v["descartes_aviso"])
    return resultado


def victimas_medianas(repeticiones):
    """Las víctimas con la MEDIANA de los p95 y de las tasas de error de las
    repeticiones (A1) y la suma de los descartes con aviso. El p95 de la carga
    None (sin respuestas) cuenta como infinito (H5); el de la BASE None deja la
    mediana sin valor (la BASE ya es un fallo de validez)."""
    medianas = {}
    for ruta in SLO_VICTIMAS_MS:
        bases = [r[ruta]["base"]["p95_ms"] for r in repeticiones]
        cargas = [r[ruta]["carga"]["p95_ms"] for r in repeticiones]
        errores = [r[ruta]["carga"]["tasa_errores"] for r in repeticiones if r[ruta]["carga"]["tasa_errores"] is not None]
        medianas[ruta] = {
            "base": {"p95_ms": None if not bases or any(b is None for b in bases) else statistics.median(bases)},
            "carga": {"peticiones": sum(r[ruta]["carga"]["peticiones"] for r in repeticiones),
                      "p95_ms": mediana_p95(cargas), "tasa_errores": statistics.median(errores) if errores else 0.0},
            "descartes_aviso": sum(r[ruta]["descartes_aviso"] for r in repeticiones)}
    return medianas


def analizar_login(filas, t0, fases, insuficientes, descartes, escenario):
    """El login atacado (L2 y L3b) en su fase de carga: p95, errores con la
    definición de B2 (E8: los 503 no cuentan), 503 aparte, tasa servida y
    descartes con aviso. Devuelve el dict y el valor de ataque_efectivo."""
    carga_f = fase_por_nombre(fases, "carga")
    filas_carga = [f for f in filas if f["nombre"] == "login_email" and f["fase"] == "carga"]
    resumen = resumen_filas(filas_carga, ESTADO_RUTAS["login_email"], es_error_login)
    marcas = descartes.get(escenario, [])
    con_aviso = sum(1 for d in marcas if t0 + carga_f["desde_s"] <= d < t0 + carga_f["hasta_s"]) \
        if escenario in insuficientes else 0
    resumen["descartes_aviso"] = con_aviso
    resumen["servida_por_s"] = resumen["peticiones"] / (carga_f["hasta_s"] - carga_f["desde_s"])
    return resumen, ataque_efectivo(resumen["p95_ms"], resumen["tasa_errores"], con_aviso)


def esperas_predichas():
    """B3 y J8, informativo: la espera de las víctimas ~ (TOPE_VUS - 40) / tasa
    de login servida. La magnitud la fija TOPE_VUS, no la tasa del ataque."""
    return (f"espera prevista de las victimas: {TOPE_VUS - 40} / 102,04 = {(TOPE_VUS - 40) / 102.04:.1f} s y "
            f"{TOPE_VUS - 40} / 73 (servida en L1) = {(TOPE_VUS - 40) / 73:.1f} s")


def lineas_fase(titulo, resumen):
    """Una línea de texto de un resumen de filas."""
    return (f"{titulo}: n={resumen['peticiones']} p50/p95/p99 {ms(resumen['p50_ms'])}/{ms(resumen['p95_ms'])}/"
            f"{ms(resumen['p99_ms'])} ms errores={resumen['errores']} estados={resumen['estados']}")


def senales_por_fase(salida_rep, fases, t0, arranques_redis):
    """Señales del log de la API por fase (H3 predice ninguna línea de las
    víctimas; la inundación sí deja login_fallido): {fase: res con senales}.
    arranques_redis es obligatorio (sin valor por defecto): olvidarlo contaría
    todo el resumen del limitador como fuera de la ventana de arranque."""
    lineas_api = leer_log(salida_rep / "log_api.txt")
    otras = {s: leer_log(salida_rep / f"log_{s}.txt") for s in ("redis", "postgres")}
    por_fase = {}
    for f in fases:
        pseudo = {"principal": {"ventana_ms": [(t0 + f["desde_s"]) * 1000, (t0 + f["hasta_s"]) * 1000]}}
        senales_escalon(lineas_api, otras, pseudo, arranques_redis)
        por_fase[f["nombre"]] = pseudo
    return por_fase


def texto_senales(pseudo):
    return ", ".join(f"{n}={s['total']}" + (f" {s['clases']}" if s["clases"] else "")
                     for n, s in pseudo.get("senales", {}).items() if s["total"])


# --- E/S con Docker ---------------------------------------------------------
# Segundos de margen entre ahora y la frontera a la que se alinea la carga de
# L3 y L3b: k6 tiene que arrancar y inicializar hasta 765 VUs antes de que
# setup() espere. Si no llega, k6 avisa (ALINEACION_PERDIDA) y SIN CONCLUSION.
MARGEN_ARRANQUE_S = 120
# Plazo de cada peticion del cliente de control y margen del contenedor (PY-5).
PLAZO_PETICION_CONTROL_S = 15
MARGEN_CLIENTE_S = 60

# Cliente de los controles de configuración: corre en un contenedor de la
# imagen de la API (python, sin red hacia fuera) en la red edge con una IP
# fija. Lee las peticiones de /datos/<fichero>.json y devuelve una línea JSON
# por petición, con la hora de inicio y fin (reloj de la VM). Sin comillas
# dobles ni acentos: se pasa por lista de argumentos con -c. Trae también la
# cabecera Retry-After tal cual llega (texto o None), porque el oráculo de L5
# la valida como literal y no puede recibirla ya convertida.
CODIGO_CLIENTE = (
    "import http.client, json, sys, time\n"
    "peticiones = json.load(open(sys.argv[1], encoding='utf-8'))\n"
    "salida = []\n"
    "for x in peticiones:\n"
    "    cabeceras = {'Host': x['host']}\n"
    "    if x.get('xff'):\n"
    "        cabeceras['X-Forwarded-For'] = x['xff']\n"
    "    cuerpo = x.get('cuerpo')\n"
    "    if cuerpo is not None:\n"
    "        cabeceras['Content-Type'] = 'application/json'\n"
    "    inicio = time.time()\n"
    "    try:\n"
    "        c = http.client.HTTPConnection('caddy', 8080, timeout=15)\n"
    "        c.request(x['metodo'], x['ruta'], body=None if cuerpo is None else cuerpo.encode('utf-8'), headers=cabeceras)\n"
    "        r = c.getresponse()\n"
    "        texto = r.read(2000).decode('utf-8', 'replace')\n"
    "        salida.append({'estado': r.status, 'cuerpo': texto, 'inicio': inicio, 'fin': time.time(),\n"
    "                       'retry_after': r.getheader('Retry-After')})\n"
    "        c.close()\n"
    "    except Exception as e:\n"
    "        salida.append({'estado': 0, 'cuerpo': type(e).__name__, 'inicio': inicio, 'fin': time.time(),\n"
    "                       'retry_after': None})\n"
    "print(json.dumps(salida))\n"
)


def peticion_control(metodo, ruta, host, xff=None, cuerpo=None):
    return {"metodo": metodo, "ruta": ruta, "host": host, "xff": xff, "cuerpo": cuerpo}


def cliente_control(ej, nombre, ip, peticiones):
    """Peticiones en orden desde un contenedor efímero con IP fija en la red
    edge (10.88.1.2 hace de Traefik; 10.88.1.3, de ajeno). Endurecido, con el
    prefijo canario_estres_ y la etiqueta canario.estres, que el detector
    clasifica. El plazo es n x 15 s mas un margen; si vence, docker rm -f y
    PARADA con la causa (PY-5). Devuelve la lista de resultados."""
    (ej.datos / f"{nombre}.json").write_text(json.dumps(peticiones), encoding="utf-8", newline="\n")
    contenedor = f"{PREFIJO_EFIMEROS}cliente_{nombre}"
    plazo = len(peticiones) * PLAZO_PETICION_CONTROL_S + MARGEN_CLIENTE_S
    try:
        # La imagen de la API lleva las etiquetas de compose (project y
        # service=api) y el contenedor las hereda: sin anularlas, `docker
        # compose logs api` (Registro) recogía la salida del cliente, con los
        # cuerpos de los 201 y sus códigos de seguimiento, en log_api.txt (el
        # anti-fuga de L5 lo detectó el 25/11/2026). Vacías, compose ya no lo
        # trata como un servicio de la pila; la clase la sigue dando
        # canario.estres (clase_contenedor).
        r = ejecutar(["docker", "run", "--rm", "--name", contenedor, "--label", "canario.estres=control",
                      "--label", "com.docker.compose.project=", "--label", "com.docker.compose.service=",
                      "--network", RED_EDGE, "--ip", ip, "--read-only", "--cap-drop", "ALL", "--security-opt",
                      "no-new-privileges", "--pids-limit", "64", "--memory", "64m", "--user", USUARIO_API,
                      "--cpuset-cpus", ej.cpus_k6, "--mount", f"type=bind,src={ej.datos},dst=/datos,readonly",
                      "--entrypoint", "python", ej.imagen, "-I", "-c", CODIGO_CLIENTE, f"/datos/{nombre}.json"],
                     timeout=plazo)
    except subprocess.TimeoutExpired:
        ejecutar(["docker", "rm", "-f", contenedor], timeout=120)
        raise Parada(f"el cliente de control {nombre} supera {plazo} s ({len(peticiones)} peticiones): se detiene") from None
    try:
        resultados = json.loads(r.out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise Parada(f"el cliente de control {nombre} no devuelve JSON (codigo {r.rc}): {r.err.strip()[-300:]!r}") from None
    if len(resultados) != len(peticiones):
        raise Parada(f"el cliente de control {nombre} devuelve {len(resultados)} resultados de {len(peticiones)}")
    return resultados


def esperar_ventana(periodo_s, minimo_s):
    """Si quedan menos de minimo_s segundos para que acabe la ventana actual
    (de periodo_s, alineada con el reloj UTC), espera a la siguiente. Reloj de
    la VM (hora_motor_ahora), el mismo que usa la API para sus contadores."""
    resto = periodo_s - hora_motor_ahora() % periodo_s
    if resto < minimo_s:
        p(f"   espera de {resto + 1:.0f} s a la ventana siguiente ({periodo_s} s)")
        time.sleep(resto + 1)


def codigo_inexistente():
    """Código de seguimiento con el formato válido que no existe (8 grupos de
    4 en base32): llega al HMAC y al SELECT."""
    crudo = base64.b32encode(secrets.token_bytes(20)).decode("ascii")
    return "-".join(crudo[i:i + 4] for i in range(0, 32, 4))


def cuerpo_login(ej):
    # L3 no da de alta ninguna empresa: un identificador aleatorio de 32 hex que no
    # existe (el login lo trata como cualquier otro fallo: 401, y cuenta en acceso).
    return json.dumps({"empresa": ej.id_a or secrets.token_hex(16), "email": f"estres-{secrets.token_hex(8)}@estres.invalid",
                       "contrasena": ej.contrasena, "codigo_totp": "000000"})


def peticion_seguimiento(xff):
    return peticion_control("POST", "/v1/seguimiento", HOST_API, xff, json.dumps({"codigo": codigo_inexistente()}))


def linea_control(veredicto, texto):
    p(f"   {veredicto:<14} {texto}")


def controles_configuracion(ej, modo, rep, ips):
    """Los controles de configuración de L3 y L3b antes de medir. PARADA si la
    pila no es la de producción (421, 403, strict). Devuelve los fallos de
    VALIDEZ (cruce de minuto de strict, D3). J5 va aparte (sandwich_j5)."""
    p(f"=== controles de configuracion, repeticion {rep}")
    fallos = []
    # E11: con el Host de produccion, desde 10.88.1.2, la petición llega a la API.
    r = cliente_control(ej, f"c421_r{rep}", IP_TRAEFIK, [peticion_control("POST", "/salud", HOST_API)])
    v, t = evaluar_control_421(r[0]["estado"])
    linea_control(v, "sin 421: " + t)
    if v == "PARADA":
        raise Parada("el Host de produccion no llega a la API: " + t)
    # C3: desde 10.88.1.3 (no es Traefik), el 403 literal de solo_traefik. Sin
    # el Host de produccion daria 421 y el control no probaria nada.
    r = cliente_control(ej, f"c403_r{rep}", IP_AJENA_EDGE, [peticion_control("POST", "/salud", HOST_API)])
    v, t = evaluar_control_403(r[0]["estado"], r[0]["cuerpo"])
    linea_control(v, "403 desde 10.88.1.3: " + t)
    if v == "PARADA":
        raise Parada("Caddyfile.produccion no esta activo para ajenos: " + t)
    # C2/J6/S1: strict, diferencial. 70 peticiones con XFF "<IP falsa que rota>,
    # 198.19.255.254" desde 10.88.1.2 contra seguimiento inexistente cuentan todas
    # para la IP de la derecha; una 71.a con "198.19.255.254, <otra IP
    # reservada>" cuenta para la otra y da 404. Han de caber en un mismo minuto
    # UTC: se empieza siempre al principio de uno (tambien aleja estas
    # peticiones de las de J5 de la repeticion anterior).
    esperar_ventana(60, 60)
    peticiones = [peticion_seguimiento(f"{falsa}, {IP_STRICT}") for falsa in ips["strict_falsas"]]
    peticiones.append(peticion_seguimiento(f"{IP_STRICT}, {ip_de_indice(INDICE_IP_S1)}"))
    r = cliente_control(ej, f"strict_r{rep}", IP_TRAEFIK, peticiones)
    v, t = evaluar_control_strict([x["estado"] for x in r], cruza_frontera(r[0]["inicio"], r[-1]["fin"], 60))
    linea_control(v, "trusted_proxies_strict: " + t)
    if v == "PARADA":
        raise Parada("trusted_proxies_strict no actua: " + t)
    if v != "PASA":
        fallos.append(fallo("control de strict: " + t))
    # D3 (solo L3b): 11 peticiones de login desde cada una de las 10 IPs de control.
    if modo == "l3b":
        esperar_ventana(VENTANA_ACCESO_S, 40)
        peticiones, dueno = [], []
        for ip in ips["control"]:
            for _ in range(LIMITE_ACCESO + 1):
                peticiones.append(peticion_control("POST", "/v1/personal/sesiones", HOST_API, ip, cuerpo_login(ej)))
                dueno.append(ip)
        r = cliente_control(ej, f"d3_r{rep}", IP_TRAEFIK, peticiones)
        por_ip = collections.defaultdict(list)
        for ip, x in zip(dueno, r, strict=True):
            por_ip[ip].append({"inicio": x["inicio"], "fin": x["fin"], "estado": x["estado"]})
        v, motivos = evaluar_d3(por_ip)
        linea_control(v, "D3, 11 peticiones por IP de control en la misma ventana: " + ("; ".join(motivos) or "la 11.a es 429"))
        if v != "PASA":
            fallos.append(fallo("D3: " + "; ".join(motivos)))
    return fallos


# Segundos que tienen que quedar de la ventana de 300 s para empezar el sandwich de
# J5: el positivo, recrear_api (up --wait, acotado por MARGEN_RECREAR_API_S) y el
# negativo tienen que caer en la MISMA ventana, y con 60 s no hay holgura. Si no
# caben, esperar_ventana espera a la siguiente.
MARGEN_SANDWICH_J5_S = 120
# El plazo de recrear_api (MARGEN_RECREAR_API_S, 120 s) se define junto a la
# función, que es quien lo aplica. Aquí solo se suma como peor caso. Sigue SIN
# MEDIR: se contrasta con la línea `recrear_api:` de la primera ejecución.


def sandwich_j5_maximo_s():
    """Peor caso del sandwich de J5: la espera maxima a la ventana
    (MARGEN_SANDWICH_J5_S + 1), recrear_api y los dos clientes de control con su
    plazo (n x PLAZO_PETICION_CONTROL_S + MARGEN_CLIENTE_S): 11 peticiones el
    positivo y 1 el negativo."""
    clientes = sum(n * PLAZO_PETICION_CONTROL_S + MARGEN_CLIENTE_S for n in (LIMITE_ACCESO + 1, 1))
    return MARGEN_SANDWICH_J5_S + 1 + MARGEN_RECREAR_API_S + clientes


def sandwich_j5(ej, modo, rep, ips_previas):
    """J5 como sandwich (H6): entre dos repeticiones se RECREA la API (sal nueva,
    contadores de la API a cero aunque Redis siga vivo) y se comprueba, con la
    misma IP y en la misma ventana, que antes de recrear daba 429 (control
    positivo: una IP saturada en una ventana todavia viva) y despues no. En L3 y
    en L3b es la regla acceso (login con 401, ventana de 300 s): el login con una
    empresa inexistente la consume igual, porque FronteraLimitador cuenta por
    ruta antes de leer el cuerpo (app/limitador.py) y L3 no tiene ninguna empresa.
    La IP es la del control de strict en L3 y una de las del control D3 de la
    repeticion anterior en L3b. Si el positivo no da 429, SIN CONCLUSION: el
    control no puede fallar en vacio. Imprime cuanto tarda (esperar la ventana de
    300 s es lo que mas cuesta). Devuelve los fallos de VALIDEZ."""
    inicio = time.time()
    p(f"=== J5, repeticion {rep}: sandwich alrededor de recrear la API (regla acceso)")
    ip = IP_STRICT if modo == "l3" else ips_previas["control"][0]
    esperar_ventana(VENTANA_ACCESO_S, MARGEN_SANDWICH_J5_S)
    saturar = [peticion_control("POST", "/v1/personal/sesiones", HOST_API, ip, cuerpo_login(ej))
               for _ in range(LIMITE_ACCESO + 1)]
    despues = peticion_control("POST", "/v1/personal/sesiones", HOST_API, ip, cuerpo_login(ej))
    positivo = cliente_control(ej, f"j5pos_r{rep}", IP_TRAEFIK, saturar)[-1]
    recrear_api(ej, rep, etiqueta="J5")
    negativo = cliente_control(ej, f"j5neg_r{rep}", IP_TRAEFIK, [despues])[0]
    v, t = evaluar_j5(positivo, negativo, VENTANA_ACCESO_S, 401)
    linea_control(v, "J5: " + t)
    p(f"   el sandwich de J5 de la repeticion {rep} ha tardado {time.time() - inicio:.0f} s")
    return [] if v == "PASA" else [fallo("J5: " + t)]


def alta_empresa(nombre):
    r = dc("run", "--rm", "-T", "gestion", "alta-empresa", "--nombre", nombre, "--zona", "Europe/Madrid")
    alta = PATRON_ALTA.search(r.out)
    if r.rc != 0 or alta is None:
        raise Parada(f"no se pudo dar de alta la empresa de prueba: {r.err.strip()[-300:]!r}")
    return alta.group(2)


def evaluar_vigilancia(ej, rep, ticks, t_ini, k6_ids, muertos_al_final, desde, hasta):
    """Muertes, huecos del lector, streamers y conciliación de una repetición
    (como evaluar_repeticion de L1, pero devolviendo fallos de validez en vez de
    emitir). "muertes" es la lista de veredictos de veredicto_muerte (FALLA, u
    OOM global de la VM = SIN CONCLUSION): veredicto_con_validez decide (H2). Los
    huecos del lector se acotan a [desde, hasta]: un lector que se corta antes
    del fin del reposo deja hueco (PY-7)."""
    eventos = [e for e in ej.eventos.copia() if e["t"] >= t_ini]
    muertes_ev = muertes_no_esperadas(eventos, ej.mantenimientos)
    fallos, muertes = [], []
    for ev in muertes_ev:
        a, b = ev["t"] - VENTANA_MUERTE_S, ev["t"] + VENTANA_MUERTE_S
        d_oom = delta_serie([(tk["t"], None if tk["padre"] is None else tk["padre"][0]) for tk in ticks], a, b)
        d_kill = delta_serie([(tk["t"], None if tk["padre"] is None else tk["padre"][1]) for tk in ticks], a, b)
        sube_k6 = any(delta_serie([(tk["t"], next((v[0] for h, v in tk["hijos"].items() if k6 in h), None))
                                  for tk in ticks], a, b) > 0 for k6 in k6_ids)
        veredicto, causa = veredicto_muerte(d_oom > 0, d_kill > 0, otro_murio(eventos, ev["id"], a, b,
                                                                            ej.mantenimientos), sube_k6)
        # Nombre y clase en la línea (plan v4.2, cambio 4), como en evaluar_repeticion.
        p(f"   repeticion {rep}: murio {ev['servicio']} ({ev['nombre']}, clase {ev['clase']}, {ev['id'][:12]}, codigo "
          f"{ev['codigo']}): {causa} (padre: oom +{d_oom}, oom_kill +{d_kill}) -> {veredicto}")
        muertes.append(veredicto)
    # Instrumentos propios con una clase que el lanzador no sabe tratar (plan v4.2,
    # cambio 3): los filtros de abajo solo miran "canario" y los ignorarían.
    desconocidos = instrumentos_desconocidos(eventos)
    if desconocidos:
        fallos.append(fallo(f"repeticion {rep}: eventos de contenedores con un valor desconocido de canario.estres: "
                            f"{desconocidos}"))
    huecos = []
    for s in SERVICIOS_PILA:
        serie = [(tk["t"], tk["c"].get(s)) for tk in ticks if desde <= tk["t"] <= hasta]
        huecos += huecos_de_serie(serie, desde=desde, hasta=hasta)
    sin_explicar = huecos_no_explicados(huecos, [e["t"] for e in eventos
                                                 if e["clase"] == "canario" and e["accion"] == "die"])
    if sin_explicar:
        fallos.append(fallo(f"repeticion {rep}: {len(sin_explicar)} huecos del lector de mas de {HUECO_MAXIMO_S} s "
                            f"fuera de una muerte registrada ({sin_explicar[:3]})"))
    if muertos_al_final:
        fallos.append(fallo(f"repeticion {rep}: streamers muertos en el reposo final: {sorted(set(muertos_al_final))}"))
    etiquetados = {s: etiquetar_cgroup([(tk["t"], tk["c"].get(s)) for tk in ticks]) for s in SERVICIOS_PILA}
    ids_rep = {e["id"] for e in eventos if e["clase"] == "canario" and e["accion"] == "start"}
    problemas = conciliar(sum(1 for e in eventos if e["clase"] == "canario" and e["accion"] == "oom"),
                          sum(acumulado_contadores(etiquetados[s][1])["oom"] for s in SERVICIOS_PILA),
                          starts_no_esperados(eventos), sum(ej.reinicios.get(i, 0) for i in ids_rep))
    if problemas:
        fallos.append(fallo(f"repeticion {rep}: el detector no concilia: {'; '.join(problemas)}"))
    reinicios = sum(ej.reinicios.get(i, 0) for i in ids_rep)
    # Los eventos de la repetición vuelven al que llama: C5 los usa.
    return {"fallos": fallos, "muertes": muertes, "reinicios": reinicios, "etiquetados": etiquetados,
            "eventos": eventos}


def memoria_informativa(vig, k6, lector_vivo, fin_reposo):
    """B5 (informativo): la puerta de memoria de R1 sobre la API, con la
    semántica de L1 y sin adaptadores (H12, PY-6): el máximo muestreado sobre
    TODA la ejecución de k6 (inicio_vm a fin_vm) y el reposo de REPOSO_S sin
    tráfico DESPUÉS de k6, con reposo_de_escalon sobre el propio resultado de
    k6 (que lleva fin_vm). La RECUPERACIÓN no es reposo. No cambia el RESULTADO
    GLOBAL."""
    if k6["inicio_vm"] is None or k6["fin_vm"] is None:
        p("   memoria sin ventana de k6")
        return
    muestras = vig["etiquetados"]["api"][0]
    maximo = maximo_memoria(muestras, k6["inicio_vm"], k6["fin_vm"])
    if maximo is None:
        p("   memoria de la API (informativo): sin muestras del lector en la ejecucion de k6")
        return
    ruta = {"lector_vivo_al_final": lector_vivo, "fin_reposo_vm": fin_reposo}
    minimo, motivo = reposo_de_escalon(muestras, k6, None, ruta, maximo[1])
    veredicto, texto, nota = veredicto_escalon_memoria(maximo[0], minimo, motivo)
    p(f"   memoria de la API en toda la ejecucion de k6 (informativo, {veredicto} por muestreo a 4 Hz): {texto}; {nota}")


def preparar_datos_k6(ej, modo, escenarios, humos, fases, alinear_ms, extra=None):
    """El texto de /datos/ejecucion.json (lo único que k6 lee, nada por argv) y
    las listas de IPs de cada escenario, que van APARTE (/datos/ips.json) para
    que l3.js las guarde en SharedArray y no una copia por VU (PY-1). extra:
    campos propios de un modo (L6: la repetición, que fija el bloque de IPs del
    relleno, y si el legítimo imprime cada respuesta, solo en el plan B)."""
    limpios = [{**{k: v for k, v in e.items() if k != "ips"}, "n_ips": len(e["ips"])} if "ips" in e else dict(e)
               for e in escenarios]
    datos = {"modo": modo, "identificador_a": ej.id_a, "identificador_b": ej.id_b, "contrasena": ej.contrasena,
             "texto_humo": ej.texto_humo, "host_api": HOST_API, "host_web": HOST_WEB, "fases": fases,
             "escenarios": limpios, "humos": humos, "alinear_epoch_ms": alinear_ms, **(extra or {})}
    return json.dumps(datos), {e["nombre"]: e["ips"] for e in escenarios if "ips" in e}


def escribir_datos_k6(ej, texto, ips):
    (ej.datos / "ejecucion.json").write_text(texto, encoding="utf-8", newline="\n")
    if ips:
        (ej.datos / "ips.json").write_text(json.dumps(ips), encoding="utf-8", newline="\n")


def estimar_repeticion_s(modo, repeticion=1):
    """Duración estimada (peor caso) de una repetición, con su arranque y la
    espera a la frontera de L3 y L3b. A partir de la repetición 2 de L3 y L3b se
    suma el sandwich de J5 (sandwich_j5_maximo_s), que va al principio de la
    repetición: espera_por_medianoche usa la estimación de la repetición
    concreta.

    L6 (V32-6): 6000 s como margen fijo. Peor caso con fase 2: 300 s de
    arranque + 60 s de BASE + 4500 s de relleno + 20 s de gracefulStop + 300 s
    de fase 2 mínima + 240 s de análisis = 5420 s más el hueco entre fases;
    6000 s cubren un hueco de hasta unos 580 s. Sobrestimar solo alarga la
    espera, y L6 arranca después de las 00:00 UTC."""
    if modo == "l6":
        return ESTIMACION_L6_S
    if modo == "pico":
        # El humo posterior acaba después de la última fase (plan v4.2, cambio 2): la
        # estimación usa su fin con los mismos valores que viajan en humos. Es una
        # estimación, no un plazo.
        duracion = max(fases_de("pico")[-1]["hasta_s"], *(fin_humo(h) for h in humos_pico()))
    else:
        duracion = {"l2": 390, "l3": 300, "l3b": 570, "l7": 390}[modo]
    espera = MARGEN_ARRANQUE_S + (300 if modo == "l3b" else 60) if modo in ("l3", "l3b") else 0
    sandwich = sandwich_j5_maximo_s() if modo in ("l3", "l3b") and repeticion > 1 else 0
    return duracion + REPOSO_S + SOBRECOSTE_S + SOBRECOSTE_REPETICION_S + espera + sandwich


def estimar_total_s(modo, repeticiones):
    """Peor caso de la ejecucion entera: cada repeticion con su estimacion y los controles."""
    return sum(estimar_repeticion_s(modo, rep) for rep in range(1, repeticiones + 1)) + SOBRECOSTE_CONTROLES_S


def comprobar_sonda_descartes(ej):
    """E14 y E16: antes de medir L4, comprueba en k6 las seis condiciones de las
    marcas de dropped_iterations. Si alguna falla, PARADA: la regla de E14 (una
    ventana con algun descarte no cumple) descansa en esa propiedad. El CSV y el
    resumen JSON quedan en la salida de la ejecucion (y entran en el anti-fuga)."""
    # Carga perezosa: solo --pico necesita el fichero; L1, L2, L3 y L3b no dependen de el.
    import sonda_descartes
    # Los avisos de limpieza llegan por el callback `avisar` y salen desde el
    # finally de ejecutar_sonda: se dicen incluso si la medida propaga una
    # excepción, y siempre ANTES de las PARADA de abajo (que se lanzan después de
    # volver). Con una PARADA por delante la ejecución termina, y un contenedor o
    # una red huérfanos quedarían sin mencionar justo cuando más falta hace saberlo.
    marcas, iteraciones, inicio, motivo = sonda_descartes.ejecutar_sonda(
        ejecutar, ej.imagen, IMG_K6, ej.cpus_k6, DIR_ESTRES,
        {"prefijo": PREFIJO_EFIMEROS, "usuario_api": USUARIO_API, "usuario_k6": USUARIO_K6, "memoria_k6": MEMORIA_K6},
        ej.salida, avisar=lambda texto: sinc(f"limpieza de la sonda de descartes: {texto}"))
    if motivo is not None:
        raise Parada("sonda de descartes de k6 (E14): " + motivo)
    veredicto, texto = sonda_descartes.evaluar_marcas(marcas, inicio, iteraciones)
    linea_control(veredicto, "sonda de descartes de k6 (E14): " + texto)
    if veredicto != "PASA":
        raise Parada("las marcas de dropped_iterations de k6 no son las que supone E14: " + texto)


def ejecutar_repeticion_fases(ej, modo, rep, n_reps):
    """Una repetición de L2, L4, L3 o L3b. L2 y L4: pila nueva (down -v, up).
    L3 y L3b: la pila sigue y la API se recrea entre repeticiones dentro del
    sandwich de J5 (la sal es nueva y los contadores de la API empiezan de
    cero; los de Redis sobrevivirian a un down -v sin ninguna ventana viva que
    probar). Despues, controles, una ejecucion de k6, reposo y análisis.
    Devuelve el dict de la repetición."""
    # Enmienda v4.4: precondición explícita. El finally de abajo lee ej.eventos.copia();
    # si ej.eventos faltara (Ejecucion nace con None), el AttributeError taparía la
    # excepción original. Se comprueba aquí, antes de cualquier efecto (sin carpeta,
    # sin Docker y sin hora_motor_ahora), con un fallo visible que dice quién lo crea.
    if ej.eventos is None:
        raise RuntimeError("ejecutar_repeticion_fases: ej.eventos sin iniciar: lo crean ejecutar_l1 y ejecutar_modo "
                           "antes de la primera repetición")
    salida_rep = ej.salida / f"rep{rep}"
    salida_rep.mkdir()
    # L7 usa el arnés de L3 (producción, l3.js, 10.88.1.2) pero con pila nueva por
    # repetición, sin sándwich de J5 y sin alinear (plan v3.2, §4).
    http_prod = modo in ("l3", "l3b", "l7")
    con_sandwich = modo in ("l3", "l3b")
    t_ini = hora_motor_ahora()
    # Enmienda v4.3, punto 2: los eventos de la repetición se guardan en el finally,
    # también con una PARADA o una excepción antes del análisis (la sonda, el
    # CONTROL_421 o ejecutar_k6), que es justo lo que se quiere diagnosticar. El try
    # empieza después de la primera t_ini: si empezara antes, una PARADA de
    # hora_motor_ahora dejaría t_ini sin definir y el NameError del finally la
    # taparía. En L3 y L3b t_ini se reasigna dentro: el finally lee el valor final.
    # guardar_eventos no lanza nunca, así que la excepción que sigue es la original.
    try:
        fallos_previos = []
        if http_prod:
            # PY-9: una repeticion no puede cruzar las 00:00 UTC.
            espera = espera_por_medianoche(t_ini, estimar_repeticion_s(modo, rep))
            if espera:
                p(f"   la repeticion cruzaria las 00:00 UTC: se espera {espera:.0f} s")
                time.sleep(espera)
            t_ini = hora_motor_ahora()
        if con_sandwich and rep > 1:
            fallos_previos += sandwich_j5(ej, modo, rep, ej.plan_ips[rep - 1])
        else:
            preparar_repeticion(ej, rep)
            if rep == 1 and modo == "pico":
                comprobar_sonda_descartes(ej)
            if modo != "l3":
                ej.id_a = alta_empresa("Empresa estres A")
                ej.id_b = alta_empresa("Empresa estres B")
                ej.ids_empresas += [ej.id_a, ej.id_b]
                p(f"   empresas de la repeticion {rep}: A (atacada) y B (la del denunciante) dadas de alta")
        fases = {"l2": fases_de("l2"), "pico": fases_de("pico"), "l3b": fases_de("l3b"), "l7": fases_de("l7"),
                 "l3": [{"nombre": "carga", "desde_s": 0, "hasta_s": 300}]}[modo]
        ips = ej.plan_ips[rep] if http_prod else None
        humos = []
        if modo == "l2":
            escenarios = escenarios_l2(ej.tasas)
        elif modo == "pico":
            escenarios = escenarios_pico(ej.tasas)
            humos = humos_pico()
        elif modo == "l3":
            escenarios = escenarios_l3(ips)
        elif modo == "l7":
            escenarios = escenarios_l7(ej.tasas, ips)
        else:
            escenarios = escenarios_l3b(ej.tasas, ips)
        texto_json, _ = preparar_datos_k6(ej, modo, escenarios, humos, fases, 0)
        mib = comprobar_presupuesto(escenarios, len(humos), len(texto_json.encode("utf-8")))
        sin_holgura = holgura_insuficiente(escenarios)
        if sin_holgura:
            raise Parada(f"VUs sin holgura sobre el SLO de su ruta: {sin_holgura}")
        p(f"   {len(escenarios)} escenarios, memoria estimada de k6 {mib} MiB de {MEMORIA_K6_MIB} MiB")
        with contextlib.ExitStack() as pila:
            # Cada Registro se da de alta en la pila justo al crearlo (PY-8): si el
            # segundo falla al arrancar, el primero se para.
            registros = []
            for servicio in ("redis", "postgres"):
                registro = Registro(servicio, salida_rep / f"log_{servicio}.txt")
                pila.callback(registro.parar)
                registros.append(registro)
            lector = iniciar_lector(ej, f"rep{rep}_{modo}")
            pila.callback(lector.parar)
            stats_ruta = salida_rep / "stats_pila.txt"
            estadisticas = Estadisticas(list(ej.ids.values()), stats_ruta)
            pila.callback(estadisticas.parar)
            registro_api = Registro("api", salida_rep / "log_api.txt")
            pila.callback(registro_api.parar)
            contexto = {"datos": ej.datos, "cpus_k6": ej.cpus_k6, "eventos": ej.eventos,
                        "vigilados": lambda: [ej.eventos, lector, estadisticas, registro_api, *registros]}
            frontera = None
            if http_prod:
                fallos_previos += controles_configuracion(ej, modo, rep, ips)
            if con_sandwich:
                ahora = hora_motor_ahora()
                if modo == "l3":
                    frontera = proxima_frontera(ahora, 60, MARGEN_ARRANQUE_S)
                    t0_objetivo = frontera
                else:
                    carga = fase_por_nombre(fases, "carga")
                    frontera = proxima_frontera(ahora, VENTANA_ACCESO_S, MARGEN_ARRANQUE_S + carga["desde_s"])
                    t0_objetivo = frontera - carga["desde_s"]
                alinear_ms, espera = int(t0_objetivo * 1000), t0_objetivo - ahora
                p(f"   la carga empieza en la frontera "
                  f"{datetime.datetime.fromtimestamp(frontera, datetime.UTC):%H:%M:%S} UTC "
                  f"(reloj de la VM, dentro de {frontera - ahora:.0f} s)")
            else:
                alinear_ms, espera = None, 0
            texto_json, ips_json = preparar_datos_k6(ej, modo, escenarios, humos, fases, alinear_ms)
            escribir_datos_k6(ej, texto_json, ips_json)
            nombre = f"{modo}_rep{rep}"
            salida_k6 = salida_rep / nombre
            salida_k6.mkdir()
            args_red = (["--network", RED_EDGE, "--ip", IP_TRAEFIK] if http_prod
                        else ["--network", f"container:{ej.ids['caddy']}"])
            script = "l3.js" if http_prod else "fases.js"
            k6 = ejecutar_k6(contexto, nombre, script, args_red, espera + duracion_total(escenarios, humos), salida_k6)
            if "CONTROL_421" in k6["registro"] or "CONTROL_SETUP" in k6["registro"]:
                # S10: el control de setup() de k6 (Host de produccion hacia la API y, en L3b, la
                # pagina del denunciante) no se cumple: el montaje no es el de produccion.
                raise Parada("el control de setup() de k6 falla (421 con el Host de produccion, POST /salud distinto "
                             "de 405 o, en L3b, GET /seguimiento distinto de 200): ver k6_salida.txt")
            time.sleep(3)
            time.sleep(REPOSO_S)
            fin_reposo_vm = hora_motor_ahora()
            muertos_al_final = comprobar_vida(contexto["vigilados"](), "reposo final")
            lector_vivo = streamer_vivo(lector)
            registrar_reinicios(ej)
            ticks = lector.copia_ticks()
            time.sleep(3)
        return analizar_repeticion_fases(ej, modo, rep, salida_rep, salida_k6, k6, fases, frontera, fallos_previos,
                                         stats_ruta, ticks, t_ini, muertos_al_final, lector_vivo, fin_reposo_vm, ips)
    finally:
        # ej.eventos.copia() se evalúa aquí, fuera de guardar_eventos, a propósito:
        # que ej.eventos exista lo garantiza la comprobación del principio de esta
        # función (enmienda v4.4), que lanza RuntimeError antes del try si falta; y
        # copia() solo toma el cerrojo y hace list(). Meterla dentro de
        # guardar_eventos obligaría a un except Exception amplio que taparía fallos
        # reales.
        guardar_eventos(salida_rep / "eventos_docker.json", [e for e in ej.eventos.copia() if e["t"] >= t_ini])


def analizar_repeticion_fases(ej, modo, rep, salida_rep, salida_k6, k6, fases, frontera, fallos_previos,
                              stats_ruta, ticks, t_ini, muertos_al_final, lector_vivo, fin_reposo_vm, ips):
    """Veredicto de cada parte de una repetición a partir del CSV, de los logs y
    de la vigilancia. Devuelve {"modo", "repeticion", "muertes", "reinicios",
    "comun" (fallos de validez comunes), "partes" ({nombre: {"resultado",
    "validez", "control_ataque", "detalle"}}), "veredictos" ({nombre:
    (veredicto, motivos)})}; agregar_fases los combina."""
    p(f"=== analisis de la repeticion {rep} ({modo})")
    csv_k6 = salida_k6 / "k6.csv"
    t0 = leer_t0(k6["registro"])
    comun = []
    if not csv_k6.is_file():
        comun.append(fallo("k6 no dejo el CSV"))
        datos = {"filas": [], "descartes": {}, "retry": [], "checks": [], "ilegibles": 0, "motivos_ilegibles": {}}
    else:
        datos = leer_csv_fases(csv_k6)
    insuficientes = set(PATRON_INSUFICIENTES.findall(k6["registro"]))
    cpu = {}
    if t0 is not None and k6["desfase"] is not None:
        cpu = cpu_en_ventana([salida_k6 / "stats.txt", stats_ruta], k6["desfase"], t0, t0 + fases[-1]["hasta_s"])
    comun += validez_generador(k6, t0, datos, insuficientes, cpu, es_http=modo in MODOS_PRODUCCION)
    desde = k6["inicio_vm"] if k6["inicio_vm"] is not None else t_ini
    vig = evaluar_vigilancia(ej, rep, ticks, t_ini, {k6["k6_id"]}, muertos_al_final, desde, fin_reposo_vm)
    comun += vig["fallos"]
    if modo == "pico" and rep == 1:
        # C5 (plan v4.2, cambio 7): la sonda de descartes corre en la repetición 1,
        # después de t_ini; su servidor tiene que morir clasificado como sonda.
        ok_c5, texto_c5 = control_c5(vig["eventos"])
        p(f"   control C5: {'PASA' if ok_c5 else 'SIN CONCLUSION'}: {texto_c5}")
        if not ok_c5:
            comun.append(fallo("C5: " + texto_c5))
    # Medianoche UTC (C8): la sal y los contadores empiezan de cero.
    if k6["inicio_vm"] is not None and k6["fin_vm"] is not None and cruza_frontera(k6["inicio_vm"], k6["fin_vm"], 86400):
        comun.append(fallo("la repeticion cruza las 00:00 UTC: la sal del limitador cambia y los contadores empiezan "
                           "de cero"))
    p("   CPU por contenedor (media/maxima, % de una CPU): "
      + ", ".join(f"{n} {c['media']:.0f}/{c['maxima']:.0f}" for n, c in sorted(cpu.items())))
    filas = [f for f in datos["filas"] if not f["nombre"].startswith("humo")]
    # Las partes informativas (h4) no llevan veredicto propio por repetición.
    nombres = [n for n in PARTES[modo] if n not in PARTES_INFORMATIVAS]
    if t0 is None or not filas:
        partes = {n: {"resultado": "SIN CONCLUSION", "validez": [], "control_ataque": None, "detalle": {}}
                  for n in nombres}
        partes[nombres[0]]["validez"] = list(fallos_previos)
    elif modo == "l2":
        partes, extra = analizar_l2(filas, datos, t0, fases, insuficientes, salida_rep, vig, k6, lector_vivo, fin_reposo_vm,
                                   arranques_redis_desde(ej, t_ini))
        comun += extra
    elif modo == "pico":
        partes, extra = analizar_pico(filas, datos, t0, fases, insuficientes, vig["reinicios"])
        comun += extra
    elif modo == "l3":
        partes = analizar_l3(filas, datos, t0, frontera, fallos_previos, salida_rep, fases, ips,
                               arranques_redis_desde(ej, t_ini))
    elif modo == "l7":
        partes, extra = analizar_l7(filas, datos, t0, fases, insuficientes, salida_rep, k6, stats_ruta,
                                    fallos_previos, arranques_redis_desde(ej, t_ini))
        comun += extra
    else:
        partes = analizar_l3b(filas, datos, t0, frontera, fases, insuficientes, fallos_previos, salida_rep, ips)
    veredictos = {}
    for n, parte in partes.items():
        veredictos[n] = veredicto_con_validez(parte["resultado"], comun + parte["validez"], parte["control_ataque"],
                                              vig["muertes"])
        motivos = veredictos[n][1]
        p(f"   repeticion {rep}, {n}: {veredictos[n][0]}" + (f" ({'; '.join(motivos)})" if motivos else ""))
    return {"modo": modo, "repeticion": rep, "muertes": vig["muertes"], "reinicios": vig["reinicios"], "comun": comun,
            "partes": partes, "veredictos": veredictos}


def analizar_l2(filas, datos, t0, fases, insuficientes, salida_rep, vig, k6, lector_vivo, fin_reposo_vm,
                arranques_redis):
    victimas, f_base = analizar_victimas(filas, t0, fases, insuficientes, datos["descartes"])
    login, efectivo = analizar_login(filas, t0, fases, insuficientes, datos["descartes"], "login_email")
    veredictos = veredictos_victimas(victimas)
    resultado = veredicto_l2(veredictos)
    p("   victimas (BASE -> INUNDACION; veredicto B1):")
    for ruta, v in victimas.items():
        p("      " + lineas_fase(f"{ruta} BASE", v["base"]))
        p("      " + lineas_fase(f"{ruta} INUNDACION", v["carga"]) + f" descartes con aviso {v['descartes_aviso']} -> "
          f"{veredictos[ruta][0]} {veredictos[ruta][1]}")
        p("      " + lineas_fase(f"{ruta} RECUPERACION (sin los primeros {EXCLUSION_RECUP_S} s)", v["recup"]))
    p("   login inundado: " + lineas_fase("INUNDACION", login) + f" 503={login['n503']} servida {login['servida_por_s']:.1f}/s "
      f"descartes con aviso {login['descartes_aviso']}; el ataque existe (B2): {efectivo}")
    p("   " + esperas_predichas())
    sonda = {f["nombre"]: resumen_filas([x for x in filas if x["nombre"] == "sonda_salud" and x["fase"] == f["nombre"]], 405)
             for f in fases}
    p("   sonda_salud p95 por fase (si suben las dos sondas: CPU, bucle o GIL; solo web_seguimiento: hilos): "
      + ", ".join(f"{n} {ms(s['p95_ms'])} ms" for n, s in sonda.items()))
    senales = senales_por_fase(salida_rep, fases, t0, arranques_redis)
    for f in fases:
        p(f"   senales del log en {f['nombre']}: {texto_senales(senales[f['nombre']]) or 'ninguna'}")
    memoria_informativa(vig, k6, lector_vivo, fin_reposo_vm)
    validez = list(f_base)
    fuera_429 = [f for f in filas if f["estado"] == 429]
    if fuera_429:
        validez.append(fallo(f"{len(fuera_429)} respuestas 429 con los limites de estres (no tocan)"))
    # H15: el reloj de fases. El login empieza donde dice el escenario.
    comun = []
    carga = fase_por_nombre(fases, "carga")
    ok, texto = evaluar_alineacion(min((f["inicio"] for f in filas if f["nombre"] == "login_email"), default=None),
                                   t0 + carga["desde_s"])
    p(f"   reloj de fases (H15): {texto}")
    if not ok:
        comun.append(fallo("reloj de fases: " + texto))
    return {"l2": {"resultado": resultado, "validez": validez, "control_ataque": efectivo,
                   "detalle": {"victimas": victimas, "login": login}}}, comun


def descartes_de_rutas(descartes_csv, t0):
    """E14: los descartes (dropped_iterations) de las 4 rutas de F2, en segundos
    relativos a t0 y ordenados, de CUALQUIER fase y con o sin el aviso de VUs
    insuficientes. Los escenarios de L4 se llaman "<ruta>__<fase>"; la sonda de
    salud (escenario sonda_salud) no es una ruta de F2 y no entra. Cada
    descarte invalida despues, en serie_cumple, las ventanas [s, s + 10) que lo
    contienen, para su ruta."""
    return {ruta: sorted(d - t0 for escenario, marcas in descartes_csv.items()
                         if escenario.startswith(ruta + "__") for d in marcas)
            for ruta in RUTAS_FASES}


def descartes_en_tramo(descartes, desde_s, hasta_s):
    """Cuantos descartes (segundos relativos) caen en [desde_s, hasta_s)."""
    return sum(1 for d in descartes if desde_s <= d < hasta_s)


def analizar_pico(filas, datos, t0, fases, insuficientes, reinicios=0):
    base_f, carga_f, recup_f = (fase_por_nombre(fases, n) for n in ("base", "carga", "recup"))
    fin_pico = carga_f["hasta_s"]
    series_base, series_recup, resumen = {}, {}, {}
    fallos, comun = [], []
    descartes = descartes_de_rutas(datos["descartes"], t0)
    for ruta in RUTAS_FASES:
        propias = [f for f in filas if f["nombre"] == ruta]
        esperado = ESTADO_RUTAS[ruta]
        # H8: en L4 el login usa la definicion de error por defecto (un 503 ES
        # error) y tambien el 99 % del estado esperado. E8 solo vale en L2 y L3b.
        r_base = resumen_filas([f for f in propias if f["fase"] == "base"], esperado)
        resumen[ruta] = {"base": r_base, "pico": resumen_filas([f for f in propias if f["fase"] == "carga"], esperado),
                         "recup": resumen_filas([f for f in propias if f["fase"] == "recup"], esperado)}
        if not r_base["peticiones"]:
            fallos.append(fallo(f"{ruta}: la BASE no tiene peticiones"))
            continue
        slo = SLO_RUTAS_MS[ruta]
        if r_base["p95_ms"] > slo:
            fallos.append(fallo(f"{ruta}: la BASE no cumple el SLO (p95 {r_base['p95_ms']:.0f} ms > {slo} ms)"))
        if r_base["tasa_errores"] >= UMBRAL_ERRORES:
            fallos.append(fallo(f"{ruta}: la BASE tiene {r_base['tasa_errores']:.2%} de errores"))
        if r_base["proporcion_esperado"] < UMBRAL_ESPERADO:
            fallos.append(fallo(f"{ruta}: solo el {r_base['proporcion_esperado']:.2%} de la BASE tiene el estado {esperado}"))
        muestras = [(f["inicio"] - t0, f["dur"]) for f in propias]
        series_base[ruta] = serie_cumple(ventanas_p95(muestras, base_f["desde_s"], base_f["hasta_s"]),
                                         r_base["p95_ms"], slo, descartes[ruta])
        series_recup[ruta] = serie_cumple(ventanas_p95(muestras, fin_pico, recup_f["hasta_s"]), r_base["p95_ms"], slo,
                                          descartes[ruta])
    # E14: un solo descarte de cualquiera de las 4 rutas dentro de la BASE
    # programada es SIN CONCLUSION por validez, se cumpla o no el 95 %.
    en_base = {ruta: descartes_en_tramo(ds, base_f["desde_s"], base_f["hasta_s"]) for ruta, ds in descartes.items()}
    if any(en_base.values()):
        fallos.append(fallo(f"E14: descartes en la BASE programada por ruta {en_base}"))
    p(f"   descartes de k6 por ruta, BASE {en_base}, PICO (solo informativo) "
      f"{ {r: descartes_en_tramo(ds, carga_f['desde_s'], carga_f['hasta_s']) for r, ds in descartes.items()} }, "
      f"RECUPERACION {  {r: descartes_en_tramo(ds, recup_f['desde_s'], math.inf) for r, ds in descartes.items()} }")
    tiempo = None
    if len(series_base) == len(RUTAS_FASES):
        # F2 y J14: el control de la BASE es de validez.
        base_ok, _, motivo = control_base_f2(series_base)
        p(f"   control de la BASE (F2, J14): {'PASA' if base_ok else 'SIN CONCLUSION'}: {motivo}")
        if not base_ok:
            fallos.append(fallo("F2: " + motivo))
        tiempo = segundos_hasta_recuperar(series_recup, fin_pico)
    v_previo = veredicto_humo(datos["checks"], "humo_previo")
    v_posterior = veredicto_humo(datos["checks"], "humo_posterior")
    humo_previo, humo_posterior = v_previo == "PASA", v_posterior == "PASA"
    p(f"   humo previo al pico: {v_previo}; humo posterior (120 s tras el fin programado del pico): {v_posterior}")
    if v_previo == "FALLA":
        fallos.append(fallo("el humo previo al pico falla: el humo posterior no demostraria nada (E5)"))
    # Cambio 6 del plan v4.2: un humo programado con 0 check no se ejecutó. Es de
    # validez y gana a la FALLA que veredicto_recuperacion daría por el posterior.
    for etapa, veredicto in (("humo_previo", v_previo), ("humo_posterior", v_posterior)):
        if veredicto == "SIN CONCLUSION":
            fallos.append(fallo(f"{etapa}: 0 check en el CSV: el humo no se ejecuto"))
    # Cambio 2 del plan v4.2: el humo previo tiene que acabar antes del pico, con el
    # reloj de H15 y sobre todas las filas (datos["filas"], antes del filtro del humo).
    ok_previo, texto_previo = humo_previo_antes_del_pico(datos["filas"], t0 + carga_f["desde_s"])
    p(f"   humo previo antes del pico: {texto_previo}")
    if not ok_previo:
        comun.append(fallo("humo previo: " + texto_previo))
    for ruta, r in resumen.items():
        p("      " + lineas_fase(f"{ruta} BASE", r["base"]))
        p("      " + lineas_fase(f"{ruta} PICO", r["pico"]))
        p("      " + lineas_fase(f"{ruta} RECUPERACION", r["recup"]))
    p(f"   tiempo de recuperacion de esta repeticion: {'no se recupera en los 180 s' if tiempo is None else f'{tiempo} s'}")
    fuera_429 = [f for f in filas if f["estado"] == 429]
    if fuera_429:
        fallos.append(fallo(f"{len(fuera_429)} respuestas 429 con los limites de estres (no tocan)"))
    # H15: el pico empieza donde dice el escenario.
    primer = min((f["inicio"] for f in filas if f["escenario"] == "login_email__carga"), default=None)
    ok, texto = evaluar_alineacion(primer, t0 + carga_f["desde_s"])
    p(f"   reloj de fases (H15): {texto}")
    if not ok:
        comun.append(fallo("reloj de fases: " + texto))
    resultado, _ = veredicto_recuperacion(math.inf if tiempo is None else tiempo, reinicios, humo_posterior)
    return {"pico": {"resultado": resultado, "validez": fallos, "control_ataque": None,
                     "detalle": {"tiempo": tiempo, "humo_posterior": humo_posterior, "humo_previo": humo_previo}}}, comun


def filas_de_ip(filas, escenario):
    """Filas con etiqueta ip del escenario, en el formato de contar_por_ip_ventana."""
    return [{"ip": f["ip"], "inicio": f["inicio"], "fin": f["fin"], "estado": f["estado"]}
            for f in filas if f["escenario"] == escenario and f["ip"] is not None]


def analizar_carga_por_ip(filas, datos, escenario, aceptado, limite, ventana_s, frontera, esperadas, fallos):
    """El oráculo por IP y ventana (C1, J2, J3, E7, H11) de L3 y L3b, con sus
    controles de validez (J2, alineación y conjunto de IPs, PY-3), que se
    añaden a fallos. Devuelve (veredicto, texto, pares)."""
    propias = filas_de_ip(filas, escenario)
    pares = contar_por_ip_ventana(propias, ventana_s, aceptado)
    ok, motivos = control_l3(pares, limite)
    p(f"   control positivo (J2): {'PASA' if ok else 'SIN CONCLUSION'} {motivos}")
    if not ok:
        fallos.append(fallo("J2: " + "; ".join(motivos)))
    alineada, texto_alineacion = evaluar_alineacion(min((f["inicio"] for f in propias), default=None), frontera)
    p(f"   alineacion con la frontera: {texto_alineacion}")
    if not alineada:
        fallos.append(fallo("alineacion con la frontera: " + texto_alineacion))
    for motivo in validar_ips_vistas(filas, escenario, esperadas):
        p(f"   IPs vistas: {motivo}")
        fallos.append(fallo("IPs vistas: " + motivo))
    n429 = sum(1 for f in propias if f["estado"] == 429)
    invalidos = retry_after_invalidos(datos["retry"], n429, ventana_s)
    veredicto, texto = veredicto_l3(pares, limite, invalidos)
    p(f"   oraculo por IP y ventana ({sum(1 for x in pares.values() if x['peticiones'])} pares, {n429} respuestas 429, "
      f"{invalidos} Retry-After no validos): {veredicto}: {texto}")
    return veredicto, texto, pares


def informar_503(filas, salida_rep):
    """H14 (informativo): los 503 de k6 conciliados uno a uno, por hora, con las
    líneas EVENTO del log de la API."""
    marcas = [m for m, msg in leer_log(salida_rep / "log_api.txt") if PATRON_EVENTO_503.search(msg)]
    intervalos = [(f["inicio"], f["fin"]) for f in filas if f["estado"] == 503]
    c = conciliar_503(intervalos, marcas)
    p(f"   informacion (H14): {len(intervalos)} respuestas 503 en k6 y {len(marcas)} lineas EVENTO en el log de la "
      f"API: {c['emparejados']} emparejadas por hora (2 s de tolerancia), {c['sin_evento']} 503 sin linea, "
      f"{c['eventos_sin_503']} lineas sin 503")


def analizar_l3(filas, datos, t0, frontera, fallos_previos, salida_rep, fases, ips, arranques_redis):
    validez = list(fallos_previos)
    veredicto, texto, pares = analizar_carga_por_ip(filas, datos, "seguimiento_ips", 404, LIMITE_SEGUIMIENTO,
                                                    VENTANA_SEGUIMIENTO_S, frontera, ips["carga"], validez)
    propias = [f for f in filas if f["escenario"] == "seguimiento_ips"]
    otros_429 = [f for f in filas if f["estado"] == 429 and f["escenario"] != "seguimiento_ips"]
    if otros_429:
        validez.append(fallo(f"{len(otros_429)} respuestas 429 donde no toca (sonda de salud, exenta)"))
    sin_error = [f for f in propias if f["estado"] not in (0, 429, 503)]
    if sin_error and sum(1 for f in sin_error if f["estado"] == 404) / len(sin_error) < UMBRAL_ESPERADO:
        validez.append(fallo("menos del 99 % del estado esperado (404) entre las respuestas que no son error"))
    # Información (no oráculo): caudal aceptado, p95, defecto de la ventana fija, 503 y sonda.
    aceptadas = [f for f in propias if f["estado"] == 404]
    duracion = fases[-1]["hasta_s"]
    en_primeros_40 = sum(1 for f in aceptadas if (f["inicio"] % 60) < 40)
    p(f"   informacion: caudal aceptado {len(aceptadas) / duracion:.1f}/s de media sobre 300/s ofrecidos; "
      f"{en_primeros_40 / max(1, len(aceptadas)):.0%} cae en los primeros 40 s de cada minuto (ventana fija alineada con el reloj UTC)")
    p("   informacion: " + lineas_fase("seguimiento", resumen_filas(propias, 404)))
    maximo, ip_max = maximo_deslizante({ip: [f["inicio"] for f in aceptadas if f["ip"] == ip]
                                        for ip in {f["ip"] for f in aceptadas}}, 60)
    p(f"   informacion (defecto de la ventana fija, l.695): maximo aceptado por una IP en un tramo deslizante de 60 s = "
      f"{maximo} (se espera como mucho 120; IP {ip_max})")
    senales = senales_por_fase(salida_rep, fases, t0, arranques_redis)["carga"]
    p(f"   informacion (H-R): senales del log: {texto_senales(senales) or 'ninguna'}")
    informar_503(filas, salida_rep)
    sonda = [f for f in filas if f["nombre"] == "sonda_salud"]
    con_503 = {int(f["inicio"] // 10) for f in propias if f["estado"] == 503}
    p("   informacion (contencion del GIL): p95 de sonda_salud "
      + f"en tramos de 10 s con 503 {ms(percentil(sorted(f['dur'] for f in sonda if int(f['inicio'] // 10) in con_503), 95))} ms, "
      + f"sin 503 {ms(percentil(sorted(f['dur'] for f in sonda if int(f['inicio'] // 10) not in con_503), 95))} ms")
    return {"l3": {"resultado": veredicto, "validez": validez, "control_ataque": None,
                   "detalle": {"texto": texto, "n_pares": len(pares)}}}


def analizar_l3b(filas, datos, t0, frontera, fases, insuficientes, fallos_previos, salida_rep, ips):
    # L3b-a: el oraculo por IP y ventana. Validez propia: J2, D3, J5 y strict (en
    # fallos_previos), la alineacion y el conjunto de IPs.
    validez_a = list(fallos_previos)
    veredicto_a, texto_a, pares = analizar_carga_por_ip(filas, datos, "login_ataque", 401, LIMITE_ACCESO,
                                                        VENTANA_ACCESO_S, frontera, ips["ataque"], validez_a)
    # L3b-b: las victimas. Validez propia: la BASE y los 429 donde no tocan; el
    # control B2 solo actua sobre este.
    victimas, validez_b = analizar_victimas(filas, t0, fases, insuficientes, datos["descartes"])
    login, efectivo = analizar_login(filas, t0, fases, insuficientes, datos["descartes"], "login_ataque")
    veredictos = veredictos_victimas(victimas)
    veredicto_b = veredicto_l2(veredictos)
    p("   victimas (BASE -> ATAQUE; veredicto B1):")
    for ruta, v in victimas.items():
        p("      " + lineas_fase(f"{ruta} BASE", v["base"]))
        p("      " + lineas_fase(f"{ruta} ATAQUE", v["carga"]) + f" descartes con aviso {v['descartes_aviso']} -> "
          f"{veredictos[ruta][0]} {veredictos[ruta][1]}")
        p("      " + lineas_fase(f"{ruta} RECUPERACION (sin los primeros {EXCLUSION_RECUP_S} s)", v["recup"]))
    p("   ataque: " + lineas_fase("ATAQUE", login) + f" 503={login['n503']} servida {login['servida_por_s']:.1f}/s; "
      f"el ataque existe (B2): {efectivo}")
    p("   " + esperas_predichas())
    fuera_429 = [f for f in filas if f["estado"] == 429 and f["escenario"] != "login_ataque"]
    if fuera_429:
        validez_b.append(fallo(f"{len(fuera_429)} respuestas 429 donde no toca (victimas o sonda)"))
    informar_503(filas, salida_rep)
    return {"l3b-a": {"resultado": veredicto_a, "validez": validez_a, "control_ataque": None,
                      "detalle": {"texto": texto_a, "n_pares": len(pares)}},
            "l3b-b": {"resultado": veredicto_b, "validez": validez_b, "control_ataque": efectivo,
                      "detalle": {"victimas": victimas, "login": login}}}


def analizar_l7(filas, datos, t0, fases, insuficientes, salida_rep, k6, stats_ruta, fallos_previos, arranques_redis):
    """L7 (plan v3.2, §4): las víctimas de L2 con B1, el control de que la
    inundación de GET /salud existe (solo rebaja un PASA) y H4 como
    información, con la CPU media de la API en la INUNDACIÓN. Validez propia:
    los controles de configuración, la BASE y los 429 (las víctimas tienen IPs
    de sobra por E4: un 429 es un fallo del montaje)."""
    victimas, validez = analizar_victimas(filas, t0, fases, insuficientes, datos["descartes"])
    validez = list(fallos_previos) + validez
    veredictos = veredictos_victimas(victimas)
    resultado = veredicto_l2(veredictos)
    p("   victimas (BASE -> INUNDACION de /salud; veredicto B1):")
    for ruta, v in victimas.items():
        p("      " + lineas_fase(f"{ruta} BASE", v["base"]))
        p("      " + lineas_fase(f"{ruta} INUNDACION", v["carga"]) + f" descartes con aviso {v['descartes_aviso']} -> "
          f"{veredictos[ruta][0]} {veredictos[ruta][1]}")
        p("      " + lineas_fase(f"{ruta} RECUPERACION (sin los primeros {EXCLUSION_RECUP_S} s)", v["recup"]))
    carga = fase_por_nombre(fases, "carga")
    inundacion = [f for f in filas if f["nombre"] == "salud_get" and f["fase"] == "carga"]
    n200 = sum(1 for f in inundacion if f["estado"] == 200)
    ok_inundacion = control_inundacion(n200)
    p("   inundacion de GET /salud: " + lineas_fase("INUNDACION", resumen_filas(inundacion, 200))
      + f"; control de que la inundacion existe (al menos {UMBRAL_INUNDACION_L7} respuestas 200): {ok_inundacion}")
    cpu_api = None
    if k6["desfase"] is not None:
        cpu = cpu_en_ventana([stats_ruta], k6["desfase"], t0 + carga["desde_s"], t0 + carga["hasta_s"])
        cpu_api = cpu.get("api", {}).get("media")
    h4 = evaluar_h4(resultado == "FALLA", cpu_api)
    p(f"   h4 de esta repeticion (informacion): {h4} (CPU media de la API en la INUNDACION "
      f"{'sin medir' if cpu_api is None else f'{cpu_api:.0f} %'}; umbral {UMBRAL_H4_CPU:.0f} %; "
      f"victimas {resultado})")
    sonda = {f["nombre"]: resumen_filas([x for x in filas if x["nombre"] == "sonda_salud" and x["fase"] == f["nombre"]], 405)
             for f in fases}
    p("   sonda_salud p95 por fase: " + ", ".join(f"{n} {ms(s['p95_ms'])} ms" for n, s in sonda.items()))
    senales = senales_por_fase(salida_rep, fases, t0, arranques_redis)
    for f in fases:
        p(f"   senales del log en {f['nombre']}: {texto_senales(senales[f['nombre']]) or 'ninguna'}")
    fuera_429 = [f for f in filas if f["estado"] == 429]
    if fuera_429:
        validez.append(fallo(f"{len(fuera_429)} respuestas 429 donde no toca (las victimas tienen IPs de sobra)"))
    # H15: la inundación empieza donde dice el escenario.
    comun = []
    ok, texto = evaluar_alineacion(min((f["inicio"] for f in filas if f["escenario"] == "inundacion_salud"),
                                       default=None), t0 + carga["desde_s"])
    p(f"   reloj de fases (H15): {texto}")
    if not ok:
        comun.append(fallo("reloj de fases: " + texto))
    return {"l7": {"resultado": resultado, "validez": validez, "control_ataque": ok_inundacion,
                   "detalle": {"victimas": victimas, "inundacion_200": n200, "inundacion_ok": ok_inundacion,
                               "cpu_api": cpu_api}}}, comun


def agregar_fases(modo, repeticiones, tamano_pedido, fallos_globales=(), controles=None):
    """Veredicto final de cada parte de la prueba (A1, J1, E9, H1, H2, H3, H4).
    Publica el de cada repetición y calcula el global: los resultados de los
    oráculos se combinan con peor_estado (o, en L2, L3b-b y L4, sobre la mediana
    de las repeticiones); la validez (comun de cada repetición, la de la parte y
    los fallos_globales: control final del detector, stream de eventos,
    anti-fuga) entra aparte por fallos; las muertes (veredicto_muerte de cada
    una, repetición por repetición) mandan sobre todo. Devuelve {nombre:
    (veredicto, motivos)}."""
    nombres = PARTES[modo]
    p(f"=== veredicto de {modo} (3 repeticiones validas, A1)")
    for r in repeticiones:
        for n, (v, motivos) in r["veredictos"].items():
            p(f"   repeticion {r['repeticion']}, {n}: {v}" + (f" ({'; '.join(motivos)})" if motivos else ""))
    muertes = [m for r in repeticiones for m in r["muertes"]]
    comun = [f for r in repeticiones for f in r["comun"]] + list(fallos_globales)
    if len(repeticiones) < 3 or tamano_pedido < 3:
        comun.append(fallo(f"solo {len(repeticiones)} repeticiones (A1 exige 3)"))
    finales = {}
    resultados_oraculo = {}
    for nombre in nombres:
        partes = [r["partes"][nombre] for r in repeticiones if nombre in r["partes"]]
        validez = comun + [f for pa in partes for f in pa["validez"]]
        control = None
        detalles = [pa["detalle"] for pa in partes]
        if nombre == "h4":
            # Información (plan v3.2, §4): con la mediana de la CPU de la API y el
            # oráculo B1 de las víctimas sobre las medianas. Nunca entra en finales.
            # Una repetición sin la CPU medida deja H4 sin evaluar (nunca se ignora).
            cpus = [r["partes"]["l7"]["detalle"].get("cpu_api") if "l7" in r["partes"] else None
                    for r in repeticiones]
            cpu = statistics.median(cpus) if cpus and None not in cpus else None
            h4 = evaluar_h4(resultados_oraculo.get("l7") == "FALLA", cpu)
            p(f"   h4 (informacion): {h4} (mediana de la CPU media de la API en la INUNDACION "
              f"{'sin medir en alguna repeticion' if cpu is None else f'{cpu:.0f} %'}; victimas "
              f"{resultados_oraculo.get('l7')})")
            continue
        if nombre in ("l2", "l3b-b", "l7"):
            if detalles and all("victimas" in d for d in detalles):
                medianas = victimas_medianas([d["victimas"] for d in detalles])
                veredictos = veredictos_victimas(medianas)
                resultado = veredicto_l2(veredictos)
                for ruta, (v, motivos) in veredictos.items():
                    p(f"   victima {ruta} (mediana de los p95): {v} {motivos}")
                if nombre == "l7":
                    # El control de L7 se cumple solo si la inundación existió en
                    # CADA repetición (al menos 17 449 respuestas 200).
                    control = all(d["inundacion_ok"] is True for d in detalles)
                else:
                    logins = [d["login"] for d in detalles]
                    errores = [x["tasa_errores"] for x in logins if x["tasa_errores"] is not None]
                    control = ataque_efectivo(mediana_p95([x["p95_ms"] for x in logins]),
                                              statistics.median(errores) if errores else None,
                                              sum(x["descartes_aviso"] for x in logins))
            else:
                resultado = "SIN CONCLUSION"
        elif nombre == "pico":
            tiempos = [d["tiempo"] for d in detalles if "tiempo" in d]
            if tiempos:
                mediana = mediana_recuperacion(tiempos)
                p(f"   tiempos de recuperacion por repeticion: {['no se recupera' if t is None else t for t in tiempos]}; "
                  f"mediana {mediana}")
                resultado, _ = veredicto_recuperacion(mediana, sum(r["reinicios"] for r in repeticiones),
                                                      all(d["humo_posterior"] for d in detalles if "humo_posterior" in d))
            else:
                resultado = "SIN CONCLUSION"
        else:
            resultado = combinar_resultados([pa["resultado"] for pa in partes]) if partes else "SIN CONCLUSION"
        resultados_oraculo[nombre] = resultado
        finales[nombre] = veredicto_con_validez(resultado, validez, control, muertes)
        if controles is not None:
            controles[nombre] = control
        # E15 y E17: sin cota de coste si la FALLA es de una muerte.
        if nombre == "l3b-b" and MOTIVO_MUERTE not in finales[nombre][1]:
            cota = texto_cota_ataque(finales[nombre][0], control, N_IPS_ATAQUE_CONGELADO)
            if cota:
                p(f"   coste del ataque (D5, E15): {cota}; un corte de 30 s: ~{102.04 * 30 / 10:.0f} IPs, o "
                  f"~{102.04 * 30 / 20:.0f} aprovechando la frontera de la ventana fija (aritmetica, sin medir)")
    return finales


# ---------------------------------------------------------------------------
# L5 y L6: E/S con Docker (plan v3.2, §2, §3 y §5.2)
# ---------------------------------------------------------------------------
def abrir_vigilancia(ej, salida_rep, pila, nombre):
    """Los streamers de una repetición (logs de Redis, PostgreSQL y la API, el
    lector de cgroup y docker stats de la pila), cada uno dado de alta en la
    pila al crearlo (PY-8), como en ejecutar_repeticion_fases. Devuelve
    {"lector", "stats_ruta", "contexto"} (el contexto de ejecutar_k6)."""
    registros = []
    for servicio in ("redis", "postgres"):
        registro = Registro(servicio, salida_rep / f"log_{servicio}.txt")
        pila.callback(registro.parar)
        registros.append(registro)
    lector = iniciar_lector(ej, nombre)
    pila.callback(lector.parar)
    stats_ruta = salida_rep / "stats_pila.txt"
    estadisticas = Estadisticas(list(ej.ids.values()), stats_ruta)
    pila.callback(estadisticas.parar)
    registro_api = Registro("api", salida_rep / "log_api.txt")
    pila.callback(registro_api.parar)
    contexto = {"datos": ej.datos, "cpus_k6": ej.cpus_k6, "eventos": ej.eventos,
                "vigilados": lambda: [ej.eventos, lector, estadisticas, registro_api, *registros]}
    return {"lector": lector, "stats_ruta": stats_ruta, "contexto": contexto}


def ejecutar_repeticion_l5(ej, rep):
    """Una repetición de L5 (§2): pila nueva, empresa B, controles de
    configuración, espera a que queden 300 s de la hora UTC, 11 denuncias en
    serie desde una IP y una 12.ª desde otra (información). Los cuerpos se
    quitan nada más volver del cliente (PY-L5)."""
    if ej.eventos is None:
        raise RuntimeError("ejecutar_repeticion_l5: ej.eventos sin iniciar: lo crea ejecutar_modo")
    salida_rep = ej.salida / f"rep{rep}"
    salida_rep.mkdir()
    t_ini = hora_motor_ahora()
    try:
        preparar_repeticion(ej, rep)
        ej.id_b = alta_empresa("Empresa estres B")
        ej.ids_empresas.append(ej.id_b)
        ips = ej.plan_ips[rep]
        with contextlib.ExitStack() as pila:
            vig_io = abrir_vigilancia(ej, salida_rep, pila, f"rep{rep}_l5")
            desde = hora_motor_ahora()
            validez = controles_configuracion(ej, "l5", rep, ips)
            esperar_ventana(VENTANA_DENUNCIA_S, MARGEN_HORA_L5_S)
            resultados = sin_cuerpos(cliente_control(
                ej, f"l5_r{rep}", IP_TRAEFIK, [peticion_denuncia(ej.id_b, ips["l5"][0]) for _ in range(DENUNCIAS_L5)]))
            duodecima = sin_cuerpos(cliente_control(ej, f"l5_otra_r{rep}", IP_TRAEFIK,
                                                    [peticion_denuncia(ej.id_b, ips["l5_otra"][0])]))[0]
            time.sleep(3)
            fin = hora_motor_ahora()
            muertos_al_final = comprobar_vida(vig_io["contexto"]["vigilados"](), "final de L5")
            registrar_reinicios(ej)
            ticks = vig_io["lector"].copia_ticks()
        vig = evaluar_vigilancia(ej, rep, ticks, t_ini, set(), muertos_al_final, desde, fin)
        veredicto, texto = evaluar_l5(resultados)
        p(f"   repeticion {rep}, l5: estados {[r['estado'] for r in resultados]}; Retry-After de la 11.a "
          f"{resultados[-1].get('retry_after')!r}: {veredicto}: {texto}")
        p(f"   informacion: la 12.a denuncia, desde otra IP, da {duodecima['estado']}")
        validez += vig["fallos"]
        if cruza_frontera(t_ini, fin, 86400):
            validez.append(fallo("la repeticion cruza las 00:00 UTC: la sal del limitador cambia"))
        parte = {"resultado": veredicto, "validez": validez, "control_ataque": None, "detalle": {"texto": texto}}
        v = veredicto_con_validez(veredicto, validez, None, vig["muertes"])
        p(f"   repeticion {rep}, l5: {v[0]}" + (f" ({'; '.join(v[1])})" if v[1] else ""))
        return {"modo": "l5", "repeticion": rep, "muertes": vig["muertes"], "reinicios": vig["reinicios"],
                "comun": [], "partes": {"l5": parte}, "veredictos": {"l5": v}}
    finally:
        guardar_eventos(salida_rep / "eventos_docker.json", [e for e in ej.eventos.copia() if e["t"] >= t_ini])


def extra_l6(rep):
    """Campos propios de L6 en ejecucion.json: la repetición (bloque de IPs del
    relleno) y si el legítimo imprime cada respuesta (solo el plan B, que esta
    implementación no activa: la fase 1 lleva CSV)."""
    return {"repeticion": rep, "imprimir_legitimo": False}


def comprobar_control_setup(registro):
    """S10: el control de setup() de l3.js (CONTROL_421 o CONTROL_SETUP) es PARADA."""
    if "CONTROL_421" in registro or "CONTROL_SETUP" in registro:
        raise Parada("el control de setup() de k6 falla (421 con el Host de produccion o POST /salud distinto de 405): "
                     "ver k6_salida.txt")


def ejecutar_fase1_l6(ej, contexto, rep, ips, salida_rep, humo):
    """Fase 1 de L6 (§3.1): vigía y relleno en una ejecución de k6 desde
    10.88.1.2. Devuelve el resultado de ejecutar_k6 con T0, el inicio del
    relleno, T_RP, cuántas RELLENO_PARADO hubo y si el aborto es válido (la
    condición para que exista la fase 2)."""
    escenarios = escenarios_l6_fase1(ips, humo)
    relleno_s = RELLENO_HUMO_S if humo else RELLENO_L6_S
    fases = [{"nombre": "base", "desde_s": 0, "hasta_s": BASE_L6_S},
             {"nombre": "relleno", "desde_s": BASE_L6_S, "hasta_s": BASE_L6_S + relleno_s}]
    texto_json, ips_json = preparar_datos_k6(ej, "l6", escenarios, [], fases, None, extra_l6(rep))
    mib = comprobar_presupuesto(escenarios, 0, len(texto_json.encode("utf-8")))
    sin_holgura = holgura_insuficiente(escenarios)
    if sin_holgura:
        raise Parada(f"VUs sin holgura sobre el SLO de su ruta: {sin_holgura}")
    p(f"=== L6, fase 1 (vigia y relleno{', HUMO' if humo else ''}): memoria estimada de k6 {mib} MiB de "
      f"{MEMORIA_K6_MIB} MiB")
    escribir_datos_k6(ej, texto_json, ips_json)
    nombre = f"l6_rep{rep}_fase1"
    salida = salida_rep / nombre
    salida.mkdir()
    k6 = ejecutar_k6(contexto, nombre, "l3.js", ["--network", RED_EDGE, "--ip", IP_TRAEFIK],
                     duracion_total(escenarios), salida)
    comprobar_control_setup(k6["registro"])
    marcas = marcas_relleno_parado(k6["registro"])
    codigo_ok, t_rp, texto_codigo = validez_codigo_fase1(k6["codigo"], marcas)
    t0 = leer_t0(k6["registro"])
    inicio_relleno = None if t0 is None else t0 + BASE_L6_S
    aborto_valido = (codigo_ok and t_rp is not None and inicio_relleno is not None
                     and "CONTROL_IP" not in k6["registro"])
    p(f"   fase 1: {texto_codigo}; la fase 2 {'se lanza' if aborto_valido else 'no se lanza'}")
    return {"k6": k6, "salida": salida, "t0": t0, "inicio_relleno": inicio_relleno, "t_rp": t_rp,
            "n_parado": len(marcas), "marcas": marcas, "codigo_ok": codigo_ok, "texto_codigo": texto_codigo,
            "aborto_valido": aborto_valido, "mantenimiento": None}


def ejecutar_fase2_l6(ej, contexto, rep, ips, salida_rep, inicio_relleno, humo, ids_fase1):
    """Fase 2 de L6 (§3.2): solo el vigía, en otra ejecución de k6 con la misma
    IP 10.88.1.2 (Caddy solo confía en ella), hasta inicio_relleno + 4290 s o
    I2 + 300 s (30 s en el humo). NO llama a controles_configuracion (N4): con
    Redis lleno, el control strict daría 503 y una PARADA falsa; la
    configuración la cubren los controles de la fase 1 y que los ids de
    Canario sean los mismos."""
    if ids_servicios() != ids_fase1:
        raise Parada("los ids de los contenedores de Canario cambiaron entre las dos fases de L6")
    ahora = hora_motor_ahora()
    # La duración se calcula con el reloj de la VM justo antes de lanzarla (V31-9).
    duracion = FASE2_HUMO_S if humo else math.ceil(fin_fase2(inicio_relleno, ahora) - ahora)
    escenarios = escenarios_l6_fase2(ips, duracion, humo)
    fases = [{"nombre": "vigia", "desde_s": 0, "hasta_s": duracion}]
    texto_json, ips_json = preparar_datos_k6(ej, "l6", escenarios, [], fases, None, extra_l6(rep))
    escribir_datos_k6(ej, texto_json, ips_json)
    p(f"=== L6, fase 2 (solo el vigia, {duracion} s, sin controles de configuracion)")
    nombre = f"l6_rep{rep}_fase2"
    salida = salida_rep / nombre
    salida.mkdir()
    k6 = ejecutar_k6(contexto, nombre, "l3.js", ["--network", RED_EDGE, "--ip", IP_TRAEFIK],
                     duracion_total(escenarios), salida)
    comprobar_control_setup(k6["registro"])
    codigo_ok, texto_codigo = validez_codigo_fase2(k6["codigo"])
    p(f"   fase 2: {texto_codigo}")
    return {"k6": k6, "salida": salida, "t0": leer_t0(k6["registro"]), "codigo_ok": codigo_ok,
            "texto_codigo": texto_codigo, "duracion_s": duracion}


def ejecutar_repeticion_l6(ej, rep, humo=False):
    """Una repetición de L6 (§3), con pila nueva y empresa B. L6 no pasa por
    ejecutar_repeticion_fases, así que comprueba aquí la medianoche (V32-7):
    espera_por_medianoche con la estimación de L6 (6000 s), antes de preparar
    la pila y de los controles de la fase 1."""
    if ej.eventos is None:
        raise RuntimeError("ejecutar_repeticion_l6: ej.eventos sin iniciar: lo crea ejecutar_modo")
    salida_rep = ej.salida / f"rep{rep}"
    salida_rep.mkdir()
    t_ini = hora_motor_ahora()
    try:
        espera = espera_por_medianoche(t_ini, estimar_repeticion_s("l6"))
        if espera:
            p(f"   la repeticion cruzaria las 00:00 UTC: se espera {espera:.0f} s")
            time.sleep(espera)
        t_ini = hora_motor_ahora()
        preparar_repeticion(ej, rep)
        ej.id_b = alta_empresa("Empresa estres B")
        ej.ids_empresas.append(ej.id_b)
        ips = ej.plan_ips[rep]
        with contextlib.ExitStack() as pila:
            vig_io = abrir_vigilancia(ej, salida_rep, pila, f"rep{rep}_l6")
            # Solo aquí, con Redis vacío (§3.1).
            fallos_previos = controles_configuracion(ej, "l6", rep, ips)
            ids_fase1 = dict(ej.ids)
            f1 = ejecutar_fase1_l6(ej, vig_io["contexto"], rep, ips, salida_rep, humo)
            f2 = None
            if f1["aborto_valido"]:
                mantenimiento, fallos_mant = mantenimiento_aborto(ej.eventos, f1["k6"]["k6_id"], f1["t_rp"],
                                                                  hora_motor_ahora)
                ej.mantenimientos.append(mantenimiento)
                f1["mantenimiento"] = mantenimiento
                fallos_previos += fallos_mant
                f2 = ejecutar_fase2_l6(ej, vig_io["contexto"], rep, ips, salida_rep, f1["inicio_relleno"], humo,
                                       ids_fase1)
            time.sleep(3)
            time.sleep(REPOSO_S)
            fin_reposo_vm = hora_motor_ahora()
            muertos_al_final = comprobar_vida(vig_io["contexto"]["vigilados"](), "reposo final")
            registrar_reinicios(ej)
            ticks = vig_io["lector"].copia_ticks()
            time.sleep(3)
        return analizar_l6(ej, rep, salida_rep, f1, f2, fallos_previos, ticks, t_ini, muertos_al_final,
                           fin_reposo_vm, humo)
    finally:
        guardar_eventos(salida_rep / "eventos_docker.json", [e for e in ej.eventos.copia() if e["t"] >= t_ini])


class AgregadorRelleno:
    """Agregador en streaming de las filas del relleno de L6 (unas 675 000
    peticiones; leer_csv_fases guardaría cada una como dict). Se pasa a
    leer_csv_fases como `desviar`: consume las filas http_req_duration del
    escenario del relleno y las del Trend fin_relleno_ms, y deja pasar todo lo
    demás (vigía, descartes, métricas propias). Guarda solo lo que se usa:
    recuentos por estado, las 422 hasta la primera línea OOM, los intervalos de
    los 503 y de los estados 0 (pocos: llegan cuando Redis ya está lleno), el
    fin máximo, O2 de H-GS, los estados 0 cortados por el aborto y cuántas
    peticiones terminaron antes de cada instante pedido (memoria del humo)."""

    def __init__(self, t_rp, t_oom, f1, instantes=()):
        self.t_rp, self.t_oom, self.f1 = t_rp, t_oom, f1
        self.n = 0
        self.estados = collections.Counter()
        self.n_antes_oom = 0
        self.n422_antes_oom = 0
        self.int503, self.int0 = [], []
        self.protos = collections.Counter()
        self.max_fin_ms = None
        self.max_trend_csv = None
        self.o2 = 0
        self.cortados0 = collections.Counter()
        self.latencia_503_ms = None
        self.instantes = list(instantes)
        self.n_hasta = [0] * len(self.instantes)

    def desviar(self, fila):
        metrica = fila.get("metric_name")
        if metrica == "fin_relleno_ms":
            valor = float(fila["metric_value"])
            self.max_trend_csv = valor if self.max_trend_csv is None else max(self.max_trend_csv, valor)
            return True
        if metrica != "http_req_duration" or fila.get("scenario") != ESCENARIO_RELLENO:
            return False
        fin_ms, dur, estado_http = int(fila["timestamp"]), float(fila["metric_value"]), int(fila["status"])
        fin = fin_ms / 1000
        inicio = fin - dur / 1000
        self.n += 1
        self.estados[estado_http] += 1
        if estado_http != 0:
            self.protos[fila["proto"]] += 1
        self.max_fin_ms = fin_ms if self.max_fin_ms is None else max(self.max_fin_ms, fin_ms)
        if self.t_oom is None or fin < self.t_oom:
            self.n_antes_oom += 1
            self.n422_antes_oom += estado_http == 422
        if estado_http == 503:
            self.int503.append((inicio, fin))
            self.latencia_503_ms = dur if self.latencia_503_ms is None else max(self.latencia_503_ms, dur)
        elif estado_http == 0:
            self.int0.append((inicio, fin, fila["error_code"]))
            if self.t_rp is not None and self.t_rp - TOLERANCIA_OOM_S <= fin <= (self.f1 if self.f1 else math.inf):
                self.cortados0[fila["error_code"]] += 1
        if self.t_rp is not None and estado_http != 0 and inicio <= self.t_rp < fin:
            self.o2 += 1
        for k, instante in enumerate(self.instantes):
            if fin <= instante:
                self.n_hasta[k] += 1
        return True


def intervalos_de(filas):
    """(intervalos_503, intervalos_0 con su error_code) de unas filas."""
    return ([(f["inicio"], f["fin"]) for f in filas if f["estado"] == 503],
            [(f["inicio"], f["fin"], f["error_code"]) for f in filas if f["estado"] == 0])


def legitimo_con_ra(filas, retry_503, fase):
    """Respuestas del legítimo de una fase, con el Retry-After de cada 503: en
    orden de fin, cada 503 toma el valor de la etiqueta ra de la siguiente fila
    de retry_after_503_s (k6 la anota justo al volver la petición). Un 503 sin
    fila queda con ra None (R1: SIN CONCLUSION del instrumento). Devuelve
    (respuestas, filas de la métrica que sobran)."""
    propias = sorted((f for f in filas if f["escenario"] == "legitimo"), key=lambda f: f["fin"])
    valores = [ra for _, ra in sorted(retry_503, key=lambda x: x[0])]
    respuestas, usados = [], 0
    for f in propias:
        ra = None
        if f["estado"] == 503:
            ra = valores[usados] if usados < len(valores) else None
            usados += 1
        respuestas.append({"t": f["inicio"], "estado": f["estado"], "ra": ra, "fase": fase, "fin": f["fin"],
                           "dur": f["dur"], "error_code": f["error_code"]})
    return respuestas, max(0, len(valores) - usados)


def muestras_k6(ruta, desfase):
    """[(t VM, contenedor, CPU %, memoria en bytes o None)] de un stats.txt de
    k6, con la hora del host corregida con el desfase de ejecutar_k6."""
    salida = []
    for marca, objeto in leer_estadisticas(ruta):
        cpu = porcentaje(objeto.get("CPUPerc", ""))
        if cpu is None:
            continue
        memoria = bytes_de((objeto.get("MemUsage") or "").split("/")[0])
        salida.append((marca - desfase, objeto.get("Name", ""), cpu, memoria))
    return salida


def analizar_l6(ej, rep, salida_rep, f1, f2, fallos_previos, ticks, t_ini, muertos_al_final, fin_reposo_vm, humo):
    """Análisis de L6 después de las dos fases (§3.3): conciliación, controles,
    validez y veredicto con evaluar_l6; en el humo, además, todo lo de §5.2.
    Devuelve el dict de la repetición; emitir_l6 publica la línea final."""
    p(f"=== analisis de L6, repeticion {rep}" + (" (HUMO)" if humo else ""))
    paradas = []
    validez = list(fallos_previos)
    k1, k2 = f1["k6"], (f2["k6"] if f2 else None)
    t0, inicio, t_rp = f1["t0"], f1["inicio_relleno"], f1["t_rp"]
    f1_vm = k1["fin_vm"]
    i2 = k2["inicio_vm"] if k2 else None
    fin_f2 = k2["fin_vm"] if k2 else None
    if not f1["codigo_ok"]:
        validez.append(fallo("fase 1: " + f1["texto_codigo"]))
    if f2 is not None and not f2["codigo_ok"]:
        validez.append(fallo("fase 2: " + f2["texto_codigo"]))
    for motivo in comprobar_ip_muestras(k1["registro"], rep):
        validez.append(fallo("IP del relleno: " + motivo))
    csv1, resumen1 = f1["salida"] / "k6.csv", f1["salida"] / "resumen.json"
    accion, texto = instrumento_fase1(csv1.is_file(), resumen1.is_file(), humo)
    p(f"   instrumento de la fase 1: {texto}")
    if accion == "PARADA":
        paradas.append(texto)
    elif accion == "SIN CONCLUSION":
        validez.append(fallo(texto))
    log = leer_log(salida_rep / "log_api.txt")
    oom = sorted((m, msg) for m, msg in log if PATRON_OOM.search(msg))
    lineas_oom = [m for m, _ in oom]
    t_oom = lineas_oom[0] if lineas_oom else None
    otras = collections.Counter(msg[msg.index("EVENTO"):] for _, msg in log
                                if "EVENTO limitador_no_disponible" in msg and not PATRON_OOM.search(msg))
    # Memoria de k6 (solo el humo): los dos instantes se fijan antes de leer el
    # CSV para contar en la misma pasada cuántas peticiones acabaron antes.
    muestras1 = muestras_k6(f1["salida"] / "stats.txt", k1["desfase"]) if k1["desfase"] is not None else []
    m1 = m2 = None
    if humo and inicio is not None and t_rp is not None:
        m1 = next(((t, b) for t, _, _, b in muestras1 if t >= inicio + 30 and b is not None), None)
        m2 = max(((t, b) for t, _, _, b in muestras1 if t < t_rp - TOLERANCIA_OOM_S and b is not None), default=None)
    agg = AgregadorRelleno(t_rp, t_oom, f1_vm, [x[0] for x in (m1, m2) if x is not None])
    vacio = {"filas": [], "descartes": {}, "retry": [], "checks": [], "ilegibles": 0, "motivos_ilegibles": {},
             "retry_503": []}
    datos1 = leer_csv_fases(csv1, desviar=agg.desviar) if csv1.is_file() else vacio
    datos2, csv2 = None, None
    if f2 is not None:
        csv2 = f2["salida"] / "k6.csv"
        if csv2.is_file():
            datos2 = leer_csv_fases(csv2)
        else:
            validez.append(fallo("la fase 2 no dejo k6.csv"))
            datos2 = vacio
    # J1 con la CPU de k6 sumada por instante (§3.7): todas las ejecuciones de k6
    # de la repetición, aunque vayan en serie.
    rutas_k6 = [f1["salida"] / "stats.txt"] + ([f2["salida"] / "stats.txt"] if f2 else [])
    cpu_maximas = []
    for fase, k, datos, codigos in ((1, k1, datos1, (0, 108)), (2, k2, datos2, (0,))):
        if k is None:
            continue
        cpu = {}
        if k["desfase"] is not None and k["inicio_vm"] is not None and k["fin_vm"] is not None:
            muestras = [(t, n, c) for ruta in rutas_k6 for t, n, c, _ in muestras_k6(ruta, k["desfase"])
                        if k["inicio_vm"] <= t <= k["fin_vm"]]
            suma = sumar_cpu_por_instante(muestras)
            cpu = {"k6": None if suma is None else {"maxima": suma}}
            if suma is not None:
                cpu_maximas.append(suma)
        insuficientes = set(PATRON_INSUFICIENTES.findall(k["registro"]))
        validez += [fallo(f"fase {fase}: {f['motivo']}") for f in
                    validez_generador(k, leer_t0(k["registro"]), datos, insuficientes, cpu, es_http=True,
                                      codigos_validos=codigos)]
    if agg.n:
        v_proto, t_proto = evaluar_protocolo(agg.protos)
        if v_proto != "PASA":
            validez.append(fallo("relleno: " + t_proto))
        if agg.estados.get(421):
            validez.append(fallo(f"relleno: {agg.estados[421]} respuestas 421 (el Host de produccion no llego)"))
    desde = k1["inicio_vm"] if k1["inicio_vm"] is not None else t_ini
    vig = evaluar_vigilancia(ej, rep, ticks, t_ini, {k1["k6_id"]} | ({k2["k6_id"]} if k2 else set()),
                             muertos_al_final, desde, fin_reposo_vm)
    validez += vig["fallos"]
    fin_ultimo = (k2 or k1)["fin_vm"]
    if k1["inicio_vm"] is not None and fin_ultimo is not None and cruza_frontera(k1["inicio_vm"], fin_ultimo, 86400):
        validez.append(fallo("la repeticion cruza las 00:00 UTC: la sal del limitador cambia y los contadores "
                             "empiezan de cero"))
    leg1, sobran1 = legitimo_con_ra(datos1["filas"], datos1["retry_503"], 1)
    leg2, sobran2 = legitimo_con_ra(datos2["filas"], datos2["retry_503"], 2) if datos2 is not None else ([], 0)
    if sobran1 or sobran2:
        validez.append(fallo(f"instrumento del Retry-After: {sobran1 + sobran2} filas de retry_after_503_s sin su 503 "
                             "del legitimo"))
    salud = [{"t": f["inicio"], "estado": f["estado"], "fase": fase}
             for fase, datos in ((1, datos1), (2, datos2)) if datos is not None
             for f in datos["filas"] if f["escenario"] == "salud_get"]
    n500 = agg.estados.get(500, 0) + sum(1 for datos in (datos1, datos2) if datos is not None
                                          for f in datos["filas"] if f["estado"] == 500)
    # Conciliación: contra las peticiones que pasan por el limitador (relleno y
    # legítimo); /salud está exenta (limitador.py:198) y no explica ninguna línea.
    fase1 = None
    if csv1.is_file():
        i503, i0 = intervalos_de([f for f in datos1["filas"] if f["escenario"] == "legitimo"])
        fase1 = (i503 + agg.int503, i0 + agg.int0)
    fase2 = None
    if f2 is not None and csv2 is not None and csv2.is_file():
        fase2 = intervalos_de([f for f in datos2["filas"] if f["escenario"] == "legitimo"])
    if f1_vm is None or t0 is None:
        validez.append(fallo("sin FinishedAt o sin T0 de la fase 1: no se concilian las lineas OOM"))
        conciliacion = {"falla": [], "sin_conclusion": [], "texto": "sin conciliar"}
    else:
        conciliacion = conciliacion_l6(lineas_oom, t_rp, f1_vm, i2, fin_f2, fase1, fase2, f1["n_parado"])
    p(f"   conciliacion de las lineas OOM (informacion): {conciliacion['texto']}")
    if oom:
        p(f"   primera linea OOM: {oom[0][1][oom[0][1].index('EVENTO'):]}")
    if otras:
        p(f"   otras lineas del limitador (informacion): {dict(otras.most_common(5))}")
    maxmemory = MAXMEMORY_HUMO_B if humo else MAXMEMORY_REAL_B
    claves = agg.n422_antes_oom
    p(f"   relleno: {agg.n} peticiones, estados {dict(sorted(agg.estados.items()))}; claves (422 antes de la "
      f"primera linea OOM) {claves}" + (f"; bytes por clave {maxmemory / claves:.1f} (maxmemory {maxmemory})"
                                       if claves else "")
      + ("" if t_oom is None or inicio is None else f"; primera linea OOM a los {t_oom - inicio:.1f} s del inicio"))
    if cpu_maximas:
        p(f"   CPU de k6 sumada por instante (J1): maxima {max(cpu_maximas):.0f} % (umbral {UMBRAL_CPU_K6:.0f} %)")
    if t0 is None or inicio is None:
        validez.append(fallo("la fase 1 no trae T0: no hay reloj de la BASE ni del relleno"))
        ev = {"resultado": "SIN CONCLUSION", "validez": validez, "falla": [], "oraculo": [],
              "muertes": vig["muertes"],
              "salud_l6": texto_salud_l6(salud, None if i2 is None or f1_vm is None else i2 - f1_vm),
              "h5": ("SIN CONCLUSION", "sin T0 de la fase 1"), "info": []}
    else:
        ev = evaluar_l6({"inicio_relleno": inicio, "t0": t0, "t_rp": t_rp, "i2": i2, "fin_vigilancia": fin_ultimo,
                         "lineas_oom": lineas_oom, "conciliacion": conciliacion, "legitimo": leg1 + leg2,
                         "salud": salud, "hueco_s": None if i2 is None or f1_vm is None else i2 - f1_vm,
                         "n500": n500, "relleno": {"n422": agg.n422_antes_oom, "n": agg.n_antes_oom},
                         "plan_b": None, "validez": validez, "muertes": vig["muertes"]})
    for linea in ev["info"]:
        p("   " + linea)
    if humo:
        paradas += informar_humo_l6(ej, f1, f2, agg, datos1, leg1 + leg2, oom, m1, m2, resumen1, cpu_maximas,
                                    conciliacion)
        if paradas:
            p("HUMO: no es evidencia")
            raise Parada("humo de L6: " + "; ".join(paradas))
    return {"modo": "l6", "repeticion": rep, "humo": humo, "ev": ev, "conciliacion": conciliacion["texto"],
            "muertes": vig["muertes"], "reinicios": vig["reinicios"]}


def informar_humo_l6(ej, f1, f2, agg, datos1, legitimo, oom, m1, m2, resumen1, cpu_maximas, conciliacion):
    """Lo que imprime el humo (§5.2), con su criterio escrito antes de verlo.
    Devuelve los motivos de PARADA (la lista vacía si no hay ninguno)."""
    paradas = []
    k1, t_rp = f1["k6"], f1["t_rp"]
    f1_vm = k1["fin_vm"]
    p("=== humo de L6 (informacion; no es evidencia)")
    # La ACL de la pila (scripts/generar_secretos.py:59-62) solo deja ping, multi,
    # exec, incr, expire, ttl y client|setinfo al usuario aplicacion y desactiva
    # default: INFO no está permitido y los secretos no se leen. Se dice, no se
    # sustituye por otra cifra.
    p("   MEMORIA_INICIAL del Redis de la pila: no medible (la ACL de la pila no permite INFO al usuario "
      "aplicacion y default esta desactivado; ver la sonda A)")
    if t_rp is None:
        paradas.append(f"el humo no lleno Redis con maxmemory {MAXMEMORY_HUMO} en {RELLENO_HUMO_S} s (sin "
                       "RELLENO_PARADO)")
        return paradas
    csv1 = f1["salida"] / "k6.csv"
    h_csv = (k1["codigo"] == 108 and f1["n_parado"] >= 1 and csv1.is_file() and datos1["ilegibles"] == 0
             and agg.max_fin_ms is not None and agg.max_fin_ms / 1000 >= t_rp - 1 and resumen1.is_file())
    p(f"   H-CSV: {'cierta' if h_csv else 'FALSA'} (codigo {k1['codigo']}, RELLENO_PARADO {f1['n_parado']}, k6.csv "
      f"{csv1.is_file()} con {datos1['ilegibles']} filas ilegibles, fin maximo del relleno "
      f"{None if agg.max_fin_ms is None else agg.max_fin_ms / 1000 - t_rp} s respecto a T_RP, resumen.json "
      f"{resumen1.is_file()})")
    if not h_csv:
        paradas.append("H-CSV falsa: plan B (§3.5) y sonda B'")
    if agg.max_fin_ms is not None and f1_vm is not None:
        motivo, info = regla_cota_humo(t_rp, agg.max_fin_ms / 1000, f1_vm)
        p("   " + info)
        if motivo:
            paradas.append(motivo)
    cortados = collections.Counter(agg.cortados0)
    for x in legitimo:
        if x["estado"] == 0 and f1_vm is not None and t_rp - TOLERANCIA_OOM_S <= x["fin"] <= f1_vm:
            cortados[x["error_code"]] += 1
    p(f"   estados 0 cortados por el aborto (fin en [T_RP - 2, F1]), por error_code: {dict(cortados)}")
    lat_legitimo = max((x["dur"] for x in legitimo if x["estado"] == 503), default=None)
    p(f"   latencia maxima de los 503: relleno {ms(agg.latencia_503_ms)} ms, legitimo {ms(lat_legitimo)} ms")
    o1 = sum(n for codigo, n in cortados.items() if codigo not in E0_OOM)
    p("   " + hipotesis_hgs(o1, agg.o2))
    if agg.n:
        extrapolado = csv1.stat().st_size / agg.n * PETICIONES_RELLENO_EXTRAPOLAR
        p(f"   CSV de la fase 1 extrapolado a {PETICIONES_RELLENO_EXTRAPOLAR} peticiones: {extrapolado / 1e9:.2f} GB "
          "(sobrestima: incluye las filas del vigia)")
        if extrapolado > TOPE_CSV_HUMO_B:
            paradas.append(f"CSV extrapolado {extrapolado / 1e9:.2f} GB > 3 GB: plan B")
    if k1["desfase"] is None:
        paradas.append(f"sin desfase host-VM valido en la fase 1 ({k1['motivo_desfase']}): no se extrapola la "
                       "memoria de k6")
    elif m1 is None or m2 is None:
        paradas.append("no hay las dos muestras de memoria de k6 (inicio del relleno + 30 s y antes de T_RP - 2 s)")
    else:
        maxima = max((b for _, _, _, b in muestras_k6(f1["salida"] / "stats.txt", k1["desfase"]) if b is not None),
                     default=m2[1])
        n1, n2 = agg.n_hasta[0], agg.n_hasta[1]
        extrapolada, motivo = extrapolar_memoria_k6(m1[1], n1, m2[1], n2, maxima)
        p(f"   memoria de k6: M1 {m1[1] / 1048576:.0f} MiB con N1 {n1}, M2 {m2[1] / 1048576:.0f} MiB con N2 {n2}; "
          + ("sin extrapolar" if extrapolada is None else f"extrapolada {extrapolada / 1073741824:.2f} GiB"))
        if motivo:
            paradas.append(motivo)
        elif extrapolada > TOPE_MEMORIA_K6_HUMO_B:
            paradas.append(f"memoria de k6 extrapolada {extrapolada / 1073741824:.2f} GiB > 3 GiB: plan B")
    if resumen1.is_file():
        try:
            resumen = json.loads(resumen1.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            resumen = None
        accion, valido, texto = comparar_trend_fin(maximo_trend(resumen, "fin_relleno_ms"), agg.max_fin_ms)
        p(f"   D-8: {texto}")
        if accion == "PARADA":
            paradas.append(texto)
    p(f"   linea OOM literal: {oom[0][1][oom[0][1].index('EVENTO'):] if oom else 'ninguna'}; RELLENO_PARADO "
      f"{f1['n_parado']} (la primera en {t_rp:.3f}, la ultima {f1['marcas'][-1] - t_rp:.3f} s despues)")
    p(f"   Retry-After de los 503 del legitimo: "
      f"{dict(collections.Counter(x['ra'] for x in legitimo if x['estado'] == 503))}; IP_MUESTRA "
      f"{len(PATRON_IP_MUESTRA.findall(k1['registro']))}; CPU de k6 sumada maxima "
      f"{max(cpu_maximas) if cpu_maximas else 'sin medir'}")
    if f2 is None:
        paradas.append("la fase 2 del humo no se lanzo")
    else:
        mant = f1["mantenimiento"]
        destroy = [e["t"] for e in ej.eventos.copia() if e["id"] == k1["k6_id"] and e["accion"] == "destroy"]
        dies = [e for e in ej.eventos.copia() if e["id"] == k1["k6_id"] and e["accion"] == "die"]
        otro = any(otro_murio([d], "", d["t"] - 1, d["t"] + 1, ej.mantenimientos) for d in dies)
        p(f"   fase 2 del humo: arranco con --ip {IP_TRAEFIK}; mantenimiento del aborto con hasta "
          f"{mant['hasta']} (destroy {destroy[:1]}, finito {math.isfinite(mant['hasta'])}); otro_murio para el die "
          f"del k6 de la fase 1: {otro}; {f2['texto_codigo']}; hueco entre F1 e I2 "
          f"{None if f1_vm is None or f2['k6']['inicio_vm'] is None else round(f2['k6']['inicio_vm'] - f1_vm, 1)} s")
        if not f2["codigo_ok"]:
            paradas.append("la fase 2 del humo sale con " + f2["texto_codigo"])
    p(f"   conciliacion completa (informacion): {conciliacion['texto']}")
    return paradas


def emitir_l6(r, globales, humo):
    """Publica L6 (§3.8): la línea l6 con el sufijo de las repeticiones, la
    línea salud_l6 y h5 (información). Nunca hay OK global con una sola
    repetición (J1): se marca NO OK aunque l6 sea PASA. En el humo, todo es
    información y termina con "HUMO: no es evidencia"."""
    ev = r["ev"]
    v, motivos = veredicto_l6(ev, globales)
    p("   salud_l6 (informacion, no cambia l6): " + ev["salud_l6"])
    p(f"   h5 (informacion): {ev['h5'][0]}: {ev['h5'][1]}")
    if humo:
        p("   humo (informacion): " + linea_l6(v, motivos))
        p("HUMO: no es evidencia")
        estado["sin_conclusion"] = True
        return v, motivos
    texto = linea_l6(v, motivos)
    if v == NO_SE_LLENO:
        p(texto)
    else:
        emitir(v, texto)
    # J1 exige 3 repeticiones: L6 no da OK global aunque pase (D-L6-2).
    p("NO OK GLOBAL: l6 se mide con 1 de 3 repeticiones; J1 exige 3")
    estado["sin_conclusion"] = True
    return v, motivos


def literales_siembra():
    """Los valores que el lanzador siembra en cada ejecución (A3): la contraseña
    sintética del login y el texto del humo (con un acento y espacios, para
    que sus formas codificadas difieran del original). Distintos en cada
    ejecución."""
    return {"contrasena": "Estres-" + secrets.token_hex(12), "texto_humo": "Humo de recuperación L4 " + secrets.token_hex(8)}


def ids_a_escanear(ej):
    return {f"empresa{i}": x for i, x in enumerate(ej.ids_empresas)}


def escanear_salida(ej):
    """Anti-fuga (A3, J7, S6, PY-4): busca los literales sembrados, tal cual y
    codificados, y cualquier código de seguimiento en TODOS los ficheros de la
    salida, y los identificadores de empresa en los que no los necesitan. El
    centinela se planta dentro de la propia salida y el MISMO recorrido tiene
    que encontrarlo todo (escanear_con_centinela); si no, SIN CONCLUSION.
    Devuelve (veredicto, texto)."""
    reales, faltan = escanear_con_centinela(ej.salida, ej.literales, ids_a_escanear(ej), [("codigo", PATRON_CODIGO)])
    return veredicto_fuga(reales, not faltan)


def escanear_texto_final(ej):
    """S7: al final de main, el texto de la salida (PARADA, traceback y
    veredictos) tambien se escanea. El control positivo va DENTRO del texto real
    que se escanea (no en una cadena aparte): se anade un centinela al final de
    ese mismo texto, se exige encontrarlo y despues se descuenta de los
    hallazgos. Si el escaner no lo encuentra, SIN CONCLUSION."""
    control = "Centinela ó " + secrets.token_hex(6)
    texto = "\n".join(lineas_salida) + "\n" + control
    hallazgos = buscar_en_bytes(texto.encode("utf-8"), {**ej.literales, **ids_a_escanear(ej), "centinela": control},
                                [("codigo", PATRON_CODIGO)])
    if "centinela" not in hallazgos:
        sinc("anti-fuga del texto de la salida: el escaner de texto no encuentra su centinela")
        return
    hallazgos = [h for h in hallazgos if h != "centinela"]
    if hallazgos:
        sinc(f"anti-fuga: valores sembrados en el texto de la salida: {hallazgos}")


def comprobar_origen_produccion():
    """S8 (L3 y L3b, en el arranque real): registra git rev-parse HEAD, exige
    que proxy/, compose.produccion.yaml y docker-compose.yml no tengan cambios
    y compara el command y los ports de caddy y networks.edge.internal del override con lo
    que resuelve docker compose con compose.produccion.yaml, como
    comando_postgres_resuelto. PARADA si algo difiere."""
    commit = ejecutar(["git", "-C", str(RAIZ), "rev-parse", "HEAD"], timeout=60)
    if commit.rc != 0:
        raise Parada(f"git rev-parse HEAD falla: {commit.err.strip()[-200:]!r}")
    p(f"   commit del repo: {commit.out.strip()}")
    estado_ = ejecutar(["git", "-C", str(RAIZ), "status", "--short", "--", "proxy/", "compose.produccion.yaml",
                        "docker-compose.yml"], timeout=60)
    if estado_.rc != 0:
        raise Parada(f"git status falla: {estado_.err.strip()[-200:]!r}")
    sucias = rutas_sucias(estado_.out)
    if sucias:
        raise Parada(f"hay cambios sin commitear en el montaje de produccion: {sucias}")
    produccion = ejecutar(["docker", "compose", "-f", str(COMPOSE), "-f", str(RAIZ / "compose.produccion.yaml"), "config",
                           "--format", "json"], timeout=120)
    nuestro = dc("config", "--format", "json", timeout=120)
    for nombre, r in (("compose.produccion.yaml", produccion), ("el override de la bateria", nuestro)):
        if r.rc != 0:
            raise Parada(f"docker compose config de {nombre} falla (codigo {r.rc}): {r.err.strip()[-300:]!r}")
    try:
        dif = diferencias_caddy_produccion(json.loads(produccion.out), json.loads(nuestro.out))
    except ValueError:
        raise Parada("docker compose config --format json no da un JSON legible") from None
    if dif:
        raise Parada(f"el override de Caddy de produccion difiere de compose.produccion.yaml: {dif}")
    p("   el override de Caddy coincide con compose.produccion.yaml (command y networks.edge.internal)")


def guardar_resultados(salida, hechas):
    (salida / "resultados.json").write_text(json.dumps(hechas, indent=1, default=str), encoding="utf-8", newline="\n")


def ejecutar_modo(modo, t, datos, salida, cpus_canario, cpus_k6, repeticiones, humo=False):
    """--l2, --pico, --l3, --l3b, --l5, --l6 o --l7: comprobaciones, controles en
    sándwich, las repeticiones, el escáner anti-fuga, el veredicto agregado y su
    emisión. L5 y L6 no usan t (no derivan ninguna tasa de ella)."""
    if modo in ("l5", "l6"):
        tasas, n_ataque = None, None
    else:
        if t != T_CONGELADA:
            raise Parada(f"--t {t} no es la t congelada ({T_CONGELADA}): las tasas ya no serian las de la segunda "
                         "congelacion")
        tasas = tasas_de(t)
        n_ataque = n_ips_ataque(tasas["login_pico"])
        comprobar_cifras_congeladas(tasas, n_ataque,
                                    ips_necesarias(TASA_VICTIMA, 570, LIMITE_DENUNCIA, VENTANA_DENUNCIA_S),
                                    ips_necesarias(TASA_VICTIMA, 570, LIMITE_SEGUIMIENTO, VENTANA_SEGUIMIENTO_S))
        if modo == "l7" and tasas["inundacion"] != TASA_SALUD_CONGELADA:
            raise Parada(f"la tasa de la inundacion de /salud ({tasas['inundacion']}) no es la congelada "
                         f"({TASA_SALUD_CONGELADA})")
    if modo == "l6" and repeticiones != 1:
        raise Parada("L6 se mide con una sola repeticion (D-L6-2): --repeticiones 1")
    plan = plan_ips(modo, repeticiones, n_ataque) if modo in MODOS_PRODUCCION else {}
    if modo != "l5":
        p(f"=== {modo}: tasas {tasas}; tiempo estimado (peor caso) {estimar_repeticion_s(modo) / 60:.1f} min la "
          f"repeticion 1 y {estimar_repeticion_s(modo, 2) / 60:.1f} min las siguientes, "
          f"{estimar_total_s(modo, repeticiones) / 3600:.1f} h en total")
    if modo in ("l2", "pico"):
        comprobar_literales_argon2()
    if modo in MODOS_PRODUCCION:
        comprobar_origen_produccion()
    ej = Ejecucion(t, datos, salida, cpus_canario, cpus_k6, None,
                   LINEA_LIMITES_PRODUCCION if modo in MODOS_PRODUCCION else LINEA_LIMITES)
    ej.modo, ej.tasas, ej.plan_ips = modo, tasas, plan
    ej.literales = literales_siembra()
    ej.contrasena, ej.texto_humo = ej.literales["contrasena"], ej.literales["texto_humo"]
    ej.id_a = ej.id_b = None
    ej.ids_empresas = []
    ej.escaneado = False
    ACTUAL["ej"] = ej
    hechas, globales = [], []
    try:
        with contextlib.ExitStack() as pila:
            pila.callback(limpiar_efimeros)
            # La PARADA se imprime AQUI, dentro del with y antes de que corran los
            # callbacks de la pila (limpiar_efimeros, eventos.parar), y no en el
            # except del try exterior: esos callbacks y el escaneo del finally
            # tardan, un segundo Ctrl+C durante ellos se llevaría por delante la
            # línea y la causa quedaría sin decir. `impresa` se lo avisa a main,
            # que si no la imprimiría otra vez (una línea PARADA, no dos).
            try:
                ej.eventos = EventosDocker(hora_motor_ahora(), salida / "docker_events.err")
                pila.callback(ej.eventos.parar)
                for rep in range(1, repeticiones + 1):
                    if modo == "l5":
                        hechas.append(ejecutar_repeticion_l5(ej, rep))
                    elif modo == "l6":
                        hechas.append(ejecutar_repeticion_l6(ej, rep, humo))
                    else:
                        hechas.append(ejecutar_repeticion_fases(ej, modo, rep, repeticiones))
                # H1: el control final del detector, las lineas ilegibles o la muerte del
                # stream de eventos son fallos de validez de todas las partes.
                if not ejecutar_control(ej, "final"):
                    globales.append(fallo("el control positivo final del detector no se ve completo"))
                if ej.eventos.ilegibles:
                    globales.append(fallo(f"{ej.eventos.ilegibles} lineas ilegibles en el stream de docker events"))
                if not streamer_vivo(ej.eventos):
                    globales.append(fallo("el stream de docker events murio durante la ejecucion"))
            except Parada as e:
                p(f"PARADA: {e}")
                e.impresa = True
                raise
        guardar_resultados(salida, hechas)
        # H1: el anti-fuga corre ANTES de emitir el veredicto de la prueba.
        try:
            v_fuga, t_fuga = escanear_salida(ej)
        except Exception as e:  # noqa: BLE001 - cualquier fallo del escaner deja SIN CONCLUSION, visible
            t_fuga = f"anti-fuga no completado: {type(e).__name__}: {e}"
            sinc(t_fuga)
            globales.append(fallo(t_fuga))
        else:
            p(f"   anti-fuga: {v_fuga}: {t_fuga}")
            if v_fuga != "PASA":
                globales.append(fallo("anti-fuga: " + t_fuga))
        ej.escaneado = True
        if modo == "l6":
            emitir_l6(hechas[0], globales, humo)
            return
        controles = {}
        finales = agregar_fases(modo, hechas, repeticiones, globales, controles)
        for nombre, (veredicto, motivos) in finales.items():
            texto = f"{nombre}: {veredicto}" + (f" ({'; '.join(motivos)})" if motivos else "")
            if nombre == "l3b-b":
                texto = linea_l3b_b(veredicto, motivos, controles.get(nombre)) or texto
            if nombre == "l5" and veredicto == "PASA":
                texto += f" ({TEXTO_COSTE_L5})"
            emitir(veredicto, texto)
    finally:
        # Lo medido hasta ahora queda escrito y escaneado tambien con PARADA o Ctrl+C (J7).
        # Cada paso en su propio try: que falle guardar no puede impedir el reescaneo (PY-4).
        try:
            guardar_resultados(salida, hechas)
            p(f"   resultados: {salida / 'resultados.json'}")
        except OSError as e:
            sinc(f"no se pudo guardar resultados.json: {type(e).__name__}: {e}")
        if not ej.escaneado:
            try:
                v_fuga, t_fuga = escanear_salida(ej)
                emitir(v_fuga, f"anti-fuga (ejecucion abortada): {t_fuga}")
            except Exception as e:  # noqa: BLE001 - igual que arriba
                sinc(f"anti-fuga no completado: {type(e).__name__}: {e}")


def main():
    analizador = argparse.ArgumentParser(description="Prueba de estres L1 de Canario")
    modo = analizador.add_mutually_exclusive_group(required=True)
    modo.add_argument("--hash", action="store_true", help="mide t (Argon2id) en el contenedor de la API")
    modo.add_argument("--l1", action="store_true", help="capacidad y codo con k6")
    modo.add_argument("--l2", action="store_true", help="aislamiento: inundacion del login y victimas (limites de estres)")
    modo.add_argument("--pico", action="store_true", help="L4: pico de 10 veces durante 30 s y recuperacion")
    modo.add_argument("--l3", action="store_true", help="200 IPs con los limites de produccion")
    modo.add_argument("--l3b", action="store_true", help="el coste del ataque de L2 con los limites de produccion")
    modo.add_argument("--l5", action="store_true", help="IP compartida: 11 denuncias desde una IP (produccion)")
    modo.add_argument("--l6", action="store_true", help="agotar el limitador llenando Redis (produccion, 1 repeticion)")
    modo.add_argument("--l7", action="store_true", help="inundacion de GET /salud con las victimas de L2 (produccion)")
    analizador.add_argument("--t", type=float, help="t en segundos de la primera congelacion (obligatorio con --l1, "
                                                    "--l2, --pico, --l3, --l3b y --l7; salvo en --l1 debe ser 0.0196)")
    analizador.add_argument("--repeticiones", type=int, default=None,
                            help="repeticiones independientes (3 por defecto; 1 en --l6)")
    analizador.add_argument("--humo", action="store_true",
                            help="solo con --l6: la sonda B (Redis pequeno, relleno de 600 s y fase 2 de 30 s)")
    analizador.add_argument("--conservar", action="store_true",
                            help="no borra la pila ni los temporales (solo para desarrollar)")
    argumentos = analizador.parse_args()
    con_t = argumentos.l1 or argumentos.l2 or argumentos.pico or argumentos.l3 or argumentos.l3b or argumentos.l7
    modo_nuevo = "l2" if argumentos.l2 else "pico" if argumentos.pico else "l3" if argumentos.l3 else \
        "l3b" if argumentos.l3b else "l5" if argumentos.l5 else "l6" if argumentos.l6 else \
        "l7" if argumentos.l7 else None
    if argumentos.repeticiones is None:
        # L6 se mide una vez (D-L6-2); el resto, con las 3 de A1.
        argumentos.repeticiones = 1 if argumentos.l6 else REPETICIONES_POR_DEFECTO
    if argumentos.humo and not argumentos.l6:
        p("PARADA: --humo solo vale con --l6")
        terminar_con_parada()
    if con_t and argumentos.t is None:
        # Sin t congelada, las tasas no serían las de la hipótesis publicada
        # antes de medir (sección 3, primera y segunda congelación).
        p("PARADA: este modo necesita --t con el valor de la primera congelacion (python tests\\estres\\lanzar.py --hash)")
        terminar_con_parada()
    if argumentos.repeticiones < 1:
        p("PARADA: --repeticiones debe ser 1 o mas")
        terminar_con_parada()
    if con_t and not T_MINIMA <= argumentos.t <= T_MAXIMA:
        p(f"PARADA: --t {argumentos.t} fuera de lo plausible ({T_MINIMA} a {T_MAXIMA} s)")
        terminar_con_parada()

    git_arranque = estado_git()
    # Precondiciones: si fallan, no se limpia nada (podrían ser recursos ajenos).
    comprobaciones_previas()
    try:
        if argumentos.hash or argumentos.l1 or modo_nuevo in ("l2", "pico"):
            comprobar_literales_argon2()
        hermanas = leer_topologia()
        canario, k6, texto, sin_smt = elegir_cpus(hermanas)
    except Parada as e:
        p(f"PARADA: {e}")
        terminar_con_parada()
    p(f"=== CPU: {texto}")
    ncpu = ejecutar(["docker", "info", "--format", "{{.NCPU}}"]).out.strip()
    if ncpu != str(len(hermanas)):
        p(f"   AVISO: docker info da {ncpu} CPU y /sys muestra {len(hermanas)}")
    if sin_smt:
        p("   AVISO: la VM no muestra hermanas de hiperhilo (cada nucleo tiene una sola CPU): dentro de la VM no "
          "comparten nucleo, pero no se ve como reparte Hyper-V las CPU virtuales entre los hilos del procesador")

    temporal = pathlib.Path(tempfile.mkdtemp(prefix="canario_estres_"))
    datos = pathlib.Path(tempfile.mkdtemp(prefix="canario_estres_datos_"))
    salida = pathlib.Path(tempfile.mkdtemp(prefix="canario_estres_salida_"))
    # L3, L3b, L5, L6 y L7: limites de produccion (sin CANARIO_LIMITES) y Caddy
    # con Caddyfile.produccion; el resto, limites de estres y Caddyfile local.
    produccion = modo_nuevo in MODOS_PRODUCCION
    for fichero in preparar_overrides(temporal, canario, None if produccion else LIMITES_ESTRES,
                                      caddy_produccion=produccion):
        BASE.extend(["-f", str(fichero)])

    parada = None
    try:
        # El override de logging de PostgreSQL va en toda pila de medida (L5 y L6
        # incluidas, aunque no usen t): preparar_repeticion lo comprueba.
        if con_t or modo_nuevo in ("l5", "l6"):
            preparar_override_postgres(temporal)
        if argumentos.humo:
            preparar_override_redis(temporal)
        if argumentos.hash:
            arrancar(("api",), canario)
            medir_hash(salida)
        elif modo_nuevo is not None:
            ejecutar_modo(modo_nuevo, argumentos.t, datos, salida, canario, k6, argumentos.repeticiones,
                          humo=argumentos.humo)
        else:
            ejecutar_l1(argumentos.t, datos, salida, canario, k6, argumentos.repeticiones)
    except Parada as e:
        parada = str(e)
        # ejecutar_modo ya la imprimió (e.impresa) antes de su limpieza; L1, --hash
        # y el resto no, y siguen imprimiéndola aquí como siempre.
        if not getattr(e, "impresa", False):
            p(f"PARADA: {parada}")
    except KeyboardInterrupt:
        # Ctrl+C: PARADA visible; la limpieza y lo medido hasta ahora siguen.
        parada = "interrumpido con Ctrl+C"
        p("PARADA: interrumpido con Ctrl+C (se limpia y se escribe lo medido hasta ahora)")
    except Exception:  # noqa: BLE001 - error inesperado del propio lanzador: se informa y se limpia
        parada = "error inesperado en el lanzador"
        p("ERROR INESPERADO:\n" + traceback.format_exc())
    finally:
        try:
            limpiar_efimeros()
        except KeyboardInterrupt:
            p(f"AVISO: segundo Ctrl+C durante la limpieza: pueden quedar contenedores con prefijo {PREFIJO_EFIMEROS}")
        if argumentos.conservar:
            p("=== --conservar: la pila y los temporales siguen ahi")
            p("   Para borrarlo (PowerShell, desde cualquier directorio):")
            p("   " + orden_powershell([*BASE, "down", "-v", "--rmi", "local"]))
            for directorio in (temporal, datos):
                p(f"   Remove-Item -Recurse -Force \"{directorio}\"")
        else:
            p("=== limpieza")
            r = dc("down", "-v", "--rmi", "local")
            p(f"down -v --rmi local -> codigo {r.rc}")
            restos = recursos_previos()
            pasa(not restos, f"ningun contenedor, red, volumen ni imagen con prefijo {PROYECTO} {restos or ''}".strip())
            shutil.rmtree(temporal, ignore_errors=True)
            shutil.rmtree(datos, ignore_errors=True)
        git_final = estado_git()
        if git_arranque is None or git_final is None:
            sinc("no se pudo comparar el estado de Git")
        else:
            iguales = git_final == git_arranque
            pasa(iguales, "la prueba no ha modificado el repo (git status igual al del arranque)")
            if not iguales:
                p(f"   al arrancar: {git_arranque}")
                p(f"   al terminar: {git_final}")
        p(f"Salida (CSV y panel de k6, logs, docker stats, resultados): {salida}")
        if ACTUAL["ej"] is not None:
            # S7: el texto que acaba de salir por pantalla (PARADA, traceback,
            # veredictos) tambien se escanea en busca de lo sembrado.
            try:
                escanear_texto_final(ACTUAL["ej"])
            except Exception as e:  # noqa: BLE001 - un fallo del escaner deja SIN CONCLUSION, visible
                sinc(f"anti-fuga del texto no completado: {type(e).__name__}: {e}")
    if parada is not None:
        estado["falla"] = True
    terminar()


if __name__ == "__main__":
    main()
