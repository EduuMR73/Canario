#!/usr/bin/env python3
"""Lanzador de la prueba de estrés L1 (capacidad y codo, docs/informe-pruebas.md,
secciones 2 y 3). Se ejecuta en el host, desde la raíz del repo, con la pila
local parada:

    python tests\\estres\\lanzar.py --hash [--conservar]
    python tests\\estres\\lanzar.py --l1 --t <segundos> [--conservar]

Las dos modalidades comparten:
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
import collections
import contextlib
import csv
import datetime
import itertools
import json
import math
import pathlib
import re
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


def clase_contenedor(atributos):
    """Qué es un contenedor por sus etiquetas: "k6", "lector" o "control" por
    canario.estres (nunca por la etiqueta de compose); "canario" si es uno de
    los 4 servicios de la pila; "auxiliar" si es de compose pero de otro
    servicio (gestion); None si no es nuestro (se ignora)."""
    propia = atributos.get("canario.estres")
    if propia in ("k6", "lector", "control"):
        return propia
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
    Sin el dato de procesos, se trata como ajeno (fallo visible)."""
    procesos = procesos or {}
    ajenos = []
    for nombre in nombres_hijos:
        encaje = PATRON_ID_LARGO.search(nombre)
        conocido = contenedores.get(encaje.group(0)) if encaje else None
        if conocido is None:
            if procesos.get(nombre, True):
                ajenos.append(nombre)
        elif clase_contenedor(conocido["etiquetas"]) is None:
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


def preparar_overrides(temporal, cpus_canario):
    """Los ficheros de compose adicionales, en el directorio temporal: el
    docker-compose.yml del repo no cambia."""
    limites = temporal / "limites_estres.yml"
    limites.write_text(f"services:\n  api:\n    environment:\n      CANARIO_LIMITES: \"{LIMITES_ESTRES}\"\n",
                       encoding="utf-8", newline="\n")
    # cpuset y no cpus: con cpus (cuota de CFS) el planificador reparte la
    # pila por las 16 CPU de la VM y solo limita el tiempo total; con cpuset
    # todos los servicios compiten por los mismos 2 núcleos, como en el VPS.
    lista = ",".join(str(c) for c in cpus_canario)
    lineas = ["services:"]
    for servicio in SERVICIOS:
        lineas += [f"  {servicio}:", f"    cpuset: \"{lista}\""]
    cpuset = temporal / "cpuset_estres.yml"
    cpuset.write_text("\n".join(lineas) + "\n", encoding="utf-8", newline="\n")
    return [limites, cpuset]


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


def comprobar_limites_api(ident):
    """La línea entera de límites de estrés en el log de ESTA API (por id: la
    API se recrea entre rutas) y RestartCount 0 recién arrancada."""
    registro = ejecutar(["docker", "logs", ident]).todo
    limites_ok = LINEA_LIMITES in [linea.rstrip("\r") for linea in registro.splitlines()]
    pasa(limites_ok, f"la API usa los limites de estres y el log lo dice con la linea entera ({LINEA_LIMITES!r})")
    if not limites_ok:
        raise Parada("la API no anuncia los limites de estres: se mediria el limitador")
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


def arrancar(servicios, cpus_canario, rep=1):
    p(f"=== arranque de la pila ({', '.join(servicios)})")
    argumentos = argumentos_arranque(rep, servicios)
    r = dc(*argumentos, timeout=1800)
    p(f"{' '.join(argumentos)} -> codigo {r.rc}")
    if r.rc != 0:
        p(r.todo.strip()[-1500:])
        raise Parada("no arranca la pila")
    comprobar_limites_api(dc("ps", "-q", "api").out.strip())
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
    contenedor = f"{PREFIJO_EFIMEROS}k6_{nombre}"
    muertos_antes = comprobar_vida(contexto["vigilados"](), f"antes de {nombre}")
    desfase_inicio = medir_desfase()
    # Endurecido como el contenedor de Playwright de las funcionales: usuario
    # de la imagen, raíz de solo lectura, sin capacidades ni nuevos
    # privilegios, el script y los datos de solo lectura y solo /salida con
    # escritura. En el espacio de red de Caddy: localhost:8443 y :8444 son
    # Caddy, con el mismo Host y SNI que desde el host, sin pasar por el
    # proxy de puertos de Docker Desktop (que se mediría también). cpuset
    # aparte del de Canario. Sin --rm: docker inspect y docker logs se leen
    # antes de borrarlo.
    r = ejecutar(["docker", "run", "-d", "--name", contenedor, "--label", "canario.estres=k6",
                  "--network", f"container:{contexto['caddy']}",
                  "--user", USUARIO_K6, "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                  "--pids-limit", "1024", "--memory", MEMORIA_K6, "--cpuset-cpus", contexto["cpus_k6"],
                  "--tmpfs", "/tmp:size=64m", "-e", "HOME=/tmp", "-e", "K6_NO_USAGE_REPORT=true",
                  "-e", "K6_CSV_TIME_FORMAT=unix_milli", "-e", "K6_WEB_DASHBOARD=true",
                  "-e", "K6_WEB_DASHBOARD_PORT=-1", "-e", "K6_WEB_DASHBOARD_EXPORT=/salida/panel.html",
                  "--mount", f"type=bind,src={DIR_ESTRES},dst=/prueba,readonly",
                  "--mount", f"type=bind,src={contexto['datos']},dst=/datos,readonly",
                  "--mount", f"type=bind,src={salida},dst=/salida",
                  IMG_K6, "run", "--no-usage-report", "--out", "csv=/salida/k6.csv", "/prueba/l1.js"], timeout=900)
    if r.rc != 0:
        raise Parada(f"no arranca el contenedor de k6: {r.err.strip()[-500:]!r}")
    k6_id = r.out.strip()
    # docker stats usa la hora del host y k6, docker events y el lector la de
    # la VM: el desfase se mide al inicio y al final del escalón. Si no se
    # puede medir o difiere en más de 1 s, la CPU del escalón es SIN
    # CONCLUSION (antes se forzaba a 0 en silencio).
    estadisticas = Estadisticas([contenedor], salida / "stats.txt")
    plazo = inicio + paso["duracion_s"] + 300
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
    res = analizar_escalon(ruta, paso, salida, codigo, bool(estado_k6.get("OOMKilled")), registro_k6, desfase,
                           contexto["stats_ruta"], motivo_desfase)
    res["k6_id"] = k6_id
    res["inicio_vm"] = a_epoch(estado_k6.get("StartedAt", ""))
    res["fin_vm"] = a_epoch(estado_k6.get("FinishedAt", ""))
    if res["inicio_vm"] is None or res["fin_vm"] is None:
        res["sin_conclusion"].append("no se pudo leer StartedAt/FinishedAt de k6: no hay ventana del escalon")
    # Vida del detector: el start y el die de k6 deben estar en el stream (un
    # control positivo gratuito en cada escalón) y todos los streamers vivos.
    for accion in ("start", "die"):
        if not contexto["eventos"].esperar(lambda e, a=accion: e["id"] == k6_id and e["accion"] == a, CENTINELA_S):
            res["sin_conclusion"].append(f"el stream de docker events no trajo el {accion} de k6: el detector no vio "
                                         "el escalon")
    muertos = muertos_antes + comprobar_vida(contexto["vigilados"](), f"despues de {nombre}")
    if muertos:
        res["sin_conclusion"].append(f"streamers muertos durante el escalon: {sorted(set(muertos))}")
    return res


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


def comprobar_misma_imagen(referencia, actual, servicio, rep, *, ruta=None):
    """PARADA si la imagen de `servicio` en la repetición `rep` no es la de la
    repetición 1. Pura. ¿Por qué un control y no fiarse de --no-build? Porque
    todo lo que se mide (el lector, el control positivo, la API de cada ruta)
    asume que la pila es la misma en las tres repeticiones; si la imagen
    cambiara, las repeticiones no serían repeticiones. Un id vacío o que no
    sea sha256:<64 hex> (docker inspect falló) también es PARADA: un fallo
    visible, nunca una comparación de dos vacíos que daría PASA.

    Con `ruta`, la comparación es la de la API recreada para esa ruta: el
    mensaje lo dice, para que la PARADA no se confunda con la del arranque de
    la repetición. El mismo `donde` sirve a los dos mensajes, y sin `ruta` son
    los de siempre."""
    donde = f"la repeticion {rep}" if ruta is None else f"la API recreada para {ruta} (repeticion {rep})"
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
    lector y el control, se fija una sola vez. En las siguientes se comparan con
    la referencia, ANTES de lanzar ningún lector."""
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
    es None"): la imagen es la misma en todas por la comprobación de imágenes."""
    if rep > 1:
        bajar_pila(ej)
    arrancar(("api", "caddy"), ej.cpus_canario, rep)
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

    def __init__(self, t, datos, salida, cpus_canario, cpus_k6, escalera):
        self.t, self.datos, self.salida, self.escalera = t, datos, salida, escalera
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


def argumentos_recreacion():
    """Argumentos de `docker compose` para recrear la API entre rutas. Pura.
    ¿Por qué --no-build? El servicio api tiene `build:` sin `image:` ni
    `pull_policy`, y sin --no-build compose construye si falta la imagen: la
    API de la ruta podría ser otra imagen que la medida en la repetición 1.
    Con --no-build, si falta, el up falla y hay PARADA visible."""
    return ["up", "-d", "--force-recreate", "--no-deps", "--no-build", "--wait", "api"]


def recrear_api(ej, rep, ruta):
    """API nueva entre rutas (cada ruta parte de una API recién arrancada). El
    die del id viejo es esperado; PostgreSQL, Redis y Caddy no deben cambiar de
    id (k6 usa el espacio de red de Caddy por id). La imagen de la API recreada
    se compara con la de la repetición 1, antes de lanzar el lector de la ruta."""
    # Sin la referencia no hay con qué comparar: PARADA antes de abrir la
    # ventana de mantenimiento, para no dejar una ventana sin recreación.
    if ej.imagenes is None:
        raise Parada("la API se recrea sin la imagen de referencia de la repeticion 1")
    viejo = ej.ids["api"]
    mantenimiento = {"ids": frozenset([viejo]), "desde": hora_motor_ahora(), "hasta": None,
                     "motivo": "recreacion de la API"}
    ej.mantenimientos.append(mantenimiento)
    argumentos = argumentos_recreacion()
    r = dc(*argumentos, timeout=900)
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
    actual = leer_imagen(nuevos["api"], f"la API recreada para {ruta} (repeticion {rep})")
    comprobar_misma_imagen(ej.imagenes["api"], actual, "api", rep, ruta=ruta)
    pasa(True, f"repeticion {rep}, {ruta}: la API recreada tiene la imagen de la repeticion 1 ({actual})")
    comprobar_limites_api(nuevos["api"])


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
        recrear_api(ej, rep, ruta)
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
        emitir(veredicto, f"repeticion {rep}: murio {ev['servicio']} ({ev['id'][:12]}, codigo {ev['codigo']}) en "
                          f"{ventana}: {causa} (padre: oom +{d_oom}, oom_kill +{d_kill})")
        escalon = por_nombre.get(ventana.split(" (")[0])
        if escalon is not None:
            escalon["no_evaluable"] = True
            muerte_en_login = muerte_en_login or escalon["ruta"] in LOGIN
            p(f"   {ventana}: latencias y codo NO EVALUABLE por la muerte")
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
    salida_rep = ej.salida / f"rep{rep}"
    salida_rep.mkdir()
    t_ini = hora_motor_ahora()
    preparar_repeticion(ej, rep)
    r = dc("run", "--rm", "-T", "gestion", "alta-empresa", "--nombre", "Empresa estres", "--zona", "Europe/Madrid")
    alta = PATRON_ALTA.search(r.out)
    if r.rc != 0 or alta is None:
        raise Parada(f"no se pudo dar de alta la empresa de prueba: {r.err.strip()[-300:]!r}")
    ej.identificador = alta.group(2)
    p(f"   empresa de prueba de la repeticion {rep}: {ej.identificador}")
    rutas = []
    with contextlib.ExitStack() as pila:
        registros = [Registro(s, salida_rep / f"log_{s}.txt") for s in ("redis", "postgres")]
        for registro in registros:
            pila.callback(registro.parar)
        contexto = {"t": ej.t, "escalera": ej.escalera, "datos": ej.datos, "salida": salida_rep,
                    "caddy": ej.ids["caddy"], "cpus_k6": ej.cpus_k6, "registros": registros}
        for n_ruta, ruta in enumerate(ORDEN_RUTAS):
            rutas.append(ejecutar_ruta(ej, rep, ruta, n_ruta, n_ruta == len(ORDEN_RUTAS) - 1, contexto))
        time.sleep(3)
    otras = {s: leer_log(salida_rep / f"log_{s}.txt") for s in ("redis", "postgres")}
    # Arranques de Redis de esta repetición (mismo reloj de la VM que el log):
    # la ventana de arranque del resumen del limitador cuenta desde ellos.
    arranques_redis = [e["t"] for e in ej.eventos.copia()
                       if e["t"] >= t_ini and e["clase"] == "canario" and e["servicio"] == "redis"
                       and e["accion"] == "start"]
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
    p(f"=== codo por ruta, repeticion {rep} (primer escalon con p95 > SLO, >= 1 % de errores o maxVUs alcanzados)")
    for ruta in ORDEN_RUTAS:
        codo = codo_de([res for res in resultados if res["ruta"] == ruta])
        p(f"   {ruta}: " + ("sin codo en la escalera medida" if codo is None else
                            f"{codo['escalon']} {codo['etiqueta']} = {codo['tasa']}/s ({'; '.join(codo['motivos_fuera'])})"))
    hipotesis(resultados, ej.t, datos_rep["muerte_en_login"])
    return {"resultados": resultados, **datos_rep}


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


def main():
    analizador = argparse.ArgumentParser(description="Prueba de estres L1 de Canario")
    modo = analizador.add_mutually_exclusive_group(required=True)
    modo.add_argument("--hash", action="store_true", help="mide t (Argon2id) en el contenedor de la API")
    modo.add_argument("--l1", action="store_true", help="capacidad y codo con k6")
    analizador.add_argument("--t", type=float, help="t en segundos de la primera congelacion (obligatorio con --l1)")
    analizador.add_argument("--repeticiones", type=int, default=REPETICIONES_POR_DEFECTO,
                            help="repeticiones independientes de --l1 (3 por defecto, unas 2 h)")
    analizador.add_argument("--conservar", action="store_true",
                            help="no borra la pila ni los temporales (solo para desarrollar)")
    argumentos = analizador.parse_args()
    if argumentos.l1 and argumentos.t is None:
        # Sin t congelada, las tasas del login no serían las de la hipótesis
        # publicada antes de medir (sección 3, primera congelación).
        p("PARADA: --l1 necesita --t con el valor de la primera congelacion (python tests\\estres\\lanzar.py --hash)")
        terminar_con_parada()
    if argumentos.repeticiones < 1:
        p("PARADA: --repeticiones debe ser 1 o mas")
        terminar_con_parada()
    if argumentos.l1 and not T_MINIMA <= argumentos.t <= T_MAXIMA:
        p(f"PARADA: --t {argumentos.t} fuera de lo plausible ({T_MINIMA} a {T_MAXIMA} s)")
        terminar_con_parada()

    git_arranque = estado_git()
    # Precondiciones: si fallan, no se limpia nada (podrían ser recursos ajenos).
    comprobaciones_previas()
    try:
        if argumentos.hash or argumentos.l1:
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
    for fichero in preparar_overrides(temporal, canario):
        BASE.extend(["-f", str(fichero)])

    parada = None
    try:
        if argumentos.l1:
            preparar_override_postgres(temporal)
        if argumentos.hash:
            arrancar(("api",), canario)
            medir_hash(salida)
        else:
            ejecutar_l1(argumentos.t, datos, salida, canario, k6, argumentos.repeticiones)
    except Parada as e:
        parada = str(e)
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
    if parada is not None:
        estado["falla"] = True
    terminar()


if __name__ == "__main__":
    main()
