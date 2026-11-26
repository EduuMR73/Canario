#!/usr/bin/env python3
"""Diagnóstico D2, "dónde espera el login" (plan del bloque 1, v4, §2, A0).

Tiene dos partes en el mismo fichero:

* La EVALUACIÓN, pura y solo con la biblioteca estándar (evaluar_d2 y sus
  ayudas): la importa tests/estres/lanzar.py en el host y la prueban las
  unitarias de tests/estres/test_diag_hilos.py. No importa uvicorn, anyio ni
  la API: esos imports van dentro de las funciones del contenedor.
* El PROCESO DE DIAGNÓSTICO (principal), que corre DENTRO del contenedor de
  la API en lugar del ENTRYPOINT de la imagen. lanzar.py --d2 lo monta de
  solo lectura en /diag/diag_hilos.py y sustituye, solo en el compose
  temporal, el entrypoint por python y la command por
  -I -B -u /diag/diag_hilos.py. Sirve la aplicación real
  (app.principal:aplicacion) con uvicorn.Server y la misma configuración que
  la command de docker-compose.yml (líneas 285-290) más el ENTRYPOINT del
  Dockerfile (línea 64): host 10.88.0.4, puerto 8000, --proxy-headers,
  --forwarded-allow-ips 10.88.0.2, sin log de acceso y sin cabecera Server.

Qué mide el proceso, cada 0,5 s y con la hora real (JSON por líneas a stdout
con el prefijo "DIAG2 ", escrito en el momento):
* el limitador por defecto de AnyIO (prestados, fichas y en espera), leído
  dentro del bucle de eventos, que es donde vive su RunVar;
* pool.get_stats() del pool de la API (app.state.pool, app/principal.py);
* el retraso del bucle de eventos;
* la CPU del proceso, del hilo principal, de los hilos argon2_* y de los de
  AnyIO (Thread.native_id y /proc/self/task/<tid>/stat);
* lambda: todo lo que entra en el limitador por defecto, contado envolviendo
  anyio.to_thread.run_sync cuando limiter es None (Starlette 1.7.0 lo busca
  como atributo en cada llamada, starlette/concurrency.py:34);
* un middleware ASGI puro (no BaseHTTPMiddleware) que cuenta las peticiones
  salvo POST /salud (la sonda que da 405 sin hilos) y cuántas ve con el
  cliente igual a la IP de Caddy;
* la clase de cada hilo de AnyIO, solo por f_code.co_name y co_filename de su
  pila (nunca f_locals ni repr): libre, semaforo, pool, argon2, bd_activa u
  otra.

Antes de servir (dentro del lifespan, así que ningún socket escucha todavía
y la carga no puede empezar) corre los controles positivos del plan y
escribe su resultado. Un control que falla no detiene el arranque: queda en
la salida y la evaluación da SIN CONCLUSION.

Desviaciones declaradas (docs/informe-pruebas.md, sección de D2): el
ENTRYPOINT de la imagen se sustituye; las muestras se escriben en el momento
y nada se escribe después de serve(), porque uvicorn instala sus gestores de
señal y vuelve a lanzar la señal al salir (server.py:88-90 y :332-349); un
force_exit (segunda señal), un OOM o un SIGKILL cortan la salida donde esté.
"""
import asyncio
import collections
import contextlib
import json
import math
import os
import secrets
import statistics
import sys
import threading
import time

# ---------------------------------------------------------------------------
# Literales compartidos por el proceso y la evaluación
# ---------------------------------------------------------------------------
# Prefijo de cada línea propia en el log de la API: la evaluación solo lee
# estas líneas y el resto del log (uvicorn, la API) no la confunde.
PREFIJO_LINEA = "DIAG2 "
PERIODO_S = 0.5
RAIZ_API = "/srv"
CLASES = ("libre", "semaforo", "pool", "argon2", "bd_activa", "otra")
# Nombres de los controles positivos del plan (§2, A0), en el orden en que
# corren. Si falta alguno o alguno no da PASA, la evaluación da SIN CONCLUSION.
CONTROLES_ESPERADOS = (
    "booleano_proxy",
    "retraso_bucle",
    "limitador_41",
    "cpu_hilo",
    "semaforo",
    "ejecutor_lento_argon2",
    "centinela",
    "pool_5_mas_1",
    "pg_sleep_bd_activa",
)
# Espera de seguridad de cualquier hilo de un control: si algo sale mal, el
# hilo se suelta solo y el arranque no se queda colgado.
ESPERA_SEGURIDAD_S = 10.0


# ---------------------------------------------------------------------------
# Piezas puras del instrumento (también las usa el proceso)
# ---------------------------------------------------------------------------
def _normalizar(archivo):
    return archivo.replace("\\", "/")


def clasificar_pila(pila):
    """Clase de un hilo de AnyIO a partir de su pila, una lista de pares
    (co_filename, co_name) del marco más interno al más externo. Solo mira
    esos dos campos del código: nunca las variables locales, que pueden
    llevar una contraseña.

    Se recorre de dentro afuera y gana la primera marca que aparece:
    * semaforo: _tomar_hueco_hash de app/personal.py (el hilo espera hueco en
      _semaforo, app/personal.py:826);
    * argon2: _verificar_en_ejecutor o _crear_hash_en_ejecutor de
      app/personal.py (el hilo espera future.result() del ejecutor de 2
      hilos, :802). _tomar_hueco_hash se llama DESDE ellas y está más
      dentro, así que mientras espera hueco el hilo sale como semaforo;
    * pool: _getconn_unchecked de psycopg_pool/pool.py, la cola de espera de
      una conexión (WaitingClient.wait se llama desde ella). La comprobación
      check_connection (app/bd.py:147) corre después, ya con la conexión, y
      ejecuta SQL: sus marcos de psycopg/ están más dentro y sale bd_activa;
    * bd_activa: cualquier marco de psycopg/ (no de psycopg_pool/);
    * libre: queue.get llamado directamente desde el bucle run del
      WorkerThread de AnyIO (anyio/_backends/_asyncio.py), es decir, el hilo
      espera trabajo. Un queue.get dentro de una ruta no cuenta como libre;
    * otra: ninguna de las anteriores.
    """
    normalizada = [(_normalizar(archivo), nombre) for archivo, nombre in pila]
    for i, (archivo, nombre) in enumerate(normalizada):
        if archivo.endswith("/app/personal.py"):
            if nombre == "_tomar_hueco_hash":
                return "semaforo"
            if nombre in ("_verificar_en_ejecutor", "_crear_hash_en_ejecutor"):
                return "argon2"
        if archivo.endswith("/psycopg_pool/pool.py") and nombre == "_getconn_unchecked":
            return "pool"
        if "/psycopg/" in archivo:
            return "bd_activa"
        if archivo.endswith("/queue.py") and nombre == "get" and i + 1 < len(normalizada):
            exterior_archivo, exterior_nombre = normalizada[i + 1]
            if exterior_archivo.endswith("/anyio/_backends/_asyncio.py") and exterior_nombre == "run":
                return "libre"
    return "otra"


def es_hilo_anyio(nombre, es_trabajador):
    """True si el hilo es un trabajador del limitador por defecto de AnyIO.
    es_trabajador: isinstance(hilo, WorkerThread). Se excluyen además, por
    nombre, los hilos del ejecutor de Argon2 (argon2_0 y argon2_1,
    app/personal.py:161-165) y los del pool de psycopg (<nombre>-worker-<i> y
    <nombre>-scheduler, psycopg_pool/pool.py:417-420): no son de AnyIO y no
    deben entrar en las fracciones aunque algún día heredaran la clase."""
    if not es_trabajador:
        return False
    if nombre.startswith("argon2_"):
        return False
    partes = nombre.rsplit("-", 2)
    if nombre.endswith("-scheduler") or (len(partes) == 3 and partes[1] == "worker" and partes[2].isdigit()):
        return False
    return True


def resumen_marco(marco):
    """"<fichero>:<función>" del marco más interno de un hilo "otra"
    (información para leer la salida; solo nombres de código)."""
    archivo, nombre = marco
    return f"{_normalizar(archivo).rsplit('/', 1)[-1]}:{nombre}"


def ticks_de_stat(texto):
    """utime + stime (en ticks de reloj) de una línea de /proc/.../stat. El
    nombre del proceso va entre paréntesis y puede llevar espacios o
    paréntesis: se corta en el ÚLTIMO ')'. Tras él, el campo 3 (estado) es
    el índice 0, así que utime (14) y stime (15) son los índices 11 y 12."""
    campos = texto[texto.rindex(")") + 2:].split()
    return int(campos[11]) + int(campos[12])


class ContadorAsgi:
    """Middleware ASGI puro (sin BaseHTTPMiddleware, que añadiría su propia
    tarea y su propio flujo de cuerpo). Va DENTRO de ProxyHeadersMiddleware
    de uvicorn (Config.load lo envuelve por fuera), así que ve el cliente ya
    reescrito con X-Forwarded-For.

    peticiones: las HTTP salvo POST /salud, contadas al entrar (como lambda).
    cliente_caddy: las HTTP, POST /salud incluida, cuyo cliente visto es la
    IP de Caddy, comparada con el literal 10.88.0.2 y no con un valor leído
    de la configuración. Debe quedar en 0: si sube, uvicorn no está
    aplicando las cabeceras de reenvío y todos los clientes parecerían el
    proxy (un solo contador del limitador para todos)."""

    IP_CADDY = "10.88.0.2"

    def __init__(self, app=None):
        self.app = app
        self.peticiones = 0
        self.cliente_caddy = 0

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            if not (scope.get("method") == "POST" and scope.get("path") == "/salud"):
                self.peticiones += 1
            cliente = scope.get("client")
            if cliente is not None and cliente[0] == self.IP_CADDY:
                self.cliente_caddy += 1
        await self.app(scope, receive, send)


class ContadorLlamadas:
    def __init__(self):
        self.llamadas = 0


def envolver_run_sync(modulo, contador):
    """Sustituye modulo.run_sync (anyio.to_thread) por un envoltorio que
    cuenta las llamadas sin limiter (las que van al limitador por defecto) y
    delega en la original con los mismos argumentos. limiter es de solo
    palabra clave en la firma de AnyIO, así que basta con mirar kwargs.
    Devuelve la original. Solo en este proceso de diagnóstico: la imagen y
    app/ no cambian."""
    original = modulo.run_sync

    async def run_sync(*args, **kwargs):
        if kwargs.get("limiter") is None:
            contador.llamadas += 1
        return await original(*args, **kwargs)

    modulo.run_sync = run_sync
    return original


def linea_json(registro):
    return PREFIJO_LINEA + json.dumps(registro, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def emitir(registro):
    # print con flush: python -u ya no usa búfer, pero el flush explícito deja
    # claro que cada muestra sale en el momento (nada se guarda para el final).
    print(linea_json(registro), flush=True)


# ---------------------------------------------------------------------------
# Evaluación pura: tabla de decisión de D2 (plan v4, §2)
# ---------------------------------------------------------------------------
# Literales de la tabla. Se escriben aquí y no se derivan de nada que mida el
# proceso: son las predicciones escritas antes de medir.
UMBRAL_PERDIDAS_PCT = 10            # > 10 % de muestras perdidas: SIN CONCLUSION
UMBRAL_RETRASO_P95_S = 1.0          # H-bucle: p95 del retraso >= 1 s
UMBRAL_CPU_PROCESO = 1.8            # H-CPU/GIL: mediana de la CPU del proceso >= 1,8
UMBRAL_CPU_PRINCIPAL = 0.9          # H-CPU/GIL: hilo principal >= 0,9
PRESTADOS_LLENO = 40                # H-hilos: los 40 prestados...
UMBRAL_PRESTADOS_PCT = 95           # ...en >= 95 % de las muestras
UMBRAL_W_ANYIO_S = 5.0              # H-hilos: W_AnyIO >= 5 s
MAX_ESPERA_POOL_HILOS = 1           # H-hilos: mediana de requests_waiting <= 1
MIN_ESPERA_POOL_BD = 3              # H-bd: mediana de requests_waiting >= 3
UMBRAL_ESPERA_POOL_MS = 1000        # H-bd: Δwait/Δqueued >= 1000 ms o "no aplica"
UMBRAL_FRACCION = 0.5               # H-hilos y H-bd: fracción >= 0,5
MARGEN_INICIO_S = 30                # ventana válida: INUNDACIÓN + 30 s...
MARGEN_FIN_S = 5                    # ...hasta el fin de la INUNDACIÓN - 5 s
TOLERANCIA_CUENTAS_PCT = 1          # lambda, middleware y k6 en ±1 %
NO_APLICA = "no aplica"
CONFIGURACION_ESPERADA = {
    "app": "app.principal:aplicacion",
    "host": "10.88.0.4",
    "port": 8000,
    "proxy_headers": True,
    "forwarded_allow_ips": "10.88.0.2",
    "access_log": False,
    "server_header": False,
}
SIN_CONCLUSION = "SIN CONCLUSION"
PARADA = "PARADA"
PARADA_M1 = "PARADA (M1)"
A2 = "A2"
A2_CON_NOTA = "A2 con nota"


def ventana_valida(inicio_inundacion, fin_inundacion):
    """[INUNDACIÓN + 30 s, fin de la INUNDACIÓN - 5 s], en segundos epoch."""
    return inicio_inundacion + MARGEN_INICIO_S, fin_inundacion - MARGEN_FIN_S


def percentil_95(valores):
    """Percentil 95 por rango más cercano (el mismo método que percentil de
    lanzar.py), o None sin valores."""
    ordenados = sorted(valores)
    if not ordenados:
        return None
    return ordenados[max(1, math.ceil(0.95 * len(ordenados))) - 1]


def _dentro_de_tolerancia(valor, referencia):
    """|valor - referencia| <= 1 % de la referencia, en enteros (sin redondeos
    de coma flotante en la frontera). Con referencia 0, nunca."""
    return referencia > 0 and abs(valor - referencia) * 100 <= TOLERANCIA_CUENTAS_PCT * referencia


def separar_registros(registros):
    """Los registros "DIAG2" ya leídos, por tipo."""
    por_tipo = collections.defaultdict(list)
    for r in registros:
        por_tipo[r.get("tipo")].append(r)
    return por_tipo


def fraccion_no_libres(clases, nombres):
    """Fracción de los hilos de AnyIO NO libres que están en `nombres`, o None
    si en esa muestra no hay ninguno no libre (la muestra no entra en la
    mediana de esa fracción)."""
    no_libres = sum(n for c, n in clases.items() if c != "libre")
    if no_libres == 0:
        return None
    return sum(clases.get(c, 0) for c in nombres) / no_libres


def _mediana(valores):
    valores = [v for v in valores if v is not None]
    return statistics.median(valores) if valores else None


def evaluar_d2(registros, ventana, inicios_k6, reproduccion, fallos_carga=(), ilegibles=0):
    """Aplica la tabla de decisión de D2, con su precedencia (la primera fila
    que se cumple gana). Devuelve {"decision", "fila", "motivos", "cifras"}.

    registros: las líneas DIAG2 ya decodificadas (configuración, controles y
    muestras). ventana: (desde, hasta) en segundos epoch, de ventana_valida,
    o None. inicios_k6: los instantes de inicio (epoch) de las peticiones de
    k6 que llegan a la API, sin la sonda POST /salud. reproduccion: {"p95_ms":
    {víctima: p95 de la INUNDACIÓN o None}, "slo_ms": {víctima: SLO}, "n429":
    429 de toda la ejecución}. fallos_carga: motivos de validez de la propia
    carga de L2 (k6, vigilancia, anti-fuga, muertes). ilegibles: líneas DIAG2
    que no se pudieron decodificar.
    """
    por_tipo = separar_registros(registros)
    motivos, cifras = [], {}

    # --- fila 1: controles, validez y muestras perdidas -------------------
    motivos += [f"carga: {m}" for m in fallos_carga]
    if ilegibles:
        motivos.append(f"{ilegibles} lineas DIAG2 ilegibles")
    configuraciones = por_tipo.get("configuracion", [])
    if len(configuraciones) != 1:
        # Más de una: el proceso arrancó más de una vez (reinicio del contenedor).
        motivos.append(f"{len(configuraciones)} lineas de configuracion (se esperaba 1)")
    else:
        efectiva = configuraciones[0]
        for clave, esperado in CONFIGURACION_ESPERADA.items():
            if efectiva.get(clave) != esperado:
                motivos.append(f"configuracion efectiva: {clave} = {efectiva.get(clave)!r}, se esperaba {esperado!r}")
    controles = {c.get("nombre"): c.get("resultado") for c in por_tipo.get("control", [])}
    cifras["controles"] = dict(controles)
    for nombre in CONTROLES_ESPERADOS:
        if controles.get(nombre) != "PASA":
            motivos.append(f"control {nombre}: {controles.get(nombre, 'ausente')}")

    muestras = sorted(por_tipo.get("muestra", []), key=lambda m: m["t"])
    if por_tipo.get("error_muestra"):
        motivos.append(f"{len(por_tipo['error_muestra'])} muestras con error")
    validas = []
    if ventana is None:
        motivos.append("sin ventana valida (falta el t0 de k6)")
    else:
        desde, hasta = ventana
        esperadas = math.floor((hasta - desde) / PERIODO_S)
        validas = [m for m in muestras if desde <= m["t"] <= hasta]
        perdidas = max(0, esperadas - len(validas))
        cifras.update({"ventana": [desde, hasta], "muestras_esperadas": esperadas,
                       "muestras_validas": len(validas), "muestras_perdidas": perdidas})
        if esperadas <= 0:
            motivos.append("ventana valida vacia")
        elif perdidas * 100 > UMBRAL_PERDIDAS_PCT * esperadas:
            motivos.append(f"muestras perdidas {perdidas} de {esperadas} (> {UMBRAL_PERDIDAS_PCT} %)")

    # Reproducción: el fenómeno que se diagnostica tiene que estar presente.
    p95 = reproduccion.get("p95_ms", {})
    slo = reproduccion.get("slo_ms", {})
    for victima, limite in slo.items():
        valor = p95.get(victima)
        # Un p95 None (sin respuestas en la INUNDACIÓN) cuenta como infinito,
        # igual que en L2 (victimas_medianas de lanzar.py).
        if valor is not None and valor <= limite:
            motivos.append(f"reproduccion: p95 de {victima} {valor:.0f} ms <= SLO {limite} ms")
    if not slo:
        motivos.append("reproduccion: sin SLO de victimas")
    if reproduccion.get("n429", 0) != 0:
        motivos.append(f"reproduccion: {reproduccion.get('n429')} respuestas 429")
    if muestras:
        # Acumulado desde que arrancó el proceso (el contador empieza en 0 y los
        # controles usan contadores propios): cubre todas las peticiones servidas.
        caddy = muestras[-1]["cliente_caddy"]
        cifras["cliente_caddy"] = caddy
        if caddy != 0:
            motivos.append(f"booleano de proxy True: {caddy} peticiones con el cliente igual a la IP de Caddy")
    else:
        motivos.append("sin muestras")

    # Cuentas cruzadas en la ventana: lambda, middleware y k6 en ±1 %.
    tasa_lambda = None
    if len(validas) >= 2:
        primera, ultima = validas[0], validas[-1]
        duracion = ultima["t"] - primera["t"]
        n_lambda = ultima["lambda_total"] - primera["lambda_total"]
        n_http = ultima["http_contadas"] - primera["http_contadas"]
        n_k6 = sum(1 for t in inicios_k6 if primera["t"] < t <= ultima["t"])
        cifras.update({"lambda_ventana": n_lambda, "middleware_ventana": n_http, "k6_ventana": n_k6,
                       "duracion_ventana_s": duracion})
        if not (_dentro_de_tolerancia(n_lambda, n_k6) and _dentro_de_tolerancia(n_http, n_k6)
                and _dentro_de_tolerancia(n_lambda, n_http)):
            motivos.append(f"lambda {n_lambda}, middleware {n_http} y k6 {n_k6} no coinciden en +-1 %")
        if duracion > 0 and n_lambda > 0:
            tasa_lambda = n_lambda / duracion
        else:
            motivos.append("lambda nula en la ventana")
    elif ventana is not None:
        motivos.append("menos de 2 muestras en la ventana")
    if any(m.get("pool_espera") is None for m in validas):
        motivos.append("muestras sin estadisticas del pool")

    # --- cifras de las hipótesis (se calculan siempre, para publicarlas) ---
    retraso_p95 = percentil_95([m["retraso_s"] for m in validas])
    cpu_proceso = _mediana([m.get("cpu_proceso") for m in validas])
    cpu_principal = _mediana([m.get("cpu_principal") for m in validas])
    llenas = sum(1 for m in validas if m["prestados"] == PRESTADOS_LLENO)
    espera_anyio = _mediana([m["en_espera"] for m in validas])
    espera_pool = _mediana([m.get("pool_espera") for m in validas])
    w_anyio = espera_anyio / tasa_lambda if tasa_lambda and espera_anyio is not None else None
    frac_sem_argon2 = _mediana([fraccion_no_libres(m["clases"], ("semaforo", "argon2")) for m in validas])
    frac_pool = _mediana([fraccion_no_libres(m["clases"], ("pool",)) for m in validas])
    espera_media_pool = None
    if len(validas) >= 2:
        d_encoladas = validas[-1].get("pool_encoladas", 0) - validas[0].get("pool_encoladas", 0)
        d_espera_ms = validas[-1].get("pool_espera_ms", 0) - validas[0].get("pool_espera_ms", 0)
        espera_media_pool = d_espera_ms / d_encoladas if d_encoladas > 0 else NO_APLICA
    cifras.update({"retraso_p95_s": retraso_p95, "cpu_proceso_mediana": cpu_proceso,
                   "cpu_principal_mediana": cpu_principal, "muestras_40_prestados": llenas,
                   "lambda_por_s": tasa_lambda, "en_espera_mediana": espera_anyio, "w_anyio_s": w_anyio,
                   "pool_espera_mediana": espera_pool, "espera_media_pool_ms": espera_media_pool,
                   "fraccion_semaforo_argon2": frac_sem_argon2, "fraccion_pool": frac_pool})
    for nombre, valor in (("retraso", retraso_p95), ("CPU del proceso", cpu_proceso),
                          ("CPU del hilo principal", cpu_principal)):
        if validas and valor is None:
            motivos.append(f"sin datos de {nombre} en la ventana")

    if motivos:
        return {"decision": SIN_CONCLUSION, "fila": 1, "motivos": motivos, "cifras": cifras}

    # --- fila 2: H-bucle --------------------------------------------------
    if retraso_p95 >= UMBRAL_RETRASO_P95_S:
        return {"decision": PARADA, "fila": 2, "cifras": cifras,
                "motivos": [f"H-bucle: p95 del retraso {retraso_p95:.3f} s >= {UMBRAL_RETRASO_P95_S} s"]}
    # --- fila 3: H-CPU/GIL ------------------------------------------------
    if cpu_proceso >= UMBRAL_CPU_PROCESO or cpu_principal >= UMBRAL_CPU_PRINCIPAL:
        return {"decision": PARADA_M1, "fila": 3, "cifras": cifras,
                "motivos": [f"H-CPU/GIL: CPU del proceso {cpu_proceso:.2f} (umbral {UMBRAL_CPU_PROCESO}), "
                            f"hilo principal {cpu_principal:.2f} (umbral {UMBRAL_CPU_PRINCIPAL})"]}
    # --- fila 4: H-hilos --------------------------------------------------
    llenas_ok = llenas * 100 >= UMBRAL_PRESTADOS_PCT * len(validas)
    if (llenas_ok and w_anyio >= UMBRAL_W_ANYIO_S and espera_pool <= MAX_ESPERA_POOL_HILOS
            and frac_sem_argon2 is not None and frac_sem_argon2 >= UMBRAL_FRACCION):
        return {"decision": A2, "fila": 4, "cifras": cifras,
                "motivos": [f"H-hilos: 40 prestados en {llenas} de {len(validas)} muestras, W_AnyIO {w_anyio:.2f} s, "
                            f"mediana de requests_waiting {espera_pool}, fraccion semaforo + argon2 "
                            f"{frac_sem_argon2:.2f}"]}
    # --- fila 5: H-bd -----------------------------------------------------
    espera_ok = espera_media_pool == NO_APLICA or espera_media_pool >= UMBRAL_ESPERA_POOL_MS
    if espera_pool >= MIN_ESPERA_POOL_BD and espera_ok and frac_pool is not None and frac_pool >= UMBRAL_FRACCION:
        return {"decision": A2_CON_NOTA, "fila": 5, "cifras": cifras,
                "motivos": [f"H-bd: mediana de requests_waiting {espera_pool}, espera media {espera_media_pool}, "
                            f"fraccion pool {frac_pool:.2f}"]}
    # --- fila 6 -----------------------------------------------------------
    return {"decision": PARADA, "fila": 6, "cifras": cifras,
            "motivos": ["ninguna hipotesis de la tabla se cumple"]}


# ---------------------------------------------------------------------------
# Proceso de diagnóstico (solo dentro del contenedor de la API)
# ---------------------------------------------------------------------------
TAREAS_VIVAS = set()  # referencia fuerte a la tarea de muestreo (el bucle solo guarda débiles)


async def esperar_hasta(objetivo):
    """Duerme hasta `objetivo` (reloj del bucle) y devuelve cuánto tarde se
    despertó: el retraso del bucle. La usan el muestreo y su control."""
    bucle = asyncio.get_running_loop()
    await asyncio.sleep(max(0.0, objetivo - bucle.time()))
    return bucle.time() - objetivo


async def esperar_condicion(condicion, plazo_s, paso_s=0.02):
    """Sondea `condicion()` hasta que devuelva algo verdadero (lo devuelve) o
    venza el plazo (None)."""
    limite = time.monotonic() + plazo_s
    while True:
        valor = condicion()
        if valor:
            return valor
        if time.monotonic() >= limite:
            return None
        await asyncio.sleep(paso_s)


def pila_de(marco):
    """(co_filename, co_name) de cada marco, de dentro afuera. Solo esos dos
    campos: ni f_locals ni repr de nada."""
    pila = []
    while marco is not None and len(pila) < 400:
        codigo = marco.f_code
        pila.append((codigo.co_filename, codigo.co_name))
        marco = marco.f_back
    return pila


def _leer_ticks(ruta):
    with open(ruta, "rb") as fichero:
        return ticks_de_stat(fichero.read().decode("ascii", "replace"))


class Muestreador:
    def __init__(self, contador_lambda, contador_asgi, obtener_pool):
        self.contador_lambda = contador_lambda
        self.contador_asgi = contador_asgi
        self.obtener_pool = obtener_pool
        self.tid_principal = threading.main_thread().native_id
        self.hz = os.sysconf("SC_CLK_TCK")
        self.previo = None  # (monotonic, ticks del proceso, {tid: ticks})
        self.n = 0

    def clases_anyio(self):
        """({clase: n}, {"fichero:funcion": n} de los "otra", [tid de AnyIO])."""
        from anyio._backends._asyncio import WorkerThread
        cuenta = dict.fromkeys(CLASES, 0)
        otras = collections.Counter()
        tids = []
        marcos = sys._current_frames()
        try:
            for hilo in threading.enumerate():
                if not es_hilo_anyio(hilo.name, isinstance(hilo, WorkerThread)):
                    continue
                marco = marcos.get(hilo.ident)
                if marco is None:
                    continue
                pila = pila_de(marco)
                marco = None
                clase = clasificar_pila(pila)
                cuenta[clase] += 1
                tids.append(hilo.native_id)
                if clase == "otra" and pila:
                    otras[resumen_marco(pila[0])] += 1
        finally:
            # Los marcos de otros hilos no deben quedar referenciados.
            del marcos
        return cuenta, dict(otras.most_common(3)), tids

    def _cpu(self, tids_anyio):
        ahora = time.monotonic()
        proceso = _leer_ticks("/proc/self/stat")
        tids_argon2 = [h.native_id for h in threading.enumerate() if h.name.startswith("argon2_")]
        por_hilo = {}
        for tid in {self.tid_principal, *tids_anyio, *tids_argon2}:
            try:
                por_hilo[tid] = _leer_ticks(f"/proc/self/task/{tid}/stat")
            except (OSError, ValueError, IndexError):
                continue  # el hilo terminó entre enumerate y la lectura
        previo, self.previo = self.previo, (ahora, proceso, por_hilo)
        if previo is None or ahora <= previo[0]:
            return {"cpu_proceso": None, "cpu_principal": None, "cpu_argon2": None, "cpu_anyio": None}
        segundos = (ahora - previo[0]) * self.hz

        def suma(tids):
            return sum(por_hilo[t] - previo[2].get(t, 0) for t in tids if t in por_hilo) / segundos

        return {"cpu_proceso": (proceso - previo[1]) / segundos, "cpu_principal": suma([self.tid_principal]),
                "cpu_argon2": suma(tids_argon2), "cpu_anyio": suma(tids_anyio)}

    def tomar_muestra(self, retraso):
        import anyio.to_thread
        t = time.time()
        estadisticas = anyio.to_thread.current_default_thread_limiter().statistics()
        pool = self.obtener_pool()
        stats = pool.get_stats() if pool is not None else None
        clases, otras, tids = self.clases_anyio()
        self.n += 1
        muestra = {"tipo": "muestra", "n": self.n, "t": t, "retraso_s": retraso,
                   "prestados": estadisticas.borrowed_tokens, "fichas": estadisticas.total_tokens,
                   "en_espera": estadisticas.tasks_waiting, "clases": clases, "otras": otras,
                   "hilos_anyio": len(tids), "lambda_total": self.contador_lambda.llamadas,
                   "http_contadas": self.contador_asgi.peticiones, "cliente_caddy": self.contador_asgi.cliente_caddy,
                   "pool_espera": None, "pool_encoladas": None, "pool_espera_ms": None, "pool_conexiones": None}
        if stats is not None:
            # Los contadores de psycopg_pool 3.3.3 son un Counter: una clave que
            # nunca se incrementó no aparece (base.py:154-160). Falta = 0.
            muestra.update({"pool_espera": stats.get("requests_waiting"),
                            "pool_encoladas": stats.get("requests_queued", 0),
                            "pool_espera_ms": stats.get("requests_wait_ms", 0),
                            "pool_conexiones": stats.get("pool_size")})
        muestra.update(self._cpu(tids))
        return muestra

    async def bucle(self, listo):
        """Una muestra cada 0,5 s en una rejilla fija del reloj del bucle. Si
        el bucle se retrasa más de un periodo, las muestras de en medio se
        pierden (la evaluación las cuenta por la hora real) y la rejilla se
        recoloca. No captura CancelledError: al parar no escribe nada."""
        await listo.wait()
        bucle = asyncio.get_running_loop()
        objetivo = bucle.time()
        while True:
            objetivo += PERIODO_S
            retraso = await esperar_hasta(objetivo)
            if retraso >= PERIODO_S:
                objetivo += math.floor(retraso / PERIODO_S) * PERIODO_S
            try:
                muestra = self.tomar_muestra(retraso)
            except Exception as error:  # noqa: BLE001 - visible en la salida y en la evaluación
                muestra = {"tipo": "error_muestra", "t": time.time(), "clase": type(error).__name__}
            emitir(muestra)


class Contexto:
    def __init__(self, aplicacion, config, contador_lambda, contador_asgi, muestreador):
        self.aplicacion = aplicacion
        self.config = config
        self.contador_lambda = contador_lambda
        self.contador_asgi = contador_asgi
        self.muestreador = muestreador

    def clases(self):
        return self.muestreador.clases_anyio()[0]

    def clase_vista(self, clase):
        """Las clases de los hilos de AnyIO si exactamente uno está en `clase`;
        si no, None (para esperar_condicion)."""
        clases = self.clases()
        return clases if clases[clase] == 1 else None


def _nombres_excepcion(error):
    nombres = [type(error).__name__]
    nombres += [type(e).__name__ for e in getattr(error, "exceptions", ())]
    return nombres


# --- controles positivos ----------------------------------------------------
async def control_booleano_proxy(ctx, proxy=None):
    """La misma petición (cliente 10.88.0.2 con X-Forwarded-For 192.0.2.10)
    por tres pilas ASGI con el mismo ContadorAsgi: con ProxyHeadersMiddleware
    y la configuración efectiva da False; sin el middleware
    (proxy_headers=False) y con forwarded_allow_ips que no incluye a Caddy
    (10.88.0.3), True. Si el booleano no distingue estos casos, su False en
    la carga no prueba nada."""
    if proxy is None:
        from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware as proxy

    async def eco(scope, receive, send):
        return None

    async def recibir():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def enviar(mensaje):
        return None

    async def visto(pila, contador):
        scope = {"type": "http", "method": "GET", "path": "/control", "headers": [(b"x-forwarded-for", b"192.0.2.10")],
                 "client": ("10.88.0.2", 40000), "scheme": "http", "query_string": b""}
        await pila(scope, recibir, enviar)
        return contador.cliente_caddy > 0

    con_proxy = ContadorAsgi(eco)
    sin_proxy = ContadorAsgi(eco)
    fuera = ContadorAsgi(eco)
    resultado = {
        "proxy_headers_true": await visto(proxy(con_proxy, trusted_hosts=ctx.config.forwarded_allow_ips), con_proxy),
        "proxy_headers_false": await visto(sin_proxy, sin_proxy),
        "ip_fuera_de_forwarded": await visto(proxy(fuera, trusted_hosts="10.88.0.3"), fuera),
    }
    ok = resultado == {"proxy_headers_true": False, "proxy_headers_false": True, "ip_fuera_de_forwarded": True}
    return [("booleano_proxy", ok, resultado)]


async def control_retraso_bucle(ctx):
    """time.sleep(0,5) en el bucle con una espera ya vencida: la misma
    esperar_hasta del muestreo debe dar un retraso >= 0,5 s. La tarea se
    crea y el bucle se bloquea sin ceder antes: la tarea solo puede correr
    después del bloqueo."""
    bucle = asyncio.get_running_loop()
    tarea = asyncio.create_task(esperar_hasta(bucle.time()))
    time.sleep(0.5)  # noqa: ASYNC251 - el bloqueo del bucle ES el control
    retraso = await tarea
    return [("retraso_bucle", retraso >= 0.5, {"retraso_s": round(retraso, 4)})]


async def control_limitador_41(ctx):
    """41 llamadas a to_thread.run_sync con el limitador por defecto: 40
    prestados y 1 en espera; el envoltorio de lambda cuenta 41 y al acabar
    no queda ninguna ficha prestada."""
    import anyio
    import anyio.to_thread
    limitador = anyio.to_thread.current_default_thread_limiter()
    soltar = threading.Event()
    antes = ctx.contador_lambda.llamadas

    def lleno():
        e = limitador.statistics()
        return {"prestados": e.borrowed_tokens, "en_espera": e.tasks_waiting} \
            if e.borrowed_tokens == 40 and e.tasks_waiting == 1 else None

    visto = None
    try:
        async with anyio.create_task_group() as grupo:
            for _ in range(41):
                grupo.start_soon(anyio.to_thread.run_sync, soltar.wait, ESPERA_SEGURIDAD_S)
            visto = await esperar_condicion(lleno, 5.0)
            soltar.set()
    finally:
        soltar.set()
    contadas = ctx.contador_lambda.llamadas - antes
    al_final = limitador.statistics().borrowed_tokens
    detalle = {"visto": visto, "llamadas_lambda": contadas, "prestados_al_final": al_final}
    return [("limitador_41", visto is not None and contadas == 41 and al_final == 0, detalle)]


async def control_cpu_hilo(ctx):
    """Un hilo en bucle activo 2 s debe dar >= 0,9 CPU y uno dormido 2 s,
    <= 0,05, leídos con la misma lectura de /proc/self/task/<tid>/stat del
    muestreo."""
    import anyio
    import anyio.to_thread
    hz = os.sysconf("SC_CLK_TCK")
    resultado = {}

    def medir(nombre, activo):
        tid = threading.get_native_id()
        ruta = f"/proc/self/task/{tid}/stat"
        ticks0, t0 = _leer_ticks(ruta), time.monotonic()
        if activo:
            while time.monotonic() - t0 < 2.0:
                pass
        else:
            time.sleep(2.0)
        resultado[nombre] = (_leer_ticks(ruta) - ticks0) / hz / (time.monotonic() - t0)

    async with anyio.create_task_group() as grupo:
        grupo.start_soon(anyio.to_thread.run_sync, medir, "activo", True)
        grupo.start_soon(anyio.to_thread.run_sync, medir, "dormido", False)
    ok = resultado.get("activo", 0) >= 0.9 and resultado.get("dormido", 1) <= 0.05
    return [("cpu_hilo", ok, {k: round(v, 3) for k, v in resultado.items()})]


async def control_semaforo(ctx):
    """Con los 2 huecos de _semaforo tomados por el control, un hilo de AnyIO
    en _tomar_hueco_hash debe clasificarse como semaforo. Después se sueltan
    y _semaforo vuelve a tener sus 2 huecos libres."""
    import anyio
    import anyio.to_thread
    from app import personal
    tomados = 0
    visto = None
    try:
        for _ in range(2):
            if personal._semaforo.acquire(blocking=False):
                tomados += 1
        if tomados != 2:
            return [("semaforo", False, {"huecos_tomados": tomados})]

        def esperar_hueco():
            personal._tomar_hueco_hash()
            personal._semaforo.release()

        async with anyio.create_task_group() as grupo:
            grupo.start_soon(anyio.to_thread.run_sync, esperar_hueco)
            # Menos que ESPERA_HASH (2 s): si venciera, saldría Saturado y un
            # EVENTO hashes_saturados en el log.
            visto = await esperar_condicion(lambda: ctx.clase_vista("semaforo"), 1.0)
            for _ in range(tomados):
                personal._semaforo.release()
            tomados = 0
    finally:
        for _ in range(tomados):
            personal._semaforo.release()
    libres = personal._semaforo._value
    return [("semaforo", visto is not None and libres == 2, {"clases": visto, "huecos_libres_al_final": libres})]


class EjecutorFalsoLento:
    """Sustituye al ejecutor de Argon2 solo durante su control: no calcula
    nada y su futuro se resuelve a los 1,0 s."""

    def submit(self, funcion, *argumentos):
        import concurrent.futures
        futuro = concurrent.futures.Future()
        threading.Timer(1.0, futuro.set_result, (False,)).start()
        return futuro


def _volcar_locales(marco):
    """SOLO para el control positivo de la contraseña centinela: lo que haría
    un instrumento descuidado (repr de las locales de cada marco). El texto
    no sale nunca de memoria; solo se usa si contiene la centinela."""
    partes = []
    while marco is not None:
        partes.append(repr(marco.f_locals))
        marco = marco.f_back
    return "".join(partes)


async def control_ejecutor_lento(ctx):
    """Un hilo de AnyIO en la función real _verificar_en_ejecutor con un
    ejecutor falso lento debe clasificarse como argon2. Ese hilo lleva en sus
    locales una contraseña centinela: la muestra que escribiría el muestreo
    en ese instante no debe contenerla, y el volcado de las locales de ese
    hilo sí (control de que la centinela estaba al alcance). Al acabar, el
    ejecutor real vuelve a su sitio y _semaforo tiene sus 2 huecos."""
    import anyio
    import anyio.to_thread
    from anyio._backends._asyncio import WorkerThread
    from app import personal
    centinela = "centinela-" + secrets.token_hex(16)
    original = personal._ejecutor
    visto, en_muestra, en_volcado = None, None, None
    personal._ejecutor = EjecutorFalsoLento()
    try:
        async with anyio.create_task_group() as grupo:
            grupo.start_soon(anyio.to_thread.run_sync, personal._verificar_en_ejecutor, None, centinela)
            visto = await esperar_condicion(lambda: ctx.clase_vista("argon2"), 0.9)
            if visto is not None:
                en_muestra = centinela in linea_json(ctx.muestreador.tomar_muestra(0.0))
                marcos = sys._current_frames()
                try:
                    volcado = ""
                    for hilo in threading.enumerate():
                        if isinstance(hilo, WorkerThread) and hilo.ident in marcos:
                            pila = pila_de(marcos[hilo.ident])
                            if clasificar_pila(pila) == "argon2":
                                volcado += _volcar_locales(marcos[hilo.ident])
                    en_volcado = centinela in volcado
                    del volcado
                finally:
                    del marcos
    finally:
        personal._ejecutor = original
    libres = personal._semaforo._value
    restaurado = personal._ejecutor is original
    return [
        ("ejecutor_lento_argon2", visto is not None and restaurado and libres == 2,
         {"clases": visto, "ejecutor_restaurado": restaurado, "huecos_libres_al_final": libres}),
        ("centinela", en_muestra is False and en_volcado is True,
         {"en_muestra": en_muestra, "en_volcado_de_locales": en_volcado}),
    ]


async def control_pool(ctx):
    """En un pool APARTE, creado con la misma bd.crear_pool() de la API y
    cerrado al acabar (el pool de la API no se toca, así que no queda ninguna
    conexión de más para la carga):
    * 5 conexiones retenidas + 1 petición: requests_waiting = 1 y un hilo de
      AnyIO clasificado como pool;
    * select pg_sleep(1) en curso: un hilo clasificado como bd_activa."""
    import anyio
    import anyio.to_thread
    from app import bd
    pool = bd.crear_pool()
    await anyio.to_thread.run_sync(lambda: pool.open(wait=True, timeout=15))
    resultados = []
    try:
        soltar = threading.Event()

        def retener(obtenida):
            with pool.connection():
                obtenida.set()
                soltar.wait(ESPERA_SEGURIDAD_S)

        def sexta():
            with pool.connection():
                pass

        def en_cola():
            stats, clases = pool.get_stats(), ctx.clases()
            return {"requests_waiting": stats.get("requests_waiting"), "clases": clases} \
                if stats.get("requests_waiting") == 1 and clases["pool"] == 1 else None

        visto, retenidas = None, 0
        try:
            async with anyio.create_task_group() as grupo:
                # Una a una: con min_size 1 el pool crece bajo demanda, y la sexta
                # solo debe pedir cuando las 5 ya están dadas.
                for _ in range(5):
                    obtenida = threading.Event()
                    grupo.start_soon(anyio.to_thread.run_sync, retener, obtenida)
                    if await esperar_condicion(obtenida.is_set, 15.0) is None:
                        break
                    retenidas += 1
                if retenidas == 5:
                    grupo.start_soon(anyio.to_thread.run_sync, sexta)
                    visto = await esperar_condicion(en_cola, 3.0)
                soltar.set()
        finally:
            soltar.set()
        esperando_al_final = pool.get_stats().get("requests_waiting")
        resultados.append(("pool_5_mas_1", visto is not None and esperando_al_final == 0,
                           {"retenidas": retenidas, "visto": visto, "requests_waiting_al_final": esperando_al_final}))

        empieza = threading.Event()

        def dormir():
            with pool.connection() as conexion:
                empieza.set()
                conexion.execute("select pg_sleep(1)")

        visto = None
        async with anyio.create_task_group() as grupo:
            grupo.start_soon(anyio.to_thread.run_sync, dormir)
            if await esperar_condicion(empieza.is_set, 5.0) is not None:
                visto = await esperar_condicion(lambda: ctx.clase_vista("bd_activa"), 0.9)
        resultados.append(("pg_sleep_bd_activa", visto is not None, {"clases": visto}))
    finally:
        await anyio.to_thread.run_sync(pool.close)
    return resultados


async def ejecutar_controles(ctx):
    """Corre los controles en orden y escribe una línea por control. Una
    excepción deja ese control en FALLA con el nombre de su clase (nunca su
    texto) y los siguientes siguen."""
    for funcion, nombres in ((control_booleano_proxy, ("booleano_proxy",)),
                             (control_retraso_bucle, ("retraso_bucle",)),
                             (control_limitador_41, ("limitador_41",)),
                             (control_cpu_hilo, ("cpu_hilo",)),
                             (control_semaforo, ("semaforo",)),
                             (control_ejecutor_lento, ("ejecutor_lento_argon2", "centinela")),
                             (control_pool, ("pool_5_mas_1", "pg_sleep_bd_activa"))):
        try:
            resultados = await funcion(ctx)
        except Exception as error:  # noqa: BLE001 - el control queda en FALLA, visible
            resultados = [(n, False, {"excepcion": _nombres_excepcion(error)}) for n in nombres]
        for nombre, ok, detalle in resultados:
            emitir({"tipo": "control", "nombre": nombre, "resultado": "PASA" if ok else "FALLA", "detalle": detalle})
    emitir({"tipo": "controles_fin", "t": time.time()})


def con_controles(original, ctx, listo):
    """Envuelve el lifespan de la API: después de su arranque (pool abierto,
    base de datos y Redis verificados) corre los controles y solo entonces
    suelta el muestreo y deja que uvicorn abra el socket. Así los controles
    van antes de la carga: up --wait no ve la API sana hasta que terminan."""
    @contextlib.asynccontextmanager
    async def ciclo(app):
        async with original(app) as estado:
            await ejecutar_controles(ctx)
            listo.set()
            yield estado
    return ciclo


async def principal():
    sys.path.insert(0, RAIZ_API)
    import anyio.to_thread
    contador_lambda = ContadorLlamadas()
    # Antes de importar la API: si algún módulo se quedara con run_sync al
    # importarse, ya se llevaría el envoltorio.
    envolver_run_sync(anyio.to_thread, contador_lambda)
    import uvicorn
    contador_asgi = ContadorAsgi()
    # Config literal (plan v4, §2, A0): la command de docker-compose.yml:285-290
    # más el ENTRYPOINT del Dockerfile:64. Se crea ANTES de importar la API,
    # como hace la CLI de uvicorn (Config configura el logging en su __init__ y
    # la aplicación se importa después, en load).
    config = uvicorn.Config(contador_asgi, host="10.88.0.4", port=8000, proxy_headers=True,
                            forwarded_allow_ips="10.88.0.2", access_log=False, server_header=False)
    emitir({"tipo": "configuracion", "t": time.time(), "app": "app.principal:aplicacion", "host": config.host,
            "port": config.port, "proxy_headers": config.proxy_headers,
            "forwarded_allow_ips": config.forwarded_allow_ips, "access_log": config.access_log,
            "server_header": config.server_header, "uvicorn": uvicorn.__version__,
            "python": sys.version.split()[0]})
    from app.principal import aplicacion
    contador_asgi.app = aplicacion
    muestreador = Muestreador(contador_lambda, contador_asgi, lambda: getattr(aplicacion.state, "pool", None))
    ctx = Contexto(aplicacion, config, contador_lambda, contador_asgi, muestreador)
    listo = asyncio.Event()
    aplicacion.router.lifespan_context = con_controles(aplicacion.router.lifespan_context, ctx, listo)
    tarea = asyncio.create_task(muestreador.bucle(listo), name="diag_muestreo")
    TAREAS_VIVAS.add(tarea)
    await uvicorn.Server(config).serve()
    # Nada después de serve(): ver la docstring del módulo.


if __name__ == "__main__":
    asyncio.run(principal())
