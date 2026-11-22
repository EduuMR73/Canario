#!/usr/bin/env python3
"""Programa del banco D1 (diagnóstico de memoria) que corre DENTRO del
contenedor de la imagen canario_diag_api. Lo lanza
tests/estres/diagnosticar_memoria.py, montado de solo lectura, con
python -I -B -u. No contiene oráculos: solo mide y emite líneas JSON por
stdout; los veredictos se deciden en el host.

Modos:
* comprobar [--regresion]: la PARADA previa del plan (cgroup v2, ficheros y
  claves, glibc, usuario, import de app.personal y anyio). Una línea JSON.
  Con --regresion comprueba los nombres que usan los caminos de abajo.
* supervisor -- <modo del hijo y sus argumentos>: PID 1. Lanza el hijo,
  muestrea el cgroup y /proc/<hijo>/status cada 0,5 s y, cuando el hijo
  muere, registra su código y memory.events. No importa la API.
* carga: el hijo de las variantes D, A, A2, A-t, E, B y C2. Importa el
  módulo real app.personal y llama a _hueco_hash y _verificar_hash desde
  hilos de AnyIO, como la ruta def del login antes del arreglo R1 (sobre
  esa API, la del commit c1eaa13). Con --camino (modo --regresion del host,
  sobre la API arreglada):
  - viejo (D y V): el camino de antes del arreglo, reconstruido como
    control: el semáforo de la API y personal._hasher.verify en el propio
    hilo de AnyIO.
  - arreglo (R): el ejecutor de la API, creado con su misma
    iniciar_ejecutor_hashes(), y personal._verificar_en_ejecutor.
* reserva: el hijo del control positivo P.

Cada línea lleva "origen": "supervisor", "hijo" o "comprobacion". Nada se
escribe en disco: la raíz es de solo lectura y no hay tmpfs (plan, PID 1).
Solo biblioteca estándar más anyio y la propia API, que vienen en la imagen.
"""
import collections
import contextlib
import ctypes
import functools
import importlib.metadata
import json
import os
import platform
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET

CGROUP = "/sys/fs/cgroup"
# CGROUP2_SUPER_MAGIC de include/uapi/linux/magic.h: el tipo que stat -f
# imprime como cgroup2fs. Se comprueba el número, no un nombre.
MAGIA_CGROUP2 = 0x63677270
# Todos los ficheros del cgroup que usa el banco. Si falta uno, PARADA: no
# hay valores por defecto (plan, PARADA previa).
FICHEROS_CGROUP = ("memory.current", "memory.peak", "memory.max", "memory.stat", "memory.swap.current",
                   "memory.swap.max", "memory.events", "memory.pressure", "memory.oom.group")
# Claves fijas de memory.stat (hechos del plan: existen en el kernel 6.6 de
# la VM; pswpin y pswpout no, y por eso no se usan).
CLAVES_STAT = ("anon", "file", "kernel", "kernel_stack", "slab", "swapcached", "anon_thp")
CLAVES_EVENTOS = ("max", "oom", "oom_kill")
CLAVES_PRESION = ("avg10", "avg60", "avg300", "total")
CLAVES_STATUS = ("VmRSS", "RssAnon", "VmSwap")
CLAVES_HITO_CGROUP = ("anon", "swapcached")
# Campos de struct mallinfo2 en el orden de malloc/malloc.h de glibc.
CAMPOS_MALLINFO2 = ("arena", "ordblks", "smblks", "hblks", "hblkhd", "usmblks", "fsmblks", "uordblks", "fordblks",
                    "keepcost")
PERIODO_S = 0.5
MIB = 1 << 20
PAGINA = 4096
# Solo se envían los bloques libres de 1 MiB o más de malloc_info: el
# oráculo de C2 mira los de 19 MiB o más, y así cada línea cabe holgada en
# los 16 KiB a partir de los cuales Docker parte las líneas del log.
FILTRO_LIBRES = MIB
# Tiempos de verify() por línea, por el mismo motivo.
LOTE_TIEMPOS = 400
# Contraseña de la carga: un literal no secreto, el mismo en todas las
# llamadas. Nunca coincide con el hash ficticio, así que cada verify() es un
# Argon2 completo, como un login sin cuenta.
CONTRASENA = "diagnostico-memoria-canario-no-secreta"
# Lo único que el supervisor deja pasar al entorno del hijo: los ajustes de
# malloc de las variantes B y C2 (alias de los tunables de glibc).
ENTORNO_PERMITIDO = ("MALLOC_ARENA_MAX", "MALLOC_MMAP_THRESHOLD_")
# Rutas de la imagen (Dockerfile: COPY app/ /srv/app/). Con -I, Python no
# añade el directorio actual ni el del script a sys.path: se pone a mano y
# de forma explícita.
RAIZ_API = "/srv"
MUESTRAS_CALIBRADO = 5
# Nombres de app.personal que usa cada modo. Los de --regresion son los de
# los caminos viejo y arreglo sobre la API arreglada (_hueco_hash ya no
# existe).
NOMBRES_API = ("_hueco_hash", "_verificar_hash", "normalizar_contrasena", "Saturado")
NOMBRES_API_REGRESION = ("iniciar_ejecutor_hashes", "instalar_ejecutor_hashes", "_verificar_en_ejecutor",
                         "_verificar_hash", "_hasher", "_HASH_FICTICIO", "_semaforo", "ESPERA_HASH",
                         "normalizar_contrasena", "Saturado", "EjecutorNoDisponible")
CAMINOS = ("viejo", "arreglo")

_cerrojo_salida = threading.Lock()


class ErrorCgroup(Exception):
    """Falta un fichero o una clave del cgroup: PARADA en el host."""


class ErrorConfiguracion(Exception):
    """Argumentos del supervisor no válidos: PARADA en el host."""


# ---------------------------------------------------------------------------
# Salida
# ---------------------------------------------------------------------------
def emitir(objeto):
    """Una línea JSON por stdout, sin búfer y con cerrojo: el supervisor
    escribe desde dos hilos (muestreo y reenvío del hijo)."""
    linea = json.dumps(objeto, separators=(",", ":"))
    with _cerrojo_salida:
        sys.stdout.write(linea + "\n")
        sys.stdout.flush()


# ---------------------------------------------------------------------------
# cgroup v2 (lo usan el supervisor, el hijo en los hitos y la comprobación)
# ---------------------------------------------------------------------------
def leer_cgroup(nombre):
    try:
        with open(os.path.join(CGROUP, nombre), encoding="ascii") as fichero:
            return fichero.read()
    except OSError as error:
        raise ErrorCgroup(f"no se puede leer {nombre}: {type(error).__name__}") from None


def entero_cgroup(nombre):
    texto = leer_cgroup(nombre).strip()
    if not texto.isdigit():
        raise ErrorCgroup(f"{nombre} no es un entero: {texto!r}")
    return int(texto)


def pares(texto, nombre, requeridas):
    """Fichero "clave valor" por línea; exige cada clave, sin defecto."""
    valores = {}
    for linea in texto.splitlines():
        partes = linea.split()
        if len(partes) == 2 and partes[1].isdigit():
            valores[partes[0]] = int(partes[1])
    faltan = [c for c in requeridas if c not in valores]
    if faltan:
        raise ErrorCgroup(f"{nombre} no tiene las claves {faltan}")
    return {c: valores[c] for c in requeridas}


def presion(texto):
    """memory.pressure: líneas "some ..." y "full ..." con avg10, avg60,
    avg300 y total."""
    resultado = {}
    for linea in texto.splitlines():
        tipo, _, resto = linea.partition(" ")
        campos = dict(par.split("=", 1) for par in resto.split() if "=" in par)
        if tipo in ("some", "full"):
            if any(c not in campos for c in CLAVES_PRESION):
                raise ErrorCgroup(f"memory.pressure ({tipo}) no tiene {CLAVES_PRESION}")
            resultado[tipo] = {c: float(campos[c]) for c in CLAVES_PRESION}
    if set(resultado) != {"some", "full"}:
        raise ErrorCgroup("memory.pressure no tiene las lineas some y full")
    return resultado


def muestra_cgroup():
    return {
        "current": entero_cgroup("memory.current"),
        "peak": entero_cgroup("memory.peak"),
        "stat": pares(leer_cgroup("memory.stat"), "memory.stat", CLAVES_STAT),
        "swap_current": entero_cgroup("memory.swap.current"),
        "eventos": pares(leer_cgroup("memory.events"), "memory.events", CLAVES_EVENTOS),
        "presion": presion(leer_cgroup("memory.pressure")),
    }


def tipo_sistema_ficheros():
    """(f_type de statfs, tipo de /proc/self/mountinfo) de /sys/fs/cgroup.
    struct statfs empieza por f_type (__fsword_t, un long) en x86_64; en
    otra arquitectura no se supone nada."""
    if platform.machine() != "x86_64":
        raise ErrorCgroup(f"arquitectura {platform.machine()}: el desplazamiento de f_type no esta comprobado")
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    memoria = ctypes.create_string_buffer(256)
    if libc.statfs(CGROUP.encode(), memoria) != 0:
        raise ErrorCgroup(f"statfs de {CGROUP} falla (errno {ctypes.get_errno()})")
    magia = ctypes.c_long.from_buffer(memoria).value
    montaje = None
    with open("/proc/self/mountinfo", encoding="utf-8") as fichero:
        for linea in fichero:
            izquierda, _, derecha = linea.partition(" - ")
            if izquierda.split()[4] == CGROUP:
                montaje = derecha.split()[0]
    return magia, montaje


def comprobar_cgroup():
    """PARADA previa: cgroup v2 con la magia de cgroup2fs y cada fichero y
    clave del banco. Devuelve los límites como texto crudo: el host los
    compara con sus literales."""
    magia, montaje = tipo_sistema_ficheros()
    if magia != MAGIA_CGROUP2 or montaje != "cgroup2":
        raise ErrorCgroup(f"{CGROUP} no es cgroup v2 (magia {magia:#x}, montaje {montaje!r})")
    for nombre in FICHEROS_CGROUP:
        leer_cgroup(nombre)
    muestra_cgroup()
    return {"magia": magia, "montaje": montaje, "memory.max": leer_cgroup("memory.max").strip(),
            "memory.swap.max": leer_cgroup("memory.swap.max").strip(),
            "memory.oom.group": leer_cgroup("memory.oom.group").strip()}


def cgroup_de_hito():
    """Lo que necesita la fórmula del retenido (anon + swap.current -
    swapcached), leído por el propio hijo en el mismo instante que su
    muestra de malloc: así el hito no depende de alinear dos relojes."""
    stat = pares(leer_cgroup("memory.stat"), "memory.stat", CLAVES_HITO_CGROUP)
    return {"anon": stat["anon"], "swapcached": stat["swapcached"],
            "swap_current": entero_cgroup("memory.swap.current")}


def entorno_comun():
    with open("/sys/kernel/mm/transparent_hugepage/enabled", encoding="ascii") as fichero:
        thp = fichero.read().strip()
    return {"glibc": os.confstr("CS_GNU_LIBC_VERSION"), "uid": os.getuid(), "gid": os.getgid(),
            "afinidad": sorted(os.sched_getaffinity(0)), "cpu_count": os.cpu_count(), "thp": thp,
            "maquina": platform.machine()}


# ---------------------------------------------------------------------------
# malloc de glibc por ctypes (solo el hijo)
# ---------------------------------------------------------------------------
class Mallinfo2(ctypes.Structure):
    _fields_ = [(campo, ctypes.c_size_t) for campo in CAMPOS_MALLINFO2]


def cargar_libc():
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    libc.mallinfo2.restype = Mallinfo2
    libc.mallinfo2.argtypes = []
    libc.open_memstream.restype = ctypes.c_void_p
    libc.open_memstream.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_size_t)]
    libc.malloc_info.restype = ctypes.c_int
    libc.malloc_info.argtypes = [ctypes.c_int, ctypes.c_void_p]
    libc.fclose.restype = ctypes.c_int
    libc.fclose.argtypes = [ctypes.c_void_p]
    libc.free.restype = None
    libc.free.argtypes = [ctypes.c_void_p]
    libc.malloc_trim.restype = ctypes.c_int
    libc.malloc_trim.argtypes = [ctypes.c_size_t]
    return libc


def mallinfo2(libc):
    """mallinfo2 suma todas las arenas (malloc.c, __libc_mallinfo2)."""
    m = libc.mallinfo2()
    return {campo: getattr(m, campo) for campo in CAMPOS_MALLINFO2}


def texto_malloc_info(libc):
    """malloc_info(0, FILE*) sobre un FILE* de open_memstream: en memoria,
    nunca en un fichero (raíz de solo lectura y sin tmpfs). El búfer lo
    reserva glibc y se libera con free tras fclose (plan, generador)."""
    bufer = ctypes.c_void_p()
    tamano = ctypes.c_size_t()
    flujo = libc.open_memstream(ctypes.byref(bufer), ctypes.byref(tamano))
    if not flujo:
        raise OSError(ctypes.get_errno(), "open_memstream falla")
    try:
        if libc.malloc_info(0, flujo) != 0:
            raise OSError(ctypes.get_errno(), "malloc_info falla")
    finally:
        cerrado = libc.fclose(flujo)
    try:
        if cerrado != 0:
            raise OSError(ctypes.get_errno(), "fclose del memstream falla")
        return ctypes.string_at(bufer, tamano.value)
    finally:
        libc.free(bufer)


def analizar_malloc_info(texto):
    """Arenas y mmap de la salida de malloc_info, con xml.etree (plan: nunca
    con expresiones regulares).

    Identificador estable de cada arena: malloc_info recorre la lista desde
    main_arena siguiendo ->next (malloc.c:5894-6051) y cada arena nueva se
    inserta justo detrás de main_arena (arena.c:671-676), así que nr=1 es
    siempre la MÁS NUEVA y el nr de una arena cambia cuando nace otra. Con N
    heaps, la arena de nr=k (k >= 1) recibe id = N - k: la más antigua es la
    1 y no cambia nunca. La principal es la 0."""
    raiz = ET.fromstring(texto)
    heaps = raiz.findall("heap")
    arenas = []
    for heap in heaps:
        nr = int(heap.get("nr"))
        sistema = [s for s in heap.findall("system") if s.get("type") == "current"]
        if len(sistema) != 1:
            raise ValueError(f"heap {nr} sin <system type=current>")
        libres = [[int(t.get(c)) for c in ("from", "to", "total", "count")]
                  for t in heap.find("sizes").findall("size") if int(t.get("to")) >= FILTRO_LIBRES]
        desordenados = [[int(t.get(c)) for c in ("from", "to", "total", "count")]
                        for t in heap.find("sizes").findall("unsorted")]
        arenas.append({"id": 0 if nr == 0 else len(heaps) - nr, "nr": nr, "sistema": int(sistema[0].get("size")),
                       "libres": libres, "desordenados": desordenados})
    mmap = [t for t in raiz.findall("total") if t.get("type") == "mmap"]
    if len(mmap) != 1:
        raise ValueError("malloc_info sin <total type=mmap>")
    return {"arenas": arenas, "mmap": {"count": int(mmap[0].get("count")), "size": int(mmap[0].get("size"))}}


# ---------------------------------------------------------------------------
# Modo comprobar
# ---------------------------------------------------------------------------
def main_comprobar(argumentos):
    resultado = {"origen": "comprobacion"}
    nombres = NOMBRES_API_REGRESION if "--regresion" in argumentos else NOMBRES_API
    try:
        resultado["cgroup"] = comprobar_cgroup()
        resultado["entorno"] = entorno_comun()
        sys.path.insert(0, RAIZ_API)
        from app import personal
        resultado["api"] = {n: hasattr(personal, n) for n in nombres}
        import inspect

        import anyio
        import anyio.to_thread
        resultado["anyio"] = importlib.metadata.version("anyio")
        parametro = inspect.signature(anyio.to_thread.run_sync).parameters["abandon_on_cancel"]
        resultado["abandon_on_cancel_por_defecto"] = parametro.default

        async def fichas():
            return anyio.to_thread.current_default_thread_limiter().total_tokens

        resultado["limitador_por_defecto"] = anyio.run(fichas, backend="asyncio")
    except Exception as error:  # noqa: BLE001 - cualquier fallo es la PARADA previa, con su clase y su texto
        resultado["error"] = f"{type(error).__name__}: {error}"
        emitir(resultado)
        return 1
    emitir(resultado)
    return 0


# ---------------------------------------------------------------------------
# Modo supervisor (PID 1)
# ---------------------------------------------------------------------------
def estado_proceso(pid):
    """VmRSS, RssAnon y VmSwap del hijo en bytes, o None si ya no existe."""
    try:
        with open(f"/proc/{pid}/status", encoding="ascii") as fichero:
            texto = fichero.read()
    except OSError:
        return None
    valores = {}
    for linea in texto.splitlines():
        clave, _, resto = linea.partition(":")
        if clave in CLAVES_STATUS:
            valores[clave] = int(resto.split()[0]) * 1024
    if any(c not in valores for c in CLAVES_STATUS):
        return None
    return valores


def reenviar(flujo):
    """Copia las líneas del hijo a la salida del supervisor: un solo
    escritor con cerrojo, así no se mezclan dos líneas en el log."""
    for crudo in iter(flujo.readline, b""):
        texto = crudo.decode("utf-8", "replace").rstrip("\n")
        with _cerrojo_salida:
            sys.stdout.write(texto + "\n")
            sys.stdout.flush()


def muestra_supervisor(pid):
    inicio = time.perf_counter()
    datos = muestra_cgroup()
    datos["hijo"] = estado_proceso(pid)
    return {"origen": "supervisor", "tipo": "muestra", "t": time.monotonic(),
            "dur": time.perf_counter() - inicio, **datos}


def entorno_hijo(asignaciones):
    entorno = dict(os.environ)
    for asignacion in asignaciones:
        clave, _, valor = asignacion.partition("=")
        if clave not in ENTORNO_PERMITIDO or not valor:
            raise ErrorConfiguracion(f"variable de entorno no permitida para el hijo: {clave!r}")
        entorno[clave] = valor
    return entorno


def main_supervisor(argumentos):
    if "--" not in argumentos:
        emitir({"origen": "supervisor", "tipo": "error", "motivo": "falta -- antes del modo del hijo"})
        return 2
    corte = argumentos.index("--")
    asignaciones = [a.removeprefix("--entorno=") for a in argumentos[:corte]]
    hijo_args = argumentos[corte + 1:]
    try:
        limites = comprobar_cgroup()
        entorno = entorno_hijo(asignaciones)
        inicial = muestra_cgroup()
    except (ErrorCgroup, ErrorConfiguracion) as error:
        emitir({"origen": "supervisor", "tipo": "error", "motivo": str(error)})
        return 3
    emitir({"origen": "supervisor", "tipo": "inicio", "t": time.monotonic(), "limites": limites,
            "eventos": inicial["eventos"], "entorno": entorno_comun(), "entorno_hijo": asignaciones})
    hijo = subprocess.Popen([sys.executable, "-I", "-B", "-u", os.path.abspath(__file__), *hijo_args],
                            stdout=subprocess.PIPE, env=entorno)
    hilo = threading.Thread(target=reenviar, args=(hijo.stdout,), daemon=True)
    hilo.start()
    # Muestreo por reloj absoluto: la duración de cada muestra no desplaza
    # las siguientes.
    siguiente = time.monotonic()
    while hijo.poll() is None:
        emitir(muestra_supervisor(hijo.pid))
        siguiente += PERIODO_S
        time.sleep(max(0.0, siguiente - time.monotonic()))
    hilo.join(timeout=30)
    final = muestra_supervisor(hijo.pid)
    emitir(final)
    # OOMKilled de docker inspect no sirve aquí: con memory.oom.group = 0 el
    # kernel mata al hijo, no al contenedor (plan, PID 1).
    emitir({"origen": "supervisor", "tipo": "fin_hijo", "t": time.monotonic(), "codigo": hijo.returncode,
            "eventos": final["eventos"], "peak": final["peak"]})
    return 0


# ---------------------------------------------------------------------------
# Modo reserva (control positivo P)
# ---------------------------------------------------------------------------
def main_reserva(argumentos):
    extra = int(valor_de(argumentos, "--extra-mib")) * MIB
    trozo = int(valor_de(argumentos, "--trozo-mib")) * MIB
    pausa = float(valor_de(argumentos, "--pausa"))
    # memory.max + swap.max + extra, leídos dentro: si alguno es "max" no hay
    # tope que rebasar y entero_cgroup lo rechaza.
    objetivo = entero_cgroup("memory.max") + entero_cgroup("memory.swap.max") + extra
    emitir({"origen": "hijo", "tipo": "reserva_inicio", "t": time.monotonic(), "objetivo": objetivo})
    trozos = []
    reservado = 0
    while reservado < objetivo:
        bloque = bytearray(trozo)
        # Un byte distinto de cero por página: cada página queda escrita y
        # cuenta como anon aunque el núcleo la hubiera dado a cero sin tocar.
        for posicion in range(0, trozo, PAGINA):
            bloque[posicion] = 1
        trozos.append(bloque)
        reservado += trozo
        emitir({"origen": "hijo", "tipo": "reserva", "t": time.monotonic(), "reservado": reservado})
        # Pausa entre trozos: sin ella los 600 MiB se escriben en menos de un
        # periodo de muestreo y no se verían "muestras subiendo hasta el
        # kill" (plan, variante P).
        time.sleep(pausa)
    emitir({"origen": "hijo", "tipo": "fin", "t": time.monotonic(), "motivo": "reserva_completa_sin_oom"})
    return 0


def valor_de(argumentos, nombre):
    if nombre not in argumentos:
        raise SystemExit(f"falta {nombre}")
    return argumentos[argumentos.index(nombre) + 1]


# ---------------------------------------------------------------------------
# Modo carga (hijo de D, A, A2, A-t, E, B y C2)
# ---------------------------------------------------------------------------
class Estado:
    """Contadores compartidos. pendientes solo lo toca el hilo del bucle;
    en_curso lo tocan los hilos de trabajo, con cerrojo."""

    def __init__(self):
        self.pendientes = 0
        self.en_curso = 0
        self.cerrojo = threading.Lock()


class Fase:
    def __init__(self, nombre, tasa, duracion):
        self.nombre, self.tasa, self.duracion = nombre, tasa, duracion
        self.llegadas = round(tasa * duracion)
        self.correctos = 0
        self.saturados = 0
        self.otras = collections.Counter()
        self.tiempos = []
        # Latencia total del llamante (solo el camino arreglo; informativa).
        self.latencias = []
        self.pendientes_max = 0
        self.retraso_max = 0.0
        self.tope_superado = False
        self.creadas = 0


def leer_fases(texto):
    """"F1:51:60,R1:0:15,..." -> [Fase]. Tasa 0 es reposo."""
    fases = []
    for parte in texto.split(","):
        nombre, tasa, duracion = parte.split(":")
        fases.append(Fase(nombre, float(tasa), float(duracion)))
    return fases


# interna: lo que dura el verify() (el intervalo de D1); latencia: lo que
# espera el llamante en total, o None si es el mismo intervalo.
Medida = collections.namedtuple("Medida", "interna latencia")


def llamar_hash(estado, hueco, verificar):
    """Una llamada como la del login antes del arreglo: el hueco del
    semáforo de la API y, dentro, un verify() completo en el mismo hilo.
    Solo se cronometra lo de dentro del hueco (plan, generador)."""
    with hueco():
        with estado.cerrojo:
            estado.en_curso += 1
        try:
            inicio = time.perf_counter()
            verificar()
            return Medida(time.perf_counter() - inicio, None)
        finally:
            with estado.cerrojo:
                estado.en_curso -= 1


def llamar_arreglo(estado, verificar):
    """Una llamada como la del login con el arreglo: el hueco y el verify()
    los hace personal._verificar_en_ejecutor. verificar() devuelve (resultado,
    duración dentro del hilo argon2); se cronometra además la espera total
    del llamante, informativa (plan R1, Tiempos)."""
    with estado.cerrojo:
        estado.en_curso += 1
    try:
        inicio = time.perf_counter()
        _, interna = verificar()
        return Medida(interna, time.perf_counter() - inicio)
    finally:
        with estado.cerrojo:
            estado.en_curso -= 1


async def tarea(anyio, estado, fase, llamada, saturado, excluidas):
    """Captura Saturado y cualquier otra excepción y las cuenta, sin
    dejarlas salir: en un TaskGroup una excepción cancelaría a las
    hermanas (plan). La cancelación (BaseException) sí sale. excluidas son
    subclases de Saturado que NO son saturación (EjecutorNoDisponible en el
    camino arreglo): se cuentan como "otras", y el host da SIN CONCLUSION."""
    try:
        medida = await anyio.to_thread.run_sync(llamada)
    except excluidas as error:
        fase.otras[type(error).__name__] += 1
    except saturado:
        fase.saturados += 1
    except Exception as error:  # noqa: BLE001 - se cuenta por clase; el host la convierte en SIN CONCLUSION
        fase.otras[type(error).__name__] += 1
    else:
        fase.correctos += 1
        fase.tiempos.append(medida.interna)
        if medida.latencia is not None:
            fase.latencias.append(medida.latencia)
    finally:
        estado.pendientes -= 1


async def fase_de_carga(anyio, estado, fase, tope, llamada, saturado, excluidas):
    """Tasa de llegada abierta con reloj absoluto (loop.time() objetivo):
    el muestreo no desvía la tasa. El tope se comprueba antes de crear cada
    tarea; al cerrar la llegada, salir del TaskGroup es drenar la fase."""
    async with anyio.create_task_group() as grupo:
        inicio = anyio.current_time()
        for i in range(fase.llegadas):
            objetivo = inicio + i / fase.tasa
            await anyio.sleep_until(objetivo)
            fase.retraso_max = max(fase.retraso_max, anyio.current_time() - objetivo)
            if estado.pendientes >= tope:
                fase.tope_superado = True
                grupo.cancel_scope.cancel()
                break
            estado.pendientes += 1
            fase.creadas += 1
            fase.pendientes_max = max(fase.pendientes_max, estado.pendientes)
            grupo.start_soon(tarea, anyio, estado, fase, llamada, saturado, excluidas)
        emitir({"origen": "hijo", "tipo": "fin_llegadas", "fase": fase.nombre, "t": time.monotonic()})


def datos_malloc(libc):
    inicio = time.perf_counter()
    info = analizar_malloc_info(texto_malloc_info(libc))
    return {"mallinfo2": mallinfo2(libc), **info, "dur_malloc": time.perf_counter() - inicio}


def datos_tracemalloc():
    import tracemalloc
    if not tracemalloc.is_tracing():
        return None
    actual, pico = tracemalloc.get_traced_memory()
    return {"actual": actual, "pico": pico, "propia": tracemalloc.get_tracemalloc_memory()}


def muestra_hijo(libc, estado, tipo, **extra):
    """Desde el hilo del bucle, que usa la arena principal (plan)."""
    return {"origen": "hijo", "tipo": tipo, "t": time.monotonic(), **datos_malloc(libc),
            "en_curso": estado.en_curso, "pendientes": estado.pendientes, "hilos": threading.active_count(),
            "tracemalloc": datos_tracemalloc(), **extra}


def hito(libc, estado, nombre, **extra):
    emitir(muestra_hijo(libc, estado, "hito", nombre=nombre, cgroup=cgroup_de_hito(), **extra))


def emitir_fase(fase, inicio, fin):
    emitir({"origen": "hijo", "tipo": "fase", "nombre": fase.nombre, "inicio": inicio, "fin": fin,
            "tasa": fase.tasa, "duracion": fase.duracion, "llegadas_previstas": fase.llegadas,
            "creadas": fase.creadas, "correctos": fase.correctos, "saturados": fase.saturados,
            "otras": dict(fase.otras), "pendientes_max": fase.pendientes_max, "retraso_max": fase.retraso_max,
            "tope_superado": fase.tope_superado})
    for tipo, valores in (("tiempos", fase.tiempos), ("latencias", fase.latencias)):
        for desde in range(0, len(valores), LOTE_TIEMPOS):
            emitir({"origen": "hijo", "tipo": tipo, "fase": fase.nombre,
                    "valores": [round(v, 6) for v in valores[desde:desde + LOTE_TIEMPOS]]})


async def muestrear(anyio, libc, estado):
    siguiente = anyio.current_time()
    while True:
        siguiente += PERIODO_S
        await anyio.sleep_until(siguiente)
        emitir(muestra_hijo(libc, estado, "muestra"))


async def recorrer_fases(anyio, contexto):
    """Fases en orden, con un hito al final de cada una. Devuelve el motivo
    de fin."""
    estado, libc = contexto["estado"], contexto["libc"]
    for fase in contexto["fases"]:
        inicio = time.monotonic()
        emitir({"origen": "hijo", "tipo": "inicio_fase", "nombre": fase.nombre, "t": inicio})
        if fase.tasa > 0:
            await fase_de_carga(anyio, estado, fase, contexto["tope"], contexto["llamada"], contexto["saturado"],
                                contexto["excluidas"])
        else:
            await anyio.sleep_until(anyio.current_time() + fase.duracion)
        emitir_fase(fase, inicio, time.monotonic())
        if fase.tope_superado:
            return "tope"
        hito(libc, estado, f"fin_{fase.nombre}")
    # malloc_trim(0) al final: informativo (plan; en glibc 2.41 systrim solo
    # actúa sobre la arena principal, malloc.c:5255).
    resultado = libc.malloc_trim(0)
    hito(libc, estado, "tras_trim", malloc_trim=resultado)
    return "completo"


async def cuerpo(contexto):
    import anyio
    import anyio.to_thread
    limitador = anyio.to_thread.current_default_thread_limiter()
    emitir({"origen": "hijo", "tipo": "limitador", "por_defecto": limitador.total_tokens,
            "usado": contexto["hilos"]})
    # D usa el MISMO limitador por defecto con 1 ficha: el camino de código es
    # idéntico al de A, solo cambia el número de hilos.
    limitador.total_tokens = contexto["hilos"]
    hito(contexto["libc"], contexto["estado"], "base")
    motivo = "plazo"
    async with anyio.create_task_group() as muestreo:
        muestreo.start_soon(muestrear, anyio, contexto["libc"], contexto["estado"])
        # Plazo de la ejecución contado desde el arranque del hijo. Al
        # cancelar, to_thread.run_sync espera al hilo en curso
        # (abandon_on_cancel=False por defecto en anyio 4.15.1,
        # _backends/_asyncio.py:2671: CancelScope(shield=True)).
        with anyio.move_on_after(contexto["limite"] - anyio.current_time()):
            motivo = await recorrer_fases(anyio, contexto)
        muestreo.cancel_scope.cancel()
    if contexto["nombres_argon2"] is not None:
        # Hilos en los que corrió de verdad _verificar_hash (camino arreglo).
        emitir({"origen": "hijo", "tipo": "hilos_argon2", "t": time.monotonic(),
                "nombres": sorted(contexto["nombres_argon2"])})
    emitir({"origen": "hijo", "tipo": "fin", "t": time.monotonic(), "motivo": motivo})


def calibrar_e(personal, objetivo):
    """Variante E: su propio PasswordHasher con m = 64 KiB y la t (número de
    pasadas) que da unos `objetivo` segundos por verify(). Se mide con t = 1
    y se escala; luego se mide la t elegida y se informa."""
    from argon2 import PasswordHasher, Type
    from argon2.exceptions import InvalidHashError, VerificationError

    def hasher(pasadas):
        return PasswordHasher(time_cost=pasadas, memory_cost=64, parallelism=1, hash_len=32, salt_len=16,
                              type=Type.ID)

    def medir(h):
        guardado = h.hash(os.urandom(16).hex())
        tiempos = []
        for _ in range(MUESTRAS_CALIBRADO):
            inicio = time.perf_counter()
            try:
                h.verify(guardado, CONTRASENA)
            except (VerificationError, InvalidHashError):
                pass
            tiempos.append(time.perf_counter() - inicio)
        return sorted(tiempos)[MUESTRAS_CALIBRADO // 2], guardado

    unitario, _ = medir(hasher(1))
    pasadas = max(1, round(objetivo / unitario))
    elegido = hasher(pasadas)
    medido, guardado = medir(elegido)
    emitir({"origen": "hijo", "tipo": "calibrado_e", "memoria_kib": 64, "pasadas": pasadas,
            "verify_t1_s": unitario, "verify_s": medido, "objetivo_s": objetivo})

    def verificar():
        # Mismo patrón que _verificar_hash (app/personal.py:671-676).
        try:
            elegido.verify(guardado, personal.normalizar_contrasena(CONTRASENA))
        except (VerificationError, InvalidHashError):
            return False
        return True

    return verificar


def hueco_viejo(personal):
    """El _hueco_hash de la API antes del arreglo (app/personal.py del
    commit c1eaa13, :660-668), reconstruido aquí porque el arreglo lo
    eliminó: el semáforo REAL de la API, con su ESPERA_HASH y su Saturado.
    No registra el EVENTO: el banco no lee el log de la API."""
    @contextlib.contextmanager
    def hueco():
        if not personal._semaforo.acquire(timeout=personal.ESPERA_HASH):
            raise personal.Saturado
        try:
            yield
        finally:
            personal._semaforo.release()
    return hueco


def verificar_viejo(personal):
    """Control de --regresion (D y V): el _verificar_hash de antes del
    arreglo con una cuenta inexistente, llamando DIRECTAMENTE a
    personal._hasher.verify desde el hilo de AnyIO que hace la llamada. Es
    el camino que el banco D1 midió (cada hilo, su arena de 19 MiB): si V no
    lo reproduce en esta misma sesión e imagen (a >= 30 en F2), la mejora de
    R no tendría con qué compararse."""
    from argon2.exceptions import InvalidHashError, VerificationError

    def verificar():
        try:
            return personal._hasher.verify(personal._HASH_FICTICIO, personal.normalizar_contrasena(CONTRASENA))
        except (VerificationError, InvalidHashError):
            return False
    return verificar


def preparar_arreglo(personal):
    """R: el ejecutor de la API, creado e instalado con sus propias
    funciones (nunca una copia), y _verificar_en_ejecutor, la función real
    del login. Para medir el mismo intervalo que D1 (el verify() completo),
    _verificar_hash se envuelve con un cronómetro que corre dentro del hilo
    argon2 y devuelve (resultado, duración); _verificar_en_ejecutor devuelve
    tal cual lo que devuelve el ejecutor. La envoltura anota además en qué
    hilos corrió. Se hace antes de la muestra base: los 2 hilos ya existen,
    pero sus tareas de arranque no calculan Argon2."""
    ejecutor = personal.iniciar_ejecutor_hashes()
    personal.instalar_ejecutor_hashes(ejecutor)
    emitir({"origen": "hijo", "tipo": "ejecutor", "t": time.monotonic(),
            "hilos": sorted(hilo.name for hilo in ejecutor._threads), "max_workers": ejecutor._max_workers})
    real = personal._verificar_hash
    nombres = set()

    def cronometrado(hash_guardado, contrasena):
        inicio = time.perf_counter()
        resultado = real(hash_guardado, contrasena)
        duracion = time.perf_counter() - inicio
        nombres.add(threading.current_thread().name)
        return resultado, duracion

    personal._verificar_hash = cronometrado

    def verificar():
        return personal._verificar_en_ejecutor(None, personal.normalizar_contrasena(CONTRASENA))
    return verificar, nombres


def llamada_de_carga(personal, argumentos, estado):
    """(llamada sin argumentos, excepciones excluidas, hilos argon2 o None)
    según el camino. Sin --camino, el de D1 sobre la API de antes del
    arreglo, sin cambios."""
    camino = valor_de(argumentos, "--camino") if "--camino" in argumentos else None
    if camino is not None and camino not in CAMINOS:
        raise SystemExit(f"camino desconocido: {camino}")
    if camino == "arreglo":
        verificar, nombres = preparar_arreglo(personal)
        return functools.partial(llamar_arreglo, estado, verificar), (personal.EjecutorNoDisponible,), nombres
    if camino == "viejo":
        return functools.partial(llamar_hash, estado, hueco_viejo(personal), verificar_viejo(personal)), (), None
    if "--argon2-e" in argumentos:
        verificar = calibrar_e(personal, float(valor_de(argumentos, "--objetivo-e")))
    else:
        def verificar():
            return personal._verificar_hash(None, personal.normalizar_contrasena(CONTRASENA))
    return functools.partial(llamar_hash, estado, personal._hueco_hash, verificar), (), None


def main_carga(argumentos):
    arranque = time.monotonic()
    limite = arranque + float(valor_de(argumentos, "--plazo"))
    emitir({"origen": "hijo", "tipo": "entorno", "t": arranque, **entorno_comun(),
            "malloc": {c: os.environ.get(c) for c in ENTORNO_PERMITIDO},
            "anyio": importlib.metadata.version("anyio")})
    sys.path.insert(0, RAIZ_API)
    inicio = time.perf_counter()
    # El módulo REAL de la API: el import calcula _HASH_FICTICIO, que sube el
    # umbral dinámico de mmap (malloc.c:3457-3462). La base se toma después.
    from app import personal
    emitir({"origen": "hijo", "tipo": "import", "dur": time.perf_counter() - inicio})
    if "--tracemalloc" in argumentos:
        import tracemalloc
        tracemalloc.start()
    estado = Estado()
    llamada, excluidas, nombres_argon2 = llamada_de_carga(personal, argumentos, estado)
    contexto = {"estado": estado, "libc": cargar_libc(), "fases": leer_fases(valor_de(argumentos, "--fases")),
                "tope": int(valor_de(argumentos, "--tope")), "hilos": int(valor_de(argumentos, "--hilos")),
                "llamada": llamada, "saturado": personal.Saturado, "excluidas": excluidas,
                "nombres_argon2": nombres_argon2, "limite": limite}
    import anyio
    anyio.run(cuerpo, contexto, backend="asyncio")
    return 0


def main():
    if len(sys.argv) < 2:
        raise SystemExit("uso: diag_memoria_contenedor.py comprobar | supervisor ... -- <hijo> | carga ... | reserva ...")
    modo, resto = sys.argv[1], sys.argv[2:]
    if modo == "comprobar":
        return main_comprobar(resto)
    if modo == "supervisor":
        return main_supervisor(resto)
    if modo == "carga":
        return main_carga(resto)
    if modo == "reserva":
        return main_reserva(resto)
    raise SystemExit(f"modo desconocido: {modo}")


if __name__ == "__main__":
    sys.exit(main())
