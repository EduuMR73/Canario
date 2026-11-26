"""Pruebas unitarias del ejecutor de Argon2 (app/personal.py, "Argon2 en un
ejecutor propio"): todo hash de contraseña se calcula en uno de sus 2 hilos,
argon2_0 y argon2_1, nunca en el hilo de la petición.

Por qué importa (banco D1, 21/11/2026): cada hilo que calcula un Argon2 de
19 MiB retiene ese bloque en su arena de glibc. Con los 40 hilos de AnyIO
fueron 766 MiB retenidos y un OOM; con 2 hilos fijos, como mucho 2 bloques.
La memoria de verdad la mide el banco (tests/estres/diagnosticar_memoria.py
--regresion); aquí se comprueba la causa: en qué hilo corre cada hash, que el
semáforo siga acotando la espera y que los fallos sean visibles.

Oráculos literales: los nombres {"argon2_0", "argon2_1"}, los 2 hilos como
máximo, el texto de cada EVENTO y el 503 con su cuerpo. Donde hay muchos
hashes, _hasher se sustituye por un doble que solo anota el hilo: 40 Argon2
reales retendrían más de 700 MiB en el proceso de unittest y en cada
mutante. El Argon2 real lo ejercitan test_login y test_personal.
"""
import ast
import asyncio
import concurrent.futures
import contextlib
import logging
import pathlib
import threading
import time
import types
import unittest
import uuid
from unittest import mock

from fastapi import FastAPI

from app import bd, personal, rutas_personal, verificacion_arranque

NOMBRES_ARGON2 = frozenset({"argon2_0", "argon2_1"})
# El del semáforo interno (con el mamparo del login, un error en cada caso).
EVENTO_SATURADOS = "ERROR:canario.personal:EVENTO hashes_saturados_interno etapa=interna"
EVENTO_SIN_CREAR = "ERROR:canario.personal:EVENTO ejecutor_no_disponible: motivo=sin_crear"
EVENTO_CERRADO = "ERROR:canario.personal:EVENTO ejecutor_no_disponible: motivo=cerrado"
CUERPO_503 = '{"detalle": "servicio ocupado; inténtelo de nuevo en unos segundos"}'.encode()
# Sondeo del semáforo con todo libre: 2 huecos y ni uno más.
SEMAFORO_LIBRE = [True, True, False]
EMPRESA = uuid.UUID(int=1)
USUARIO = uuid.UUID(int=2)
DISPOSITIVO = uuid.UUID(int=3)
CONTRASENA_NUEVA = "Contrasena-nueva-12"
# 40 hilos, como el limitador por defecto de AnyIO, y 400 llamadas en total.
HILOS = 40
LLAMADAS = 400
# Espera del semáforo en las pruebas de saturación, y cuánto se observa a los
# llamantes bloqueados: 5 veces más, para que un result() con cualquier plazo
# de ese orden ya hubiera saltado.
ESPERA_CORTA = 0.2
OBSERVACION_S = 1.0
# Ningún doble espera más que esto: si una prueba falla a medias, el
# ejecutor compartido no se queda bloqueado para las siguientes.
PLAZO_SEGURIDAD_S = 30
EJECUTOR = None


def setUpModule():
    # Un solo ejecutor, creado con la función de la API, para todo el módulo.
    global EJECUTOR
    EJECUTOR = personal.iniciar_ejecutor_hashes()


class Detenido(Exception):
    """La lanza el doble para cortar un camino justo después del hash."""


class HasherDoble:
    """Sustituye a personal._hasher. Anota en qué hilo se le llama y avisa
    de cada entrada; si se le pide, espera un evento, duerme, lanza una
    excepción o pide otro hash desde dentro (llamada anidada)."""

    def __init__(self, dormir=0.0, bloqueo=None, error=None, anidar=False):
        self.dormir, self.bloqueo, self.error, self.anidar = dormir, bloqueo, error, anidar
        self.hilos = []
        self.dentro = threading.Semaphore(0)

    def _anotar(self):
        self.hilos.append(threading.current_thread().name)
        self.dentro.release()
        if self.bloqueo is not None:
            self.bloqueo.wait(PLAZO_SEGURIDAD_S)
        if self.dormir:
            time.sleep(self.dormir)
        if self.anidar:
            personal._crear_hash_en_ejecutor("anidada")
        if self.error is not None:
            raise self.error

    def verify(self, _guardado, _contrasena):
        self._anotar()
        return True

    def hash(self, _contrasena):
        self._anotar()
        return "$argon2id$doble"


def sondear_semaforo():
    """Cuántos huecos se pueden tomar sin esperar (hasta 3), y los devuelve."""
    tomados = [personal._semaforo.acquire(blocking=False) for _ in range(3)]
    for _ in range(sum(tomados)):
        personal._semaforo.release()
    return tomados


def en_hilos(funcion, veces):
    """Llama a funcion `veces` veces desde cada uno de HILOS hilos, que
    arrancan a la vez tras una barrera para forzar el solapamiento. Devuelve
    las excepciones (vacío si todo fue bien)."""
    barrera = threading.Barrier(HILOS, timeout=PLAZO_SEGURIDAD_S)
    errores = []

    def trabajar():
        try:
            barrera.wait()
            for _ in range(veces):
                funcion()
        except Exception as error:  # noqa: BLE001 - se devuelve a la prueba, que la muestra
            errores.append(error)

    hilos = [threading.Thread(target=trabajar, name=f"prueba_{i}") for i in range(HILOS)]
    for hilo in hilos:
        hilo.start()
    for hilo in hilos:
        hilo.join(PLAZO_SEGURIDAD_S)
    errores += [TimeoutError(f"{h.name} sigue vivo") for h in hilos if h.is_alive()]
    return errores


class ConEjecutor(unittest.TestCase):
    """Instala el ejecutor del módulo y lo restaura al terminar."""

    def setUp(self):
        self.enterContext(mock.patch.object(personal, "_ejecutor", EJECUTOR))


class Ejecutor(ConEjecutor):
    def test_dos_hilos_como_maximo(self):
        self.assertEqual(personal._ejecutor._max_workers, 2)
        self.assertEqual({hilo.name for hilo in personal._ejecutor._threads}, NOMBRES_ARGON2)

    def test_sin_dos_hilos_no_arranca(self):
        def de_un_hilo(max_workers, thread_name_prefix):
            return concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix=thread_name_prefix)

        # Control: con el ThreadPoolExecutor real, los 2 hilos exactos.
        sano = personal.iniciar_ejecutor_hashes()
        self.assertEqual({hilo.name for hilo in sano._threads}, NOMBRES_ARGON2)
        sano.shutdown(wait=True)
        # Con un solo hilo, la barrera de 2 no se abre: EjecutorNoArrancado.
        with mock.patch.object(personal, "ThreadPoolExecutor", de_un_hilo), \
                mock.patch.object(personal, "ESPERA_ARRANQUE_HILOS", ESPERA_CORTA), \
                self.assertRaises(personal.EjecutorNoArrancado) as error:
            personal.iniciar_ejecutor_hashes()
        self.assertEqual(str(error.exception), "la barrera de arranque no se abre en 0.2 s: menos de 2 hilos")


async def entrar(gestor):
    async with gestor:
        pass


def importar_principal():
    # app.principal llama a logging.basicConfig al importarse; aquí se evita
    # para que los registros de las demás pruebas no salgan por stderr.
    with mock.patch.object(logging, "basicConfig"):
        from app import principal
    return principal


class ArranqueDeLaApi(unittest.TestCase):
    def test_sin_ejecutor_la_api_no_arranca(self):
        principal = importar_principal()
        # Control: con el ejecutor real, el arranque pasa de este paso y lo
        # instala; se detiene en el siguiente (el secreto), a propósito.
        with mock.patch.object(personal, "_ejecutor", None), \
                mock.patch.object(bd, "comprobar_secreto", side_effect=bd.ErrorConfiguracion("prueba")), \
                self.assertLogs("canario.arranque", "ERROR") as registro, \
                self.assertRaises(verificacion_arranque.ArranqueBloqueado) as error:
            try:
                asyncio.run(entrar(principal.ciclo_de_vida(FastAPI())))
            finally:
                instalado = personal._ejecutor
        self.assertEqual(str(error.exception), "secreto")
        self.assertEqual(registro.output, ["ERROR:canario.arranque:ARRANQUE BLOQUEADO: secreto: prueba"])
        self.assertEqual({hilo.name for hilo in instalado._threads}, NOMBRES_ARGON2)
        # Sin los 2 hilos, la API no arranca y lo registra.
        with mock.patch.object(personal, "_ejecutor", None), \
                mock.patch.object(personal, "iniciar_ejecutor_hashes",
                                  side_effect=personal.EjecutorNoArrancado("motivo de prueba")), \
                self.assertLogs("canario.arranque", "ERROR") as registro, \
                self.assertRaises(verificacion_arranque.ArranqueBloqueado) as error:
            try:
                asyncio.run(entrar(principal.ciclo_de_vida(FastAPI())))
            finally:
                instalado = personal._ejecutor
        self.assertEqual(str(error.exception), "ejecutor_hashes")
        self.assertEqual(registro.output,
                         ["ERROR:canario.arranque:ARRANQUE BLOQUEADO: ejecutor_hashes: motivo de prueba"])
        self.assertIsNone(instalado)


class HilosDeArgon2(ConEjecutor):
    def test_cuarenta_hilos_solo_calculan_argon2_0_y_argon2_1(self):
        doble = HasherDoble(dormir=0.001)
        with mock.patch.object(personal, "_hasher", doble), mock.patch.object(personal, "ESPERA_HASH", 60.0):
            # Control: desde los mismos 40 hilos, la llamada directa (el
            # camino viejo) calcula en más de 2 hilos. Si no, la prueba no
            # distinguiría nada, y falla.
            self.assertEqual(en_hilos(lambda: personal._verificar_hash(None, "contrasena-de-prueba"), 1), [])
            self.assertGreater(len(set(doble.hilos)), 2)
            doble.hilos.clear()
            errores = en_hilos(lambda: personal._verificar_en_ejecutor(None, "contrasena-de-prueba"), LLAMADAS // HILOS)
        self.assertEqual(errores, [])
        self.assertEqual(len(doble.hilos), LLAMADAS)
        self.assertLessEqual(set(doble.hilos), NOMBRES_ARGON2)


class BaseFalsa:
    """Base de datos falsa: sentencia -> fila de fetchone (None si no está)."""

    def __init__(self, filas=None):
        self.filas = filas or {}

    @contextlib.contextmanager
    def transaccion(self, _pool, _empresa_id, solo_lectura=False):
        yield types.SimpleNamespace(execute=self.ejecutar)

    def ejecutar(self, sql, _parametros=None):
        return types.SimpleNamespace(fetchone=lambda: self.filas.get(sql))


class CadaCamino(ConEjecutor):
    """Los 3 caminos que calculan Argon2 lo hacen en el ejecutor. El hilo de
    la prueba no es del ejecutor: un camino que calculara en el hilo del
    llamante dejaría su nombre."""

    def setUp(self):
        super().setUp()
        self.assertNotIn(threading.current_thread().name, NOMBRES_ARGON2)

    def test_iniciar_sesion(self):
        doble = HasherDoble()
        with mock.patch.object(personal, "_hasher", doble), \
                mock.patch.object(personal.bd, "transaccion_empresa", BaseFalsa().transaccion), \
                mock.patch.object(personal, "resolver_empresa", return_value=None), \
                self.assertLogs("canario.personal", "WARNING"), \
                self.assertRaises(personal.CredencialesNoValidas):
            personal.iniciar_sesion(None, None, "0" * 32, "nadie@empresa.es", "Contrasena-cualquiera-1", "000000",
                                    None, 150)
        self.assertEqual(len(doble.hilos), 1)
        self.assertLessEqual(set(doble.hilos), NOMBRES_ARGON2)

    def test_cambiar_contrasena(self):
        doble = HasherDoble(error=Detenido())
        sesion = types.SimpleNamespace(empresa_id=EMPRESA, usuario_id=USUARIO, dispositivo_id=DISPOSITIVO,
                                       email="titular@empresa.es", nombre_empresa="Empresa")
        with mock.patch.object(personal, "_hasher", doble), \
                mock.patch.object(personal.bd, "transaccion_empresa", BaseFalsa().transaccion), \
                mock.patch.object(personal, "_comprobar_factores", return_value=5), \
                self.assertRaises(Detenido):
            personal.cambiar_contrasena(None, None, sesion, "Contrasena-actual-1", CONTRASENA_NUEVA, "000000", 150)
        self.assertEqual(len(doble.hilos), 1)
        self.assertLessEqual(set(doble.hilos), NOMBRES_ARGON2)

    def test_activar(self):
        doble = HasherDoble(error=Detenido())
        base = BaseFalsa({personal.SQL_INVITACION_ABIERTA: (uuid.UUID(int=6), USUARIO, "titular@empresa.es", "Empresa"),
                          personal.SQL_CLAVE_ACTUAL: (1, b"envuelta")})
        with mock.patch.object(personal, "_hasher", doble), \
                mock.patch.object(personal.bd, "transaccion_empresa", base.transaccion), \
                mock.patch.object(personal, "_empresa_de_invitacion", return_value=(EMPRESA, b"h")), \
                self.assertRaises(Detenido):
            personal.activar(None, None, "token", CONTRASENA_NUEVA)
        self.assertEqual(len(doble.hilos), 1)
        self.assertLessEqual(set(doble.hilos), NOMBRES_ARGON2)


class ResultadoSinPlazo(ConEjecutor):
    def test_sin_plazo_y_la_tercera_satura_sin_encolarse(self):
        liberar = threading.Event()
        doble = HasherDoble(bloqueo=liberar)
        resultados = {}

        def llamar(clave):
            try:
                resultados[clave] = personal._verificar_en_ejecutor(None, "contrasena-de-prueba")
            except BaseException as error:  # noqa: BLE001 - la prueba mira qué llegó
                resultados[clave] = error

        llamantes = [threading.Thread(target=llamar, args=(i,)) for i in range(2)]
        with mock.patch.object(personal, "_hasher", doble), mock.patch.object(personal, "ESPERA_HASH", ESPERA_CORTA):
            try:
                for hilo in llamantes:
                    hilo.start()
                for _ in range(2):
                    self.assertTrue(doble.dentro.acquire(timeout=5), "los 2 hashes no llegan al ejecutor")
                # Los 2 siguen esperando su hash, sin TimeoutError: result()
                # no tiene plazo.
                time.sleep(OBSERVACION_S)
                self.assertEqual(resultados, {})
                self.assertTrue(all(hilo.is_alive() for hilo in llamantes))
                # Un tercero no se encola en el ejecutor: Saturado.
                with self.assertLogs("canario.personal", "WARNING") as registro:
                    tercero = threading.Thread(target=llamar, args=("tercero",))
                    tercero.start()
                    tercero.join(ESPERA_CORTA + 5)
                self.assertFalse(tercero.is_alive(), "el tercero espera en el ejecutor en vez de saturar")
                self.assertIs(type(resultados["tercero"]), personal.Saturado)
                self.assertEqual(registro.output, [EVENTO_SATURADOS])
                self.assertEqual(len(doble.hilos), 2)
            finally:
                liberar.set()
                for hilo in llamantes:
                    hilo.join(PLAZO_SEGURIDAD_S)
        # Al liberarlos, los 2 terminan con su resultado (sin cuenta, False).
        self.assertEqual((resultados[0], resultados[1]), (False, False))
        self.assertEqual(set(doble.hilos), NOMBRES_ARGON2)
        self.assertEqual(sondear_semaforo(), SEMAFORO_LIBRE)


class Saturacion(ConEjecutor):
    def test_sin_hueco_saturado_sin_calcular_y_con_su_evento(self):
        doble = HasherDoble()
        with mock.patch.object(personal, "_hasher", doble):
            ocupados = sum(personal._semaforo.acquire(blocking=False) for _ in range(3))
            try:
                self.assertEqual(ocupados, 2)
                with mock.patch.object(personal, "ESPERA_HASH", 0.05), \
                        self.assertLogs("canario.personal", "WARNING") as registro, \
                        self.assertRaises(personal.Saturado):
                    personal._crear_hash_en_ejecutor(CONTRASENA_NUEVA)
                self.assertEqual(registro.output, [EVENTO_SATURADOS])
                self.assertEqual(doble.hilos, [])
            finally:
                for _ in range(ocupados):
                    personal._semaforo.release()
            # Control: con los huecos libres, el mismo hash se calcula.
            self.assertEqual(personal._crear_hash_en_ejecutor(CONTRASENA_NUEVA), "$argon2id$doble")
        self.assertLessEqual(set(doble.hilos), NOMBRES_ARGON2)
        self.assertEqual(sondear_semaforo(), SEMAFORO_LIBRE)


class Excepciones(ConEjecutor):
    def test_error_del_hash_llega_tal_cual_y_libera(self):
        # Control: sin error, la verificación vuelve.
        with mock.patch.object(personal, "_hasher", HasherDoble()):
            self.assertFalse(personal._verificar_en_ejecutor(None, "contrasena-de-prueba"))
        # Un RuntimeError dentro del hash es un RuntimeError para el
        # llamante, no un 503 de ejecutor no disponible.
        with mock.patch.object(personal, "_hasher", HasherDoble(error=RuntimeError("fallo del doble"))), \
                self.assertNoLogs("canario.personal", "DEBUG"), \
                self.assertRaises(RuntimeError) as error:
            personal._verificar_en_ejecutor(None, "contrasena-de-prueba")
        self.assertIs(type(error.exception), RuntimeError)
        self.assertEqual(str(error.exception), "fallo del doble")
        self.assertEqual(sondear_semaforo(), SEMAFORO_LIBRE)

    def test_sin_ejecutor_503_con_su_evento_y_libera(self):
        doble = HasherDoble()
        with mock.patch.object(personal, "_hasher", doble):
            # Control: con el ejecutor instalado, el hash se calcula.
            self.assertEqual(personal._crear_hash_en_ejecutor(CONTRASENA_NUEVA), "$argon2id$doble")
            doble.hilos.clear()
            with mock.patch.object(personal, "_ejecutor", None), \
                    self.assertLogs("canario.personal", "ERROR") as registro, \
                    self.assertRaises(personal.EjecutorNoDisponible):
                personal._crear_hash_en_ejecutor(CONTRASENA_NUEVA)
        self.assertEqual(registro.output, [EVENTO_SIN_CREAR])
        self.assertEqual(doble.hilos, [])
        self.assertEqual(sondear_semaforo(), SEMAFORO_LIBRE)

    def test_ejecutor_cerrado_503_con_su_evento_y_libera(self):
        doble = HasherDoble()
        cerrado = personal.iniciar_ejecutor_hashes()
        with mock.patch.object(personal, "_hasher", doble), mock.patch.object(personal, "_ejecutor", cerrado):
            # Control: abierto, el mismo ejecutor calcula.
            self.assertFalse(personal._verificar_en_ejecutor(None, "contrasena-de-prueba"))
            cerrado.shutdown(wait=True)
            doble.hilos.clear()
            with self.assertLogs("canario.personal", "ERROR") as registro, \
                    self.assertRaises(personal.EjecutorNoDisponible):
                personal._verificar_en_ejecutor(None, "contrasena-de-prueba")
        self.assertEqual(registro.output, [EVENTO_CERRADO])
        self.assertEqual(doble.hilos, [])
        self.assertEqual(sondear_semaforo(), SEMAFORO_LIBRE)

    def test_llamada_anidada_rechazada_y_libera(self):
        # Control: el mismo hash sin anidar se calcula.
        with mock.patch.object(personal, "_hasher", HasherDoble()):
            self.assertEqual(personal._crear_hash_en_ejecutor(CONTRASENA_NUEVA), "$argon2id$doble")
        doble = HasherDoble(anidar=True)
        with mock.patch.object(personal, "_hasher", doble), self.assertRaises(personal.HashAnidado):
            personal._crear_hash_en_ejecutor(CONTRASENA_NUEVA)
        # El de fuera llegó al ejecutor; el de dentro no tomó hueco ni llegó.
        self.assertEqual(len(doble.hilos), 1)
        self.assertLessEqual(set(doble.hilos), NOMBRES_ARGON2)
        self.assertEqual(sondear_semaforo(), SEMAFORO_LIBRE)

    def test_ejecutor_no_disponible_es_503_con_retry_after(self):
        app = FastAPI()
        rutas_personal.instalar_errores(app)

        @app.get("/sana")
        def sana():
            return {"estado": "ok"}

        @app.get("/sin-ejecutor")
        def sin_ejecutor():
            raise personal.EjecutorNoDisponible("cerrado")

        # Control: la aplicación responde por la misma vía.
        self.assertEqual(llamar_asgi(app, "/sana"), (200, None, b'{"estado":"ok"}'))
        self.assertEqual(llamar_asgi(app, "/sin-ejecutor"), (503, b"5", CUERPO_503))


def llamar_asgi(app, ruta):
    """(código, Retry-After, cuerpo) de un GET por la aplicación ASGI."""
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "GET", "scheme": "http",
             "path": ruta, "raw_path": ruta.encode(), "root_path": "", "query_string": b"", "headers": [],
             "client": None, "server": ("api", 8000)}
    mensajes = []

    async def recibir():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def enviar(mensaje):
        mensajes.append(mensaje)

    asyncio.run(app(scope, recibir, enviar))
    inicio = next(m for m in mensajes if m["type"] == "http.response.start")
    reintentar = dict(inicio["headers"]).get(b"retry-after")
    cuerpo = b"".join(m.get("body", b"") for m in mensajes if m["type"] == "http.response.body")
    return inicio["status"], reintentar, cuerpo


class Semaforo(ConEjecutor):
    def test_libre_tras_cada_salida(self):
        liberar = threading.Event()
        bloqueado = HasherDoble(bloqueo=liberar)
        with mock.patch.object(personal, "_hasher", bloqueado):
            llamante = threading.Thread(target=personal._verificar_en_ejecutor, args=(None, "contrasena-de-prueba"))
            llamante.start()
            try:
                self.assertTrue(bloqueado.dentro.acquire(timeout=5))
                # Control: con un hash en curso, el sondeo ve un hueco menos.
                self.assertEqual(sondear_semaforo(), [True, False, False])
            finally:
                liberar.set()
                llamante.join(PLAZO_SEGURIDAD_S)
        self.assertEqual(sondear_semaforo(), SEMAFORO_LIBRE)
        with mock.patch.object(personal, "_hasher", HasherDoble()):
            personal._verificar_en_ejecutor(None, "contrasena-de-prueba")
            self.assertEqual(sondear_semaforo(), SEMAFORO_LIBRE)
            personal._crear_hash_en_ejecutor(CONTRASENA_NUEVA)
            self.assertEqual(sondear_semaforo(), SEMAFORO_LIBRE)


# ---------------------------------------------------------------------------
# Guarda estática sobre app/
# ---------------------------------------------------------------------------
FUNCIONES_EN_EJECUTOR = ("_verificar_hash", "_crear_hash")
# Cada función de entrada envía al ejecutor una sola función fija.
ENVIOS = {"_verificar_en_ejecutor": "_verificar_hash", "_crear_hash_en_ejecutor": "_crear_hash"}
MOTIVO_HASHER = "_hasher fuera de su definicion, _HASH_FICTICIO, _verificar_hash y _crear_hash"
MOTIVO_ARGON2 = "argon2 importado fuera de personal.py"
MOTIVO_ENVIO = "usada fuera de su envio al ejecutor"
MOTIVO_ENVIAR = "_enviar_al_ejecutor llamado fuera de _verificar_en_ejecutor y _crear_hash_en_ejecutor"


def _nombre(nodo):
    if isinstance(nodo, ast.Name):
        return nodo.id
    if isinstance(nodo, ast.Attribute):
        return nodo.attr
    return None


def _contextos(arbol):
    """Para cada nodo: (sentencia de primer nivel, función de primer nivel
    que lo contiene o None)."""
    contexto = {}
    for sentencia in arbol.body:
        funcion = sentencia.name if isinstance(sentencia, (ast.FunctionDef, ast.AsyncFunctionDef)) else None
        for nodo in ast.walk(sentencia):
            contexto[nodo] = (sentencia, funcion)
    return contexto


def _asignacion_de(sentencia, nombre):
    return (isinstance(sentencia, ast.Assign) and len(sentencia.targets) == 1
            and isinstance(sentencia.targets[0], ast.Name) and sentencia.targets[0].id == nombre)


def _hasher_permitido(ruta, sentencia, funcion):
    return ruta == "personal.py" and (
        funcion in FUNCIONES_EN_EJECUTOR
        or _asignacion_de(sentencia, "_hasher") or _asignacion_de(sentencia, "_HASH_FICTICIO"))


def _envios_permitidos(arbol):
    """Los nodos Name que son el primer argumento correcto de
    _enviar_al_ejecutor dentro de su función de entrada."""
    permitidos = set()
    for sentencia in arbol.body:
        esperado = ENVIOS.get(getattr(sentencia, "name", None))
        for nodo in ast.walk(sentencia):
            if (esperado and isinstance(nodo, ast.Call) and _nombre(nodo.func) == "_enviar_al_ejecutor"
                    and nodo.args and isinstance(nodo.args[0], ast.Name) and nodo.args[0].id == esperado):
                permitidos.add(nodo.args[0])
    return permitidos


def infracciones(fuentes):
    """Infracciones de la guarda en {ruta relativa a app/: texto}."""
    salida, constructores = [], 0
    for ruta, texto in sorted(fuentes.items()):
        arbol = ast.parse(texto)
        contexto = _contextos(arbol)
        envios = _envios_permitidos(arbol) if ruta == "personal.py" else set()
        for nodo in ast.walk(arbol):
            linea = getattr(nodo, "lineno", 0)
            nombre = _nombre(nodo)
            if isinstance(nodo, ast.Import) and any(a.name.split(".")[0] == "argon2" for a in nodo.names) \
                    and ruta != "personal.py":
                salida.append(f"{ruta}:{linea}: {MOTIVO_ARGON2}")
            if isinstance(nodo, ast.ImportFrom) and (nodo.module or "").split(".")[0] == "argon2" \
                    and ruta != "personal.py":
                salida.append(f"{ruta}:{linea}: {MOTIVO_ARGON2}")
            if isinstance(nodo, ast.Call) and _nombre(nodo.func) == "PasswordHasher":
                constructores += 1
            # _hasher con cualquier uso: nombre, atributo (personal._hasher),
            # texto para getattr o una declaración global.
            if (nombre == "_hasher" and isinstance(nodo, (ast.Name, ast.Attribute))) or \
                    (isinstance(nodo, ast.Constant) and nodo.value == "_hasher") or \
                    (isinstance(nodo, (ast.Global, ast.Nonlocal)) and "_hasher" in nodo.names):
                sentencia, funcion = contexto[nodo]
                if not (isinstance(nodo, ast.Name) and _hasher_permitido(ruta, sentencia, funcion)):
                    salida.append(f"{ruta}:{linea}: {MOTIVO_HASHER}")
            if nombre in FUNCIONES_EN_EJECUTOR and isinstance(nodo, (ast.Name, ast.Attribute)) and nodo not in envios:
                salida.append(f"{ruta}:{linea}: {nombre} {MOTIVO_ENVIO}")
            if isinstance(nodo, ast.Call) and _nombre(nodo.func) == "_enviar_al_ejecutor" \
                    and (ruta != "personal.py" or contexto[nodo][1] not in ENVIOS):
                salida.append(f"{ruta}:{linea}: {MOTIVO_ENVIAR}")
    if constructores != 1:
        salida.append(f"PasswordHasher( aparece {constructores} veces y no 1")
    return salida


def fuentes_de_app():
    raiz = pathlib.Path(personal.__file__).resolve().parent
    return {ruta.relative_to(raiz).as_posix(): ruta.read_text(encoding="utf-8")
            for ruta in sorted(raiz.rglob("*.py")) if "__pycache__" not in ruta.parts}


class GuardaEstatica(unittest.TestCase):
    def test_argon2_solo_en_el_ejecutor(self):
        fuentes = fuentes_de_app()
        # Control: la misma guarda sobre una copia con un atajo de cada tipo
        # encuentra cada uno. Si no, que app/ no tenga infracciones no
        # demostraría nada.
        n = fuentes["personal.py"].count("\n")
        trampas = dict(fuentes)
        trampas["personal.py"] = fuentes["personal.py"] + (
            "\n\ndef atajo(guardado, contrasena):\n"
            "    alias = _hasher\n"
            "    return alias.verify(guardado, contrasena) or _verificar_hash(guardado, contrasena)\n"
            "\n\ndef otro_envio(contrasena):\n"
            "    return _enviar_al_ejecutor(_crear_hash, contrasena)\n")
        trampas["trampa.py"] = ("import argon2\nfrom argon2 import PasswordHasher\nfrom app import personal\n"
                                "segundo = PasswordHasher()\nfuga = getattr(personal, \"_hasher\")\n")
        self.assertEqual(sorted(infracciones(trampas)), sorted([
            f"personal.py:{n + 4}: {MOTIVO_HASHER}",
            f"personal.py:{n + 5}: _verificar_hash {MOTIVO_ENVIO}",
            f"personal.py:{n + 9}: _crear_hash {MOTIVO_ENVIO}",
            f"personal.py:{n + 9}: {MOTIVO_ENVIAR}",
            f"trampa.py:1: {MOTIVO_ARGON2}",
            f"trampa.py:2: {MOTIVO_ARGON2}",
            f"trampa.py:5: {MOTIVO_HASHER}",
            "PasswordHasher( aparece 2 veces y no 1",
        ]))
        self.assertEqual(infracciones(fuentes), [])
