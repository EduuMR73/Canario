"""Pruebas unitarias del mamparo global del login (app/personal.py, "Mamparo
global del login"; plan del bloque 1, A2): u1 a u6, con u2b y u2c.

Por qué importa (D2, 26/11): las rutas del login eran def y retenían un hilo
de AnyIO mientras esperaban a Argon2; con 40 hilos compartidos, una
inundación del login dejaba sin hilos a las víctimas del denunciante. El
mamparo hace esperar el turno en el bucle de eventos y solo deja tomar hilo
(de su propio limitador) a las HASHES_SIMULTANEOS admitidas.

Arnés: el de tests/unit/test_errores.py (llamar, la aplicación ASGI sin
servidor), en versión asíncrona para lanzar varias peticiones a la vez. Un
asyncio.run por escenario, con un plazo de PLAZO_PRUEBA_S: si se supera, la
prueba no PASA, da "SIN CONCLUSION". Un TimeoutError que salga de la
aplicación no se confunde con ese plazo: sigue su camino (u2c depende de
ello). Cada prueba negativa lleva su control
positivo; si el control falla, el mensaje empieza por "SIN CONCLUSION". Los
oráculos son literales (N = 2, ESPERA_HASH = 2,0 s, los textos de cada
EVENTO y el 503 con su cuerpo), no se leen del código que se prueba.

Los controles que necesitan otra forma del mamparo (u2b, u2c, u3 y u6) la sacan
del código real con una sustitución de texto literal: si el texto no aparece
exactamente una vez, SIN CONCLUSION (un mutante que no cambia nada no prueba
nada).

Límite declarado (u3): la cancelación se hace con un ámbito de AnyIO, que es
la que respeta abandon_on_cancel=False. Una cancelación nativa de asyncio
(task.cancel()) suelta el turno antes de que acabe el hilo (comprobado con
anyio 4.15.1); lo cubre el semáforo interno de app/personal.py, que lo
delata con EVENTO hashes_saturados_interno (u6).
"""
import ast
import asyncio
import concurrent.futures
import contextlib
import inspect
import json
import logging
import pathlib
import re
import textwrap
import threading
import time
import types
import unittest
from unittest import mock

import anyio
import anyio.to_thread
from fastapi import FastAPI

from app import (bd, claves, frontera_http, limitador, personal, rutas_personal, rutas_web, solicitudes,
                 verificacion_arranque)

# Plazo de cada escenario: más, y la prueba da SIN CONCLUSION.
PLAZO_PRUEBA_S = 10
# Ningún doble de la prueba espera más que esto en un hilo, aunque la prueba
# se corte a medias.
PLAZO_SEGURIDAD_S = 30
# Cuánto se observa a una petición antes de dar por hecho que espera.
OBSERVACION_S = 1.0
# Literales del plan: N = HASHES_SIMULTANEOS y ESPERA_HASH.
N = 2
ESPERA_HASH_S = 2.0
HOLGURA_503_S = 0.5
RUTA_LOGIN = "/v1/personal/sesiones"
RUTA_VICTIMA = "/v1/seguimiento"
CUERPO_VICTIMA = b'{"estado":"ok"}'
CUERPO_401 = '{"detalle": "credenciales no válidas"}'.encode()
CUERPO_503 = '{"detalle": "servicio ocupado; inténtelo de nuevo en unos segundos"}'.encode()
LOGIN_A = {"empresa": "0" * 32, "email": "titular@alfa.test", "contrasena": "Contrasena-de-prueba-1",
           "codigo_totp": "000000"}
LOGIN_B = {"empresa": "f" * 32, "email": "nadie@otra.test", "contrasena": "Otra-contrasena-12",
           "codigo_totp": "999999"}
EVENTO_ADMISION = "WARNING:canario.personal:EVENTO hashes_saturados etapa=admision"
EVENTO_INTERNO = "ERROR:canario.personal:EVENTO hashes_saturados_interno etapa=interna"
PREFIJO_RESUMEN = "WARNING:canario.personal:EVENTO hashes_saturados_resumen etapa=admision "
EVENTO_CAIDO = "ERROR:canario.personal:EVENTO resumen_saturacion_caido: RuntimeError"
# u2b: un hash más largo que ESPERA_HASH, dónde cae el 503 del control y
# entre qué tiempos debe llegar el 401 del código real.
HASH_LARGO_S = 2.5
HASH_CORTO_S = 0.05
VENTANA_503_S = (1.9, 2.4)
PREMISA_401_S = 2.45
TECHO_401_S = 3.0
# u2b y u2c: una respuesta que no espera ni turno ni hash.
TECHO_INMEDIATO_S = 0.5
# u2c: el 500 de ErroresInternos (app/frontera_http.py) y su línea de log.
CUERPO_500 = b'{"detalle": "error interno"}'
EVENTO_INTERNO_API = "ERROR:canario.api:ERROR INTERNO: TimeoutError"
EJECUTOR = None


def setUpModule():
    global EJECUTOR
    EJECUTOR = personal.iniciar_ejecutor_hashes()


# ---------------------------------------------------------------------------
# Arnés
# ---------------------------------------------------------------------------
def ejecutar(escenario):
    """Un asyncio.run con plazo. escenario es una función async sin
    argumentos.

    Por qué asyncio.wait y no asyncio.wait_for: con wait_for, el except
    TimeoutError que distingue el plazo de la prueba no puede separarlo de un
    TimeoutError salido de la aplicación, y lo convertía en "SIN CONCLUSION".
    Con wait, el plazo se ve porque la tarea no ha terminado, y si terminó,
    tarea.result() devuelve su resultado o propaga su excepción real."""
    async def con_plazo():
        tarea = asyncio.ensure_future(escenario())
        hechas, _ = await asyncio.wait({tarea}, timeout=PLAZO_PRUEBA_S)
        if not hechas:
            tarea.cancel()
            raise AssertionError(f"SIN CONCLUSION: el escenario espera más de {PLAZO_PRUEBA_S} s")
        return tarea.result()
    return asyncio.run(con_plazo())


async def esperar_que(condicion, motivo, plazo=5.0):
    limite = time.monotonic() + plazo
    while not condicion():
        if time.monotonic() > limite:
            raise AssertionError(f"SIN CONCLUSION: {motivo}")
        await asyncio.sleep(0.01)


async def llamar(app, metodo, ruta, cuerpo=None):
    """(código, cabeceras, cuerpo) de una petición por la aplicación ASGI,
    como test_errores.llamar pero sin su asyncio.run y sin Authorization."""
    cabeceras = []
    datos = b""
    if cuerpo is not None:
        datos = json.dumps(cuerpo).encode()
        cabeceras += [(b"content-type", b"application/json"), (b"content-length", str(len(datos)).encode())]
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": metodo,
             "scheme": "http", "path": ruta, "raw_path": ruta.encode("utf-8"), "root_path": "",
             "query_string": b"", "headers": cabeceras, "client": None, "server": ("api", 8000)}
    mensajes = []

    async def recibir():
        return {"type": "http.request", "body": datos, "more_body": False}

    async def enviar(mensaje):
        mensajes.append(mensaje)

    await app(scope, recibir, enviar)
    inicio = next(m for m in mensajes if m["type"] == "http.response.start")
    return (inicio["status"], list(inicio["headers"]),
            b"".join(m.get("body", b"") for m in mensajes if m["type"] == "http.response.body"))


async def medido(app, cuerpo):
    inicio = time.monotonic()
    respuesta = await llamar(app, "POST", RUTA_LOGIN, cuerpo)
    return respuesta, time.monotonic() - inicio


class LoginFalso:
    """Sustituye a personal.iniciar_sesion: anota en qué hilo entra y espera
    a que la prueba lo suelte (o duerme), y falla como un login malo.
    acabado se marca al salir del hilo: una prueba cuya respuesta llega antes
    (el control de u2b) lo espera para que el hilo no sobreviva a su bucle."""

    def __init__(self, dormir=0.0):
        self.dormir = dormir
        self.soltar = threading.Event()
        self.acabado = threading.Event()
        self.entradas = []

    def __call__(self, *_argumentos):
        self.entradas.append(threading.current_thread().name)
        try:
            if self.dormir:
                time.sleep(self.dormir)
            else:
                self.soltar.wait(PLAZO_SEGURIDAD_S)
            raise personal.CredencialesNoValidas
        finally:
            self.acabado.set()


def _con_victima(app):
    # Una víctima como las del denunciante: def, en el limitador por defecto.
    @app.get(RUTA_VICTIMA)
    def victima():
        return {"estado": "ok"}
    return app


def aplicacion_mamparo():
    """El router real con el mamparo creado como en el arranque. Se llama
    dentro del bucle de eventos. Reloj fijo: todas las saturaciones caen en
    la misma ventana."""
    app = FastAPI()
    rutas_personal.instalar_errores(app)
    app.include_router(rutas_personal.router)
    app.state.pool = None
    app.state.claves = None
    app.state.semaforo_hash, app.state.limitador_hash = personal.crear_mamparo()
    app.state.resumen_saturacion = personal.ResumenSaturacion(reloj=lambda: 0.0)
    return _con_victima(app)


def aplicacion_produccion():
    """aplicacion_mamparo con ErroresInternos por fuera, como lo monta
    app/frontera_http.instalar en producción. Solo para u2b y u2c: lo que
    prueban es la respuesta que ve el cliente cuando algo sale de la ruta (un
    TimeoutError da 500, no un 503 de saturación), y sin ErroresInternos ese
    error no llegaría a ser una respuesta."""
    app = aplicacion_mamparo()
    app.add_middleware(frontera_http.ErroresInternos)
    return app


def aplicacion_def():
    """Control de u1: el login como era antes del mamparo, una ruta def en el
    limitador por defecto, con la misma función de personal."""
    app = FastAPI()
    rutas_personal.instalar_errores(app)

    @app.post(RUTA_LOGIN, status_code=201)
    def iniciar_sesion_antes(datos: rutas_personal.Login):
        personal.iniciar_sesion(None, None, datos.empresa, datos.email, datos.contrasena, datos.codigo_totp, None)

    return _con_victima(app)


def mutante(funcion, original, nuevo):
    """La función de app/personal.py con original sustituido por nuevo, con
    los globales del módulo real (sus parches valen). SIN CONCLUSION si
    original no aparece exactamente una vez."""
    fuente = textwrap.dedent(inspect.getsource(funcion))
    veces = fuente.count(original)
    if veces != 1:
        raise AssertionError(f"SIN CONCLUSION: el texto a mutar aparece {veces} veces en {funcion.__qualname__}")
    espacio = {}
    exec(compile(fuente.replace(original, nuevo), f"<mutante de {funcion.__qualname__}>", "exec"),  # noqa: S102
         vars(personal), espacio)
    return espacio[funcion.__name__]


# Texto exacto de en_mamparo y su forma con fail_after envolviendo run_sync.
MAMPARO_PLAZO_EN_LA_ESPERA = (
    "    try:\n"
    "        with anyio.fail_after(ESPERA_HASH):\n"
    "            await estado.semaforo_hash.acquire()\n"
    "    except TimeoutError:\n"
    "        estado.resumen_saturacion.anotar()\n"
    "        raise Saturado from None\n"
    "    try:\n"
    "        return await anyio.to_thread.run_sync(funcion, *argumentos, limiter=estado.limitador_hash,\n"
    "                                              abandon_on_cancel=False)\n"
    "    finally:\n"
    "        estado.semaforo_hash.release()\n")
MAMPARO_PLAZO_ENVOLVIENDO = (
    "    try:\n"
    "        with anyio.fail_after(ESPERA_HASH):\n"
    "            await estado.semaforo_hash.acquire()\n"
    "            try:\n"
    "                return await anyio.to_thread.run_sync(funcion, *argumentos, limiter=estado.limitador_hash,\n"
    "                                                      abandon_on_cancel=False)\n"
    "            finally:\n"
    "                estado.semaforo_hash.release()\n"
    "    except TimeoutError:\n"
    "        estado.resumen_saturacion.anotar()\n"
    "        raise Saturado from None\n")
# Control de u2b: el plazo envolviendo espera y run_sync, pero con un
# asyncio.timeout. Por qué no basta MAMPARO_PLAZO_ENVOLVIENDO: con
# abandon_on_cancel=False, fail_after espera a que acabe el hilo y sale la
# respuesta de la función, el 401 a los 2,5 s (mutante equivalente en anyio
# 4.15.1, medido). La cancelación nativa de asyncio no respeta ese escudo y
# corta a los 2 s.
# app/personal.py importa asyncio, así que el mutante compila con sus globales.
MAMPARO_PLAZO_ASYNCIO = MAMPARO_PLAZO_ENVOLVIENDO.replace("        with anyio.fail_after(ESPERA_HASH):\n",
                                                          "        async with asyncio.timeout(ESPERA_HASH):\n")
# Control de u2c: el with solo con la espera del turno, como el real, pero con
# run_sync dentro del try cuyo except TimeoutError da Saturado: un
# TimeoutError de la función se convertiría en el 503 de saturación.
MAMPARO_EXCEPT_ENSANCHADO = (
    "    try:\n"
    "        with anyio.fail_after(ESPERA_HASH):\n"
    "            await estado.semaforo_hash.acquire()\n"
    "        try:\n"
    "            return await anyio.to_thread.run_sync(funcion, *argumentos, limiter=estado.limitador_hash,\n"
    "                                                  abandon_on_cancel=False)\n"
    "        finally:\n"
    "            estado.semaforo_hash.release()\n"
    "    except TimeoutError:\n"
    "        estado.resumen_saturacion.anotar()\n"
    "        raise Saturado from None\n")


# ---------------------------------------------------------------------------
# u1: las víctimas no esperan a los logins
# ---------------------------------------------------------------------------
class U1VictimaNoEspera(unittest.TestCase):
    """Limitador por defecto a 3 fichas, N logins bloqueados dentro de la
    admisión y 6 esperando turno: la víctima termina ANTES de soltar los
    logins. Control: con el login en el limitador por defecto (ruta def), la
    víctima solo termina después."""

    def escenario(self, fabrica, reparto_esperado):
        login = LoginFalso()

        async def escenario():
            anyio.to_thread.current_default_thread_limiter().total_tokens = 3
            app = fabrica()
            logins = [asyncio.create_task(llamar(app, "POST", RUTA_LOGIN, LOGIN_A)) for _ in range(8)]
            await esperar_que(lambda: reparto_esperado(app, login), "los 8 logins no llegan al reparto esperado")
            victima = asyncio.create_task(llamar(app, "GET", RUTA_VICTIMA))
            await asyncio.wait({victima}, timeout=OBSERVACION_S)
            antes = victima.done()
            login.soltar.set()
            resultados = await asyncio.gather(*logins)
            return antes, await victima, resultados

        try:
            # ESPERA_HASH alta: aquí no se prueba el 503 (u2), y ninguno de los
            # 6 que esperan debe salir por plazo mientras se observa.
            with mock.patch.object(personal, "iniciar_sesion", login), mock.patch.object(personal, "ESPERA_HASH", 30.0):
                return ejecutar(escenario)
        finally:
            login.soltar.set()

    def test_la_victima_termina_antes_de_soltar_los_logins(self):
        def reparto_def(_app, login):
            por_defecto = anyio.to_thread.current_default_thread_limiter()
            return len(login.entradas) == 3 and por_defecto.statistics().tasks_waiting == 5

        def reparto_mamparo(app, login):
            por_defecto = anyio.to_thread.current_default_thread_limiter()
            return (len(login.entradas) == N and app.state.semaforo_hash.statistics().tasks_waiting == 6
                    and por_defecto.borrowed_tokens == 0)

        antes_control, victima_control, logins_control = self.escenario(aplicacion_def, reparto_def)
        self.assertFalse(antes_control, "SIN CONCLUSION: con el login en el limitador por defecto, la victima "
                                        "tambien termina antes de soltar los logins")
        self.assertEqual((victima_control[0], victima_control[2]), (200, CUERPO_VICTIMA),
                         "SIN CONCLUSION: la victima del control no responde 200 al soltar los logins")
        self.assertEqual([(r[0], r[2]) for r in logins_control], [(401, CUERPO_401)] * 8,
                         "SIN CONCLUSION: los logins del control no responden 401")
        antes, victima, logins = self.escenario(aplicacion_mamparo, reparto_mamparo)
        self.assertTrue(antes)
        self.assertEqual((victima[0], victima[2]), (200, CUERPO_VICTIMA))
        self.assertEqual([(r[0], r[2]) for r in logins], [(401, CUERPO_401)] * 8)


# ---------------------------------------------------------------------------
# u2: el login N+1 da 503 con Retry-After tras ESPERA_HASH
# ---------------------------------------------------------------------------
class U2Saturado(unittest.TestCase):
    def test_el_login_n_mas_1_da_503_tras_la_espera_sin_tocar_personal(self):
        login = LoginFalso()

        async def escenario():
            app = aplicacion_mamparo()
            admitidos = [asyncio.create_task(llamar(app, "POST", RUTA_LOGIN, LOGIN_A)) for _ in range(N)]
            await esperar_que(lambda: len(login.entradas) == N, "los N logins no llegan a personal")
            # Dos más a la vez, con empresa y email distintos: los dos sin turno.
            saturados = await asyncio.gather(medido(app, LOGIN_A), medido(app, LOGIN_B))
            entradas_saturados = len(login.entradas)
            login.soltar.set()
            resultados_admitidos = await asyncio.gather(*admitidos)
            despues = await medido(app, LOGIN_A)
            return saturados, entradas_saturados, resultados_admitidos, despues

        try:
            with mock.patch.object(personal, "iniciar_sesion", login), \
                    self.assertLogs("canario.personal", "WARNING") as registro:
                saturados, entradas_saturados, admitidos, despues = ejecutar(escenario)
        finally:
            login.soltar.set()
        # Control: los admitidos y uno con turno libre llegan a personal (401).
        self.assertEqual([(r[0], r[2]) for r in admitidos], [(401, CUERPO_401)] * N,
                         "SIN CONCLUSION: los logins admitidos no responden 401")
        self.assertEqual((despues[0][0], despues[0][2]), (401, CUERPO_401),
                         "SIN CONCLUSION: con turno libre, el login no responde 401")
        self.assertLess(despues[1], ESPERA_HASH_S, "SIN CONCLUSION: con turno libre, el login espera el plazo")
        for (codigo, cabeceras, cuerpo), segundos in saturados:
            self.assertEqual((codigo, dict(cabeceras).get(b"retry-after"), cuerpo), (503, b"5", CUERPO_503))
            self.assertGreaterEqual(segundos, ESPERA_HASH_S)
            self.assertLessEqual(segundos, ESPERA_HASH_S + HOLGURA_503_S)
        # Igual byte a byte sea cual sea la empresa o el email, y sin llegar a
        # personal (ninguna entrada más que las N admitidas).
        self.assertEqual(saturados[0][0], saturados[1][0])
        self.assertEqual(entradas_saturados, N)
        # Dos saturaciones en la misma ventana: una sola línea.
        self.assertEqual(registro.output, [EVENTO_ADMISION])


# ---------------------------------------------------------------------------
# u2b: un login admitido no da 503 aunque su hash pase de ESPERA_HASH
# ---------------------------------------------------------------------------
class U2bAdmitidoNunca503(unittest.TestCase):
    """Propiedad: un login admitido termina con la respuesta de su función
    aunque el hash dure más que ESPERA_HASH; ningún plazo lo corta (el plazo
    cubre solo la espera del turno, invariante de app/personal.py).

    Control: con un asyncio.timeout envolviendo espera y run_sync, el mismo
    login da el 503 de saturación hacia los 2 s, con el hash aún en marcha; y
    con un hash de 0,05 s, ese mismo mutante da 401 (el 503 del control viene
    del plazo, no de otra cosa).

    Límite: solo se prueba el camino del 401. El 201 necesita el pool de la
    base de datos, que esta prueba no tiene."""

    def escenario(self, en_mamparo, dormir):
        """((código, cabeceras, cuerpo), segundos, entradas en personal)."""
        login = LoginFalso(dormir=dormir)

        async def escenario():
            respuesta = await medido(aplicacion_produccion(), LOGIN_A)
            # En el control la respuesta llega antes de que acabe el hilo: se
            # le espera para que no sobreviva a este bucle ni pise la
            # siguiente medición.
            await esperar_que(login.acabado.is_set, "el hilo del login no acaba")
            return respuesta

        with mock.patch.object(personal, "iniciar_sesion", login), mock.patch.object(personal, "en_mamparo", en_mamparo):
            respuesta, segundos = ejecutar(escenario)
        return respuesta, segundos, len(login.entradas)

    def test_hash_mas_largo_que_la_espera_da_401_y_no_503(self):
        self.assertIn("async with asyncio.timeout(ESPERA_HASH):", MAMPARO_PLAZO_ASYNCIO,
                      "SIN CONCLUSION: el mutante de asyncio.timeout no cambia nada")
        con_timeout = mutante(personal.en_mamparo, MAMPARO_PLAZO_EN_LA_ESPERA, MAMPARO_PLAZO_ASYNCIO)
        with self.assertLogs("canario.personal", "DEBUG") as registro:
            (codigo, cabeceras, cuerpo), segundos, entradas = self.escenario(con_timeout, HASH_LARGO_S)
        self.assertEqual((codigo, dict(cabeceras).get(b"retry-after"), cuerpo), (503, b"5", CUERPO_503),
                         f"SIN CONCLUSION: con asyncio.timeout envolviendo run_sync, un hash de 2,5 s no da 503 "
                         f"(da {codigo})")
        self.assertTrue(VENTANA_503_S[0] <= segundos <= VENTANA_503_S[1],
                        f"SIN CONCLUSION: el 503 del control no cae en {VENTANA_503_S} s ({segundos:.3f} s)")
        self.assertEqual(registro.output, [EVENTO_ADMISION],
                         "SIN CONCLUSION: el 503 del control no deja la linea de saturacion")
        self.assertEqual(entradas, 1, f"SIN CONCLUSION: el control entra {entradas} veces en personal")
        # Refuerzo del control: con un hash corto, el mismo mutante responde
        # lo que responde la función.
        (codigo, _, cuerpo), segundos, _ = self.escenario(con_timeout, HASH_CORTO_S)
        self.assertEqual((codigo, cuerpo), (401, CUERPO_401),
                         f"SIN CONCLUSION: con un hash de 0,05 s, el mutante no da 401 (da {codigo})")
        self.assertLess(segundos, TECHO_INMEDIATO_S,
                        f"SIN CONCLUSION: con un hash de 0,05 s, el mutante tarda {segundos:.3f} s")
        with self.assertNoLogs("canario.personal", "DEBUG"):
            (codigo, _, cuerpo), segundos, entradas = self.escenario(personal.en_mamparo, HASH_LARGO_S)
        # El oráculo va antes que la premisa: un plazo nativo que corte el hash
        # (asyncio.wait_for alrededor de run_sync) responde a los ~2 s con un
        # 500 y sin logs en canario.personal. Si la premisa fuera primero, esa
        # regresión saldría como SIN CONCLUSION en vez de FALLA.
        self.assertEqual((codigo, cuerpo), (401, CUERPO_401))
        # Premisa: el hash pasó del plazo. Un 401 solo llega cuando el hash ya
        # terminó, así que solo falla si el hash fue más corto de lo previsto.
        self.assertGreaterEqual(segundos, PREMISA_401_S,
                                f"SIN CONCLUSION: el hash no pasa del plazo ({segundos:.3f} s, da {codigo})")
        self.assertLessEqual(segundos, TECHO_401_S)
        self.assertEqual(entradas, 1)


# ---------------------------------------------------------------------------
# u2c: un TimeoutError de la función da 500, no el 503 de saturación
# ---------------------------------------------------------------------------
class U2cTimeoutDeLaFuncion(unittest.TestCase):
    """Propiedad: el except TimeoutError de en_mamparo solo captura el plazo
    de la espera del turno. Un TimeoutError que salga de la función (por
    ejemplo, de la base de datos) llega a ErroresInternos y da 500, sin
    anotar una saturación que no ha habido, y el turno se devuelve.

    Controles: con el plazo envolviendo run_sync, o con el except ensanchado
    hasta run_sync, ese TimeoutError da el 503 de saturación."""

    def escenario(self, en_mamparo):
        """(((código, cabeceras, cuerpo), segundos), turnos libres al final)."""
        def lanza_timeout(*_argumentos):
            raise TimeoutError("detalle")

        async def escenario():
            app = aplicacion_produccion()
            respuesta = await medido(app, LOGIN_A)
            return respuesta, app.state.semaforo_hash.value

        with mock.patch.object(personal, "iniciar_sesion", lanza_timeout), \
                mock.patch.object(personal, "en_mamparo", en_mamparo):
            return ejecutar(escenario)

    def test_timeout_de_la_funcion_da_500_y_devuelve_el_turno(self):
        controles = {"fail_after envolviendo": MAMPARO_PLAZO_ENVOLVIENDO,
                     "except ensanchado": MAMPARO_EXCEPT_ENSANCHADO}
        for caso, texto in controles.items():
            with self.subTest(control=caso):
                with self.assertLogs("canario.personal", "DEBUG") as registro:
                    ((codigo, cabeceras, cuerpo), segundos), _ = self.escenario(
                        mutante(personal.en_mamparo, MAMPARO_PLAZO_EN_LA_ESPERA, texto))
                self.assertEqual((codigo, dict(cabeceras).get(b"retry-after"), cuerpo), (503, b"5", CUERPO_503),
                                 f"SIN CONCLUSION: con {caso}, el TimeoutError de la funcion no da 503 (da {codigo})")
                self.assertLess(segundos, TECHO_INMEDIATO_S,
                                f"SIN CONCLUSION: con {caso}, el 503 tarda {segundos:.3f} s")
                self.assertEqual(registro.output, [EVENTO_ADMISION],
                                 f"SIN CONCLUSION: con {caso}, el 503 no deja la linea de saturacion")
        with self.assertNoLogs("canario.personal", "DEBUG"), self.assertLogs("canario.api", "DEBUG") as registro_api:
            ((codigo, cabeceras, cuerpo), segundos), libres = self.escenario(personal.en_mamparo)
        self.assertEqual((codigo, dict(cabeceras).get(b"retry-after"), cuerpo), (500, None, CUERPO_500))
        self.assertLess(segundos, TECHO_INMEDIATO_S)
        self.assertEqual(registro_api.output, [EVENTO_INTERNO_API])
        self.assertEqual(libres, N)


# ---------------------------------------------------------------------------
# u3: cancelación en la espera y dentro del hilo
# ---------------------------------------------------------------------------
def estado_mamparo():
    semaforo, limitador_hash = personal.crear_mamparo()
    return types.SimpleNamespace(semaforo_hash=semaforo, limitador_hash=limitador_hash,
                                 resumen_saturacion=personal.ResumenSaturacion(reloj=lambda: 0.0))


async def cancelable(funcion_mamparo, estado, funcion, ambitos):
    with anyio.CancelScope() as ambito:
        ambitos.append(ambito)
        await funcion_mamparo(estado, funcion)


class U3Cancelacion(unittest.TestCase):
    def test_cancelada_en_la_espera_no_se_queda_ningun_turno(self):
        llamadas = []

        async def escenario():
            estado = estado_mamparo()
            for _ in range(N):
                await estado.semaforo_hash.acquire()
            ambitos = []
            tarea = asyncio.create_task(cancelable(personal.en_mamparo, estado, llamadas.append, ambitos))
            await esperar_que(lambda: estado.semaforo_hash.statistics().tasks_waiting == 1,
                              "la peticion no llega a esperar turno")
            ambitos[0].cancel()
            await tarea
            durante = (estado.semaforo_hash.value, estado.semaforo_hash.statistics().tasks_waiting,
                       estado.limitador_hash.borrowed_tokens)
            for _ in range(N):
                estado.semaforo_hash.release()
            return durante, estado.semaforo_hash.value, ambitos[0].cancelled_caught

        with self.assertNoLogs("canario.personal", "DEBUG"):
            durante, libres, cancelada = ejecutar(escenario)
        # Control: la cancelación llegó de verdad a la espera.
        self.assertTrue(cancelada, "SIN CONCLUSION: la cancelacion no llego a la peticion")
        self.assertEqual(durante, (0, 0, 0))
        self.assertEqual(libres, N)
        self.assertEqual(llamadas, [])

    def escenario_dentro(self, funcion_mamparo):
        soltar = threading.Event()
        entradas = []

        def bloqueada():
            entradas.append(threading.current_thread().name)
            soltar.wait(PLAZO_SEGURIDAD_S)

        async def escenario():
            estado = estado_mamparo()
            ambitos = []
            tarea = asyncio.create_task(cancelable(funcion_mamparo, estado, bloqueada, ambitos))
            await esperar_que(lambda: len(entradas) == 1, "la funcion no llega al hilo")
            ambitos[0].cancel()
            await asyncio.sleep(OBSERVACION_S / 2)
            durante = (tarea.done(), estado.limitador_hash.borrowed_tokens, estado.semaforo_hash.value)
            soltar.set()
            await tarea
            return durante, (estado.limitador_hash.borrowed_tokens, estado.semaforo_hash.value)

        try:
            return ejecutar(escenario)
        finally:
            soltar.set()

    def test_cancelada_dentro_del_hilo_devuelve_las_fichas_al_acabar_el_hilo(self):
        abandona = mutante(personal.en_mamparo, "abandon_on_cancel=False", "abandon_on_cancel=True")
        durante_control, al_final_control = self.escenario_dentro(abandona)
        self.assertEqual(durante_control, (True, 0, N),
                         "SIN CONCLUSION: con abandon_on_cancel=True, las fichas no se liberan antes de acabar el hilo")
        self.assertEqual(al_final_control, (0, N), "SIN CONCLUSION: el control no deja las fichas a 0")
        durante, al_final = self.escenario_dentro(personal.en_mamparo)
        # Con el hilo aún en marcha: la petición no ha acabado, y su ficha y su
        # turno siguen tomados.
        self.assertEqual(durante, (False, 1, N - 1))
        self.assertEqual(al_final, (0, N))


# ---------------------------------------------------------------------------
# u4: guarda estática del grafo de llamantes de Argon2
# ---------------------------------------------------------------------------
ENTRADAS_HASH = ("_verificar_en_ejecutor", "_crear_hash_en_ejecutor")
# Literales: quién llega a un hash dentro de app/personal.py y qué rutas lo
# piden desde fuera.
LLAMANTES_EN_PERSONAL = {"_comprobar_factores", "iniciar_sesion", "cambiar_contrasena", "activar"}
RUTAS_CON_HASH = {"rutas_personal.py:iniciar_sesion", "rutas_personal.py:activar",
                  "rutas_personal.py:cambiar_contrasena"}
MOTIVO_ASYNC = "no es async def"
MOTIVO_FUERA = "fuera del mamparo"
MOTIVO_IMPORTA = "importa de app.personal una funcion que calcula un hash"
MOTIVO_LIMITER = "run_sync de en_mamparo sin limiter= del mamparo"
MOTIVO_ABANDONO = "run_sync de en_mamparo sin abandon_on_cancel=False"
MOTIVO_PLAZO = "fail_after de en_mamparo con algo mas que la espera del turno"
# Lo único que puede ir dentro del plazo (c'): la espera del turno.
CUERPO_DEL_PLAZO = ["await estado.semaforo_hash.acquire()"]


def _nombre(nodo):
    if isinstance(nodo, ast.Name):
        return nodo.id
    if isinstance(nodo, ast.Attribute):
        return nodo.attr
    return None


def _funciones(arbol):
    """(nombre, nodo) de las funciones de primer nivel y de los métodos de
    las clases de primer nivel."""
    for sentencia in arbol.body:
        if isinstance(sentencia, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield sentencia.name, sentencia
        elif isinstance(sentencia, ast.ClassDef):
            for metodo in sentencia.body:
                if isinstance(metodo, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    yield f"{sentencia.name}.{metodo.name}", metodo


def llamantes_en_personal(arbol):
    """Las funciones de personal.py que llegan, directa o indirectamente, a
    una entrada de Argon2 (punto fijo sobre los nombres que usan)."""
    funciones = dict(_funciones(arbol))
    alcanzan = set(ENTRADAS_HASH)
    crece = True
    while crece:
        crece = False
        for nombre, nodo in funciones.items():
            if nombre not in alcanzan and any(isinstance(n, ast.Name) and n.id in alcanzan for n in ast.walk(nodo)):
                alcanzan.add(nombre)
                crece = True
    return alcanzan - set(ENTRADAS_HASH)


def analizar(fuentes):
    """(llamantes en personal.py, rutas que llegan a un hash, infracciones)."""
    arbol_personal = ast.parse(fuentes["personal.py"])
    llamantes = llamantes_en_personal(arbol_personal)
    expuestas = llamantes | set(ENTRADAS_HASH)
    rutas, infracciones = set(), []
    for ruta, texto in sorted(fuentes.items()):
        if ruta == "personal.py":
            continue
        arbol = ast.parse(texto)
        padres = {hijo: padre for padre in ast.walk(arbol) for hijo in ast.iter_child_nodes(padre)}
        for nodo in ast.walk(arbol):
            if isinstance(nodo, ast.ImportFrom) and (nodo.module or "").endswith("personal") \
                    and any(a.name in expuestas for a in nodo.names):
                infracciones.append(f"{ruta}:{nodo.lineno}: {MOTIVO_IMPORTA}")
        for nombre, funcion in _funciones(arbol):
            usos = [n for n in ast.walk(funcion) if isinstance(n, ast.Attribute) and n.attr in expuestas
                    and isinstance(n.value, ast.Name) and n.value.id == "personal"]
            if not usos:
                continue
            rutas.add(f"{ruta}:{nombre}")
            if not isinstance(funcion, ast.AsyncFunctionDef):
                infracciones.append(f"{ruta}:{nombre}: {MOTIVO_ASYNC}")
            for uso in usos:
                llamada = padres.get(uso)
                en_mamparo = (isinstance(llamada, ast.Call) and _nombre(llamada.func) == "en_mamparo"
                              and len(llamada.args) >= 2 and llamada.args[1] is uso
                              and isinstance(padres.get(llamada), ast.Await))
                if not en_mamparo:
                    infracciones.append(f"{ruta}:{uso.lineno}: personal.{uso.attr} {MOTIVO_FUERA}")
    mamparo = dict(_funciones(arbol_personal)).get("en_mamparo")
    if not isinstance(mamparo, ast.AsyncFunctionDef):
        infracciones.append(f"personal.py:en_mamparo: {MOTIVO_ASYNC}")
    else:
        envios = [n for n in ast.walk(mamparo) if isinstance(n, ast.Call) and _nombre(n.func) == "run_sync"]
        argumentos = {k.arg: k.value for k in envios[0].keywords} if len(envios) == 1 else {}
        limite = argumentos.get("limiter")
        if not (isinstance(limite, ast.Attribute) and limite.attr == "limitador_hash"):
            infracciones.append(f"personal.py: {MOTIVO_LIMITER}")
        abandono = argumentos.get("abandon_on_cancel")
        if not (isinstance(abandono, ast.Constant) and abandono.value is False):
            infracciones.append(f"personal.py: {MOTIVO_ABANDONO}")
        # c': el plazo cubre SOLO la espera del turno (invariante de
        # app/personal.py). Un with con más dentro cortaría un hash admitido
        # (u2b) o convertiría un TimeoutError de la función en 503 (u2c).
        plazos = [n for n in ast.walk(mamparo) if isinstance(n, (ast.With, ast.AsyncWith))
                  and any(isinstance(i.context_expr, ast.Call) and _nombre(i.context_expr.func) == "fail_after"
                          for i in n.items)]
        if not (len(plazos) == 1 and [ast.unparse(s) for s in plazos[0].body] == CUERPO_DEL_PLAZO):
            infracciones.append(f"personal.py: {MOTIVO_PLAZO}")
    return llamantes, rutas, infracciones


def fuentes_de_app():
    raiz = pathlib.Path(personal.__file__).resolve().parent
    return {ruta.relative_to(raiz).as_posix(): ruta.read_text(encoding="utf-8")
            for ruta in sorted(raiz.rglob("*.py")) if "__pycache__" not in ruta.parts}


def con_cambio(fuentes, fichero, original, nuevo):
    veces = fuentes[fichero].count(original)
    if veces != 1:
        raise AssertionError(f"SIN CONCLUSION: {original!r} aparece {veces} veces en {fichero}")
    return {**fuentes, fichero: fuentes[fichero].replace(original, nuevo)}


class U4GrafoDeLlamantes(unittest.TestCase):
    def test_solo_las_tres_rutas_async_y_por_el_mamparo(self):
        fuentes = fuentes_de_app()
        # Controles: cada atajo sobre una copia se detecta. Si no, que app/
        # no tenga infracciones no demostraría nada.
        controles = {
            "sin limiter=": (con_cambio(fuentes, "personal.py", "*argumentos, limiter=estado.limitador_hash,",
                                        "*argumentos,"), f"personal.py: {MOTIVO_LIMITER}"),
            "abandon_on_cancel=True": (con_cambio(fuentes, "personal.py", "abandon_on_cancel=False)",
                                                  "abandon_on_cancel=True)"), f"personal.py: {MOTIVO_ABANDONO}"),
            "ruta def": (con_cambio(fuentes, "rutas_personal.py", "async def activar(", "def activar("),
                         f"rutas_personal.py:activar: {MOTIVO_ASYNC}"),
            "fail_after envolviendo": (con_cambio(fuentes, "personal.py", MAMPARO_PLAZO_EN_LA_ESPERA,
                                                  MAMPARO_PLAZO_ENVOLVIENDO), f"personal.py: {MOTIVO_PLAZO}"),
        }
        for caso, (copia, esperada) in controles.items():
            with self.subTest(control=caso):
                self.assertIn(esperada, analizar(copia)[2], f"SIN CONCLUSION: el control {caso!r} no se detecta")
        llamantes, rutas, infracciones = analizar(fuentes)
        self.assertEqual(llamantes, LLAMANTES_EN_PERSONAL)
        self.assertEqual(rutas, RUTAS_CON_HASH)
        self.assertEqual(infracciones, [])


# ---------------------------------------------------------------------------
# u5: el arranque crea el mamparo y comprueba sus valores
# ---------------------------------------------------------------------------
def importar_principal():
    # app.principal llama a logging.basicConfig al importarse; se evita para
    # que los registros de las demás pruebas no salgan por stderr.
    with mock.patch.object(logging, "basicConfig"):
        from app import principal
    return principal


class Anotador(logging.Handler):
    def __init__(self, orden):
        super().__init__(logging.DEBUG)
        self.orden = orden

    def emit(self, record):
        self.orden.append(record.getMessage())


class PoolFalso:
    def __init__(self, orden):
        self.orden = orden

    def open(self, wait, timeout):
        pass

    def close(self):
        self.orden.append("pool cerrado")


class LimitadorFalso:
    def __init__(self, orden):
        self.orden = orden

    async def verificar(self):
        return []

    async def cerrar(self):
        self.orden.append("limitador cerrado")


PATRON_RESUMEN_PARCIAL = re.compile(r"EVENTO hashes_saturados_resumen etapa=admision n=1 inicio=(\d+) fin=(\d+) "
                                    r"parcial=1")


def tareas_de_resumen():
    return [t for t in asyncio.all_tasks() if t.get_coro().__qualname__ == "ResumenSaturacion.vaciar_cada"]


class U5Arranque(unittest.TestCase):
    def arrancar(self, ejecutor=None, mamparo=None):
        """Recorre ciclo_de_vida con todo lo de fuera sustituido. Devuelve
        (lo visto dentro, la tarea, la excepción del arranque, el orden de
        los eventos y cierres)."""
        principal = importar_principal()
        orden = []
        anotador = Anotador(orden)
        registro = logging.getLogger("canario.personal")

        async def vida():
            app = FastAPI()
            visto, tareas = None, []
            try:
                async with principal.ciclo_de_vida(app):
                    estado = app.state
                    tareas = tareas_de_resumen()
                    visto = (estado.semaforo_hash.value, estado.semaforo_hash.max_value,
                             estado.limitador_hash.total_tokens,
                             type(estado.resumen_saturacion) is personal.ResumenSaturacion,
                             len(tareas), tareas[0].done() if tareas else None)
                    estado.resumen_saturacion.anotar()
            except verificacion_arranque.ArranqueBloqueado as error:
                return visto, tareas_de_resumen(), error, orden
            return visto, tareas, None, orden

        parches = [
            mock.patch.object(personal, "_ejecutor", None),
            mock.patch.object(personal, "iniciar_ejecutor_hashes", return_value=ejecutor or EJECUTOR),
            mock.patch.object(bd, "comprobar_secreto"),
            mock.patch.object(claves, "cargar", return_value=object()),
            mock.patch.object(limitador, "cargar_limites", return_value=({}, "prueba")),
            mock.patch.object(limitador, "leer_contrasena"),
            mock.patch.object(limitador, "describir_limites", return_value="prueba"),
            mock.patch.object(rutas_web, "cargar_origen", return_value=("https://web.test", "prueba")),
            mock.patch.object(solicitudes, "cargar_origen", return_value="https://personal.test"),
            mock.patch.object(bd, "crear_pool", return_value=PoolFalso(orden)),
            mock.patch.object(verificacion_arranque, "verificar"),
            mock.patch.object(limitador, "Limitador", return_value=LimitadorFalso(orden)),
        ]
        if mamparo is not None:
            parches.append(mock.patch.object(personal, "crear_mamparo", mamparo))
        registro.addHandler(anotador)
        try:
            with contextlib.ExitStack() as pila:
                for parche in parches:
                    pila.enter_context(parche)
                return ejecutar(vida)
        finally:
            registro.removeHandler(anotador)

    def test_crea_el_mamparo_la_tarea_y_la_para_antes_de_cerrar(self):
        visto, tareas, error, orden = self.arrancar()
        self.assertIsNone(error)
        self.assertEqual(visto, (N, N, N, True, 1, False))
        # Al salir: la tarea cancelada (CancelledError no se captura), el
        # resumen parcial escrito, y después el limitador y el pool.
        self.assertTrue(tareas[0].cancelled())
        self.assertEqual(len(orden), 4, f"{orden}")
        self.assertEqual(orden[0], "EVENTO hashes_saturados etapa=admision")
        encontrado = PATRON_RESUMEN_PARCIAL.fullmatch(orden[1])
        self.assertIsNotNone(encontrado, orden[1])
        inicio, fin = int(encontrado.group(1)), int(encontrado.group(2))
        self.assertEqual((inicio % 60, fin - inicio), (0, 60))
        self.assertEqual(orden[2:], ["limitador cerrado", "pool cerrado"])

    def test_con_un_valor_distinto_no_arranca(self):
        def limitador_de_3():
            return anyio.Semaphore(2, max_value=2), anyio.CapacityLimiter(3)

        def semaforo_de_3():
            return anyio.Semaphore(3, max_value=3), anyio.CapacityLimiter(2)

        ejecutor_de_3 = concurrent.futures.ThreadPoolExecutor(max_workers=3)
        casos = {
            "limitador": ({"mamparo": limitador_de_3},
                          "semaforo=2/2 limitador=3 ejecutor=2; se esperaba 2 en los tres"),
            "semaforo": ({"mamparo": semaforo_de_3},
                         "semaforo=3/3 limitador=2 ejecutor=2; se esperaba 2 en los tres"),
            "ejecutor": ({"ejecutor": ejecutor_de_3},
                         "semaforo=2/2 limitador=2 ejecutor=3; se esperaba 2 en los tres"),
        }
        try:
            for caso, (argumentos, detalle) in casos.items():
                with self.subTest(caso=caso), self.assertLogs("canario.arranque", "ERROR") as registro:
                    visto, tareas, error, orden = self.arrancar(**argumentos)
                    self.assertEqual(str(error), "mamparo_hashes")
                    self.assertEqual(registro.output,
                                     [f"ERROR:canario.arranque:ARRANQUE BLOQUEADO: mamparo_hashes: {detalle}"])
                    self.assertIsNone(visto)
                    self.assertEqual(tareas, [])
                    self.assertEqual(orden, ["limitador cerrado", "pool cerrado"])
        finally:
            ejecutor_de_3.shutdown(wait=True)


# ---------------------------------------------------------------------------
# u6: ResumenSaturacion (reloj inyectado) y el evento interno
# ---------------------------------------------------------------------------
class Reloj:
    def __init__(self, ahora=0.0):
        self.ahora = ahora

    def __call__(self):
        return self.ahora


class U6Resumen(unittest.TestCase):
    def test_cien_saturaciones_dan_una_linea(self):
        reloj = Reloj()
        resumen = personal.ResumenSaturacion(reloj=reloj)
        with self.assertLogs("canario.personal", "DEBUG") as registro:
            for i in range(100):
                reloj.ahora = i * 0.59
                resumen.anotar()
        self.assertEqual(registro.output, [EVENTO_ADMISION])
        # Control: en la ventana siguiente, la primera vuelve a escribir.
        reloj.ahora = 60.0
        with self.assertLogs("canario.personal", "DEBUG") as registro:
            resumen.anotar()
        self.assertEqual(registro.output, [EVENTO_ADMISION], "SIN CONCLUSION: la ventana siguiente no escribe")

    def test_al_cerrar_la_ventana_vaciar_da_n_inicio_y_fin(self):
        reloj = Reloj()
        resumen = personal.ResumenSaturacion(reloj=reloj)
        with self.assertLogs("canario.personal", "DEBUG"):
            for i in range(100):
                reloj.ahora = i * 0.59
                resumen.anotar()
        # Control: sin vaciar no sale (el reloj solo, a 61 s), y con la
        # ventana aún abierta tampoco.
        reloj.ahora = 61.0
        with self.assertNoLogs("canario.personal", "DEBUG"):
            resumen.vaciar(59.9)
        with self.assertLogs("canario.personal", "DEBUG") as registro:
            resumen.vaciar(61.0)
        self.assertEqual(registro.output, [PREFIJO_RESUMEN + "n=100 inicio=0 fin=60"])
        # Una sola vez.
        with self.assertNoLogs("canario.personal", "DEBUG"):
            resumen.vaciar(62.0)

    def test_forzar_da_parcial_1(self):
        reloj = Reloj(10.0)
        resumen = personal.ResumenSaturacion(reloj=reloj)
        with self.assertLogs("canario.personal", "DEBUG"):
            resumen.anotar()
        # Control: sin forzar, la ventana abierta no sale.
        with self.assertNoLogs("canario.personal", "DEBUG"):
            resumen.vaciar(10.0)
        with self.assertLogs("canario.personal", "DEBUG") as registro:
            resumen.vaciar(forzar=True)
        self.assertEqual(registro.output, [PREFIJO_RESUMEN + "n=1 inicio=0 fin=60 parcial=1"])
        # Con una ventana cerrada y otra abierta, solo la abierta es parcial.
        with self.assertLogs("canario.personal", "DEBUG"):
            resumen.anotar()
            resumen.anotar()
            reloj.ahora = 70.0
            resumen.anotar()
        with self.assertLogs("canario.personal", "DEBUG") as registro:
            resumen.vaciar(forzar=True)
        self.assertEqual(registro.output, [PREFIJO_RESUMEN + "n=2 inicio=0 fin=60",
                                           PREFIJO_RESUMEN + "n=1 inicio=60 fin=120 parcial=1"])

    def test_periodo_literal(self):
        self.assertEqual(personal.PERIODO_RESUMEN, 5)
        self.assertEqual(inspect.signature(personal.ResumenSaturacion.vaciar_cada).parameters["periodo"].default, 5)
        self.assertEqual(inspect.signature(personal.ResumenSaturacion.lanzar_tarea).parameters["periodo"].default, 5)

    def escenario_vaciar_que_lanza(self, metodo):
        async def escenario():
            resumen = personal.ResumenSaturacion(reloj=lambda: 0.0)
            llamadas = []

            def vaciar_que_lanza(ahora=None, forzar=False):
                llamadas.append(ahora)
                if len(llamadas) == 1:
                    raise RuntimeError("detalle que no debe salir")

            resumen.vaciar = vaciar_que_lanza
            tarea = asyncio.create_task(metodo(resumen)(0.01))
            await esperar_que(lambda: len(llamadas) >= 3 or tarea.done(), "la tarea no llega a vaciar")
            viva = not tarea.done()
            error = None if viva else tarea.exception()
            tarea.cancel()
            await asyncio.wait({tarea})
            return viva, type(error).__name__ if error else None, tarea.cancelled()

        return ejecutar(escenario)

    def test_un_vaciar_que_lanza_deja_su_evento_y_la_tarea_sigue(self):
        sin_manejo = mutante(personal.ResumenSaturacion.vaciar_cada,
                             ("        try:\n"
                              "            self.vaciar(self.reloj())\n"
                              "        except Exception as error:  # noqa: BLE001 - se registra y la tarea sigue\n"
                              "            registro.error(\"EVENTO resumen_saturacion_caido: %s\", "
                              "type(error).__name__)\n"),
                             "        self.vaciar(self.reloj())\n")
        with self.assertNoLogs("canario.personal", "DEBUG"):
            control = self.escenario_vaciar_que_lanza(lambda r: types.MethodType(sin_manejo, r))
        self.assertEqual(control, (False, "RuntimeError", False),
                         "SIN CONCLUSION: sin el manejo, la tarea no muere con el error")
        with self.assertLogs("canario.personal", "DEBUG") as registro:
            resultado = self.escenario_vaciar_que_lanza(lambda r: r.vaciar_cada)
        # Viva tras el fallo, y la cancelación sí la para.
        self.assertEqual(resultado, (True, None, True))
        self.assertEqual(registro.output, [EVENTO_CAIDO])

    def test_el_interno_sale_en_cada_caso(self):
        doble = types.SimpleNamespace(verify=lambda _g, _c: True, hash=lambda _c: "$argon2id$doble")
        with mock.patch.object(personal, "_ejecutor", EJECUTOR), mock.patch.object(personal, "_hasher", doble):
            # Control: con huecos libres, ni evento ni 503.
            with self.assertNoLogs("canario.personal", "DEBUG"):
                self.assertEqual(personal._crear_hash_en_ejecutor("Contrasena-nueva-12"), "$argon2id$doble")
            ocupados = sum(personal._semaforo.acquire(blocking=False) for _ in range(N + 1))
            try:
                self.assertEqual(ocupados, N, "SIN CONCLUSION: el semaforo interno no tiene N huecos")
                with mock.patch.object(personal, "ESPERA_HASH", 0.05), \
                        self.assertLogs("canario.personal", "DEBUG") as registro:
                    for llamada in (lambda: personal._verificar_en_ejecutor(None, "contrasena-de-prueba"),
                                    lambda: personal._verificar_en_ejecutor(None, "contrasena-de-prueba"),
                                    lambda: personal._crear_hash_en_ejecutor("Contrasena-nueva-12")):
                        with self.assertRaises(personal.Saturado):
                            llamada()
            finally:
                for _ in range(ocupados):
                    personal._semaforo.release()
        self.assertEqual(registro.output, [EVENTO_INTERNO] * 3)


if __name__ == "__main__":
    unittest.main()
