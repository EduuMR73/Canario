"""Pruebas de tests/estres/diag_hilos.py sin Docker ni la API: la tabla de
decisión de D2 (una fila por caso, sus fronteras y su precedencia), la
clasificación de los hilos, los contadores y los controles que no necesitan
el contenedor.

    python -m unittest tests.estres.test_diag_hilos

Los oráculos son literales (decisiones, filas y umbrales escritos aquí), no
constantes leídas de diag_hilos. Cada caso negativo tiene su control positivo:
el escenario base, que da A2, cambiado en una sola cosa.
"""
import asyncio
import copy
import pathlib
import sys
import threading
import time
import types
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import diag_hilos as D  # noqa: E402

T0 = 1_800_000_000.0
# Ventana de la INUNDACIÓN de L2 (fases_de("l2"): carga de 150 a 270 s):
# [150 + 30, 270 - 5] = 85 s, 170 muestras esperadas.
DESDE, HASTA = T0 + 180.0, T0 + 265.0
VENTANA = (DESDE, HASTA)
NOMBRES_CONTROLES = ("booleano_proxy", "retraso_bucle", "limitador_41", "cpu_hilo", "semaforo",
                     "ejecutor_lento_argon2", "centinela", "pool_5_mas_1", "pg_sleep_bd_activa")
REPRO_OK = {"p95_ms": {"denuncia": 9000.0, "seguimiento": 9000.0, "web_seguimiento": 9000.0},
            "slo_ms": {"denuncia": 1000, "seguimiento": 500, "web_seguimiento": 300}, "n429": 0}
CLASES_HILOS = {"libre": 0, "semaforo": 30, "pool": 0, "argon2": 2, "bd_activa": 3, "otra": 5}


def configuracion(**cambios):
    base = {"tipo": "configuracion", "app": "app.principal:aplicacion", "host": "10.88.0.4", "port": 8000,
            "proxy_headers": True, "forwarded_allow_ips": "10.88.0.2", "access_log": False, "server_header": False}
    base.update(cambios)
    return base


def controles(resultado=None, falta=None):
    resultado = resultado or {}
    return [{"tipo": "control", "nombre": n, "resultado": resultado.get(n, "PASA")}
            for n in NOMBRES_CONTROLES if n != falta]


def muestras(n=171, lambda_por_s=100.0, **campos):
    """n muestras cada 0,5 s desde DESDE (la 171 cae justo en HASTA), con el
    escenario de H-hilos: 40 prestados, 600 en espera (W = 600 / 100 = 6 s),
    requests_waiting 0, fracción semáforo + argon2 = 32 / 40 = 0,8, CPU baja
    y retraso pequeño. campos cambia un valor en todas."""
    lista = []
    for i in range(n):
        m = {"tipo": "muestra", "n": i, "t": DESDE + i * 0.5, "retraso_s": 0.01, "prestados": 40, "fichas": 40,
             "en_espera": 600, "clases": dict(CLASES_HILOS), "otras": {}, "hilos_anyio": 40,
             "lambda_total": round(i * 0.5 * lambda_por_s), "http_contadas": round(i * 0.5 * lambda_por_s),
             "cliente_caddy": 0, "pool_espera": 0, "pool_encoladas": 0, "pool_espera_ms": 0, "pool_conexiones": 5,
             "cpu_proceso": 1.0, "cpu_principal": 0.3, "cpu_argon2": 0.6, "cpu_anyio": 0.1}
        m.update(copy.deepcopy(campos))
        lista.append(m)
    return lista


def inicios_de(lista):
    """Inicios de k6 que coinciden con lambda: tantos como lambda sube entre
    la primera y la última muestra, todos dentro de (primera, última]."""
    primera, ultima = lista[0], lista[-1]
    total = ultima["lambda_total"] - primera["lambda_total"]
    paso = (ultima["t"] - primera["t"]) / total
    return [primera["t"] + (j + 1) * paso for j in range(total)]


def evaluar(lista=None, ctrl=None, conf=None, repro=None, inicios=None, ventana=VENTANA, **kw):
    lista = muestras() if lista is None else lista
    registros = [conf or configuracion()] + (controles() if ctrl is None else ctrl) + lista
    if inicios is None:
        validas = [m for m in lista if m["tipo"] == "muestra" and DESDE <= m["t"] <= HASTA]
        inicios = inicios_de(validas) if len(validas) >= 2 else []
    return D.evaluar_d2(registros, ventana, inicios, repro or copy.deepcopy(REPRO_OK), **kw)


class TablaDeDecision(unittest.TestCase):
    def test_control_positivo_escenario_base_da_a2_fila_4(self):
        r = evaluar()
        self.assertEqual((r["decision"], r["fila"]), ("A2", 4), r["motivos"])

    def test_fila_1_control_fallido_gana_a_todo(self):
        for nombre in NOMBRES_CONTROLES:
            with self.subTest(control=nombre):
                r = evaluar(ctrl=controles({nombre: "FALLA"}))
                self.assertEqual((r["decision"], r["fila"]), ("SIN CONCLUSION", 1))
                # También con H-bucle presente: la fila 1 va antes que la 2.
                r = evaluar(lista=muestras(retraso_s=5.0), ctrl=controles({nombre: "FALLA"}))
                self.assertEqual((r["decision"], r["fila"]), ("SIN CONCLUSION", 1))

    def test_fila_1_control_ausente(self):
        r = evaluar(ctrl=controles(falta="centinela"))
        self.assertEqual(r["decision"], "SIN CONCLUSION")
        self.assertTrue(any("centinela" in m and "ausente" in m for m in r["motivos"]), r["motivos"])

    def test_fila_1_configuracion_efectiva(self):
        self.assertEqual(evaluar(conf=configuracion(forwarded_allow_ips="*"))["decision"], "SIN CONCLUSION")
        self.assertEqual(evaluar(conf=configuracion(proxy_headers=False))["decision"], "SIN CONCLUSION")
        self.assertEqual(evaluar(conf=configuracion(host="0.0.0.0"))["decision"], "SIN CONCLUSION")  # noqa: S104
        # Dos líneas de configuración: el proceso arrancó dos veces.
        lista = muestras()
        registros = [configuracion(), configuracion()] + controles() + lista
        r = D.evaluar_d2(registros, VENTANA, inicios_de(lista), copy.deepcopy(REPRO_OK))
        self.assertEqual(r["decision"], "SIN CONCLUSION")

    def test_fila_1_frontera_muestras_perdidas(self):
        # 171 muestras en la ventana y 170 esperadas: quitar k deja k - 1 perdidas.
        base = muestras()
        perdidas_17 = base[:50] + base[68:]   # quita 18: 17 de 170 = 10 % exacto, no pasa de 10 %
        perdidas_18 = base[:50] + base[69:]   # quita 19: 18 de 170 > 10 %
        r = evaluar(lista=perdidas_17)
        self.assertEqual(r["cifras"]["muestras_perdidas"], 17)
        self.assertEqual(r["decision"], "A2", r["motivos"])
        r = evaluar(lista=perdidas_18)
        self.assertEqual(r["cifras"]["muestras_perdidas"], 18)
        self.assertEqual(r["decision"], "SIN CONCLUSION")

    def test_fila_1_cuentas_cruzadas_frontera_1_por_ciento(self):
        # lambda = k6 = 8500 en la ventana. middleware 8585: justo el 1 % (vale);
        # 8586: más del 1 % (fallo de control).
        for extra, esperado in ((85, "A2"), (86, "SIN CONCLUSION")):
            with self.subTest(extra=extra):
                lista = muestras()
                lista[-1]["http_contadas"] = 8500 + extra
                r = evaluar(lista=lista)
                self.assertEqual(r["cifras"]["lambda_ventana"], 8500)
                self.assertEqual(r["cifras"]["k6_ventana"], 8500)
                self.assertEqual(r["decision"], esperado, r["motivos"])

    def test_fila_1_k6_no_coincide(self):
        lista = muestras()
        inicios = inicios_de(lista)[:8400]  # 100 de 8500 menos: 1,18 %
        self.assertEqual(evaluar(lista=lista, inicios=inicios)["decision"], "SIN CONCLUSION")
        # Control: un inicio fuera de la ventana no cuenta.
        self.assertEqual(evaluar(lista=lista, inicios=inicios_de(lista) + [HASTA + 10])["decision"], "A2")

    def test_fila_1_reproduccion(self):
        repro = copy.deepcopy(REPRO_OK)
        repro["p95_ms"]["denuncia"] = 1000.0  # igual al SLO: no está por encima
        self.assertEqual(evaluar(repro=repro)["decision"], "SIN CONCLUSION")
        repro["p95_ms"]["denuncia"] = 1001.0  # control: por encima
        self.assertEqual(evaluar(repro=repro)["decision"], "A2")
        repro["p95_ms"]["web_seguimiento"] = None  # sin respuestas: cuenta como infinito
        self.assertEqual(evaluar(repro=repro)["decision"], "A2")
        repro["n429"] = 1
        self.assertEqual(evaluar(repro=repro)["decision"], "SIN CONCLUSION")

    def test_fila_1_booleano_de_proxy_true(self):
        lista = muestras()
        lista[-1]["cliente_caddy"] = 1
        r = evaluar(lista=lista)
        self.assertEqual(r["decision"], "SIN CONCLUSION")
        self.assertTrue(any("booleano de proxy True" in m for m in r["motivos"]))

    def test_fila_1_validez_de_la_carga_e_instrumento(self):
        self.assertEqual(evaluar(fallos_carga=["k6 no dejo el CSV"])["decision"], "SIN CONCLUSION")
        self.assertEqual(evaluar(ilegibles=1)["decision"], "SIN CONCLUSION")
        self.assertEqual(evaluar(ventana=None)["decision"], "SIN CONCLUSION")
        lista = muestras()
        lista[10]["pool_espera"] = None
        self.assertEqual(evaluar(lista=lista)["decision"], "SIN CONCLUSION")
        lista = muestras() + [{"tipo": "error_muestra", "t": DESDE + 3, "clase": "OSError"}]
        self.assertEqual(evaluar(lista=lista)["decision"], "SIN CONCLUSION")

    def test_fila_2_h_bucle_frontera(self):
        r = evaluar(lista=muestras(retraso_s=1.0))
        self.assertEqual((r["decision"], r["fila"]), ("PARADA", 2))
        r = evaluar(lista=muestras(retraso_s=0.999))
        self.assertEqual((r["decision"], r["fila"]), ("A2", 4))
        # p95 por rango más cercano sobre 171: la 163.ª. 9 muestras a 1 s la hacen 1 s; 8, no.
        for n_altas, esperado in ((9, "PARADA"), (8, "A2")):
            with self.subTest(n_altas=n_altas):
                lista = muestras()
                for m in lista[-n_altas:]:
                    m["retraso_s"] = 1.0
                self.assertEqual(evaluar(lista=lista)["decision"], esperado)

    def test_fila_3_h_cpu_frontera(self):
        for campos, esperado in (({"cpu_proceso": 1.8}, ("PARADA (M1)", 3)), ({"cpu_proceso": 1.79}, ("A2", 4)),
                                 ({"cpu_principal": 0.9}, ("PARADA (M1)", 3)), ({"cpu_principal": 0.89}, ("A2", 4))):
            with self.subTest(campos=campos):
                r = evaluar(lista=muestras(**campos))
                self.assertEqual((r["decision"], r["fila"]), esperado)

    def test_precedencia_fila_2_antes_que_3(self):
        r = evaluar(lista=muestras(retraso_s=2.0, cpu_proceso=1.95))
        self.assertEqual((r["decision"], r["fila"]), ("PARADA", 2))

    def test_fila_4_frontera_prestados_95_por_ciento(self):
        # 171 muestras: el 95 % son 162,45, así que hacen falta 163 con 40 prestados.
        for llenas, esperado in ((163, ("A2", 4)), (162, ("PARADA", 6))):
            with self.subTest(llenas=llenas):
                lista = muestras()
                for m in lista[llenas:]:
                    m["prestados"] = 39
                r = evaluar(lista=lista)
                self.assertEqual((r["decision"], r["fila"]), esperado)

    def test_fila_4_frontera_w_anyio(self):
        # lambda 100/s: 500 en espera dan W = 5,0 s (vale); 499, 4,99 s (no).
        for espera, esperado in ((500, ("A2", 4)), (499, ("PARADA", 6))):
            with self.subTest(espera=espera):
                r = evaluar(lista=muestras(en_espera=espera))
                self.assertEqual((r["decision"], r["fila"]), esperado)
                self.assertAlmostEqual(r["cifras"]["w_anyio_s"], espera / 100)

    def test_fila_4_frontera_requests_waiting(self):
        self.assertEqual(evaluar(lista=muestras(pool_espera=1))["fila"], 4)
        r = evaluar(lista=muestras(pool_espera=2))
        self.assertEqual((r["decision"], r["fila"]), ("PARADA", 6))

    def test_fila_4_frontera_fraccion_semaforo_argon2(self):
        mitad = {"libre": 0, "semaforo": 10, "pool": 0, "argon2": 10, "bd_activa": 0, "otra": 20}
        menos = {"libre": 0, "semaforo": 10, "pool": 0, "argon2": 9, "bd_activa": 0, "otra": 21}
        self.assertEqual(evaluar(lista=muestras(clases=mitad))["fila"], 4)
        self.assertEqual(evaluar(lista=muestras(clases=menos))["fila"], 6)
        # Los libres no cuentan en el denominador: con 100 libres sigue en 0,5.
        self.assertEqual(evaluar(lista=muestras(clases={**mitad, "libre": 100}))["fila"], 4)
        # Si todos son libres no hay fracción: no se puede dar H-hilos.
        todos_libres = {"libre": 40, "semaforo": 0, "pool": 0, "argon2": 0, "bd_activa": 0, "otra": 0}
        self.assertEqual(evaluar(lista=muestras(clases=todos_libres))["fila"], 6)

    def escenario_bd(self, **campos):
        """H-bd: requests_waiting 3, fracción pool 20 / 40 = 0,5 y espera media
        de 1000 ms (1 000 000 ms en 1000 encoladas)."""
        valores = {"pool_espera": 3, "clases": {"libre": 0, "semaforo": 5, "pool": 20, "argon2": 0, "bd_activa": 5,
                                                "otra": 10}}
        valores.update(campos)
        espera_total_ms = valores.pop("espera_total_ms", 1_000_000)
        encoladas = valores.pop("encoladas", 1000)
        lista = muestras(**valores)
        lista[-1]["pool_encoladas"] = encoladas
        lista[-1]["pool_espera_ms"] = espera_total_ms
        return lista

    def test_fila_5_h_bd_control_positivo_y_fronteras(self):
        r = evaluar(lista=self.escenario_bd())
        self.assertEqual((r["decision"], r["fila"]), ("A2 con nota", 5), r["motivos"])
        self.assertEqual(r["cifras"]["espera_media_pool_ms"], 1000)
        self.assertEqual(evaluar(lista=self.escenario_bd(espera_total_ms=999_000))["fila"], 6)
        self.assertEqual(evaluar(lista=self.escenario_bd(pool_espera=2))["fila"], 6)
        menos = {"libre": 0, "semaforo": 5, "pool": 19, "argon2": 0, "bd_activa": 5, "otra": 11}
        self.assertEqual(evaluar(lista=self.escenario_bd(clases=menos))["fila"], 6)

    def test_fila_5_no_aplica(self):
        # Sin ninguna petición encolada en la ventana, Δwait/Δqueued es "no aplica" y vale.
        r = evaluar(lista=self.escenario_bd(encoladas=0, espera_total_ms=0))
        self.assertEqual(r["cifras"]["espera_media_pool_ms"], "no aplica")
        self.assertEqual((r["decision"], r["fila"]), ("A2 con nota", 5))

    def test_fila_6_ninguna(self):
        r = evaluar(lista=muestras(prestados=10, en_espera=0))
        self.assertEqual((r["decision"], r["fila"]), ("PARADA", 6))

    def test_solo_cuentan_las_muestras_de_la_ventana(self):
        fuera = muestras(n=20, retraso_s=9.0)
        for i, m in enumerate(fuera):
            m["t"] = DESDE - 30 + i * 0.5
            m["lambda_total"] = m["http_contadas"] = 0
        lista = fuera + muestras()
        self.assertEqual(evaluar(lista=lista)["decision"], "A2")
        # Control: las mismas muestras lentas dentro de la ventana sí dan H-bucle.
        dentro = muestras()
        for m in dentro[:20]:
            m["retraso_s"] = 9.0
        self.assertEqual(evaluar(lista=dentro)["decision"], "PARADA")


class Piezas(unittest.TestCase):
    def test_ventana_valida(self):
        self.assertEqual(D.ventana_valida(T0 + 150, T0 + 270), (T0 + 180, T0 + 265))

    def test_percentil_95(self):
        self.assertIsNone(D.percentil_95([]))
        self.assertEqual(D.percentil_95(list(range(1, 101))), 95)
        self.assertEqual(D.percentil_95([3]), 3)
        self.assertEqual(D.percentil_95(list(range(1, 21))), 19)

    def test_ticks_de_stat_con_parentesis_en_el_nombre(self):
        linea = "7 (a) b) S 1 7 7 0 -1 4194560 100 0 0 0 250 50 0 0 20 0 3 0 100 0 0"
        self.assertEqual(D.ticks_de_stat(linea), 300)

    def test_linea_json(self):
        linea = D.linea_json({"tipo": "muestra", "t": 1.5})
        self.assertTrue(linea.startswith("DIAG2 "))
        self.assertEqual(linea, 'DIAG2 {"t":1.5,"tipo":"muestra"}')


PERSONAL = "/srv/app/personal.py"
ANYIO = "/opt/venv/lib/python3.12/site-packages/anyio/_backends/_asyncio.py"
POOL = "/opt/venv/lib/python3.12/site-packages/psycopg_pool/pool.py"
CURSOR = "/opt/venv/lib/python3.12/site-packages/psycopg/cursor.py"
CONEXION = "/opt/venv/lib/python3.12/site-packages/psycopg/connection.py"
COLA = "/usr/local/lib/python3.12/queue.py"
HILOS = "/usr/local/lib/python3.12/threading.py"
FUTUROS = "/usr/local/lib/python3.12/concurrent/futures/_base.py"
RUTAS = "/srv/app/rutas_personal.py"


class Clasificacion(unittest.TestCase):
    def test_libre(self):
        self.assertEqual(D.clasificar_pila([(HILOS, "wait"), (COLA, "get"), (ANYIO, "run"), (HILOS, "_bootstrap")]),
                         "libre")

    def test_queue_get_dentro_de_una_ruta_no_es_libre(self):
        self.assertEqual(D.clasificar_pila([(HILOS, "wait"), (COLA, "get"), (RUTAS, "iniciar_sesion"),
                                            (ANYIO, "run")]), "otra")

    def test_semaforo_gana_a_argon2_mientras_espera_hueco(self):
        pila = [(HILOS, "acquire"), (PERSONAL, "_tomar_hueco_hash"), (PERSONAL, "_verificar_en_ejecutor"),
                (PERSONAL, "_comprobar_factores"), (PERSONAL, "iniciar_sesion"), (ANYIO, "run")]
        self.assertEqual(D.clasificar_pila(pila), "semaforo")

    def test_argon2(self):
        for funcion in ("_verificar_en_ejecutor", "_crear_hash_en_ejecutor"):
            with self.subTest(funcion=funcion):
                pila = [(HILOS, "wait"), (FUTUROS, "result"), (PERSONAL, funcion), (ANYIO, "run")]
                self.assertEqual(D.clasificar_pila(pila), "argon2")

    def test_pool_en_la_cola(self):
        pila = [(HILOS, "wait"), (POOL, "wait"), (POOL, "_getconn_unchecked"), (POOL, "getconn"),
                (PERSONAL, "resolver_empresa"), (ANYIO, "run")]
        self.assertEqual(D.clasificar_pila(pila), "pool")

    def test_check_connection_es_bd_activa_no_pool(self):
        pila = [(CONEXION, "wait"), (CONEXION, "execute"), (POOL, "check_connection"), (POOL, "_check_connection"),
                (POOL, "getconn"), (ANYIO, "run")]
        self.assertEqual(D.clasificar_pila(pila), "bd_activa")

    def test_bd_activa(self):
        self.assertEqual(D.clasificar_pila([(CONEXION, "wait"), (CURSOR, "execute"), (PERSONAL, "iniciar_sesion"),
                                            (ANYIO, "run")]), "bd_activa")

    def test_otra(self):
        self.assertEqual(D.clasificar_pila([("/srv/app/cripto.py", "cifrar"), (ANYIO, "run")]), "otra")
        self.assertEqual(D.clasificar_pila([]), "otra")

    def test_nombres_de_otro_fichero_no_cuentan(self):
        self.assertEqual(D.clasificar_pila([("/srv/app/otro.py", "_tomar_hueco_hash"), (ANYIO, "run")]), "otra")

    def test_hilos_de_anyio(self):
        self.assertTrue(D.es_hilo_anyio("AnyIO worker thread", True))
        self.assertFalse(D.es_hilo_anyio("AnyIO worker thread", False))
        for nombre in ("argon2_0", "argon2_1", "canario-worker-0", "canario-worker-2", "canario-scheduler"):
            with self.subTest(nombre=nombre):
                self.assertFalse(D.es_hilo_anyio(nombre, True))

    def test_resumen_marco(self):
        self.assertEqual(D.resumen_marco(("/srv/app/cripto.py", "cifrar")), "cripto.py:cifrar")


class SinLocales(unittest.TestCase):
    """La pila que se clasifica no lleva nada de las variables locales; el
    volcado de locales (solo del control positivo) sí."""

    def test_centinela(self):
        centinela = "centinela-de-prueba-0123456789abcdef"
        listo, soltar = threading.Event(), threading.Event()

        def con_secreto(contrasena):
            listo.set()
            soltar.wait(5)
            return contrasena

        hilo = threading.Thread(target=con_secreto, args=(centinela,))
        hilo.start()
        try:
            self.assertTrue(listo.wait(5))
            marco = sys._current_frames()[hilo.ident]
            pila = D.pila_de(marco)
            texto = D.linea_json({"pila": pila, "clase": D.clasificar_pila(pila)})
            self.assertNotIn(centinela, texto)
            self.assertIn(centinela, D._volcar_locales(marco))  # control positivo
            del marco
        finally:
            soltar.set()
            hilo.join(5)


class Contadores(unittest.TestCase):
    def test_contador_asgi(self):
        llamadas = []

        async def app(scope, receive, send):
            llamadas.append(scope["type"])

        contador = D.ContadorAsgi(app)

        async def lanzar():
            for scope in ({"type": "http", "method": "POST", "path": "/salud", "client": ("127.0.0.1", 1)},
                          {"type": "http", "method": "GET", "path": "/salud", "client": ("10.88.0.4", 1)},
                          {"type": "http", "method": "POST", "path": "/sesiones", "client": ("127.0.0.1", 1)},
                          {"type": "http", "method": "POST", "path": "/salud", "client": ("10.88.0.2", 1)},
                          {"type": "lifespan"}):
                await contador(scope, None, None)

        asyncio.run(lanzar())
        self.assertEqual(contador.peticiones, 2)  # sin los dos POST /salud ni el lifespan
        self.assertEqual(contador.cliente_caddy, 1)
        self.assertEqual(llamadas, ["http", "http", "http", "http", "lifespan"])  # todo llega a la app

    def test_envolver_run_sync(self):
        vistas = []

        async def run_sync(func, *args, abandon_on_cancel=False, limiter=None):
            vistas.append((func, args, limiter))
            return "hecho"

        modulo = types.SimpleNamespace(run_sync=run_sync)
        contador = D.ContadorLlamadas()
        original = D.envolver_run_sync(modulo, contador)
        self.assertIs(original, run_sync)

        async def lanzar():
            self.assertEqual(await modulo.run_sync(len, "a"), "hecho")
            await modulo.run_sync(len, "b", limiter=None)
            await modulo.run_sync(len, "c", limiter=object())

        asyncio.run(lanzar())
        self.assertEqual(contador.llamadas, 2)  # la del limitador propio no cuenta
        self.assertEqual([v[1] for v in vistas], [("a",), ("b",), ("c",)])


class ProxyFiel:
    """Lo mínimo de ProxyHeadersMiddleware de uvicorn 0.54.0
    (middleware/proxy_headers.py:24-62): si el cliente es de confianza, lo
    sustituye por el último X-Forwarded-For."""

    def __init__(self, app, trusted_hosts):
        self.app, self.confianza = app, {h.strip() for h in trusted_hosts.split(",")}

    async def __call__(self, scope, receive, send):
        if scope["client"][0] in self.confianza:
            for nombre, valor in scope["headers"]:
                if nombre == b"x-forwarded-for":
                    scope["client"] = (valor.decode("latin1").split(",")[-1].strip(), 0)
        await self.app(scope, receive, send)


class ProxyRoto:
    """Un proxy que nunca reescribe el cliente (como proxy_headers=False)."""

    def __init__(self, app, trusted_hosts):
        self.app = app

    async def __call__(self, scope, receive, send):
        await self.app(scope, receive, send)


class ControlesSinContenedor(unittest.TestCase):
    def contexto(self):
        return types.SimpleNamespace(config=types.SimpleNamespace(forwarded_allow_ips="10.88.0.2"))

    def test_booleano_proxy_pasa_con_un_proxy_fiel(self):
        [(nombre, ok, detalle)] = asyncio.run(D.control_booleano_proxy(self.contexto(), ProxyFiel))
        self.assertEqual(nombre, "booleano_proxy")
        self.assertTrue(ok, detalle)
        self.assertEqual(detalle, {"proxy_headers_true": False, "proxy_headers_false": True,
                                   "ip_fuera_de_forwarded": True})

    def test_booleano_proxy_falla_si_el_proxy_no_reescribe(self):
        [(_, ok, detalle)] = asyncio.run(D.control_booleano_proxy(self.contexto(), ProxyRoto))
        self.assertFalse(ok)
        self.assertTrue(detalle["proxy_headers_true"])

    @unittest.skipUnless(__import__("importlib").util.find_spec("uvicorn"), "uvicorn no instalado en el host")
    def test_booleano_proxy_con_el_middleware_real_de_uvicorn(self):
        [(_, ok, detalle)] = asyncio.run(D.control_booleano_proxy(self.contexto()))
        self.assertTrue(ok, detalle)

    @unittest.skipUnless(__import__("importlib").util.find_spec("anyio"), "anyio no instalado en el host")
    def test_limitador_41_con_anyio_real(self):
        # El control entero con el AnyIO del host y el envoltorio de lambda puesto
        # (se restaura al acabar: el módulo es global del proceso de pruebas).
        import anyio.to_thread
        contador = D.ContadorLlamadas()
        original = D.envolver_run_sync(anyio.to_thread, contador)
        try:
            [(nombre, ok, detalle)] = asyncio.run(D.control_limitador_41(types.SimpleNamespace(
                contador_lambda=contador)))
        finally:
            anyio.to_thread.run_sync = original
        self.assertEqual(nombre, "limitador_41")
        self.assertTrue(ok, detalle)
        self.assertEqual(detalle, {"visto": {"prestados": 40, "en_espera": 1}, "llamadas_lambda": 41,
                                   "prestados_al_final": 0})

    @unittest.skipUnless(__import__("importlib").util.find_spec("anyio"), "anyio no instalado en el host")
    def test_limitador_41_sin_envoltorio_falla(self):
        # Control del anterior: sin el envoltorio, lambda no cuenta nada y el control falla.
        [(_, ok, detalle)] = asyncio.run(D.control_limitador_41(types.SimpleNamespace(
            contador_lambda=D.ContadorLlamadas())))
        self.assertFalse(ok)
        self.assertEqual(detalle["llamadas_lambda"], 0)

    @unittest.skipUnless(__import__("importlib").util.find_spec("anyio"), "anyio no instalado en el host")
    def test_clases_anyio_con_hilos_reales(self):
        # Un trabajador de AnyIO ocupado en una función de esta prueba es "otra";
        # cuando acaba y espera trabajo, "libre" (queue.get desde WorkerThread.run).
        import anyio
        import anyio.to_thread
        muestreador = D.Muestreador.__new__(D.Muestreador)  # sin __init__: no hace falta /proc
        soltar = threading.Event()
        vistas = {}

        def ocupado():
            soltar.wait(5)

        async def medir():
            async with anyio.create_task_group() as grupo:
                grupo.start_soon(anyio.to_thread.run_sync, ocupado)
                vistas["ocupado"] = await D.esperar_condicion(
                    lambda: r if (r := muestreador.clases_anyio())[0]["otra"] == 1 else None, 5.0)
                soltar.set()
            vistas["libre"] = await D.esperar_condicion(
                lambda: r if (r := muestreador.clases_anyio())[0]["libre"] == 1 else None, 5.0)

        asyncio.run(medir())
        self.assertIsNotNone(vistas["ocupado"])
        self.assertEqual(vistas["ocupado"][1], {"threading.py:wait": 1})
        self.assertIsNotNone(vistas["libre"])
        self.assertEqual(vistas["libre"][0]["otra"], 0)

    def test_retraso_bucle(self):
        [(nombre, ok, detalle)] = asyncio.run(D.control_retraso_bucle(None))
        self.assertEqual(nombre, "retraso_bucle")
        self.assertTrue(ok, detalle)
        self.assertGreaterEqual(detalle["retraso_s"], 0.5)

    def test_esperar_hasta_sin_bloqueo_da_retraso_pequeno(self):
        # Control del anterior: sin el time.sleep el retraso no llega a 0,5 s.
        async def medir():
            bucle = asyncio.get_running_loop()
            return await D.esperar_hasta(bucle.time() + 0.05)

        self.assertLess(asyncio.run(medir()), 0.5)

    def test_ejecutor_falso_lento(self):
        inicio = time.monotonic()
        futuro = D.EjecutorFalsoLento().submit(len, "no se llama")
        self.assertFalse(futuro.done())
        self.assertIs(futuro.result(timeout=5), False)
        self.assertGreaterEqual(time.monotonic() - inicio, 0.9)


if __name__ == "__main__":
    unittest.main()
