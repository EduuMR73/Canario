"""Pruebas unitarias de la lógica pura de app/limitador.py: qué regla limita
cada ruta, el análisis estricto de CANARIO_LIMITES y la huella del cliente.
De consumir_una_vez, las órdenes que manda (con un pipeline falso) y los
argumentos que rechaza antes de llegar a Redis.

Lo que habla con Redis (contar, caducar, fallar cerrado) lo prueba la batería
tests/security/verificar_denuncia.py contra un Redis real.

Del evento de "Redis no ha podido contar" (causa y espera): _causa, los tramos
de espera, texto_evento y el pool real de redis-py 8.1.0 contra un servidor
TCP local que acepta y no responde (o cierra), sin Redis ni Docker.
"""
import ast
import asyncio
import contextlib
import copy
import pathlib
import re
import tempfile
import types
import unittest
import uuid
from unittest import mock

from redis import exceptions as errores_redis
from redis.asyncio import BlockingConnectionPool, Redis

from app import limitador

ErrorConexion = errores_redis.ConnectionError

# La configuración por defecto escrita entera: cada prueba cambia una sola cosa.
VALIDA = ("denuncia=10/3600,seguimiento=60/60,mensajes=30/3600,acceso=10/300,otras=60/60,cuenta=60/60,"
          "registro=10/3600,destinatario=3/900,destinatario_dia=10/86400")


def con(cambio_viejo, cambio_nuevo):
    texto = VALIDA.replace(cambio_viejo, cambio_nuevo)
    # Sin cambio, la prueba mediría la configuración válida: fallo visible
    # (no un assert, que python -O elimina).
    if texto == VALIDA:
        raise AssertionError(f"el cambio {cambio_viejo!r} no se ha aplicado")
    return {"CANARIO_LIMITES": texto}


class ReglaDeCadaRuta(unittest.TestCase):
    def test_reglas(self):
        casos = {
            "/salud": None,
            "/salud/": "otras",
            "/v1/seguimiento": "seguimiento",
            "/v1/seguimiento/": "otras",
            "/v1/seguimiento/mensajes": "mensajes",
            "/v1/personal/sesiones": "acceso",
            "/v1/personal/activacion": "acceso",
            "/v1/personal/activacion/confirmar": "acceso",
            "/v1/personal/contrasena": "acceso",
            # Login externo (app/rutas_externo.py): todo lo que abre o cierra
            # un flujo o pide un código. La lista de proveedores, en otras.
            "/v1/personal/externo/google/inicio": "acceso",
            "/v1/personal/externo/google/vuelta": "acceso",
            "/v1/personal/sesiones/externa": "acceso",
            "/v1/personal/externo/google/vinculo/inicio": "acceso",
            "/v1/personal/externo/google/vinculo": "acceso",
            "/v1/personal/externo/proveedores": "otras",
            "/v1/personal/externo/github/vuelta": "otras",
            # Cada solicitud envía un correo: regla propia. La verificación,
            # sin correo y con un token de 256 bits, en otras.
            "/v1/personal/registro": "registro",
            "/v1/personal/registro/": "otras",
            "/v1/personal/registro/verificacion": "otras",
            # Sin Argon2 ni nada que adivinar: "otras" (ver app/limitador.py).
            "/v1/personal/sesiones/renovacion": "otras",
            "/v1/empresas/abc/denuncias": "denuncia",
            "/v1/empresas//denuncias": "otras",
            "/v1/empresas/a/b/denuncias": "otras",
            "/v1/empresas/abc/denuncias/": "otras",
            "/v1/personal/denuncias": "otras",
            "": "otras",
            # Páginas del denunciante (app/rutas_web.py): cada acción con la
            # regla de su ruta de /v1; los formularios (GET), en otras.
            "/web/": "otras",
            "/web/empresas/abc": "otras",
            "/web/empresas/abc/denuncias": "denuncia",
            "/web/empresas/a/b/denuncias": "otras",
            "/web/seguimiento": "otras",
            "/web/seguimiento/consulta": "seguimiento",
            "/web/seguimiento/consulta/": "otras",
            "/web/seguimiento/mensajes": "mensajes",
            "/web/v1/seguimiento": "otras",
        }
        for ruta, regla in casos.items():
            with self.subTest(ruta=ruta):
                self.assertEqual(limitador.regla_de(ruta), regla)


class CargarLimites(unittest.TestCase):
    def test_sin_variable_los_de_por_defecto(self):
        limites, origen = limitador.cargar_limites({})
        self.assertEqual(origen, "por defecto")
        self.assertEqual(limitador.describir_limites(limites),
                         "acceso=10/300 cuenta=60/60 denuncia=10/3600 destinatario=3/900 "
                         "destinatario_dia=10/86400 mensajes=30/3600 otras=60/60 registro=10/3600 seguimiento=60/60")

    def test_configurados_validos(self):
        limites, origen = limitador.cargar_limites(con("denuncia=10/3600", "denuncia=1000000/86400"))
        self.assertEqual(origen, "configurados")
        self.assertEqual(limites["denuncia"], limitador.Limite(1_000_000, 86_400))
        self.assertEqual(limites["otras"], limitador.Limite(60, 60))
        # Un nombre con guion bajo es válido.
        self.assertEqual(limites["destinatario_dia"], limitador.Limite(10, 86_400))

    def test_no_muta_los_de_por_defecto(self):
        limites, _ = limitador.cargar_limites({})
        limites["denuncia"] = limitador.Limite(1, 1)
        self.assertEqual(limitador.LIMITES_POR_DEFECTO["denuncia"], limitador.Limite(10, 3600))

    def test_errores(self):
        casos = {
            "vacia": ({"CANARIO_LIMITES": ""}, "CANARIO_LIMITES: elemento mal formado"),
            "espacio": (con(",seguimiento", ", seguimiento"), "CANARIO_LIMITES: elemento mal formado"),
            "coma final": ({"CANARIO_LIMITES": VALIDA + ","}, "CANARIO_LIMITES: elemento mal formado"),
            "mayusculas": (con("otras=", "Otras="), "CANARIO_LIMITES: elemento mal formado"),
            "cero a la izquierda": (con("otras=60/60", "otras=060/60"), "CANARIO_LIMITES: elemento mal formado"),
            "cero peticiones": (con("otras=60/60", "otras=0/60"), "CANARIO_LIMITES: elemento mal formado"),
            "ocho digitos": (con("otras=60/60", "otras=10000000/60"), "CANARIO_LIMITES: elemento mal formado"),
            "guion bajo al principio": (con("otras=", "_otras="), "CANARIO_LIMITES: elemento mal formado"),
            "guion bajo al final": (con("otras=", "otras_="), "CANARIO_LIMITES: elemento mal formado"),
            "dos guiones bajos": (con("destinatario_dia=", "destinatario__dia="),
                                  "CANARIO_LIMITES: elemento mal formado"),
            "repetida": ({"CANARIO_LIMITES": VALIDA + ",otras=60/60"}, "CANARIO_LIMITES: la regla otras se repite"),
            "un millon y uno": (con("otras=60/60", "otras=1000001/60"),
                                "CANARIO_LIMITES: otras supera 1000000 peticiones"),
            "ventana 7": (con("otras=60/60", "otras=60/7"), "CANARIO_LIMITES: la ventana de otras no divide el dia"),
            "ventana 86401": (con("otras=60/60", "otras=60/86401"),
                              "CANARIO_LIMITES: la ventana de otras no divide el dia"),
            "falta una": ({"CANARIO_LIMITES": VALIDA.replace(",cuenta=60/60", "")},
                          ("CANARIO_LIMITES: reglas ['acceso', 'denuncia', 'destinatario', 'destinatario_dia', "
                           "'mensajes', 'otras', 'registro', 'seguimiento'], se esperan ['acceso', 'cuenta', "
                           "'denuncia', 'destinatario', 'destinatario_dia', 'mensajes', 'otras', 'registro', "
                           "'seguimiento']")),
            "sobra una": ({"CANARIO_LIMITES": VALIDA + ",foo=1/60"},
                          ("CANARIO_LIMITES: reglas ['acceso', 'cuenta', 'denuncia', 'destinatario', "
                           "'destinatario_dia', 'foo', 'mensajes', 'otras', 'registro', 'seguimiento'], se esperan "
                           "['acceso', 'cuenta', 'denuncia', 'destinatario', 'destinatario_dia', 'mensajes', 'otras', "
                           "'registro', 'seguimiento']")),
        }
        for motivo, (entorno, mensaje) in casos.items():
            with self.subTest(motivo=motivo):
                with self.assertRaises(limitador.ErrorConfiguracion) as error:
                    limitador.cargar_limites(entorno)
                self.assertEqual(str(error.exception), mensaje)


class DecidirVariasReglas(unittest.TestCase):
    """decidir: las dos reglas del destinatario contadas a la vez."""
    QUINCE = limitador.Limite(3, 900)
    DIA = limitador.Limite(10, 86_400)

    def test_en_el_limite_se_permite(self):
        self.assertEqual(limitador.decidir([("destinatario", 3, self.QUINCE, 100),
                                            ("destinatario_dia", 10, self.DIA, 5000)]),
                         (True, 0, ()))

    def test_basta_con_superar_una(self):
        self.assertEqual(limitador.decidir([("destinatario", 2, self.QUINCE, 100),
                                            ("destinatario_dia", 11, self.DIA, 5000)]),
                         (False, 5000, ("destinatario_dia",)))
        self.assertEqual(limitador.decidir([("destinatario", 4, self.QUINCE, 100),
                                            ("destinatario_dia", 4, self.DIA, 5000)]),
                         (False, 100, ("destinatario",)))

    def test_retry_after_el_mayor_y_un_solo_primer_exceso(self):
        # Las dos superadas: el mayor de los segundos, aunque la del día
        # vaya primero o segunda; y solo la que acaba de pasar de su límite
        # cuenta como primer exceso.
        self.assertEqual(limitador.decidir([("destinatario", 5, self.QUINCE, 100),
                                            ("destinatario_dia", 11, self.DIA, 5000)]),
                         (False, 5000, ("destinatario_dia",)))
        self.assertEqual(limitador.decidir([("destinatario_dia", 12, self.DIA, 50),
                                            ("destinatario", 4, self.QUINCE, 800)]),
                         (False, 800, ("destinatario",)))


class HuellaDelCliente(unittest.TestCase):
    SAL = bytes(32)

    def test_vector_literal(self):
        # HMAC-SHA256(sal, b"canario/limite/v1" + b"\x04" + 192.0.2.1), 32
        # primeros hexadecimales, calculado aparte.
        self.assertEqual(limitador.huella_cliente(self.SAL, "192.0.2.1"), "f4e862be5c01853fa32672841176e088")

    def test_ipv4_mapeada_es_la_misma_ipv4(self):
        self.assertEqual(limitador.huella_cliente(self.SAL, "::ffff:192.0.2.1"),
                         limitador.huella_cliente(self.SAL, "192.0.2.1"))

    def test_ipv6_por_bloque_64(self):
        misma = limitador.huella_cliente(self.SAL, "2001:db8:1:2::1")
        self.assertEqual(misma, limitador.huella_cliente(self.SAL, "2001:db8:1:2:ffff:ffff:ffff:ffff"))
        self.assertNotEqual(misma, limitador.huella_cliente(self.SAL, "2001:db8:1:3::1"))

    def test_otra_sal_otra_huella(self):
        self.assertNotEqual(limitador.huella_cliente(self.SAL, "192.0.2.1"),
                            limitador.huella_cliente(b"\x01" * 32, "192.0.2.1"))

    def test_direccion_que_no_es_ip(self):
        for malo in ("hola", "", "999.1.1.1", "192.0.2.1 "):
            with self.subTest(malo=malo), self.assertRaises(ValueError):
                limitador.huella_cliente(self.SAL, malo)

    def test_cuenta_y_cliente_nunca_comparten_huella(self):
        empresa, usuario = uuid.UUID(int=1), uuid.UUID(int=2)
        cuenta = limitador.huella_cuenta(self.SAL, empresa, usuario)
        self.assertRegex(cuenta, r"\A[0-9a-f]{32}\Z")
        self.assertNotEqual(cuenta, limitador.huella_cuenta(self.SAL, empresa, uuid.UUID(int=3)))
        self.assertNotEqual(cuenta, limitador.huella_cliente(self.SAL, "192.0.2.1"))

    def test_destinatario_vector_literal(self):
        # HMAC-SHA256(sal, b"canario/limite/destinatario/v1" + email), 32
        # primeros hexadecimales, calculado aparte. El email nunca va en claro.
        self.assertEqual(limitador.huella_destinatario(self.SAL, "persona@empresa.es"),
                         "1f71e98e27f9c5c77bce307c4e1855ce")
        self.assertNotEqual(limitador.huella_destinatario(self.SAL, "otra@empresa.es"),
                            limitador.huella_destinatario(self.SAL, "persona@empresa.es"))


class SalDiaria(unittest.TestCase):
    def test_cambia_a_medianoche_utc(self):
        sal = limitador._Sal()
        primera = sal.del_instante(86_399)
        self.assertEqual(len(primera), 32)
        self.assertIs(sal.del_instante(0.5), primera)
        segunda = sal.del_instante(86_400)
        self.assertNotEqual(primera, segunda)
        self.assertIs(sal.del_instante(172_799), segunda)


class TuboFalso:
    """Pipeline de redis-py con transacción: apunta las órdenes y devuelve un
    resultado fijo al ejecutar."""

    def __init__(self, resultado):
        self.resultado = resultado
        self.ordenes = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    def execute_command(self, *orden):
        self.ordenes.append(orden)

    async def execute(self):
        return self.resultado


class ConsumirUnaVez(unittest.TestCase):
    JTI = "0123456789abcdef0123456789abcdef"

    def consumir(self, resultado, espacio="ticket", identificador=JTI, segundos=300):
        tubo = TuboFalso(resultado)
        cliente = mock.Mock()
        cliente.pipeline.return_value = tubo
        objeto = limitador.Limitador.__new__(limitador.Limitador)
        objeto._cliente = cliente
        devuelto = asyncio.run(objeto.consumir_una_vez(espacio, identificador, segundos))
        return devuelto, tubo.ordenes, cliente.pipeline.call_args

    def test_solo_la_primera_vez(self):
        # INCR devuelve 1 la primera vez; 2 o más, una repetición.
        primera, ordenes, llamada = self.consumir([1, True])
        self.assertIs(primera, True)
        self.assertEqual(ordenes, [("INCR", f"limite:ticket:{self.JTI}"),
                                   ("EXPIRE", f"limite:ticket:{self.JTI}", 300, "NX")])
        self.assertEqual(llamada, mock.call(transaction=True))
        self.assertIs(self.consumir([2, False])[0], False)
        self.assertIs(self.consumir([7, False])[0], False)

    def test_argumentos_no_validos_no_llegan_a_redis(self):
        self.assertIs(self.consumir([1, True], segundos=3600)[0], True)  # control
        self.assertIs(self.consumir([1, True], espacio="flujo")[0], True)  # control: el del flujo externo
        for nombre, cambios in {"espacio fuera de la lista": {"espacio": "acceso"},
                                "identificador con mayusculas": {"identificador": self.JTI.upper()},
                                "identificador con dos puntos": {"identificador": self.JTI[:-1] + ":"},
                                "segundos cero": {"segundos": 0}, "segundos de mas": {"segundos": 3601},
                                "segundos bool": {"segundos": True}}.items():
            with self.subTest(nombre), self.assertRaises(ValueError):
                self.consumir([1, True], **cambios)

    def test_espacios_que_no_chocan_con_las_reglas(self):
        # Las claves de las reglas son limite:<regla>:...: un espacio con el
        # nombre de una regla compartiría sus claves.
        self.assertEqual(limitador.ESPACIOS_UNA_VEZ, ("ticket", "flujo"))
        self.assertEqual(set(limitador.ESPACIOS_UNA_VEZ) & set(limitador.LIMITES_POR_DEFECTO), set())
        self.assertEqual(set(limitador.ESPACIOS_UNA_VEZ) & {"arranque"}, set())

    def test_redis_que_falla_es_no_disponible(self):
        cliente = mock.Mock()
        cliente.pipeline.side_effect = limitador.RedisError("caido")
        objeto = limitador.Limitador.__new__(limitador.Limitador)
        objeto._cliente = cliente
        with self.assertRaises(limitador.NoDisponible) as capturada:
            asyncio.run(objeto.consumir_una_vez("ticket", self.JTI, 300))
        # RedisError a secas no es ni conexión ni plazo ni permiso: "otra".
        self.assertEqual((capturada.exception.clase, capturada.exception.causa), ("RedisError", "otra"))
        self.assertIn(capturada.exception.espera, ("<0.25", "0.25-0.5", ">0.5"))


# ---------------------------------------------------------------------------
# Causa y espera del evento de "Redis no ha podido contar"
# ---------------------------------------------------------------------------
HUELLA = "0123456789abcdef0123456789abcdef"
# Tope de cada prueba con sockets: si algo se cuelga, falla (visible) y no
# bloquea la batería.
TOPE_SEGUNDOS = 5


def con_causa(clase, args, causa):
    """Excepción de redis-py con su __cause__, como la deja un raise ... from."""
    error = clase(*args)
    error.__cause__ = causa
    return error


def pool_agotado():
    """El error que da BlockingConnectionPool.get_connection al vencer su
    plazo: ConnectionError("No connection available.") from TimeoutError
    (redis/asyncio/connection.py:3099 de redis-py 8.1.0)."""
    return con_causa(ErrorConexion, ("No connection available.",), TimeoutError())


def no_permission_del_multi():
    """NoPermissionError como lo deja la anotación del pipeline.

    Hecho VERIFICADO LEYENDO EL CÓDIGO de redis-py 8.1.0, no probado en
    ejecución (ninguna batería provoca NOPERM): redis/asyncio/client.py:2057
    y :2151 llaman a annotate_exception (definida en :2154-2162), que solo
    cambia exception.args por "Command # n (<orden y clave>) of pipeline
    caused error: <args originales>"; después se relanza la MISMA excepción
    (:2065 y :2152): la clase se conserva, y el mensaje lleva la clave con la
    huella del cliente. Aquí se construye el resultado a mano."""
    originales = ("this user has no permissions to run the 'incr' command",)
    error = errores_redis.NoPermissionError(*originales)
    error.args = (f"Command # 1 (INCR limite:acceso:19000:{HUELLA}) of pipeline caused error: {originales}",)
    return error


def limitador_que_falla(error):
    """Limitador cuyo cliente de Redis lanza error al abrir el pipeline."""
    objeto = limitador.Limitador.__new__(limitador.Limitador)
    objeto.limites = dict(limitador.LIMITES_POR_DEFECTO)
    objeto._sal = limitador._Sal()
    cliente = mock.Mock()
    cliente.pipeline.side_effect = error
    objeto._cliente = cliente
    return objeto


def reloj(*valores):
    """(sustituto del módulo time de limitador, lista de llamadas). Solo se
    sustituye el nombre time DENTRO de app/limitador: asyncio usa su propio
    time.monotonic y no se entera."""
    pendientes = iter(valores)
    llamadas = []

    def monotonic():
        llamadas.append(None)
        return next(pendientes)
    return types.SimpleNamespace(monotonic=monotonic, time=lambda: 100.0), llamadas


class CausaDelError(unittest.TestCase):
    def test_conjuntos_cerrados_literales(self):
        self.assertEqual(limitador.CAUSAS, ("pool_agotado", "permiso", "plazo", "conexion", "otra"))
        self.assertEqual(limitador.ESPERAS, ("<0.25", "0.25-0.5", ">0.5"))

    def test_tabla_un_literal_por_fila(self):
        casos = {
            "pool agotado": (pool_agotado(), "pool_agotado"),
            "AuthenticationError": (errores_redis.AuthenticationError("clave"), "permiso"),
            "AuthorizationError": (errores_redis.AuthorizationError("acl"), "permiso"),
            "NoPermissionError": (errores_redis.NoPermissionError("noperm"), "permiso"),
            "NoPermissionError anotado desde el MULTI": (no_permission_del_multi(), "permiso"),
            "TimeoutError de redis": (errores_redis.TimeoutError("plazo"), "plazo"),
            "TimeoutError del lenguaje": (TimeoutError("plazo"), "plazo"),
            "ConnectionError": (ErrorConexion("caido"), "conexion"),
            "BusyLoadingError": (errores_redis.BusyLoadingError("cargando"), "conexion"),
            "MaxConnectionsError": (errores_redis.MaxConnectionsError("tope"), "conexion"),
            "OSError": (OSError("red"), "conexion"),
            "ConnectionResetError": (ConnectionResetError("reinicio"), "conexion"),
            "ResponseError": (errores_redis.ResponseError("OOM command not allowed"), "otra"),
            "OutOfMemoryError": (errores_redis.OutOfMemoryError("sin memoria"), "otra"),
            "RedisError": (errores_redis.RedisError("generico"), "otra"),
            "algo que no es de redis": (ValueError("otro"), "otra"),
        }
        for nombre, (error, esperada) in casos.items():
            with self.subTest(nombre):
                self.assertEqual(limitador._causa(error), esperada)
        # Control: la tabla ejerce las cinco causas; una fila menos dejaría una sin probar.
        self.assertEqual({esperada for _, esperada in casos.values()},
                         {"pool_agotado", "permiso", "plazo", "conexion", "otra"})

    def test_pool_agotado_solo_con_la_forma_exacta(self):
        class Hija(ErrorConexion):
            pass

        mensaje = ("No connection available.",)
        # Control positivo (el gemelo de cada fila de abajo): la forma exacta.
        self.assertEqual(limitador._causa(con_causa(ErrorConexion, mensaje, TimeoutError())), "pool_agotado")
        self.assertEqual(limitador._causa(ErrorConexion(*mensaje)), "conexion")
        casos = {
            "sin __cause__": (con_causa(ErrorConexion, mensaje, None), "conexion"),
            "__cause__ de otro tipo": (con_causa(ErrorConexion, mensaje, OSError()), "conexion"),
            "__cause__ TimeoutError de redis": (con_causa(ErrorConexion, mensaje, errores_redis.TimeoutError()),
                                                "conexion"),
            "subclase con el mismo args y __cause__": (con_causa(Hija, mensaje, TimeoutError()), "conexion"),
            "BusyLoadingError con el mismo args y __cause__": (
                con_causa(errores_redis.BusyLoadingError, mensaje, TimeoutError()), "conexion"),
            "AuthenticationError con el mismo args y __cause__": (
                con_causa(errores_redis.AuthenticationError, mensaje, TimeoutError()), "permiso"),
            "otro texto": (con_causa(ErrorConexion, ("No connection available",), TimeoutError()), "conexion"),
            "texto en bytes": (con_causa(ErrorConexion, (b"No connection available.",), TimeoutError()),
                               "conexion"),
            "dos args": (con_causa(ErrorConexion, mensaje + ("x",), TimeoutError()), "conexion"),
            "sin args": (con_causa(ErrorConexion, (), TimeoutError()), "conexion"),
        }
        for nombre, (error, esperada) in casos.items():
            with self.subTest(nombre):
                self.assertEqual(limitador._causa(error), esperada)

    def test_robustez_nunca_lanza(self):
        class StrQueLanza(ErrorConexion):
            def __str__(self):
                raise RuntimeError("str lanza")

        class OtraStrQueLanza(Exception):
            def __str__(self):
                raise RuntimeError("str lanza")

        class ClaseQueLanza(Exception):
            @property
            def __class__(self):
                raise RuntimeError("__class__ lanza")

        raro = ClaseQueLanza()
        # Control: este objeto SÍ hace lanzar a un isinstance directo; sin el
        # try de _causa, la prueba de abajo no pasaría. Si no lanza, no mide nada.
        with self.assertRaises(RuntimeError, msg="SIN CONCLUSION: el objeto raro no lanza en isinstance"):
            isinstance(raro, OSError)
        casos = {
            "ConnectionError con __str__ que lanza": (StrQueLanza("x"), "conexion"),
            "Exception con __str__ que lanza": (OtraStrQueLanza("x"), "otra"),
            "__class__ que lanza": (raro, "otra"),
            "None": (None, "otra"),
            "un objeto cualquiera": (object(), "otra"),
            "un texto": ("ConnectionError", "otra"),
            "un entero": (7, "otra"),
        }
        for nombre, (error, esperada) in casos.items():
            with self.subTest(nombre):
                self.assertEqual(limitador._causa(error), esperada)


class EsperaDelFallo(unittest.TestCase):
    # Bordes literales: 0,25 y 0,5 pertenecen al tramo central.
    BORDES = {0.249: "<0.25", 0.25: "0.25-0.5", 0.5: "0.25-0.5", 0.501: ">0.5"}

    def comprobar(self, lanzar):
        for borde, tramo in self.BORDES.items():
            # monotonic: entrada (0.0) y fallo (borde). Dos llamadas exactas.
            sustituto, llamadas = reloj(0.0, borde)
            with self.subTest(borde=borde), mock.patch.object(limitador, "time", sustituto):
                with self.assertRaises(limitador.NoDisponible) as capturada:
                    lanzar()
                self.assertEqual(capturada.exception.espera, tramo)
                self.assertEqual(len(llamadas), 2)

    def test_bordes_en_contar_varias(self):
        objeto = limitador_que_falla(ErrorConexion("caido"))
        self.comprobar(lambda: asyncio.run(objeto._contar_varias(("otras",), HUELLA, 100)))

    def test_bordes_en_consumir_una_vez(self):
        objeto = limitador_que_falla(ErrorConexion("caido"))
        self.comprobar(lambda: asyncio.run(objeto.consumir_una_vez("ticket", "0123456789abcdef0123456789abcdef", 300)))


class CaminoRealDeLimitador(unittest.TestCase):
    ERRORES = {
        "ConnectionError": (ErrorConexion("caido"), "ConnectionError", "conexion"),
        "TimeoutError de redis": (errores_redis.TimeoutError("lento"), "TimeoutError", "plazo"),
        "BusyLoadingError": (errores_redis.BusyLoadingError("cargando"), "BusyLoadingError", "conexion"),
        "AuthenticationError": (errores_redis.AuthenticationError("clave"), "AuthenticationError", "permiso"),
        "NoPermissionError": (errores_redis.NoPermissionError("noperm"), "NoPermissionError", "permiso"),
        "ResponseError": (errores_redis.ResponseError("OOM"), "ResponseError", "otra"),
        "OSError": (OSError("red"), "OSError", "conexion"),
        "pool agotado": (pool_agotado(), "ConnectionError", "pool_agotado"),
    }

    def test_contar_varias_y_consumir_lanzan_no_disponible_completo(self):
        for nombre, (error, clase, causa) in self.ERRORES.items():
            objeto = limitador_que_falla(error)
            for via, lanzar in {
                "_contar_varias": lambda objeto=objeto: objeto._contar_varias(("otras",), HUELLA, 100),
                "consumir": lambda objeto=objeto: objeto.consumir("otras", "192.0.2.1", 100),
                "consumir_destinatario": lambda objeto=objeto: objeto.consumir_destinatario("a@b.es", 100),
            }.items():
                sustituto, _ = reloj(0.0, 0.1)
                with self.subTest(nombre, via=via), mock.patch.object(limitador, "time", sustituto):
                    with self.assertRaises(limitador.NoDisponible) as capturada:
                        asyncio.run(lanzar())
                    self.assertEqual((capturada.exception.clase, capturada.exception.causa,
                                      capturada.exception.espera), (clase, causa, "<0.25"))

    def test_consumir_una_vez_lanza_no_disponible_completo(self):
        for nombre, (error, clase, causa) in self.ERRORES.items():
            sustituto, _ = reloj(0.0, 0.3)
            with self.subTest(nombre), mock.patch.object(limitador, "time", sustituto):
                with self.assertRaises(limitador.NoDisponible) as capturada:
                    asyncio.run(limitador_que_falla(error).consumir_una_vez(
                        "flujo", "0123456789abcdef0123456789abcdef", 600))
                self.assertEqual((capturada.exception.clase, capturada.exception.causa,
                                  capturada.exception.espera), (clase, causa, "0.25-0.5"))


class EventoSinDatos(unittest.TestCase):
    # La línea entera, con su forma (A-Za-z en la clase, dos conjuntos cerrados).
    PATRON = re.compile(r"EVENTO limitador_no_disponible: [A-Za-z]+ "
                        r"causa=(pool_agotado|permiso|plazo|conexion|otra) espera=(<0\.25|0\.25-0\.5|>0\.5)")
    # Nada de esto puede salir en el evento: ni el puerto, ni el host, ni el
    # usuario de Redis, ni el prefijo de las claves.
    PROHIBIDO = ("6379", "redis:", "aplicacion", "limite:")

    def test_texto_literal_y_formato(self):
        self.assertEqual(
            limitador.texto_evento(limitador.NoDisponible("ConnectionError", "conexion", "0.25-0.5")),
            "EVENTO limitador_no_disponible: ConnectionError causa=conexion espera=0.25-0.5")
        # Control: la expresión acepta toda combinación de los conjuntos...
        for causa in ("pool_agotado", "permiso", "plazo", "conexion", "otra"):
            for espera in ("<0.25", "0.25-0.5", ">0.5"):
                with self.subTest(causa=causa, espera=espera):
                    texto = limitador.texto_evento(limitador.NoDisponible("TimeoutError", causa, espera))
                    self.assertIsNotNone(self.PATRON.fullmatch(texto))
        # ...y rechaza lo que no es de ellos.
        for malo in ("EVENTO limitador_no_disponible: TimeoutError causa=inventada espera=<0.25",
                     "EVENTO limitador_no_disponible: TimeoutError causa=plazo espera=1.5",
                     "EVENTO limitador_no_disponible: TimeoutError causa=plazo espera=<0.25 10.9.8.7:6379"):
            with self.subTest(malo=malo):
                self.assertIsNone(self.PATRON.fullmatch(malo))

    def test_los_tres_datos_son_obligatorios(self):
        for argumentos in ((), ("ConnectionError",), ("ConnectionError", "conexion")):
            with self.subTest(argumentos=argumentos), self.assertRaises(TypeError):
                limitador.NoDisponible(*argumentos)
        # Sin validación: no puede lanzar en el camino de error, ni con valores fuera de los conjuntos.
        error = limitador.NoDisponible("X", "inventada", "raro")
        self.assertEqual((error.clase, error.causa, error.espera), ("X", "inventada", "raro"))
        # copy reconstruye con args: los tres tienen que estar en él.
        copia = copy.copy(limitador.NoDisponible("ConnectionError", "conexion", "<0.25"))
        self.assertEqual((copia.clase, copia.causa, copia.espera), ("ConnectionError", "conexion", "<0.25"))

    def fallar_y_formatear(self, error):
        sustituto, _ = reloj(0.0, 0.1)
        with mock.patch.object(limitador, "time", sustituto):
            with self.assertRaises(limitador.NoDisponible) as capturada:
                asyncio.run(limitador_que_falla(error)._contar_varias(("otras",), HUELLA, 100))
        return limitador.texto_evento(capturada.exception)

    def test_centinela_de_conexion(self):
        centinela = "10.9.8.7:6379"
        error = ErrorConexion(f"Error 111 connecting to {centinela}. Connection refused.")
        # Control positivo: el centinela SÍ está en el mensaje de la excepción
        # (si no, el que no esté en el evento no probaría nada).
        self.assertIn(centinela, str(error), "SIN CONCLUSION: el centinela no está en str(error)")
        texto = self.fallar_y_formatear(error)
        self.assertEqual(texto, "EVENTO limitador_no_disponible: ConnectionError causa=conexion espera=<0.25")
        for prohibido in (centinela, "10.9.8.7") + self.PROHIBIDO:
            with self.subTest(prohibido=prohibido):
                self.assertNotIn(prohibido, texto)

    def test_centinela_de_permiso_desde_el_multi(self):
        error = no_permission_del_multi()
        # Control positivo: la clave con la huella SÍ está en el mensaje.
        self.assertIn("limite:", str(error), "SIN CONCLUSION: 'limite:' no está en str(error)")
        self.assertIn(HUELLA, str(error), "SIN CONCLUSION: la huella no está en str(error)")
        texto = self.fallar_y_formatear(error)
        self.assertEqual(texto, "EVENTO limitador_no_disponible: NoPermissionError causa=permiso espera=<0.25")
        for prohibido in (HUELLA,) + self.PROHIBIDO:
            with self.subTest(prohibido=prohibido):
                self.assertNotIn(prohibido, texto)

    def test_el_literal_solo_esta_en_texto_evento(self):
        carpeta = pathlib.Path(limitador.__file__).resolve().parent
        ficheros = sorted(carpeta.rglob("*.py"))
        textos = {fichero: fichero.read_text(encoding="utf-8") for fichero in ficheros}
        # Control positivo: el recorrido lee los ficheros de app/ y encuentra
        # el otro evento del limitador una vez.
        self.assertGreater(len(textos), 10, "SIN CONCLUSION: el recorrido no ve app/")
        self.assertEqual(sum(t.count("EVENTO limitador_cliente_invalido") for t in textos.values()), 1,
                         "SIN CONCLUSION: el recorrido no encuentra el otro evento")
        literal = "EVENTO limitador_no_disponible"
        encontrados = [(fichero.name, texto.count("\n", 0, encaje.start()) + 1)
                       for fichero, texto in textos.items() for encaje in re.finditer(re.escape(literal), texto)]
        self.assertEqual(len(encontrados), 1, f"el literal sale {len(encontrados)} veces: {encontrados}")
        nombre, linea = encontrados[0]
        self.assertEqual(nombre, "limitador.py")
        arbol = ast.parse(textos[carpeta / "limitador.py"])
        funcion = next(n for n in ast.walk(arbol) if isinstance(n, ast.FunctionDef) and n.name == "texto_evento")
        self.assertTrue(funcion.lineno <= linea <= funcion.end_lineno,
                        f"el literal está en la línea {linea}, fuera de texto_evento ({funcion.lineno})")


# Contraseña con el formato del secreto (64 caracteres de PATRON_CONTRASENA):
# no es ningún secreto. FICHERO_CONTRASENA se redirige a un fichero temporal
# con ella; nunca se abre secrets/.
CONTRASENA_FALSA = "0123456789abcdef" * 4


@contextlib.asynccontextmanager
async def servidor_falso(atender):
    """Servidor TCP en 127.0.0.1 y un puerto libre. Da el puerto."""
    servidor = await asyncio.start_server(atender, "127.0.0.1", 0)
    try:
        yield servidor.sockets[0].getsockname()[1]
    finally:
        servidor.close()
        await servidor.wait_closed()


def acepta_y_calla(aceptada):
    """Manejador que acepta, avisa con el Event y no responde nunca: lee hasta
    que el cliente cierra."""
    async def atender(lector, escritor):
        aceptada.set()
        try:
            await lector.read()
        except OSError:
            pass  # el cliente cierra a la fuerza (Windows): es lo esperado
        finally:
            escritor.close()
    return atender


def acepta_y_cierra(aceptada):
    """Manejador que acepta, avisa con el Event y cierra al instante."""
    async def atender(_lector, escritor):
        aceptada.set()
        escritor.close()
        with contextlib.suppress(OSError):
            await escritor.wait_closed()
    return atender


async def capturar(esperable):
    """El NoDisponible que lanza lo esperado, o None si no lanza."""
    try:
        await esperable
    except limitador.NoDisponible as error:
        return error
    return None


class CausasConRedisPyReal(unittest.TestCase):
    """El pool y las conexiones REALES de redis-py 8.1.0 contra un servidor
    local, sin Redis. Cada prueba, dentro de asyncio.wait_for con tope."""

    def setUp(self):
        carpeta = tempfile.TemporaryDirectory()
        self.addCleanup(carpeta.cleanup)
        fichero = pathlib.Path(carpeta.name) / "contrasena_redis"
        fichero.write_text(CONTRASENA_FALSA, encoding="ascii", newline="")
        for nombre, valor in (("FICHERO_CONTRASENA", fichero), ("HOST", "127.0.0.1")):
            parche = mock.patch.object(limitador, nombre, valor)
            parche.start()
            self.addCleanup(parche.stop)

    def correr(self, corutina):
        return asyncio.run(asyncio.wait_for(corutina, TOPE_SEGUNDOS))

    def test_a_pool_agotado_con_el_pool_real(self):
        # Un solo pool de una conexión, con socket_timeout de 1 s (lo comparten
        # todas sus conexiones) y 0,05 s de espera por una libre. La tarea A
        # pide contar: toma la única conexión y se queda en el apretón de manos
        # (AUTH), porque el servidor acepta y no responde. Cuando el servidor
        # avisa de que aceptó, A tiene la conexión. B arranca entonces: el pool
        # está lleno y B falla al cabo de 0,05 s con "No connection available."
        # (pool_agotado). Determinista: el orden lo fija el Event, no el
        # tiempo, y no hay sleeps. Si una versión de redis-py cambia esa
        # cadena, esta prueba deja de dar pool_agotado y falla (no hace falta
        # una guarda de versión aparte).
        async def escenario():
            aceptada = asyncio.Event()
            async with servidor_falso(acepta_y_calla(aceptada)) as puerto:
                opciones = {**limitador._opciones_conexion(), "host": "127.0.0.1", "port": puerto,
                            "socket_timeout": 1, "socket_connect_timeout": 1}
                objeto = limitador.Limitador.__new__(limitador.Limitador)
                objeto.limites = dict(limitador.LIMITES_POR_DEFECTO)
                objeto._sal = limitador._Sal()
                objeto._cliente = Redis(connection_pool=BlockingConnectionPool(
                    max_connections=1, timeout=0.05, credential_provider=limitador._Credenciales(), **opciones))
                tarea_a = espera_evento = None
                try:
                    tarea_a = asyncio.ensure_future(objeto._contar_varias(("otras",), HUELLA, 100))
                    espera_evento = asyncio.ensure_future(aceptada.wait())
                    await asyncio.wait({tarea_a, espera_evento}, return_when=asyncio.FIRST_COMPLETED)
                    if not aceptada.is_set():
                        raise AssertionError(f"SIN CONCLUSION: A termino sin que el servidor aceptara: {tarea_a}")
                    fallo_b = await capturar(objeto._contar_varias(("otras",), HUELLA, 100))
                    fallo_a = await capturar(tarea_a)
                finally:
                    # Un fallo a mitad no deja tareas vivas ni "Task exception
                    # was never retrieved": se cancela lo que siga en marcha y
                    # se espera a todas (gather recoge también sus excepciones).
                    tareas = [tarea for tarea in (tarea_a, espera_evento) if tarea is not None]
                    for tarea in tareas:
                        tarea.cancel()
                    await asyncio.gather(*tareas, return_exceptions=True)
                    await objeto.cerrar()
            return fallo_b, fallo_a

        fallo_b, fallo_a = self.correr(escenario())
        # Primero el control positivo: la propia tarea A, al vencer su segundo,
        # falla con "plazo". Sin él, "pool_agotado" podría ser un fallo de otra cosa.
        self.assertIsNotNone(fallo_a, "SIN CONCLUSION: A no ha fallado")
        self.assertEqual(fallo_a.causa, "plazo", "SIN CONCLUSION: el control de A no es plazo")
        # Después el oráculo: B, con el pool lleno.
        self.assertIsNotNone(fallo_b)
        self.assertEqual((fallo_b.clase, fallo_b.causa), ("ConnectionError", "pool_agotado"))
        self.assertIn(fallo_b.espera, ("<0.25", "0.25-0.5", ">0.5"))

    def test_b_servidor_que_no_contesta_es_plazo(self):
        async def escenario():
            aceptada = asyncio.Event()
            async with servidor_falso(acepta_y_calla(aceptada)) as puerto:
                with mock.patch.object(limitador, "PUERTO", puerto):
                    objeto = limitador.Limitador(dict(limitador.LIMITES_POR_DEFECTO))
                try:
                    fallo = await capturar(objeto._contar_varias(("otras",), HUELLA, 100))
                finally:
                    await objeto.cerrar()
            return fallo, aceptada.is_set()

        fallo, acepto = self.correr(escenario())
        # Control: el servidor aceptó, así que el plazo fue al leer, no al conectar.
        self.assertTrue(acepto, "SIN CONCLUSION: el servidor no recibió la conexión")
        self.assertIsNotNone(fallo)
        self.assertEqual(fallo.causa, "plazo")

    def test_c_servidor_que_cierra_es_conexion(self):
        # No un puerto cerrado: en Windows tarda ~2 s en rechazar y acabaría en plazo.
        async def escenario():
            aceptada = asyncio.Event()
            async with servidor_falso(acepta_y_cierra(aceptada)) as puerto:
                with mock.patch.object(limitador, "PUERTO", puerto):
                    objeto = limitador.Limitador(dict(limitador.LIMITES_POR_DEFECTO))
                try:
                    fallo = await capturar(objeto._contar_varias(("otras",), HUELLA, 100))
                finally:
                    await objeto.cerrar()
            return fallo, aceptada.is_set()

        fallo, acepto = self.correr(escenario())
        self.assertTrue(acepto, "SIN CONCLUSION: el servidor no recibió la conexión")
        self.assertIsNotNone(fallo)
        self.assertEqual(fallo.causa, "conexion")
