"""Pruebas unitarias de la lógica pura de app/limitador.py: qué regla limita
cada ruta, el análisis estricto de CANARIO_LIMITES y la huella del cliente.
De consumir_una_vez, las órdenes que manda (con un pipeline falso) y los
argumentos que rechaza antes de llegar a Redis.

Lo que habla con Redis (contar, caducar, fallar cerrado) lo prueba la batería
tests/security/verificar_denuncia.py contra un Redis real.
"""
import asyncio
import unittest
import uuid
from unittest import mock

from app import limitador

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
        with self.assertRaises(limitador.NoDisponible):
            asyncio.run(objeto.consumir_una_vez("ticket", self.JTI, 300))
