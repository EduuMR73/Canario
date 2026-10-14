"""Pruebas unitarias de la lógica pura de app/limitador.py: qué regla limita
cada ruta, el análisis estricto de CANARIO_LIMITES y la huella del cliente.

Lo que habla con Redis (contar, caducar, fallar cerrado) lo prueba la batería
tests/security/verificar_denuncia.py contra un Redis real.
"""
import unittest
import uuid

from app import limitador

# La configuración por defecto escrita entera: cada prueba cambia una sola cosa.
VALIDA = "denuncia=10/3600,seguimiento=60/60,mensajes=30/3600,acceso=10/300,otras=60/60,cuenta=60/60"


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
            # Sin Argon2 ni nada que adivinar: "otras" (ver app/limitador.py).
            "/v1/personal/sesiones/renovacion": "otras",
            "/v1/empresas/abc/denuncias": "denuncia",
            "/v1/empresas//denuncias": "otras",
            "/v1/empresas/a/b/denuncias": "otras",
            "/v1/empresas/abc/denuncias/": "otras",
            "/v1/personal/denuncias": "otras",
            "": "otras",
        }
        for ruta, regla in casos.items():
            with self.subTest(ruta=ruta):
                self.assertEqual(limitador.regla_de(ruta), regla)


class CargarLimites(unittest.TestCase):
    def test_sin_variable_los_de_por_defecto(self):
        limites, origen = limitador.cargar_limites({})
        self.assertEqual(origen, "por defecto")
        self.assertEqual(limitador.describir_limites(limites),
                         "acceso=10/300 cuenta=60/60 denuncia=10/3600 mensajes=30/3600 otras=60/60 seguimiento=60/60")

    def test_configurados_validos(self):
        limites, origen = limitador.cargar_limites(con("denuncia=10/3600", "denuncia=1000000/86400"))
        self.assertEqual(origen, "configurados")
        self.assertEqual(limites["denuncia"], limitador.Limite(1_000_000, 86_400))
        self.assertEqual(limites["otras"], limitador.Limite(60, 60))

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
            "repetida": ({"CANARIO_LIMITES": VALIDA + ",otras=60/60"}, "CANARIO_LIMITES: la regla otras se repite"),
            "un millon y uno": (con("otras=60/60", "otras=1000001/60"),
                                "CANARIO_LIMITES: otras supera 1000000 peticiones"),
            "ventana 7": (con("otras=60/60", "otras=60/7"), "CANARIO_LIMITES: la ventana de otras no divide el dia"),
            "ventana 86401": (con("otras=60/60", "otras=60/86401"),
                              "CANARIO_LIMITES: la ventana de otras no divide el dia"),
            "falta una": ({"CANARIO_LIMITES": VALIDA.replace(",cuenta=60/60", "")},
                          ("CANARIO_LIMITES: reglas ['acceso', 'denuncia', 'mensajes', 'otras', 'seguimiento'], "
                           "se esperan ['acceso', 'cuenta', 'denuncia', 'mensajes', 'otras', 'seguimiento']")),
            "sobra una": ({"CANARIO_LIMITES": VALIDA + ",foo=1/60"},
                          ("CANARIO_LIMITES: reglas ['acceso', 'cuenta', 'denuncia', 'foo', 'mensajes', 'otras', "
                           "'seguimiento'], se esperan ['acceso', 'cuenta', 'denuncia', 'mensajes', 'otras', "
                           "'seguimiento']")),
        }
        for motivo, (entorno, mensaje) in casos.items():
            with self.subTest(motivo=motivo):
                with self.assertRaises(limitador.ErrorConfiguracion) as error:
                    limitador.cargar_limites(entorno)
                self.assertEqual(str(error.exception), mensaje)


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


class SalDiaria(unittest.TestCase):
    def test_cambia_a_medianoche_utc(self):
        sal = limitador._Sal()
        primera = sal.del_instante(86_399)
        self.assertEqual(len(primera), 32)
        self.assertIs(sal.del_instante(0.5), primera)
        segunda = sal.del_instante(86_400)
        self.assertNotEqual(primera, segunda)
        self.assertIs(sal.del_instante(172_799), segunda)
