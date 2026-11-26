"""Pruebas de las funciones puras de tests/estres/lanzar.py (sin Docker):

    python -m unittest tests/estres/test_lanzar.py

Cada oráculo es un literal escrito aquí, no derivado de las constantes del
lanzador que se prueba (160 MiB = 167772160, 19456 KiB, 2 hashes, 256 MiB =
268435456, 64 MiB = 67108864). Cada comprobación negativa lleva su control
positivo en la misma prueba: si el positivo falla, la prueba falla (el
resultado sería SIN CONCLUSION, nunca un PASA vacío).
"""
import contextlib
import csv
import io
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import lanzar as L  # noqa: E402
import sonda_descartes  # noqa: E402

MIB = 1048576
ID_API = "a" * 64
ID_API_NUEVO = "b" * 64
ID_PG = "c" * 64
ID_K6 = "d" * 64

# --- Literales medidos del plan v4.2 (no se derivan de lanzar.py) -------------
# M2: cabecera del CSV de k6 v2.3.0 con 'check' en systemTags (m2.js, sin
# K6_CSV_TIME_FORMAT), medidas_v4_25nov/m2.csv, 25/11/2026. Sin columna error.
CABECERA_M2 = ("metric_name,timestamp,metric_value,check,error_code,expected_response,method,name,proto,scenario,"
               "status,extra_tags,metadata")
# Cabecera real de L4 con fases.js del commit c7791e6 (sin 'check'): primera
# línea de rep1/pico_rep1/k6.csv de canario_estres_salida_px5x7po1, k6 v2.3.0,
# 24/11/2026.
CABECERA_L4 = ("metric_name,timestamp,metric_value,error_code,expected_response,method,name,proto,scenario,status,"
               "extra_tags,metadata")
# Fila checks real del humo previo de L4 (misma salida, línea 48055 del k6.csv).
FILA_CHECKS_L4 = "checks,1795546507075,1.000000,,,,,,humo_previo,,ruta=humo,"
# Fila checks de M4 con la cabecera M2 (medidas_v4_25nov/m4.csv, k6 v2.3.0 con
# K6_CSV_TIME_FORMAT=unix_milli, 25/11/2026).
FILA_CHECKS_M4 = "checks,1795596322789,1.000000,humo_previo: x,,,,,,default,,,"
# M4-real: cabecera de l3.js (sin 'check') y fila http_req_duration de una
# petición fallida de L3b (status 0, proto vacío, error_code 1050),
# medidas_v4_25nov/fila_status0_l3b_rep1.csv, k6 v2.3.0, 25/11/2026.
CABECERA_L3B = ("metric_name,timestamp,metric_value,error_code,expected_response,method,name,proto,scenario,status,"
                "extra_tags,metadata")
FILA_M4_REAL = ("http_req_duration,1795592728795,15000.393788,1050,false,POST,login_email,,login_ataque,0,"
                "ip=198.18.5.119&ruta=login_email&fase=carga,")
# Peticiones de setup() de l3.js, fuera de todo escenario (scenario vacío), con la
# cabecera de l3.js (CABECERA_L3B): medidas_v4_25nov/filas_setup_l3_l3b.csv, copia
# de canario_estres_salida_anx_ifad/rep1/l3_rep1/k6.csv:3 y de
# canario_estres_salida_ky1_5amj/rep1/l3b_rep1/k6.csv:7 y :16, k6 v2.3.0,
# 25/11/2026 (enmienda v4.3, punto 1).
FILAS_SETUP_L3 = (
    "http_req_duration,1795556284245,1.864927,1405,false,POST,http://caddy:8080/salud,HTTP/1.1,,405,,",
    "http_req_duration,1795592410286,1.888676,1405,false,POST,http://caddy:8080/salud,HTTP/1.1,,405,,",
    "http_req_duration,1795592410293,6.870392,,true,GET,http://caddy:8080/seguimiento,HTTP/1.1,,200,,",
)
# Un 404 de L4 con error_code 1404 y la cabecera de L4 (CABECERA_L4):
# medidas_v4_25nov/fila_404_l4_rep1.csv, copia de
# canario_estres_salida_px5x7po1/rep1/pico_rep1/k6.csv:31, k6 v2.3.0, 24/11/2026.
FILA_404_L4 = ("http_req_duration,1795546367107,39.437354,1404,false,POST,seguimiento,HTTP/1.1,seguimiento__cal,404,"
               "ruta=seguimiento&fase=cal,")
# Cabecera real del CSV de la sonda de descartes (sonda_descartes.csv de
# canario_estres_salida_px5x7po1, k6 v2.3.0, 24/11/2026).
CABECERA_SONDA = "metric_name,timestamp,metric_value,name,scenario,status,extra_tags,metadata"
# Etiquetas de la imagen de la API (M1-bis: docker image inspect
# canario_estres-api:latest, 25/11/2026) y del lector (M1-contenedor: docker ps
# --format {{.Labels}} de canario_estres_lector_3 durante L3b, 25/11/2026).
ETIQUETAS_IMAGEN_API = {"com.docker.compose.project": "canario_estres", "com.docker.compose.service": "api",
                        "com.docker.compose.version": "5.1.4"}
ETIQUETAS_LECTOR = ("canario.estres=lector,com.docker.compose.project=canario_estres,com.docker.compose.service=api,"
                    "com.docker.compose.version=5.1.4,desktop.docker.io/ports.scheme=v2")
# Nombre del servidor de la sonda con el prefijo del lanzador
# (PREFIJO_EFIMEROS = PROYECTO + "_", lanzar.py:261 del commit c7791e6). Se
# escribe sin barra inicial porque así llega, según se supone, el atributo name
# de docker events. Procedencia: M5 del 25/11/2026 (PENDIENTE, sin medir; enmienda
# v4.3, punto 6). Si la M5 diera una barra, este literal y los eventos de las
# pruebas cambian con ella.
NOMBRE_SERVIDOR_SONDA = "canario_estres_sonda_lento"


def ev(accion, ident=ID_API, t=100.0, clase="canario", codigo=None, servicio="api"):
    return {"id": ident, "accion": accion, "t": t, "clase": clase, "servicio": servicio, "nombre": servicio,
            "codigo": codigo}


def cg(anon=0, swap=0, swapcached=0, inode=1, oom=0, oom_kill=0):
    return {"anon": anon, "swapcached": swapcached, "swap_current": swap, "inode": inode, "oom": oom,
            "oom_kill": oom_kill, "file": 0, "kernel": 0, "pids": 1, "pico": None, "swap_pico": None}


class HoraMotor(unittest.TestCase):
    def test_z_y_desfase(self):
        self.assertEqual(L.hora_motor("2026-11-22T10:00:00Z"), 1795341600.0)
        self.assertEqual(L.hora_motor("2026-11-22T10:00:00.5Z"), 1795341600.5)
        # 11:00 en +01:00 es la misma hora que 10:00Z.
        self.assertEqual(L.hora_motor("2026-11-22T11:00:00+01:00"), 1795341600.0)
        self.assertEqual(L.hora_motor("2026-11-22T05:00:00.123456789-05:00"), 1795341600.123456789)

    def test_formato_invalido_es_parada_no_cero(self):
        for texto in ("", "ayer", "2026-11-22 10:00:00", None):
            with self.assertRaises(L.Parada):
                L.hora_motor(texto)


class Eventos(unittest.TestCase):
    def test_parseo_y_clases(self):
        linea = json.dumps({"Type": "container", "Action": "die", "timeNano": 1795341600500000000,
                            "Actor": {"ID": ID_API, "Attributes": {
                                "exitCode": "137", "name": "canario_estres-api-1",
                                "com.docker.compose.project": "canario_estres",
                                "com.docker.compose.service": "api"}}})
        e = L.parsear_evento(linea)
        self.assertEqual((e["accion"], e["clase"], e["codigo"], e["t"]), ("die", "canario", "137", 1795341600.5))
        # Control positivo de la clasificación: las otras clases.
        # k6 con las etiquetas medidas: canario.estres=k6 y ninguna de compose
        # (M1-contenedor, canario_estres_k6_l3b_rep2, 25/11/2026).
        self.assertEqual(L.clase_contenedor({"canario.estres": "k6"}), "k6")
        # El control sale de la imagen de la API (lanzar.py, ejecutar_control): hereda sus
        # etiquetas de compose (M1-bis, 25/11/2026) y aun así es "control".
        self.assertEqual(L.clase_contenedor({**ETIQUETAS_IMAGEN_API, "canario.estres": "control"}), "control")
        self.assertEqual(L.clase_contenedor({"com.docker.compose.project": "canario_estres",
                                             "com.docker.compose.service": "gestion"}), "auxiliar")
        self.assertIsNone(L.clase_contenedor({"com.docker.compose.project": "otro"}))
        # Negativo: una línea que no es JSON es un error visible, no se pierde.
        with self.assertRaises(ValueError):
            L.parsear_evento("no es json")
        self.assertIsNone(L.parsear_evento(json.dumps({"Type": "network"})))

    def test_exec_start_se_normaliza(self):
        linea = json.dumps({"Type": "container", "Action": "exec_start: sh", "timeNano": 1, "Actor": {"ID": "x"}})
        self.assertEqual(L.parsear_evento(linea)["accion"], "exec_start")

    def test_d_canario_estres_manda_sobre_compose(self):
        # Plan v4.2, prueba d: las etiquetas medidas del lector (ETIQUETAS_LECTOR), que
        # heredan las de compose de la imagen de la API.
        lector = L.etiquetas_de(ETIQUETAS_LECTOR)
        self.assertEqual(lector["com.docker.compose.service"], "api")
        self.assertEqual(L.clase_contenedor(lector), "lector")
        # Con canario.estres=sonda (el servidor de la sonda, misma imagen): "sonda", no "canario".
        self.assertEqual(L.clase_contenedor({**lector, "canario.estres": "sonda"}), "sonda")
        # Un valor desconocido: la clase de instrumento, nunca "canario" ni None.
        self.assertEqual(L.clase_contenedor({**lector, "canario.estres": "otro"}), "instrumento_desconocido")
        # Control: las mismas etiquetas de compose sin canario.estres son la API ("canario").
        sin_propia = {k: v for k, v in lector.items() if k != "canario.estres"}
        self.assertEqual(L.clase_contenedor(sin_propia), "canario")


class Ventanas(unittest.TestCase):
    def setUp(self):
        self.pasos = [{"nombre": "login_email__e1", "desde": 100.0, "hasta": 200.0, "cal_hasta": 130.0},
                      {"nombre": "login_email__e2", "desde": 230.0, "hasta": 300.0, "cal_hasta": None}]
        self.mant = [{"ids": frozenset([ID_API]), "desde": 310.0, "hasta": 320.0, "motivo": "recreacion de la API"}]
        self.v = L.construir_ventanas(self.pasos, self.mant)

    def test_bordes_exactos(self):
        self.assertEqual(L.ventana_atribuida(100.0, self.v), "login_email__e1 (calentamiento)")
        self.assertEqual(L.ventana_atribuida(129.999, self.v), "login_email__e1 (calentamiento)")
        # El borde final pertenece a la ventana siguiente (semiabierta).
        self.assertEqual(L.ventana_atribuida(130.0, self.v), "login_email__e1")
        self.assertEqual(L.ventana_atribuida(199.999, self.v), "login_email__e1")
        self.assertEqual(L.ventana_atribuida(230.0, self.v), "login_email__e2")
        self.assertIsNone(L.ventana_atribuida(99.999, self.v))

    def test_reposo_se_atribuye_al_escalon_anterior(self):
        self.assertEqual(L.ventana_atribuida(200.0, self.v), "login_email__e1")
        self.assertEqual(L.ventana_atribuida(229.0, self.v), "login_email__e1")

    def test_mantenimiento(self):
        self.assertEqual(L.ventana_atribuida(315.0, self.v), "recreacion de la API")
        self.assertIsNone(L.ventana_atribuida(320.0, self.v))


class Encarnaciones(unittest.TestCase):
    def test_dos_start_seguidos_mismo_id(self):
        eventos = [ev("start", t=1.0), ev("die", t=2.0, codigo="137"), ev("start", t=3.0)]
        encs = L.encarnaciones_eventos(eventos)
        self.assertEqual(len(encs), 2)
        self.assertEqual((encs[0]["inicio"], encs[0]["fin"], encs[0]["codigo"]), (1.0, 2.0, "137"))
        self.assertIsNone(encs[1]["fin"])
        # Dos start sin die entre medias: también dos.
        self.assertEqual(len(L.encarnaciones_eventos([ev("start", t=1.0), ev("start", t=2.0)])), 2)
        # Control: un solo start es una sola.
        self.assertEqual(len(L.encarnaciones_eventos([ev("start", t=1.0)])), 1)

    def test_cgroup_inode_nuevo_o_contador_que_baja(self):
        serie = [(1.0, cg(inode=7)), (1.25, cg(inode=7, oom=1)), (1.5, None), (1.75, cg(inode=9)),
                 (2.0, cg(inode=9, oom_kill=1))]
        muestras, encs = L.etiquetar_cgroup(serie)
        self.assertEqual([e["indice"] for e in encs], [0, 1])
        self.assertEqual([m["enc"] for m in muestras], [0, 0, 1, 1])
        # Mismo inode pero el contador baja: también una encarnación nueva.
        _, encs = L.etiquetar_cgroup([(1.0, cg(inode=7, oom_kill=2)), (1.25, cg(inode=7, oom_kill=0))])
        self.assertEqual(len(encs), 2)
        # Control: mismo inode y contadores crecientes: una sola.
        _, encs = L.etiquetar_cgroup([(1.0, cg(inode=7)), (1.25, cg(inode=7, oom=1, oom_kill=1))])
        self.assertEqual(len(encs), 1)

    def test_contadores_acumulados(self):
        serie = [(1.0, cg(inode=7, oom_kill=0)), (1.25, cg(inode=7, oom_kill=1)),
                 (1.5, cg(inode=9, oom_kill=0)), (1.75, cg(inode=9, oom_kill=2))]
        _, encs = L.etiquetar_cgroup(serie)
        self.assertEqual(L.acumulado_contadores(encs), {"oom": 0, "oom_kill": 3})


class Muertes(unittest.TestCase):
    def setUp(self):
        self.mant_api = [{"ids": frozenset([ID_API]), "desde": 100.0, "hasta": 130.0, "motivo": "recreacion"}]

    def test_die_esperado_del_id_viejo_no_cuenta(self):
        eventos = [ev("die", ID_API, 105.0, codigo="0"), ev("destroy", ID_API, 106.0)]
        self.assertEqual(L.muertes_no_esperadas(eventos, self.mant_api), [])

    def test_control_positivo_un_die_no_esperado_se_detecta(self):
        # Mismo die, sin mantenimiento: debe detectarse. Si no, el negativo
        # de arriba no demostraría nada.
        eventos = [ev("die", ID_API, 105.0, codigo="137")]
        self.assertEqual(len(L.muertes_no_esperadas(eventos, [])), 1)

    def test_die_de_postgres_en_la_ventana_de_la_api_es_falla(self):
        eventos = [ev("die", ID_API, 105.0), ev("die", ID_PG, 106.0, codigo="137", servicio="postgres")]
        muertes = L.muertes_no_esperadas(eventos, self.mant_api)
        self.assertEqual([m["id"] for m in muertes], [ID_PG])

    def test_die_del_id_viejo_tras_su_destroy_no_es_esperado(self):
        eventos = [ev("destroy", ID_API, 104.0), ev("die", ID_API, 105.0)]
        self.assertEqual(len(L.muertes_no_esperadas(eventos, self.mant_api)), 1)

    def test_k6_y_lector_no_son_muertes_de_canario(self):
        eventos = [ev("die", ID_K6, 105.0, clase="k6", codigo="0"), ev("die", "e" * 64, 106.0, clase="lector")]
        self.assertEqual(L.muertes_no_esperadas(eventos, []), [])

    def test_starts_no_esperados(self):
        eventos = [ev("start", ID_API, 1.0), ev("start", ID_API, 3.0), ev("start", ID_PG, 1.0, servicio="postgres")]
        self.assertEqual(L.starts_no_esperados(eventos), 1)
        self.assertEqual(L.starts_no_esperados(eventos[:1] + eventos[2:]), 0)

    def test_otro_murio(self):
        eventos = [ev("die", ID_K6, 105.0, clase="k6", codigo="137")]
        self.assertTrue(L.otro_murio(eventos, ID_API, 100.0, 110.0, []))
        # Control: el fin normal de k6 (código 0) no cuenta, ni fuera de la ventana.
        self.assertFalse(L.otro_murio([ev("die", ID_K6, 105.0, clase="k6", codigo="0")], ID_API, 100.0, 110.0, []))
        self.assertFalse(L.otro_murio(eventos, ID_API, 200.0, 210.0, []))

    def test_e_el_die_137_de_la_sonda_no_es_una_muerte_de_canario(self):
        # Plan v4.2, prueba e: el die del servidor de la sonda tal como llega de docker
        # events, con las etiquetas heredadas de la imagen de la API (M1-bis) y la suya.
        def die(atributos):
            return L.parsear_evento(json.dumps({"Type": "container", "Action": "die", "timeNano": 105000000000,
                                                "Actor": {"ID": "f" * 64, "Attributes": {
                                                    **atributos, "exitCode": "137", "name": NOMBRE_SERVIDOR_SONDA}}}))
        sonda = die({**ETIQUETAS_IMAGEN_API, "canario.estres": "sonda"})
        self.assertEqual(sonda["clase"], "sonda")
        self.assertEqual(L.muertes_no_esperadas([sonda], []), [])
        self.assertFalse(L.otro_murio([sonda], ID_API, 100.0, 110.0, []))
        # Control: el mismo die con clase canario (sin canario.estres) es una muerte.
        canario = die(ETIQUETAS_IMAGEN_API)
        self.assertEqual(canario["clase"], "canario")
        self.assertEqual(len(L.muertes_no_esperadas([canario], [])), 1)
        self.assertTrue(L.otro_murio([canario], ID_API, 100.0, 110.0, []))


class ControlC5(unittest.TestCase):
    """Plan v4.2, prueba i: el die del servidor de la sonda clasificado como sonda."""

    def die(self, nombre, codigo, heredadas):
        # El servidor sale de la imagen de la API (hereda M1-bis); el k6 de la sonda, de la
        # de k6 (sin etiquetas de compose, como canario_estres_k6_l3b_rep2 en M1-contenedor).
        atributos = {**(ETIQUETAS_IMAGEN_API if heredadas else {}), "canario.estres": "sonda", "exitCode": codigo,
                     "name": nombre}
        return L.parsear_evento(json.dumps({"Type": "container", "Action": "die", "timeNano": 1050000000000,
                                            "Actor": {"ID": ("f" if heredadas else "e") * 64,
                                                      "Attributes": atributos}}))

    def test_el_nombre_del_servidor_es_el_literal(self):
        # El oráculo es el literal, no la función.
        self.assertEqual(sonda_descartes.nombre_servidor(L.PREFIJO_EFIMEROS), NOMBRE_SERVIDOR_SONDA)
        # Control: con otro prefijo el nombre cambia (la función usa el prefijo que recibe).
        self.assertEqual(sonda_descartes.nombre_servidor("p_"), "p_sonda_lento")

    def test_i_c5(self):
        servidor = self.die(NOMBRE_SERVIDOR_SONDA, "137", True)
        k6_sonda = self.die("canario_estres_sonda_k6", "0", False)
        # rep1 sin el die de la sonda: SIN CONCLUSION.
        ok, texto = L.control_c5([])
        self.assertFalse(ok)
        self.assertIn("no hay un die de canario_estres_sonda_lento clasificado como sonda", texto)
        # Control: con el die del servidor, PASA, y los die salen por clase.
        ok, texto = L.control_c5([servidor, k6_sonda])
        self.assertTrue(ok, texto)
        self.assertIn("die por clase {'sonda': 2}", texto)
        # Control negativo: solo el die del k6 de la sonda (misma clase, otro nombre): SIN CONCLUSION.
        self.assertEqual(k6_sonda["clase"], "sonda")
        self.assertFalse(L.control_c5([k6_sonda])[0])
        # El die del servidor con la clase de compose (el fallo 2 de L4) tampoco vale.
        compose = {**servidor, "clase": "canario"}
        self.assertFalse(L.control_c5([compose])[0])


class RegladelPadre(unittest.TestCase):
    def test_oom_es_propio_limite(self):
        self.assertEqual(L.veredicto_muerte(True, True, False, False), ("FALLA", "OOM por su propio limite"))

    def test_oom_kill_sin_oom_es_sin_conclusion(self):
        self.assertEqual(L.veredicto_muerte(False, True, False, False)[0], "SIN CONCLUSION")

    def test_nada_es_falla_no_atribuible(self):
        self.assertEqual(L.veredicto_muerte(False, False, False, False), ("FALLA", "no atribuible"))

    def test_k6_muerto_mas_api_muerta_es_falla(self):
        estado, causa = L.veredicto_muerte(True, True, True, False)
        self.assertEqual(estado, "FALLA")
        self.assertIn("no atribuible", causa)
        self.assertIn("murio otro contenedor", causa)

    def test_oom_de_k6_en_la_misma_ventana_es_atribucion_dudosa(self):
        estado, causa = L.veredicto_muerte(True, True, False, True)
        self.assertEqual(estado, "FALLA")
        self.assertIn("atribucion dudosa", causa)

    def test_delta_del_padre(self):
        serie = [(1.0, 0), (2.0, 0), (3.0, 1), (4.0, 1)]
        self.assertEqual(L.delta_serie(serie, 2.0, 3.5), 1)
        self.assertEqual(L.delta_serie(serie, 3.5, 4.5), 0)  # control: sin incremento
        self.assertEqual(L.delta_serie([], 0.0, 1.0), 0)


class Huecos(unittest.TestCase):
    def test_hueco_de_mas_de_3_s(self):
        serie = [(0.0, cg()), (0.25, cg()), (4.0, cg())]
        self.assertEqual(L.huecos_de_serie(serie), [(0.25, 4.0)])
        # Control: justo 3 s no es hueco.
        self.assertEqual(L.huecos_de_serie([(0.0, cg()), (3.0, cg())]), [])

    def test_ruta_ausente_cuenta_como_hueco_y_se_explica_con_una_muerte(self):
        serie = [(0.0, cg()), (1.0, None), (2.0, None), (5.0, None), (5.5, cg())]
        huecos = L.huecos_de_serie(serie)
        self.assertEqual(huecos, [(0.0, 5.5)])
        self.assertEqual(L.huecos_no_explicados(huecos, []), huecos)
        self.assertEqual(L.huecos_no_explicados(huecos, [1.2]), [])


class Memoria(unittest.TestCase):
    def test_formula_de_r1(self):
        # anon 100 MiB + swap 30 MiB - swapcached 10 MiB = 120 MiB; file y kernel no entran.
        m = cg(anon=104857600, swap=31457280, swapcached=10485760)
        m["file"], m["kernel"] = 999999999, 999999999
        self.assertEqual(L.memoria_puerta(m), 125829120)

    def test_160_mib_justos_pasa_y_un_byte_mas_falla(self):
        self.assertEqual(L.veredicto_memoria(167772160, False)[0], "PASA")
        self.assertEqual(L.veredicto_memoria(167772161, False)[0], "FALLA")

    def test_coherencia_con_margen(self):
        # 167772160 - 2 x 19456 KiB = 127926272.
        self.assertEqual(L.veredicto_memoria(127926272, True)[0], "PASA")
        self.assertEqual(L.veredicto_memoria(127926273, True)[0], "SIN CONCLUSION")
        # El mismo valor sin margen PASA: el margen es lo que lo cambia.
        self.assertEqual(L.veredicto_memoria(127926273, False)[0], "PASA")
        self.assertEqual(L.veredicto_memoria(167772161, True)[0], "FALLA")

    def test_sin_muestras_es_sin_conclusion(self):
        self.assertEqual(L.veredicto_memoria(None, False)[0], "SIN CONCLUSION")

    def test_indicio_de_picos(self):
        maximo = 150 * MIB
        # Retenido estable (el mínimo del reposo es casi el máximo): sin margen.
        self.assertFalse(L.hay_indicio_picos(maximo, maximo - 1000))
        # Justo 19456 KiB por debajo: todavía sin margen; 1 byte más: con margen.
        self.assertFalse(L.hay_indicio_picos(maximo, maximo - 19922944))
        self.assertTrue(L.hay_indicio_picos(maximo, maximo - 19922945))
        # Devuelve en el reposo: con margen.
        self.assertTrue(L.hay_indicio_picos(maximo, 60 * MIB))
        # Sin reposo: con margen por defecto.
        self.assertTrue(L.hay_indicio_picos(maximo, None))

    def test_maximo_y_minimo_en_ventana_y_encarnacion(self):
        serie = [(1.0, cg(anon=10 * MIB, inode=1)), (2.0, cg(anon=50 * MIB, inode=1)),
                 (3.0, cg(anon=30 * MIB, inode=1)), (4.0, cg(anon=5 * MIB, inode=2)),
                 (5.0, cg(anon=40 * MIB, inode=1))]
        muestras, _ = L.etiquetar_cgroup(serie)
        self.assertEqual(L.maximo_memoria(muestras, 1.0, 3.0)[:2], (50 * MIB, 0))
        self.assertIsNone(L.maximo_memoria(muestras, 10.0, 11.0))
        # Reposo [3, 5): la muestra de otra encarnación (inode 2, enc 1) no cuenta.
        self.assertEqual(L.minimo_reposo(muestras, 3.0, 5.0, 0), 30 * MIB)
        self.assertEqual(L.minimo_reposo(muestras, 3.0, 5.0, 1), 5 * MIB)
        self.assertIsNone(L.minimo_reposo(muestras, 20.0, 30.0, 0))


def muestras_de(*tramos, enc=0):
    """Muestras ya etiquetadas cada 0,25 s para tramos (desde, hasta, valor de
    anon), con los dos extremos incluidos."""
    muestras = []
    for desde, hasta, valor in tramos:
        for k in range(round((hasta - desde) * 4) + 1):
            muestras.append({**cg(anon=valor), "t": desde + k * 0.25, "enc": enc})
    return muestras


class HuecosAcotados(unittest.TestCase):
    def test_hueco_inicial_con_desde(self):
        serie = [(105.0, cg()), (105.25, cg())]
        self.assertEqual(L.huecos_de_serie(serie, desde=100.0), [(100.0, 105.0)])
        # Control: sin desde, la misma serie no tiene hueco (lo de siempre), y
        # con la primera muestra justo 3 s después de desde tampoco.
        self.assertEqual(L.huecos_de_serie(serie), [])
        self.assertEqual(L.huecos_de_serie([(103.0, cg())], desde=100.0, hasta=103.0), [])

    def test_cierre_con_hasta(self):
        serie = [(100.0, cg()), (100.25, cg())]
        self.assertEqual(L.huecos_de_serie(serie, hasta=104.0), [(100.25, 104.0)])
        # Control: cierre a 3 s justos de la última muestra, sin hueco.
        self.assertEqual(L.huecos_de_serie(serie, hasta=103.25), [])

    def test_tramo_sin_muestras(self):
        self.assertEqual(L.huecos_de_serie([], desde=100.0, hasta=110.0), [(100.0, 110.0)])
        # Control: sin acotar, una serie vacía no tiene huecos (lo de siempre).
        self.assertEqual(L.huecos_de_serie([]), [])


class Reposo(unittest.TestCase):
    RES = {"ruta": "login_email", "escalon": "e4", "k6_id": ID_K6, "fin_vm": 1100.0}

    def final(self, fin=1133.0, vivo=True):
        return {"fin_reposo_vm": fin, "lector_vivo_al_final": vivo}

    def siguiente(self, inicio=1140.0):
        return {"ruta": "login_email", "escalon": "e5", "k6_id": ID_K6, "inicio_vm": inicio}

    def estable(self):
        return muestras_de((1100.0, 1109.75, 139812864), (1110.0, 1133.0, 139000000))

    def test_final_estable_de_33_s(self):
        self.assertEqual(L.reposo_de_escalon(self.estable(), self.RES, None, self.final(), 0), (139000000, None))

    def test_final_truncado_a_5_s_es_reposo_corto(self):
        cortado = muestras_de((1100.0, 1105.0, 139000000))
        self.assertEqual(L.reposo_de_escalon(cortado, self.RES, None, self.final(), 0), (None, "reposo corto"))
        # Control positivo: el reposo entero sí vale.
        self.assertEqual(L.reposo_de_escalon(self.estable(), self.RES, None, self.final(), 0)[0], 139000000)

    def test_final_de_3_s_de_la_ultima_ruta_es_reposo_corto(self):
        tres = muestras_de((1100.0, 1103.0, 139000000))
        self.assertEqual(L.reposo_de_escalon(tres, self.RES, None, self.final(fin=1103.0), 0), (None, "reposo corto"))

    def test_lector_muerto_al_final(self):
        self.assertEqual(L.reposo_de_escalon(self.estable(), self.RES, None, self.final(vivo=False), 0),
                         (None, "lector muerto en el reposo final"))
        self.assertEqual(L.reposo_de_escalon(self.estable(), self.RES, None, self.final(vivo=True), 0)[0], 139000000)

    def test_hueco_de_5_s_en_medio(self):
        con_hueco = muestras_de((1100.0, 1110.0, 139000000), (1115.0, 1133.0, 139000000))
        self.assertEqual(L.reposo_de_escalon(con_hueco, self.RES, None, self.final(), 0), (None, "hueco en el reposo"))
        # Control: un tramo de 3 s justos sin muestras no es hueco.
        sin_hueco = muestras_de((1100.0, 1110.0, 139000000), (1113.0, 1133.0, 139000000))
        self.assertEqual(L.reposo_de_escalon(sin_hueco, self.RES, None, self.final(), 0)[0], 139000000)

    def test_hueco_inicial_de_5_s(self):
        tarde = muestras_de((1105.0, 1133.0, 139000000))
        self.assertEqual(L.reposo_de_escalon(tarde, self.RES, None, self.final(), 0), (None, "hueco en el reposo"))
        # Control: la primera muestra a 3 s justos del fin del escalón vale.
        a_tiempo = muestras_de((1103.0, 1133.0, 139000000))
        self.assertEqual(L.reposo_de_escalon(a_tiempo, self.RES, None, self.final(), 0)[0], 139000000)

    def test_corte_al_final_deja_hueco(self):
        hasta_1130 = muestras_de((1100.0, 1130.0, 139000000))
        self.assertEqual(L.reposo_de_escalon(hasta_1130, self.RES, None, self.final(fin=1134.0), 0),
                         (None, "hueco en el reposo"))
        self.assertEqual(L.reposo_de_escalon(hasta_1130, self.RES, None, self.final(fin=1133.0), 0)[0], 139000000)

    def test_intermedio_acaba_en_el_inicio_del_siguiente(self):
        muestras = muestras_de((1100.0, 1140.0, 139000000), (1140.25, 1173.0, 100000000))
        self.assertEqual(L.reposo_de_escalon(muestras, self.RES, self.siguiente(), self.final(fin=1173.0), 0),
                         (139000000, None))
        # Control: si se tomara el reposo final, la muestra baja sí entraría.
        self.assertEqual(L.reposo_de_escalon(muestras, self.RES, None, self.final(fin=1173.0), 0)[0], 100000000)

    def test_borde_la_muestra_en_hasta_cuenta(self):
        muestras = muestras_de((1100.0, 1139.75, 139000000), (1140.0, 1140.0, 138000000),
                               (1140.25, 1173.0, 139500000))
        self.assertEqual(L.reposo_de_escalon(muestras, self.RES, self.siguiente(1140.0), self.final(), 0)[0],
                         138000000)
        # Control: con el fin 0,25 s antes, esa muestra queda fuera.
        self.assertEqual(L.reposo_de_escalon(muestras, self.RES, self.siguiente(1139.75), self.final(), 0)[0],
                         139000000)

    def test_tolerancia_de_medio_segundo(self):
        muestras = muestras_de((1100.0, 1173.0, 139000000))
        # Última muestra a 29,5 s del fin del escalón: vale; a 29,25 s, no.
        self.assertEqual(L.reposo_de_escalon(muestras, self.RES, self.siguiente(1129.5), self.final(), 0)[0],
                         139000000)
        self.assertEqual(L.reposo_de_escalon(muestras, self.RES, self.siguiente(1129.25), self.final(), 0),
                         (None, "reposo corto"))

    def test_intermedio_corto(self):
        muestras = muestras_de((1100.0, 1173.0, 139000000))
        self.assertEqual(L.reposo_de_escalon(muestras, self.RES, self.siguiente(1120.0), self.final(), 0),
                         (None, "reposo corto"))
        self.assertEqual(L.reposo_de_escalon(muestras, self.RES, self.siguiente(1140.0), self.final(), 0)[0],
                         139000000)

    def test_intermedio_con_hueco(self):
        con_hueco = muestras_de((1100.0, 1110.0, 139000000), (1115.0, 1173.0, 139000000))
        self.assertEqual(L.reposo_de_escalon(con_hueco, self.RES, self.siguiente(), self.final(), 0),
                         (None, "hueco en el reposo"))
        sin_hueco = muestras_de((1100.0, 1110.0, 139000000), (1113.0, 1173.0, 139000000))
        self.assertEqual(L.reposo_de_escalon(sin_hueco, self.RES, self.siguiente(), self.final(), 0)[0], 139000000)

    def test_siguiente_lanzado_sin_hora(self):
        muestras = muestras_de((1100.0, 1173.0, 139000000))
        sin_hora = {**self.siguiente(), "inicio_vm": None}
        self.assertEqual(L.reposo_de_escalon(muestras, self.RES, sin_hora, self.final(), 0),
                         (None, "siguiente escalon sin hora"))
        self.assertEqual(L.reposo_de_escalon(muestras, self.RES, self.siguiente(), self.final(), 0)[0], 139000000)

    def test_escalon_sin_hora_de_fin(self):
        sin_fin = {**self.RES, "fin_vm": None}
        self.assertEqual(L.reposo_de_escalon(self.estable(), sin_fin, None, self.final(), 0),
                         (None, "escalon sin hora de fin"))
        self.assertEqual(L.reposo_de_escalon(self.estable(), self.RES, None, self.final(), 0)[0], 139000000)

    def test_otra_encarnacion_no_cuenta(self):
        muestras = muestras_de((1100.0, 1133.0, 139000000), enc=0) + muestras_de((1100.0, 1133.0, 52428800), enc=1)
        self.assertEqual(L.reposo_de_escalon(muestras, self.RES, None, self.final(), 0)[0], 139000000)
        # Control: las de la encarnación 1 están en la ventana y cuentan para ella.
        self.assertEqual(L.reposo_de_escalon(muestras, self.RES, None, self.final(), 1)[0], 52428800)
        # La API recreada a mitad del reposo: la encarnación del máximo no lo cubre.
        partido = muestras_de((1100.0, 1115.0, 139000000), enc=0) + muestras_de((1115.25, 1133.0, 52428800), enc=1)
        self.assertEqual(L.reposo_de_escalon(partido, self.RES, None, self.final(), 0), (None, "reposo corto"))


class SiguienteLanzado(unittest.TestCase):
    E4 = {"ruta": "login_email", "escalon": "e4", "k6_id": ID_K6, "fin_vm": 1100.0}

    def test_solo_cuenta_la_clave_k6_id(self):
        lanzado = {"ruta": "login_email", "escalon": "e5", "k6_id": ID_K6, "inicio_vm": 1140.0}
        sin_k6 = {"ruta": "login_email", "escalon": "e5", "inicio_vm": 1140.0}
        self.assertIs(L.siguiente_lanzado([self.E4, lanzado], 0), lanzado)
        self.assertIsNone(L.siguiente_lanzado([self.E4, sin_k6], 0))
        # Los dos resultados, que solo difieren en k6_id, dan reposos distintos:
        # el intermedio no ve la muestra baja; el final, sí.
        muestras = muestras_de((1100.0, 1140.0, 139000000), (1140.25, 1173.0, 100000000))
        final = {"fin_reposo_vm": 1173.0, "lector_vivo_al_final": True}
        self.assertEqual(L.reposo_de_escalon(muestras, self.E4, L.siguiente_lanzado([self.E4, lanzado], 0), final,
                                             0)[0], 139000000)
        self.assertEqual(L.reposo_de_escalon(muestras, self.E4, L.siguiente_lanzado([self.E4, sin_k6], 0), final,
                                             0)[0], 100000000)

    def test_salta_los_no_lanzados(self):
        no_lanzado = {"ruta": "login_email", "escalon": "e5", "motivo_cobertura": "no se lanzo"}
        e6 = {"ruta": "login_email", "escalon": "e6", "k6_id": ID_K6, "inicio_vm": 1200.0}
        self.assertIs(L.siguiente_lanzado([self.E4, no_lanzado, e6], 0), e6)
        # Un no lanzado seguido de nada: reposo final.
        self.assertIsNone(L.siguiente_lanzado([self.E4, no_lanzado], 0))

    def test_no_cruza_de_ruta(self):
        otra = {"ruta": "login_empresa", "escalon": "e1", "k6_id": ID_K6, "inicio_vm": 1200.0}
        self.assertIsNone(L.siguiente_lanzado([self.E4, otra], 0))
        # Control: la misma, en la misma ruta, sí es el siguiente.
        misma = {**otra, "ruta": "login_email"}
        self.assertIs(L.siguiente_lanzado([self.E4, misma], 0), misma)


class VeredictoEscalon(unittest.TestCase):
    def test_retenido_estable_sin_margen(self):
        self.assertEqual(L.veredicto_escalon_memoria(139812864, 139000000, None),
                         ("PASA", "maximo 139812864 B <= 167772160 B", "retenido estable: sin margen"))

    def test_indicio_de_picos_con_margen(self):
        # 139812864 - 19922945 = 119889919: devuelve más de 19456 KiB.
        self.assertEqual(L.veredicto_escalon_memoria(139812864, 119889919, None),
                         ("SIN CONCLUSION", "maximo 139812864 B cabe, pero con 2 x 19456 KiB de reservas de Argon2 no "
                          "muestreadas (179658752 B) no cabe en 167772160 B", "con margen de 2 x 19456 KiB"))

    def test_sin_reposo_valido_dice_el_motivo(self):
        self.assertEqual(L.veredicto_escalon_memoria(139812864, None, "reposo corto")[::2],
                         ("SIN CONCLUSION", "con margen de 2 x 19456 KiB (sin reposo valido: reposo corto)"))
        # Control: con margen y un máximo que cabe con él, PASA.
        self.assertEqual(L.veredicto_escalon_memoria(127926272, None, "reposo corto"),
                         ("PASA", "maximo 127926272 B <= 167772160 B",
                          "con margen de 2 x 19456 KiB (sin reposo valido: reposo corto)"))


class EvaluarRepeticion(unittest.TestCase):
    """evaluar_repeticion con un ej falso, sin Docker, y la salida capturada."""

    def ruta(self, ticks_hasta=1133.0, fin_reposo=1133.0, vivo=True, muertos=(), **cambios):
        res = {"ruta": "login_email", "escalon": "e5", "principal": {"p95_ms": 1.0}, "k6_id": ID_K6,
               "inicio_vm": 1000.0, "fin_vm": 1100.0, "ventana_principal_s": [1000.0, 1100.0], "ventana_cal_s": None,
               "no_evaluable": False, "cubierto": True, "solo_memoria": False, "motivo_cobertura": "cobertura 100 %",
               "sin_conclusion": []}
        res.update(cambios)
        # Máximo 139812864 B a mitad del escalón; 139000000 B en el resto.
        ticks = [{"t": 1000.0 + k * 0.25, "c": {"api": cg(anon=139812864 if k == 200 else 139000000)},
                  "padre": None, "hijos": {}} for k in range(round((ticks_hasta - 1000.0) * 4) + 1)]
        return {"ruta": "login_email", "resultados": [res], "ticks": ticks, "fin_reposo_vm": fin_reposo,
                "lector_vivo_al_final": vivo, "muertos_al_final": list(muertos)}

    def evaluar(self, rutas):
        lineas = []
        ej = types.SimpleNamespace(eventos=types.SimpleNamespace(copia=list), mantenimientos=[], reinicios={})
        with mock.patch.object(L, "p", lineas.append), \
                mock.patch.dict(L.estado, {"falla": False, "sin_conclusion": False}):
            datos = L.evaluar_repeticion(ej, 1, rutas, 0.0, False)
            sin_conclusion = L.estado["sin_conclusion"]
        return [x for x in lineas if "login_email__e" in x], datos, sin_conclusion

    def test_ultimo_escalon_con_reposo_final_valido_pasa_sin_margen(self):
        lineas, datos, sin_conclusion = self.evaluar([self.ruta()])
        self.assertEqual(lineas, ["PASA  repeticion 1, login_email__e5 (escalon): memoria maximo 139812864 B <= "
                                  "167772160 B; retenido estable: sin margen"])
        self.assertEqual(datos["max_memoria"], 139812864)
        self.assertFalse(sin_conclusion)

    def test_misma_serie_truncada_es_sin_conclusion(self):
        lineas, _, sin_conclusion = self.evaluar([self.ruta(ticks_hasta=1105.0)])
        self.assertEqual(lineas, ["SIN CONCLUSION repeticion 1, login_email__e5 (escalon): memoria maximo 139812864 B "
                                  "cabe, pero con 2 x 19456 KiB de reservas de Argon2 no muestreadas (179658752 B) no "
                                  "cabe en 167772160 B; con margen de 2 x 19456 KiB (sin reposo valido: reposo corto)"])
        self.assertTrue(sin_conclusion)

    def test_lector_muerto_al_final_es_sin_conclusion(self):
        lineas, _, _ = self.evaluar([self.ruta(vivo=False)])
        self.assertEqual(lineas, ["SIN CONCLUSION repeticion 1, login_email__e5 (escalon): memoria maximo 139812864 B "
                                  "cabe, pero con 2 x 19456 KiB de reservas de Argon2 no muestreadas (179658752 B) no "
                                  "cabe en 167772160 B; con margen de 2 x 19456 KiB (sin reposo valido: lector muerto "
                                  "en el reposo final)"])

    def test_streamers_muertos_al_final_dan_sin_conclusion(self):
        lineas = []
        ej = types.SimpleNamespace(eventos=types.SimpleNamespace(copia=list), mantenimientos=[], reinicios={})
        with mock.patch.object(L, "p", lineas.append), \
                mock.patch.dict(L.estado, {"falla": False, "sin_conclusion": False}):
            L.evaluar_repeticion(ej, 1, [self.ruta(muertos=["log_api"])], 0.0, False)
            sin_conclusion = L.estado["sin_conclusion"]
        self.assertIn("SIN CONCLUSION repeticion 1, login_email: streamers muertos en el reposo final: ['log_api']",
                      lineas)
        self.assertTrue(sin_conclusion)
        # Control: el caso sin muertos (test de arriba) no da SIN CONCLUSION.
        self.assertFalse(self.evaluar([self.ruta()])[2])

    def test_j_instrumento_desconocido_en_l1_es_sin_conclusion(self):
        # Plan v4.2, prueba j (L1): un die de un contenedor con un valor desconocido de
        # canario.estres, con las etiquetas medidas del lector (ETIQUETAS_LECTOR).
        def correr(valor):
            atributos = {**L.etiquetas_de(ETIQUETAS_LECTOR), "canario.estres": valor, "exitCode": "1",
                         "name": "canario_estres_raro"}
            evento = L.parsear_evento(json.dumps({"Type": "container", "Action": "die", "timeNano": 1050000000000,
                                                  "Actor": {"ID": "f" * 64, "Attributes": atributos}}))
            lineas = []
            ej = types.SimpleNamespace(eventos=types.SimpleNamespace(copia=lambda: [evento]), mantenimientos=[],
                                       reinicios={})
            with mock.patch.object(L, "p", lineas.append), \
                    mock.patch.dict(L.estado, {"falla": False, "sin_conclusion": False}):
                L.evaluar_repeticion(ej, 1, [self.ruta()], 0.0, False)
                return lineas, L.estado["sin_conclusion"]
        lineas, sin_conclusion = correr("otro")
        self.assertIn("SIN CONCLUSION repeticion 1: eventos de contenedores con un valor desconocido de canario.estres: "
                      "['canario_estres_raro']", lineas)
        self.assertTrue(sin_conclusion)
        # Control: el mismo evento con canario.estres=lector no da nada.
        lineas, sin_conclusion = correr("lector")
        self.assertFalse(any("valor desconocido" in x for x in lineas))
        self.assertFalse(sin_conclusion)

    def test_solo_memoria_tiene_veredicto(self):
        lineas, datos, _ = self.evaluar([self.ruta(solo_memoria=True)])
        self.assertEqual(lineas, ["PASA  repeticion 1, login_email__e5 (escalon): memoria maximo 139812864 B <= "
                                  "167772160 B; retenido estable: sin margen"])
        self.assertEqual(datos["max_memoria"], 139812864)

    def test_no_cubierto_solo_informa(self):
        lineas, datos, _ = self.evaluar([self.ruta(cubierto=False, motivo_cobertura="cobertura 80 %")])
        self.assertIn("   informativo (escalon no cubierto: cobertura 80 %): repeticion 1, login_email__e5 (escalon): "
                      "memoria maximo 139812864 B <= 167772160 B; retenido estable: sin margen", lineas)
        self.assertIsNone(datos["max_memoria"])

    def test_no_evaluable_sin_veredicto(self):
        lineas, datos, _ = self.evaluar([self.ruta(no_evaluable=True)])
        self.assertEqual([x for x in lineas if "(escalon)" in x], [])
        self.assertIn("   login_email__e5: sin veredicto de memoria (murio un contenedor, ya es FALLA o SIN CONCLUSION "
                      "arriba)", lineas)
        self.assertIsNone(datos["max_memoria"])

    def test_escalon_intermedio_usa_el_siguiente_lanzado(self):
        ruta = self.ruta(ticks_hasta=1273.0, fin_reposo=1273.0, escalon="e4")
        ruta["resultados"].append({**ruta["resultados"][0], "escalon": "e5", "inicio_vm": 1140.0, "fin_vm": 1240.0,
                                   "ventana_principal_s": [1140.0, 1240.0]})
        lineas, _, _ = self.evaluar([ruta])
        self.assertEqual(lineas, [
            "PASA  repeticion 1, login_email__e4 (escalon): memoria maximo 139812864 B <= 167772160 B; retenido "
            "estable: sin margen",
            "PASA  repeticion 1, login_email__e5 (escalon): memoria maximo 139000000 B <= 167772160 B; retenido "
            "estable: sin margen"])


class Cobertura(unittest.TestCase):
    def test_95_por_ciento(self):
        self.assertTrue(L.escalon_cubierto(950, 10.0, 100, 0, False, False)[0])
        self.assertFalse(L.escalon_cubierto(949, 10.0, 100, 0, False, False)[0])

    def test_descartes_con_aviso_cubierto_y_sin_aviso_no(self):
        self.assertTrue(L.escalon_cubierto(100, 10.0, 100, 50, True, False)[0])
        self.assertFalse(L.escalon_cubierto(900, 10.0, 100, 50, False, False)[0])

    def test_generador_saturado_o_sin_medir_no_cubre(self):
        self.assertFalse(L.escalon_cubierto(1000, 10.0, 100, 0, False, True)[0])
        self.assertFalse(L.escalon_cubierto(1000, 10.0, 100, 0, False, None)[0])
        self.assertFalse(L.escalon_cubierto(100, 10.0, 100, 50, True, True)[0])


class Protocolo(unittest.TestCase):
    def test_protocolo(self):
        self.assertEqual(L.evaluar_protocolo({"HTTP/1.1": 100})[0], "PASA")
        self.assertEqual(L.evaluar_protocolo({"HTTP/1.1": 100, "HTTP/2.0": 1})[0], "SIN CONCLUSION")

    def test_sin_ninguna_respuesta_con_protocolo_es_sin_conclusion(self):
        self.assertEqual(L.evaluar_protocolo({})[0], "SIN CONCLUSION")


class Agregacion(unittest.TestCase):
    def test_peor_caso_no_la_mediana(self):
        maximos = [100 * MIB, 100 * MIB, 170 * MIB]
        self.assertEqual(L.peor_caso(maximos), 178257920)
        self.assertEqual(L.veredicto_memoria(L.peor_caso(maximos), False)[0], "FALLA")
        # Con la mediana (100 MiB) pasaría: justo lo que no debe hacerse.
        self.assertEqual(L.veredicto_memoria(104857600, False)[0], "PASA")
        self.assertIsNone(L.peor_caso([None, None]))

    def test_peor_estado(self):
        self.assertEqual(L.peor_estado(["PASA", "SIN CONCLUSION"]), "SIN CONCLUSION")
        self.assertEqual(L.peor_estado(["PASA", "SIN CONCLUSION", "FALLA"]), "FALLA")
        self.assertEqual(L.peor_estado(["PASA"]), "PASA")

    def test_resumen_de_latencias(self):
        r = L.resumen_latencias([300.0, 100.0, None, 200.0])
        self.assertEqual((r["mediana"], r["minimo"], r["maximo"]), (200.0, 100.0, 300.0))
        self.assertIsNone(L.resumen_latencias([None]))

    def test_primera_repeticion_sistematicamente_distinta(self):
        distinta = {f"e{i}": [900.0, 500.0, 520.0] for i in range(4)}
        self.assertTrue(L.primera_repeticion_distinta(distinta)[0])
        # Control: sin diferencia sistemática.
        normal = {f"e{i}": [500.0, 510.0, 490.0] for i in range(4)}
        self.assertFalse(L.primera_repeticion_distinta(normal)[0])
        self.assertFalse(L.primera_repeticion_distinta({"e1": [1.0]})[0])


class Conciliacion(unittest.TestCase):
    def test_conciliar(self):
        self.assertEqual(L.conciliar(2, 2, 1, 1), [])
        self.assertEqual(L.conciliar(3, 2, 0, 0), [])
        self.assertEqual(len(L.conciliar(1, 2, 0, 0)), 1)
        self.assertEqual(len(L.conciliar(2, 2, 1, 0)), 1)
        self.assertEqual(len(L.conciliar(0, 1, 2, 1)), 2)


class Relojes(unittest.TestCase):
    def test_desfase(self):
        self.assertEqual(L.desfase_valido(2.0, 2.5), (2.25, None))
        self.assertIsNone(L.desfase_valido(2.0, 3.5)[0])
        self.assertIsNone(L.desfase_valido(None, 2.0)[0])
        self.assertIsNotNone(L.desfase_valido(None, 2.0)[1])
        # 0 es un desfase válido (no se confunde con "sin medir").
        self.assertEqual(L.desfase_valido(0.0, 0.0), (0.0, None))


class PostgreSQL(unittest.TestCase):
    ORIGINAL = ["postgres", "-c", "max_connections=20", "-c", "ssl=off"]

    def test_diferencias_solo_los_dos_c(self):
        nuevo = self.ORIGINAL + ["-c", "log_checkpoints=on", "-c", "log_autovacuum_min_duration=0"]
        self.assertEqual(L.diferencias_comando(self.ORIGINAL, nuevo), [])
        # Negativo: un parámetro de más, o uno cambiado, es diferencia.
        self.assertTrue(L.diferencias_comando(self.ORIGINAL, nuevo + ["-c", "fsync=off"]))
        self.assertTrue(L.diferencias_comando(self.ORIGINAL, ["postgres", "-c", "max_connections=99"]))

    def test_yaml_escapa_dolar_y_comillas(self):
        texto = L.yaml_comando(["postgres", "-c", 'a="$x"'])
        self.assertIn('"a=\\"$$x\\""', texto)
        self.assertTrue(texto.startswith("services:\n  postgres:\n    command:\n"))

    def test_args_incluyen(self):
        args = ["postgres", "-c", "ssl=off", "-c", "log_checkpoints=on", "-c", "log_autovacuum_min_duration=0"]
        self.assertTrue(L.args_incluyen(args, L.EXTRAS_POSTGRES))
        self.assertFalse(L.args_incluyen(args[:5], L.EXTRAS_POSTGRES))


class Lector(unittest.TestCase):
    def inicio(self, **cambios):
        base = {"rutas": {"api": ["/sys/fs/cgroup/docker/x"]}, "padres": {"api": "/sys/fs/cgroup/docker"},
                "limites": {"api": {"memory.max": "268435456", "memory.swap.max": "268435456"}}, "hijos": []}
        base.update(cambios)
        return base

    def test_literales_de_la_api(self):
        self.assertEqual(L.problemas_inicio(self.inicio(), ["api"]), [])
        malo = self.inicio(limites={"api": {"memory.max": "536870912", "memory.swap.max": "268435456"}})
        self.assertEqual(len(L.problemas_inicio(malo, ["api"])), 1)

    def test_una_sola_ruta(self):
        for rutas in ([], ["a", "b"]):
            self.assertEqual(len(L.problemas_inicio(self.inicio(rutas={"api": rutas}), ["api"])), 1)

    def test_literales_del_control(self):
        ok = self.inicio(rutas={"control": ["/x"]}, padres={"control": "/p"},
                         limites={"control": {"memory.max": "67108864", "memory.swap.max": "67108864"}})
        self.assertEqual(L.problemas_inicio(ok, ["control"]), [])
        # Con los literales de la API, el control NO es el control.
        mal = self.inicio(rutas={"control": ["/x"]}, padres={"control": "/p"},
                          limites={"control": {"memory.max": "268435456", "memory.swap.max": "268435456"}})
        self.assertEqual(len(L.problemas_inicio(mal, ["control"])), 1)

    def test_hijos_ajenos(self):
        conocidos = {ID_API: {"nombre": "api", "etiquetas": {"com.docker.compose.project": "canario_estres",
                                                              "com.docker.compose.service": "api"}},
                     ID_K6: {"nombre": "k6", "etiquetas": {"canario.estres": "k6"}},
                     "f" * 64: {"nombre": "ajeno", "etiquetas": {}}}
        self.assertEqual(L.hijos_ajenos([f"docker-{ID_API}.scope", ID_K6], conocidos), [])
        self.assertEqual(L.hijos_ajenos([ID_API, "f" * 64], conocidos), ["ajeno"])
        # Un hijo cuyo id no se conoce también es ajeno.
        self.assertEqual(L.hijos_ajenos(["init.scope"], conocidos), ["init.scope"])
        # Un cgroup sin id y sin procesos (buildkit sin construir) no es ajeno;
        # con procesos, o sin el dato, sí. Un contenedor ajeno con id lo es
        # siempre, tenga o no procesos.
        procesos = {"buildkit": False, "buildx": True}
        self.assertEqual(L.hijos_ajenos(["buildkit", "buildx"], conocidos, procesos), ["buildx"])
        self.assertEqual(L.hijos_ajenos(["buildkit"], conocidos), ["buildkit"])
        self.assertEqual(L.hijos_ajenos(["f" * 64], conocidos, {"f" * 64: False}), ["ajeno"])

    def test_hijos_ajenos_con_un_valor_desconocido_de_canario_estres(self):
        # Enmienda v4.3, punto 4: con las etiquetas medidas del lector (ETIQUETAS_LECTOR) y
        # otro valor de canario.estres, el hijo es ajeno (antes del cambio 3, PARADA).
        raro = {**L.etiquetas_de(ETIQUETAS_LECTOR), "canario.estres": "otro"}
        conocidos = {"f" * 64: {"nombre": "canario_estres_raro", "etiquetas": raro}}
        self.assertEqual(L.hijos_ajenos(["f" * 64], conocidos), ["canario_estres_raro"])
        # Control: las mismas etiquetas con canario.estres=lector no son ajenas.
        conocidos = {"f" * 64: {"nombre": "canario_estres_lector_3", "etiquetas": L.etiquetas_de(ETIQUETAS_LECTOR)}}
        self.assertEqual(L.hijos_ajenos(["f" * 64], conocidos), [])

    def test_etiquetas(self):
        self.assertEqual(L.etiquetas_de("a=b,canario.estres=k6,sin_valor"), {"a": "b", "canario.estres": "k6"})

    def test_los_programas_embebidos_compilan_sin_comillas_dobles(self):
        for codigo in (L.CODIGO_LECTOR, L.CODIGO_CONTROL, L.CODIGO_HASH):
            compile(codigo, "<embebido>", "exec")
            self.assertNotIn('"', codigo)


class ControlPositivo(unittest.TestCase):
    def datos_buenos(self):
        serie = [(i * 0.25, cg(anon=(i + 1) * 4 * MIB, swap=(i * MIB if i > 4 else 0), inode=1,
                               oom_kill=1 if i == 11 else 0)) for i in range(12)]
        serie += [(3.0 + i * 0.25, cg(anon=(i + 1) * 4 * MIB, inode=2, oom_kill=1 if i == 5 else 0))
                  for i in range(6)]
        muestras, encs = L.etiquetar_cgroup(serie)
        eventos = [ev("start", "c1", 0.0, clase="control"), ev("die", "c1", 3.0, clase="control", codigo="137"),
                   ev("start", "c1", 3.1, clase="control"), ev("die", "c1", 4.6, clase="control", codigo="137")]
        limites = {"memory.max": "67108864", "memory.swap.max": "67108864"}
        return encs, muestras, eventos, limites

    def test_control_completo_pasa_todo(self):
        resultado = L.evaluar_control(*self.datos_buenos(), 2)
        self.assertTrue(all(ok for ok, _ in resultado), [t for ok, t in resultado if not ok])

    def test_si_falta_algo_el_control_falla(self):
        encs, muestras, eventos, limites = self.datos_buenos()
        # Sin el segundo die 137.
        self.assertFalse(all(ok for ok, _ in L.evaluar_control(encs, muestras, eventos[:3], limites, 2)))
        # Sin reinicio (una sola encarnación y un solo start).
        _, una = L.etiquetar_cgroup([(0.0, cg(anon=MIB)), (0.25, cg(anon=2 * MIB))])
        self.assertFalse(all(ok for ok, _ in L.evaluar_control(una, muestras, eventos[:2], limites, 2)))
        # Con los límites de la API, no es el control.
        mal = {"memory.max": "268435456", "memory.swap.max": "268435456"}
        self.assertFalse(all(ok for ok, _ in L.evaluar_control(encs, muestras, eventos, mal, 2)))
        # Sin swap nunca visto.
        sin_swap = [{**m, "swap_current": 0} for m in muestras]
        self.assertFalse(all(ok for ok, _ in L.evaluar_control(encs, sin_swap, eventos, limites, 2)))

    def test_oom_solo_cuenta_por_el_padre(self):
        encs, muestras, eventos, limites = self.datos_buenos()
        # Control positivo: con 2 subidas en el padre, todo pasa.
        self.assertTrue(all(ok for ok, _ in L.evaluar_control(encs, muestras, eventos, limites, 2)))
        # Negativo: 0 subidas en el padre y 2 eventos oom de Docker (y oom_kill
        # visto en el hijo) NO bastan: el control no se ve completo.
        con_oom_docker = eventos + [ev("oom", "c1", 2.9, clase="control"), ev("oom", "c1", 4.5, clase="control")]
        resultado = L.evaluar_control(encs, muestras, con_oom_docker, limites, 0)
        self.assertFalse(all(ok for ok, _ in resultado))
        self.assertEqual([t for ok, t in resultado if not ok][0][:30], "el contador oom del cgroup pad")
        # Una sola subida tampoco basta.
        self.assertFalse(all(ok for ok, _ in L.evaluar_control(encs, muestras, eventos, limites, 1)))


IMAGEN_REF = "sha256:e830c91b8c28e06ee560d56d618113a56de4a0fed87c8e8ca02607f1b339c671"
IMAGEN_OTRA = "sha256:" + "b" * 64
IMAGEN_CADDY = "sha256:" + "c" * 64
ID_CADDY = "e" * 64


class ArgumentosArranque(unittest.TestCase):
    def test_solo_la_repeticion_1_construye(self):
        self.assertEqual(L.argumentos_arranque(1), ["up", "-d", "--build", "--wait", "api", "caddy"])
        # Control positivo del negativo: las siguientes NO llevan --build.
        self.assertEqual(L.argumentos_arranque(2), ["up", "-d", "--no-build", "--wait", "api", "caddy"])
        self.assertEqual(L.argumentos_arranque(3), ["up", "-d", "--no-build", "--wait", "api", "caddy"])

    def test_servicios_a_medida_para_hash(self):
        self.assertEqual(L.argumentos_arranque(1, ("api",)), ["up", "-d", "--build", "--wait", "api"])


class MismaImagen(unittest.TestCase):
    def test_imagen_distinta_es_parada_con_el_mensaje_literal(self):
        with self.assertRaises(L.Parada) as ctx:
            L.comprobar_misma_imagen(IMAGEN_REF, "sha256:" + "b" * 64, "api", 2)
        self.assertEqual(str(ctx.exception),
                         "la imagen de api de la repeticion 2 no es la de la repeticion 1 "
                         "(sha256:e830c91b8c28e06ee560d56d618113a56de4a0fed87c8e8ca02607f1b339c671 frente a "
                         "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)")

    def test_control_positivo_el_mismo_id_no_para(self):
        self.assertIsNone(L.comprobar_misma_imagen(IMAGEN_REF, IMAGEN_REF, "api", 2))

    def test_vacio_o_mal_formado_es_parada(self):
        for malo in ("", "e830c91b8c28e06ee560d56d618113a56de4a0fed87c8e8ca02607f1b339c671", "sha256:abc",
                     "sha256:" + "B" * 64, "sha256:" + "b" * 65, None):
            with self.assertRaises(L.Parada, msg=repr(malo)):
                L.comprobar_misma_imagen(IMAGEN_REF, malo, "caddy", 3)
        # Dos vacíos iguales tampoco dan PASA (referencia mal formada).
        with self.assertRaises(L.Parada):
            L.comprobar_misma_imagen("", "", "api", 2)
        # Control: un id bien formado y distinto de ceros pasa su formato.
        self.assertIsNone(L.comprobar_misma_imagen(IMAGEN_OTRA, IMAGEN_OTRA, "api", 2))


class OrquestacionImagen(unittest.TestCase):
    """preparar_repeticion y iniciar_lector con Docker simulado, sobre dos
    repeticiones. La parte previa al alta de la empresa se aísla en
    preparar_repeticion para no montar mocks de todo ejecutar_repeticion."""

    def montar(self, imagen_rep2, contenedor=ID_API):
        """En la repetición 2, el contenedor `contenedor` (la API por defecto)
        pasa a tener la imagen `imagen_rep2`."""
        self.llamadas_control, self.arranques, self.lineas = [], [], []
        self.lineas_arranque = []
        imagen_de = {ID_API: IMAGEN_REF, ID_CADDY: IMAGEN_CADDY}

        def ejecutar_falso(args, timeout=900):
            return L.R(0, imagen_de[args[-1]] + "\n", "")

        def arrancar_falso(servicios, cpus, linea, rep=1):
            self.arranques.append(rep)
            self.lineas_arranque.append(linea)
            if rep == 2:
                imagen_de[contenedor] = imagen_rep2

        ids = {"api": ID_API, "caddy": ID_CADDY, "postgres": ID_PG, "redis": "f" * 64}
        parches = [mock.patch.object(L, "ejecutar", ejecutar_falso), mock.patch.object(L, "arrancar", arrancar_falso),
                   mock.patch.object(L, "ids_servicios", lambda: dict(ids)),
                   mock.patch.object(L, "bajar_pila", lambda ej: None),
                   mock.patch.object(L, "comprobar_postgres_args", lambda ej: None),
                   mock.patch.object(L, "ejecutar_control",
                                     lambda ej, etapa: self.llamadas_control.append((etapa, ej.imagen)) or True),
                   mock.patch.object(L, "p", self.lineas.append),
                   mock.patch.dict(L.estado, {"falla": False, "sin_conclusion": False})]
        for parche in parches:
            parche.start()
            self.addCleanup(parche.stop)
        return L.Ejecucion(0.05, None, pathlib.Path("."), [0], [1], {}, linea_limites=LINEA_PRODUCCION_LITERAL)

    def test_control_inicial_una_sola_vez_y_misma_imagen_pasa(self):
        ej = self.montar(IMAGEN_REF)
        L.preparar_repeticion(ej, 1)
        L.preparar_repeticion(ej, 2)
        self.assertEqual(self.llamadas_control, [("inicial", IMAGEN_REF)])
        self.assertEqual(self.arranques, [1, 2])
        # La línea de límites de la ejecución llega a arrancar en las dos
        # repeticiones. El oráculo es el literal de producción, no ej.linea_limites
        # (que saldría del propio objeto) y distinto de L.LINEA_LIMITES.
        self.assertNotEqual(LINEA_PRODUCCION_LITERAL, L.LINEA_LIMITES)
        self.assertEqual(self.lineas_arranque, [LINEA_PRODUCCION_LITERAL, LINEA_PRODUCCION_LITERAL])
        self.assertIn("PASA  repeticion 2: misma imagen que la repeticion 1 en api (" + IMAGEN_REF + ") y caddy ("
                      + IMAGEN_CADDY + ")", self.lineas)
        self.assertIn("   repeticion 1: imagenes de referencia, api " + IMAGEN_REF + " y caddy " + IMAGEN_CADDY,
                      self.lineas)
        self.assertEqual(ej.imagen, IMAGEN_REF)

    def test_imagen_de_la_api_distinta_en_la_2_da_parada(self):
        # Que esta PARADA llega antes de cualquier lector lo da el orden de
        # ejecutar_repeticion (preparar_repeticion va antes de las rutas), no
        # esta prueba: aquí se comprueba la PARADA y su mensaje.
        ej = self.montar(IMAGEN_OTRA)
        L.preparar_repeticion(ej, 1)
        with self.assertRaises(L.Parada) as ctx:
            L.preparar_repeticion(ej, 2)
        self.assertEqual(str(ctx.exception),
                         "la imagen de api de la repeticion 2 no es la de la repeticion 1 ("
                         + IMAGEN_REF + " frente a " + IMAGEN_OTRA + ")")
        self.assertEqual(self.llamadas_control, [("inicial", IMAGEN_REF)])
        self.assertFalse(L.estado["falla"])

    def test_imagen_de_caddy_distinta_en_la_2_da_parada(self):
        # Negativo de caddy con la API igual; su control positivo es la
        # repetición 1 de esta misma prueba, que pasa sin PARADA.
        ej = self.montar(IMAGEN_OTRA, contenedor=ID_CADDY)
        L.preparar_repeticion(ej, 1)
        self.assertEqual(ej.imagenes, {"api": IMAGEN_REF, "caddy": IMAGEN_CADDY})
        with self.assertRaises(L.Parada) as ctx:
            L.preparar_repeticion(ej, 2)
        self.assertEqual(str(ctx.exception),
                         "la imagen de caddy de la repeticion 2 no es la de la repeticion 1 ("
                         + IMAGEN_CADDY + " frente a " + IMAGEN_OTRA + ")")

    def test_id_mal_formado_en_la_1_da_parada(self):
        # Control positivo: test_control_inicial_una_sola_vez_y_misma_imagen_pasa.
        ej = self.montar(IMAGEN_REF)
        with mock.patch.object(L, "ejecutar", lambda args, timeout=900: L.R(0, "\n", "")):
            with self.assertRaises(L.Parada) as ctx:
                L.preparar_repeticion(ej, 1)
        self.assertIn("no se obtiene un id de imagen sha256:<64 hex> de api en la repeticion 1", str(ctx.exception))
        self.assertEqual(self.llamadas_control, [])

    def test_control_con_el_mismo_id_el_lector_recibe_ese_id(self):
        ej = self.montar(IMAGEN_REF)
        L.preparar_repeticion(ej, 1)
        L.preparar_repeticion(ej, 2)
        with mock.patch.object(L, "Lector", side_effect=RuntimeError("parada del montaje")) as lector:
            with self.assertRaises(RuntimeError):
                L.iniciar_lector(ej, "login")
        self.assertEqual(lector.call_args[0][0], IMAGEN_REF)


class PuntosDeArranque(unittest.TestCase):
    """Que todo punto que arranca la pila de una repetición pasa por
    preparar_repeticion (y con él por argumentos_arranque y comprobar_imagenes).
    Es una prueba de texto del código: una estructura nueva que arrancara la
    pila por su cuenta con --build la haría fallar."""

    def test_l1_y_fases_arrancan_por_preparar_repeticion(self):
        import inspect
        for funcion in (L.ejecutar_repeticion, L.ejecutar_repeticion_fases):
            fuente = inspect.getsource(funcion)
            self.assertIn("preparar_repeticion(ej, rep)", fuente, funcion.__name__)
            self.assertNotIn("arrancar(", fuente, funcion.__name__)
            self.assertNotIn("ej.imagen is None", fuente, funcion.__name__)
        # Control positivo: preparar_repeticion sí arranca y comprueba imágenes.
        fuente = inspect.getsource(L.preparar_repeticion)
        self.assertIn("arrancar((", fuente)
        self.assertIn("comprobar_imagenes(ej, rep)", fuente)

    def test_recrear_api_no_construye(self):
        import inspect
        self.assertNotIn("--build", inspect.getsource(L.recrear_api))
        # Control positivo: el arranque de la repetición 1 sí construye.
        self.assertIn("--build", L.argumentos_arranque(1))


# Línea de límites de PRODUCCIÓN como literal (la de app/limitador.py por
# defecto, con el prefijo de la API). Es DISTINTA de L.LINEA_LIMITES: si el
# código sustituyera la de la ejecución por la constante de estrés, las
# pruebas que comparan contra este literal lo verían. No se deriva de L.
LINEA_PRODUCCION_LITERAL = ("INFO canario.arranque: LIMITES (por defecto): acceso=10/300 cuenta=60/60 "
                            "denuncia=10/3600 destinatario=3/900 destinatario_dia=10/86400 mensajes=30/3600 "
                            "otras=60/60 registro=10/3600 seguimiento=60/60")
ARGUMENTOS_INSPECT_API_NUEVO = ["docker", "inspect", "--format", "{{.Image}}", "b" * 64]


class ArgumentosRecreacion(unittest.TestCase):
    def test_la_recreacion_no_construye(self):
        self.assertEqual(L.argumentos_recreacion(),
                         ["up", "-d", "--force-recreate", "--no-deps", "--no-build", "--wait",
                          "--wait-timeout", "90", "api"])
        self.assertNotIn("--build", L.argumentos_recreacion())
        # Control positivo: el arranque de la repetición 1 sí lleva --build,
        # así que el assertNotIn de arriba sabe ver la opción.
        self.assertIn("--build", L.argumentos_arranque(1))

    def test_la_espera_de_salud_cabe_en_el_plazo_con_30_s_de_holgura(self):
        # Oráculos literales: 90 s de --wait-timeout y 120 s de plazo del
        # subprocess. Los 30 s de diferencia son los 10 s del stop de la API
        # vieja y los 20 s de borrarla y crear la nueva, que compose no cronometra.
        self.assertEqual(L.ESPERA_SALUD_RECREAR_S, 90)
        self.assertEqual(L.MARGEN_RECREAR_API_S, 120)
        self.assertTrue(90 <= 120 - 30)
        # Control: el valor que va en los argumentos es el mismo de la constante
        # (y no un 90 que se desincronice de ella).
        argumentos = L.argumentos_recreacion()
        self.assertEqual(argumentos[argumentos.index("--wait-timeout") + 1], "90")


class MismaImagenConRuta(unittest.TestCase):
    """Los dos mensajes con `etiqueta`. El control (sin `etiqueta`, los de
    siempre) son las pruebas de MismaImagen, que no cambian."""

    def test_imagen_distinta_con_ruta(self):
        with self.assertRaises(L.Parada) as ctx:
            L.comprobar_misma_imagen(IMAGEN_REF, IMAGEN_OTRA, "api", 2, etiqueta="login_empresa")
        self.assertEqual(str(ctx.exception),
                         "la imagen de api de la API recreada para login_empresa (repeticion 2) no es la de la "
                         "repeticion 1 (sha256:e830c91b8c28e06ee560d56d618113a56de4a0fed87c8e8ca02607f1b339c671 "
                         "frente a sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)")

    def test_formato_con_ruta(self):
        with self.assertRaises(L.Parada) as ctx:
            L.comprobar_misma_imagen(IMAGEN_REF, "", "api", 3, etiqueta="denuncia")
        self.assertEqual(str(ctx.exception),
                         "no se obtiene un id de imagen sha256:<64 hex> de api en la API recreada para denuncia "
                         "(repeticion 3): ''")

    def test_control_con_ruta_y_misma_imagen_no_para(self):
        self.assertIsNone(L.comprobar_misma_imagen(IMAGEN_REF, IMAGEN_REF, "api", 2, etiqueta="login_empresa"))


class RecrearApi(unittest.TestCase):
    """recrear_api con Docker simulado. Cada negativo parte del montaje del
    control y cambia una sola cosa."""

    def montar(self, imagen_nueva=IMAGEN_REF, inspect=None):
        """`imagen_nueva` es la imagen del contenedor nuevo de la API;
        `inspect`, si se da, sustituye la respuesta del docker inspect."""
        self.llamadas_dc, self.inspecciones, self.limites, self.lineas = [], [], [], []
        # Orden de las horas del motor y del up: la ventana de mantenimiento
        # tiene que abrirse antes del up y cerrarse después.
        self.orden = []
        horas = iter([100.0, 101.0])
        imagen_de = {ID_API_NUEVO: imagen_nueva}

        def hora_falsa():
            hora = next(horas)
            self.orden.append(("hora", hora))
            return hora

        def ejecutar_falso(args, timeout=900):
            # Registra el plazo: el inspect tiene que llevar el suyo de 60 s.
            self.inspecciones.append((list(args), timeout))
            if inspect is not None:
                return inspect()
            # Un id desconocido (el contenedor viejo, por ejemplo) da KeyError.
            return L.R(0, imagen_de[args[-1]] + "\n", "")

        def dc_falso(*args, timeout=900):
            self.llamadas_dc.append((list(args), timeout))
            self.orden.append(("dc",))
            return L.R(0, "", "")

        ids = {"api": ID_API_NUEVO, "caddy": ID_CADDY, "postgres": ID_PG, "redis": "f" * 64}
        self.misma = mock.MagicMock(wraps=L.comprobar_misma_imagen)
        parches = [mock.patch.object(L, "ejecutar", ejecutar_falso), mock.patch.object(L, "dc", dc_falso),
                   mock.patch.object(L, "ids_servicios", lambda: dict(ids)),
                   mock.patch.object(L, "comprobar_limites_api",
                                     lambda ident, linea: self.limites.append((ident, linea))),
                   mock.patch.object(L, "hora_motor_ahora", hora_falsa),
                   mock.patch.object(L, "comprobar_misma_imagen", self.misma),
                   mock.patch.object(L, "p", self.lineas.append),
                   mock.patch.dict(L.estado, {"falla": False, "sin_conclusion": False})]
        for parche in parches:
            parche.start()
            self.addCleanup(parche.stop)
        ej = L.Ejecucion(0.05, None, pathlib.Path("."), [0], [1], {}, linea_limites=LINEA_PRODUCCION_LITERAL)
        ej.ids = {"api": ID_API, "caddy": ID_CADDY, "postgres": ID_PG, "redis": "f" * 64}
        ej.imagenes = {"api": IMAGEN_REF, "caddy": IMAGEN_CADDY}
        return ej

    def test_control_misma_imagen(self):
        ej = self.montar()
        L.recrear_api(ej, 2, etiqueta="login_empresa")
        # D1: oráculo con literales, plazo de 120 s para el subprocess y
        # --wait-timeout de 90 s para la espera de salud de compose.
        self.assertEqual(self.llamadas_dc,
                         [(["up", "-d", "--force-recreate", "--no-deps", "--no-build", "--wait",
                            "--wait-timeout", "90", "api"], 120)])
        self.assertIn("up -d --force-recreate --no-deps --no-build --wait --wait-timeout 90 api -> codigo 0",
                      self.lineas)
        self.assertEqual(self.inspecciones, [(ARGUMENTOS_INSPECT_API_NUEVO, 60)])
        self.assertIn("PASA  repeticion 2, login_empresa: la API recreada tiene la imagen de la repeticion 1 "
                      "(sha256:e830c91b8c28e06ee560d56d618113a56de4a0fed87c8e8ca02607f1b339c671)", self.lineas)
        self.assertEqual(ej.ids["api"], ID_API_NUEVO)
        # La línea que recibe la comprobación es la de la ejecución (literal de
        # producción), no la de estrés.
        self.assertEqual(self.limites, [(ID_API_NUEVO, LINEA_PRODUCCION_LITERAL)])
        self.assertEqual(ej.mantenimientos[-1]["desde"], 100.0)
        self.assertEqual(ej.mantenimientos[-1]["hasta"], 101.0)
        self.assertEqual(ej.mantenimientos[-1]["ids"], frozenset([ID_API]))
        # La ventana se abre antes del up y se cierra después (mata mover
        # "hasta" delante del up, que los valores 100.0 y 101.0 no ven).
        self.assertEqual(self.orden, [("hora", 100.0), ("dc",), ("hora", 101.0)])
        self.misma.assert_called_once_with(IMAGEN_REF, IMAGEN_REF, "api", 2, etiqueta="login_empresa")
        self.assertFalse(L.estado["falla"])

    def test_imagen_distinta_da_parada(self):
        ej = self.montar(imagen_nueva=IMAGEN_OTRA)
        with self.assertRaises(L.Parada) as ctx:
            L.recrear_api(ej, 2, etiqueta="login_empresa")
        self.assertEqual(str(ctx.exception),
                         "la imagen de api de la API recreada para login_empresa (repeticion 2) no es la de la "
                         "repeticion 1 (sha256:e830c91b8c28e06ee560d56d618113a56de4a0fed87c8e8ca02607f1b339c671 "
                         "frente a sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)")
        # El estado refleja el contenedor real aunque haya PARADA.
        self.assertEqual(ej.ids["api"], ID_API_NUEVO)
        self.assertEqual(ej.mantenimientos[-1]["hasta"], 101.0)
        self.assertEqual(self.limites, [])
        self.assertFalse([linea for linea in self.lineas if linea.startswith("PASA  repeticion")])

    def test_sin_imagen_de_referencia_da_parada(self):
        ej = self.montar()
        ej.imagenes = None
        with self.assertRaises(L.Parada) as ctx:
            L.recrear_api(ej, 2, etiqueta="login_empresa")
        self.assertEqual(str(ctx.exception), "la API se recrea sin la imagen de referencia de la repeticion 1")
        self.assertEqual(self.llamadas_dc, [])
        self.assertEqual(ej.mantenimientos, [])

    def test_inspect_con_codigo_1_da_parada_con_la_cola_del_stderr(self):
        # 100 "C" y 300 "D" con salto final: la PARADA lleva solo los 300
        # ÚLTIMOS caracteres tras el strip, que son las "D".
        ej = self.montar(inspect=lambda: L.R(1, "", "C" * 100 + "D" * 300 + "\n"))
        with self.assertRaises(L.Parada) as ctx:
            L.recrear_api(ej, 2, etiqueta="login_empresa")
        self.assertEqual(str(ctx.exception),
                         "docker inspect de la API recreada para login_empresa (repeticion 2) falla (codigo 1): '"
                         + "D" * 300 + "'")
        self.misma.assert_not_called()
        self.assertEqual(self.limites, [])

    def test_inspect_que_no_responde_da_parada(self):
        # Solo el inspect lanza TimeoutExpired; el up (dc) responde con 0.
        # Control: test_control_misma_imagen, con el plazo de 60 s registrado.
        def colgado():
            raise subprocess.TimeoutExpired(ARGUMENTOS_INSPECT_API_NUEVO, 60)

        ej = self.montar(inspect=colgado)
        with self.assertRaises(L.Parada) as ctx:
            L.recrear_api(ej, 2, etiqueta="login_empresa")
        self.assertEqual(str(ctx.exception),
                         "docker inspect de la API recreada para login_empresa (repeticion 2) no responde en 60 s")
        self.assertEqual(self.inspecciones, [(ARGUMENTOS_INSPECT_API_NUEVO, 60)])
        self.misma.assert_not_called()


class ComprobarImagenesInspect(unittest.TestCase):
    """PY-2: comprobar_imagenes ya no descarta el código ni el stderr de
    docker inspect, y le da su plazo de 60 s."""

    def montar(self, respuesta):
        self.inspecciones, self.lineas = [], []

        def ejecutar_falso(args, timeout=900):
            self.inspecciones.append((list(args), timeout))
            return respuesta(args)

        parches = [mock.patch.object(L, "ejecutar", ejecutar_falso),
                   mock.patch.object(L, "p", self.lineas.append)]
        for parche in parches:
            parche.start()
            self.addCleanup(parche.stop)
        ej = L.Ejecucion(0.05, None, pathlib.Path("."), [0], [1], {})
        ej.ids = {"api": ID_API, "caddy": ID_CADDY, "postgres": ID_PG, "redis": "f" * 64}
        return ej

    def test_control_codigo_0_con_plazo_de_60_s(self):
        imagen_de = {ID_API: IMAGEN_REF, ID_CADDY: IMAGEN_CADDY}
        ej = self.montar(lambda args: L.R(0, imagen_de[args[-1]] + "\n", ""))
        L.comprobar_imagenes(ej, 1)
        self.assertEqual(self.inspecciones,
                         [(["docker", "inspect", "--format", "{{.Image}}", "a" * 64], 60),
                          (["docker", "inspect", "--format", "{{.Image}}", "e" * 64], 60)])
        self.assertEqual(ej.imagenes, {"api": IMAGEN_REF, "caddy": IMAGEN_CADDY})

    def test_inspect_con_codigo_1_da_parada(self):
        # Control: test_control_codigo_0_con_plazo_de_60_s y
        # OrquestacionImagen.test_id_mal_formado_en_la_1_da_parada (rc 0).
        ej = self.montar(lambda args: L.R(1, "", "Error: No such object: aaaa\n"))
        with self.assertRaises(L.Parada) as ctx:
            L.comprobar_imagenes(ej, 1)
        self.assertEqual(str(ctx.exception),
                         "docker inspect de api en la repeticion 1 falla (codigo 1): 'Error: No such object: aaaa'")
        self.assertIsNone(ej.imagenes)


class ConexionRecrearApi(unittest.TestCase):
    """ejecutar_ruta llama a recrear_api con la repetición y la ruta (como
    `etiqueta`), ANTES del lector de la ruta."""

    def lanzar(self, n_ruta):
        orden = []

        class Centinela(Exception):
            pass

        def lector_falso(ej, nombre):
            orden.append(("lector", nombre))
            raise Centinela

        # create_autospec: el doble tiene la firma REAL de recrear_api
        # (ej, rep, *, etiqueta). Con un lambda de *args, la firma vieja y la
        # nueva pasaban igual y la llamada rota de L3 y L3b no se veía.
        self.recrear = mock.create_autospec(L.recrear_api, side_effect=lambda *args, **kwargs: orden.append("recrear"))
        parches = [mock.patch.object(L, "recrear_api", self.recrear),
                   mock.patch.object(L, "iniciar_lector", lector_falso),
                   mock.patch.object(L, "p")]
        for parche in parches:
            parche.start()
            self.addCleanup(parche.stop)
        ej = L.Ejecucion(0.05, None, pathlib.Path("."), [0], [1], {"login_empresa": []})
        with self.assertRaises(Centinela):
            L.ejecutar_ruta(ej, 2, "login_empresa", n_ruta, False, {"salida": pathlib.Path(".")})
        return ej, orden

    def test_recrear_api_antes_del_lector(self):
        ej, orden = self.lanzar(1)
        self.assertEqual(orden, ["recrear", ("lector", "rep2_login_empresa")])
        # La llamada literal: repetición 2 y la ruta como `etiqueta`.
        self.assertEqual(self.recrear.call_args_list, [mock.call(ej, 2, etiqueta="login_empresa")])

    def test_control_primera_ruta_no_recrea(self):
        _, orden = self.lanzar(0)
        self.assertEqual(orden, [("lector", "rep2_login_empresa")])
        self.recrear.assert_not_called()


class SandwichJ5ConRecrearApiReal(unittest.TestCase):
    """sandwich_j5 con la recrear_api REAL y Docker simulado, con `ejecutar`
    como en RecrearApi.montar. Los dobles de ControlesConMocks y
    EstimacionDeTiempo sustituyen recrear_api por un autospec y prueban el
    orden; aquí se prueba que la llamada real desde el sandwich es válida y
    que sus textos y PARADAS llevan "J5". Cada negativo se compara con el
    control positivo (`correr()` sin cambios)."""
    POSITIVO = {"estado": 429, "inicio": 1795342203.0, "fin": 1795342203.1}
    NEGATIVO = {"estado": 401, "inicio": 1795342213.0, "fin": 1795342213.1}
    ARGUMENTOS_UP = ["up", "-d", "--force-recreate", "--no-deps", "--no-build", "--wait",
                     "--wait-timeout", "90", "api"]
    LINEA_MEDIDA_OK = "recrear_api: 2.5 s (plazo 120 s, espera de salud 90 s)"

    @contextlib.contextmanager
    def entorno(self, imagen_nueva=IMAGEN_REF, dc_efecto=None, con_referencia=True, monotonic=(10.0, 12.5)):
        """`dc_efecto(timeout)` sustituye la respuesta del up (devuelve un L.R
        o lanza); `monotonic` son los dos instantes (antes y después del up)."""
        e = types.SimpleNamespace(orden=[], lineas=[], controles=[], llamadas_dc=[], fallos=None, parada=None)
        horas = iter([100.0, 101.0])
        instantes = iter(monotonic)
        imagen_de = {ID_API_NUEVO: imagen_nueva}

        def hora_falsa():
            hora = next(horas)
            e.orden.append(("hora", hora))
            return hora

        def ejecutar_falso(args, timeout=900):
            # Solo el docker inspect de leer_imagen llega aquí: el up va por dc.
            return L.R(0, imagen_de[args[-1]] + "\n", "")

        def dc_falso(*args, timeout=900):
            e.llamadas_dc.append((list(args), timeout))
            e.orden.append(("dc",))
            return L.R(0, "", "") if dc_efecto is None else dc_efecto(timeout)

        def cliente_falso(ej, nombre, ip, peticiones):
            e.orden.append(nombre)
            return [dict(self.POSITIVO if nombre == "j5pos_r2" else self.NEGATIVO)]

        ids = {"api": ID_API_NUEVO, "caddy": ID_CADDY, "postgres": ID_PG, "redis": "f" * 64}
        # Los espías se crean ANTES de parchear: envuelven las funciones reales.
        e.misma = mock.MagicMock(wraps=L.comprobar_misma_imagen)
        e.leer = mock.MagicMock(wraps=L.leer_imagen)
        # time solo se sustituye en el espacio de nombres de lanzar: monotonic con
        # los valores fijos de la prueba y time() constante para la línea del sandwich.
        reloj = types.SimpleNamespace(time=lambda: 1000.0, monotonic=lambda: next(instantes))
        parches = [mock.patch.object(L, "ejecutar", ejecutar_falso), mock.patch.object(L, "dc", dc_falso),
                   mock.patch.object(L, "ids_servicios", lambda: dict(ids)),
                   mock.patch.object(L, "comprobar_limites_api", lambda ident, linea: None),
                   mock.patch.object(L, "hora_motor_ahora", hora_falsa),
                   mock.patch.object(L, "comprobar_misma_imagen", e.misma),
                   mock.patch.object(L, "leer_imagen", e.leer),
                   mock.patch.object(L, "cliente_control", cliente_falso),
                   mock.patch.object(L, "esperar_ventana", lambda *a: None),
                   mock.patch.object(L, "linea_control", lambda veredicto, texto: e.controles.append((veredicto, texto))),
                   mock.patch.object(L, "p", e.lineas.append),
                   mock.patch.object(L, "time", reloj),
                   mock.patch.dict(L.estado, {"falla": False, "sin_conclusion": False})]
        ej = L.Ejecucion(0.05, None, pathlib.Path("."), [0], [1], {}, linea_limites=LINEA_PRODUCCION_LITERAL)
        ej.ids = {"api": ID_API, "caddy": ID_CADDY, "postgres": ID_PG, "redis": "f" * 64}
        ej.imagenes = {"api": IMAGEN_REF, "caddy": IMAGEN_CADDY} if con_referencia else None
        ej.id_a, ej.contrasena = "a" * 32, "x"
        e.ej = ej
        with contextlib.ExitStack() as pila:
            for parche in parches:
                pila.enter_context(parche)
            yield e

    def correr(self, **cambios):
        """sandwich_j5 (L3, repetición 2) con la recrear_api real. Devuelve el
        estado del montaje con `fallos` o con el texto de la `parada`."""
        with self.entorno(**cambios) as e:
            try:
                e.fallos = L.sandwich_j5(e.ej, "l3", 2, {})
            except L.Parada as parada:
                e.parada = str(parada)
        return e

    def test_j5_control_positivo_con_la_recrear_api_real(self):
        e = self.correr()
        self.assertIsNone(e.parada)
        self.assertEqual(e.fallos, [])
        # Orden literal: positivo, ventana abierta, up, ventana cerrada, negativo.
        self.assertEqual(e.orden, ["j5pos_r2", ("hora", 100.0), ("dc",), ("hora", 101.0), "j5neg_r2"])
        self.assertEqual(e.llamadas_dc, [(self.ARGUMENTOS_UP, 120)])
        mantenimiento = e.ej.mantenimientos[-1]
        self.assertEqual((mantenimiento["desde"], mantenimiento["hasta"], mantenimiento["ids"]),
                         (100.0, 101.0, frozenset([ID_API])))
        self.assertEqual(e.ej.ids["api"], ID_API_NUEVO)
        # Los textos de leer_imagen y de pasa llevan "J5".
        e.leer.assert_called_once_with(ID_API_NUEVO, "la API recreada para J5 (repeticion 2)")
        e.misma.assert_called_once_with(IMAGEN_REF, IMAGEN_REF, "api", 2, etiqueta="J5")
        self.assertIn("PASA  repeticion 2, J5: la API recreada tiene la imagen de la repeticion 1 "
                      "(sha256:e830c91b8c28e06ee560d56d618113a56de4a0fed87c8e8ca02607f1b339c671)", e.lineas)
        self.assertIn(self.LINEA_MEDIDA_OK, e.lineas)
        self.assertEqual(e.controles, [("PASA", "J5: 429 antes de recrear y 401 despues, en la misma ventana")])

    def test_j5_imagen_distinta_es_parada_con_el_mensaje_completo(self):
        e = self.correr(imagen_nueva=IMAGEN_OTRA)
        self.assertEqual(e.parada,
                         "la imagen de api de la API recreada para J5 (repeticion 2) no es la de la "
                         "repeticion 1 (sha256:e830c91b8c28e06ee560d56d618113a56de4a0fed87c8e8ca02607f1b339c671 "
                         "frente a sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)")
        # El negativo no llega a lanzarse con una API de otra imagen.
        self.assertEqual(e.orden, ["j5pos_r2", ("hora", 100.0), ("dc",), ("hora", 101.0)])
        # Control: con la misma imagen no hay PARADA (test anterior, repetido aquí
        # para que esta prueba no dependa del orden de ejecución).
        self.assertIsNone(self.correr().parada)

    def test_j5_sin_imagen_de_referencia_es_parada_literal(self):
        e = self.correr(con_referencia=False)
        self.assertEqual(e.parada, "la API se recrea sin la imagen de referencia de la repeticion 1")
        # PARADA antes de abrir la ventana y antes del up: ni mantenimiento ni dc ni medida.
        self.assertEqual(e.orden, ["j5pos_r2"])
        self.assertEqual(e.ej.mantenimientos, [])
        self.assertEqual(e.llamadas_dc, [])
        self.assertEqual([x for x in e.lineas if x.startswith("recrear_api:")], [])
        # Control: con referencia, la misma ejecución no para.
        self.assertIsNone(self.correr().parada)

    def test_j5_dc_que_vence_el_plazo_es_parada_y_deja_la_medida(self):
        def vence(timeout):
            raise subprocess.TimeoutExpired(["docker", "compose"], timeout)

        # M2: time.monotonic con valores fijos y la línea entera comparada como literal.
        e = self.correr(dc_efecto=vence, monotonic=(10.0, 130.0))
        self.assertEqual(e.parada, "la API no se recrea en 120 s (plazo del lanzador)")
        self.assertEqual(e.llamadas_dc, [(self.ARGUMENTOS_UP, 120)])
        self.assertIn("recrear_api: 120.0 s (plazo 120 s, espera de salud 90 s)", e.lineas)
        # No se llama a hora_motor_ahora dentro del finally ni después: una sola
        # hora (la apertura de la ventana) y ningún negativo.
        self.assertEqual(e.orden, ["j5pos_r2", ("hora", 100.0), ("dc",)])
        # Control: con rc=0 y los mismos instantes no hay PARADA; la PARADA viene del plazo.
        control = self.correr(monotonic=(10.0, 130.0))
        self.assertIsNone(control.parada)
        self.assertIn("recrear_api: 120.0 s (plazo 120 s, espera de salud 90 s)", control.lineas)

    def test_j5_dc_con_codigo_1_es_parada_y_deja_la_medida(self):
        e = self.correr(dc_efecto=lambda timeout: L.R(1, "", "fallo de compose\n"), monotonic=(10.0, 11.5))
        self.assertEqual(e.parada, "no se recrea la API: 'fallo de compose'")
        self.assertIn("recrear_api: 1.5 s (plazo 120 s, espera de salud 90 s)", e.lineas)
        self.assertIn("up -d --force-recreate --no-deps --no-build --wait --wait-timeout 90 api -> codigo 1", e.lineas)
        # La ventana de mantenimiento se cierra aunque el código no sea 0.
        self.assertEqual(e.ej.mantenimientos[-1]["hasta"], 101.0)
        # Control: con rc=0, sin PARADA.
        self.assertIsNone(self.correr(monotonic=(10.0, 11.5)).parada)


class FalsoProceso:
    def __init__(self, codigo, salida=b""):
        self.returncode = codigo
        self.stdout = io.BytesIO(salida)
        self._codigo = codigo

    def poll(self):
        return self._codigo


class LectorSinInicio(unittest.TestCase):
    """PY-2: la PARADA del lector da su causa y no espera los 60 s."""

    def lanzar(self, proceso, err=b""):
        def popen_falso(args, stdout, stderr, creationflags):
            stderr.write(err)
            stderr.flush()
            return proceso

        carpeta = tempfile.TemporaryDirectory()
        self.addCleanup(carpeta.cleanup)
        parches = [mock.patch.object(L.subprocess, "Popen", popen_falso), mock.patch.object(L, "parar_proceso"),
                   mock.patch.object(L, "ejecutar")]
        for parche in parches:
            parche.start()
            self.addCleanup(parche.stop)
        ej = L.Ejecucion(0.05, None, pathlib.Path(carpeta.name), [0], [1], {})
        ej.imagen = IMAGEN_REF
        ej.ids = {s: "a" * 64 for s in L.SERVICIOS_PILA}
        return ej

    def test_proceso_terminado_da_codigo_y_cola_del_err_sin_esperar_60_s(self):
        err = (b"x" * 500) + b"Unable to find image\nError response from daemon: No such image: " + b"sha256:e830\n"
        ej = self.lanzar(FalsoProceso(125), err)
        inicio = time.monotonic()
        with self.assertRaises(L.Parada) as ctx:
            L.iniciar_lector(ej, "login")
        self.assertLess(time.monotonic() - inicio, 10)
        texto = str(ctx.exception)
        self.assertIn("125", texto)
        self.assertIn("No such image", texto)
        self.assertTrue(texto.startswith("el lector de cgroup no da su linea de inicio"))
        # La cola son unos 300 caracteres, no el fichero entero.
        self.assertNotIn("x" * 400, texto)

    def test_control_positivo_proceso_vivo_con_inicio_si_lo_da(self):
        linea = json.dumps({"tipo": "inicio", "rutas": {}}).encode() + b"\n"
        proceso = FalsoProceso(None, linea)
        ej = self.lanzar(proceso)
        lector = L.Lector(ej.imagen, {"api": ej.ids["api"]}, "1", 10, ej.salida / "ok.err")
        self.addCleanup(lector.err.close)
        self.assertTrue(lector.esperar("inicio", 5))

    def test_mensaje_puro(self):
        self.assertEqual(L.mensaje_lector_sin_inicio(125, "No such image"),
                         "el lector de cgroup no da su linea de inicio (codigo de salida 125; cola del .err: "
                         "'No such image')")
        # Control: con el proceso vivo no inventa un código.
        self.assertEqual(L.mensaje_lector_sin_inicio(None, ""),
                         "el lector de cgroup no da su linea de inicio (el proceso sigue en marcha; cola del .err: "
                         "'')")


class LiteralesArgon2(unittest.TestCase):
    def cuenta(self, texto):
        return [len(patron.findall(texto)) for patron in L.LITERALES_ARGON2]

    def test_personal_py_real_tiene_los_literales(self):
        texto = (pathlib.Path(__file__).resolve().parents[2] / "app" / "personal.py").read_text(encoding="utf-8")
        self.assertEqual(self.cuenta(texto), [1] * len(L.LITERALES_ARGON2))

    def test_un_valor_distinto_se_detecta(self):
        base = ("MEMORIA_ARGON2_KIB = 19456\nHASHES_SIMULTANEOS = 2\nITERACIONES_ARGON2 = 2\nPARALELISMO_ARGON2 = 1\n"
                "_hasher = PasswordHasher(time_cost=ITERACIONES_ARGON2, memory_cost=MEMORIA_ARGON2_KIB, "
                "parallelism=PARALELISMO_ARGON2, hash_len=32, salt_len=16, type=Type.ID)\n")
        self.assertEqual(self.cuenta(base), [1] * len(L.LITERALES_ARGON2))
        for viejo, nuevo in (("HASHES_SIMULTANEOS = 2", "HASHES_SIMULTANEOS = 3"),
                             ("MEMORIA_ARGON2_KIB = 19456", "MEMORIA_ARGON2_KIB = 65536")):
            self.assertNotEqual(self.cuenta(base.replace(viejo, nuevo)), [1] * len(L.LITERALES_ARGON2))


# ---------------------------------------------------------------------------
# L2, L3, L3b y L4. Los oráculos son literales de la segunda congelación
# (docs/informe-pruebas.md y sus erratas E1-E13), no derivados del código que se
# prueba. Cada comprobación negativa lleva su control positivo.
# ---------------------------------------------------------------------------
import csv as _csv  # noqa: E402
import tempfile  # noqa: E402


class Tasas(unittest.TestCase):
    def test_tasas_congeladas(self):
        self.assertEqual(L.tasas_de(0.0196), {"inundacion": 153.06, "login_pico": 102.04, "login_base": 10.2})
        # Control: otra t da otras tasas (la función no devuelve un literal).
        self.assertNotEqual(L.tasas_de(0.02)["login_pico"], 102.04)

    def test_n_de_ips_y_rangos_de_victimas(self):
        self.assertEqual(L.n_ips_ataque(102.04), 3402)
        self.assertEqual(L.ips_necesarias(5, 570, 10, 3600), 428)
        self.assertEqual(L.ips_necesarias(5, 570, 60, 60), 8)

    def test_tramo_con_decimales_va_por_100_s(self):
        self.assertEqual(L.tramo(153.06, 120, 150, 600), {"rate": 15306, "time_unit_s": 100, "duracion_s": 120,
                                                           "inicio_s": 150, "vus": 600})
        self.assertEqual(L.tramo(5, 390, 0, 50)["rate"], 5)
        self.assertEqual(L.tramo(10.2, 30, 0, 32)["rate"], 1020)

    def test_literales_de_produccion(self):
        self.assertEqual(
            L.LINEA_LIMITES_PRODUCCION,
            "INFO canario.arranque: LIMITES (por defecto): acceso=10/300 cuenta=60/60 denuncia=10/3600 "
            "destinatario=3/900 destinatario_dia=10/86400 mensajes=30/3600 otras=60/60 registro=10/3600 "
            "seguimiento=60/60")
        raiz = pathlib.Path(__file__).resolve().parents[2]
        texto = (raiz / "tests" / "security" / "verificar_denuncia.py").read_text(encoding="utf-8")
        self.assertIn("LIMITES (por defecto): acceso=10/300 cuenta=60/60 denuncia=10/3600 destinatario=3/900 ", texto)

    def test_403_literal_esta_en_el_caddy(self):
        raiz = pathlib.Path(__file__).resolve().parents[2]
        comun = (raiz / "proxy" / "comun.caddy").read_text(encoding="utf-8")
        self.assertIn("respond `" + L.CUERPO_403 + "` {err.status_code}", comun)
        produccion = (raiz / "proxy" / "Caddyfile.produccion").read_text(encoding="utf-8")
        self.assertIn("not remote_ip 10.88.1.2", produccion)
        self.assertEqual(L.CUERPO_403, '{"detalle": "petición no válida"}')


class Overrides(unittest.TestCase):
    def preparar(self, **kw):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            ficheros = L.preparar_overrides(d, [2, 4], **kw)
            return [(f.name, f.read_text(encoding="utf-8")) for f in ficheros]

    def test_estres_por_defecto_como_l1(self):
        ficheros = self.preparar()
        self.assertEqual([n for n, _ in ficheros], ["limites_estres.yml", "cpuset_estres.yml"])
        self.assertIn('CANARIO_LIMITES: "denuncia=1000000/3600', ficheros[0][1])

    def test_produccion_omite_canario_limites_y_no_lo_deja_vacio(self):
        ficheros = self.preparar(limites=None, caddy_produccion=True)
        self.assertEqual([n for n, _ in ficheros], ["cpuset_estres.yml", "caddy_produccion.yml"])
        for _, texto in ficheros:
            self.assertNotIn("CANARIO_LIMITES", texto)
        caddy = ficheros[1][1]
        self.assertIn('command: ["caddy", "run", "--config", "/etc/caddy/Caddyfile.produccion", "--adapter", '
                      '"caddyfile"]', caddy)
        self.assertIn("ports: !reset []", caddy)
        self.assertIn("edge:\n    internal: true", caddy)
        # Control: sin caddy_produccion no hay override de Caddy.
        self.assertNotIn("caddy_produccion.yml", [n for n, _ in self.preparar(limites=None)])


class ComprobarLimites(unittest.TestCase):
    def comprobar(self, registro, linea=None):
        def falso(args, timeout=900):
            return L.R(0, registro if args[1] == "logs" else "0\n", "")
        with mock.patch.object(L, "ejecutar", falso), mock.patch.object(L, "p", lambda t: None), \
                mock.patch.dict(L.estado, {"falla": False, "sin_conclusion": False}):
            if linea is None:
                return L.comprobar_limites_api("x")
            return L.comprobar_limites_api("x", linea)

    def test_linea_de_produccion_y_de_estres_se_distinguen(self):
        self.assertIsNone(self.comprobar(L.LINEA_LIMITES_PRODUCCION + "\n", L.LINEA_LIMITES_PRODUCCION))
        self.assertIsNone(self.comprobar(L.LINEA_LIMITES + "\n"))
        # Negativo: la linea de estres no vale cuando se esperan los de produccion.
        with self.assertRaises(L.Parada):
            self.comprobar(L.LINEA_LIMITES + "\n", L.LINEA_LIMITES_PRODUCCION)


class Ejecutar_k6(unittest.TestCase):
    def ejecutar(self, eventos, duracion=390):
        llamadas = []
        estado_json = json.dumps({"OOMKilled": False, "StartedAt": "2026-11-22T10:00:00.0Z",
                                  "FinishedAt": "2026-11-22T10:10:00.0Z"})

        def falso(args, timeout=900):
            llamadas.append((args, timeout))
            if args[1] == "run":
                return L.R(0, "k6id\n", "")
            if args[1] == "wait":
                return L.R(0, "0\n", "")
            if args[1] == "logs":
                return L.R(0, "T0_MS=1\n", "")
            if args[1] == "inspect":
                return L.R(0, estado_json, "")
            return L.R(0, "", "")

        contexto = {"vigilados": lambda: [], "cpus_k6": "4,6", "datos": pathlib.Path("d"),
                    "eventos": types.SimpleNamespace(esperar=lambda pred, plazo: any(pred(e) for e in eventos))}
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(L, "ejecutar", falso), mock.patch.object(L, "medir_desfase", lambda: 0.0), \
                    mock.patch.object(L, "Estadisticas", lambda c, destino: types.SimpleNamespace(parar=lambda: None)), \
                    mock.patch.object(L, "p", lambda t: None):
                res = L.ejecutar_k6(contexto, "prueba", "fases.js", ["--network", "none"], duracion, pathlib.Path(d))
        return res, llamadas

    def test_devuelve_sin_conclusion_como_lista_con_el_die_ausente(self):
        solo_start = [{"id": "k6id", "accion": "start"}]
        res, _ = self.ejecutar(solo_start)
        self.assertEqual(len(res["sin_conclusion"]), 1)
        self.assertIn("die", res["sin_conclusion"][0])
        # Control positivo: con start y die, la lista esta vacia.
        res, _ = self.ejecutar(solo_start + [{"id": "k6id", "accion": "die"}])
        self.assertEqual(res["sin_conclusion"], [])

    def test_plazo_de_wait_es_duracion_mas_graceful_mas_300(self):
        _, llamadas = self.ejecutar([])
        esperas = [t for a, t in llamadas if a[1] == "wait"]
        self.assertEqual(esperas, [390 + 20 + 300])

    def test_k_plazo_real_de_docker_wait_en_l4(self):
        # Enmienda v4.3, punto 3 (prueba k): el plazo que llega a docker wait en L4, con
        # la duración que calcula ejecutar_repeticion_fases (espera 0 + duracion_total).
        # Humo posterior a los 300 s con maxDuration 90 s y gracefulStop 20 s, literales:
        # duracion_total = 300 + 90 + 20 = 410 y el plazo = 410 + 20 (GRACEFUL_STOP_S) +
        # 300 (INICIALIZACION_S) = 730. El gracefulStop cuenta dos veces (en fin_humo y
        # en el plazo): queda escrito y es hacia el lado seguro (más plazo, nunca menos).
        esc = L.escenarios_pico(L.tasas_de(0.0196))
        humo = {"nombre": "humo_posterior", "inicio_s": 300, "max_duracion_s": 90, "graceful_stop_s": 20}
        _, llamadas = self.ejecutar([], duracion=0 + L.duracion_total(esc, [humo]))
        self.assertEqual([t for a, t in llamadas if a[1] == "wait"], [730])
        # Control: con maxDuration 100 s el plazo sube a 740.
        _, llamadas = self.ejecutar([], duracion=0 + L.duracion_total(esc, [{**humo, "max_duracion_s": 100}]))
        self.assertEqual([t for a, t in llamadas if a[1] == "wait"], [740])

    def test_script_y_red_van_en_el_run(self):
        _, llamadas = self.ejecutar([])
        run = next(a for a, _ in llamadas if a[1] == "run")
        self.assertIn("/prueba/fases.js", run)
        self.assertEqual(run[run.index("--network") + 1], "none")
        self.assertIn("no-new-privileges", run)


class Ips(unittest.TestCase):
    def test_indices_literales(self):
        self.assertEqual(L.ip_de_indice(0), "198.18.0.1")
        self.assertEqual(L.ip_de_indice(253), "198.18.0.254")
        self.assertEqual(L.ip_de_indice(254), "198.18.1.1")
        self.assertEqual(L.ip_de_indice(130047), "198.19.255.254")
        self.assertEqual(L.ip_de_indice(130046), "198.19.255.253")
        with self.assertRaises(ValueError):
            L.ip_de_indice(130048)

    def test_plan_l3b_no_se_solapa_ni_toca_strict_ni_cambia_entre_repeticiones(self):
        plan = L.plan_ips("l3b", 3, 3402)
        todas = []
        for rep in (1, 2, 3):
            self.assertEqual({k: len(v) for k, v in plan[rep].items()},
                             {"ataque": 3402, "control": 10, "denuncia": 428, "seguimiento": 8, "web_seguimiento": 8,
                              "strict_falsas": 70})
            for rol, ips in plan[rep].items():
                if rol != "strict_falsas":
                    todas += ips
        self.assertEqual(len(todas), len(set(todas)))
        for reservada in ("198.19.255.254", "198.19.255.253", "198.19.255.252"):
            self.assertNotIn(reservada, todas)
        # El bloque con nombre de las IPs falsas de strict (S9): 70 distintas, el
        # mismo en las tres repeticiones, entre 198.19.255.182 y 198.19.255.251,
        # sin tocar ninguna IP de los demas bloques ni las reservadas.
        falsas = plan[1]["strict_falsas"]
        self.assertEqual((falsas[0], falsas[-1]), ("198.19.255.182", "198.19.255.251"))
        self.assertEqual(len(set(falsas)), 70)
        self.assertEqual(plan[2]["strict_falsas"], falsas)
        self.assertEqual(plan[3]["strict_falsas"], falsas)
        self.assertFalse(set(falsas) & set(todas))
        self.assertNotIn(L.ip_de_indice(130045), falsas)
        self.assertEqual(L.ip_de_indice(130045), "198.19.255.252")
        # Cambian en cada repeticion.
        self.assertNotEqual(plan[1]["ataque"][0], plan[2]["ataque"][0])

    def test_plan_l3_son_200_ips(self):
        self.assertEqual(len(L.plan_ips("l3", 2)[1]["carga"]), 200)

    def test_solape_se_detecta_y_para(self):
        # Control positivo: bloques disjuntos, sin problemas.
        self.assertEqual(L.solapes_de_bloques({"a": (0, 10), "b": (10, 10)}), [])
        # Negativos: solape y salida del espacio permitido.
        self.assertTrue(L.solapes_de_bloques({"a": (0, 10), "b": (5, 10)}))
        self.assertTrue(L.solapes_de_bloques({"a": (130040, 10)}))
        with self.assertRaises(L.Parada):
            L.plan_ips("l3b", 40, 3402)


class Degradacion(unittest.TestCase):
    def test_bordes_2x_frente_a_mas_100(self):
        # base 10 ms: el suelo de +100 manda (110); base 200 ms: manda el doble (400).
        self.assertFalse(L.degradada(10, 110, 10000))
        self.assertTrue(L.degradada(10, 110.1, 10000))
        self.assertFalse(L.degradada(200, 400, 10000))
        self.assertTrue(L.degradada(200, 400.1, 10000))

    def test_el_slo_tambien_degrada(self):
        self.assertFalse(L.degradada(400, 500, 500))
        self.assertTrue(L.degradada(400, 501, 500))

    def test_victima(self):
        base = 50
        ok = {"peticiones": 600, "p95_ms": 120, "tasa_errores": 0.0}
        self.assertEqual(L.veredicto_victima(base, ok, 500, 0), ("PASA", []))
        self.assertEqual(L.veredicto_victima(base, {**ok, "p95_ms": 151}, 500, 0)[0], "FALLA")
        self.assertEqual(L.veredicto_victima(base, {**ok, "tasa_errores": 0.01}, 500, 0)[0], "FALLA")
        self.assertEqual(L.veredicto_victima(base, {**ok, "tasa_errores": 0.0099}, 500, 0)[0], "PASA")
        self.assertEqual(L.veredicto_victima(base, ok, 500, 1)[0], "FALLA")
        self.assertEqual(L.veredicto_victima(base, {**ok, "p95_ms": 600}, 500, 0)[0], "FALLA")
        # Una victima caida es FALLA, no SIN CONCLUSION.
        self.assertEqual(L.veredicto_victima(base, {"peticiones": 0, "p95_ms": None, "tasa_errores": None}, 500, 0)[0],
                         "FALLA")

    def test_veredicto_l2_es_el_de_la_peor(self):
        self.assertEqual(L.veredicto_l2({"a": ("PASA", []), "b": ("PASA", [])}), "PASA")
        self.assertEqual(L.veredicto_l2({"a": ("PASA", []), "b": ("FALLA", ["x"])}), "FALLA")

    def test_errores_del_login_no_cuentan_503(self):
        self.assertFalse(L.es_error_login(503))
        self.assertFalse(L.es_error_login(401))
        self.assertTrue(L.es_error_login(0))
        self.assertTrue(L.es_error_login(500))
        self.assertTrue(L.es_error_login(502))
        # B2: control positivo (1 % o mas de errores, p95 alto, descartes) y negativo.
        self.assertTrue(L.ataque_efectivo(1501, 0.0, 0))
        self.assertFalse(L.ataque_efectivo(1500, 0.0, 0))
        self.assertTrue(L.ataque_efectivo(100, 0.01, 0))
        self.assertTrue(L.ataque_efectivo(100, 0.0, 3))
        self.assertFalse(L.ataque_efectivo(100, 0.0099, 0))

    def test_mediana_con_none_como_infinito(self):
        inf = float("inf")
        # H5: un p95 sin respuestas (la victima cayo) cuenta como infinito: 100, 200, 300, inf -> (200 + 300) / 2.
        self.assertEqual(L.mediana_p95([100, None, 300, 200]), 250.0)
        # Con dos de tres sin respuestas, la mediana es infinita (no 100).
        self.assertEqual(L.mediana_p95([None, None, 100]), inf)
        # Control positivo: sin ningun None, la mediana de siempre.
        self.assertEqual(L.mediana_p95([100, 300, 200]), 200)
        self.assertEqual(L.mediana_p95([None]), inf)
        self.assertIsNone(L.mediana_p95([]))


class ValidezYControles(unittest.TestCase):
    def f(self, motivo="m"):
        return {"motivo": motivo}

    def test_control_positivo_sin_fallos_deja_pasar(self):
        self.assertEqual(L.veredicto_con_validez("PASA", [], True), ("PASA", []))
        self.assertEqual(L.veredicto_con_validez("FALLA", [], True), ("FALLA", []))

    def test_la_validez_gana_a_falla(self):
        v, _ = L.veredicto_con_validez("FALLA", [self.f("cpu de k6")], True)
        self.assertEqual(v, "SIN CONCLUSION")
        # peor_estado NO sirve: daria FALLA.
        self.assertEqual(L.peor_estado(["FALLA", "SIN CONCLUSION"]), "FALLA")

    def test_control_del_ataque_solo_rebaja_un_pasa(self):
        self.assertEqual(L.veredicto_con_validez("PASA", [], False)[0], "SIN CONCLUSION")
        self.assertEqual(L.veredicto_con_validez("FALLA", [], False)[0], "FALLA")
        # None = no aplica.
        self.assertEqual(L.veredicto_con_validez("PASA", [], None)[0], "PASA")

    def test_la_muerte_de_canario_es_falla_y_la_validez_no_la_rebaja(self):
        # H2 y H10: la muerte (FALLA de veredicto_muerte) gana a cualquier fallo de validez.
        v = L.veredicto_con_validez("PASA", [self.f("cpu de k6")], False, muertes=["FALLA"])
        self.assertEqual(v[0], "FALLA")
        v = L.veredicto_con_validez("SIN CONCLUSION", [self.f("cpu de k6")], None, muertes=["SIN CONCLUSION", "FALLA"])
        self.assertEqual(v[0], "FALLA")
        # Solo el OOM global de la VM (SIN CONCLUSION) no es una muerte de Canario.
        v = L.veredicto_con_validez("PASA", [], True, muertes=["SIN CONCLUSION"])
        self.assertEqual(v[0], "SIN CONCLUSION")
        # Control positivo: sin muertes ni fallos, el resultado de los oraculos.
        self.assertEqual(L.veredicto_con_validez("PASA", [], True, muertes=[])[0], "PASA")
        self.assertEqual(L.veredicto_con_validez("PASA", [], True, muertes=())[0], "PASA")

    def test_combinar_resultados_con_peor_estado(self):
        # H3: FALLA > SIN CONCLUSION > PASA; la validez entra aparte.
        self.assertEqual(L.combinar_resultados(["PASA", "SIN CONCLUSION", "FALLA"]), "FALLA")
        self.assertEqual(L.combinar_resultados(["PASA", "SIN CONCLUSION", "PASA"]), "SIN CONCLUSION")
        self.assertEqual(L.combinar_resultados(["PASA", "PASA", "PASA"]), "PASA")


class AgregarFases(unittest.TestCase):
    """agregar_fases: los veredictos finales de cada parte (A1, E9, H1-H4, E15)."""

    def setUp(self):
        self.parche = mock.patch.object(L, "p", lambda *a, **k: None)
        self.parche.start()
        self.addCleanup(self.parche.stop)

    def victimas(self, carga_p95, base_p95=50):
        return {ruta: {"base": {"p95_ms": base_p95},
                       "carga": {"peticiones": 600, "p95_ms": carga_p95, "tasa_errores": 0.0},
                       "descartes_aviso": 0} for ruta in L.SLO_VICTIMAS_MS}

    def login(self, p95):
        return {"p95_ms": p95, "tasa_errores": 0.0, "descartes_aviso": 0}

    def repeticion(self, numero, partes, muertes=(), comun=()):
        return {"modo": "x", "repeticion": numero, "muertes": list(muertes), "reinicios": 0, "comun": list(comun),
                "partes": partes, "veredictos": {n: ("PASA", []) for n in partes}}

    def parte(self, resultado, validez=(), control=None, detalle=None):
        return {"resultado": resultado, "validez": list(validez), "control_ataque": control, "detalle": detalle or {}}

    def l3(self, resultados, **extra):
        return [self.repeticion(i + 1, {"l3": self.parte(r)}, **extra) for i, r in enumerate(resultados)]

    def test_l3_combina_con_peor_estado(self):
        self.assertEqual(L.agregar_fases("l3", self.l3(["PASA", "PASA", "PASA"]), 3)["l3"][0], "PASA")
        self.assertEqual(L.agregar_fases("l3", self.l3(["PASA", "FALLA", "PASA"]), 3)["l3"][0], "FALLA")
        self.assertEqual(L.agregar_fases("l3", self.l3(["PASA", "SIN CONCLUSION", "PASA"]), 3)["l3"][0], "SIN CONCLUSION")

    def test_a1_exige_tres_repeticiones(self):
        self.assertEqual(L.agregar_fases("l3", self.l3(["PASA", "PASA"]), 2)["l3"][0], "SIN CONCLUSION")
        self.assertEqual(L.agregar_fases("l3", self.l3(["PASA", "PASA", "PASA"]), 2)["l3"][0], "SIN CONCLUSION")

    def test_la_validez_de_una_repeticion_gana_a_la_falla_de_otra(self):
        repeticiones = [self.repeticion(1, {"l3": self.parte("FALLA")}),
                        self.repeticion(2, {"l3": self.parte("PASA", validez=[{"motivo": "J2"}])}),
                        self.repeticion(3, {"l3": self.parte("PASA")})]
        self.assertEqual(L.agregar_fases("l3", repeticiones, 3)["l3"][0], "SIN CONCLUSION")

    def test_los_fallos_globales_dan_sin_conclusion_y_la_muerte_los_supera(self):
        globales = [{"motivo": "anti-fuga"}]
        self.assertEqual(L.agregar_fases("l3", self.l3(["PASA"] * 3), 3, globales)["l3"][0], "SIN CONCLUSION")
        self.assertEqual(L.agregar_fases("l3", self.l3(["PASA"] * 3, muertes=["FALLA"]), 3, globales)["l3"][0], "FALLA")
        # Control positivo: sin globales, PASA.
        self.assertEqual(L.agregar_fases("l3", self.l3(["PASA"] * 3), 3, [])["l3"][0], "PASA")

    def l3b(self, carga_victimas, p95_login, resultado_a="PASA"):
        detalle = {"victimas": self.victimas(carga_victimas), "login": self.login(p95_login)}
        return [self.repeticion(i, {"l3b-a": self.parte(resultado_a),
                                    "l3b-b": self.parte("PASA", detalle=detalle)}) for i in (1, 2, 3)]

    def test_l3b_da_dos_veredictos_independientes(self):
        # Victimas a 400 ms con base 50 (limite max(100, 150)) y login a 2000 ms (> 1500: el ataque existe, B2).
        finales = L.agregar_fases("l3b", self.l3b(400, 2000), 3)
        self.assertEqual(sorted(finales), ["l3b-a", "l3b-b"])
        self.assertEqual(finales["l3b-a"][0], "PASA")
        self.assertEqual(finales["l3b-b"][0], "FALLA")
        # Control positivo: victimas a 60 ms con el ataque existente: l3b-b PASA.
        self.assertEqual(L.agregar_fases("l3b", self.l3b(60, 2000), 3)["l3b-b"][0], "PASA")
        # Una FALLA de l3b-a no se mezcla con l3b-b.
        finales = L.agregar_fases("l3b", self.l3b(60, 2000, resultado_a="FALLA"), 3)
        self.assertEqual((finales["l3b-a"][0], finales["l3b-b"][0]), ("FALLA", "PASA"))

    def test_b2_solo_actua_sobre_l3b_b_y_solo_rebaja_un_pasa(self):
        # Ataque inexistente (login a 100 ms, sin errores ni descartes) con victimas sanas: SIN CONCLUSION en l3b-b
        # y no toca a l3b-a.
        finales = L.agregar_fases("l3b", self.l3b(60, 100), 3)
        self.assertEqual((finales["l3b-a"][0], finales["l3b-b"][0]), ("PASA", "SIN CONCLUSION"))
        # Con las victimas caidas y el ataque inexistente sigue siendo FALLA: B2 no rebaja una FALLA.
        self.assertEqual(L.agregar_fases("l3b", self.l3b(400, 100), 3)["l3b-b"][0], "FALLA")

    def test_la_linea_de_l3b_b_es_la_literal_de_e15_y_no_hay_punto_de_politica(self):
        self.assertEqual(L.LINEA_L3B_B_FALLA, "L3b-b: FALLA (esperada por el diseño; NO OK; misma amenaza que L2, "
                                              "threat-model §8, ABIERTA)")
        fuente = pathlib.Path(L.__file__).read_text(encoding="utf-8")
        # E15: L3b-b entra en el resultado global como cualquier otra parte; no hay interruptor.
        self.assertNotIn("L3B_B_CUENTA_PARA_GLOBAL", fuente)
        self.assertEqual(L.PARTES["l3b"], ("l3b-a", "l3b-b"))

    def test_la_cota_del_coste_solo_con_falla_de_l3b_b_y_b2(self):
        self.assertEqual(L.texto_cota_ataque("FALLA", True, 3402),
                         "cota superior del coste a esta tasa y duracion, IPv4: 3402 IPs sostenidas")
        # Cada una de las otras combinaciones: nada.
        self.assertEqual(L.texto_cota_ataque("FALLA", False, 3402), "")
        self.assertEqual(L.texto_cota_ataque("PASA", True, 3402), "")
        self.assertEqual(L.texto_cota_ataque("SIN CONCLUSION", True, 3402), "")


class DescartesE14(unittest.TestCase):
    """E14: los descartes de k6 en L4 invalidan ventanas por ruta."""

    def csv(self):
        return {"denuncia__base": [1000.5, 1010.5], "denuncia__carga": [1200.0],
                "seguimiento__recup": [1500.0], "web_seguimiento__base": [1020.0],
                "login_email__carga": [1190.0], "sonda_salud": [1005.0, 1006.0]}

    def test_cuatro_rutas_en_cualquier_fase_y_sin_la_sonda_de_salud(self):
        d = L.descartes_de_rutas(self.csv(), 1000.0)
        self.assertEqual(d, {"denuncia": [0.5, 10.5, 200.0], "seguimiento": [500.0], "web_seguimiento": [20.0],
                             "login_email": [190.0]})
        # Control: sin descartes, listas vacias en las cuatro rutas.
        self.assertEqual(L.descartes_de_rutas({}, 1000.0),
                         {"denuncia": [], "seguimiento": [], "web_seguimiento": [], "login_email": []})
        # seguimiento no recoge los de web_seguimiento (prefijo distinto).
        self.assertNotIn(20.0, d["seguimiento"])

    def test_descartes_en_tramo_es_semiabierto(self):
        self.assertEqual(L.descartes_en_tramo([0.5, 10.5, 30.0], 0, 30), 2)
        self.assertEqual(L.descartes_en_tramo([0.5, 10.5, 30.0], 30, 60), 1)
        self.assertEqual(L.descartes_en_tramo([], 0, 30), 0)

    def test_un_descarte_invalida_las_diez_ventanas_que_lo_contienen(self):
        # Descarte en 15,5: afecta a las ventanas de inicio 6 a 15 y a ninguna mas (E9, E14).
        ventanas = [(s, 10.0, 50) for s in range(0, 30)]
        serie = L.serie_cumple(ventanas, 10.0, 500, [15.5])
        malas = [s for s, ok in serie if not ok]
        self.assertEqual(malas, list(range(6, 16)))
        # Con o sin aviso es lo mismo: serie_cumple no mira el aviso. Control: sin descartes, todas cumplen.
        self.assertTrue(all(ok for _, ok in L.serie_cumple(ventanas, 10.0, 500, [])))

    def test_la_recuperacion_no_se_da_con_un_descarte_dentro_de_la_ventana(self):
        # Fin del pico 180. Todo bien salvo un descarte en 200,5: las ventanas 191 a 200 no cumplen,
        # asi que s0 = 201 -> 21 s (y no 0).
        ventanas = [(s, 10.0, 50) for s in range(180, 350)]
        serie = L.serie_cumple(ventanas, 10.0, 500, [200.5])
        self.assertEqual(L.segundos_hasta_recuperar({"a": serie}, 180), 21)
        # Control positivo: sin el descarte, 0 s.
        self.assertEqual(L.segundos_hasta_recuperar({"a": L.serie_cumple(ventanas, 10.0, 500, [])}, 180), 0)


class VentanasLimitador(unittest.TestCase):
    def filas(self, ip, inicios, estado, dur=0.05):
        return [{"ip": ip, "inicio": t, "fin": t + dur, "estado": estado} for t in inicios]

    def test_ambigua_si_cruza_la_frontera(self):
        self.assertEqual(L.ventana_de_peticion(119.99, 120.05, 60), (1, True))
        self.assertEqual(L.ventana_de_peticion(100.0, 100.05, 60), (1, False))
        self.assertEqual(L.ventana_de_peticion(60.0, 60.05, 60), (1, False))

    def test_61_aceptadas_no_ambiguas_es_falla_y_60_pasa(self):
        # Control positivo: 60 aceptadas y el resto 429 pasa.
        ok = self.filas("a", [60 + i * 0.5 for i in range(60)], 404) + self.filas("a", [95 + i * 0.1 for i in range(5)], 429)
        v, _ = L.veredicto_l3(L.contar_por_ip_ventana(ok, 60, 404), 60)
        self.assertEqual(v, "PASA")
        malo = self.filas("a", [60 + i * 0.4 for i in range(61)], 404)
        v, _ = L.veredicto_l3(L.contar_por_ip_ventana(malo, 60, 404), 60)
        self.assertEqual(v, "FALLA")

    def test_solo_pasa_contando_ambiguas_es_sin_conclusion(self):
        filas = self.filas("a", [60 + i * 0.4 for i in range(60)], 404)
        filas += [{"ip": "a", "inicio": 119.99, "fin": 120.05, "estado": 404}]
        v, _ = L.veredicto_l3(L.contar_por_ip_ventana(filas, 60, 404), 60)
        self.assertEqual(v, "SIN CONCLUSION")

    def test_solo_cuenta_el_estado_aceptado_y_los_503_van_aparte(self):
        filas = self.filas("a", [60 + i * 0.4 for i in range(60)], 404) + self.filas("a", [90, 91, 92], 503)
        pares = L.contar_por_ip_ventana(filas, 60, 404)
        self.assertEqual(L.veredicto_l3(pares, 60)[0], "PASA")
        self.assertEqual(pares[("a", 1)]["n503"], 3)
        # En L3b el aceptado es 401: los 404 no cuentan.
        self.assertEqual(L.contar_por_ip_ventana(filas, 60, 401)[("a", 1)]["aceptadas"], 0)

    def test_retry_after_fuera_de_rango_es_falla_con_control(self):
        pares = L.contar_por_ip_ventana(self.filas("a", [60 + i for i in range(10)], 404), 60, 404)
        self.assertEqual(L.veredicto_l3(pares, 60, 0)[0], "PASA")
        self.assertEqual(L.veredicto_l3(pares, 60, 1)[0], "FALLA")
        self.assertTrue(L.retry_after_valido(1, 60))
        self.assertTrue(L.retry_after_valido(60, 60))
        self.assertFalse(L.retry_after_valido(61, 60))
        self.assertTrue(L.retry_after_valido(61, 300))
        self.assertFalse(L.retry_after_valido(301, 300))
        self.assertFalse(L.retry_after_valido(0, 60))
        self.assertFalse(L.retry_after_valido(-1, 60))
        # Un 429 sin fila de Retry-After tambien cuenta como no valido.
        self.assertEqual(L.retry_after_invalidos([30, 61, -1], 5, 60), 2 + 2)
        self.assertEqual(L.retry_after_invalidos([30, 31], 2, 60), 0)

    def test_control_positivo_j2(self):
        # 60 aceptadas y luego 429: control bien.
        buenos = self.filas("a", [60 + i * 0.5 for i in range(60)], 404) + self.filas("a", [91 + i * 0.1 for i in range(3)], 429)
        self.assertTrue(L.control_l3(L.contar_por_ip_ventana(buenos, 60, 404), 60)[0])
        # Un 429 en la peticion 10: el limite no es el esperado, SIN CONCLUSION.
        malos = self.filas("a", [60 + i * 0.5 for i in range(9)], 404) + self.filas("a", [65], 429)
        self.assertFalse(L.control_l3(L.contar_por_ip_ventana(malos, 60, 404), 60)[0])
        # Con 3 peticiones previas con estado 503 y 0, 429 en la 58.a ya no es de las protegidas (60 - 2 = 58).
        previas = self.filas("a", [60, 61], 503) + self.filas("a", [62 + i * 0.2 for i in range(56)], 404) \
            + self.filas("a", [80], 429)
        self.assertTrue(L.control_l3(L.contar_por_ip_ventana(previas, 60, 404), 60)[0])
        # Control del control: el mismo 429 sin las previas si es una violacion.
        sin_previas = self.filas("a", [62 + i * 0.2 for i in range(56)], 404) + self.filas("a", [80], 429)
        self.assertFalse(L.control_l3(L.contar_por_ip_ventana(sin_previas, 60, 404), 60)[0])

    def test_ambiguas_al_inicio_relajan_el_control(self):
        # Una peticion de 'a' cruza la frontera de las 60: puede haber gastado 1 del contador de la ventana 1.
        filas = [{"ip": "a", "inicio": 59.99, "fin": 60.05, "estado": 404}]
        filas += self.filas("a", [61 + i * 0.5 for i in range(59)], 404) + self.filas("a", [95], 429)
        pares = L.contar_por_ip_ventana(filas, 60, 404)
        self.assertEqual(pares[("a", 1)]["ambiguas_inicio"], 1)
        self.assertTrue(L.control_l3(pares, 60)[0])
        # Control: sin la ambigua, un 429 tras 59 aceptadas viola el control.
        self.assertFalse(L.control_l3(L.contar_por_ip_ventana(filas[1:], 60, 404), 60)[0])

    def test_maximo_deslizante(self):
        # 60 en el final de una ventana y 60 en el principio de la siguiente: 120 en un tramo de 60 s.
        inicios = [30 + i * 0.4 for i in range(60)] + [60 + i * 0.4 for i in range(60)]
        self.assertEqual(L.maximo_deslizante({"a": inicios}, 60)[0], 120)
        self.assertEqual(L.maximo_deslizante({"a": [0.0, 1.0, 61.0]}, 60)[0], 2)


class ControlesDeConfiguracion(unittest.TestCase):
    def peticiones(self, estados, ini=0.0):
        return [{"inicio": ini + i * 0.01, "fin": ini + i * 0.01 + 0.005, "estado": e} for i, e in enumerate(estados)]

    def test_d3_pasa_y_cada_motivo_da_sin_conclusion(self):
        bien = {"1.1.1.1": self.peticiones([401] * 10 + [429], 310.0)}
        self.assertEqual(L.evaluar_d3(bien), ("PASA", []))
        # la 11.a no es 429: el limite no esta activo.
        self.assertEqual(L.evaluar_d3({"1.1.1.1": self.peticiones([401] * 11, 310.0)})[0], "SIN CONCLUSION")
        # una de las 10 primeras no es 401 (E6).
        self.assertEqual(L.evaluar_d3({"1.1.1.1": self.peticiones([401] * 4 + [503] + [401] * 5 + [429], 310.0)})[0],
                         "SIN CONCLUSION")
        # alguna ambigua: cruza la frontera de 300 s.
        cruza = self.peticiones([401] * 10 + [429], 599.99)
        self.assertEqual(L.evaluar_d3({"1.1.1.1": cruza})[0], "SIN CONCLUSION")
        # faltan peticiones.
        self.assertEqual(L.evaluar_d3({"1.1.1.1": self.peticiones([401] * 5, 310.0)})[0], "SIN CONCLUSION")

    def test_strict_diferencial(self):
        bien = [404] * 60 + [429] * 10 + [404]
        self.assertEqual(L.evaluar_control_strict(bien, False)[0], "PASA")
        # Sin strict, Caddy toma la IP de la izquierda: las 70 cuentan para las IPs falsas, una vez cada una, y la
        # 71.a (con 198.19.255.254 a la izquierda) cuenta para esa IP, que nunca se contó: las 71 dan 404.
        v, t = L.evaluar_control_strict([404] * 71, False)
        self.assertEqual(v, "PARADA")
        self.assertIn("sin strict", t)
        # Sin confianza en 10.88.1.2: todo cuenta para la IP de la conexion, la 71.a da 429.
        v, t = L.evaluar_control_strict([404] * 60 + [429] * 11, False)
        self.assertEqual(v, "PARADA")
        self.assertIn("sin confianza", t)
        # El patron antiguo de 70 sin la 71.a ya no vale.
        self.assertEqual(L.evaluar_control_strict([404] * 60 + [429] * 10, False)[0], "PARADA")
        # Si cruzan la frontera de minuto, SIN CONCLUSION (no PARADA).
        self.assertEqual(L.evaluar_control_strict(bien, True)[0], "SIN CONCLUSION")
        self.assertTrue(L.cruza_frontera(119.9, 120.1, 60))
        self.assertFalse(L.cruza_frontera(120.0, 179.9, 60))

    def test_403_compara_estado_y_cuerpo(self):
        self.assertEqual(L.evaluar_control_403(403, '{"detalle": "petición no válida"}')[0], "PASA")
        self.assertEqual(L.evaluar_control_403(403, '{"detalle": "host no válido"}')[0], "PARADA")
        self.assertEqual(L.evaluar_control_403(421, '{"detalle": "petición no válida"}')[0], "PARADA")

    def test_421_es_parada(self):
        self.assertEqual(L.evaluar_control_421(405)[0], "PASA")
        self.assertEqual(L.evaluar_control_421(421)[0], "PARADA")
        self.assertEqual(L.evaluar_control_421(0)[0], "PARADA")

    def test_fronteras(self):
        # 2026-11-22 10:07:13 UTC = 1795342033: la siguiente de 5 minutos con 120 s de margen es 10:10:00.
        self.assertEqual(L.proxima_frontera(1795342033, 300, 120), 1795342200)
        # Si justo cabe, no espera una mas.
        self.assertEqual(L.proxima_frontera(1795342080, 300, 120), 1795342200)
        self.assertEqual(L.proxima_frontera(1795342081, 300, 120), 1795342500)
        self.assertTrue(L.cruza_frontera(1795391999.5, 1795392000.5, 86400))
        self.assertFalse(L.cruza_frontera(1795300000, 1795300500, 86400))

    def test_alineacion(self):
        self.assertTrue(L.evaluar_alineacion(1795342200.4, 1795342200)[0])
        self.assertTrue(L.evaluar_alineacion(1795342199.97, 1795342200)[0])
        self.assertFalse(L.evaluar_alineacion(1795342199.5, 1795342200)[0])
        self.assertFalse(L.evaluar_alineacion(1795342204.0, 1795342200)[0])
        self.assertFalse(L.evaluar_alineacion(None, 1795342200)[0])


class Recuperacion(unittest.TestCase):
    def test_cada_peticion_cuenta_en_todas_las_ventanas_que_contienen_su_inicio(self):
        # Una peticion en t = 15,5 cae en las ventanas de inicio 6 a 15 (10 ventanas), no en las demas.
        v = L.ventanas_p95([(15.5, 7.0)], 0, 30)
        con = [s for s, p95, n in v if n]
        self.assertEqual(con, list(range(6, 16)))
        self.assertEqual({p95 for _, p95, n in v if n}, {7.0})
        # Las ventanas llegan hasta s + 10 <= hasta.
        self.assertEqual(v[-1][0], 20)

    def serie(self, desde, hasta, malos=()):
        return [(s, s not in malos) for s in range(desde, hasta)]

    def test_30_ventanas_consecutivas_y_tiempo_desde_el_fin_del_pico(self):
        # fin del pico 180: ventanas 180-199 malas, desde la 200 todas bien: s0 = 200 -> 20 s.
        s = self.serie(180, 350, malos=set(range(180, 200)))
        self.assertEqual(L.segundos_hasta_recuperar({"a": s, "b": s}, 180), 20)
        # Exactamente 30 ventanas buenas al final (inicios 320..349): se recupera en 140 s.
        s = self.serie(180, 350, malos=set(range(180, 320)))
        self.assertEqual(L.segundos_hasta_recuperar({"a": s}, 180), 140)
        # 29 ventanas buenas: no se recupera (control del borde).
        s = self.serie(180, 350, malos=set(range(180, 321)))
        self.assertIsNone(L.segundos_hasta_recuperar({"a": s}, 180))

    def test_todas_las_rutas_deben_cumplir(self):
        a = self.serie(180, 350)
        b = self.serie(180, 350, malos={200})
        # b tiene una mala en 200: s0 = 201 -> 21 s.
        self.assertEqual(L.segundos_hasta_recuperar({"a": a, "b": b}, 180), 21)
        # Control: sin la mala, 0 s.
        self.assertEqual(L.segundos_hasta_recuperar({"a": a, "b": a}, 180), 0)

    def test_control_de_la_base(self):
        base = self.serie(30, 141)
        ok, fraccion, _ = L.control_base_f2({"a": base})
        self.assertTrue(ok)
        self.assertEqual(fraccion, 1.0)
        # El 94 % no basta aunque encadene 30 seguidas: 111 ventanas, 7 malas = 93,7 %.
        malas = set(range(100, 107))
        ok, fraccion, motivo = L.control_base_f2({"a": self.serie(30, 141, malos=malas)})
        self.assertFalse(ok)
        self.assertLess(fraccion, 0.95)
        self.assertIn("solo el", motivo)
        # Con 5 malas (95,5 %) y un tramo de 54 seguidas: pasa. Control del umbral.
        ok, _, _ = L.control_base_f2({"a": self.serie(30, 141, malos={45, 100, 101, 102, 103})})
        self.assertTrue(ok)
        # Si no encadena 30 seguidas, falla aunque supere el 95 %.
        ok, _, motivo = L.control_base_f2({"a": self.serie(30, 141, malos=set(range(35, 140, 20)))})
        self.assertFalse(ok)

    def test_descartes_hacen_no_cumplir_la_ventana(self):
        v = [(0, 10.0, 50), (1, 10.0, 50)]
        self.assertEqual(L.serie_cumple(v, 10.0, 500, []), [(0, True), (1, True)])
        # un descarte en t = 0,5 cae en la ventana [0,10) pero tambien en [1, 11)? No: 0,5 < 1.
        self.assertEqual(L.serie_cumple(v, 10.0, 500, [0.5]), [(0, False), (1, True)])
        # degradada: 111 > max(20, 110)
        self.assertEqual(L.serie_cumple([(0, 111.0, 50)], 10.0, 500, []), [(0, False)])
        # sin p95: no cumple.
        self.assertEqual(L.serie_cumple([(0, None, 0)], 10.0, 500, []), [(0, False)])

    def test_mediana_con_infinito_y_f3(self):
        inf = float("inf")
        self.assertEqual(L.mediana_recuperacion([10, 20, None]), 20)
        self.assertEqual(L.mediana_recuperacion([10, None, None]), inf)
        self.assertEqual(L.veredicto_recuperacion(59, 0, True)[0], "PASA")
        self.assertEqual(L.veredicto_recuperacion(60, 0, True)[0], "FALLA")
        self.assertEqual(L.veredicto_recuperacion(inf, 0, True)[0], "FALLA")
        self.assertEqual(L.veredicto_recuperacion(10, 1, True)[0], "FALLA")
        self.assertEqual(L.veredicto_recuperacion(10, 0, False)[0], "FALLA")

    def test_humo(self):
        bien = [("humo_previo: a", 1.0), ("humo_previo: b", 1.0), ("humo_previo: c", 1.0), ("humo_previo: d", 1.0)]
        self.assertTrue(L.humo_ok(bien, "humo_previo"))
        self.assertFalse(L.humo_ok(bien[:3], "humo_previo"))
        self.assertFalse(L.humo_ok(bien[:3] + [("humo_previo: d", 0.0)], "humo_previo"))
        # Las de la otra etapa no cuentan.
        self.assertFalse(L.humo_ok(bien, "humo_posterior"))


class Escenarios(unittest.TestCase):
    def test_fases_literales(self):
        self.assertEqual(L.fases_de("pico"), [{"nombre": "cal", "desde_s": 0, "hasta_s": 30},
                                              {"nombre": "base", "desde_s": 30, "hasta_s": 150},
                                              {"nombre": "carga", "desde_s": 150, "hasta_s": 180},
                                              {"nombre": "recup", "desde_s": 180, "hasta_s": 360}])
        self.assertEqual([f["hasta_s"] for f in L.fases_de("l2")], [30, 150, 270, 390])
        self.assertEqual([f["hasta_s"] for f in L.fases_de("l3b")], [30, 150, 450, 570])
        # el humo posterior es 120 s despues del fin programado del pico (E10).
        self.assertEqual(L.HUMO_POSTERIOR_S, 180 + 120)

    def test_l2(self):
        esc = {e["nombre"]: e for e in L.escenarios_l2(L.tasas_de(0.0196))}
        self.assertEqual(esc["login_email"]["rate"], 15306)
        self.assertEqual((esc["login_email"]["inicio_s"], esc["login_email"]["duracion_s"], esc["login_email"]["vus"]),
                         (150, 120, 600))
        for ruta in ("denuncia", "seguimiento", "web_seguimiento"):
            self.assertEqual((esc[ruta]["rate"], esc[ruta]["inicio_s"], esc[ruta]["duracion_s"], esc[ruta]["vus"]),
                             (5, 0, 390, 50))
        self.assertEqual(esc["sonda_salud"]["rate"], 1)
        self.assertEqual(L.presupuesto_k6_mib(list(esc.values())), 765 * 5)
        self.assertEqual(L.comprobar_presupuesto(list(esc.values())), 3825)

    def test_pico(self):
        esc = {e["nombre"]: e for e in L.escenarios_pico(L.tasas_de(0.0196))}
        self.assertEqual(esc["login_email__base"]["rate"], 1020)
        self.assertEqual(esc["login_email__base"]["time_unit_s"], 100)
        self.assertEqual(esc["login_email__carga"]["rate"], 10204)
        self.assertEqual(esc["denuncia__base"]["rate"], 5)
        self.assertEqual(esc["denuncia__carga"]["rate"], 50)
        self.assertEqual((esc["denuncia__carga"]["inicio_s"], esc["denuncia__carga"]["duracion_s"]), (150, 30))
        self.assertEqual((esc["web_seguimiento__recup"]["inicio_s"], esc["web_seguimiento__recup"]["duracion_s"]),
                         (180, 180))
        # Todo x 10 en el pico, el login a 2/t.
        for ruta in ("denuncia", "seguimiento", "web_seguimiento"):
            self.assertEqual(esc[f"{ruta}__carga"]["rate"], 10 * esc[f"{ruta}__base"]["rate"])
        lista = list(esc.values())
        self.assertEqual(L.holgura_insuficiente(lista), [])
        self.assertLessEqual(L.comprobar_presupuesto(lista, 2), 4096)
        self.assertEqual(L.presupuesto_k6_mib(lista, 2), 747 * 5)

    def test_k_el_plazo_de_docker_wait_sale_de_los_valores_que_viajan_en_humos(self):
        # Plan v4.2, prueba k. Escenarios del pico, que acaban a los 360 s (fases_de("pico")).
        esc = L.escenarios_pico(L.tasas_de(0.0196))
        # Humo posterior a los 300 s con maxDuration 90 s y gracefulStop 20 s, literales
        # de la prueba: el plazo cubre 300 + 90 + 20 = 410 s.
        humos = [{"nombre": "humo_posterior", "inicio_s": 300, "max_duracion_s": 90, "graceful_stop_s": 20}]
        self.assertEqual(L.duracion_total(esc, humos), 410)
        # Control: cambiar maxDuration o gracefulStop cambia el plazo (no queda un 60 escrito a mano).
        self.assertEqual(L.duracion_total(esc, [{**humos[0], "max_duracion_s": 100}]), 420)
        self.assertEqual(L.duracion_total(esc, [{**humos[0], "graceful_stop_s": 30}]), 420)
        # Sin humos, el fin del último escenario.
        self.assertEqual(L.duracion_total(esc), 360)
        # Los humos que manda el lanzador llevan los dos valores, los mismos en los dos.
        self.assertEqual([(h["nombre"], h["inicio_s"]) for h in L.humos_pico()],
                         [("humo_previo", 140), ("humo_posterior", 300)])
        self.assertEqual({(h["max_duracion_s"], h["graceful_stop_s"]) for h in L.humos_pico()},
                         {(L.HUMO_MAX_DURACION_S, L.HUMO_GRACEFUL_STOP_S)})
        # maxDuration por encima de 4 plazos de 15 s (fases.js, PLAZO = '15s').
        self.assertGreater(L.HUMO_MAX_DURACION_S, 4 * 15)

    def test_k_fases_js_lee_maxduration_y_gracefulstop_de_humos(self):
        import re
        js = (pathlib.Path(__file__).resolve().parent / "fases.js").read_text(encoding="utf-8")
        # Ningún maxDuration escrito a mano: viene de h.max_duracion_s, validado con exigir.
        self.assertEqual(re.findall(r"maxDuration: '(\d+)s'", js), [])
        self.assertIn("maxDuration: `${h.max_duracion_s}s`", js)
        self.assertIn("gracefulStop: `${h.graceful_stop_s}s`", js)
        self.assertIn("`${h.nombre}: max_duracion_s`", js)
        self.assertIn("`${h.nombre}: graceful_stop_s`", js)
        # Control: el gracefulStop de los demás escenarios sigue escrito (20 s, fases.js:83).
        self.assertEqual(re.findall(r"gracefulStop: '(\d+)s'", js), ["20"])
        # Cambio 1: 'check' en systemTags.
        self.assertIn("'expected_response', 'check'],", js)

    def test_presupuesto_pasa_de_4_gib_es_parada_con_su_control(self):
        # Control positivo: 819 VUs caben (4095 MiB).
        self.assertEqual(L.comprobar_presupuesto([{"vus": 819}]), 4095)
        with self.assertRaises(L.Parada):
            L.comprobar_presupuesto([{"vus": 820}])
        with self.assertRaises(L.Parada):
            L.comprobar_presupuesto([{"vus": 819}], humos=1)

    def test_holgura(self):
        # 16 VUs a 5/s son 3,2 s (> 1 s de la denuncia): bien. 4 VUs son 0,8 s: no basta.
        bien = {"nombre": "a", "ruta": "denuncia", "vus": 16, "rate": 5, "time_unit_s": 1}
        mal = {"nombre": "b", "ruta": "denuncia", "vus": 4, "rate": 5, "time_unit_s": 1}
        self.assertEqual(L.holgura_insuficiente([bien, mal]), ["b"])
        # tasa con time_unit 100: 1020 por 100 s son 10,2/s: 32 VUs son 3,1 s (> 1,5 s).
        self.assertEqual(L.holgura_insuficiente([{"nombre": "l", "ruta": "login_email", "vus": 32, "rate": 1020,
                                                  "time_unit_s": 100}]), [])

    def test_l3(self):
        plan = L.plan_ips("l3", 1)
        esc = {e["nombre"]: e for e in L.escenarios_l3(plan[1])}
        self.assertEqual((esc["seguimiento_ips"]["rate"], esc["seguimiento_ips"]["duracion_s"],
                          esc["seguimiento_ips"]["vus"]), (300, 300, 600))
        self.assertEqual(len(esc["seguimiento_ips"]["ips"]), 200)
        self.assertTrue(esc["seguimiento_ips"]["etiquetar_ip"])
        self.assertEqual(L.comprobar_presupuesto(list(esc.values())), 615 * 5)

    def test_l3b(self):
        plan = L.plan_ips("l3b", 1, 3402)
        esc = {e["nombre"]: e for e in L.escenarios_l3b(L.tasas_de(0.0196), plan[1])}
        ataque = esc["login_ataque"]
        self.assertEqual((ataque["rate"], ataque["time_unit_s"], ataque["inicio_s"], ataque["duracion_s"]),
                         (10204, 100, 150, 300))
        self.assertEqual(len(ataque["ips"]), 3402)
        self.assertEqual([len(esc[r]["ips"]) for r in ("denuncia", "seguimiento", "web_seguimiento")], [428, 8, 8])
        self.assertEqual(esc["denuncia"]["duracion_s"], 570)
        self.assertEqual(L.comprobar_presupuesto(list(esc.values())), 765 * 5)
        # 300 s x 102,04/s = 30612 peticiones entre 3402 IPs: 8,9988 por IP, por debajo de 10 (D2).
        self.assertLess(30612 / 3402, 9.0)


import collections  # noqa: E402


class CsvFases(unittest.TestCase):
    def test_lee_filas_descartes_retry_y_checks(self):
        # Cabecera medida M2 (plan v4.2): k6 v2.3.0 con 'check' en systemTags, m2.js en
        # medidas_v4_25nov/m2.csv, 25/11/2026. Sin columna error.
        columnas = CABECERA_M2.split(",")
        # Filas con la forma de las reales: error_code 1404 y expected_response false en un
        # 404 (k6.csv de rep1 de L4, canario_estres_salida_px5x7po1, 24/11/2026) y extra_tags
        # con el formato k=v&k=v de la fila de L3b (fila_status0_l3b_rep1.csv, 25/11/2026),
        # en su mismo orden ip, ruta, fase.
        filas = [
            ["http_req_duration", "1795342200500", "500.0", "", "1404", "false", "POST", "seguimiento", "HTTP/1.1",
             "seguimiento_ips", "404", "ip=198.18.0.1&ruta=seguimiento&fase=carga", ""],
            ["http_reqs", "1795342200500", "1", "", "1404", "false", "POST", "seguimiento", "HTTP/1.1",
             "seguimiento_ips", "404", "ip=198.18.0.9", ""],
            ["dropped_iterations", "1795342201000", "1", "", "", "", "", "", "", "seguimiento_ips", "", "", ""],
            ["retry_after_s", "1795342202000", "33", "", "", "", "", "seguimiento", "", "seguimiento_ips", "",
             "ip=198.18.0.1", ""],
            ["checks", "1795342203000", "1", "humo_previo: denuncia 201 con codigo", "", "", "", "", "", "humo_previo",
             "", "ruta=humo", ""],
        ]
        with tempfile.TemporaryDirectory() as d:
            ruta = pathlib.Path(d) / "k6.csv"
            with open(ruta, "w", encoding="utf-8", newline="") as f:
                w = _csv.writer(f, lineterminator="\n")
                w.writerow(columnas)
                w.writerows(filas)
            datos = L.leer_csv_fases(ruta)
        self.assertEqual(len(datos["filas"]), 1)
        fila = datos["filas"][0]
        # La marca es el FIN: inicio = marca - duracion (500 ms).
        self.assertEqual(fila["fin"], 1795342200.5)
        self.assertAlmostEqual(fila["inicio"], 1795342200.0)
        self.assertEqual((fila["estado"], fila["nombre"], fila["ip"], fila["fase"]), (404, "seguimiento",
                                                                                   "198.18.0.1", "carga"))
        self.assertEqual(datos["descartes"], {"seguimiento_ips": [1795342201.0]})
        self.assertEqual(datos["retry"], [33.0])
        self.assertEqual(datos["checks"], [("humo_previo: denuncia 201 con codigo", 1.0)])

    def leer_texto(self, cabecera, *filas):
        """leer_csv_fases sobre un CSV escrito con la cabecera y las filas tal cual (LF)."""
        with tempfile.TemporaryDirectory() as d:
            ruta = pathlib.Path(d) / "k6.csv"
            ruta.write_text("\n".join((cabecera, *filas)) + "\n", encoding="utf-8", newline="")
            return L.leer_csv_fases(ruta)

    # Los cuatro check del humo previo: la fila checks real de L4 (FILA_CHECKS_L4) con la
    # columna check de M2 rellena con los nombres de fases.js de esta copia (humo,
    # check en las líneas 251, 263, 266 y 273).
    CHECKS_HUMO_PREVIO = [
        "checks,1795546507075,1.000000,humo_previo: denuncia 201 con codigo,,,,,,humo_previo,,ruta=humo,",
        "checks,1795546507082,1.000000,humo_previo: seguimiento 200 con el texto sembrado,,,,,,humo_previo,,ruta=humo,",
        "checks,1795546507086,1.000000,humo_previo: formulario web 200,,,,,,humo_previo,,ruta=humo,",
        "checks,1795546507095,1.000000,humo_previo: consulta web 200 con el texto sembrado,,,,,,humo_previo,,ruta=humo,",
    ]

    def test_a_cabecera_m2_con_los_cuatro_checks_del_humo_previo(self):
        datos = self.leer_texto(CABECERA_M2, *self.CHECKS_HUMO_PREVIO)
        self.assertEqual(datos["ilegibles"], 0)
        self.assertTrue(L.humo_ok(datos["checks"], "humo_previo"))
        # Control: el mismo CSV con un check a 0 da False.
        uno_a_cero = [*self.CHECKS_HUMO_PREVIO[:3], self.CHECKS_HUMO_PREVIO[3].replace(",1.000000,", ",0.000000,")]
        datos = self.leer_texto(CABECERA_M2, *uno_a_cero)
        self.assertEqual(datos["ilegibles"], 0)
        self.assertFalse(L.humo_ok(datos["checks"], "humo_previo"))

    def test_b_la_cabecera_real_de_l4_deja_la_fila_checks_ilegible(self):
        datos = self.leer_texto(CABECERA_L4, FILA_CHECKS_L4)
        self.assertEqual((datos["ilegibles"], datos["checks"]), (1, []))
        self.assertEqual(datos["motivos_ilegibles"], {"checks sin la columna check": 1})
        k6 = {"codigo": 0, "oom": False, "sin_conclusion": [], "registro": "T0_MS=1795546367000\n", "desfase": 0.0,
              "motivo_desfase": None}
        fallos = L.validez_generador(k6, 1795546367.0, {**datos, "filas": [{"proto": "HTTP/1.1", "estado": 201}]},
                                     set(), {"k6": {"maxima": 100.0}})
        self.assertEqual([f["motivo"] for f in fallos],
                         ["1 filas ilegibles en el CSV de k6 ({'checks sin la columna check': 1})"])
        self.assertEqual(L.veredicto_con_validez("PASA", fallos, None)[0], "SIN CONCLUSION")
        # Control positivo: con la cabecera M2 y la fila checks de M4, 0 ilegibles.
        datos = self.leer_texto(CABECERA_M2, FILA_CHECKS_M4)
        self.assertEqual((datos["ilegibles"], datos["checks"]), (0, [("humo_previo: x", 1.0)]))

    def test_f_http_req_duration_sin_columna_status_es_ilegible(self):
        # Un 404 real de L4 (rep1/pico_rep1/k6.csv, 24/11/2026) con la cabecera M2.
        con_status = "http_req_duration,1795546367107,39.437354,,1404,false,POST,seguimiento,HTTP/1.1,seguimiento__cal,404,ruta=seguimiento&fase=cal,"
        sin_columna = CABECERA_M2.replace(",status,", ",")
        sin_status = "http_req_duration,1795546367107,39.437354,,1404,false,POST,seguimiento,HTTP/1.1,seguimiento__cal,ruta=seguimiento&fase=cal,"
        datos = self.leer_texto(sin_columna, sin_status)
        # Ilegible, no estado 0.
        self.assertEqual((datos["filas"], datos["ilegibles"]), ([], 1))
        self.assertEqual(datos["motivos_ilegibles"], {"http_req_duration sin la columna status": 1})
        # Control: la misma fila con status se lee.
        datos = self.leer_texto(CABECERA_M2, con_status)
        self.assertEqual(datos["ilegibles"], 0)
        self.assertEqual([(f["estado"], f["nombre"], f["escenario"]) for f in datos["filas"]],
                         [(404, "seguimiento", "seguimiento__cal")])

    def test_f_bis_la_fila_m4_real_de_estado_0_se_lee_y_es_error(self):
        datos = self.leer_texto(CABECERA_L3B, FILA_M4_REAL)
        self.assertEqual(datos["ilegibles"], 0)
        self.assertEqual([(f["estado"], f["proto"], f["error_code"]) for f in datos["filas"]], [(0, "", "1050")])
        # Cuenta como error (el login espera 401), no como ilegible.
        self.assertEqual(L.resumen_filas(datos["filas"], 401)["errores"], 1)
        # Control: la misma fila con status 200 y proto vacío es ilegible.
        con_200 = FILA_M4_REAL.replace(",login_ataque,0,", ",login_ataque,200,")
        self.assertNotEqual(con_200, FILA_M4_REAL)
        datos = self.leer_texto(CABECERA_L3B, con_200)
        self.assertEqual((datos["filas"], datos["ilegibles"]), ([], 1))
        self.assertEqual(datos["motivos_ilegibles"], {"http_req_duration con proto vacio y estado 200": 1})

    def test_h_un_csv_de_l3_sin_columna_check_no_tiene_ilegibles(self):
        # Cabecera de l3.js (sin 'check') y su fila real, sin filas checks.
        datos = self.leer_texto(CABECERA_L3B, FILA_M4_REAL)
        self.assertNotIn("check", CABECERA_L3B.split(","))
        self.assertEqual((len(datos["filas"]), datos["ilegibles"], datos["checks"]), (1, 0, []))
        # Enmienda v4.3, punto 1: las peticiones de setup() de l3.js salen con scenario
        # vacío y se leen (FILAS_SETUP_L3, literales medidos).
        datos = self.leer_texto(CABECERA_L3B, *FILAS_SETUP_L3)
        self.assertEqual(datos["ilegibles"], 0)
        self.assertEqual([(f["estado"], f["escenario"]) for f in datos["filas"]], [(405, ""), (405, ""), (200, "")])
        # Control: las mismas filas con status o con name vacíos son ilegibles.
        sin_status = [f.replace(",,405,", ",,,").replace(",,200,", ",,,") for f in FILAS_SETUP_L3]
        self.assertTrue(all(a != b for a, b in zip(sin_status, FILAS_SETUP_L3, strict=True)))
        datos = self.leer_texto(CABECERA_L3B, *sin_status)
        self.assertEqual((datos["filas"], datos["motivos_ilegibles"]), ([], {"http_req_duration con status vacio": 3}))
        sin_name = [f.replace("http://caddy:8080/salud", "").replace("http://caddy:8080/seguimiento", "")
                    for f in FILAS_SETUP_L3]
        datos = self.leer_texto(CABECERA_L3B, *sin_name)
        self.assertEqual((datos["filas"], datos["motivos_ilegibles"]), ([], {"http_req_duration con name vacio": 3}))

    def test_error_code_vacio_con_un_404_es_ilegible(self):
        # Enmienda v4.3, punto 3: el 404 literal de L4 (FILA_404_L4, error_code 1404).
        # Con error_code vacío no es una fila que k6 escriba: en L4 todo 4xx y 5xx trae
        # 1000 + estado, y el 429 de L3 trae 1429 (barrido de QA, enmienda v4.3).
        vacio = FILA_404_L4.replace(",1404,", ",,")
        self.assertNotEqual(vacio, FILA_404_L4)
        datos = self.leer_texto(CABECERA_L4, vacio)
        self.assertEqual((datos["filas"], datos["motivos_ilegibles"]),
                         ([], {"http_req_duration con error_code vacio y estado 404": 1}))
        # Control: el mismo 404 con 1404 se lee.
        datos = self.leer_texto(CABECERA_L4, FILA_404_L4)
        self.assertEqual(datos["ilegibles"], 0)
        self.assertEqual([(f["estado"], f["error_code"]) for f in datos["filas"]], [(404, "1404")])

    def test_status_no_numerico_es_ilegible(self):
        no_numerico = FILA_404_L4.replace(",seguimiento__cal,404,", ",seguimiento__cal,cuatro,")
        self.assertNotEqual(no_numerico, FILA_404_L4)
        datos = self.leer_texto(CABECERA_L4, no_numerico)
        self.assertEqual((datos["filas"], datos["motivos_ilegibles"]),
                         ([], {"http_req_duration con status no numerico": 1}))
        # Control: la fila literal se lee.
        self.assertEqual(self.leer_texto(CABECERA_L4, FILA_404_L4)["ilegibles"], 0)

    def test_name_vacio_es_ilegible(self):
        sin_name = FILA_404_L4.replace(",POST,seguimiento,", ",POST,,")
        self.assertNotEqual(sin_name, FILA_404_L4)
        datos = self.leer_texto(CABECERA_L4, sin_name)
        self.assertEqual((datos["filas"], datos["motivos_ilegibles"]), ([], {"http_req_duration con name vacio": 1}))
        # Control: la fila literal se lee con su name.
        self.assertEqual([f["nombre"] for f in self.leer_texto(CABECERA_L4, FILA_404_L4)["filas"]], ["seguimiento"])

    def test_check_vacio_es_ilegible(self):
        # La fila checks de M4 con la columna check vacía.
        vacio = FILA_CHECKS_M4.replace(",humo_previo: x,", ",,")
        self.assertNotEqual(vacio, FILA_CHECKS_M4)
        datos = self.leer_texto(CABECERA_M2, vacio)
        self.assertEqual((datos["checks"], datos["motivos_ilegibles"]), ([], {"checks con check vacio": 1}))
        # Control: la fila literal se lee.
        self.assertEqual(self.leer_texto(CABECERA_M2, FILA_CHECKS_M4)["checks"], [("humo_previo: x", 1.0)])

    def test_t0(self):
        self.assertEqual(L.leer_t0('time="x" level=info msg="T0_MS=1795342200123" source=console'), 1795342200.123)
        self.assertIsNone(L.leer_t0("sin marca"))
        # dos marcas: no concluye.
        self.assertIsNone(L.leer_t0("T0_MS=1\nT0_MS=2"))

    def test_resumen_filas(self):
        filas = [{"dur": d, "estado": e} for d, e in ((10, 404), (20, 404), (30, 404), (40, 503), (1000, 0))]
        r = L.resumen_filas(filas, 404)
        self.assertEqual((r["peticiones"], r["errores"], r["n503"]), (5, 2, 1))
        self.assertEqual(r["p95_ms"], 1000)
        # Con la definicion del login, el 503 no es error.
        r = L.resumen_filas(filas, 401, L.es_error_login)
        self.assertEqual(r["errores"], 1)


class EscanerAntiFuga(unittest.TestCase):
    def test_formas_codificadas(self):
        formas = L.formas_codificadas("Humo de recuperación 1")
        self.assertIn("Humo%20de%20recuperaci%C3%B3n%201", formas)
        self.assertIn("Humo+de+recuperaci%C3%B3n+1", formas)
        self.assertIn("Humo de recuperaci\\u00f3n 1", formas)
        self.assertIn("Humo de recuperación 1", formas)

    def test_busca_tal_cual_y_codificado_con_su_control(self):
        literales = {"texto": "Humo de recuperación 1"}
        for contenido in (b"xx Humo de recuperaci\xc3\xb3n 1 yy", b"Humo%20de%20recuperaci%C3%B3n%201",
                          b'{"t": "Humo de recuperaci\\u00f3n 1"}'):
            self.assertEqual(L.buscar_en_bytes(contenido, literales), ["texto"])
        # Control negativo: otro contenido no lo encuentra.
        self.assertEqual(L.buscar_en_bytes(b"nada que ver", literales), [])

    def test_patron_de_codigo(self):
        patrones = [("codigo", L.PATRON_CODIGO)]
        self.assertEqual(L.buscar_en_bytes(b"x ABCD-EFGH-IJKL-MNOP-QRST-UVWX-2345-6723 y", {}, patrones), ["codigo"])
        self.assertEqual(L.buscar_en_bytes(b"ABCD-EFGH-IJKL", {}, patrones), [])

    def test_directorio_ids_solo_en_los_ficheros_que_no_los_necesitan(self):
        ident = "0123456789abcdef0123456789abcdef"
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            (d / "k6.csv").write_text("x " + ident, encoding="utf-8")
            (d / "log_api.txt").write_text("empresa " + ident, encoding="utf-8")
            (d / "k6_salida.txt").write_text("limpio", encoding="utf-8")
            (d / "otro.txt").write_text("clave Estres-abc", encoding="utf-8")
            hallazgos = L.escanear_directorio(d, {"contrasena": "Estres-abc"}, {"empresa0": ident}, [])
        self.assertEqual(hallazgos, {"k6.csv": ["empresa0"], "otro.txt": ["contrasena"]})

    def test_escaneo_por_trozos_con_solape(self):
        with tempfile.TemporaryDirectory() as d:
            ruta = pathlib.Path(d) / "grande.txt"
            ruta.write_bytes(b"a" * 1000 + b"SECRETO-XYZ" + b"b" * 1000)
            # Trozo de 1005 bytes: el literal cae partido entre dos trozos.
            self.assertEqual(L.escanear_fichero(ruta, {"s": "SECRETO-XYZ"}, trozo=1005, solape=64), ["s"])

    def test_centinela_es_el_control_del_escaner(self):
        self.assertEqual(L.veredicto_fuga({}, True)[0], "PASA")
        self.assertEqual(L.veredicto_fuga({"a": ["x"]}, True)[0], "SIN CONCLUSION")
        # Si no ve su centinela, no es de fiar aunque no encuentre nada.
        self.assertEqual(L.veredicto_fuga({}, False)[0], "SIN CONCLUSION")

    def ejecucion(self, literales=None, ids=()):
        return types.SimpleNamespace(salida=pathlib.Path(tempfile.mkdtemp()), ids_empresas=list(ids),
                                     literales=literales or {"contrasena": "Estres-abc"})

    def test_escanear_salida_pasa_con_su_control_y_sin_ficheros_con_fugas(self):
        ej = self.ejecucion()
        try:
            (ej.salida / "k6_salida.txt").write_text("todo limpio", encoding="utf-8")
            self.assertEqual(L.escanear_salida(ej)[0], "PASA")
            # El centinela se borra al terminar.
            self.assertFalse((ej.salida / L.CARPETA_CENTINELA).exists())
        finally:
            shutil.rmtree(ej.salida, ignore_errors=True)

    def test_un_escaner_ciego_da_sin_conclusion(self):
        ej = self.ejecucion()
        try:
            # El escaner no encuentra nada, ni su propio centinela: no es de fiar.
            with mock.patch.object(L, "escanear_fichero", lambda *a, **k: []):
                v, t = L.escanear_salida(ej)
            self.assertEqual(v, "SIN CONCLUSION")
            self.assertIn("centinela", t)
        finally:
            shutil.rmtree(ej.salida, ignore_errors=True)

    def test_una_fuga_real_da_sin_conclusion_y_el_centinela_no_la_tapa(self):
        ej = self.ejecucion()
        try:
            (ej.salida / "k6_salida.txt").write_text("la clave es Estres-abc", encoding="utf-8")
            v, t = L.escanear_salida(ej)
            self.assertEqual(v, "SIN CONCLUSION")
            self.assertIn("k6_salida.txt", t)
            self.assertNotIn(L.CARPETA_CENTINELA, t)
        finally:
            shutil.rmtree(ej.salida, ignore_errors=True)

    def test_un_codigo_de_seguimiento_en_cualquier_fichero_es_fuga(self):
        ej = self.ejecucion()
        try:
            (ej.salida / "log_api.txt").write_text("codigo ABCD-EFGH-IJKL-MNOP-QRST-UVWX-2345-6723", encoding="utf-8")
            self.assertEqual(L.escanear_salida(ej)[0], "SIN CONCLUSION")
        finally:
            shutil.rmtree(ej.salida, ignore_errors=True)

    def test_patron_de_codigo_minusculas_y_32_seguidos(self):
        patrones = [("codigo", L.PATRON_CODIGO)]
        self.assertEqual(L.buscar_en_bytes(b"abcd-efgh-ijkl-mnop-qrst-uvwx-2345-6723", {}, patrones), ["codigo"])
        self.assertEqual(L.buscar_en_bytes(b"x ABCDEFGHIJKLMNOPQRSTUVWX23456723 y", {}, patrones), ["codigo"])
        # Control negativo: 31 caracteres seguidos o 7 grupos no son un codigo.
        self.assertEqual(L.buscar_en_bytes(b"ABCDEFGHIJKLMNOPQRSTUVWX2345672", {}, patrones), [])
        self.assertEqual(L.buscar_en_bytes(b"ABCD-EFGH-IJKL-MNOP-QRST-UVWX-2345", {}, patrones), [])

    def test_el_centinela_va_dentro_del_texto_real_que_se_escanea(self):
        ej = self.ejecucion()
        vistos = []
        real = L.buscar_en_bytes

        def espia(contenido, literales, patrones=()):
            vistos.append((contenido, literales))
            return real(contenido, literales, patrones)
        try:
            with mock.patch.object(L, "lineas_salida", ["linea uno", "linea dos"]), \
                    mock.patch.object(L, "buscar_en_bytes", espia), mock.patch.object(L, "sinc", lambda t: None):
                L.escanear_texto_final(ej)
        finally:
            shutil.rmtree(ej.salida, ignore_errors=True)
        self.assertEqual(len(vistos), 1)
        contenido, literales = vistos[0]
        texto = contenido.decode("utf-8")
        # Es UNA sola busqueda sobre el texto de la salida mas el centinela, que va al final.
        self.assertTrue(texto.startswith("linea uno" + chr(10) + "linea dos" + chr(10)))
        self.assertTrue(texto.endswith(literales["centinela"]))

    def test_escanear_texto_final_con_su_control(self):
        ej = self.ejecucion(ids=["0123456789abcdef0123456789abcdef"])
        avisos = []
        with mock.patch.object(L, "sinc", lambda t: avisos.append(t)):
            # Texto limpio: sin avisos.
            with mock.patch.object(L, "lineas_salida", ["todo bien"]):
                L.escanear_texto_final(ej)
            self.assertEqual(avisos, [])
            # La contrasena sembrada en una linea: aviso, y no repite el valor.
            with mock.patch.object(L, "lineas_salida", ["fallo con Estres-abc en el texto"]):
                L.escanear_texto_final(ej)
            self.assertEqual(len(avisos), 1)
            self.assertNotIn("Estres-abc", avisos[0])
            # Un escaner de texto ciego no es de fiar: aviso por su centinela.
            avisos.clear()
            with mock.patch.object(L, "lineas_salida", ["todo bien"]), \
                    mock.patch.object(L, "buscar_en_bytes", lambda *a, **k: []):
                L.escanear_texto_final(ej)
            self.assertEqual(len(avisos), 1)
            self.assertIn("centinela", avisos[0])


class ControlesPuros(unittest.TestCase):
    """Funciones puras de la ronda de correcciones, con oraculos literales y su control positivo."""

    def test_ips_vistas_son_exactamente_las_del_plan(self):
        esperadas = ["198.18.0.1", "198.18.0.2"]
        filas = [{"escenario": "seguimiento_ips", "ip": "198.18.0.1"}, {"escenario": "seguimiento_ips", "ip": "198.18.0.2"}]
        # Control positivo: coinciden y ninguna fila sin ip.
        self.assertEqual(L.validar_ips_vistas(filas, "seguimiento_ips", esperadas), [])
        # Falta una IP del plan.
        self.assertEqual(len(L.validar_ips_vistas(filas[:1], "seguimiento_ips", esperadas)), 1)
        # Sobra una IP que no es del plan.
        extra = filas + [{"escenario": "seguimiento_ips", "ip": "198.18.0.9"}]
        self.assertEqual(len(L.validar_ips_vistas(extra, "seguimiento_ips", esperadas)), 1)
        # Una fila sin etiqueta ip es un motivo propio (y deja el conjunto igual).
        sin_ip = filas + [{"escenario": "seguimiento_ips", "ip": None}]
        self.assertEqual(len(L.validar_ips_vistas(sin_ip, "seguimiento_ips", esperadas)), 1)
        # Las filas de otro escenario no cuentan.
        otras = filas + [{"escenario": "sonda_salud", "ip": None}]
        self.assertEqual(L.validar_ips_vistas(otras, "seguimiento_ips", esperadas), [])

    def test_conciliar_503_uno_a_uno_por_hora(self):
        c = L.conciliar_503([(100.0, 100.5), (200.0, 200.4)], [100.2, 200.2])
        self.assertEqual(c, {"emparejados": 2, "sin_evento": 0, "eventos_sin_503": 0})
        c = L.conciliar_503([(100.0, 100.5), (200.0, 200.4)], [100.2, 150.0])
        self.assertEqual(c, {"emparejados": 1, "sin_evento": 1, "eventos_sin_503": 1})
        # Un evento se empareja con un solo 503: dos 503 y una linea dejan uno sin linea.
        c = L.conciliar_503([(100.0, 100.5), (100.1, 100.6)], [100.3])
        self.assertEqual((c["emparejados"], c["sin_evento"]), (1, 1))
        # Tolerancia de 2 s: 1,9 s despues del fin empareja y 2,6 s no.
        self.assertEqual(L.conciliar_503([(100.0, 100.5)], [102.4])["emparejados"], 1)
        self.assertEqual(L.conciliar_503([(100.0, 100.5)], [103.1])["emparejados"], 0)

    def test_cifras_congeladas_como_literales(self):
        tasas = L.tasas_de(0.0196)
        # Control positivo: las cifras derivadas de t = 0,0196 son las de la segunda congelacion.
        L.comprobar_cifras_congeladas(tasas, 3402, 428, 8)
        self.assertEqual((tasas["inundacion"], tasas["login_pico"], tasas["login_base"]), (153.06, 102.04, 10.20))
        # Cada cifra que no coincide para la ejecucion.
        with self.assertRaises(L.Parada):
            L.comprobar_cifras_congeladas(tasas, 3401, 428, 8)
        with self.assertRaises(L.Parada):
            L.comprobar_cifras_congeladas(tasas, 3402, 427, 8)
        with self.assertRaises(L.Parada):
            L.comprobar_cifras_congeladas(tasas, 3402, 428, 9)
        with self.assertRaises(L.Parada):
            L.comprobar_cifras_congeladas({**tasas, "inundacion": 153.07}, 3402, 428, 8)

    def test_espera_por_medianoche(self):
        medianoche = 1795392000
        # No cruza: 0.
        self.assertEqual(L.espera_por_medianoche(medianoche - 1000, 500), 0.0)
        # Cruza: espera hasta las 00:00 mas 5 s de margen.
        self.assertEqual(L.espera_por_medianoche(medianoche - 1000, 1500), 1005.0)
        # Esperar mas de 1800 s es PARADA, no una espera.
        with self.assertRaises(L.Parada):
            L.espera_por_medianoche(medianoche - 2000, 2500)

    def test_j5_el_sandwich_necesita_el_positivo_y_la_misma_ventana(self):
        def pet(estado, inicio):
            return {"estado": estado, "inicio": inicio, "fin": inicio + 0.1}
        base = 1795342203.0
        # Control positivo: 429 antes y 404 despues, en la misma ventana de 60 s.
        self.assertEqual(L.evaluar_j5(pet(429, base), pet(404, base + 10), 60, 404)[0], "PASA")
        # El positivo no da 429: el control no discrimina.
        self.assertEqual(L.evaluar_j5(pet(404, base), pet(404, base + 10), 60, 404)[0], "SIN CONCLUSION")
        # El negativo sigue dando 429: el contador sobrevivio a la recreacion.
        self.assertEqual(L.evaluar_j5(pet(429, base), pet(429, base + 10), 60, 404)[0], "SIN CONCLUSION")
        # Otra ventana: el negativo no discrimina.
        self.assertEqual(L.evaluar_j5(pet(429, base), pet(404, base + 60), 60, 404)[0], "SIN CONCLUSION")
        # Un estado distinto del aceptado tras recrear.
        self.assertEqual(L.evaluar_j5(pet(429, base), pet(500, base + 10), 60, 404)[0], "SIN CONCLUSION")
        # Peticion ambigua (cruza la frontera de ventana): no discrimina.
        cruza = {"estado": 429, "inicio": 1795342259.95, "fin": 1795342260.05}
        self.assertEqual(L.evaluar_j5(cruza, pet(404, 1795342265.0), 60, 404)[0], "SIN CONCLUSION")

    def test_rutas_sucias(self):
        self.assertEqual(L.rutas_sucias(""), [])
        self.assertEqual(L.rutas_sucias(None), [])
        self.assertEqual(L.rutas_sucias(" M proxy/comun.caddy\n?? proxy/nuevo.caddy\n"),
                         [" M proxy/comun.caddy", "?? proxy/nuevo.caddy"])

    def test_diferencias_del_caddy_de_produccion(self):
        produccion = {"services": {"caddy": {"command": ["caddy", "run", "--config", "/etc/caddy/Caddyfile.produccion"]}},
                      "networks": {"edge": {"internal": True}}}
        # Control positivo: iguales, sin diferencias.
        self.assertEqual(L.diferencias_caddy_produccion(produccion, json.loads(json.dumps(produccion))), [])
        distinto = json.loads(json.dumps(produccion))
        distinto["services"]["caddy"]["command"] = ["caddy", "run"]
        self.assertEqual(len(L.diferencias_caddy_produccion(produccion, distinto)), 1)
        abierta = json.loads(json.dumps(produccion))
        abierta["networks"]["edge"]["internal"] = False
        self.assertEqual(len(L.diferencias_caddy_produccion(produccion, abierta)), 1)
        # Un JSON sin la clave es una diferencia visible, no un error.
        self.assertEqual(len(L.diferencias_caddy_produccion(produccion, {"services": {}, "networks": {}})), 3)
        # Seguridad 8: los ports de caddy tambien se comparan (vacios en los dos = sin diferencia).
        con_puertos = json.loads(json.dumps(produccion))
        con_puertos["services"]["caddy"]["ports"] = [{"published": "8443"}]
        self.assertEqual(len(L.diferencias_caddy_produccion(produccion, con_puertos)), 1)

    def test_presupuesto_con_el_tamano_del_json(self):
        escenarios = [{"vus": 100}]
        self.assertEqual(L.presupuesto_k6_mib(escenarios, 0, 0), 500)
        # 1 MiB de ejecucion.json x 4 copias por VU: 100 x (5 + 4) MiB.
        self.assertEqual(L.presupuesto_k6_mib(escenarios, 0, 1048576), 900)
        self.assertEqual(L.comprobar_presupuesto(escenarios, 0, 1048576), 900)
        with self.assertRaises(L.Parada):
            L.comprobar_presupuesto([{"vus": 1000}], 0, 1048576)

    def test_csv_con_filas_ilegibles_las_cuenta(self):
        # Cabecera M2 (k6 v2.3.0, medidas_v4_25nov/m2.csv, 25/11/2026) y un 404 con la forma
        # real (error_code 1404, expected_response false: k6.csv de rep1 de L4, 24/11/2026).
        columnas = CABECERA_M2.split(",")
        buena = ["http_req_duration", "1795342200500", "500.0", "", "1404", "false", "POST", "seguimiento", "HTTP/1.1",
                 "seguimiento_ips", "404", "ip=198.18.0.1", ""]
        mala = list(buena)
        mala[1] = "no-es-un-numero"
        with tempfile.TemporaryDirectory() as d:
            ruta = pathlib.Path(d) / "k6.csv"
            with open(ruta, "w", encoding="utf-8", newline="") as f:
                w = _csv.writer(f, lineterminator="\n")
                w.writerow(columnas)
                w.writerows([buena, mala])
            datos = L.leer_csv_fases(ruta)
        self.assertEqual((len(datos["filas"]), datos["ilegibles"]), (1, 1))

    def test_victimas_medianas_con_una_ruta_caida(self):
        def rep(base, carga):
            return {ruta: {"base": {"p95_ms": base}, "carga": {"peticiones": 10, "p95_ms": carga, "tasa_errores": 0.0},
                           "descartes_aviso": 0} for ruta in L.SLO_VICTIMAS_MS}
        # Dos repeticiones sin respuestas en la carga (p95 None = infinito): la mediana es infinita y la victima FALLA.
        medianas = L.victimas_medianas([rep(50, 60), rep(50, None), rep(50, None)])
        ruta = next(iter(L.SLO_VICTIMAS_MS))
        self.assertEqual(medianas[ruta]["carga"]["p95_ms"], float("inf"))
        self.assertEqual(L.veredictos_victimas(medianas)[ruta][0], "FALLA")
        # Control positivo: tres repeticiones sanas, PASA.
        sanas = L.victimas_medianas([rep(50, 60), rep(50, 70), rep(50, 80)])
        self.assertEqual(sanas[ruta]["carga"]["p95_ms"], 70)
        self.assertEqual(L.veredictos_victimas(sanas)[ruta][0], "PASA")
        # Una BASE sin respuestas deja la mediana de la BASE sin valor y el veredicto en SIN CONCLUSION.
        sin_base = L.victimas_medianas([rep(None, 60), rep(50, 60), rep(50, 60)])
        self.assertIsNone(sin_base[ruta]["base"]["p95_ms"])
        self.assertEqual(L.veredictos_victimas(sin_base)[ruta][0], "SIN CONCLUSION")


class ValidezDelGenerador(unittest.TestCase):
    def k6(self, **cambios):
        base = {"codigo": 0, "oom": False, "sin_conclusion": [], "registro": "T0_MS=1795342200123\n",
                "desfase": 0.0, "motivo_desfase": None}
        return {**base, **cambios}

    def csv(self, **cambios):
        base = {"filas": [{"proto": "HTTP/1.1", "estado": 200}], "descartes": {}, "ilegibles": 0}
        return {**base, **cambios}

    def fallos(self, k6=None, t0=1795342200.1, csv=None, insuficientes=(), cpu=None, es_http=False):
        return L.validez_generador(k6 or self.k6(), t0, csv or self.csv(), set(insuficientes),
                                   cpu if cpu is not None else {"k6": {"maxima": 100.0}}, es_http)

    def test_sin_fallos_es_la_lista_vacia(self):
        self.assertEqual(self.fallos(), [])

    def test_cada_causa_da_un_fallo(self):
        casos = {
            "codigo de k6": dict(k6=self.k6(codigo=1)),
            "oom de k6": dict(k6=self.k6(oom=True)),
            "sin T0": dict(t0=None),
            "alineacion perdida": dict(k6=self.k6(registro="ALINEACION_PERDIDA tarde_ms=9000")),
            "cpu sin medir": dict(k6=self.k6(desfase=None, motivo_desfase="reloj")),
            "cpu de k6 alta": dict(cpu={"k6": {"maxima": 321.0}}),
            "sin muestras de cpu": dict(cpu={"k6": None}),
            "descartes sin aviso": dict(csv=self.csv(descartes={"seguimiento__base": [1.0]})),
            "filas ilegibles": dict(csv=self.csv(ilegibles=2)),
            "protocolo": dict(csv=self.csv(filas=[{"proto": "HTTP/2.0", "estado": 200}])),
            "sin peticiones": dict(csv=self.csv(filas=[])),
            "sin conclusion de ejecutar_k6": dict(k6=self.k6(sin_conclusion=["start sin ver"])),
        }
        for nombre, argumentos in casos.items():
            with self.subTest(nombre):
                self.assertEqual(len(self.fallos(**argumentos)), 1, nombre)

    def test_descartes_con_el_aviso_no_son_fallo_de_validez(self):
        csv = self.csv(descartes={"seguimiento__base": [1.0]})
        self.assertEqual(self.fallos(csv=csv, insuficientes={"seguimiento__base"}), [])

    def test_los_421_solo_cuentan_en_http(self):
        csv = self.csv(filas=[{"proto": "HTTP/1.1", "estado": 421}])
        self.assertEqual(self.fallos(csv=csv, es_http=False), [])
        self.assertEqual(len(self.fallos(csv=csv, es_http=True)), 1)


class ControlesConMocks(unittest.TestCase):
    """E/S con Docker sustituida por mocks: el orden de las llamadas y las PARADAS."""

    def resultado(self, rc=0, out="", err=""):
        return types.SimpleNamespace(rc=rc, out=out, err=err, todo=out + err)

    def ejecucion(self, directorio):
        return types.SimpleNamespace(datos=pathlib.Path(directorio), imagen="imagen", cpus_k6="2,3",
                                     id_a="a" * 32, contrasena="Estres-x", linea_limites="x")

    def test_cliente_de_control_con_plazo_y_limpieza(self):
        with tempfile.TemporaryDirectory() as d:
            ej = self.ejecucion(d)
            llamadas = []

            def vencido(args, timeout=900):
                llamadas.append((args, timeout))
                if args[:2] == ["docker", "run"]:
                    raise subprocess.TimeoutExpired(args, timeout)
                return self.resultado()
            with mock.patch.object(L, "ejecutar", vencido):
                with self.assertRaises(L.Parada):
                    L.cliente_control(ej, "x", "10.88.1.2", [L.peticion_control("POST", "/salud", "h")])
            # PY-5: 1 peticion x 15 s + 60 s de margen, y el contenedor se borra a la fuerza.
            self.assertEqual(llamadas[0][1], 75)
            # Anti-fuga de L5 (25/11/2026): el cliente anula las etiquetas de
            # compose heredadas de la imagen, para que `compose logs api` no
            # recoja su salida (cuerpos con códigos de seguimiento).
            orden = llamadas[0][0]
            etiquetas = [orden[i + 1] for i, x in enumerate(orden) if x == "--label"]
            self.assertIn("com.docker.compose.project=", etiquetas)
            self.assertIn("com.docker.compose.service=", etiquetas)
            self.assertIn("canario.estres=control", etiquetas)
            self.assertEqual(llamadas[1][0][:3], ["docker", "rm", "-f"])
            # Control positivo: con respuesta, devuelve los resultados.
            salida = '[{"estado": 405, "cuerpo": "", "inicio": 1.0, "fin": 2.0}]'
            with mock.patch.object(L, "ejecutar", lambda args, timeout=900: self.resultado(out=salida)):
                r = L.cliente_control(ej, "x", "10.88.1.2", [L.peticion_control("POST", "/salud", "h")])
            self.assertEqual(r[0]["estado"], 405)
            # Y un numero de resultados distinto del de peticiones es PARADA.
            with mock.patch.object(L, "ejecutar", lambda args, timeout=900: self.resultado(out="[]")):
                with self.assertRaises(L.Parada):
                    L.cliente_control(ej, "x", "10.88.1.2", [L.peticion_control("POST", "/salud", "h")])

    def sandwich(self, positivo, negativo, modo="l3"):
        orden = []
        respuestas = {"j5pos_r2": [positivo], "j5neg_r2": [negativo]}

        def cliente(ej, nombre, ip, peticiones):
            orden.append(nombre)
            return respuestas[nombre]

        # create_autospec: el doble lleva la firma REAL (ej, rep, *, etiqueta).
        # El `def recrear(ej)` de antes aceptaba la llamada vieja `recrear_api(ej)`
        # que fallaba de verdad en la repetición 2.
        recrear = mock.create_autospec(L.recrear_api, side_effect=lambda *args, **kwargs: orden.append("recrear_api"))
        ips_previas = {"control": ["198.18.9.9"]}
        pet = lambda estado, inicio: {"estado": estado, "inicio": inicio, "fin": inicio + 0.1}  # noqa: E731
        respuestas["j5pos_r2"] = [pet(*positivo)]
        respuestas["j5neg_r2"] = [pet(*negativo)]
        ej = types.SimpleNamespace(id_a="a" * 32, contrasena="x")
        with mock.patch.object(L, "cliente_control", cliente), mock.patch.object(L, "recrear_api", recrear), \
                mock.patch.object(L, "esperar_ventana", lambda *a: None), mock.patch.object(L, "p", lambda *a: None), \
                mock.patch.object(L, "linea_control", lambda *a: None):
            fallos = L.sandwich_j5(ej, modo, 2, ips_previas)
        self.assertEqual(recrear.call_args_list, [mock.call(ej, 2, etiqueta="J5")])
        return orden, fallos

    def test_j5_recrea_la_api_entre_el_positivo_y_el_negativo(self):
        base = 1795342203.0
        # PY-12: en L3 y en L3b el sandwich usa la regla acceso: el aceptado es 401, no 404.
        for modo in ("l3", "l3b"):
            orden, fallos = self.sandwich((429, base), (401, base + 10), modo=modo)
            self.assertEqual(orden, ["j5pos_r2", "recrear_api", "j5neg_r2"], modo)
            self.assertEqual(fallos, [], modo)
            # H6: J5 da SIN CONCLUSION, no FALLA: si el contador sobrevive a la recreacion, hay un fallo de validez.
            self.assertEqual(len(self.sandwich((429, base), (429, base + 10), modo=modo)[1]), 1, modo)
            # Sin positivo (la IP no estaba saturada) tampoco se da por bueno.
            self.assertEqual(len(self.sandwich((401, base), (401, base + 10), modo=modo)[1]), 1, modo)
            # Un 404 (la regla de seguimiento) ya no es el aceptado.
            self.assertEqual(len(self.sandwich((429, base), (404, base + 10), modo=modo)[1]), 1, modo)

    def test_el_login_de_l3_usa_una_empresa_inexistente_de_32_hex(self):
        cuerpo = json.loads(L.cuerpo_login(types.SimpleNamespace(id_a=None, contrasena="Estres-x")))
        self.assertRegex(cuerpo["empresa"], "^[0-9a-f]{32}$")
        # Control: con empresa de la ejecucion, es esa.
        self.assertEqual(json.loads(L.cuerpo_login(types.SimpleNamespace(id_a="a" * 32, contrasena="x")))["empresa"],
                         "a" * 32)

    def test_s8_falla_si_un_compose_config_falla_y_muestra_su_error(self):
        config = json.dumps({"services": {"caddy": {"command": ["caddy"]}}, "networks": {"edge": {"internal": True}}})

        def ejecutar(args, timeout=900):
            if "rev-parse" in args:
                return self.resultado(out="abc123\n")
            if "status" in args:
                return self.resultado(out="")
            return self.resultado(rc=1, err="error de compose visible")
        with mock.patch.object(L, "p", lambda *a: None), mock.patch.object(L, "ejecutar", ejecutar), \
                mock.patch.object(L, "dc", lambda *a, **k: self.resultado(out=config)):
            with self.assertRaises(L.Parada) as contexto:
                L.comprobar_origen_produccion()
        self.assertIn("error de compose visible", str(contexto.exception))

    def test_origen_de_produccion(self):
        config = json.dumps({"services": {"caddy": {"command": ["caddy"]}}, "networks": {"edge": {"internal": True}}})

        def ejecutar(sucio, config_prod):
            def f(args, timeout=900):
                if "rev-parse" in args:
                    return self.resultado(out="abc123\n")
                if "status" in args:
                    return self.resultado(out=sucio)
                return self.resultado(out=config_prod)
            return f
        with mock.patch.object(L, "p", lambda *a: None), mock.patch.object(L, "dc", lambda *a, **k: self.resultado(out=config)):
            # Control positivo: limpio y con el mismo config.
            with mock.patch.object(L, "ejecutar", ejecutar("", config)):
                L.comprobar_origen_produccion()
            # Cambios sin commitear en proxy/: PARADA.
            with mock.patch.object(L, "ejecutar", ejecutar(" M proxy/comun.caddy\n", config)):
                with self.assertRaises(L.Parada):
                    L.comprobar_origen_produccion()
            # El override difiere de compose.produccion.yaml: PARADA.
            otro = json.dumps({"services": {"caddy": {"command": ["otro"]}}, "networks": {"edge": {"internal": True}}})
            with mock.patch.object(L, "ejecutar", ejecutar("", otro)):
                with self.assertRaises(L.Parada):
                    L.comprobar_origen_produccion()


class SondaDeDescartes(unittest.TestCase):
    """E16: las seis condiciones de la sonda de E14, con el patron REAL de k6."""
    T0 = 1795342200.0
    # Patron real: descarta 0,5 a 2,0, lanza la de 2,5, descarta 3,0 a 4,5, lanza la de 5,0, y asi hasta 12,0.
    REAL = [0.5, 1.0, 1.5, 2.0, 3.0, 3.5, 4.0, 4.5, 5.5, 6.0, 6.5, 7.0, 8.0, 8.5, 9.0, 9.5, 10.5, 11.0, 11.5, 12.0]

    def evaluar(self, relativas, iteraciones=5):
        return sonda_descartes.evaluar_marcas([self.T0 + r for r in relativas], self.T0, iteraciones)

    def test_patron_real_pasa(self):
        v, t = self.evaluar(self.REAL)
        self.assertEqual(v, "PASA", t)
        # 24 o 25 llegadas programadas (la de 12,0 s compite con el fin del plazo): el +-1 lo cubre.
        self.assertEqual(self.evaluar(self.REAL, 4)[0], "PASA")
        self.assertEqual(self.evaluar(self.REAL, 3)[0], "PASA")

    def test_la_primera_marca_puede_tener_k_0_por_la_carrera_de_arranque(self):
        # La llegada de 0 s se descarta si el VU aun no esta esperando: marcas en 0,0, 0,5, 1,0, 1,5, 2,0, 3,0...
        marcas = [0.0] + self.REAL
        self.assertEqual(marcas[:6], [0.0, 0.5, 1.0, 1.5, 2.0, 3.0])
        v, t = self.evaluar(marcas, 4)
        self.assertEqual(v, "PASA", t)
        # Con k = 2 como primera marca sigue siendo PARADA (se cubre mas abajo): aqui, k = 0 y k = 1 son los unicos.
        self.assertEqual(self.evaluar(self.REAL[1:], 5)[0], "PARADA")

    def test_cada_condicion_incumplida_da_parada(self):
        casos = {
            "(1) menos de 5 marcas": (self.REAL[:4], 5),
            "(1) sin marcas": ([], 5),
            "(2) una marca fuera de +-0,2 s": ([0.5, 1.0, 1.5, 2.0, 3.0, 3.74], 5),
            "(2) una marca antes de T0 (k negativo)": ([-0.5, 0.0, 0.5, 1.0, 1.5, 2.0], 5),
            "(3) k repetido (marcas al quedar libre el VU)": ([0.5, 1.0, 1.5, 2.0, 2.1, 3.0, 3.5], 5),
            "(4) todas al final": ([9.0, 9.5, 10.0, 10.5, 11.0, 11.5], 5),
            "(4) primera con k = 2": ([1.0, 1.5, 2.0, 3.0, 3.5, 4.0], 5),
            "(5) salto de k de 3": ([0.5, 1.0, 1.5, 3.0, 3.5, 4.0], 5),
            "(6) la conciliacion no cuadra": (self.REAL, 0),
            "(6) y sobran iteraciones": (self.REAL, 9),
        }
        for nombre, (relativas, iteraciones) in casos.items():
            with self.subTest(nombre):
                v, t = self.evaluar(relativas, iteraciones)
                self.assertEqual(v, "PARADA", nombre)
                self.assertIn(nombre[:3], t)

    def test_sin_t0_es_parada(self):
        self.assertEqual(sonda_descartes.evaluar_marcas([self.T0 + 0.5], None, 5)[0], "PARADA")

    def test_cada_condicion_es_una_funcion_con_nombre(self):
        ks = [1, 2, 3, 4, 6]
        self.assertTrue(sonda_descartes.condicion_1_minimo([0] * 5))
        self.assertFalse(sonda_descartes.condicion_1_minimo([0] * 4))
        self.assertTrue(sonda_descartes.condicion_3_sin_repetidos(ks))
        self.assertFalse(sonda_descartes.condicion_3_sin_repetidos([1, 1]))
        self.assertTrue(sonda_descartes.condicion_4_primera([0, 1]))
        self.assertTrue(sonda_descartes.condicion_4_primera([1, 2]))
        self.assertFalse(sonda_descartes.condicion_4_primera([2, 3]))
        self.assertTrue(sonda_descartes.condicion_5_saltos(ks))
        self.assertFalse(sonda_descartes.condicion_5_saltos([1, 4]))
        self.assertTrue(sonda_descartes.condicion_6_conciliacion(20, 5))
        self.assertFalse(sonda_descartes.condicion_6_conciliacion(20, 2))

    def test_los_parametros_congelados_coinciden_en_el_js_y_en_el_py(self):
        # E16: 12 s, 2/s, 1 VU, gracefulStop de 5 s, endpoint de 2 s y 24 llegadas programadas.
        import re
        carpeta = pathlib.Path(__file__).resolve().parent
        js = (carpeta / "sonda_descartes.js").read_text(encoding="utf-8")
        self.assertEqual(re.findall(r"rate: (\d+),", js), ["2"])
        self.assertEqual(re.findall(r"duration: '(\d+)s'", js), ["12"])
        self.assertEqual(re.findall(r"preAllocatedVUs: (\d+),", js), ["1"])
        self.assertEqual(re.findall(r"maxVUs: (\d+),", js), ["1"])
        self.assertEqual(re.findall(r"gracefulStop: '(\d+)s'", js), ["5"])
        self.assertEqual((sonda_descartes.TASA_LLEGADAS, sonda_descartes.DURACION_ESCENARIO_S), (2, 12))
        self.assertEqual(sonda_descartes.LLEGADAS_PROGRAMADAS, 24)
        self.assertIn("time.sleep(2)", sonda_descartes.CODIGO_SERVIDOR)

    def test_servidor_lento_compila_y_no_lleva_comillas_dobles_ni_barras(self):
        import ast
        ast.parse(sonda_descartes.CODIGO_SERVIDOR)
        self.assertNotIn('"', sonda_descartes.CODIGO_SERVIDOR)
        self.assertNotIn(chr(92), sonda_descartes.CODIGO_SERVIDOR)

    def test_leer_marcas_del_csv_cuenta_marcas_e_iteraciones(self):
        with tempfile.TemporaryDirectory() as d:
            ruta = pathlib.Path(d) / "sonda.csv"
            # Cabecera real de sonda_descartes.csv (CABECERA_SONDA, k6 v2.3.0, 24/11/2026) y
            # filas con su forma (dropped_iterations,<ms>,1.000000,,sonda,,,).
            ruta.write_text(CABECERA_SONDA + "\n"
                            "dropped_iterations,1795342200500,1.000000,,sonda,,,\n"
                            "http_reqs,1795342200600,1.000000,lento,sonda,200,,\n"
                            "iterations,1795342200700,1.000000,,sonda,,,\n"
                            "dropped_iterations,1795342201000,1.000000,,sonda,,,\n", encoding="utf-8", newline="")
            self.assertEqual(sonda_descartes.leer_marcas(ruta), ([1795342200.5, 1795342201.0], 1))
            # Una ultima linea sin salto final es un error visible, no una fila menos.
            ruta.write_text(CABECERA_SONDA + "\n"
                            "dropped_iterations,1795342200500,1.000000,,sonda,,,", encoding="utf-8", newline="")
            with self.assertRaises(ValueError):
                sonda_descartes.leer_marcas(ruta)

    def test_la_sonda_se_ejecuta_con_el_cpuset_de_k6_y_captura_el_plazo(self):
        llamadas = []

        def vencido(args, timeout=900):
            llamadas.append(args)
            if args[:2] == ["docker", "run"] and "--rm" in args:
                raise subprocess.TimeoutExpired(args, timeout)
            return types.SimpleNamespace(rc=0, out="", err="", todo="")
        constantes = {"prefijo": "p_", "usuario_api": "1:1", "usuario_k6": "2:2", "memoria_k6": "1g"}
        avisos = []
        marcas, iteraciones, inicio, motivo = sonda_descartes.ejecutar_sonda(
            vencido, "img", "k6", "2,3", pathlib.Path("."), constantes, avisar=avisos.append)
        self.assertEqual((marcas, iteraciones, inicio), ([], 0, None))
        self.assertIn("plazo", motivo)
        # Las limpiezas responden rc=0 y los listados salen vacíos: ningún aviso.
        self.assertEqual(avisos, [])
        # Los dos contenedores van en el cpuset de k6 y la red se borra explicitamente.
        corridas = [a for a in llamadas if a[:2] == ["docker", "run"]]
        self.assertEqual(len(corridas), 2)
        for a in corridas:
            self.assertEqual(a[a.index("--cpuset-cpus") + 1], "2,3")
        self.assertIn(["docker", "network", "rm", "p_sonda_red"], llamadas)

    def test_lanzar_no_importa_la_sonda_al_cargarse(self):
        fuente = pathlib.Path(L.__file__).read_text(encoding="utf-8")
        for linea in fuente.splitlines():
            if linea.startswith(("import sonda_descartes", "from sonda_descartes")):
                self.fail("lanzar.py importa sonda_descartes en el nivel del modulo: debe cargarse solo en --pico")
        self.assertIn("    import sonda_descartes\n", fuente)


class CondicionDeLaSonda(unittest.TestCase):
    """La sonda de descartes (E14) corre solo en la repetición 1 de --pico.
    Se ejecuta ejecutar_repeticion_fases de verdad, con todo lo de Docker
    simulado, y se corta con una excepción centinela justo después del punto
    donde se decide la sonda (la primera llamada a fases_de). Los oráculos son
    literales: las ocho combinaciones modo x repetición y cuáles llaman."""

    class Corte(Exception):
        pass

    def correr(self, modo, rep):
        """Devuelve la lista de llamadas a la sonda de esa combinación."""
        llamadas = []

        def corte(*_):
            raise self.Corte()

        with tempfile.TemporaryDirectory() as d:
            ej = L.Ejecucion(0.05, None, pathlib.Path(d), [0], [1], {})
            ej.plan_ips = {1: ["10.0.0.1"], 2: ["10.0.0.2"]}
            ej.ids_empresas = []
            # Enmienda v4.4: un ej.eventos falso explícito (como en EvaluarRepeticion), sin
            # eventos; ejecutar_repeticion_fases exige que exista.
            ej.eventos = types.SimpleNamespace(copia=list)
            parches = [mock.patch.object(L, "hora_motor_ahora", lambda: 100.0),
                       mock.patch.object(L, "espera_por_medianoche", lambda *a: 0),
                       mock.patch.object(L, "preparar_repeticion", lambda *a: None),
                       mock.patch.object(L, "sandwich_j5", lambda *a: []),
                       mock.patch.object(L, "alta_empresa", lambda nombre: "e" * 32),
                       mock.patch.object(L, "comprobar_sonda_descartes", lambda e: llamadas.append((modo, rep))),
                       mock.patch.object(L, "fases_de", corte),
                       mock.patch.object(L, "p", lambda *a, **k: None)]
            for parche in parches:
                parche.start()
                self.addCleanup(parche.stop)
            # La excepción que sale es la original (Corte), no la del finally.
            with self.assertRaises(self.Corte):
                L.ejecutar_repeticion_fases(ej, modo, rep, 2)
            # Control positivo: el finally escribió el fichero de eventos, vacío.
            destino = pathlib.Path(d) / f"rep{rep}" / "eventos_docker.json"
            self.assertEqual(json.loads(destino.read_text(encoding="utf-8")), [])
        return llamadas

    def test_solo_pico_en_la_repeticion_1(self):
        esperado = {("l2", 1): [], ("l2", 2): [], ("pico", 1): [("pico", 1)], ("pico", 2): [],
                    ("l3", 1): [], ("l3", 2): [], ("l3b", 1): [], ("l3b", 2): []}
        obtenido = {(m, r): self.correr(m, r) for m in ("l2", "pico", "l3", "l3b") for r in (1, 2)}
        self.assertEqual(obtenido, esperado)

    def test_control_positivo_la_sonda_si_se_llama(self):
        # Si el montaje no llegara al punto de decisión, todo sería [] y la
        # prueba anterior pasaría en vacío: aquí se exige al menos una llamada.
        self.assertEqual(self.correr("pico", 1), [("pico", 1)])


class PrecondicionDeEventos(unittest.TestCase):
    """Enmienda v4.4: ejecutar_repeticion_fases y ejecutar_repeticion exigen
    ej.eventos antes de cualquier efecto. Los mensajes son literales."""
    MENSAJE_FASES = ("ejecutar_repeticion_fases: ej.eventos sin iniciar: lo crean ejecutar_l1 y ejecutar_modo antes "
                     "de la primera repetición")
    MENSAJE_L1 = ("ejecutar_repeticion: ej.eventos sin iniciar: lo crean ejecutar_l1 y ejecutar_modo antes de la "
                  "primera repetición")

    class Corte(Exception):
        pass

    def correr(self, funcion, eventos):
        """Ejecuta la repetición 1 (L2 en fases) con ej.eventos = eventos y
        preparar_repeticion cortando con Corte. Devuelve (excepción, carpeta rep1
        existe, llamadas a hora_motor_ahora)."""
        def corte(*_):
            raise self.Corte()
        hora = mock.MagicMock(return_value=1000.0)
        with tempfile.TemporaryDirectory() as d, contextlib.ExitStack() as pila:
            ej = L.Ejecucion(0.05, None, pathlib.Path(d), [0], [1], {})
            ej.eventos = eventos
            for parche in (mock.patch.object(L, "hora_motor_ahora", hora),
                           mock.patch.object(L, "preparar_repeticion", corte),
                           mock.patch.object(L, "p", lambda *a, **k: None)):
                pila.enter_context(parche)
            try:
                if funcion == "fases":
                    L.ejecutar_repeticion_fases(ej, "l2", 1, 1)
                else:
                    L.ejecutar_repeticion(ej, 1, 1)
            except Exception as error:  # noqa: BLE001 - la prueba mira el tipo exacto
                excepcion = error
            else:
                excepcion = None
            return excepcion, (pathlib.Path(d) / "rep1").exists(), hora.call_count

    def comprobar(self, funcion, mensaje):
        excepcion, carpeta, horas = self.correr(funcion, None)
        # Sin ej.eventos: RuntimeError con su mensaje literal (nunca AttributeError), sin
        # carpeta rep1 y sin llamar a hora_motor_ahora.
        self.assertIs(type(excepcion), RuntimeError, repr(excepcion))
        self.assertEqual(str(excepcion), mensaje)
        self.assertFalse(carpeta)
        self.assertEqual(horas, 0)
        # Control: con el falso, sale la excepción original (Corte) tras crear rep1.
        excepcion, carpeta, horas = self.correr(funcion, types.SimpleNamespace(copia=list))
        self.assertIs(type(excepcion), self.Corte, repr(excepcion))
        self.assertTrue(carpeta)
        self.assertEqual(horas, 1)

    def test_fases_sin_eventos_es_runtimeerror_antes_de_cualquier_efecto(self):
        self.comprobar("fases", self.MENSAJE_FASES)

    def test_l1_sin_eventos_es_runtimeerror_antes_de_cualquier_efecto(self):
        self.comprobar("l1", self.MENSAJE_L1)


class ConexionDelSandwichEnLasRepeticiones(unittest.TestCase):
    """ejecutar_repeticion_fases de verdad (como CondicionDeLaSonda: Docker
    simulado y corte en la primera llamada a fases_de), con sandwich_j5 y
    preparar_repeticion en autospec y el plan de IPs en literales. La medianoche
    se prueba SIN parchear espera_por_medianoche (D4): solo la hora del motor y
    time.sleep. Sin esto, nada ejercitaba la rama del sandwich de la repetición 2
    de L3 y L3b."""

    class Corte(Exception):
        pass

    PLAN = {1: ["10.0.0.1"], 2: ["10.0.0.2"], 3: ["10.0.0.3"]}
    # 2026-11-22 23:43:20 UTC: a 1000 s de las 00:00 UTC (1795392000).
    HORA_CERCA = 1795391000.0
    # A 50 000 s de las 00:00 UTC: ninguna repetición (1306 s o 1816 s) la cruza.
    HORA_LEJOS = 1795342000.0

    def correr(self, modo, rep, hora=HORA_LEJOS):
        """Ejecuta la repetición `rep` de `modo` con la hora del motor `hora`.
        Devuelve el montaje con los espías (sandwich, preparar, dormir) y `ej`."""
        r = types.SimpleNamespace(sandwich=mock.create_autospec(L.sandwich_j5, return_value=[]),
                                  preparar=mock.create_autospec(L.preparar_repeticion, return_value=None),
                                  dormir=mock.MagicMock())

        def corte(*_):
            raise self.Corte()

        with tempfile.TemporaryDirectory() as d, contextlib.ExitStack() as pila:
            r.ej = L.Ejecucion(0.05, None, pathlib.Path(d), [0], [1], {})
            r.ej.plan_ips = {numero: list(ips) for numero, ips in self.PLAN.items()}
            r.ej.ids_empresas = []
            # Enmienda v4.4: un ej.eventos falso explícito, sin eventos.
            r.ej.eventos = types.SimpleNamespace(copia=list)
            for parche in (mock.patch.object(L, "hora_motor_ahora", lambda: hora),
                           mock.patch.object(L, "preparar_repeticion", r.preparar),
                           mock.patch.object(L, "sandwich_j5", r.sandwich),
                           mock.patch.object(L, "alta_empresa", lambda nombre: "e" * 32),
                           mock.patch.object(L, "comprobar_sonda_descartes", lambda e: None),
                           mock.patch.object(L, "fases_de", corte),
                           mock.patch.object(L, "p", lambda *a, **k: None),
                           mock.patch.object(L.time, "sleep", r.dormir)):
                pila.enter_context(parche)
            # La excepción que sale es la original (Corte), no la del finally.
            with self.assertRaises(self.Corte):
                L.ejecutar_repeticion_fases(r.ej, modo, rep, 3)
            # Control positivo: el finally escribió el fichero de eventos, vacío.
            destino = pathlib.Path(d) / f"rep{rep}" / "eventos_docker.json"
            self.assertEqual(json.loads(destino.read_text(encoding="utf-8")), [])
        return r

    def test_l3_y_l3b_en_las_repeticiones_2_y_3_llaman_al_sandwich_sin_preparar(self):
        # La IP previa de la repetición n es la del plan de la n - 1 (literales).
        previas = {2: ["10.0.0.1"], 3: ["10.0.0.2"]}
        for modo in ("l3", "l3b"):
            for rep in (2, 3):
                with self.subTest(modo=modo, rep=rep):
                    r = self.correr(modo, rep)
                    r.sandwich.assert_called_once_with(r.ej, modo, rep, previas[rep])
                    r.preparar.assert_not_called()
        # Control: L2 en la repetición 2 prepara la pila y no llama al sandwich.
        r = self.correr("l2", 2)
        r.preparar.assert_called_once_with(r.ej, 2)
        r.sandwich.assert_not_called()
        # Control: la repetición 1 de L3 también prepara la pila (el sandwich es de la 2 en adelante).
        r = self.correr("l3", 1)
        r.preparar.assert_called_once_with(r.ej, 1)
        r.sandwich.assert_not_called()

    def test_lejos_de_la_medianoche_no_se_espera(self):
        for modo in ("l3", "l3b"):
            with self.subTest(modo=modo):
                r = self.correr(modo, 2, hora=self.HORA_LEJOS)
                r.dormir.assert_not_called()
                # El montaje llegó al sandwich: el "no se espera" no es vacío.
                r.sandwich.assert_called_once()

    def test_cerca_de_la_medianoche_se_espera_la_cantidad_exacta(self):
        # 1000 s hasta las 00:00 UTC + 5 s de margen = 1005 s, y 1005 <= 1800
        # (el máximo de espera_por_medianoche): se espera, no hay PARADA.
        for modo in ("l3", "l3b"):
            with self.subTest(modo=modo):
                r = self.correr(modo, 2, hora=self.HORA_CERCA)
                r.dormir.assert_called_once_with(1005.0)
                r.sandwich.assert_called_once()


class LimpiezaDeLaSonda(unittest.TestCase):
    """v3.4: la limpieza de la sonda decide por POSTCONDICION (los listados por
    etiqueta), nunca por el texto del stderr de los borrados, y avisa por el
    callback `avisar` (con nombre y obligatorio). Contrato de 4 valores:
    (marcas, iteraciones, inicio, motivo). k6 vence su plazo en casi todas las
    pruebas, así que el motivo es el mismo literal y solo cambia lo que
    responden los borrados y los listados.

    Procedencia de las medidas (Docker 29.5.3, PowerShell 5, 24/11/2026):
    `docker rm -f` de un contenedor inexistente da rc 0 con "No such container"
    en stderr; `docker network rm` de una red inexistente da rc 1 con "network
    ... not found"; los listados por etiqueta salen por stdout con rc 0 y quedan
    vacíos cuando el recurso no existe. NO se midió un contenedor en marcha que
    pase por "removing". Los textos de Docker que solo hacen de relleno llevan
    el comentario "ilustrativo: el código no lo interpreta"."""
    CONSTANTES = {"prefijo": "p_", "usuario_api": "1:1", "usuario_k6": "2:2", "memoria_k6": "1g"}
    MOTIVO_K6 = "la sonda supera el plazo de 300 s: ['docker', 'run', '--rm']"
    # Llamadas de limpieza, literales completos (argumentos y plazo).
    RM_LENTO = (["docker", "rm", "-f", "p_sonda_lento"], 120)
    RM_K6 = (["docker", "rm", "-f", "p_sonda_k6"], 120)
    RM_RED = (["docker", "network", "rm", "p_sonda_red"], 120)
    LS_PS = (["docker", "ps", "-a", "--filter", "label=canario.estres=sonda", "--format", "{{.Names}}"], 60)
    LS_RED = (["docker", "network", "ls", "--filter", "label=canario.estres=sonda", "--format", "{{.Name}}"], 60)
    CINCO = [RM_LENTO, RM_K6, RM_RED, LS_PS, LS_RED]
    CREAR_RED = (["docker", "network", "create", "--internal", "--label", "canario.estres=sonda", "p_sonda_red"], 120)
    # Los tres avisos de "sigue existiendo" con todo en rc 0 y sin stderr.
    SIGUE_LENTO = "contenedor p_sonda_lento sigue existiendo tras el borrado (docker rm -f: codigo 0)"
    SIGUE_K6 = "contenedor p_sonda_k6 sigue existiendo tras el borrado (docker rm -f: codigo 0)"
    SIGUE_RED = "red p_sonda_red sigue existiendo tras el borrado (docker network rm: codigo 0)"

    @staticmethod
    def respuesta(rc=0, out="", err=""):
        return types.SimpleNamespace(rc=rc, out=out, err=err, todo=out + err)

    def sonda(self, reglas=None, ps="", red="", crear=None, en_k6=None, avisar_lanza=None, tmp_falso=None,
              rmtree_lanza=None):
        """Ejecuta ejecutar_sonda con un `ejecutar` falso y devuelve un
        SimpleNamespace con: resultado (los 4 valores o None), excepcion (la que
        salió de ejecutar_sonda o None), avisos (los que recibió `avisar`),
        llamadas (las de limpieza: borrados y listados), todas (también las
        creaciones) y rmtree (las rutas con que se llamó a shutil.rmtree).
        `reglas` mapea tuple(args) a una respuesta o a una excepción que se
        lanza; `ps` y `red` son el stdout de los dos listados; `crear` es la
        respuesta de network create; `en_k6` es la excepción del docker run --rm
        de k6 (por defecto TimeoutExpired); `avisar_lanza` se lanza en la primera
        llamada a avisar; `tmp_falso` sustituye a mkdtemp; `rmtree_lanza` es lo
        que lanza shutil.rmtree (después de borrar el temporal real, si lo es)."""
        reglas = dict(reglas or {})
        reglas.setdefault(tuple(self.LS_PS[0]), self.respuesta(out=ps))
        reglas.setdefault(tuple(self.LS_RED[0]), self.respuesta(out=red))
        avisos, llamadas, todas, rutas = [], [], [], []

        def ejecutar(args, timeout=900):
            todas.append((list(args), timeout))
            if args[:2] != ["docker", "run"] and args[:3] != ["docker", "network", "create"]:
                llamadas.append((list(args), timeout))
            if args[:3] == ["docker", "network", "create"] and crear is not None:
                return crear
            if args[:2] == ["docker", "run"] and "--rm" in args:
                raise en_k6 if en_k6 is not None else subprocess.TimeoutExpired(args, timeout)
            regla = reglas.get(tuple(args))
            if isinstance(regla, BaseException):
                raise regla
            return regla if regla is not None else self.respuesta()

        def avisar(texto):
            avisos.append(texto)
            if avisar_lanza is not None and len(avisos) == 1:
                raise avisar_lanza

        real_rmtree = shutil.rmtree

        def espia_rmtree(ruta, *args, **kwargs):
            rutas.append(ruta)
            if tmp_falso is None:
                real_rmtree(ruta)
            if rmtree_lanza is not None:
                raise rmtree_lanza

        r = types.SimpleNamespace(resultado=None, excepcion=None, avisos=avisos, llamadas=llamadas, todas=todas,
                                  rmtree=rutas)
        with contextlib.ExitStack() as pila:
            pila.enter_context(mock.patch.object(sonda_descartes.shutil, "rmtree", espia_rmtree))
            if tmp_falso is not None:
                pila.enter_context(mock.patch.object(sonda_descartes.tempfile, "mkdtemp", return_value=tmp_falso))
            try:
                r.resultado = sonda_descartes.ejecutar_sonda(
                    ejecutar, "img", "k6", "2,3", pathlib.Path("."), self.CONSTANTES, avisar=avisar)
            except BaseException as error:  # noqa: BLE001 - la prueba mira qué excepción salió
                r.excepcion = error
        return r

    def test_p1_las_tres_creaciones_llevan_la_etiqueta_y_los_listados_la_filtran(self):
        # QA H1: si una creación pierde la etiqueta, el listado no la ve y todo parece limpio.
        r = self.sonda(crear=self.respuesta())
        creaciones = [a for a, _ in r.todas if a[:2] == ["docker", "run"] or a[:3] == ["docker", "network", "create"]]
        # Control: de verdad se hicieron las tres creaciones (network create, run -d, run --rm).
        self.assertEqual(len(creaciones), 3)
        self.assertEqual(creaciones[0][:3], ["docker", "network", "create"])
        self.assertEqual(creaciones[1][:3], ["docker", "run", "-d"])
        self.assertEqual(creaciones[2][:3], ["docker", "run", "--rm"])
        for argumentos in creaciones:
            with self.subTest(creacion=argumentos[:3]):
                self.assertEqual(argumentos.count("--label"), 1)
                self.assertEqual(argumentos[argumentos.index("--label") + 1], "canario.estres=sonda")
        # Control: el filtro de los dos listados lleva la misma etiqueta, escrita a mano.
        filtros = [a[a.index("--filter") + 1] for a, _ in r.llamadas if "--filter" in a]
        self.assertEqual(filtros, ["label=canario.estres=sonda", "label=canario.estres=sonda"])

    def test_a_control_positivo_todo_limpio(self):
        r = self.sonda()
        self.assertIsNone(r.excepcion)
        self.assertEqual(r.resultado, ([], 0, None, self.MOTIVO_K6))
        self.assertEqual(r.avisos, [])
        self.assertEqual(r.llamadas, self.CINCO)

    def test_b_lo_medido_ausente_con_los_textos_de_docker_no_da_aviso(self):
        # Medido en Docker 29.5.3: rm -f de un inexistente da rc 0 con stderr; network rm da rc 1.
        reglas = {
            tuple(self.RM_LENTO[0]): self.respuesta(0, "", "Error response from daemon: No such container: p_sonda_lento\n"),
            tuple(self.RM_K6[0]): self.respuesta(0, "", "Error response from daemon: No such container: p_sonda_k6\n"),
            tuple(self.RM_RED[0]): self.respuesta(1, "", "Error response from daemon: network p_sonda_red not found\n"),
        }
        r = self.sonda(reglas)
        self.assertEqual(r.resultado, ([], 0, None, self.MOTIVO_K6))
        self.assertEqual(r.avisos, [])
        self.assertEqual(r.llamadas, self.CINCO)

    def test_b2_network_create_fallido_con_listados_vacios_no_da_aviso(self):
        # ilustrativo: el código no lo interpreta (el texto de Pool overlaps).
        crear = self.respuesta(1, "", "Error response from daemon: Pool overlaps with other one on this address space\n")
        reglas = {
            tuple(self.RM_LENTO[0]): self.respuesta(0, "", "Error response from daemon: No such container: p_sonda_lento\n"),
            tuple(self.RM_K6[0]): self.respuesta(0, "", "Error response from daemon: No such container: p_sonda_k6\n"),
            tuple(self.RM_RED[0]): self.respuesta(1, "", "Error response from daemon: network p_sonda_red not found\n"),
        }
        r = self.sonda(reglas, crear=crear)
        self.assertEqual(r.resultado, ([], 0, None, "no se crea la red de la sonda: "
                                       "'Error response from daemon: Pool overlaps with other one on this address space'"))
        self.assertEqual(r.avisos, [])
        self.assertEqual(r.todas, [self.CREAR_RED] + self.CINCO)

    def test_c_sigue_el_contenedor_tras_un_rm_con_rc_0(self):
        r = self.sonda(ps="p_sonda_k6\n")
        self.assertEqual(r.avisos, ["contenedor p_sonda_k6 sigue existiendo tras el borrado (docker rm -f: codigo 0)"])
        self.assertEqual(r.llamadas, self.CINCO)
        # Control: test_a, con el listado vacío, no da aviso.

    def test_c2_sigue_el_contenedor_tras_un_rm_con_rc_1(self):
        # ilustrativo: el código no lo interpreta (el "x" del stderr).
        r = self.sonda({tuple(self.RM_K6[0]): self.respuesta(1, "", "x\n")}, ps="p_sonda_k6\n")
        self.assertEqual(r.avisos, ["contenedor p_sonda_k6 sigue existiendo tras el borrado (docker rm -f: codigo 1: 'x')"])
        self.assertEqual(r.llamadas, self.CINCO)

    def test_d_sigue_la_red(self):
        # ilustrativo: el código no lo interpreta (el "y" del stderr).
        r = self.sonda({tuple(self.RM_RED[0]): self.respuesta(1, "", "y\n")}, red="p_sonda_red\n")
        self.assertEqual(r.avisos, ["red p_sonda_red sigue existiendo tras el borrado (docker network rm: codigo 1: 'y')"])
        self.assertEqual(r.llamadas, self.CINCO)

    def test_d2_siguen_los_tres_en_orden_servidor_k6_y_red(self):
        r = self.sonda(ps="p_sonda_k6\np_sonda_lento\n", red="p_sonda_red\n")
        self.assertEqual(r.avisos, [
            "contenedor p_sonda_lento sigue existiendo tras el borrado (docker rm -f: codigo 0)",
            "contenedor p_sonda_k6 sigue existiendo tras el borrado (docker rm -f: codigo 0)",
            "red p_sonda_red sigue existiendo tras el borrado (docker network rm: codigo 0)"])
        self.assertEqual(r.llamadas, self.CINCO)

    def test_e_nombres_parecidos_no_cuentan(self):
        r = self.sonda(ps="p_sonda_k6x\nxp_sonda_lento\n", red="otro_p_sonda_red\n")
        self.assertEqual(r.avisos, [])
        self.assertEqual(r.llamadas, self.CINCO)
        # Control: test_c, con el nombre exacto, sí avisa.

    def test_e2_varias_lineas_solo_cuenta_la_exacta(self):
        r = self.sonda(ps="p_sonda_k6x\np_sonda_k6\notro\n")
        self.assertEqual(r.avisos, ["contenedor p_sonda_k6 sigue existiendo tras el borrado (docker rm -f: codigo 0)"])

    def test_e3_el_listado_se_lee_con_strip_y_sin_lineas_vacias(self):
        r = self.sonda(ps="  p_sonda_k6 \r\n\r\n")
        self.assertEqual(r.avisos, ["contenedor p_sonda_k6 sigue existiendo tras el borrado (docker rm -f: codigo 0)"])

    def test_e4_lo_que_sale_por_stderr_del_listado_no_cuenta(self):
        r = self.sonda({tuple(self.LS_PS[0]): self.respuesta(0, "", "p_sonda_k6\n")})
        self.assertEqual(r.avisos, [])
        self.assertEqual(r.llamadas, self.CINCO)
        # Control: test_c, con el mismo nombre en stdout, sí avisa.

    def test_f_el_listado_de_contenedores_que_falla_avisa_y_el_de_la_red_se_ejecuta(self):
        casos = [
            ("rc 1", self.respuesta(1, "", "z\n"),
             "no se puede comprobar si quedan contenedores de la sonda: docker ps codigo 1: 'z'"),
            ("plazo", subprocess.TimeoutExpired(self.LS_PS[0], 60),
             "no se puede comprobar si quedan contenedores de la sonda: docker ps no responde en 60 s"),
            ("OSError", OSError("w"),
             "no se puede comprobar si quedan contenedores de la sonda: no se puede lanzar docker (OSError: w)"),
        ]
        for nombre, regla, esperado in casos:
            with self.subTest(fallo=nombre):
                r = self.sonda({tuple(self.LS_PS[0]): regla})
                self.assertEqual(r.avisos, [esperado])
                self.assertEqual(r.llamadas, self.CINCO)

    def test_f2_el_listado_de_la_red_que_falla_avisa(self):
        casos = [
            ("rc 1", self.respuesta(1, "", "z\n"),
             "no se puede comprobar si queda la red de la sonda: docker network ls codigo 1: 'z'"),
            ("plazo", subprocess.TimeoutExpired(self.LS_RED[0], 60),
             "no se puede comprobar si queda la red de la sonda: docker network ls no responde en 60 s"),
            ("OSError", OSError("w"),
             "no se puede comprobar si queda la red de la sonda: no se puede lanzar docker (OSError: w)"),
        ]
        for nombre, regla, esperado in casos:
            with self.subTest(fallo=nombre):
                r = self.sonda({tuple(self.LS_RED[0]): regla})
                self.assertEqual(r.avisos, [esperado])
                self.assertEqual(r.llamadas, self.CINCO)

    def test_f3_los_dos_listados_fallan_a_la_vez(self):
        r = self.sonda({tuple(self.LS_PS[0]): self.respuesta(1, "", "z\n"), tuple(self.LS_RED[0]): OSError("w")})
        self.assertEqual(r.avisos, [
            "no se puede comprobar si quedan contenedores de la sonda: docker ps codigo 1: 'z'",
            "no se puede comprobar si queda la red de la sonda: no se puede lanzar docker (OSError: w)"])
        self.assertEqual(r.llamadas, self.CINCO)

    def test_g_el_rm_del_servidor_vence_el_plazo_y_el_recurso_ausente_no_avisa(self):
        r = self.sonda({tuple(self.RM_LENTO[0]): subprocess.TimeoutExpired(self.RM_LENTO[0], 120)})
        self.assertEqual(r.resultado, ([], 0, None, self.MOTIVO_K6))
        self.assertEqual(r.avisos, [])
        self.assertEqual(r.llamadas, self.CINCO)

    def test_g2_el_rm_del_servidor_vence_el_plazo_y_el_recurso_presente_avisa(self):
        r = self.sonda({tuple(self.RM_LENTO[0]): subprocess.TimeoutExpired(self.RM_LENTO[0], 120)},
                       ps="p_sonda_lento\n")
        self.assertEqual(r.avisos, [
            "contenedor p_sonda_lento sigue existiendo tras el borrado (docker rm -f: no responde en 120 s)"])
        self.assertEqual(r.llamadas, self.CINCO)

    def test_g3_el_rm_del_servidor_con_oserror_ausente_y_presente(self):
        regla = {tuple(self.RM_LENTO[0]): OSError("v")}
        ausente = self.sonda(regla)
        self.assertEqual(ausente.avisos, [])
        self.assertEqual(ausente.llamadas, self.CINCO)
        presente = self.sonda(regla, ps="p_sonda_lento\n")
        self.assertEqual(presente.avisos, [
            "contenedor p_sonda_lento sigue existiendo tras el borrado "
            "(docker rm -f: no se puede lanzar docker (OSError: v))"])
        self.assertEqual(presente.llamadas, self.CINCO)

    def test_h_una_excepcion_durante_la_medida_se_relanza_tras_limpiar_y_avisar(self):
        for nombre, excepcion in (("KeyboardInterrupt", KeyboardInterrupt()), ("RuntimeError", RuntimeError("r"))):
            with self.subTest(excepcion=nombre):
                r = self.sonda(en_k6=excepcion, ps="p_sonda_k6\n")
                self.assertIs(r.excepcion, excepcion)
                self.assertIsNone(r.resultado)
                self.assertEqual(r.avisos, [self.SIGUE_K6])
                self.assertEqual(r.llamadas, self.CINCO)

    def test_h2_control_el_plazo_de_k6_devuelve_el_motivo_y_el_mismo_aviso(self):
        r = self.sonda(ps="p_sonda_k6\n")
        self.assertIsNone(r.excepcion)
        self.assertEqual(r.resultado, ([], 0, None, self.MOTIVO_K6))
        self.assertEqual(r.avisos, [self.SIGUE_K6])
        self.assertEqual(r.llamadas, self.CINCO)

    def test_i_segundo_ctrl_c_en_cada_paso_de_docker(self):
        todos = ("limpieza interrumpida con Ctrl+C: pueden quedar contenedor p_sonda_lento, contenedor p_sonda_k6, "
                 "red p_sonda_red; la red se borra a mano con: docker network rm p_sonda_red")
        solo_red = ("limpieza interrumpida con Ctrl+C: pueden quedar red p_sonda_red; "
                    "la red se borra a mano con: docker network rm p_sonda_red")
        casos = [
            ("paso 1", self.RM_LENTO, self.CINCO[:1], todos),
            ("paso 2", self.RM_K6, self.CINCO[:2], todos),
            ("paso 3", self.RM_RED, self.CINCO[:3], todos),
            ("paso 4", self.LS_PS, self.CINCO[:4], todos),
            ("paso 5", self.LS_RED, self.CINCO, solo_red),
        ]
        for nombre, paso, llamadas_esperadas, aviso in casos:
            with self.subTest(paso=nombre):
                interrupcion = KeyboardInterrupt()
                r = self.sonda({tuple(paso[0]): interrupcion})
                self.assertIs(r.excepcion, interrupcion)
                # Ni una llamada de Docker después del paso interrumpido.
                self.assertEqual(r.llamadas, llamadas_esperadas)
                # El rmtree se intentó igualmente (es local).
                self.assertEqual(len(r.rmtree), 1)
                self.assertEqual(r.avisos, [aviso])

    def test_i2_ctrl_c_en_el_rmtree_solo_avisa_de_lo_que_no_confirmo_ningun_listado(self):
        # Con los listados vacíos no queda nada de Docker pendiente: se relanza y no hay aviso.
        interrupcion = KeyboardInterrupt()
        r = self.sonda(rmtree_lanza=interrupcion)
        self.assertIs(r.excepcion, interrupcion)
        self.assertEqual(r.llamadas, self.CINCO)
        self.assertEqual(r.avisos, [])
        # Control: con k6 presente en el listado sí queda algo pendiente, y sin orden manual
        # para la red porque el listado de la red la confirmó ausente.
        interrupcion = KeyboardInterrupt()
        r = self.sonda(rmtree_lanza=interrupcion, ps="p_sonda_k6\n")
        self.assertIs(r.excepcion, interrupcion)
        self.assertEqual(r.avisos, [
            "contenedor p_sonda_k6 sigue existiendo tras el borrado (docker rm -f: codigo 0)",
            "limpieza interrumpida con Ctrl+C: pueden quedar contenedor p_sonda_k6"])

    def test_j_el_temporal_que_no_se_borra_avisa_y_los_pasos_de_docker_ya_se_hicieron(self):
        # Elección: la ruta literal con barra, que Path de Windows muestra con barra invertida.
        # En otro sistema el texto sería distinto, así que la prueba solo vale en Windows.
        if sys.platform != "win32":
            self.skipTest("el literal del oráculo es el de Windows (C:\\tmp_prueba_sonda)")
        r = self.sonda(tmp_falso="C:/tmp_prueba_sonda", rmtree_lanza=OSError("t"))
        self.assertEqual(r.avisos, ["no se borra el temporal C:\\tmp_prueba_sonda: OSError: t"])
        self.assertEqual(r.llamadas, self.CINCO)
        self.assertEqual(r.rmtree, [pathlib.Path("C:/tmp_prueba_sonda")])
        # Control: test_a, con el temporal borrado, no da aviso.

    def test_k_si_avisar_falla_se_siguen_emitiendo_los_demas_y_se_relanza_la_primera(self):
        fallo = RuntimeError("consola")
        r = self.sonda(ps="p_sonda_k6\np_sonda_lento\n", avisar_lanza=fallo)
        # Sin otra excepción en curso, ejecutar_sonda lanza la de avisar.
        self.assertIs(r.excepcion, fallo)
        self.assertEqual(r.avisos, [self.SIGUE_LENTO, self.SIGUE_K6])
        self.assertEqual(r.llamadas, self.CINCO)

    def test_k2_con_ctrl_c_en_k6_un_avisar_que_falla_no_tapa_la_interrupcion(self):
        interrupcion = KeyboardInterrupt()
        r = self.sonda(en_k6=interrupcion, ps="p_sonda_k6\n", avisar_lanza=RuntimeError("consola"))
        self.assertIs(r.excepcion, interrupcion)
        self.assertEqual(r.avisos, [self.SIGUE_K6])
        self.assertEqual(r.llamadas, self.CINCO)

    def test_l_avisar_es_obligatorio(self):
        with self.assertRaises(TypeError):
            sonda_descartes.ejecutar_sonda(lambda *a, **k: self.respuesta(), "img", "k6", "2,3",
                                           pathlib.Path("."), self.CONSTANTES)
        # Control: con avisar= funciona (test_a).
        self.assertEqual(self.sonda().resultado, ([], 0, None, self.MOTIVO_K6))

    def comprobar(self, avisos_del_doble=("texto de prueba",), resultado_sonda=None):
        """comprobar_sonda_descartes con ejecutar_sonda sustituida por un doble
        que llama por sí mismo a kwargs["avisar"] y devuelve 4 valores. Devuelve
        (texto de la PARADA o None, líneas impresas, estado de sin_conclusion,
        llamadas del doble)."""
        lineas, recibidas = [], []

        def doble(*args, **kwargs):
            recibidas.append((args, kwargs))
            for texto in avisos_del_doble:
                kwargs["avisar"](texto)
            return resultado_sonda

        ej = types.SimpleNamespace(imagen="img", cpus_k6="2,3", salida=pathlib.Path("."))
        with mock.patch.object(sonda_descartes, "ejecutar_sonda", doble), \
                mock.patch.object(L, "p", lineas.append), \
                mock.patch.dict(L.estado, {"falla": False, "sin_conclusion": False}):
            try:
                L.comprobar_sonda_descartes(ej)
                parada = None
            except L.Parada as error:
                parada = str(error)
            sin_conclusion = L.estado["sin_conclusion"]
        return parada, lineas, sin_conclusion, recibidas

    def test_m_lanzar_pasa_avisar_por_nombre_y_el_aviso_con_motivo_da_parada_y_sin_conclusion(self):
        parada, lineas, sin_conclusion, recibidas = self.comprobar(
            resultado_sonda=([], 0, None, "k6 termina con codigo 1: 'x'"))
        # Un solo intento, con avisar por nombre y los siete argumentos posicionales de antes.
        self.assertEqual(len(recibidas), 1)
        args, kwargs = recibidas[0]
        self.assertEqual(list(kwargs), ["avisar"])
        self.assertTrue(callable(kwargs["avisar"]))
        self.assertEqual(len(args), 7)
        self.assertEqual(parada, "sonda de descartes de k6 (E14): k6 termina con codigo 1: 'x'")
        self.assertEqual(lineas, ["SIN CONCLUSION limpieza de la sonda de descartes: texto de prueba"])
        self.assertTrue(sin_conclusion)

    def test_m2_el_aviso_sin_marcas_da_la_segunda_parada(self):
        # Sin marcas la sonda es PARADA (condición 1): la segunda PARADA de la función.
        parada, lineas, sin_conclusion, _ = self.comprobar(resultado_sonda=([], 0, 1795342200.0, None))
        self.assertTrue(parada.startswith("las marcas de dropped_iterations de k6 no son las que supone E14: "))
        self.assertEqual(lineas[0], "SIN CONCLUSION limpieza de la sonda de descartes: texto de prueba")
        self.assertIn("sonda de descartes de k6 (E14): ", lineas[1])
        self.assertEqual(len(lineas), 2)
        self.assertTrue(sin_conclusion)

    def test_m3_control_sin_avisos_ni_motivo_no_para(self):
        t0 = 1795342200.0
        marcas = [t0 + r for r in SondaDeDescartes.REAL]
        parada, lineas, sin_conclusion, _ = self.comprobar(avisos_del_doble=(), resultado_sonda=(marcas, 5, t0, None))
        self.assertIsNone(parada)
        # Una sola línea, la del veredicto PASA de la sonda, y ninguna de limpieza.
        self.assertEqual(len(lineas), 1)
        self.assertIn("PASA", lineas[0])
        self.assertFalse(sin_conclusion)

    def test_n_integracion_la_red_que_sigue_sale_como_sin_conclusion_y_despues_la_parada(self):
        # comprobar_sonda_descartes con la ejecutar_sonda REAL y L.ejecutar simulado. El prefijo
        # real es PREFIJO_EFIMEROS ("canario_estres_"), así que la red se llama
        # canario_estres_sonda_red (escrito a mano).
        lineas = []

        def ejecutar_falso(args, timeout=900):
            if args[:2] == ["docker", "run"] and "--rm" in args:
                raise subprocess.TimeoutExpired(args, 300)
            if args[:3] == ["docker", "network", "ls"]:
                return self.respuesta(out="canario_estres_sonda_red\n")
            return self.respuesta()

        ej = types.SimpleNamespace(imagen="img", cpus_k6="2,3", salida=pathlib.Path("."))
        with mock.patch.object(L, "ejecutar", ejecutar_falso), \
                mock.patch.object(L, "p", lineas.append), \
                mock.patch.dict(L.estado, {"falla": False, "sin_conclusion": False}):
            with self.assertRaises(L.Parada) as contexto:
                L.comprobar_sonda_descartes(ej)
            sin_conclusion = L.estado["sin_conclusion"]
        self.assertEqual(lineas, [
            "SIN CONCLUSION limpieza de la sonda de descartes: red canario_estres_sonda_red sigue existiendo "
            "tras el borrado (docker network rm: codigo 0)"])
        self.assertEqual(str(contexto.exception),
                         "sonda de descartes de k6 (E14): la sonda supera el plazo de 300 s: ['docker', 'run', '--rm']")
        self.assertTrue(sin_conclusion)


class LectorCsvRoto(unittest.TestCase):
    # Cabecera M2 (k6 v2.3.0, medidas_v4_25nov/m2.csv, 25/11/2026) y un 404 con la forma
    # real (error_code 1404, expected_response false: k6.csv de rep1 de L4, 24/11/2026).
    COLUMNAS = CABECERA_M2
    BUENA = "http_req_duration,1795342200500,500.0,,1404,false,POST,seguimiento,HTTP/1.1,seguimiento_ips,404,ip=198.18.0.1,"

    def leer(self, contenido):
        with tempfile.TemporaryDirectory() as d:
            ruta = pathlib.Path(d) / "k6.csv"
            ruta.write_text(contenido, encoding="utf-8", newline="")
            return L.leer_csv_fases(ruta)

    def test_control_positivo_un_csv_sano_no_tiene_ilegibles(self):
        datos = self.leer(self.COLUMNAS + chr(10) + self.BUENA + chr(10))
        self.assertEqual((len(datos["filas"]), datos["ilegibles"]), (1, 0))

    def test_una_ultima_linea_sin_salto_final_cuenta_como_ilegible(self):
        datos = self.leer(self.COLUMNAS + chr(10) + self.BUENA + chr(10) + self.BUENA)
        self.assertEqual(datos["ilegibles"], 1)

    def test_csv_error_se_cuenta_y_deja_de_leer(self):
        # Un campo de mas de 131072 caracteres hace que el modulo csv lance csv.Error.
        rota = "http_req_duration,1795342200500,500.0,," + "x" * 200000 + chr(10)
        datos = self.leer(self.COLUMNAS + chr(10) + self.BUENA + chr(10) + rota + self.BUENA + chr(10))
        self.assertEqual(len(datos["filas"]), 1)
        self.assertEqual(datos["ilegibles"], 1)


class MemoriaSinVentana(unittest.TestCase):
    def test_sin_inicio_o_fin_de_k6_se_dice_y_se_vuelve(self):
        lineas = []
        vig = {"etiquetados": {"api": ([{"t": 1.0, "enc": 0}], None)}}
        with mock.patch.object(L, "p", lineas.append):
            L.memoria_informativa(vig, {"inicio_vm": None, "fin_vm": 5.0}, True, 9.0)
            L.memoria_informativa(vig, {"inicio_vm": 1.0, "fin_vm": None}, True, 9.0)
        self.assertEqual(lineas, ["   memoria sin ventana de k6"] * 2)
        # Control positivo: con ventana, la linea es otra (sin muestras utiles en la ventana).
        lineas.clear()
        with mock.patch.object(L, "p", lineas.append):
            L.memoria_informativa({"etiquetados": {"api": ([], None)}}, {"inicio_vm": 1.0, "fin_vm": 5.0}, True, 9.0)
        self.assertNotIn("   memoria sin ventana de k6", lineas)
        self.assertEqual(len(lineas), 1)


class AnalisisSintetico(unittest.TestCase):
    """analizar_pico, analizar_l2, analizar_l3b, analizar_victimas y evaluar_vigilancia con filas
    sinteticas y oraculos literales (QA R3): fallan si se revierte H8, E14, H15 o se mezclan validez_a y validez_b."""
    T0 = 1795342200.0

    def setUp(self):
        self.parche = mock.patch.object(L, "p", lambda *a, **k: None)
        self.parche.start()
        self.addCleanup(self.parche.stop)

    def fila(self, inicio, dur, nombre, estado, escenario=None, fase=None, ip=None):
        return {"inicio": inicio, "fin": inicio + dur / 1000, "dur": dur, "estado": estado, "nombre": nombre,
                "escenario": escenario or nombre, "proto": "HTTP/1.1", "error_code": "", "ip": ip, "fase": fase,
                "etapa": None}

    def humo(self):
        return [(f"{etapa}: {x}", 1.0) for etapa in ("humo_previo", "humo_posterior") for x in "abcd"]

    def filas_pico(self, login_503_en_base=0, login_carga_desfase=0.0):
        fases = L.fases_de("pico")
        filas = []
        for f in fases:
            if f["nombre"] == "cal":
                continue
            carga = f["nombre"] == "carga"
            for ruta in L.RUTAS_FASES:
                tasa = (102 if carga else 10) if ruta == "login_email" else (50 if carga else 5)
                n = int(tasa * (f["hasta_s"] - f["desde_s"]))
                for i in range(n):
                    inicio = self.T0 + f["desde_s"] + i / tasa
                    estado = L.ESTADO_RUTAS[ruta]
                    if ruta == "login_email" and f["nombre"] == "base" and i < login_503_en_base:
                        estado = 503
                    if ruta == "login_email" and carga:
                        inicio += login_carga_desfase
                    filas.append(self.fila(inicio, 30, ruta, estado, f"{ruta}__{f['nombre']}", f["nombre"]))
        return filas, fases

    def pico(self, descartes=None, reinicios=0, checks=None, filas_humo=(), **cambios):
        filas, fases = self.filas_pico(**cambios)
        # datos["filas"] son TODAS las filas del CSV (con las del humo), como en
        # analizar_repeticion_fases; analizar_pico recibe aparte las que no son del humo.
        datos = {"descartes": descartes or {}, "checks": self.humo() if checks is None else checks,
                 "filas": filas + list(filas_humo)}
        return L.analizar_pico(filas, datos, self.T0, fases, set(), reinicios)

    def motivos(self, parte):
        return [f["motivo"] for f in parte["validez"]]

    def test_pico_sano_pasa_sin_fallos(self):
        partes, comun = self.pico()
        self.assertEqual(partes["pico"]["resultado"], "PASA")
        self.assertEqual((partes["pico"]["validez"], comun), ([], []))

    def test_h8_el_503_del_login_de_l4_cuenta_como_error_de_la_base(self):
        # 3 % de 503 en la BASE del login: con la definicion por defecto es error (y no solo "esperado").
        partes, _ = self.pico(login_503_en_base=36)
        self.assertTrue(any("de errores" in m for m in self.motivos(partes["pico"])), self.motivos(partes["pico"]))

    def test_e14_un_descarte_en_la_base_es_validez_y_en_el_pico_solo_se_informa(self):
        partes, _ = self.pico(descartes={"login_email__base": [self.T0 + 40.0]})
        self.assertTrue(any(m.startswith("E14") for m in self.motivos(partes["pico"])))
        # Control: el mismo descarte en el PICO no invalida la BASE.
        partes, _ = self.pico(descartes={"login_email__carga": [self.T0 + 160.0]})
        self.assertFalse(any(m.startswith("E14") for m in self.motivos(partes["pico"])))
        # La sonda de salud no cuenta.
        partes, _ = self.pico(descartes={"sonda_salud": [self.T0 + 40.0]})
        self.assertFalse(any(m.startswith("E14") for m in self.motivos(partes["pico"])))

    def test_h15_el_reloj_de_fases_del_pico(self):
        _, comun = self.pico(login_carga_desfase=5.0)
        self.assertEqual(len(comun), 1)
        self.assertIn("reloj de fases", comun[0]["motivo"])
        self.assertEqual(self.pico(login_carga_desfase=1.0)[1], [])

    def test_qa_r4_los_reinicios_llegan_al_veredicto_de_l4(self):
        self.assertEqual(self.pico(reinicios=1)[0]["pico"]["resultado"], "FALLA")
        self.assertEqual(self.pico(reinicios=0)[0]["pico"]["resultado"], "PASA")

    def test_g_una_etapa_programada_con_0_checks_es_sin_conclusion(self):
        # Plan v4.2, prueba g. Sin ningún check del humo posterior: no se ejecutó.
        solo_previo = [(f"humo_previo: {x}", 1.0) for x in "abcd"]
        self.assertEqual(L.veredicto_humo(solo_previo, "humo_posterior"), "SIN CONCLUSION")
        partes, comun = self.pico(checks=solo_previo)
        self.assertIn("humo_posterior: 0 check en el CSV: el humo no se ejecuto", self.motivos(partes["pico"]))
        self.assertEqual(L.veredicto_con_validez(partes["pico"]["resultado"], comun + partes["pico"]["validez"],
                                                 None)[0], "SIN CONCLUSION")
        # Control: 4 checks a 1 en cada etapa dan PASA.
        self.assertEqual(L.veredicto_humo(self.humo(), "humo_posterior"), "PASA")
        partes, comun = self.pico()
        self.assertEqual(L.veredicto_con_validez(partes["pico"]["resultado"], comun + partes["pico"]["validez"],
                                                 None), ("PASA", []))
        # Un check a 0 sigue siendo FALLA, no SIN CONCLUSION.
        uno_a_cero = solo_previo + [("humo_posterior: a", 0.0)]
        self.assertEqual(L.veredicto_humo(uno_a_cero, "humo_posterior"), "FALLA")

    def fila_humo(self, fin_relativo_s):
        """Una petición del humo previo que TERMINA en t0 + fin_relativo_s (la marca del
        CSV es el fin), con etapa=humo_previo como en extra_tags."""
        fila = self.fila(self.T0 + fin_relativo_s - 0.012, 12, "humo_denuncia", 201, "humo_previo")
        fila["etapa"] = "humo_previo"
        return fila

    def test_k_el_humo_previo_tiene_que_acabar_antes_del_pico(self):
        # Plan v4.2, prueba k: la carga empieza en t0 + 150 s (fases_de("pico"), literal en
        # test_fases_literales). Fin a los 151 s: SIN CONCLUSION.
        partes, comun = self.pico(filas_humo=[self.fila_humo(100.0), self.fila_humo(151.0)])
        self.assertEqual(len(comun), 1)
        self.assertTrue(comun[0]["motivo"].startswith("humo previo: la ultima peticion del humo previo termina 1.00 s "
                                                      "despues del inicio de la carga"), comun[0]["motivo"])
        self.assertEqual(L.veredicto_con_validez(partes["pico"]["resultado"], comun + partes["pico"]["validez"],
                                                 None)[0], "SIN CONCLUSION")
        # Control: fin a los 149 s, nada.
        partes, comun = self.pico(filas_humo=[self.fila_humo(100.0), self.fila_humo(149.0)])
        self.assertEqual(comun, [])
        # Las filas de otra etapa no cuentan aunque acaben tarde.
        tarde = self.fila_humo(151.0)
        tarde["etapa"] = "humo_posterior"
        self.assertEqual(self.pico(filas_humo=[self.fila_humo(149.0), tarde])[1], [])

    def analizar_rep(self, modo, rep, eventos):
        """analizar_repeticion_fases sin CSV ni T0 (todas las partes SIN CONCLUSION) y
        con los eventos dados: solo interesa qué entra en comun."""
        ej = types.SimpleNamespace(eventos=types.SimpleNamespace(copia=lambda: list(eventos)), mantenimientos=[],
                                   reinicios={})
        k6 = {"registro": "", "codigo": 0, "oom": False, "sin_conclusion": [], "desfase": None,
              "motivo_desfase": "sin medir", "inicio_vm": None, "fin_vm": None, "k6_id": ID_K6}
        with tempfile.TemporaryDirectory() as d:
            salida_rep = pathlib.Path(d)
            res = L.analizar_repeticion_fases(ej, modo, rep, salida_rep, salida_rep / "no_existe", k6,
                                              L.fases_de("l2" if modo == "l2" else "pico"), None, [],
                                              salida_rep / "stats.txt", self.ticks(), 1000.0, [], True, 1010.0, None)
        return [f["motivo"] for f in res["comun"]]

    def test_c5_solo_en_pico_rep1_y_entra_en_comun(self):
        # Enmienda v4.3, punto 3. El die del servidor de la sonda como llega de docker
        # events (etiquetas heredadas M1-bis y nombre NOMBRE_SERVIDOR_SONDA).
        servidor = L.parsear_evento(json.dumps({"Type": "container", "Action": "die", "timeNano": 1001000000000,
                                                "Actor": {"ID": "f" * 64, "Attributes": {
                                                    **ETIQUETAS_IMAGEN_API, "canario.estres": "sonda",
                                                    "exitCode": "137", "name": NOMBRE_SERVIDOR_SONDA}}}))
        # pico, rep1, sin el die: C5 entra en comun.
        self.assertTrue(any(m.startswith("C5: ") for m in self.analizar_rep("pico", 1, [])))
        # Control: pico, rep1, con el die del servidor: no hay C5 en comun.
        self.assertFalse(any(m.startswith("C5: ") for m in self.analizar_rep("pico", 1, [servidor])))
        # Fuera de pico rep1 no corre aunque falte el die: pico rep2 y l2 rep1.
        self.assertFalse(any(m.startswith("C5: ") for m in self.analizar_rep("pico", 2, [])))
        self.assertFalse(any(m.startswith("C5: ") for m in self.analizar_rep("l2", 1, [])))

    def test_la_linea_de_muerte_lleva_nombre_y_clase(self):
        # Plan v4.2, cambio 4: un die no esperado de la API (ev: nombre "api", clase canario).
        lineas = []
        with mock.patch.object(L, "p", lineas.append):
            self.vigilar(eventos=[ev("die", ID_API, 1005.0, codigo="137")])
        muertes = [x for x in lineas if "murio" in x]
        self.assertEqual(len(muertes), 1)
        self.assertTrue(muertes[0].startswith("   repeticion 1: murio api (api, clase canario, aaaaaaaaaaaa, codigo 137)"),
                        muertes[0])
        # Control: sin el die no hay línea de muerte.
        lineas.clear()
        with mock.patch.object(L, "p", lineas.append):
            self.vigilar()
        self.assertFalse(any("murio" in x for x in lineas))

    def filas_victimas(self, fases, dur_carga=30, dur_base=30, login=True, desfase_login=0.0):
        filas = []
        for f in fases:
            if f["nombre"] == "cal":
                continue
            for ruta in ("denuncia", "seguimiento", "web_seguimiento"):
                dur = dur_carga if f["nombre"] == "carga" else (dur_base if f["nombre"] == "base" else 30)
                for i in range(int(5 * (f["hasta_s"] - f["desde_s"]))):
                    filas.append(self.fila(self.T0 + f["desde_s"] + i / 5, dur, ruta, L.ESTADO_RUTAS[ruta], ruta,
                                           f["nombre"]))
        return filas

    def test_analizar_victimas_la_base_es_el_control(self):
        fases = L.fases_de("l2")
        sanas, f_sanas = L.analizar_victimas(self.filas_victimas(fases), self.T0, fases, set(), {})
        self.assertEqual(f_sanas, [])
        self.assertEqual(L.veredictos_victimas(sanas)["denuncia"][0], "PASA")
        # BASE de la denuncia a 1200 ms (SLO 1000): fallo de validez.
        _, fallos = L.analizar_victimas(self.filas_victimas(fases, dur_base=1200), self.T0, fases, set(), {})
        self.assertTrue(any("la BASE no cumple el SLO" in f["motivo"] for f in fallos))
        # Un descarte en la BASE tambien.
        _, fallos = L.analizar_victimas(self.filas_victimas(fases), self.T0, fases, set(),
                                        {"denuncia": [self.T0 + 40.0]})
        self.assertTrue(any("descartes en la BASE" in f["motivo"] for f in fallos))

    def analizar_l2(self, desfase_login=0.0, dur_carga=30):
        fases = L.fases_de("l2")
        filas = self.filas_victimas(fases, dur_carga=dur_carga)
        for i in range(300):
            filas.append(self.fila(self.T0 + 150 + desfase_login + i * 0.4, 2000, "login_email", 401, "login_email", "carga"))
        datos = {"descartes": {}, "checks": [], "retry": []}
        k6 = {"inicio_vm": self.T0 - 30, "fin_vm": self.T0 + 400}
        vig = {"etiquetados": {"api": ([], None)}}
        with tempfile.TemporaryDirectory() as d:
            return L.analizar_l2(filas, datos, self.T0, fases, set(), pathlib.Path(d), vig, k6, True, self.T0 + 500, [])

    def test_analizar_l2_sano_y_con_victimas_degradadas(self):
        partes, comun = self.analizar_l2()
        self.assertEqual(partes["l2"]["resultado"], "PASA")
        self.assertEqual((partes["l2"]["validez"], comun), ([], []))
        self.assertTrue(partes["l2"]["control_ataque"])
        # Victimas a 4000 ms en la inundacion: FALLA del oraculo, no de validez.
        partes, _ = self.analizar_l2(dur_carga=4000)
        self.assertEqual(partes["l2"]["resultado"], "FALLA")
        self.assertEqual(partes["l2"]["validez"], [])

    def test_h15_el_reloj_de_fases_de_l2(self):
        self.assertEqual(self.analizar_l2()[1], [])
        _, comun = self.analizar_l2(desfase_login=5.0)
        self.assertEqual(len(comun), 1)
        self.assertIn("reloj de fases", comun[0]["motivo"])

    def analizar_l3b(self, previos=(), dur_base=30):
        fases = L.fases_de("l3b")
        filas = self.filas_victimas(fases, dur_base=dur_base)
        ips = ["198.18.0.1", "198.18.0.2"]
        for i in range(18):
            filas.append(self.fila(self.T0 + 150 + i * 0.5, 100, "login_email", 401, "login_ataque", "carga", ips[i % 2]))
        datos = {"descartes": {}, "checks": [], "retry": []}
        with tempfile.TemporaryDirectory() as d:
            return L.analizar_l3b(filas, datos, self.T0, self.T0 + 150, fases, set(), list(previos), pathlib.Path(d),
                                  {"ataque": ips})

    def test_l3b_no_mezcla_la_validez_de_a_y_de_b(self):
        previo = {"motivo": "J5 de prueba"}
        partes = self.analizar_l3b(previos=[previo])
        self.assertIn("J5 de prueba", self.motivos(partes["l3b-a"]))
        self.assertNotIn("J5 de prueba", self.motivos(partes["l3b-b"]))
        # Control positivo: sin previos, ninguno lo lleva.
        sin = self.analizar_l3b()
        self.assertNotIn("J5 de prueba", self.motivos(sin["l3b-a"]) + self.motivos(sin["l3b-b"]))
        # Una BASE fuera del SLO es de l3b-b y no de l3b-a.
        base_mala = self.analizar_l3b(dur_base=1200)
        self.assertTrue(any("la BASE no cumple el SLO" in m for m in self.motivos(base_mala["l3b-b"])))
        self.assertFalse(any("la BASE" in m for m in self.motivos(base_mala["l3b-a"])))

    def ticks(self, hasta=1010.0):
        return [{"t": 1000.0 + k * 0.25, "c": {s: cg(anon=1) for s in L.SERVICIOS_PILA}, "padre": None, "hijos": {}}
                for k in range(int((hasta - 1000.0) * 4) + 1)]

    def vigilar(self, eventos=(), muertos=(), reinicios=None):
        ej = types.SimpleNamespace(eventos=types.SimpleNamespace(copia=lambda: list(eventos)), mantenimientos=[],
                                   reinicios=reinicios or {})
        return L.evaluar_vigilancia(ej, 1, self.ticks(), 0.0, {ID_K6}, list(muertos), 1000.0, 1010.0)

    def test_evaluar_vigilancia(self):
        vig = self.vigilar()
        self.assertEqual((vig["fallos"], vig["muertes"], vig["reinicios"]), ([], [], 0))
        # Streamers muertos en el reposo: fallo de validez.
        self.assertEqual(len(self.vigilar(muertos=["log_api"])["fallos"]), 1)
        # Un die no esperado de la API: la muerte es FALLA (sin padre que atribuya un OOM global).
        vig = self.vigilar(eventos=[ev("die", ID_API, 1005.0, codigo="137")])
        self.assertEqual(vig["muertes"], ["FALLA"])
        # Los reinicios por politica salen en vig (QA R4).
        vig = self.vigilar(eventos=[ev("start", ID_API, 1001.0), ev("start", ID_API, 1002.0)], reinicios={ID_API: 1})
        self.assertEqual(vig["reinicios"], 1)

    def test_j_instrumento_desconocido_en_fases_es_sin_conclusion(self):
        # Plan v4.2, prueba j (fases): el mismo die que en la prueba de L1, con las
        # etiquetas medidas del lector (ETIQUETAS_LECTOR) y otro valor de canario.estres.
        def evento(valor):
            atributos = {**L.etiquetas_de(ETIQUETAS_LECTOR), "canario.estres": valor, "exitCode": "1",
                         "name": "canario_estres_raro"}
            return L.parsear_evento(json.dumps({"Type": "container", "Action": "die", "timeNano": 1005000000000,
                                                "Actor": {"ID": "f" * 64, "Attributes": atributos}}))
        vig = self.vigilar(eventos=[evento("otro")])
        self.assertEqual([f["motivo"] for f in vig["fallos"]],
                         ["repeticion 1: eventos de contenedores con un valor desconocido de canario.estres: "
                          "['canario_estres_raro']"])
        self.assertEqual(vig["muertes"], [])
        # Control: el mismo evento con canario.estres=lector no da nada.
        vig = self.vigilar(eventos=[evento("lector")])
        self.assertEqual((vig["fallos"], vig["muertes"]), ([], []))


class EventosPorRepeticion(unittest.TestCase):
    """Plan v4.2, cambio 4, y enmienda v4.3, punto 2: eventos_docker.json por
    repetición, escrito en el finally y sin lanzar nunca."""

    def evento(self, t, nombre="canario_estres-api-1"):
        return ev("die", ID_API, t, codigo="137", servicio="api") | {"nombre": nombre}

    def test_guardar_eventos_escribe_el_fichero(self):
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(L, "p", lambda *a: None), \
                mock.patch.dict(L.estado, {"falla": False, "sin_conclusion": False}):
            destino = pathlib.Path(d) / "eventos_docker.json"
            L.guardar_eventos(destino, [self.evento(1005.0)])
            self.assertEqual(json.loads(destino.read_text(encoding="utf-8")), [self.evento(1005.0)])
            self.assertFalse(L.estado["sin_conclusion"])

    def test_si_la_escritura_falla_da_sin_conclusion_y_no_lanza(self):
        for nombre, destino_de, eventos in (
                ("carpeta inexistente (OSError)", lambda d: pathlib.Path(d) / "no_existe" / "e.json", []),
                ("no serializable (TypeError)", lambda d: pathlib.Path(d) / "e.json", [object()]),
                ("referencia circular (ValueError)", lambda d: pathlib.Path(d) / "e.json", None)):
            with self.subTest(nombre), tempfile.TemporaryDirectory() as d, \
                    mock.patch.object(L, "p", lambda *a: None), \
                    mock.patch.dict(L.estado, {"falla": False, "sin_conclusion": False}):
                if eventos is None:
                    circular = []
                    circular.append(circular)
                    eventos = circular
                L.guardar_eventos(destino_de(d), eventos)
                self.assertTrue(L.estado["sin_conclusion"], nombre)
        # Control: con un destino válido y eventos serializables, sin SIN CONCLUSION.
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(L, "p", lambda *a: None), \
                mock.patch.dict(L.estado, {"falla": False, "sin_conclusion": False}):
            L.guardar_eventos(pathlib.Path(d) / "e.json", [self.evento(1005.0)])
            self.assertFalse(L.estado["sin_conclusion"])

    def ej_fases(self, d, eventos):
        return types.SimpleNamespace(salida=pathlib.Path(d), eventos=types.SimpleNamespace(copia=lambda: list(eventos)),
                                     tasas=L.tasas_de(0.0196), contrasena="Estres-xxxxxxxxxxxxxxxx", texto_humo="Humo",
                                     ids_empresas=[], ids={"caddy": "c" * 64}, datos=pathlib.Path(d), cpus_k6="2,3",
                                     plan_ips={}, id_a=None, id_b=None)

    def parches_fases(self, pila, llamadas, preparar):
        """Todo lo de Docker de ejecutar_repeticion_fases (L2, repetición 1) sustituido.
        guardar_eventos se envuelve para contar sus llamadas."""
        original = L.guardar_eventos
        falso = types.SimpleNamespace(parar=lambda: None, copia_ticks=lambda: [])

        def contar(destino, eventos):
            llamadas.append(destino)
            original(destino, eventos)
        for parche in (mock.patch.object(L, "p", lambda *a: None),
                       mock.patch.object(L, "hora_motor_ahora", lambda: 1000.0),
                       mock.patch.object(L, "preparar_repeticion", preparar),
                       mock.patch.object(L, "alta_empresa", lambda nombre: "a" * 32),
                       mock.patch.object(L, "Registro", lambda *a: falso),
                       mock.patch.object(L, "iniciar_lector", lambda *a: falso),
                       mock.patch.object(L, "Estadisticas", lambda *a: falso),
                       mock.patch.object(L, "escribir_datos_k6", lambda *a: None),
                       mock.patch.object(L, "ejecutar_k6", lambda *a: {"registro": ""}),
                       mock.patch.object(L.time, "sleep", lambda s: None),
                       mock.patch.object(L, "comprobar_vida", lambda *a: []),
                       mock.patch.object(L, "streamer_vivo", lambda s: True),
                       mock.patch.object(L, "registrar_reinicios", lambda ej: None),
                       mock.patch.object(L, "analizar_repeticion_fases", lambda *a: {"analizada": True}),
                       mock.patch.object(L, "guardar_eventos", contar),
                       mock.patch.dict(L.estado, {"falla": False, "sin_conclusion": False})):
            pila.enter_context(parche)

    def test_con_una_parada_antes_del_analisis_el_fichero_existe_y_la_parada_sigue(self):
        def parada(ej, rep):
            raise L.Parada("parada simulada antes del analisis")
        eventos = [self.evento(999.0, "anterior"), self.evento(1005.0)]
        with tempfile.TemporaryDirectory() as d, contextlib.ExitStack() as pila:
            llamadas = []
            self.parches_fases(pila, llamadas, parada)
            with self.assertRaises(L.Parada) as contexto:
                L.ejecutar_repeticion_fases(self.ej_fases(d, eventos), "l2", 1, 1)
            self.assertEqual(str(contexto.exception), "parada simulada antes del analisis")
            destino = pathlib.Path(d) / "rep1" / "eventos_docker.json"
            self.assertEqual(llamadas, [destino])
            # Solo los eventos desde t_ini (1000.0): el de 999.0 es de antes.
            self.assertEqual(json.loads(destino.read_text(encoding="utf-8")), [self.evento(1005.0)])

    def test_sin_parada_el_fichero_se_escribe_una_sola_vez(self):
        eventos = [self.evento(1005.0)]
        with tempfile.TemporaryDirectory() as d, contextlib.ExitStack() as pila:
            llamadas = []
            self.parches_fases(pila, llamadas, lambda ej, rep: None)
            self.assertEqual(L.ejecutar_repeticion_fases(self.ej_fases(d, eventos), "l2", 1, 1), {"analizada": True})
            destino = pathlib.Path(d) / "rep1" / "eventos_docker.json"
            self.assertEqual(llamadas, [destino])
            self.assertEqual(json.loads(destino.read_text(encoding="utf-8")), eventos)

    # --- La misma pareja para L1 (ejecutar_repeticion) -------------------------
    DATOS_REP_L1 = {"max_memoria": None, "muertes": 0, "muerte_en_login": False}

    def ej_l1(self, d, eventos):
        return types.SimpleNamespace(salida=pathlib.Path(d), eventos=types.SimpleNamespace(copia=lambda: list(eventos)),
                                     t=0.0196, escalera={}, datos=pathlib.Path(d), ids={"caddy": "c" * 64},
                                     cpus_k6="2,3", identificador=None)

    def parches_l1(self, pila, llamadas, preparar):
        """Todo lo de Docker de ejecutar_repeticion (L1) sustituido. guardar_eventos se
        envuelve para contar sus llamadas. La salida de alta-empresa tiene la forma
        que exige PATRON_ALTA."""
        original = L.guardar_eventos
        falso = types.SimpleNamespace(parar=lambda: None)
        alta = ("empresa creada: empresa_id=00000000-0000-0000-0000-000000000000 "
                "identificador_publico=" + "a" * 32 + "\n")

        def contar(destino, eventos):
            llamadas.append(destino)
            original(destino, eventos)
        for parche in (mock.patch.object(L, "p", lambda *a: None),
                       mock.patch.object(L, "hora_motor_ahora", lambda: 1000.0),
                       mock.patch.object(L, "preparar_repeticion", preparar),
                       mock.patch.object(L, "dc", lambda *a, **k: L.R(0, alta, "")),
                       mock.patch.object(L, "Registro", lambda *a: falso),
                       mock.patch.object(L, "ejecutar_ruta", lambda ej, rep, ruta, *a: {"ruta": ruta, "resultados": []}),
                       mock.patch.object(L.time, "sleep", lambda s: None),
                       mock.patch.object(L, "leer_log", lambda ruta: []),
                       mock.patch.object(L, "evaluar_repeticion", lambda *a: dict(self.DATOS_REP_L1)),
                       mock.patch.object(L, "ejecutar", lambda *a, **k: L.R(0, "", "")),
                       mock.patch.object(L, "tabla", lambda resultados: None),
                       mock.patch.object(L, "codo_de", lambda resultados: None),
                       mock.patch.object(L, "hipotesis", lambda *a: None),
                       mock.patch.object(L, "guardar_eventos", contar),
                       mock.patch.dict(L.estado, {"falla": False, "sin_conclusion": False})):
            pila.enter_context(parche)

    def test_l1_con_una_parada_antes_del_analisis_el_fichero_existe_y_la_parada_sigue(self):
        def parada(ej, rep):
            raise L.Parada("parada simulada antes del analisis de L1")
        eventos = [self.evento(999.0, "anterior"), self.evento(1005.0)]
        with tempfile.TemporaryDirectory() as d, contextlib.ExitStack() as pila:
            llamadas = []
            self.parches_l1(pila, llamadas, parada)
            with self.assertRaises(L.Parada) as contexto:
                L.ejecutar_repeticion(self.ej_l1(d, eventos), 1, 1)
            self.assertEqual(str(contexto.exception), "parada simulada antes del analisis de L1")
            destino = pathlib.Path(d) / "rep1" / "eventos_docker.json"
            self.assertEqual(llamadas, [destino])
            # Solo los eventos desde t_ini (1000.0): el de 999.0 es de antes.
            self.assertEqual(json.loads(destino.read_text(encoding="utf-8")), [self.evento(1005.0)])

    def test_l1_sin_parada_el_fichero_se_escribe_una_sola_vez(self):
        eventos = [self.evento(1005.0)]
        with tempfile.TemporaryDirectory() as d, contextlib.ExitStack() as pila:
            llamadas = []
            self.parches_l1(pila, llamadas, lambda ej, rep: None)
            self.assertEqual(L.ejecutar_repeticion(self.ej_l1(d, eventos), 1, 1),
                             {"resultados": [], **self.DATOS_REP_L1})
            destino = pathlib.Path(d) / "rep1" / "eventos_docker.json"
            self.assertEqual(llamadas, [destino])
            self.assertEqual(json.loads(destino.read_text(encoding="utf-8")), eventos)


class LineasDeL3bB(unittest.TestCase):
    def test_pasa_con_b2_es_el_literal_de_e17_sin_cifra_de_ips(self):
        esperado = ("L3b-b: PASA con B2 cumplido: en este montaje (IPv4, 102,04/s, 300 s) las víctimas no se degradaron; "
                    "no se da cifra de coste (E15); no cierra threat-model §8 l.760-764, que sigue ABIERTA; la "
                    "diferencia con L2 se explica en el informe")
        self.assertEqual(L.linea_l3b_b("PASA", [], True), esperado)
        self.assertEqual(L.LINEA_L3B_B_PASA, esperado)
        self.assertNotIn("3402", esperado)
        docs = pathlib.Path(__file__).resolve().parents[2] / "docs" / "informe-pruebas.md"
        # La copia puede traer un docs/ anterior a E17: solo se compara si el texto ya la tiene.
        if docs.is_file() and "**E17." in docs.read_text(encoding="utf-8"):
            self.assertIn(esperado, docs.read_text(encoding="utf-8"))
        # Con SIN CONCLUSION, o con PASA sin B2, no hay linea propia.
        self.assertIsNone(L.linea_l3b_b("SIN CONCLUSION", ["x"], True))
        self.assertIsNone(L.linea_l3b_b("PASA", [], False))
        self.assertIsNone(L.linea_l3b_b("PASA", [], None))

    def test_falla_del_oraculo_y_falla_por_muerte(self):
        self.assertEqual(L.linea_l3b_b("FALLA", ["p95 degradado"], True), L.LINEA_L3B_B_FALLA)
        self.assertIn("esperada por el diseño", L.LINEA_L3B_B_FALLA)
        muerte = L.linea_l3b_b("FALLA", [L.MOTIVO_MUERTE, "CPU de k6 alta"], True)
        self.assertTrue(muerte.startswith("L3b-b: FALLA (murió un servicio de Canario; NO OK)"))
        self.assertIn("CPU de k6 alta", muerte)
        self.assertNotIn("esperada por el diseño", muerte)

    def test_la_muerte_da_esa_linea_y_ninguna_cota_de_coste(self):
        def repeticion(n, muertes):
            detalle = {"victimas": {r: {"base": {"p95_ms": 50}, "carga": {"peticiones": 600, "p95_ms": 60, "tasa_errores": 0.0},
                                        "descartes_aviso": 0} for r in L.SLO_VICTIMAS_MS},
                       "login": {"p95_ms": 2000, "tasa_errores": 0.0, "descartes_aviso": 0}}
            return {"modo": "l3b", "repeticion": n, "muertes": list(muertes), "reinicios": 0, "comun": [],
                    "partes": {"l3b-a": {"resultado": "PASA", "validez": [], "control_ataque": None, "detalle": {}},
                               "l3b-b": {"resultado": "PASA", "validez": [], "control_ataque": None, "detalle": detalle}},
                    "veredictos": {"l3b-a": ("PASA", []), "l3b-b": ("PASA", [])}}
        for muertes, hay_cota, linea in (([], False, L.LINEA_L3B_B_PASA), (["FALLA"], False, None)):
            lineas, controles = [], {}
            with mock.patch.object(L, "p", lineas.append):
                finales = L.agregar_fases("l3b", [repeticion(i, muertes if i == 1 else []) for i in (1, 2, 3)], 3, (),
                                          controles)
            v, motivos = finales["l3b-b"]
            self.assertEqual(any("coste del ataque" in x for x in lineas), hay_cota)
            if muertes:
                self.assertEqual(v, "FALLA")
                self.assertIn(L.MOTIVO_MUERTE, motivos)
                self.assertIn("murió un servicio", L.linea_l3b_b(v, motivos, controles["l3b-b"]))
            else:
                self.assertEqual(L.linea_l3b_b(v, motivos, controles["l3b-b"]), linea)


class EstimacionDeTiempo(unittest.TestCase):
    def test_el_sandwich_de_j5_son_541_s_de_peor_caso(self):
        # 121 s de espera maxima + 120 s para recrear la API + 225 s (11 peticiones x 15 s + 60 s) + 75 s (1 x 15 + 60).
        self.assertEqual(L.MARGEN_SANDWICH_J5_S, 120)
        self.assertEqual(L.sandwich_j5_maximo_s(), 541)

    def test_repeticion_1_frente_a_repeticion_2_en_l3_y_l3b(self):
        # L3: 300 + 30 + 15 + 240 + (120 + 60) = 765 s; L3b: 570 + 30 + 15 + 240 + (120 + 300) = 1275 s.
        self.assertEqual(L.estimar_repeticion_s("l3", 1), 765)
        self.assertEqual(L.estimar_repeticion_s("l3", 2), 765 + 541)
        self.assertEqual(L.estimar_repeticion_s("l3b", 1), 1275)
        self.assertEqual(L.estimar_repeticion_s("l3b", 2), 1275 + 541)
        self.assertEqual(L.estimar_repeticion_s("l3", 3), L.estimar_repeticion_s("l3", 2))
        # Control: L2 y L4 no tienen sandwich, ninguna repetición cambia. L4 (plan v4.2,
        # cambio 2): el humo posterior acaba en 300 + 90 (maxDuration) + 20 (gracefulStop)
        # = 410 s, después de las fases (360 s): 410 + 30 + 15 + 240 = 695 s (antes 645).
        for modo, esperado in (("l2", 675), ("pico", 695)):
            self.assertEqual((L.estimar_repeticion_s(modo, 1), L.estimar_repeticion_s(modo, 2)), (esperado, esperado))

    def test_totales_con_tres_repeticiones(self):
        self.assertEqual(L.estimar_total_s("l3", 3), 765 + 2 * 1306 + 240)
        self.assertEqual(L.estimar_total_s("l3b", 3), 1275 + 2 * 1816 + 240)
        self.assertEqual(L.estimar_total_s("l2", 3), 3 * 675 + 240)

    def test_la_medianoche_usa_la_estimacion_de_la_repeticion_concreta(self):
        # Con 1000 s hasta las 00:00 UTC, la repeticion 1 de L3 (765 s) cabe y la 2 (1306 s) no.
        medianoche = 1795392000
        ahora = medianoche - 1000
        self.assertEqual(L.espera_por_medianoche(ahora, L.estimar_repeticion_s("l3", 1)), 0.0)
        self.assertEqual(L.espera_por_medianoche(ahora, L.estimar_repeticion_s("l3", 2)), 1005.0)

    def test_el_sandwich_espera_a_la_ventana_con_120_s_de_margen(self):
        pedidos = []
        base = 1795342203.0
        pet = lambda e, t: {"estado": e, "inicio": t, "fin": t + 0.1}  # noqa: E731
        respuestas = {"j5pos_r2": [pet(429, base)], "j5neg_r2": [pet(401, base + 10)]}
        # create_autospec con la firma real (ej, rep, *, etiqueta): el doble
        # anterior, `lambda ej: None`, aceptaba la llamada vieja y rota.
        recrear = mock.create_autospec(L.recrear_api, return_value=None)
        ej = types.SimpleNamespace(id_a="a" * 32, contrasena="x")
        with mock.patch.object(L, "esperar_ventana", lambda periodo, minimo: pedidos.append((periodo, minimo))), \
                mock.patch.object(L, "cliente_control", lambda ej, n, ip, p_: respuestas[n]), \
                mock.patch.object(L, "recrear_api", recrear), mock.patch.object(L, "p", lambda *a: None), \
                mock.patch.object(L, "linea_control", lambda *a: None):
            L.sandwich_j5(ej, "l3", 2, {})
        self.assertEqual(pedidos, [(300, 120)])
        self.assertEqual(recrear.call_args_list, [mock.call(ej, 2, etiqueta="J5")])


class ScriptsDeK6(unittest.TestCase):
    def test_cliente_de_control_compila_y_no_lleva_comillas_dobles(self):
        import ast
        ast.parse(L.CODIGO_CLIENTE)
        self.assertNotIn('"', L.CODIGO_CLIENTE)

    def test_los_scripts_estan_en_utf8_sin_bom_ni_crlf(self):
        for nombre in ("fases.js", "l3.js", "sonda_descartes.js", "sonda_descartes.py"):
            crudo = (pathlib.Path(__file__).resolve().parent / nombre).read_bytes()
            self.assertFalse(crudo.startswith(b"\xef\xbb\xbf"), nombre)
            self.assertNotIn(b"\r\n", crudo, nombre)
            crudo.decode("utf-8")

    def test_l3_js_guarda_las_ips_en_un_sharedarray_y_aborta_con_421(self):
        js = (pathlib.Path(__file__).resolve().parent / "l3.js").read_text(encoding="utf-8")
        self.assertIn("import { SharedArray } from 'k6/data';", js)
        self.assertIn("open('/datos/ips.json')", js)
        # S10: el control del 421 en setup() y la salida literal que el lanzador convierte en PARADA.
        self.assertIn("console.error('CONTROL_421');", js)
        self.assertIn("exec.test.abort(", js)
        # Seguridad 4: POST /salud tiene que dar 405 (no solo no dar 421) y, en L3b, GET /seguimiento 200.
        self.assertIn("control.status !== 405", js)
        self.assertIn("datos.modo === 'l3b'", js)
        self.assertIn("web.status !== 200", js)
        self.assertIn("CONTROL_SETUP", js)
        # Las IPs ya no viajan dentro de ejecucion.json (e.ips): solo su numero.
        self.assertNotIn("e.ips", js)
        self.assertIn("e.n_ips", js)

    def test_preparar_datos_k6_separa_las_ips(self):
        ej = types.SimpleNamespace(id_a="a" * 32, id_b="b" * 32, contrasena="Estres-x", texto_humo="Humo")
        escenarios = [{"nombre": "login_ataque", "ips": ["198.18.0.1", "198.18.0.2"], "rate": 1}, {"nombre": "s", "rate": 1}]
        texto, ips = L.preparar_datos_k6(ej, "l3b", escenarios, [], [], 0)
        datos = json.loads(texto)
        self.assertEqual(ips, {"login_ataque": ["198.18.0.1", "198.18.0.2"]})
        self.assertEqual(datos["escenarios"][0], {"nombre": "login_ataque", "rate": 1, "n_ips": 2})
        self.assertNotIn("198.18.0.1", texto)
        # Control: un escenario sin ips queda igual.
        self.assertEqual(datos["escenarios"][1], {"nombre": "s", "rate": 1})

    def test_fases_js_usa_los_campos_de_rutas_web(self):
        # H-web: campo codigo y Origin del sitio, como exige app/rutas_web.py.
        raiz = pathlib.Path(__file__).resolve().parents[2]
        web = (raiz / "app" / "rutas_web.py").read_text(encoding="utf-8")
        self.assertIn('FormularioCodigo = Annotated[dict, Depends(formulario("codigo"))]', web)
        self.assertIn('ORIGEN_POR_DEFECTO = "https://localhost:8444"', web)
        js = (pathlib.Path(__file__).resolve().parent / "fases.js").read_text(encoding="utf-8")
        self.assertIn("const ORIGEN_WEB = 'https://localhost:8444';", js)
        self.assertIn("`codigo=${codigo}`", js)
        self.assertIn("/seguimiento/consulta", js)


class ParadaEnCurso(unittest.TestCase):
    """D2 y M1: en --l2, --pico, --l3 y --l3b la línea "PARADA: <texto>" sale en
    cuanto se produce, antes de los callbacks de la pila (limpiar_efimeros,
    eventos.parar) y del escaneo del finally, para que un segundo Ctrl+C
    durante ellos no deje la causa sin decir. Se ejecutan ejecutar_modo y main de
    verdad con todo lo de Docker simulado; el orden de todo va en `e.orden`."""
    CAUSA = "causa literal de la parada"
    LINEA = "PARADA: causa literal de la parada"

    class Fin(Exception):
        pass

    @staticmethod
    def ctrl_c():
        raise KeyboardInterrupt

    def montar(self, pila, e, escanear, limpiar):
        """Sustituye lo de Docker bajo ejecutar_modo (L2, repetición 1 que da
        PARADA). `escanear()` y `limpiar()` son lo que hacen esas dos llamadas."""
        e.orden = []

        def repeticion_falsa(ej, modo, rep, n_reps):
            raise L.Parada(self.CAUSA)

        def escanear_falso(ej):
            e.orden.append("<escanear_salida>")
            return escanear()

        def limpiar_falso():
            e.orden.append("<limpiar_efimeros>")
            limpiar()

        eventos = types.SimpleNamespace(parar=lambda: e.orden.append("<eventos.parar>"), ilegibles=0)
        for parche in (mock.patch.object(L, "p", e.orden.append),
                       mock.patch.object(L, "comprobar_cifras_congeladas", lambda *a: None),
                       mock.patch.object(L, "comprobar_literales_argon2", lambda: None),
                       mock.patch.object(L, "EventosDocker", lambda inicio, ruta: eventos),
                       mock.patch.object(L, "hora_motor_ahora", lambda: 100.0),
                       mock.patch.object(L, "ejecutar_repeticion_fases", repeticion_falsa),
                       mock.patch.object(L, "escanear_salida", escanear_falso),
                       mock.patch.object(L, "limpiar_efimeros", limpiar_falso),
                       mock.patch.dict(L.estado, {"falla": False, "sin_conclusion": False}),
                       mock.patch.dict(L.ACTUAL, {"ej": None})):
            pila.enter_context(parche)

    def montar_main(self, pila, e, argv, ejecutar_l1=None):
        """Lo que main necesita además: argumentos, precondiciones, topología de
        CPU, directorios temporales dentro de `e.raiz`, overrides, limpieza y el
        final (terminar lanza Fin en vez de salir del proceso)."""
        def terminar_falso():
            raise self.Fin()

        parches = [mock.patch.object(sys, "argv", argv),
                   mock.patch.object(L, "estado_git", lambda: []),
                   mock.patch.object(L, "comprobaciones_previas", lambda: None),
                   mock.patch.object(L, "leer_topologia", lambda: [(0, 1)]),
                   mock.patch.object(L, "elegir_cpus", lambda hermanas: ([0], [1], "texto", False)),
                   mock.patch.object(L, "ejecutar", lambda args, timeout=900: L.R(0, "1\n", "")),
                   mock.patch.object(L, "tempfile", types.SimpleNamespace(
                       mkdtemp=lambda prefix="": tempfile.mkdtemp(prefix=prefix, dir=str(e.raiz)))),
                   mock.patch.object(L, "preparar_overrides", lambda *a, **k: []),
                   mock.patch.object(L, "preparar_override_postgres", lambda temporal: None),
                   mock.patch.object(L, "dc", lambda *a, **k: L.R(0, "", "")),
                   mock.patch.object(L, "recursos_previos", lambda: []),
                   mock.patch.object(L, "escanear_texto_final", lambda ej: None),
                   mock.patch.object(L, "terminar", terminar_falso)]
        if ejecutar_l1 is not None:
            parches.append(mock.patch.object(L, "ejecutar_l1", ejecutar_l1))
        for parche in parches:
            pila.enter_context(parche)

    def ejecutar_modo(self, e):
        L.ejecutar_modo("l2", 0.0196, e.raiz, e.raiz, [0], [1], 1)

    def lineas_parada(self, e):
        return [linea for linea in e.orden if linea.startswith("PARADA")]

    def test_parada_mas_ctrl_c_en_el_escaner_deja_la_linea_ya_impresa(self):
        with tempfile.TemporaryDirectory() as d, contextlib.ExitStack() as pila:
            e = types.SimpleNamespace(raiz=pathlib.Path(d))
            self.montar(pila, e, escanear=self.ctrl_c, limpiar=lambda: None)
            with self.assertRaises(KeyboardInterrupt):
                self.ejecutar_modo(e)
        # La línea está, una sola vez, y salió ANTES de la limpieza y del escaneo
        # que recibió el Ctrl+C.
        self.assertEqual(self.lineas_parada(e), [self.LINEA])
        self.assertLess(e.orden.index(self.LINEA), e.orden.index("<eventos.parar>"))
        self.assertLess(e.orden.index(self.LINEA), e.orden.index("<limpiar_efimeros>"))
        self.assertLess(e.orden.index(self.LINEA), e.orden.index("<escanear_salida>"))

    def test_parada_mas_ctrl_c_en_limpiar_efimeros_deja_la_linea_ya_impresa(self):
        # M1: limpiar_efimeros es un callback del ExitStack y corre antes que el
        # finally de ejecutar_modo. Un Ctrl+C ahí ya encuentra la línea impresa.
        with tempfile.TemporaryDirectory() as d, contextlib.ExitStack() as pila:
            e = types.SimpleNamespace(raiz=pathlib.Path(d))
            self.montar(pila, e, escanear=lambda: ("PASA", "anti-fuga sin hallazgos"), limpiar=self.ctrl_c)
            with self.assertRaises(KeyboardInterrupt):
                self.ejecutar_modo(e)
        self.assertEqual(self.lineas_parada(e), [self.LINEA])
        self.assertLess(e.orden.index(self.LINEA), e.orden.index("<limpiar_efimeros>"))

    def test_control_sin_ctrl_c_una_sola_linea_parada_tambien_con_main(self):
        # 1. ejecutar_modo solo: la PARADA sale con `impresa` y una sola línea.
        with tempfile.TemporaryDirectory() as d, contextlib.ExitStack() as pila:
            e = types.SimpleNamespace(raiz=pathlib.Path(d))
            self.montar(pila, e, escanear=lambda: ("PASA", "anti-fuga sin hallazgos"), limpiar=lambda: None)
            with self.assertRaises(L.Parada) as ctx:
                self.ejecutar_modo(e)
        self.assertIs(ctx.exception.impresa, True)
        self.assertEqual(self.lineas_parada(e), [self.LINEA])
        # 2. main con ejecutar_modo real (--l2): main no la imprime otra vez.
        with tempfile.TemporaryDirectory() as d, contextlib.ExitStack() as pila:
            e = types.SimpleNamespace(raiz=pathlib.Path(d))
            self.montar(pila, e, escanear=lambda: ("PASA", "anti-fuga sin hallazgos"), limpiar=lambda: None)
            self.montar_main(pila, e, ["lanzar.py", "--l2", "--t", "0.0196", "--repeticiones", "1"])
            with self.assertRaises(self.Fin):
                L.main()
        self.assertEqual(self.lineas_parada(e), [self.LINEA])
        # 3. Control del control: una PARADA que NO viene de ejecutar_modo (L1) la
        # sigue imprimiendo main, una vez. Si main no imprimiera nada, el punto 2
        # pasaría en vacío.
        with tempfile.TemporaryDirectory() as d, contextlib.ExitStack() as pila:
            e = types.SimpleNamespace(raiz=pathlib.Path(d))
            self.montar(pila, e, escanear=lambda: ("PASA", "anti-fuga sin hallazgos"), limpiar=lambda: None)

            def l1_falso(t, datos, salida, cpus_canario, cpus_k6, repeticiones):
                raise L.Parada("causa literal de L1")
            self.montar_main(pila, e, ["lanzar.py", "--l1", "--t", "0.0196", "--repeticiones", "1"], l1_falso)
            with self.assertRaises(self.Fin):
                L.main()
        self.assertEqual(self.lineas_parada(e), ["PARADA: causa literal de L1"])


def evento_lim(causa, espera, clase="ConnectionError"):
    """Línea del evento tal como la escribe app/limitador.py (texto_evento)."""
    return f"EVENTO limitador_no_disponible: {clase} causa={causa} espera={espera}"


class ParserLimitador(unittest.TestCase):
    def test_linea_nueva(self):
        self.assertEqual(L.parsear_limitador("EVENTO limitador_no_disponible: ConnectionError causa=pool_agotado "
                                             "espera=0.25-0.5"),
                         ("ConnectionError", "pool_agotado", "0.25-0.5", "pool_agotado", "0.25-0.5"))
        # Los otros dos tramos y otra clase: el signo < y > no rompe el \S+.
        self.assertEqual(L.parsear_limitador("EVENTO limitador_no_disponible: TimeoutError causa=plazo espera=<0.25")[:3],
                         ("TimeoutError", "plazo", "<0.25"))
        self.assertEqual(L.parsear_limitador("EVENTO limitador_no_disponible: OSError causa=conexion espera=>0.5")[:3],
                         ("OSError", "conexion", ">0.5"))
        # Con el prefijo real del logger (formato de app/principal.py:40, "%(levelname)s %(name)s: %(message)s"
        # y logger canario.limitador), sin prefijo de servicio por --no-log-prefix.
        self.assertEqual(L.parsear_limitador("ERROR canario.limitador: EVENTO limitador_no_disponible: "
                                             "ConnectionError causa=otra espera=<0.25")[:3],
                         ("ConnectionError", "otra", "<0.25"))

    def test_texto_de_mas_tras_los_campos_no_pasa_como_valido(self):
        # La línea sigue casando (cuenta en el total de SENALES) pero la espera es anómala.
        self.assertEqual(L.parsear_limitador("EVENTO limitador_no_disponible: ConnectionError causa=plazo "
                                             "espera=<0.25 basura"),
                         ("ConnectionError", "plazo", "fuera_de_conjunto", "plazo", "<0.25 basura"))
        self.assertEqual(L.parsear_limitador("EVENTO limitador_no_disponible: ConnectionError causa=plazo basura"),
                         ("ConnectionError", "plazo", "fuera_de_conjunto", "plazo", "basura"))
        # Control positivo: la misma línea sin sobrante, y con espacios finales, es válida.
        self.assertEqual(L.parsear_limitador("EVENTO limitador_no_disponible: ConnectionError causa=plazo "
                                             "espera=<0.25")[2], "<0.25")
        self.assertEqual(L.parsear_limitador("EVENTO limitador_no_disponible: ConnectionError causa=plazo "
                                             "espera=<0.25  ")[2], "<0.25")

    def test_linea_antigua_da_sin_dato(self):
        self.assertEqual(L.parsear_limitador("EVENTO limitador_no_disponible: ConnectionError"),
                         ("ConnectionError", "sin_dato", "sin_dato", None, None))
        # Control positivo: la clase sale igual en la línea antigua y en la nueva (el grupo 1 no cambia).
        self.assertEqual(L.parsear_limitador("EVENTO limitador_no_disponible: ConnectionError causa=plazo "
                                             "espera=<0.25")[0], "ConnectionError")

    def test_valor_fuera_de_conjunto_no_se_acepta_en_silencio(self):
        casos = (
            ("EVENTO limitador_no_disponible: ConnectionError causa=redis_caido espera=<0.25",
             ("ConnectionError", "fuera_de_conjunto", "<0.25", "redis_caido", "<0.25")),
            ("EVENTO limitador_no_disponible: ConnectionError causa=plazo espera=1.0",
             ("ConnectionError", "plazo", "fuera_de_conjunto", "plazo", "1.0")),
            # El centinela de la propia agregación tampoco vale como valor del log.
            ("EVENTO limitador_no_disponible: ConnectionError causa=sin_dato espera=<0.25",
             ("ConnectionError", "fuera_de_conjunto", "<0.25", "sin_dato", "<0.25")),
            # Mayúsculas: el conjunto es exacto.
            ("EVENTO limitador_no_disponible: ConnectionError causa=PLAZO espera=<0.25",
             ("ConnectionError", "fuera_de_conjunto", "<0.25", "PLAZO", "<0.25")),
        )
        for linea, esperado in casos:
            with self.subTest(linea=linea):
                self.assertEqual(L.parsear_limitador(linea), esperado)
        # Control positivo: cada valor válido literal sí se acepta tal cual.
        for causa in ("pool_agotado", "permiso", "plazo", "conexion", "otra"):
            for espera in ("<0.25", "0.25-0.5", ">0.5"):
                self.assertEqual(L.parsear_limitador(evento_lim(causa, espera))[1:3], (causa, espera))

    def test_otras_lineas_no_son_el_evento(self):
        self.assertIsNone(L.parsear_limitador("EVENTO hashes_saturados"))
        self.assertIsNone(L.parsear_limitador("SIN CONEXION: PoolTimeout"))

    def test_senales_sigue_contando_la_clase(self):
        # El patrón de SENALES es el mismo: el grupo 1 sigue siendo la clase.
        patron = dict(L.SENALES)["limitador_no_disponible"]
        self.assertEqual(patron.search(evento_lim("plazo", "<0.25", clase="TimeoutError")).group(1), "TimeoutError")
        self.assertEqual(patron.search("EVENTO limitador_no_disponible: ConnectionError").group(1), "ConnectionError")


class ResumenLimitador(unittest.TestCase):
    def test_recuento_por_causa_y_espera_de_pool(self):
        lineas = [(10.0, evento_lim("pool_agotado", "<0.25")), (11.0, evento_lim("pool_agotado", "0.25-0.5")),
                  (12.0, evento_lim("pool_agotado", "0.25-0.5")), (13.0, evento_lim("pool_agotado", ">0.5")),
                  (14.0, evento_lim("plazo", ">0.5")), (15.0, evento_lim("otra", "<0.25")),
                  (16.0, "EVENTO hashes_saturados"), (17.0, "EVENTO limitador_no_disponible: ConnectionError"),
                  (18.0, evento_lim("rara", "<0.25"))]
        r = L.resumir_limitador(lineas, [])
        self.assertEqual(r["total"], 8)
        self.assertEqual(r["causas"], {"pool_agotado": 4, "permiso": 0, "plazo": 1, "conexion": 0, "otra": 1,
                                       "sin_dato": 1, "fuera_de_conjunto": 1})
        # La espera de plazo (">0.5") NO entra en el recuento de pool_agotado.
        self.assertEqual(r["esperas_pool"], {"<0.25": 1, "0.25-0.5": 2, ">0.5": 1, "sin_dato": 0,
                                             "fuera_de_conjunto": 0})
        self.assertEqual(r["valores_ajenos"], ["causa='rara'"])
        self.assertEqual((r["espera_anomala"], r["campos_ajenos"]), (1, 1))  # la línea antigua; "rara"
        # Control positivo: sin eventos todo es 0 (el recuento no inventa).
        vacio = L.resumir_limitador([(1.0, "EVENTO hashes_saturados")], [])
        self.assertEqual((vacio["total"], sum(vacio["causas"].values()), sum(vacio["esperas_pool"].values())), (0, 0, 0))

    def test_ventana_de_arranque_de_redis_con_sus_bordes(self):
        # Arranque de Redis en t = 100.0: la ventana es [100.0, 110.0).
        lineas = [(99.999, evento_lim("conexion", "<0.25")),    # antes del start: fuera
                  (100.0, evento_lim("conexion", "<0.25")),     # borde inicial: dentro
                  (109.999, evento_lim("conexion", "<0.25")),   # dentro
                  (110.0, evento_lim("conexion", "<0.25")),     # borde final: fuera (semiabierta)
                  (200.0, evento_lim("conexion", "<0.25")),     # lejos: fuera
                  (105.0, evento_lim("permiso", "<0.25")),      # dentro
                  (110.001, evento_lim("permiso", "<0.25"))]    # fuera
        r = L.resumir_limitador(lineas, [100.0])
        self.assertEqual(r["arranque"], {"conexion": {"dentro": 2, "fuera": 3}, "permiso": {"dentro": 1, "fuera": 1}})
        self.assertEqual(r["arranques_redis"], 1)
        # Control positivo: sin ningún start conocido, todo cae fuera (y se ve en arranques_redis = 0).
        sin = L.resumir_limitador(lineas, [])
        self.assertEqual(sin["arranque"], {"conexion": {"dentro": 0, "fuera": 5}, "permiso": {"dentro": 0, "fuera": 2}})
        self.assertEqual(sin["arranques_redis"], 0)

    def test_la_ventana_solo_afecta_a_conexion_y_permiso(self):
        lineas = [(100.0, evento_lim("plazo", "<0.25")), (100.0, evento_lim("pool_agotado", "<0.25")),
                  (100.0, evento_lim("otra", "<0.25"))]
        r = L.resumir_limitador(lineas, [100.0])
        self.assertEqual(r["arranque"], {"conexion": {"dentro": 0, "fuera": 0}, "permiso": {"dentro": 0, "fuera": 0}})
        self.assertEqual(r["total"], 3)

    def test_varios_arranques_de_redis(self):
        # Dos arranques (por ejemplo una repetición y un reinicio): cada uno abre su ventana.
        lineas = [(105.0, evento_lim("conexion", "<0.25")), (505.0, evento_lim("conexion", "<0.25")),
                  (300.0, evento_lim("conexion", "<0.25"))]
        r = L.resumir_limitador(lineas, [100.0, 500.0])
        self.assertEqual(r["arranque"]["conexion"], {"dentro": 2, "fuera": 1})


class SenalesEscalonLimitador(unittest.TestCase):
    def res(self):
        # Escalón de 100 s a 200 s (ms); la ventana de senales_escalon es [99, 201] s.
        return {"principal": {"ventana_ms": [100000, 200000]}}

    def test_solo_cuenta_la_ventana_del_escalon(self):
        lineas = [(98.9, evento_lim("pool_agotado", "<0.25")),   # fuera de la ventana
                  (99.0, evento_lim("pool_agotado", "0.25-0.5")),
                  (150.0, evento_lim("conexion", "<0.25")),
                  (201.0, evento_lim("permiso", "<0.25")),
                  (201.1, evento_lim("permiso", "<0.25"))]       # fuera de la ventana
        res = self.res()
        L.senales_escalon(lineas, {"redis": [], "postgres": []}, res, [145.0])
        self.assertEqual(res["limitador"]["total"], 3)
        self.assertEqual(res["limitador"]["causas"]["pool_agotado"], 1)
        self.assertEqual(res["limitador"]["arranque"]["conexion"], {"dentro": 1, "fuera": 0})
        self.assertEqual(res["limitador"]["arranque"]["permiso"], {"dentro": 0, "fuera": 1})
        # Coherente con el total de siempre de la señal.
        self.assertEqual(res["senales"]["limitador_no_disponible"]["total"], 3)
        self.assertEqual(res["senales"]["limitador_no_disponible"]["clases"], {"ConnectionError": 3})
        # Control positivo: sin la ventana (escalón sin datos) no se inventa el resumen.
        sin = {"principal": {}}
        L.senales_escalon(lineas, {}, sin, [])
        self.assertNotIn("limitador", sin)


class SalidaLimitador(unittest.TestCase):
    def resumen(self, lineas, arranques):
        return L.resumir_limitador(lineas, arranques)

    def test_columnas_y_valores_literales(self):
        self.assertEqual(
            list(L.COLUMNAS_LIMITADOR),
            ["limitador_pool_agotado", "limitador_permiso", "limitador_plazo", "limitador_conexion",
             "limitador_otra", "limitador_sin_dato", "limitador_fuera_de_conjunto",
             "limitador_espera_anomala", "pool_espera_menos_025", "pool_espera_025_a_05", "pool_espera_mas_05", "pool_espera_sin_dato", "pool_espera_fuera_de_conjunto",
             "conexion_fuera_arranque", "conexion_dentro_arranque", "permiso_fuera_arranque",
             "permiso_dentro_arranque", "arranques_redis_vistos"])
        lineas = [(100.0, evento_lim("pool_agotado", ">0.5")), (101.0, evento_lim("pool_agotado", "<0.25")),
                  (102.0, evento_lim("conexion", "<0.25")), (150.0, evento_lim("conexion", "<0.25")),
                  (103.0, evento_lim("permiso", "<0.25")), (104.0, evento_lim("otra", "<0.25")),
                  (105.0, "EVENTO limitador_no_disponible: ConnectionError")]
        self.assertEqual(L.valores_limitador(self.resumen(lineas, [100.0])),
                         [2, 1, 0, 2, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1])
        # Control positivo: un escalón sin resumen da None en cada columna, del mismo ancho.
        self.assertEqual(L.valores_limitador(None), [None] * 18)

    def test_csv_con_las_columnas_nuevas(self):
        lineas = [(100.0, evento_lim("pool_agotado", "0.25-0.5")), (150.0, evento_lim("conexion", "<0.25"))]
        res = {"ruta": "denuncia", "escalon": "e1", "etiqueta": "x", "tasa": 10, "sin_conclusion": [],
               "limitador": self.resumen(lineas, [145.0])}
        con_resumen_ausente = {"ruta": "denuncia", "escalon": "e2", "etiqueta": "y", "tasa": 20, "sin_conclusion": []}
        with tempfile.TemporaryDirectory() as d:
            L.escribir_resultados([res, con_resumen_ausente], pathlib.Path(d))
            with open(pathlib.Path(d) / "resultados.csv", encoding="utf-8", newline="") as fichero:
                filas = list(csv.DictReader(fichero))
        self.assertEqual(filas[0]["limitador_pool_agotado"], "1")
        self.assertEqual(filas[0]["pool_espera_025_a_05"], "1")
        self.assertEqual(filas[0]["conexion_dentro_arranque"], "1")
        self.assertEqual(filas[0]["conexion_fuera_arranque"], "0")
        self.assertEqual(filas[0]["arranques_redis_vistos"], "1")
        # Control positivo: la columna de siempre sigue donde estaba y sin_conclusion sigue al final.
        self.assertEqual(filas[0]["sin_conclusion"], "")
        self.assertEqual(list(filas[0])[-1], "sin_conclusion")
        # Escalón sin resumen: celdas vacías, no ceros inventados.
        self.assertEqual(filas[1]["limitador_pool_agotado"], "")

    def test_linea_legible(self):
        lineas = [(100.0, evento_lim("pool_agotado", "0.25-0.5")), (101.0, evento_lim("pool_agotado", "<0.25")),
                  (102.0, evento_lim("conexion", "<0.25"))]
        self.assertEqual(
            L.lineas_limitador(self.resumen(lineas, [100.0])),
            ["      limitador (causa, informacion): n=3 pool_agotado=2 plazo=0 conexion=1 permiso=0 otra=0 "
             "sin_dato=0 fuera_de_conjunto=0 espera_anomala=0; espera de pool_agotado: <0.25=1 0.25-0.5=1 >0.5=0 "
             "sin_dato=0 "
             "fuera_de_conjunto=0; conexion fuera/dentro de los 10 s tras el arranque de Redis 0/1; permiso "
             "fuera/dentro 0/0; arranques de Redis vistos 1"])
        # Sin eventos: una línea que lo dice.
        self.assertEqual(L.lineas_limitador(self.resumen([], [])), ["      limitador (causa): sin eventos"])

    def test_aviso_si_hay_lineas_sin_causa_o_ajenas(self):
        lineas = [(1.0, "EVENTO limitador_no_disponible: ConnectionError"), (2.0, evento_lim("rara", "<0.25"))]
        salida = L.lineas_limitador(self.resumen(lineas, []))
        self.assertEqual(len(salida), 2)
        self.assertEqual(salida[1], "      AVISO limitador: lineas sin causa (1), causas fuera del conjunto (1), "
                                    "esperas sin dato o fuera del conjunto (1); 1 campos con valor ajeno, muestra "
                                    "[\"causa='rara'\"]: imagen distinta de la esperada o log alterado")
        # Control positivo: con todo válido no hay aviso.
        limpio = L.lineas_limitador(self.resumen([(1.0, evento_lim("plazo", "<0.25"))], []))
        self.assertEqual(len(limpio), 1)

    def test_espera_ajena_con_causa_plazo_avisa_y_no_contamina_el_pool(self):
        r = self.resumen([(1.0, evento_lim("plazo", "1.0"))], [])
        self.assertEqual((r["espera_anomala"], r["campos_ajenos"], r["valores_ajenos"]), (1, 1, ["espera='1.0'"]))
        self.assertEqual(r["esperas_pool"], {"<0.25": 0, "0.25-0.5": 0, ">0.5": 0, "sin_dato": 0,
                                             "fuera_de_conjunto": 0})
        self.assertEqual(L.valores_limitador(r)[:8], [0, 0, 1, 0, 0, 0, 0, 1])
        salida = L.lineas_limitador(r)
        self.assertEqual(len(salida), 2)
        self.assertEqual(salida[1], "      AVISO limitador: lineas sin causa (0), causas fuera del conjunto (0), "
                                    "esperas sin dato o fuera del conjunto (1); 1 campos con valor ajeno, muestra "
                                    "[\"espera='1.0'\"]: imagen distinta de la esperada o log alterado")
        # Control positivo: con espera válida, la misma causa no da columna ni aviso.
        bien = self.resumen([(1.0, evento_lim("plazo", "0.25-0.5"))], [])
        self.assertEqual(bien["espera_anomala"], 0)
        self.assertEqual(len(L.lineas_limitador(bien)), 1)

    def test_pool_agotado_sin_espera_avisa(self):
        r = self.resumen([(1.0, "EVENTO limitador_no_disponible: ConnectionError causa=pool_agotado")], [])
        self.assertEqual(r["esperas_pool"]["sin_dato"], 1)
        self.assertEqual((r["espera_anomala"], r["campos_ajenos"]), (1, 0))
        salida = L.lineas_limitador(r)
        self.assertEqual(len(salida), 2)
        self.assertEqual(salida[1], "      AVISO limitador: lineas sin causa (0), causas fuera del conjunto (0), "
                                    "esperas sin dato o fuera del conjunto (1); 0 campos con valor ajeno, muestra "
                                    "[]: imagen distinta de la esperada o log alterado")
        # Control positivo: la misma causa con su espera no avisa.
        bien = self.resumen([(1.0, evento_lim("pool_agotado", "<0.25"))], [])
        self.assertEqual((bien["esperas_pool"]["sin_dato"], bien["espera_anomala"]), (0, 0))
        self.assertEqual(len(L.lineas_limitador(bien)), 1)

    def test_total_de_valores_ajenos_mas_alla_de_la_muestra(self):
        lineas = [(float(i), evento_lim(f"c{i}", "<0.25")) for i in range(7)]
        r = self.resumen(lineas, [])
        self.assertEqual((r["campos_ajenos"], len(r["valores_ajenos"])), (7, 5))
        self.assertIn("7 campos con valor ajeno", L.lineas_limitador(r)[1])


class DeFicheroAResumen(unittest.TestCase):
    """Punta a punta: una línea con la forma que deja Registro
    (docker compose logs -f -t --no-color --no-log-prefix) pasa por leer_log
    y senales_escalon."""

    def test_linea_real_del_log(self):
        # 2026-11-23T20:00:00Z = 1795464000 (comprobado con date -u -d); formato del mensaje:
        # "%(levelname)s %(name)s: %(message)s" (app/principal.py:40), logger canario.limitador.
        contenido = (
            "2026-11-23T20:00:00.123456789Z ERROR canario.limitador: EVENTO limitador_no_disponible: "
            "ConnectionError causa=pool_agotado espera=0.25-0.5\n"
            "2026-11-23T20:00:03.000000000Z ERROR canario.limitador: EVENTO limitador_no_disponible: "
            "ConnectionError causa=conexion espera=<0.25\n"
            "2026-11-23T20:00:05.000000000Z ERROR canario.limitador: EVENTO limitador_no_disponible: "
            "ConnectionError causa=conexion espera=<0.25\n"
            "2026-11-23T20:00:06.000000000Z INFO canario.arranque: otra linea\n"
            "linea sin marca de tiempo\n")
        with tempfile.TemporaryDirectory() as d:
            ruta = pathlib.Path(d) / "log_denuncia_api.txt"
            ruta.write_text(contenido, encoding="utf-8", newline="\n")
            lineas = L.leer_log(ruta)
        # La línea sin marca se descarta; las otras cuatro dan (epoch, mensaje).
        self.assertEqual(len(lineas), 4)
        self.assertAlmostEqual(lineas[0][0], 1795464000.123457, places=5)
        self.assertEqual(lineas[1][0], 1795464003.0)
        self.assertEqual(lineas[2][0], 1795464005.0)
        self.assertEqual(lineas[0][1], "ERROR canario.limitador: EVENTO limitador_no_disponible: ConnectionError "
                                       "causa=pool_agotado espera=0.25-0.5")
        res = {"principal": {"ventana_ms": [1795463990000, 1795464010000]}}
        # Redis arrancó en 1795463995.0: la ventana es [1795463995, 1795464005).
        L.senales_escalon(lineas, {"redis": [], "postgres": []}, res, [1795463995.0])
        lim = res["limitador"]
        self.assertEqual(lim["total"], 3)
        self.assertEqual((lim["causas"]["pool_agotado"], lim["causas"]["conexion"]), (1, 2))
        self.assertEqual(lim["esperas_pool"]["0.25-0.5"], 1)
        self.assertEqual(lim["arranque"]["conexion"], {"dentro": 1, "fuera": 1})
        self.assertEqual((lim["espera_anomala"], lim["campos_ajenos"]), (0, 0))
        self.assertEqual(res["senales"]["limitador_no_disponible"]["total"], 3)
        # Control positivo: una línea antigua (sin causa) sigue contando en SENALES y sale como anomalía.
        antigua = [(1795464000.0, "ERROR canario.limitador: EVENTO limitador_no_disponible: ConnectionError"),
                   (1795464001.0, "ERROR canario.limitador: EVENTO limitador_no_disponible: ConnectionError "
                                  "causa=plazo espera=<0.25 basura")]
        res2 = {"principal": {"ventana_ms": [1795463990000, 1795464010000]}}
        L.senales_escalon(antigua, {}, res2, [])
        self.assertEqual(res2["senales"]["limitador_no_disponible"]["total"], 2)
        self.assertEqual(res2["senales"]["limitador_no_disponible"]["clases"], {"ConnectionError": 2})
        self.assertEqual((res2["limitador"]["causas"]["sin_dato"], res2["limitador"]["espera_anomala"]), (1, 2))


class ArranquesDeRedisYSenalesPorFase(unittest.TestCase):
    """Condición 4 de QA: senales_por_fase (L2 y L3) llama a senales_escalon
    con la firma de cuatro argumentos y le pasa los arranques de Redis de la
    repetición, sacados de ej.eventos desde t_ini."""

    def falso_ej(self, eventos):
        return types.SimpleNamespace(eventos=types.SimpleNamespace(copia=lambda: list(eventos)))

    def test_arranques_redis_desde_filtra_por_tiempo_clase_servicio_y_accion(self):
        eventos = [
            {"t": 100.0, "clase": "canario", "servicio": "redis", "accion": "start"},     # entra
            {"t": 50.0, "clase": "canario", "servicio": "redis", "accion": "start"},      # antes de t_ini
            {"t": 120.0, "clase": "canario", "servicio": "redis", "accion": "die"},       # otra acción
            {"t": 130.0, "clase": "canario", "servicio": "postgres", "accion": "start"},  # otro servicio
            {"t": 140.0, "clase": "k6", "servicio": "redis", "accion": "start"},          # otra clase
            {"t": 90.0, "clase": "canario", "servicio": "redis", "accion": "start"}]      # borde: t == t_ini entra
        self.assertEqual(L.arranques_redis_desde(self.falso_ej(eventos), 90.0), [100.0, 90.0])
        # Control positivo: sin eventos del tipo pedido la lista es vacía (no inventa).
        self.assertEqual(L.arranques_redis_desde(self.falso_ej(eventos[1:5]), 90.0), [])

    def test_senales_por_fase_pasa_los_arranques_y_no_da_typeerror(self):
        # 2026-11-23T20:00:00Z = 1795464000. Fase de 0 a 10 s: ventana [t0-1, t0+11].
        contenido = ("2026-11-23T20:00:02.000000000Z ERROR canario.limitador: EVENTO limitador_no_disponible: "
                     "ConnectionError causa=conexion espera=<0.25\n")
        with tempfile.TemporaryDirectory() as d:
            (pathlib.Path(d) / "log_api.txt").write_text(contenido, encoding="utf-8", newline="\n")
            fases = [{"nombre": "carga", "desde_s": 0, "hasta_s": 10}]
            con = L.senales_por_fase(pathlib.Path(d), fases, 1795464000.0, [1795464001.0])
            sin = L.senales_por_fase(pathlib.Path(d), fases, 1795464000.0, [])
        self.assertEqual(con["carga"]["limitador"]["arranque"]["conexion"], {"dentro": 1, "fuera": 0})
        self.assertEqual(con["carga"]["limitador"]["arranques_redis"], 1)
        self.assertEqual(con["carga"]["senales"]["limitador_no_disponible"]["total"], 1)
        # Control positivo: sin arranques conocidos la misma línea cae fuera.
        self.assertEqual(sin["carga"]["limitador"]["arranque"]["conexion"], {"dentro": 0, "fuera": 1})
        self.assertEqual(sin["carga"]["limitador"]["arranques_redis"], 0)


# ---------------------------------------------------------------------------
# L5, L6 y L7 (plan v3.2, 25/11/2026, con D-8). Cada prueba lleva el ID del plan.
# Todos los valores esperados son literales escritos aquí, no salen del código
# que se prueba; cada negativa lleva su control positivo en la misma prueba.
# ---------------------------------------------------------------------------
import builtins  # noqa: E402
import inspect  # noqa: E402
import ipaddress  # noqa: E402
import math  # noqa: E402
import os  # noqa: E402

DIR_ESTRES = pathlib.Path(__file__).resolve().parent
# 00:00 UTC de un día cualquiera, múltiplo de 3600 y de 86400 (1795392000 / 86400 = 20780).
HORA_EXACTA = 1795392000.0


def peticion_l5(estado, ra=None, inicio=HORA_EXACTA + 100.0, cuerpo=""):
    return {"estado": estado, "retry_after": ra, "inicio": inicio, "fin": inicio + 0.1, "cuerpo": cuerpo}


def serie_l5(ultima_estado=429, ultima_ra="1800", primeras=None, base=HORA_EXACTA + 100.0):
    estados = primeras if primeras is not None else [201] * 10
    resultados = [peticion_l5(e, inicio=base + i) for i, e in enumerate(estados)]
    resultados.append(peticion_l5(ultima_estado, ultima_ra, inicio=base + len(estados)))
    return resultados


class L5IpCompartida(unittest.TestCase):
    def test_u_l5_1_429_con_retry_after_valido_pasa(self):
        for ra in ("1800", "1", "3600"):
            v, texto = L.evaluar_l5(serie_l5(ultima_ra=ra))
            self.assertEqual(v, "PASA", ra)
        self.assertIn("coste asumido, threat-model §8 l.706", texto)

    def test_u_l5_2_retry_after_no_valido_falla(self):
        # Control positivo en la misma prueba: "1800" pasa.
        self.assertEqual(L.evaluar_l5(serie_l5(ultima_ra="1800"))[0], "PASA")
        for ra in ("0", "3601", "abc", None, "+5", " 5", "²"):
            self.assertEqual(L.evaluar_l5(serie_l5(ultima_ra=ra))[0], "FALLA", repr(ra))
        # Y una 11.a que no es 429 tambien es FALLA.
        self.assertEqual(L.evaluar_l5(serie_l5(ultima_estado=201, ultima_ra=None))[0], "FALLA")

    def test_u_l5_3_controles_y_ventana_dan_sin_conclusion(self):
        self.assertEqual(L.evaluar_l5(serie_l5(primeras=[201] * 9 + [422]))[0], "SIN CONCLUSION")
        self.assertEqual(L.evaluar_l5(serie_l5(ultima_estado=503, ultima_ra="5"))[0], "SIN CONCLUSION")
        self.assertEqual(L.evaluar_l5(serie_l5(ultima_estado=0, ultima_ra=None))[0], "SIN CONCLUSION")
        # Cruce de hora: la 1.a empieza en 3599,5 s de la hora y la 11.a acaba en 3600,5.
        cruza = serie_l5(base=HORA_EXACTA + 3599.5 - 10)
        cruza[0]["inicio"] = HORA_EXACTA + 3599.5
        cruza[-1]["inicio"], cruza[-1]["fin"] = HORA_EXACTA + 3600.4, HORA_EXACTA + 3600.5
        self.assertEqual(L.evaluar_l5(cruza)[0], "SIN CONCLUSION")
        # Control: la misma serie dentro de la hora pasa.
        self.assertEqual(L.evaluar_l5(serie_l5())[0], "PASA")

    def test_u_l5_4_el_cliente_trae_el_retry_after_sin_comillas_dobles(self):
        self.assertNotIn('"', L.CODIGO_CLIENTE)
        self.assertIn("getheader('Retry-After')", L.CODIGO_CLIENTE)
        import ast
        ast.parse(L.CODIGO_CLIENTE)

    def test_u_l5_5_evaluar_l5_no_imprime_ni_escribe_el_cuerpo(self):
        self.assertEqual(list(inspect.signature(L.evaluar_l5).parameters), ["resultados"])
        centinela = "CENTINELA-L5-ABCD-EFGH"
        resultados = serie_l5()
        for r in resultados[:10]:
            r["cuerpo"] = centinela
        salida, errores = io.StringIO(), io.StringIO()
        anterior = os.getcwd()
        with tempfile.TemporaryDirectory() as d:
            os.chdir(d)
            try:
                with contextlib.redirect_stdout(salida), contextlib.redirect_stderr(errores), \
                        mock.patch("builtins.open", side_effect=AssertionError("open")) as abrir, \
                        mock.patch.object(pathlib.Path, "write_text", side_effect=AssertionError("write_text")) as wt, \
                        mock.patch.object(pathlib.Path, "write_bytes", side_effect=AssertionError("write_bytes")) as wb:
                    v, texto = L.evaluar_l5(resultados)
                    abrir.assert_not_called()
                    wt.assert_not_called()
                    wb.assert_not_called()
                    # Controles positivos de la prueba, con los mismos parches activos.
                    print(centinela + "-CONTROL")
                    with self.assertRaises(AssertionError):
                        builtins.open("x", "w")
                listado = os.listdir(d)
            finally:
                os.chdir(anterior)
        self.assertEqual(v, "PASA")
        self.assertNotIn(centinela, texto)
        self.assertEqual(listado, [])
        capturado = salida.getvalue() + errores.getvalue()
        self.assertIn(centinela + "-CONTROL", capturado)
        self.assertEqual(capturado.replace(centinela + "-CONTROL", ""), "\n")

    def test_l5_sin_cuerpos_quita_solo_el_cuerpo(self):
        limpios = L.sin_cuerpos([{"estado": 201, "cuerpo": "AAAA", "inicio": 1.0, "fin": 2.0, "retry_after": None}])
        self.assertEqual(limpios, [{"estado": 201, "inicio": 1.0, "fin": 2.0, "retry_after": None}])


class IpsDeL6(unittest.TestCase):
    def test_u_ip_1_vectores_literales_de_ip_relleno(self):
        self.assertEqual(L.ip_relleno(0, 1), "100.64.0.1")
        self.assertEqual(L.ip_relleno(253, 1), "100.64.0.254")
        self.assertEqual(L.ip_relleno(254, 1), "100.64.1.1")
        self.assertEqual(L.ip_relleno(0, 2), "100.79.97.3")
        for i, rep in ((-1, 1), (1000000, 1), (0, 0), (999999, 5)):
            with self.assertRaises(ValueError, msg=(i, rep)):
                L.ip_relleno(i, rep)

    def test_u_ip_2_los_mismos_vectores_estan_en_l3_js(self):
        js = (DIR_ESTRES / "l3.js").read_text(encoding="utf-8")
        for par in ("[0, 1, '100.64.0.1']", "[253, 1, '100.64.0.254']", "[254, 1, '100.64.1.1']",
                    "[0, 2, '100.79.97.3']"):
            self.assertIn(par, js)
        self.assertIn("console.error('CONTROL_IP');", js)

    def test_u_ip_3_una_ip_muestra_que_no_coincide_es_fallo(self):
        bueno = 'msg="IP_MUESTRA i=0 ip=100.64.0.1" source=console\nmsg="IP_MUESTRA i=10000 ip=100.64.39.95" x\n'
        self.assertEqual(L.comprobar_ip_muestras(bueno, 1), [])
        malo = bueno.replace("100.64.39.95", "100.64.39.96")
        self.assertEqual(len(L.comprobar_ip_muestras(malo, 1)), 1)
        # Sin ninguna muestra no se comprueba nada, y CONTROL_IP tambien es fallo.
        self.assertEqual(len(L.comprobar_ip_muestras("", 1)), 1)
        self.assertEqual(len(L.comprobar_ip_muestras("CONTROL_IP\n" + bueno, 1)), 1)

    def cuerpo_de(self, js, nombre):
        inicio = js.index(f"export function {nombre}(")
        fin = js.index("\n}\n", inicio)
        return js[inicio:fin]

    def test_u_ip_4_el_relleno_indexa_con_iteration_in_test(self):
        js = (DIR_ESTRES / "l3.js").read_text(encoding="utf-8")
        cuerpo = self.cuerpo_de(js, "denuncia_relleno")
        self.assertIn("exec.scenario.iterationInTest", cuerpo)
        self.assertNotIn("__ITER", cuerpo)
        self.assertNotIn("iterationInScenario", cuerpo)

    def test_u_ip_5_la_ip_del_legitimo_esta_fuera_de_todo_lo_reservado(self):
        plan = L.plan_ips("l6", 1)
        ip = plan[1]["legitimo_l6"]
        self.assertEqual(ip, ["198.18.0.1"])
        self.assertNotIn(ipaddress.ip_address(ip[0]), ipaddress.ip_network("100.64.0.0/10"))
        self.assertNotIn(ip[0], ("198.19.255.254", "198.19.255.253", "198.19.255.252"))
        self.assertNotIn(ip[0], plan[1]["strict_falsas"])
        self.assertEqual(L.solapes_de_bloques({("global", "strict_falsas"): (130045 - 70, 70), (1, "legitimo_l6"): (0, 1)}),
                         [])
        # Control: el índice 130044, que pareceria libre, si se solapa con strict_falsas.
        self.assertNotEqual(L.solapes_de_bloques({("global", "strict_falsas"): (130045 - 70, 70),
                                                  (1, "x"): (130044, 1)}), [])


class ConciliarOom(unittest.TestCase):
    def grupo(self, intervalos_503, intervalos_0, marcas, tolerancia=2.0):
        return L.conciliar_oom(intervalos_503, intervalos_0, [marcas], tolerancia)["grupos"][0]

    def test_u_l6_1_linea_con_503(self):
        g = self.grupo([(100.0, 100.5)], [], [100.2])
        self.assertEqual((g["con_503"], g["con_0"], g["sin_pareja"]), ([(100.2, (100.0, 100.5))], [], []))

    def test_u_l6_2_linea_con_estado_0_1050(self):
        g = self.grupo([], [(99.0, 100.1, "1050")], [100.2])
        self.assertEqual((g["con_503"], g["con_0"], g["sin_pareja"]), ([], [(100.2, (99.0, 100.1, "1050"))], []))

    def test_u_l6_3_estado_0_fuera_de_e0_no_empareja(self):
        g = self.grupo([], [(99.0, 100.1, "1211")], [100.2])
        self.assertEqual(g["sin_pareja"], [100.2])
        # En C1 eso es FALLA; control: con 1050 no lo es.
        c = L.conciliacion_l6([100.2], 1000.0, 1010.0, None, None, ([], [(99.0, 100.1, "1211")]), None)
        self.assertEqual(len(c["falla"]), 1)
        c = L.conciliacion_l6([100.2], 1000.0, 1010.0, None, None, ([], [(99.0, 100.1, "1050")]), None)
        self.assertEqual(c["falla"], [])

    def test_u_l6_4_uno_a_uno(self):
        g = self.grupo([], [(99.0, 100.5, "1050")], [100.2, 100.3])
        self.assertEqual((len(g["con_0"]), len(g["sin_pareja"])), (1, 1))

    def test_u_l6_5_regresion_de_los_recuentos_de_conciliar_503(self):
        def recuentos(intervalos, marcas):
            r = L.conciliar_oom(intervalos, [], [marcas])
            g = r["grupos"][0]
            return len(g["con_503"]), r["intervalos_sin_usar"], len(g["sin_pareja"])
        self.assertEqual(recuentos([(100.0, 100.5), (200.0, 200.4)], [100.2, 200.2]), (2, 0, 0))
        self.assertEqual(recuentos([(100.0, 100.5), (200.0, 200.4)], [100.2, 150.0]), (1, 1, 1))
        self.assertEqual(recuentos([(100.0, 100.5), (100.1, 100.6)], [100.3]), (1, 1, 0))
        self.assertEqual(recuentos([(100.0, 100.5)], [102.4])[0], 1)
        self.assertEqual(recuentos([(100.0, 100.5)], [103.1])[0], 0)

    def test_u_oom_a_maximo_frente_a_voraz_por_inicio(self):
        g = self.grupo([(0, 10), (1, 3)], [], [2, 8])
        self.assertEqual(sorted(g["con_503"]), [(2, (1, 3)), (8, (0, 10))])
        self.assertEqual(g["sin_pareja"], [])
        self.assertEqual(L.conciliar_503([(0, 10), (1, 3)], [2, 8])["emparejados"], 1)

    def test_u_oom_b_maximo_con_tolerancia(self):
        g = self.grupo([(0, 10), (1, 2)], [], [1.5, 5])
        self.assertEqual(sorted(g["con_503"]), [(1.5, (1, 2)), (5, (0, 10))])
        self.assertEqual(g["sin_pareja"], [])
        self.assertEqual(L.conciliar_503([(0, 10), (1, 2)], [1.5, 5])["emparejados"], 1)

    def test_u_oom_c_un_solo_paso_sobre_503_y_estados_0(self):
        g = self.grupo([(0, 10)], [(0, 3, "1050")], [2, 8])
        self.assertEqual([t for t, _ in g["con_0"]], [2])
        self.assertEqual([t for t, _ in g["con_503"]], [8])
        self.assertEqual(g["sin_pareja"], [])

    def test_u_oom_d_prioridad_de_c1_y_grupos_fuera_de_orden(self):
        r = L.conciliar_oom([(0, 10)], [], [[9.0], [9.5]])["grupos"]
        self.assertEqual(([t for t, _ in r[0]["con_503"]], r[0]["sin_pareja"]), ([9.0], []))
        self.assertEqual(r[1]["sin_pareja"], [9.5])
        with self.assertRaises(ValueError):
            L.conciliar_oom([(0, 10)], [], [[9.5], [9.0]])


class ConciliacionL6(unittest.TestCase):
    def test_u_l6_6_ventana_excluida_y_c3(self):
        lineas = [997.9, 998.0, 1001.9, 1002.1]
        c = L.conciliacion_l6(lineas, 1000.0, 1003.0, None, None, ([], []), None)
        self.assertEqual(len(c["falla"]), 1)
        self.assertIn("997.900", c["falla"][0])
        c = L.conciliacion_l6(lineas[1:], 1000.0, 1003.0, None, None, ([], []), None)
        self.assertEqual((c["falla"], c["sin_conclusion"]), ([], []))
        self.assertEqual((c["n"]["C2"], c["c3"]), (3, 2))
        self.assertIn("C2 3 (", c["texto"])
        self.assertIn("C3 2;", c["texto"])

    def test_u_l6_7_c4b_y_c4c(self):
        c = L.conciliacion_l6([1004.9], 1000.0, 1003.0, None, None, ([], []), None)
        self.assertEqual((c["falla"], c["sin_conclusion"], c["n"]["C4b"]), ([], [], 1))
        c = L.conciliacion_l6([1005.1], 1000.0, 1003.0, None, None, ([], []), None)
        self.assertEqual((c["falla"], len(c["sin_conclusion"])), ([], 1))

    def test_u_l6_8_c5_sin_pareja_es_falla(self):
        c = L.conciliacion_l6([2050.0], 1000.0, 1003.0, 2000.0, 2100.0, ([], []), ([], []))
        self.assertEqual(len(c["falla"]), 1)
        # Control: con su 503 en la fase 2, no.
        c = L.conciliacion_l6([2050.0], 1000.0, 1003.0, 2000.0, 2100.0, ([], []), ([(2049.9, 2050.1)], []))
        self.assertEqual(c["falla"], [])

    def test_u_l6_9_cota_de_30_s_y_cota_por_f1(self):
        t_rp = 1000.0
        c = L.conciliacion_l6([1029.9], t_rp, 1045.0, None, None, ([], []), None)
        self.assertEqual((c["falla"], c["sin_conclusion"], c["n"]["C2"]), ([], [], 1))
        self.assertIn("F1 - T_RP = 45.0", c["texto"])
        c = L.conciliacion_l6([1030.1], t_rp, 1045.0, None, None, ([], []), None)
        self.assertEqual((c["falla"], len(c["sin_conclusion"])), ([], 1))
        c = L.conciliacion_l6([1030.1], t_rp, 1045.0, None, None, ([(1030.0, 1030.2)], []), None)
        self.assertEqual((c["falla"], c["sin_conclusion"]), ([], []))
        # Cota por F1 = 1010.
        c = L.conciliacion_l6([1009.9], t_rp, 1010.0, None, None, ([], []), None)
        self.assertEqual((c["sin_conclusion"], c["n"]["C2"]), ([], 1))
        c = L.conciliacion_l6([1011.9], t_rp, 1010.0, None, None, ([], []), None)
        self.assertEqual((c["sin_conclusion"], c["n"]["C4b"]), ([], 1))
        c = L.conciliacion_l6([1012.1], t_rp, 1010.0, None, None, ([], []), None)
        self.assertEqual(len(c["sin_conclusion"]), 1)


class HumoDeL6(unittest.TestCase):
    def test_u_humo_1_regla_de_los_15_s(self):
        self.assertIsNone(L.regla_cota_humo(1000.0, 1015.0, 1020.0)[0])
        motivo, _ = L.regla_cota_humo(1000.0, 1015.1, 1020.0)
        self.assertIn("revisar la cota de 30 s antes de congelar", motivo)
        motivo, info = L.regla_cota_humo(1000.0, 1010.0, 1040.0)
        self.assertIsNone(motivo)
        self.assertIn("F1 - T_RP = 40.0", info)
        # Modo B': la cifra llega del Trend de resumen.json (D-8), ya calculada.
        for maximo_ms, para in ((1015000, False), (1015100, True)):
            resumen = {"metrics": {"fin_relleno_ms": {"values": {"max": maximo_ms}}}}
            motivo, _ = L.regla_cota_humo(1000.0, L.maximo_trend(resumen, "fin_relleno_ms") / 1000, 1040.0)
            self.assertEqual(motivo is not None, para, maximo_ms)

    def test_d8_trend_fin_relleno_en_l3_js_justo_tras_el_post(self):
        js = (DIR_ESTRES / "l3.js").read_text(encoding="utf-8")
        self.assertIn("const finRelleno = new Trend('fin_relleno_ms');", js)
        self.assertNotIn("Gauge", js)
        inicio = js.index("export function denuncia_relleno(")
        cuerpo = js[inicio:js.index("\n}\n", inicio)]
        post = cuerpo.index("http.post(")
        fin_post = cuerpo.index("});", post)
        anade = cuerpo.index("finRelleno.add(Date.now()")
        self.assertLess(fin_post, anade)
        # Nada entre la vuelta del post y el add.
        self.assertEqual(cuerpo[fin_post + 3:anade].strip(), "")

    def test_d8_comparacion_del_trend_con_el_csv(self):
        self.assertEqual(L.comparar_trend_fin(None, 1795546367123)[0], "PARADA")
        csv_ms = 1795546367123
        # R2: vale con |Trend - CSV| <= 1000 ms en los dos sentidos; se publica con signo.
        for diferencia, vale, texto_signo in ((0, True, "+0 ms"), (-1000, True, "-1000 ms"), (1000, True, "+1000 ms"),
                                              (1001, False, "+1001 ms"), (-1001, False, "-1001 ms")):
            accion, valido, texto = L.comparar_trend_fin(float(csv_ms + diferencia), csv_ms)
            self.assertEqual((accion, valido), (None, vale), diferencia)
            self.assertIn(texto_signo, texto)
            self.assertEqual("NO VALE" in texto, not vale, diferencia)
        self.assertIsNone(L.maximo_trend({"metrics": {}}, "fin_relleno_ms"))
        self.assertEqual(L.maximo_trend({"metrics": {"fin_relleno_ms": {"values": {"max": 5.0}}}}, "fin_relleno_ms"), 5.0)

    def test_u_d4_1_sin_csv_ni_resumen(self):
        accion, texto = L.instrumento_fase1(False, False, humo=False)
        self.assertEqual(accion, "SIN CONCLUSION")
        self.assertIn("fallo del instrumento", texto)
        self.assertEqual(L.instrumento_fase1(False, False, humo=True)[0], "PARADA")
        # Control positivo: plan B con resumen.json y sin k6.csv es evaluable.
        self.assertIsNone(L.instrumento_fase1(False, True, humo=False, plan_b=True)[0])
        self.assertIsNone(L.instrumento_fase1(True, True, humo=False)[0])

    def test_h_gs_es_informacion(self):
        self.assertIn("CORTA", L.hipotesis_hgs(2, 0))
        self.assertIn("RESPETA", L.hipotesis_hgs(0, 3))
        self.assertIn("sin cerrar", L.hipotesis_hgs(0, 0))

    def test_extrapolacion_de_la_memoria_de_k6(self):
        mib = 1048576
        valor, motivo = L.extrapolar_memoria_k6(100 * mib, 1000, 200 * mib, 11000, 200 * mib)
        self.assertIsNone(motivo)
        # Pendiente de 100 MiB por 10 000 peticiones: 200 MiB + 664 000 x 10 240 bytes.
        self.assertAlmostEqual(valor, 200 * mib + 664000 * 10485.76, places=3)
        self.assertIsNotNone(L.extrapolar_memoria_k6(100 * mib, 1000, 200 * mib, 5999, 200 * mib)[1])
        self.assertEqual(L.extrapolar_memoria_k6(300 * mib, 1000, 200 * mib, 11000, 300 * mib), (300 * mib, None))

    def test_override_de_redis_cambia_solo_maxmemory(self):
        original = ["redis-server", "--save", "", "--maxmemory", "64mb", "--maxmemory-policy", "noeviction"]
        self.assertEqual(L.comando_con_maxmemory(original, "4mb"),
                         ["redis-server", "--save", "", "--maxmemory", "4mb", "--maxmemory-policy", "noeviction"])
        with self.assertRaises(L.Parada):
            L.comando_con_maxmemory(["redis-server"], "4mb")
        with self.assertRaises(L.Parada):
            L.comando_con_maxmemory(original + ["--maxmemory", "1mb"], "4mb")
        self.assertEqual(L.yaml_comando_servicio("redis", ["a", ""]), 'services:\n  redis:\n    command:\n      - "a"\n'
                                                                       '      - ""\n')


def datos_l6(**cambios):
    """Una L6 que PASA con H5 CONFIRMADA: inicio del relleno en 0 (T0 en -60),
    primera OOM a 2700, 503 del legítimo a 2750 (fase 1) y 3600 (fase 2), y 30
    respuestas 404 desde 3610 (R = 3610)."""
    legitimo = [{"t": -60.0 + 2 * i, "estado": 404, "ra": None, "fase": 1} for i in range(30)]
    legitimo.append({"t": 2750.0, "estado": 503, "ra": "5", "fase": 1})
    legitimo.append({"t": 3600.0, "estado": 503, "ra": "5", "fase": 2})
    legitimo += [{"t": 3610.0 + 2 * i, "estado": 404, "ra": None, "fase": 2} for i in range(30)]
    salud = [{"t": -60.0 + i, "estado": 200, "fase": 1} for i in range(60)] + [{"t": 3100.0, "estado": 200, "fase": 2}]
    d = {"inicio_relleno": 0.0, "t0": -60.0, "t_rp": 2800.0, "i2": 3000.0, "fin_vigilancia": 4290.0,
         "lineas_oom": [2700.0], "conciliacion": {"falla": [], "sin_conclusion": []}, "legitimo": legitimo,
         "salud": salud, "hueco_s": 25.0, "n500": 0, "relleno": {"n422": 1000, "n": 1000}, "plan_b": None,
         "validez": [], "muertes": []}
    d.update(cambios)
    return d


def legitimo_con(*extra, base=30, desde=None):
    """BASE de `base` respuestas 404 y las respuestas extra (t, estado, ra, fase)."""
    respuestas = [{"t": -60.0 + 2 * i, "estado": 404, "ra": None, "fase": 1} for i in range(base)]
    respuestas += [{"t": t, "estado": e, "ra": ra, "fase": f} for t, e, ra, f in extra]
    if desde is not None:
        respuestas += [{"t": desde + 2 * i, "estado": 404, "ra": None, "fase": 2} for i in range(30)]
    return respuestas


def veredicto(d, globales=()):
    ev = L.evaluar_l6(d)
    return L.veredicto_l6(ev, globales), ev


class EvaluarL6(unittest.TestCase):
    def test_u_l6_10_pasa_y_confirmada(self):
        (v, motivos), ev = veredicto(datos_l6())
        self.assertEqual((v, motivos), ("PASA", []))
        self.assertEqual(ev["h5"][0], "CONFIRMADA")

    def test_u_l6_11_el_503_cuenta_en_cualquiera_de_las_dos_fases(self):
        solo_f2 = legitimo_con((3600.0, 503, "5", 2), desde=3610.0)
        self.assertEqual(veredicto(datos_l6(legitimo=solo_f2))[0][0], "PASA")
        en_c2 = legitimo_con((2801.0, 503, "5", 1), desde=3610.0)
        self.assertEqual(veredicto(datos_l6(legitimo=en_c2))[0][0], "PASA")

    def test_u_l6_12_un_retry_after_4_es_falla_en_cualquier_fase(self):
        self.assertEqual(veredicto(datos_l6(legitimo=legitimo_con((3600.0, 503, "4", 2), desde=3610.0)))[0][0], "FALLA")
        self.assertEqual(veredicto(datos_l6(legitimo=legitimo_con((2750.0, 503, "4", 1), desde=3610.0)))[0][0], "FALLA")
        # Control: con "5", PASA.
        self.assertEqual(veredicto(datos_l6(legitimo=legitimo_con((2750.0, 503, "5", 1), desde=3610.0)))[0][0], "PASA")

    def test_u_l6_13_503_sin_linea_oom_es_sin_conclusion(self):
        (v, motivos), _ = veredicto(datos_l6(lineas_oom=[]))
        self.assertEqual(v, "SIN CONCLUSION")
        self.assertIn("Q3", motivos[0])

    def test_u_l6_14_un_500_o_un_retry_after_mal_es_falla(self):
        self.assertEqual(veredicto(datos_l6(n500=1))[0][0], "FALLA")
        # Con su fila presente: "5 " y "ausente" (sin cabecera) son FALLA.
        for ra in ("5 ", "ausente"):
            self.assertEqual(veredicto(datos_l6(legitimo=legitimo_con((2750.0, 503, ra, 1), desde=3610.0)))[0][0],
                             "FALLA", repr(ra))
        # R1: sin la fila de retry_after_503_s (ra None) es el instrumento: SIN CONCLUSION, nunca FALLA.
        (v, motivos), _ = veredicto(datos_l6(legitimo=legitimo_con((2750.0, 503, None, 1), desde=3610.0)))
        self.assertEqual(v, "SIN CONCLUSION")
        self.assertIn("instrumento del Retry-After", motivos[0])
        # Control positivo: con "5" y su fila, PASA.
        self.assertEqual(veredicto(datos_l6(legitimo=legitimo_con((2750.0, 503, "5", 1), desde=3610.0)))[0][0], "PASA")

    def test_u_l6_15_mas_de_120_s_entre_la_oom_y_el_503_es_informacion(self):
        (v, _), ev = veredicto(datos_l6(legitimo=legitimo_con((2850.0, 503, "5", 1), desde=3610.0)))
        self.assertEqual(v, "PASA")
        self.assertEqual(len(ev["info"]), 1)
        self.assertIn("150 s", ev["info"][0])
        # Control: a 50 s no hay linea.
        self.assertEqual(veredicto(datos_l6())[1]["info"], [])

    def test_u_l6_16_control_del_99_por_ciento_de_422(self):
        self.assertEqual(veredicto(datos_l6(relleno={"n422": 989, "n": 1000}))[0][0], "SIN CONCLUSION")
        self.assertEqual(veredicto(datos_l6(relleno={"n422": 990, "n": 1000}))[0][0], "PASA")

    def test_u_l6_17_no_se_lleno_impide_el_ok(self):
        d = datos_l6(lineas_oom=[], t_rp=None, i2=None, legitimo=legitimo_con(desde=100.0))
        (v, _), ev = veredicto(d)
        self.assertEqual(v, "NO SE LLENO (H5 refutada)")
        self.assertEqual(ev["h5"][0], "REFUTADA")
        lineas = []
        with mock.patch.object(L, "p", lineas.append), mock.patch.dict(L.estado, {"falla": False, "sin_conclusion": False}):
            L.emitir_l6({"ev": ev}, [], False)
            self.assertTrue(L.estado["falla"] or L.estado["sin_conclusion"])
        self.assertTrue(any("NO SE LLENO" in x for x in lineas))

    def test_u_l6_18_la_base_es_el_control_positivo(self):
        con_503 = legitimo_con((2750.0, 503, "5", 1), desde=3610.0)
        con_503[5] = {"t": -50.0, "estado": 503, "ra": "5", "fase": 1}
        self.assertEqual(veredicto(datos_l6(legitimo=con_503))[0][0], "SIN CONCLUSION")
        corta = legitimo_con((2750.0, 503, "5", 1), base=24, desde=3610.0)
        self.assertEqual(veredicto(datos_l6(legitimo=corta))[0][0], "SIN CONCLUSION")
        # Control: 25 respuestas bastan.
        justa = legitimo_con((2750.0, 503, "5", 1), base=25, desde=3610.0)
        self.assertEqual(veredicto(datos_l6(legitimo=justa))[0][0], "PASA")

    def test_u_l6_19_h5_por_r_y_por_el_llenado(self):
        self.assertEqual(veredicto(datos_l6(legitimo=legitimo_con((2750.0, 503, "5", 1), desde=3597.0)))[1]["h5"][0],
                         "SIN CONCLUSION")
        tarde = legitimo_con((2750.0, 503, "5", 1), (4199.0, 503, "5", 2), desde=4201.0)
        self.assertEqual(veredicto(datos_l6(legitimo=tarde))[1]["h5"][0], "REFUTADA")
        lleno_tarde = datos_l6(lineas_oom=[3700.0], legitimo=legitimo_con((3750.0, 503, "5", 1), desde=3800.0))
        self.assertEqual(veredicto(lleno_tarde)[1]["h5"][0], "REFUTADA")
        # Control: R = 3598 y R = 4200 son los bordes admitidos.
        for r in (3598.0, 4200.0):
            d = datos_l6(legitimo=legitimo_con((2750.0, 503, "5", 1), desde=r))
            self.assertEqual(veredicto(d)[1]["h5"][0], "CONFIRMADA", r)

    def test_u_l6_20_fase_2_tarde(self):
        self.assertEqual(veredicto(datos_l6(i2=3477.9))[1]["h5"][0], "CONFIRMADA")
        (v, _), ev = veredicto(datos_l6(i2=3478.0))
        self.assertEqual((v, ev["h5"][0]), ("PASA", "SIN CONCLUSION"))
        tarde_y_lleno = datos_l6(i2=3478.0, lineas_oom=[3700.0],
                                 legitimo=legitimo_con((3750.0, 503, "5", 1), desde=3800.0))
        self.assertEqual(veredicto(tarde_y_lleno)[1]["h5"][0], "REFUTADA")

    def test_u_l6_21_salud_l6_no_cambia_l6(self):
        salud = datos_l6()["salud"] + [{"t": 3200.0, "estado": 503, "fase": 2}]
        (v, _), ev = veredicto(datos_l6(salud=salud))
        self.assertEqual(v, "PASA")
        self.assertIn("503 en 3200.000 (fase 2)", ev["salud_l6"])
        self.assertIn("hueco sin sondas entre fases de 25.0 s", ev["salud_l6"])
        # Control: sin fallos, todas 200.
        self.assertIn("/salud 200 en 61 de 61 sondas", veredicto(datos_l6())[1]["salud_l6"])

    def test_u_l6_22_una_repeticion_nunca_da_ok(self):
        self.assertIn("1 de 3 repeticiones", L.linea_l6("PASA", []))
        (_, _), ev = veredicto(datos_l6())
        lineas = []
        with mock.patch.object(L, "p", lineas.append), mock.patch.dict(L.estado, {"falla": False, "sin_conclusion": False}):
            v, _ = L.emitir_l6({"ev": ev}, [], False)
            no_ok = L.estado["falla"] or L.estado["sin_conclusion"]
        self.assertEqual(v, "PASA")
        self.assertTrue(no_ok)
        self.assertTrue(any(x.startswith("PASA") and "1 de 3 repeticiones" in x for x in lineas))

    def test_u_l6_23_patron_oom(self):
        self.assertIsNotNone(L.PATRON_OOM.search(
            "WARNING canario: EVENTO limitador_no_disponible: OutOfMemoryError causa=otra espera=<0.25"))
        self.assertIsNotNone(L.PATRON_OOM.search(
            "EVENTO limitador_no_disponible: OutOfMemoryError causa=otra espera=>0.5"))
        self.assertIsNone(L.PATRON_OOM.search(
            "EVENTO limitador_no_disponible: OutOfMemoryError causa=conexion espera=<0.25"))
        self.assertIsNone(L.PATRON_OOM.search(
            "EVENTO limitador_no_disponible: ResponseError causa=otra espera=<0.25"))

    def test_u_l6_24_lanzar_no_importa_la_app(self):
        texto = (DIR_ESTRES / "lanzar.py").read_text(encoding="utf-8")
        self.assertNotIn("REINTENTAR_TRAS", texto)
        self.assertNotIn("from app", texto)

    def test_validez_global_gana_a_pasa_y_la_muerte_a_todo(self):
        self.assertEqual(veredicto(datos_l6(), [L.fallo("anti-fuga")])[0][0], "SIN CONCLUSION")
        self.assertEqual(veredicto(datos_l6(muertes=["FALLA"]), [L.fallo("x")])[0][0], "FALLA")
        self.assertEqual(veredicto(datos_l6(conciliacion={"falla": [], "sin_conclusion": ["C4c"]}))[0][0],
                         "SIN CONCLUSION")
        (v, motivos), _ = veredicto(datos_l6(conciliacion={"falla": ["C1 sin pareja"], "sin_conclusion": []}))
        self.assertEqual((v, motivos), ("FALLA", ["C1 sin pareja"]))


class FaseDosYPlazos(unittest.TestCase):
    def test_u_f2_1_fin_de_la_fase_2_y_estimacion(self):
        self.assertEqual(L.fin_fase2(0, 3000), 4290)
        self.assertEqual(L.fin_fase2(0, 3990), 4290)
        self.assertEqual(L.fin_fase2(0, 4100), 4400)
        self.assertEqual(L.estimar_repeticion_s("l6"), 6000)

    def flujo_l6(self, padre, espera):
        ej = types.SimpleNamespace(eventos=types.SimpleNamespace(copia=lambda: []), salida=None,
                                   plan_ips={1: {"legitimo_l6": ["198.18.0.1"], "strict_falsas": []}},
                                   ids={}, ids_empresas=[], mantenimientos=[])

        class Corte(Exception):
            pass
        padre.hora.side_effect = [1795546367.0, 1795546380.0, 1795546390.0]
        if isinstance(espera, Exception):
            padre.espera.side_effect = espera
        else:
            padre.espera.return_value = espera
        padre.controles.side_effect = Corte()
        padre.alta.return_value = "b" * 32
        padre.vigilancia.return_value = {"contexto": {}, "lector": None, "stats_ruta": None}
        with tempfile.TemporaryDirectory() as d:
            ej.salida = pathlib.Path(d)
            with mock.patch.object(L, "hora_motor_ahora", padre.hora), \
                    mock.patch.object(L, "espera_por_medianoche", padre.espera), \
                    mock.patch.object(L.time, "sleep", padre.sleep), \
                    mock.patch.object(L, "preparar_repeticion", padre.preparar), \
                    mock.patch.object(L, "alta_empresa", padre.alta), \
                    mock.patch.object(L, "abrir_vigilancia", padre.vigilancia), \
                    mock.patch.object(L, "controles_configuracion", padre.controles), \
                    mock.patch.object(L, "guardar_eventos", padre.guardar), \
                    mock.patch.object(L, "p", lambda *a: None):
                try:
                    L.ejecutar_repeticion_l6(ej, 1)
                except Corte:
                    return "corte"
                except L.Parada:
                    return "parada"
        return "sin excepcion"

    def test_u_l6_25_la_medianoche_se_comprueba_en_el_flujo_de_l6(self):
        padre = mock.Mock()
        self.assertEqual(self.flujo_l6(padre, 0.0), "corte")
        padre.espera.assert_called_once_with(1795546367.0, 6000)
        nombres = [c[0] for c in padre.mock_calls]
        self.assertLess(nombres.index("espera"), nombres.index("controles"))
        padre.sleep.assert_not_called()
        # Con espera, duerme y vuelve a tomar t_ini despues.
        padre = mock.Mock()
        self.assertEqual(self.flujo_l6(padre, 12.0), "corte")
        padre.sleep.assert_called_once_with(12.0)
        nombres = [c[0] for c in padre.mock_calls]
        self.assertEqual(nombres[:4], ["hora", "espera", "sleep", "hora"])
        # Control positivo: la PARADA de espera_por_medianoche corta antes de los controles.
        padre = mock.Mock()
        self.assertEqual(self.flujo_l6(padre, L.Parada("cruza")), "parada")
        padre.controles.assert_not_called()

    def test_u_n4_1_la_fase_2_no_llama_a_los_controles(self):
        ids = {"api": "a" * 64}
        k6 = {"registro": "T0_MS=1795546367000\n", "codigo": 0, "k6_id": "d" * 64}
        llamadas = []
        with tempfile.TemporaryDirectory() as d:
            ej = types.SimpleNamespace(datos=pathlib.Path(d), id_a=None, id_b="b" * 32, contrasena="Estres-xxxxxxxxxxxx",
                                       texto_humo="h")
            salida = pathlib.Path(d)
            with mock.patch.object(L, "controles_configuracion", side_effect=AssertionError("controles")) as ctl, \
                    mock.patch.object(L, "ids_servicios", lambda: dict(ids)), \
                    mock.patch.object(L, "hora_motor_ahora", lambda: 1000.0), \
                    mock.patch.object(L, "ejecutar_k6", lambda *a: llamadas.append(a) or k6), \
                    mock.patch.object(L, "p", lambda *a: None):
                f2 = L.ejecutar_fase2_l6(ej, {}, 1, {"legitimo_l6": ["198.18.0.1"]}, salida, 0.0, False, ids)
                ctl.assert_not_called()
                # Control positivo: ids distintos entre fases es PARADA.
                with self.assertRaises(L.Parada):
                    L.ejecutar_fase2_l6(ej, {}, 1, {"legitimo_l6": ["198.18.0.1"]}, salida, 0.0, False, {"api": "x"})
        self.assertEqual(len(llamadas), 1)
        # Fin en inicio_relleno + 4290 = 4290; empieza en 1000: 3290 s.
        self.assertEqual((f2["duracion_s"], llamadas[0][4]), (3290, 3290))
        self.assertTrue(f2["codigo_ok"])


class PlanB(unittest.TestCase):
    def test_u_pb_1_recuento(self):
        lineas = [900.0 + i for i in range(10)]
        self.assertFalse(L.oraculo_recuento_plan_b(lineas, 1000.0, 8, {"1050": 2})[0])
        self.assertTrue(L.oraculo_recuento_plan_b(lineas + [950.0], 1000.0, 8, {"1050": 2})[0])

    def test_u_pb_2_solo_1050_cuenta_en_n0(self):
        lineas = [900.0 + i for i in range(10)]
        falla, texto = L.oraculo_recuento_plan_b(lineas, 1000.0, 8, {"1211": 2})
        self.assertTrue(falla)
        self.assertIn("N_0 0", texto)

    def test_u_pb_3_la_ventana_c2_no_entra_en_n_oom(self):
        lineas = [900.0 + i for i in range(10)] + [998.0, 1001.0, 1015.0, 1030.0]
        falla, texto = L.oraculo_recuento_plan_b(lineas, 1000.0, 8, {"1050": 2})
        self.assertFalse(falla)
        self.assertIn("N_OOM 10", texto)

    def test_u_pb_4_lineas_legitimo_y_r(self):
        self.assertEqual(L.parsear_legitimo("LEGITIMO t=1795546367000 estado=503 ra=5"), (1795546367.0, 503, "5"))
        self.assertEqual(L.parsear_legitimo('msg="LEGITIMO t=1795546367000 estado=404 ra=" x'),
                         (1795546367.0, 404, None))
        self.assertIsNone(L.parsear_legitimo("otra cosa"))
        respuestas = [(100.0, 503)] + [(101.0 + i, 404) for i in range(29)] + [(150.0, 503)]
        respuestas += [(200.0 + i, 404) for i in range(30)]
        self.assertEqual(L.calcular_r(respuestas), 200.0)
        # Control: sin el segundo 503, la primera racha ya tiene 30 y R = 101.
        self.assertEqual(L.calcular_r(respuestas[:30] + [(140.0, 404)]), 101.0)

    def test_u_pb_5_completitud_de_las_lineas_legitimo(self):
        incompleto = {"falla_recuento": None, "legitimo_completo": L.legitimo_completo(2249, 2250)}
        (v, _), ev = veredicto(datos_l6(plan_b=incompleto))
        self.assertEqual((v, ev["h5"][0]), ("PASA", "SIN CONCLUSION"))
        en_f2 = legitimo_con((3600.0, 503, "5", 2), desde=3610.0)
        self.assertEqual(veredicto(datos_l6(plan_b=incompleto, legitimo=en_f2))[1]["h5"][0], "CONFIRMADA")
        completo = {"falla_recuento": None, "legitimo_completo": L.legitimo_completo(2250, 2250)}
        self.assertEqual(veredicto(datos_l6(plan_b=completo))[1]["h5"][0], "CONFIRMADA")
        # Y el recuento del plan B da FALLA.
        falla = {"falla_recuento": "N_OOM 11, N_503 8, N_0 2", "legitimo_completo": True}
        self.assertEqual(veredicto(datos_l6(plan_b=falla))[0][0], "FALLA")


class CodigosDeK6EnL6(unittest.TestCase):
    def test_u_k6_1_codigos_validos_de_la_fase_1(self):
        self.assertEqual(L.validez_codigo_fase1(0, [])[:2], (True, None))
        self.assertEqual(L.validez_codigo_fase1(108, [1000.5])[:2], (True, 1000.5))
        valido, t_rp, texto = L.validez_codigo_fase1(108, L.marcas_relleno_parado(
            'msg="RELLENO_PARADO t=1000700"\nmsg="RELLENO_PARADO t=1000500"\nmsg="RELLENO_PARADO t=1000900"\n'))
        self.assertEqual((valido, t_rp), (True, 1000.5))
        self.assertIn("3 lineas RELLENO_PARADO", texto)

    def test_u_k6_2_codigos_no_validos_de_la_fase_1(self):
        for codigo, marcas in ((108, []), (0, [1000.0]), (105, []), (137, []), (1, []), (None, []), (None, [1000.0])):
            self.assertFalse(L.validez_codigo_fase1(codigo, marcas)[0], (codigo, marcas))

    def test_u_k6_3_la_fase_2_solo_vale_con_0(self):
        self.assertTrue(L.validez_codigo_fase2(0)[0])
        self.assertFalse(L.validez_codigo_fase2(108)[0])
        self.assertFalse(L.validez_codigo_fase2(None)[0])

    def test_u_k6_4_validez_generador_con_codigos_validos(self):
        k6 = {"codigo": 108, "oom": False, "sin_conclusion": [], "registro": "T0_MS=1795342200123\n", "desfase": 0.0,
              "motivo_desfase": None}
        csv_ = {"filas": [{"proto": "HTTP/1.1", "estado": 404}], "descartes": {}, "ilegibles": 0}
        cpu = {"k6": {"maxima": 100.0}}
        self.assertEqual(L.validez_generador(k6, 1795342200.1, csv_, set(), cpu, codigos_validos=(0, 108)), [])
        self.assertEqual(len(L.validez_generador(k6, 1795342200.1, csv_, set(), cpu)), 1)
        self.assertEqual(len(L.validez_generador({**k6, "codigo": None}, 1795342200.1, csv_, set(), cpu,
                                                 codigos_validos=(0, 108))), 1)


class MantenimientoDelAborto(unittest.TestCase):
    class Eventos:
        def __init__(self, eventos, aparece=True):
            self.eventos, self.aparece = eventos, aparece

        def esperar(self, predicado, plazo):
            return self.aparece and any(predicado(e) for e in self.eventos)

        def copia(self):
            return list(self.eventos)

    def test_u_py3_1_hasta_es_el_destroy_y_finito(self):
        eventos = self.Eventos([ev("die", ID_K6, 1010.0, clase="k6", codigo="108"),
                                ev("destroy", ID_K6, 1050.0, clase="k6")])
        m, fallos = L.mantenimiento_aborto(eventos, ID_K6, 1000.0, lambda: 9999.0)
        self.assertEqual((m["hasta"], m["desde"], m["ids"], fallos), (1050.0, 1000.0, frozenset([ID_K6]), []))
        self.assertTrue(math.isfinite(m["hasta"]))
        ventanas = L.construir_ventanas([], [m])
        self.assertEqual(ventanas[0]["hasta"], 1050.0)

    def test_u_py3_2_el_die_108_registrado_no_es_otro_que_muere(self):
        die = ev("die", ID_K6, 1010.0, clase="k6", codigo="108")
        m = {"ids": frozenset([ID_K6]), "desde": 1000.0, "hasta": 1050.0, "motivo": "aborto"}
        self.assertFalse(L.otro_murio([die], ID_API, 1005.0, 1015.0, [m]))
        self.assertTrue(L.otro_murio([die], ID_API, 1005.0, 1015.0, []))

    def test_u_py3_3_sin_destroy_sin_conclusion_y_hasta_finito(self):
        eventos = self.Eventos([ev("die", ID_K6, 1010.0, clase="k6", codigo="108")], aparece=False)
        m, fallos = L.mantenimiento_aborto(eventos, ID_K6, 1000.0, lambda: 1060.0)
        self.assertEqual(m["hasta"], 1060.0)
        self.assertEqual(len(fallos), 1)
        self.assertIn("destroy", fallos[0]["motivo"])


class CpuSumadaDeK6(unittest.TestCase):
    def test_la_cpu_de_k6_se_suma_por_instante(self):
        dos = [(100.2, "canario_estres_k6_a", 200.0), (100.7, "canario_estres_k6_b", 150.0)]
        self.assertEqual(L.sumar_cpu_por_instante(dos), 350.0)
        self.assertGreater(L.sumar_cpu_por_instante(dos), L.UMBRAL_CPU_K6)
        uno = [(100.2, "canario_estres_k6_a", 300.0)]
        self.assertEqual(L.sumar_cpu_por_instante(uno), 300.0)
        self.assertLessEqual(L.sumar_cpu_por_instante(uno), 320.0)
        # Dos muestras del mismo contenedor en el mismo segundo no se suman.
        self.assertEqual(L.sumar_cpu_por_instante([(100.1, "a", 200.0), (100.9, "a", 210.0)]), 210.0)
        self.assertIsNone(L.sumar_cpu_por_instante([]))


CABECERA_L6 = CABECERA_L3B


class AgregadorDelRelleno(unittest.TestCase):
    def escribir(self, d, filas):
        ruta = pathlib.Path(d) / "k6.csv"
        ruta.write_text(CABECERA_L6 + "\n" + "\n".join(filas) + "\n", encoding="utf-8", newline="\n")
        return ruta

    def test_el_relleno_no_se_guarda_como_filas_y_se_agrega(self):
        filas = [
            "http_req_duration,1000100,50.0,1422,false,POST,denuncia_relleno,HTTP/1.1,denuncia_relleno,422,ruta=denuncia,",
            "fin_relleno_ms,1000101,1000101.000000,,,,denuncia_relleno,,denuncia_relleno,,ruta=denuncia,",
            "http_req_duration,1000300,100.0,1503,false,POST,denuncia_relleno,HTTP/1.1,denuncia_relleno,503,ruta=denuncia,",
            "http_req_duration,1000400,15000.0,1050,false,POST,denuncia_relleno,,denuncia_relleno,0,ruta=denuncia,",
            "http_req_duration,1000200,20.0,1404,false,POST,legitimo,HTTP/1.1,legitimo,404,ruta=seguimiento,",
            "http_req_duration,1000350,20.0,1503,false,POST,legitimo,HTTP/1.1,legitimo,503,ruta=seguimiento,",
            "retry_after_503_s,1000351,5.000000,,,,legitimo,,legitimo,,ra=5&ruta=seguimiento,",
        ]
        with tempfile.TemporaryDirectory() as d:
            agg = L.AgregadorRelleno(t_rp=1000.39, t_oom=1000.25, f1=1001.0, instantes=[1000.2])
            datos = L.leer_csv_fases(self.escribir(d, filas), desviar=agg.desviar)
        self.assertEqual([f["escenario"] for f in datos["filas"]], ["legitimo", "legitimo"])
        self.assertEqual(datos["ilegibles"], 0)
        self.assertEqual((agg.n, dict(agg.estados)), (3, {422: 1, 503: 1, 0: 1}))
        self.assertEqual((agg.n_antes_oom, agg.n422_antes_oom), (1, 1))
        self.assertEqual((agg.max_fin_ms, agg.max_trend_csv), (1000400, 1000101.0))
        self.assertEqual([(round(a, 3), round(b, 3)) for a, b in agg.int503], [(1000.2, 1000.3)])
        self.assertEqual(dict(agg.cortados0), {"1050": 1})
        self.assertEqual(agg.n_hasta, [1])
        respuestas, sobran = L.legitimo_con_ra(datos["filas"], datos["retry_503"], 1)
        self.assertEqual([(x["estado"], x["ra"]) for x in respuestas], [(404, None), (503, "5")])
        self.assertEqual(sobran, 0)
        # Un 503 sin su fila de retry_after_503_s queda sin cabecera (ra None).
        sin_ra, _ = L.legitimo_con_ra(datos["filas"], [], 1)
        self.assertEqual(sin_ra[1]["ra"], None)


class L7InundacionDeSalud(unittest.TestCase):
    def test_fases_y_escenario_de_la_inundacion(self):
        self.assertEqual([f["hasta_s"] for f in L.fases_de("l7")], [30, 150, 270, 390])
        plan = L.plan_ips("l7", 3)
        escenarios = L.escenarios_l7(L.tasas_de(0.0196), plan[1])
        inundacion = next(e for e in escenarios if e["nombre"] == "inundacion_salud")
        self.assertEqual({k: inundacion[k] for k in ("rate", "time_unit_s", "duracion_s", "inicio_s", "vus")},
                         {"rate": 15306, "time_unit_s": 100, "duracion_s": 120, "inicio_s": 150, "vus": 600})
        self.assertEqual((inundacion["funcion"], len(inundacion["ips"])), ("salud_get", 1))

    def test_ips_de_l7_sin_solapes(self):
        plan = L.plan_ips("l7", 3)
        for rep in (1, 2, 3):
            self.assertEqual([len(plan[rep][r]) for r in ("denuncia", "seguimiento", "web_seguimiento")], [293, 8, 8])
        todas = [ip for rep in (1, 2, 3) for r in ("denuncia", "seguimiento", "web_seguimiento", "inundacion")
                 for ip in plan[rep][r]]
        self.assertEqual(len(todas), len(set(todas)))

    def test_control_de_que_la_inundacion_existe(self):
        self.assertFalse(L.control_inundacion(17448))
        self.assertTrue(L.control_inundacion(17449))

    def test_tasa_de_salud_congelada(self):
        self.assertEqual(L.TASA_SALUD_CONGELADA, 153.06)
        self.assertEqual(L.tasas_de(0.0196)["inundacion"], 153.06)

    def test_h4(self):
        self.assertEqual(L.evaluar_h4(False, 89.9), "NO EVALUADA")
        self.assertEqual(L.evaluar_h4(True, 89.9), "REFUTA")
        self.assertEqual(L.evaluar_h4(False, 90.0), "REFUTA")
        self.assertEqual(L.evaluar_h4(True, 90.0), "CONFIRMA")
        self.assertEqual(L.evaluar_h4(True, None), "SIN CONCLUSION")

    def test_l7_va_por_las_fases_y_su_estimacion(self):
        self.assertIn('"l7": fases_de("l7")', inspect.getsource(L.ejecutar_repeticion_fases))
        # 390 + 30 de reposo + 15 + 240 de sobrecoste, sin espera ni sandwich.
        self.assertEqual((L.estimar_repeticion_s("l7", 1), L.estimar_repeticion_s("l7", 2)), (675, 675))

    def test_partes_nuevas_y_las_actuales_intactas(self):
        self.assertEqual(L.PARTES["l2"], ("l2",))
        self.assertEqual(L.PARTES["pico"], ("pico",))
        self.assertEqual(L.PARTES["l3"], ("l3",))
        self.assertEqual(L.PARTES["l3b"], ("l3b-a", "l3b-b"))
        self.assertEqual((L.PARTES["l5"], L.PARTES["l6"], L.PARTES["l7"]),
                         (("l5",), ("l6", "salud_l6", "h5"), ("l7", "h4")))
        self.assertEqual(list(inspect.signature(L.ejecutar_k6).parameters),
                         ["contexto", "nombre", "script", "args_red", "duracion_s", "salida"])

    def test_agregado_de_l7_con_el_control_de_la_inundacion(self):
        def repeticion(n, ok):
            detalle = {"victimas": {r: {"base": {"p95_ms": 50}, "carga": {"peticiones": 600, "p95_ms": 60,
                                                                          "tasa_errores": 0.0},
                                        "descartes_aviso": 0} for r in L.SLO_VICTIMAS_MS},
                       "inundacion_200": 18000 if ok else 100, "inundacion_ok": ok, "cpu_api": 95.0}
            return {"modo": "l7", "repeticion": n, "muertes": [], "reinicios": 0, "comun": [],
                    "partes": {"l7": {"resultado": "PASA", "validez": [], "control_ataque": ok, "detalle": detalle}},
                    "veredictos": {"l7": ("PASA", [])}}
        lineas = []
        with mock.patch.object(L, "p", lineas.append):
            finales = L.agregar_fases("l7", [repeticion(i, True) for i in (1, 2, 3)], 3)
            self.assertEqual(finales, {"l7": ("PASA", [])})
            self.assertTrue(any("h4 (informacion): REFUTA" in x for x in lineas))
            # Una repeticion sin inundacion rebaja el PASA.
            rebajado = L.agregar_fases("l7", [repeticion(1, False), repeticion(2, True), repeticion(3, True)], 3)
        self.assertEqual(rebajado["l7"][0], "SIN CONCLUSION")


class EscenariosYArranqueDeL6(unittest.TestCase):
    def test_escenarios_de_la_fase_1(self):
        esc = {e["nombre"]: e for e in L.escenarios_l6_fase1({"legitimo_l6": ["198.18.0.1"]})}
        campos = ("rate", "time_unit_s", "duracion_s", "inicio_s", "vus")
        self.assertEqual({k: esc["denuncia_relleno"][k] for k in campos},
                         {"rate": 150, "time_unit_s": 1, "duracion_s": 4500, "inicio_s": 60, "vus": 600})
        self.assertEqual({k: esc["legitimo"][k] for k in campos},
                         {"rate": 50, "time_unit_s": 100, "duracion_s": 4560, "inicio_s": 0, "vus": 15})
        self.assertNotIn("ips", esc["denuncia_relleno"])
        self.assertEqual(esc["legitimo"]["ips"], ["198.18.0.1"])
        self.assertEqual(sorted(esc), ["denuncia_relleno", "legitimo", "salud_get", "sonda_salud"])
        self.assertEqual(L.holgura_insuficiente(list(esc.values())), [])
        self.assertLessEqual(L.presupuesto_k6_mib(list(esc.values())), 4096)
        humo = {e["nombre"]: e for e in L.escenarios_l6_fase1({"legitimo_l6": ["198.18.0.1"]}, humo=True)}
        self.assertEqual(humo["denuncia_relleno"]["duracion_s"], 600)

    def test_escenarios_de_la_fase_2(self):
        real = [e["nombre"] for e in L.escenarios_l6_fase2({"legitimo_l6": ["198.18.0.1"]}, 812)]
        self.assertEqual(real, ["legitimo", "salud_get", "sonda_salud"])
        humo = [e["nombre"] for e in L.escenarios_l6_fase2({"legitimo_l6": ["198.18.0.1"]}, 30, humo=True)]
        self.assertEqual(humo, ["legitimo", "salud_get"])

    def test_l3_js_acepta_l6_y_l7_y_el_relleno_se_para_con_cinco_503(self):
        js = (DIR_ESTRES / "l3.js").read_text(encoding="utf-8")
        self.assertIn("['l3', 'l3b', 'l6', 'l7'].includes(datos.modo)", js)
        for funcion in ("salud_get", "denuncia_relleno", "legitimo"):
            self.assertIn(f"export function {funcion}(", js)
        inicio = js.index("export function denuncia_relleno(")
        cuerpo = js[inicio:js.index("\n}\n", inicio)]
        self.assertIn("respuesta.headers['Retry-After'] === '5'", cuerpo)
        self.assertIn("rachaRelleno >= 5", cuerpo)
        self.assertIn("console.log(`RELLENO_PARADO t=${Date.now()}`);", cuerpo)
        self.assertIn("exec.test.abort(", cuerpo)
        self.assertIn("if (i % 10000 === 0)", cuerpo)
        self.assertIn("const retryAfter503 = new Trend('retry_after_503_s');", js)

    def test_ips_de_l5(self):
        plan = L.plan_ips("l5", 3)
        self.assertEqual([len(plan[1]["l5"]), len(plan[1]["l5_otra"])], [1, 1])
        self.assertNotEqual(plan[1]["l5"], plan[1]["l5_otra"])
        self.assertNotEqual(plan[1]["l5"], plan[2]["l5"])

    def test_humo_sin_l6_es_parada(self):
        lineas = []

        class Fin(Exception):
            pass

        def fin():
            raise Fin()
        with mock.patch.object(sys, "argv", ["lanzar.py", "--l5", "--humo"]), mock.patch.object(L, "p", lineas.append), \
                mock.patch.object(L, "terminar_con_parada", fin):
            with self.assertRaises(Fin):
                L.main()
        self.assertIn("PARADA: --humo solo vale con --l6", lineas)

    def test_l6_con_mas_de_una_repeticion_es_parada(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(L, "p", lambda *a: None), self.assertRaises(L.Parada):
                L.ejecutar_modo("l6", None, pathlib.Path(d), pathlib.Path(d), [0], [1], 3)

    def test_override_de_redis_compara_con_lo_que_resuelve_compose(self):
        original = ["redis-server", "--save", "", "--maxmemory", "64mb", "--maxmemory-policy", "noeviction"]
        humo = ["redis-server", "--save", "", "--maxmemory", "4mb", "--maxmemory-policy", "noeviction"]

        def config(*comandos):
            respuestas = iter(L.R(0, json.dumps({"services": {"redis": {"command": c}}}), "") for c in comandos)
            return lambda *a, **k: next(respuestas)
        with tempfile.TemporaryDirectory() as d, mock.patch.object(L, "BASE", list(L.BASE)), \
                mock.patch.object(L, "p", lambda *a: None):
            with mock.patch.object(L, "dc", config(original, humo)):
                L.preparar_override_redis(pathlib.Path(d), "4mb")
            texto = (pathlib.Path(d) / "redis_humo.yml").read_text(encoding="utf-8")
            self.assertIn('      - "4mb"\n', texto)
            # Si compose resuelve otra cosa (algo mas que --maxmemory), PARADA.
            with mock.patch.object(L, "dc", config(original, humo + ["--loglevel", "debug"])):
                with self.assertRaises(L.Parada):
                    L.preparar_override_redis(pathlib.Path(d), "4mb")

    def test_lineas_despues_de_la_fase_2(self):
        # Hasta 2 s despues del fin de la fase 2, informacion; despues, SIN CONCLUSION.
        c = L.conciliacion_l6([2101.9], 1000.0, 1003.0, 2000.0, 2100.0, ([], []), ([], []))
        self.assertEqual((c["falla"], c["sin_conclusion"], c["n"]["C5b"]), ([], [], 1))
        c = L.conciliacion_l6([2102.1], 1000.0, 1003.0, 2000.0, 2100.0, ([], []), ([], []))
        self.assertEqual((c["falla"], len(c["sin_conclusion"])), ([], 1))


class D2(unittest.TestCase):
    """--d2 (plan del bloque 1, v4, §2, A0): solo lo puro del lanzador. La
    tabla de decisión se prueba en test_diag_hilos.py."""

    FUENTE = pathlib.Path("C:/repo con espacios/tests/estres/diag_hilos.py")
    API = {"image": "canario_estres-api", "command": ["--host", "10.88.0.4", "--proxy-headers",
                                                      "--forwarded-allow-ips", "10.88.0.2"],
           "read_only": True, "cap_drop": ["ALL"], "pids_limit": 64, "mem_limit": "268435456"}

    def con_override(self, **cambios):
        despues = {**self.API, "entrypoint": ["python"], "command": ["-I", "-B", "-u", "/diag/diag_hilos.py"],
                   "volumes": [{"type": "bind", "source": str(self.FUENTE), "target": "/diag/diag_hilos.py",
                                "read_only": True, "bind": {"create_host_path": True}}]}
        despues.update(cambios)
        return despues

    def test_motivo_modo(self):
        self.assertIsNone(L.motivo_modo_d2("l2", 1))
        self.assertIn("una sola repeticion", L.motivo_modo_d2("l2", 3))
        self.assertIn("solo mide la carga de L2", L.motivo_modo_d2("l3", 1))

    def test_ejecutar_modo_d2_con_tres_repeticiones_es_parada_antes_de_docker(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(L, "p", lambda *a: None), \
                mock.patch.object(L, "ejecutar", side_effect=AssertionError("no debe tocar Docker")):
            with self.assertRaises(L.Parada):
                L.ejecutar_modo("l2", 0.0196, pathlib.Path(d), pathlib.Path(d), [0], [1], 3, d2=True)

    def test_main_d2_con_repeticiones_2_es_parada(self):
        lineas = []

        class Fin(Exception):
            pass

        def fin():
            raise Fin()
        with mock.patch.object(sys, "argv", ["lanzar.py", "--d2", "--t", "0.0196", "--repeticiones", "2"]), \
                mock.patch.object(L, "p", lineas.append), mock.patch.object(L, "terminar_con_parada", fin):
            with self.assertRaises(Fin):
                L.main()
        self.assertIn("PARADA: --d2 se mide con una sola repeticion (--repeticiones 2)", lineas)

    def test_yaml_del_override(self):
        texto = L.yaml_override_d2(pathlib.Path("C:/a $b/diag_hilos.py"))
        self.assertEqual(texto.splitlines()[:4], ["services:", "  api:", '    entrypoint: ["python"]',
                                                  '    command: ["-I", "-B", "-u", "/diag/diag_hilos.py"]'])
        self.assertIn('        target: "/diag/diag_hilos.py"\n', texto)
        self.assertIn("        read_only: true\n", texto)
        self.assertIn("$$b", texto)  # compose no interpola el $ de la ruta
        self.assertNotIn("compose.produccion", texto)

    def test_diferencias_override_control_positivo(self):
        self.assertEqual(L.diferencias_override_d2(self.API, self.con_override(), self.FUENTE), [])

    def test_diferencias_override_detecta_lo_que_no_toca(self):
        for cambios, texto in (({"pids_limit": 128}, "pids_limit cambia"),
                               ({"read_only": False}, "read_only cambia"),
                               ({"entrypoint": ["uvicorn"]}, "entrypoint"),
                               ({"command": ["-u", "/diag/diag_hilos.py"]}, "command"),
                               ({"volumes": []}, "montaje"),
                               ({"volumes": [{"type": "bind", "source": str(self.FUENTE),
                                              "target": "/diag/diag_hilos.py", "read_only": False}]}, "montaje"),
                               ({"volumes": [{"type": "bind", "source": "C:/otro/diag_hilos.py",
                                              "target": "/diag/diag_hilos.py", "read_only": True}]}, "montaje")):
            with self.subTest(cambios=cambios):
                dif = L.diferencias_override_d2(self.API, self.con_override(**cambios), self.FUENTE)
                self.assertTrue(any(texto in d for d in dif), dif)

    def test_preparar_override_compara_con_lo_que_resuelve_compose(self):
        def config(*servicios):
            respuestas = iter(L.R(0, json.dumps({"services": {"api": s}}), "") for s in servicios)
            return lambda *a, **k: next(respuestas)
        with tempfile.TemporaryDirectory() as d, mock.patch.object(L, "BASE", list(L.BASE)), \
                mock.patch.object(L, "p", lambda *a: None), mock.patch.object(L, "DIAG_HILOS", self.FUENTE), \
                mock.patch.object(pathlib.Path, "is_file", lambda self: True):
            with mock.patch.object(L, "dc", config(self.API, self.con_override())):
                L.preparar_override_d2(pathlib.Path(d))
            self.assertEqual(L.BASE[-2:], ["-f", str(pathlib.Path(d) / "d2_api.yml")])
            with mock.patch.object(L, "dc", config(self.API, self.con_override(mem_limit="1g"))):
                with self.assertRaises(L.Parada):
                    L.preparar_override_d2(pathlib.Path(d))

    def test_registros_d2(self):
        lineas = [(1.0, "INFO canario.arranque: LIMITES (configurados): ..."),
                  (2.0, 'DIAG2 {"tipo":"configuracion","port":8000}'),
                  (3.0, 'DIAG2 {"tipo":"muestra"'),
                  (4.0, "DIAG2 [1, 2]"),
                  (5.0, 'DIAG2 {"tipo":"control","nombre":"semaforo","resultado":"PASA"}')]
        registros, ilegibles = L.registros_d2(lineas)
        self.assertEqual([r["tipo"] for r in registros], ["configuracion", "control"])
        self.assertEqual(ilegibles, 2)

    def test_inicios_k6_sin_la_sonda(self):
        filas = [{"nombre": "login_email", "inicio": 3.0}, {"nombre": "sonda_salud", "inicio": 1.0},
                 {"nombre": "denuncia", "inicio": 2.0}]
        self.assertEqual(L.inicios_k6_d2(filas), [2.0, 3.0])

    def test_reunir_d2_sin_salida_de_k6_no_concluye(self):
        # Sin T0 ni CSV no hay ventana: SIN CONCLUSION, nunca una decisión.
        hecha = {"repeticion": 1, "comun": [], "muertes": [],
                 "partes": {"l2": {"resultado": "FALLA", "validez": [], "control_ataque": True,
                                   "detalle": {"victimas": {}}}}}
        with tempfile.TemporaryDirectory() as d:
            r = L.reunir_d2(pathlib.Path(d), pathlib.Path(d) / "l2_rep1", hecha, [])
        self.assertEqual((r["decision"], r["fila"]), ("SIN CONCLUSION", 1))
        self.assertIn("sin ventana valida (falta el t0 de k6)", r["motivos"])

    def test_reunir_d2_lleva_la_validez_de_l2(self):
        hecha = {"repeticion": 1, "comun": [L.fallo("k6 no dejo el CSV")], "muertes": [],
                 "partes": {"l2": {"resultado": "FALLA", "validez": [], "control_ataque": True,
                                   "detalle": {"victimas": {}}}}}
        with tempfile.TemporaryDirectory() as d:
            r = L.reunir_d2(pathlib.Path(d), pathlib.Path(d) / "l2_rep1", hecha, [L.fallo("anti-fuga: hallazgo")])
        self.assertIn("carga: k6 no dejo el CSV", r["motivos"])
        self.assertIn("carga: anti-fuga: hallazgo", r["motivos"])


if __name__ == "__main__":
    unittest.main()
