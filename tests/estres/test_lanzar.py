"""Pruebas de las funciones puras de tests/estres/lanzar.py (sin Docker):

    python -m unittest tests/estres/test_lanzar.py

Cada oráculo es un literal escrito aquí, no derivado de las constantes del
lanzador que se prueba (160 MiB = 167772160, 19456 KiB, 2 hashes, 256 MiB =
268435456, 64 MiB = 67108864). Cada comprobación negativa lleva su control
positivo en la misma prueba: si el positivo falla, la prueba falla (el
resultado sería SIN CONCLUSION, nunca un PASA vacío).
"""
import io
import json
import pathlib
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import lanzar as L  # noqa: E402

MIB = 1048576
ID_API = "a" * 64
ID_API_NUEVO = "b" * 64
ID_PG = "c" * 64
ID_K6 = "d" * 64


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
        self.assertEqual(L.clase_contenedor({"canario.estres": "k6"}), "k6")
        self.assertEqual(L.clase_contenedor({"canario.estres": "control"}), "control")
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
        imagen_de = {ID_API: IMAGEN_REF, ID_CADDY: IMAGEN_CADDY}

        def ejecutar_falso(args, timeout=900):
            return L.R(0, imagen_de[args[-1]] + "\n", "")

        def arrancar_falso(servicios, cpus, rep=1):
            self.arranques.append(rep)
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
        return L.Ejecucion(0.05, None, pathlib.Path("."), [0], [1], {})

    def test_control_inicial_una_sola_vez_y_misma_imagen_pasa(self):
        ej = self.montar(IMAGEN_REF)
        L.preparar_repeticion(ej, 1)
        L.preparar_repeticion(ej, 2)
        self.assertEqual(self.llamadas_control, [("inicial", IMAGEN_REF)])
        self.assertEqual(self.arranques, [1, 2])
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


if __name__ == "__main__":
    unittest.main()
