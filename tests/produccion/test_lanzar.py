"""Pruebas de las funciones puras de tests/produccion/lanzar.py (plan v3, §6),
sin red ni Docker: ninguna abre un socket real. Desde la raíz del repo:

    python -m unittest tests.produccion.test_lanzar -v

Cada oráculo es un literal escrito aquí (t_1 = 0,878 s, t_629 = 59,950 s,
t_630 = 60,000 s, 1830 llegadas, [0,270; 0,400], la línea LIMITES de
tests/security/verificar_denuncia.py:386-387, los cuerpos de las baterías),
no derivado de las constantes del lanzador. Cada comprobación negativa lleva
su control positivo en la misma prueba.
"""
import datetime
import json
import math
import pathlib
import sys
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import lanzar as L  # noqa: E402

# Literales de las baterías (tests/security/verificar_denuncia.py:317, 324-330,
# 347, 396 y verificar_despliegue.py:146), escritos aquí otra vez.
C404 = '{"detalle": "código de seguimiento no válido"}'.encode()
C422 = '{"detalle": "petición no válida"}'.encode()
C429 = '{"detalle": "demasiadas peticiones; inténtelo de nuevo más tarde"}'.encode()
C413 = '{"detalle": "cuerpo de la petición demasiado grande"}'.encode()
SEGURIDAD = {
    "strict-transport-security": "max-age=63072000",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    "cache-control": "no-store",
}
LINEA_LIMITES = ("LIMITES (por defecto): acceso=10/300 cuenta=60/60 denuncia=10/3600 destinatario=3/900 "
                 "destinatario_dia=10/86400 mensajes=30/3600 otras=60/60 registro=10/3600 seguimiento=60/60")
LINEA_CONFIGURADOS = ("LIMITES (configurados): acceso=1000/300 cuenta=1000/60 denuncia=1000/3600 "
                      "destinatario=1000/900 destinatario_dia=1000/86400 mensajes=1000/3600 otras=1000/60 "
                      "registro=1000/3600 seguimiento=1000/60")
DIA = datetime.datetime(2026, 11, 25, tzinfo=datetime.UTC).timestamp()


def r404(t, dur=0.05, red="A"):
    return {"estado": 404, "cuerpo": C404, "cabeceras": {}, "inicio": t, "fin": t + dur, "red": red}


def r429(t, ra="30", dur=0.05, cuerpo=C429, red="A"):
    cab = dict(SEGURIDAD)
    if ra is not None:
        cab["retry-after"] = ra
    return {"estado": 429, "cuerpo": cuerpo, "cabeceras": cab, "inicio": t, "fin": t + dur, "red": red}


def r(estado, t, cuerpo=b"", dur=0.05, red="A"):
    return {"estado": estado, "cuerpo": cuerpo, "cabeceras": {}, "inicio": t, "fin": t + dur, "red": red}


# ---------------------------------------------------------------------------
class Topes(unittest.TestCase):
    def test_por_encima_de_los_topes_es_parada_y_en_el_tope_construye(self):
        for args in ((21, 120, 2400, 10), (20, 121, 2400, 10), (20, 120, 2401, 10), (20, 120, 2400, 11)):
            with self.assertRaises(L.Parada, msg=args):
                L.construir_plan_a(*args)
        # Control: en los topes exactos construye el plan de 1830 llegadas.
        self.assertEqual(len(L.construir_plan_a(20, 120, 2400, 10)), 1830)

    def test_b_y_sondas_por_encima_del_tope(self):
        with self.assertRaises(L.Parada):
            L.validar_topes(20, 120, 2400, 10, tasa_b=0.6)
        with self.assertRaises(L.Parada):
            L.validar_topes(20, 120, 2400, 10, periodo_sonda=0.9)
        L.validar_topes(20, 120, 2400, 10, tasa_b=0.5, periodo_sonda=1.0)

    def test_destino_por_defecto_local(self):
        self.assertEqual(L.analizar_argumentos(["--prueba", "p3"]).destino, "local")

    def test_produccion_sin_franja_es_parada(self):
        sin = L.analizar_argumentos(["--prueba", "p3", "--destino", "produccion", "--origen-a", "192.168.1.20"])
        with self.assertRaises(L.Parada):
            L.validar_argumentos(sin)
        # Control: con la franja, pasa la validación.
        con = L.analizar_argumentos(["--prueba", "p3", "--destino", "produccion", "--origen-a", "192.168.1.20",
                                     "--franja-autorizada", "19:00-21:00"])
        L.validar_argumentos(con)

    def test_p1_local_no_existe(self):
        with self.assertRaises(L.Parada):
            L.validar_argumentos(L.analizar_argumentos(["--prueba", "p1"]))
        L.validar_argumentos(L.analizar_argumentos(["--prueba", "p2"]))


class Rampa(unittest.TestCase):
    def test_tiempos_literales(self):
        t = L.tiempos_rampa()
        self.assertEqual(len(t), 1830)
        for k, esperado in ((0, 0.000), (1, 0.878), (629, 59.950), (630, 60.000), (1829, 119.950)):
            self.assertAlmostEqual(t[k], esperado, delta=0.001, msg=f"t_{k}")
        # Control: el hueco entre t_629 y t_630 es de unos 0,05 s.
        self.assertAlmostEqual(t[630] - t[629], 0.05, delta=0.001)


class RelojA1(unittest.TestCase):
    def muestras_qa5(self):
        # d real 0,35 s, RTT 0,03 s, 10 muestras en t_i = 100 + 1,1 i, Date = suelo
        # de la hora del servidor en el punto medio (modelo de la prueba).
        res = []
        for i in range(10):
            t = 100.0 + 1.1 * i
            res.append((t, t + 0.03, math.floor(t + 0.015 + 0.35)))
        return res

    def test_una_muestra(self):
        doce = DIA + 12 * 3600
        d_min, d_max = L.intervalo_a1([(doce - 0.4, doce - 0.3, int(doce))])
        self.assertAlmostEqual(d_min, 0.3, delta=1e-6)
        self.assertAlmostEqual(d_max, 1.4, delta=1e-6)

    def test_date_atrasado_vacia_la_interseccion(self):
        muestras = self.muestras_qa5()
        self.assertEqual(L.evaluar_a1(muestras)[0], "PASA")
        t, f, fecha = muestras[8]
        muestras[8] = (t, f, fecha - 1)
        self.assertEqual(L.evaluar_a1(muestras)[0], "SIN CONCLUSION")

    def test_anchura_qa5(self):
        v, (d_min, d_max), _ = L.evaluar_a1(self.muestras_qa5())
        self.assertEqual(v, "PASA")
        self.assertAlmostEqual(d_min, 0.270, delta=0.001)
        self.assertAlmostEqual(d_max, 0.400, delta=0.001)
        self.assertTrue(d_min <= 0.35 <= d_max)
        self.assertAlmostEqual(d_max - d_min, 0.13, delta=0.001)

    def test_mas_ancho_de_1_5_es_sin_conclusion(self):
        self.assertEqual(L.evaluar_a1([(100.0, 100.6, 100)])[0], "SIN CONCLUSION")   # [-0,6; 1,0]: 1,6 s
        self.assertEqual(L.evaluar_a1([(100.0, 100.4, 100)])[0], "PASA")             # 1,4 s

    def test_a1_inicial_y_final(self):
        self.assertIsNone(L.combinar_a1((0.1, 0.3), (0.4, 0.6)))
        self.assertEqual(L.combinar_a1((0.1, 0.3), (0.2, 0.5)), (0.1, 0.5))


class GuardaD10(unittest.TestCase):
    T0 = 1_000_020.0   # 1000020 / 60 = 16667: frontera exacta del servidor en t0 con d = 0

    def test_a_20_por_segundo_sin_ambiguas_y_control_sin_guarda(self):
        tiempos = [i * 0.05 for i in range(3600)]           # 180 s a 20/s: 3 fronteras
        for guarda, esperado_cero in ((True, True), (False, False)):
            lanzadas, _ = L.planificar_guarda(tiempos, self.T0 + 0.5, 0.0, 0.3, guarda=guarda)
            # Petición de 0,2 s con el desfase real 0,15 dentro de [0; 0,3].
            ambiguas = [plan for _, plan in lanzadas if L.clasificar(plan, plan + 0.2, 0.0, 0.3, 60)[1]]
            if esperado_cero:
                self.assertEqual(ambiguas, [])
            else:
                fronteras = {math.floor((p + 0.6) / 60) for p in ambiguas}
                self.assertEqual(len(fronteras), 3, "sin la guarda hay ambiguas en cada frontera")

    def test_borde_qa6(self):
        self.assertTrue(L.permite_guarda(118.699, 0.0, 0.3))
        self.assertFalse(L.permite_guarda(118.700, 0.0, 0.3))
        self.assertEqual(L.clasificar(118.699, 118.699 + 1.000, 0.0, 0.3, 60), (1, False))
        self.assertEqual(L.clasificar(118.699, 118.699 + 1.001, 0.0, 0.3, 60), (1, True))

    def test_omitidas_no_se_reenvian(self):
        tiempos = L.tiempos_rampa()
        t0 = self.T0 + 30.0     # la frontera de t0 + 30 s cae en mitad de la rampa
        lanzadas, omitidas = L.planificar_guarda(tiempos, t0, 0.0, 0.3)
        self.assertTrue(omitidas, "control: con fronteras dentro de la carga hay omitidas")
        self.assertEqual(len(lanzadas), 1830 - len(omitidas))
        self.assertEqual(len({k for k, _ in lanzadas} | {k for k, _ in omitidas}), 1830)
        self.assertTrue(all(L.permite_guarda(plan, 0.0, 0.3) for _, plan in lanzadas))
        self.assertFalse(any(L.permite_guarda(plan, 0.0, 0.3) for _, plan in omitidas))

    def test_omitidas_no_cuentan_en_el_retraso(self):
        reloj, parada, registro, conexiones = L.Reloj(), L.EstadoParada(), [], []
        t0 = reloj.ahora() + 0.05
        llegadas = [i * 0.01 for i in range(20)]

        def enviar(con, reloj_):
            return {"estado": 404, "inicio": reloj_.ahora(), "fin": reloj_.ahora(), "ms": 1.0}

        omitidas, descartes = L.ejecutar_a(llegadas, t0, reloj, Falsa, enviar, parada, 2.0, 10, 2400, registro,
                                           conexiones, permite=lambda t: not (t0 + 0.05 <= t < t0 + 0.10))
        k_lanzadas = {f["k"] for f in registro}
        k_omitidas = {k for k, _ in omitidas}
        self.assertTrue(k_omitidas, "control: la guarda simulada omite algo")
        self.assertFalse(k_lanzadas & k_omitidas)
        self.assertEqual(k_lanzadas | k_omitidas | {k for k, _ in descartes}, set(range(20)))
        # El control de retraso solo ve las lanzadas.
        retrasos = [f["real"] - f["planeada"] for f in registro]
        self.assertEqual(len(retrasos), len(k_lanzadas))


class Falsa:
    """Conexión falsa: nunca abre un socket."""

    def __init__(self):
        self.cerrada = False

    def close(self):
        self.cerrada = True


class Franja(unittest.TestCase):
    AMPLIA = (21 * 3600, 23 * 3600)

    def test_borde_de_las_22_47(self):
        L.comprobar_franja_p6(DIA + 22 * 3600 + 46 * 60 + 59.5, 0.4, 0.4, self.AMPLIA)
        with self.assertRaises(L.Parada):
            L.comprobar_franja_p6(DIA + 22 * 3600 + 46 * 60 + 59.7, 0.4, 0.4, self.AMPLIA)

    def test_antes_de_las_22_rechazada(self):
        with self.assertRaises(L.Parada):
            L.comprobar_franja_p6(DIA + 21 * 3600 + 59 * 60, 0.4, 0.4, self.AMPLIA)
        L.comprobar_franja_p6(DIA + 22 * 3600 + 1, 0.4, 0.4, self.AMPLIA)

    def test_n7_franja_autorizada(self):
        with self.assertRaises(L.Parada):
            L.comprobar_franja_p6(DIA + 22 * 3600 + 30 * 60, 0.0, 0.0, L.leer_franja("21:00-22:35"))
        L.comprobar_franja_p6(DIA + 22 * 3600 + 30 * 60, 0.0, 0.0, L.leer_franja("21:00-23:00"))

    def test_franja_mal_escrita(self):
        for texto in ("21:00", "22:00-21:00", "25:00-26:00", None):
            with self.assertRaises(L.Parada):
                L.leer_franja(texto)
        self.assertEqual(L.leer_franja("19:00-21:00"), (19 * 3600, 21 * 3600))


def bloque(started="2026-11-25T19:03:05.5Z", primera="2026-11-25T19:03:06.000000001Z",
           lineas=(("2026-11-25T19:03:07.123456789Z", LINEA_LIMITES),), extra=(), salto="\n"):
    imagen = "sha256:" + "ab" * 32
    filas = ["CANARIO_P4_INICIO", f"API {started} 0 {imagen}", f"PRIMERA_MARCA {primera}"]
    filas += list(extra) + [f"{m} INFO canario.arranque: {t}" for m, t in lineas] + ["CANARIO_P4_FIN"]
    return salto.join(filas) + salto


class P4(unittest.TestCase):
    def test_literal_con_crlf_y_nueve_decimales_pasa(self):
        self.assertEqual(L.analizar_bloque_p4(bloque(salto="\r\n"))["veredicto"], "PASA")

    def test_configurados_o_una_regla_de_menos_es_falla(self):
        self.assertEqual(L.analizar_bloque_p4(bloque())["veredicto"], "PASA")   # control
        configurados = bloque(lineas=(("2026-11-25T19:03:07Z", LINEA_LIMITES.replace("por defecto", "configurados")),))
        self.assertEqual(L.analizar_bloque_p4(configurados)["veredicto"], "FALLA")
        de_menos = bloque(lineas=(("2026-11-25T19:03:07Z", LINEA_LIMITES.replace(" seguimiento=60/60", "")),))
        self.assertEqual(L.analizar_bloque_p4(de_menos)["veredicto"], "FALLA")

    def test_aviso_de_sudo_es_sin_conclusion(self):
        for ajena in ("[sudo] password for x:", "Sorry, try again."):
            a = L.analizar_bloque_p4(bloque(extra=(ajena,)))
            self.assertEqual(a["veredicto"], "SIN CONCLUSION", ajena)
            self.assertFalse(a["formato_valido"])

    def test_interrogacion_es_sin_conclusion_qa3(self):
        self.assertEqual(L.analizar_bloque_p4(bloque(lineas=(("2026-11-25T19:03:07Z",
                                                              LINEA_LIMITES.replace("é", "?")
                                                              .replace("acceso", "acc?so")),)))["veredicto"],
                         "SIN CONCLUSION")

    def test_rotacion_y_ausencia(self):
        rotado = bloque(primera="2026-11-25T19:03:06Z", started="2026-11-25T19:03:05Z", lineas=())
        self.assertEqual(L.analizar_bloque_p4(rotado)["veredicto"], "SIN CONCLUSION")
        cubierto = bloque(primera="2026-11-25T19:03:04Z", started="2026-11-25T19:03:05Z", lineas=())
        self.assertEqual(L.analizar_bloque_p4(cubierto)["veredicto"], "FALLA")

    def test_linea_anterior_al_arranque_es_falla(self):
        vieja = bloque(primera="2026-11-25T18:00:00Z", lineas=(("2026-11-25T18:00:01Z", LINEA_LIMITES),))
        self.assertEqual(L.analizar_bloque_p4(vieja)["veredicto"], "FALLA")

    def test_relectura_con_otro_started_at(self):
        a = L.analizar_bloque_p4(bloque())
        self.assertTrue(L.comparar_relectura(a, L.analizar_bloque_p4(bloque()))[0])
        otro = L.analizar_bloque_p4(bloque(started="2026-11-25T19:03:05.6Z"))
        iguales, motivo = L.comparar_relectura(a, otro)
        self.assertFalse(iguales)
        self.assertIn("repetir P4", motivo)

    def test_control_local(self):
        local = L.analizar_bloque_p4(bloque(lineas=(("2026-11-25T19:03:07Z", LINEA_CONFIGURADOS),)))
        self.assertEqual(local["veredicto"], "FALLA")
        self.assertTrue(L.control_p4_correcto(local))
        self.assertFalse(L.control_p4_correcto(L.analizar_bloque_p4(bloque())))


def filas_p1_a(inicio=62.0, malo=None):
    filas = [r404(inicio + i * 0.05) for i in range(60)] + [r429(inicio + 3 + i * 0.05) for i in range(10)]
    if malo is not None:
        filas[malo - 1] = r429(filas[malo - 1]["inicio"])
    return filas


class P1(unittest.TestCase):
    def ips_distintas(self):
        return "198.51.100.10", "203.0.113.20"

    def test_pasa_sin_consultar_ips(self):
        llamadas = []
        b = [r404(65.0 + i * 0.05, red="B") for i in range(5)]
        v, _ = L.veredicto_p1(filas_p1_a(), b, 0.0, 0.3, lambda: llamadas.append(1) or self.ips_distintas())
        self.assertEqual(v, "PASA")
        self.assertEqual(llamadas, [])

    def test_b_con_429(self):
        b = [r404(65.0 + i * 0.05, red="B") for i in range(4)] + [r429(65.3, red="B")]
        self.assertEqual(L.veredicto_p1(filas_p1_a(), b, 0.0, 0.3, self.ips_distintas)[0], "FALLA")
        self.assertEqual(L.veredicto_p1(filas_p1_a(), b, 0.0, 0.3, lambda: ("x", "x"))[0], "SIN CONCLUSION")

    def test_b_ambigua_o_fuera_de_la_ventana(self):
        # [119,7; 119,75 + 0,3 = 120,05]: cruza la frontera de las 120.
        ambigua = [r404(65.0 + i * 0.05, red="B") for i in range(4)] + [r404(119.7, red="B")]
        fuera = [r404(65.0 + i * 0.05, red="B") for i in range(4)] + [r404(125.0, red="B")]
        for b in (ambigua, fuera):
            self.assertEqual(L.veredicto_p1(filas_p1_a(), b, 0.0, 0.3, self.ips_distintas)[0], "SIN CONCLUSION")

    def test_a_con_429_en_la_30(self):
        b = [r404(65.0 + i * 0.05, red="B") for i in range(5)]
        self.assertEqual(L.veredicto_p1(filas_p1_a(malo=30), b, 0.0, 0.3, self.ips_distintas)[0], "SIN CONCLUSION")


class P1b(unittest.TestCase):
    def test_429_de_otro_es_falla(self):
        buenas = filas_p1_a()
        self.assertEqual(L.veredicto_p1b(buenas, True, 0.0, 0.3)[0], "PASA")
        malas = filas_p1_a()
        malas[64] = r429(malas[64]["inicio"], cuerpo=b"Too Many Requests")
        self.assertEqual(L.veredicto_p1b(malas, True, 0.0, 0.3)[0], "FALLA")

    def test_502_en_la_10_es_sin_conclusion(self):
        filas = filas_p1_a()
        filas[9] = r(502, filas[9]["inicio"])
        v, texto = L.veredicto_p1b(filas, True, 0.0, 0.3)
        self.assertEqual(v, "SIN CONCLUSION")
        self.assertIn("control de P1b, peticion 10 = 502", texto)

    def test_error_en_61_a_70_es_sin_conclusion(self):
        for estado in (0, 502):
            filas = filas_p1_a()
            filas[65] = r(estado, filas[65]["inicio"])
            self.assertEqual(L.veredicto_p1b(filas, True, 0.0, 0.3)[0], "SIN CONCLUSION", estado)
        # Control: un 200 ahí sí es FALLA (el límite no actuó).
        filas = filas_p1_a()
        filas[65] = r(200, filas[65]["inicio"])
        self.assertEqual(L.veredicto_p1b(filas, True, 0.0, 0.3)[0], "FALLA")

    def test_sin_p1b_c_en_pasa(self):
        self.assertEqual(L.veredicto_p1b(filas_p1_a(), False, 0.0, 0.3)[0], "SIN CONCLUSION")
        self.assertEqual(L.veredicto_p1b_c(filas_p1_a(), 0.0, 0.3)[0], "PASA")

    def test_lista_xff(self):
        lista = L.lista_xff()
        self.assertEqual(len(lista), 70)
        self.assertTrue(L.validar_xff(lista))
        self.assertFalse(L.validar_xff(lista[:-1] + ["198.18.0.1"]))
        self.assertFalse(L.validar_xff(lista[:-1] + [lista[0]]))


class P2(unittest.TestCase):
    def filas(self, ultima, malo=None):
        filas = [r(422, 7200.0 + i * 0.1, C422) for i in range(10)] + [ultima]
        if malo is not None:
            filas[malo] = r429(filas[malo]["inicio"], ra="3599")
        return filas

    def test_veredictos(self):
        self.assertEqual(L.veredicto_p2(self.filas(r429(7202.0, ra="3599")), 0.0, 0.3)[0], "PASA")
        for ra in ("0", "3601", None):
            self.assertEqual(L.veredicto_p2(self.filas(r429(7202.0, ra=ra)), 0.0, 0.3)[0], "FALLA", ra)
        self.assertEqual(L.veredicto_p2(self.filas(r429(7202.0, ra="3599"), malo=4), 0.0, 0.3)[0],
                         "SIN CONCLUSION")

    def test_error_en_la_11_es_sin_conclusion(self):
        for estado in (0, 503):
            self.assertEqual(L.veredicto_p2(self.filas(r(estado, 7202.0)), 0.0, 0.3)[0], "SIN CONCLUSION", estado)
        self.assertEqual(L.veredicto_p2(self.filas(r(422, 7202.0, C422)), 0.0, 0.3)[0], "FALLA")

    def test_599_s_no_arranca(self):
        restantes = L.segundos_restantes_hora(DIA + 3001, 0.0)
        self.assertAlmostEqual(restantes, 599, delta=1e-6)
        self.assertFalse(L.p2_puede_arrancar(restantes))
        self.assertTrue(L.p2_puede_arrancar(601))


class P3(unittest.TestCase):
    JUSTO = {"estado": 405, "cuerpo": b"", "cabeceras": {"via": "1.1 Caddy"}}

    def grande(self, cabeceras=None):
        return {"estado": 413, "cuerpo": C413, "cabeceras": cabeceras or {"connection": "close"}}

    def test_veredictos(self):
        self.assertEqual(L.veredicto_p3(self.JUSTO, self.grande(), 0.30)[0], "PASA")
        self.assertEqual(L.veredicto_p3(self.JUSTO, self.grande(), 0.51)[0], "FALLA")
        self.assertEqual(L.veredicto_p3({"estado": 405, "cabeceras": {}}, self.grande(), 0.30)[0], "SIN CONCLUSION")

    def test_sin_connection_close_sigue_pasa_y_lo_anota(self):
        v, texto, conexion = L.veredicto_p3(self.JUSTO, self.grande({"content-type": "application/json"}), 0.30)
        self.assertEqual(v, "PASA")
        self.assertEqual(conexion, "")
        self.assertIn("D1", texto)


def filas_p6_a(ventana=1, n404=60, n429=10, extra=()):
    base = ventana * 60 + 1.0
    filas = [{"inicio": base + i * 0.4, "fin": base + i * 0.4 + 0.05, "estado": 404, "es_429": False,
              "retry_after": -1} for i in range(n404)]
    filas += [{"inicio": base + 30 + i * 0.1, "fin": base + 30 + i * 0.1 + 0.05, "estado": 429, "es_429": True,
               "retry_after": 30} for i in range(n429)]
    return filas + list(extra)


def filas_b(n=60, ms=50.0, estados=None):
    return [{"estado": (estados or {}).get(i, 404), "ms": ms} for i in range(n)]


class P6(unittest.TestCase):
    def v(self, a, b, parada=None, retraso=True, descartes=0):
        return L.veredicto_p6(a, b, 0.0, 0.3, parada, descartes, retraso, 100.0)[0]

    def test_61_aceptadas_falla_y_60_pasa(self):
        self.assertEqual(self.v(filas_p6_a(n404=60), filas_b()), "PASA")
        self.assertEqual(self.v(filas_p6_a(n404=61), filas_b()), "FALLA")

    def test_ninguna_429_de_a(self):
        self.assertEqual(self.v(filas_p6_a(n429=0), filas_b()), "SIN CONCLUSION")

    def test_ambigua_aceptada_y_ambigua_429(self):
        cruza_404 = {"inicio": 119.9, "fin": 119.95, "estado": 404, "es_429": False, "retry_after": -1}
        cruza_429 = {"inicio": 119.9, "fin": 119.95, "estado": 429, "es_429": True, "retry_after": 30}
        self.assertEqual(self.v(filas_p6_a(extra=[cruza_404]), filas_b()), "SIN CONCLUSION")
        self.assertEqual(self.v(filas_p6_a(extra=[cruza_429]), filas_b()), "PASA")

    def test_parada_por_sondas(self):
        self.assertIsNotNone(L.evaluar_sondas([(200, 5.01), (200, 5.01)], 2.0))
        self.assertIsNone(L.evaluar_sondas([(200, 5.00), (200, 5.00)], 2.0))
        self.assertIsNone(L.evaluar_sondas([(200, 0.1), (200, 5.01)], 2.0))
        self.assertIsNotNone(L.evaluar_sondas([(200, 0.1), (200, 0.61)], 0.2))
        self.assertIsNone(L.evaluar_sondas([(200, 0.1), (200, 0.59)], 0.2))
        self.assertIsNotNone(L.evaluar_sondas([(503, 0.1), (0, 0.1)], 2.0))

    def test_error_de_b_gana_a_la_parada(self):
        parada = {"causa": "vecina", "motivo": "vecina_1: x", "instante": 100.0}
        self.assertEqual(self.v(filas_p6_a(), filas_b(20, estados={3: 0}), parada), "FALLA")
        self.assertEqual(self.v(filas_p6_a(), filas_b(20), parada), "SIN CONCLUSION")

    def test_p50_con_parada_y_sin_ella_qa2(self):
        parada = {"causa": "vecina", "motivo": "vecina_1: x", "instante": 100.0}
        self.assertEqual(self.v(filas_p6_a(), filas_b(20, ms=500.0), parada), "SIN CONCLUSION")
        self.assertEqual(self.v(filas_p6_a(), filas_b(60, ms=500.0)), "FALLA")
        self.assertEqual(self.v(filas_p6_a(), filas_b(60, ms=50.0)), "PASA")

    def test_retraso_y_descartes(self):
        self.assertEqual(self.v(filas_p6_a(), filas_b(), retraso=False), "SIN CONCLUSION")
        self.assertEqual(self.v(filas_p6_a(), filas_b(), descartes=1), "SIN CONCLUSION")

    def test_retraso_del_planificador(self):
        self.assertFalse(L.control_retraso([0.6] * 2 + [0.0] * 98)[0])
        self.assertTrue(L.control_retraso([0.6] * 1 + [0.0] * 99)[0])
        self.assertFalse(L.control_retraso([2.1] + [0.0] * 999)[0])

    def test_hmac_y_bytes_del_fichero(self):
        for malo in (b"\xef\xbb\xbfhttps://a.invalid/ 200\n", b"https://a.invalid/ 200\r\n"):
            with self.assertRaises(L.Parada):
                L.validar_bytes_vecinas(malo)
        self.assertEqual(L.validar_bytes_vecinas(b"https://a.invalid/ 200\n"), "https://a.invalid/ 200\n")
        # RFC 4231, caso 2: clave "Jefe", datos "what do ya want for nothing?".
        self.assertEqual(L.hmac_vecinas(b"Jefe", b"what do ya want for nothing?"),
                         "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")

    def test_vecinas_alias(self):
        vecinas = L.leer_vecinas("https://a.invalid/ 200\nhttps://b.invalid:8443/x 301\n")
        self.assertEqual([v["alias"] for v in vecinas], ["vecina_1", "vecina_2"])
        with self.assertRaises(L.Parada):
            L.leer_vecinas("http://a.invalid/ 200\n")

    def test_marca_q12(self):
        self.assertEqual(L.validar_marca_q12("2026-11-25T21:00:00Z"), "2026-11-25T21:00:00Z")
        for mala in ("2026-11-25 21:00:00", "2026-11-25T21:00:00Z; rm", "2026-11-25T21:00:00Z\n"):
            with self.assertRaises(L.Parada):
                L.validar_marca_q12(mala)
        comando = L.comando_q12(DIA + 21 * 3600, DIA + 21 * 3600 + 60)
        self.assertIn("--since 2026-11-25T20:59:55Z --until 2026-11-25T21:01:05Z", comando)
        self.assertIn("grep -F 'EVENTO limitador_no_disponible: '", comando)

    def test_analisis_q12(self):
        ventanas = {"p1": (DIA + 100, DIA + 200)}
        evento = "2026-11-25T00:02:30.5Z ERROR canario.limitador: EVENTO limitador_no_disponible: X causa=plazo espera=<0.25"
        texto = "CANARIO_Q12_INICIO\n" + evento + "\nCANARIO_Q12_FIN\n"
        self.assertEqual(L.analizar_q12(texto, ventanas)[0], "SIN CONCLUSION")
        self.assertEqual(L.analizar_q12("CANARIO_Q12_INICIO\nCANARIO_Q12_FIN\n", ventanas)[0], "PASA")
        self.assertEqual(L.analizar_q12("CANARIO_Q12_INICIO\nbasura\nCANARIO_Q12_FIN\n", ventanas)[0], "SIN CONCLUSION")

    def test_congelacion_sin_rellenar_es_parada(self):
        # Las cinco constantes sin rellenar se pasan como valores explícitos:
        # antes se leían las del módulo, y la prueba solo podía pasar antes del
        # commit de congelación.
        vacias = dict.fromkeys(("P5_P50_MS", "P5_P95_MS", "P5_MAX_MS", "P6_P50_B_MAX_MS", "HMAC_VECINAS"))
        with self.assertRaises(L.Parada):
            L.comprobar_congelacion(vacias)
        self.assertEqual(L.verificar_congelacion(vacias)[0], "PARADA")

    def test_congelacion_del_25_11_es_la_de_p5_y_pasa(self):
        # Control positivo: las constantes del módulo son las congeladas el
        # 25/11/2026 con P5 en producción (literales, no derivadas del código)
        # y verificar_congelacion las da por buenas.
        self.assertEqual(L.valores_congelados(), {
            "P5_P50_MS": 428.0, "P5_P95_MS": 634.4, "P5_MAX_MS": 961.7, "P6_P50_B_MAX_MS": 856.0,
            "HMAC_VECINAS": "210d0bba62fb47aca06fded4221abf56685b24cf31f2c17c84740b040abd16d2"})
        self.assertEqual(L.verificar_congelacion()[0], "PASA")

    def test_falla_de_a_en_ventana_incompleta(self):
        # Parada a los 40 s de la ventana 1 (instante 100): la ventana no es
        # completa, pero 61 aceptadas no ambiguas ya son FALLA.
        parada = {"causa": "vecina", "motivo": "vecina_1: x", "instante": 100.0}
        self.assertEqual(self.v(filas_p6_a(n404=61), filas_b(), parada), "FALLA")
        # Control: con 60, la misma parada da SIN CONCLUSION (ventana incompleta).
        self.assertEqual(self.v(filas_p6_a(n404=60), filas_b(), parada), "SIN CONCLUSION")


class Congelacion(unittest.TestCase):
    HMAC = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"

    def valores(self, **cambios):
        v = {"P5_P50_MS": 41.3, "P5_P95_MS": 60.2, "P5_MAX_MS": 95.0, "P6_P50_B_MAX_MS": 82.6,
             "HMAC_VECINAS": self.HMAC}
        v.update(cambios)
        return v

    def test_texto_que_imprime_p5_es_coherente(self):
        texto = L.texto_congelacion({"p50": 41.26, "p95": 60.21, "max": 95.04})
        self.assertEqual(texto, "P5_P50_MS = 41.3, P5_P95_MS = 60.2, P5_MAX_MS = 95.0, P6_P50_B_MAX_MS = 82.6")

    def test_rellenas_coherentes_pasa_e_incoherentes_parada(self):
        self.assertEqual(L.verificar_congelacion(self.valores())[0], "PASA")
        for cambio in ({"P6_P50_B_MAX_MS": 82.5}, {"P5_P50_MS": 41.26, "P6_P50_B_MAX_MS": 82.52},
                       {"P5_P95_MS": 30.0}, {"HMAC_VECINAS": "ABC"}, {"P5_MAX_MS": None}):
            self.assertEqual(L.verificar_congelacion(self.valores(**cambio))[0], "PARADA", cambio)

    def test_modo_en_argumentos(self):
        self.assertEqual(L.analizar_argumentos(["--prueba", "verificar-congelacion"]).prueba, "verificar-congelacion")


class P5(unittest.TestCase):
    def filas(self, n=300, estados=None, ms=40.0):
        return [{"estado": (estados or {}).get(i, 404), "ms": ms} for i in range(n)]

    def test_veredictos(self):
        v, _, stats = L.veredicto_p5(self.filas(), True, "")
        self.assertEqual(v, "PASA")
        self.assertEqual(stats["n"], 300)
        self.assertEqual(L.veredicto_p5(self.filas(estados={7: 429}), True, "")[0], "SIN CONCLUSION")
        # Errores: con 10 sin respuesta quedan 290 (PASA, se publican); con 11, 289.
        diez = {i: 0 for i in range(10)}
        v, texto, stats = L.veredicto_p5(self.filas(estados=diez), True, "")
        self.assertEqual((v, stats["errores"]), ("PASA", 10))
        once = {i: 0 for i in range(11)}
        self.assertEqual(L.veredicto_p5(self.filas(estados=once), True, "")[0], "SIN CONCLUSION")
        self.assertEqual(L.veredicto_p5(self.filas(n=299), True, "")[0], "SIN CONCLUSION")
        self.assertEqual(L.veredicto_p5(self.filas(), False, "lento")[0], "SIN CONCLUSION")

    def test_ensayo_local_corto(self):
        self.assertEqual(L.minimo_respuestas_p5(300), 290)
        self.assertEqual(L.veredicto_p5(self.filas(n=30), True, "", previstas=30)[0], "PASA")

    def test_hilo_de_parada_colgado(self):
        envios, conexiones, registro = [], [], []
        candado = threading.Lock()

        def enviar(con, reloj):
            with candado:
                envios.append(time.monotonic())
            time.sleep(0.01)
            return {"estado": 404, "inicio": reloj.ahora(), "fin": reloj.ahora(), "ms": 10.0}

        colgado = threading.Event()
        hilo_parada = threading.Thread(target=colgado.wait, daemon=True)   # nunca avisa
        hilo_parada.start()
        reloj, parada = L.Reloj(), L.EstadoParada()
        inicio = time.monotonic()
        # 200 llegadas repartidas en 4 s y un plazo de 0,3 s: con margen holgado
        # (1 s), lo que se comprueba es que A para por su plazo y no por la
        # parada, sin depender de la precisión del reloj del sistema.
        L.ejecutar_a([i * 0.02 for i in range(200)], reloj.ahora(), reloj, Falsa, enviar, parada, 0.3, 10, 2400,
                     registro, conexiones)
        try:
            self.assertTrue(envios, "control: A llego a enviar")
            self.assertLess(max(envios), inicio + 0.3 + 1.0)
            self.assertLess(len(envios), 200 // 2, "A no llega a la mitad de las llegadas: paro por su plazo")
            self.assertEqual(len(conexiones), 10)
            self.assertTrue(all(c.cerrada for c in conexiones))
            self.assertTrue(hilo_parada.is_alive())
        finally:
            colgado.set()


class IpPublica(unittest.TestCase):
    TRACE = "fl=123f45\nh=1.1.1.1\nip=203.0.113.7\nts=1764000000.123\nvisit_scheme=https\nuag=\ncolo=MAD\n"

    def test_solo_ip(self):
        self.assertEqual(L.extraer_ip_trace(self.TRACE), "203.0.113.7")
        with self.assertRaises(L.Parada):
            L.extraer_ip_trace("fl=123f45\nh=1.1.1.1\n")

    def test_global(self):
        with self.assertRaises(L.Parada):
            L.validar_ip_publica("203.0.113.7")      # documentación, no global
        with self.assertRaises(L.Parada):
            L.validar_ip_publica("192.168.1.2")
        self.assertEqual(L.validar_ip_publica("1.1.1.1"), "1.1.1.1")

    def test_ssh_g_solo_user_y_hostname(self):
        texto = "user deploy\nhostname vps.ejemplo.invalid\nport 22\nforwardagent no\n"
        self.assertEqual(L.leer_ssh_g(texto), ("deploy", "vps.ejemplo.invalid"))


class AntiFugaYGlobal(unittest.TestCase):
    def test_ip_local_plantada_se_encuentra(self):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            (d / "salida.txt").write_text("conexion desde 192.168.1.34.\n", encoding="utf-8")
            reales, faltan = L.escanear_con_centinela(d, {}, [("origen_a", L.patron_aislado("192.168.1.34"))])
            self.assertEqual(reales, {"salida.txt": ["origen_a"]})
            self.assertEqual(faltan, [])
            # Control: sin la IP no hay hallazgos y el centinela se sigue viendo.
            (d / "salida.txt").write_text("limpio\n", encoding="utf-8")
            reales, faltan = L.escanear_con_centinela(d, {}, [("origen_a", L.patron_aislado("192.168.1.34"))])
            self.assertEqual((reales, faltan), ({}, []))
            self.assertFalse((d / L.CARPETA_CENTINELA).exists())

    def test_patron_aislado(self):
        p = L.patron_aislado("10.0.0.1")
        self.assertIsNone(p.search(b"110.0.0.12"))
        self.assertIsNotNone(p.search(b"desde 10.0.0.1, fin"))

    def test_sin_centinela_es_sin_conclusion(self):
        self.assertEqual(L.veredicto_fuga({}, False)[0], "SIN CONCLUSION")
        self.assertEqual(L.veredicto_fuga({}, True)[0], "PASA")

    def test_prueba_no_ejecutada_es_no_ok(self):
        self.assertEqual(L.resultado_global({"P1": "NO EJECUTADA"}, "PASA", True), ("NO OK", 1))
        self.assertEqual(L.resultado_global({}, "PASA", True), ("NO OK", 1))
        self.assertEqual(L.resultado_global({"P1": "SIN CONCLUSION"}, "PASA", True), ("NO OK", 1))
        self.assertEqual(L.resultado_global({"P1": "PASA"}, "PASA", False), ("NO OK", 1))
        self.assertEqual(L.resultado_global({"P1": "PASA", "P0": "HECHO"}, "PASA", True), ("OK", 0))


class FuncionesCopiadas(unittest.TestCase):
    """Los mismos casos literales que tests/estres/test_lanzar.py:1988-2064 y
    :2519-2555 para las funciones copiadas."""

    def filas(self, ip, inicios, estado, dur=0.05):
        return [{"ip": ip, "inicio": t, "fin": t + dur, "estado": estado} for t in inicios]

    def test_ambigua_si_cruza_la_frontera(self):
        self.assertEqual(L.ventana_de_peticion(119.99, 120.05, 60), (1, True))
        self.assertEqual(L.ventana_de_peticion(100.0, 100.05, 60), (1, False))
        self.assertEqual(L.ventana_de_peticion(60.0, 60.05, 60), (1, False))

    def test_61_aceptadas_no_ambiguas_es_falla_y_60_pasa(self):
        ok = self.filas("a", [60 + i * 0.5 for i in range(60)], 404) + self.filas("a", [95 + i * 0.1 for i in range(5)], 429)
        self.assertEqual(L.veredicto_l3(L.contar_por_ip_ventana(ok, 60, 404), 60)[0], "PASA")
        malo = self.filas("a", [60 + i * 0.4 for i in range(61)], 404)
        self.assertEqual(L.veredicto_l3(L.contar_por_ip_ventana(malo, 60, 404), 60)[0], "FALLA")

    def test_solo_pasa_contando_ambiguas_es_sin_conclusion(self):
        filas = self.filas("a", [60 + i * 0.4 for i in range(60)], 404)
        filas += [{"ip": "a", "inicio": 119.99, "fin": 120.05, "estado": 404}]
        self.assertEqual(L.veredicto_l3(L.contar_por_ip_ventana(filas, 60, 404), 60)[0], "SIN CONCLUSION")

    def test_retry_after(self):
        pares = L.contar_por_ip_ventana(self.filas("a", [60 + i for i in range(10)], 404), 60, 404)
        self.assertEqual(L.veredicto_l3(pares, 60, 0)[0], "PASA")
        self.assertEqual(L.veredicto_l3(pares, 60, 1)[0], "FALLA")
        self.assertTrue(L.retry_after_valido(1, 60))
        self.assertTrue(L.retry_after_valido(60, 60))
        self.assertFalse(L.retry_after_valido(61, 60))
        self.assertFalse(L.retry_after_valido(0, 60))
        self.assertFalse(L.retry_after_valido(-1, 60))

    def test_control_positivo_j2(self):
        buenos = self.filas("a", [60 + i * 0.5 for i in range(60)], 404) + self.filas("a", [91 + i * 0.1 for i in range(3)], 429)
        self.assertTrue(L.control_l3(L.contar_por_ip_ventana(buenos, 60, 404), 60)[0])
        malos = self.filas("a", [60 + i * 0.5 for i in range(9)], 404) + self.filas("a", [65], 429)
        self.assertFalse(L.control_l3(L.contar_por_ip_ventana(malos, 60, 404), 60)[0])
        previas = self.filas("a", [60, 61], 503) + self.filas("a", [62 + i * 0.2 for i in range(56)], 404) \
            + self.filas("a", [80], 429)
        self.assertTrue(L.control_l3(L.contar_por_ip_ventana(previas, 60, 404), 60)[0])
        sin_previas = self.filas("a", [62 + i * 0.2 for i in range(56)], 404) + self.filas("a", [80], 429)
        self.assertFalse(L.control_l3(L.contar_por_ip_ventana(sin_previas, 60, 404), 60)[0])

    def test_ambiguas_al_inicio_relajan_el_control(self):
        filas = [{"ip": "a", "inicio": 59.99, "fin": 60.05, "estado": 404}]
        filas += self.filas("a", [61 + i * 0.5 for i in range(59)], 404) + self.filas("a", [95], 429)
        pares = L.contar_por_ip_ventana(filas, 60, 404)
        self.assertEqual(pares[("a", 1)]["ambiguas_inicio"], 1)
        self.assertTrue(L.control_l3(pares, 60)[0])
        self.assertFalse(L.control_l3(L.contar_por_ip_ventana(filas[1:], 60, 404), 60)[0])

    def test_maximo_deslizante(self):
        inicios = [30 + i * 0.4 for i in range(60)] + [60 + i * 0.4 for i in range(60)]
        self.assertEqual(L.maximo_deslizante({"a": inicios}, 60)[0], 120)
        self.assertEqual(L.maximo_deslizante({"a": [0.0, 1.0, 61.0]}, 60)[0], 2)

    def test_percentil(self):
        self.assertEqual(L.percentil([10, 20, 30, 40], 50), 20)
        self.assertEqual(L.percentil(list(range(1, 101)), 95), 95)
        self.assertIsNone(L.percentil([], 50))

    def test_busca_tal_cual_y_codificado(self):
        literales = {"texto": "Humo de recuperación 1"}
        for contenido in (b"xx Humo de recuperaci\xc3\xb3n 1 yy", b"Humo%20de%20recuperaci%C3%B3n%201",
                          b'{"t": "Humo de recuperaci\\u00f3n 1"}'):
            self.assertEqual(L.buscar_en_bytes(contenido, literales), ["texto"])
        self.assertEqual(L.buscar_en_bytes(b"nada que ver", literales), [])

    def test_patron_de_codigo(self):
        patrones = [("codigo", L.PATRON_CODIGO)]
        self.assertEqual(L.buscar_en_bytes(b"x ABCD-EFGH-IJKL-MNOP-QRST-UVWX-2345-6723 y", {}, patrones), ["codigo"])
        self.assertEqual(L.buscar_en_bytes(b"ABCD-EFGH-IJKL", {}, patrones), [])
        self.assertRegex(L.codigo_inexistente(), r"^[A-Z2-7]{4}(-[A-Z2-7]{4}){7}$")

    def test_escaneo_por_trozos_con_solape(self):
        with tempfile.TemporaryDirectory() as d:
            ruta = pathlib.Path(d) / "grande.txt"
            ruta.write_bytes(b"a" * 1000 + b"SECRETO-XYZ" + b"b" * 1000)
            self.assertEqual(L.escanear_fichero(ruta, {"s": "SECRETO-XYZ"}, trozo=1005, solape=64), ["s"])

    def test_es_429(self):
        self.assertTrue(L.es_429(r429(0.0, ra="60"), 60))
        self.assertFalse(L.es_429(r429(0.0, ra="61"), 60))
        sin_cabecera = r429(0.0)
        del sin_cabecera["cabeceras"]["x-content-type-options"]
        self.assertFalse(L.es_429(sin_cabecera, 60))


class Q12Loggers(unittest.TestCase):
    def test_los_tres_loggers_y_otro_no(self):
        ventanas = {"p1": (DIA + 100, DIA + 200)}
        cola = " EVENTO limitador_no_disponible: X causa=pool_agotado espera=>0.5"
        for logger in ("canario.limitador", "canario.personal", "canario.externo"):
            texto = f"CANARIO_Q12_INICIO\n2026-11-25T00:02:30Z ERROR {logger}:{cola}\nCANARIO_Q12_FIN\n"
            self.assertEqual(L.analizar_q12(texto, ventanas)[0], "SIN CONCLUSION", logger)
            self.assertEqual(L.analizar_q12(texto, ventanas)[2]["por_prueba"], {"p1": 1})
        # Control: un logger que no escribe el evento es una línea fuera de formato.
        texto = f"CANARIO_Q12_INICIO\n2026-11-25T00:02:30Z ERROR canario.otro:{cola}\nCANARIO_Q12_FIN\n"
        self.assertIn("fuera de formato", L.analizar_q12(texto, ventanas)[1])


class CarpetaYPortapapeles(unittest.TestCase):
    def test_carpeta_personal_con_las_dos_barras(self):
        lit = L.literales_carpeta_personal("C:\\Users\\Persona")
        self.assertEqual(lit["carpeta_personal_barras"], "C:/Users/Persona")
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            (d / "salida.txt").write_text("ruta C:/Users/Persona/AppData\n", encoding="utf-8")
            reales, faltan = L.escanear_con_centinela(d, lit, [])
            self.assertEqual((reales, faltan), ({"salida.txt": ["carpeta_personal_barras"]}, []))

    def test_portapapeles(self):
        self.assertTrue(L.evaluar_portapapeles({"AllowClipboardHistory": 0, "AllowCrossDeviceClipboard": 0})[0])
        for valores in ({}, {"AllowClipboardHistory": 0}, {"AllowClipboardHistory": 0, "AllowCrossDeviceClipboard": 1}):
            confirmado, texto = L.evaluar_portapapeles(valores)
            self.assertFalse(confirmado, valores)
            self.assertIn("declaracion del autor", texto)

    def test_aviso_visible_y_declaracion_obligatoria(self):
        salida = SalidaFalsa()
        ctx = SimpleNamespace(args=SimpleNamespace(portapapeles_sin_historial=True), salida=salida)
        L.confirmar_portapapeles(ctx, leer=lambda: {"AllowClipboardHistory": None, "AllowCrossDeviceClipboard": None})
        self.assertTrue(any(x.startswith("   AVISO PORTAPAPELES: ") for x in salida.lineas))
        self.assertIs(salida.resumen["portapapeles_confirmado_por_registro"], False)
        with self.assertRaises(L.Parada):
            L.confirmar_portapapeles(SimpleNamespace(args=SimpleNamespace(portapapeles_sin_historial=False),
                                                     salida=SalidaFalsa()), leer=dict)


class SalidaFalsa:
    def __init__(self):
        self.lineas, self.filas, self.resumen, self.veredictos = [], [], {}, {}

    def p(self, texto):
        self.lineas.append(texto)

    def veredicto(self, prueba, v, texto):
        self.veredictos[prueba] = (v, texto)

    def fila(self, *args, **kwargs):
        self.filas.append(args)


class ConexionRed(Falsa):
    def __init__(self, red):
        super().__init__()
        self.red = red


class OrdenP1(unittest.TestCase):
    """prueba_p1 con conexiones falsas: B abre su TLS antes y envía sus 5
    justo después de la 61.ª de A."""

    def test_orden_real(self):
        llamadas, n_a, t = [], [0], [60.5]
        reloj = SimpleNamespace(ahora=lambda: 30.0, dormir_hasta=lambda *a, **k: True)

        def peticion(con, reloj_, metodo, ruta, cuerpo=None, cabeceras=(), **k):
            llamadas.append((con.red, metodo, ruta))
            t[0] += 0.01
            if con.red == "A" and ruta == L.RUTA_SEGUIMIENTO:
                n_a[0] += 1
                res = r404(t[0]) if n_a[0] <= 60 else r429(t[0])
            else:
                res = r404(t[0], red=con.red)
            res["ms"] = 10.0
            return res

        ctx = SimpleNamespace(args=SimpleNamespace(rol=None, frontera_utc=None), reloj=reloj, salida=SalidaFalsa(),
                              conexion=lambda red, sitio="api": ConexionRed(red),
                              consultar_ip=lambda red: {"A": "198.51.100.1", "B": "203.0.113.1"}[red])
        with mock.patch.object(L, "peticion", peticion), \
                mock.patch.object(L, "abrir_prueba", lambda c, p: {"a1": (0.0, 0.3), "ips": {}, "inicio_local": 0}), \
                mock.patch.object(L, "cerrar_prueba", lambda c, p, e: ((0.0, 0.3), "")), \
                mock.patch.object(L, "esperar_frontera", lambda *a, **k: 60.0):
            L.prueba_p1(ctx)
        posts = [red for red, metodo, ruta in llamadas if ruta == L.RUTA_SEGUIMIENTO]
        self.assertEqual(llamadas[0], ("B", "GET", L.RUTA_SALUD))
        self.assertEqual(posts, ["A"] * 61 + ["B"] * 5 + ["A"] * 9)
        self.assertEqual(ctx.salida.veredictos["P1"][0], "PASA")


class RolesYCombinar(unittest.TestCase):
    def test_roles_en_argumentos(self):
        self.assertEqual(L.redes_de("p1", "a"), "A")
        self.assertEqual(L.redes_de("p6", "b"), "B")
        base = ["--destino", "produccion", "--franja-autorizada", "19:00-21:00", "--origen-a", "192.168.1.2"]
        with self.assertRaises(L.Parada):
            L.validar_argumentos(L.analizar_argumentos(["--prueba", "p1", "--rol", "a", *base]))
        with self.assertRaises(L.Parada):
            L.validar_argumentos(L.analizar_argumentos(["--prueba", "p2", "--rol", "a", *base]))
        L.validar_argumentos(L.analizar_argumentos(["--prueba", "p1", "--rol", "a", "--frontera-utc", "19:30", *base]))

    def preparar(self, d, head_b="abc", ip_b="203.0.113.20", b_429=False):
        a = [r404(62.0 + i * 0.05) for i in range(60)] + [r429(66.0 + i * 0.05) for i in range(10)]
        b = [r404(92.0 + i * 0.05, red="B") for i in range(5)]
        if b_429:
            b[4] = r429(92.3, red="B")
        for nombre, rol, head, filas in (("a", "a", "abc", a), ("b", "b", head_b, b)):
            (d / nombre).mkdir()
            resumen = {"head": head, "porcelana_vacia": True, "rol": rol, "prueba": "p1",
                       "filas_combinar": L.filas_para_combinar(filas, (0.0, 0.0))}
            (d / nombre / "resumen.json").write_text(json.dumps(resumen), encoding="utf-8")
        (d / "ips_a.txt").write_text("2026-11-25T19:00:00 p1 A 198.51.100.10\n", encoding="utf-8")
        (d / "ips_b.txt").write_text(f"2026-11-25T19:00:00 p1 B {ip_b}\n", encoding="utf-8")
        args = SimpleNamespace(combinar=(str(d / "a"), str(d / "b")), ips_a=str(d / "ips_a.txt"),
                               ips_b=str(d / "ips_b.txt"), p0_revisado=True)
        return SimpleNamespace(args=args, salida=SalidaFalsa(), patrones_fuga=[])

    def test_combinar_p1(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = self.preparar(pathlib.Path(d))
            L.combinar(ctx)
            self.assertEqual(ctx.salida.veredictos["P1"][0], "PASA")
        with tempfile.TemporaryDirectory() as d:
            ctx = self.preparar(pathlib.Path(d), b_429=True)
            L.combinar(ctx)
            self.assertEqual(ctx.salida.veredictos["P1"][0], "FALLA")

    def test_combinar_se_niega(self):
        for cambios in ({"head_b": "otro"}, {"ip_b": "198.51.100.10"}):
            with tempfile.TemporaryDirectory() as d:
                with self.assertRaises(L.Parada, msg=cambios):
                    L.combinar(self.preparar(pathlib.Path(d), **cambios))


class RespuestaFalsa:
    status = 413

    def getheaders(self):
        return [("Content-Type", "application/json")]

    def read(self, n):
        return C413


class ConexionP3(Falsa):
    def __init__(self, respuesta):
        super().__init__()
        self.respuesta = respuesta

    def putrequest(self, *a, **k):
        pass

    def putheader(self, *a):
        pass

    def endheaders(self, cuerpo=None):
        raise ConnectionResetError("reset durante el envio")

    def getresponse(self):
        if self.respuesta is None:
            raise ConnectionResetError("reset al leer")
        return self.respuesta


class PeticionP3(unittest.TestCase):
    def test_reset_al_enviar_y_413_leido(self):
        con = ConexionP3(RespuestaFalsa())
        res = L.peticion_p3(con, L.Reloj(), b"x" * 10)
        self.assertEqual(res["estado"], 413)
        self.assertEqual(res["cuerpo"], C413)
        self.assertIn("envio: ConnectionResetError", res["error"])
        self.assertIsNotNone(res["segundos"])
        self.assertTrue(con.cerrada)
        # Control: si tampoco se puede leer, no hay estado ni tiempo.
        con = ConexionP3(None)
        res = L.peticion_p3(con, L.Reloj(), b"x" * 10)
        self.assertEqual((res["estado"], res["segundos"]), (0, None))
        self.assertTrue(con.cerrada)


if __name__ == "__main__":
    unittest.main()
