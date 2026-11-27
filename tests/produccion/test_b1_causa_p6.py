"""Pruebas de tests/produccion/b1_causa_p6.py con filas SINTÉTICAS: ninguna
lee una salida real de P6, ni abre la red, ni llama a git (subprocess se
sustituye). Desde la raíz del repo:

    python -m unittest tests.produccion.test_b1_causa_p6 -v

Cada oráculo es un literal escrito aquí y calculado a mano en el comentario
de cada escenario (ventanas de 60 s: la 100 es [6000; 6060), la 101 es
[6060; 6120) y la 102 es [6120; 6180)), no derivado del script. Las columnas
del CSV, el HEAD y el SHA-256 también son literales. Cada comprobación
negativa lleva su control positivo en la misma prueba; si el control no da lo
esperado, la prueba falla con "SIN CONCLUSION", nunca pasa.
"""
import contextlib
import csv
import io
import json
import pathlib
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import b1_causa_p6 as B  # noqa: E402

# Literales: HEAD de 4ec7d90 (git rev-parse) y SHA-256 de
# `git show 4ec7d90:tests/produccion/lanzar.py`, medidos el 27/11/2026.
HEAD = "4ec7d90aae264f228d52abb96445eec8d06f3b02"
SHA = "e3bf7913f08ea028f63559f53ea958a2a54fc3f4bd6c4d0551a1dde7361b9989"
# COLUMNAS_CSV de lanzar.py en 4ec7d90 (:1437-1438), escritas aquí otra vez.
COLUMNAS = ("prueba", "red", "ruta", "planeada", "real", "inicio_servidor", "fin_servidor", "estado", "ms",
            "retry_after", "ambigua", "nota")
SEGUIMIENTO = "/v1/seguimiento"

# Escenarios de A1 (d_min, d_max):
# * FIN: el final se va hacia arriba; envolvente [0,0; 0,5] (lado fin).
# * INICIO: el final se va hacia abajo; envolvente [-0,2; 0,3] (lado inicio).
# * QUIETO: inicial = final = envolvente = [0,0; 0,3] (sin deriva).
FIN = ((0.0, 0.3), (0.2, 0.5), (0.0, 0.5))
INICIO = ((0.0, 0.3), (-0.2, 0.1), (-0.2, 0.3))
QUIETO = ((0.0, 0.3), (0.0, 0.3), (0.0, 0.3))


def fila(ini, fin, env, ambigua, estado=404, hueco=0.0, ms=None):
    """Fila de A enviada, tal como la escribe Salida.fila: hora del servidor =
    hora local + envolvente, `real` con %.6f y `ms` con %.3f. hueco es
    inicio_local - real (negativo: la fila empieza antes de su real)."""
    real = ini - hueco
    return {"prueba": "p6", "red": "A", "ruta": SEGUIMIENTO, "planeada": f"{real - 0.001:.6f}",
            "real": f"{real:.6f}", "inicio_servidor": f"{ini + env[0]:.6f}", "fin_servidor": f"{fin + env[1]:.6f}",
            "estado": str(estado), "ms": f"{(fin - ini) * 1000:.3f}" if ms is None else ms, "retry_after": "",
            "ambigua": ambigua, "nota": ""}


def ajenas():
    """Filas que el script tiene que saltarse: A1 (ruta del CSS, sin real),
    una omitida y un descarte (sin real ni hora del servidor), una de B y una
    sonda."""
    vacia = dict.fromkeys(COLUMNAS, "")
    return [dict(vacia, prueba="p6", red="A", ruta="/estatico/canario.css", estado="200", ms="12.000",
                 nota="A1 inicial"),
            dict(vacia, prueba="p6", red="A", ruta=SEGUIMIENTO, planeada="6059.500000",
                 nota="omitida por la guarda (D10)"),
            dict(vacia, prueba="p6", red="A", ruta=SEGUIMIENTO, planeada="6059.600000", nota="descarte"),
            dict(vacia, prueba="p6", red="B", ruta=SEGUIMIENTO, planeada="6059.000000", real="6059.000000",
                 inicio_servidor="6059.000000", fin_servidor="6060.300000", estado="404", ms="1000.000",
                 ambigua="1"),
            dict(vacia, prueba="p6", red="vecina_1", ruta="sonda", planeada="6040.000000", real="6040.000000",
                 estado="200", ms="5.000", nota="carga")]


def rellenos(env, hueco=0.0, ms=None):
    """Tres 404 no ambiguas de 50 ms en 6030, 6031 y 6032 (ventana 100 con
    cualquiera de las tres envolventes: como mucho [6029,8; 6032,55])."""
    return [fila(6030.0 + i, 6030.05 + i, env, "0", hueco=hueco, ms=ms) for i in range(3)]


def escenario(a1, ambiguas, relleno=None, extra=(), **resumen_extra):
    inicial, final, env = a1
    filas = ajenas() + (rellenos(env) if relleno is None else relleno) + ambiguas + list(extra)
    resumen = {"head": HEAD, "sha256_lanzar": SHA, "prueba": "p6",
               "a1": {"p6": {"inicial": list(inicial), "final": list(final), "envolvente": list(env)}}}
    resumen.update(resumen_extra)
    return filas, resumen


# Las cuatro combinaciones, cada una con dos ambiguas (en las ventanas 100 y
# 101; la 2.ª es la 1.ª desplazada 60 s). Guarda de 4ec7d90 con el A1
# inicial [0,0; 0,3]: deja lanzar en t si t + 0,3 + 1,001 <= frontera
# siguiente, es decir, hasta 6058,699 en la ventana 100.
def solo_a_fin(hueco_amb=0.0):
    # [6058,5; 6059,6]: inicial -> [6058,5; 6059,9], no ambigua; envolvente ->
    # [6058,5; 6060,1], ambigua por el fin. Guarda en 6058,5: 6059,801 <= 6060,
    # la deja pasar. Solo (a), lado fin.
    return [fila(6058.5, 6059.6, FIN[2], "1", hueco=hueco_amb), fila(6118.5, 6119.6, FIN[2], "1")]


def solo_b():
    # [6059,0; 6059,8] sin deriva: [6059,0; 6060,1], ambigua con el inicial.
    # Guarda en 6059,0: 6060,301 > 6060, la rechaza. Solo (b).
    return [fila(6059.0, 6059.8, QUIETO[2], "1"), fila(6119.0, 6119.8, QUIETO[2], "1")]


def las_dos():
    # [6058,8; 6059,6]: inicial -> [6058,8; 6059,9], no ambigua; envolvente ->
    # [6058,8; 6060,1], ambigua. Guarda en 6058,8: 6060,101 > 6060, la rechaza.
    return [fila(6058.8, 6059.6, FIN[2], "1"), fila(6118.8, 6119.6, FIN[2], "1")]


def ninguna():
    # [6058,0; 6059,8] (1,8 s): inicial -> [6058,0; 6060,1], ya ambigua.
    # Guarda en 6058,0: 6059,301 <= 6060, la deja pasar. Ninguna.
    return [fila(6058.0, 6059.8, FIN[2], "1"), fila(6118.0, 6119.8, FIN[2], "1")]


def solo_a_inicio():
    # [6060,1; 6060,5]: inicial -> [6060,1; 6060,8], ventana 101 sin cruzar;
    # envolvente [-0,2; 0,3] -> [6059,9; 6060,8], ambigua por el inicio.
    # Guarda en 6060,1: 6061,401 <= 6120, la deja pasar. Solo (a), lado inicio.
    return [fila(6060.1, 6060.5, INICIO[2], "1"), fila(6120.1, 6120.5, INICIO[2], "1")]


class Base(unittest.TestCase):
    def control(self, condicion, texto):
        """Control positivo: si no se cumple, la prueba no puede pasar."""
        if not condicion:
            self.fail(f"SIN CONCLUSION: {texto}")

    def analizar(self, filas_resumen, sha=SHA):
        filas, resumen = filas_resumen
        return B.analizar(filas, resumen, sha)


class Combinaciones(Base):
    def test_solo_a_lado_fin(self):
        v, lineas = self.analizar(escenario(FIN, solo_a_fin()))
        self.assertEqual(v, "HECHO")
        texto = "\n".join(lineas)
        self.assertEqual(texto.count("resultado: solo (a)"), 2)
        self.assertEqual(texto.count("lado fin (d_max_final 0.500000 > d_max_inicial 0.300000)"), 2)
        self.assertNotIn("lado inicio", texto)

    def test_solo_a_lado_inicio(self):
        v, lineas = self.analizar(escenario(INICIO, solo_a_inicio()))
        self.assertEqual(v, "HECHO")
        texto = "\n".join(lineas)
        self.assertEqual(texto.count("resultado: solo (a)"), 2)
        self.assertEqual(texto.count("lado inicio (d_min_final -0.200000 < d_min_inicial 0.000000)"), 2)
        self.assertNotIn("lado fin", texto)

    def test_solo_b(self):
        v, lineas = self.analizar(escenario(QUIETO, solo_b()))
        self.assertEqual(v, "HECHO")
        self.assertEqual("\n".join(lineas).count("resultado: solo (b)"), 2)

    def test_las_dos(self):
        v, lineas = self.analizar(escenario(FIN, las_dos()))
        self.assertEqual(v, "HECHO")
        self.assertEqual("\n".join(lineas).count("resultado: las dos"), 2)

    def test_ninguna_es_parada_y_control_las_dos(self):
        # Control: misma envolvente y mismas ventanas, otra duración: HECHO.
        v, _ = self.analizar(escenario(FIN, las_dos()))
        self.control(v == "HECHO", "el escenario de control no da HECHO")
        v, lineas = self.analizar(escenario(FIN, ninguna()))
        self.assertEqual(v, "PARADA")
        self.assertEqual("\n".join(lineas).count("resultado: ninguna"), 2)

    def test_una_ninguna_basta_para_parada(self):
        mezcla = [solo_a_fin()[0], ninguna()[1]]
        v, lineas = self.analizar(escenario(FIN, mezcla))
        self.assertEqual(v, "PARADA")
        texto = "\n".join(lineas)
        self.assertIn("resultado: solo (a)", texto)
        self.assertIn("resultado: ninguna", texto)

    def test_429_ambigua_no_cuenta(self):
        # Una 429 de [6178,9; 6179,6] con la envolvente FIN acaba en 6180,1:
        # ambigua, pero no es aceptada y no entra en las 2.
        extra = [fila(6178.9, 6179.6, FIN[2], "1", estado=429)]
        v, _ = self.analizar(escenario(FIN, solo_a_fin()))
        self.control(v == "HECHO", "sin la 429 no da HECHO")
        v, _ = self.analizar(escenario(FIN, solo_a_fin(), extra=extra))
        self.assertEqual(v, "HECHO")


class Identidad(Base):
    def test_head_de_otro_commit(self):
        v, _ = self.analizar(escenario(FIN, solo_a_fin()))
        self.control(v == "HECHO", "con el HEAD de 4ec7d90 no da HECHO")
        v, lineas = self.analizar(escenario(FIN, solo_a_fin(), head="52d0fce1d8e7a0b6c7f0d5c3b9a1e2f3a4b5c6d7"))
        self.assertEqual(v, "SIN CONCLUSION")
        self.assertIn("no empieza por 4ec7d90", lineas[-1])

    def test_sin_head(self):
        filas, resumen = escenario(FIN, solo_a_fin())
        del resumen["head"]
        self.assertEqual(B.analizar(filas, resumen, SHA)[0], "SIN CONCLUSION")

    def test_sha_distinto_o_git_fallido(self):
        v, _ = self.analizar(escenario(FIN, solo_a_fin()), sha=SHA)
        self.control(v == "HECHO", "con el SHA igual no da HECHO")
        otro = "0" * 64
        self.assertEqual(self.analizar(escenario(FIN, solo_a_fin()), sha=otro)[0], "SIN CONCLUSION")
        self.assertEqual(self.analizar(escenario(FIN, solo_a_fin(), sha256_lanzar=otro))[0], "SIN CONCLUSION")
        self.assertEqual(self.analizar(escenario(FIN, solo_a_fin()), sha=None)[0], "SIN CONCLUSION")

    def test_sha_de_git_con_subprocess_sustituido(self):
        # SHA-256 de b"abc" (FIPS 180-2, ejemplo B.1), literal.
        abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        bien = SimpleNamespace(returncode=0, stdout=b"abc", stderr=b"")
        with mock.patch.object(B.subprocess, "run", return_value=bien) as run:
            self.control(B.sha256_lanzador_git(pathlib.Path("raiz")) == abc, "el control con b'abc' no da su SHA")
        self.assertEqual(run.call_args.args[0],
                         ["git", "-C", "raiz", "show", "4ec7d90:tests/produccion/lanzar.py"])
        self.assertNotIn("shell", run.call_args.kwargs)
        for malo in (SimpleNamespace(returncode=128, stdout=b"", stderr=b"fatal"),
                     SimpleNamespace(returncode=128, stdout=b"abc", stderr=b""),
                     SimpleNamespace(returncode=0, stdout=b"", stderr=b"")):
            with mock.patch.object(B.subprocess, "run", return_value=malo):
                self.assertIsNone(B.sha256_lanzador_git(pathlib.Path("raiz")), malo)


class Reconstruccion(Base):
    """Las tres comprobaciones en el borde, con la resolución de 1 µs de las
    columnas (%.6f y %.3f): 9 µs dentro y 11 µs fuera de cada límite de
    10 µs; 9 ms dentro y 11 ms fuera del de 10 ms. Base: solo (a), lado fin,
    que da HECHO."""

    def test_empieza_antes_de_real(self):
        # Un relleno con real 9 µs después del inicio: hueco -9 µs >= -10 µs.
        dentro = rellenos(FIN[2])[:2] + [fila(6032.0, 6032.05, FIN[2], "0", hueco=-0.000009)]
        v, lineas = self.analizar(escenario(FIN, solo_a_fin(), relleno=dentro))
        self.control(v == "HECHO", "con -9 us no da HECHO")
        self.assertIn("1 filas con hueco negativo", "\n".join(lineas))
        fuera = rellenos(FIN[2])[:2] + [fila(6032.0, 6032.05, FIN[2], "0", hueco=-0.000011)]
        v, lineas = self.analizar(escenario(FIN, solo_a_fin(), relleno=fuera))
        self.assertEqual(v, "SIN CONCLUSION")
        self.assertIn("empiezan antes de su real", lineas[-1])
        self.assertIn("1 filas con hueco negativo", lineas[-1])   # se publica también al fallar

    def test_duracion_frente_a_ms(self):
        # Relleno de 50 ms reales: ms 50,009 (9 µs) dentro, 50,011 (11 µs) fuera.
        v, _ = self.analizar(escenario(FIN, solo_a_fin(), relleno=rellenos(FIN[2], ms="50.009")))
        self.control(v == "HECHO", "con 9 us de diferencia no da HECHO")
        v, lineas = self.analizar(escenario(FIN, solo_a_fin(), relleno=rellenos(FIN[2], ms="50.011")))
        self.assertEqual(v, "SIN CONCLUSION")
        self.assertIn("fin - inicio distinto de ms", lineas[-1])

    def test_hueco_de_una_ambigua(self):
        # Rellenos con hueco 0: la mediana es 0 y solo mira la ambigua.
        v, _ = self.analizar(escenario(FIN, solo_a_fin(hueco_amb=0.009)))
        self.control(v == "HECHO", "con 9 ms en la ambigua no da HECHO")
        v, lineas = self.analizar(escenario(FIN, solo_a_fin(hueco_amb=0.011)))
        self.assertEqual(v, "SIN CONCLUSION")
        self.assertIn("ambigua de la linea", lineas[-1])
        self.assertIn("mas de 10 ms", lineas[-1])

    def test_mediana(self):
        # 5 filas: 3 rellenos con hueco h y 2 ambiguas con hueco 0; la mediana
        # es h. Con h = 9 ms, dentro; con 11 ms, fuera (y las ambiguas, bien).
        v, lineas = self.analizar(escenario(FIN, solo_a_fin(), relleno=rellenos(FIN[2], hueco=0.009)))
        self.control(v == "HECHO", "con mediana de 9 ms no da HECHO")
        self.assertIn("mediana 9.000000 ms", "\n".join(lineas))
        v, lineas = self.analizar(escenario(FIN, solo_a_fin(), relleno=rellenos(FIN[2], hueco=0.011)))
        self.assertEqual(v, "SIN CONCLUSION")
        self.assertIn("mediana del hueco 11.000 ms", lineas[-1])
        self.assertNotIn("ambigua de la linea", lineas[-1])

    def test_envolvente_desplazada(self):
        # Lo que el control busca: un resumen con otra envolvente. Con
        # [0,0; 0,5] escrita pero filas hechas con [0,05; 0,5] (inicial
        # [0,05; 0,3], final [0,2; 0,5]), cada inicio local sale 50 ms tarde.
        mal = ((0.05, 0.3), (0.2, 0.5), (0.05, 0.5))
        filas, _ = escenario(mal, [fila(6058.5, 6059.6, mal[2], "1"), fila(6118.5, 6119.6, mal[2], "1")])
        _, resumen = escenario(FIN, [])
        v, _ = self.analizar(escenario(FIN, solo_a_fin()))
        self.control(v == "HECHO", "con la envolvente buena no da HECHO")
        v, lineas = B.analizar(filas, resumen, SHA)
        self.assertEqual(v, "SIN CONCLUSION")
        self.assertIn("mas de 10 ms", lineas[-1])


class DatosYCarpeta(Base):
    def escribir(self, carpeta, filas, resumen, columnas=COLUMNAS):
        with open(carpeta / "peticiones.csv", "w", encoding="utf-8", newline="") as fichero:
            escritor = csv.DictWriter(fichero, fieldnames=columnas, lineterminator="\n")
            escritor.writeheader()
            escritor.writerows(filas)
        (carpeta / "resumen.json").write_text(json.dumps(resumen, indent=2, sort_keys=True) + "\n",
                                              encoding="utf-8", newline="\n")

    def main(self, carpeta):
        salida = io.StringIO()
        with mock.patch.object(B, "sha256_lanzador_git", return_value=SHA), contextlib.redirect_stdout(salida):
            codigo = B.main([str(carpeta)])
        return codigo, salida.getvalue()

    def test_carpeta_sin_ficheros(self):
        with tempfile.TemporaryDirectory() as d:
            carpeta = pathlib.Path(d)
            codigo, texto = self.main(carpeta)
            self.assertEqual(codigo, 2)
            self.assertIn("B1 SIN CONCLUSION: faltan las salidas de P6: peticiones.csv, resumen.json", texto)
            # Control: la misma carpeta con los dos ficheros da HECHO (código 0).
            self.escribir(carpeta, *escenario(FIN, solo_a_fin()))
            codigo, texto = self.main(carpeta)
            self.control(codigo == 0 and "B1 HECHO" in texto, f"con los ficheros no da HECHO: {texto}")

    def test_carpeta_con_un_solo_fichero_o_inexistente(self):
        with tempfile.TemporaryDirectory() as d:
            carpeta = pathlib.Path(d)
            self.escribir(carpeta, *escenario(FIN, solo_a_fin()))
            self.control(self.main(carpeta)[0] == 0, "con los dos ficheros no da HECHO")
            (carpeta / "resumen.json").unlink()
            codigo, texto = self.main(carpeta)
            self.assertEqual(codigo, 2)
            self.assertIn("faltan las salidas de P6: resumen.json", texto)
            self.assertEqual(self.main(carpeta / "no_existe")[0], 2)

    def test_codigo_de_parada(self):
        with tempfile.TemporaryDirectory() as d:
            carpeta = pathlib.Path(d)
            self.escribir(carpeta, *escenario(FIN, las_dos()))
            self.control(self.main(carpeta)[0] == 0, "las dos no da HECHO")
            self.escribir(carpeta, *escenario(FIN, ninguna()))
            codigo, texto = self.main(carpeta)
            self.assertEqual(codigo, 1)
            self.assertIn("B1 PARADA", texto)

    def test_columnas_de_otro_lanzador(self):
        with tempfile.TemporaryDirectory() as d:
            carpeta = pathlib.Path(d)
            self.escribir(carpeta, *escenario(FIN, solo_a_fin()))
            self.control(self.main(carpeta)[0] == 0, "con las columnas de 4ec7d90 no da HECHO")
            otras = COLUMNAS[:-1] + ("comentario",)
            filas, resumen = escenario(FIN, solo_a_fin())
            filas = [{("comentario" if k == "nota" else k): v for k, v in f.items()} for f in filas]
            self.escribir(carpeta, filas, resumen, otras)
            codigo, texto = self.main(carpeta)
            self.assertEqual(codigo, 2)
            self.assertIn("columnas de peticiones.csv", texto)

    def test_numero_de_ambiguas(self):
        v, _ = self.analizar(escenario(FIN, solo_a_fin()))
        self.control(v == "HECHO", "con 2 ambiguas no da HECHO")
        v, lineas = self.analizar(escenario(FIN, solo_a_fin()[:1]))
        self.assertEqual(v, "SIN CONCLUSION")
        self.assertIn("1 aceptadas (404) ambiguas en el CSV", lineas[-1])
        tres = solo_a_fin() + [fila(6178.5, 6179.6, FIN[2], "1")]   # [6178,5; 6180,1]: ambigua
        self.assertEqual(self.analizar(escenario(FIN, tres))[0], "SIN CONCLUSION")

    def test_a1_ausente_o_incoherente(self):
        v, _ = self.analizar(escenario(FIN, solo_a_fin()))
        self.control(v == "HECHO", "con el A1 completo no da HECHO")
        filas, resumen = escenario(FIN, solo_a_fin())
        del resumen["a1"]
        self.assertEqual(B.analizar(filas, resumen, SHA)[0], "SIN CONCLUSION")
        filas, resumen = escenario(FIN, solo_a_fin())
        resumen["a1"]["p6"]["envolvente"] = [0.0, 0.4]   # combinar_a1 da [0,0; 0,5]
        v, lineas = B.analizar(filas, resumen, SHA)
        self.assertEqual(v, "SIN CONCLUSION")
        self.assertIn("no es combinar_a1", lineas[-1])
        filas, resumen = escenario(FIN, solo_a_fin())
        resumen["a1"]["p6"]["final"] = None              # A1 final fallido
        self.assertEqual(B.analizar(filas, resumen, SHA)[0], "SIN CONCLUSION")

    def test_fila_incoherente_o_columna_ambigua_falsa(self):
        v, _ = self.analizar(escenario(FIN, solo_a_fin()))
        self.control(v == "HECHO", "con las filas coherentes no da HECHO")
        # Con real y sin hora del servidor: no se descarta en silencio.
        rota = dict(rellenos(FIN[2])[0], inicio_servidor="", fin_servidor="")
        v, lineas = self.analizar(escenario(FIN, solo_a_fin(), relleno=[rota] + rellenos(FIN[2])[1:]))
        self.assertEqual(v, "SIN CONCLUSION")
        self.assertIn("fila de A con real", lineas[-1])
        # Un relleno de [6030,0; 6030,55] marcado como ambiguo.
        falsa = [fila(6030.0, 6030.05, FIN[2], "1")] + rellenos(FIN[2])[1:]
        v, lineas = self.analizar(escenario(FIN, solo_a_fin(), relleno=falsa))
        self.assertEqual(v, "SIN CONCLUSION")
        self.assertIn("columna ambigua no cuadra", lineas[-1])


if __name__ == "__main__":
    unittest.main()
