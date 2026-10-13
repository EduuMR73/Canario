"""Pruebas unitarias de la lógica pura de app/instruccion.py: la redacción
(art. 32.2), el cursor del listado y la máquina de estados.

La redacción es destructiva e irreversible: un error de posición dejaría a la
vista un dato que había que suprimir, o taparía otro. Por eso los oráculos
son los textos de salida completos, escritos a mano.
"""
import datetime
import types
import unittest
import uuid

from app import instruccion, personal

UUID_CURSOR = "0f8fad5b-d9cb-469f-a165-70867728950e"


class Tachar(unittest.TestCase):
    def test_un_tramo(self):
        self.assertEqual(instruccion.tachar("hola mundo", [(5, "mundo")]), "hola █████")

    def test_orden_de_los_tramos_indiferente(self):
        tramos = [(0, "hola"), (5, "mundo")]
        self.assertEqual(instruccion.tachar("hola mundo", tramos), "████ █████")
        self.assertEqual(instruccion.tachar("hola mundo", list(reversed(tramos))), "████ █████")

    def test_tramos_solapados_se_unen(self):
        # Cada tramo se compara con el original, no con el texto ya tachado.
        self.assertEqual(instruccion.tachar("hola mundo", [(0, "hola m"), (3, "a mun")]), "████████do")

    def test_conserva_la_longitud_y_sin_tramos_no_cambia(self):
        texto = "a\nb\tc 😀"
        self.assertEqual(len(instruccion.tachar(texto, [(0, "a\nb")])), len(texto))
        self.assertEqual(instruccion.tachar(texto, []), texto)

    def test_cuenta_en_puntos_de_codigo(self):
        # Fuera del plano básico, un carácter es 1 posición aquí y 2 en UTF-16.
        self.assertEqual(instruccion.tachar("a😀b", [(1, "😀"), (2, "b")]), "a██")
        with self.assertRaises(instruccion.FragmentoNoCoincide):
            # La posición de "b" contada en UTF-16 sería 3.
            instruccion.tachar("a😀b", [(3, "b")])

    def test_final_exacto(self):
        self.assertEqual(instruccion.tachar("hola mundo", [(9, "o")]), "hola mund█")  # control
        for desde, fragmento in ((10, "o"), (6, "mundo"), (9, "o!")):
            with self.subTest(desde=desde, fragmento=fragmento), self.assertRaises(instruccion.FragmentoNoCoincide):
                instruccion.tachar("hola mundo", [(desde, fragmento)])

    def test_desde_negativo(self):
        # texto[-5:-2] es "mun": sin la comprobación de desde >= 0, este tramo
        # coincidiría y se tacharía contando desde el final.
        with self.assertRaises(instruccion.FragmentoNoCoincide):
            instruccion.tachar("hola mundo", [(-5, "mun")])
        self.assertEqual(instruccion.tachar("hola mundo", [(5, "mun")]), "hola ███do")  # control

    def test_fragmento_vacio_o_distinto(self):
        for desde, fragmento in ((0, ""), (0, "Hola"), (1, "hola")):
            with self.subTest(fragmento=fragmento), self.assertRaises(instruccion.FragmentoNoCoincide):
                instruccion.tachar("hola mundo", [(desde, fragmento)])

    def test_un_tramo_malo_invalida_toda_la_peticion(self):
        with self.assertRaises(instruccion.FragmentoNoCoincide):
            instruccion.tachar("hola mundo", [(0, "hola"), (5, "mundO")])

    def test_volver_a_tachar_lo_tachado_es_idempotente(self):
        self.assertEqual(instruccion.tachar("████ mundo", [(0, "████")]), "████ mundo")


class Cursor(unittest.TestCase):
    def test_forma_exacta(self):
        self.assertEqual(instruccion.leer_cursor(f"2026-10-12.{UUID_CURSOR}"),
                         (datetime.date(2026, 10, 12), uuid.UUID(UUID_CURSOR)))

    def test_rechazados(self):
        rechazados = {
            "fecha compacta": f"20261012.{UUID_CURSOR}",
            "fecha imposible": f"2026-13-45.{UUID_CURSOR}",
            "uuid en mayusculas": f"2026-10-12.{UUID_CURSOR.upper()}",
            "uuid sin guiones": f"2026-10-12.{UUID_CURSOR.replace('-', '')}",
            "salto final": f"2026-10-12.{UUID_CURSOR}\n",
            "espacio inicial": f" 2026-10-12.{UUID_CURSOR}",
            # \d de un patrón str casa con dígitos no ASCII; fromisoformat los rechaza.
            "digitos arabes": "\u0662\u0660\u0662\u0666-\u0661\u0660-\u0661\u0662." + UUID_CURSOR,
            "vacio": "",
        }
        for motivo, texto in rechazados.items():
            with self.subTest(motivo=motivo):
                with self.assertRaises(instruccion.CursorNoValido) as error:
                    instruccion.leer_cursor(texto)
                self.assertEqual(str(error.exception), "cursor no valido")


class MaquinaDeEstados(unittest.TestCase):
    """Invariantes que el resto del módulo da por ciertas."""

    def test_transiciones_literales(self):
        self.assertEqual(instruccion.TRANSICIONES, {
            "nueva": ("en_instruccion", "inadmitida", "no_veraz"),
            "en_instruccion": ("resuelta", "archivada", "no_veraz"),
            "resuelta": ("no_veraz",),
            "archivada": ("no_veraz",),
            "inadmitida": ("no_veraz",),
        })

    def test_no_veraz_no_es_un_estado_visible_ni_se_sale_de_el(self):
        self.assertNotIn("no_veraz", instruccion.ESTADOS)
        self.assertNotIn("no_veraz", instruccion.TRANSICIONES)
        self.assertTrue(all("no_veraz" in destinos for destinos in instruccion.TRANSICIONES.values()))

    def test_destinos_coherentes(self):
        todos = {d for destinos in instruccion.TRANSICIONES.values() for d in destinos}
        self.assertEqual(set(instruccion.ESTADOS_DESTINO), todos)
        self.assertEqual(set(instruccion.TRANSICIONES), set(instruccion.ESTADOS))
        self.assertTrue(set(instruccion.ESTADOS_CERRADOS) <= set(instruccion.ESTADOS))


class GuardasPreviasALaBaseDeDatos(unittest.TestCase):
    """Lo que se rechaza antes de abrir ninguna transacción: con pool=None, si
    la función llegara a la base de datos fallaría con otro error."""

    INSTRUCTOR = types.SimpleNamespace(rol="instructor", usuario_id=uuid.UUID(int=9), empresa_id=uuid.UUID(int=1))
    ADMIN = types.SimpleNamespace(rol="admin", usuario_id=uuid.UUID(int=8), empresa_id=uuid.UUID(int=1))

    def test_solo_admin(self):
        llamadas = {
            "listar_auditoria": lambda s: instruccion.listar_auditoria(None, s, 1),
            "verificar_auditoria": lambda s: instruccion.verificar_auditoria(None, s),
            "asignar": lambda s: instruccion.asignar(None, s, uuid.UUID(int=3), uuid.UUID(int=9)),
            "redactar_denuncia": lambda s: instruccion.redactar_denuncia(None, None, s, uuid.UUID(int=3), [(0, "a")]),
            "redactar_mensaje": lambda s: instruccion.redactar_mensaje(None, None, s, uuid.UUID(int=3), 1,
                                                                       [(0, "a")]),
        }
        for nombre, llamada in llamadas.items():
            with self.subTest(funcion=nombre), self.assertRaises(personal.Prohibido):
                llamada(self.INSTRUCTOR)

    def test_cambiar_estado_orden_de_comprobaciones(self):
        denuncia = uuid.UUID(int=3)
        casos = (
            (self.ADMIN, "nueva", "m", ValueError),
            (self.INSTRUCTOR, "no_veraz", "m", personal.Prohibido),
            (self.ADMIN, "no_veraz", "m", instruccion.MensajeNoPermitido),
            (self.ADMIN, "resuelta", None, instruccion.MensajeFinalObligatorio),
        )
        for sesion, nuevo, mensaje, excepcion in casos:
            with self.subTest(rol=sesion.rol, nuevo=nuevo), self.assertRaises(excepcion):
                instruccion.cambiar_estado(None, None, sesion, denuncia, nuevo, mensaje)

    def test_listar_filtro_y_cursor(self):
        with self.assertRaises(ValueError) as error:
            instruccion.listar_denuncias(None, self.ADMIN, estado="no_veraz")
        self.assertEqual(str(error.exception), "estado desconocido")
        with self.assertRaises(instruccion.CursorNoValido):
            instruccion.listar_denuncias(None, self.ADMIN, cursor="x")
