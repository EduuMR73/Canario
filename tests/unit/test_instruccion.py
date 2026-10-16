"""Pruebas unitarias de la lógica pura de app/instruccion.py: la redacción
(art. 32.2), el cursor del listado, la máquina de estados y quién puede qué
(los roles, antes de tocar la base de datos, y a quién se asigna una denuncia).

La redacción es destructiva e irreversible: un error de posición dejaría a la
vista un dato que había que suprimir, o taparía otro. Por eso los oráculos
son los textos de salida completos, escritos a mano.
"""
import contextlib
import datetime
import types
import unittest
import uuid
from unittest import mock

import psycopg

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
    AUDITOR = types.SimpleNamespace(rol="auditor", usuario_id=uuid.UUID(int=7), empresa_id=uuid.UUID(int=1))

    def pasa_la_puerta(self, llamada, sesion):
        """Control: con pool=None, quien pasa la puerta por rol falla después,
        al usar la base de datos, con un error que no es Prohibido."""
        with self.assertRaises(Exception) as error:
            llamada(sesion)
        self.assertNotIsInstance(error.exception, personal.Prohibido)

    def test_solo_admin(self):
        llamadas = {
            "asignar": lambda s: instruccion.asignar(None, s, uuid.UUID(int=3), uuid.UUID(int=9)),
            "redactar_denuncia": lambda s: instruccion.redactar_denuncia(None, None, s, uuid.UUID(int=3), [(0, "a")]),
            "redactar_mensaje": lambda s: instruccion.redactar_mensaje(None, None, s, uuid.UUID(int=3), 1,
                                                                       [(0, "a")]),
        }
        for nombre, llamada in llamadas.items():
            for sesion in (self.INSTRUCTOR, self.AUDITOR):
                with self.subTest(funcion=nombre, rol=sesion.rol), self.assertRaises(personal.Prohibido):
                    llamada(sesion)

    def test_auditoria_para_admin_y_auditor(self):
        llamadas = {
            "listar_auditoria": lambda s: instruccion.listar_auditoria(None, s, 1),
            "verificar_auditoria": lambda s: instruccion.verificar_auditoria(None, s),
        }
        for nombre, llamada in llamadas.items():
            with self.subTest(funcion=nombre, rol="instructor"), self.assertRaises(personal.Prohibido):
                llamada(self.INSTRUCTOR)
            for sesion in (self.AUDITOR, self.ADMIN):
                with self.subTest(funcion=nombre, rol=sesion.rol):
                    self.pasa_la_puerta(llamada, sesion)

    def test_el_auditor_no_toca_ninguna_denuncia(self):
        denuncia = uuid.UUID(int=3)
        llamadas = {
            "listar_denuncias": lambda s: instruccion.listar_denuncias(None, s),
            "leer_denuncia": lambda s: instruccion.leer_denuncia(None, None, s, denuncia),
            "enviar_mensaje": lambda s: instruccion.enviar_mensaje(None, None, s, denuncia, "hola"),
            "cambiar_estado": lambda s: instruccion.cambiar_estado(None, None, s, denuncia, "en_instruccion", None),
        }
        for nombre, llamada in llamadas.items():
            with self.subTest(funcion=nombre, rol="auditor"), self.assertRaises(personal.Prohibido):
                llamada(self.AUDITOR)
            with self.subTest(funcion=nombre, rol="instructor"):
                self.pasa_la_puerta(llamada, self.INSTRUCTOR)

    def test_roles_literales(self):
        # Oráculo literal: quién instruye y quién lee la auditoría. Añadir un
        # rol a una de estas listas es una decisión, no un efecto secundario.
        self.assertEqual(personal.ROLES, ("admin", "instructor", "auditor"))
        self.assertEqual(personal.ROLES_INSTRUCCION, ("admin", "instructor"))
        self.assertEqual(personal.ROLES_AUDITORIA, ("admin", "auditor"))

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


class _ErrorAsignacion(psycopg.Error):
    """El error del trigger canal.controlar_asignacion_denuncia, con su SQLSTATE."""
    sqlstate = "CN004"


class _ConexionAsignar:
    """Doble de la conexión de asignar: el admin que actúa, el destino con su
    rol y una denuncia abierta sin asignar. Registra las sentencias."""

    def __init__(self, rol_destino, error_al_asignar=None):
        self.rol_destino, self.error_al_asignar = rol_destino, error_al_asignar
        self.sentencias = []

    def execute(self, sql, parametros=None):
        self.sentencias.append(sql)
        respuesta = mock.Mock()
        if sql == instruccion.SQL_BLOQUEAR_ADMINS:
            respuesta.fetchall.return_value = [(Asignar.ADMIN.usuario_id, True)]
        elif sql == instruccion.SQL_BLOQUEAR_DESTINO:
            respuesta.fetchone.return_value = (True, self.rol_destino)
        elif sql == instruccion.SQL_BLOQUEAR_DENUNCIA:
            respuesta.fetchone.return_value = ("nueva", None)
        elif sql == instruccion.SQL_ASIGNAR and self.error_al_asignar is not None:
            raise self.error_al_asignar
        return respuesta


class Asignar(unittest.TestCase):
    """Asignar da acceso al contenido: solo a un rol que instruye."""
    ADMIN = types.SimpleNamespace(rol="admin", usuario_id=uuid.UUID(int=8), empresa_id=uuid.UUID(int=1))

    def asignar(self, conexion):
        @contextlib.contextmanager
        def transaccion(_pool, _empresa_id, solo_lectura=False):
            yield conexion

        with mock.patch.object(instruccion.bd, "transaccion_empresa", transaccion):
            instruccion.asignar(None, self.ADMIN, uuid.UUID(int=3), uuid.UUID(int=9))

    def test_a_un_auditor_no_y_sin_escribir_nada(self):
        conexion = _ConexionAsignar("auditor")
        with self.assertRaises(instruccion.DestinoNoValido):
            self.asignar(conexion)
        self.assertNotIn(instruccion.SQL_ASIGNAR, conexion.sentencias)
        self.assertNotIn(instruccion.SQL_AUDITAR, conexion.sentencias)
        # Control: a un instructor, sí, con su fila de auditoría.
        conexion = _ConexionAsignar("instructor")
        self.asignar(conexion)
        self.assertIn(instruccion.SQL_ASIGNAR, conexion.sentencias)
        self.assertIn(instruccion.SQL_AUDITAR, conexion.sentencias)

    def test_el_rechazo_de_la_base_de_datos_es_el_mismo_409(self):
        # Si la comprobación de la API no lo parase, el trigger lo para: la
        # respuesta es DestinoNoValido (409), no un 500. Otro error de la base
        # de datos sigue su camino.
        with self.assertRaises(instruccion.DestinoNoValido):
            self.asignar(_ConexionAsignar("instructor", _ErrorAsignacion("trigger")))
        with self.assertRaises(psycopg.OperationalError):
            self.asignar(_ConexionAsignar("instructor", psycopg.OperationalError("otro")))
