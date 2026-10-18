"""Pruebas unitarias de la lógica pura de app/instruccion.py: la redacción
(art. 32.2), el cursor del listado, la máquina de estados, quién puede qué
(los roles, antes de tocar la base de datos, y a quién se asigna una denuncia)
el tope de lecturas (sus fronteras, el orden escribir y contar, y a quién
avisa) y la auditoría por la API (qué acciones llevan una cuenta y dónde, y
las páginas desde lo más reciente).

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

from app import avisos, instruccion, personal

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
            "listar_auditoria_reciente": lambda s: instruccion.listar_auditoria_reciente(None, s),
            "listar_auditoria_reciente con antes": lambda s: instruccion.listar_auditoria_reciente(None, s, 50),
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


class DecidirLecturas(unittest.TestCase):
    """El tope de lecturas: oráculo literal de cada frontera."""

    def test_umbrales_literales(self):
        # Cambiarlos es una decisión (docs/threat-model.md, 8), no un efecto secundario.
        self.assertEqual((instruccion.LECTURAS_AVISO, instruccion.LECTURAS_TOPE), (20, 50))

    def test_fronteras(self):
        casos = {
            (1, True): (True, None),
            (19, True): (True, None),
            (20, True): (True, "aviso"),
            # Releer la vigésima no vuelve a avisar.
            (20, False): (True, None),
            (21, True): (True, None),
            (49, True): (True, None),
            (50, True): (True, "tope"),
            (50, False): (True, None),
            (51, True): (False, None),
        }
        for (distintas, primera), esperado in casos.items():
            with self.subTest(distintas=distintas, primera=primera):
                self.assertEqual(instruccion.decidir_lecturas(distintas, primera), esperado)


class _ConexionAuditoria:
    """Doble de la conexión de la auditoría: la cuenta está activa y la
    consulta devuelve las secuencias que se le digan. Registra la sentencia y
    los parámetros."""

    def __init__(self, secuencias):
        self.secuencias = secuencias
        self.sql = self.parametros = None

    def execute(self, sql, parametros=None):
        respuesta = mock.Mock()
        if sql == instruccion.SQL_ACTOR_ACTIVO:
            respuesta.fetchone.return_value = (1,)
        else:
            self.sql, self.parametros = sql, parametros
            respuesta.fetchall.return_value = [
                (s, datetime.date(2026, 10, 18), "plataforma", "invitacion_admin_plataforma", uuid.UUID(int=s), None,
                 None, "admin@empresa.es") for s in self.secuencias]
        return respuesta


class Auditoria(unittest.TestCase):
    ADMIN = types.SimpleNamespace(rol="admin", usuario_id=uuid.UUID(int=8), empresa_id=uuid.UUID(int=1))

    def llamar(self, conexion, funcion, *argumentos):
        @contextlib.contextmanager
        def transaccion(_pool, _empresa_id, solo_lectura=False):
            yield conexion

        with mock.patch.object(instruccion.bd, "transaccion_empresa", transaccion):
            return funcion(None, self.ADMIN, *argumentos)

    def test_acciones_con_cuenta_literales(self):
        # Oráculo literal: qué acciones llevan una cuenta y dónde. Una acción
        # de cuenta nueva que no esté aquí sale sin email, con el id a la vista.
        self.assertEqual(instruccion.ACCIONES_CUENTA_EN_OBJETO, {
            "acceso", "activacion", "cambio_contrasena", "invitacion", "baja", "anulacion_invitacion",
            "invitacion_admin_plataforma", "reinvitacion_admin_plataforma", "aprobacion_registro"})
        self.assertEqual(instruccion.ACCIONES_CUENTA_EN_DESTINO, {"asignacion"})

    def test_parametros_de_la_consulta(self):
        conexion = _ConexionAuditoria([])
        self.llamar(conexion, instruccion.listar_auditoria_reciente)
        self.assertEqual(conexion.parametros, {
            "en_objeto": ["acceso", "activacion", "anulacion_invitacion", "aprobacion_registro", "baja",
                          "cambio_contrasena", "invitacion", "invitacion_admin_plataforma",
                          "reinvitacion_admin_plataforma"],
            "en_destino": ["asignacion"], "limite": 201})

    def test_reciente_sin_antes_y_con_antes(self):
        conexion = _ConexionAuditoria([])
        self.llamar(conexion, instruccion.listar_auditoria_reciente)
        self.assertIs(conexion.sql, instruccion.SQL_AUDITORIA_RECIENTE)
        self.assertNotIn("antes", conexion.parametros)
        self.llamar(conexion, instruccion.listar_auditoria_reciente, 50)
        self.assertIs(conexion.sql, instruccion.SQL_AUDITORIA_ANTERIOR)
        self.assertEqual(conexion.parametros["antes"], 50)

    def test_anterior(self):
        # 201 filas (300 a 100, descendentes): la página son 200 y la última
        # es la 101, que es lo que se pasa como antes para seguir.
        pagina = self.llamar(_ConexionAuditoria(range(300, 99, -1)), instruccion.listar_auditoria_reciente)
        self.assertEqual((len(pagina.filas), pagina.filas[0].secuencia, pagina.anterior), (200, 300, 101))
        # Exactamente 200: no hay más páginas.
        pagina = self.llamar(_ConexionAuditoria(range(200, 0, -1)), instruccion.listar_auditoria_reciente, 201)
        self.assertEqual((len(pagina.filas), pagina.anterior), (200, None))

    def test_siguiente_sin_cambios(self):
        # El listado desde el principio sigue como antes del 6b-3c.
        pagina = self.llamar(_ConexionAuditoria(range(1, 202)), instruccion.listar_auditoria, 1)
        self.assertEqual((len(pagina.filas), pagina.siguiente), (200, 201))
        self.assertEqual(pagina.filas[0].cuenta_email, "admin@empresa.es")


class _ConexionLeer:
    """Doble de la conexión de leer_denuncia: una denuncia asignada sin
    mensajes y el conteo de lecturas que se le diga. Registra las sentencias
    y los avisos que se piden."""

    def __init__(self, distintas, veces):
        self.distintas, self.veces = distintas, veces
        self.sentencias = []

    def execute(self, sql, parametros=None):
        self.sentencias.append(sql)
        respuesta = mock.Mock()
        if sql == instruccion.SQL_LEER_ASIGNADA:
            respuesta.fetchone.return_value = (datetime.date(2026, 10, 18), "nueva", b"cifrado", 1)
        elif sql == instruccion.SQL_LECTURAS_DEL_DIA:
            respuesta.fetchone.return_value = (self.distintas, self.veces, 3600)
        elif sql == avisos.SQL_DESTINATARIOS:
            respuesta.fetchall.return_value = [("auditora@empresa.es",), ("otro.admin@empresa.es",)]
        elif sql == avisos.SQL_NOMBRE_EMPRESA:
            respuesta.fetchone.return_value = ("Empresa",)
        elif sql == instruccion.SQL_EMAIL_ACTOR:
            respuesta.fetchone.return_value = ("lectora@empresa.es",)
        return respuesta


class LeerConTope(unittest.TestCase):
    ADMIN = types.SimpleNamespace(rol="admin", usuario_id=uuid.UUID(int=8), empresa_id=uuid.UUID(int=1))

    def leer(self, conexion):
        @contextlib.contextmanager
        def transaccion(_pool, _empresa_id, solo_lectura=False):
            yield conexion

        with mock.patch.object(instruccion.bd, "transaccion_empresa", transaccion), \
                mock.patch.object(instruccion.denuncias, "leer_mensajes_y_claves", return_value=([], {})), \
                mock.patch.object(instruccion.denuncias, "descifrar_expediente",
                                  return_value=({"categoria": "fraude", "texto": "t"}, [])):
            return instruccion.leer_denuncia(None, None, self.ADMIN, uuid.UUID(int=3))

    def test_la_fila_se_escribe_antes_de_contar(self):
        # Contar antes dejaría pasar a dos lecturas simultáneas con la última plaza.
        conexion = _ConexionLeer(1, 1)
        self.leer(conexion)
        self.assertLess(conexion.sentencias.index(instruccion.SQL_AUDITAR),
                        conexion.sentencias.index(instruccion.SQL_LECTURAS_DEL_DIA))

    def test_por_encima_del_tope_rechaza_sin_avisar(self):
        conexion = _ConexionLeer(51, 1)
        with self.assertRaises(instruccion.LimiteLecturas) as error:
            self.leer(conexion)
        self.assertEqual(error.exception.segundos, 3600)
        self.assertNotIn(avisos.SQL_DESTINATARIOS, conexion.sentencias)
        # Control: en el tope justo, se lee y se avisa.
        lectura = self.leer(_ConexionLeer(50, 1))
        self.assertEqual((lectura.lecturas_hoy, lectura.umbral), (50, "tope"))

    def test_aviso_a_quien_vigila(self):
        lectura = self.leer(_ConexionLeer(20, 1))
        self.assertEqual((lectura.lecturas_hoy, lectura.umbral), (20, "aviso"))
        self.assertEqual([c.destinatario for c in lectura.correos], ["auditora@empresa.es", "otro.admin@empresa.es"])
        self.assertTrue(all(c.tipo == "aviso_lecturas" and "lectora@empresa.es" in c.cuerpo for c in lectura.correos))
        # Ni el id de la denuncia ni su contenido van en el aviso.
        self.assertFalse(any(str(uuid.UUID(int=3)) in c.cuerpo or "fraude" in c.cuerpo for c in lectura.correos))
        # Control: sin umbral no se pide ningún aviso.
        conexion = _ConexionLeer(21, 1)
        self.assertEqual(self.leer(conexion).correos, ())
        self.assertNotIn(avisos.SQL_DESTINATARIOS, conexion.sentencias)
