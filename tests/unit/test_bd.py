"""Pruebas unitarias de app/bd.py: el contexto de empresa, que es lo que la
RLS usa para aislar a cada empresa.

Dos garantías: el contexto solo se fija local a la transacción (con
set_config(..., true) y el valor enlazado), y una conexión que vuelva al pool
con contexto se descarta en vez de servir a la petición siguiente, que podría
ser de otra empresa. Se prueban con una conexión y un pool falsos que anotan
cada sentencia: lo que hace PostgreSQL con ellas lo prueba la batería
tests/security/verificar_esquema.py.
"""
import contextlib
import unittest
import uuid

import psycopg

from app import bd

EMPRESA = uuid.UUID(int=1)
# Literales: las sentencias exactas que deben llegar a PostgreSQL.
SQL_FIJAR = "select set_config('app.empresa_id', %s, true)"
SQL_LEER = "select current_setting('app.empresa_id', true)"
SQL_SOLO_LECTURA = "set transaction isolation level repeatable read, read only"


class Resultado:
    def __init__(self, fila):
        self.fila = fila

    def fetchone(self):
        return self.fila


class ConexionFalsa:
    """Anota cada sentencia y cada rollback, en orden."""

    def __init__(self, valor_contexto=None):
        self.registro = []
        self.valor_contexto = valor_contexto

    def execute(self, sql, parametros=None):
        self.registro.append(("execute", sql, parametros))
        return Resultado((self.valor_contexto,))

    def rollback(self):
        self.registro.append(("rollback",))

    @contextlib.contextmanager
    def transaction(self):
        self.registro.append(("transaction",))
        yield


class PoolFalso:
    def __init__(self):
        self.conexion = ConexionFalsa()
        self.usado = False

    @contextlib.contextmanager
    def connection(self):
        self.usado = True
        yield self.conexion


class FijarContexto(unittest.TestCase):
    def test_local_a_la_transaccion_y_enlazado(self):
        conexion = ConexionFalsa()
        bd.fijar_contexto(conexion, EMPRESA)
        self.assertEqual(conexion.registro,
                         [("execute", SQL_FIJAR, ["00000000-0000-0000-0000-000000000001"])])

    def test_solo_uuid(self):
        conexion = ConexionFalsa()
        for malo in ("00000000-0000-0000-0000-000000000001", 1, None):
            with self.subTest(malo=malo):
                with self.assertRaises(TypeError) as error:
                    bd.fijar_contexto(conexion, malo)
                self.assertEqual(str(error.exception), "empresa_id debe ser uuid.UUID")
        self.assertEqual(conexion.registro, [])


class TransaccionEmpresa(unittest.TestCase):
    def test_tipo_validado_antes_de_pedir_conexion(self):
        pool = PoolFalso()
        with self.assertRaises(TypeError), bd.transaccion_empresa(pool, str(EMPRESA)):
            pass
        self.assertFalse(pool.usado)

    def test_orden_de_sentencias(self):
        for solo_lectura, esperado in (
                (False, [("transaction",), ("execute", SQL_FIJAR, [str(EMPRESA)])]),
                (True, [("transaction",), ("execute", SQL_SOLO_LECTURA, None), ("execute", SQL_FIJAR, [str(EMPRESA)])])):
            with self.subTest(solo_lectura=solo_lectura):
                pool = PoolFalso()
                with bd.transaccion_empresa(pool, EMPRESA, solo_lectura=solo_lectura) as conexion:
                    self.assertIs(conexion, pool.conexion)
                self.assertEqual(pool.conexion.registro, esperado)


class ConexionDevueltaAlPool(unittest.TestCase):
    def test_sin_contexto_vuelve_al_pool(self):
        for valor in (None, ""):
            with self.subTest(valor=valor):
                conexion = ConexionFalsa(valor)
                bd._comprobar_sin_contexto(conexion)
                self.assertEqual(conexion.registro, [("execute", SQL_LEER, None), ("rollback",)])

    def test_con_contexto_se_descarta(self):
        conexion = ConexionFalsa("00000000-0000-0000-0000-000000000001")
        with self.assertRaises(bd.ContextoArrastrado) as error:
            bd._comprobar_sin_contexto(conexion)
        self.assertEqual(str(error.exception), "conexion devuelta al pool con contexto de empresa: se descarta")
        # El rollback va antes de lanzar: la conexión no queda a medias.
        self.assertEqual(conexion.registro, [("execute", SQL_LEER, None), ("rollback",)])

    def test_el_pool_la_trata_como_error_de_conexion(self):
        # psycopg_pool cierra la conexión si el reset lanza un psycopg.Error.
        self.assertTrue(issubclass(bd.ContextoArrastrado, psycopg.Error))


class SecretoDeLaBaseDeDatos(unittest.TestCase):
    class Fichero:
        def __init__(self, contenido=None, error=None):
            self.contenido, self.error = contenido, error

        def read_text(self, encoding):
            if self.error:
                raise self.error
            return self.contenido

    def test_valido_sin_tocar_los_parametros_globales(self):
        parametros = bd._parametros_con_contrasena("aplicacion", self.Fichero("Abc123-_x"))
        self.assertEqual((parametros["user"], parametros["password"], parametros["host"], parametros["dbname"]),
                         ("aplicacion", "Abc123-_x", "postgres", "canario"))
        self.assertNotIn("password", bd.PARAMETROS_CONEXION)

    def test_formato_y_lectura_sin_el_valor(self):
        casos = (
            (self.Fichero(""), "el secreto de la base de datos tiene un formato inesperado"),
            (self.Fichero("secreto\n"), "el secreto de la base de datos tiene un formato inesperado"),
            (self.Fichero("sec reto"), "el secreto de la base de datos tiene un formato inesperado"),
            (self.Fichero(error=FileNotFoundError("ruta")),
             "no se puede leer el secreto de la base de datos (FileNotFoundError)"),
        )
        for fichero, mensaje in casos:
            with self.subTest(mensaje=mensaje, contenido=repr(fichero.contenido)):
                with self.assertRaises(bd.ErrorConfiguracion) as error:
                    bd._parametros_con_contrasena("aplicacion", fichero)
                self.assertEqual(str(error.exception), mensaje)
