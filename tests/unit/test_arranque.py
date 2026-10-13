"""Pruebas unitarias de app/verificacion_arranque.py: cada desviación del
catálogo bloquea el arranque con su identificador exacto, y solo con él.

Límite asumido: el catálogo sano de la conexión falsa se construye con las
constantes del módulo (RELACIONES, POLITICAS...). Aquí se prueba la lógica de
comparación, con identificadores y detalles literales; que esas constantes
coincidan con PostgreSQL real lo prueba la batería
tests/security/verificar_arranque.py, que provoca cada desviación en una base
de datos de verdad.
"""
import contextlib
import unittest

from app import bd
from app import verificacion_arranque as va


class Resultado:
    def __init__(self, filas):
        self.filas = filas

    def fetchone(self):
        return self.filas[0] if self.filas else None

    def fetchall(self):
        return self.filas


def catalogo_sano():
    """Respuesta de cada consulta en una base de datos correcta."""
    return {
        "search_path": [("pg_catalog, canal",)],
        "identidad": [("aplicacion", "aplicacion", "canario")],
        "atributos": [(False, False, False, False, False)],
        "pertenencia": [(0,)],
        "propiedad": [(0,)],
        "esquema_bd": [(True, False, False, False, False)],
        "relaciones": [(n, rls, force) for n, (rls, force) in va.RELACIONES.items()],
        "privilegios_tabla": [(x,) for x in va.PRIVILEGIOS_TABLA],
        "privilegios_columna": [(x,) for x in va.PRIVILEGIOS_COLUMNA],
        "funciones": [(x,) for x in va.FUNCIONES_EJECUTABLES],
        "definidor": [(x,) for x in va.FUNCIONES_DEFINIDOR],
        "propietario_funciones": [(False, False, False)],
        "propietario_supresion": [(False, False, False)],
        "propietario_redaccion": [(False, False, False)],
        "politicas": [(x,) for x in va.POLITICAS],
    }


class ConexionFalsa:
    """Responde según el texto de la consulta. Una consulta desconocida es un
    error visible: la prueba no puede pasar por no haberla reconocido."""

    def __init__(self, catalogo):
        self.catalogo = catalogo
        self.sentencias = []

    def clave(self, sql):
        exactas = {va.SQL_SEARCH_PATH: "search_path", va.SQL_PERTENENCIA: "pertenencia",
                   va.SQL_PROPIEDAD: "propiedad", va.SQL_ESQUEMA_BD: "esquema_bd",
                   va.SQL_RELACIONES: "relaciones", va.SQL_PRIVILEGIOS_TABLA: "privilegios_tabla",
                   va.SQL_PRIVILEGIOS_COLUMNA: "privilegios_columna", va.SQL_FUNCIONES_EJECUTABLES: "funciones",
                   va.SQL_FUNCIONES_DEFINIDOR: "definidor", va.SQL_POLITICAS: "politicas"}
        if sql in exactas:
            return exactas[sql]
        if sql.startswith("select current_user, session_user"):
            return "identidad"
        if "rolcreaterole" in sql:
            return "atributos"
        for duenio in ("propietario_funciones", "propietario_supresion", "propietario_redaccion"):
            if f"rolname = '{duenio}'" in sql:
                return duenio
        raise AssertionError(f"consulta no prevista: {sql[:60]!r}")

    def execute(self, sql):
        self.sentencias.append(sql)
        if sql in ("set local search_path = pg_catalog", bd.SQL_SOLO_LECTURA):
            return Resultado([])
        return Resultado(self.catalogo[self.clave(sql)])


def con(clave, filas):
    catalogo = catalogo_sano()
    catalogo[clave] = filas
    return ConexionFalsa(catalogo)


def con_relaciones(cambio):
    filas = {n: (r, f) for n, r, f in catalogo_sano()["relaciones"]}
    cambio(filas)
    return con("relaciones", [(n, r, f) for n, (r, f) in filas.items()])


class Comprobar(unittest.TestCase):
    def test_catalogo_sano_sin_fallos(self):
        conexion = ConexionFalsa(catalogo_sano())
        self.assertEqual(va.comprobar(conexion), [])
        # El search_path se lee antes de fijarlo en local.
        self.assertEqual(conexion.sentencias[:2], [va.SQL_SEARCH_PATH, "set local search_path = pg_catalog"])

    def test_cada_desviacion_su_identificador(self):
        casos = {
            "search_path con public": (
                con("search_path", [("public",)]),
                [("search_path", "search_path = 'public'")]),
            "otra sesion": (
                con("identidad", [("aplicacion", "postgres", "canario")]),
                [("identidad", "current_user = aplicacion, session_user = postgres, base = canario")]),
            "rol con BYPASSRLS": (
                con("atributos", [(False, True, False, False, False)]),
                [("rol_atributos", ("super, bypassrls, createrole, createdb, replication = "
                                    "(False, True, False, False, False)"))]),
            "rol miembro de otro": (
                con("pertenencia", [(1,)]),
                [("pertenencia", "el rol pertenece a 1 rol(es)")]),
            "rol dueno de objetos": (
                con("propiedad", [(2,)]),
                [("propiedad", "el rol es dueno de 2 objeto(s)")]),
            "tablas temporales": (
                con("esquema_bd", [(True, False, False, False, True)]),
                [("esquema_bd", ("usage canal, create canal, create public, create bd, temp bd = "
                                 "(True, False, False, False, True)"))]),
            "tabla de mas": (
                con_relaciones(lambda f: f.update(intrusa=(False, False))),
                [("tablas", "sobra ['intrusa'], falta []")]),
            "tabla de menos": (
                con_relaciones(lambda f: f.pop("mensaje")),
                [("tablas", "sobra [], falta ['mensaje']")]),
            "denuncia sin FORCE": (
                con_relaciones(lambda f: f.update(denuncia=(True, False))),
                [("rls", "RLS o FORCE distintos de lo esperado en ['denuncia']")]),
            "DELETE en denuncia": (
                con("privilegios_tabla", [(x,) for x in va.PRIVILEGIOS_TABLA | {"denuncia|DELETE"}]),
                [("privilegios_tabla", "sobra ['denuncia|DELETE'], falta []")]),
            "UPDATE del contenido": (
                con("privilegios_columna",
                    [(x,) for x in va.PRIVILEGIOS_COLUMNA | {"denuncia|contenido_cifrado|UPDATE"}]),
                [("privilegios_columna", "sobra ['denuncia|contenido_cifrado|UPDATE'], falta []")]),
            "funcion ejecutable de mas": (
                con("funciones", [(x,) for x in va.FUNCIONES_EJECUTABLES | {"canal.suprimir_denuncias_caducadas()"}]),
                [("funciones", "sobra ['canal.suprimir_denuncias_caducadas()'], falta []")]),
            "definidor con otro dueno": (
                con("definidor", [(x,) for x in (va.FUNCIONES_DEFINIDOR - {"buscar_codigo|propietario_funciones"})
                                  | {"buscar_codigo|postgres"}]),
                [("funciones_definidor",
                  "sobra ['buscar_codigo|postgres'], falta ['buscar_codigo|propietario_funciones']")]),
            "dueno de la supresion con login": (
                con("propietario_supresion", [(False, False, True)]),
                [("propietario_supresion", "super, bypassrls, login = (False, False, True)")]),
            "dueno de la redaccion inexistente": (
                con("propietario_redaccion", []),
                [("propietario_redaccion", "super, bypassrls, login = None")]),
            "politica de borrado": (
                con("politicas", [(x,) for x in va.POLITICAS | {"denuncia|denuncia_delete|d|t|aplicacion|true|"}]),
                [("politicas", "sobra ['denuncia|denuncia_delete|d|t|aplicacion|true|'], falta []")]),
        }
        for motivo, (conexion, esperado) in casos.items():
            with self.subTest(motivo=motivo):
                self.assertEqual(va.comprobar(conexion), esperado)


class PoolFalso:
    """pool.connection() entrega siempre la misma conexión falsa."""

    def __init__(self, conexion):
        self._conexion = conexion

    def connection(self):
        return contextlib.nullcontext(self._conexion)


class ConTransaccion(ConexionFalsa):
    def transaction(self):
        return contextlib.nullcontext()


class Verificar(unittest.TestCase):
    def test_sano_arranca_en_solo_lectura(self):
        conexion = ConTransaccion(catalogo_sano())
        with self.assertLogs("canario.arranque", "INFO") as registro:
            va.verificar(PoolFalso(conexion))
        self.assertEqual(registro.output, ["INFO:canario.arranque:ARRANQUE VERIFICADO"])
        self.assertEqual(conexion.sentencias[0], "set transaction isolation level repeatable read, read only")

    def test_desviado_bloquea_y_registra(self):
        catalogo = catalogo_sano()
        catalogo["pertenencia"] = [(1,)]
        catalogo["propiedad"] = [(3,)]
        with self.assertLogs("canario.arranque", "ERROR") as registro, \
                self.assertRaises(va.ArranqueBloqueado) as error:
            va.verificar(PoolFalso(ConTransaccion(catalogo)))
        self.assertEqual(str(error.exception), "2 comprobacion(es) fallida(s)")
        self.assertEqual(registro.output, [
            "ERROR:canario.arranque:ARRANQUE BLOQUEADO: pertenencia: el rol pertenece a 1 rol(es)",
            "ERROR:canario.arranque:ARRANQUE BLOQUEADO: propiedad: el rol es dueno de 3 objeto(s)",
        ])
