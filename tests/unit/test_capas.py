"""Prueba de arquitectura: la lógica no sabe de HTTP.

La convención está escrita en la cabecera de app/personal.py: la lógica
recibe y devuelve valores, y el transporte (rutas, cookies, cabeceras,
códigos de estado) vive solo en las rutas. Aquí deja de ser un comentario:
se comprueba con el árbol sintáctico de cada módulo de LOGICA que ninguno
importa fastapi o starlette, ni un módulo de transporte de la propia API
(app/rutas_*, app/principal.py, app/frontera_http.py o el broker). Quien la
rompa lo ve en rojo.

Se analiza el código fuente (ast), no lo que se ha importado al ejecutar:
detecta también una importación dentro de una función o de una rama que la
prueba no recorre. No ve una importación dinámica (importlib o __import__
con un texto); ninguna de la lógica la usa.

LOGICA es una lista literal. Fuera de ella, a propósito:
* app/limitador.py: es también un middleware ASGI (FronteraLimitador).
* app/validacion.py: tipos de la frontera para pydantic.
* app/solicitudes.py: importa app/rutas_web.py (analizar_origen y
  ErrorConfiguracion), una dependencia de la lógica hacia el transporte
  anterior a esta prueba. Corregirla es un bloque aparte; hasta entonces
  queda fuera, y a la vista aquí.
* app/gestion.py, app/verificacion_arranque.py y app/comprobar_salud.py:
  órdenes y comprobaciones de operación, no lógica de la API.
"""
import ast
import pathlib
import unittest

import app

LOGICA = ("avisos", "bd", "claves", "cliente_broker", "correo", "cripto", "denuncias", "externo", "instruccion",
          "personal", "proveedores_externos", "tokens")
PAQUETES_HTTP = ("fastapi", "starlette")
TRANSPORTE_PROPIO = ("app.principal", "app.frontera_http", "app.broker")


def importaciones(fuente):
    """Nombres completos de todo lo que importa un código fuente, también
    dentro de funciones. "from app import x" cuenta como "app.x". Una
    importación relativa es del propio paquete: "from . import x" cuenta
    como "app.x" (los módulos de LOGICA están directamente en app/)."""
    nombres = set()
    for nodo in ast.walk(ast.parse(fuente)):
        if isinstance(nodo, ast.Import):
            nombres.update(alias.name for alias in nodo.names)
        elif isinstance(nodo, ast.ImportFrom):
            modulo = nodo.module or ""
            if nodo.level:
                modulo = "app" + (f".{modulo}" if modulo else "")
            nombres.add(modulo)
            nombres.update(f"{modulo}.{alias.name}" for alias in nodo.names)
    return nombres


def prohibidas(fuente):
    """Las importaciones que la lógica no puede tener, ordenadas."""
    def prohibida(nombre):
        raiz = nombre.split(".")[0]
        return (raiz in PAQUETES_HTTP or nombre.startswith("app.rutas_")
                or any(nombre == t or nombre.startswith(t + ".") for t in TRANSPORTE_PROPIO))
    return sorted(n for n in importaciones(fuente) if prohibida(n))


class Controles(unittest.TestCase):
    """La comprobación detecta lo que tiene que detectar y nada más: sin
    esto, una lista vacía en la prueba de abajo no demostraría nada."""

    def test_detecta_cada_forma_de_importar_http(self):
        casos = {
            "import fastapi": ["fastapi"],
            "import starlette.responses": ["starlette.responses"],
            "from fastapi import Request": ["fastapi", "fastapi.Request"],
            "from starlette.background import BackgroundTask": [
                "starlette.background", "starlette.background.BackgroundTask"],
            "def f():\n    from fastapi.responses import Response\n": [
                "fastapi.responses", "fastapi.responses.Response"],
            "from app import rutas_personal": ["app.rutas_personal"],
            "from app.rutas_web import analizar_origen": ["app.rutas_web", "app.rutas_web.analizar_origen"],
            "import app.frontera_http": ["app.frontera_http"],
            "from app import principal, cripto": ["app.principal"],
            "from app import broker": ["app.broker"],
            "from . import rutas_web": ["app.rutas_web"],
            "from .frontera_http import responder": ["app.frontera_http", "app.frontera_http.responder"],
        }
        for fuente, esperado in casos.items():
            with self.subTest(fuente=fuente):
                self.assertEqual(prohibidas(fuente), esperado)

    def test_no_marca_lo_permitido(self):
        for fuente in ("import fastapi_extra", "from app import cripto, bd", "import redis",
                       "from app.cripto import cifrar", "from app import broker_de_otra_cosa",
                       "import starlettes", "from . import cripto"):
            with self.subTest(fuente=fuente):
                self.assertEqual(prohibidas(fuente), [])


class LaLogicaNoSabeDeHttp(unittest.TestCase):
    def test_ningun_modulo_de_la_logica_importa_transporte(self):
        # El app/ importado: en los mutantes de verificar_unitarios.py es la
        # copia mutada, no el del repositorio.
        directorio = pathlib.Path(app.__file__).parent
        for modulo in LOGICA:
            with self.subTest(modulo=modulo):
                fuente = (directorio / f"{modulo}.py").read_text(encoding="utf-8")
                self.assertEqual(prohibidas(fuente), [])


if __name__ == "__main__":
    unittest.main()
