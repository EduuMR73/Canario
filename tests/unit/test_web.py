"""Pruebas unitarias de la lógica pura de app/rutas_web.py: el origen del sitio
(configuración y comprobación), la lectura estricta del formulario, el orden
origen antes del cuerpo y las plantillas (autoescape, nada marcado como
seguro, textos de cada categoría y estado).

Las páginas contra la base de datos y a través de Caddy las prueba la batería
tests/security/verificar_web.py.
"""
import ast
import asyncio
import datetime
import pathlib
import re
import types
import unittest

import jinja2
from fastapi import HTTPException
from pydantic import ValidationError

from app import denuncias, rutas_web
from app.rutas_denuncias import NuevaDenuncia

ORIGEN = "https://localhost:8444"
FECHA = datetime.date(2026, 10, 15)
# Lo que debe estar escapado en la página: si sale tal cual, es XSS.
INYECCION = '"><script>alert(1)</script>'

# Las plantillas que existen: una que falte o sobre se ve aquí, y así las
# comprobaciones de abajo no pasan en vacío.
PLANTILLAS = {"base.html", "creada.html", "denuncia.html", "expediente.html", "inicio.html", "macros.html",
              "seguimiento.html"}
# Lo que marcaría HTML como seguro en una plantilla.
MARCA_SEGURO = re.compile(r"\|\s*safe\b|\{%-?\s*autoescape\s+false", re.IGNORECASE)


def expediente(**cambios):
    datos = {"codigo": "ABC", "estado": "Recibida", "fecha": FECHA, "categoria": "Acoso",
             "texto_denuncia": "texto", "mensajes": [], "errores": {}, "aviso": "", "texto": ""}
    return {**datos, **cambios}


class Origen(unittest.TestCase):
    def test_cargar_por_defecto(self):
        self.assertEqual(rutas_web.cargar_origen({}), ("https://localhost:8444", "por defecto"))

    def test_cargar_configurados_validos(self):
        for valor in ("https://canal.ejemplo.org", "https://canal.ejemplo.org:8444", "https://a"):
            with self.subTest(valor=valor):
                self.assertEqual(rutas_web.cargar_origen({"CANARIO_ORIGEN_WEB": valor}), (valor, "configurado"))

    def test_cargar_rechazos(self):
        # Valores que un navegador nunca enviaría en Origin: con ellos se
        # rechazaría todo formulario, así que la API no debe arrancar.
        for valor in ("http://canal.ejemplo.org", "https://Canal.ejemplo.org", "https://canal.ejemplo.org/",
                      "https://canal.ejemplo.org/ruta", "https://canal.ejemplo.org:443", "https://canal.ejemplo.org:0",
                      "https://canal.ejemplo.org:65536", "https://canal.ejemplo.org\n", " https://canal.ejemplo.org",
                      "https://-canal.ejemplo.org", "null", ""):
            with self.subTest(valor=valor), self.assertRaises(rutas_web.ErrorConfiguracion):
                rutas_web.cargar_origen({"CANARIO_ORIGEN_WEB": valor})

    def test_comprobacion(self):
        casos = [
            ({"origin": ORIGEN}, True),
            ({"origin": ORIGEN, "sec-fetch-site": "same-origin"}, True),
            # same-site no basta: el 8443 de la API es del mismo sitio.
            ({"origin": ORIGEN, "sec-fetch-site": "same-site"}, False),
            ({"origin": ORIGEN, "sec-fetch-site": "cross-site"}, False),
            ({"origin": ORIGEN, "sec-fetch-site": "none"}, False),
            ({"origin": "https://localhost:8443", "sec-fetch-site": "same-site"}, False),
            ({"origin": "https://otro.ejemplo"}, False),
            # Lo que manda el navegador con Referrer-Policy no-referrer.
            ({"origin": "null"}, False),
            ({"sec-fetch-site": "same-origin"}, False),
            ({}, False),
        ]
        for cabeceras, esperado in casos:
            with self.subTest(cabeceras=cabeceras):
                self.assertIs(rutas_web.origen_aceptado(cabeceras, ORIGEN), esperado)


class Formulario(unittest.TestCase):
    def test_valido(self):
        # CRLF del envío -> LF; "+" es espacio; UTF-8 en %XX.
        self.assertEqual(rutas_web.leer_formulario(b"categoria=acoso&texto=hola%0D%0Aadi%C3%B3s+mundo",
                                                   ("categoria", "texto")),
                         {"categoria": "acoso", "texto": "hola\nadiós mundo"})
        # El orden de los campos no importa, y un campo vacío llega vacío (lo
        # rechaza después la validación, con el formulario).
        self.assertEqual(rutas_web.leer_formulario(b"texto=&categoria=", ("categoria", "texto")),
                         {"categoria": "", "texto": ""})

    def test_solo_crlf_se_convierte(self):
        # Un CR suelto no lo genera un navegador; se deja tal cual (TextoLibre
        # lo admite) en vez de reinterpretarlo.
        self.assertEqual(rutas_web.leer_formulario(b"codigo=a%0Db", ("codigo",)), {"codigo": "a\rb"})

    def test_rechazos(self):
        campos = ("categoria", "texto")
        for cuerpo in (b"categoria=acoso&texto=100%", b"categoria=acoso&texto=%G1", b"categoria=acoso;texto=x",
                       b"categoria=acoso&texto=x&otro=y", b"categoria=acoso", b"categoria=acoso&categoria=fraude",
                       b"categoria=acoso&texto=%FF", b"", b"categoria=acoso&texto=x&", b"=x&texto=y",
                       "categoria=acoso&texto=ñ".encode(), b"categoria=acoso&&texto=x", b"categoria&texto=x",
                       # UTF-8 no válido en %XX: un surrogate (U+D800), un NUL
                       # "overlong" y un punto por encima de U+10FFFF. Un
                       # navegador no los genera (codifica una cadena de valores
                       # escalares, WHATWG URL).
                       b"categoria=acoso&texto=%ED%A0%80", b"categoria=acoso&texto=%C0%80",
                       b"categoria=acoso&texto=%F4%90%80%80"):
            with self.subTest(cuerpo=cuerpo):
                self.assertIsNone(rutas_web.leer_formulario(cuerpo, campos))


class PeticionFalsa:
    """Lo que la dependencia usa de una petición: cabeceras, el origen del
    sitio y el cuerpo, anotando si se ha leído."""

    def __init__(self, cabeceras, cuerpo=b"codigo=x"):
        self.headers = cabeceras
        self.app = types.SimpleNamespace(state=types.SimpleNamespace(origen_web=ORIGEN))
        self._cuerpo = cuerpo
        self.leido = False

    async def body(self):
        self.leido = True
        return self._cuerpo


def resolver(peticion):
    return asyncio.run(rutas_web.formulario("codigo")(peticion))


class Dependencia(unittest.TestCase):
    def test_correcta(self):
        peticion = PeticionFalsa({"origin": ORIGEN, "content-type": "application/x-www-form-urlencoded"})
        self.assertEqual(resolver(peticion), {"codigo": "x"})

    def test_origen_antes_del_cuerpo(self):
        # Un envío de otro sitio se rechaza sin leer el cuerpo.
        peticion = PeticionFalsa({"origin": "https://otro.ejemplo", "content-type": "application/x-www-form-urlencoded"})
        with self.assertRaises(HTTPException) as contexto:
            resolver(peticion)
        self.assertEqual(contexto.exception.status_code, 403)
        self.assertFalse(peticion.leido)

    def test_tipo_y_cuerpo(self):
        casos = [({"content-type": "multipart/form-data; boundary=x"}, b"codigo=x", 415),
                 ({"content-type": "application/json"}, b"codigo=x", 415),
                 ({}, b"codigo=x", 415),
                 ({"content-type": "application/x-www-form-urlencoded"}, b"codigo=x&codigo=y", 400)]
        for cabeceras, cuerpo, codigo in casos:
            with self.subTest(cabeceras=cabeceras, cuerpo=cuerpo), self.assertRaises(HTTPException) as contexto:
                resolver(PeticionFalsa({"origin": ORIGEN, **cabeceras}, cuerpo))
            self.assertEqual(contexto.exception.status_code, codigo)


class Plantillas(unittest.TestCase):
    def test_existen_y_compilan(self):
        self.assertEqual(set(rutas_web.entorno_plantillas.list_templates()), PLANTILLAS)

    def test_autoescape(self):
        datos = expediente(codigo=INYECCION, texto_denuncia=INYECCION, texto=INYECCION,
                           mensajes=[{"fecha": FECHA, "autor": "Usted", "texto": INYECCION}])
        html = rutas_web.pagina("expediente.html", **datos).body.decode()
        self.assertNotIn("<script>", html)
        self.assertEqual(html.count("&lt;script&gt;"), 4)
        # Control: el mismo render sin autoescape deja el script tal cual, así
        # que la comprobación de arriba distingue.
        sin_escape = jinja2.Environment(loader=rutas_web.entorno_plantillas.loader, autoescape=False,
                                        undefined=jinja2.StrictUndefined)
        crudo = sin_escape.get_template("expediente.html").render(
            longitud_maxima=rutas_web.LONGITUD_MAXIMA_TEXTO, categorias=rutas_web.CATEGORIAS, **datos)
        self.assertEqual(crudo.count("<script>"), 4)

    def test_nada_marcado_como_seguro(self):
        # Control: la expresión detecta cada forma.
        for muestra in ("{{ x|safe }}", "{{ x | safe }}", "{% autoescape false %}", "{%- autoescape false %}"):
            with self.subTest(muestra=muestra):
                self.assertTrue(MARCA_SEGURO.search(muestra))
        for nombre in sorted(PLANTILLAS):
            with self.subTest(plantilla=nombre):
                texto = (rutas_web.DIRECTORIO_PLANTILLAS / nombre).read_text(encoding="utf-8")
                self.assertIsNone(MARCA_SEGURO.search(texto))
        # En el código (no en los comentarios, que lo explican): ni Markup ni
        # markupsafe.
        arbol = ast.parse(pathlib.Path(rutas_web.__file__).read_text(encoding="utf-8"))
        nombres = {n.id for n in ast.walk(arbol) if isinstance(n, ast.Name)}
        nombres |= {n.attr for n in ast.walk(arbol) if isinstance(n, ast.Attribute)}
        modulos = {a.name for n in ast.walk(arbol) if isinstance(n, ast.Import) for a in n.names}
        modulos |= {n.module for n in ast.walk(arbol) if isinstance(n, ast.ImportFrom)}
        self.assertNotIn("Markup", nombres)
        self.assertNotIn("markupsafe", modulos)

    def test_variable_que_falta_es_un_error(self):
        with self.assertRaises(jinja2.UndefinedError):
            rutas_web.pagina("seguimiento.html")

    def test_textarea_conserva_el_salto_inicial(self):
        # El analizador HTML descarta un salto tras <textarea>: la plantilla
        # pone uno propio para que el del texto se conserve.
        html = rutas_web.pagina("expediente.html", **expediente(texto="\nprimera")).body.decode()
        self.assertIn(">\n\nprimera</textarea>", html)


class Textos(unittest.TestCase):
    def test_categorias_estados_y_autores(self):
        self.assertEqual(tuple(rutas_web.CATEGORIAS), denuncias.CATEGORIAS)
        # Los estados que el denunciante puede ver: todos los del CHECK de
        # canal.denuncia (db/init/02_esquema.sql) menos no_veraz.
        self.assertEqual(set(rutas_web.ESTADOS), {"nueva", "en_instruccion", "resuelta", "archivada", "inadmitida"})
        self.assertEqual(set(rutas_web.AUTORES), {"denunciante", "personal"})

    def test_errores_sin_eco(self):
        with self.assertRaises(ValidationError) as contexto:
            NuevaDenuncia.model_validate({"categoria": INYECCION, "texto": " "})
        errores = rutas_web.errores_por_campo(contexto.exception, {"categoria": rutas_web.ERROR_CATEGORIA,
                                                                   "texto": rutas_web.ERROR_TEXTO})
        self.assertEqual(errores, {"categoria": rutas_web.ERROR_CATEGORIA, "texto": rutas_web.ERROR_TEXTO})


if __name__ == "__main__":
    unittest.main()
