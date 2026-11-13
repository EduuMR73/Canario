"""Pruebas unitarias de la lógica pura de app/rutas_web.py: el origen del sitio
(configuración y comprobación), la lectura estricta del formulario, el orden
origen antes del cuerpo, las plantillas (autoescape, nada marcado como
seguro, textos de cada categoría y estado) y los caracteres invisibles del
texto libre, que se pintan como una marca visible (app/invisibles.py).

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

from app import denuncias, invisibles, rutas_web
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
        # Las mismas funciones que el entorno real (la marca de los invisibles):
        # solo cambia el autoescape.
        sin_escape.globals.update(segmentar=invisibles.segmentar, aviso_invisibles=invisibles.aviso)
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



# Los caracteres invisibles del texto libre (app/invisibles.py). Oráculos
# literales: los códigos de Unicode (PropList.txt para Bidi_Control y la
# categoría Cc) y los textos de la página, los mismos que en
# spa/src/app/denuncias/invisibles.spec.ts. Los invisibles van como escapes:
# un carácter bidi literal en el fuente reordenaría lo que se lee de la prueba.
BIDI_CONTROL = ["\u061c", "\u200e", "\u200f", "\u202a", "\u202b", "\u202c",
                "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069"]
# Lo que no debe llegar sin marcar a la página: los de control salvo
# tabulador y LF, los 12 de Bidi_Control y los cuatro de ancho cero.
INVISIBLE_EN_PAGINA = re.compile("[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u061c\u180e\u200b\u200e\u200f"
                                 "\u202a-\u202e\u2060\u2066-\u2069\ufeff]")


def normal(texto):
    return {"segmentos": [{"valor": texto, "marca": None, "codigos": None}], "invisibles": 0}


class Invisibles(unittest.TestCase):
    def test_texto_sin_invisibles_queda_igual(self):
        # Ni el tabulador, ni los saltos, ni lo que forma texto legítimo: ZWJ
        # de un emoji compuesto, ZWNJ del persa, la bandera de Escocia con sus
        # etiquetas, el guion blando y un selector de variación.
        for texto in ("Pagó 500 € el 21/03.\n\tSegunda línea.\r\nTercera.",
                      "\U0001f468\u200d\U0001f469\u200d\U0001f467",
                      "\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645",
                      "\U0001f3f4\U000e0067\U000e0062\U000e0073\U000e0063\U000e0074\U000e007f",
                      "in\u00adforme \u2764\ufe0f"):
            with self.subTest(texto=ascii(texto)):
                self.assertEqual(invisibles.segmentar(texto), normal(texto))
        self.assertEqual(invisibles.segmentar(""), {"segmentos": [], "invisibles": 0})

    def test_cada_invisible_su_marca(self):
        self.assertEqual(invisibles.segmentar("pagó \u202e0051\u202c euros"), {"segmentos": [
            {"valor": "pagó ", "marca": None, "codigos": None},
            {"valor": "\u202e", "marca": "[invisible: invierte el texto]", "codigos": "U+202E"},
            {"valor": "0051", "marca": None, "codigos": None},
            {"valor": "\u202c", "marca": "[invisible: cambia la dirección]", "codigos": "U+202C"},
            {"valor": " euros", "marca": None, "codigos": None},
        ], "invisibles": 2})
        for caracter in BIDI_CONTROL:
            with self.subTest(caracter=ascii(caracter)):
                segmentado = invisibles.segmentar("a" + caracter + "b")
                self.assertEqual(segmentado["invisibles"], 1)
                self.assertEqual(segmentado["segmentos"][1]["valor"], caracter)
        for caracter, codigo in (("\r", "U+000D"), ("\u001b", "U+001B"), ("\u000c", "U+000C"), ("\u0085", "U+0085"),
                                 ("\u007f", "U+007F")):
            with self.subTest(caracter=ascii(caracter)):
                self.assertEqual(invisibles.segmentar("a" + caracter + "b")["segmentos"][1],
                                 {"valor": caracter, "marca": "[invisible: carácter de control]", "codigos": codigo})
        for caracter in ("\u200b", "\u2060", "\ufeff", "\u180e"):
            with self.subTest(caracter=ascii(caracter)):
                self.assertEqual(invisibles.segmentar("a" + caracter + "b")["segmentos"][1]["marca"],
                                 "[invisible: ancho cero]")
        # El CR de un CRLF es un salto; el CR suelto, no.
        self.assertEqual(invisibles.segmentar("a\r\n\tb")["invisibles"], 0)
        self.assertEqual(invisibles.segmentar("a\r\r\nb")["invisibles"], 1)

    def test_rachas_y_codigos(self):
        self.assertEqual(invisibles.segmentar("a\u202c\u200b\u200fb")["segmentos"][1], {
            "valor": "\u202c\u200b\u200f",
            "marca": "[3 invisibles: cambia la dirección, ancho cero]",
            "codigos": "U+202C U+200B U+200F",
        })
        larga = invisibles.segmentar("\u200b" * 10000)
        self.assertEqual(len(larga["segmentos"]), 1)
        self.assertEqual(larga["invisibles"], 10000)
        self.assertEqual(larga["segmentos"][0]["marca"], "[10000 invisibles: ancho cero]")
        self.assertEqual(larga["segmentos"][0]["codigos"],
                         "U+200B U+200B U+200B U+200B U+200B U+200B U+200B U+200B U+200B U+200B y 9990 más")

    def test_marca_escrita_a_mano_no_cuenta(self):
        falsa = "Mire: [invisible: invierte el texto] y [U+202E]."
        self.assertEqual(invisibles.segmentar(falsa), normal(falsa))

    def test_aviso(self):
        self.assertEqual(invisibles.aviso(1), "Este texto tiene 1 carácter invisible. Puede desordenar o esconder "
                         "parte de lo que se lee, así que se muestra marcado entre corchetes. El texto guardado no "
                         "cambia.")
        self.assertEqual(invisibles.aviso(4), "Este texto tiene 4 caracteres invisibles. Pueden desordenar o "
                         "esconder parte de lo que se lee, así que se muestran marcados entre corchetes. El texto "
                         "guardado no cambia.")

    def test_marcados_en_la_pagina(self):
        # Un mensaje del personal con un RLM, una marca escrita a mano, un RLO
        # y una racha de PDF y espacio de ancho cero; el texto de la denuncia,
        # sin invisibles, es el control de que el texto normal sale igual.
        mensaje = "\u200f[invisible: invierte el texto] el plazo es el \u202e21/30\u202c\u200b."
        datos = expediente(texto_denuncia="Texto <b>normal</b>.",
                           mensajes=[{"fecha": FECHA, "autor": "Personal de la empresa", "texto": mensaje}])
        html = rutas_web.pagina("expediente.html", **datos).body.decode()
        self.assertIsNone(INVISIBLE_EN_PAGINA.search(html))
        self.assertIn('<div class="texto">Texto &lt;b&gt;normal&lt;/b&gt;.</div>', html)
        self.assertIn('<p class="aviso" id="aviso-invisibles-1">Este texto tiene 4 caracteres invisibles. Pueden '
                      'desordenar o esconder parte de lo que se lee, así que se muestran marcados entre corchetes. '
                      'El texto guardado no cambia.</p>', html)
        self.assertIn('<div class="texto" aria-describedby="aviso-invisibles-1">'
                      '<span class="invisible-marcado" title="U+200F">[invisible: cambia la dirección]</span>'
                      '[invisible: invierte el texto] el plazo es el '
                      '<span class="invisible-marcado" title="U+202E">[invisible: invierte el texto]</span>21/30'
                      '<span class="invisible-marcado" title="U+202C U+200B">[2 invisibles: cambia la dirección, '
                      'ancho cero]</span>.</div>', html)
        self.assertEqual(html.count('class="invisible-marcado"'), 3)
        self.assertEqual(html.count('class="aviso"'), 1)
        # Control: sin segmentar, el RLO llega a la página y la comprobación
        # lo ve, así que la de arriba distingue.
        sin_marcar = jinja2.Environment(loader=rutas_web.entorno_plantillas.loader, autoescape=True,
                                        undefined=jinja2.StrictUndefined)
        sin_marcar.globals.update(segmentar=normal, aviso_invisibles=invisibles.aviso)
        crudo = sin_marcar.get_template("expediente.html").render(
            longitud_maxima=rutas_web.LONGITUD_MAXIMA_TEXTO, categorias=rutas_web.CATEGORIAS, **datos)
        self.assertIsNotNone(INVISIBLE_EN_PAGINA.search(crudo))


if __name__ == "__main__":
    unittest.main()
