"""Los caracteres invisibles del texto libre en las páginas sin JS del
denunciante (docs/threat-model.md, 6.11).

Es la misma regla que la SPA (spa/src/app/denuncias/invisibles.ts), para el
otro lado: aquí el denunciante lee los mensajes del personal. El texto se
guarda tal cual, porque es una prueba (6.16), y un U+202E (RIGHT-TO-LEFT
OVERRIDE) da la vuelta a lo que le sigue dentro de su párrafo: un plazo
"21/30" se leería "03/12" (CWE-451, como Trojan Source, CVE-2021-42574). El
<div> lo aísla de lo que hay alrededor, pero no lo frena dentro (UAX #9, X8).
Quitarlo escondería que alguien lo puso. Así que cada racha de invisibles se
pinta como una marca visible, con un aviso que dice cuántos hay, y lo guardado
no cambia.

La plantilla recibe segmentos y los escapa uno a uno con el autoescape de
Jinja2: no hay HTML hecho aquí ni nada marcado como seguro (app/rutas_web.py).

Qué se marca y qué no, con el porqué, está en invisibles.ts; las dos listas
son la misma y cada una tiene sus pruebas con los mismos oráculos
(tests/unit/test_web.py e invisibles.spec.ts). Aquí la propiedad Bidi_Control
va escrita a mano, porque unicodedata no la expone: son los 12 de PropList.txt
de Unicode.
"""
import unicodedata

BIDI_CONTROL = frozenset("\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
ANCHO_CERO = frozenset("\u200b\u2060\ufeff\u180e")
# El title de una racha larga se corta: basta para saber de qué se trata.
CODIGOS_MAXIMOS = 10


def _nombre(caracter, siguiente):
    """Qué hace un carácter invisible, en palabras de quien lo lee, o None si
    no se marca. El siguiente carácter decide el del CR."""
    if caracter == "\u202e":
        return "invierte el texto"
    if caracter in BIDI_CONTROL:
        return "cambia la dirección"
    if caracter in ANCHO_CERO:
        return "ancho cero"
    if caracter in "\t\n" or (caracter == "\r" and siguiente == "\n"):
        return None
    if unicodedata.category(caracter) == "Cc":
        return "carácter de control"
    return None


def _marca(nombres):
    if len(nombres) == 1:
        return f"[invisible: {nombres[0]}]"
    return f"[{len(nombres)} invisibles: {', '.join(dict.fromkeys(nombres))}]"


def _codigos(racha):
    vistos = " ".join(f"U+{ord(c):04X}" for c in racha[:CODIGOS_MAXIMOS])
    return f"{vistos} y {len(racha) - CODIGOS_MAXIMOS} más" if len(racha) > CODIGOS_MAXIMOS else vistos


def segmentar(texto):
    """Parte el texto en segmentos: el texto normal tal cual y cada racha de
    invisibles seguidos en uno solo, con su marca. Una racha es un solo
    elemento en la página. Devuelve {"segmentos": [{"valor", "marca",
    "codigos"}], "invisibles": n}, con marca y codigos a None en el texto
    normal."""
    segmentos = []
    normal, racha, nombres = [], [], []
    invisibles = 0

    def cerrar_normal():
        if normal:
            segmentos.append({"valor": "".join(normal), "marca": None, "codigos": None})
            normal.clear()

    def cerrar_racha():
        if racha:
            segmentos.append({"valor": "".join(racha), "marca": _marca(nombres), "codigos": _codigos(racha)})
            racha.clear()
            nombres.clear()

    for i, caracter in enumerate(texto):
        nombre = _nombre(caracter, texto[i + 1] if i + 1 < len(texto) else None)
        if nombre is None:
            cerrar_racha()
            normal.append(caracter)
        else:
            cerrar_normal()
            racha.append(caracter)
            nombres.append(nombre)
            invisibles += 1
    cerrar_normal()
    cerrar_racha()
    return {"segmentos": segmentos, "invisibles": invisibles}


def aviso(invisibles):
    """El aviso que va encima de un texto con invisibles."""
    if invisibles == 1:
        return ("Este texto tiene 1 carácter invisible. Puede desordenar o esconder parte de lo que se lee, así "
                "que se muestra marcado entre corchetes. El texto guardado no cambia.")
    return (f"Este texto tiene {invisibles} caracteres invisibles. Pueden desordenar o esconder parte de lo que se "
            "lee, así que se muestran marcados entre corchetes. El texto guardado no cambia.")
