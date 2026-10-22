"""Pruebas unitarias de app/proveedores_externos.py: la configuración de
Google (desactivado, a medias, formato), la URL de autorización exacta, cada
comprobación del id_token por separado y cómo se trata cada respuesta del
token endpoint. Sin red: el envío se sustituye por una función de la prueba
(la conexión real la prueba tests/security/verificar_externo.py).

Los valores de configuración son inventados y se escriben en un directorio
temporal propio de cada prueba.
"""
import base64
import json
import pathlib
import tempfile
import unittest
import urllib.parse

from app import proveedores_externos as externos

CLIENT_ID = "123456789012-prueba.apps.googleusercontent.com"
# Sin imitar el formato de un secreto real de Google: gitleaks lo marcaría.
CLIENT_SECRET = "secreto-falso-de-prueba"
ORIGEN = "https://localhost:8445"
REDIRECT = "https://localhost:8445/v1/personal/externo/google/vuelta"
NONCE = "n" * 43
STATE = "s" * 43
RETO = "c" * 43
VERIFIER = "v" * 43
SUB = "109876543210987654321"
AHORA = 1_800_000_000
CONFIG = externos.ConfigGoogle(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, redirect_uri=REDIRECT)


def b64(datos):
    return base64.urlsafe_b64encode(datos).rstrip(b"=").decode("ascii")


def id_token(**cambios):
    claims = {"iss": "https://accounts.google.com", "aud": CLIENT_ID, "exp": AHORA + 300, "iat": AHORA,
              "nonce": NONCE, "sub": SUB}
    for nombre, valor in cambios.items():
        if valor is None:
            claims.pop(nombre)
        else:
            claims[nombre] = valor
    # La firma no se verifica (canje directo por TLS): da igual cuál sea.
    return b64(b'{"alg":"RS256"}') + "." + b64(json.dumps(claims).encode()) + ".firma"


def validar(token):
    return externos.validar_id_token_google(token, CLIENT_ID, NONCE, ahora=lambda: AHORA)


class Configuracion(unittest.TestCase):
    def setUp(self):
        self._directorio = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self._directorio.name)

    def tearDown(self):
        self._directorio.cleanup()

    def cargar(self, client_id, client_secret):
        fid, fsecreto = self.dir / "id", self.dir / "secreto"
        for fichero, valor in ((fid, client_id), (fsecreto, client_secret)):
            if valor is not None:
                fichero.write_bytes(valor)
        return externos.cargar_google(ORIGEN, fichero_id=fid, fichero_secreto=fsecreto)

    def test_marcadores_desactivan(self):
        self.assertIsNone(self.cargar(b"sin-configurar:client-id", b"sin-configurar:client-secret"))

    def test_configurado(self):
        config = self.cargar(CLIENT_ID.encode(), CLIENT_SECRET.encode())
        self.assertEqual(config, CONFIG)
        self.assertNotIn(CLIENT_SECRET, repr(config))

    def test_a_medias(self):
        casos = {
            "sin secreto": ((CLIENT_ID.encode(), b"sin-configurar:client-secret"),
                            "google configurado a medias: google_client_secret conserva su marcador"),
            "sin id": ((b"sin-configurar:client-id", CLIENT_SECRET.encode()),
                       "google configurado a medias: google_client_id conserva su marcador"),
        }
        for motivo, (valores, mensaje) in casos.items():
            with self.subTest(motivo=motivo):
                with self.assertRaises(externos.ErrorConfiguracion) as error:
                    self.cargar(*valores)
                self.assertEqual(str(error.exception), mensaje)

    def test_formatos_rechazados(self):
        malos = {"salto final": CLIENT_SECRET.encode() + b"\n", "espacio": b"secreto falso",
                 "vacio": b"", "no ascii": "secreto-ñ".encode(), "256 caracteres": b"a" * 256}
        for motivo, valor in malos.items():
            with self.subTest(motivo=motivo):
                with self.assertRaises(externos.ErrorConfiguracion) as error:
                    self.cargar(CLIENT_ID.encode(), valor)
                self.assertNotIn(CLIENT_SECRET, str(error.exception))

    def test_falta_fichero(self):
        with self.assertRaises(externos.ErrorConfiguracion) as error:
            self.cargar(CLIENT_ID.encode(), None)
        self.assertEqual(str(error.exception), "google_client_secret: falta el fichero (scripts/generar_secretos.py)")

    def test_origen(self):
        self.assertEqual(externos.cargar_origen({"CANARIO_ORIGEN_PERSONAL": ORIGEN}), ORIGEN)
        for malo in (None, "http://localhost:8445", "https://localhost:8445/", "https://LOCALHOST:8445",
                     "https://localhost:443"):
            with self.subTest(origen=malo):
                entorno = {} if malo is None else {"CANARIO_ORIGEN_PERSONAL": malo}
                with self.assertRaises(externos.ErrorConfiguracion):
                    externos.cargar_origen(entorno)


class Autorizacion(unittest.TestCase):
    def test_url_exacta(self):
        self.assertEqual(
            externos.url_autorizacion_google(CONFIG, STATE, RETO, NONCE),
            "https://accounts.google.com/o/oauth2/v2/auth"
            "?client_id=123456789012-prueba.apps.googleusercontent.com"
            "&redirect_uri=https%3A%2F%2Flocalhost%3A8445%2Fv1%2Fpersonal%2Fexterno%2Fgoogle%2Fvuelta"
            "&response_type=code&scope=openid"
            f"&state={STATE}&code_challenge={RETO}&code_challenge_method=S256&nonce={NONCE}")


class IdToken(unittest.TestCase):
    def test_valido(self):
        self.assertEqual(validar(id_token()), SUB)
        self.assertEqual(validar(id_token(iss="accounts.google.com")), SUB)
        self.assertEqual(validar(id_token(azp=CLIENT_ID)), SUB)

    def test_emisor(self):
        for iss in ("https://accounts.google.com/", "https://evil.example", None):
            with self.subTest(iss=iss):
                with self.assertRaises(externos.CanjeFallido) as error:
                    validar(id_token(iss=iss))
                self.assertEqual(error.exception.motivo, "iss")

    def test_audiencia(self):
        for aud in ("otro-cliente", [CLIENT_ID], [CLIENT_ID, "otro-cliente"], None):
            with self.subTest(aud=aud):
                with self.assertRaises(externos.CanjeFallido) as error:
                    validar(id_token(aud=aud))
                self.assertEqual(error.exception.motivo, "aud")
        with self.assertRaises(externos.CanjeFallido) as error:
            validar(id_token(azp="otro-cliente"))
        self.assertEqual(error.exception.motivo, "azp")

    def test_caducidad(self):
        for exp in (AHORA, AHORA - 1, True, str(AHORA + 300), float(AHORA + 300), None):
            with self.subTest(exp=exp):
                with self.assertRaises(externos.CanjeFallido) as error:
                    validar(id_token(exp=exp))
                self.assertEqual(error.exception.motivo, "exp")

    def test_nonce(self):
        for nonce in ("m" * 43, NONCE + "x", 42, None):
            with self.subTest(nonce=nonce):
                with self.assertRaises(externos.CanjeFallido) as error:
                    validar(id_token(nonce=nonce))
                self.assertEqual(error.exception.motivo, "nonce")

    def test_sub(self):
        self.assertEqual(validar(id_token(sub="a" * 255)), "a" * 255)
        for sub in ("a" * 256, "con espacio", "", "salto\n", 12345, None):
            with self.subTest(sub=sub):
                with self.assertRaises(externos.CanjeFallido) as error:
                    validar(id_token(sub=sub))
                self.assertEqual(error.exception.motivo, "sub")

    def test_formato(self):
        cabecera = b64(b'{"alg":"RS256"}')
        for token in (None, 7, "dos.partes", "a.b.c.d", cabecera + ".%%%.firma", cabecera + "." + b64(b"[1]") + ".f",
                      cabecera + "." + b64(b"no es json") + ".f", cabecera + "." + b64(b"[" * 5000) + ".f"):
            with self.subTest(token=repr(token)[:40]):
                with self.assertRaises(externos.CanjeFallido) as error:
                    validar(token)
                self.assertEqual(error.exception.motivo, "id_token_formato")


class Canje(unittest.TestCase):
    def canjear(self, estado, cuerpo):
        enviados = []

        def enviar(host, ruta, datos):
            enviados.append((host, ruta, datos))
            return estado, cuerpo

        resultado = externos.canjear_google(CONFIG, "4/codigo", VERIFIER, NONCE, enviar=enviar, ahora=lambda: AHORA)
        return resultado, enviados

    def test_bueno_y_peticion_exacta(self):
        sub, enviados = self.canjear(200, json.dumps({"id_token": id_token(), "access_token": "x"}).encode())
        self.assertEqual(sub, SUB)
        self.assertEqual(len(enviados), 1)
        host, ruta, datos = enviados[0]
        self.assertEqual((host, ruta), ("oauth2.googleapis.com", "/token"))
        self.assertEqual(urllib.parse.parse_qs(datos.decode("ascii"), strict_parsing=True), {
            "code": ["4/codigo"], "client_id": [CLIENT_ID], "client_secret": [CLIENT_SECRET],
            "redirect_uri": [REDIRECT], "grant_type": ["authorization_code"], "code_verifier": [VERIFIER]})

    def test_rechazado(self):
        for estado in (400, 401):
            with self.subTest(estado=estado):
                with self.assertRaises(externos.CanjeFallido) as error:
                    self.canjear(estado, b'{"error":"invalid_grant"}')
                self.assertEqual(error.exception.motivo, "rechazado")

    def test_no_disponible(self):
        for estado in (302, 403, 429, 500, 503):
            with self.subTest(estado=estado):
                with self.assertRaises(externos.ProveedorNoDisponible) as error:
                    self.canjear(estado, b"")
                self.assertEqual(error.exception.motivo, "estado")

    def test_respuesta_no_valida(self):
        casos = {b"no es json": "json", b"[1]": "json", b"[" * 5000: "json", b"{}": "id_token_formato",
                 json.dumps({"id_token": id_token(aud="otro")}).encode(): "aud"}
        for cuerpo, motivo in casos.items():
            with self.subTest(motivo=motivo, cuerpo=cuerpo[:20]):
                with self.assertRaises(externos.CanjeFallido) as error:
                    self.canjear(200, cuerpo)
                self.assertEqual(error.exception.motivo, motivo)


if __name__ == "__main__":
    unittest.main()
