"""Pruebas unitarias del transporte de las credenciales del personal
(app/rutas_personal.py): cliente con Bearer o navegador con cookies.

Primero las dos funciones puras (qué cookies de Canario trae una petición y si
es del navegador), con una tabla de casos. Después, de punta a punta por la
aplicación ASGI con el router real y la dependencia real: solo se sustituyen
las funciones de app/personal.py, que necesitan la base de datos. Así se
comprueba lo que sale de verdad: el estado, el cuerpo y cada Set-Cookie,
literales.

Lo que el navegador hace con esas cabeceras (que envíe Sec-Fetch-Site, que
respete __Host-) no se puede probar aquí: lo prueba la batería con un
navegador real (bloque 6b). Las cookies a través de Caddy las prueba
tests/security/verificar_sesion.py.
"""
import asyncio
import json
import re
import unittest
import uuid
from unittest import mock

from fastapi import FastAPI

from app import personal, rutas_personal

ORIGEN = "https://localhost:8445"
OTRO_PUERTO = "https://localhost:8444"
# Lo que manda la SPA: un GET no lleva Origin (MDN, Origin), un POST sí.
LECTURA = {"sec-fetch-site": "same-origin"}
ESCRITURA = {"sec-fetch-site": "same-origin", "origin": ORIGEN}

JWT = "eyJhbGciOiJIUzI1NiJ9.e30.firma-de_prueba"
RENOVACION = "0123456789abcdef0123456789abcdef.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
DISPOSITIVO = "0123456789abcdef0123456789abcdef.BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

# Set-Cookie exactos de Starlette 1.7.0 (observados con la versión fijada).
COOKIE_ACCESO = f"__Host-canario_acceso={JWT}; HttpOnly; Max-Age=300; Path=/; SameSite=strict; Secure"
COOKIE_RENOVACION = (f"__Host-canario_renovacion={RENOVACION}; HttpOnly; Max-Age=28800; Path=/; "
                     "SameSite=strict; Secure")
COOKIE_DISPOSITIVO = (f"__Host-canario_dispositivo={DISPOSITIVO}; HttpOnly; Max-Age=7776000; Path=/; "
                      "SameSite=strict; Secure")
# Un borrado: mismo nombre, vacía, caducada y con los mismos atributos
# (sin Secure, el navegador ignora el borrado de una cookie __Host-).
BORRADO = re.compile(r'(__Host-canario_[a-z]+)=""; expires=[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} '
                     r"\d{2}:\d{2}:\d{2} GMT; HttpOnly; Max-Age=0; Path=/; SameSite=strict; Secure")

SESION = personal.Sesion(empresa_id=uuid.UUID(int=1), identificador="alfa", sesion_id=uuid.UUID(int=9),
                         usuario_id=uuid.UUID(int=2), dispositivo_id=uuid.UUID(int=8), rol="instructor",
                         email="instructor@alfa.test", nombre_empresa="Alfa")
LOGIN = {"empresa": "alfa", "email": "instructor@alfa.test", "contrasena": "una contraseña larga",
         "codigo_totp": "123456"}


class CookiesCanario(unittest.TestCase):
    def test_lee_las_suyas_e_ignora_el_resto(self):
        cabeceras = [f"otra=1; __Host-canario_acceso={JWT};tema=oscuro", f"__Host-canario_renovacion={RENOVACION}"]
        self.assertEqual(rutas_personal.cookies_canario(cabeceras),
                         {"__Host-canario_acceso": JWT, "__Host-canario_renovacion": RENOVACION})

    def test_nombres_parecidos_no_son_suyas(self):
        # Sin el prefijo exacto, una cookie puede venir de cualquier puerto o
        # ruta: no se lee.
        for cabecera in ("__host-canario_acceso=x", "canario_acceso=x", "__Host-canario_acceso2=x",
                         " __Host-Canario_acceso=x"):
            with self.subTest(cabecera=cabecera):
                self.assertEqual(rutas_personal.cookies_canario([cabecera]), {})

    def test_repetida_o_demasiado_larga_no_vale_ninguna(self):
        for cabeceras in (["__Host-canario_acceso=a; __Host-canario_acceso=b"],
                          ["__Host-canario_acceso=a", "__Host-canario_acceso=a"],
                          ["__Host-canario_dispositivo=" + "x" * 513]):
            with self.subTest(cabeceras=[c[:60] for c in cabeceras]), self.assertRaises(personal.SesionNoValida):
                rutas_personal.cookies_canario(cabeceras)
        # Control: 512 caracteres sí.
        largo = "x" * 512
        self.assertEqual(rutas_personal.cookies_canario(["__Host-canario_dispositivo=" + largo]),
                         {"__Host-canario_dispositivo": largo})


class EsNavegador(unittest.TestCase):
    def test_cliente_sin_sec_fetch_site_ni_cookies(self):
        # Las baterías y cualquier cliente que no es un navegador: Bearer.
        for metodo, cabeceras in (("GET", {}), ("POST", {"authorization": "Bearer x"}),
                                  ("POST", {"origin": OTRO_PUERTO})):
            with self.subTest(metodo=metodo, cabeceras=cabeceras):
                self.assertFalse(rutas_personal.es_navegador(metodo, cabeceras, False, ORIGEN))

    def test_spa(self):
        for metodo, cabeceras, hay_cookies in (("GET", LECTURA, True), ("HEAD", LECTURA, True),
                                               ("GET", LECTURA, False), ("POST", ESCRITURA, False),
                                               ("POST", ESCRITURA, True), ("PUT", ESCRITURA, True),
                                               ("DELETE", ESCRITURA, True)):
            with self.subTest(metodo=metodo, cabeceras=cabeceras, hay_cookies=hay_cookies):
                self.assertTrue(rutas_personal.es_navegador(metodo, cabeceras, hay_cookies, ORIGEN))

    def test_rechazos_y_su_sitio_para_el_log(self):
        casos = [
            # Otro puerto de localhost es el mismo sitio: SameSite no lo frena.
            ("POST", {"sec-fetch-site": "same-site", "origin": OTRO_PUERTO}, True, "same-site"),
            ("GET", {"sec-fetch-site": "same-site"}, True, "same-site"),
            ("POST", {"sec-fetch-site": "cross-site", "origin": "https://atacante.example"}, True, "cross-site"),
            # Navegación escrita a mano o desde un marcador.
            ("GET", {"sec-fetch-site": "none"}, True, "none"),
            # Cookies sin Sec-Fetch-Site: no es la SPA.
            ("GET", {}, True, "-"),
            ("POST", {"origin": ORIGEN}, True, "-"),
            # Mismo origen según Sec-Fetch-Site pero sin el Origin de la SPA.
            ("POST", {"sec-fetch-site": "same-origin"}, True, "same-origin"),
            ("POST", {"sec-fetch-site": "same-origin", "origin": "null"}, False, "same-origin"),
            ("DELETE", {"sec-fetch-site": "same-origin", "origin": "https://localhost:8443"}, True, "same-origin"),
            ("POST", {"sec-fetch-site": "same-origin", "origin": ORIGEN + "/"}, True, "same-origin"),
            # Un valor que ningún navegador envía no llega al log tal cual.
            ("GET", {"sec-fetch-site": "same-origin\nEVENTO falso"}, True, "otro"),
        ]
        for metodo, cabeceras, hay_cookies, sitio in casos:
            with self.subTest(metodo=metodo, cabeceras=cabeceras, hay_cookies=hay_cookies):
                with self.assertRaises(rutas_personal.OrigenNoPermitido) as contexto:
                    rutas_personal.es_navegador(metodo, cabeceras, hay_cookies, ORIGEN)
                self.assertEqual(contexto.exception.sitio, sitio)

    def test_sin_origen_configurado_falla_cerrado(self):
        with self.assertRaises(rutas_personal.OrigenNoPermitido):
            rutas_personal.es_navegador("POST", ESCRITURA, True, None)
        # Control: un GET no compara el origen.
        self.assertTrue(rutas_personal.es_navegador("GET", LECTURA, True, None))

    def test_bearer_en_el_navegador_es_ambiguo(self):
        with self.assertRaises(personal.SesionNoValida):
            rutas_personal.es_navegador("GET", {**LECTURA, "authorization": "Bearer x"}, True, ORIGEN)


# ---------------------------------------------------------------------------
# De punta a punta por la aplicación ASGI
# ---------------------------------------------------------------------------
class LimitadorQueAdmite:
    async def consumir_cuenta(self, _empresa_id, _usuario_id):
        return True, 0, False


def aplicacion():
    app = FastAPI()
    rutas_personal.instalar_errores(app)
    app.include_router(rutas_personal.router)
    app.state.pool = None
    app.state.claves = None
    app.state.limitador = LimitadorQueAdmite()
    app.state.origen_personal = ORIGEN
    # El sitio del denunciante: /yo compone con él el enlace del canal
    # (app/rutas_personal.py). La API real lo fija al arrancar.
    app.state.origen_web = OTRO_PUERTO
    return app


def llamar(metodo, ruta, cabeceras=None, cuerpo=None):
    """(estado, cuerpo, [Set-Cookie]) de una petición por la aplicación ASGI."""
    datos = b"" if cuerpo is None else json.dumps(cuerpo).encode("utf-8")
    lista = [(n.encode("latin-1"), v.encode("latin-1")) for n, v in (cabeceras or {}).items()]
    if cuerpo is not None:
        lista.append((b"content-type", b"application/json"))
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": metodo,
             "scheme": "http", "path": ruta, "raw_path": ruta.encode("utf-8"), "root_path": "",
             "query_string": b"", "headers": lista, "client": None, "server": ("api", 8000)}
    mensajes = []

    async def recibir():
        return {"type": "http.request", "body": datos, "more_body": False}

    async def enviar(mensaje):
        mensajes.append(mensaje)

    asyncio.run(aplicacion()(scope, recibir, enviar))
    inicio = next(m for m in mensajes if m["type"] == "http.response.start")
    cookies = [v.decode("latin-1") for n, v in inicio["headers"] if n == b"set-cookie"]
    cuerpo = b"".join(m.get("body", b"") for m in mensajes if m["type"] == "http.response.body")
    return inicio["status"], cuerpo, cookies


def con_cookies(cabeceras, **valores):
    nombres = {"acceso": "__Host-canario_acceso", "renovacion": "__Host-canario_renovacion",
               "dispositivo": "__Host-canario_dispositivo"}
    return {**cabeceras, "cookie": "; ".join(f"{nombres[n]}={v}" for n, v in valores.items())}


class Respuestas(unittest.TestCase):
    def test_login_en_el_navegador_pone_las_tres_cookies(self):
        acceso = personal.Acceso(JWT, RENOVACION, DISPOSITIVO)
        with mock.patch.object(personal, "iniciar_sesion", return_value=acceso) as iniciar:
            estado, cuerpo, cookies = llamar("POST", "/v1/personal/sesiones", ESCRITURA, LOGIN)
        self.assertEqual((estado, json.loads(cuerpo)), (201, {"expira_en": 300}))
        self.assertEqual(cookies, [COOKIE_ACCESO, COOKIE_RENOVACION, COOKIE_DISPOSITIVO])
        # Sin cookie de dispositivo, entra sin dispositivo.
        self.assertIsNone(iniciar.call_args.args[6])

    def test_login_en_el_navegador_lee_el_dispositivo_de_su_cookie(self):
        acceso = personal.Acceso(JWT, RENOVACION, None)
        with mock.patch.object(personal, "iniciar_sesion", return_value=acceso) as iniciar:
            estado, _, cookies = llamar("POST", "/v1/personal/sesiones",
                                        con_cookies(ESCRITURA, dispositivo=DISPOSITIVO), LOGIN)
        self.assertEqual(iniciar.call_args.args[6], DISPOSITIVO)
        # Entró con dispositivo de confianza: no hay uno nuevo que guardar.
        self.assertEqual((estado, cookies), (201, [COOKIE_ACCESO, COOKIE_RENOVACION]))

    def test_login_en_el_navegador_con_el_dispositivo_en_el_cuerpo_es_422(self):
        with mock.patch.object(personal, "iniciar_sesion") as iniciar:
            estado, cuerpo, cookies = llamar("POST", "/v1/personal/sesiones", ESCRITURA,
                                             {**LOGIN, "token_dispositivo": DISPOSITIVO})
        self.assertEqual((estado, cuerpo, cookies), (422, '{"detalle": "petición no válida"}'.encode(), []))
        iniciar.assert_not_called()

    def test_login_del_cliente_sin_cookies_y_con_los_tokens_en_el_cuerpo(self):
        # Control de las anteriores: el cliente con Bearer no cambia.
        acceso = personal.Acceso(JWT, RENOVACION, DISPOSITIVO)
        with mock.patch.object(personal, "iniciar_sesion", return_value=acceso):
            estado, cuerpo, cookies = llamar("POST", "/v1/personal/sesiones", {}, LOGIN)
        self.assertEqual((estado, cookies), (201, []))
        self.assertEqual(json.loads(cuerpo), {"token_acceso": JWT, "token_renovacion": RENOVACION, "expira_en": 300,
                                              "token_dispositivo": DISPOSITIVO})

    def test_renovacion_en_el_navegador_lee_su_cookie(self):
        nuevo = personal.Acceso(JWT, RENOVACION)
        with mock.patch.object(personal, "renovar", return_value=nuevo) as renovar:
            estado, cuerpo, cookies = llamar("POST", "/v1/personal/sesiones/renovacion",
                                             con_cookies(ESCRITURA, renovacion="viejo.token"), {})
        self.assertEqual(renovar.call_args.args[2], "viejo.token")
        self.assertEqual((estado, json.loads(cuerpo), cookies), (200, {"expira_en": 300},
                                                                  [COOKIE_ACCESO, COOKIE_RENOVACION]))

    def test_renovacion_cada_token_en_su_sitio(self):
        with mock.patch.object(personal, "renovar") as renovar:
            # En el navegador, en el cuerpo no; en el cliente, sin él no.
            en_el_cuerpo = llamar("POST", "/v1/personal/sesiones/renovacion",
                                  con_cookies(ESCRITURA, renovacion="a.b"), {"token_renovacion": "a.b"})
            sin_token = llamar("POST", "/v1/personal/sesiones/renovacion", {}, {})
            sin_cookie = llamar("POST", "/v1/personal/sesiones/renovacion", ESCRITURA, {})
        self.assertEqual(en_el_cuerpo[0], 422)
        self.assertEqual(sin_token[0], 422)
        self.assertEqual((sin_cookie[0], sin_cookie[1]), (401, '{"detalle": "sesión no válida"}'.encode()))
        renovar.assert_not_called()

    def test_ruta_con_sesion_usa_la_cookie_de_acceso(self):
        with mock.patch.object(personal, "autenticar", return_value=SESION) as autenticar, \
                mock.patch.object(personal, "invitacion_pendiente", return_value=False), \
                mock.patch.object(personal, "vinculos", return_value=()):
            estado, _, _ = llamar("GET", "/v1/personal/yo", con_cookies(LECTURA, acceso=JWT, renovacion="r.r"))
        self.assertEqual((estado, autenticar.call_args.args[2]), (200, JWT))

    def test_cierre_en_el_navegador_borra_acceso_y_renovacion(self):
        with mock.patch.object(personal, "autenticar", return_value=SESION), \
                mock.patch.object(personal, "cerrar_sesion") as cerrar:
            estado, _, cookies = llamar("DELETE", "/v1/personal/sesiones/actual",
                                        con_cookies(ESCRITURA, acceso=JWT, dispositivo=DISPOSITIVO))
        cerrar.assert_called_once()
        self.assertEqual(estado, 204)
        self.assertEqual([BORRADO.fullmatch(c) and BORRADO.fullmatch(c).group(1) for c in cookies],
                         ["__Host-canario_acceso", "__Host-canario_renovacion"])

    def test_origen_rechazado_403_con_evento_y_sin_llegar_a_la_logica(self):
        with mock.patch.object(personal, "iniciar_sesion") as iniciar, \
                self.assertLogs("canario.personal", "WARNING") as registro:
            estado, cuerpo, _ = llamar("POST", "/v1/personal/sesiones",
                                       {"sec-fetch-site": "same-site", "origin": OTRO_PUERTO}, LOGIN)
        self.assertEqual((estado, cuerpo), (403, b'{"detalle": "permiso denegado"}'))
        iniciar.assert_not_called()
        self.assertEqual(registro.output, [
            "WARNING:canario.personal:EVENTO origen_rechazado: metodo=POST ruta=/v1/personal/sesiones sitio=same-site"])

    def test_bearer_y_cookie_a_la_vez_401_sin_autenticar(self):
        with mock.patch.object(personal, "autenticar") as autenticar:
            estado, _, _ = llamar("GET", "/v1/personal/yo",
                                  {**con_cookies(LECTURA, acceso=JWT), "authorization": f"Bearer {JWT}"})
        self.assertEqual(estado, 401)
        autenticar.assert_not_called()


if __name__ == "__main__":
    unittest.main()
