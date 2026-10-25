"""Pruebas unitarias de las rutas del login externo (app/rutas_externo.py).

De punta a punta por la aplicación ASGI, con los routers reales y sus
dependencias reales, como tests/unit/test_transporte.py: solo se sustituyen
el broker (app/cliente_broker.py), las funciones de app/personal.py que
necesitan la base de datos y el limitador (Redis). El flujo y el ticket son
los de verdad, sellados con app/externo.py. Así se comprueba lo que sale: el
estado, el destino del 303, cada Set-Cookie y cada EVENTO, literales.

Lo que depende del navegador (que guarde la cookie Strict de la vuelta, que
mande Fetch Metadata), de Redis, de PostgreSQL o del broker de verdad lo
prueba la batería tests/security/verificar_login_externo.py.
"""
import asyncio
import contextlib
import datetime
import json
import re
import unittest
import uuid
from unittest import mock
from urllib.parse import urlencode

from fastapi import FastAPI

from app import (
    claves,
    cliente_broker,
    correo,
    cripto,
    externo,
    frontera_http,
    limitador,
    personal,
    rutas_externo,
    rutas_personal,
)

ORIGEN = "https://localhost:8445"
LECTURA = {"sec-fetch-site": "same-origin"}
ESCRITURA = {"sec-fetch-site": "same-origin", "origin": ORIGEN}
# Lo que manda el navegador al volver de Google.
NAVEGACION = {"sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document"}

CLAVE_FLUJO = bytes(range(32))
CLAVE_IDENTIDADES = bytes(range(32, 64))
CLAVES = claves.Claves(maestra=bytes(32), hmac_codigos=bytes(32), firma_tokens=bytes(range(64, 96)),
                       hmac_identidades=CLAVE_IDENTIDADES, flujo_externo=CLAVE_FLUJO)
EMPRESA = uuid.UUID(int=1)
IDENTIFICADOR = "0123456789abcdef0123456789abcdef"
SESION_ID = uuid.UUID(int=9)
SESION = personal.Sesion(empresa_id=EMPRESA, identificador=IDENTIFICADOR, sesion_id=SESION_ID,
                         usuario_id=uuid.UUID(int=2), dispositivo_id=uuid.UUID(int=8), rol="admin",
                         email="titular@alfa.test", nombre_empresa="Alfa")
SUB = "109876543210987654321"
CODE = "4/0AQSTgQ-codigo-de-prueba"
URL_GOOGLE = "https://accounts.google.com/o/oauth2/v2/auth?client_id=x&state=y"
ISS = "https://accounts.google.com"
JWT = "eyJhbGciOiJIUzI1NiJ9.e30.firma-de_prueba"
RENOVACION = "0123456789abcdef0123456789abcdef.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
DISPOSITIVO = "0123456789abcdef0123456789abcdef.BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
RUTA_VUELTA = "/v1/personal/externo/google/vuelta"

# Literales del formato (tests/unit/test_externo.py) y de Starlette 1.7.0.
COOKIE_FLUJO = re.compile(r"__Host-canario_flujo=([A-Za-z0-9_-]{244}); HttpOnly; Max-Age=600; Path=/; "
                          r"SameSite=lax; Secure")
COOKIE_TICKET = re.compile(r"__Host-canario_ticket=([A-Za-z0-9_-]{180}); HttpOnly; Max-Age=300; Path=/; "
                           r"SameSite=strict; Secure")
COOKIE_ACCESO = f"__Host-canario_acceso={JWT}; HttpOnly; Max-Age=300; Path=/; SameSite=strict; Secure"
COOKIE_RENOVACION = (f"__Host-canario_renovacion={RENOVACION}; HttpOnly; Max-Age=28800; Path=/; "
                     "SameSite=strict; Secure")
BORRADO = re.compile(r'(__Host-canario_[a-z]+)=""; expires=[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} '
                     r"\d{2}:\d{2}:\d{2} GMT; HttpOnly; Max-Age=0; Path=/; SameSite=(lax|strict); Secure")
CUERPO_401 = '{"detalle": "credenciales no válidas"}'.encode()


class LimitadorFalso:
    """consumir_una_vez sin Redis: apunta cada llamada y devuelve primera
    (o lanza fallo)."""

    def __init__(self, primera=True, fallo=None):
        self.primera = primera
        self.fallo = fallo
        self.llamadas = []

    async def consumir_cuenta(self, _empresa_id, _usuario_id):
        return True, 0, False

    async def consumir_una_vez(self, espacio, identificador, segundos):
        self.llamadas.append((espacio, identificador, segundos))
        if self.fallo is not None:
            raise self.fallo
        return self.primera


def aplicacion(limitador_falso):
    app = FastAPI()
    rutas_personal.instalar_errores(app)
    rutas_externo.instalar_errores(app)
    app.include_router(rutas_personal.router)
    app.include_router(rutas_externo.router)
    app.include_router(rutas_externo.router_vuelta)
    app.state.pool = None
    app.state.claves = CLAVES
    app.state.limitador = limitador_falso
    app.state.origen_personal = ORIGEN
    app.state.origen_web = "https://localhost:8444"
    return app


class Respuesta:
    def __init__(self, inicio, cuerpo):
        self.estado = inicio["status"]
        self.cabeceras = [(n.decode("latin-1"), v.decode("latin-1")) for n, v in inicio["headers"]]
        self.cuerpo = cuerpo

    def cabecera(self, nombre):
        valores = [v for n, v in self.cabeceras if n == nombre]
        return valores[0] if len(valores) == 1 else valores or None

    @property
    def cookies(self):
        return [v for n, v in self.cabeceras if n == "set-cookie"]


def llamar(metodo, ruta, cabeceras=None, cuerpo=None, consulta="", limitador_falso=None):
    datos = b"" if cuerpo is None else json.dumps(cuerpo).encode("utf-8")
    lista = [(n.encode("latin-1"), v.encode("latin-1")) for n, v in (cabeceras or {}).items()]
    if cuerpo is not None:
        lista.append((b"content-type", b"application/json"))
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": metodo,
             "scheme": "http", "path": ruta, "raw_path": ruta.encode("utf-8"), "root_path": "",
             "query_string": consulta.encode("latin-1"), "headers": lista, "client": None,
             "server": ("api", 8000)}
    mensajes = []

    async def recibir():
        return {"type": "http.request", "body": datos, "more_body": False}

    async def enviar(mensaje):
        mensajes.append(mensaje)

    asyncio.run(aplicacion(limitador_falso or LimitadorFalso())(scope, recibir, enviar))
    inicio = next(m for m in mensajes if m["type"] == "http.response.start")
    return Respuesta(inicio, b"".join(m.get("body", b"") for m in mensajes if m["type"] == "http.response.body"))


def con_cookies(cabeceras, **valores):
    return {**cabeceras, "cookie": "; ".join(f"__Host-canario_{n}={v}" for n, v in valores.items())}


def flujo(proposito=externo.PROPOSITO_ACCESO):
    sesion_id = SESION_ID if proposito == externo.PROPOSITO_VINCULO else None
    nuevo = externo.nuevo_flujo("google", proposito, EMPRESA, IDENTIFICADOR, sesion_id)
    return nuevo, externo.sellar_flujo(CLAVE_FLUJO, nuevo)


def ticket(proposito=externo.PROPOSITO_ACCESO):
    return externo.emitir_ticket(CLAVE_FLUJO, CLAVE_IDENTIDADES, flujo(proposito)[0], SUB)


def consulta_de(valor_flujo, **cambios):
    parametros = {"state": valor_flujo.state, "code": CODE, "iss": ISS, "scope": "openid", "authuser": "0"}
    parametros.update(cambios)
    return urlencode([(n, v) for n, v in parametros.items() if v is not None])


def borradas(respuesta):
    return [(BORRADO.fullmatch(c).group(1), BORRADO.fullmatch(c).group(2)) for c in respuesta.cookies
            if BORRADO.fullmatch(c)]


# ---------------------------------------------------------------------------
# Cookies y transporte
# ---------------------------------------------------------------------------
class Cookies(unittest.TestCase):
    def test_flujo_y_ticket_reales_pasan_el_filtro_de_cookies(self):
        # Literales: los nombres, y que un flujo y un ticket de verdad (244 y
        # 180 caracteres) caben en el tope de una cookie de Canario. Si no
        # cupieran, cada petición con ellos sería un 401.
        self.assertEqual(rutas_personal.COOKIES[3:], ("__Host-canario_flujo", "__Host-canario_ticket"))
        sellado, texto_ticket = flujo()[1], ticket()
        self.assertEqual((len(sellado), len(texto_ticket)), (244, 180))
        leidas = rutas_personal.cookies_canario([f"__Host-canario_flujo={sellado}; __Host-canario_ticket={texto_ticket}"])
        self.assertEqual(leidas, {"__Host-canario_flujo": sellado, "__Host-canario_ticket": texto_ticket})
        # Y como las demás: repetida, no vale ninguna.
        with self.assertRaises(personal.SesionNoValida):
            rutas_personal.cookies_canario([f"__Host-canario_flujo={sellado}", f"__Host-canario_flujo={sellado}"])


class SoloNavegador(unittest.TestCase):
    def test_cliente_sin_cookies_ni_fetch_metadata_403_con_evento(self):
        with mock.patch.object(cliente_broker, "proveedores", return_value=("google",)) as proveedores:
            control = llamar("GET", "/v1/personal/externo/proveedores", LECTURA)
            with self.assertLogs("canario.personal", "WARNING") as registro:
                rechazo = llamar("GET", "/v1/personal/externo/proveedores", {})
        self.assertEqual((control.estado, json.loads(control.cuerpo)), (200, {"proveedores": ["google"]}))
        self.assertEqual((rechazo.estado, rechazo.cuerpo), (403, b'{"detalle": "permiso denegado"}'))
        self.assertEqual(proveedores.call_count, 1)
        self.assertEqual(registro.output, ["WARNING:canario.personal:EVENTO origen_rechazado: metodo=GET "
                                           "ruta=/v1/personal/externo/proveedores sitio=-"])


# ---------------------------------------------------------------------------
# Inicio
# ---------------------------------------------------------------------------
class Inicio(unittest.TestCase):
    def test_pone_el_flujo_lax_y_devuelve_la_url(self):
        with mock.patch.object(personal, "empresa_con_dispositivo", return_value=EMPRESA) as empresa, \
                mock.patch.object(cliente_broker, "autorizar", return_value=URL_GOOGLE) as autorizar:
            respuesta = llamar("POST", "/v1/personal/externo/google/inicio",
                               con_cookies(ESCRITURA, dispositivo=DISPOSITIVO), {"empresa": IDENTIFICADOR})
        self.assertEqual((respuesta.estado, json.loads(respuesta.cuerpo)), (200, {"url": URL_GOOGLE}))
        self.assertEqual(empresa.call_args.args[1:], (IDENTIFICADOR, DISPOSITIVO))
        [cookie] = respuesta.cookies
        abierto = externo.abrir_flujo(CLAVE_FLUJO, COOKIE_FLUJO.fullmatch(cookie).group(1))
        self.assertEqual((abierto.proveedor, abierto.proposito, abierto.empresa_id, abierto.identificador,
                          abierto.sesion_id), ("google", externo.PROPOSITO_ACCESO, EMPRESA, IDENTIFICADOR, None))
        self.assertEqual(autorizar.call_args.args, ("google", abierto.state, abierto.code_challenge, abierto.nonce))

    def test_sin_dispositivo_409_sin_ir_al_proveedor(self):
        with mock.patch.object(personal, "empresa_con_dispositivo", side_effect=personal.SinDispositivo), \
                mock.patch.object(cliente_broker, "autorizar") as autorizar:
            respuesta = llamar("POST", "/v1/personal/externo/google/inicio", ESCRITURA, {"empresa": IDENTIFICADOR})
        self.assertEqual((respuesta.estado, respuesta.cookies), (409, []))
        self.assertEqual(json.loads(respuesta.cuerpo), {
            "detalle": "este navegador no es de confianza para esa empresa; "
                       "la primera vez entre con su contraseña y su código"})
        autorizar.assert_not_called()

    def test_broker_caido_o_sin_configurar_sin_cookie(self):
        casos = {cliente_broker.BrokerNoDisponible("red"): (503, "5"), cliente_broker.NoConfigurado(): (404, None)}
        for error, (codigo, reintentar) in casos.items():
            with self.subTest(error=type(error).__name__):
                with mock.patch.object(personal, "empresa_con_dispositivo", return_value=EMPRESA), \
                        mock.patch.object(cliente_broker, "autorizar", side_effect=error):
                    respuesta = llamar("POST", "/v1/personal/externo/google/inicio", ESCRITURA,
                                       {"empresa": IDENTIFICADOR})
                self.assertEqual((respuesta.estado, respuesta.cookies, respuesta.cabecera("retry-after")),
                                 (codigo, [], reintentar))


# ---------------------------------------------------------------------------
# La vuelta
# ---------------------------------------------------------------------------
class Vuelta(unittest.TestCase):
    def volver(self, cabeceras, consulta, limitador_falso=None, sub=SUB):
        limitador_falso = limitador_falso or LimitadorFalso()
        with mock.patch.object(cliente_broker, "canjear", return_value=sub) as canjear:
            respuesta = llamar("GET", RUTA_VUELTA, cabeceras, consulta=consulta, limitador_falso=limitador_falso)
        return respuesta, canjear, limitador_falso

    def test_valida_deja_el_ticket_y_borra_el_flujo(self):
        for proposito, destino in ((externo.PROPOSITO_ACCESO, "/entrar/codigo"),
                                   (externo.PROPOSITO_VINCULO, "/cuenta?vinculo=pendiente")):
            with self.subTest(proposito=proposito):
                valor, sellado = flujo(proposito)
                respuesta, canjear, falso = self.volver(con_cookies(NAVEGACION, flujo=sellado), consulta_de(valor))
                self.assertEqual((respuesta.estado, respuesta.cabecera("location")), (303, destino))
                self.assertEqual(canjear.call_args.args, ("google", CODE, valor.verifier, valor.nonce))
                # El flujo se gasta antes del canje, con su jti y lo que le queda.
                [(espacio, jti, segundos)] = falso.llamadas
                self.assertEqual((espacio, jti), ("flujo", valor.jti.hex()))
                self.assertTrue(590 <= segundos <= 600, segundos)
                ticket_puesto = COOKIE_TICKET.fullmatch(respuesta.cookies[0]).group(1)
                abierto = externo.abrir_ticket(CLAVE_FLUJO, ticket_puesto, proposito)
                self.assertEqual(abierto.sub_hmac, cripto.hmac_identidad(CLAVE_IDENTIDADES, EMPRESA, "google", SUB))
                self.assertEqual(borradas(respuesta), [("__Host-canario_flujo", "lax")])

    def test_rechazos_no_llegan_al_broker(self):
        valor, sellado = flujo()
        otro_valor, otro_sellado = flujo()
        valida = con_cookies(NAVEGACION, flujo=sellado)
        casos = {
            "transporte": [({**valida, "sec-fetch-mode": "cors"}, consulta_de(valor)),
                           ({**valida, "sec-fetch-dest": "iframe"}, consulta_de(valor)),
                           ({**valida, "authorization": "Bearer x"}, consulta_de(valor)),
                           ({"cookie": valida["cookie"]}, consulta_de(valor))],
            "cookie": [({**NAVEGACION, "cookie": f"__Host-canario_flujo={sellado}; __Host-canario_flujo={sellado}"},
                        consulta_de(valor))],
            "flujo": [(NAVEGACION, consulta_de(valor)),
                      (con_cookies(NAVEGACION, flujo=sellado[:-1] + ("A" if sellado[-1] != "A" else "B")),
                       consulta_de(valor)),
                      (con_cookies(NAVEGACION, flujo=ticket()), consulta_de(valor))],
            # El state de otro flujo (el del atacante) con la cookie de este navegador.
            "state": [(valida, consulta_de(otro_valor)), (valida, consulta_de(valor, state=None)),
                      (con_cookies(NAVEGACION, flujo=otro_sellado), consulta_de(valor))],
            "iss": [(valida, consulta_de(valor, iss=None)), (valida, consulta_de(valor, iss="accounts.google.com"))],
            "parametros": [(valida, consulta_de(valor) + "&state=" + valor.state)],
            "code": [(valida, consulta_de(valor, code=None)), (valida, consulta_de(valor, code="con espacio"))],
        }
        for motivo, peticiones in casos.items():
            for indice, (cabeceras, consulta) in enumerate(peticiones):
                with self.subTest(motivo=motivo, caso=indice):
                    with self.assertLogs("canario.externo", "WARNING") as registro:
                        respuesta, canjear, falso = self.volver(cabeceras, consulta)
                    self.assertEqual((respuesta.estado, respuesta.cabecera("location")),
                                     (303, "/entrar?externo=fallido"))
                    self.assertEqual(registro.output, [
                        f"WARNING:canario.externo:EVENTO vuelta_rechazada: proveedor=google motivo={motivo}"])
                    canjear.assert_not_called()
                    self.assertEqual(falso.llamadas, [])
                    self.assertIsNone(COOKIE_TICKET.fullmatch((respuesta.cookies or [""])[0]))
                    self.assertEqual(borradas(respuesta), [("__Host-canario_flujo", "lax")])

    def test_flujo_repetido_no_llega_al_broker(self):
        valor, sellado = flujo()
        with self.assertLogs("canario.externo", "WARNING") as registro:
            respuesta, canjear, falso = self.volver(con_cookies(NAVEGACION, flujo=sellado), consulta_de(valor),
                                                    LimitadorFalso(primera=False))
        self.assertEqual((respuesta.estado, respuesta.cabecera("location")), (303, "/entrar?externo=fallido"))
        self.assertEqual(registro.output,
                         ["WARNING:canario.externo:EVENTO vuelta_rechazada: proveedor=google motivo=repetida"])
        self.assertEqual(len(falso.llamadas), 1)
        canjear.assert_not_called()

    def test_cancelar_y_otros_errores_del_proveedor(self):
        for proposito, prefijo in ((externo.PROPOSITO_ACCESO, "/entrar?externo="),
                                   (externo.PROPOSITO_VINCULO, "/cuenta?vinculo=")):
            valor, sellado = flujo(proposito)
            cabeceras = con_cookies(NAVEGACION, flujo=sellado)
            with self.subTest(proposito=proposito, error="access_denied"):
                with self.assertNoLogs("canario.externo", "WARNING"):
                    respuesta, canjear, _ = self.volver(cabeceras, f"error=access_denied&state={valor.state}")
                self.assertEqual(respuesta.cabecera("location"), prefijo + "cancelado")
                canjear.assert_not_called()
            with self.subTest(proposito=proposito, error="server_error"):
                with self.assertLogs("canario.externo", "WARNING") as registro:
                    respuesta, canjear, _ = self.volver(cabeceras, f"error=server_error&state={valor.state}")
                self.assertEqual(respuesta.cabecera("location"), prefijo + "fallido")
                self.assertEqual(registro.output, [
                    "WARNING:canario.externo:EVENTO vuelta_rechazada: proveedor=google motivo=error_proveedor"])
                canjear.assert_not_called()

    def test_fallos_del_broker_y_de_redis_sin_ticket(self):
        # El EVENTO de un broker caído lo deja cliente_broker, que aquí es falso.
        evento = "WARNING:canario.externo:EVENTO vuelta_rechazada: proveedor=google motivo="
        casos = {
            "canje rechazado": (cliente_broker.CanjeRechazado(), None, "fallido", [evento + "canje"]),
            "broker caido": (cliente_broker.BrokerNoDisponible("red"), None, "no_disponible", []),
            "sin configurar": (cliente_broker.NoConfigurado(), None, "no_disponible", [evento + "no_configurado"]),
            "redis caido": (None, limitador.NoDisponible("ConnectionError"), "no_disponible",
                            ["ERROR:canario.externo:EVENTO limitador_no_disponible: ConnectionError"]),
        }
        for nombre, (error_broker, error_redis, resultado, eventos) in casos.items():
            with self.subTest(nombre):
                valor, sellado = flujo()
                registro = self.assertLogs("canario.externo", "WARNING") if eventos else \
                    self.assertNoLogs("canario.externo", "WARNING")
                with mock.patch.object(cliente_broker, "canjear", side_effect=error_broker, return_value=SUB) as canjear, \
                        registro as capturado:
                    respuesta = llamar("GET", RUTA_VUELTA, con_cookies(NAVEGACION, flujo=sellado),
                                       consulta=consulta_de(valor), limitador_falso=LimitadorFalso(fallo=error_redis))
                if eventos:
                    self.assertEqual(capturado.output, eventos)
                self.assertEqual((respuesta.estado, respuesta.cabecera("location")),
                                 (303, "/entrar?externo=" + resultado))
                self.assertEqual(borradas(respuesta), [("__Host-canario_flujo", "lax")])
                self.assertEqual(len(respuesta.cookies), 1)
                self.assertEqual(canjear.called, error_redis is None)


class FronteraEnLaVuelta(unittest.TestCase):
    """Un error de la frontera en la vuelta es un 303, nunca un JSON en la
    pantalla (app/frontera_http.py, NAVEGACION)."""

    def frontera(self, ruta, resultado=None, fallo=None):
        class Contador:
            async def consumir(self, _regla, _cliente):
                if fallo is not None:
                    raise fallo
                return resultado

        async def interior(scope, receive, send):
            raise AssertionError("no debe llegar a la ruta")

        app = mock.Mock()
        app.state.limitador = Contador()
        scope = {"type": "http", "path": ruta, "client": ("10.0.0.1", 1), "app": app}
        enviados = []

        async def send(mensaje):
            enviados.append(mensaje)
        with self.assertLogs("canario.limitador", "ERROR") if fallo else contextlib.nullcontext():
            asyncio.run(limitador.FronteraLimitador(interior)(scope, None, send))
        return enviados

    def test_limitador_responde_303_en_la_vuelta(self):
        # Control: en cualquier otra ruta, el 429 de siempre.
        otra = self.frontera("/v1/personal/sesiones/externa", resultado=(False, 30))
        self.assertEqual((otra[0]["status"], otra[1]["body"]),
                         (429, '{"detalle": "demasiadas peticiones; inténtelo de nuevo más tarde"}'.encode()))
        for nombre, argumentos in {"429": {"resultado": (False, 30)},
                                   "503": {"fallo": limitador.NoDisponible("ConnectionError")}}.items():
            with self.subTest(nombre):
                enviados = self.frontera(RUTA_VUELTA, **argumentos)
                self.assertEqual(enviados[0], {"type": "http.response.start", "status": 303, "headers": [
                    (b"location", b"/entrar?externo=no_disponible"), (b"content-length", b"0")]})
                self.assertEqual(enviados[1], {"type": "http.response.body", "body": b""})

    def test_navegacion_son_justo_las_rutas_de_la_vuelta(self):
        self.assertEqual(frontera_http.NAVEGACION, {RUTA_VUELTA: "/entrar?externo=no_disponible"})
        self.assertEqual({ruta.path for ruta in rutas_externo.router_vuelta.routes}, set(frontera_http.NAVEGACION))
        self.assertEqual(rutas_externo.RESULTADOS, ("cancelado", "no_disponible", "fallido"))


# ---------------------------------------------------------------------------
# El paso del código
# ---------------------------------------------------------------------------
class SesionExterna(unittest.TestCase):
    def test_con_ticket_abre_la_sesion_y_borra_el_ticket(self):
        texto = ticket()
        abierto = externo.abrir_ticket(CLAVE_FLUJO, texto, externo.PROPOSITO_ACCESO)
        falso = LimitadorFalso()

        def iniciar(_pool, _claves, recibido, codigo, dispositivo, gastar):
            self.assertEqual((recibido, codigo, dispositivo), (abierto, "123456", DISPOSITIVO))
            self.assertIs(gastar(), True)
            return personal.Acceso(JWT, RENOVACION, None)

        with mock.patch.object(personal, "iniciar_sesion_externa", side_effect=iniciar) as llamada:
            respuesta = llamar("POST", "/v1/personal/sesiones/externa",
                               con_cookies(ESCRITURA, ticket=texto, dispositivo=DISPOSITIVO),
                               {"codigo_totp": "123456"}, limitador_falso=falso)
        llamada.assert_called_once()
        self.assertEqual((respuesta.estado, json.loads(respuesta.cuerpo)), (201, {"expira_en": 300}))
        self.assertEqual(respuesta.cookies[:2], [COOKIE_ACCESO, COOKIE_RENOVACION])
        self.assertEqual(borradas(respuesta), [("__Host-canario_ticket", "strict")])
        [(espacio, jti, segundos)] = falso.llamadas
        self.assertEqual((espacio, jti), ("ticket", abierto.jti.hex()))
        self.assertTrue(290 <= segundos <= 300, segundos)

    def test_401_uniforme_sin_www_authenticate(self):
        casos = {
            "sin ticket": (ESCRITURA, None),
            "ticket de vinculo": (con_cookies(ESCRITURA, ticket=ticket(externo.PROPOSITO_VINCULO)), None),
            "un flujo": (con_cookies(ESCRITURA, ticket=flujo()[1]), None),
            "codigo malo": (con_cookies(ESCRITURA, ticket=ticket()), personal.CredencialesNoValidas),
        }
        for nombre, (cabeceras, error) in casos.items():
            with self.subTest(nombre):
                with mock.patch.object(personal, "iniciar_sesion_externa", side_effect=error) as iniciar:
                    respuesta = llamar("POST", "/v1/personal/sesiones/externa", cabeceras, {"codigo_totp": "123456"})
                self.assertEqual((respuesta.estado, respuesta.cuerpo, respuesta.cookies), (401, CUERPO_401, []))
                self.assertIsNone(respuesta.cabecera("www-authenticate"))
                self.assertEqual(iniciar.called, error is not None)
        # Control: el 401 de una sesión que no vale sí la lleva (y la SPA renueva).
        sesion = llamar("GET", "/v1/personal/yo", con_cookies(LECTURA, renovacion="r.r"))
        self.assertEqual((sesion.estado, sesion.cabecera("www-authenticate")), (401, "Bearer"))


# ---------------------------------------------------------------------------
# Vínculos
# ---------------------------------------------------------------------------
def con_sesion(cabeceras, **valores):
    return con_cookies(cabeceras, acceso=JWT, **valores)


class Vinculos(unittest.TestCase):
    def test_inicio_pide_el_codigo_y_abre_un_flujo_de_su_sesion(self):
        with mock.patch.object(personal, "autenticar", return_value=SESION), \
                mock.patch.object(personal, "iniciar_vinculo") as iniciar, \
                mock.patch.object(cliente_broker, "autorizar", return_value=URL_GOOGLE):
            respuesta = llamar("POST", "/v1/personal/externo/google/vinculo/inicio", con_sesion(ESCRITURA),
                               {"codigo_totp": "123456"})
        self.assertEqual((respuesta.estado, json.loads(respuesta.cuerpo)), (200, {"url": URL_GOOGLE}))
        self.assertEqual(iniciar.call_args.args[2:], (SESION, "google", "123456"))
        abierto = externo.abrir_flujo(CLAVE_FLUJO, COOKIE_FLUJO.fullmatch(respuesta.cookies[0]).group(1))
        self.assertEqual((abierto.proposito, abierto.sesion_id, abierto.empresa_id),
                         (externo.PROPOSITO_VINCULO, SESION_ID, EMPRESA))

    def test_inicio_con_codigo_malo_401_sin_flujo(self):
        with mock.patch.object(personal, "autenticar", return_value=SESION), \
                mock.patch.object(personal, "iniciar_vinculo", side_effect=personal.CredencialesNoValidas), \
                mock.patch.object(cliente_broker, "autorizar") as autorizar:
            respuesta = llamar("POST", "/v1/personal/externo/google/vinculo/inicio", con_sesion(ESCRITURA),
                               {"codigo_totp": "000000"})
        self.assertEqual((respuesta.estado, respuesta.cuerpo, respuesta.cookies), (401, CUERPO_401, []))
        self.assertIsNone(respuesta.cabecera("www-authenticate"))
        autorizar.assert_not_called()

    def test_completar_con_el_ticket_avisa_y_borra_el_ticket(self):
        texto = ticket(externo.PROPOSITO_VINCULO)
        falso = LimitadorFalso()

        def completar(_pool, _claves, sesion, recibido, gastar):
            self.assertEqual((sesion, recibido.proposito, recibido.sesion_id), (SESION, "vinculo", SESION_ID))
            self.assertIs(gastar(), True)
            return personal.CambioDeVinculo(correos=("aviso al titular", "aviso al admin"))

        with mock.patch.object(personal, "autenticar", return_value=SESION), \
                mock.patch.object(personal, "completar_vinculo", side_effect=completar), \
                mock.patch.object(correo, "enviar_todos") as enviar:
            respuesta = llamar("POST", "/v1/personal/externo/google/vinculo", con_sesion(ESCRITURA, ticket=texto),
                               limitador_falso=falso)
        self.assertEqual(respuesta.estado, 204)
        self.assertEqual(borradas(respuesta), [("__Host-canario_ticket", "strict")])
        enviar.assert_called_once_with(("aviso al titular", "aviso al admin"))
        self.assertEqual([llamada[0] for llamada in falso.llamadas], ["ticket"])

    def test_completar_rechazos(self):
        casos = {
            "ticket de acceso": (ticket(), None, 401, CUERPO_401),
            "de otra sesion": (ticket(externo.PROPOSITO_VINCULO), personal.VinculoNoValido, 401, CUERPO_401),
            # Un texto fijo por motivo: la SPA no los distingue por el estado.
            "identidad ya vinculada": (ticket(externo.PROPOSITO_VINCULO), personal.VinculoDuplicado("identidad"),
                                       409, '{"detalle": "esa cuenta externa ya está vinculada a otra cuenta de '
                                            'la empresa"}'.encode()),
            "cuenta con vinculo": (ticket(externo.PROPOSITO_VINCULO), personal.VinculoDuplicado("cuenta"), 409,
                                   '{"detalle": "su cuenta ya tiene vinculada una cuenta de ese proveedor"}'.encode()),
        }
        for nombre, (texto, error, codigo, cuerpo) in casos.items():
            with self.subTest(nombre):
                with mock.patch.object(personal, "autenticar", return_value=SESION), \
                        mock.patch.object(personal, "completar_vinculo", side_effect=error) as completar, \
                        mock.patch.object(correo, "enviar_todos") as enviar:
                    respuesta = llamar("POST", "/v1/personal/externo/google/vinculo",
                                       con_sesion(ESCRITURA, ticket=texto))
                self.assertEqual((respuesta.estado, respuesta.cuerpo, respuesta.cookies), (codigo, cuerpo, []))
                self.assertIsNone(respuesta.cabecera("www-authenticate"))
                self.assertEqual(completar.called, error is not None)
                enviar.assert_not_called()

    def test_revocar_con_codigo_y_avisos(self):
        cambio = personal.CambioDeVinculo(correos=("aviso",))
        with mock.patch.object(personal, "autenticar", return_value=SESION), \
                mock.patch.object(personal, "revocar_vinculo", return_value=cambio) as revocar, \
                mock.patch.object(correo, "enviar_todos") as enviar:
            respuesta = llamar("DELETE", "/v1/personal/externo/google/vinculo", con_sesion(ESCRITURA),
                               {"codigo_totp": "123456"})
        self.assertEqual(respuesta.estado, 204)
        self.assertEqual(revocar.call_args.args[2:], (SESION, "google", "123456"))
        enviar.assert_called_once_with(("aviso",))

    def test_yo_solo_el_proveedor_y_el_dia(self):
        vinculo = personal.Vinculo(proveedor="google", creada=datetime.date(2026, 10, 25))
        with mock.patch.object(personal, "autenticar", return_value=SESION), \
                mock.patch.object(personal, "invitacion_pendiente", return_value=False), \
                mock.patch.object(personal, "vinculos", return_value=(vinculo,)):
            respuesta = llamar("GET", "/v1/personal/yo", con_sesion(LECTURA))
        self.assertEqual(respuesta.estado, 200)
        self.assertEqual(json.loads(respuesta.cuerpo)["vinculos"], [{"proveedor": "google", "creada": "2026-10-25"}])


if __name__ == "__main__":
    unittest.main()
