"""Pruebas unitarias de la traducción de excepciones a respuestas HTTP del
personal (app/rutas_personal.py, instalar_errores), del evento de redacción
y del evento de acceso denegado.

Se instala sobre una aplicación FastAPI real, sin servidor, y se llama a cada
manejador registrado. Un cambio en esta tabla cambia un código HTTP de
seguridad (401, 403, 409, 429, 503...): los valores esperados son literales.
El acceso denegado se prueba además de punta a punta por la aplicación ASGI,
con el router real y la dependencia de sesión real (solo se sustituye
personal.autenticar, que necesita la base de datos): así se comprueba que la
sesión que deja la dependencia llega al manejador.
"""
import asyncio
import types
import unittest
import uuid
from unittest import mock

from fastapi import FastAPI, Request

from app import cripto, denuncias, instruccion, limitador, personal, rutas_personal

# Excepción -> (código, cuerpo, cabeceras extra que deben estar).
ESPERADO = {
    personal.CredencialesNoValidas: (401, "credenciales no válidas", {}),
    personal.SesionNoValida: (401, "sesión no válida", {"www-authenticate": "Bearer"}),
    personal.InvitacionNoValida: (401, "invitación no válida", {}),
    personal.CodigoNoValido: (422, "código no válido", {}),
    personal.Saturado: (503, "servicio ocupado; inténtelo de nuevo en unos segundos", {"retry-after": "5"}),
    personal.Prohibido: (403, "permiso denegado", {}),
    personal.NoEncontrado: (404, "recurso no encontrado", {}),
    personal.EmailDuplicado: (409, "ya existe una cuenta con ese email", {}),
    personal.UltimoAdmin: (409, "la empresa se quedaría sin ningún admin activo", {}),
    personal.EmpresaSinClave: (503, "el canal de esta empresa no está disponible; inténtelo más tarde", {}),
    denuncias.EmpresaSinClave: (503, "el canal de esta empresa no está disponible; inténtelo más tarde", {}),
    cripto.ErrorIntegridad: (500, "error interno", {}),
    instruccion.TransicionNoValida: (409, "la denuncia no puede pasar a ese estado desde el actual", {}),
    instruccion.DenunciaCerrada: (409, "la denuncia está cerrada", {}),
    instruccion.LimiteMensajes: (409, "la denuncia ha alcanzado el máximo de mensajes", {}),
    instruccion.DestinoNoValido: (409, "la cuenta de destino no está activa", {}),
    instruccion.MensajeFinalObligatorio: (422, "cerrar una denuncia exige un mensaje final para el denunciante", {}),
    instruccion.MensajeNoPermitido: (422, "declarar una denuncia no veraz no admite mensaje", {}),
    instruccion.FragmentoNoCoincide: (409, "el texto indicado no está en esa posición", {}),
}


def aplicacion():
    app = FastAPI()
    rutas_personal.instalar_errores(app)
    return app


def peticion(scope=None):
    # Sin sesión en el estado, salvo que el scope la traiga.
    return Request({"type": "http", **(scope or {})})


def responder(app, error, scope=None):
    return asyncio.run(app.exception_handlers[type(error)](peticion(scope), error))


def detalle(texto):
    return ('{"detalle": "' + texto + '"}').encode()


class TablaDeErrores(unittest.TestCase):
    def test_cada_excepcion_su_respuesta(self):
        app = aplicacion()
        # Estos tres dejan un evento (su texto se prueba en test_eventos_sin_datos);
        # el resto no registra nada. 403 y 404 tampoco, porque la petición no
        # trae sesión (con sesión, AccesoDenegado).
        con_evento = (personal.EmpresaSinClave, denuncias.EmpresaSinClave, cripto.ErrorIntegridad)
        for clase, (codigo, cuerpo, cabeceras) in ESPERADO.items():
            with self.subTest(excepcion=f"{clase.__module__}.{clase.__name__}"):
                if clase in con_evento:
                    registro = self.assertLogs("canario.personal", "ERROR")
                else:
                    registro = self.assertNoLogs("canario.personal", "DEBUG")
                with registro:
                    respuesta = responder(app, clase())
                self.assertEqual(respuesta.status_code, codigo)
                self.assertEqual(respuesta.body, detalle(cuerpo))
                self.assertEqual(respuesta.headers["content-type"], "application/json")
                for nombre, valor in cabeceras.items():
                    self.assertEqual(respuesta.headers.get(nombre), valor)

    def test_contrasena_no_valida_devuelve_su_motivo(self):
        motivo = "la contraseña debe tener entre 12 y 128 caracteres"
        respuesta = responder(aplicacion(), personal.ContrasenaNoValida(motivo))
        self.assertEqual((respuesta.status_code, respuesta.body), (422, detalle(motivo)))

    def test_limite_de_cuenta_con_sus_segundos(self):
        respuesta = responder(aplicacion(), rutas_personal.LimiteCuentaSuperado(37))
        self.assertEqual((respuesta.status_code, respuesta.headers.get("retry-after")), (429, "37"))
        self.assertEqual(respuesta.body, detalle("demasiadas peticiones; inténtelo de nuevo más tarde"))

    def test_limitador_no_disponible_falla_cerrado(self):
        with self.assertLogs("canario.personal", "ERROR") as registro:
            respuesta = responder(aplicacion(), limitador.NoDisponible("ConnectionError"))
        self.assertEqual((respuesta.status_code, respuesta.headers.get("retry-after")), (503, "5"))
        self.assertEqual(registro.output, ["ERROR:canario.personal:EVENTO limitador_no_disponible: ConnectionError"])

    def test_eventos_sin_datos(self):
        app = aplicacion()
        with self.assertLogs("canario.personal", "ERROR") as registro:
            responder(app, denuncias.EmpresaSinClave())
            responder(app, cripto.ErrorIntegridad("detalle interno"))
        self.assertEqual(registro.output, [
            "ERROR:canario.personal:EVENTO empresa_sin_clave: una empresa activa no tiene clave de cifrado",
            "ERROR:canario.personal:INTEGRIDAD: un secreto o una clave del personal no se puede descifrar en su sitio",
        ])


class EventoDeRedaccion(unittest.TestCase):
    def test_posiciones_y_longitudes_nunca_el_texto(self):
        sesion = types.SimpleNamespace(empresa_id=uuid.UUID(int=1), usuario_id=uuid.UUID(int=2))
        tramos = [rutas_personal.Tramo(desde=3, texto="NombreSecreto"), rutas_personal.Tramo(desde=40, texto="ab")]
        with self.assertLogs("canario.personal", "WARNING") as registro:
            rutas_personal._registrar_redaccion(sesion, uuid.UUID(int=3), None, tramos)
            rutas_personal._registrar_redaccion(sesion, uuid.UUID(int=3), 7, tramos[:1])
        self.assertEqual(registro.output, [
            ("WARNING:canario.personal:EVENTO redaccion: empresa=00000000-0000-0000-0000-000000000001 "
             "cuenta=00000000-0000-0000-0000-000000000002 denuncia=00000000-0000-0000-0000-000000000003 "
             "mensaje=- tramos=3+13,40+2"),
            ("WARNING:canario.personal:EVENTO redaccion: empresa=00000000-0000-0000-0000-000000000001 "
             "cuenta=00000000-0000-0000-0000-000000000002 denuncia=00000000-0000-0000-0000-000000000003 "
             "mensaje=7 tramos=3+13"),
        ])
        self.assertNotIn("NombreSecreto", "\n".join(registro.output))


SESION = personal.Sesion(empresa_id=uuid.UUID(int=1), identificador="alfa", sesion_id=uuid.UUID(int=9),
                         usuario_id=uuid.UUID(int=2), dispositivo_id=uuid.UUID(int=8), rol="instructor",
                         email="instructor@alfa.test", nombre_empresa="Alfa")
INICIO_EVENTO = ("WARNING:canario.personal:EVENTO acceso_denegado: empresa=00000000-0000-0000-0000-000000000001 "
                 "cuenta=00000000-0000-0000-0000-000000000002 ")


class AccesoDenegado(unittest.TestCase):
    """El manejador, llamado con una petición construida a mano."""

    def test_con_sesion_una_linea_por_denegacion(self):
        app = aplicacion()
        scope = {"method": "POST", "state": {"sesion_personal": SESION},
                 "route": types.SimpleNamespace(path="/v1/personal/denuncias/{denuncia_id}/redaccion"),
                 "path_params": {"denuncia_id": "00000000-0000-0000-0000-000000000003"}}
        with self.assertLogs("canario.personal", "WARNING") as registro:
            prohibido = responder(app, personal.Prohibido(), scope)
            no_encontrado = responder(app, personal.NoEncontrado(), scope)
        self.assertEqual((prohibido.status_code, prohibido.body), (403, detalle("permiso denegado")))
        self.assertEqual((no_encontrado.status_code, no_encontrado.body), (404, detalle("recurso no encontrado")))
        self.assertEqual(registro.output, [
            (INICIO_EVENTO + "codigo=403 metodo=POST ruta=/v1/personal/denuncias/{denuncia_id}/redaccion "
             "ids=denuncia_id=00000000-0000-0000-0000-000000000003"),
            (INICIO_EVENTO + "codigo=404 metodo=POST ruta=/v1/personal/denuncias/{denuncia_id}/redaccion "
             "ids=denuncia_id=00000000-0000-0000-0000-000000000003"),
        ])

    def test_sin_sesion_ninguna_linea(self):
        # El camino anónimo no deja líneas (docs/threat-model.md, 6.5). El
        # control es la prueba anterior: con sesión, sí.
        app = aplicacion()
        scope = {"method": "GET", "path_params": {"denuncia_id": "00000000-0000-0000-0000-000000000003"}}
        with self.assertNoLogs("canario.personal", "DEBUG"):
            self.assertEqual(responder(app, personal.Prohibido(), scope).status_code, 403)
            self.assertEqual(responder(app, personal.NoEncontrado(), scope).status_code, 404)


class LimitadorQueAdmite:
    async def consumir_cuenta(self, _empresa_id, _usuario_id):
        return True, 0, False


def aplicacion_completa():
    app = aplicacion()
    app.include_router(rutas_personal.router)
    # Las rutas leen pool y claves antes de validar el id; ninguna prueba
    # llega a usarlos, porque la denegación ocurre antes.
    app.state.pool = None
    app.state.claves = None
    app.state.limitador = LimitadorQueAdmite()
    return app


def llamar(app, metodo, ruta):
    """Una petición por la aplicación ASGI, como la entregaría uvicorn: con la
    ruta ya decodificada (un %0A llega como salto de línea)."""
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": metodo,
             "scheme": "http", "path": ruta, "raw_path": ruta.encode("utf-8"), "root_path": "",
             "query_string": b"", "headers": [(b"authorization", b"Bearer token")], "client": None,
             "server": ("api", 8000)}
    mensajes = []

    async def recibir():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def enviar(mensaje):
        mensajes.append(mensaje)

    asyncio.run(app(scope, recibir, enviar))
    estado = next(m["status"] for m in mensajes if m["type"] == "http.response.start")
    return estado, b"".join(m.get("body", b"") for m in mensajes if m["type"] == "http.response.body")


class AccesoDenegadoPorLaAplicacion(unittest.TestCase):
    """De la dependencia de sesión al manejador, con el router real."""

    def test_instructor_en_ruta_de_admin(self):
        with mock.patch.object(personal, "autenticar", return_value=SESION), \
                self.assertLogs("canario.personal", "WARNING") as registro:
            respuesta = llamar(aplicacion_completa(), "POST",
                               "/v1/personal/usuarios/00000000-0000-0000-0000-000000000003/baja")
        self.assertEqual(respuesta, (403, detalle("permiso denegado")))
        self.assertEqual(registro.output, [
            INICIO_EVENTO + ("codigo=403 metodo=POST ruta=/v1/personal/usuarios/{usuario_id}/baja "
                             "ids=usuario_id=00000000-0000-0000-0000-000000000003")])

    def test_salto_de_linea_en_la_ruta_no_llega_al_log(self):
        with mock.patch.object(personal, "autenticar", return_value=SESION), \
                self.assertLogs("canario.personal", "WARNING") as registro:
            respuesta = llamar(aplicacion_completa(), "GET",
                               "/v1/personal/denuncias/x\nEVENTO redaccion: falso")
        self.assertEqual(respuesta, (404, detalle("recurso no encontrado")))
        self.assertEqual(registro.output, [
            INICIO_EVENTO + "codigo=404 metodo=GET ruta=/v1/personal/denuncias/{denuncia_id} ids=denuncia_id=invalido"])

    def test_token_no_valido_no_registra(self):
        # Sin sesión no hay cuenta a la que atribuir nada: 401 y ninguna línea.
        with mock.patch.object(personal, "autenticar", side_effect=personal.SesionNoValida), \
                self.assertNoLogs("canario.personal", "DEBUG"):
            respuesta = llamar(aplicacion_completa(), "POST",
                               "/v1/personal/usuarios/00000000-0000-0000-0000-000000000003/baja")
        self.assertEqual(respuesta, (401, detalle("sesión no válida")))
