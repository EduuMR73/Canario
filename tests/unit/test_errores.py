"""Pruebas unitarias de la traducción de excepciones a respuestas HTTP del
personal (app/rutas_personal.py, instalar_errores) y del evento de redacción.

Se instala sobre una aplicación FastAPI real, sin servidor, y se llama a cada
manejador registrado. Un cambio en esta tabla cambia un código HTTP de
seguridad (401, 403, 409, 429, 503...): los valores esperados son literales.
"""
import asyncio
import types
import unittest
import uuid

from fastapi import FastAPI

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


def responder(app, error):
    return asyncio.run(app.exception_handlers[type(error)](None, error))


def detalle(texto):
    return ('{"detalle": "' + texto + '"}').encode()


class TablaDeErrores(unittest.TestCase):
    def test_cada_excepcion_su_respuesta(self):
        app = aplicacion()
        # Estos tres dejan un evento (su texto se prueba en test_eventos_sin_datos);
        # el resto no registra nada.
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
