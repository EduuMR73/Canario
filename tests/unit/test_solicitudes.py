"""Pruebas unitarias del registro "primero el email" (app/solicitudes.py).

Uniformidad: POST /v1/personal/registro responde igual en todos los casos, y
todo el trabajo se hace después de responder (procesar). Como defensa en
profundidad frente a lo que ese trabajo pueda notarse en otras peticiones,
y como en tests/unit/test_login.py, aquí se comprueba la causa y no el
tiempo (que mide la batería tests/security/verificar_registro.py): las mismas
sentencias, en el mismo orden, confirmando sin esperar al disco, exista o no
la empresa, tenga o no cuenta el email. La base de datos se sustituye por un
doble que registra las sentencias y responde lo que toca en cada camino.
"""
import contextlib
import hashlib
import re
import unittest
import uuid
from unittest import mock

import psycopg

from app import correo, cripto, personal, rutas_web, solicitudes

EMPRESA = uuid.UUID(int=1)
IDENTIFICADOR = "0123456789abcdef0123456789abcdef"
EMAIL = "persona@empresa.es"
ORIGEN = "https://localhost:8445"


class _Resultado:
    def __init__(self, fila):
        self._fila = fila

    def fetchone(self):
        return self._fila


class _Conexion:
    """Responde según el camino: nombre de la empresa (o ninguna fila con un
    contexto que no es de ninguna), cuenta existente y solicitud pendiente."""

    def __init__(self, empresa_visible, cuenta, pendiente):
        self.empresa_visible, self.cuenta, self.pendiente = empresa_visible, cuenta, pendiente
        self.sentencias = []
        self.insertada = None

    def execute(self, sql, parametros=None):
        self.sentencias.append(" ".join(sql.split()))
        if sql == solicitudes.SQL_NOMBRE_EMPRESA:
            return _Resultado(("Acme",) if self.empresa_visible else None)
        if sql == solicitudes.SQL_CUENTA_EXISTE:
            return _Resultado((self.cuenta,))
        if sql == solicitudes.SQL_PENDIENTE_VERIFICADA:
            return _Resultado((self.pendiente,))
        if sql == solicitudes.SQL_NUEVA_SOLICITUD:
            self.insertada = parametros
            return _Resultado((uuid.UUID(int=9),) if parametros["crear"] else None)
        return _Resultado(None)


def solicitar(resuelta, cuenta=False, pendiente=False):
    conexion = _Conexion(resuelta is not None, cuenta, pendiente)
    contextos = []

    @contextlib.contextmanager
    def transaccion(_pool, empresa_id, solo_lectura=False):
        contextos.append((empresa_id, solo_lectura))
        yield conexion

    with mock.patch.object(personal, "resolver_empresa", return_value=resuelta), \
            mock.patch.object(solicitudes.bd, "transaccion_empresa", transaccion):
        resultado = solicitudes.solicitar(None, ORIGEN, IDENTIFICADOR, EMAIL)
    return resultado, conexion, contextos


# Oráculo literal: las sentencias de todos los caminos, en orden.
SENTENCIAS = [
    "set local synchronous_commit to off",
    "select nombre from canal.empresa",
    "select exists (select 1 from canal.usuario_personal where email = %s)",
    ("select exists (select 1 from canal.solicitud_registro where email = %s and not cerrada and verificada "
     "and caduca > now())"),
    ("update canal.solicitud_registro set cerrada = true where email = %s and not cerrada "
     "and (not verificada or caduca <= now())"),
    ("insert into canal.solicitud_registro (empresa_id, email, token_sha256) select %(empresa)s, %(email)s, "
     "%(huella)s where %(crear)s returning id"),
]


class Solicitar(unittest.TestCase):
    def test_mismas_sentencias_en_todos_los_caminos(self):
        caminos = {
            "empresa inexistente": ((None,), None),
            "email con cuenta": ((EMPRESA, True, False), "aviso_cuenta"),
            "solicitud ya verificada": ((EMPRESA, False, True), "aviso_pendiente"),
            "email nuevo": ((EMPRESA, False, False), "verificacion"),
        }
        for camino, (argumentos, tipo) in caminos.items():
            with self.subTest(camino=camino):
                resultado, conexion, contextos = solicitar(*argumentos)
                self.assertEqual(conexion.sentencias, SENTENCIAS)
                self.assertEqual(len(contextos), 1)
                self.assertIs(contextos[0][1], False)
                self.assertEqual(None if resultado is None else resultado.tipo, tipo)
                # Solo el email nuevo crea solicitud.
                self.assertIs(conexion.insertada["crear"], tipo == "verificacion")

    def test_sin_empresa_contexto_aleatorio(self):
        _, conexion, contextos = solicitar(None)
        # Un uuid4 nuevo, nunca el nulo ni uno fijo: cero filas bajo RLS.
        self.assertEqual(contextos[0][0].version, 4)
        self.assertEqual(conexion.insertada["empresa"], contextos[0][0])
        self.assertNotEqual(solicitar(None)[2][0][0], contextos[0][0])

    def test_enlace_y_huella(self):
        resultado, conexion, _ = solicitar(EMPRESA)
        self.assertEqual(resultado.destinatario, EMAIL)
        encaje = re.search(r"https://localhost:8445/registro/verificacion#0123456789abcdef0123456789abcdef\."
                           r"([A-Za-z0-9_-]{43})\n", resultado.cuerpo)
        self.assertIsNotNone(encaje)
        # Lo guardado es SHA-256 de la etiqueta del registro y el token, nunca
        # el token.
        crudo = cripto.leer_token(encaje.group(1))
        self.assertEqual(conexion.insertada["huella"], hashlib.sha256(b"canario/registro/v1" + crudo).digest())
        self.assertNotIn(encaje.group(1), resultado.asunto)

    def test_avisos_sin_enlace(self):
        for argumentos in ((EMPRESA, True, False), (EMPRESA, False, True)):
            with self.subTest(argumentos=argumentos):
                resultado, _, _ = solicitar(*argumentos)
                self.assertNotIn("https://", resultado.cuerpo)
                self.assertIn("Acme", resultado.cuerpo)


class Origen(unittest.TestCase):
    def test_obligatorio(self):
        with self.assertRaises(rutas_web.ErrorConfiguracion) as error:
            solicitudes.cargar_origen({})
        self.assertEqual(str(error.exception),
                         "CANARIO_ORIGEN_PERSONAL: obligatoria (origen https de la SPA del personal)")

    def test_mal_formado(self):
        for malo in ("http://localhost:8445", "https://localhost:8445/", "https://LOCALHOST:8445", "",
                     "https://localhost:443"):
            with self.subTest(malo=malo), self.assertRaises(rutas_web.ErrorConfiguracion) as error:
                solicitudes.cargar_origen({"CANARIO_ORIGEN_PERSONAL": malo})
            self.assertTrue(str(error.exception).startswith("CANARIO_ORIGEN_PERSONAL: "))

    def test_valido(self):
        self.assertEqual(solicitudes.cargar_origen({"CANARIO_ORIGEN_PERSONAL": ORIGEN}), ORIGEN)


class Procesar(unittest.TestCase):
    """procesar corre después de responder: lo que haga ya no cambia la
    respuesta, así que un fallo solo puede ir al log, y sin datos."""

    def test_fallo_al_log_sin_email_y_sin_correo(self):
        error = psycopg.OperationalError(f'Key (email)=({EMAIL}) already exists')
        with mock.patch.object(solicitudes, "solicitar", side_effect=error), \
                mock.patch.object(correo, "enviar") as enviar, \
                self.assertLogs("canario.solicitudes", "ERROR") as registro:
            solicitudes.procesar(None, ORIGEN, IDENTIFICADOR, EMAIL)
        self.assertEqual(registro.output,
                         ["ERROR:canario.solicitudes:EVENTO registro_fallido: error=OperationalError"])
        # El texto del error lleva el email (control): el log no.
        self.assertIn(EMAIL, str(error))
        self.assertNotIn(EMAIL, "\n".join(registro.output))
        enviar.assert_not_called()

    def test_envia_el_correo_que_toca(self):
        mensaje = correo.Correo(tipo="verificacion", destinatario=EMAIL, asunto="Asunto", cuerpo="Cuerpo\n")
        for devuelto, envios in ((mensaje, [mock.call(mensaje)]), (None, [])):
            with self.subTest(devuelto=devuelto), \
                    mock.patch.object(solicitudes, "solicitar", return_value=devuelto) as solicitar, \
                    mock.patch.object(correo, "enviar") as enviar:
                solicitudes.procesar("pool", ORIGEN, IDENTIFICADOR, EMAIL)
                solicitar.assert_called_once_with("pool", ORIGEN, IDENTIFICADOR, EMAIL)
                self.assertEqual(enviar.call_args_list, envios)
