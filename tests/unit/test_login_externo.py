"""Pruebas unitarias del login externo y de los vínculos en app/personal.py:
qué sentencias se ejecutan, en qué orden y qué se rechaza antes de escribir.

La base de datos se sustituye por una conexión falsa que devuelve filas fijas
y apunta cada sentencia; el ticket se gasta con una función de la prueba que
apunta cuándo se la llama. Lo que depende de PostgreSQL de verdad (RLS, los
índices únicos, que la reserva case con la cuenta vinculada y no con otra)
lo prueba tests/security/verificar_login_externo.py.

El TOTP es real: el secreto de RFC 4226 cifrado con la clave de la empresa,
y el código del paso 5 (instante 150), como tests/unit/test_login.py.
"""
import contextlib
import dataclasses
import types
import unittest
import uuid
from unittest import mock

import psycopg

from app import claves, cripto, externo, personal

MAESTRA = bytes(range(32))
CLAVE_EMPRESA = bytes([7]) * 32
EMPRESA = uuid.UUID(int=1)
USUARIO = uuid.UUID(int=2)
DISPOSITIVO = uuid.UUID(int=3)
SESION = uuid.UUID(int=4)
OTRA_SESION = uuid.UUID(int=5)
IDENTIFICADOR = "0123456789abcdef0123456789abcdef"
SECRETO_RFC = b"12345678901234567890"
INSTANTE = 150
CODIGO = "254676"
SUB_HMAC = bytes(range(32, 64))
CLAVES = claves.Claves(maestra=MAESTRA, hmac_codigos=bytes(32), firma_tokens=bytes(range(64, 96)),
                       hmac_identidades=bytes(32), flujo_externo=bytes(32))
ENVUELTA = (cripto.envolver_clave(MAESTRA, CLAVE_EMPRESA, EMPRESA, 1),)
CIFRADO = cripto.cifrar(CLAVE_EMPRESA, SECRETO_RFC, cripto.aad_totp(EMPRESA, USUARIO))
# Fila de una reserva: (dispositivo, cuenta, rol, hash, secreto, versión, intentos).
RESERVADA = (DISPOSITIVO, USUARIO, "admin", "$argon2id$hash-de-la-cuenta", CIFRADO, 1, 1)
# Lo que devuelve un INSERT ... RETURNING id u otra sentencia sin fila propia.
POR_DEFECTO = (uuid.UUID(int=99),)
# Lo que devuelve SQL_NUEVA_SESION: el id y los segundos hasta el cierre por
# inactividad y hasta las 8 horas.
NUEVA_SESION = (uuid.UUID(int=98), 900, 28800)
SESION_PERSONAL = personal.Sesion(empresa_id=EMPRESA, identificador=IDENTIFICADOR, sesion_id=SESION,
                                  usuario_id=USUARIO, dispositivo_id=DISPOSITIVO, rol="admin",
                                  email="titular@empresa.es", nombre_empresa="Empresa", inactividad_en=843,
                                  caduca_en=27001)


def ticket(proposito=externo.PROPOSITO_ACCESO, sesion_id=None, empresa_id=EMPRESA):
    return externo.Ticket(proveedor="google", proposito=proposito, caduca=INSTANTE + 300, jti=bytes(16),
                          empresa_id=empresa_id, identificador=IDENTIFICADOR, sesion_id=sesion_id, sub_hmac=SUB_HMAC)


class Base:
    """Base de datos falsa compartida por las transacciones de una prueba.
    filas: sentencia -> fila de fetchone (None: ninguna) o lista de fetchall.
    Fuera de EMPRESA (un contexto aleatorio) no hay ninguna fila, como con
    RLS."""

    def __init__(self, filas=None, errores=None):
        self.filas = filas or {}
        self.errores = errores or {}
        self.registro = []
        self.llamadas = []
        self.empresas = []

    def ejecutar(self, empresa_id, sql, parametros):
        self.registro.append(sql)
        self.llamadas.append((sql, parametros))
        if sql in self.errores:
            raise self.errores[sql]
        valor = self.filas.get(sql, POR_DEFECTO) if empresa_id == EMPRESA else None
        resultado = mock.Mock()
        resultado.fetchone.return_value = valor
        resultado.fetchall.return_value = valor if isinstance(valor, list) else []
        return resultado

    @contextlib.contextmanager
    def transaccion(self, _pool, empresa_id, solo_lectura=False):
        self.empresas.append(empresa_id)
        yield types.SimpleNamespace(execute=lambda sql, parametros=None: self.ejecutar(empresa_id, sql, parametros))

    def gastador(self, resultado=True):
        def gastar():
            self.registro.append("gastar_ticket")
            return resultado
        return gastar

    def antes(self, primero, despues):
        return self.registro.index(primero) < self.registro.index(despues)


@contextlib.contextmanager
def parches(base, resuelta=EMPRESA):
    with mock.patch.object(personal.bd, "transaccion_empresa", base.transaccion), \
            mock.patch.object(personal, "resolver_empresa", return_value=resuelta):
        yield


def filas_login(**cambios):
    filas = {personal.SQL_RESERVAR_DISPOSITIVO_EXTERNO: RESERVADA, personal.SQL_CLAVE_VERSION: ENVUELTA,
             personal.SQL_NUEVA_SESION: NUEVA_SESION}
    filas.update(cambios)
    return filas


class ReservaPorLaCuentaVinculada(unittest.TestCase):
    def test_sentencia(self):
        sql = personal.SQL_RESERVAR_DISPOSITIVO_EXTERNO
        # El dispositivo del navegador, de la cuenta vinculada a esa cuenta
        # externa con un vínculo vigente; nunca por el email.
        for fragmento in ("d.token_sha256 = %(huella)s", "i.empresa_id = d.empresa_id and i.usuario_id = d.usuario_id",
                          "i.proveedor = %(proveedor)s and i.sub_hmac = %(sub_hmac)s and not i.revocada",
                          "u.activo and u.totp_activo", "not d.revocado and d.caduca > now()",
                          "d.intentos_fallidos < %(tope_dispositivo)s"):
            with self.subTest(fragmento=fragmento):
                self.assertIn(fragmento, sql)
        self.assertNotIn("email", sql)
        # Las mismas columnas que la reserva con contraseña: comparten
        # _comprobar_codigo y _avisar_fallo.
        self.assertEqual(sql.split("returning")[1], personal.SQL_RESERVAR_DISPOSITIVO.split("returning")[1])


class LoginExterno(unittest.TestCase):
    def entrar(self, base, gastar=True, resuelta=EMPRESA, codigo=CODIGO, token=None, el_ticket=None):
        token = token or cripto.generar_token()[0]
        with parches(base, resuelta):
            return personal.iniciar_sesion_externa(None, CLAVES, el_ticket or ticket(), codigo, token,
                                                   base.gastador(gastar), INSTANTE)

    def test_acierto_gasta_el_ticket_antes_de_escribir(self):
        base = Base(filas_login())
        acceso = self.entrar(base)
        self.assertIsNone(acceso.token_dispositivo)
        self.assertTrue(base.antes("gastar_ticket", personal.SQL_CONFIRMAR_ACCESO))
        self.assertTrue(base.antes(personal.SQL_CONFIRMAR_ACCESO, personal.SQL_VINCULO_VIGENTE))
        self.assertTrue(base.antes(personal.SQL_VINCULO_VIGENTE, personal.SQL_NUEVA_SESION))
        # Ni camino sin confianza ni dispositivo nuevo: la confianza solo nace
        # de la contraseña y el TOTP.
        for sql in (personal.SQL_RESERVAR_DISPOSITIVO, personal.SQL_RESERVAR_CUENTA, personal.SQL_NUEVO_DISPOSITIVO):
            self.assertNotIn(sql, base.registro)
        self.assertEqual(base.registro.count(personal.SQL_AUDITAR), 1)
        self.assertEqual(base.empresas, [EMPRESA, EMPRESA])

    def test_auditoria_y_reserva_con_el_vinculo(self):
        base = Base(filas_login())
        self.entrar(base)
        llamadas = dict(base.llamadas)
        self.assertEqual(llamadas[personal.SQL_AUDITAR], [EMPRESA, f"personal:{USUARIO}", "acceso_externo", USUARIO])
        reserva = llamadas[personal.SQL_RESERVAR_DISPOSITIVO_EXTERNO]
        self.assertEqual((reserva["proveedor"], reserva["sub_hmac"]), ("google", SUB_HMAC))
        self.assertIs(llamadas[personal.SQL_CONFIRMAR_ACCESO]["sin_confianza"], False)

    def test_el_acceso_lleva_los_segundos_que_da_la_base(self):
        # Los segundos restantes salen de la base de datos, que es la que
        # decide, y no se recalculan aquí: con otra fila, otros segundos.
        base = Base(filas_login(**{personal.SQL_NUEVA_SESION: (uuid.UUID(int=98), 897, 28000)}))
        acceso = self.entrar(base)
        self.assertEqual((acceso.inactividad_en, acceso.caduca_en), (897, 28000))
        self.assertEqual(dict(base.llamadas)[personal.SQL_NUEVA_SESION]["inactividad"], 15)

    def test_sin_vinculo_el_mismo_trabajo_y_el_mismo_fallo(self):
        for nombre, filas in (("con vinculo", filas_login()),
                              ("sin vinculo", filas_login(**{personal.SQL_RESERVAR_DISPOSITIVO_EXTERNO: None}))):
            with self.subTest(nombre):
                base = Base(filas)
                with mock.patch.object(personal.cripto, "verificar_totp", wraps=cripto.verificar_totp) as totp:
                    if nombre == "sin vinculo":
                        with self.assertRaises(personal.CredencialesNoValidas), \
                                self.assertLogs("canario.personal", "WARNING") as registro:
                            self.entrar(base)
                        self.assertIn(f"EVENTO login_fallido: empresa={EMPRESA} usuario=- camino=externo",
                                      registro.output[0])
                        self.assertNotIn("gastar_ticket", base.registro)
                    else:
                        self.entrar(base)
                # Un cálculo TOTP en los dos caminos, haya cuenta o no.
                self.assertEqual(totp.call_count, 1)

    def test_codigo_malo_no_gasta_el_ticket(self):
        base = Base(filas_login())
        with self.assertRaises(personal.CredencialesNoValidas), self.assertLogs("canario.personal", "WARNING"):
            self.entrar(base, codigo="162583")
        self.assertNotIn("gastar_ticket", base.registro)
        self.assertNotIn(personal.SQL_CONFIRMAR_ACCESO, base.registro)

    def test_ticket_repetido_no_escribe(self):
        base = Base(filas_login())
        with self.assertRaises(personal.CredencialesNoValidas), self.assertLogs("canario.personal", "WARNING"):
            self.entrar(base, gastar=False)
        self.assertIn("gastar_ticket", base.registro)
        for sql in (personal.SQL_CONFIRMAR_ACCESO, personal.SQL_NUEVA_SESION, personal.SQL_AUDITAR):
            self.assertNotIn(sql, base.registro)

    def test_vinculo_revocado_entre_la_reserva_y_la_escritura(self):
        base = Base(filas_login(**{personal.SQL_VINCULO_VIGENTE: None}))
        with self.assertRaises(personal.CredencialesNoValidas), self.assertLogs("canario.personal", "WARNING"):
            self.entrar(base)
        self.assertNotIn(personal.SQL_NUEVA_SESION, base.registro)

    def test_empresa_que_ya_no_es_la_del_ticket(self):
        # El identificador resuelve a otra empresa (o a ninguna): contexto
        # aleatorio, las mismas sentencias y cero filas.
        for resuelta in (uuid.UUID(int=77), None):
            with self.subTest(resuelta=resuelta):
                base = Base(filas_login())
                with self.assertRaises(personal.CredencialesNoValidas), \
                        self.assertLogs("canario.personal", "WARNING") as registro:
                    self.entrar(base, resuelta=resuelta)
                self.assertNotIn(EMPRESA, base.empresas)
                self.assertNotIn(resuelta, base.empresas)
                self.assertIn(personal.SQL_RESERVAR_DISPOSITIVO_EXTERNO, base.registro)
                self.assertIn("empresa=- usuario=- camino=externo", registro.output[0])


class EmpresaConDispositivo(unittest.TestCase):
    def consultar(self, base, token, resuelta=EMPRESA):
        with parches(base, resuelta):
            return personal.empresa_con_dispositivo(None, IDENTIFICADOR, token)

    def test_con_dispositivo_vigente(self):
        base = Base({personal.SQL_DISPOSITIVO_VIGENTE: (DISPOSITIVO,)})
        self.assertEqual(self.consultar(base, cripto.generar_token()[0]), EMPRESA)

    def test_sin_dispositivo(self):
        token = cripto.generar_token()[0]
        for nombre, base, valor, resuelta in (
                ("sin cookie", Base(), None, EMPRESA), ("cookie mal formada", Base(), "x" * 43, EMPRESA),
                ("empresa que no resuelve", Base(), token, None),
                ("dispositivo no vigente", Base({personal.SQL_DISPOSITIVO_VIGENTE: None}), token, EMPRESA)):
            with self.subTest(nombre), self.assertRaises(personal.SinDispositivo):
                self.consultar(base, valor, resuelta)


class Vincular(unittest.TestCase):
    # De solo lectura: las pruebas de la clase la comparten, así que cada una
    # trabaja sobre su copia. Si alguna la modificara, fallaría en vez de
    # contaminar en silencio a las demás.
    FILAS = types.MappingProxyType({personal.SQL_VINCULO_DE: None, personal.SQL_RESERVAR_DISPOSITIVO_SESION: RESERVADA,
                                    personal.SQL_CLAVE_VERSION: ENVUELTA})

    def iniciar(self, base, proveedor="google", codigo=CODIGO):
        with parches(base):
            personal.iniciar_vinculo(None, CLAVES, SESION_PERSONAL, proveedor, codigo, INSTANTE)

    def completar(self, base, el_ticket, gastar=True):
        with parches(base):
            return personal.completar_vinculo(None, CLAVES, SESION_PERSONAL, el_ticket, base.gastador(gastar))

    def test_iniciar_pide_un_codigo_y_lo_gasta(self):
        base = Base(dict(self.FILAS))
        self.iniciar(base)
        self.assertTrue(base.antes(personal.SQL_RESERVAR_DISPOSITIVO_SESION, personal.SQL_GASTAR_PASO_TOTP))
        self.assertTrue(base.antes(personal.SQL_GASTAR_PASO_TOTP, personal.SQL_LIBERAR_DISPOSITIVO))
        # Control: con un código malo, ni se gasta ni se libera.
        base = Base(dict(self.FILAS))
        with self.assertRaises(personal.CredencialesNoValidas):
            self.iniciar(base, codigo="162583")
        self.assertNotIn(personal.SQL_GASTAR_PASO_TOTP, base.registro)

    def test_iniciar_con_un_vinculo_ya_hecho_no_gasta_el_codigo(self):
        base = Base({**self.FILAS, personal.SQL_VINCULO_DE: POR_DEFECTO})
        with self.assertRaises(personal.VinculoDuplicado) as error:
            self.iniciar(base)
        self.assertEqual(error.exception.motivo, "cuenta")
        self.assertNotIn(personal.SQL_RESERVAR_DISPOSITIVO_SESION, base.registro)

    def test_proveedor_desconocido(self):
        base = Base(dict(self.FILAS))
        with self.assertRaises(personal.NoEncontrado):
            self.iniciar(base, proveedor="github")
        self.assertEqual(base.registro, [])

    def test_completar_solo_con_el_ticket_de_esta_sesion(self):
        base = Base({personal.avisos.SQL_DESTINATARIOS: [("vigila@empresa.es",)],
                     personal.avisos.SQL_NOMBRE_EMPRESA: ("Empresa",)})
        cambio = self.completar(base, ticket(externo.PROPOSITO_VINCULO, SESION))  # control
        self.assertEqual([c.destinatario for c in cambio.correos], ["titular@empresa.es", "vigila@empresa.es"])
        self.assertEqual(base.registro[:3], [personal.SQL_BLOQUEAR_CUENTA, personal.SQL_SESION_VIGENTE, "gastar_ticket"])
        self.assertTrue(base.antes("gastar_ticket", personal.SQL_NUEVO_VINCULO))
        for nombre, el_ticket in (("otra sesion", ticket(externo.PROPOSITO_VINCULO, OTRA_SESION)),
                                  ("otra empresa", ticket(externo.PROPOSITO_VINCULO, SESION, uuid.UUID(int=77)))):
            with self.subTest(nombre):
                base = Base()
                with self.assertRaises(personal.VinculoNoValido):
                    self.completar(base, el_ticket)
                self.assertEqual(base.registro, [])
                self.assertEqual(base.empresas, [])

    def test_completar_con_la_sesion_ya_cerrada_o_el_ticket_gastado(self):
        for nombre, filas, gastar in (("sesion cerrada", {personal.SQL_SESION_VIGENTE: None}, True),
                                      ("ticket gastado", {}, False)):
            with self.subTest(nombre):
                base = Base(filas)
                with self.assertRaises(personal.VinculoNoValido):
                    self.completar(base, ticket(externo.PROPOSITO_VINCULO, SESION), gastar)
                self.assertNotIn(personal.SQL_NUEVO_VINCULO, base.registro)
                if nombre == "sesion cerrada":
                    self.assertNotIn("gastar_ticket", base.registro)

    def test_completar_duplicado_por_indice(self):
        class Duplicado(psycopg.Error):
            sqlstate = "23505"

            def __init__(self, indice):
                super().__init__("duplicate key")
                self.indice = indice

            @property
            def diag(self):
                return types.SimpleNamespace(constraint_name=self.indice)

        for indice, motivo in (("identidad_externa_una_por_identidad", "identidad"),
                               ("identidad_externa_una_por_cuenta", "cuenta")):
            with self.subTest(indice=indice):
                base = Base(errores={personal.SQL_NUEVO_VINCULO: Duplicado(indice)})
                with self.assertRaises(personal.VinculoDuplicado) as error:
                    self.completar(base, ticket(externo.PROPOSITO_VINCULO, SESION))
                self.assertEqual(error.exception.motivo, motivo)
        # Otro índice no se disfraza de duplicado: sigue su camino.
        base = Base(errores={personal.SQL_NUEVO_VINCULO: Duplicado("otro_indice")})
        with self.assertRaises(Duplicado):
            self.completar(base, ticket(externo.PROPOSITO_VINCULO, SESION))


class Desvincular(unittest.TestCase):
    # De solo lectura, por lo mismo que Vincular.FILAS.
    FILAS = types.MappingProxyType({
        personal.SQL_VINCULO_DE: POR_DEFECTO, personal.SQL_RESERVAR_DISPOSITIVO_SESION: RESERVADA,
        personal.SQL_CLAVE_VERSION: ENVUELTA, personal.avisos.SQL_NOMBRE_EMPRESA: ("Empresa",)})

    def revocar(self, base, codigo=CODIGO):
        with parches(base):
            return personal.revocar_vinculo(None, CLAVES, SESION_PERSONAL, "google", codigo, INSTANTE)

    def test_con_codigo_revoca_avisa_y_audita(self):
        base = Base(dict(self.FILAS))
        cambio = self.revocar(base)
        self.assertEqual([c.destinatario for c in cambio.correos], ["titular@empresa.es"])
        # Orden de bloqueos: cuenta (el paso), vínculo, dispositivo, auditoría.
        for primero, despues in ((personal.SQL_GASTAR_PASO_TOTP, personal.SQL_REVOCAR_VINCULO),
                                 (personal.SQL_REVOCAR_VINCULO, personal.SQL_LIBERAR_DISPOSITIVO),
                                 (personal.SQL_LIBERAR_DISPOSITIVO, personal.SQL_AUDITAR)):
            self.assertTrue(base.antes(primero, despues))

    def test_sin_codigo_no_revoca(self):
        base = Base(dict(self.FILAS))
        with self.assertRaises(personal.CredencialesNoValidas):
            self.revocar(base, codigo="162583")
        self.assertNotIn(personal.SQL_REVOCAR_VINCULO, base.registro)

    def test_sin_vinculo_no_gasta_el_codigo(self):
        base = Base({**self.FILAS, personal.SQL_VINCULO_DE: None})
        with self.assertRaises(personal.NoEncontrado):
            self.revocar(base)
        self.assertNotIn(personal.SQL_RESERVAR_DISPOSITIVO_SESION, base.registro)


class LoQueRevocaLosVinculos(unittest.TestCase):
    """La baja, la activación, el cambio de contraseña y la reinvitación de
    plataforma revocan los vínculos, en su sitio del orden de bloqueos: tras
    la cuenta y la invitación, antes de los dispositivos."""

    def comprobar(self, base):
        self.assertIn(personal.SQL_REVOCAR_VINCULOS, base.registro)
        self.assertTrue(base.antes(personal.SQL_REVOCAR_VINCULOS, personal.SQL_REVOCAR_DISPOSITIVOS))

    def test_baja(self):
        base = Base({personal.SQL_BLOQUEAR_ADMINS: [(USUARIO, True), (uuid.UUID(int=8), True)],
                     personal.SQL_USUARIO: (USUARIO, "admin", True, True)})
        otro_admin = dataclasses.replace(SESION_PERSONAL, usuario_id=uuid.UUID(int=8))
        with parches(base):
            personal.dar_de_baja(None, otro_admin, USUARIO)
        self.assertTrue(base.antes(personal.SQL_CERRAR_INVITACIONES, personal.SQL_REVOCAR_VINCULOS))
        self.comprobar(base)

    def test_reinvitacion_de_plataforma(self):
        base = Base({personal.SQL_EMPRESA_VISIBLE: (1,), personal.SQL_CLAVE_ACTUAL: (1, b"envuelta"),
                     personal.SQL_USUARIO_POR_EMAIL: (USUARIO, "admin", True)})
        conexion = types.SimpleNamespace(execute=lambda sql, parametros=None: base.ejecutar(EMPRESA, sql, parametros))
        personal.reinvitar_admin_plataforma(conexion, EMPRESA, IDENTIFICADOR, "admin@empresa.es")
        self.comprobar(base)

    def test_cambio_de_contrasena(self):
        base = Base({personal.SQL_RESERVAR_DISPOSITIVO_SESION: RESERVADA, personal.SQL_CLAVE_VERSION: ENVUELTA,
                     personal.SQL_NUEVA_SESION: NUEVA_SESION})
        with parches(base), mock.patch.object(personal, "_comprobar_factores", return_value=5):
            personal.cambiar_contrasena(None, CLAVES, SESION_PERSONAL, "Contrasena-actual-1", "Contrasena-nueva-12",
                                        CODIGO, INSTANTE)
        self.assertTrue(base.antes(personal.SQL_CAMBIAR_CONTRASENA, personal.SQL_REVOCAR_VINCULOS))
        self.comprobar(base)

    def test_activacion(self):
        base = Base({personal.SQL_INVITACION_PENDIENTE: (uuid.UUID(int=6), USUARIO, "hash", CIFRADO, 1, ENVUELTA[0]),
                     personal.SQL_EMAIL_ROL: ("titular@empresa.es", "admin"),
                     personal.avisos.SQL_NOMBRE_EMPRESA: ("Empresa",)})
        with parches(base), mock.patch.object(personal, "_empresa_de_invitacion", return_value=(EMPRESA, b"h")):
            personal.confirmar_activacion(None, CLAVES, "token", CODIGO, INSTANTE)
        self.assertTrue(base.antes(personal.SQL_ACTIVAR_CUENTA, personal.SQL_REVOCAR_VINCULOS))
        self.comprobar(base)


if __name__ == "__main__":
    unittest.main()
