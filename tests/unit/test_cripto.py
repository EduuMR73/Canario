"""Pruebas unitarias de app/cripto.py: cifrado autenticado, AAD, relleno,
código de seguimiento, TOTP y tokens del personal.

Los oráculos son literales: vectores oficiales (RFC 4226, apéndice D; RFC
6238, apéndice B), bytes escritos a mano o valores calculados aparte con la
biblioteca estándar a partir del formato documentado. Nunca se derivan de la
función que se prueba. Cada rechazo lleva al lado su caso válido.
"""
import hashlib
import unittest
import uuid

from app import cripto

CLAVE = bytes(range(32))
OTRA_CLAVE = bytes(range(1, 33))
EMPRESA = uuid.UUID(int=1)
OTRA_EMPRESA = uuid.UUID(int=2)
DENUNCIA = uuid.UUID(int=3)
MENSAJE = uuid.UUID(int=4)
PERSONA = uuid.UUID(int=5)

# RFC 4226, apéndice D: secreto ASCII "12345678901234567890", contadores 0 a 9.
SECRETO_RFC = b"12345678901234567890"
HOTP_RFC4226 = ["755224", "287082", "359152", "969429", "338314",
                "254676", "287922", "162583", "399871", "520489"]
# RFC 6238, apéndice B, filas SHA1 (8 dígitos): instante -> código.
TOTP_RFC6238 = {59: "94287082", 1111111109: "07081804", 1111111111: "14050471",
                1234567890: "89005924", 2000000000: "69279037", 20000000000: "65353130"}


class CifradoAutenticado(unittest.TestCase):
    AAD = b"contexto"

    def test_ida_y_vuelta_y_longitud(self):
        cifrado = cripto.cifrar(CLAVE, b"hola", self.AAD)
        # 1 (formato) + 12 (nonce) + 4 (datos) + 16 (tag).
        self.assertEqual(len(cifrado), 33)
        self.assertEqual(cifrado[:1], b"\x01")
        self.assertEqual(cripto.descifrar(CLAVE, cifrado, self.AAD), b"hola")

    def test_vacio_valido(self):
        cifrado = cripto.cifrar(CLAVE, b"", self.AAD)
        self.assertEqual(len(cifrado), 29)
        self.assertEqual(cripto.descifrar(CLAVE, cifrado, self.AAD), b"")

    def test_nonce_distinto_en_cada_cifrado(self):
        self.assertNotEqual(cripto.cifrar(CLAVE, b"igual", self.AAD), cripto.cifrar(CLAVE, b"igual", self.AAD))

    def test_un_bit_alterado_en_cada_zona(self):
        cifrado = cripto.cifrar(CLAVE, b"datos de prueba", self.AAD)
        self.assertEqual(cripto.descifrar(CLAVE, cifrado, self.AAD), b"datos de prueba")  # control
        # Nonce (1), cuerpo (13) y tag (último byte).
        for posicion in (1, 13, len(cifrado) - 1):
            with self.subTest(posicion=posicion):
                alterado = bytearray(cifrado)
                alterado[posicion] ^= 0x01
                with self.assertRaises(cripto.ErrorIntegridad) as error:
                    cripto.descifrar(CLAVE, bytes(alterado), self.AAD)
                self.assertEqual(str(error.exception), "el cifrado no es autentico para este contexto")

    def test_otro_aad_u_otra_clave(self):
        cifrado = cripto.cifrar(CLAVE, b"x", self.AAD)
        for clave, aad in ((CLAVE, b"contextO"), (OTRA_CLAVE, self.AAD)):
            with self.subTest(aad=aad), self.assertRaises(cripto.ErrorIntegridad):
                cripto.descifrar(clave, cifrado, aad)

    def test_formato_desconocido(self):
        cifrado = cripto.cifrar(CLAVE, b"", self.AAD)
        for malo in (cifrado[:28], b"\x02" + cifrado[1:], bytearray(cifrado)):
            with self.subTest(malo=bytes(malo)[:4]):
                with self.assertRaises(cripto.ErrorIntegridad) as error:
                    cripto.descifrar(CLAVE, malo, self.AAD)
                self.assertEqual(str(error.exception), "formato de cifrado desconocido")

    def test_clave_de_32_bytes_exactos(self):
        for clave in (bytes(31), bytes(33), bytearray(32), "0" * 32):
            with self.subTest(clave=type(clave).__name__ + str(len(clave))):
                with self.assertRaises(ValueError) as error:
                    cripto.cifrar(clave, b"x", self.AAD)
                self.assertEqual(str(error.exception), "la clave debe tener 32 bytes")


class DatosAsociados(unittest.TestCase):
    def test_aad_denuncia_literal(self):
        self.assertEqual(cripto.aad_denuncia(EMPRESA, DENUNCIA),
                         b"canario/denuncia/v1" + bytes(15) + b"\x01" + bytes(15) + b"\x03")

    def test_aad_clave_empresa_literal(self):
        self.assertEqual(cripto.aad_clave_empresa(EMPRESA, 7),
                         b"canario/clave_empresa/v1" + bytes(15) + b"\x01" + b"\x00\x00\x00\x07")

    def test_aad_mensaje_literal_por_autor(self):
        base = b"canario/mensaje/v1" + bytes(15) + b"\x01" + bytes(15) + b"\x03" + bytes(15) + b"\x04"
        self.assertEqual(cripto.aad_mensaje(EMPRESA, DENUNCIA, MENSAJE, "denunciante", None), base + b"D" + bytes(16))
        self.assertEqual(cripto.aad_mensaje(EMPRESA, DENUNCIA, MENSAJE, "personal", PERSONA),
                         base + b"P" + bytes(15) + b"\x05")

    def test_aad_distintos_con_los_mismos_ids(self):
        aads = {cripto.aad_denuncia(EMPRESA, DENUNCIA), cripto.aad_totp(EMPRESA, DENUNCIA),
                cripto.aad_clave_empresa(EMPRESA, 1),
                cripto.aad_mensaje(EMPRESA, DENUNCIA, DENUNCIA, "denunciante", None)}
        self.assertEqual(len(aads), 4)

    def test_version_de_clave(self):
        for valida in (1, 2**31 - 1):
            with self.subTest(valida=valida):
                cripto.aad_clave_empresa(EMPRESA, valida)
        # bool es int en Python: se excluye a propósito.
        for mala in (0, -1, 2**31, True, 1.0):
            with self.subTest(mala=mala):
                with self.assertRaises(ValueError) as error:
                    cripto.aad_clave_empresa(EMPRESA, mala)
                self.assertEqual(str(error.exception), "version de clave fuera de rango")

    def test_ids_deben_ser_uuid(self):
        with self.assertRaises(TypeError) as error:
            cripto.aad_denuncia(str(EMPRESA), DENUNCIA)
        self.assertEqual(str(error.exception), "se esperaba uuid.UUID")

    def test_autor_y_autor_id_coherentes(self):
        casos = (("otro", None, "autor desconocido"),
                 ("personal", None, "autor_id incoherente con el autor"),
                 ("denunciante", PERSONA, "autor_id incoherente con el autor"))
        for autor, autor_id, mensaje in casos:
            with self.subTest(autor=autor):
                with self.assertRaises(ValueError) as error:
                    cripto.aad_mensaje(EMPRESA, DENUNCIA, MENSAJE, autor, autor_id)
                self.assertEqual(str(error.exception), mensaje)


class ClavesDeEmpresa(unittest.TestCase):
    def test_ida_y_vuelta(self):
        envuelta = cripto.envolver_clave(CLAVE, OTRA_CLAVE, EMPRESA, 1)
        self.assertEqual(cripto.desenvolver_clave(CLAVE, envuelta, EMPRESA, 1), OTRA_CLAVE)

    def test_atada_a_empresa_version_y_maestra(self):
        envuelta = cripto.envolver_clave(CLAVE, OTRA_CLAVE, EMPRESA, 1)
        for maestra, empresa, version in ((CLAVE, OTRA_EMPRESA, 1), (CLAVE, EMPRESA, 2), (OTRA_CLAVE, EMPRESA, 1)):
            with self.subTest(version=version), self.assertRaises(cripto.ErrorIntegridad):
                cripto.desenvolver_clave(maestra, envuelta, empresa, version)

    def test_clave_de_empresa_de_32_bytes(self):
        with self.assertRaises(ValueError) as error:
            cripto.envolver_clave(CLAVE, bytes(31), EMPRESA, 1)
        self.assertEqual(str(error.exception), "la clave de empresa debe tener 32 bytes")

    def test_desenvuelta_de_longitud_distinta(self):
        # Autentica bien pero no mide 32: nunca se usa como clave.
        envuelta = cripto.cifrar(CLAVE, bytes(31), cripto.aad_clave_empresa(EMPRESA, 1))
        with self.assertRaises(cripto.ErrorIntegridad) as error:
            cripto.desenvolver_clave(CLAVE, envuelta, EMPRESA, 1)
        self.assertEqual(str(error.exception), "la clave desenvuelta no tiene 32 bytes")


class Relleno(unittest.TestCase):
    def test_literales(self):
        self.assertEqual(cripto.rellenar(b""), bytes(256))
        self.assertEqual(cripto.rellenar(b"a"), b"\x00\x00\x00\x01a" + bytes(251))

    def test_tramos_de_256(self):
        for datos, tamano in ((252, 256), (253, 512), (508, 512), (509, 768)):
            with self.subTest(datos=datos):
                rellenado = cripto.rellenar(b"x" * datos)
                self.assertEqual(len(rellenado), tamano)
                self.assertEqual(cripto.quitar_relleno(rellenado), b"x" * datos)

    def test_quitar_relleno_estricto(self):
        casos = (
            (bytes(255), "relleno con tamano invalido"),
            (bytes(257), "relleno con tamano invalido"),
            # Declara 253 bytes en un bloque de 256: el contenido se saldría.
            ((253).to_bytes(4, "big") + bytes(252), "relleno invalido"),
            # Un byte no cero en la zona de ceros.
            ((1).to_bytes(4, "big") + b"a" + bytes(250) + b"\x01", "relleno invalido"),
            # 10 bytes en 512: sobra un bloque entero.
            ((10).to_bytes(4, "big") + bytes(508), "relleno mas largo de lo necesario"),
        )
        for rellenado, mensaje in casos:
            with self.subTest(mensaje=mensaje, longitud=len(rellenado)):
                with self.assertRaises(cripto.ErrorIntegridad) as error:
                    cripto.quitar_relleno(rellenado)
                self.assertEqual(str(error.exception), mensaje)
        # Control: longitud 0 en un bloque de 256 es válida.
        self.assertEqual(cripto.quitar_relleno(bytes(256)), b"")

    def test_misma_longitud_cifrada_dentro_del_tramo(self):
        aad = cripto.aad_denuncia(EMPRESA, DENUNCIA)
        corto = cripto.cifrar_contenido(CLAVE, b"a", aad)
        largo = cripto.cifrar_contenido(CLAVE, b"a" * 252, aad)
        self.assertEqual(len(corto), len(largo))
        self.assertEqual(len(corto), 29 + 256)
        self.assertEqual(cripto.descifrar_contenido(CLAVE, largo, aad), b"a" * 252)


class CodigoDeSeguimiento(unittest.TestCase):
    def test_generar_y_leer(self):
        texto, crudo = cripto.generar_codigo()
        self.assertRegex(texto, r"\A[A-Z2-7]{4}(-[A-Z2-7]{4}){7}\Z")
        self.assertEqual(len(crudo), 20)
        self.assertEqual(cripto.leer_codigo(texto), crudo)

    def test_formas_admitidas(self):
        for texto in ("A" * 32, "a" * 32, "aaaa-AAAA " * 3 + "aaaa-aaaa", " " + "A" * 32 + " ",
                      "A" * 32 + "-" * 32):
            with self.subTest(texto=texto):
                self.assertEqual(cripto.leer_codigo(texto), bytes(20))

    def test_formas_rechazadas(self):
        rechazados = {
            "31 caracteres": "A" * 31,
            "33 caracteres": "A" * 33,
            "65 de entrada": "A" * 32 + "-" * 33,
            "digito 0": "0" + "A" * 31,
            "digito 1": "1" + "A" * 31,
            "digito 8": "8" + "A" * 31,
            "digito 9": "9" + "A" * 31,
            "tabulador": "A" * 16 + "\t" + "A" * 16,
            "salto de linea": "A" * 32 + "\n",
            "no es str": b"A" * 32,
        }
        for motivo, texto in rechazados.items():
            with self.subTest(motivo=motivo):
                self.assertIsNone(cripto.leer_codigo(texto))

    def test_ligadura_no_se_convierte_en_letras(self):
        # "\ufb00".upper() es "FF": sin isascii() antes, 16 ligaduras serían un código.
        self.assertIsNone(cripto.leer_codigo("\ufb00" * 16))
        self.assertEqual(cripto.leer_codigo("FF" * 16), bytes.fromhex("294a5294a5" * 4))  # control

    def test_hmac_literal(self):
        # HMAC-SHA256(clave, b"canario/seguimiento/v1" + crudo), calculado aparte.
        self.assertEqual(cripto.hmac_codigo(bytes(32), bytes(20)).hex(),
                         "a384d09cf3a94df3abf8c4edc18d1cc4552899736189e5fcfe7e723c8b4a3d1a")
        self.assertNotEqual(cripto.hmac_codigo(bytes(32), bytes(20)), cripto.hmac_codigo(CLAVE, bytes(20)))

    def test_hmac_exige_20_bytes(self):
        for crudo in (bytes(19), bytes(21), "A" * 20):
            with self.subTest(crudo=crudo):
                with self.assertRaises(ValueError) as error:
                    cripto.hmac_codigo(CLAVE, crudo)
                self.assertEqual(str(error.exception), "el codigo debe tener 20 bytes")


class IdentidadExterna(unittest.TestCase):
    SUB = "109876543210987654321"

    def test_hmac_literal(self):
        # HMAC-SHA256(bytes(range(32)), b"canario/identidad/v1" + empresa(16)
        # + 0x06 "google" + 0x15 sub), calculado aparte con hmac y hashlib.
        self.assertEqual(cripto.hmac_identidad(CLAVE, EMPRESA, "google", self.SUB).hex(),
                         "801248867701d6f6c6913e5a5f61000e0404c81851ce93e53ac9f57ab137efe5")

    def test_empresa_proveedor_y_clave_cambian_la_huella(self):
        base = cripto.hmac_identidad(CLAVE, EMPRESA, "google", self.SUB)
        self.assertEqual(base, cripto.hmac_identidad(CLAVE, EMPRESA, "google", self.SUB))  # control
        for otra in (cripto.hmac_identidad(CLAVE, OTRA_EMPRESA, "google", self.SUB),
                     cripto.hmac_identidad(CLAVE, EMPRESA, "github", self.SUB),
                     cripto.hmac_identidad(OTRA_CLAVE, EMPRESA, "google", self.SUB)):
            self.assertNotEqual(otra, base)
        # Con la longitud delante, mover un carácter del proveedor al sub da
        # otra huella.
        self.assertNotEqual(cripto.hmac_identidad(CLAVE, EMPRESA, "ab", "c"),
                            cripto.hmac_identidad(CLAVE, EMPRESA, "a", "bc"))

    def test_partes_no_validas(self):
        self.assertEqual(len(cripto.hmac_identidad(CLAVE, EMPRESA, "google", "x" * 255)), 32)  # control
        for proveedor, sub in (("google", ""), ("", self.SUB), ("google", "x" * 256), ("google", "ñ"),
                               ("google", b"123"), (None, self.SUB)):
            with self.subTest(proveedor=proveedor, sub=sub):
                with self.assertRaises(ValueError):
                    cripto.hmac_identidad(CLAVE, EMPRESA, proveedor, sub)
        with self.assertRaises(TypeError):
            cripto.hmac_identidad(CLAVE, "00000000-0000-0000-0000-000000000001", "google", self.SUB)

    def test_etiquetas_de_las_cookies(self):
        self.assertEqual(cripto.ETIQUETA_FLUJO_EXTERNO, b"canario/flujo_externo/v1")
        self.assertEqual(cripto.ETIQUETA_TICKET_EXTERNO, b"canario/ticket_externo/v1")
        cifrado = cripto.cifrar(CLAVE, b"x", cripto.ETIQUETA_FLUJO_EXTERNO)
        self.assertEqual(cripto.descifrar(CLAVE, cifrado, cripto.ETIQUETA_FLUJO_EXTERNO), b"x")  # control
        with self.assertRaises(cripto.ErrorIntegridad):
            cripto.descifrar(CLAVE, cifrado, cripto.ETIQUETA_TICKET_EXTERNO)


class Totp(unittest.TestCase):
    def test_vectores_rfc4226(self):
        for contador, esperado in enumerate(HOTP_RFC4226):
            with self.subTest(contador=contador):
                self.assertEqual(cripto.codigo_totp(SECRETO_RFC, contador), esperado)

    def test_vectores_rfc6238_sha1(self):
        for instante, esperado in TOTP_RFC6238.items():
            with self.subTest(instante=instante):
                self.assertEqual(cripto.codigo_totp(SECRETO_RFC, cripto.paso_totp(instante), 8), esperado)

    def test_ventana_de_un_paso_a_cada_lado(self):
        # Instante 150: paso 5. Se aceptan los pasos 4, 5 y 6 (RFC 4226 da sus
        # códigos) y se rechazan el 3 y el 7. Instantes >= 30: con instante < 30
        # el paso -1 no existe (inalcanzable con el reloj real).
        for paso in (4, 5, 6):
            with self.subTest(paso=paso):
                self.assertEqual(cripto.verificar_totp(SECRETO_RFC, HOTP_RFC4226[paso], 150), paso)
        for paso in (3, 7):
            with self.subTest(paso=paso):
                self.assertIsNone(cripto.verificar_totp(SECRETO_RFC, HOTP_RFC4226[paso], 150))

    def test_codigo_mal_formado(self):
        self.assertEqual(cripto.verificar_totp(SECRETO_RFC, "254676", 150), 5)  # control
        for malo in ("25467", "2546760", " 254676", "254676\n", 254676, "\uff12\uff15\uff14\uff16\uff17\uff16"):
            with self.subTest(malo=repr(malo)):
                self.assertIsNone(cripto.verificar_totp(SECRETO_RFC, malo, 150))

    def test_uri_literal(self):
        self.assertEqual(cripto.uri_totp(bytes(20), "a:b+c d@x.es"),
                         "otpauth://totp/Canario:a%3Ab%2Bc%20d@x.es?secret=" + "A" * 32
                         + "&issuer=Canario&algorithm=SHA1&digits=6&period=30")


class TokensDelPersonal(unittest.TestCase):
    def test_generar_y_leer(self):
        texto, crudo = cripto.generar_token()
        self.assertRegex(texto, r"\A[A-Za-z0-9_-]{43}\Z")
        self.assertEqual(cripto.leer_token(texto), crudo)

    def test_solo_forma_canonica(self):
        # 43 caracteres son 258 bits para 256: los 2 bits sobrantes del último
        # carácter deben ser cero. "A" * 43 son 32 bytes cero; "...B" decodifica
        # a lo mismo con un bit sobrante en 1.
        self.assertEqual(cripto.leer_token("A" * 43), bytes(32))  # control
        self.assertIsNone(cripto.leer_token("A" * 42 + "B"))

    def test_formas_rechazadas(self):
        for malo in ("A" * 42, "A" * 44, "A" * 42 + "+", "A" * 42 + "/", "A" * 42 + "=", None):
            with self.subTest(malo=malo):
                self.assertIsNone(cripto.leer_token(malo))

    def test_huella_literal_y_por_tipo(self):
        self.assertEqual(cripto.huella_token(cripto.ETIQUETA_RENOVACION, bytes(32)).hex(),
                         "5e49a25083b928ae40fe8932fd22212170ed414ab73d87cf4129ae57671f5ede")
        self.assertEqual(cripto.huella_token(b"canario/renovacion/v1", bytes(32)),
                         hashlib.sha256(b"canario/renovacion/v1" + bytes(32)).digest())
        # La etiqueta del registro, con su literal: un enlace de verificación
        # no puede valer como invitación ni al revés.
        self.assertEqual(cripto.ETIQUETA_REGISTRO, b"canario/registro/v1")
        self.assertEqual(cripto.huella_token(cripto.ETIQUETA_REGISTRO, bytes(32)).hex(),
                         "ad5a80af45c3fb89a3a1fd0e24749bc85bb4ab6215c4136d6ffbcdb3d3966747")
        huellas = {cripto.huella_token(e, bytes(32)) for e in
                   (cripto.ETIQUETA_INVITACION, cripto.ETIQUETA_DISPOSITIVO, cripto.ETIQUETA_RENOVACION,
                    cripto.ETIQUETA_REGISTRO)}
        self.assertEqual(len(huellas), 4)

    def test_huella_rechazos(self):
        with self.assertRaises(ValueError) as error:
            cripto.huella_token(b"canario/otro/v1", bytes(32))
        self.assertEqual(str(error.exception), "etiqueta de token desconocida")
        with self.assertRaises(ValueError) as error:
            cripto.huella_token(cripto.ETIQUETA_RENOVACION, bytes(31))
        self.assertEqual(str(error.exception), "el token debe tener 32 bytes")
