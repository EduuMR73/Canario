"""Pruebas unitarias de app/externo.py: el flujo hacia el proveedor y el
ticket de vuelta del login externo.

Los oráculos son literales: el vector de PKCE de RFC 7636 (apéndice B), las
longitudes del formato documentado y los valores escritos a mano. Cada
rechazo lleva al lado su caso válido, que demuestra que el rechazo no viene
de otra cosa.
"""
import base64
import unittest
import uuid

from app import cliente_broker, cripto, externo, proveedores_externos

CLAVE = bytes(range(32))
OTRA_CLAVE = bytes(range(1, 33))
CLAVE_IDENTIDADES = bytes(range(32, 64))
EMPRESA = uuid.UUID(int=1)
SESION = uuid.UUID(int=7)
IDENTIFICADOR = "0123456789abcdef0123456789abcdef"
SUB = "109876543210987654321"
AHORA = 1_800_000_000
# RFC 7636, apéndice B.
VERIFIER_RFC = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CHALLENGE_RFC = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
ISS_GOOGLE = "https://accounts.google.com"
# Cifrado (1 + 12 + texto + 16 bytes) en base64url sin relleno: flujo de 154
# bytes y ticket de 106 (la cabecera de app/externo.py).
LONGITUD_TEXTO_FLUJO = 244
LONGITUD_TEXTO_TICKET = 180


def flujo(proposito=externo.PROPOSITO_ACCESO, sesion_id=None, ahora=AHORA):
    return externo.nuevo_flujo("google", proposito, EMPRESA, IDENTIFICADOR, sesion_id, ahora=ahora)


def b64(datos):
    return base64.urlsafe_b64encode(datos).decode("ascii").rstrip("=")


def alterar(texto, posicion):
    """El mismo texto con un carácter cambiado por otro del alfabeto."""
    nuevo = "A" if texto[posicion] != "A" else "B"
    return texto[:posicion] + nuevo + texto[posicion + 1:]


class Flujo(unittest.TestCase):
    def test_ida_y_vuelta_de_acceso_y_de_vinculo(self):
        for proposito, sesion in ((externo.PROPOSITO_ACCESO, None), (externo.PROPOSITO_VINCULO, SESION)):
            with self.subTest(proposito=proposito):
                original = flujo(proposito, sesion)
                texto = externo.sellar_flujo(CLAVE, original)
                self.assertEqual(len(texto), LONGITUD_TEXTO_FLUJO)
                self.assertEqual(externo.abrir_flujo(CLAVE, texto, ahora=AHORA + 1), original)
                self.assertEqual(original.caduca, AHORA + 600)

    def test_valores_aleatorios_de_43_caracteres_y_nuevos_cada_vez(self):
        uno, otro = flujo(), flujo()
        for valor in (uno.state, uno.nonce, uno.verifier):
            self.assertEqual(len(valor), 43)
            self.assertTrue(proveedores_externos.PATRON_VALOR_API.fullmatch(valor))
        self.assertTrue(proveedores_externos.PATRON_VERIFIER.fullmatch(uno.verifier))
        self.assertEqual(len({uno.state, uno.nonce, uno.verifier, otro.state, otro.nonce, otro.verifier}), 6)

    def test_code_challenge_del_vector_de_rfc7636(self):
        crudo = base64.urlsafe_b64decode(VERIFIER_RFC + "=")
        con_vector = externo.Flujo(proveedor="google", proposito=externo.PROPOSITO_ACCESO, caduca=AHORA + 600,
                                   empresa_id=EMPRESA, identificador=IDENTIFICADOR, sesion_id=None,
                                   state_crudo=bytes(32), nonce_crudo=bytes(32), verifier_crudo=crudo)
        self.assertEqual(con_vector.verifier, VERIFIER_RFC)
        self.assertEqual(con_vector.code_challenge, CHALLENGE_RFC)

    def test_secretos_fuera_del_repr(self):
        uno = flujo()
        for secreto in (uno.state, uno.nonce, uno.verifier):
            self.assertNotIn(secreto, repr(uno))
        self.assertNotIn(repr(uno.verifier_crudo), repr(uno))

    def test_campos_no_validos_al_crear(self):
        self.assertEqual(flujo(externo.PROPOSITO_VINCULO, SESION).sesion_id, SESION)  # control
        casos = {
            "proveedor desconocido": ("github", externo.PROPOSITO_ACCESO, EMPRESA, IDENTIFICADOR, None),
            "proposito desconocido": ("google", "otro", EMPRESA, IDENTIFICADOR, None),
            "vinculo sin sesion": ("google", externo.PROPOSITO_VINCULO, EMPRESA, IDENTIFICADOR, None),
            "vinculo con la sesion nula": ("google", externo.PROPOSITO_VINCULO, EMPRESA, IDENTIFICADOR,
                                           uuid.UUID(int=0)),
            "acceso con sesion": ("google", externo.PROPOSITO_ACCESO, EMPRESA, IDENTIFICADOR, SESION),
            "identificador en mayusculas": ("google", externo.PROPOSITO_ACCESO, EMPRESA, IDENTIFICADOR.upper(), None),
            "identificador corto": ("google", externo.PROPOSITO_ACCESO, EMPRESA, IDENTIFICADOR[:-1], None),
            "empresa como texto": ("google", externo.PROPOSITO_ACCESO, str(EMPRESA), IDENTIFICADOR, None),
        }
        for nombre, argumentos in casos.items():
            with self.subTest(nombre):
                with self.assertRaises(ValueError):
                    externo.nuevo_flujo(*argumentos, ahora=AHORA)

    def test_caducidad(self):
        texto = externo.sellar_flujo(CLAVE, flujo())
        self.assertEqual(externo.abrir_flujo(CLAVE, texto, ahora=AHORA + 599).caduca, AHORA + 600)  # control
        for ahora in (AHORA + 600, AHORA + 10_000):
            with self.subTest(ahora=ahora):
                with self.assertRaises(externo.FlujoNoValido):
                    externo.abrir_flujo(CLAVE, texto, ahora=ahora)
        # Con más vida de la que se le da al emitirlo: solo lo haría quien
        # tuviera la clave o un reloj que va hacia atrás; no se acepta.
        with self.assertRaises(externo.FlujoNoValido):
            externo.abrir_flujo(CLAVE, texto, ahora=AHORA - 1)

    def test_alterado_de_otra_clave_o_ticket(self):
        texto = externo.sellar_flujo(CLAVE, flujo())
        self.assertEqual(externo.abrir_flujo(CLAVE, texto, ahora=AHORA).identificador, IDENTIFICADOR)  # control
        ticket = externo.emitir_ticket(CLAVE, CLAVE_IDENTIDADES, flujo(), SUB, ahora=AHORA)
        for nombre, clave, valor in (("principio", CLAVE, alterar(texto, 0)), ("medio", CLAVE, alterar(texto, 120)),
                                     ("tag", CLAVE, alterar(texto, len(texto) - 2)),
                                     ("otra clave", OTRA_CLAVE, texto), ("un ticket", CLAVE, ticket)):
            with self.subTest(nombre):
                with self.assertRaises(externo.FlujoNoValido):
                    externo.abrir_flujo(clave, valor, ahora=AHORA)

    def test_solo_la_forma_exacta(self):
        texto = externo.sellar_flujo(CLAVE, flujo())
        self.assertEqual(b64(base64.urlsafe_b64decode(texto)), texto)  # control: 183 bytes, sin relleno
        # "+" y "/" son del alfabeto estándar: un descodificador permisivo los
        # aceptaría en lugar de "-" y "_".
        casos = [("con relleno", texto + "="), ("con espacio", texto + " "), ("con mas", "+" + texto[1:]),
                 ("con barra", "/" + texto[1:]), ("corto", texto[:-4]), ("largo", texto + "AAAA"), ("vacio", ""),
                 ("no texto", None)]
        for nombre, valor in casos:
            with self.subTest(nombre):
                with self.assertRaises(externo.FlujoNoValido):
                    externo.abrir_flujo(CLAVE, valor, ahora=AHORA)


    def test_jti_del_state_y_segundos_restantes(self):
        # Literal: los 16 primeros bytes del SHA-256 de un state de 32 ceros.
        fijo = externo.Flujo(proveedor="google", proposito=externo.PROPOSITO_ACCESO, caduca=AHORA + 600,
                             empresa_id=EMPRESA, identificador=IDENTIFICADOR, sesion_id=None,
                             state_crudo=bytes(32), nonce_crudo=bytes(range(32)), verifier_crudo=bytes(range(32)))
        self.assertEqual(fijo.jti.hex(), "66687aadf862bd776c8fc18b8e9f8e20")
        # El mismo flujo abierto otra vez da el mismo jti (es lo que se gasta);
        # otro flujo, otro.
        uno = flujo()
        self.assertEqual(externo.abrir_flujo(CLAVE, externo.sellar_flujo(CLAVE, uno), ahora=AHORA).jti, uno.jti)
        self.assertNotEqual(flujo().jti, uno.jti)
        self.assertEqual(fijo.segundos_restantes(AHORA), 600)
        self.assertEqual(fijo.segundos_restantes(AHORA + 599), 1)
        # Nunca 0: un TTL de 0 en EXPIRE borraría la clave en el acto.
        self.assertEqual(fijo.segundos_restantes(AHORA + 700), 1)


class ComprobarVuelta(unittest.TestCase):
    def setUp(self):
        self.flujo = flujo()

    def test_valida(self):
        self.assertIsNone(externo.comprobar_vuelta(self.flujo, "google", self.flujo.state, ISS_GOOGLE))

    def test_rechazos_con_su_motivo(self):
        externo.comprobar_vuelta(self.flujo, "google", self.flujo.state, ISS_GOOGLE)  # control
        casos = {
            "proveedor": ("github", self.flujo.state, ISS_GOOGLE),
            "state": ("google", flujo().state, ISS_GOOGLE),
            "iss": ("google", self.flujo.state, None),
        }
        casos_state = ("", None, self.flujo.state + "x", "ñ" * 43)
        casos_iss = ("accounts.google.com", "https://accounts.google.com/", "https://evil.example", "")
        for motivo, argumentos in casos.items():
            with self.subTest(motivo):
                with self.assertRaises(externo.VueltaNoValida) as error:
                    externo.comprobar_vuelta(self.flujo, *argumentos)
                self.assertEqual(error.exception.motivo, motivo)
        for state in casos_state:
            with self.subTest(state=state):
                with self.assertRaises(externo.VueltaNoValida) as error:
                    externo.comprobar_vuelta(self.flujo, "google", state, ISS_GOOGLE)
                self.assertEqual(error.exception.motivo, "state")
        # RFC 9207, 2.4: comparación exacta con el issuer, sin normalizar.
        for iss in casos_iss:
            with self.subTest(iss=iss):
                with self.assertRaises(externo.VueltaNoValida) as error:
                    externo.comprobar_vuelta(self.flujo, "google", self.flujo.state, iss)
                self.assertEqual(error.exception.motivo, "iss")


class Ticket(unittest.TestCase):
    def test_ida_y_vuelta_sin_el_sub(self):
        for proposito, sesion in ((externo.PROPOSITO_ACCESO, None), (externo.PROPOSITO_VINCULO, SESION)):
            with self.subTest(proposito=proposito):
                texto = externo.emitir_ticket(CLAVE, CLAVE_IDENTIDADES, flujo(proposito, sesion), SUB, ahora=AHORA)
                self.assertEqual(len(texto), LONGITUD_TEXTO_TICKET)
                ticket = externo.abrir_ticket(CLAVE, texto, proposito, ahora=AHORA + 1)
                self.assertEqual((ticket.proveedor, ticket.proposito, ticket.caduca, ticket.empresa_id,
                                  ticket.identificador, ticket.sesion_id),
                                 ("google", proposito, AHORA + 300, EMPRESA, IDENTIFICADOR, sesion))
                # La huella es la de cripto con la empresa del flujo; el sub no
                # está en el texto en claro.
                self.assertEqual(ticket.sub_hmac, cripto.hmac_identidad(CLAVE_IDENTIDADES, EMPRESA, "google", SUB))
                claro = cripto.descifrar(CLAVE, base64.urlsafe_b64decode(texto + "=" * (-len(texto) % 4)),
                                         cripto.ETIQUETA_TICKET_EXTERNO)
                self.assertNotIn(SUB.encode("ascii"), claro)
                self.assertEqual(len(claro), 106)

    def test_jti_nuevo_en_cada_ticket(self):
        uno = externo.abrir_ticket(CLAVE, externo.emitir_ticket(CLAVE, CLAVE_IDENTIDADES, flujo(), SUB, ahora=AHORA),
                                   externo.PROPOSITO_ACCESO, ahora=AHORA)
        otro = externo.abrir_ticket(CLAVE, externo.emitir_ticket(CLAVE, CLAVE_IDENTIDADES, flujo(), SUB, ahora=AHORA),
                                    externo.PROPOSITO_ACCESO, ahora=AHORA)
        self.assertEqual(len(uno.jti), 16)
        self.assertNotEqual(uno.jti, otro.jti)
        self.assertEqual(uno.sub_hmac, otro.sub_hmac)

    def test_proposito_caducidad_clave_y_flujo(self):
        texto = externo.emitir_ticket(CLAVE, CLAVE_IDENTIDADES, flujo(), SUB, ahora=AHORA)
        self.assertEqual(externo.abrir_ticket(CLAVE, texto, externo.PROPOSITO_ACCESO, ahora=AHORA + 299).caduca,
                         AHORA + 300)  # control
        casos = {
            "otro proposito": (CLAVE, texto, externo.PROPOSITO_VINCULO, AHORA),
            "caducado": (CLAVE, texto, externo.PROPOSITO_ACCESO, AHORA + 300),
            "del futuro": (CLAVE, texto, externo.PROPOSITO_ACCESO, AHORA - 1),
            "otra clave": (OTRA_CLAVE, texto, externo.PROPOSITO_ACCESO, AHORA),
            "alterado": (CLAVE, alterar(texto, 90), externo.PROPOSITO_ACCESO, AHORA),
            "un flujo": (CLAVE, externo.sellar_flujo(CLAVE, flujo()), externo.PROPOSITO_ACCESO, AHORA),
            "no texto": (CLAVE, None, externo.PROPOSITO_ACCESO, AHORA),
        }
        for nombre, (clave, valor, proposito, ahora) in casos.items():
            with self.subTest(nombre):
                with self.assertRaises(externo.TicketNoValido):
                    externo.abrir_ticket(clave, valor, proposito, ahora=ahora)

    def test_segundos_restantes(self):
        ticket = externo.abrir_ticket(CLAVE, externo.emitir_ticket(CLAVE, CLAVE_IDENTIDADES, flujo(), SUB, ahora=AHORA),
                                      externo.PROPOSITO_ACCESO, ahora=AHORA)
        self.assertEqual(ticket.segundos_restantes(AHORA), 300)
        self.assertEqual(ticket.segundos_restantes(AHORA + 299), 1)
        # Nunca 0: un TTL de 0 en EXPIRE borraría la clave en el acto.
        self.assertEqual(ticket.segundos_restantes(AHORA + 400), 1)


class Coherencia(unittest.TestCase):
    def test_cada_proveedor_del_broker_tiene_codigo_emisor_y_endpoint(self):
        # Literal: hoy solo Google. Añadir GitHub (A2) obliga a tocar los tres.
        self.assertEqual(set(proveedores_externos.PROVEEDORES), {"google"})
        self.assertEqual(set(externo.CODIGOS_PROVEEDOR), {"google"})
        self.assertEqual(set(externo.EMISORES_AUTORIZACION), {"google"})
        self.assertEqual(set(cliente_broker.ENDPOINTS_AUTORIZACION), {"google"})
        self.assertEqual(externo.EMISORES_AUTORIZACION["google"], ISS_GOOGLE)
        self.assertEqual(cliente_broker.ENDPOINTS_AUTORIZACION["google"],
                         "https://accounts.google.com/o/oauth2/v2/auth")
        self.assertEqual((externo.DURACION_FLUJO, externo.DURACION_TICKET), (600, 300))


if __name__ == "__main__":
    unittest.main()
