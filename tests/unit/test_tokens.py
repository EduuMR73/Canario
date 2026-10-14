"""Pruebas unitarias de app/tokens.py: la forma exacta del JWT de acceso y
cada regla de su validación (RFC 8725; OWASP ASVS 5.0.0, V9).

Los tokens de las pruebas se forjan aquí con hmac y base64 de la biblioteca
estándar, sin PyJWT: así el oráculo no depende de la pieza que se prueba. Cada
prueba negativa empieza por su control: el mismo token bien formado, forjado
por el mismo camino, se acepta. Si el control falla, el rechazo no
demostraría nada.
"""
import base64
import hashlib
import hmac
import json
import time
import unittest
import uuid

from app import tokens

CLAVE = bytes(range(32))
EMPRESA = "0123456789abcdef0123456789abcdef"
# Con letras: en mayúsculas tienen que dar otro texto.
USUARIO = "a0000000-0000-4000-8000-0000000000b2"
SESION = "c0000000-0000-4000-8000-0000000000d9"
CABECERA = {"alg": "HS256", "typ": "canario-acceso+jwt"}


def b64(datos):
    return base64.urlsafe_b64encode(datos).rstrip(b"=").decode("ascii")


def parte(objeto):
    return b64(json.dumps(objeto, separators=(",", ":")).encode("utf-8"))


def forjar(claims, cabecera=CABECERA, clave=CLAVE):
    entrada = parte(cabecera) + "." + parte(claims)
    return entrada + "." + b64(hmac.new(clave, entrada.encode("ascii"), hashlib.sha256).digest())


def claims_validos(**cambios):
    ahora = int(time.time())
    claims = {"iss": "canario", "aud": "canario-personal", "sub": USUARIO, "emp": EMPRESA, "sid": SESION,
              "iat": ahora, "exp": ahora + 300}
    claims.update(cambios)
    return {k: v for k, v in claims.items() if v is not None}


def leer(parte_b64):
    return json.loads(base64.urlsafe_b64decode(parte_b64 + "=" * (-len(parte_b64) % 4)))


class Emitir(unittest.TestCase):
    def test_forma_exacta(self):
        token = tokens.emitir(CLAVE, EMPRESA, uuid.UUID(USUARIO), uuid.UUID(SESION), ahora=1_000_000_000.9)
        cabecera, cuerpo, firma = token.split(".")
        self.assertEqual(leer(cabecera), CABECERA)
        self.assertEqual(leer(cuerpo), {"iss": "canario", "aud": "canario-personal", "sub": USUARIO, "emp": EMPRESA,
                                        "sid": SESION, "iat": 1_000_000_000, "exp": 1_000_000_300})
        esperada = hmac.new(CLAVE, (cabecera + "." + cuerpo).encode("ascii"), hashlib.sha256).digest()
        self.assertEqual(firma, b64(esperada))


class Verificar(unittest.TestCase):
    def aceptado(self, token):
        portador = tokens.verificar(CLAVE, token)
        self.assertEqual(portador, tokens.Portador(identificador=EMPRESA, usuario_id=uuid.UUID(USUARIO),
                                                   sesion_id=uuid.UUID(SESION)))

    def rechazados(self, casos):
        for motivo, token in casos.items():
            with self.subTest(motivo=motivo):
                with self.assertRaises(tokens.TokenNoValido) as error:
                    tokens.verificar(CLAVE, token)
                # El motivo concreto no sale: ni en el mensaje ni encadenado.
                self.assertEqual(str(error.exception), "")
                self.assertIsNone(error.exception.__cause__)

    def test_control_emitido_y_forjado(self):
        self.aceptado(tokens.emitir(CLAVE, EMPRESA, uuid.UUID(USUARIO), uuid.UUID(SESION)))
        self.aceptado(forjar(claims_validos()))

    def test_cabecera_exacta(self):
        self.aceptado(forjar(claims_validos()))
        self.rechazados({
            "typ JWT": forjar(claims_validos(), {"alg": "HS256", "typ": "JWT"}),
            "typ at+jwt": forjar(claims_validos(), {"alg": "HS256", "typ": "at+jwt"}),
            "sin typ": forjar(claims_validos(), {"alg": "HS256"}),
            "con kid": forjar(claims_validos(), {**CABECERA, "kid": "1"}),
            "con jku": forjar(claims_validos(), {**CABECERA, "jku": "https://atacante.test/claves"}),
        })

    def test_algoritmo(self):
        self.aceptado(forjar(claims_validos()))
        sin_firma = parte({"alg": "none", "typ": CABECERA["typ"]}) + "." + parte(claims_validos()) + "."
        hs512 = parte({"alg": "HS512", "typ": CABECERA["typ"]}) + "." + parte(claims_validos())
        hs512 += "." + b64(hmac.new(CLAVE, hs512.encode("ascii"), hashlib.sha512).digest())
        self.rechazados({"alg none": sin_firma, "HS512 con la misma clave": hs512})

    def test_firma(self):
        bueno = forjar(claims_validos())
        self.aceptado(bueno)
        cabecera, cuerpo, firma = bueno.split(".")
        otra = forjar(claims_validos(), clave=bytes(32))
        self.rechazados({
            "otra clave": otra,
            "cuerpo cambiado": cabecera + "." + parte(claims_validos(sub=SESION, sid=USUARIO)) + "." + firma,
            "sin firma": cabecera + "." + cuerpo + ".",
        })

    def test_claims_exactos(self):
        self.aceptado(forjar(claims_validos()))
        casos = {f"sin {claim}": forjar(claims_validos(**{claim: None})) for claim in tokens.CLAIMS}
        casos["con un rol"] = forjar(claims_validos(rol="admin"))
        casos["con jti"] = forjar(claims_validos(jti="x"))
        self.rechazados(casos)

    def test_audiencia_y_emisor(self):
        self.aceptado(forjar(claims_validos()))
        self.rechazados({
            "aud ajena": forjar(claims_validos(aud="otra")),
            "aud en lista": forjar(claims_validos(aud=["canario-personal"])),
            "iss ajeno": forjar(claims_validos(iss="otro")),
        })

    def test_caducidad_y_duracion(self):
        ahora = int(time.time())
        self.aceptado(forjar(claims_validos(iat=ahora - 290, exp=ahora + 10)))
        self.rechazados({
            "caducado": forjar(claims_validos(iat=ahora - 400, exp=ahora - 100)),
            "dura una hora": forjar(claims_validos(exp=ahora + 3600)),
            "emitido en el futuro": forjar(claims_validos(iat=ahora + 600, exp=ahora + 900)),
        })

    def test_formas_de_los_claims(self):
        ahora = int(time.time())
        self.aceptado(forjar(claims_validos()))
        self.rechazados({
            "sub en mayusculas": forjar(claims_validos(sub=USUARIO.upper())),
            "sid con urn": forjar(claims_validos(sid="urn:uuid:" + SESION)),
            "sid sin guiones": forjar(claims_validos(sid=SESION.replace("-", ""))),
            "emp que no es un identificador": forjar(claims_validos(emp="acme")),
            "iat booleano": forjar(claims_validos(iat=True, exp=301)),
            "iat decimal": forjar(claims_validos(iat=ahora + 0.5, exp=ahora + 300.5)),
        })

    def test_entradas_raras(self):
        bueno = forjar(claims_validos())
        self.aceptado(bueno)
        self.rechazados({
            "no es texto": None,
            "bytes": bueno.encode("ascii"),
            "vacio": "",
            "demasiado largo": bueno + "A" * 1024,
            "dos partes": bueno.rsplit(".", 1)[0],
        })
