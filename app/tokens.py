"""JWT de acceso del personal (docs/threat-model.md, 6.3).

Un JWT firmado con HMAC-SHA256 (HS256) y la clave clave_firma_tokens
(app/claves.py). Dura 5 minutos y dice quién es el portador: la cuenta (sub),
la empresa (emp, su identificador público) y la sesión (sid). No dice qué
puede hacer: el rol y el estado de la cuenta se leen de la base de datos en
cada petición (app/personal.py, autenticar). Así una baja surte efecto al
momento aunque el JWT siga vivo, y un JWT no puede llevar un rol que la
cuenta ya no tiene.

El sid es lo que permite cortar un JWT antes de que caduque: cerrar la
sesión, cambiar la contraseña o dar de baja la cuenta revocan su fila, y la
lectura de cada petición lo ve (OWASP ASVS 5.0.0, 7.4.1). Es el mismo claim
que usa OpenID Connect Back-Channel Logout 1.0 para cerrar sesiones.

Validación (RFC 8725 y OWASP ASVS 5.0.0, V9), toda explícita:
* Un solo algoritmo, HS256, con una clave que solo sirve para esto (RFC 8725,
  3.1). PyJWT rechaza "none" y cualquier otro algoritmo si se le pasa la
  lista (comprobado en la versión fijada).
* La cabecera tiene que ser exactamente {"alg": "HS256", "typ": TIPO}. PyJWT
  no comprueba typ (comprobado en la versión fijada: acepta typ "JWT"), así
  que se comprueba aquí (RFC 8725, 3.11; ASVS 9.2.2). Exigir la cabecera
  exacta rechaza también jku, jwk, x5u o kid: la clave nunca sale del token
  (ASVS 9.1.3).
* iss y aud fijos (RFC 8725, 3.8 y 3.9). Los claims tienen que ser
  exactamente los de CLAIMS, cada uno con su forma: un token de otro tipo o
  con claims de más no se acepta (RFC 8725, 3.12).
* exp obligatorio. PyJWT solo valida exp si el token lo trae (comprobado en
  la versión fijada, api_jwt.py): se exige con options.require. Además, exp
  tiene que ser iat + DURACION_ACCESO: un token que dure más no lo ha
  emitido esta API.

Sin kid ni varias claves a la vez: rotar clave_firma_tokens invalida los
accesos vivos, que duran 5 minutos, y el cliente pide otro con su token de
renovación, que es opaco y no depende de esta clave.

Límite asumido: quien tenga clave_firma_tokens puede forjar un JWT de
cualquier cuenta, porque los ids de cuenta salen en los logs. Necesitaría
además el id de una sesión viva de esa cuenta, y la cuenta tendría que
seguir activa. Es una clave del mismo nivel que clave_maestra
(docs/threat-model.md, 8).
"""
import re
import time
import uuid
from dataclasses import dataclass

import jwt

from app import denuncias

ALGORITMO = "HS256"
# Tipo explícito propio (RFC 8725, 3.11). No es "at+jwt" (RFC 9068) porque
# este token no es un access token de OAuth 2.0 y no lleva sus claims.
TIPO = "canario-acceso+jwt"
CABECERA = {"alg": ALGORITMO, "typ": TIPO}
EMISOR = "canario"
AUDIENCIA = "canario-personal"
# 5 minutos: lo que puede usar quien robe un JWT antes de tener que renovarlo.
DURACION_ACCESO = 300
CLAIMS = ("iss", "aud", "sub", "emp", "sid", "iat", "exp")
# Un JWT de esta API mide 377 caracteres (medido con la versión fijada). Lo
# que pase de aquí no se analiza.
LONGITUD_MAXIMA = 1024
PATRON_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


class TokenNoValido(Exception):
    """El JWT no vale. Nunca lleva el token ni el motivo concreto."""


@dataclass(frozen=True)
class Portador:
    identificador: str
    usuario_id: uuid.UUID
    sesion_id: uuid.UUID


def emitir(clave, identificador, usuario_id, sesion_id, ahora=None):
    """JWT de acceso para una sesión recién creada o renovada."""
    iat = int(time.time() if ahora is None else ahora)
    claims = {"iss": EMISOR, "aud": AUDIENCIA, "sub": str(usuario_id), "emp": identificador,
              "sid": str(sesion_id), "iat": iat, "exp": iat + DURACION_ACCESO}
    # headers solo añade typ: PyJWT pone alg a partir de algorithm.
    return jwt.encode(claims, clave, algorithm=ALGORITMO, headers={"typ": TIPO})


def _uuid(texto):
    # Solo la forma canónica en minúsculas: uuid.UUID acepta también llaves,
    # guiones de menos o el prefijo urn:uuid:.
    if not isinstance(texto, str) or not PATRON_UUID.fullmatch(texto):
        raise TokenNoValido
    return uuid.UUID(texto)


def verificar(clave, token):
    """Portador de un JWT válido, o TokenNoValido."""
    if not isinstance(token, str) or len(token) > LONGITUD_MAXIMA:
        raise TokenNoValido
    try:
        completo = jwt.decode_complete(token, clave, algorithms=[ALGORITMO], audience=AUDIENCIA,
                                       issuer=EMISOR, options={"require": list(CLAIMS), "strict_aud": True})
    except jwt.PyJWTError:
        raise TokenNoValido from None
    claims = completo["payload"]
    if completo["header"] != CABECERA or set(claims) != set(CLAIMS):
        raise TokenNoValido
    # bool es un int en Python: se descarta a propósito.
    iat, exp = claims["iat"], claims["exp"]
    if type(iat) is not int or type(exp) is not int or exp != iat + DURACION_ACCESO:
        raise TokenNoValido
    if not isinstance(claims["emp"], str) or not denuncias.PATRON_IDENTIFICADOR.fullmatch(claims["emp"]):
        raise TokenNoValido
    return Portador(identificador=claims["emp"], usuario_id=_uuid(claims["sub"]), sesion_id=_uuid(claims["sid"]))
