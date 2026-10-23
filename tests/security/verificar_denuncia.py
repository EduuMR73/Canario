#!/usr/bin/env python3
"""Batería de pruebas de seguridad de la denuncia anónima (bloque 2).

Paso (a), cifrado, claves y gestión (app/cripto.py, app/claves.py,
app/gestion.py y el arranque de app/principal.py). Qué prueba:
* AES-256-GCM y el formato propio frente a un vector oficial del NIST (CAVP,
  gcmEncryptExtIV256.rsp, Count 0 de Keylen 256, IVlen 96, PTlen 128,
  AADlen 128) y HMAC-SHA256 frente a RFC 4231 (caso 2).
* Que un cifrado alterado, movido a otra denuncia, empresa, tabla, mensaje o
  autor, o con otra clave, no se descifra; el relleno; el formato del código
  de seguimiento y su lectura estricta.
* Que la API no arranca sin sus claves de cifrado o con claves mal formadas,
  y no las muestra en el log.
* Que el servicio gestion da de alta empresas con su clave envuelta, rota
  claves, se niega con otra clave maestra, con una clave alterada o con una
  base de datos que no es la esperada, y deja visible un alta a medias con el
  comando para completarla; y que la API no tiene el secreto de plataforma.
* Que ninguna clave (maestra, HMAC y las claves de empresa desenvueltas)
  aparece en los logs de la API, PostgreSQL y Caddy ni en las salidas de
  gestion, en hexadecimal, en mayúsculas, en base64 o como bytes de Python.
  Control: la clave maestra escrita a propósito en el log de la API sí se
  encuentra.

Paso (b), crear denuncia y seguimiento (app/denuncias.py,
app/rutas_denuncias.py, app/frontera_http.py y proxy/Caddyfile):
* Crear: 201 solo con el código y la fecha del día en la zona de la empresa
  (Madrid y Canarias); el mismo 404 byte a byte para una empresa desconocida,
  mal formada o inactiva; 503 con un evento sin identificar la empresa si no
  tiene clave; el mismo 422, sin devolver lo enviado, para cualquier
  petición inválida (también JSON inválido y Content-Type que no es JSON).
* Seguimiento: 200 con el texto exacto (también con caracteres especiales y
  con el texto más largo admitido), las formas equivalentes del código
  resuelven, y el mismo 404 para cualquier código que no es de una denuncia.
* El volcado de la base de datos no contiene textos, códigos ni categorías
  en claro, y cada HMAC guardado es el de la fórmula del modelo de amenazas.
* Un cifrado cambiado a otra denuncia o empresa da 500 y un evento de
  integridad sin datos; un error no previsto da 500 y solo su clase y
  SQLSTATE en el log.
* Límite de cuerpo de 128 KiB en la API (también por trozos y con
  Content-Length declarado) y en Caddy.
* El uso normal no deja ninguna línea en el log de la API; ningún texto,
  código ni HMAC aparece en los logs; PostgreSQL no registra DETAIL.

Paso (c), mensajes del denunciante (POST /v1/seguimiento/mensajes y los
mensajes del seguimiento):
* 201 solo con la secuencia y la fecha del día en la zona de la empresa
  (Madrid y Canarias); el seguimiento devuelve los textos exactos en orden,
  con autor genérico y sin id ni autor_id, también los del personal.
* El mismo 404 que el seguimiento para cualquier código que no es de una
  denuncia, y el mismo 422 sin eco para cualquier petición inválida, sin
  guardar nada.
* Una denuncia resuelta o archivada responde 409 y no guarda el mensaje; en
  instrucción lo acepta. El mensaje número 201 de una denuncia responde 409.
* Si el personal archiva la denuncia mientras llega un mensaje, el mensaje
  espera y recibe 409; si el personal deshace, se guarda. Si la denuncia
  sigue bloqueada más que lock_timeout, 503 con Retry-After y un evento sin
  datos en el log.
* Tras rotar la clave de la empresa, los mensajes nuevos usan la nueva y los
  antiguos se siguen leyendo con la suya. Un mensaje cambiado de fila (de la
  misma denuncia o de otra empresa) da 500 y un evento de integridad.

Supresión legal (arts. 32.4 y 26.2 de la Ley 2/2023, gestion
suprimir-caducadas y la frontera HTTP):
* Un mensaje que llega mientras se suprime su denuncia espera y recibe el
  mismo 404 que un código inexistente, no un 500; si la supresión se deshace,
  se guarda. Tras suprimir, el código responde el mismo 404 byte a byte en el
  seguimiento y en los mensajes. Dentro del contenedor de la API, leer o
  escribir tras resolver el código de una denuncia ya suprimida da
  CodigoNoEncontrado, no un error interno.
* gestion suprime por lotes, informa solo de recuentos por empresa y
  artículo, salta una denuncia en uso y lo avisa con código de salida 75, y la
  suprime en la ejecución siguiente; no imprime códigos ni textos.

Limitador de peticiones (app/limitador.py, sección r, con los límites de
producción):
* Cada regla (denuncia, seguimiento, mensajes y otras) admite exactamente su
  límite por cliente a través de Caddy, también con peticiones inválidas o
  códigos inexistentes, y la siguiente es 429 con Retry-After; otro cliente
  no comparte el contador; /salud está exenta; toda ruta sin regla propia cae
  en otras.
* Redis solo guarda claves con el formato literal, con TTL y sin ninguna IP;
  la huella agrupa IPv6 por /64 y la sal cambia al reiniciar la API.
* Con Redis en pausa o parado, 503 con Retry-After en el plazo y un evento
  sin IP; al volver, Redis no conserva nada y la API atiende sin 503.
* Redis sin volúmenes y con /data de solo lectura; la ACL solo permite
  contar en limite:*; una ACL permisiva, el usuario default activo o otra
  contraseña bloquean el arranque, y también un secreto de Redis o un
  CANARIO_LIMITES no válidos.

Cada prueba negativa lleva su control positivo: si el control falla, el
resultado es SIN CONCLUSION, nunca PASA. Los oráculos son literales.

Cómo se ejecuta (desde la raíz del repositorio, en PowerShell, con Docker en
marcha y los secretos generados con scripts/generar_secretos.py):

    python tests/security/verificar_denuncia.py

Usa un proyecto de Docker propio (canario_denuncia) y levanta postgres, redis,
api y caddy, más ejecuciones sueltas de gestion. Necesita que el proyecto canario esté
parado (las subredes de app y edge son fijas). Al terminar lo borra todo
(down -v y las imágenes construidas).

Claves de cifrado FALSAS en toda la batería: se generan en cada ejecución y
un fichero compose adicional, en el directorio temporal, sustituye con ellas
las cinco claves de la API (clave_maestra, clave_hmac_codigos, clave_firma_tokens,
clave_hmac_identidades y clave_flujo_externo). Así la prueba sabe qué
buscar en los logs sin leer nunca las reales, y la sección a) comprueba
(por su sha256, dentro del contenedor) que la API usa las falsas. De
secrets/ solo se usan las contraseñas de los roles, sin leerlas aquí: compose
las monta como secretos, y una ejecución suelta de gestion monta la de
aplicacion con --mount. Redis también usa secretos FALSOS: una contraseña
generada aquí y una ACL con los permisos literales de producción más un
usuario inspector de solo lectura, que solo existe en la batería (la ACL
real no permite leer qué guarda Redis). Las secciones funcionales corren con
límites altos (CANARIO_LIMITES, en otro fichero compose adicional); r)
vuelve a arrancar la API sin él.

La salida completa se guarda en verificacion_denuncia.txt dentro del
directorio temporal del sistema. El código de salida es 0 solo si el
resultado global es OK. Solo usa la biblioteca estándar.
"""
import ast
import base64
import concurrent.futures
import hashlib
import hmac
import json
import pathlib
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
import uuid

RAIZ = pathlib.Path.cwd()
PROYECTO = "canario_denuncia"
SALIDA = pathlib.Path(tempfile.gettempdir()) / "verificacion_denuncia.txt"
# main() añade el fichero compose con las claves falsas antes de usarla.
BASE = ["docker", "compose", "-p", PROYECTO, "-f", "docker-compose.yml"]
# Se rellena en preparar_claves_falsas: BASE sin los límites de prueba.
BASE_PRODUCCION = []
# Contraseñas FALSAS de Redis de esta ejecución (aplicacion e inspector).
CONTRASENAS_REDIS = {}
# Claves de cifrado falsas de esta ejecución: nombre del secreto -> hex.
CLAVES_FALSAS = {}
# Claves de empresa desenvueltas durante la prueba (hex), para buscarlas en los
# logs. Nunca se imprimen.
CLAVES_EMPRESA = set()
# Empresas dadas de alta por gestion: etiqueta -> (uuid, identificador, zona).
EMPRESAS = {}
# Códigos de seguimiento y textos de las denuncias creadas en f): se buscan
# en los logs y en el volcado. Marcadores aleatorios de esta ejecución.
CODIGOS = {}
MARCADORES = {}

lineas_salida = []
estado = {"falla": False, "sin_conclusion": False}

# ---------------------------------------------------------------------------
# Oráculos literales
# ---------------------------------------------------------------------------
SUBREDES_FIJAS = {"10.88.0.0/28", "10.88.1.0/28"}
TEXTO_VERIFICADO = "ARRANQUE VERIFICADO"
TEXTO_BLOQUEADO = "ARRANQUE BLOQUEADO: "
# Variable obligatoria de la API (app/solicitudes.py): sin ella no arranca. Las
# APIs temporales la llevan para que lo que se prueba sea lo que se pretende.
ENTORNO_API = {"CANARIO_ORIGEN_PERSONAL": "https://localhost:8445"}

# NIST CAVP, gcmEncryptExtIV256.rsp, [Keylen = 256] [IVlen = 96] [PTlen = 128]
# [AADlen = 128] [Taglen = 128], Count = 0.
NIST_CLAVE = "92e11dcdaa866f5ce790fd24501f92509aacf4cb8b1339d50c9c1240935dd08b"
NIST_IV = "ac93a1a6145299bde902f21a"
NIST_TEXTO = "2d71bcfa914e4ac045b2aa60955fad24"
NIST_AAD = "1e0889016f67601c8ebea4943bc23ad6"
NIST_CIFRADO = "8995ae2e6df3dbf96fac7b7137bae67f"
NIST_TAG = "eca5aa77d51d4a0a14d9c51e1da474ab"
# RFC 4231, 4.3 (Test Case 2).
RFC4231_CLAVE = "4a656665"
RFC4231_DATOS = "7768617420646f2079612077616e7420666f72206e6f7468696e673f"
RFC4231_HMAC = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"

ETIQUETA_SEGUIMIENTO = "canario/seguimiento/v1"
# Relleno a bloques de 256 con 4 bytes de longitud: 0 y 252 bytes caben en
# 256; 253 y 508 en 512; 509 en 768.
TAMANOS_RELLENO = [256, 256, 512, 512, 768]
# Etiqueta + campos fijos: clave_empresa 24+16+4, denuncia 19+16+16,
# mensaje 18+16+16+16+1+16.
LONGITUDES_AAD = [44, 51, 83, 83]
# Formato 1 + nonce 12 + 256 de relleno + tag 16.
TAMANO_CIFRADO_CORTO = 285
# Formato 1 + nonce 12 + clave 32 + tag 16.
TAMANO_CLAVE_ENVUELTA = 61
PATRON_CODIGO = r"([A-Z2-7]{4}-){7}[A-Z2-7]{4}"

PATRON_ALTA = re.compile(r"empresa creada: empresa_id=([0-9a-f-]{36}) identificador_publico=([0-9a-f]{32})")
PATRON_CLAVE = re.compile(r"clave creada: empresa_id=([0-9a-f-]{36}) version=(\d+)")
TEXTO_NO_DESENVUELVE = "no desenvuelve la version"
TEXTO_EMPRESA_NO_EXISTE = "la empresa no existe"
TEXTO_SIN_CLAVE = "NO tiene clave"
# Claves de empresa al llegar a e): A v1 a v3 (d) y v4 (m), B v1 y v2, C v1
# (d) y la de la empresa inactiva de f), v1.
CLAVES_EMPRESA_ESPERADAS = 8
# Cualquier secuencia de 64 hexadecimales: el formato de las claves.
PATRON_CLAVE_HEX = re.compile(r"[0-9a-fA-F]{64}")

# Se ejecuta dentro de la imagen de la API, con el código real de app/cripto.py.
PRUEBA_CRIPTO = f"""
import hashlib, hmac, json, re, uuid
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app import cripto
res = {{}}

def resultado(f):
    try:
        f()
        return "acepta"
    except cripto.ErrorIntegridad:
        return "ErrorIntegridad"
    except Exception as error:
        return type(error).__name__

K = bytes.fromhex("{NIST_CLAVE}")
IV = bytes.fromhex("{NIST_IV}")
AAD = bytes.fromhex("{NIST_AAD}")
res["nist_cifrado"] = AESGCM(K).encrypt(IV, bytes.fromhex("{NIST_TEXTO}"), AAD).hex()
blob = b"\\x01" + IV + bytes.fromhex("{NIST_CIFRADO}") + bytes.fromhex("{NIST_TAG}")
res["nist_descifrado"] = cripto.descifrar(K, blob, AAD).hex()
res["tag_alterado"] = resultado(lambda: cripto.descifrar(K, blob[:-1] + bytes([blob[-1] ^ 1]), AAD))
res["cifrado_alterado"] = resultado(lambda: cripto.descifrar(K, blob[:13] + bytes([blob[13] ^ 1]) + blob[14:], AAD))
res["aad_alterado"] = resultado(lambda: cripto.descifrar(K, blob, AAD[:-1] + bytes([AAD[-1] ^ 1])))
res["formato_desconocido"] = resultado(lambda: cripto.descifrar(K, b"\\x02" + blob[1:], AAD))
res["demasiado_corto"] = resultado(lambda: cripto.descifrar(K, blob[:28], AAD))

res["rfc4231"] = hmac.new(bytes.fromhex("{RFC4231_CLAVE}"), bytes.fromhex("{RFC4231_DATOS}"), hashlib.sha256).hexdigest()
kh = bytes(range(32))
crudo = bytes(range(20))
res["hmac_codigo_etiqueta"] = cripto.hmac_codigo(kh, crudo) == hmac.new(
    kh, b"{ETIQUETA_SEGUIMIENTO}" + crudo, hashlib.sha256).digest()
res["hmac_codigo_otra_clave"] = cripto.hmac_codigo(kh, crudo) != cripto.hmac_codigo(bytes(32), crudo)

res["relleno_tamanos"] = [len(cripto.rellenar(b"x" * n)) for n in (0, 252, 253, 508, 509)]
res["relleno_ida_vuelta"] = all(cripto.quitar_relleno(cripto.rellenar(b"y" * n)) == b"y" * n
                                for n in (0, 1, 252, 253, 1000))
basura = bytearray(cripto.rellenar(b"abc"))
basura[-1] = 1
res["relleno_basura"] = resultado(lambda: cripto.quitar_relleno(bytes(basura)))
res["relleno_bloque_extra"] = resultado(lambda: cripto.quitar_relleno(cripto.rellenar(b"abc") + bytes(256)))
res["relleno_longitud_falsa"] = resultado(lambda: cripto.quitar_relleno((10**6).to_bytes(4, "big") + bytes(252)))

E, D, M, U = (uuid.UUID(int=i) for i in (1, 2, 3, 4))
res["aad_longitudes"] = [len(cripto.aad_clave_empresa(E, 1)), len(cripto.aad_denuncia(E, D)),
                         len(cripto.aad_mensaje(E, D, M, "denunciante", None)),
                         len(cripto.aad_mensaje(E, D, M, "personal", U))]
clave = cripto.nueva_clave_empresa()
c = cripto.cifrar_contenido(clave, b"hola", cripto.aad_denuncia(E, D))
res["tamano_cifrado"] = len(c)
res["contenido_control"] = cripto.descifrar_contenido(clave, c, cripto.aad_denuncia(E, D)).decode()
res["contenido_otra_denuncia"] = resultado(lambda: cripto.descifrar_contenido(clave, c, cripto.aad_denuncia(E, M)))
res["contenido_otra_empresa"] = resultado(lambda: cripto.descifrar_contenido(clave, c, cripto.aad_denuncia(U, D)))
res["contenido_como_mensaje"] = resultado(lambda: cripto.descifrar_contenido(
    clave, c, cripto.aad_mensaje(E, D, M, "denunciante", None)))
res["contenido_otra_clave"] = resultado(lambda: cripto.descifrar_contenido(
    cripto.nueva_clave_empresa(), c, cripto.aad_denuncia(E, D)))
cm = cripto.cifrar_contenido(clave, b"m", cripto.aad_mensaje(E, D, M, "denunciante", None))
res["mensaje_control"] = cripto.descifrar_contenido(clave, cm, cripto.aad_mensaje(E, D, M, "denunciante", None)).decode()
res["mensaje_otro_id"] = resultado(lambda: cripto.descifrar_contenido(
    clave, cm, cripto.aad_mensaje(E, D, U, "denunciante", None)))
res["mensaje_como_personal"] = resultado(lambda: cripto.descifrar_contenido(
    clave, cm, cripto.aad_mensaje(E, D, M, "personal", U)))
res["autor_personal_sin_id"] = resultado(lambda: cripto.aad_mensaje(E, D, M, "personal", None))
res["autor_denunciante_con_id"] = resultado(lambda: cripto.aad_mensaje(E, D, M, "denunciante", U))
res["uuid_en_texto"] = resultado(lambda: cripto.aad_denuncia(str(E), D))
res["version_cero"] = resultado(lambda: cripto.aad_clave_empresa(E, 0))
res["version_booleana"] = resultado(lambda: cripto.aad_clave_empresa(E, True))
res["nonce_distinto"] = cripto.cifrar(clave, b"a", b"") != cripto.cifrar(clave, b"a", b"")

maestra = cripto.nueva_clave_empresa()
datos = cripto.nueva_clave_empresa()
envuelta = cripto.envolver_clave(maestra, datos, E, 1)
res["envuelta_tamano"] = len(envuelta)
res["envuelta_control"] = cripto.desenvolver_clave(maestra, envuelta, E, 1) == datos
res["envuelta_otra_version"] = resultado(lambda: cripto.desenvolver_clave(maestra, envuelta, E, 2))
res["envuelta_otra_empresa"] = resultado(lambda: cripto.desenvolver_clave(maestra, envuelta, U, 1))
res["envuelta_otra_maestra"] = resultado(lambda: cripto.desenvolver_clave(
    cripto.nueva_clave_empresa(), envuelta, E, 1))

codigos = [cripto.generar_codigo() for _ in range(1000)]
res["codigo_formato"] = all(re.fullmatch(r"{PATRON_CODIGO}", t) for t, _ in codigos)
res["codigo_bytes"] = all(len(b) == 20 for _, b in codigos)
res["codigos_distintos"] = len({{b for _, b in codigos}})
t, b0 = codigos[0]
res["codigo_lectura_exacta"] = cripto.leer_codigo(t) == b0
res["codigo_minusculas_sin_guiones"] = cripto.leer_codigo(t.replace("-", "").lower()) == b0
res["codigo_con_espacios"] = cripto.leer_codigo(t.replace("-", " ")) == b0
res["codigo_hmac_igual_en_formas_equivalentes"] = (
    cripto.hmac_codigo(kh, cripto.leer_codigo(t)) == cripto.hmac_codigo(kh, cripto.leer_codigo(t.lower())))
# 32 letras A son 20 bytes a cero: un código válido conocido.
res["ligadura_control"] = cripto.leer_codigo("FF" + "A" * 30) is not None
res["ligadura"] = cripto.leer_codigo("\\ufb00" + "A" * 30)
invalidos = {{"vacio": "", "corto": t[:-1], "largo": t + "A", "con_cero": "0" + t[1:],
              "con_uno": "1" + t[1:], "no_ascii": "\\u00c1" + t[1:], "con_relleno": t.replace("-", "")[:-1] + "=",
              "excesivo": "A" * 65, "no_texto": None, "bytes": b"A" * 32}}
res["codigos_invalidos"] = {{k: cripto.leer_codigo(v) for k, v in invalidos.items()}}
print(json.dumps(res, sort_keys=True))
"""

# Respuestas de error de la API, literales (app/frontera_http.py y
# app/rutas_denuncias.py).
# Una empresa que no existe responde exactamente igual que una ruta que no
# existe: no se puede distinguir una cosa de la otra.
CUERPO_404_RUTA = b'{"detalle": "recurso no encontrado"}'
CUERPO_404_EMPRESA = CUERPO_404_RUTA
CUERPO_404_CODIGO = '{"detalle": "código de seguimiento no válido"}'.encode()
# Errores que genera Caddy (proxy/Caddyfile, handle_errors).
CUERPO_413_CADDY = '{"detalle": "cuerpo de la petición demasiado grande"}'.encode()
CUERPO_502_CADDY = b'{"detalle": "servicio no disponible"}'
CUERPO_421_CADDY = '{"detalle": "host no válido"}'.encode()
# Cabeceras de seguridad que deben llevar todas las respuestas a través de
# Caddy, también las de error que genera él.
CABECERAS_SEGURIDAD = {
    "strict-transport-security": "max-age=63072000",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    "cache-control": "no-store",
}
PLAZO_CUERPO_CADDY = 30  # read_body del Caddyfile, en segundos
CUERPO_405 = '{"detalle": "método no permitido"}'.encode()
CUERPO_413 = '{"detalle": "cuerpo de la petición demasiado grande"}'.encode()
CUERPO_422 = '{"detalle": "petición no válida"}'.encode()
CUERPO_500 = b'{"detalle": "error interno"}'
CUERPO_503 = '{"detalle": "el canal de esta empresa no está disponible; inténtelo más tarde"}'.encode()
CUERPO_409_CERRADA = '{"detalle": "la denuncia está cerrada y no admite mensajes"}'.encode()
CUERPO_409_LIMITE = '{"detalle": "la denuncia ha alcanzado el máximo de mensajes"}'.encode()
CUERPO_503_OCUPADO = '{"detalle": "servicio ocupado; inténtelo de nuevo en unos segundos"}'.encode()
REINTENTAR_TRAS = "5"
TEXTO_SATURACION = "SATURACION: LockNotAvailable 55P03"
CLAVES_RESPUESTA_CREAR = ["codigo_seguimiento", "fecha"]
CLAVES_RESPUESTA_SEGUIMIENTO = ["categoria", "estado", "fecha", "mensajes", "texto"]
CLAVES_RESPUESTA_MENSAJE = ["fecha", "secuencia"]
CLAVES_MENSAJE = ["autor", "fecha", "secuencia", "texto"]
MAXIMO_MENSAJES = 200
# Versión de la clave de A tras d) (v1, v2 y v3) y tras la rotación de m).
VERSION_CLAVE_A = 3
VERSION_CLAVE_A_ROTADA = 4
LIMITE_CUERPO = 131072  # 128 KiB, en la API y en Caddy
LONGITUD_MAXIMA_TEXTO = 10000
TEXTO_EVENTO_SIN_CLAVE = "EVENTO empresa_sin_clave"
TEXTO_INTEGRIDAD = "INTEGRIDAD: "
TEXTO_ERROR_INTERNO = "ERROR INTERNO: InsufficientPrivilege 42501"

# Limitador (app/limitador.py; docs/threat-model.md, 6.8 y 6.9).
# Permisos del usuario aplicacion de Redis: copia literal de los de
# scripts/generar_secretos.py (r1 comprueba que siguen siendo iguales). La
# ACL de la batería es esa línea con una contraseña falsa, más un usuario
# inspector de solo lectura que solo existe aquí: la ACL real no permite
# SCAN ni GET, y sin él no se podría comprobar qué guarda Redis.
PERMISOS_ACL_APLICACION = ("resetkeys ~limite:* resetchannels -@all "
                           "+ping +multi +exec +incr +expire +ttl +client|setinfo")
PERMISOS_ACL_INSPECTOR = "resetkeys ~* resetchannels -@all +ping +scan +get +pttl +dbsize +client|setinfo"
# Límites altos para las secciones funcionales, que mandan decenas de
# peticiones por minuto desde pocas IPs. r) vuelve a arrancar la API sin
# ellos y prueba los de producción.
LIMITES_PRUEBA = ("denuncia=1000/3600,seguimiento=1000/60,mensajes=1000/3600,acceso=1000/300,otras=1000/60,"
                  "cuenta=1000/60,registro=1000/3600,destinatario=1000/900,destinatario_dia=1000/86400")
TEXTO_LIMITES_PRUEBA = ("LIMITES (configurados): acceso=1000/300 cuenta=1000/60 denuncia=1000/3600 "
                        "destinatario=1000/900 destinatario_dia=1000/86400 mensajes=1000/3600 otras=1000/60 registro=1000/3600 "
                        "seguimiento=1000/60")
TEXTO_LIMITES_PRODUCCION = ("LIMITES (por defecto): acceso=10/300 cuenta=60/60 denuncia=10/3600 destinatario=3/900 "
                            "destinatario_dia=10/86400 mensajes=30/3600 otras=60/60 registro=10/3600 seguimiento=60/60")
TEXTO_LIMITADOR_VERIFICADO = "LIMITADOR VERIFICADO"
# regla -> (peticiones, ventana en segundos), los de producción. La regla
# acceso (login del personal) y cuenta (rutas con sesión) las prueba con
# ráfagas tests/security/verificar_personal.py; aquí solo cuentan para la
# ventana de sus claves.
LIMITES_PRODUCCION = {"denuncia": (10, 3600), "seguimiento": (60, 60), "mensajes": (30, 3600), "acceso": (10, 300),
                      "otras": (60, 60), "cuenta": (60, 60), "registro": (10, 3600), "destinatario": (3, 900),
                      "destinatario_dia": (10, 86400)}
CUERPO_429 = '{"detalle": "demasiadas peticiones; inténtelo de nuevo más tarde"}'.encode()
TEXTO_EVENTO_LIMITADOR = "EVENTO limitador_no_disponible: "
# Clientes de prueba con IP fija en la red edge (fuera del rango automático):
# llegan a la API a través de Caddy, como un cliente real.
IP_CLIENTE_A = "10.88.1.3"
IP_CLIENTE_B = "10.88.1.4"
# Las únicas claves que puede haber en Redis: las de las reglas (ventana y
# HMAC de 128 bits) y las de la comprobación de arranque.
PATRON_CLAVE_LIMITE = re.compile(
    r"limite:(denuncia|seguimiento|mensajes|acceso|otras|cuenta):[0-9]+:[0-9a-f]{32}|limite:arranque:[0-9a-f]{16}")
# Rutas de la API y la regla que las limita (cada parámetro de ruta,
# sustituido por "x"). Una ruta nueva hace fallar r) hasta que
# alguien decida su regla. Las de la instrucción (bloque 4b) van a otras, como
# la administración de cuentas: por IP, otras es la primera capa de toda ruta
# con sesión, y la segunda es la regla cuenta, por identidad
# (app/rutas_personal.py, probada en tests/security/verificar_personal.py, h).
RUTAS_API = {"/salud": None, "/v1/empresas/x/denuncias": "denuncia", "/v1/seguimiento": "seguimiento",
             "/v1/seguimiento/mensajes": "mensajes",
             "/v1/personal/activacion": "acceso", "/v1/personal/activacion/confirmar": "acceso",
             "/v1/personal/sesiones": "acceso", "/v1/personal/contrasena": "acceso",
             "/v1/personal/sesiones/renovacion": "otras", "/v1/personal/sesiones/actual": "otras", "/v1/personal/yo": "otras", "/v1/personal/usuarios": "otras",
             "/v1/personal/usuarios/x/invitacion": "otras", "/v1/personal/usuarios/x/baja": "otras",
             "/v1/personal/denuncias": "otras", "/v1/personal/denuncias/x": "otras",
             "/v1/personal/denuncias/x/mensajes": "otras", "/v1/personal/denuncias/x/estado": "otras",
             "/v1/personal/denuncias/x/asignacion": "otras", "/v1/personal/auditoria": "otras",
             "/v1/personal/auditoria/verificacion": "otras",
             # La auditoría desde lo más reciente es una lectura con sesión,
             # como la auditoría por posición.
             "/v1/personal/auditoria/recientes": "otras",
             # Redacción (art. 32.2): instrucción de un admin, con sesión,
             # como el resto de la instrucción.
             "/v1/personal/denuncias/x/redaccion": "otras",
             "/v1/personal/denuncias/x/mensajes/x/redaccion": "otras",
             # Registro "primero el email" (app/solicitudes.py): la solicitud,
             # que envía un correo, con su regla; la verificación y lo del
             # admin, en otras.
             "/v1/personal/registro": "registro", "/v1/personal/registro/verificacion": "otras",
             "/v1/personal/solicitudes": "otras", "/v1/personal/solicitudes/x": "otras",
             "/v1/personal/solicitudes/x/aprobacion": "otras",
             # Páginas del denunciante (app/rutas_web.py): cada acción, con la
             # misma regla que su ruta de /v1 (mismo contador); las que solo
             # muestran un formulario, en otras.
             "/web/": "otras", "/web/empresas/x": "otras", "/web/empresas/x/denuncias": "denuncia",
             "/web/seguimiento": "otras", "/web/seguimiento/consulta": "seguimiento",
             "/web/seguimiento/mensajes": "mensajes"}
# Rutas sin regla propia (no registradas o con un segmento de más): deben caer
# en otras. Se pasan al script de dentro separadas por comas (ninguna lleva).
RUTAS_SIN_REGLA = ("/v1/nueva", "/otra", "/salud/", "/v1/empresas/a/b/denuncias", "/web/empresas/a/b/denuncias",
                   "/web/seguimiento/consulta/")
# Procesos de un contenedor: "<pid> <línea de comandos>" por línea, leídos de
# /proc con sh (sin ps, que la imagen no trae). Las propias líneas de sh y tr
# no contienen "python" ni "uvicorn".
LISTAR_PROCESOS = 'for p in /proc/[0-9]*; do printf "%s " "${p#/proc/}"; tr "\\0" " " < "$p/cmdline"; echo; done'
# Aplicación ASGI mínima para el control de r4: el mismo uvicorn de la imagen
# de la API con --workers 2.
ECO_PROCESOS = """async def aplicacion(scope, receive, send):
    if scope["type"] == "lifespan":
        while True:
            mensaje = await receive()
            if mensaje["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif mensaje["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return
"""
TEXTO_BLOQUEO_PERMISIVA ="ARRANQUE BLOQUEADO: limitador: la ACL permite GET"
TEXTO_BLOQUEO_DEFAULT = "ARRANQUE BLOQUEADO: limitador: Redis responde sin autenticar (usuario default activo)"
TEXTO_BLOQUEO_CONTRASENA = "ARRANQUE BLOQUEADO: limitador: sin conexion con Redis en 15 s (AuthenticationError)"

# Cliente HTTP de prueba: corre con la imagen de la API en la red app (directo
# a la API) o en la red edge (a través de Caddy, con TLS y SNI localhost, sin
# verificar el certificado del CA local). Las peticiones llegan por la
# entrada estándar en JSON: en Windows la línea de comandos tiene un límite de
# 32 KB y los cuerpos de prueba llegan a 128 KiB.
CLIENTE_HTTP = r'''
import base64, http.client, json, socket, ssl, sys, time

def lento(pt):
    """Envía la mitad del cuerpo, espera pt["pausa"] segundos y envía el
    resto, por un socket TLS directo. Devuelve el estado HTTP que llegue, o el
    error si el servidor cortó la conexión."""
    contexto = ssl.create_default_context()
    contexto.check_hostname = False
    contexto.verify_mode = ssl.CERT_NONE
    s = contexto.wrap_socket(socket.create_connection((pt["host"], pt["puerto"]), timeout=pt["pausa"] + 30),
                             server_hostname="localhost")
    cuerpo = pt["prefijo"].encode("utf-8")
    cabeceras = (f"POST {pt['ruta']} HTTP/1.1\r\nHost: localhost:{pt['puerto']}\r\n"
                 f"Content-Type: application/json\r\nContent-Length: {len(cuerpo)}\r\nConnection: close\r\n\r\n")
    mitad = len(cuerpo) // 2
    inicio = time.monotonic()
    try:
        s.sendall(cabeceras.encode("ascii") + cuerpo[:mitad])
        time.sleep(pt["pausa"])
        s.sendall(cuerpo[mitad:])
        datos = b""
        while True:
            trozo = s.recv(65536)
            if not trozo:
                break
            datos += trozo
    except OSError as error:
        return {"error": type(error).__name__, "segundos": round(time.monotonic() - inicio, 1)}
    finally:
        s.close()
    linea = datos.split(b"\r\n", 1)[0].split()
    estado = int(linea[1]) if len(linea) > 1 and linea[1].isdigit() else None
    return {"estado": estado, "cuerpo": base64.b64encode(datos.split(b"\r\n\r\n", 1)[-1]).decode("ascii"),
            "segundos": round(time.monotonic() - inicio, 1)}

salida = []
for pt in json.load(sys.stdin):
    conexion = None
    try:
        if pt.get("pausa") is not None:
            salida.append(lento(pt))
            continue
        if pt.get("tls"):
            contexto = ssl.create_default_context()
            contexto.check_hostname = False
            contexto.verify_mode = ssl.CERT_NONE
            crudo = socket.create_connection((pt["host"], pt["puerto"]), timeout=30)
            conexion = http.client.HTTPConnection("localhost", pt["puerto"], timeout=30)
            conexion.sock = contexto.wrap_socket(crudo, server_hostname="localhost")
        else:
            conexion = http.client.HTTPConnection(pt["host"], pt["puerto"], timeout=30)
        if "tamano" in pt:
            # Cuerpo JSON válido de un tamaño exacto: el JSON admite espacios
            # al final.
            prefijo = pt["prefijo"].encode("utf-8")
            cuerpo = prefijo + b" " * (pt["tamano"] - len(prefijo))
        elif pt.get("cuerpo") is not None:
            cuerpo = base64.b64decode(pt["cuerpo"])
        else:
            cuerpo = None
        if pt.get("trozos"):
            # Un iterable sin Content-Length: http.client lo envía por trozos.
            trozos = [cuerpo[i:i + 16384] for i in range(0, len(cuerpo), 16384)]
            conexion.request(pt["metodo"], pt["ruta"], body=iter(trozos), headers=pt.get("cabeceras", {}))
        else:
            conexion.request(pt["metodo"], pt["ruta"], body=cuerpo, headers=pt.get("cabeceras", {}))
        respuesta = conexion.getresponse()
        datos = respuesta.read()
        salida.append({"estado": respuesta.status, "cuerpo": base64.b64encode(datos).decode("ascii"),
                       "cabeceras": {k.lower(): v for k, v in respuesta.getheaders()}})
    except Exception as error:
        salida.append({"error": type(error).__name__})
    finally:
        if conexion is not None:
            conexion.close()
print(json.dumps(salida))
'''

# Se ejecuta dentro del contenedor de la API, con la clave maestra FALSA de
# esta ejecución. Devuelve versiones y longitudes, y aparte las claves de
# empresa en hex: la batería las guarda para buscarlas en los logs y nunca las
# imprime. Esta salida es la de "docker compose exec", no el log del
# contenedor.
DESENVOLVER = """
import json, sys, uuid
from app import bd, claves, cripto
maestra = claves.cargar_maestra()
pool = bd.crear_pool(tamano_maximo=1)
pool.open(wait=True, timeout=15)
res = {}
claves_hex = []
for texto in sys.argv[1:]:
    empresa = uuid.UUID(texto)
    with bd.transaccion_empresa(pool, empresa) as c:
        filas = c.execute("select version, clave_envuelta from canal.clave_empresa order by version").fetchall()
    salida = []
    for version, envuelta in filas:
        try:
            clave = cripto.desenvolver_clave(maestra, bytes(envuelta), empresa, version)
            salida.append([version, len(clave)])
            claves_hex.append(clave.hex())
        except cripto.ErrorIntegridad:
            salida.append([version, "ErrorIntegridad"])
    res[texto] = salida
pool.close()
print(json.dumps({"longitudes": res, "claves": claves_hex}, sort_keys=True))
"""

# Se ejecuta dentro del contenedor de la API: inserta, como haría el personal
# (bloque 4), un mensaje cifrado con autor "personal" y su autor_id. El
# contenido se escribe aquí con el formato del modelo de amenazas ({"texto",
# "v": 1}, JSON compacto con claves ordenadas), no con el código de la API:
# si la API leyera otro formato, el seguimiento fallaría.
MENSAJE_PERSONAL = """
import json, sys, uuid
from app import bd, claves, cripto
maestra = claves.cargar_maestra()
empresa, denuncia, autor = (uuid.UUID(x) for x in sys.argv[1:4])
texto = sys.argv[4]
pool = bd.crear_pool(tamano_maximo=1)
pool.open(wait=True, timeout=15)
mensaje = uuid.uuid4()
with bd.transaccion_empresa(pool, empresa) as c:
    version, envuelta = c.execute(
        "select version, clave_envuelta from canal.clave_empresa order by version desc limit 1").fetchone()
    clave = cripto.desenvolver_clave(maestra, bytes(envuelta), empresa, version)
    contenido = json.dumps({"texto": texto, "v": 1}, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    cifrado = cripto.cifrar_contenido(clave, contenido.encode("utf-8"),
                                      cripto.aad_mensaje(empresa, denuncia, mensaje, "personal", autor))
    c.execute("insert into canal.mensaje (empresa_id, denuncia_id, id, autor, autor_id, contenido_cifrado, "
              "version_clave) values (%s, %s, %s, 'personal', %s, %s, %s)",
              [empresa, denuncia, mensaje, autor, cifrado, version])
pool.close()
print("insertado")
"""

# Se ejecuta dentro del contenedor de la API, con el código y la base de datos
# reales. Ejercita la carrera "el código resolvió una denuncia que después se
# suprimió", que por HTTP no tiene ningún punto de pausa en consultar() (no
# toma bloqueos): sustituye _resolver_codigo SOLO en este proceso para que
# devuelva la empresa y el id de una denuncia ya suprimida. El código de
# producción no se toca. Control: con una denuncia que existe, las dos
# funciones responden con normalidad. Solo imprime nombres de clase.
RAMAS_SUPRESION = """
import json, sys, uuid
from app import bd, claves, denuncias
empresa, existente, suprimida = (uuid.UUID(x) for x in sys.argv[1:4])
claves_api = claves.cargar()
pool = bd.crear_pool(tamano_maximo=1)
pool.open(wait=True, timeout=15)

def clase(funcion):
    try:
        return type(funcion()).__name__
    except Exception as error:
        return type(error).__name__

res = {}
for nombre, denuncia in (("existente", existente), ("suprimida", suprimida)):
    denuncias._resolver_codigo = lambda p, c, codigo, d=denuncia: (empresa, d)
    res["consultar_" + nombre] = clase(lambda: denuncias.consultar(pool, claves_api, "x"))
    res["mensaje_" + nombre] = clase(lambda: denuncias.enviar_mensaje(pool, claves_api, "x", "rama"))
pool.close()
print(json.dumps(res, sort_keys=True))
"""

# Se ejecuta dentro del contenedor de la API, con el código real: la regla de
# cada ruta que la aplicación tiene registrada y de otras que no existen, y la
# huella de cliente (app/limitador.py) con IPv4 e IPv6. No abre conexiones.
# Las rutas salen de aplicacion.openapi(), que las genera desde el enrutador
# real aunque la API no lo sirva (openapi_url=None). En FastAPI 0.143.0,
# aplicacion.routes guarda los routers incluidos como objetos internos sin
# path (comprobado). Una ruta con include_in_schema=False no saldría aquí,
# pero igual quedaría limitada por la regla otras.
LIMITADOR_DENTRO = """
import json
import re
import sys
from app import limitador
from app.principal import aplicacion
# Cualquier parámetro de ruta ({identificador}, {secuencia}...) pasa a "x",
# también los que se añadan: la ruta nueva sigue fallando por RUTAS_API.
rutas = sorted(re.sub("[{][^}]*[}]", "x", r) for r in aplicacion.openapi()["paths"])
res = {"rutas": {r: limitador.regla_de(r) for r in rutas},
       "otras": {r: limitador.regla_de(r) for r in sys.argv[1].split(",")}}
s1, s2 = b"1" * 32, b"2" * 32
h = limitador.huella_cliente
res["ipv6_mismo_64"] = h(s1, "2001:db8::1") == h(s1, "2001:db8::ffff:ffff:ffff:ffff")
res["ipv6_otro_64"] = h(s1, "2001:db8::1") != h(s1, "2001:db8:0:1::1")
res["ipv4_en_ipv6"] = h(s1, "::ffff:10.88.1.3") == h(s1, "10.88.1.3")
res["ipv4_distintas"] = h(s1, "10.88.1.3") != h(s1, "10.88.1.4")
res["otra_sal"] = h(s1, "10.88.1.3") != h(s2, "10.88.1.3")
res["longitud"] = len(h(s1, "10.88.1.3"))
try:
    h(s1, "no es una ip")
    res["no_ip"] = "aceptada"
except ValueError:
    res["no_ip"] = "ValueError"
print(json.dumps(res, sort_keys=True))
"""


# ---------------------------------------------------------------------------
# Utilidades de ejecución y de informe
# ---------------------------------------------------------------------------
class R:
    def __init__(self, rc, out, err):
        self.rc, self.out, self.err = rc, out, err

    @property
    def todo(self):
        return self.out + self.err


class Parada(Exception):
    pass


def p(texto=""):
    print(texto, flush=True)
    lineas_salida.append(texto)


def ejecutar(args, entrada=None, timeout=900):
    # check=False explícito: el código de salida lo revisa cada prueba.
    r = subprocess.run(args, input=entrada, capture_output=True, timeout=timeout, check=False)
    return R(r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace"))


def dc(*args, entrada=None):
    return ejecutar(BASE + list(args), entrada=entrada)


def dc_con_gestion(*args):
    """compose con el perfil gestion. down solo actúa sobre los servicios de
    los perfiles activos: sin él, la imagen de gestion quedaría sin borrar."""
    return ejecutar(BASE + ["--profile", "gestion"] + list(args))


def sup(sql):
    """SQL como superusuario por el socket del contenedor (peer)."""
    return dc("exec", "-T", "postgres", "psql", "-U", "postgres", "-d", "canario", "-X", "-q",
              "-A", "-t", "-v", "ON_ERROR_STOP=1", "-f", "-", entrada=sql.encode("utf-8"))


def pasa(cond, texto):
    p(("PASA  " if cond else "FALLA ") + texto)
    if not cond:
        estado["falla"] = True


def sinc(texto):
    p("SIN CONCLUSION " + texto)
    estado["sin_conclusion"] = True


def negativo(nombre, cond, control_ok, detalle=""):
    if not control_ok:
        sinc(f"{nombre}: el control positivo fallo {detalle}".rstrip())
        return
    pasa(cond, nombre)
    if not cond and detalle:
        p(f"   {detalle}")


def contenedor(servicio):
    cid = dc("ps", "-a", "-q", servicio).out.strip()
    if not cid:
        raise Parada(f"no hay contenedor para el servicio {servicio}")
    return cid


def salud(cid):
    return ejecutar(["docker", "inspect", "--format", "{{json .State.Health.Status}}", cid]).out.strip().strip('"')


def esperar(condicion, maximo):
    """Espera hasta que condicion() sea verdadera o pasen maximo segundos."""
    limite = time.monotonic() + maximo
    while time.monotonic() < limite:
        if condicion():
            return True
        time.sleep(1)
    return condicion()


TEMPORAL = None
IMAGEN_API = ""
# Todo lo que imprime gestion (salida y errores), para comprobar que nunca
# muestra claves.
salidas_gestion = []


def texto_acl(aplicacion, default="user default off", contrasena=None):
    """Una ACL de Redis con la contraseña falsa de esta ejecución.

    aplicacion son los permisos de su usuario (los literales de producción, u
    otros en las desviaciones de r). El usuario inspector solo existe en la
    batería.
    """
    hash_aplicacion = hashlib.sha256((contrasena or CONTRASENAS_REDIS["aplicacion"]).encode("ascii")).hexdigest()
    hash_inspector = hashlib.sha256(CONTRASENAS_REDIS["inspector"].encode("ascii")).hexdigest()
    return (f"{default}\nuser aplicacion on #{hash_aplicacion} {aplicacion}\n"
            f"user inspector on #{hash_inspector} {PERMISOS_ACL_INSPECTOR}\n")


def fichero_secreto(nombre, ruta):
    # Ruta con barras normales y entre comillas: la del directorio temporal de
    # Windows puede llevar espacios.
    return [f"  {nombre}:", f"    file: \"{ruta.as_posix()}\""]


def preparar_claves_falsas():
    """Genera las claves y los secretos de Redis falsos y los ficheros compose
    que los montan, más el que fija los límites de prueba.

    BASE_PRODUCCION queda con los secretos falsos y sin límites de prueba: la
    API arrancada con ella usa los de producción.
    """
    directorio = TEMPORAL / "claves_compose"
    directorio.mkdir()
    lineas = ["secrets:"]
    for nombre in ("clave_maestra", "clave_hmac_codigos", "clave_firma_tokens",
                   "clave_hmac_identidades", "clave_flujo_externo"):
        CLAVES_FALSAS[nombre] = secrets.token_hex(32)
        (directorio / nombre).write_text(CLAVES_FALSAS[nombre], encoding="ascii", newline="")
        lineas += fichero_secreto(nombre, directorio / nombre)
    # Mismo formato que scripts/generar_secretos.py (token_urlsafe(48)).
    for usuario in ("aplicacion", "inspector"):
        CONTRASENAS_REDIS[usuario] = secrets.token_urlsafe(48)
    (directorio / "contrasena_redis").write_text(CONTRASENAS_REDIS["aplicacion"], encoding="ascii", newline="")
    (directorio / "redis_acl").write_text(texto_acl(PERMISOS_ACL_APLICACION), encoding="ascii", newline="\n")
    lineas += fichero_secreto("contrasena_redis", directorio / "contrasena_redis")
    lineas += fichero_secreto("redis_acl", directorio / "redis_acl")
    adicional = TEMPORAL / "claves_falsas.yml"
    adicional.write_text("\n".join(lineas) + "\n", encoding="utf-8", newline="\n")
    BASE.extend(["-f", str(adicional)])
    BASE_PRODUCCION.extend(BASE)
    limites = TEMPORAL / "limites_prueba.yml"
    limites.write_text(f"services:\n  api:\n    environment:\n      CANARIO_LIMITES: \"{LIMITES_PRUEBA}\"\n",
                       encoding="utf-8", newline="\n")
    BASE.extend(["-f", str(limites)])
    return directorio


def gestion(*args):
    """gestion por docker compose (contraseñas de secrets/ y claves falsas)."""
    r = dc("run", "--rm", "-T", "gestion", *args)
    salidas_gestion.append(r.out + r.err)
    return r


def gestion_suelta(maestra, *args):
    """gestion con la imagen de la API y una clave maestra elegida por la prueba.

    La contraseña de aplicacion es la de secrets/, montada con --mount (sin
    leerla aquí): hace falta para llegar a la base de datos.
    """
    contrasena = (RAIZ / "secrets" / "contrasena_aplicacion.txt").resolve()
    r = ejecutar(["docker", "run", "--rm", "--network", f"{PROYECTO}_data",
                  "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                  "--mount", f"type=bind,src={contrasena},dst=/run/secrets/contrasena_aplicacion,readonly",
                  "--mount", f"type=bind,src={maestra},dst=/run/secrets/clave_maestra,readonly",
                  "--entrypoint", "python", IMAGEN_API, "-m", "app.gestion", *args])
    salidas_gestion.append(r.out + r.err)
    return r


def desenvolver(*empresas):
    """Versiones y longitudes de las claves de cada empresa, vistas por la API."""
    r = dc("exec", "-T", "api", "python", "-c", DESENVOLVER, *empresas)
    try:
        datos = json.loads(r.out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise Parada(f"no se pudo desenvolver desde la API: {r.err.strip()[-400:]!r}") from None
    CLAVES_EMPRESA.update(datos["claves"])
    return datos["longitudes"]


def claves_en_bd(empresa):
    r = sup(f"select version || '|' || octet_length(clave_envuelta) || '|' || get_byte(clave_envuelta, 0) "
            f"from canal.clave_empresa where empresa_id = '{empresa}' order by version;")
    if r.rc != 0:
        raise Parada(f"no se pudieron leer las claves como superusuario: {r.err.strip()[:300]}")
    return r.out.split()


# ---------------------------------------------------------------------------
# Comprobaciones
# ---------------------------------------------------------------------------
def seccion_a():
    global IMAGEN_API
    p("=== a) arranque con las claves de esta ejecucion")
    # Con Caddy: la sección k) prueba el límite de cuerpo también a través de él.
    r = dc("up", "-d", "--build", "--wait", "postgres", "api", "caddy")
    p(f"up -d --build --wait postgres api caddy -> codigo {r.rc}")
    if r.rc != 0:
        p(r.todo.strip()[-1500:])
        raise Parada("no arranca la API o Caddy")
    IMAGEN_API = ejecutar(["docker", "inspect", "--format", "{{.Config.Image}}", contenedor("api")]).out.strip()
    registro = dc("logs", "--no-color", "--no-log-prefix", "api").todo
    pasa(TEXTO_VERIFICADO in registro and TEXTO_BLOQUEADO not in registro,
         f"a) la API arranca con sus claves y registra {TEXTO_VERIFICADO!r}")
    pasa(TEXTO_LIMITADOR_VERIFICADO in registro, f"a) la API verifica Redis y registra {TEXTO_LIMITADOR_VERIFICADO!r}")
    pasa(TEXTO_LIMITES_PRUEBA in registro,
         f"a) las secciones funcionales usan los limites de prueba y el log lo dice ({TEXTO_LIMITES_PRUEBA!r})")
    pasa(salud(contenedor("api")) == "healthy", "a) la API esta healthy")
    pasa(dc("exec", "-T", "api", "test", "-f", "/run/secrets/contrasena_aplicacion").rc == 0,
         "a) /run/secrets/contrasena_aplicacion existe en la API (sin leerlo)")
    # Las claves que ve la API son las falsas de esta ejecución: se compara su
    # sha256 dentro del contenedor, sin sacar la clave.
    for nombre, valor in {**CLAVES_FALSAS, "contrasena_redis": CONTRASENAS_REDIS["aplicacion"]}.items():
        r = dc("exec", "-T", "api", "sha256sum", f"/run/secrets/{nombre}")
        esperado = hashlib.sha256(valor.encode("ascii")).hexdigest()
        pasa(r.rc == 0 and r.out.split()[:1] == [esperado],
             f"a) la API usa la {nombre} falsa de esta ejecucion (sha256 dentro del contenedor)")
    control = dc("exec", "-T", "api", "test", "-f", "/run/secrets/contrasena_aplicacion").rc == 0
    negativo("a) la API no tiene el secreto de plataforma",
             dc("exec", "-T", "api", "test", "-e", "/run/secrets/contrasena_plataforma").rc != 0, control)
    servicios = dc("config", "--services").out.split()
    con_perfil = dc_con_gestion("config", "--services").out.split()
    negativo(f"a) gestion no forma parte de un up normal ({sorted(servicios)})",
             "gestion" not in servicios, "gestion" in con_perfil, f"con perfil: {sorted(con_perfil)}")


def seccion_b():
    p("=== b) criptografia (codigo real de app/cripto.py)")
    r = ejecutar(["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
                  "--security-opt", "no-new-privileges:true", "--entrypoint", "python", IMAGEN_API,
                  "-c", PRUEBA_CRIPTO])
    try:
        res = json.loads(r.out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        sinc(f"b) no se pudo ejecutar la prueba de criptografia: {r.err.strip()[-600:]!r}")
        return
    p(f"   resultado: {json.dumps(res, sort_keys=True)}")

    pasa(res["nist_cifrado"] == NIST_CIFRADO + NIST_TAG, "b) AES-256-GCM coincide con el vector del NIST")
    pasa(res["nist_descifrado"] == NIST_TEXTO, "b) descifrar() lee el vector del NIST en el formato propio")
    control = res["nist_descifrado"] == NIST_TEXTO
    for clave in ("tag_alterado", "cifrado_alterado", "aad_alterado", "formato_desconocido", "demasiado_corto"):
        negativo(f"b) vector del NIST con {clave.replace('_', ' ')}: ErrorIntegridad ({res[clave]})",
                 res[clave] == "ErrorIntegridad", control)
    pasa(res["rfc4231"] == RFC4231_HMAC, "b) HMAC-SHA256 coincide con RFC 4231 (caso 2)")
    pasa(res["hmac_codigo_etiqueta"] is True,
         f"b) hmac_codigo = HMAC-SHA256(clave, {ETIQUETA_SEGUIMIENTO!r} || codigo)")
    pasa(res["hmac_codigo_otra_clave"] is True, "b) con otra clave HMAC el resultado cambia")

    pasa(res["relleno_tamanos"] == TAMANOS_RELLENO, f"b) relleno a bloques de 256 ({res['relleno_tamanos']})")
    control = res["relleno_ida_vuelta"] is True
    pasa(control, "b) control: el relleno se quita y devuelve el contenido exacto")
    for clave in ("relleno_basura", "relleno_bloque_extra", "relleno_longitud_falsa"):
        negativo(f"b) {clave.replace('_', ' ')}: ErrorIntegridad ({res[clave]})",
                 res[clave] == "ErrorIntegridad", control)

    pasa(res["aad_longitudes"] == LONGITUDES_AAD, f"b) longitudes de AAD fijas ({res['aad_longitudes']})")
    pasa(res["tamano_cifrado"] == TAMANO_CIFRADO_CORTO,
         f"b) un texto de 4 bytes ocupa {res['tamano_cifrado']} bytes cifrado (no revela su longitud)")
    control = res["contenido_control"] == "hola"
    pasa(control, "b) control: el contenido se descifra en su sitio")
    for clave in ("contenido_otra_denuncia", "contenido_otra_empresa", "contenido_como_mensaje",
                  "contenido_otra_clave"):
        negativo(f"b) {clave.replace('_', ' ')}: ErrorIntegridad ({res[clave]})",
                 res[clave] == "ErrorIntegridad", control)
    control = res["mensaje_control"] == "m"
    pasa(control, "b) control: el mensaje se descifra con su id y su autor")
    for clave in ("mensaje_otro_id", "mensaje_como_personal"):
        negativo(f"b) {clave.replace('_', ' ')}: ErrorIntegridad ({res[clave]})",
                 res[clave] == "ErrorIntegridad", control)
    for clave in ("autor_personal_sin_id", "autor_denunciante_con_id", "version_cero", "version_booleana"):
        pasa(res[clave] == "ValueError", f"b) {clave.replace('_', ' ')} se rechaza ({res[clave]})")
    pasa(res["uuid_en_texto"] == "TypeError", f"b) un uuid en texto se rechaza ({res['uuid_en_texto']})")
    pasa(res["nonce_distinto"] is True, "b) dos cifrados del mismo texto son distintos (nonce aleatorio)")

    pasa(res["envuelta_tamano"] == TAMANO_CLAVE_ENVUELTA, f"b) clave envuelta de {res['envuelta_tamano']} bytes")
    control = res["envuelta_control"] is True
    pasa(control, "b) control: la clave se desenvuelve con su empresa, su version y su maestra")
    for clave in ("envuelta_otra_version", "envuelta_otra_empresa", "envuelta_otra_maestra"):
        negativo(f"b) {clave.replace('_', ' ')}: ErrorIntegridad ({res[clave]})",
                 res[clave] == "ErrorIntegridad", control)

    pasa(res["codigo_formato"] is True and res["codigo_bytes"] is True,
         "b) 1000 codigos con 8 grupos de 4 en base32 y 20 bytes (160 bits)")
    pasa(res["codigos_distintos"] == 1000, f"b) 1000 codigos distintos ({res['codigos_distintos']})")
    control = res["codigo_lectura_exacta"] is True
    pasa(control, "b) control: un codigo se lee tal como se muestra")
    for clave in ("codigo_minusculas_sin_guiones", "codigo_con_espacios", "codigo_hmac_igual_en_formas_equivalentes"):
        pasa(res[clave] is True, f"b) {clave.replace('_', ' ')}")
    negativo(f"b) la ligadura U+FB00 no se convierte en un codigo valido ({res['ligadura']})",
             res["ligadura"] is None, res["ligadura_control"] is True)
    invalidos = res["codigos_invalidos"]
    negativo(f"b) codigos invalidos rechazados sin excepcion ({invalidos})",
             invalidos == {k: None for k in ("vacio", "corto", "largo", "con_cero", "con_uno", "no_ascii",
                                             "con_relleno", "excesivo", "no_texto", "bytes")}, control)


def arrancar_api_temporal(etiqueta, montajes, entorno=None):
    """Arranca la imagen de la API con secretos falsos y devuelve su log."""
    nombre = f"{PROYECTO}_api_{etiqueta}"
    argumentos = []
    for origen, destino in montajes:
        argumentos += ["--mount", f"type=bind,src={origen},dst=/run/secrets/{destino},readonly"]
    for variable, valor in {**ENTORNO_API, **(entorno or {})}.items():
        argumentos += ["-e", f"{variable}={valor}"]
    ejecutar(["docker", "run", "-d", "--name", nombre, "--network", f"{PROYECTO}_data",
              "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
              *argumentos, IMAGEN_API])
    try:
        esperar(lambda: ejecutar(["docker", "inspect", "--format", "{{.State.Running}}", nombre]).out.strip()
                == "false", 60)
        return ejecutar(["docker", "logs", nombre]).todo
    finally:
        ejecutar(["docker", "rm", "-f", nombre])


def seccion_c():
    p("=== c) la API no arranca sin sus claves de cifrado")
    d = TEMPORAL / "falsos"
    d.mkdir()
    valores = {"contrasena": secrets.token_urlsafe(48), "maestra": secrets.token_hex(32),
               "hmac": secrets.token_hex(32), "firma": secrets.token_hex(32),
               "identidades": secrets.token_hex(32), "flujo": secrets.token_hex(32)}
    ficheros = {
        "contrasena": valores["contrasena"],
        # Bien formada: la comprobación del secreto de Redis va después de la
        # de claves y no debe interferir.
        "redis": secrets.token_urlsafe(48),
        "maestra": valores["maestra"],
        "hmac": valores["hmac"],
        "maestra_salto": valores["maestra"] + "\n",
        "maestra_mayusculas": valores["maestra"].upper(),
        "maestra_corta": valores["maestra"][:-2],
        "hmac_igual": valores["maestra"],
        "firma": valores["firma"],
        "firma_igual": valores["hmac"],
        "identidades": valores["identidades"],
        "identidades_igual": valores["hmac"],
        "flujo": valores["flujo"],
        "flujo_igual": valores["identidades"],
    }
    for nombre, contenido in ficheros.items():
        (d / nombre).write_text(contenido, encoding="ascii", newline="")

    def montar(maestra="maestra", hmac="hmac", firma="firma", identidades="identidades", flujo="flujo"):
        lista = [(d / "contrasena", "contrasena_aplicacion"), (d / "redis", "contrasena_redis")]
        if maestra:
            lista.append((d / maestra, "clave_maestra"))
        if hmac:
            lista.append((d / hmac, "clave_hmac_codigos"))
        if firma:
            lista.append((d / firma, "clave_firma_tokens"))
        if identidades:
            lista.append((d / identidades, "clave_hmac_identidades"))
        if flujo:
            lista.append((d / flujo, "clave_flujo_externo"))
        return lista

    # Control: con claves falsas bien formadas, la comprobación de claves pasa
    # y la API llega a la conexión (que falla por la contraseña falsa).
    control_log = arrancar_api_temporal("claves_ok", montar())
    control = (f"{TEXTO_BLOQUEADO}conexion" in control_log and f"{TEXTO_BLOQUEADO}claves" not in control_log)
    pasa(control, "c) control: con claves bien formadas la API pasa la comprobacion de claves "
                  f"y llega a la conexion ({TEXTO_BLOQUEADO}conexion)")
    casos = [
        ("sin_maestra", montar(maestra=None), "no se puede leer clave_maestra"),
        ("sin_hmac", montar(hmac=None), "no se puede leer clave_hmac_codigos"),
        ("maestra_salto", montar(maestra="maestra_salto"), "clave_maestra no tiene el formato esperado"),
        ("maestra_mayusculas", montar(maestra="maestra_mayusculas"), "clave_maestra no tiene el formato esperado"),
        ("maestra_corta", montar(maestra="maestra_corta"), "clave_maestra no tiene el formato esperado"),
        ("hmac_igual", montar(hmac="hmac_igual"), "clave_maestra y clave_hmac_codigos son iguales"),
        ("sin_firma", montar(firma=None), "no se puede leer clave_firma_tokens"),
        ("firma_igual", montar(firma="firma_igual"), "clave_hmac_codigos y clave_firma_tokens son iguales"),
        ("sin_identidades", montar(identidades=None), "no se puede leer clave_hmac_identidades"),
        ("identidades_igual", montar(identidades="identidades_igual"),
         "clave_hmac_codigos y clave_hmac_identidades son iguales"),
        ("sin_flujo", montar(flujo=None), "no se puede leer clave_flujo_externo"),
        ("flujo_igual", montar(flujo="flujo_igual"), "clave_hmac_identidades y clave_flujo_externo son iguales"),
    ]
    for etiqueta, montajes, motivo in casos:
        registro = arrancar_api_temporal(etiqueta, montajes)
        esperado = f"{TEXTO_BLOQUEADO}claves: {motivo}"
        negativo(f"c) {etiqueta.replace('_', ' ')}: la API no arranca y registra {esperado!r}",
                 esperado in registro and TEXTO_VERIFICADO not in registro
                 and f"{TEXTO_BLOQUEADO}conexion" not in registro,
                 control, f"log: {registro.strip()[-300:]!r}")
        fugas = [n for n in ("maestra", "hmac", "firma") if valores[n] in registro or valores[n].upper() in registro]
        negativo(f"c) {etiqueta.replace('_', ' ')}: ninguna clave aparece en el log {fugas if fugas else ''}".strip(),
                 not fugas, control)


def seccion_d():
    p("=== d) servicio gestion: alta de empresas y claves")
    # La imagen se construye aparte: si la construyera el primer "run", su
    # salida (con los digests sha256 de las capas) se mezclaría con la del
    # programa y la comprobación final de fugas no miraría solo lo que
    # imprime gestion.
    r = dc_con_gestion("build", "gestion")
    if r.rc != 0:
        raise Parada(f"no se pudo construir la imagen de gestion: {r.err.strip()[-300:]}")
    altas = {}
    # A en la península y B en Canarias: las secciones HTTP comprueban la
    # fecha de cada una en su zona.
    for etiqueta, nombre, zona in (("A", "Empresa A", "Europe/Madrid"), ("B", "Empresa B", "Atlantic/Canary")):
        r = gestion("alta-empresa", "--nombre", nombre, "--zona", zona)
        alta = PATRON_ALTA.search(r.out)
        clave = PATRON_CLAVE.search(r.out)
        ok = r.rc == 0 and alta is not None and clave is not None and clave.group(2) == "1"
        pasa(ok, f"d) alta-empresa {etiqueta} ({zona}): empresa, directorio y clave version 1 (codigo {r.rc})")
        if not ok:
            p(f"   salida: {r.out.strip()[-300:]!r} error: {r.err.strip()[-300:]!r}")
            raise Parada("gestion no da de alta empresas")
        altas[etiqueta] = alta.group(1)
        EMPRESAS[etiqueta] = (uuid.UUID(alta.group(1)), alta.group(2), zona)
    A, B = altas["A"], altas["B"]
    r = sup(f"select zona_horaria from canal.empresa where id in ('{A}', '{B}') order by id = '{B}';")
    pasa(r.out.split() == ["Europe/Madrid", "Atlantic/Canary"],
         f"d) cada empresa guarda la zona pedida en el alta ({r.out.split()})")

    # Zona horaria fuera de la lista: gestion la rechaza antes de conectar y
    # no crea nada. Control: las altas de arriba sí crearon sus empresas.
    antes = sup("select count(*) from canal.empresa;").out.strip()
    r = gestion("alta-empresa", "--nombre", "Empresa UTC", "--zona", "UTC")
    despues = sup("select count(*) from canal.empresa;").out.strip()
    negativo(f"d) alta-empresa con --zona UTC se rechaza sin crear empresa (codigo {r.rc}, {antes} -> {despues})",
             r.rc != 0 and "invalid choice" in r.err and antes == despues, len(EMPRESAS) == 2)
    r = gestion("alta-empresa", "--nombre", "Empresa sin zona")
    negativo(f"d) alta-empresa sin --zona se rechaza (codigo {r.rc})",
             r.rc != 0 and "--zona" in r.err, len(EMPRESAS) == 2)

    for etiqueta, empresa in altas.items():
        filas = claves_en_bd(empresa)
        pasa(filas == [f"1|{TAMANO_CLAVE_ENVUELTA}|1"],
             f"d) {etiqueta}: en la BD solo hay la clave envuelta v1 de {TAMANO_CLAVE_ENVUELTA} bytes "
             f"con formato 1 ({filas})")
    r = sup(f"select count(*) from canal.directorio_empresas where empresa_id in ('{A}', '{B}');")
    pasa(r.out.strip() == "2", f"d) las dos empresas estan en el directorio ({r.out.strip()})")

    res = desenvolver(A, B)
    control = res == {A: [[1, 32]], B: [[1, 32]]}
    pasa(control, f"d) control: la API desenvuelve la clave de cada empresa con su clave maestra ({res})")

    # Clave de A copiada como versión 2 de B (como superusuario): el AAD ata
    # la clave a su empresa y su versión.
    r = sup(f"insert into canal.clave_empresa (empresa_id, version, clave_envuelta) "
            f"select '{B}', 2, clave_envuelta from canal.clave_empresa where empresa_id = '{A}' and version = 1;")
    if r.rc != 0:
        raise Parada(f"no se pudo copiar la clave: {r.err.strip()[:300]}")
    res = desenvolver(A, B)
    negativo(f"d) la clave de A copiada como version 2 de B no se desenvuelve ({res.get(B)})",
             res.get(B) == [[1, 32], [2, "ErrorIntegridad"]], res.get(A) == [[1, 32]])

    control_a = gestion("nueva-clave", "--empresa-id", A)
    control = control_a.rc == 0 and f"empresa_id={A} version=2" in control_a.out
    pasa(control, f"d) control: nueva-clave rota la clave de A a la version 2 (codigo {control_a.rc})")
    r = gestion("nueva-clave", "--empresa-id", B)
    negativo("d) nueva-clave se niega si una clave existente de la empresa no se desenvuelve",
             r.rc != 0 and TEXTO_NO_DESENVUELVE in r.err and claves_en_bd(B) == [f"1|{TAMANO_CLAVE_ENVUELTA}|1",
                                                                              f"2|{TAMANO_CLAVE_ENVUELTA}|1"],
             control, f"codigo {r.rc}, error {r.err.strip()[-300:]!r}")
    sup(f"delete from canal.clave_empresa where empresa_id = '{B}' and version = 2;")
    r = gestion("nueva-clave", "--empresa-id", B)
    pasa(r.rc == 0 and f"empresa_id={B} version=2" in r.out, "d) sin la clave alterada, B rota a la version 2")
    res = desenvolver(A, B)
    pasa(res == {A: [[1, 32], [2, 32]], B: [[1, 32], [2, 32]]},
         f"d) las versiones antiguas y nuevas se desenvuelven ({res})")

    inexistente = str(uuid.uuid4())
    r = gestion("nueva-clave", "--empresa-id", inexistente)
    negativo("d) nueva-clave con una empresa inexistente se rechaza sin crear nada",
             r.rc != 0 and TEXTO_EMPRESA_NO_EXISTE in r.err and claves_en_bd(inexistente) == [],
             control, f"codigo {r.rc}, error {r.err.strip()[-300:]!r}")

    # Otra clave maestra, distinta de la de esta ejecución. Control: la misma
    # ejecución suelta con la clave maestra de esta ejecución sí crea la
    # versión siguiente.
    otra = TEMPORAL / "otra_maestra"
    otra.write_text(secrets.token_hex(32), encoding="ascii", newline="")
    r = gestion_suelta(otra, "nueva-clave", "--empresa-id", A)
    sin_cambios = len(claves_en_bd(A)) == 2
    control_buena = gestion_suelta(DIRECTORIO_CLAVES / "clave_maestra", "nueva-clave", "--empresa-id", A)
    negativo("d) con otra clave maestra, nueva-clave se niega y no crea ninguna clave",
             r.rc != 0 and TEXTO_NO_DESENVUELVE in r.err and sin_cambios,
             control_buena.rc == 0 and f"empresa_id={A} version=3" in control_buena.out,
             f"otra: codigo {r.rc} {r.err.strip()[-200:]!r}; buena: codigo {control_buena.rc} "
             f"{control_buena.err.strip()[-200:]!r}")

    # Base de datos desviada: gestion aplica las comprobaciones del arranque y
    # no guarda claves. El alta queda a medias, de forma visible y con el
    # comando para completarla.
    r = sup("GRANT DELETE ON canal.denuncia TO aplicacion;")
    if r.rc != 0:
        raise Parada(f"no se pudo provocar la desviacion: {r.err.strip()[:300]}")
    try:
        desviada = gestion("nueva-clave", "--empresa-id", A)
        sin_cambios = len(claves_en_bd(A)) == 3
        alta = gestion("alta-empresa", "--nombre", "Empresa C", "--zona", "Europe/Madrid")
    finally:
        revertida = sup("REVOKE DELETE ON canal.denuncia FROM aplicacion;").rc == 0
    if not revertida:
        raise Parada("no se pudo revertir la desviacion")
    negativo("d) con la BD desviada (DELETE en denuncia), nueva-clave se niega y nombra privilegios_tabla",
             desviada.rc != 0 and "privilegios_tabla" in desviada.err and sin_cambios,
             control, f"codigo {desviada.rc}, error {desviada.err.strip()[-300:]!r}")
    creada = PATRON_ALTA.search(alta.out)
    C = creada.group(1) if creada else ""
    comando = f"nueva-clave --empresa-id {C}"
    negativo("d) un alta con la BD desviada crea la empresa, avisa de que NO tiene clave y da el comando",
             alta.rc != 0 and creada is not None and TEXTO_SIN_CLAVE in alta.err and comando in alta.err
             and claves_en_bd(C) == [],
             control, f"codigo {alta.rc}, salida {alta.out.strip()[-200:]!r}, error {alta.err.strip()[-300:]!r}")
    if C:
        r = gestion("nueva-clave", "--empresa-id", C)
        pasa(r.rc == 0 and f"empresa_id={C} version=1" in r.out and len(claves_en_bd(C)) == 1,
             "d) con la BD revertida, el comando indicado completa el alta (version 1)")

    # Si salta, se muestra lo que precede a cada coincidencia, nunca el valor.
    contextos = [repr(s[max(0, m.start() - 40):m.start()])
                 for s in salidas_gestion for m in PATRON_CLAVE_HEX.finditer(s)]
    # Control: el patrón detecta una clave falsa con el formato de las reales
    # metida en una línea como las de gestion.
    control_patron = PATRON_CLAVE_HEX.search(f"clave creada: {secrets.token_hex(32)}") is not None
    negativo(f"d) ninguna de las {len(salidas_gestion)} salidas de gestion contiene 64 hexadecimales seguidos",
             not contextos and len(salidas_gestion) >= 8, control_patron)
    for contexto in contextos:
        p(f"   coincidencia precedida de {contexto} (valor omitido)")


# ---------------------------------------------------------------------------
# Peticiones HTTP
# ---------------------------------------------------------------------------
def http(peticiones, red="app", ip=None):
    """Ejecuta las peticiones con el cliente de prueba y devuelve sus respuestas.

    ip fija la dirección del cliente (fuera del rango automático de la red),
    para que el limitador vea siempre el mismo cliente.
    """
    fija = ["--ip", ip] if ip else []
    r = ejecutar(["docker", "run", "--rm", "-i", "--network", f"{PROYECTO}_{red}", *fija, "--read-only",
                  "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                  "--entrypoint", "python", IMAGEN_API, "-c", CLIENTE_HTTP],
                 entrada=json.dumps(peticiones).encode("utf-8"))
    try:
        respuestas = json.loads(r.out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise Parada(f"el cliente HTTP no devolvio resultado: {r.err.strip()[-400:]!r}") from None
    for respuesta in respuestas:
        if "cuerpo" in respuesta:
            respuesta["cuerpo"] = base64.b64decode(respuesta["cuerpo"])
    return respuestas


def pt(metodo, ruta, datos=None, crudo=None, tipo="application/json", cabeceras=None, **extra):
    """Una petición para el cliente de prueba, directa a la API."""
    todas = {} if tipo is None else {"Content-Type": tipo}
    todas.update(cabeceras or {})
    if crudo is None and datos is not None:
        crudo = json.dumps(datos, ensure_ascii=False).encode("utf-8")
    peticion = {"host": "api", "puerto": 8000, "metodo": metodo, "ruta": ruta, "cabeceras": todas, **extra}
    if crudo is not None:
        peticion["cuerpo"] = base64.b64encode(crudo).decode("ascii")
    return peticion


def por_caddy(peticion):
    return {**peticion, "host": "caddy", "puerto": 8443, "tls": True}


def ruta_denuncias(identificador):
    return f"/v1/empresas/{identificador}/denuncias"


def seguimiento(codigo):
    return pt("POST", "/v1/seguimiento", {"codigo": codigo})


def json_de(respuesta):
    try:
        return json.loads(respuesta["cuerpo"].decode("utf-8"))
    except (KeyError, ValueError, UnicodeDecodeError):
        return None


def dia_en(zona):
    """El día de hoy en una zona, según PostgreSQL (zona escrita como literal)."""
    return sup(f"select (now() at time zone '{zona}')::date;").out.strip()


def lineas_log(servicio):
    return dc("logs", "--no-color", "--no-log-prefix", servicio).todo.splitlines()


def hmac_de(codigo):
    """HMAC del código con la clave falsa de esta ejecución y la fórmula del
    modelo de amenazas (6.1), escrita aquí: HMAC-SHA256(clave, etiqueta ||
    bytes del código)."""
    crudo = base64.b32decode(codigo.replace("-", ""))
    return hmac.new(bytes.fromhex(CLAVES_FALSAS["clave_hmac_codigos"]),
                    ETIQUETA_SEGUIMIENTO.encode("ascii") + crudo, hashlib.sha256).hexdigest()


def denuncia_de(codigo):
    """id de la denuncia de un código, buscado como superusuario por su HMAC."""
    r = sup(f"select denuncia_id from canal.busqueda_seguimiento where codigo_hmac = '\\x{hmac_de(codigo)}';")
    return r.out.strip()


def nuevo_mensaje(codigo, texto):
    return pt("POST", "/v1/seguimiento/mensajes", {"codigo": codigo, "texto": texto})


def mensajes_en_bd(denuncia_id):
    return sup(f"select count(*) from canal.mensaje where denuncia_id = '{denuncia_id}';").out.strip()


def retener_y_enviar(sentencia, final, codigo, texto, pausa_tras_ver=0):
    """Retiene la fila de una denuncia en una transacción del superusuario y,
    mientras tanto, envía un mensaje por la API.

    La transacción ejecuta `sentencia` (que bloquea la fila), espera a que la
    API quede esperando un bloqueo, opcionalmente duerme `pausa_tras_ver`
    segundos y termina con `final` (COMMIT o ROLLBACK). Devuelve la respuesta
    de la API y si se vio a la API esperando (el control de que hubo
    contención de verdad). pg_stat_clear_snapshot(): dentro de una
    transacción, pg_stat_activity se lee una vez y se cachea.
    """
    api_esperando = ("EXISTS (SELECT 1 FROM pg_stat_activity WHERE application_name = 'canario-api' "
                     "AND wait_event_type = 'Lock')")
    sql = ("SET application_name = 'prueba_retencion';\nBEGIN;\n"
           f"{sentencia}\n"
           "DO $$ BEGIN FOR i IN 1..300 LOOP PERFORM pg_stat_clear_snapshot(); "
           f"EXIT WHEN {api_esperando}; PERFORM pg_sleep(0.1); END LOOP; END $$;\n"
           "SELECT pg_stat_clear_snapshot();\n"
           f"SELECT 'visto|' || ({api_esperando})::text;\n"
           + (f"SELECT pg_sleep({pausa_tras_ver});\n" if pausa_tras_ver else "")
           + f"{final};\n")

    def en_pausa():
        return sup("select count(*) from pg_stat_activity where application_name = 'prueba_retencion' "
                   "and wait_event = 'PgSleep';").out.strip() == "1"
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        futuro = pool.submit(sup, sql)
        respuesta = http([nuevo_mensaje(codigo, texto)])[0] if esperar(en_pausa, 30) else None
        retencion = futuro.result()
    if respuesta is None or retencion.rc != 0:
        raise Parada(f"no se pudo retener la denuncia: {retencion.err.strip()[:300]!r}")
    return respuesta, "visto|true" in retencion.out.split()


# ---------------------------------------------------------------------------
# Secciones HTTP
# ---------------------------------------------------------------------------
def seccion_f():
    p("=== f) crear denuncia")
    _, ident_a, zona_a = EMPRESAS["A"]
    _, ident_b, zona_b = EMPRESAS["B"]
    # Empresa inactiva (con clave, por gestion) y empresa sin clave (como
    # superusuario, como quedaría un alta a medias).
    r = gestion("alta-empresa", "--nombre", "Empresa inactiva", "--zona", "Europe/Madrid")
    alta = PATRON_ALTA.search(r.out)
    if r.rc != 0 or alta is None:
        raise Parada(f"no se pudo dar de alta la empresa inactiva: {r.err.strip()[-300:]!r}")
    EMPRESAS["inactiva"] = (uuid.UUID(alta.group(1)), alta.group(2), "Europe/Madrid")
    r = sup("with e as (insert into canal.empresa (nombre, zona_horaria) values ('Empresa sin clave', 'Europe/Madrid') "
            "returning id) insert into canal.directorio_empresas (empresa_id) select id from e "
            "returning identificador_publico;")
    ident_sin_clave = r.out.strip()
    if r.rc != 0 or not re.fullmatch(r"[0-9a-f]{32}", ident_sin_clave):
        raise Parada(f"no se pudo crear la empresa sin clave: {r.err.strip()[:300]!r}")
    EMPRESAS["sin_clave"] = (None, ident_sin_clave, "Europe/Madrid")

    for nombre in ("A", "A2", "B", "inactiva", "utf", "limite", "422"):
        MARCADORES[nombre] = f"marcador-{nombre}-{secrets.token_hex(8)}"
    # Se guarda tal cual: tildes, eñe, un emoji y un control bidireccional
    # (U+202E). Escaparlo al mostrarlo es tarea del cliente. El control se
    # construye con chr() y no se escribe en el fuente: un carácter bidi
    # literal en el código es justo lo que permite el ataque Trojan Source.
    MARCADORES["utf"] = ("ñandú, acción y " + chr(0x1F600) + " con un control bidi " + chr(0x202E)
                         + " al final " + MARCADORES["utf"])
    MARCADORES["limite"] += "x" * (LONGITUD_MAXIMA_TEXTO - len(MARCADORES["limite"]))
    validas = {
        "A": (ident_a, "acoso", "application/json"),
        "A2": (ident_a, "otros", "application/json"),
        "B": (ident_b, "fraude", "application/json"),
        "inactiva": (EMPRESAS["inactiva"][1], "corrupcion", "application/json"),
        "utf": (ident_a, "proteccion_datos", "application/json; charset=utf-8"),
        "limite": (ident_a, "seguridad_laboral", "application/json"),
    }
    peticiones = [pt("POST", ruta_denuncias(ident), {"categoria": cat, "texto": MARCADORES[nombre]}, tipo=tipo)
                  for nombre, (ident, cat, tipo) in validas.items()]
    respuestas = dict(zip(validas, http(peticiones)))
    dias = {zona_a: dia_en(zona_a), zona_b: dia_en(zona_b)}
    for nombre, respuesta in respuestas.items():
        cuerpo = json_de(respuesta)
        ok = (respuesta.get("estado") == 201 and isinstance(cuerpo, dict) and sorted(cuerpo) == CLAVES_RESPUESTA_CREAR
              and re.fullmatch(PATRON_CODIGO, cuerpo.get("codigo_seguimiento", "")) is not None)
        if ok:
            CODIGOS[nombre] = cuerpo["codigo_seguimiento"]
        zona = zona_b if nombre == "B" else zona_a
        pasa(ok and cuerpo["fecha"] == dias[zona],
             f"f) {nombre}: 201 solo con codigo_seguimiento (8 grupos de 4) y fecha, que es la de hoy en {zona} "
             f"({respuesta.get('estado')}, {cuerpo.get('fecha') if isinstance(cuerpo, dict) else None})")
    control = len(CODIGOS) == len(validas)
    pasa(len(set(CODIGOS.values())) == len(CODIGOS), "f) cada denuncia recibe un codigo distinto")
    pasa("limite" in CODIGOS, f"f) un texto de exactamente {LONGITUD_MAXIMA_TEXTO} caracteres se acepta")
    for etiqueta in ("A", "B"):
        empresa, _, zona = EMPRESAS[etiqueta]
        r = sup(f"select distinct fecha::text from canal.denuncia where empresa_id = '{empresa}';")
        pasa(r.out.split() == [dias[zona]], f"f) en la BD, las denuncias de {etiqueta} tienen la fecha de {zona} "
                                            f"({r.out.split()})")
    sup(f"update canal.empresa set activa = false where id = '{EMPRESAS['inactiva'][0]}';")

    # Mismo 404, byte a byte, para todo lo que no es una empresa activa.
    casos = {"desconocida": secrets.token_hex(16), "de un caracter": "x", "en mayusculas": ident_a.upper(),
             "de 33 caracteres": ident_a + "0", "con caracteres de ruta": "..%2F..", "inactiva": EMPRESAS["inactiva"][1]}
    antes = sup("select count(*) from canal.denuncia;").out.strip()
    respuestas = http([pt("POST", ruta_denuncias(i), {"categoria": "acoso", "texto": "hola"}) for i in casos.values()])
    despues = sup("select count(*) from canal.denuncia;").out.strip()
    for nombre, respuesta in zip(casos, respuestas):
        negativo(f"f) empresa {nombre}: 404 con el cuerpo exacto",
                 respuesta.get("estado") == 404 and respuesta.get("cuerpo") == CUERPO_404_EMPRESA, control,
                 f"respuesta: {respuesta}")
    negativo(f"f) ninguna de esas peticiones crea una denuncia ({antes} -> {despues})", antes == despues, control)

    # Empresa sin clave: 503 y un evento en el log sin identificar la empresa.
    antes = len(lineas_log("api"))
    respuesta = http([pt("POST", ruta_denuncias(ident_sin_clave), {"categoria": "acoso", "texto": "hola"})])[0]
    nuevas = lineas_log("api")[antes:]
    negativo("f) empresa sin clave: 503 con el cuerpo exacto",
             respuesta.get("estado") == 503 and respuesta.get("cuerpo") == CUERPO_503, control, f"respuesta: {respuesta}")
    negativo(f"f) el 503 registra {TEXTO_EVENTO_SIN_CLAVE!r} sin el identificador ni el uuid de la empresa",
             any(TEXTO_EVENTO_SIN_CLAVE in l for l in nuevas)
             and not any(ident_sin_clave in l for l in nuevas), control, f"lineas nuevas: {nuevas}")

    # 422 uniforme y sin eco: el marcador va en el campo que falla.
    m = MARCADORES["422"]
    valido = json.dumps({"categoria": "acoso", "texto": m}).encode("utf-8")
    invalidas = {
        "categoria fuera de la lista": pt("POST", ruta_denuncias(ident_a), {"categoria": m, "texto": "hola"}),
        "categoria en mayusculas": pt("POST", ruta_denuncias(ident_a), {"categoria": "ACOSO", "texto": m}),
        "campo extra": pt("POST", ruta_denuncias(ident_a), {"categoria": "acoso", "texto": "hola", "extra": m}),
        "texto vacio": pt("POST", ruta_denuncias(ident_a), {"categoria": "acoso", "texto": ""}),
        "texto solo de espacios": pt("POST", ruta_denuncias(ident_a), {"categoria": "acoso", "texto": "   "}),
        f"texto de {LONGITUD_MAXIMA_TEXTO + 1} caracteres": pt(
            "POST", ruta_denuncias(ident_a),
            {"categoria": "acoso", "texto": m + "x" * (LONGITUD_MAXIMA_TEXTO + 1 - len(m))}),
        "texto numerico": pt("POST", ruta_denuncias(ident_a), {"categoria": "acoso", "texto": 12345}),
        "sin texto": pt("POST", ruta_denuncias(ident_a), {"categoria": "acoso"}),
        "JSON invalido": pt("POST", ruta_denuncias(ident_a), crudo=b'{"categoria": "acoso", "texto": "' + m.encode()),
        "Content-Type text/plain": pt("POST", ruta_denuncias(ident_a), crudo=valido, tipo="text/plain"),
        "sin Content-Type": pt("POST", ruta_denuncias(ident_a), crudo=valido, tipo=None),
    }
    antes = sup("select count(*) from canal.denuncia;").out.strip()
    respuestas = http(list(invalidas.values()))
    despues = sup("select count(*) from canal.denuncia;").out.strip()
    for nombre, respuesta in zip(invalidas, respuestas):
        negativo(f"f) {nombre}: 422 con el cuerpo exacto, sin devolver lo enviado",
                 respuesta.get("estado") == 422 and respuesta.get("cuerpo") == CUERPO_422, control,
                 f"respuesta: {respuesta}")
    negativo(f"f) ninguna peticion invalida crea una denuncia ({antes} -> {despues})", antes == despues, control)


def seccion_g():
    p("=== g) seguimiento")
    if not {"A", "B", "utf", "limite", "inactiva"} <= set(CODIGOS):
        sinc("g) faltan codigos de f): no se puede probar el seguimiento")
        return
    _, _, zona_a = EMPRESAS["A"]
    _, _, zona_b = EMPRESAS["B"]
    codigo_a = CODIGOS["A"]
    peticiones = {
        "A": seguimiento(codigo_a),
        "A en minusculas y sin guiones": seguimiento(codigo_a.replace("-", "").lower()),
        "A con espacios": seguimiento(codigo_a.replace("-", " ")),
        "B": seguimiento(CODIGOS["B"]),
        "utf": seguimiento(CODIGOS["utf"]),
        "limite": seguimiento(CODIGOS["limite"]),
        "inactiva": seguimiento(CODIGOS["inactiva"]),
    }
    respuestas = dict(zip(peticiones, http(list(peticiones.values()))))
    esperados = {
        "A": {"estado": "nueva", "fecha": dia_en(zona_a), "categoria": "acoso", "texto": MARCADORES["A"], "mensajes": []},
        "B": {"estado": "nueva", "fecha": dia_en(zona_b), "categoria": "fraude", "texto": MARCADORES["B"], "mensajes": []},
        "utf": {"estado": "nueva", "fecha": dia_en(zona_a), "categoria": "proteccion_datos", "texto": MARCADORES["utf"],
                "mensajes": []},
        "limite": {"estado": "nueva", "fecha": dia_en(zona_a), "categoria": "seguridad_laboral",
                   "texto": MARCADORES["limite"], "mensajes": []},
        "inactiva": {"estado": "nueva", "fecha": dia_en("Europe/Madrid"), "categoria": "corrupcion",
                     "texto": MARCADORES["inactiva"], "mensajes": []},
    }
    for nombre, esperado in esperados.items():
        respuesta = respuestas[nombre]
        pasa(respuesta.get("estado") == 200 and json_de(respuesta) == esperado,
             f"g) {nombre}: 200 con estado, fecha, categoria, texto exacto y mensajes vacios")
    control = respuestas["A"].get("estado") == 200 and json_de(respuestas["A"]) == esperados["A"]
    pasa(sorted(json_de(respuestas["A"]) or {}) == CLAVES_RESPUESTA_SEGUIMIENTO,
         "g) la respuesta no lleva ningun campo mas (ni el id interno de la denuncia)")
    for nombre in ("A en minusculas y sin guiones", "A con espacios"):
        negativo(f"g) {nombre}: la misma respuesta que con el codigo tal como se mostro",
                 respuestas[nombre].get("cuerpo") == respuestas["A"].get("cuerpo"), control)
    negativo("g) una empresa desactivada no acepta denuncias (f) pero su seguimiento sigue funcionando",
             respuestas["inactiva"].get("estado") == 200, control)

    # Mismo 404 para todo lo que no es un código de una denuncia.
    otro = "B" if codigo_a[0] != "B" else "C"
    aleatorio = base64.b32encode(secrets.token_bytes(20)).decode("ascii")
    casos = {
        "con un caracter cambiado": otro + codigo_a[1:],
        "aleatorio con formato valido": "-".join(aleatorio[i:i + 4] for i in range(0, 32, 4)),
        "vacio": "",
        "de un caracter": "x",
        "con un caracter de mas": codigo_a + "A",
        "con un cero": "0" + codigo_a[1:],
        "con un caracter no ASCII": "Á" + codigo_a[1:],
        "de 200 caracteres": "A" * 200,
    }
    respuestas = http([seguimiento(c) for c in casos.values()])
    for nombre, respuesta in zip(casos, respuestas):
        negativo(f"g) codigo {nombre}: 404 con el cuerpo exacto",
                 respuesta.get("estado") == 404 and respuesta.get("cuerpo") == CUERPO_404_CODIGO, control,
                 f"respuesta: {respuesta}")
    otros = {
        "codigo numerico": (pt("POST", "/v1/seguimiento", {"codigo": 12345}), 422, CUERPO_422),
        "campo extra": (pt("POST", "/v1/seguimiento", {"codigo": codigo_a, "extra": 1}), 422, CUERPO_422),
        "GET /v1/seguimiento": (pt("GET", "/v1/seguimiento", tipo=None), 405, CUERPO_405),
        "ruta inexistente": (pt("POST", "/v1/no-existe", {"codigo": codigo_a}), 404, CUERPO_404_RUTA),
    }
    respuestas = http([peticion for peticion, _, _ in otros.values()])
    for (nombre, (_, estado, cuerpo)), respuesta in zip(otros.items(), respuestas):
        negativo(f"g) {nombre}: {estado} con el cuerpo exacto",
                 respuesta.get("estado") == estado and respuesta.get("cuerpo") == cuerpo, control,
                 f"respuesta: {respuesta}")
    pasa("POST" in (respuestas[2].get("cabeceras") or {}).get("allow", ""),
         "g) el 405 conserva la cabecera Allow con POST")


def seccion_m():
    p("=== m) mensajes del denunciante")
    empresa_a, ident_a, zona_a = EMPRESAS["A"]
    _, ident_b, zona_b = EMPRESAS["B"]
    dia_a, dia_b = dia_en(zona_a), dia_en(zona_b)
    # Una denuncia por caso, para que ninguno dependa del estado de otro. Sus
    # códigos pasan a CODIGOS: h) y l) los buscan en el volcado y los logs.
    casos = ("M", "MB", "instruccion", "resuelta", "archivada", "tope", "carrera", "carrera_ctl", "espera",
             "personal")
    respuestas = http([pt("POST", ruta_denuncias(ident_b if c == "MB" else ident_a),
                          {"categoria": "otros", "texto": f"denuncia {c}"}) for c in casos])
    codigos = {}
    for caso, respuesta in zip(casos, respuestas):
        cuerpo = json_de(respuesta)
        if respuesta.get("estado") == 201 and isinstance(cuerpo, dict):
            codigos[caso] = cuerpo["codigo_seguimiento"]
    if len(codigos) != len(casos):
        sinc(f"m) no se pudieron crear las denuncias de prueba ({sorted(codigos)})")
        return
    CODIGOS.update({f"m_{c}": v for c, v in codigos.items()})
    ids = {c: denuncia_de(v) for c, v in codigos.items()}

    for nombre in ("m1", "m2", "m3", "mb", "m4", "personal", "422"):
        MARCADORES[f"mensaje_{nombre}"] = f"marcador-mensaje-{nombre}-{secrets.token_hex(8)}"
    # Mismos caracteres especiales que la denuncia de f), y el texto más largo
    # admitido.
    MARCADORES["mensaje_m1"] = ("ñandú, acción y " + chr(0x1F600) + " con un control bidi " + chr(0x202E)
                                + " al final " + MARCADORES["mensaje_m1"])
    MARCADORES["mensaje_m2"] += "x" * (LONGITUD_MAXIMA_TEXTO - len(MARCADORES["mensaje_m2"]))
    m = {k: MARCADORES[f"mensaje_{k}"] for k in ("m1", "m2", "m3", "mb", "m4", "personal", "422")}

    # Envío: secuencia y fecha del día en la zona de cada empresa. El tercero
    # usa una forma equivalente del código (minúsculas, sin guiones).
    codigo_m = codigos["M"]
    envios = {
        "m1": (nuevo_mensaje(codigo_m, m["m1"]), 1, dia_a),
        "m2": (nuevo_mensaje(codigo_m, m["m2"]), 2, dia_a),
        "m3": (nuevo_mensaje(codigo_m.replace("-", "").lower(), m["m3"]), 3, dia_a),
        "mb": (nuevo_mensaje(codigos["MB"], m["mb"]), 1, dia_b),
    }
    respuestas = dict(zip(envios, http([peticion for peticion, _, _ in envios.values()])))
    for nombre, (_, secuencia, dia) in envios.items():
        respuesta = respuestas[nombre]
        pasa(respuesta.get("estado") == 201 and json_de(respuesta) == {"secuencia": secuencia, "fecha": dia},
             f"m) mensaje {nombre}: 201 solo con secuencia {secuencia} y fecha {dia} "
             f"({respuesta.get('estado')}, {json_de(respuesta)})")
    control = all(respuestas[n].get("estado") == 201 for n in envios)
    pasa(control and sorted(json_de(respuestas["m1"]) or {}) == CLAVES_RESPUESTA_MENSAJE,
         "m) la respuesta del envio no lleva ningun campo mas (ni ids)")
    pasa(control, f"m) un mensaje de exactamente {LONGITUD_MAXIMA_TEXTO} caracteres se acepta")

    # Seguimiento: los textos exactos, en orden, con autor genérico.
    esperado_m = {"estado": "nueva", "fecha": dia_a, "categoria": "otros", "texto": "denuncia M", "mensajes": [
        {"secuencia": 1, "fecha": dia_a, "autor": "denunciante", "texto": m["m1"]},
        {"secuencia": 2, "fecha": dia_a, "autor": "denunciante", "texto": m["m2"]},
        {"secuencia": 3, "fecha": dia_a, "autor": "denunciante", "texto": m["m3"]},
    ]}
    esperado_mb = {"estado": "nueva", "fecha": dia_b, "categoria": "otros", "texto": "denuncia MB", "mensajes": [
        {"secuencia": 1, "fecha": dia_b, "autor": "denunciante", "texto": m["mb"]},
    ]}
    seg_m, seg_mb = http([seguimiento(codigo_m), seguimiento(codigos["MB"])])
    pasa(seg_m.get("estado") == 200 and json_de(seg_m) == esperado_m,
         "m) seguimiento de M: los 3 mensajes con su secuencia, fecha, autor y texto exacto")
    pasa(seg_mb.get("estado") == 200 and json_de(seg_mb) == esperado_mb,
         f"m) seguimiento de MB: su mensaje con la fecha de {zona_b}")
    pasa(all(sorted(x) == CLAVES_MENSAJE for x in (json_de(seg_m) or {}).get("mensajes", [{}])),
         "m) cada mensaje del seguimiento lleva solo secuencia, fecha, autor y texto")
    r = sup(f"select version_clave from canal.mensaje where denuncia_id = '{ids['M']}' order by secuencia;")
    pasa(r.out.split() == [str(VERSION_CLAVE_A)] * 3,
         f"m) los mensajes se cifran con la version mas alta de la clave de A ({r.out.split()})")

    # Mismo 404 que el seguimiento para todo lo que no es un código, sin
    # guardar nada. Control: los envíos de arriba.
    aleatorio = base64.b32encode(secrets.token_bytes(20)).decode("ascii")
    otro = "B" if codigo_m[0] != "B" else "C"
    invalidos = {
        "con un caracter cambiado": otro + codigo_m[1:],
        "aleatorio con formato valido": "-".join(aleatorio[i:i + 4] for i in range(0, 32, 4)),
        "vacio": "",
        "de 200 caracteres": "A" * 200,
    }
    antes = sup("select count(*) from canal.mensaje;").out.strip()
    respuestas = http([nuevo_mensaje(c, "hola") for c in invalidos.values()])
    despues = sup("select count(*) from canal.mensaje;").out.strip()
    for nombre, respuesta in zip(invalidos, respuestas):
        negativo(f"m) mensaje con codigo {nombre}: 404 con el cuerpo exacto del seguimiento",
                 respuesta.get("estado") == 404 and respuesta.get("cuerpo") == CUERPO_404_CODIGO, control,
                 f"respuesta: {respuesta}")
    negativo(f"m) ninguno de esos envios guarda un mensaje ({antes} -> {despues})", antes == despues, control)

    # 422 uniforme y sin eco: el marcador va en el campo que falla.
    marca = m["422"]
    valido = json.dumps({"codigo": codigo_m, "texto": marca}).encode("utf-8")
    ruta = "/v1/seguimiento/mensajes"
    invalidas = {
        "texto vacio": nuevo_mensaje(codigo_m, ""),
        "texto solo de espacios": nuevo_mensaje(codigo_m, "   "),
        f"texto de {LONGITUD_MAXIMA_TEXTO + 1} caracteres":
            nuevo_mensaje(codigo_m, marca + "x" * (LONGITUD_MAXIMA_TEXTO + 1 - len(marca))),
        "texto numerico": pt("POST", ruta, {"codigo": codigo_m, "texto": 12345}),
        "sin texto": pt("POST", ruta, {"codigo": codigo_m}),
        "codigo numerico": pt("POST", ruta, {"codigo": 12345, "texto": marca}),
        "campo extra": pt("POST", ruta, {"codigo": codigo_m, "texto": "hola", "extra": marca}),
        "JSON invalido": pt("POST", ruta, crudo=b'{"codigo": "x", "texto": "' + marca.encode()),
        "Content-Type text/plain": pt("POST", ruta, crudo=valido, tipo="text/plain"),
    }
    antes = sup("select count(*) from canal.mensaje;").out.strip()
    respuestas = http(list(invalidas.values()))
    despues = sup("select count(*) from canal.mensaje;").out.strip()
    for nombre, respuesta in zip(invalidas, respuestas):
        negativo(f"m) mensaje con {nombre}: 422 con el cuerpo exacto, sin devolver lo enviado",
                 respuesta.get("estado") == 422 and respuesta.get("cuerpo") == CUERPO_422, control,
                 f"respuesta: {respuesta}")
    negativo(f"m) ningun envio invalido guarda un mensaje ({antes} -> {despues})", antes == despues, control)

    # Estado: en instrucción acepta (control); resuelta y archivada, 409 sin
    # guardar nada. El seguimiento de una archivada sigue funcionando.
    for caso, estado_denuncia in (("instruccion", "en_instruccion"), ("resuelta", "resuelta"),
                                  ("archivada", "archivada")):
        sup(f"update canal.denuncia set estado = '{estado_denuncia}' where id = '{ids[caso]}';")
    r_instr, r_resuelta, r_archivada, seg_archivada = http([
        nuevo_mensaje(codigos["instruccion"], "hola"), nuevo_mensaje(codigos["resuelta"], "hola"),
        nuevo_mensaje(codigos["archivada"], "hola"), seguimiento(codigos["archivada"])])
    control_estado = r_instr.get("estado") == 201
    pasa(control_estado, "m) control: una denuncia en instruccion acepta mensajes")
    for nombre, respuesta in (("resuelta", r_resuelta), ("archivada", r_archivada)):
        negativo(f"m) denuncia {nombre}: 409 con el cuerpo exacto y sin guardar el mensaje",
                 respuesta.get("estado") == 409 and respuesta.get("cuerpo") == CUERPO_409_CERRADA
                 and mensajes_en_bd(ids[nombre]) == "0", control_estado, f"respuesta: {respuesta}")
    negativo("m) el seguimiento de una denuncia archivada sigue dando 200 con su estado",
             seg_archivada.get("estado") == 200 and (json_de(seg_archivada) or {}).get("estado") == "archivada",
             control_estado, f"respuesta: {seg_archivada}")

    # Tope: se rellenan 199 mensajes como superusuario (contenido falso: esta
    # denuncia no se consulta después). El 200 se acepta (control) y el 201 no.
    r = sup(f"do $$ begin for i in 1..{MAXIMO_MENSAJES - 1} loop insert into canal.mensaje "
            "(empresa_id, denuncia_id, autor, contenido_cifrado, version_clave) "
            f"values ('{empresa_a}', '{ids['tope']}', 'denunciante', '\\xdeadbeef', 1); end loop; end $$;")
    if r.rc != 0:
        raise Parada(f"no se pudo rellenar la denuncia del tope: {r.err.strip()[:300]}")
    ultimo, sobra = http([nuevo_mensaje(codigos["tope"], "el ultimo"), nuevo_mensaje(codigos["tope"], "sobra")])
    control_tope = ultimo.get("estado") == 201 and (json_de(ultimo) or {}).get("secuencia") == MAXIMO_MENSAJES
    pasa(control_tope, f"m) control: el mensaje numero {MAXIMO_MENSAJES} de una denuncia se acepta")
    negativo(f"m) el mensaje numero {MAXIMO_MENSAJES + 1}: 409 con el cuerpo exacto y la denuncia sigue con "
             f"{MAXIMO_MENSAJES}",
             sobra.get("estado") == 409 and sobra.get("cuerpo") == CUERPO_409_LIMITE
             and mensajes_en_bd(ids["tope"]) == str(MAXIMO_MENSAJES), control_tope, f"respuesta: {sobra}")

    # Carrera: el personal archiva la denuncia mientras llega un mensaje. El
    # mensaje espera a que termine y ve el estado final: con COMMIT, 409; con
    # ROLLBACK (control), 201.
    archivar = "update canal.denuncia set estado = 'archivada' where id = '{}';"
    ctl_carrera, visto_ctl = retener_y_enviar(archivar.format(ids["carrera_ctl"]), "ROLLBACK",
                                              codigos["carrera_ctl"], "llega durante un cierre que se deshace")
    control_carrera = visto_ctl and ctl_carrera.get("estado") == 201
    pasa(control_carrera, f"m) control: la API espera al cierre y, si se deshace, guarda el mensaje "
                          f"(esperando {visto_ctl}, {ctl_carrera.get('estado')})")
    carrera, visto = retener_y_enviar(archivar.format(ids["carrera"]), "COMMIT",
                                      codigos["carrera"], "llega durante el cierre")
    negativo("m) un mensaje que llega mientras se archiva la denuncia espera y recibe 409 sin guardarse",
             visto and carrera.get("estado") == 409 and carrera.get("cuerpo") == CUERPO_409_CERRADA
             and mensajes_en_bd(ids["carrera"]) == "0", control_carrera, f"respuesta: {carrera}, esperando {visto}")

    # Saturación: la fila sigue bloqueada más que lock_timeout (2 s). 503 con
    # Retry-After y un evento sin datos. Control: se vio a la API esperando.
    lineas_antes = len(lineas_log("api"))
    espera, visto = retener_y_enviar(f"select 1 from canal.denuncia where id = '{ids['espera']}' "
                                     "for no key update;", "ROLLBACK", codigos["espera"], "llega bloqueado",
                                     pausa_tras_ver=4)
    nuevas = lineas_log("api")[lineas_antes:]
    negativo("m) con la denuncia bloqueada mas que lock_timeout: 503 con el cuerpo exacto y Retry-After",
             espera.get("estado") == 503 and espera.get("cuerpo") == CUERPO_503_OCUPADO
             and (espera.get("cabeceras") or {}).get("retry-after") == REINTENTAR_TRAS
             and mensajes_en_bd(ids["espera"]) == "0", visto, f"respuesta: {espera}")
    negativo(f"m) el 503 registra solo {TEXTO_SATURACION!r}, sin ids ni codigo",
             any(TEXTO_SATURACION in l for l in nuevas)
             and not any(v in l for l in nuevas for v in (ids["espera"], codigos["espera"], empresa_a.hex,
                                                          str(empresa_a))),
             visto, f"lineas nuevas: {nuevas}")

    # Integridad: un mensaje cambiado de fila no se descifra (el AAD lleva su
    # id, su denuncia y su empresa). Control: antes y después, 200.
    def cifrado_de(denuncia_id, secuencia):
        return sup(f"select encode(contenido_cifrado, 'hex') from canal.mensaje "
                   f"where denuncia_id = '{denuncia_id}' and secuencia = {secuencia};").out.strip()

    def poner(denuncia_id, secuencia, hexadecimal):
        sup(f"update canal.mensaje set contenido_cifrado = '\\x{hexadecimal}' "
            f"where denuncia_id = '{denuncia_id}' and secuencia = {secuencia};")
    originales = {1: cifrado_de(ids["M"], 1), 2: cifrado_de(ids["M"], 2), 3: cifrado_de(ids["M"], 3)}
    del_b = cifrado_de(ids["MB"], 1)
    control_integridad = all(originales.values()) and bool(del_b) and http([seguimiento(codigo_m)])[0].get("estado") == 200
    lineas_antes = len(lineas_log("api"))
    poner(ids["M"], 1, originales[2])
    poner(ids["M"], 2, originales[1])
    try:
        intercambiados = http([seguimiento(codigo_m)])[0]
    finally:
        poner(ids["M"], 1, originales[1])
        poner(ids["M"], 2, originales[2])
    poner(ids["M"], 3, del_b)
    try:
        de_otra_empresa = http([seguimiento(codigo_m)])[0]
    finally:
        poner(ids["M"], 3, originales[3])
    nuevas = lineas_log("api")[lineas_antes:]
    for nombre, respuesta in (("intercambiado con otro de la misma denuncia", intercambiados),
                              ("de una denuncia de otra empresa", de_otra_empresa)):
        negativo(f"m) con el cifrado de un mensaje {nombre}: 500 generico",
                 respuesta.get("estado") == 500 and respuesta.get("cuerpo") == CUERPO_500, control_integridad,
                 f"respuesta: {respuesta}")
    negativo(f"m) queda un evento {TEXTO_INTEGRIDAD!r} sin ids, codigo ni texto",
             any(TEXTO_INTEGRIDAD in l for l in nuevas)
             and not any(v in l for l in nuevas for v in (ids["M"], codigo_m, m["m1"], m["m3"])),
             control_integridad, f"lineas nuevas: {nuevas}")
    restaurado = http([seguimiento(codigo_m)])[0]
    pasa(restaurado.get("estado") == 200 and json_de(restaurado) == esperado_m,
         "m) al restaurar los cifrados, M vuelve a dar 200 con sus mensajes")

    # Rotación: tras nueva-clave, el mensaje nuevo usa la versión nueva y el
    # seguimiento lee los antiguos con la suya.
    r = gestion("nueva-clave", "--empresa-id", str(empresa_a))
    if r.rc != 0 or f"version={VERSION_CLAVE_A_ROTADA}" not in r.out:
        raise Parada(f"no se pudo rotar la clave de A: {r.err.strip()[-300:]!r}")
    enviado, seg_rotado = http([nuevo_mensaje(codigo_m, m["m4"]), seguimiento(codigo_m)])
    versiones = sup(f"select version_clave from canal.mensaje where denuncia_id = '{ids['M']}' "
                    "order by secuencia;").out.split()
    pasa(enviado.get("estado") == 201 and versiones == [str(VERSION_CLAVE_A)] * 3 + [str(VERSION_CLAVE_A_ROTADA)],
         f"m) tras rotar, el mensaje nuevo usa la version {VERSION_CLAVE_A_ROTADA} y los antiguos "
         f"conservan la {VERSION_CLAVE_A} ({versiones})")
    esperado_rotado = {**esperado_m, "mensajes": esperado_m["mensajes"] + [
        {"secuencia": 4, "fecha": dia_a, "autor": "denunciante", "texto": m["m4"]}]}
    pasa(seg_rotado.get("estado") == 200 and json_de(seg_rotado) == esperado_rotado,
         "m) el seguimiento descifra los mensajes de las dos versiones de la clave")

    # Mensajes del personal: autor "personal" y nunca quién. Se inserta uno
    # como lo haría el personal, con un usuario de A, y luego el denunciante
    # responde.
    r = sup(f"insert into canal.usuario_personal (empresa_id, email, hash_contrasena, rol) "
            f"values ('{empresa_a}', 'instructora@ejemplo.test', 'x', 'instructor') returning id;")
    autor_id = r.out.strip()
    if r.rc != 0 or not autor_id:
        raise Parada(f"no se pudo crear el usuario del personal: {r.err.strip()[:300]}")
    r = dc("exec", "-T", "api", "python", "-c", MENSAJE_PERSONAL, str(empresa_a), ids["personal"], autor_id,
           m["personal"])
    if r.rc != 0 or "insertado" not in r.out:
        raise Parada(f"no se pudo insertar el mensaje del personal: {r.err.strip()[-300:]!r}")
    respuesta, seg_personal = http([nuevo_mensaje(codigos["personal"], "respuesta del denunciante"),
                                    seguimiento(codigos["personal"])])
    esperado_personal = [
        {"secuencia": 1, "fecha": dia_a, "autor": "personal", "texto": m["personal"]},
        {"secuencia": 2, "fecha": dia_a, "autor": "denunciante", "texto": "respuesta del denunciante"},
    ]
    control_personal = (respuesta.get("estado") == 201 and seg_personal.get("estado") == 200
                        and (json_de(seg_personal) or {}).get("mensajes") == esperado_personal)
    pasa(control_personal, "m) el seguimiento muestra el mensaje del personal y la respuesta, en orden y con su autor")
    ids_mensajes = sup(f"select id from canal.mensaje where denuncia_id = '{ids['personal']}';").out.split()
    cuerpo = (seg_personal.get("cuerpo") or b"").decode("utf-8", "replace")
    filtrados = [n for n, v in [("autor_id", autor_id), ("autor_id sin guiones", autor_id.replace("-", "")),
                                ("id de la denuncia", ids["personal"])] + [("id de un mensaje", i) for i in ids_mensajes]
                 if v in cuerpo]
    negativo(f"m) la respuesta no contiene autor_id ni ningun id interno {filtrados if filtrados else ''}".strip(),
             not filtrados and len(ids_mensajes) == 2, control_personal)


def seccion_h():
    p("=== h) volcado de la base de datos")
    r = dc("exec", "-T", "postgres", "pg_dump", "-U", "postgres", "-d", "canario", "--data-only")
    volcado = r.out
    hmacs = sup("select encode(codigo_hmac, 'hex') from canal.busqueda_seguimiento;").out.split()
    # Control: el volcado tiene los datos (los HMAC de los códigos) y el HMAC
    # de cada código es el de la fórmula del modelo de amenazas.
    control = (r.rc == 0 and len(hmacs) == len(CODIGOS) and all(h in volcado for h in hmacs)
               and sorted(hmac_de(c) for c in CODIGOS.values()) == sorted(hmacs))
    pasa(control, f"h) control: el volcado contiene los {len(hmacs)} HMAC, y cada uno es "
                  "HMAC-SHA256(clave, etiqueta || codigo)")
    buscadas = {f"texto de {n}": MARCADORES[n] for n in ("A", "A2", "B", "inactiva", "utf", "limite")}
    # Los mensajes guardados en m) (el de 422 nunca se guardó).
    buscadas.update({f"texto del {n}": v for n, v in MARCADORES.items()
                     if n.startswith("mensaje_") and n != "mensaje_422"})
    buscadas.update({f"codigo de {n}": c for n, c in CODIGOS.items()})
    buscadas.update({f"codigo de {n} sin guiones": c.replace("-", "") for n, c in CODIGOS.items()})
    buscadas.update({f"categoria {c}": c for c in ("acoso", "fraude", "corrupcion", "proteccion_datos",
                                                  "seguridad_laboral", "otros")})
    buscadas["campo \"categoria\""] = '"categoria"'
    encontradas = sorted(n for n, valor in buscadas.items() if valor in volcado)
    negativo(f"h) el volcado no contiene en claro ningun texto, codigo ni categoria ({len(buscadas)} buscados) "
             f"{encontradas if encontradas else ''}".strip(), not encontradas, control)


def seccion_i():
    p("=== i) integridad: cifrados cambiados de sitio")
    if not {"A", "A2", "B"} <= set(CODIGOS):
        sinc("i) faltan codigos de f)")
        return
    id_a, id_a2, id_b = denuncia_de(CODIGOS["A"]), denuncia_de(CODIGOS["A2"]), denuncia_de(CODIGOS["B"])
    antes = http([seguimiento(CODIGOS["A"]), seguimiento(CODIGOS["A2"])])
    control = all(x.get("estado") == 200 for x in antes) and all((id_a, id_a2, id_b))
    pasa(control, "i) control: antes de tocar nada, A y A2 se consultan con 200")
    intercambio = (f"with a as (select contenido_cifrado c from canal.denuncia where id = '{id_a}'), "
                   f"b as (select contenido_cifrado c from canal.denuncia where id = '{id_a2}') "
                   "update canal.denuncia set contenido_cifrado = case when id = "
                   f"'{id_a}' then (select c from b) else (select c from a) end where id in ('{id_a}', '{id_a2}');")
    lineas_antes = len(lineas_log("api"))
    sup(intercambio)
    try:
        cambiada = http([seguimiento(CODIGOS["A"])])[0]
    finally:
        sup(intercambio)
    nuevas = lineas_log("api")[lineas_antes:]
    negativo("i) con el cifrado de otra denuncia de la misma empresa: 500 generico",
             cambiada.get("estado") == 500 and cambiada.get("cuerpo") == CUERPO_500, control, f"respuesta: {cambiada}")
    negativo(f"i) queda un evento {TEXTO_INTEGRIDAD!r} sin ids, codigo ni texto",
             any(TEXTO_INTEGRIDAD in l for l in nuevas)
             and not any(v in l for l in nuevas for v in (id_a, id_a2, CODIGOS["A"], MARCADORES["A"])),
             control, f"lineas nuevas: {nuevas}")
    original = sup(f"select encode(contenido_cifrado, 'hex') from canal.denuncia where id = '{id_a2}';").out.strip()
    sup(f"update canal.denuncia set contenido_cifrado = (select contenido_cifrado from canal.denuncia "
        f"where id = '{id_b}') where id = '{id_a2}';")
    try:
        ajena = http([seguimiento(CODIGOS["A2"])])[0]
    finally:
        sup(f"update canal.denuncia set contenido_cifrado = '\\x{original}' where id = '{id_a2}';")
    negativo("i) con el cifrado de una denuncia de otra empresa: 500 generico",
             ajena.get("estado") == 500 and ajena.get("cuerpo") == CUERPO_500, control, f"respuesta: {ajena}")
    despues = http([seguimiento(CODIGOS["A"]), seguimiento(CODIGOS["A2"])])
    pasa(all(x.get("estado") == 200 for x in despues), "i) al restaurar los cifrados, A y A2 vuelven a dar 200")


def seccion_j():
    p("=== j) errores no previstos: 500 generico y log sin detalles")
    if "A" not in CODIGOS:
        sinc("j) falta el codigo de A")
        return
    lineas_antes = len(lineas_log("api"))
    revocado = sup("REVOKE SELECT ON canal.denuncia FROM aplicacion;").rc == 0
    try:
        respuesta = http([seguimiento(CODIGOS["A"])])[0]
    finally:
        restaurado = sup("GRANT SELECT ON canal.denuncia TO aplicacion;").rc == 0
    nuevas = lineas_log("api")[lineas_antes:]
    control = revocado and restaurado
    negativo("j) sin permiso de lectura (error de la BD no previsto): 500 con el cuerpo exacto",
             respuesta.get("estado") == 500 and respuesta.get("cuerpo") == CUERPO_500, control, f"respuesta: {respuesta}")
    negativo(f"j) el log registra solo {TEXTO_ERROR_INTERNO!r}: sin mensaje, sin traceback y sin tabla",
             any(TEXTO_ERROR_INTERNO in l for l in nuevas)
             and not any(t in l for l in nuevas for t in ("permission denied", "Traceback", "canal.denuncia",
                                                           "Exception in ASGI")),
             control, f"lineas nuevas: {nuevas}")
    pasa(http([seguimiento(CODIGOS["A"])])[0].get("estado") == 200, "j) con el permiso restaurado vuelve a dar 200")


def seccion_k():
    p("=== k) limite de cuerpo: en la API y en Caddy")
    _, ident_a, _ = EMPRESAS["A"]
    prefijo = json.dumps({"categoria": "otros", "texto": "prueba del limite de cuerpo"})
    base = pt("POST", ruta_denuncias(ident_a))
    casos = {
        "justo en el limite": ({**base, "prefijo": prefijo, "tamano": LIMITE_CUERPO}, 201),
        "un byte por encima": ({**base, "prefijo": prefijo, "tamano": LIMITE_CUERPO + 1}, 413),
        "por trozos, justo en el limite": ({**base, "prefijo": prefijo, "tamano": LIMITE_CUERPO, "trozos": True}, 201),
        "por trozos, un byte por encima (sin Content-Length)":
            ({**base, "prefijo": prefijo, "tamano": LIMITE_CUERPO + 1, "trozos": True}, 413),
        "Content-Length declarado por encima": (
            pt("POST", ruta_denuncias(ident_a), crudo=b"{}", cabeceras={"Content-Length": str(LIMITE_CUERPO + 1)}), 413),
    }
    respuestas = dict(zip(casos, http([peticion for peticion, _ in casos.values()])))
    control = all(respuestas[n].get("estado") == 201 for n in ("justo en el limite", "por trozos, justo en el limite"))
    pasa(control, "k) control: directo a la API, un cuerpo de exactamente 128 KiB se acepta (entero y por trozos)")
    for nombre, (_, estado) in casos.items():
        if estado == 413:
            negativo(f"k) directo a la API, {nombre}: 413 de la propia API",
                     respuestas[nombre].get("estado") == 413 and respuestas[nombre].get("cuerpo") == CUERPO_413,
                     control, f"respuesta: {respuestas[nombre]}")
    # A través de Caddy: el 413 lo da Caddy, sin contactar con la API. Una
    # respuesta que pasa por la API lleva "Via: 1.1 Caddy"; una que genera
    # Caddy, no. Todas llevan las cabeceras de seguridad y ninguna "Server".
    casos = {
        "justo en el limite": por_caddy({**base, "prefijo": prefijo, "tamano": LIMITE_CUERPO}),
        "un byte por encima": por_caddy({**base, "prefijo": prefijo, "tamano": LIMITE_CUERPO + 1}),
        "por trozos, un byte por encima": por_caddy({**base, "prefijo": prefijo, "tamano": LIMITE_CUERPO + 1,
                                                     "trozos": True}),
    }
    respuestas = dict(zip(casos, http(list(casos.values()), red="edge")))
    aceptada = respuestas["justo en el limite"]
    control = aceptada.get("estado") == 201 and "via" in (aceptada.get("cabeceras") or {})
    pasa(control, f"k) control: a traves de Caddy, 128 KiB se aceptan y pasan por la API "
                  f"({aceptada.get('estado')}, Via: {(aceptada.get('cabeceras') or {}).get('via')})")
    for nombre in ("un byte por encima", "por trozos, un byte por encima"):
        respuesta = respuestas[nombre]
        cabeceras = respuesta.get("cabeceras") or {}
        negativo(f"k) a traves de Caddy, {nombre}: 413 de Caddy (sin Via: no llega a la API) con su JSON",
                 respuesta.get("estado") == 413 and "via" not in cabeceras
                 and respuesta.get("cuerpo") == CUERPO_413_CADDY, control, f"respuesta: {respuesta}")
        faltan = {k: v for k, v in CABECERAS_SEGURIDAD.items() if cabeceras.get(k) != v}
        negativo(f"k) el 413 de Caddy ({nombre}) lleva las cabeceras de seguridad, JSON y ninguna Server "
                 f"{faltan if faltan else ''}".strip(),
                 not faltan and "server" not in cabeceras and cabeceras.get("content-type") == "application/json",
                 control, f"cabeceras: {cabeceras}")
    faltan = {k: v for k, v in CABECERAS_SEGURIDAD.items() if (aceptada.get("cabeceras") or {}).get(k) != v}
    pasa(not faltan and "server" not in (aceptada.get("cabeceras") or {}),
         "k) la respuesta normal a traves de Caddy lleva las mismas cabeceras y ninguna Server")

    # Subida lenta (slowloris): la mitad del cuerpo, una pausa y el resto.
    # Control: con una pausa corta se acepta; con una pausa mayor que read_body
    # la petición no se acepta y no crea ninguna denuncia.
    lento = {**base, "host": "caddy", "puerto": 8443, "prefijo": json.dumps({"categoria": "otros", "texto": "lento"})}
    antes = sup("select count(*) from canal.denuncia;").out.strip()
    corta, larga = http([{**lento, "pausa": 2}, {**lento, "pausa": PLAZO_CUERPO_CADDY + 5}], red="edge")
    despues = sup("select count(*) from canal.denuncia;").out.strip()
    p(f"   subida lenta: pausa 2 s -> {corta}; pausa {PLAZO_CUERPO_CADDY + 5} s -> {larga}")
    control_lento = corta.get("estado") == 201
    pasa(control_lento, "k) control: una subida con una pausa de 2 s se acepta")
    negativo(f"k) una subida parada mas de read_body ({PLAZO_CUERPO_CADDY} s) se corta sin crear denuncia",
             larga.get("estado") != 201 and int(despues) == int(antes) + 1, control_lento,
             f"antes {antes}, despues {despues}")

    # Host distinto de localhost: 421 del sitio por defecto, por las rutas, con
    # las cabeceras de seguridad y el JSON. Control: con el Host correcto, 200.
    respuestas = http([por_caddy(pt("GET", "/salud", tipo=None)),
                       por_caddy(pt("GET", "/salud", tipo=None, cabeceras={"Host": "otro.ejemplo"}))], red="edge")
    control = respuestas[0].get("estado") == 200
    respuesta = respuestas[1]
    cabeceras = respuesta.get("cabeceras") or {}
    faltan = {k: v for k, v in CABECERAS_SEGURIDAD.items() if cabeceras.get(k) != v}
    negativo(f"k) Host distinto de localhost: 421 con su JSON, las cabeceras de seguridad y ninguna Server "
             f"{faltan if faltan else ''}".strip(),
             respuesta.get("estado") == 421 and respuesta.get("cuerpo") == CUERPO_421_CADDY and not faltan
             and "server" not in cabeceras, control, f"respuesta: {respuesta}")

    # API caída: el 502 que genera Caddy también lleva cabeceras y JSON.
    control = http([por_caddy(pt("GET", "/salud", tipo=None))], red="edge")[0].get("estado") == 200
    dc("stop", "api")
    try:
        respuesta = http([por_caddy(pt("GET", "/salud", tipo=None))], red="edge")[0]
    finally:
        dc("start", "api")
        if not esperar(lambda: salud(contenedor("api")) == "healthy", 90):
            raise Parada("la API no vuelve a estar healthy tras pararla")
    cabeceras = respuesta.get("cabeceras") or {}
    faltan = {k: v for k, v in CABECERAS_SEGURIDAD.items() if cabeceras.get(k) != v}
    negativo(f"k) con la API parada, Caddy responde 502 con su JSON, las cabeceras de seguridad y ninguna Server "
             f"{faltan if faltan else ''}".strip(),
             respuesta.get("estado") == 502 and respuesta.get("cuerpo") == CUERPO_502_CADDY and not faltan
             and "server" not in cabeceras, control, f"respuesta: {respuesta}")


def seccion_l():
    p("=== l) logs del camino anonimo")
    if not {"A", "B", "m_archivada"} <= set(CODIGOS):
        sinc("l) faltan codigos de f) o de m)")
        return
    _, ident_a, _ = EMPRESAS["A"]
    # Crear, consultar, enviar un mensaje, un 404, un 409 y un 422 son el uso
    # normal: no deben dejar ninguna línea, porque cada línea lleva la hora.
    # Control: un caso que sí se registra (empresa sin clave) añade una línea
    # en el mismo log.
    antes = len(lineas_log("api"))
    respuestas = http([
        pt("POST", ruta_denuncias(ident_a), {"categoria": "acoso", "texto": "uso normal"}),
        seguimiento(CODIGOS["A"]),
        seguimiento(CODIGOS["B"]),
        nuevo_mensaje(CODIGOS["A"], "mensaje de uso normal"),
        pt("POST", ruta_denuncias(secrets.token_hex(16)), {"categoria": "acoso", "texto": "hola"}),
        seguimiento("x"),
        nuevo_mensaje(CODIGOS["m_archivada"], "a una denuncia archivada"),
        pt("POST", ruta_denuncias(ident_a), {"categoria": "no", "texto": "hola"}),
    ])
    nuevas = lineas_log("api")[antes:]
    previas = len(lineas_log("api"))
    http([pt("POST", ruta_denuncias(EMPRESAS["sin_clave"][1]), {"categoria": "acoso", "texto": "hola"})])
    control = (len(lineas_log("api")) > previas
               and [x.get("estado") for x in respuestas] == [201, 200, 200, 201, 404, 404, 409, 422])
    negativo(f"l) crear, consultar, enviar un mensaje, 404, 409 y 422 no dejan ninguna linea en el log de la API "
             f"({len(nuevas)} nuevas)", nuevas == [], control, f"lineas nuevas: {nuevas}")

    # Textos y códigos en los logs de la API, PostgreSQL y Caddy. Control: un
    # marcador escrito a propósito en el log de la API se encuentra.
    def textos():
        return {s: dc("logs", "--no-color", "--no-log-prefix", s).todo for s in ("api", "postgres", "caddy")}
    buscadas = {f"texto de {n}": MARCADORES[n] for n in ("A", "A2", "B", "inactiva", "utf", "422")}
    buscadas.update({f"texto del {n}": v for n, v in MARCADORES.items() if n.startswith("mensaje_")})
    buscadas.update({f"codigo de {n}": c for n, c in CODIGOS.items()})
    buscadas.update({f"codigo de {n} sin guiones": c.replace("-", "") for n, c in CODIGOS.items()})
    buscadas.update({f"HMAC del codigo de {n}": hmac_de(c) for n, c in CODIGOS.items()})

    def encontradas():
        actuales = textos()
        return sorted({f"{n} en {s}" for n, v in buscadas.items() for s, t in actuales.items() if v in t})
    halladas = encontradas()
    testigo = f"testigo-{secrets.token_hex(8)}"
    buscadas["testigo"] = testigo
    dc("exec", "-T", "api", "sh", "-c", f"echo {testigo} > /proc/1/fd/1")
    control = esperar(lambda: "testigo en api" in encontradas(), 10)
    negativo(f"l) ningun texto, codigo ni HMAC aparece en los logs de la API, PostgreSQL ni Caddy "
             f"{halladas if halladas else ''}".strip(), not halladas, control)

    # log_error_verbosity=terse: el log del servidor no lleva DETAIL, que
    # repetiría valores de la fila. Control: la línea del error sí aparece.
    hmac_repetido = hmac_de(CODIGOS["A"])
    sup("insert into canal.busqueda_seguimiento (codigo_hmac, empresa_id, denuncia_id) "
        "select codigo_hmac, empresa_id, denuncia_id from canal.busqueda_seguimiento "
        f"where codigo_hmac = '\\x{hmac_repetido}';")
    registro = dc("logs", "--no-color", "--no-log-prefix", "postgres").todo
    control = "duplicate key value violates unique constraint" in registro
    negativo("l) un duplicado deja su ERROR en el log de PostgreSQL, sin DETAIL ni el valor de la clave",
             "DETAIL" not in registro and hmac_repetido not in registro, control)


def seccion_n():
    # Va después de l): h) busca en el volcado el HMAC de cada código de
    # CODIGOS, así que estas denuncias, que se suprimen, usan los suyos
    # propios. Y antes de e), que busca claves también en las salidas de
    # gestion de esta sección.
    p("=== n) supresion legal (arts. 32.4 y 26.2)")
    empresa_a, ident_a, zona_a = EMPRESAS["A"]
    # "ramas" no se caduca: es el control de n4.
    casos = ("carrera", "art32", "art26", "en_uso", "ramas")
    marcas = {c: f"marcador-supresion-{c}-{secrets.token_hex(8)}" for c in casos}
    respuestas = http([pt("POST", ruta_denuncias(ident_a), {"categoria": "otros", "texto": marcas[c]})
                       for c in casos])
    codigos = {c: (json_de(r) or {}).get("codigo_seguimiento") for c, r in zip(casos, respuestas)}
    if not all(r.get("estado") == 201 for r in respuestas) or not all(codigos.values()):
        sinc(f"n) no se pudieron crear las denuncias de prueba ({[r.get('estado') for r in respuestas]})")
        return
    ids = {c: denuncia_de(v) for c, v in codigos.items()}
    hoy = f"(now() at time zone '{zona_a}')::date"

    def caducar(caso, intervalo, estado_denuncia="nueva"):
        # Como superusuario: el trigger de fecha solo actúa al insertar.
        return sup(f"update canal.denuncia set fecha = ({hoy} - interval '{intervalo}')::date, "
                   f"estado = '{estado_denuncia}' where id = '{ids[caso]}';").rc == 0

    # n1) Un mensaje llega mientras se suprime su denuncia. La supresión (como
    #     plataforma, en una transacción abierta) ya la ha borrado y la tiene
    #     bloqueada: el mensaje espera y, al confirmarse, no la encuentra.
    #     Debe ser el 404 de un código inexistente, no un 500. Control: si la
    #     supresión se deshace, el mensaje se guarda (201), y en los dos casos
    #     se vio a la API esperando.
    if not caducar("carrera", "4 months"):
        sinc("n1) no se pudo caducar la denuncia de prueba")
        return
    seg_antes = http([seguimiento(codigos["carrera"])])[0]
    supresion = ("SET ROLE plataforma;\nselect * from canal.suprimir_denuncias_caducadas(100);\nRESET ROLE;")
    ctl_resp, ctl_visto = retener_y_enviar(supresion, "ROLLBACK", codigos["carrera"], "llega durante la supresion")
    control = seg_antes.get("estado") == 200 and ctl_resp.get("estado") == 201 and ctl_visto
    pasa(control, f"n1) control: con la supresion deshecha, el mensaje que esperaba se guarda "
                  f"({ctl_resp.get('estado')}, se vio a la API esperando: {ctl_visto})")
    resp, visto = retener_y_enviar(supresion, "COMMIT", codigos["carrera"], "llega durante la supresion")
    negativo("n1) con la supresion confirmada, el mensaje que esperaba recibe el 404 del codigo inexistente",
             resp.get("estado") == 404 and resp.get("cuerpo") == CUERPO_404_CODIGO and visto, control,
             f"respuesta: {resp}; visto: {visto}")
    restos = sup(f"select (select count(*) from canal.denuncia where id = '{ids['carrera']}') || '|' || "
                 f"(select count(*) from canal.mensaje where denuncia_id = '{ids['carrera']}') || '|' || "
                 f"(select count(*) from canal.busqueda_seguimiento where denuncia_id = '{ids['carrera']}') || '|' || "
                 f"(select string_agg(actor || ':' || accion, ',') from canal.registro_auditoria "
                 f"where objeto_id = '{ids['carrera']}');").out.strip()
    negativo(f"n1) no queda nada de la denuncia (ni su mensaje anterior ni su codigo) y la auditoria guarda "
             f"solo sistema:supresion_art32 ({restos})", restos == "0|0|0|sistema:supresion_art32", control)

    # n2) El código suprimido responde exactamente como uno que nunca existió.
    aleatorio = base64.b32encode(secrets.token_bytes(20)).decode("ascii")
    inexistente = "-".join(aleatorio[i:i + 4] for i in range(0, 32, 4))
    seg_sup, seg_inex, men_sup, men_inex = http([
        seguimiento(codigos["carrera"]), seguimiento(inexistente),
        nuevo_mensaje(codigos["carrera"], "hola"), nuevo_mensaje(inexistente, "hola")])
    control_n2 = seg_antes.get("estado") == 200
    negativo("n2) seguimiento de un codigo suprimido: el mismo 404, byte a byte, que uno inexistente",
             seg_sup.get("estado") == 404 and seg_sup.get("cuerpo") == seg_inex.get("cuerpo") == CUERPO_404_CODIGO,
             control_n2, f"suprimido: {seg_sup}; inexistente: {seg_inex}")
    negativo("n2) mensaje a un codigo suprimido: el mismo 404, byte a byte, que a uno inexistente",
             men_sup.get("estado") == 404 and men_sup.get("cuerpo") == men_inex.get("cuerpo") == CUERPO_404_CODIGO,
             control_n2, f"suprimido: {men_sup}; inexistente: {men_inex}")

    # n3) gestion suprimir-caducadas: art. 32.4 (nueva con 3 meses justos) y
    #     art. 26.2 (archivada con 10 años); la denuncia "en_uso" la retiene
    #     otra sesión y se salta. Control: la sesión seguía reteniéndola
    #     cuando gestion terminó.
    if not (caducar("art32", "3 months") and caducar("art26", "10 years", "archivada")
            and caducar("en_uso", "4 months")):
        sinc("n3) no se pudieron caducar las denuncias de prueba")
        return
    retiene = (f"SET application_name = 'n_retiene';\nBEGIN;\n"
               f"select 1 from canal.denuncia where id = '{ids['en_uso']}' for no key update;\n"
               "select pg_sleep(60);\nROLLBACK;\n")

    def retenida():
        return sup("select count(*) from pg_stat_activity where application_name = 'n_retiene' "
                   "and wait_event = 'PgSleep';").out.strip() == "1"
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        futuro = pool.submit(sup, retiene)
        lista = esperar(retenida, 30)
        primera = gestion("suprimir-caducadas") if lista else None
        seguia = retenida()
        sup("select pg_terminate_backend(pid) from pg_stat_activity where application_name = 'n_retiene';")
        futuro.result()
    if primera is None:
        sinc("n3) la sesion que retiene la denuncia no llego a su pausa")
        return
    esperado = [f"suprimidas: empresa_id={empresa_a} articulo=art26 denuncias=1",
                f"suprimidas: empresa_id={empresa_a} articulo=art32 denuncias=1",
                "total suprimidas: 2", "solicitudes de registro podadas: 0"]
    aviso = "AVISO: quedan 1 denuncias caducadas que estaban en uso; vuelva a ejecutar suprimir-caducadas"
    p(f"   gestion (1): codigo {primera.rc}; salida {primera.out.strip().splitlines()}")
    # 75 literal (EX_TEMPFAIL), no app.gestion.SALIDA_EN_USO: el oráculo no
    # se deriva del código que se prueba.
    negativo("n3) gestion suprime art32 y art26, solo con recuentos, salta la denuncia en uso, lo avisa y sale con 75",
             primera.rc == 75 and primera.out.strip().splitlines() == esperado and aviso in primera.err,
             seguia, f"stderr: {primera.err.strip()[-300:]!r}")
    quedan = sup(f"select count(*) from canal.denuncia where id in ('{ids['art32']}', '{ids['art26']}', "
                 f"'{ids['en_uso']}');").out.strip()
    negativo(f"n3) de las tres caducadas solo queda la que estaba en uso ({quedan})", quedan == "1", seguia)
    segunda = gestion("suprimir-caducadas")
    pasa(segunda.rc == 0 and segunda.out.strip().splitlines() == [
        f"suprimidas: empresa_id={empresa_a} articulo=art32 denuncias=1", "total suprimidas: 1",
        "solicitudes de registro podadas: 0"],
         f"n3) liberada, la ejecucion siguiente la suprime y sale con 0 ({segunda.rc}, {segunda.out.strip().splitlines()})")
    tercera = gestion("suprimir-caducadas")
    pasa(tercera.rc == 0 and tercera.out.strip().splitlines() == ["total suprimidas: 0", "solicitudes de registro podadas: 0"],
         f"n3) sin nada que suprimir: total 0 y codigo 0 ({tercera.rc}, {tercera.out.strip().splitlines()})")
    lote_malo = gestion("suprimir-caducadas", "--lote", "0")
    negativo("n3) un lote fuera de 1..500 se rechaza antes de conectar",
             lote_malo.rc == 2 and "debe estar entre 1 y 500" in lote_malo.err, tercera.rc == 0,
             f"codigo {lote_malo.rc}: {lote_malo.err.strip()[-200:]!r}")
    # Ni códigos, ni textos, ni HMAC en lo que imprime gestion. Control: la
    # búsqueda sí encuentra lo que gestion imprime de verdad.
    salidas = "\n".join(r.out + r.err for r in (primera, segunda, tercera))
    buscadas = list(marcas.values()) + list(codigos.values()) + [hmac_de(c) for c in codigos.values()]
    negativo("n3) las salidas de gestion no contienen codigos, textos ni HMAC de las denuncias suprimidas",
             not any(b in salidas for b in buscadas), "total suprimidas" in salidas)

    # n4) Las dos ramas de la carrera, de forma determinista y con el código
    #     real (RAMAS_SUPRESION): un código que resolvió la denuncia "carrera",
    #     suprimida en n1, da CodigoNoEncontrado (el 404 uniforme) al leerla y
    #     al escribir un mensaje. Control: con la denuncia "ramas", que existe,
    #     la lectura y el mensaje funcionan.
    r = dc("exec", "-T", "api", "python", "-c", RAMAS_SUPRESION, str(empresa_a), ids["ramas"], ids["carrera"])
    try:
        ramas = json.loads(r.out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        sinc(f"n4) el script de las ramas no devolvio resultado: {r.err.strip()[-300:]!r}")
        return
    p(f"   ramas: {ramas}")
    control = ramas.get("consultar_existente") == "EstadoDenuncia" and ramas.get("mensaje_existente") == "MensajeEnviado"
    pasa(control, "n4) control: con una denuncia que existe, la lectura y el mensaje funcionan")
    negativo("n4) leer una denuncia suprimida tras resolver su codigo da CodigoNoEncontrado (404), no un error interno",
             ramas.get("consultar_suprimida") == "CodigoNoEncontrado", control, f"ramas: {ramas}")
    negativo("n4) escribir en una denuncia suprimida tras resolver su codigo da CodigoNoEncontrado (404)",
             ramas.get("mensaje_suprimida") == "CodigoNoEncontrado", control, f"ramas: {ramas}")


def formas(clave_hex):
    """Cómo podría aparecer una clave en un log: hex, hex en mayúsculas, base64
    y la representación de bytes de Python (sin el b'' que la rodea)."""
    crudo = bytes.fromhex(clave_hex)
    return [clave_hex, clave_hex.upper(), base64.b64encode(crudo).decode("ascii"), repr(crudo)[2:-1]]


def seccion_e():
    p("=== e) ninguna clave aparece en los logs")
    # Todas las claves de empresa que existen: la API las desenvuelve aquí, así
    # que también se busca lo que la propia API ha tenido en memoria.
    r = sup("select id from canal.empresa order by id;")
    if r.rc != 0:
        raise Parada(f"no se pudieron leer las empresas: {r.err.strip()[:300]}")
    desenvolver(*r.out.split())
    buscadas = dict(CLAVES_FALSAS)
    for i, clave in enumerate(sorted(CLAVES_EMPRESA)):
        buscadas[f"clave_empresa_{i + 1}"] = clave

    def textos():
        return {
            "log de la API": dc("logs", "--no-color", "--no-log-prefix", "api").todo,
            "log de PostgreSQL": dc("logs", "--no-color", "--no-log-prefix", "postgres").todo,
            "log de Caddy": dc("logs", "--no-color", "--no-log-prefix", "caddy").todo,
            "salidas de gestion": "\n".join(salidas_gestion),
        }

    def encontradas(fuentes):
        # Solo nombres de clave y de fuente, nunca el valor.
        return sorted({f"{nombre} en {fuente}" for nombre, clave in buscadas.items()
                       for fuente, texto in fuentes.items() for forma in formas(clave) if forma in texto})

    antes = encontradas(textos())
    # Control: la clave maestra falsa escrita a propósito en la salida del
    # proceso principal de la API, que es lo que Docker guarda como su log.
    # Demuestra que la búsqueda la encontraría si se filtrara. Con salto de
    # línea final: el driver json-file guarda el log por líneas y retiene una
    # sin terminar. Se espera a que Docker la registre.
    inyeccion = dc("exec", "-T", "api", "sh", "-c", "{ cat /run/secrets/clave_maestra; echo; } > /proc/1/fd/1")
    despues = []

    def encontrada():
        despues[:] = encontradas(textos())
        return "clave_maestra en log de la API" in despues

    control = inyeccion.rc == 0 and esperar(encontrada, 10)
    n_empresa = len(buscadas) - len(CLAVES_FALSAS)
    negativo(f"e) ninguna de las {len(buscadas)} claves (maestra, HMAC y {n_empresa} de empresa) aparece "
             f"en los logs de la API, PostgreSQL y Caddy ni en las salidas de gestion {antes if antes else ''}".strip(),
             not antes and n_empresa == CLAVES_EMPRESA_ESPERADAS, control,
             f"inyeccion: codigo {inyeccion.rc} {inyeccion.err.strip()[-200:]!r}; tras inyectar: {despues}")


# ---------------------------------------------------------------------------
# r) Limitador de peticiones
# ---------------------------------------------------------------------------
def dc_produccion(*args, extra=None):
    """compose sin los límites de prueba: la API usa los de producción."""
    return ejecutar(BASE_PRODUCCION + (extra or []) + list(args))


def redis_cli(usuario, *args, entrada=None):
    """redis-cli dentro del contenedor de Redis con la contraseña FALSA del
    usuario, por entorno y no como argumento. Con usuario None, sin
    autenticar."""
    autenticacion = ["-e", f"REDISCLI_AUTH={CONTRASENAS_REDIS[usuario]}", "redis", "redis-cli", "--user", usuario] \
        if usuario else ["redis", "redis-cli"]
    return dc("exec", "-T", *autenticacion, *args, entrada=entrada)


def contenido_redis():
    """Todas las claves de Redis con su valor y su PTTL (usuario inspector).

    PTTL y no TTL: TTL da segundos enteros y devuelve 0 a una clave a la que
    le queda menos de un segundo; PTTL da milisegundos, y sus únicos valores
    especiales son -1 (sin caducidad) y -2 (no existe), como en TTL
    (documentación oficial de Redis). Solo se piden de las claves con
    caracteres normales: una clave con otros caracteres ya es una anomalía y
    se informa sin leerla.
    """
    r = redis_cli("inspector", "--scan")
    if r.rc != 0:
        raise Parada(f"no se pudo recorrer Redis con el usuario inspector: {r.todo.strip()[-300:]!r}")
    claves = sorted(set(r.out.split()))
    legibles = [c for c in claves if re.fullmatch(r"[A-Za-z0-9:._-]+", c)]
    res = {c: (None, None) for c in claves}
    if legibles:
        ordenes = "".join(f"GET {c}\nPTTL {c}\n" for c in legibles)
        lineas = redis_cli("inspector", entrada=ordenes.encode("ascii")).out.split("\n")
        for i, clave in enumerate(legibles):
            valor, ttl = (lineas[2 * i:2 * i + 2] + ["", ""])[:2]
            res[clave] = (valor.strip(), ttl.strip())
    return res


def esperar_ventana(ventana, margen):
    """Si quedan menos de margen segundos para que acabe la ventana actual,
    espera a la siguiente: una ráfaga partida entre dos ventanas no llegaría
    al límite. Es el reloj del anfitrión; Docker Desktop sincroniza con él el
    de su máquina virtual, y el margen cubre una deriva de segundos."""
    resto = ventana - int(time.time()) % ventana
    if resto < margen:
        p(f"   espera de {resto + 3} s a la ventana siguiente ({ventana} s)")
        time.sleep(resto + 3)


def codigo_inexistente():
    aleatorio = base64.b32encode(secrets.token_bytes(20)).decode("ascii")
    return "-".join(aleatorio[i:i + 4] for i in range(0, 32, 4))


def es_429(respuesta, ventana):
    """429 con el cuerpo exacto, las cabeceras de seguridad de Caddy y un
    Retry-After entre 1 y la ventana."""
    cabeceras = respuesta.get("cabeceras", {})
    tras = cabeceras.get("retry-after", "")
    return (respuesta.get("estado") == 429 and respuesta.get("cuerpo") == CUERPO_429
            and tras.isdigit() and 1 <= int(tras) <= ventana
            and all(cabeceras.get(k) == v for k, v in CABECERAS_SEGURIDAD.items()))


def es_503_limitador(respuesta):
    return (respuesta.get("estado") == 503 and respuesta.get("cuerpo") == CUERPO_503_OCUPADO
            and respuesta.get("cabeceras", {}).get("retry-after") == REINTENTAR_TRAS)


def desviar_acl(etiqueta, acl, mensaje):
    """Arranca Redis con otra ACL (secreto redis_acl sustituido), reinicia la
    API y comprueba que no arranca. Después devuelve la ACL de la batería y
    comprueba que la API vuelve a estar sana (control)."""
    fichero = TEMPORAL / f"acl_{etiqueta}"
    fichero.write_text(acl, encoding="ascii", newline="\n")
    variante = TEMPORAL / f"acl_{etiqueta}.yml"
    variante.write_text("\n".join(["secrets:"] + fichero_secreto("redis_acl", fichero)) + "\n",
                        encoding="utf-8", newline="\n")
    cid = contenedor("api")
    control_antes = salud(cid) == "healthy"
    previas = "\n".join(lineas_log("api")).count(mensaje)
    r = dc_produccion("up", "-d", "--force-recreate", "--no-deps", "redis", extra=["-f", str(variante)])
    # Con otra contraseña su healthcheck falla: basta con que acepte conexiones.
    arrancado = r.rc == 0 and esperar(lambda: any(t in redis_cli(None, "PING").out for t in ("PONG", "NOAUTH")), 30)
    dc_produccion("restart", "api")
    bloqueado = esperar(lambda: "\n".join(lineas_log("api")).count(mensaje) > previas, 60)
    no_sana = salud(cid) != "healthy"
    vuelta = dc_produccion("up", "-d", "--force-recreate", "--no-deps", "--wait", "redis")
    dc_produccion("restart", "api")
    control_despues = vuelta.rc == 0 and esperar(lambda: salud(cid) == "healthy", 90)
    negativo(f"r11) {etiqueta}: la API no arranca y registra {mensaje!r}", bloqueado and no_sana,
             control_antes and arrancado and control_despues,
             f"healthy antes {control_antes}, Redis arrancado {arrancado}, healthy tras revertir {control_despues}; "
             f"log: {lineas_log('api')[-4:]}")
    if not control_despues:
        raise Parada(f"la API no vuelve a estar healthy tras revertir la ACL {etiqueta}")


def seccion_r():
    p("=== r) limitador de peticiones (Redis)")
    # r1) La ACL de la batería es la de producción: los permisos literales de
    # aquí coinciden con los de scripts/generar_secretos.py (se lee el código
    # del script, nunca los secretos).
    arbol = ast.parse((RAIZ / "scripts" / "generar_secretos.py").read_text(encoding="utf-8"))
    permisos = [ast.literal_eval(n.value) for n in arbol.body if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "PERMISOS_ACL_APLICACION" for t in n.targets)]
    pasa(permisos == [PERMISOS_ACL_APLICACION],
         f"r1) los permisos de aplicacion en la ACL de la bateria son los de generar_secretos.py ({permisos})")

    # r2) Redis no puede escribir en disco: sin volúmenes ni tmpfs, raíz de
    # solo lectura (incluido /data). Control: la misma imagen sin read_only
    # sí escribe en /data.
    i = json.loads(ejecutar(["docker", "inspect", contenedor("redis")]).out)[0]
    montajes = sorted((m["Type"], m["Destination"]) for m in i["Mounts"])
    pasa(montajes == [("bind", "/run/secrets/contrasena_redis"), ("bind", "/run/secrets/redis_acl")]
         and not i["HostConfig"].get("Tmpfs"), f"r2) redis: solo sus dos secretos montados ({montajes})")
    pasa(i["HostConfig"]["ReadonlyRootfs"] is True, "r2) redis: raiz de solo lectura")
    imagen = i["Config"]["Image"]
    volumenes = ejecutar(["docker", "image", "inspect", "--format", "{{json .Config.Volumes}}", imagen]).out.strip()
    pasa(volumenes == "null", f"r2) la imagen de redis no declara VOLUME ({volumenes})")
    escritura = dc("exec", "-T", "redis", "sh", "-c", "touch /data/prueba")
    control = ejecutar(["docker", "run", "--rm", "--user", "redis", "--entrypoint", "sh", imagen, "-c",
                        "touch /data/prueba && echo escrito"])
    negativo("r2) /data no es escribible en el contenedor de redis", escritura.rc != 0,
             control.rc == 0 and "escrito" in control.out, f"control: {control.todo.strip()[-200:]!r}")

    # r3) La ACL: aplicacion cuenta en limite:* (con TTL, para no dejar una
    # clave sin caducidad) y nada más; sin autenticar no se responde.
    r = redis_cli("aplicacion", entrada=b"MULTI\nINCR limite:arranque:0000000000000000\n"
                                       b"EXPIRE limite:arranque:0000000000000000 60 NX\nEXEC\n")
    control = r.out.split() == ["OK", "QUEUED", "QUEUED", "1", "1"]
    pasa(control, f"r3) control: aplicacion hace INCR y EXPIRE NX en limite:* dentro de MULTI ({r.out.split()})")
    for orden in (["GET", "limite:x"], ["SET", "limite:x", "1"], ["DEL", "limite:x"], ["SCAN", "0"], ["KEYS", "*"],
                  ["CONFIG", "GET", "dir"], ["CONFIG", "SET", "dir", "/tmp"], ["BGSAVE"], ["SAVE"], ["FLUSHALL"],
                  ["EVAL", "return 1", "0"], ["INCR", "otra:clave"], ["ACL", "LIST"]):
        r = redis_cli("aplicacion", *orden)
        negativo(f"r3) aplicacion: {' '.join(orden)} -> NOPERM", "NOPERM" in r.out, control,
                 f"salida: {r.todo.strip()[:200]!r}")
    pong = redis_cli("aplicacion", "PING").out.strip()
    r = redis_cli(None, "PING")
    negativo("r3) sin autenticar, Redis responde NOAUTH (usuario default desactivado)", "NOAUTH" in r.out,
             pong == "PONG", f"salida: {r.todo.strip()[:200]!r}")

    # r4) La API con los límites de producción (sin CANARIO_LIMITES).
    r = dc_produccion("up", "-d", "--wait", "api")
    p(f"up -d --wait api con los limites de produccion -> codigo {r.rc}")
    if r.rc != 0:
        p(r.todo.strip()[-1500:])
        raise Parada("no arranca la API con los limites de produccion")
    registro = dc("logs", "--no-color", "--no-log-prefix", "api").todo
    pasa(TEXTO_LIMITES_PRODUCCION in registro and TEXTO_LIMITADOR_VERIFICADO in registro
         and TEXTO_BLOQUEADO not in registro,
         f"r4) la API arranca con los limites de produccion y lo registra ({TEXTO_LIMITES_PRODUCCION!r})")
    entorno = json.loads(ejecutar(["docker", "inspect", "--format", "{{json .Config.Env}}",
                                   contenedor("api")]).out)
    pasa(not any(e.startswith("CANARIO_LIMITES=") for e in entorno), "r4) la API no tiene CANARIO_LIMITES")
    # Un solo proceso: la sal vive en la memoria del proceso, y con varios
    # workers cada uno tendría la suya y el límite se multiplicaría (8).
    # Control: la misma imagen con --workers 2 muestra los procesos hijos, así
    # que el recuento distingue.
    def procesos(contenedor_id):
        salida = ejecutar(["docker", "exec", contenedor_id, "sh", "-c", LISTAR_PROCESOS]).out
        return [l.strip() for l in salida.splitlines() if "python" in l or "uvicorn" in l]
    (TEMPORAL / "eco_procesos").mkdir()
    (TEMPORAL / "eco_procesos" / "eco.py").write_text(ECO_PROCESOS, encoding="utf-8", newline="\n")
    nombre = f"{PROYECTO}_api_r_workers"
    ejecutar(["docker", "run", "-d", "--name", nombre, "--network", "none", "--read-only", "--cap-drop", "ALL",
              "--security-opt", "no-new-privileges:true",
              "--mount", f"type=bind,src={TEMPORAL / 'eco_procesos'},dst=/eco,readonly",
              "--entrypoint", "uvicorn", IMAGEN_API, "eco:aplicacion", "--app-dir", "/eco", "--workers", "2"])
    try:
        esperar(lambda: sum("spawn_main" in l for l in procesos(nombre)) >= 2, 30)
        control_lista = procesos(nombre)
    finally:
        ejecutar(["docker", "rm", "-f", nombre])
    control = sum("spawn_main" in l for l in control_lista) >= 2
    reales = procesos(contenedor("api"))
    negativo(f"r4) la API corre en un solo proceso de uvicorn, el 1 ({reales})",
             len(reales) == 1 and reales[0].startswith("1 ") and "uvicorn app.principal:aplicacion" in reales[0],
             control, f"control con --workers 2: {control_lista}")

    # r5) Ráfagas desde el cliente A, a través de Caddy. Cada regla admite
    # exactamente su límite y la petición siguiente es 429. El cliente B, con
    # otra IP, no comparte contador: si la API contara por la IP de Caddy, B
    # también recibiría 429. Cuentan también las peticiones inválidas (422) y
    # los códigos inexistentes (404).
    _, ident_a, _ = EMPRESAS["A"]
    inexistente = codigo_inexistente()
    casos = [
        ("denuncia", pt("POST", ruta_denuncias(ident_a), {"categoria": "acoso"}), 422),
        ("seguimiento", seguimiento(inexistente), 404),
        ("mensajes", nuevo_mensaje(inexistente, "hola"), 404),
        ("otras", pt("GET", "/v1/no-existe"), 404),
    ]
    bloqueado = {}
    ventana_mensajes = None
    for regla, peticion, esperado in casos:
        maximo, ventana = LIMITES_PRODUCCION[regla]
        esperar_ventana(ventana, 30 if ventana == 60 else 300)
        if regla == "mensajes":
            ventana_mensajes = int(time.time()) // ventana
        respuestas = http([por_caddy(peticion)] * (maximo + 1), red="edge", ip=IP_CLIENTE_A)
        estados = [x.get("estado") for x in respuestas[:-1]]
        control = estados == [esperado] * maximo
        pasa(control, f"r5) {regla}: las {maximo} primeras peticiones del cliente A responden {esperado} "
                      f"({sorted(set(estados))})")
        bloqueado[regla] = es_429(respuestas[-1], ventana)
        negativo(f"r5) {regla}: la peticion {maximo + 1} es 429 con el cuerpo exacto, las cabeceras de seguridad "
                 f"y Retry-After entre 1 y {ventana}", bloqueado[regla], control,
                 f"respuesta: {respuestas[-1]}")
        otro = http([por_caddy(peticion)], red="edge", ip=IP_CLIENTE_B)[0]
        negativo(f"r5) {regla}: el cliente B no comparte el contador de A ({otro.get('estado')})",
                 otro.get("estado") == esperado, bloqueado[regla])
    # /salud está exenta: el cliente A, ya bloqueado en "otras", sigue
    # recibiendo 200 aunque pase de 60 por minuto.
    salud_a = http([por_caddy(pt("GET", "/salud", tipo=None))] * 70, red="edge", ip=IP_CLIENTE_A)
    negativo(f"r5) /salud esta exenta: 70 peticiones seguidas del cliente A bloqueado responden 200 "
             f"({sorted({x.get('estado') for x in salud_a})})",
             all(x.get("estado") == 200 for x in salud_a), bloqueado.get("otras", False))

    # r6) Qué guarda Redis: solo claves con el formato literal, con TTL que
    # no pasa de su ventana, valores enteros, y nunca la IP de un cliente, en
    # claro ni como hash sin clave. Control: las ráfagas han creado claves.
    contenido = contenido_redis()
    control = any(c.startswith("limite:denuncia:") for c in contenido) and bloqueado.get("denuncia", False)
    raras = [c for c in contenido if not PATRON_CLAVE_LIMITE.fullmatch(c)]
    negativo(f"r6) todas las claves de Redis tienen el formato limite:<regla>:<ventana>:<hmac> "
             f"({len(contenido)} claves) {raras if raras else ''}".strip(), not raras, control)
    sin_ttl = []
    caducadas = 0
    for clave, (valor, pttl) in contenido.items():
        partes = clave.split(":")
        regla = partes[1] if len(partes) > 1 else ""
        ventana = 60 if regla == "arranque" else LIMITES_PRODUCCION.get(regla, (0, 0))[1]
        if pttl == "-2":
            # Caducó entre el SCAN y el PTTL (también entre GET y PTTL):
            # tenía caducidad.
            caducadas += 1
            continue
        # pttl "-1" (sin caducidad) o None (clave no leída) no cumplen.
        if not (pttl and pttl.isdigit() and 1 <= int(pttl) <= ventana * 1000 and valor and valor.isdigit()):
            sin_ttl.append((clave, valor, pttl))
    negativo(f"r6) todas las claves caducan (PTTL entre 1 ms y su ventana) y tienen un valor entero "
             f"({caducadas} caducadas durante la lectura) {sin_ttl[:3] if sin_ttl else ''}".strip(), not sin_ttl, control)
    buscadas = {}
    for ip in (IP_CLIENTE_A, IP_CLIENTE_B):
        empaquetada = bytes(int(x) for x in ip.split("."))
        buscadas[ip] = [ip, ip.replace(".", ""), empaquetada.hex(), hashlib.sha256(ip.encode("ascii")).hexdigest()[:32],
                        hashlib.sha256(empaquetada).hexdigest()[:32]]
    texto = "\n".join(f"{c} {v}" for c, (v, _) in contenido.items())
    encontradas = sorted({ip for ip, formas_ip in buscadas.items() for f in formas_ip if f in texto})
    negativo(f"r6) ninguna IP de cliente aparece en Redis, ni en claro ni como SHA-256 sin clave "
             f"{encontradas if encontradas else ''}".strip(), not encontradas, control)

    # r7) Código real dentro de la API: regla de cada ruta registrada (una
    # ruta nueva hace fallar esta prueba hasta que se decida su regla) y de
    # rutas inexistentes, y la huella de cliente con IPv4 e IPv6.
    r = dc("exec", "-T", "api", "python", "-c", LIMITADOR_DENTRO, ",".join(RUTAS_SIN_REGLA))
    try:
        res = json.loads(r.out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        sinc(f"r7) no se pudo ejecutar la prueba del limitador dentro de la API: {r.err.strip()[-300:]!r}")
        res = None
    if res is not None:
        pasa(res["rutas"] == RUTAS_API, f"r7) reglas de las rutas registradas = {res['rutas']}")
        pasa(res["otras"] == {r_: "otras" for r_ in RUTAS_SIN_REGLA},
             f"r7) lo que no tiene regla propia cae en otras (cerrado por construccion): {res['otras']}")
        control = res["ipv4_distintas"] is True and res["longitud"] == 32
        pasa(control, "r7) control: dos IPv4 distintas tienen huellas distintas de 128 bits")
        for clave, texto_prueba in (("ipv6_mismo_64", "dos IPv6 del mismo /64 comparten huella"),
                                    ("ipv6_otro_64", "una IPv6 de otro /64 tiene otra huella"),
                                    ("ipv4_en_ipv6", "una IPv4 escrita como IPv6 (::ffff:) cuenta como la IPv4"),
                                    ("otra_sal", "con otra sal, la misma IP tiene otra huella")):
            negativo(f"r7) {texto_prueba}", res[clave] is True, control)
        pasa(res["no_ip"] == "ValueError", f"r7) una direccion que no es una IP se rechaza ({res['no_ip']})")

    # r8) La sal solo vive en la memoria del proceso: tras reiniciar la API,
    # el mismo cliente, en la misma ventana, tiene otra huella y su contador
    # vuelve a empezar. Control: antes del reinicio estaba bloqueado.
    antes = {c for c in contenido_redis() if c.startswith("limite:mensajes:")}
    dc_produccion("restart", "api")
    sana = esperar(lambda: salud(contenedor("api")) == "healthy", 90)
    respuesta = http([por_caddy(nuevo_mensaje(inexistente, "hola"))], red="edge", ip=IP_CLIENTE_A)[0]
    despues = contenido_redis()
    nuevas = {c: v for c, (v, _) in despues.items() if c.startswith("limite:mensajes:") and c not in antes}
    huellas_antes = {c.rsplit(":", 1)[1] for c in antes}
    nueva = next(iter(nuevas), "")
    otra_huella = (len(nuevas) == 1 and list(nuevas.values()) == ["1"]
                   and nueva.split(":")[2] == str(ventana_mensajes)
                   and nueva.rsplit(":", 1)[1] not in huellas_antes)
    negativo("r8) tras reiniciar la API, el cliente A tiene otra huella en la misma ventana y su contador empieza "
             f"de nuevo ({respuesta.get('estado')}, claves nuevas {nuevas})",
             respuesta.get("estado") == 404 and otra_huella, sana and bloqueado.get("mensajes", False))

    # r9) Redis en pausa (acepta la conexión pero no contesta): la petición
    # se rechaza en el plazo, sin retener a la API. Control: la misma
    # petición antes de la pausa.
    peticiones = [por_caddy(pt("GET", "/salud", tipo=None)), por_caddy(seguimiento(inexistente))]
    inicio = time.monotonic()
    base = http(peticiones, red="edge", ip=IP_CLIENTE_B)
    segundos_base = time.monotonic() - inicio
    control = base[0].get("estado") == 200 and base[1].get("estado") == 404
    previas = len(lineas_log("api"))
    dc("pause", "redis")
    try:
        inicio = time.monotonic()
        pausa = http(peticiones, red="edge", ip=IP_CLIENTE_B)
        segundos_pausa = time.monotonic() - inicio
    finally:
        dc("unpause", "redis")
    nuevas_lineas = lineas_log("api")[previas:]
    negativo(f"r9) con Redis en pausa: 503 con el cuerpo exacto y Retry-After {REINTENTAR_TRAS}, sin esperar "
             f"({segundos_pausa:.1f} s frente a {segundos_base:.1f} s sin pausa)",
             es_503_limitador(pausa[1]) and segundos_pausa < segundos_base + 3, control,
             f"respuesta: {pausa[1]}")
    negativo(f"r9) con Redis en pausa, /salud sigue respondiendo 200 ({pausa[0].get('estado')})",
             pausa[0].get("estado") == 200, control)
    negativo(f"r9) el rechazo registra {TEXTO_EVENTO_LIMITADOR + 'TimeoutError'!r} sin la IP del cliente",
             any(TEXTO_EVENTO_LIMITADOR + "TimeoutError" in l for l in nuevas_lineas)
             and not any(IP_CLIENTE_B in l for l in nuevas_lineas), control, f"lineas nuevas: {nuevas_lineas}")

    # r10) Redis parado: las cuatro reglas responden 503 y /salud 200. Al
    # volver, Redis no conserva ningún contador y la primera petición ya se
    # atiende (las conexiones muertas del pool se sustituyen).
    claves_antes = redis_cli("inspector", "DBSIZE").out.strip()
    previas = len(lineas_log("api"))
    dc("stop", "redis")
    try:
        parado = http([por_caddy(x) for x in (pt("POST", ruta_denuncias(ident_a), {"categoria": "acoso"}),
                                              seguimiento(inexistente), nuevo_mensaje(inexistente, "hola"),
                                              pt("GET", "/v1/no-existe"), pt("GET", "/salud", tipo=None))],
                      red="edge", ip=IP_CLIENTE_B)
    finally:
        dc("start", "redis")
    nuevas_lineas = lineas_log("api")[previas:]
    control = parado[-1].get("estado") == 200
    pasa(control, f"r10) control: con Redis parado /salud responde 200 ({parado[-1].get('estado')})")
    for nombre, respuesta in zip(("denuncia", "seguimiento", "mensajes", "otras"), parado):
        negativo(f"r10) con Redis parado, {nombre}: 503 con el cuerpo exacto y Retry-After {REINTENTAR_TRAS}",
                 es_503_limitador(respuesta), control, f"respuesta: {respuesta}")
    negativo(f"r10) cada rechazo registra {TEXTO_EVENTO_LIMITADOR!r} sin la IP del cliente",
             sum(TEXTO_EVENTO_LIMITADOR in l for l in nuevas_lineas) >= 4
             and not any(IP_CLIENTE_B in l for l in nuevas_lineas), control, f"lineas nuevas: {nuevas_lineas}")
    vuelto = esperar(lambda: salud(contenedor("redis")) == "healthy", 60)
    claves_despues = redis_cli("inspector", "DBSIZE").out.strip()
    negativo(f"r10) tras reiniciarse, Redis no conserva ningun contador (DBSIZE {claves_antes} -> {claves_despues})",
             claves_despues == "0", vuelto and claves_antes.isdigit() and int(claves_antes) > 0)
    respuesta = http([por_caddy(seguimiento(inexistente))], red="edge", ip=IP_CLIENTE_B)[0]
    pasa(vuelto and respuesta.get("estado") == 404,
         f"r10) con Redis de vuelta, la primera peticion se atiende sin 503 ({respuesta.get('estado')})")

    # r11) Arranque verificado del limitador: cada ACL desviada bloquea el
    # arranque; al devolver la de la batería, la API vuelve a arrancar.
    desviar_acl("permisiva", texto_acl("resetkeys ~* &* +@all"), TEXTO_BLOQUEO_PERMISIVA)
    desviar_acl("default_activo", texto_acl(PERMISOS_ACL_APLICACION, default="user default on nopass ~* &* +@all"),
                TEXTO_BLOQUEO_DEFAULT)
    desviar_acl("otra_contrasena", texto_acl(PERMISOS_ACL_APLICACION, contrasena=secrets.token_urlsafe(48)),
                TEXTO_BLOQUEO_CONTRASENA)

    # r12) Comprobaciones previas: secreto de Redis y CANARIO_LIMITES. Con
    # todo bien formado (control), la API pasa de ellas y llega a la conexión
    # (que falla por la contraseña falsa de la base de datos).
    d = TEMPORAL / "previas_limitador"
    d.mkdir()
    redis_falsa = secrets.token_urlsafe(48)
    for nombre, contenido_fichero in (("pg", secrets.token_urlsafe(48)), ("maestra", secrets.token_hex(32)),
                                      ("hmac", secrets.token_hex(32)), ("firma", secrets.token_hex(32)),
                                      ("identidades", secrets.token_hex(32)), ("flujo", secrets.token_hex(32)),
                                      ("redis", redis_falsa),
                                      ("redis_salto", redis_falsa + "\n")):
        (d / nombre).write_text(contenido_fichero, encoding="ascii", newline="")
    base_montajes = [(d / "pg", "contrasena_aplicacion"), (d / "maestra", "clave_maestra"),
                     (d / "hmac", "clave_hmac_codigos"), (d / "firma", "clave_firma_tokens"),
                     (d / "identidades", "clave_hmac_identidades"), (d / "flujo", "clave_flujo_externo")]
    validos = ("denuncia=5/3600,seguimiento=6/60,mensajes=7/3600,acceso=9/300,otras=8/60,cuenta=4/60,"
               "registro=3/3600,destinatario=2/900,destinatario_dia=1/86400")
    control_log = arrancar_api_temporal("r_control", base_montajes + [(d / "redis", "contrasena_redis")],
                                        {"CANARIO_LIMITES": validos})
    control = (f"{TEXTO_BLOQUEADO}conexion" in control_log
               and "LIMITES (configurados): acceso=9/300 cuenta=4/60 denuncia=5/3600 destinatario=2/900 "
                   "destinatario_dia=1/86400 mensajes=7/3600 otras=8/60 registro=3/3600 "
                   "seguimiento=6/60"
               in control_log)
    pasa(control, "r12) control: con el secreto de Redis y CANARIO_LIMITES validos la API los acepta, registra los "
                  "limites configurados y llega a la conexion")
    casos = [
        ("r_sin_redis", base_montajes, None,
         "secreto_redis: no se puede leer el secreto de Redis (FileNotFoundError)"),
        ("r_redis_salto", base_montajes + [(d / "redis_salto", "contrasena_redis")], None,
         "secreto_redis: el secreto de Redis tiene un formato inesperado"),
        ("r_limites_incompletos", base_montajes + [(d / "redis", "contrasena_redis")],
         {"CANARIO_LIMITES": "denuncia=10/3600"},
         ("limites: CANARIO_LIMITES: reglas ['denuncia'], se esperan "
          "['acceso', 'cuenta', 'denuncia', 'destinatario', 'destinatario_dia', 'mensajes', 'otras', 'registro', "
          "'seguimiento']")),
        ("r_limites_ventana", base_montajes + [(d / "redis", "contrasena_redis")],
         {"CANARIO_LIMITES": "denuncia=10/7,seguimiento=60/60,mensajes=30/3600,acceso=10/300,otras=60/60,"
                            "cuenta=60/60,registro=10/3600,destinatario=3/900,destinatario_dia=10/86400"},
         "limites: CANARIO_LIMITES: la ventana de denuncia no divide el dia"),
        ("r_limites_mal_formados", base_montajes + [(d / "redis", "contrasena_redis")],
         {"CANARIO_LIMITES": "denuncia=0/3600,seguimiento=60/60,mensajes=30/3600,acceso=10/300,otras=60/60,"
                            "cuenta=60/60,registro=10/3600,destinatario=3/900,destinatario_dia=10/86400"},
         "limites: CANARIO_LIMITES: elemento mal formado"),
    ]
    for etiqueta, montajes, entorno_api, motivo in casos:
        registro = arrancar_api_temporal(etiqueta, montajes, entorno_api)
        esperado = f"{TEXTO_BLOQUEADO}{motivo}"
        negativo(f"r12) {etiqueta[2:].replace('_', ' ')}: la API no arranca y registra {esperado!r}",
                 esperado in registro and f"{TEXTO_BLOQUEADO}conexion" not in registro
                 and redis_falsa not in registro, control, f"log: {registro.strip()[-300:]!r}")

    # r13) Ni las IPs de los clientes ni las contraseñas de Redis aparecen en
    # los logs. Control: las peticiones de A llegaron a la API (fue
    # bloqueado).
    textos = {s: dc("logs", "--no-color", "--no-log-prefix", s).todo for s in ("api", "redis", "caddy")}
    fugas = sorted({f"{n} en {s}" for s, t in textos.items()
                    for n, v in (("ip_a", IP_CLIENTE_A), ("ip_b", IP_CLIENTE_B),
                                 ("contrasena_aplicacion", CONTRASENAS_REDIS["aplicacion"]),
                                 ("contrasena_inspector", CONTRASENAS_REDIS["inspector"])) if v in t})
    negativo(f"r13) ni las IPs de los clientes ni las contrasenas de Redis aparecen en los logs de api, redis y caddy "
             f"{fugas if fugas else ''}".strip(), not fugas, bloqueado.get("denuncia", False))


def seccion_s():
    p("=== s) limpieza")
    r = dc_con_gestion("down", "-v", "--rmi", "local")
    p(f"down -v --rmi local -> codigo {r.rc}")
    for etiqueta, orden in [
        ("contenedor", ["docker", "ps", "-a", "--format", "{{.Names}}"]),
        ("red", ["docker", "network", "ls", "--format", "{{.Name}}"]),
        ("volumen", ["docker", "volume", "ls", "--format", "{{.Name}}"]),
        ("imagen", ["docker", "image", "ls", "--format", "{{.Repository}}"]),
    ]:
        restos = [n for n in ejecutar(orden).out.split() if n.startswith(PROYECTO)]
        pasa(not restos, f"s) ningun {etiqueta} con prefijo {PROYECTO} {restos if restos else ''}".strip())
    final = estado_git()
    if ESTADO_GIT_ARRANQUE is None or final is None:
        sinc("s) no se pudo comparar el estado de Git")
    else:
        pasa(final == ESTADO_GIT_ARRANQUE, "s) la bateria no ha modificado el repo (git status igual al del arranque)")


def terminar():
    resultado = "NO OK (hay FALLA o SIN CONCLUSION)" if estado["falla"] or estado["sin_conclusion"] else "OK"
    p("RESULTADO GLOBAL: " + resultado)
    SALIDA.write_text("\n".join(lineas_salida) + "\n", encoding="utf-8", newline="\n")
    sys.exit(0 if resultado == "OK" else 1)


def terminar_con_parada():
    p("RESULTADO GLOBAL: NO OK (PARADA)")
    SALIDA.write_text("\n".join(lineas_salida) + "\n", encoding="utf-8", newline="\n")
    sys.exit(1)


def estado_git():
    try:
        r = ejecutar(["git", "status", "--short", "-uall"], timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    return [l.rstrip() for l in r.out.splitlines() if l.strip()] if r.rc == 0 else None


def recursos_previos():
    previos = []
    for orden in (["docker", "ps", "-a", "--format", "{{.Names}}"],
                  ["docker", "network", "ls", "--format", "{{.Name}}"],
                  ["docker", "volume", "ls", "--format", "{{.Name}}"]):
        previos += [n for n in ejecutar(orden).out.split() if n.startswith(PROYECTO)]
    return previos


def subredes_ocupadas():
    ocupadas = []
    for red in ejecutar(["docker", "network", "ls", "-q"]).out.split():
        partes = ejecutar(["docker", "network", "inspect", "--format",
                           "{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}", red]).out.split()
        if partes and set(partes[1:]) & SUBREDES_FIJAS:
            ocupadas.append(partes[0])
    return ocupadas


ESTADO_GIT_ARRANQUE = None
DIRECTORIO_CLAVES = None


def main():
    global ESTADO_GIT_ARRANQUE, TEMPORAL, DIRECTORIO_CLAVES
    ESTADO_GIT_ARRANQUE = estado_git()
    # Precondiciones: si fallan, no se limpia nada (podrían ser recursos ajenos).
    if ejecutar(["docker", "info", "--format", "{{.ServerVersion}}"]).rc != 0:
        p("PARADA: docker info falla")
        terminar_con_parada()
    previos = recursos_previos()
    if previos:
        p(f"PARADA: ya existen recursos con prefijo {PROYECTO}: {previos}")
        terminar_con_parada()
    ocupadas = subredes_ocupadas()
    if ocupadas:
        p(f"PARADA: las subredes fijas ya estan en uso por {ocupadas} (pare el proyecto canario)")
        terminar_con_parada()
    # Solo se comprueba que existen (is_file), nunca se leen. Las claves de
    # cifrado de secrets/ no hacen falta: la batería usa falsas. compose
    # valida igualmente que existan todos los ficheros de secretos que
    # declara, y el fichero adicional solo sustituye las cinco claves.
    for fichero in ("contrasena_redis.txt", "redis_acl.conf", "contrasena_postgres_superusuario.txt",
                    "contrasena_migrador.txt", "contrasena_aplicacion.txt", "contrasena_plataforma.txt"):
        if not (RAIZ / "secrets" / fichero).is_file():
            p(f"PARADA: secrets/{fichero} no existe (scripts/generar_secretos.py)")
            terminar_con_parada()
    TEMPORAL = pathlib.Path(tempfile.mkdtemp(prefix="canario_denuncia_"))
    DIRECTORIO_CLAVES = preparar_claves_falsas()
    parada = None
    try:
        # e) busca las claves en los logs después de todo lo demás, incluidas
        # las peticiones HTTP. r) va detrás: vuelve a crear la API con los
        # límites de producción, y el log del contenedor anterior se pierde.
        for seccion in (seccion_a, seccion_b, seccion_c, seccion_d, seccion_f, seccion_g, seccion_m, seccion_h,
                        seccion_i, seccion_j, seccion_k, seccion_l, seccion_n, seccion_e, seccion_r):
            seccion()
    except Parada as e:
        parada = str(e)
        p(f"PARADA: {parada}")
    except Exception:  # noqa: BLE001 - error inesperado del propio test: se informa y se limpia
        parada = "error inesperado en el test"
        p("ERROR INESPERADO:\n" + traceback.format_exc())
    finally:
        for etiqueta in ("claves_ok", "sin_maestra", "sin_hmac", "maestra_salto", "maestra_mayusculas",
                         "maestra_corta", "hmac_igual", "r_control", "r_sin_redis", "r_redis_salto",
                         "r_limites_incompletos", "r_limites_ventana", "r_limites_mal_formados", "r_workers"):
            ejecutar(["docker", "rm", "-f", f"{PROYECTO}_api_{etiqueta}"])
        # Por si r) se cortó con Redis en pausa: down no para un contenedor
        # pausado.
        dc("unpause", "redis")
        if parada is not None:
            dc_con_gestion("down", "-v", "--rmi", "local")
        else:
            seccion_s()
        shutil.rmtree(TEMPORAL, ignore_errors=True)
    if parada is not None:
        estado["falla"] = True
    terminar()


if __name__ == "__main__":
    main()
