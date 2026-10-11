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

Cada prueba negativa lleva su control positivo: si el control falla, el
resultado es SIN CONCLUSION, nunca PASA. Los oráculos son literales.

Cómo se ejecuta (desde la raíz del repositorio, en PowerShell, con Docker en
marcha y los secretos generados con scripts/generar_secretos.py):

    python tests/security/verificar_denuncia.py

Usa un proyecto de Docker propio (canario_denuncia) y solo levanta postgres y
api, más ejecuciones sueltas de gestion. Necesita que el proyecto canario esté
parado (las subredes de app y edge son fijas). Al terminar lo borra todo
(down -v y las imágenes construidas).

Claves de cifrado FALSAS en toda la batería: se generan en cada ejecución y
un fichero compose adicional, en el directorio temporal, sustituye con ellas
los secretos clave_maestra y clave_hmac_codigos. Así la prueba sabe qué
buscar en los logs sin leer nunca las reales, y la sección a) comprueba
(por su sha256, dentro del contenedor) que la API usa las falsas. De
secrets/ solo se usan las contraseñas de los roles, sin leerlas aquí: compose
las monta como secretos, y una ejecución suelta de gestion monta la de
aplicacion con --mount.

La salida completa se guarda en verificacion_denuncia.txt dentro del
directorio temporal del sistema. El código de salida es 0 solo si el
resultado global es OK. Solo usa la biblioteca estándar.
"""
import base64
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
# Claves de empresa al llegar a e): A v1 a v3, B v1 y v2, C v1 (d) y la de la
# empresa inactiva de f), v1.
CLAVES_EMPRESA_ESPERADAS = 7
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
CUERPO_404_RUTA = '{"detalle": "recurso no encontrado"}'.encode("utf-8")
CUERPO_404_EMPRESA = CUERPO_404_RUTA
CUERPO_404_CODIGO = '{"detalle": "código de seguimiento no válido"}'.encode("utf-8")
# Errores que genera Caddy (proxy/Caddyfile, handle_errors).
CUERPO_413_CADDY = '{"detalle": "cuerpo de la petición demasiado grande"}'.encode("utf-8")
CUERPO_502_CADDY = '{"detalle": "servicio no disponible"}'.encode("utf-8")
CUERPO_421_CADDY = '{"detalle": "host no válido"}'.encode("utf-8")
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
CUERPO_405 = '{"detalle": "método no permitido"}'.encode("utf-8")
CUERPO_413 = '{"detalle": "cuerpo de la petición demasiado grande"}'.encode("utf-8")
CUERPO_422 = '{"detalle": "petición no válida"}'.encode("utf-8")
CUERPO_500 = '{"detalle": "error interno"}'.encode("utf-8")
CUERPO_503 = '{"detalle": "el canal de esta empresa no está disponible; inténtelo más tarde"}'.encode("utf-8")
CLAVES_RESPUESTA_CREAR = ["codigo_seguimiento", "fecha"]
CLAVES_RESPUESTA_SEGUIMIENTO = ["categoria", "estado", "fecha", "mensajes", "texto"]
LIMITE_CUERPO = 131072  # 128 KiB, en la API y en Caddy
LONGITUD_MAXIMA_TEXTO = 10000
TEXTO_EVENTO_SIN_CLAVE = "EVENTO empresa_sin_clave"
TEXTO_INTEGRIDAD = "INTEGRIDAD: "
TEXTO_ERROR_INTERNO = "ERROR INTERNO: InsufficientPrivilege 42501"

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


def preparar_claves_falsas():
    """Genera las claves falsas y el fichero compose que las monta."""
    directorio = TEMPORAL / "claves_compose"
    directorio.mkdir()
    lineas = ["secrets:"]
    for nombre in ("clave_maestra", "clave_hmac_codigos"):
        CLAVES_FALSAS[nombre] = secrets.token_hex(32)
        (directorio / nombre).write_text(CLAVES_FALSAS[nombre], encoding="ascii", newline="")
        # Ruta con barras normales y entre comillas: la del directorio
        # temporal de Windows puede llevar espacios.
        lineas += [f"  {nombre}:", f"    file: \"{(directorio / nombre).as_posix()}\""]
    adicional = TEMPORAL / "claves_falsas.yml"
    adicional.write_text("\n".join(lineas) + "\n", encoding="utf-8", newline="\n")
    BASE.extend(["-f", str(adicional)])
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
    pasa(salud(contenedor("api")) == "healthy", "a) la API esta healthy")
    pasa(dc("exec", "-T", "api", "test", "-f", "/run/secrets/contrasena_aplicacion").rc == 0,
         "a) /run/secrets/contrasena_aplicacion existe en la API (sin leerlo)")
    # Las claves que ve la API son las falsas de esta ejecución: se compara su
    # sha256 dentro del contenedor, sin sacar la clave.
    for nombre, valor in CLAVES_FALSAS.items():
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


def arrancar_api_temporal(etiqueta, montajes):
    """Arranca la imagen de la API con secretos falsos y devuelve su log."""
    nombre = f"{PROYECTO}_api_{etiqueta}"
    argumentos = []
    for origen, destino in montajes:
        argumentos += ["--mount", f"type=bind,src={origen},dst=/run/secrets/{destino},readonly"]
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
               "hmac": secrets.token_hex(32)}
    ficheros = {
        "contrasena": valores["contrasena"],
        "maestra": valores["maestra"],
        "hmac": valores["hmac"],
        "maestra_salto": valores["maestra"] + "\n",
        "maestra_mayusculas": valores["maestra"].upper(),
        "maestra_corta": valores["maestra"][:-2],
        "hmac_igual": valores["maestra"],
    }
    for nombre, contenido in ficheros.items():
        (d / nombre).write_text(contenido, encoding="ascii", newline="")

    def montar(maestra="maestra", hmac="hmac"):
        lista = [(d / "contrasena", "contrasena_aplicacion")]
        if maestra:
            lista.append((d / maestra, "clave_maestra"))
        if hmac:
            lista.append((d / hmac, "clave_hmac_codigos"))
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
    ]
    for etiqueta, montajes, motivo in casos:
        registro = arrancar_api_temporal(etiqueta, montajes)
        esperado = f"{TEXTO_BLOQUEADO}claves: {motivo}"
        negativo(f"c) {etiqueta.replace('_', ' ')}: la API no arranca y registra {esperado!r}",
                 esperado in registro and TEXTO_VERIFICADO not in registro
                 and f"{TEXTO_BLOQUEADO}conexion" not in registro,
                 control, f"log: {registro.strip()[-300:]!r}")
        fugas = [n for n in ("maestra", "hmac") if valores[n] in registro or valores[n].upper() in registro]
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
def http(peticiones, red="app"):
    """Ejecuta las peticiones con el cliente de prueba y devuelve sus respuestas."""
    r = ejecutar(["docker", "run", "--rm", "-i", "--network", f"{PROYECTO}_{red}", "--read-only",
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
    if not {"A", "B"} <= set(CODIGOS):
        sinc("l) faltan codigos de f)")
        return
    _, ident_a, _ = EMPRESAS["A"]
    # Crear, consultar, un 404 y un 422 son el uso normal: no deben dejar
    # ninguna línea, porque cada línea lleva la hora. Control: un caso que sí
    # se registra (empresa sin clave) añade una línea en el mismo log.
    antes = len(lineas_log("api"))
    respuestas = http([
        pt("POST", ruta_denuncias(ident_a), {"categoria": "acoso", "texto": "uso normal"}),
        seguimiento(CODIGOS["A"]),
        seguimiento(CODIGOS["B"]),
        pt("POST", ruta_denuncias(secrets.token_hex(16)), {"categoria": "acoso", "texto": "hola"}),
        seguimiento("x"),
        pt("POST", ruta_denuncias(ident_a), {"categoria": "no", "texto": "hola"}),
    ])
    nuevas = lineas_log("api")[antes:]
    previas = len(lineas_log("api"))
    http([pt("POST", ruta_denuncias(EMPRESAS["sin_clave"][1]), {"categoria": "acoso", "texto": "hola"})])
    control = (len(lineas_log("api")) > previas
               and [x.get("estado") for x in respuestas] == [201, 200, 200, 404, 404, 422])
    negativo(f"l) crear, consultar, 404 y 422 no dejan ninguna linea en el log de la API ({len(nuevas)} nuevas)",
             nuevas == [], control, f"lineas nuevas: {nuevas}")

    # Textos y códigos en los logs de la API, PostgreSQL y Caddy. Control: un
    # marcador escrito a propósito en el log de la API se encuentra.
    def textos():
        return {s: dc("logs", "--no-color", "--no-log-prefix", s).todo for s in ("api", "postgres", "caddy")}
    buscadas = {f"texto de {n}": MARCADORES[n] for n in ("A", "A2", "B", "inactiva", "utf", "422")}
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
    # declara, y el fichero adicional solo sustituye los dos de cifrado.
    for fichero in ("contrasena_redis.txt", "redis_acl.conf", "contrasena_postgres_superusuario.txt",
                    "contrasena_migrador.txt", "contrasena_aplicacion.txt", "contrasena_plataforma.txt"):
        if not (RAIZ / "secrets" / fichero).is_file():
            p(f"PARADA: secrets/{fichero} no existe (scripts/generar_secretos.py)")
            terminar_con_parada()
    TEMPORAL = pathlib.Path(tempfile.mkdtemp(prefix="canario_denuncia_"))
    DIRECTORIO_CLAVES = preparar_claves_falsas()
    parada = None
    try:
        # e) va al final: busca las claves en los logs después de todo lo
        # demás, incluidas las peticiones HTTP.
        for seccion in (seccion_a, seccion_b, seccion_c, seccion_d, seccion_f, seccion_g, seccion_h,
                        seccion_i, seccion_j, seccion_k, seccion_l, seccion_e):
            seccion()
    except Parada as e:
        parada = str(e)
        p(f"PARADA: {parada}")
    except Exception:  # error inesperado del propio test: se informa y se limpia
        parada = "error inesperado en el test"
        p("ERROR INESPERADO:\n" + traceback.format_exc())
    finally:
        for etiqueta in ("claves_ok", "sin_maestra", "sin_hmac", "maestra_salto", "maestra_mayusculas",
                         "maestra_corta", "hmac_igual"):
            ejecutar(["docker", "rm", "-f", f"{PROYECTO}_api_{etiqueta}"])
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
