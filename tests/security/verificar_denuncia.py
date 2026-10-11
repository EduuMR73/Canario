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
  aparece en los logs de la API ni de PostgreSQL ni en las salidas de
  gestion, en hexadecimal, en mayúsculas, en base64 o como bytes de Python.
  Control: la clave maestra escrita a propósito en el log de la API sí se
  encuentra.

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
# Claves de empresa al final de d): A v1 a v3, B v1 y v2, C v1.
CLAVES_EMPRESA_ESPERADAS = 6
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
    r = dc("up", "-d", "--build", "--wait", "postgres", "api")
    p(f"up -d --build --wait postgres api -> codigo {r.rc}")
    if r.rc != 0:
        p(r.todo.strip()[-1500:])
        raise Parada("no arranca la API")
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
    for etiqueta, nombre in (("A", "Empresa A"), ("B", "Empresa B")):
        r = gestion("alta-empresa", "--nombre", nombre)
        alta = PATRON_ALTA.search(r.out)
        clave = PATRON_CLAVE.search(r.out)
        ok = r.rc == 0 and alta is not None and clave is not None and clave.group(2) == "1"
        pasa(ok, f"d) alta-empresa {etiqueta}: empresa, directorio y clave version 1 (codigo {r.rc})")
        if not ok:
            p(f"   salida: {r.out.strip()[-300:]!r} error: {r.err.strip()[-300:]!r}")
            raise Parada("gestion no da de alta empresas")
        altas[etiqueta] = alta.group(1)
    A, B = altas["A"], altas["B"]

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
        alta = gestion("alta-empresa", "--nombre", "Empresa C")
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
             f"en los logs de la API y de PostgreSQL ni en las salidas de gestion {antes if antes else ''}".strip(),
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
        for seccion in (seccion_a, seccion_b, seccion_c, seccion_d, seccion_e):
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
