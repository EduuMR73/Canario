#!/usr/bin/env python3
"""Batería de pruebas de seguridad del registro del personal, "primero el
email" (app/solicitudes.py, app/correo.py y las rutas de app/rutas_personal.py),
con la pila real: API, PostgreSQL, Redis y Mailpit (el SMTP de desarrollo).

Qué prueba:

* a) el arranque: la API registra el origen de la SPA del personal; Mailpit
  corre sin root, de solo lectura, sin capacidades, con sus límites, solo en
  la red interna correo y sin puertos publicados, y desde esa red no se sale a
  internet;
* c) el control positivo de extremo a extremo: solicitud, correo con el
  enlace (token en el fragmento), verificación, la solicitud aparece al admin,
  aprobación con un rol (sin token en la respuesta), correo de invitación,
  activación con TOTP, login con el rol aprobado y la fila de auditoría;
* d) enumeración: la misma respuesta byte a byte para una empresa que no
  existe, un email con cuenta y uno nuevo; lo que cambia es el correo, que
  solo lee el dueño del buzón (aviso sin enlace, o nada); y el mismo tiempo
  (medianas), con un control de sensibilidad;
* e) la verificación: un token usado, desconocido, mal formado, caducado o de
  otro tipo (una invitación) da el mismo 401; un token de verificación no
  sirve como invitación;
* f) el admin: lo no verificado no se ve, un rol en el cuerpo del registro es
  un 422, la aprobación entre empresas es un 404 con su evento, un instructor
  recibe 403, un email que ya tiene cuenta da 409, el rechazo cierra y se
  audita, y una solicitud verificada no se sustituye (sale un aviso);
* g) CR, LF y NUL en el email: 422 sin crear nada ni enviar correo;
* h) el límite por destinatario con su valor de producción (3 en 15
  minutos): el cuarto es 429 con Retry-After y otro email sigue pasando; un
  solo evento, sin el email;
* i) sin Mailpit, la respuesta no cambia y el fallo queda en el log sin el
  email; ni emails, ni tokens, ni enlaces en los logs de la API, PostgreSQL y
  Redis;
* j) sin CANARIO_ORIGEN_PERSONAL, o mal formado, la API no arranca.

Cada prueba negativa lleva su control positivo: si el control falla, el
resultado es SIN CONCLUSION, nunca PASA. Los oráculos son literales.

Cómo se ejecuta (desde la raíz del repositorio, en PowerShell, con Docker en
marcha y los secretos generados con scripts/generar_secretos.py):

    python tests/security/verificar_registro.py

Usa un proyecto de Docker propio (canario_registro) con los perfiles
desarrollo (Mailpit) y gestion. No levanta Caddy: habla con la API por la red
app. Necesita que el proyecto canario y las demás baterías estén parados: la
subred 10.88.0.0/28 es fija (si está en uso, PARADA). Al terminar lo borra
todo (down -v y las imágenes construidas). No lee ningún secreto: la API y
gestion los reciben de secrets/ como Docker secrets, y las APIs temporales de
j) usan secretos falsos. Los ficheros auxiliares van a un directorio temporal
del sistema, nunca al repositorio. La salida completa se guarda en
verificacion_registro.txt dentro del directorio temporal del sistema. El
código de salida es 0 solo si el resultado global es OK.

Solo usa la biblioteca estándar.
"""
import base64
import hashlib
import hmac
import json
import pathlib
import re
import secrets
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import traceback

RAIZ = pathlib.Path.cwd()
PROYECTO = "canario_registro"
SALIDA = pathlib.Path(tempfile.gettempdir()) / "verificacion_registro.txt"
BASE = ["docker", "compose", "-p", PROYECTO, "-f", "docker-compose.yml", "--profile", "desarrollo",
        "--profile", "gestion"]

lineas_salida = []
estado = {"falla": False, "sin_conclusion": False}

# ---------------------------------------------------------------------------
# Oráculos literales
# ---------------------------------------------------------------------------
SUBRED_APP = "10.88.0.0/28"
ORIGEN_PERSONAL = "https://localhost:8445"
TEXTO_ORIGEN = "ORIGEN PERSONAL: https://localhost:8445"
TEXTO_BLOQUEADO = "ARRANQUE BLOQUEADO: "
LIMITES_PRUEBA = ("denuncia=1000/3600,seguimiento=1000/60,mensajes=1000/3600,acceso=1000/300,otras=1000/60,"
                  "cuenta=1000/60,registro=1000/3600,destinatario=1000/900")
# h) El de producción para destinatario (3 cada 15 minutos); el resto, altos.
LIMITES_DESTINATARIO = ("denuncia=1000/3600,seguimiento=1000/60,mensajes=1000/3600,acceso=1000/300,otras=1000/60,"
                        "cuenta=1000/60,registro=1000/3600,destinatario=3/900")
VENTANA_DESTINATARIO = 900

# Mailpit (docker-compose.yml)
USUARIO_MAILPIT = "10003:10003"
MEMORIA_MAILPIT = 134217728  # 128m
PIDS = 64

# Respuestas (app/rutas_personal.py y app/frontera_http.py)
CUERPO_202 = '{"mensaje":"si los datos son correctos, recibirá un correo en unos minutos"}'.encode()
CUERPO_401 = '{"detalle": "solicitud no válida"}'.encode()
CUERPO_401_INVITACION = '{"detalle": "invitación no válida"}'.encode()
CUERPO_404 = b'{"detalle": "recurso no encontrado"}'
CUERPO_409 = b'{"detalle": "ya existe una cuenta con ese email"}'
CUERPO_422 = '{"detalle": "petición no válida"}'.encode()
CUERPO_429 = '{"detalle": "demasiadas peticiones; inténtelo de nuevo más tarde"}'.encode()
TIPO_JSON = "application/json"

# Correos (app/solicitudes.py)
REMITENTE = "no-responder@canario.invalid"
ASUNTO_VERIFICACION = "Confirme su email para registrarse en Canario"
ASUNTO_AVISO_CUENTA = "Intento de registro con su email en Canario"
ASUNTO_AVISO_PENDIENTE = "Su solicitud de registro en Canario sigue pendiente"
ASUNTO_INVITACION = "Active su cuenta del personal en Canario"
PATRON_VERIFICACION = re.compile(r"https://localhost:8445/registro/verificacion#([0-9a-f]{32}\.[A-Za-z0-9_-]{43})")
PATRON_ACTIVACION = re.compile(r"https://localhost:8445/activacion#([0-9a-f]{32}\.[A-Za-z0-9_-]{43})")
ACCION_APROBACION = "aprobacion_registro"
ACCION_RECHAZO = "rechazo_registro"
TEXTO_EVENTO_DESTINATARIO = "EVENTO limite_destinatario"
TEXTO_EVENTO_CORREO = "EVENTO correo_fallido: tipo=verificacion error="
TEXTO_EVENTO_DENEGADO = "EVENTO acceso_denegado: "
CLAVES_APROBACION = ["usuario_id"]
CLAVES_LISTADO = ["hay_mas", "solicitudes"]
CLAVES_SOLICITUD = ["email", "solicitud_id"]

PATRON_ALTA = re.compile(r"empresa creada: empresa_id=([0-9a-f-]{36}) identificador_publico=([0-9a-f]{32})")
PATRON_INVITACION_GESTION = re.compile(r"token_invitacion=([0-9a-f]{32}\.[A-Za-z0-9_-]{43})\n")
EMPRESA_INEXISTENTE = "0" * 32

# Cliente HTTP: corre con la imagen de la API en la red app, directo a la
# API. Mide cada petición en milisegundos.
CLIENTE_HTTP = r'''
import base64, http.client, json, sys, time

def una(pt):
    conexion = None
    try:
        conexion = http.client.HTTPConnection("api", 8000, timeout=30)
        conexion.connect()
        cuerpo = base64.b64decode(pt["cuerpo"]) if pt.get("cuerpo") is not None else None
        inicio = time.perf_counter()
        conexion.request(pt["metodo"], pt["ruta"], body=cuerpo, headers=pt.get("cabeceras", {}))
        respuesta = conexion.getresponse()
        datos = respuesta.read()
        ms = (time.perf_counter() - inicio) * 1000
        return {"estado": respuesta.status, "cuerpo": base64.b64encode(datos).decode("ascii"),
                "cabeceras": {k.lower(): v for k, v in respuesta.getheaders()}, "ms": ms}
    except Exception as error:
        return {"error": type(error).__name__, "metodo": pt["metodo"], "ruta": pt["ruta"]}
    finally:
        if conexion is not None:
            conexion.close()

print(json.dumps([una(pt) for pt in json.load(sys.stdin)]))
'''

# Lector del buzón de Mailpit por su API HTTP, desde la red correo (la única
# donde está). "borrar" vacía el buzón.
LECTOR_CORREO = r'''
import json, sys, urllib.request
orden = json.load(sys.stdin)
base = "http://mailpit:8025/api/v1"
if orden == "borrar":
    urllib.request.urlopen(urllib.request.Request(base + "/messages", method="DELETE"), timeout=10).read()
    print(json.dumps("borrado"))
    sys.exit()
lista = json.load(urllib.request.urlopen(base + "/messages?limit=1000", timeout=10))
salida = []
for m in lista.get("messages") or []:
    d = json.load(urllib.request.urlopen(base + "/message/" + m["ID"], timeout=10))
    salida.append({"para": [a["Address"] for a in d.get("To") or []], "de": (d.get("From") or {}).get("Address"),
                   "asunto": d.get("Subject"), "texto": d.get("Text")})
print(json.dumps(salida))
'''

PRUEBA_SALIDA = ("import socket\n"
                 "try:\n"
                 "    socket.create_connection(('1.1.1.1', 443), timeout=5).close(); print('CONECTA')\n"
                 "except OSError as e:\n"
                 "    print('SIN_SALIDA', type(e).__name__)\n")


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


def sup(sql):
    """SQL como superusuario por el socket del contenedor (peer)."""
    return dc("exec", "-T", "postgres", "psql", "-U", "postgres", "-d", "canario", "-X", "-q",
              "-A", "-t", "-v", "ON_ERROR_STOP=1", "-f", "-", entrada=sql.encode("utf-8"))


def valor(sql):
    r = sup(sql)
    if r.rc != 0:
        raise Parada(f"consulta como superusuario fallida: {r.err.strip()[:300]}")
    return r.out.strip()


def pasa(cond, texto):
    p(("PASA  " if cond else "FALLA ") + texto)
    if not cond:
        estado["falla"] = True


def sinc(texto):
    p("SIN CONCLUSION " + texto)
    estado["sin_conclusion"] = True


def negativo(nombre, cond, control_ok, detalle=""):
    """Prueba negativa con control: si el control falla, SIN CONCLUSION."""
    if not control_ok:
        sinc(f"{nombre}: el control positivo fallo {detalle}".rstrip())
        return
    pasa(cond, nombre)
    if not cond and detalle:
        p(f"   {detalle}")


def esperar(condicion, maximo):
    limite = time.monotonic() + maximo
    while time.monotonic() < limite:
        if condicion():
            return True
        time.sleep(1)
    return condicion()


def contenedor(servicio):
    cid = dc("ps", "-q", servicio).out.strip()
    if not cid:
        raise Parada(f"no hay contenedor para el servicio {servicio}")
    return cid


def inspeccionar(objeto, formato="{{json .}}"):
    r = ejecutar(["docker", "inspect", "--format", formato, objeto])
    if r.rc != 0:
        raise Parada(f"docker inspect {objeto} fallo: {r.err.strip()[:200]}")
    return json.loads(r.out)


def log_de(servicio):
    return dc("logs", "--no-color", "--no-log-prefix", servicio).todo


TEMPORAL = None
IMAGEN_API = ""
ESTADO_GIT_ARRANQUE = None
# Lo que no debe aparecer en ningún log: emails y tokens de la batería.
SENSIBLES = set()


# ---------------------------------------------------------------------------
# HTTP, correo y TOTP de la batería
# ---------------------------------------------------------------------------
def http(peticiones):
    r = ejecutar(["docker", "run", "--rm", "-i", "--network", f"{PROYECTO}_app", "--read-only",
                  "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                  "--entrypoint", "python", IMAGEN_API, "-c", CLIENTE_HTTP],
                 entrada=json.dumps(peticiones).encode("utf-8"))
    try:
        respuestas = json.loads(r.out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise Parada(f"el cliente HTTP no devolvio resultado: {r.err.strip()[-400:]!r}") from None
    for respuesta in respuestas:
        if "error" in respuesta:
            p(f"  [cliente HTTP] {respuesta['error']} en {respuesta['metodo']} {respuesta['ruta']}")
        if "cuerpo" in respuesta:
            respuesta["cuerpo"] = base64.b64decode(respuesta["cuerpo"])
    return respuestas


def una(peticion):
    return http([peticion])[0]


def pt(metodo, ruta, datos=None, token=None, crudo=None):
    cabeceras = {"Content-Type": "application/json"}
    if isinstance(token, Sesion):
        token = token.vigente()
    if token is not None:
        cabeceras["Authorization"] = f"Bearer {token}"
    if crudo is None and datos is not None:
        crudo = json.dumps(datos, ensure_ascii=False).encode("utf-8")
    peticion = {"metodo": metodo, "ruta": ruta, "cabeceras": cabeceras}
    if crudo is not None:
        peticion["cuerpo"] = base64.b64encode(crudo).decode("ascii")
    return peticion


def json_de(respuesta):
    try:
        return json.loads(respuesta["cuerpo"].decode("utf-8"))
    except (KeyError, ValueError, UnicodeDecodeError):
        return None


def es(respuesta, codigo, cuerpo):
    return (respuesta.get("estado") == codigo and respuesta.get("cuerpo") == cuerpo
            and respuesta.get("cabeceras", {}).get("content-type") == TIPO_JSON)


def registro(empresa, email):
    SENSIBLES.add(email)
    return pt("POST", "/v1/personal/registro", {"empresa": empresa, "email": email})


def verificacion(token):
    return pt("POST", "/v1/personal/registro/verificacion", {"token": token})


def buzon(orden="leer"):
    r = ejecutar(["docker", "run", "--rm", "-i", "--network", f"{PROYECTO}_correo", "--read-only",
                  "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                  "--entrypoint", "python", IMAGEN_API, "-c", LECTOR_CORREO],
                 entrada=json.dumps(orden).encode("utf-8"))
    try:
        return json.loads(r.out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise Parada(f"no se pudo leer el buzon de Mailpit: {r.err.strip()[-400:]!r}") from None


def correos_para(email):
    return [c for c in buzon() if c["para"] == [email]]


def esperar_correos(email, cuantos, maximo=30):
    """Los correos de email cuando haya al menos cuantos, o los que haya."""
    encontrados = []

    def hay():
        encontrados[:] = correos_para(email)
        return len(encontrados) >= cuantos
    esperar(hay, maximo)
    return list(encontrados)


def token_de(correo_recibido, patron):
    encaje = patron.search(correo_recibido.get("texto") or "")
    if encaje:
        SENSIBLES.add(encaje.group(1))
    return encaje.group(1) if encaje else None


def totp(secreto_texto, paso, digitos=6):
    """TOTP propio de la batería (RFC 6238 sobre RFC 4226), independiente de
    app/cripto.py."""
    clave = base64.b32decode(secreto_texto + "=" * (-len(secreto_texto) % 8))
    mac = hmac.new(clave, paso.to_bytes(8, "big"), hashlib.sha1).digest()
    o = mac[-1] & 0x0F
    return f"{(int.from_bytes(mac[o:o + 4], 'big') & 0x7FFFFFFF) % 10 ** digitos:0{digitos}d}"


ULTIMO_PASO = {}


def codigo_libre(secreto):
    """Código del paso actual sin usar; si ya se usó, espera al siguiente
    (como tests/security/verificar_personal.py)."""
    while True:
        actual = int(time.time()) // 30
        if actual > ULTIMO_PASO.get(secreto, -1):
            return totp(secreto, actual), actual
        time.sleep(30 - time.time() % 30 + 0.5)


class Cuenta:
    def __init__(self, empresa, email):
        self.empresa, self.email = empresa, email
        self.contrasena = secrets.token_urlsafe(18)
        self.secreto = None
        self.dispositivo = None
        SENSIBLES.add(email)


def activar(cuenta, token):
    """Activa la cuenta con el token de su invitación. Cierto si termina."""
    SENSIBLES.add(token)
    r1 = una(pt("POST", "/v1/personal/activacion", {"token": token, "contrasena": cuenta.contrasena}))
    cuenta.secreto = (json_de(r1) or {}).get("secreto_totp")
    if r1.get("estado") != 200 or not cuenta.secreto:
        return False
    codigo, paso = codigo_libre(cuenta.secreto)
    r2 = una(pt("POST", "/v1/personal/activacion/confirmar", {"token": token, "codigo_totp": codigo}))
    if r2.get("estado") != 200:
        return False
    ULTIMO_PASO[cuenta.secreto] = paso
    cuenta.dispositivo = (json_de(r2) or {}).get("token_dispositivo")
    SENSIBLES.add(cuenta.dispositivo)
    return True


class Sesion:
    """Acceso y renovación; renueva el acceso pasados 4 minutos."""

    def __init__(self, datos):
        self.jwt, self.renovacion = datos["token_acceso"], datos["token_renovacion"]
        self.desde = time.monotonic()

    def vigente(self):
        if time.monotonic() - self.desde > 240:
            r = una(pt("POST", "/v1/personal/sesiones/renovacion", {"token_renovacion": self.renovacion}))
            datos = json_de(r) or {}
            if r.get("estado") == 200:
                self.jwt, self.renovacion = datos["token_acceso"], datos["token_renovacion"]
                self.desde = time.monotonic()
        return self.jwt


def iniciar_sesion(cuenta):
    codigo, paso = codigo_libre(cuenta.secreto)
    r = una(pt("POST", "/v1/personal/sesiones", {
        "empresa": cuenta.empresa, "email": cuenta.email, "contrasena": cuenta.contrasena, "codigo_totp": codigo,
        "token_dispositivo": cuenta.dispositivo}))
    if r.get("estado") != 201:
        return None
    ULTIMO_PASO[cuenta.secreto] = paso
    return Sesion(json_de(r))


def listado(sesion):
    return json_de(una(pt("GET", "/v1/personal/solicitudes", token=sesion))) or {}


def id_de(sesion, email):
    """El id de la solicitud de ese email en el listado del admin, o None."""
    return next((s["solicitud_id"] for s in listado(sesion).get("solicitudes", []) if s["email"] == email), None)


def gestion(*args):
    return dc("run", "--rm", "-T", "gestion", *args)


def con_limites(limites):
    """Recrea la API con esos límites (CANARIO_LIMITES en un compose adicional)."""
    fichero = TEMPORAL / f"limites_{secrets.token_hex(4)}.yml"
    fichero.write_text(f"services:\n  api:\n    environment:\n      CANARIO_LIMITES: \"{limites}\"\n",
                       encoding="utf-8", newline="\n")
    r = ejecutar(BASE + ["-f", str(fichero), "up", "-d", "--wait", "api"])
    if r.rc != 0:
        p(r.todo.strip()[-1500:])
        raise Parada("la API no arranca con los limites pedidos")
    return fichero


# ---------------------------------------------------------------------------
# Secciones
# ---------------------------------------------------------------------------
EMPRESAS = {}
ADMINS = {}
SESIONES = {}
LIMITES_ACTUALES = None


def seccion_a():
    global IMAGEN_API, LIMITES_ACTUALES
    p("=== a) arranque: API con su origen y Mailpit endurecido en una red interna")
    LIMITES_ACTUALES = TEMPORAL / "limites.yml"
    LIMITES_ACTUALES.write_text(f"services:\n  api:\n    environment:\n      CANARIO_LIMITES: \"{LIMITES_PRUEBA}\"\n",
                                encoding="utf-8", newline="\n")
    r = ejecutar(BASE + ["-f", str(LIMITES_ACTUALES), "up", "-d", "--build", "--wait", "api", "mailpit"])
    p(f"up -d --build --wait api mailpit -> codigo {r.rc}")
    if r.rc != 0:
        p(r.todo.strip()[-1500:])
        raise Parada("no arranca la pila con Mailpit")
    IMAGEN_API = inspeccionar(contenedor("api"), "{{json .Config.Image}}")
    pasa(TEXTO_ORIGEN in log_de("api"), f"a) la API registra el origen de la SPA ({TEXTO_ORIGEN!r})")
    i = inspeccionar(contenedor("mailpit"))
    hc = i["HostConfig"]
    pasa(i["Config"]["User"] == USUARIO_MAILPIT, f"a) mailpit: User = {i['Config']['User']!r}")
    pasa(hc["ReadonlyRootfs"] is True, f"a) mailpit: ReadonlyRootfs = {hc['ReadonlyRootfs']}")
    pasa(hc["CapDrop"] == ["ALL"] and not hc["CapAdd"], f"a) mailpit: CapDrop = {hc['CapDrop']}, CapAdd = {hc['CapAdd']}")
    pasa(hc["SecurityOpt"] == ["no-new-privileges:true"], f"a) mailpit: SecurityOpt = {hc['SecurityOpt']}")
    pasa(hc["Memory"] == MEMORIA_MAILPIT and hc["PidsLimit"] == PIDS,
         f"a) mailpit: Memory = {hc['Memory']}, PidsLimit = {hc['PidsLimit']}")
    redes = sorted(i["NetworkSettings"]["Networks"])
    pasa(redes == [f"{PROYECTO}_correo"], f"a) mailpit: solo en la red correo ({redes})")
    publicados = {k: v for k, v in (i["NetworkSettings"]["Ports"] or {}).items() if v}
    pasa(not publicados and not hc["PortBindings"], f"a) mailpit: sin puertos publicados ({publicados})")
    estado_salud = inspeccionar(contenedor("mailpit"), "{{json .State.Health.Status}}")
    pasa(estado_salud == "healthy", f"a) mailpit: healthy con su healthcheck ({estado_salud})")
    red = inspeccionar(f"{PROYECTO}_correo")
    pasa(red["Internal"] is True, f"a) la red correo es interna ({red['Internal']})")
    control = ejecutar(["docker", "run", "--rm", "--network", "bridge", "--entrypoint", "python", IMAGEN_API,
                        "-c", PRUEBA_SALIDA])
    desde_correo = ejecutar(["docker", "run", "--rm", "--network", f"{PROYECTO}_correo", "--entrypoint", "python",
                             IMAGEN_API, "-c", PRUEBA_SALIDA])
    negativo(f"a) desde la red correo no se llega a 1.1.1.1:443 ({desde_correo.out.strip()})",
             desde_correo.out.startswith("SIN_SALIDA"), control.out.strip() == "CONECTA",
             f"control en la red bridge: {control.out.strip()!r}")


def seccion_b():
    p("=== b) preparacion: dos empresas con su admin activado")
    for clave in ("A", "B"):
        r = gestion("alta-empresa", "--nombre", f"Empresa Registro {clave}", "--zona", "Europe/Madrid")
        alta = PATRON_ALTA.search(r.out)
        if r.rc != 0 or alta is None:
            raise Parada(f"no se pudo dar de alta la empresa {clave}: {r.err.strip()[-300:]!r}")
        EMPRESAS[clave] = (alta.group(1), alta.group(2))
        admin = Cuenta(alta.group(2), f"admin.{clave.lower()}@registro.test")
        r = gestion("alta-admin", "--identificador", alta.group(2), "--email", admin.email)
        invitacion = PATRON_INVITACION_GESTION.search(r.out)
        if r.rc != 0 or invitacion is None or not activar(admin, invitacion.group(1)):
            raise Parada(f"no se pudo activar el admin de {clave}: {r.err.strip()[-300:]!r}")
        ADMINS[clave] = admin
        SESIONES[clave] = iniciar_sesion(admin)
        if SESIONES[clave] is None:
            raise Parada(f"no se pudo iniciar sesion con el admin de {clave}")
    pasa(True, f"b) empresas A y B con su admin activado y en sesion ({EMPRESAS['A'][1]}, {EMPRESAS['B'][1]})")
    buzon("borrar")


def seccion_c():
    p("=== c) control de extremo a extremo: registro, verificacion, aprobacion, activacion y login")
    ident = EMPRESAS["A"][1]
    email = "nueva.persona@registro.test"
    r = una(registro(ident, email))
    pasa(es(r, 202, CUERPO_202), f"c) POST /registro -> 202 con el cuerpo fijo ({r.get('estado')}, {r.get('cuerpo')!r})")
    correos = esperar_correos(email, 1)
    correo = correos[0] if correos else {}
    token = token_de(correo, PATRON_VERIFICACION)
    pasa(len(correos) == 1 and correo.get("asunto") == ASUNTO_VERIFICACION and correo.get("de") == REMITENTE
         and token is not None and token.startswith(ident + "."),
         f"c) llega un correo de verificacion con el enlace a la SPA y el token en el fragmento "
         f"({len(correos)}, {correo.get('asunto')!r})")
    if token is None:
        raise Parada("sin el correo de verificacion no se puede seguir")
    pasa(token not in (correo.get("asunto") or ""), "c) el token no va en el asunto")
    # Sin verificar, el admin no la ve.
    antes = listado(SESIONES["A"])
    pasa(sorted(antes) == CLAVES_LISTADO and antes.get("solicitudes") == [] and antes.get("hay_mas") is False,
         f"c) sin verificar, el admin no ve la solicitud ({antes})")
    r = una(verificacion(token))
    pasa(r.get("estado") == 204 and r.get("cuerpo") == b"", f"c) POST /registro/verificacion -> 204 ({r.get('estado')})")
    despues = listado(SESIONES["A"])
    filas = despues.get("solicitudes") or []
    pasa(len(filas) == 1 and sorted(filas[0]) == CLAVES_SOLICITUD and filas[0]["email"] == email,
         f"c) verificada, aparece en el listado del admin con solo id y email ({despues})")
    solicitud = filas[0]["solicitud_id"] if filas else "x"
    r = una(pt("POST", f"/v1/personal/solicitudes/{solicitud}/aprobacion", {"rol": "instructor"}, token=SESIONES["A"]))
    datos = json_de(r) or {}
    pasa(r.get("estado") == 201 and sorted(datos) == CLAVES_APROBACION,
         f"c) aprobacion -> 201 con solo el id de la cuenta, sin token de invitacion ({r.get('estado')}, {sorted(datos)})")
    invitaciones = [c for c in esperar_correos(email, 2) if c["asunto"] == ASUNTO_INVITACION]
    token_invitacion = token_de(invitaciones[0], PATRON_ACTIVACION) if invitaciones else None
    pasa(len(invitaciones) == 1 and token_invitacion is not None,
         f"c) la invitacion llega solo al email verificado, con el enlace de activacion ({len(invitaciones)})")
    persona = Cuenta(ident, email)
    activada = token_invitacion is not None and activar(persona, token_invitacion)
    pasa(activada, "c) la persona activa su cuenta con el enlace del correo (contrasena y TOTP)")
    sesion = iniciar_sesion(persona) if activada else None
    yo = json_de(una(pt("GET", "/v1/personal/yo", token=sesion))) if sesion else {}
    pasa(bool(yo) and yo.get("rol") == "instructor" and yo.get("email") == email,
         f"c) y entra con el rol que eligio el admin ({(yo or {}).get('rol')})")
    filas = (json_de(una(pt("GET", "/v1/personal/auditoria", token=SESIONES["A"]))) or {}).get("filas", [])
    aprobaciones = [f for f in filas if f["accion"] == ACCION_APROBACION]
    pasa(len(aprobaciones) == 1 and aprobaciones[0]["objeto_id"] == datos.get("usuario_id")
         and aprobaciones[0]["actor"].startswith("personal:"),
         f"c) la aprobacion queda en la auditoria con el admin y la cuenta creada ({aprobaciones})")
    r = una(verificacion(token))
    pasa(es(r, 401, CUERPO_401), f"c) el enlace de verificacion ya usado da 401 ({r.get('estado')})")
    estado["c_ok"] = activada and sesion is not None


def seccion_d():
    p("=== d) enumeracion: misma respuesta, el correo solo lo lee el dueno, y el mismo tiempo")
    buzon("borrar")
    ident = EMPRESAS["A"][1]
    casos = {"empresa inexistente": registro(EMPRESA_INEXISTENTE, "inexistente@registro.test"),
             "email con cuenta": registro(ident, ADMINS["A"].email),
             "email nuevo": registro(ident, "otra.nueva@registro.test")}
    respuestas = dict(zip(casos, http(list(casos.values()))))
    # Todo menos la fecha, que cambia de una respuesta a otra.
    huellas = {k: (v.get("estado"), v.get("cuerpo"),
                   sorted((c, x) for c, x in (v.get("cabeceras") or {}).items() if c != "date"))
               for k, v in respuestas.items()}
    pasa(all(es(v, 202, CUERPO_202) for v in respuestas.values()) and len({repr(h) for h in huellas.values()}) == 1,
         f"d) las tres responden 202 con el mismo cuerpo y las mismas cabeceras ({[v.get('estado') for v in respuestas.values()]})")
    nuevo = esperar_correos("otra.nueva@registro.test", 1)
    aviso = esperar_correos(ADMINS["A"].email, 1)
    control = len(nuevo) == 1 and nuevo[0]["asunto"] == ASUNTO_VERIFICACION
    pasa(control, f"d) control: el email nuevo recibe su enlace de verificacion ({len(nuevo)})")
    negativo("d) el email con cuenta recibe un aviso, sin enlace",
             len(aviso) == 1 and aviso[0]["asunto"] == ASUNTO_AVISO_CUENTA and "https://" not in aviso[0]["texto"],
             control, f"correos: {aviso}")
    negativo("d) para una empresa que no existe no sale ningun correo",
             correos_para("inexistente@registro.test") == [], control)
    filas = valor("select count(*) from canal.solicitud_registro where email = 'inexistente@registro.test';")
    negativo(f"d) ni se guarda nada ({filas} filas)", filas == "0", control)

    # Tiempos: muestras intercaladas de los tres caminos; cada email nuevo es
    # distinto (cada uno crea su solicitud). Control de sensibilidad: un 422
    # (sin base de datos ni Redis) se distingue de un registro.
    muestras = {"inexistente": [], "cuenta": [], "nuevo": [], "sin_bd": []}
    for vuelta in range(10):
        tanda = []
        for i in range(4):
            tanda += [registro(EMPRESA_INEXISTENTE, "tiempos@registro.test"),
                      registro(ident, ADMINS["A"].email),
                      registro(ident, f"tiempo.{vuelta}.{i}@registro.test"),
                      pt("POST", "/v1/personal/registro", {"empresa": ident})]
        res = http(tanda)
        for j, nombre in enumerate(["inexistente", "cuenta", "nuevo", "sin_bd"] * 4):
            if "ms" in res[j]:
                muestras[nombre].append(res[j]["ms"])
    mediana = {k: statistics.median(v) for k, v in muestras.items() if v}
    p("   medianas en ms: " + ", ".join(f"{k}={v:.1f}" for k, v in mediana.items()))
    if len(mediana) != 4:
        sinc("d) faltan muestras de tiempo")
        return
    control = mediana["inexistente"] - mediana["sin_bd"] >= 2
    negativo("d) tiempos: empresa inexistente y email con cuenta difieren menos de 3 ms",
             abs(mediana["inexistente"] - mediana["cuenta"]) < 3, control,
             f"control: un registro no se distingue de un 422 ({mediana})")
    negativo("d) tiempos: empresa inexistente y email nuevo difieren menos de 3 ms",
             abs(mediana["inexistente"] - mediana["nuevo"]) < 3, control, f"{mediana}")


def seccion_e():
    p("=== e) verificacion: el mismo 401 para todo lo que no vale")
    buzon("borrar")
    ident_a, ident_b = EMPRESAS["A"][1], EMPRESAS["B"][1]
    http([registro(ident_a, "e.uno@registro.test"), registro(ident_a, "e.dos@registro.test"),
          registro(ident_b, "e.tres@registro.test")])
    tokens = {}
    for email in ("e.uno@registro.test", "e.dos@registro.test", "e.tres@registro.test"):
        correos = esperar_correos(email, 1)
        tokens[email] = token_de(correos[0], PATRON_VERIFICACION) if correos else None
    if None in tokens.values():
        sinc(f"e) no llegaron los tres correos de verificacion ({tokens})")
        return
    uno, dos, tres = tokens.values()
    # Un token de verificación no sirve como invitación (etiquetas distintas).
    r = una(pt("POST", "/v1/personal/activacion", {"token": uno, "contrasena": "una-contrasena-larga"}))
    pasa(es(r, 401, CUERPO_401_INVITACION), f"e) el token de verificacion no vale como invitacion ({r.get('estado')})")
    # El token con el identificador de otra empresa: la huella no existe en ella.
    cruzado = ident_b + "." + uno.split(".")[1]
    # Caducado: se adelanta su caducidad como superusuario con el trigger
    # desactivado solo en esa transacción.
    sup("BEGIN;\nALTER TABLE canal.solicitud_registro DISABLE TRIGGER solicitud_registro_transicion;\n"
        "UPDATE canal.solicitud_registro SET caduca = now() - interval '1 second' WHERE email = 'e.dos@registro.test';\n"
        "ALTER TABLE canal.solicitud_registro ENABLE TRIGGER solicitud_registro_transicion;\nCOMMIT;\n")
    malos = {"desconocido": f"{ident_a}.{'A' * 43}", "mal formado": "no-es-un-token",
             "empresa inexistente": f"{EMPRESA_INEXISTENTE}.{uno.split('.')[1]}",
             "de otra empresa": cruzado, "caducado": dos, "vacio": ""}
    respuestas = dict(zip(malos, http([verificacion(t) for t in malos.values()])))
    control = una(verificacion(uno))
    control_ok = control.get("estado") == 204
    pasa(control_ok, f"e) control: el token bueno verifica despues de todos los malos ({control.get('estado')})")
    for nombre, r in respuestas.items():
        negativo(f"e) token {nombre} -> 401 con el mismo cuerpo ({r.get('estado')})", es(r, 401, CUERPO_401), control_ok)
    r = una(verificacion(tres))
    pasa(r.get("estado") == 204, f"e) el de la empresa B verifica en B ({r.get('estado')})")


def seccion_f():
    p("=== f) administracion de solicitudes")
    buzon("borrar")
    ident = EMPRESAS["A"][1]
    # Un rol (o una contraseña) en el cuerpo: 422 y nada creado.
    con_rol = pt("POST", "/v1/personal/registro", {"empresa": ident, "email": "f.rol@registro.test", "rol": "admin"})
    con_contrasena = pt("POST", "/v1/personal/registro",
                        {"empresa": ident, "email": "f.rol@registro.test", "contrasena": "x" * 20})
    r1, r2 = http([con_rol, con_contrasena])
    filas = valor("select count(*) from canal.solicitud_registro where email = 'f.rol@registro.test';")
    pasa(es(r1, 422, CUERPO_422) and es(r2, 422, CUERPO_422) and filas == "0",
         f"f) un rol o una contrasena en el cuerpo del registro -> 422 sin crear nada ({r1.get('estado')}, "
         f"{r2.get('estado')}, {filas} filas)")
    # Dos solicitudes verificadas en A.
    emails = ["f.cruzada@registro.test", "f.rechazada@registro.test", "f.duplicada@registro.test"]
    http([registro(ident, e) for e in emails])
    for e in emails:
        correos = esperar_correos(e, 1)
        token = token_de(correos[0], PATRON_VERIFICACION) if correos else None
        if token is None or una(verificacion(token)).get("estado") != 204:
            sinc(f"f) no se pudo preparar la solicitud verificada de {e}")
            return
    ids = {e: id_de(SESIONES["A"], e) for e in emails}
    control = all(ids.values())
    pasa(control, "f) control: las tres solicitudes verificadas aparecen al admin de A")
    # B no ve las de A, y aprobar una de A desde B es el 404 de lo inexistente.
    visto_b = [s["email"] for s in listado(SESIONES["B"]).get("solicitudes", [])]
    negativo(f"f) el admin de B no ve las solicitudes de A ({visto_b})", not set(visto_b) & set(emails), control)
    eventos_antes = log_de("api").count(TEXTO_EVENTO_DENEGADO)
    r = una(pt("POST", f"/v1/personal/solicitudes/{ids[emails[0]]}/aprobacion", {"rol": "admin"}, token=SESIONES["B"]))
    negativo(f"f) aprobar desde B una solicitud de A -> 404 ({r.get('estado')})", es(r, 404, CUERPO_404), control)
    negativo("f) y deja EVENTO acceso_denegado", log_de("api").count(TEXTO_EVENTO_DENEGADO) > eventos_antes, control)
    sigue = id_de(SESIONES["A"], emails[0]) is not None
    negativo("f) la solicitud sigue pendiente en A", sigue, control)
    # Un instructor no administra solicitudes.
    instructor = Cuenta(ident, "f.instructor@registro.test")
    r = una(pt("POST", "/v1/personal/usuarios", {"email": instructor.email, "rol": "instructor"}, token=SESIONES["A"]))
    token_inv = (json_de(r) or {}).get("token_invitacion")
    sesion_instr = iniciar_sesion(instructor) if token_inv and activar(instructor, token_inv) else None
    if sesion_instr is None:
        sinc("f) no se pudo preparar la cuenta del instructor")
    else:
        lista = una(pt("GET", "/v1/personal/solicitudes", token=sesion_instr))
        aprueba = una(pt("POST", f"/v1/personal/solicitudes/{ids[emails[0]]}/aprobacion", {"rol": "admin"},
                         token=sesion_instr))
        rechaza = una(pt("DELETE", f"/v1/personal/solicitudes/{ids[emails[0]]}", token=sesion_instr))
        pasa(all(x.get("estado") == 403 for x in (lista, aprueba, rechaza)),
             f"f) un instructor recibe 403 al listar, aprobar y rechazar ({lista.get('estado')}, "
             f"{aprueba.get('estado')}, {rechaza.get('estado')})")
    # Rechazo: 204, se audita, y después ni aprobar ni rechazar (404).
    r = una(pt("DELETE", f"/v1/personal/solicitudes/{ids[emails[1]]}", token=SESIONES["A"]))
    pasa(r.get("estado") == 204, f"f) rechazar -> 204 ({r.get('estado')})")
    otra = una(pt("POST", f"/v1/personal/solicitudes/{ids[emails[1]]}/aprobacion", {"rol": "instructor"},
                  token=SESIONES["A"]))
    negativo(f"f) una rechazada ya no se aprueba (404, {otra.get('estado')})", es(otra, 404, CUERPO_404),
             r.get("estado") == 204)
    filas = (json_de(una(pt("GET", "/v1/personal/auditoria", token=SESIONES["A"]))) or {}).get("filas", [])
    pasa(any(f["accion"] == ACCION_RECHAZO and f["objeto_id"] == ids[emails[1]] for f in filas),
         "f) el rechazo queda en la auditoria con el id de la solicitud")
    pasa(correos_para(emails[1]) and all(c["asunto"] == ASUNTO_VERIFICACION for c in correos_para(emails[1])),
         "f) el rechazo no envia correo (solo esta el de verificacion)")
    # Un email que ya tiene cuenta: 409 y la solicitud sigue.
    r = una(pt("POST", "/v1/personal/usuarios", {"email": emails[2], "rol": "instructor"}, token=SESIONES["A"]))
    duplicada = una(pt("POST", f"/v1/personal/solicitudes/{ids[emails[2]]}/aprobacion", {"rol": "instructor"},
                       token=SESIONES["A"]))
    negativo(f"f) aprobar un email que ya tiene cuenta -> 409 ({duplicada.get('estado')})",
             es(duplicada, 409, CUERPO_409), r.get("estado") == 201)
    # Una verificada no se sustituye: el nuevo registro da el mismo 202 y un aviso.
    buzon("borrar")
    r = una(registro(ident, emails[0]))
    avisos = esperar_correos(emails[0], 1)
    negativo("f) repetir el registro de una solicitud verificada: 202, aviso de pendiente y la solicitud sigue",
             es(r, 202, CUERPO_202) and len(avisos) == 1 and avisos[0]["asunto"] == ASUNTO_AVISO_PENDIENTE
             and "https://" not in avisos[0]["texto"] and id_de(SESIONES["A"], emails[0]) == ids[emails[0]],
             control, f"respuesta {r.get('estado')}, correos {avisos}")
    # Una sin verificar sí se sustituye: el enlace anterior deja de valer y el nuevo vale.
    http([registro(ident, "f.repetida@registro.test")])
    primero = esperar_correos("f.repetida@registro.test", 1)
    http([registro(ident, "f.repetida@registro.test")])
    ambos = esperar_correos("f.repetida@registro.test", 2)
    viejo = token_de(primero[0], PATRON_VERIFICACION) if primero else None
    nuevos = [token_de(c, PATRON_VERIFICACION) for c in ambos]
    nuevo = next((t for t in nuevos if t and t != viejo), None)
    if viejo is None or nuevo is None:
        sinc(f"f) no llegaron los dos enlaces de la solicitud repetida ({len(ambos)})")
    else:
        r_viejo, r_nuevo = una(verificacion(viejo)), una(verificacion(nuevo))
        negativo(f"f) repetir una sin verificar invalida el enlace anterior ({r_viejo.get('estado')})",
                 es(r_viejo, 401, CUERPO_401), r_nuevo.get("estado") == 204, f"nuevo: {r_nuevo.get('estado')}")
    # Aprobación con un rol que no existe: 422.
    r = una(pt("POST", f"/v1/personal/solicitudes/{ids[emails[0]]}/aprobacion", {"rol": "superadmin"},
               token=SESIONES["A"]))
    pasa(es(r, 422, CUERPO_422), f"f) aprobar con un rol que no existe -> 422 ({r.get('estado')})")


def seccion_g():
    p("=== g) CR, LF y NUL en el email: 422 sin crear nada ni enviar correo")
    buzon("borrar")
    ident = EMPRESAS["A"][1]
    malos = ["g@registro.test\r\nBcc: otro@registro.test", "g@registro.test\nBcc: otro@registro.test",
             "g@registro.test\x00", "g\x00@registro.test", "g@registro.test\r"]
    respuestas = http([pt("POST", "/v1/personal/registro", {"empresa": ident, "email": m}) for m in malos])
    control = una(registro(ident, "g@registro.test"))
    control_ok = es(control, 202, CUERPO_202)
    for m, r in zip(malos, respuestas):
        negativo(f"g) email {m!r} -> 422 ({r.get('estado')})", es(r, 422, CUERPO_422), control_ok)
    llegados = esperar_correos("g@registro.test", 1)
    otros = [c for c in buzon() if c["para"] != ["g@registro.test"]]
    filas = valor("select count(*) from canal.solicitud_registro where email like 'g@%' or email like 'g%otro%';")
    negativo(f"g) solo existe la solicitud y el correo del control ({filas} filas, {len(otros)} correos ajenos)",
             filas == "1" and not otros and len(llegados) == 1, control_ok)


def seccion_h():
    p("=== h) limite por destinatario con el valor de produccion (3 cada 15 minutos)")
    con_limites(LIMITES_DESTINATARIO)
    ident = EMPRESAS["A"][1]
    # Las cuatro, dentro de la misma ventana de 15 minutos.
    while VENTANA_DESTINATARIO - int(time.time()) % VENTANA_DESTINATARIO < 120:
        time.sleep(10)
    antes = log_de("api").count(TEXTO_EVENTO_DESTINATARIO)
    res = http([registro(ident, "h.buzon@registro.test") for _ in range(4)]
               + [registro(EMPRESA_INEXISTENTE, "h.buzon@registro.test"), registro(ident, "h.otro@registro.test")])
    control = all(es(r, 202, CUERPO_202) for r in res[:3]) and es(res[5], 202, CUERPO_202)
    pasa(control, f"h) control: tres registros al mismo email y uno a otro pasan ({[r.get('estado') for r in res]})")
    for etiqueta, r in (("el cuarto", res[3]), ("el quinto, con otra empresa", res[4])):
        espera = (r.get("cabeceras") or {}).get("retry-after", "")
        negativo(f"h) {etiqueta} al mismo email -> 429 con Retry-After ({r.get('estado')}, {espera!r})",
                 es(r, 429, CUERPO_429) and espera.isdigit() and 1 <= int(espera) <= VENTANA_DESTINATARIO, control)
    eventos = [l for l in log_de("api").splitlines() if TEXTO_EVENTO_DESTINATARIO in l]
    negativo(f"h) un solo EVENTO limite_destinatario, sin el email ({len(eventos) - antes})",
             len(eventos) - antes == 1 and not any("@" in l for l in eventos), control)
    con_limites(LIMITES_PRUEBA)


def seccion_i():
    p("=== i) sin Mailpit la respuesta no cambia y el fallo queda en el log, sin datos")
    ident = EMPRESAS["A"][1]
    dc("stop", "mailpit")
    try:
        antes = log_de("api").count(TEXTO_EVENTO_CORREO)
        r = una(registro(ident, "i.sin.correo@registro.test"))
        aparece = esperar(lambda: log_de("api").count(TEXTO_EVENTO_CORREO) > antes, 30)
    finally:
        dc("start", "mailpit")
    pasa(es(r, 202, CUERPO_202), f"i) con Mailpit parado, el registro responde el mismo 202 ({r.get('estado')})")
    eventos = [l for l in log_de("api").splitlines() if TEXTO_EVENTO_CORREO in l]
    pasa(aparece and not any("@" in l for l in eventos),
         f"i) el fallo deja EVENTO correo_fallido con el tipo y la clase del error, sin el email ({eventos[-1:]})")
    textos = {s: log_de(s) for s in ("api", "postgres", "redis", "mailpit")}
    fugas = sorted({f"{s}" for s, t in textos.items() for v in SENSIBLES if v and v in t and s != "mailpit"})
    negativo(f"i) ningun email, token ni enlace de la bateria aparece en los logs de api, postgres y redis {fugas}",
             not fugas, bool(SENSIBLES) and estado.get("c_ok", False))
    negativo("i) los logs de la API no llevan la ruta de la SPA con un token",
             "#" + ident not in textos["api"], estado.get("c_ok", False))


def seccion_j():
    p("=== j) sin CANARIO_ORIGEN_PERSONAL, o mal formado, la API no arranca")
    d = TEMPORAL / "falsos"
    d.mkdir()
    ficheros = {"contrasena_aplicacion": secrets.token_urlsafe(48), "clave_maestra": secrets.token_hex(32),
                "clave_hmac_codigos": secrets.token_hex(32), "clave_firma_tokens": secrets.token_hex(32),
                "contrasena_redis": secrets.token_urlsafe(48)}
    montajes = []
    for nombre, contenido in ficheros.items():
        (d / nombre).write_text(contenido, encoding="ascii", newline="")
        montajes += ["--mount", f"type=bind,src={d / nombre},dst=/run/secrets/{nombre},readonly"]

    def arrancar(etiqueta, entorno):
        nombre = f"{PROYECTO}_api_{etiqueta}"
        variables = [a for k, v in entorno.items() for a in ("-e", f"{k}={v}")]
        ejecutar(["docker", "run", "-d", "--name", nombre, "--network", f"{PROYECTO}_data", "--read-only",
                  "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", *montajes, *variables, IMAGEN_API])
        try:
            esperar(lambda: ejecutar(["docker", "inspect", "--format", "{{.State.Running}}", nombre]).out.strip()
                    == "false", 60)
            return ejecutar(["docker", "logs", nombre]).todo
        finally:
            ejecutar(["docker", "rm", "-f", nombre])
    control = arrancar("control", {"CANARIO_ORIGEN_PERSONAL": ORIGEN_PERSONAL})
    control_ok = TEXTO_ORIGEN in control and f"{TEXTO_BLOQUEADO}conexion" in control
    pasa(control_ok, "j) control: con el origen bien formado la API lo registra y llega a la conexion "
                     "(que falla por la contrasena falsa)")
    casos = {
        "sin variable": ({}, "origen_personal: CANARIO_ORIGEN_PERSONAL: obligatoria (origen https de la SPA del personal)"),
        "http": ({"CANARIO_ORIGEN_PERSONAL": "http://localhost:8445"},
                 "origen_personal: CANARIO_ORIGEN_PERSONAL: se espera https://host o https://host:puerto, en minusculas"),
        "con ruta": ({"CANARIO_ORIGEN_PERSONAL": "https://localhost:8445/"},
                     "origen_personal: CANARIO_ORIGEN_PERSONAL: se espera https://host o https://host:puerto, en minusculas"),
        "puerto 443": ({"CANARIO_ORIGEN_PERSONAL": "https://localhost:443"},
                       "origen_personal: CANARIO_ORIGEN_PERSONAL: puerto no valido (el 443 se omite)"),
    }
    for etiqueta, (entorno, motivo) in casos.items():
        log = arrancar(etiqueta.replace(" ", "_"), entorno)
        negativo(f"j) {etiqueta}: la API no arranca y registra {TEXTO_BLOQUEADO + motivo!r}",
                 TEXTO_BLOQUEADO + motivo in log and f"{TEXTO_BLOQUEADO}conexion" not in log, control_ok,
                 f"log: {log.strip()[-300:]!r}")


def seccion_s():
    p("=== s) limpieza")
    r = dc("down", "-v", "--rmi", "local")
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
        iguales = final == ESTADO_GIT_ARRANQUE
        pasa(iguales, "s) la bateria no ha modificado el repo (git status igual al del arranque)")
        if not iguales:
            p(f"   al arrancar: {ESTADO_GIT_ARRANQUE}")
            p(f"   al terminar: {final}")


# ---------------------------------------------------------------------------
# Arranque y cierre
# ---------------------------------------------------------------------------
def terminar():
    if estado["falla"] or estado["sin_conclusion"]:
        resultado = "NO OK (hay FALLA o SIN CONCLUSION)"
    else:
        resultado = "OK"
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
    if r.rc != 0:
        return None
    return [l.rstrip() for l in r.out.splitlines() if l.strip()]


def recursos_previos():
    previos = []
    for orden in (["docker", "ps", "-a", "--format", "{{.Names}}"],
                  ["docker", "network", "ls", "--format", "{{.Name}}"],
                  ["docker", "volume", "ls", "--format", "{{.Name}}"]):
        previos += [n for n in ejecutar(orden).out.split() if n.startswith(PROYECTO)]
    return previos


def subred_ocupada():
    for red in ejecutar(["docker", "network", "ls", "-q"]).out.split():
        r = ejecutar(["docker", "network", "inspect", "--format",
                      "{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}", red])
        partes = r.out.split()
        if partes and SUBRED_APP in partes[1:]:
            return partes[0]
    return None


def main():
    global ESTADO_GIT_ARRANQUE, TEMPORAL
    ESTADO_GIT_ARRANQUE = estado_git()
    # Precondiciones: si fallan, no se limpia nada (podrían ser recursos ajenos).
    if ejecutar(["docker", "info", "--format", "{{.ServerVersion}}"]).rc != 0:
        p("PARADA: docker info falla")
        terminar_con_parada()
    previos = recursos_previos()
    if previos:
        p(f"PARADA: ya existen recursos con prefijo {PROYECTO}: {previos}")
        terminar_con_parada()
    ocupada = subred_ocupada()
    if ocupada:
        p(f"PARADA: la subred {SUBRED_APP} ya esta en uso por {ocupada} (pare el proyecto canario)")
        terminar_con_parada()
    r = dc("config", "--quiet")
    if r.rc != 0:
        p(f"PARADA: docker compose config falla (genere los secretos con scripts/generar_secretos.py): "
          f"{r.err.strip()[:300]}")
        terminar_con_parada()
    TEMPORAL = pathlib.Path(tempfile.mkdtemp(prefix="canario_registro_"))
    parada = None
    try:
        for seccion in (seccion_a, seccion_b, seccion_c, seccion_d, seccion_e, seccion_f, seccion_g, seccion_h,
                        seccion_i, seccion_j):
            seccion()
    except Parada as e:
        parada = str(e)
        p(f"PARADA: {parada}")
    except Exception:  # noqa: BLE001 - error inesperado del propio test: se informa y se limpia
        parada = "error inesperado en el test"
        p("ERROR INESPERADO:\n" + traceback.format_exc())
    finally:
        if parada is not None:
            dc("down", "-v", "--rmi", "local")
        else:
            seccion_s()
        shutil.rmtree(TEMPORAL, ignore_errors=True)
    if parada is not None:
        estado["falla"] = True
    terminar()


if __name__ == "__main__":
    main()
