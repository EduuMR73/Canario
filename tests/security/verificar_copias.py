#!/usr/bin/env python3
"""Batería de pruebas de seguridad de las copias de seguridad cifradas
(despliegue/copias.py; docs/operacion.md, "Copias de seguridad", y
docs/threat-model.md, 6.20 y 8).

Qué prueba, con el script real (despliegue/copias.py) ejecutado desde aquí, con
un PostgreSQL de verdad (el de db/Dockerfile con el esquema entero), age 1.3.2
en un contenedor y un servidor falso de Backblaze B2 y de latido en un hilo:

* a) una copia de una base con datos sembrados se descifra con la clave
  principal, se restaura en una instancia nueva con solo db/init/01_roles.sh
  (pg_restore --create --clean --if-exists --exit-on-error) y los recuentos por
  tabla y la cadena de auditoría (verificar_cadena_auditoria y el último hash
  de cada empresa, recalculado aquí en Python) coinciden con el manifiesto y con
  valores literales; la clave de respaldo también descifra;
* b) un fichero cifrado con un byte alterado no se descifra (control: el
  original sí);
* c) una clave age equivocada no descifra (control: la buena sí);
* d) una base vacía sube a cuarentena/ (no a base/), con el motivo en el
  manifiesto, código 6 y /fail (control: con datos, sube a base/);
* e) el protocolo con B2 (autorización v4, URL de subida, SHA1 y longitud, nombre
  único con la hora, ningún X-Bz-Info, token de subida distinto del de cuenta),
  el POST del latido de éxito con el fileId, el SHA1 y los bytes de lo subido, y
  que una clave con capacidades de más, con dos buckets o con prefijo hace que
  el script se niegue sin subir nada (control: solo writeFiles sobre un bucket,
  sube); una clave equivocada y un latido que falla tampoco filtran la clave ni
  la URL del latido;
* f) un proceso de la tubería que falla (el contenedor parado, o age) no sube
  nada, no hace latido de éxito y hace /fail (control: sin fallos, sube y hace
  el latido de éxito);
* g) eventos: solo salen los tipos permitidos (con el formato real del log de la
  API), el cursor lleva el Id del contenedor y avanza sin repetir; una rotación
  del log que se come líneas da el código de hueco, subiendo lo que había, y el
  hueco persiste hasta que se reconoce (control: sin hueco, código 0); una API
  recreada NO da hueco sino el aviso de contenedor nuevo y se exporta todo (el
  control es la rotación real, que sí da hueco); un cursor dañado o en el
  formato antiguo falla de forma visible; el latido de los eventos (ping en cada
  ejecución correcta, /fail con el motivo);
* h) ninguna marca sembrada en claro (ni de la base ni del log) aparece en el
  temporal, en lo subido ni en la salida del script y de esta batería; tampoco
  la clave de B2 (literal ni como base64(id:clave)) ni la URL del latido.
  Control: las marcas sí están en la base restaurada y en el log descifrado, y la
  búsqueda encuentra una marca en un texto de muestra;
* i) una cadena de auditoría rota (manipulada aquí y restaurada después) sube a
  cuarentena/ con código 6, el manifiesto dice cadena_rota_en y hay /fail
  (control: restaurada la cadena, sube a base/);
* j) configuración y B2: destinatarios inválidos (uno solo, uno clásico age1...
  o dos iguales) dan código 3; un bucket distinto del esperado, código 4; una
  subida que devuelve 500 repetido, código 8 y /fail; una confirmación de B2 con
  otro SHA1, código 8; un presupuesto de tiempo agotado, código 10 y /fail;
  argumentos no válidos, código 2; https obligatorio fuera del modo de prueba y
  un abridor sin file:// (cada uno con su control positivo).

Lo que no prueba: el SIGTERM (en Windows no hay forma de mandarlo a un proceso
de Python), Backblaze real (Object Lock, ciclo de vida, la clave
restringida, la respuesta real de b2_authorize_account: el servidor falso sigue
la documentación v4), healthchecks.io real, la sustitución de la clave por el atacante (B2 real), las unidades de systemd ni el
usuario root del VPS. Eso se comprueba en el VPS con docs/operacion.md.

Cada prueba negativa lleva su control positivo: si el control falla, el
resultado es SIN CONCLUSION, nunca PASA. Los oráculos son literales.

Cómo se ejecuta (desde la raíz del repositorio, en PowerShell, con Docker en
marcha y acceso a internet para descargar age):

    python tests/security/verificar_copias.py

Usa un proyecto de Docker propio (canario_copias) con tres instancias de
PostgreSQL (con datos, vacía y la de restauración), contenedores desechables
con el prefijo canario_copias y dos imágenes: canario_copias-postgres (la de
db/Dockerfile) y canario_copias-herramientas (esa más age v1.3.2, bajado de la
release oficial de GitHub con ADD --checksum). No necesita secrets/ ni lo lee:
las contraseñas de la prueba las genera la batería. Al terminar lo borra todo
(down -v, contenedores, imágenes) también si algo falla. Los ficheros auxiliares
van a un directorio temporal del sistema, nunca al repositorio. La salida
completa se guarda en verificacion_copias.txt en el directorio temporal del
sistema. El código de salida es 0 solo si el resultado global es OK.

Solo usa la biblioteca estándar.
"""
import base64
import datetime
import hashlib
import http.server
import importlib.util
import io
import json
import pathlib
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import traceback
import urllib.parse

RAIZ = pathlib.Path.cwd()
PROYECTO = "canario_copias"
SALIDA = pathlib.Path(tempfile.gettempdir()) / "verificacion_copias.txt"
COPIAS = RAIZ / "despliegue" / "copias.py"
IMG_PG = f"{PROYECTO}-postgres"
IMG_HERR = f"{PROYECTO}-herramientas"

lineas_salida = []
estado = {"falla": False, "sin_conclusion": False}

# ---------------------------------------------------------------------------
# Oráculos literales
# ---------------------------------------------------------------------------
# age v1.3.2, linux-amd64. El sha256 es el de la release oficial: el campo
# "digest" del asset en la API de GitHub (repos/FiloSottile/age/releases, tag
# v1.3.2, publicada el 29 de agosto de 2026) y el sha256 del fichero descargado
# a mano coinciden.
AGE_URL = "https://github.com/FiloSottile/age/releases/download/v1.3.2/age-v1.3.2-linux-amd64.tar.gz"
AGE_SHA256 = "cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10"

EMPRESA_A = "a0000000-0000-4000-8000-000000000001"
EMPRESA_B = "b0000000-0000-4000-8000-000000000002"
USUARIO_A = "a0000000-0000-4000-8000-0000000000a1"
USUARIO_B = "b0000000-0000-4000-8000-0000000000b1"
DENUNCIA_A = "a0000000-0000-4000-8000-0000000000d1"
DENUNCIA_B = "b0000000-0000-4000-8000-0000000000d1"
IDENT_A = "a" * 32
IDENT_B = "b" * 32

# Marcas sembradas: nunca deben verse en claro fuera de la base y del log
# descifrado. No se imprimen nunca (solo su etiqueta).
MARCA_EMAIL = "marca-sembrada-7f3a91@ejemplo.test"
MARCA_NOMBRE = "Empresa-MARCA-9c1d44"
MARCA_BYTEA = "MARCA-BYTEA-5e2b87"
MARCA_EVENTO = "MARCA-EVENTO-31ab6f"
MARCAS = {"email": MARCA_EMAIL, "nombre de empresa": MARCA_NOMBRE, "bytes de denuncia": MARCA_BYTEA,
          "evento": MARCA_EVENTO}
# Credenciales de la prueba (las inventa la batería): tampoco deben salir.
B2_ID = "ID-PRUEBA-b2-8c20"
B2_CLAVE = "CLAVE-PRUEBA-b2-4d7e19"
LATIDO_UUID = "6d5c1f7e-2a4b-4c11-9e0a-3b7f55aa1c02"
LATIDO_EVENTOS_UUID = "0b8e24d9-71c3-4f0a-8a55-c1d9e2f6b304"
# Lo que SIEMPRE lleva un tar o un volcado en claro: si aparece fuera del
# cifrado, hay texto plano en el disco o en el envío.
PLANOS = ("PGDMP", "manifiesto.json", "volcado.dump", "eventos.log", "ustar")

# Recuentos esperados tras sembrar (literales, de la siembra de a)).
RECUENTOS = {
    "canal.busqueda_seguimiento": 0, "canal.clave_empresa": 2, "canal.denuncia": 2,
    "canal.directorio_empresas": 2, "canal.dispositivo_personal": 0, "canal.empresa": 2,
    "canal.identidad_externa": 0, "canal.invitacion_personal": 0, "canal.mensaje": 2,
    "canal.registro_auditoria": 4, "canal.sesion_personal": 0, "canal.solicitud_registro": 0,
    "canal.usuario_personal": 2,
}
RECUENTOS_VACIA = {t: 0 for t in RECUENTOS}
ULTIMA_SECUENCIA = {EMPRESA_A: 3, EMPRESA_B: 1}

# Códigos de salida de copias.py (docstring del script).
RC_ERROR, RC_ARGUMENTOS, RC_CONFIG, RC_CLAVE, RC_HUECO, RC_BASE, RC_PROCESO, RC_SUBIDA, RC_LATIDO, RC_TIEMPO = (
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10)

TOKEN_CUENTA = "TOKEN-CUENTA-PRUEBA"
TOKEN_SUBIDA = "TOKEN-SUBIDA-PRUEBA"
BUCKET = "BUCKET-PRUEBA"

# Eventos del log falso: (mensaje, ¿sale?). Literales.
# Formato real: "%(levelname)s %(name)s: %(message)s" (app/principal.py) con el
# mensaje de app/rutas_personal.py (_registrar_redaccion): posiciones y
# longitudes de los tramos ("desde+longitud", separados por comas), nunca texto.
EV_REDACCION = f"WARNING canario.personal: EVENTO redaccion: empresa={EMPRESA_A} cuenta={USUARIO_A} denuncia={DENUNCIA_A} mensaje=- tramos=0+4,10+3"
# Solo para h): una línea permitida con una marca de texto, para comprobar que
# lo exportado no sale en claro. El log real no lleva texto libre.
EV_MARCADO = f"WARNING canario.personal: EVENTO declaracion_no_veraz: empresa={EMPRESA_A} cuenta={USUARIO_A} denuncia={DENUNCIA_A} {MARCA_EVENTO}"
EV_NO_VERAZ = f"WARNING canario.personal: EVENTO declaracion_no_veraz: empresa={EMPRESA_A} cuenta={USUARIO_A} denuncia={DENUNCIA_B}"
EV_REUTILIZACION = f"WARNING canario.personal: EVENTO reutilizacion_renovacion: empresa={EMPRESA_B} usuario={USUARIO_B} sesion={DENUNCIA_A}"
EV_NO_PERMITIDO = f"WARNING canario.personal: EVENTO limite_cuenta: empresa={EMPRESA_A}"
EV_EN_MEDIO = "INFO canario.api: un texto que contiene EVENTO redaccion: falso en medio"
EV_OTRO_LOGGER = "WARNING uvicorn.error: EVENTO redaccion: no es un logger de canario"

# ---------------------------------------------------------------------------
# Utilidades de ejecución y de informe
# ---------------------------------------------------------------------------
class R:
    """Resultado de un comando: código, y stdout y stderr en bytes y en texto."""

    def __init__(self, rc, out, err):
        self.rc, self.out_b, self.err_b = rc, out, err
        self.out, self.err = out.decode("utf-8", "replace"), err.decode("utf-8", "replace")

    @property
    def todo(self):
        return self.out + self.err

    def lineas(self):
        return [l.strip() for l in self.out.splitlines() if l.strip()]


class Parada(Exception):
    pass


def p(texto=""):
    print(texto, flush=True)
    lineas_salida.append(texto)


def ejecutar(args, timeout=900, entrada=None):
    # check=False explícito: el código de salida se comprueba en cada llamada.
    r = subprocess.run(args, capture_output=True, timeout=timeout, check=False, input=entrada)
    return R(r.returncode, r.stdout, r.stderr)


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


TEMPORAL = None      # directorio temporal de la batería (fuera del repo)
CLAVES = None        # claves age de la prueba
DESTINATARIOS = None
SALIDAS_SCRIPT = []  # stdout y stderr de TODAS las ejecuciones de copias.py
SERVIDORES = []      # todos los servidores falsos creados
CONTROLES = {}       # controles de la búsqueda de h)
ESTADO_GIT_ARRANQUE = None
IDS = {}             # nombre de servicio -> id de contenedor
# La clave de B2 tal como viaja en la cabecera Authorization (Basic): también
# se busca así, no solo literal. Calculado aquí con las constantes de la prueba.
B2_BASE64 = base64.b64encode(f"{B2_ID}:{B2_CLAVE}".encode()).decode()

AGE_PRUEBA = ("docker run --rm -i --network none --read-only --cap-drop ALL --security-opt no-new-privileges "
              f"--entrypoint age {IMG_HERR}")


def dc(*args, entrada=None, timeout=900):
    return ejecutar(["docker", "compose", "-p", PROYECTO, "--project-directory", str(TEMPORAL),
                     "-f", str(TEMPORAL / "compose.yml"), *args], entrada=entrada, timeout=timeout)


def esperar_sano(cid, maximo=240):
    salud = ""
    for _ in range(maximo):
        salud = ejecutar(["docker", "inspect", "--format", "{{.State.Health.Status}}", cid]).out.strip()
        if salud == "healthy":
            return salud
        time.sleep(1)
    return salud


def psql(servicio, sql, base="canario"):
    return ejecutar(["docker", "exec", "-i", IDS[servicio], "psql", "-U", "postgres", "-d", base, "-X", "-q",
                     "-A", "-t", "-v", "ON_ERROR_STOP=1", "-f", "-"], entrada=sql.encode("utf-8"))


# ---------------------------------------------------------------------------
# Servidor falso de Backblaze B2 y de latido
# ---------------------------------------------------------------------------
class ServidorB2:
    """Sigue la documentación v4 de B2 (b2_authorize_account, b2_get_upload_url,
    b2_upload_file) y responde a los pings de healthchecks.io (el de la base y el
    de los eventos, con su cuerpo). Registra todo."""

    def __init__(self, capacidades=("writeFiles",), buckets=1, prefijo=None, clave=B2_CLAVE, latido_estado=200,
                 subida_estado=None, sha1_confirmado=None):
        self.capacidades, self.buckets, self.prefijo = list(capacidades), buckets, prefijo
        self.clave, self.latido_estado = clave, latido_estado
        self.subida_estado, self.sha1_confirmado = subida_estado, sha1_confirmado
        self.peticiones = []    # (metodo, ruta sin consulta)
        self.subidas = []       # {"nombre", "cuerpo", "cabeceras"}
        self.latidos = []       # latido de la base: "ok" | "fail"
        self.latidos_eventos = []  # latido de los eventos
        self.pings = []         # {"uuid", "fallo", "metodo", "cuerpo"}
        self.autorizaciones = []
        self.consultas_url = []
        self.intentos_subida = 0
        servidor = self

        class Manejador(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):  # silencio
                pass

            def responder(self, codigo, datos, tipo="application/json"):
                cuerpo = datos if isinstance(datos, bytes) else json.dumps(datos).encode()
                self.send_response(codigo)
                self.send_header("Content-Type", tipo)
                self.send_header("Content-Length", str(len(cuerpo)))
                self.end_headers()
                self.wfile.write(cuerpo)

            def cabeceras(self):
                return {k.lower(): v for k, v in self.headers.items()}

            def tratar(self, metodo):
                ruta, _, consulta = self.path.partition("?")
                cab = self.cabeceras()
                cuerpo = self.rfile.read(int(cab.get("content-length", "0"))) if metodo == "POST" else b""
                servidor.peticiones.append((metodo, ruta))
                if ruta.startswith("/ping/"):
                    partes = ruta.split("/")  # "", "ping", uuid y, quizá, "fail"
                    fallo = len(partes) > 3 and partes[3] == "fail"
                    servidor.pings.append({"uuid": partes[2], "fallo": fallo, "metodo": metodo, "cuerpo": cuerpo})
                    lista = servidor.latidos_eventos if partes[2] == LATIDO_EVENTOS_UUID else servidor.latidos
                    lista.append("fail" if fallo else "ok")
                    return self.responder(servidor.latido_estado, b"OK", "text/plain")
                if metodo == "GET" and ruta == "/b2api/v4/b2_authorize_account":
                    esperado = "Basic " + base64.b64encode(f"{B2_ID}:{servidor.clave}".encode()).decode()
                    servidor.autorizaciones.append(cab.get("authorization") == esperado)
                    if cab.get("authorization") != esperado:
                        return self.responder(401, {"code": "unauthorized", "status": 401,
                                                    "message": "Invalid credentials"})
                    cubos = [{"id": f"{BUCKET}-{i}" if i else BUCKET, "name": f"nombre-{i}"} for i in range(servidor.buckets)]
                    return self.responder(200, {
                        "accountId": "CUENTA-PRUEBA", "authorizationToken": TOKEN_CUENTA,
                        "applicationKeyExpirationTimestamp": None,
                        "apiInfo": {"storageApi": {
                            "absoluteMinimumPartSize": "5000000", "apiUrl": servidor.url,
                            "allowed": {"buckets": cubos, "capabilities": servidor.capacidades,
                                        "namePrefix": servidor.prefijo},
                            "downloadUrl": servidor.url, "recommendedPartSize": "100000000",
                            "s3ApiUrl": servidor.url}}})
                if metodo == "GET" and ruta == "/b2api/v4/b2_get_upload_url":
                    servidor.consultas_url.append((cab.get("authorization"), urllib.parse.parse_qs(consulta)))
                    if cab.get("authorization") != TOKEN_CUENTA:
                        return self.responder(401, {"code": "bad_auth_token", "status": 401})
                    return self.responder(200, {"bucketId": BUCKET, "uploadUrl": f"{servidor.url}/subir/{BUCKET}",
                                                "authorizationToken": TOKEN_SUBIDA})
                if metodo == "POST" and ruta == f"/subir/{BUCKET}":
                    if cab.get("authorization") != TOKEN_SUBIDA:
                        return self.responder(401, {"code": "bad_auth_token", "status": 401})
                    servidor.intentos_subida += 1
                    if servidor.subida_estado is not None:
                        return self.responder(servidor.subida_estado, {"code": "service_unavailable",
                                                                       "status": servidor.subida_estado})
                    sha1 = hashlib.sha1(cuerpo, usedforsecurity=False).hexdigest()
                    if cab.get("x-bz-content-sha1") != sha1 or int(cab.get("content-length", "-1")) != len(cuerpo):
                        return self.responder(400, {"code": "bad_request", "status": 400})
                    nombre = urllib.parse.unquote(cab.get("x-bz-file-name", ""))
                    servidor.subidas.append({"nombre": nombre, "cuerpo": cuerpo, "cabeceras": cab})
                    return self.responder(200, {"fileId": f"ID-ARCHIVO-{len(servidor.subidas)}", "fileName": nombre,
                                                "bucketId": BUCKET, "contentSha1": servidor.sha1_confirmado or sha1,
                                                "contentLength": len(cuerpo), "action": "upload", "fileInfo": {}})
                return self.responder(404, {"code": "not_found", "status": 404})

            def do_GET(self):
                self.tratar("GET")

            def do_POST(self):
                self.tratar("POST")

        self.http = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Manejador)
        self.url = f"http://127.0.0.1:{self.http.server_address[1]}"
        self.hilo = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.hilo.start()
        SERVIDORES.append(self)

    def credenciales(self, bucket_id=BUCKET):
        d = pathlib.Path(tempfile.mkdtemp(prefix="cred-", dir=TEMPORAL))
        (d / "b2_id").write_text(B2_ID, encoding="ascii", newline="")
        (d / "b2_clave").write_text(B2_CLAVE, encoding="ascii", newline="")
        (d / "bucket_id").write_text(bucket_id, encoding="ascii", newline="")
        (d / "latido_url").write_text(f"{self.url}/ping/{LATIDO_UUID}\n", encoding="ascii", newline="")
        (d / "latido_eventos_url").write_text(f"{self.url}/ping/{LATIDO_EVENTOS_UUID}\n", encoding="ascii", newline="")
        return d

    def cerrar(self):
        self.http.shutdown()
        self.http.server_close()


def correr(orden, servidor, bd=None, api=None, cursor=None, temporal=None, age=AGE_PRUEBA, destinatarios=None,
           bucket_id=BUCKET, presupuesto=None, extra=()):
    """Ejecuta despliegue/copias.py con las opciones de prueba, desde aquí."""
    args = [sys.executable, "-I", str(COPIAS), orden, "--b2-url", servidor.url,
            "--credenciales", str(servidor.credenciales(bucket_id)),
            "--destinatarios", str(destinatarios or DESTINATARIOS), "--age", age, "--docker", "docker"]
    if orden == "base":
        args += ["--contenedor-bd", bd]
    else:
        args += ["--contenedor-api", api, "--estado", str(cursor)]
    if temporal is not None:
        args += ["--temporal", str(temporal), "--conservar-temporal"]
    if presupuesto is not None:
        args += ["--presupuesto", str(presupuesto)]
    args += list(extra)
    r = ejecutar(args, timeout=1800)
    SALIDAS_SCRIPT.append(r.todo)
    return r


def descifrar(cifrado, clave):
    return ejecutar(["docker", "run", "--rm", "-i", "--network", "none", "--read-only", "--cap-drop", "ALL",
                     "--security-opt", "no-new-privileges", "--mount",
                     f"type=bind,src={CLAVES},dst=/claves,readonly", "--entrypoint", "age", IMG_HERR,
                     "-d", "-i", f"/claves/{clave}"], entrada=cifrado, timeout=300)


def abrir_tar(cifrado, clave="principal.key"):
    """(miembros {nombre: bytes}, resultado de age). Parada si no descifra."""
    r = descifrar(cifrado, clave)
    if r.rc != 0:
        return None, r
    with tarfile.open(fileobj=io.BytesIO(r.out_b)) as t:
        return {m.name: t.extractfile(m).read() for m in t.getmembers() if m.isfile()}, r


def instante_del_nombre(nombre):
    """Instante UTC del nombre <prefijo>/AAAAMMDDTHHMMSSZ.age, o None."""
    m = re.fullmatch(r"[a-z]+/(\d{8}T\d{6}Z)\.age", nombre)
    if m is None:
        return None
    return datetime.datetime.strptime(m.group(1), "%Y%m%dT%H%M%SZ").replace(tzinfo=datetime.UTC)


def es_reciente(nombre, prefijo):
    """El nombre es <prefijo>/<instante> y el instante es de hace menos de 30 minutos."""
    instante = instante_del_nombre(nombre)
    ahora = datetime.datetime.now(datetime.UTC)
    return nombre.startswith(prefijo + "/") and instante is not None and abs((ahora - instante).total_seconds()) < 1800


# ---------------------------------------------------------------------------
# Preparación
# ---------------------------------------------------------------------------
def servicio_bd(init_dir, volumen, solo_roles, copia_dir=None):
    centinela = "" if solo_roles else (" || '|' || (to_regprocedure('canal.redactar_mensaje(uuid,integer,uuid,bytea,bytea,integer)') "
                                       "is not null)::text")
    esperado = "*|6" if solo_roles else "*|6|true"
    consulta = ("select current_setting('listen_addresses') || '|' || (select count(*) from pg_roles where rolname in "
                "('migrador','aplicacion','plataforma','propietario_funciones','propietario_supresion',"
                f"'propietario_redaccion')){centinela}")
    # $$ : Compose interpreta $ y hay que duplicarlo.
    prueba = (f"x=$$(psql -U postgres -d canario -Atc \"{consulta}\") || exit 1; "
              f"case $$x in '{esperado}') exit 0;; *) exit 1;; esac")
    # La contraseña de la prueba la genera la batería (secretos propios, nunca los de secrets/).
    servicio = {
        "image": IMG_PG, "pull_policy": "never", "user": "70:70", "read_only": True,
        "command": ["postgres", "-c", "hba_file=/etc/postgresql/pg_hba.conf", "-c", "listen_addresses=*",
                    "-c", "unix_socket_permissions=0700", "-c", "password_encryption=scram-sha-256", "-c", "ssl=off"],
        "environment": {"POSTGRES_DB": "canario",
                        "POSTGRES_PASSWORD_FILE": "/run/secrets/contrasena_postgres_superusuario"},
        "secrets": ["contrasena_postgres_superusuario", "contrasena_migrador", "contrasena_aplicacion",
                    "contrasena_plataforma"],
        "tmpfs": ["/tmp:rw,noexec,nosuid,size=64m", "/var/run/postgresql:rw,noexec,nosuid,uid=70,gid=70,size=8m"],
        "volumes": [f"{volumen}:/var/lib/postgresql",
                    {"type": "bind", "source": (RAIZ / "db" / "pg_hba.conf").as_posix(),
                     "target": "/etc/postgresql/pg_hba.conf", "read_only": True},
                    {"type": "bind", "source": init_dir.as_posix(), "target": "/docker-entrypoint-initdb.d",
                     "read_only": True}],
        "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"], "networks": ["datos"],
        "mem_limit": "512m", "pids_limit": 64,
        "healthcheck": {"test": ["CMD-SHELL", prueba], "interval": "5s", "timeout": "5s", "retries": 40,
                        "start_period": "10s"},
    }
    if copia_dir is not None:
        # El volcado descifrado, en solo lectura: pg_restore lo lee de un
        # fichero, como en docs/operacion.md.
        servicio["volumes"].append({"type": "bind", "source": copia_dir.as_posix(), "target": "/copia",
                                    "read_only": True})
    return servicio


def escribir_compose():
    secretos = TEMPORAL / "secretos"
    secretos.mkdir()
    for nombre in ("contrasena_postgres_superusuario", "contrasena_migrador", "contrasena_aplicacion",
                   "contrasena_plataforma"):
        (secretos / f"{nombre}.txt").write_text(secrets.token_hex(24), encoding="ascii", newline="")
    solo_roles = TEMPORAL / "solo_roles"
    solo_roles.mkdir()
    (TEMPORAL / "copia").mkdir()
    # Copia de 01_roles.sh: la instancia de restauración solo tiene los roles.
    shutil.copyfile(RAIZ / "db" / "init" / "01_roles.sh", solo_roles / "01_roles.sh")
    compose = {
        "name": PROYECTO,
        "services": {
            "bd": servicio_bd(RAIZ / "db" / "init", "datos_bd", False),
            "bd_vacia": servicio_bd(RAIZ / "db" / "init", "datos_vacia", False),
            "restauracion": servicio_bd(solo_roles, "datos_restauracion", True, TEMPORAL / "copia"),
        },
        "networks": {"datos": {"internal": True}},
        "volumes": {"datos_bd": {}, "datos_vacia": {}, "datos_restauracion": {}},
        "secrets": {n: {"file": (secretos / f"{n}.txt").as_posix()} for n in (
            "contrasena_postgres_superusuario", "contrasena_migrador", "contrasena_aplicacion",
            "contrasena_plataforma")},
    }
    # JSON es YAML válido: se evita escapar a mano.
    (TEMPORAL / "compose.yml").write_text(json.dumps(compose, indent=1), encoding="utf-8", newline="\n")


def construir_imagenes():
    r = ejecutar(["docker", "build", "-t", IMG_PG, str(RAIZ / "db")])
    p(f"docker build {IMG_PG} -> codigo {r.rc}")
    if r.rc != 0:
        raise Parada(f"no se construye la imagen de postgres: {r.todo.strip()[-400:]}")
    dockerfile = f"""FROM {IMG_PG}
USER root
ADD --checksum=sha256:{AGE_SHA256} {AGE_URL} /tmp/age.tar.gz
RUN tar -xzf /tmp/age.tar.gz -C /tmp && install -m 0755 /tmp/age/age /usr/local/bin/age \\
    && install -m 0755 /tmp/age/age-keygen /usr/local/bin/age-keygen && rm -rf /tmp/age /tmp/age.tar.gz
USER 70:70
"""
    contexto = TEMPORAL / "imagen"
    contexto.mkdir()
    (contexto / "Dockerfile").write_text(dockerfile, encoding="utf-8", newline="\n")
    r = ejecutar(["docker", "build", "-t", IMG_HERR, str(contexto)])
    p(f"docker build {IMG_HERR} (age v1.3.2 con ADD --checksum) -> codigo {r.rc}")
    if r.rc != 0:
        raise Parada(f"no se construye la imagen con age (sin red, o el sha256 no coincide): {r.todo.strip()[-400:]}")


def generar_claves():
    global CLAVES, DESTINATARIOS
    CLAVES = TEMPORAL / "claves"
    CLAVES.mkdir()
    recipientes = {}
    for nombre in ("principal", "respaldo", "otra"):
        r = ejecutar(["docker", "run", "--rm", "--network", "none", "--entrypoint", "age-keygen", IMG_HERR, "-pq"])
        if r.rc != 0 or "AGE-SECRET-KEY-PQ-1" not in r.out:
            raise Parada(f"age-keygen -pq no genera una clave poscuantica: {r.err.strip()[-300:]}")
        (CLAVES / f"{nombre}.key").write_text(r.out, encoding="ascii", newline="\n")
        m = re.search(r"public key: (age1pq1[a-z0-9]+)", r.out)
        if m is None:
            y = ejecutar(["docker", "run", "--rm", "--network", "none", "--mount",
                          f"type=bind,src={CLAVES},dst=/claves,readonly", "--entrypoint", "age-keygen",
                          IMG_HERR, "-y", f"/claves/{nombre}.key"])
            m = re.search(r"(age1pq1[a-z0-9]+)", y.out)
        if m is None:
            raise Parada("no se obtiene el destinatario de la clave age generada")
        recipientes[nombre] = m.group(1)
    DESTINATARIOS = TEMPORAL / "destinatarios.txt"
    DESTINATARIOS.write_text(f"# principal\n{recipientes['principal']}\n# respaldo\n{recipientes['respaldo']}\n",
                             encoding="ascii", newline="\n")
    p("claves age -pq generadas: principal, respaldo y una ajena (solo para la prueba c)")


# ---------------------------------------------------------------------------
# Siembra y recálculo independiente de la cadena
# ---------------------------------------------------------------------------
def sembrar():
    sql = f"""
INSERT INTO canal.empresa (id, nombre) VALUES ('{EMPRESA_A}', '{MARCA_NOMBRE}'), ('{EMPRESA_B}', 'Empresa B');
INSERT INTO canal.directorio_empresas (identificador_publico, empresa_id) VALUES
    ('{IDENT_A}', '{EMPRESA_A}'), ('{IDENT_B}', '{EMPRESA_B}');
INSERT INTO canal.clave_empresa (empresa_id, version, clave_envuelta) VALUES
    ('{EMPRESA_A}', 1, '\\x01'), ('{EMPRESA_B}', 1, '\\x02');
INSERT INTO canal.usuario_personal (empresa_id, id, email, hash_contrasena, rol) VALUES
    ('{EMPRESA_A}', '{USUARIO_A}', '{MARCA_EMAIL}', 'x', 'admin'),
    ('{EMPRESA_B}', '{USUARIO_B}', 'otro@ejemplo.test', 'x', 'admin');
INSERT INTO canal.denuncia (empresa_id, id, contenido_cifrado, version_clave) VALUES
    ('{EMPRESA_A}', '{DENUNCIA_A}', convert_to('{MARCA_BYTEA}', 'UTF8'), 1),
    ('{EMPRESA_B}', '{DENUNCIA_B}', '\\xdeadbeef', 1);
INSERT INTO canal.mensaje (empresa_id, denuncia_id, autor, contenido_cifrado, version_clave) VALUES
    ('{EMPRESA_A}', '{DENUNCIA_A}', 'denunciante', '\\xdeadbeef', 1),
    ('{EMPRESA_B}', '{DENUNCIA_B}', 'denunciante', '\\xdeadbeef', 1);
INSERT INTO canal.registro_auditoria (empresa_id, actor, accion, objeto_id) VALUES
    ('{EMPRESA_A}', 'sistema', 'crear_denuncia', '{DENUNCIA_A}'),
    ('{EMPRESA_A}', 'sistema', 'lectura_denuncia', '{DENUNCIA_A}'),
    ('{EMPRESA_A}', 'sistema', 'asignar_denuncia', '{DENUNCIA_A}'),
    ('{EMPRESA_B}', 'sistema', 'crear_denuncia', '{DENUNCIA_B}');
"""
    r = psql("bd", sql)
    pasa(r.rc == 0 and "ERROR" not in r.err, f"a) datos sembrados en la base de la prueba {r.err.strip()[:300]}")
    return r.rc == 0


def hash_esperado_python(empresa, servicio):
    """Último hash de la cadena de una empresa, recalculado aquí en Python con
    la fórmula de canal.encadenar_auditoria (independiente del script)."""
    r = psql(servicio, "select secuencia, coalesce(encode(hash_anterior, 'hex'), ''), encode(hash, 'hex'), fecha::text, "
                       "actor, accion, coalesce(objeto_id::text, ''), coalesce(destino_id::text, '') "
                       f"from canal.registro_auditoria where empresa_id = '{empresa}' order by secuencia;")
    previo = ""
    for fila in (l.split("|") for l in r.lineas()):
        secuencia, anterior, guardado, fecha, actor, accion, objeto, destino = fila
        elementos = [anterior or None, empresa, int(secuencia), fecha, actor, accion, objeto or None, destino or None]
        calculado = hashlib.sha256(json.dumps(elementos, separators=(", ", ": "), ensure_ascii=False)
                                   .encode("utf-8")).hexdigest()
        if anterior != previo or calculado != guardado:
            raise Parada(f"el recalculo en Python de la cadena de {empresa} no coincide con la base: no se ajusta el test")
        previo = guardado
    return previo


# ---------------------------------------------------------------------------
# Secciones
# ---------------------------------------------------------------------------
def seccion_a():
    p("=== a) copia, descifrado y restauracion con solo 01_roles.sh")
    r = dc("up", "-d", "bd", "bd_vacia")
    p(f"up -d bd bd_vacia -> codigo {r.rc}")
    if r.rc != 0:
        raise Parada(f"no arrancan las bases: {r.todo.strip()[-400:]}")
    for servicio in ("bd", "bd_vacia"):
        IDS[servicio] = dc("ps", "-q", servicio).out.strip()
        if esperar_sano(IDS[servicio]) != "healthy":
            raise Parada(f"{servicio} no llega a healthy")
    if not sembrar():
        raise Parada("la siembra falla")
    esperado_hash = {e: hash_esperado_python(e, "bd") for e in (EMPRESA_A, EMPRESA_B)}
    pasa(all(len(h) == 64 for h in esperado_hash.values()), "a) cadena de auditoria recalculada en Python para las dos empresas")

    servidor = ServidorB2()
    r = correr("base", servidor, bd=IDS["bd"])
    control_copia = r.rc == 0 and len(servidor.subidas) == 1
    pasa(control_copia, f"a) copias.py base con datos: codigo {r.rc} y una subida {r.err.strip()[-300:]}")
    CONTROLES["servidor_a"] = servidor
    if not control_copia:
        raise Parada("sin copia subida no se puede seguir con a)")
    cifrado = servidor.subidas[0]["cuerpo"]
    CONTROLES["cifrado_a"] = cifrado
    miembros, r = abrir_tar(cifrado)
    pasa(miembros is not None, f"a) la clave principal descifra la copia {r.err.strip()[:200]}")
    if miembros is None:
        raise Parada("no se descifra la copia con la clave principal")
    pasa(sorted(miembros) == ["manifiesto.json", "volcado.dump"], f"a) el tar lleva exactamente manifiesto.json y volcado.dump ({sorted(miembros)})")
    manifiesto = json.loads(miembros["manifiesto.json"])
    dump = miembros["volcado.dump"]
    CONTROLES["tar_plano_tiene_marcadores"] = dump.startswith(b"PGDMP") and b"manifiesto.json" in r.out_b
    respaldo, _r2 = abrir_tar(cifrado, "respaldo.key")
    pasa(respaldo is not None and respaldo["volcado.dump"] == dump, "a) la clave de respaldo descifra lo mismo que la principal")

    pasa(manifiesto["recuentos"] == RECUENTOS, "a) los recuentos del manifiesto son los literales sembrados")
    if manifiesto["recuentos"] != RECUENTOS:
        p(f"   manifiesto: {manifiesto['recuentos']}")
    auditoria = [(f["empresa"], f["ultima_secuencia"], f["ultimo_hash"]) for f in manifiesto["auditoria"]]
    esperado_aud = [(EMPRESA_A, ULTIMA_SECUENCIA[EMPRESA_A], esperado_hash[EMPRESA_A]),
                    (EMPRESA_B, ULTIMA_SECUENCIA[EMPRESA_B], esperado_hash[EMPRESA_B])]
    pasa(auditoria == esperado_aud, "a) el manifiesto lleva la ultima secuencia (3 y 1) y el ultimo hash recalculado en Python")
    pasa(manifiesto["cadena_rota_en"] is None, "a) el manifiesto dice que la cadena esta intacta")
    pasa(manifiesto["volcado_sha256"] == hashlib.sha256(dump).hexdigest() and manifiesto["volcado_bytes"] == len(dump),
         "a) el sha256 y la longitud del volcado del manifiesto son los del volcado")

    # Restauración en una instancia nueva con solo 01_roles.sh. El volcado
    # descifrado va a un fichero que la instancia monta en solo lectura.
    (TEMPORAL / "copia" / "volcado.dump").write_bytes(dump)
    r = dc("up", "-d", "restauracion")
    IDS["restauracion"] = dc("ps", "-q", "restauracion").out.strip()
    if r.rc != 0 or esperar_sano(IDS["restauracion"]) != "healthy":
        raise Parada(f"no arranca la instancia de restauracion: {r.todo.strip()[-300:]}")
    antes = psql("restauracion", "select count(*) from pg_database where datname = 'canario';").out.strip()
    p(f"instancia de restauracion con solo los roles: base canario existe={antes}")
    # El 01_roles.sh exige la base canario: pg_restore la tiene que BORRAR y crear
    # de nuevo (--clean --if-exists). Con --create no se puede usar
    # --single-transaction (pg_restore lo rechaza, pg_restore.c): se usa
    # --exit-on-error, y ante cualquier error se descarta la instancia.
    # El healthcheck de la instancia se conecta a canario cada pocos segundos y
    # un DROP DATABASE justo entonces falla ("being accessed by other users"):
    # se reintenta solo ese error, que ocurre antes de cambiar nada.
    for _ in range(5):
        r = ejecutar(["docker", "exec", "-i", IDS["restauracion"], "pg_restore", "-U", "postgres", "-d", "postgres",
                      "--create", "--clean", "--if-exists", "--exit-on-error", "/copia/volcado.dump"], timeout=600)
        if r.rc == 0 or "being accessed by other users" not in r.err:
            break
        time.sleep(2)
    pasa(r.rc == 0, f"a) pg_restore --create --clean --if-exists --exit-on-error termina con 0 {r.err.strip()[-400:]}")
    if r.rc != 0:
        raise Parada("la restauracion falla")

    consulta = " union all ".join(
        f"select '{t}', count(*)::text from {t}" for t in sorted(RECUENTOS)) + " order by 1;"
    filas = {l.split("|")[0]: int(l.split("|")[1]) for l in psql("restauracion", consulta).lineas()}
    pasa(filas == RECUENTOS, "a) los recuentos de la base restaurada son los literales (y los del manifiesto)")
    if filas != RECUENTOS:
        p(f"   restaurado: {filas}")
    r = psql("restauracion", "select coalesce(canal.verificar_cadena_auditoria()::text, 'NULL');")
    pasa(r.lineas() == ["NULL"], f"a) verificar_cadena_auditoria() en la base restaurada devuelve NULL ({r.lineas()})")
    r = psql("restauracion", "select empresa_id, max(secuencia), (array_agg(encode(hash, 'hex') order by secuencia desc))[1] "
                             "from canal.registro_auditoria group by empresa_id order by empresa_id;")
    restaurado = [(f.split("|")[0], int(f.split("|")[1]), f.split("|")[2]) for f in r.lineas()]
    pasa(restaurado == esperado_aud, "a) ultima secuencia y ultimo hash por empresa restaurados = manifiesto = recalculo en Python")
    pasa(psql("restauracion", "select count(*) from pg_policies where schemaname = 'canal';").out.strip() ==
         psql("bd", "select count(*) from pg_policies where schemaname = 'canal';").out.strip() != "0",
         "a) las politicas RLS restauradas son las mismas que en el origen (y no cero)")
    acl_orig = psql("bd", "select pg_get_userbyid(datdba) || ' ' || coalesce(datacl::text, 'NULL') from pg_database where datname = 'canario';").out.strip()
    acl_rest = psql("restauracion", "select pg_get_userbyid(datdba) || ' ' || coalesce(datacl::text, 'NULL') from pg_database where datname = 'canario';").out.strip()
    pasa(acl_orig == acl_rest and acl_orig.startswith("migrador ") and "aplicacion=c/" in acl_orig,
         "a) dueno (migrador) y permisos de conexion de la base restaurada = los del origen")
    if acl_orig != acl_rest:
        p(f"   origen: {acl_orig} | restaurada: {acl_rest}")
    r = psql("restauracion", "select count(*) from canal.usuario_personal where email = '" + MARCA_EMAIL + "';")
    CONTROLES["marca_en_bd_restaurada"] = r.out.strip() == "1"


def seccion_b_c():
    p("=== b) byte alterado y c) clave equivocada")
    cifrado = CONTROLES["cifrado_a"]
    control, _r_ok = abrir_tar(cifrado)
    alterado = bytearray(cifrado)
    alterado[len(alterado) // 2] ^= 0x01
    r = descifrar(bytes(alterado), "principal.key")
    negativo("b) un fichero con un byte alterado no se descifra (codigo distinto de 0 y ninguna salida)",
             r.rc != 0 and not r.out_b, control is not None, f"codigo {r.rc} salida {len(r.out_b)} bytes")
    r = descifrar(cifrado, "otra.key")
    negativo("c) una clave age equivocada no descifra (codigo distinto de 0 y ninguna salida)",
             r.rc != 0 and not r.out_b, control is not None, f"codigo {r.rc} salida {len(r.out_b)} bytes")
    pasa(r.rc != 0 and "no identity matched" in r.err, f"c) age dice que ninguna identidad encaja ({r.err.strip()[:150]})")


def seccion_d():
    p("=== d) base vacia: sube a cuarentena, no a base")
    servidor = ServidorB2()
    r = correr("base", servidor, bd=IDS["bd_vacia"])
    control = len(CONTROLES["servidor_a"].subidas) == 1 and es_reciente(CONTROLES["servidor_a"].subidas[0]["nombre"], "base")
    nombres = [s["nombre"] for s in servidor.subidas]
    negativo(f"d) base vacia: falla con el codigo {RC_BASE}, sube SOLO a cuarentena/ (nada a base/) y hace /fail",
             r.rc == RC_BASE and len(nombres) == 1 and es_reciente(nombres[0], "cuarentena")
             and servidor.latidos == ["fail"] and "cuarentena/" in r.err,
             control, f"codigo {r.rc} subidas {nombres} latidos {servidor.latidos} {r.err.strip()[-200:]}")
    if len(servidor.subidas) == 1:
        miembros, _ = abrir_tar(servidor.subidas[0]["cuerpo"])
        manifiesto = json.loads(miembros["manifiesto.json"]) if miembros else {}
        pasa(manifiesto.get("motivos") == ["base_vacia"] and manifiesto.get("estable") is True
             and manifiesto.get("cadena_rota_en") is None,
             "d) el manifiesto de la cuarentena dice motivos=['base_vacia'], estable=true y cadena intacta")
        fail = [x for x in servidor.pings if x["fallo"]]
        pasa(len(fail) == 1 and b"base_vacia" in fail[0]["cuerpo"] and b"ID-ARCHIVO-1" in fail[0]["cuerpo"],
             "d) el cuerpo del /fail lleva el motivo y el fileId del objeto de cuarentena")
    pasa(CONTROLES["servidor_a"].latidos == ["ok"], "d) control: con datos se subio a base/ y el latido de exito fue el unico")


def seccion_e():
    p("=== e) protocolo con B2 y clave con permisos de mas")
    s = CONTROLES["servidor_a"]
    subida = s.subidas[0]
    cab = subida["cabeceras"]
    cuerpo = subida["cuerpo"]
    rutas = [f"{m} {r}" for m, r in s.peticiones if not r.startswith("/ping/")]
    pasa(rutas == ["GET /b2api/v4/b2_authorize_account", "GET /b2api/v4/b2_get_upload_url", f"POST /subir/{BUCKET}"],
         f"e) secuencia de llamadas: authorize, get_upload_url, upload ({rutas})")
    pasa(s.autorizaciones == [True], "e) b2_authorize_account con Basic base64(id:clave)")
    pasa(s.consultas_url == [(TOKEN_CUENTA, {"bucketId": [BUCKET]})], "e) b2_get_upload_url con el token de cuenta y el bucket de la clave")
    pasa(cab.get("authorization") == TOKEN_SUBIDA, "e) la subida usa el token de subida, no el de cuenta")
    pasa(cab.get("x-bz-content-sha1") == hashlib.sha1(cuerpo, usedforsecurity=False).hexdigest(),
         "e) X-Bz-Content-Sha1 es el SHA1 del cuerpo (calculado aqui)")
    pasa(cab.get("content-length") == str(len(cuerpo)) and len(cuerpo) > 0, "e) Content-Length es la longitud exacta del cuerpo")
    pasa(re.fullmatch(r"base/\d{8}T\d{6}Z\.age", subida["nombre"]) is not None,
         f"e) el nombre es base/AAAAMMDDTHHMMSSZ.age, unico con la hora ({subida['nombre']})")
    pasa(es_reciente(subida["nombre"], "base"), "e) la hora del nombre es la de ahora en UTC")
    sha1_calculado = hashlib.sha1(cuerpo, usedforsecurity=False).hexdigest()
    esperado_ping = {"objeto": subida["nombre"], "fileId": "ID-ARCHIVO-1", "sha1": sha1_calculado, "bytes": len(cuerpo)}
    ping = s.pings[0] if s.pings else None
    pasa(ping is not None and ping["metodo"] == "POST" and not ping["fallo"] and ping["uuid"] == LATIDO_UUID
         and [json.loads(l) for l in ping["cuerpo"].decode().splitlines()] == [esperado_ping],
         "e) el latido de exito es un POST con el fileId, el SHA1 y los bytes del objeto subido (literales y calculados aqui)")
    pasa(not [k for k in cab if k.startswith("x-bz-info")], "e) ningun X-Bz-Info en la subida")
    pasa(cuerpo.startswith(b"age-encryption.org/v1\n"), "e) el cuerpo es un fichero age")

    control = len(s.subidas) == 1
    variantes = [
        ("con una capacidad de mas (deleteFiles)", {"capacidades": ("writeFiles", "deleteFiles")}),
        ("con readFiles ademas de writeFiles", {"capacidades": ("readFiles", "writeFiles")}),
        ("sin writeFiles (solo listBuckets)", {"capacidades": ("listBuckets",)}),
        ("con dos buckets", {"buckets": 2}),
        ("limitada a un prefijo", {"prefijo": "base/"}),
    ]
    for texto, opciones in variantes:
        sv = ServidorB2(**opciones)
        r = correr("base", sv, bd=IDS["bd"])
        negativo(f"e) clave {texto}: el script se niega (codigo {RC_CLAVE}), sin subir nada y con /fail",
                 r.rc == RC_CLAVE and not sv.subidas and sv.latidos == ["fail"], control,
                 f"codigo {r.rc} subidas {len(sv.subidas)} {r.err.strip()[-200:]}")

    sv = ServidorB2(clave="otra-clave-distinta")
    r = correr("base", sv, bd=IDS["bd"])
    negativo(f"e) clave de B2 equivocada: codigo {RC_CLAVE}, sin subir y el error no contiene la clave",
             r.rc == RC_CLAVE and not sv.subidas and "rechaza la clave" in r.err and B2_CLAVE not in r.todo, control)

    sv = ServidorB2(latido_estado=500)
    r = correr("base", sv, bd=IDS["bd"])
    negativo(f"e) latido que falla (HTTP 500): codigo {RC_LATIDO}, la copia si se subio y el error no lleva la URL",
             r.rc == RC_LATIDO and len(sv.subidas) == 1 and LATIDO_UUID not in r.todo and "HTTP 500" in r.err, control,
             f"codigo {r.rc} subidas {len(sv.subidas)}")


def seccion_f():
    p("=== f) un proceso de la tuberia falla")
    control_servidor = CONTROLES["servidor_a"]
    control = len(control_servidor.subidas) == 1 and control_servidor.latidos == ["ok"]
    # f1: el contenedor de la base parado (docker exec falla).
    ejecutar(["docker", "stop", IDS["bd"]])
    sv = ServidorB2()
    r = correr("base", sv, bd=IDS["bd"])
    negativo(f"f) contenedor de la base parado: codigo {RC_PROCESO}, sin subir y con /fail, sin latido de exito",
             r.rc == RC_PROCESO and not sv.subidas and sv.latidos == ["fail"], control,
             f"codigo {r.rc} subidas {len(sv.subidas)} latidos {sv.latidos} {r.err.strip()[-200:]}")
    ejecutar(["docker", "start", IDS["bd"]])
    pasa(esperar_sano(IDS["bd"]) == "healthy", "f) la base vuelve a estar healthy tras la prueba")
    # f2: age falla (el ultimo proceso de la tuberia).
    sv = ServidorB2()
    r = correr("base", sv, bd=IDS["bd"], age=f"docker run --rm -i --entrypoint false {IMG_HERR}")
    negativo(f"f) age que falla: codigo {RC_PROCESO}, sin subir y con /fail, sin latido de exito",
             r.rc == RC_PROCESO and not sv.subidas and sv.latidos == ["fail"] and "age falla" in r.err, control,
             f"codigo {r.rc} subidas {len(sv.subidas)} latidos {sv.latidos} {r.err.strip()[-200:]}")
    # Control reforzado: la misma llamada sin fallos sube y hace el latido de exito.
    sv = ServidorB2()
    r = correr("base", sv, bd=IDS["bd"])
    pasa(r.rc == 0 and len(sv.subidas) == 1 and sv.latidos == ["ok"],
         f"f) control: sin fallos sube y hace el latido de exito (codigo {r.rc})")


def cambiar_actor(actor):
    """Cambia el actor de la fila 2 de la empresa A. La inmutabilidad la
    garantiza un trigger que solo un superusuario puede desactivar: es lo que
    hace aqui, y siempre lo vuelve a activar."""
    return psql("bd", "ALTER TABLE canal.registro_auditoria DISABLE TRIGGER auditoria_inmutable_fila;\n"
                      f"UPDATE canal.registro_auditoria SET actor = '{actor}' WHERE empresa_id = '{EMPRESA_A}' AND secuencia = 2;\n"
                      "ALTER TABLE canal.registro_auditoria ENABLE TRIGGER auditoria_inmutable_fila;")


def cadena_de_bd():
    return psql("bd", "select coalesce(canal.verificar_cadena_auditoria()::text, 'NULL');").lineas()


def seccion_i():
    p("=== i) cadena de auditoria rota: cuarentena")
    sv = ServidorB2()
    r = None
    try:
        r_sql = cambiar_actor("manipulado")
        # Control de la manipulacion: la funcion de la base dice que la cadena se
        # rompe en la secuencia 2 (literal).
        control_rota = r_sql.rc == 0 and cadena_de_bd() == ["2"]
        r = correr("base", sv, bd=IDS["bd"])
    finally:
        # Siempre se restaura, tambien si la prueba falla: las secciones
        # siguientes usan esta base.
        cambiar_actor("sistema")
    restaurada = cadena_de_bd() == ["NULL"]
    sv_ok = ServidorB2()
    r_ok = correr("base", sv_ok, bd=IDS["bd"])
    control_ok = (restaurada and r_ok.rc == 0 and len(sv_ok.subidas) == 1 and es_reciente(sv_ok.subidas[0]["nombre"], "base")
                  and sv_ok.latidos == ["ok"])
    pasa(control_rota, "i) control: manipular el actor de la fila 2 rompe la cadena en la secuencia 2 (verificar_cadena_auditoria = 2)")
    pasa(restaurada, "i) control: restaurado el actor, la cadena vuelve a estar intacta (NULL)")
    nombres = [s["nombre"] for s in sv.subidas]
    negativo(f"i) cadena rota: codigo {RC_BASE}, sube SOLO a cuarentena/ y hace /fail con el motivo",
             r.rc == RC_BASE and len(nombres) == 1 and es_reciente(nombres[0], "cuarentena") and sv.latidos == ["fail"]
             and b"cadena_rota_en=2" in sv.pings[-1]["cuerpo"] and b"ID-ARCHIVO-1" in sv.pings[-1]["cuerpo"],
             control_rota and control_ok, f"codigo {r.rc} subidas {nombres} latidos {sv.latidos} {r.err.strip()[-200:]}")
    if len(sv.subidas) == 1 and control_rota:
        miembros, _ = abrir_tar(sv.subidas[0]["cuerpo"])
        manifiesto = json.loads(miembros["manifiesto.json"]) if miembros else {}
        pasa(manifiesto.get("cadena_rota_en") == 2 and manifiesto.get("motivos") == ["cadena_rota_en=2"]
             and manifiesto.get("estable") is True, "i) el manifiesto de la cuarentena dice cadena_rota_en=2, motivos y estable=true")
    pasa(control_ok, "i) control: restaurada la cadena, la copia sube a base/ con el latido de exito")


def destinatario_clasico():
    r = ejecutar(["docker", "run", "--rm", "--network", "none", "--entrypoint", "age-keygen", IMG_HERR])
    m = re.search(r"(age1(?!pq1)[a-z0-9]{50,})", r.out)
    if r.rc != 0 or m is None:
        raise Parada(f"age-keygen (clasica) no da un destinatario age1...: {r.err.strip()[-200:]}")
    return m.group(1)


def seccion_j():
    p("=== j) configuracion y B2: destinatarios, bucket, 500, SHA1, presupuesto, argumentos, https y file://")
    sv_ok = ServidorB2()
    r_ok = correr("base", sv_ok, bd=IDS["bd"])
    control = r_ok.rc == 0 and len(sv_ok.subidas) == 1 and sv_ok.latidos == ["ok"]
    pasa(control, f"j) control: la configuracion buena sube y hace el latido de exito (codigo {r_ok.rc})")

    # Destinatarios invalidos: codigo 3, sin tocar B2 (ni una peticion).
    pq = [l for l in DESTINATARIOS.read_text(encoding="ascii").splitlines() if l.startswith("age1pq1")]
    clasico = destinatario_clasico()
    casos = (("uno solo", [pq[0]]), ("uno clasico age1... y uno poscuantico", [pq[0], clasico]),
             ("dos iguales", [pq[0], pq[0]]))
    for nombre, lineas in casos:
        fichero = TEMPORAL / "destinatarios_malos.txt"
        fichero.write_text("\n".join(lineas) + "\n", encoding="ascii", newline="\n")
        sv = ServidorB2()
        r = correr("base", sv, bd=IDS["bd"], destinatarios=fichero)
        negativo(f"j) destinatarios {nombre}: codigo {RC_CONFIG}, ni una peticion a B2 y nada subido",
                 r.rc == RC_CONFIG and "dos destinatarios" in r.err and not sv.peticiones and not sv.subidas,
                 control, f"codigo {r.rc} {r.err.strip()[-200:]}")

    # Bucket distinto del esperado (la configuracion dice otro).
    sv = ServidorB2()
    r = correr("base", sv, bd=IDS["bd"], bucket_id="BUCKET-OTRO")
    negativo(f"j) clave de un bucket distinto del esperado: codigo {RC_CLAVE}, sin subir y con /fail",
             r.rc == RC_CLAVE and "bucket distinto" in r.err and not sv.subidas and sv.latidos == ["fail"],
             control, f"codigo {r.rc} subidas {len(sv.subidas)} {r.err.strip()[-200:]}")

    # Subida con 500 repetido: se reintenta INTENTOS_SUBIDA (3, literal) veces y falla.
    sv = ServidorB2(subida_estado=500)
    r = correr("base", sv, bd=IDS["bd"])
    negativo(f"j) subida que devuelve 500 repetido: tres intentos, codigo {RC_SUBIDA}, nada subido y /fail",
             r.rc == RC_SUBIDA and sv.intentos_subida == 3 and not sv.subidas and sv.latidos == ["fail"]
             and "HTTP 500" in r.err, control, f"codigo {r.rc} intentos {sv.intentos_subida} {r.err.strip()[-200:]}")

    # B2 confirma otro SHA1 que el enviado.
    sv = ServidorB2(sha1_confirmado="0" * 40)
    r = correr("base", sv, bd=IDS["bd"])
    negativo(f"j) B2 confirma otro SHA1: codigo {RC_SUBIDA}, sin latido de exito y con /fail",
             r.rc == RC_SUBIDA and "distinta" in r.err and sv.latidos == ["fail"], control,
             f"codigo {r.rc} latidos {sv.latidos} {r.err.strip()[-200:]}")

    # Presupuesto de tiempo agotado (1 s, imposible para docker exec + pg_dump + age).
    sv = ServidorB2()
    r = correr("base", sv, bd=IDS["bd"], presupuesto=1)
    negativo(f"j) presupuesto de tiempo agotado: codigo {RC_TIEMPO}, nada subido y /fail con el motivo",
             r.rc == RC_TIEMPO and "presupuesto" in r.err and not sv.subidas and sv.latidos == ["fail"]
             and b"presupuesto" in sv.pings[-1]["cuerpo"], control,
             f"codigo {r.rc} subidas {len(sv.subidas)} latidos {sv.latidos} {r.err.strip()[-200:]}")

    # Argumentos no validos: codigo 2 antes de tocar nada.
    for texto, extra in (("un presupuesto de 0", ["base", "--presupuesto", "0"]), ("una orden desconocida", ["otra"])):
        r = ejecutar([sys.executable, "-I", str(COPIAS), *extra])
        SALIDAS_SCRIPT.append(r.todo)
        negativo(f"j) argumentos no validos ({texto}): codigo {RC_ARGUMENTOS}", r.rc == RC_ARGUMENTOS, control,
                 f"codigo {r.rc} {r.err.strip()[-200:]}")

    # https obligatorio y abridor sin file://, con el modulo cargado desde aqui.
    spec = importlib.util.spec_from_file_location("copias_bajo_prueba", COPIAS)
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    sv = ServidorB2()
    control_https = (modulo.exigir_https("https://ejemplo.test/x", False, "la URL", RC_CONFIG) == "https://ejemplo.test/x"
                     and modulo.exigir_https(f"{sv.url}/x", True, "la URL", RC_CONFIG) == f"{sv.url}/x")
    pasa(control_https, "j) control: https vale siempre y http solo en el modo de prueba")
    try:
        modulo.exigir_https("http://ejemplo.test/x", False, "la URL", RC_CONFIG)
        codigo = None
    except modulo.Fallo as e:
        codigo = e.codigo
    negativo(f"j) http fuera del modo de prueba: se rechaza con el codigo {RC_CONFIG}", codigo == RC_CONFIG, control_https)
    try:
        modulo.autorizar_b2(sv.url, B2_ID, B2_CLAVE, BUCKET, False)
        codigo = None
    except modulo.Fallo as e:
        codigo = e.codigo
    api_url, _, _ = modulo.autorizar_b2(sv.url, B2_ID, B2_CLAVE, BUCKET, True)
    negativo(f"j) una apiUrl http en la respuesta de B2: se rechaza con el codigo {RC_CLAVE} (control: en modo de prueba pasa)",
             codigo == RC_CLAVE, api_url == sv.url, f"codigo {codigo}")
    fichero_b = TEMPORAL / "objeto_prueba.bin"
    fichero_b.write_bytes(b"datos de prueba")
    try:
        modulo.subir_a_b2(sv.url, TOKEN_CUENTA, BUCKET, "base/x.age", fichero_b, False)
        codigo = None
    except modulo.Fallo as e:
        codigo = e.codigo
    sin_subir = not sv.subidas
    objeto = modulo.subir_a_b2(sv.url, TOKEN_CUENTA, BUCKET, "base/x.age", fichero_b, True)
    negativo(f"j) una uploadUrl http: se rechaza con el codigo {RC_SUBIDA} y no se sube nada (control: en modo de prueba sube)",
             codigo == RC_SUBIDA and sin_subir, objeto["fileId"] == "ID-ARCHIVO-1", f"codigo {codigo}")
    fichero_f = TEMPORAL / "fichero_local.txt"
    fichero_f.write_text("CONTENIDO-FILE-PRUEBA", encoding="ascii", newline="")
    try:
        leido = modulo.pedir(fichero_f.as_uri(), {})
    except modulo.ErrorRed:
        leido = None
    estado_http, _cuerpo = modulo.pedir(f"{sv.url}/b2api/v4/b2_get_upload_url", {})
    negativo("j) el abridor no abre file://: una URL de fichero da error y no devuelve el contenido (control: http responde)",
             leido is None, estado_http == 401, f"leido {leido}")


def crear_api_falsa(nombre, opciones_log=()):
    """Contenedor que reenvia a su stderr (como el logging de la API) lo que se
    escribe en un fifo. Con opciones de rotacion para provocar un hueco."""
    r = ejecutar(["docker", "run", "-d", "--name", nombre, "--network", "none", "--read-only", "--cap-drop", "ALL",
                  "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,noexec,nosuid,size=1m",
                  "--log-driver", "json-file", *opciones_log, "--entrypoint", "sh", IMG_HERR, "-c",
                  "mkfifo /tmp/f && while true; do while read -r l; do echo \"$l\" >&2; done < /tmp/f; done"])
    if r.rc != 0:
        raise Parada(f"no arranca la API falsa: {r.todo.strip()[-300:]}")
    for _ in range(50):
        if ejecutar(["docker", "exec", nombre, "test", "-p", "/tmp/f"]).rc == 0:
            return
        time.sleep(0.2)
    raise Parada("la API falsa no crea su fifo")


def escribir_log(nombre, lineas):
    r = ejecutar(["docker", "exec", "-i", nombre, "sh", "-c", "cat > /tmp/f"],
                 entrada=("\n".join(lineas) + "\n").encode("utf-8"), timeout=120)
    if r.rc != 0:
        raise Parada(f"no se escribe en el log de la API falsa: {r.todo.strip()[-200:]}")
    time.sleep(1)


def mensajes_de(cifrado):
    miembros, r = abrir_tar(cifrado)
    if miembros is None:
        raise Parada(f"no se descifra la copia de eventos: {r.err.strip()[-200:]}")
    return [l.split(" ", 1)[1] for l in miembros["eventos.log"].decode("utf-8").splitlines()], miembros


def leer_cursor_literal(ruta):
    """(id, ns) del cursor, con una expresion regular escrita aqui (no la del script)."""
    m = re.fullmatch(r"v1 ([0-9a-f]{64}) (\d+)\n", pathlib.Path(ruta).read_text(encoding="ascii"))
    return (m.group(1), int(m.group(2))) if m else None


def id_real(contenedor):
    return ejecutar(["docker", "inspect", "--type", "container", "--format", "{{.Id}}", contenedor]).out.strip()


def seccion_g():
    p("=== g) eventos: filtro, cursor, hueco por rotacion, API recreada, cursor danado y latido")
    api = f"{PROYECTO}_api1"
    crear_api_falsa(api)
    cursor = TEMPORAL / "cursor1.txt"
    sv = ServidorB2()
    escribir_log(api, [EV_REDACCION, EV_NO_PERMITIDO, EV_EN_MEDIO, EV_OTRO_LOGGER, EV_NO_VERAZ])
    r1 = correr("eventos", sv, api=api, cursor=cursor)
    control = r1.rc == 0 and len(sv.subidas) == 1
    pasa(control, f"g) primera exportacion: codigo {r1.rc} y una subida {r1.err.strip()[-200:]}")
    if not control:
        return
    pasa(re.fullmatch(r"eventos/\d{8}T\d{6}Z\.age", sv.subidas[0]["nombre"]) is not None,
         f"g) nombre eventos/AAAAMMDDTHHMMSSZ.age ({sv.subidas[0]['nombre']})")
    mensajes, _miembros = mensajes_de(sv.subidas[0]["cuerpo"])
    negativo("g) solo salen los tipos permitidos: las dos del personal permitidas, y ni un tipo no permitido, ni EVENTO en medio de una linea, ni otro logger",
             mensajes == [EV_REDACCION, EV_NO_VERAZ], control, f"salieron {len(mensajes)} lineas")
    c1 = leer_cursor_literal(cursor)
    pasa(c1 is not None and c1[1] > 0 and c1[0] == id_real(api),
         "g) el cursor es 'v1 <Id del contenedor> <ns>' y el Id es el de docker inspect (comprobado aqui)")
    pasa(sv.latidos_eventos == ["ok"] and sv.latidos == [] and sv.pings[0]["metodo"] == "POST"
         and [json.loads(l)["fileId"] for l in sv.pings[0]["cuerpo"].decode().splitlines()] == ["ID-ARCHIVO-1"],
         "g) el latido de los eventos (su propia URL): un POST de exito con el fileId, y el de la base sin tocar")

    escribir_log(api, [EV_REUTILIZACION, EV_NO_PERMITIDO, EV_REDACCION.replace("tramos=0+4", "tramos=5+2")])
    r2 = correr("eventos", sv, api=api, cursor=cursor)
    pasa(r2.rc == 0 and len(sv.subidas) == 2, f"g) segunda exportacion: codigo {r2.rc} y una subida mas")
    if len(sv.subidas) == 2:
        mensajes2, _ = mensajes_de(sv.subidas[1]["cuerpo"])
        pasa(mensajes2 == [EV_REUTILIZACION, EV_REDACCION.replace("tramos=0+4", "tramos=5+2")],
             "g) la segunda solo lleva lo nuevo (el cursor evita repetir)")
    c2 = leer_cursor_literal(cursor)
    pasa(c2 is not None and c2[1] > c1[1] and c2[0] == c1[0], "g) el cursor avanza y conserva el Id del contenedor")
    r3 = correr("eventos", sv, api=api, cursor=cursor)
    pasa(r3.rc == 0 and len(sv.subidas) == 2, "g) sin eventos nuevos: codigo 0 y no sube nada")
    pasa(sv.latidos_eventos == ["ok", "ok", "ok"] and sv.pings[-1]["cuerpo"] == b"",
         "g) el latido de los eventos llega en CADA ejecucion correcta, tambien sin nada que subir (cuerpo vacio)")

    # Cursor danado: falla de forma visible, sin subir ni mover nada. Control:
    # el cursor bueno (el de arriba) funciona.
    for texto, esperado, nombre in (("basura\n", "punto inventado", "danado"),
                                    ("123456789012345678\n", "formato antiguo", "en el formato antiguo")):
        malo = TEMPORAL / "cursor_malo.txt"
        malo.write_text(texto, encoding="ascii", newline="")
        svm = ServidorB2()
        rm = correr("eventos", svm, api=api, cursor=malo)
        negativo(f"g) un cursor {nombre}: codigo {RC_ERROR}, falla de forma visible, no sube nada y hace /fail",
                 rm.rc == RC_ERROR and esperado in rm.err and not svm.subidas and svm.latidos_eventos == ["fail"]
                 and malo.read_text(encoding="ascii") == texto,
                 r3.rc == 0, f"codigo {rm.rc} {rm.err.strip()[-200:]}")

    # Hueco: contenedor con rotacion minima; tras fijar el cursor se escriben
    # muchas lineas y el log se come las anteriores.
    api2 = f"{PROYECTO}_api2"
    crear_api_falsa(api2, ["--log-opt", "max-size=1k", "--log-opt", "max-file=2"])
    cursor2 = TEMPORAL / "cursor2.txt"
    sv2 = ServidorB2()
    escribir_log(api2, [EV_NO_VERAZ])
    ra = correr("eventos", sv2, api=api2, cursor=cursor2)
    escribir_log(api2, [EV_REDACCION.replace("tramos=0+4", f"tramos={i}+1") for i in range(120)])
    rb = correr("eventos", sv2, api=api2, cursor=cursor2)
    subidas_antes_control = len(sv2.subidas)
    escribir_log(api2, [EV_NO_VERAZ])
    rc_ = correr("eventos", sv2, api=api2, cursor=cursor2)
    hueco_fichero = TEMPORAL / "cursor2.hueco"
    existia = hueco_fichero.is_file()
    hueco_fichero.unlink(missing_ok=True)  # "reconocerlo": borrar el fichero del hueco
    rd = correr("eventos", sv2, api=api2, cursor=cursor2)
    control_hueco = ra.rc == 0 and rd.rc == 0 and existia
    negativo(f"g) una rotacion que se come lineas: codigo {RC_HUECO}, avisa del HUECO y sube lo que habia",
             rb.rc == RC_HUECO and "HUECO" in rb.err and subidas_antes_control == 2, control_hueco,
             f"codigo {rb.rc} subidas {subidas_antes_control} {rb.err.strip()[-200:]}")
    negativo(f"g) el hueco persiste hasta reconocerlo: la ejecucion siguiente sigue con el codigo {RC_HUECO} y sigue subiendo lo nuevo",
             rc_.rc == RC_HUECO and "sin reconocer" in rc_.err and len(sv2.subidas) == 3, control_hueco,
             f"codigo {rc_.rc} subidas {len(sv2.subidas)}")
    pasa(rd.rc == 0 and len(sv2.subidas) == 3,
         "g) control: reconocido el hueco (fichero borrado) y sin eventos nuevos, codigo 0")
    pasa(sv2.latidos_eventos == ["ok", "fail", "fail", "ok"], f"g) latidos de los eventos: ok, fail, fail, ok ({sv2.latidos_eventos})")
    fallos = [x for x in sv2.pings if x["fallo"]]
    pasa(len(fallos) == 2 and all(b"HUECO" in x["cuerpo"] for x in fallos) and b"ID-ARCHIVO-2" in fallos[0]["cuerpo"],
         "g) el /fail de los eventos lleva el motivo (HUECO) y lo subido en el cuerpo")

    # API recreada: NO es un hueco. Mismo flujo que el de arriba, pero el
    # contenedor se destruye y se crea otro con el mismo nombre (otro Id). El
    # control es la rotacion real de arriba, que SI da hueco.
    api5 = f"{PROYECTO}_api5"
    crear_api_falsa(api5)
    cursor5 = TEMPORAL / "cursor5.txt"
    sv5 = ServidorB2()
    escribir_log(api5, [EV_NO_VERAZ])
    r5a = correr("eventos", sv5, api=api5, cursor=cursor5)
    id_antes = id_real(api5)
    ejecutar(["docker", "rm", "-f", "-v", api5])
    crear_api_falsa(api5)
    pasa(id_real(api5) != id_antes and id_real(api5) != "", "g) la API recreada es un contenedor con otro Id (comprobado con docker inspect)")
    nueva = EV_REDACCION.replace("tramos=0+4", "tramos=7+7")
    escribir_log(api5, [nueva])
    r5b = correr("eventos", sv5, api=api5, cursor=cursor5)
    negativo("g) API recreada: NO hay HUECO (codigo 0), si el aviso 'contenedor_nuevo', y se exporta todo el log nuevo",
             r5a.rc == 0 and r5b.rc == 0 and "HUECO" not in r5b.todo and "EVENTO contenedor_nuevo" in r5b.err
             and len(sv5.subidas) == 2 and not (TEMPORAL / "cursor5.hueco").exists(),
             rb.rc == RC_HUECO and "HUECO" in rb.err, f"codigos {r5a.rc} {r5b.rc} {r5b.err.strip()[-300:]}")
    if len(sv5.subidas) == 2:
        mensajes5, miembros5 = mensajes_de(sv5.subidas[1]["cuerpo"])
        manifiesto5 = json.loads(miembros5["manifiesto.json"])
        pasa(mensajes5 == [nueva] and manifiesto5["contenedor_nuevo"] is True and manifiesto5["desde_exclusivo_ns"] is None
             and manifiesto5["hueco"] is False, "g) lo exportado es todo el log nuevo; el manifiesto dice contenedor_nuevo y no hueco")
        pasa(sv5.latidos_eventos == ["ok", "ok"] and b"contenedor_nuevo" in sv5.pings[-1]["cuerpo"],
             "g) el aviso de contenedor nuevo va en el cuerpo del latido (exito)")
    c5 = leer_cursor_literal(cursor5)
    pasa(c5 is not None and c5[0] == id_real(api5), "g) tras el aviso, el cursor ya lleva el Id del contenedor nuevo")


def buscar(datos, marcas):
    """Etiquetas de las marcas que aparecen en datos (bytes)."""
    return [etiqueta for etiqueta, valor in marcas.items() if valor.encode("utf-8") in datos]


def seccion_h():
    p("=== h) ninguna marca en claro fuera del cifrado")
    # Una copia de la base y una de eventos con el temporal conservado.
    temporal_base = TEMPORAL / "tmp_base"
    temporal_base.mkdir()
    sv = ServidorB2()
    r = correr("base", sv, bd=IDS["bd"], temporal=temporal_base)
    ficheros = [f for f in temporal_base.rglob("*") if f.is_file()]
    control_t = r.rc == 0 and len(ficheros) >= 1 and all(f.stat().st_size > 0 for f in ficheros)
    api = f"{PROYECTO}_api3"
    crear_api_falsa(api)
    escribir_log(api, [EV_REDACCION, EV_NO_VERAZ, EV_MARCADO])
    temporal_ev = TEMPORAL / "tmp_eventos"
    temporal_ev.mkdir()
    sv_ev = ServidorB2()
    r2 = correr("eventos", sv_ev, api=api, cursor=TEMPORAL / "cursor3.txt", temporal=temporal_ev)
    ficheros_ev = [f for f in temporal_ev.rglob("*") if f.is_file()]
    control_e = r2.rc == 0 and len(ficheros_ev) >= 1
    if sv_ev.subidas:
        _, miembros_ev = mensajes_de(sv_ev.subidas[0]["cuerpo"])
        CONTROLES["marca_evento_en_log_descifrado"] = MARCA_EVENTO.encode() in miembros_ev["eventos.log"]

    # Controles de la propia busqueda: encuentra una marca en un texto de muestra.
    muestra = ("contiene " + MARCA_EMAIL).encode()
    pasa(buscar(muestra, MARCAS) == ["email"], "h) control: la busqueda encuentra una marca en un texto de muestra")
    muestra_b64 = ("Authorization: Basic " + B2_BASE64).encode()
    pasa(buscar(muestra_b64, {"clave de B2 en base64": B2_BASE64}) == ["clave de B2 en base64"],
         "h) control: la busqueda encuentra base64(id:clave) en una cabecera de muestra")
    pasa(CONTROLES.get("marca_en_bd_restaurada") is True, "h) control: la marca del email esta en la base restaurada")
    pasa(CONTROLES.get("marca_evento_en_log_descifrado") is True, "h) control: la marca del evento esta en el log descifrado")
    pasa(CONTROLES.get("tar_plano_tiene_marcadores") is True, "h) control: el tar descifrado lleva los marcadores de texto plano (PGDMP, manifiesto.json)")
    pasa(control_t, f"h) control: la copia de la base deja su temporal cifrado ({len(ficheros)} fichero(s))")
    pasa(control_e, f"h) control: la copia de eventos deja su temporal cifrado ({len(ficheros_ev)} fichero(s))")
    if not (control_t and control_e and all(CONTROLES.get(k) is True for k in (
            "marca_en_bd_restaurada", "marca_evento_en_log_descifrado", "tar_plano_tiene_marcadores"))):
        sinc("h) los controles de la busqueda fallaron: no se puede concluir")
        return

    # La clave de B2 se busca literal Y como la manda el cliente (Basic base64).
    todo_marcas = {**MARCAS, "clave de B2": B2_CLAVE, "URL del latido": LATIDO_UUID,
                   "URL del latido de eventos": LATIDO_EVENTOS_UUID, "clave de B2 en base64": B2_BASE64}
    todo_planos = {f"texto plano {x!r}": x for x in PLANOS}
    for nombre, conjunto in (("temporal de la copia de la base", ficheros), ("temporal de la copia de eventos", ficheros_ev)):
        datos = b"".join(f.read_bytes() for f in conjunto)
        negativo(f"h) {nombre}: ninguna marca sembrada ni texto plano de tar o volcado",
                 not buscar(datos, {**todo_marcas, **todo_planos}), control_t and control_e,
                 f"encontrado: {buscar(datos, {**todo_marcas, **todo_planos})}")
    subido = b"".join(s["cuerpo"] for sv_ in SERVIDORES for s in sv_.subidas)
    negativo(f"h) lo subido a B2 ({sum(len(sv_.subidas) for sv_ in SERVIDORES)} objetos): ninguna marca ni texto plano",
             not buscar(subido, {**todo_marcas, **todo_planos}), control_t and control_e,
             f"encontrado: {buscar(subido, {**todo_marcas, **todo_planos})}")
    # Lo que el script manda a los latidos (cuerpos) tampoco lleva marcas ni claves.
    cuerpos = b"".join(x["cuerpo"] for sv_ in SERVIDORES for x in sv_.pings)
    negativo("h) los cuerpos de los latidos: ninguna marca, ni la clave de B2, ni texto plano",
             not buscar(cuerpos, {**todo_marcas, **todo_planos}) and len(cuerpos) > 0, control_t and control_e,
             f"encontrado: {buscar(cuerpos, {**todo_marcas, **todo_planos})}")
    salida_scripts = "\n".join(SALIDAS_SCRIPT).encode("utf-8")
    negativo(f"h) salida de las {len(SALIDAS_SCRIPT)} ejecuciones de copias.py: ninguna marca, ni la clave de B2 (ni en base64), ni la URL de los latidos",
             not buscar(salida_scripts, todo_marcas), control_t and control_e and len(SALIDAS_SCRIPT) > 5,
             f"encontrado: {buscar(salida_scripts, todo_marcas)}")
    salida_bateria = "\n".join(lineas_salida).encode("utf-8")
    negativo("h) salida de esta bateria: ninguna marca, ni la clave de B2 (ni en base64), ni la URL de los latidos",
             not buscar(salida_bateria, todo_marcas), control_t and control_e,
             f"encontrado: {buscar(salida_bateria, todo_marcas)}")


# ---------------------------------------------------------------------------
# Limpieza y principal
# ---------------------------------------------------------------------------
def recursos_previos():
    previos = []
    for orden in (["docker", "ps", "-a", "--format", "{{.Names}}"],
                  ["docker", "network", "ls", "--format", "{{.Name}}"],
                  ["docker", "volume", "ls", "--format", "{{.Name}}"],
                  ["docker", "image", "ls", "--format", "{{.Repository}}"]):
        previos += [n for n in ejecutar(orden).out.split() if n.startswith(PROYECTO)]
    return previos


def estado_git():
    try:
        r = ejecutar(["git", "status", "--short", "-uall"], timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.rc != 0:
        return None
    return [l.rstrip() for l in r.out.splitlines() if l.strip()]


def limpiar():
    """down -v, los contenedores desechables y las imagenes: siempre, tambien si algo falla."""
    for sv in SERVIDORES:
        try:
            sv.cerrar()
        except OSError:
            pass
    if TEMPORAL is not None and (TEMPORAL / "compose.yml").is_file():
        r = dc("down", "-v", "--remove-orphans")
        p(f"down -v --remove-orphans -> codigo {r.rc}")
    nombres = [n for n in ejecutar(["docker", "ps", "-a", "--format", "{{.Names}}"]).out.split() if n.startswith(PROYECTO)]
    if nombres:
        ejecutar(["docker", "rm", "-f", "-v", *nombres])
    ejecutar(["docker", "rmi", IMG_HERR])
    ejecutar(["docker", "rmi", IMG_PG])
    restos = recursos_previos()
    pasa(not restos, f"z) ningun recurso de Docker con prefijo {PROYECTO} {restos if restos else ''}".strip())
    if TEMPORAL is not None:
        shutil.rmtree(TEMPORAL, ignore_errors=True)
    final = estado_git()
    if ESTADO_GIT_ARRANQUE is None or final is None:
        sinc("z) no se pudo comparar el estado de Git")
    else:
        pasa(final == ESTADO_GIT_ARRANQUE, "z) la bateria no ha modificado el repo (git status igual al del arranque)")


def terminar():
    resultado = "NO OK (hay FALLA o SIN CONCLUSION)" if estado["falla"] or estado["sin_conclusion"] else "OK"
    p("RESULTADO GLOBAL: " + resultado)
    SALIDA.write_text("\n".join(lineas_salida) + "\n", encoding="utf-8", newline="\n")
    sys.exit(0 if resultado == "OK" else 1)


def terminar_con_parada():
    p("RESULTADO GLOBAL: NO OK (PARADA)")
    SALIDA.write_text("\n".join(lineas_salida) + "\n", encoding="utf-8", newline="\n")
    sys.exit(1)


def main():
    global TEMPORAL, ESTADO_GIT_ARRANQUE
    ESTADO_GIT_ARRANQUE = estado_git()
    # Precondiciones: si fallan, no se limpia nada (podrian ser recursos ajenos).
    if ejecutar(["docker", "info", "--format", "{{.ServerVersion}}"]).rc != 0:
        p("PARADA: docker info falla")
        terminar_con_parada()
    previos = recursos_previos()
    if previos:
        p(f"PARADA: ya existen recursos con prefijo {PROYECTO}: {previos}")
        terminar_con_parada()
    for ruta in (COPIAS, RAIZ / "db" / "pg_hba.conf", RAIZ / "db" / "init" / "01_roles.sh", RAIZ / "db" / "Dockerfile"):
        if not ruta.is_file():
            p(f"PARADA: no existe {ruta}")
            terminar_con_parada()
    TEMPORAL = pathlib.Path(tempfile.mkdtemp(prefix="canario-copias-"))
    parada = None
    try:
        escribir_compose()
        construir_imagenes()
        generar_claves()
        seccion_a()
        seccion_b_c()
        seccion_d()
        seccion_e()
        seccion_f()
        seccion_i()
        seccion_j()
        seccion_g()
        seccion_h()
    except Parada as e:
        parada = str(e)
        p(f"PARADA: {parada}")
    except Exception:  # noqa: BLE001 - error inesperado del propio test: se informa y se limpia
        parada = "error inesperado en el test"
        p("ERROR INESPERADO:\n" + traceback.format_exc())
    finally:
        limpiar()
    if parada is not None:
        estado["falla"] = True
    terminar()


if __name__ == "__main__":
    main()
