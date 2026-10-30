#!/usr/bin/env python3
"""Batería de escaneos de seguridad: secretos en Git, dependencias de Python,
análisis estático, vulnerabilidades y secretos de las imágenes, configuración
de los Dockerfiles, dependencias de npm de la SPA y SBOM.

Qué prueba:
  a) que las herramientas son las fijadas (versión y digest) y responden;
  b) gitleaks sobre el historial de Git y sobre lo que se podría commitear (lo
     seguido más lo nuevo no ignorado, sin secrets/), con el secreto
     enmascarado en la salida, y que en secrets/ Git solo sigue .gitkeep y
     README.md;
  c) pip-audit sobre requirements.txt (sin vulnerabilidades conocidas) y que
     sus hashes coinciden con los ficheros que publica PyPI;
  d) bandit sobre app/ (sin hallazgos de severidad media o alta y sin # nosec);
  e) Trivy sobre las cinco imágenes (api, caddy, postgres, redis y mailpit, la del
     correo de desarrollo): ninguna
     vulnerabilidad HIGH o CRITICAL con arreglo publicado que no esté declarada
     como no explotable en tests/security/canario.openvex.json, ningún secreto,
     declaraciones VEX vigentes (30 días como máximo), con efecto y atadas a la
     versión exacta del componente; postgres sin gosu y sin root por defecto;
     caddy sin curl, libcurl ni brotli-libs;
     las vulnerabilidades sin arreglo se listan (riesgo residual, sección 8 del
     modelo de amenazas);
  f) que lo que el VEX declara no alcanzable no lo es: Caddy solo con HTTP/1.1
     (configuración adaptada y ALPN real en los dos puertos), cada file_server
     detrás de la quita de la cabecera Range, sin ECH, sin el servidor ACME
     (acme_server) y sin verificar nunca el certificado de otro (lista blanca
     sobre la configuración adaptada);
     mailpit sin configuración y solo en su red interna; y en postgres, que
     libcurl solo la enlaza el módulo OAuth del lado cliente de libpq y que
     pg_hba.conf no tiene el método oauth;
  g) Trivy sobre los Dockerfiles (sin fallos HIGH o CRITICAL);
  h) un SBOM CycloneDX por imagen, que se deja en el directorio temporal del
     sistema (canario_sbom);
  i) versiones de las herramientas y fecha de la base de datos de Trivy, para
     poder reproducir el resultado;
  j) Trivy sobre spa/package-lock.json, con las dependencias de desarrollo:
     ninguna vulnerabilidad HIGH o CRITICAL con arreglo publicado que no esté
     declarada en el mismo VEX (con su control y su atadura a la versión,
     como en las imágenes). La imagen de Caddy solo lleva el JavaScript
     compilado, sin package.json: Trivy no sabría de qué paquetes viene, así
     que se escanea el lock. Las de desarrollo cuentan porque se ejecutan al
     compilar (proxy/Dockerfile). Además: cada override de spa/package.json
     (vite y zod) es el que está en el lock y sigue haciendo falta (falla
     cuando el paquete que lo fija ya trae una versión arreglada, para
     retirarlo), y cada entrada del lock que cambia respecto a HEAD se lista
     con su fecha de publicación y tiene al menos 14 días (la consulta al
     registro de npm es solo de metadatos, en JSON).
Cada prueba negativa lleva su control positivo con datos sintéticos: si el
control falla, el resultado es SIN CONCLUSION, nunca PASA. Los oráculos son
literales.

Cómo se ejecuta (desde la raíz del repositorio, en PowerShell, con Docker en
marcha y conexión a internet):

    python tests/security/verificar_escaneos.py

Necesita red para descargar las imágenes de las herramientas, los paquetes de
pip-audit y bandit (con hashes), la base de datos de Trivy, los avisos de OSV
y las fechas de publicación del registro de npm.
Si falla algo de eso, el resultado es SIN CONCLUSION. Los escaneos de Trivy y
de gitleaks se ejecutan después sin red (--network none).

Usa un proyecto de Docker propio (canario_escaneos): construye las imágenes de
postgres, api y caddy con docker-compose.yml y no levanta ningún servicio. Los
contenedores de las herramientas no reciben el socket de Docker (las imágenes
se les pasan exportadas con docker save), ni secretos, ni el directorio
secrets/: el historial de Git se monta como .git en solo lectura y lo demás es
una copia temporal sin secrets/. Todos corren con el sistema de ficheros de
solo lectura, sin capacidades, sin escalada de privilegios y sin root. Al
terminar lo borra todo (imágenes construidas, volumen de caché, red y
contenedores). No lee ningún secreto: solo comprueba que los ficheros de
secrets/ existen.

Los ficheros auxiliares van a un directorio temporal del sistema, nunca dentro
del repositorio. La salida completa se guarda en verificacion_escaneos.txt
dentro del directorio temporal del sistema. El código de salida es 0 solo si
el resultado global es OK.

Solo usa la biblioteca estándar.
"""
import collections
import datetime
import json
import pathlib
import re
import secrets
import shutil
import string
import subprocess
import sys
import tempfile
import traceback
import urllib.error
import urllib.parse
import urllib.request

RAIZ = pathlib.Path.cwd()
PROYECTO = "canario_escaneos"
SALIDA = pathlib.Path(tempfile.gettempdir()) / "verificacion_escaneos.txt"
DIR_SBOM = pathlib.Path(tempfile.gettempdir()) / "canario_sbom"
BASE = ["docker", "compose", "-p", PROYECTO, "-f", "docker-compose.yml"]

lineas_salida = []
estado = {"falla": False, "sin_conclusion": False}

# ---------------------------------------------------------------------------
# Oráculos literales
# ---------------------------------------------------------------------------
# Herramientas fijadas por versión y digest (índice multiarquitectura).
# Trivy 0.74.0: release inmutable del 14 de agosto de 2026, posterior al
# compromiso de marzo (GHSA-69fq-xp46-6x23); el mismo digest en Docker Hub y
# GHCR; firma cosign verificada al fijarlo con la identidad
# reusable-release.yaml@refs/tags/v0.74.0. gitleaks 8.30.1: el mismo digest en
# Docker Hub y GHCR; no publica firma. Ninguna tenía menos de 14 días.
IMG_TRIVY = "aquasec/trivy:0.74.0@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969"
IMG_GITLEAKS = "ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"
# El mismo Python que la imagen de la API.
IMG_PYTHON = "python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1"
VERSION_TRIVY = "Version: 0.74.0"
VERSION_GITLEAKS = "v8.30.1"
VERSION_PIP_AUDIT = "pip-audit 2.10.1"
VERSION_BANDIT = "bandit 1.9.4"
# Repositorio de la base de datos explícito: el oficial, no un espejo.
DB_TRIVY = "ghcr.io/aquasecurity/trivy-db:2"

# Controles
REGLA_GITLEAKS = "github-pat"
REGLA_SECRETO_TRIVY = "github-pat"
AVISO_CONTROL_PIP = "PYSEC-2019-217"  # Jinja2 2.10, CVE-2019-10906
CVE_CONTROL_TRIVY = "CVE-2019-10906"
REQUISITO_VULNERABLE = (
    "jinja2==2.10 \\\n"
    "    --hash=sha256:74c935a1b8bb9a3947c50a54766a969d4846290e1e788ea44c1392163723c3bd \\\n"
    "    --hash=sha256:f84be1bb0040caca4cea721fcbbbbd61f9be9464ca236387158b0feea01914a4\n"
)
MENSAJE_HASH = "THESE PACKAGES DO NOT MATCH THE HASHES"
PAQUETE_ALTERADO = "fastapi"
TEST_BANDIT_CONTROL = "B602"
CODIGO_BANDIT_CONTROL = "import subprocess\n\n\ndef f(orden):\n    return subprocess.call(orden, shell=True)\n"
CHECK_CONTROL_DOCKERFILE = "DS-0002"
# Control de j): un lock con @angular/common 22.0.0, que tiene este aviso HIGH
# con arreglo en la 22.0.1 (Trivy 0.74.0 lo informa por su CVE, comprobado).
AVISO_CONTROL_NPM = "CVE-2026-54266"
LOCK_CONTROL = {
    "name": "control", "lockfileVersion": 3, "requires": True,
    "packages": {"": {"name": "control", "dependencies": {"@angular/common": "22.0.0"}},
                 "node_modules/@angular/common": {"version": "22.0.0"}},
}
# Overrides de spa/package.json: (paquete que fija la versión vulnerable,
# dependencia, primera versión arreglada, versión que declararía un padre ya
# arreglado, para el control). vite (CVE-2026-112942, arreglada en la 8.3.3):
# @angular/build 22.2.x fija vite 8.3.0 exacta; se fuerza la 8.3.4, la que ya
# usa @angular/build 22.3.0-next, con más de 14 días al fijarla. zod
# (CVE-2023-54404, arreglada en la 4.6.6): @angular/cli 22.2.x fija zod 4.6.5
# exacta; la 4.6.6 se publicó el 11 de octubre de 2026.
OVERRIDES_SPA = {"vite": "8.3.4", "zod": "4.6.6"}
OVERRIDES_MOTIVO = {"vite": ("@angular/build", (8, 3, 3), "8.3.4"),
                    "zod": ("@angular/cli", (4, 6, 6), "4.6.6")}
# Regla de los 14 días (docs/threat-model.md, 6.17) sobre lo que cambia en el
# lock. Control: vite 8.3.4 (publicada el 8 de octubre) evaluada como si
# hoy fuera el 9 de octubre tiene menos de 14 días.
DIAS_ESPERA = 14
CONTROL_RECIENTE = ("vite", "8.3.4", datetime.datetime(2026, 10, 9, tzinfo=datetime.UTC))
REGISTRO_NPM = "https://registry.npmjs.org/"
DOCKERFILE_CONTROL = "FROM alpine:3.20\nRUN echo hola\n"
SEGUIDOS_EN_SECRETS = ["secrets/.gitkeep", "secrets/README.md"]
SBOM_API_CONTROL = ("fastapi", "0.143.0")

# Postgres
GOSU = "/usr/local/bin/gosu"
USUARIO_POSTGRES = "70:70"
IMG_POSTGRES_BASE = "postgres:18.6-alpine@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873"
# Alcanzabilidad de libcurl en postgres (CVE-2026-92392 y CVE-2026-111497): el
# único fichero que la enlaza, el módulo OAuth del lado cliente de libpq, y el
# pg_hba.conf real. Control: una regla con el método oauth.
LIBPQ_OAUTH = "/usr/local/lib/libpq-oauth-18.so"
PG_HBA = RAIZ / "db" / "pg_hba.conf"
PG_HBA_CONTROL = "host canario aplicacion samenet oauth issuer=https://idp.invalid scope=openid\n"

# Caddy sin curl (proxy/Dockerfile): ni curl ni lo que solo él necesitaba, con
# sus CVE (CVE-2026-92392 y CVE-2026-111497). Control: la imagen base los trae.
IMG_CADDY_BASE = "caddy:2.11.7-alpine@sha256:d8542f48d34a9cf4e4c11a478865229840e87e4c96ea3f439101f31a5d35f75f"
PAQUETES_SIN_CURL = ("curl", "libcurl", "brotli-libs")

# VEX
VEX = RAIZ / "tests" / "security" / "canario.openvex.json"
MAX_DIAS_VEX = 30
JUSTIFICACIONES_OPENVEX = {"component_not_present", "vulnerable_code_not_present",
                           "vulnerable_code_not_in_execute_path",
                           "vulnerable_code_cannot_be_controlled_by_adversary",
                           "inline_mitigations_already_exist"}
# Lo que el VEX declara no explotable en cada imagen.
# CVE-2026-111943 se retiró el 26 de octubre de 2026, cuando la base de datos
# de Trivy la bajó a MEDIUM, y se volvió a declarar el 29, cuando la subió
# otra vez a HIGH. CVE-2026-116587 (go-jose) entró el 29 de octubre de 2026.
CVES_VEX = {"caddy": {"CVE-2026-78667", "CVE-2026-78669", "CVE-2026-97031", "CVE-2026-111943",
                      "CVE-2026-116587"},
            "mailpit": {"CVE-2026-111943"},
            "postgres": {"CVE-2026-92392", "CVE-2026-111497"}}
# Lo que el mismo VEX declara no explotable en spa/package-lock.json (j).
# CVE-2026-109869 (undici 8.11.2) se retiró el 29 de octubre de 2026 al
# adoptar undici 8.12.2, que la arregla, cumplidos los 14 días.
CVES_VEX_LOCK = set()
# Para el control de atadura a la versión: las mismas declaraciones con la
# versión siguiente del componente no deben suprimir nada.
VERSIONES_VEX = {"pkg:golang/stdlib@v1.26.8": "pkg:golang/stdlib@v1.26.9",
                 "pkg:golang/stdlib@v1.27.2": "pkg:golang/stdlib@v1.27.3",
                 "pkg:golang/golang.org/x/net@v0.59.0": "pkg:golang/golang.org/x/net@v0.60.0",
                 "pkg:golang/github.com/go-jose/go-jose/v4@v4.1.5": "pkg:golang/github.com/go-jose/go-jose/v4@v4.1.6",
                 "pkg:apk/alpine/libcurl@8.22.0-r0": "pkg:apk/alpine/libcurl@8.23.0-r0",
                 "pkg:apk/alpine/brotli-libs@1.2.0-r1": "pkg:apk/alpine/brotli-libs@1.2.1-r0"}

# Caddy
PROTOCOLOS_CADDY = ["h1"]
ALPN_REAL = "http/1.1"
ALPN_CONTROL = "h2"

IMAGENES = ("api", "caddy", "postgres", "redis", "mailpit")
SEVERIDADES = "HIGH,CRITICAL"

TEMPORAL = None
ESTADO_GIT_ARRANQUE = None
NOMBRES = {}


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


class SinRed(Exception):
    """Un paso que necesita red falló: lo que depende de él queda SIN CONCLUSION."""


def p(texto=""):
    print(texto, flush=True)
    lineas_salida.append(texto)


def ejecutar(args, entrada=None, timeout=900, cwd=None):
    # check=False explícito: el código de salida lo revisa cada prueba.
    r = subprocess.run(args, input=entrada, capture_output=True, timeout=timeout, check=False, cwd=cwd)
    return R(r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace"))


def dc(*args):
    return ejecutar(BASE + list(args))


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


def montaje(origen, destino, escritura=False):
    return ["--mount", f"type=bind,src={origen},dst={destino}" + ("" if escritura else ",readonly")]


def herramienta(imagen, args, montajes=(), red=False, entrypoint=None, timeout=900, tmp_exec=False):
    """Contenedor desechable con mínimo privilegio: raíz de solo lectura, sin
    capacidades, sin escalada, usuario nobody, /tmp en memoria y sin red salvo
    que la necesite."""
    orden = ["docker", "run", "--rm", "--read-only", "--cap-drop", "ALL",
             "--security-opt", "no-new-privileges", "--user", "65534:65534", "-e", "HOME=/tmp",
             "--tmpfs", "/tmp:size=1g" + (",exec" if tmp_exec else "")]
    if not red:
        orden += ["--network", "none"]
    if entrypoint:
        orden += ["--entrypoint", entrypoint]
    for m in montajes:
        orden += m
    return ejecutar(orden + [imagen] + list(args), timeout=timeout)


def token_sintetico():
    """Token con la forma de un PAT de GitHub, aleatorio en cada ejecución: no
    es de nadie y nunca se imprime."""
    alfabeto = string.ascii_letters + string.digits
    return "ghp_" + "".join(secrets.choice(alfabeto) for _ in range(36))


def json_de(ruta):
    try:
        return json.loads(pathlib.Path(ruta).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def escribir(ruta, texto):
    ruta = pathlib.Path(ruta)
    ruta.parent.mkdir(parents=True, exist_ok=True)
    ruta.write_text(texto, encoding="utf-8", newline="\n")
    return ruta


# ---------------------------------------------------------------------------
# a) Herramientas
# ---------------------------------------------------------------------------
def seccion_a():
    p("=== a) herramientas fijadas")
    for imagen in (IMG_TRIVY, IMG_GITLEAKS, IMG_PYTHON):
        r = ejecutar(["docker", "pull", "-q", imagen], timeout=600)
        if r.rc != 0:
            raise SinRed(f"no se pudo descargar {imagen}: {r.err.strip()[-200:]}")
        digest = imagen.split("@", 1)[1]
        repo_digests = ejecutar(["docker", "image", "inspect", "--format", "{{json .RepoDigests}}", imagen]).out
        pasa(digest in repo_digests, f"a) {imagen.split('@')[0]} tiene el digest fijado")
    r = herramienta(IMG_TRIVY, ["--version"])
    pasa(VERSION_TRIVY in r.out, f"a) trivy --version contiene '{VERSION_TRIVY}'")
    r = herramienta(IMG_GITLEAKS, ["version"])
    pasa(r.out.strip() == VERSION_GITLEAKS, f"a) gitleaks version es '{VERSION_GITLEAKS}'")


# ---------------------------------------------------------------------------
# b) Secretos en Git (gitleaks)
# ---------------------------------------------------------------------------
GIT_SEGURO = ["-e", "GIT_CONFIG_COUNT=1", "-e", "GIT_CONFIG_KEY_0=safe.directory", "-e", "GIT_CONFIG_VALUE_0=*"]


def gitleaks(modo, origen, informe, montaje_origen):
    """gitleaks sin red, con el secreto enmascarado (--redact) y el informe en JSON."""
    salida = TEMPORAL / "gitleaks"
    salida.mkdir(exist_ok=True)
    r = herramienta(IMG_GITLEAKS, [modo, origen, "--redact", "--no-banner", "--report-format", "json",
                                   "--report-path", f"/out/{informe}"],
                    montajes=[montaje_origen, montaje(salida, "/out", escritura=True)])
    return r, json_de(salida / informe)


def gitleaks_git(ruta_git, informe):
    salida = TEMPORAL / "gitleaks"
    salida.mkdir(exist_ok=True)
    orden = ["docker", "run", "--rm", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
             "--user", "65534:65534", "--network", "none", *GIT_SEGURO,
             *montaje(ruta_git, "/repo/.git"), *montaje(salida, "/out", escritura=True),
             IMG_GITLEAKS, "git", "/repo", "--redact", "--no-banner", "--report-format", "json",
             "--report-path", f"/out/{informe}"]
    r = ejecutar(orden)
    return r, json_de(salida / informe)


def git_control(*args, cwd):
    """git en el repositorio de control, sin la configuración global ni hooks."""
    ganchos = TEMPORAL / "sin_ganchos"
    ganchos.mkdir(exist_ok=True)
    base = ["git", "-c", "user.name=control", "-c", "user.email=control@canario.invalid",
            "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", "-c", f"core.hooksPath={ganchos}"]
    return ejecutar(base + list(args), cwd=cwd)


def seccion_b():
    p("=== b) secretos en Git (gitleaks)")
    # Control: un repositorio temporal, fuera del proyecto, con un token
    # sintético commiteado. gitleaks debe encontrarlo en el historial y en el
    # directorio, y la salida no debe contener el token.
    token = token_sintetico()
    ctl = TEMPORAL / "control_git"
    ctl.mkdir()
    escribir(ctl / "config.py", f'token = "{token}"\n')
    ok_git = all(git_control(*a, cwd=ctl).rc == 0 for a in (["init", "-q"], ["add", "config.py"], ["commit", "-qm", "control"]))
    if not ok_git:
        raise Parada("no se pudo crear el repositorio de control con git")
    r_ch, rep_ch = gitleaks_git(ctl / ".git", "control_historial.json")
    control_historial = r_ch.rc == 1 and bool(rep_ch) and rep_ch[0].get("RuleID") == REGLA_GITLEAKS
    pasa(control_historial, f"b) control: gitleaks git encuentra el token sintetico con la regla {REGLA_GITLEAKS}")
    copia = TEMPORAL / "control_dir"
    copia.mkdir()
    shutil.copyfile(ctl / "config.py", copia / "config.py")
    r_cd, rep_cd = gitleaks("dir", "/c", "control_dir.json", montaje(copia, "/c"))
    control_dir = r_cd.rc == 1 and bool(rep_cd) and rep_cd[0].get("RuleID") == REGLA_GITLEAKS
    pasa(control_dir, f"b) control: gitleaks dir encuentra el token sintetico con la regla {REGLA_GITLEAKS}")
    textos = r_ch.todo + r_cd.todo + json.dumps(rep_ch) + json.dumps(rep_cd)
    negativo("b) --redact: el token no aparece en la salida ni en los informes (Secret y Match = REDACTED)",
             token not in textos and all(x.get("Secret") == "REDACTED" for x in (rep_ch or []) + (rep_cd or [])),
             control_historial and control_dir)

    # Historial real: solo se monta .git, en solo lectura.
    r, rep = gitleaks_git(RAIZ / ".git", "historial.json")
    negativo("b) historial de Git: ningun hallazgo", r.rc == 0 and rep == [], control_historial,
             f"rc={r.rc} reglas={[x.get('RuleID') for x in rep or []]} ficheros={[x.get('File') for x in rep or []]}")
    commits = re.search(r"(\d+) commits scanned", r.todo)
    p(f"   commits escaneados: {commits.group(1) if commits else 'desconocido'}")

    # Candidatos a commit: lo seguido y lo nuevo no ignorado, copiado a un
    # directorio temporal SIN secrets/ (no se abre nada de ese directorio).
    r = ejecutar(["git", "ls-files", "-co", "--exclude-standard", "-z"], cwd=RAIZ)
    if r.rc != 0:
        raise Parada("git ls-files falla")
    candidatos = TEMPORAL / "candidatos"
    copiados = []
    for ruta in r.out.split("\0"):
        if not ruta or ruta.startswith("secrets/"):
            continue
        origen = RAIZ / ruta
        if not origen.is_file():  # borrado en el árbol de trabajo
            continue
        destino = candidatos / ruta
        destino.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(origen, destino)
        copiados.append(ruta)
    en_secrets = [c.relative_to(candidatos).as_posix() for c in candidatos.rglob("*")
                  if c.relative_to(candidatos).as_posix().startswith("secrets")]
    pasa(copiados and not en_secrets, f"b) copia de candidatos: {len(copiados)} ficheros, ninguno bajo secrets/ {en_secrets if en_secrets else ''}".strip())
    r, rep = gitleaks("dir", "/c", "candidatos.json", montaje(candidatos, "/c"))
    negativo("b) candidatos a commit (seguidos y nuevos no ignorados, sin secrets/): ningun hallazgo",
             r.rc == 0 and rep == [], control_dir,
             f"rc={r.rc} reglas={[x.get('RuleID') for x in rep or []]} ficheros={[x.get('File') for x in rep or []]}")

    # secrets/: Git solo sigue los dos ficheros públicos y nada más es candidato.
    seguidos = sorted(ejecutar(["git", "ls-files", "secrets/"], cwd=RAIZ).out.split())
    pasa(seguidos == SEGUIDOS_EN_SECRETS, f"b) en secrets/ Git solo sigue {SEGUIDOS_EN_SECRETS} (sigue {seguidos})")
    nuevos = ejecutar(["git", "ls-files", "-o", "--exclude-standard", "secrets/"], cwd=RAIZ).out.split()
    pasa(not nuevos, f"b) en secrets/ no hay ficheros nuevos sin ignorar {nuevos if nuevos else ''}".strip())


# ---------------------------------------------------------------------------
# c) y d) Dependencias de Python (pip-audit, hashes) y análisis estático (bandit)
# ---------------------------------------------------------------------------
GUION_PYTHON = """set -u
python -m venv --without-pip /tmp/v || exit 10
python -m pip --python /tmp/v/bin/python install -q --require-hashes --only-binary :all: \\
    -r /h/requisitos.txt > /out/instalar.txt 2>&1
echo $? > /out/instalar.rc
[ "$(cat /out/instalar.rc)" = 0 ] || exit 0
/tmp/v/bin/pip-audit --version > /out/version_pip_audit.txt 2>&1
/tmp/v/bin/bandit --version > /out/version_bandit.txt 2>&1
A="/tmp/v/bin/pip-audit --require-hashes --disable-pip --vulnerability-service osv --progress-spinner off --format json"
$A -r /control/vulnerable.txt > /out/audit_control.json 2> /out/audit_control.err; echo $? > /out/audit_control.rc
$A -r /repo/requirements.txt > /out/audit_real.json 2> /out/audit_real.err; echo $? > /out/audit_real.rc
D="python -m pip download -q --no-deps --require-hashes --only-binary :all:"
$D -d /tmp/dl_real -r /repo/requirements.txt > /out/hash_real.txt 2>&1; echo $? > /out/hash_real.rc
$D -d /tmp/dl_control -r /control/alterado.txt > /out/hash_control.txt 2>&1; echo $? > /out/hash_control.rc
/tmp/v/bin/bandit -f json -q /control/control_bandit.py > /out/bandit_control.json 2> /out/bandit_control.err
/tmp/v/bin/bandit -r -f json -q /repo/app > /out/bandit_real.json 2> /out/bandit_real.err
exit 0
"""


def requirements_alterado():
    """requirements.txt con TODOS los hashes de un paquete alterados en un dígito."""
    texto = (RAIZ / "requirements.txt").read_text(encoding="utf-8")
    bloque = re.search(rf"^{PAQUETE_ALTERADO}==\S+ \\\n(?:\s+--hash=sha256:[0-9a-f]{{64}}(?: \\)?\n)+", texto, re.MULTILINE)
    if not bloque:
        raise Parada(f"no se encuentra {PAQUETE_ALTERADO} con hashes en requirements.txt")
    nuevo = bloque.group(0)
    for h in re.findall(r"sha256:([0-9a-f]{64})", nuevo):
        nuevo = nuevo.replace(h, ("0" if h[0] != "0" else "1") + h[1:])
    return texto.replace(bloque.group(0), nuevo)


def leer(ruta):
    try:
        return pathlib.Path(ruta).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def seccion_c_d():
    p("=== c) dependencias de Python (pip-audit y hashes de requirements.txt)")
    control = TEMPORAL / "control_python"
    escribir(control / "vulnerable.txt", REQUISITO_VULNERABLE)
    escribir(control / "alterado.txt", requirements_alterado())
    escribir(control / "control_bandit.py", CODIGO_BANDIT_CONTROL)
    guion = escribir(TEMPORAL / "python" / "guion.sh", GUION_PYTHON)
    salida = TEMPORAL / "python" / "salida"
    salida.mkdir(parents=True)
    r = herramienta(IMG_PYTHON, ["sh", "/trabajo/guion.sh"], red=True, tmp_exec=True, timeout=1200, montajes=[
        montaje(guion.parent, "/trabajo"), montaje(salida, "/out", escritura=True), montaje(control, "/control"),
        montaje(RAIZ / "requirements.txt", "/repo/requirements.txt"),
        montaje(RAIZ / "tests" / "security" / "requisitos_escaneos.txt", "/h/requisitos.txt"),
        montaje(RAIZ / "app", "/repo/app")])
    if r.rc != 0 or leer(salida / "instalar.rc").strip() != "0":
        p(leer(salida / "instalar.txt")[-600:])
        raise SinRed("no se pudieron instalar pip-audit y bandit con --require-hashes")
    pasa(leer(salida / "version_pip_audit.txt").strip() == VERSION_PIP_AUDIT, f"c) {VERSION_PIP_AUDIT} instalado con --require-hashes")

    # pip-audit: control con Jinja2 2.10 y requirements.txt real.
    ctl = json_de(salida / "audit_control.json")
    avisos_ctl = {v["id"] for d in (ctl or {}).get("dependencies", []) for v in d.get("vulns", [])}
    control_audit = AVISO_CONTROL_PIP in avisos_ctl
    pasa(control_audit, f"c) control: pip-audit (OSV) detecta {AVISO_CONTROL_PIP} en jinja2 2.10")
    if not control_audit and not ctl:
        p(leer(salida / "audit_control.err")[-400:])
    real = json_de(salida / "audit_real.json")
    dependencias = (real or {}).get("dependencies", [])
    avisos = [(d["name"], d["version"], v["id"]) for d in dependencias for v in d.get("vulns", [])]
    leida = any(d["name"] == "fastapi" for d in dependencias)
    negativo(f"c) requirements.txt: ninguna vulnerabilidad conocida en {len(dependencias)} dependencias",
             leer(salida / "audit_real.rc").strip() == "0" and not avisos, control_audit and leida, str(avisos))

    # Integridad: pip-audit con --disable-pip solo exige que haya hash, no que
    # sea válido (pip_audit/_dependency_source/requirement.py). La validez la
    # comprueba pip al descargar los wheels de esta plataforma, igual que al
    # construir la imagen.
    control_hash = leer(salida / "hash_control.rc").strip() != "0" and MENSAJE_HASH in leer(salida / "hash_control.txt")
    pasa(control_hash, f"c) control: con los hashes de {PAQUETE_ALTERADO} alterados, pip download falla con '{MENSAJE_HASH}'")
    negativo("c) los hashes de requirements.txt coinciden con los ficheros de PyPI (pip download --require-hashes)",
             leer(salida / "hash_real.rc").strip() == "0", control_hash, leer(salida / "hash_real.txt")[-400:])

    p("=== d) analisis estatico de app/ (bandit)")
    pasa(leer(salida / "version_bandit.txt").splitlines()[:1] == [VERSION_BANDIT], f"d) {VERSION_BANDIT} instalado con --require-hashes")
    ctl = json_de(salida / "bandit_control.json")
    control_bandit = any(x["test_id"] == TEST_BANDIT_CONTROL for x in (ctl or {}).get("results", []))
    pasa(control_bandit, f"d) control: bandit detecta {TEST_BANDIT_CONTROL} (subprocess con shell=True)")
    real = json_de(salida / "bandit_real.json")
    if real is None:
        raise Parada("bandit no produjo JSON sobre app/")
    graves = [(x["test_id"], x["issue_severity"], x["filename"], x["line_number"]) for x in real["results"]
              if x["issue_severity"] in ("MEDIUM", "HIGH")]
    leves = [(x["test_id"], x["filename"], x["line_number"]) for x in real["results"] if x["issue_severity"] == "LOW"]
    totales = real["metrics"]["_totals"]
    negativo("d) app/: ningun hallazgo de severidad media o alta", not graves, control_bandit and totales["loc"] > 0, str(graves))
    # Un # nosec silencia a bandit: cualquiera nuevo debe revisarse, no pasar solo.
    pasa(totales["nosec"] == 0, f"d) app/: ningun # nosec (hay {totales['nosec']})")
    p(f"   lineas analizadas: {totales['loc']}; hallazgos leves: {leves if leves else 'ninguno'}")


# ---------------------------------------------------------------------------
# e) Imágenes (Trivy)
# ---------------------------------------------------------------------------
def trivy(args, montajes=(), red=False, timeout=900):
    cache = ["-v", f"{NOMBRES['cache']}:/cache"]
    return herramienta(IMG_TRIVY, ["--cache-dir", "/cache", *args], montajes=[cache, *montajes], red=red, timeout=timeout)


def escanear(nombre, vex=None, extra=()):
    """Trivy sobre la imagen exportada, sin red y sin actualizar la base de datos."""
    montajes = [montaje(TEMPORAL / "imagenes", "/img")]
    args = ["image", "--input", f"/img/{nombre}.tar", "--scanners", "vuln,secret", "--severity", SEVERIDADES,
            "--skip-db-update", "--offline-scan", "--skip-version-check", "--no-progress", "-q", "--format", "json",
            "--show-suppressed", *extra]
    if vex is not None:
        montajes.append(montaje(vex.parent, "/vex"))
        args += ["--vex", f"/vex/{vex.name}"]
    r = trivy(args, montajes=montajes)
    try:
        return r, json.loads(r.out)
    except ValueError:
        return r, None


def hallazgos(informe):
    vulns, suprimidas, secretos_img = [], [], []
    for res in (informe or {}).get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            vulns.append((res["Target"], v))
        for s in res.get("Secrets") or []:
            secretos_img.append((res["Target"], s["RuleID"]))
        suprimidas.extend(res.get("ExperimentalModifiedFindings") or [])
    return vulns, suprimidas, secretos_img


def preparar_imagenes():
    # gestion y mailpit están bajo su perfil: sin --profile, config no los
    # incluye.
    r = dc("--profile", "gestion", "--profile", "desarrollo", "config", "--format", "json")
    try:
        servicios = json.loads(r.out)["services"]
    except (ValueError, KeyError):
        raise Parada("docker compose config no devuelve JSON") from None
    # gestion se construye con el mismo Dockerfile y contexto que la API: su
    # escaneo es el de la API.
    pasa(servicios["gestion"].get("build") == servicios["api"].get("build"),
         "e) gestion se construye exactamente como la API (mismo build): escanear api la cubre")
    # Igual el broker de canje (app/broker.py): misma imagen, otro punto de entrada.
    pasa(servicios["broker"].get("build") == servicios["api"].get("build"),
         "e) el broker se construye exactamente como la API (mismo build): escanear api la cubre")
    r = dc("build", "postgres", "api", "caddy")
    if r.rc != 0:
        raise SinRed(f"no se pudieron construir las imagenes: {r.err.strip()[-300:]}")
    # Las imágenes que no se construyen se descargan tal como las fija
    # docker-compose.yml (versión y digest).
    for servicio in ("redis", "mailpit"):
        NOMBRES[servicio] = servicios[servicio]["image"]
        r = ejecutar(["docker", "pull", "-q", NOMBRES[servicio]], timeout=600)
        if r.rc != 0:
            raise SinRed(f"no se pudo descargar {NOMBRES[servicio]}")
    for servicio in ("api", "caddy", "postgres"):
        NOMBRES[servicio] = f"{PROYECTO}-{servicio}"
    (TEMPORAL / "imagenes").mkdir()
    for nombre in IMAGENES:
        r = ejecutar(["docker", "save", "-o", str(TEMPORAL / "imagenes" / f"{nombre}.tar"), NOMBRES[nombre]])
        if r.rc != 0:
            raise Parada(f"docker save {NOMBRES[nombre]} falla: {r.err.strip()[-200:]}")
    # Caché de la base de datos en un volumen del proyecto (se borra al final),
    # del usuario nobody: el único paso como root es este chown, con solo la
    # capacidad CHOWN.
    r = ejecutar(["docker", "volume", "create", NOMBRES["cache"]])
    if r.rc != 0:
        raise Parada("no se pudo crear el volumen de cache")
    r = ejecutar(["docker", "run", "--rm", "--network", "none", "--user", "0", "--cap-drop", "ALL", "--cap-add", "CHOWN",
                  "--entrypoint", "chown", "-v", f"{NOMBRES['cache']}:/cache", IMG_TRIVY, "65534:65534", "/cache"])
    if r.rc != 0:
        raise Parada("no se pudo preparar el volumen de cache")
    r = trivy(["image", "--download-db-only", "--db-repository", DB_TRIVY, "--skip-version-check", "--no-progress", "-q"],
              red=True, timeout=600)
    if r.rc != 0:
        raise SinRed(f"no se pudo descargar la base de datos de Trivy: {r.err.strip()[-300:]}")


def seccion_e():
    p("=== e) imagenes (Trivy: vulnerabilidades y secretos)")
    preparar_imagenes()

    # Postgres: sin gosu y sin root por defecto. Control: la imagen base lo
    # trae y no declara usuario.
    def tiene_gosu(imagen):
        r = ejecutar(["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--user", "70:70",
                      "--entrypoint", "sh", imagen, "-c", f"test -e {GOSU} && echo si || echo no"])
        return r.out.strip()

    def usuario(imagen):
        return ejecutar(["docker", "image", "inspect", "--format", "{{.Config.User}}", imagen]).out.strip()

    ejecutar(["docker", "pull", "-q", IMG_POSTGRES_BASE], timeout=600)
    negativo(f"e) postgres: la imagen no contiene {GOSU}", tiene_gosu(NOMBRES["postgres"]) == "no",
             tiene_gosu(IMG_POSTGRES_BASE) == "si")
    negativo(f"e) postgres: la imagen declara USER {USUARIO_POSTGRES}", usuario(NOMBRES["postgres"]) == USUARIO_POSTGRES,
             usuario(IMG_POSTGRES_BASE) == "")

    # Caddy sin curl, libcurl ni brotli-libs. Control: la imagen base los trae.
    def paquetes_apk(imagen):
        orden = "; ".join(f"apk info -e {n} >/dev/null && echo {n}" for n in PAQUETES_SIN_CURL)
        r = ejecutar(["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
                      "--user", "65534:65534", "--entrypoint", "sh", imagen, "-c", f"{orden}; true"])
        return sorted(r.out.split())

    ejecutar(["docker", "pull", "-q", IMG_CADDY_BASE], timeout=600)
    en_base = paquetes_apk(IMG_CADDY_BASE)
    en_caddy = paquetes_apk(NOMBRES["caddy"])
    negativo(f"e) caddy: la imagen no contiene {list(PAQUETES_SIN_CURL)} ({en_caddy})", en_caddy == [],
             en_base == sorted(PAQUETES_SIN_CURL), f"control: la base trae {en_base}")

    # Control de Trivy: rootfs sintético con Jinja2 2.10 y un token.
    token = token_sintetico()
    rfs = TEMPORAL / "control_rootfs"
    escribir(rfs / "usr/lib/python3.12/site-packages/Jinja2-2.10.dist-info/METADATA",
             "Metadata-Version: 2.1\nName: Jinja2\nVersion: 2.10\n")
    escribir(rfs / "etc/config.py", f'token = "{token}"\n')
    r = trivy(["rootfs", "/rfs", "--scanners", "vuln,secret", "--severity", SEVERIDADES, "--skip-db-update",
               "--offline-scan", "--skip-version-check", "--no-progress", "-q", "--format", "json"],
              montajes=[montaje(rfs, "/rfs")])
    vulns, _, secretos_ctl = hallazgos(json_de_texto(r.out))
    control_vuln = any(v["VulnerabilityID"] == CVE_CONTROL_TRIVY for _, v in vulns)
    control_secreto = any(regla == REGLA_SECRETO_TRIVY for _, regla in secretos_ctl)
    pasa(control_vuln, f"e) control: Trivy detecta {CVE_CONTROL_TRIVY} en un rootfs con Jinja2 2.10")
    pasa(control_secreto, f"e) control: Trivy detecta un secreto {REGLA_SECRETO_TRIVY} en el rootfs")
    negativo("e) control: el token sintetico no aparece en la salida de Trivy", token not in r.todo, control_secreto)

    # VEX: forma y vigencia de cada declaración.
    documento = json_de(VEX)
    if documento is None:
        raise Parada(f"{VEX} no es JSON valido")
    ahora = datetime.datetime.now(datetime.UTC)
    for d in documento.get("statements", []):
        cve = d["vulnerability"]["name"]
        momento = datetime.datetime.fromisoformat(d.get("timestamp") or documento["timestamp"])
        dias = (ahora - momento).total_seconds() / 86400
        pasa(-1 <= dias <= MAX_DIAS_VEX, f"e) VEX {cve}: declaracion con {dias:.1f} dias (maximo {MAX_DIAS_VEX}; caducada obliga a revisarla)")
        pasa(d.get("status") == "not_affected" and d.get("justification") in JUSTIFICACIONES_OPENVEX
             and len(d.get("impact_statement", "")) > 40,
             f"e) VEX {cve}: not_affected con justificacion OpenVEX valida ({d.get('justification')}) e impact_statement")
        # El componente vulnerable: el subcomponente de un binario (Go) o, en
        # un paquete del sistema o de npm, el propio producto.
        subcomponentes = ([s["@id"] for prod in d["products"] for s in prod.get("subcomponents", [])]
                          or [prod["@id"] for prod in d["products"]])
        pasa(subcomponentes and all("@" in s for s in subcomponentes),
             f"e) VEX {cve}: atada a version exacta del componente {subcomponentes}")

    # El VEX declara exactamente lo que esperan CVES_VEX y CVES_VEX_LOCK: una
    # declaración olvidada al retirarla, o una nueva sin comprobar, se ve aquí
    # y no a los 30 días. Control: la misma comparación con una declaración
    # de más tiene que fallar (no es una comparación que siempre acierta).
    # Una declaración por cada imagen y CVE: la misma CVE en dos imágenes
    # (CVE-2026-111943 en caddy y mailpit) son dos declaraciones.
    esperadas = collections.Counter([c for cves in CVES_VEX.values() for c in cves] + list(CVES_VEX_LOCK))

    def declaradas_en(doc):
        return collections.Counter(d["vulnerability"]["name"] for d in doc.get("statements", []))

    con_una_de_mas = {**documento, "statements": [*documento.get("statements", []),
                                                    {"vulnerability": {"name": "CVE-0000-0000"}}]}
    control_lista = declaradas_en(con_una_de_mas) != esperadas
    pasa(control_lista, "e) control: una declaracion de mas en el VEX se detecta")
    declaradas = declaradas_en(documento)
    negativo("e) VEX: una declaracion por cada imagen y CVE de CVES_VEX y CVES_VEX_LOCK, ni una mas ni una menos",
             declaradas == esperadas, control_lista,
             f"sobran {sorted((declaradas - esperadas).elements())}, faltan {sorted((esperadas - declaradas).elements())}")

    # Cada imagen con declaraciones: sin VEX (control: el VEX es lo que las
    # suprime) y con el VEX movido a la versión siguiente del componente
    # (control de atadura a la versión).
    vex_movido = escribir_vex_movido()
    control_vex = {}
    for nombre, cves in sorted(CVES_VEX.items()):
        _, sin_vex = escanear(nombre)
        cves_sin_vex = {v["VulnerabilityID"] for _, v in hallazgos(sin_vex)[0]}
        control_vex[nombre] = cves <= cves_sin_vex
        pasa(control_vex[nombre], f"e) control: sin VEX, Trivy reporta en {nombre} {sorted(cves)}")
        _, movido = escanear(nombre, vex=vex_movido)
        cves_movido = {v["VulnerabilityID"] for _, v in hallazgos(movido)[0]}
        negativo(f"e) VEX atado a la version en {nombre}: con otra version del componente no suprime nada",
                 cves <= cves_movido, control_vex[nombre], f"siguen {sorted(cves_movido & cves)}")

    # Las cinco imágenes con el VEX real.
    suprimidas_total = set()
    for nombre in IMAGENES:
        r, informe = escanear(nombre, vex=VEX)
        if informe is None:
            raise Parada(f"Trivy no produjo JSON para {nombre}: {r.err.strip()[-300:]}")
        vulns, suprimidas, secretos_img = hallazgos(informe)
        con_arreglo = sorted({(v["VulnerabilityID"], v["PkgName"], v.get("InstalledVersion"), v.get("FixedVersion"))
                              for _, v in vulns if v.get("FixedVersion")})
        sin_arreglo = sorted({(v["VulnerabilityID"], v["PkgName"], v.get("Status")) for _, v in vulns if not v.get("FixedVersion")})
        for m in suprimidas:
            if m.get("Status") == "not_affected" and str(m.get("Source", "")).endswith(VEX.name):
                suprimidas_total.add((nombre, m["Finding"]["VulnerabilityID"]))
        negativo(f"e) {nombre}: ninguna vulnerabilidad {SEVERIDADES} con arreglo sin declarar en el VEX",
                 not con_arreglo, control_vuln, str(con_arreglo))
        negativo(f"e) {nombre}: ningun secreto en la imagen", not secretos_img, control_secreto, str(secretos_img))
        so = (informe.get("Metadata") or {}).get("OS") or {}
        p(f"   {nombre} ({so.get('Family', '?')} {so.get('Name', '')}): sin arreglo publicado {len(sin_arreglo)}"
          + (f" -> {sorted({c for c, _, _ in sin_arreglo})}" if sin_arreglo else ""))
    for nombre, cves in sorted(CVES_VEX.items()):
        for cve in sorted(cves):
            negativo(f"e) VEX {cve}: suprime el hallazgo en {nombre} (una declaracion sin efecto se revisa y se retira)",
                     (nombre, cve) in suprimidas_total, control_vex[nombre])


def escribir_vex_movido():
    """El VEX con cada componente en su versión siguiente: no debe suprimir
    nada (control de la atadura a la versión, e y j)."""
    texto = VEX.read_text(encoding="utf-8")
    for actual, siguiente in VERSIONES_VEX.items():
        texto = texto.replace(actual, siguiente)
    return escribir(TEMPORAL / "vex_movido" / "movido.openvex.json", texto)


def json_de_texto(texto):
    try:
        return json.loads(texto)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# f) Alcanzabilidad en Caddy (lo que sostiene el VEX)
# ---------------------------------------------------------------------------
CLIENTE_ALPN = """import socket
import ssl
import sys
import time

# Ofrece h2 y http/1.1 por ALPN y escribe el protocolo que elige cada servidor.
# Cada argumento es host:puerto.
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.set_alpn_protocols(["h2", "http/1.1"])
for destino in sys.argv[1:]:
    host, puerto = destino.rsplit(":", 1)
    for _ in range(60):
        try:
            with socket.create_connection((host, int(puerto)), timeout=5) as s:
                with ctx.wrap_socket(s, server_hostname="localhost") as t:
                    print(destino, t.selected_alpn_protocol())
                    break
        except OSError:
            time.sleep(0.5)
    else:
        print(destino, "sin-conexion")
"""
# Puertos en los que escucha Caddy: la API, el sitio del denunciante y la SPA
# del personal.
PUERTOS_CADDY = ("8443", "8444", "8445")
# El de producción: los tres sitios en un puerto, detrás de Traefik.
PUERTOS_CADDY_PRODUCCION = ["8080"]
# Lo que carga el Caddyfile local: él y los ficheros que importa
# (proxy/Caddyfile). Los controles se construyen sobre una copia de todos.
FICHEROS_CADDY = ("Caddyfile", "global.caddy", "servidor.caddy", "comun.caddy")
# Condición de la lista blanca de CVE-2026-111943 que en producción no aplica:
# allí Caddy no gestiona ningún certificado (sin app tls), lo que se comprueba
# aparte y es más estricto que tener solo emisores internal.
CONDICION_SOLO_INTERNAL = "solo emisores internal"
# Cambio que convierte el Caddyfile real en el de control de la quita de Range:
# el sitio del denunciante, el que tiene file_server, sin importar sin_range.
CONTROL_SIN_RANGE = ("\timport sin_range\n\timport cabeceras_html\n", "\timport cabeceras_html\n")
# CVE-2026-111943: cambios que hacen que Caddy verifique certificados ajenos,
# uno por condición de la lista blanca. Se aplican en orden y cada uno a la
# primera aparición: el emisor acme va en el sitio sin nombre (con localhost
# en dos políticas, caddy adapt se niega) y client_auth en el primer sitio.
CONTROL_X509 = [
    ("\tadmin off\n", "\tadmin localhost:2019\n"),
    ("\tskip_install_trust\n", ""),
    ("https://:8443, https://:8444, https://:8445 {\n\ttls internal\n",
     "https://:8443, https://:8444, https://:8445 {\n\ttls {\n\t\tissuer acme\n\t}\n"),
    ("\ttls internal\n", "\ttls internal {\n\t\tclient_auth {\n\t\t\tmode request\n\t\t}\n\t}\n"),
    ("\treverse_proxy api:8000 {", "\treverse_proxy https://api:8000 {"),
]
# Mailpit con una variable de reenvío y en una red con salida: lo que haría
# que abriese conexiones TLS hacia fuera.
COMPOSE_CONTROL_MAILPIT = """services:
  mailpit:
    environment:
      MP_SMTP_RELAY_HOST: relay.canario.invalid
    networks:
      - correo
      - edge
"""


def quita_range(manejador):
    """Un manejador headers que borra Range de la petición."""
    borradas = ((manejador.get("request") or {}).get("delete") or [])
    return manejador.get("handler") == "headers" and "range" in [b.lower() for b in borradas]


def file_servers(rutas, quitado=False):
    """Para cada file_server, si alguna ruta anterior quita Range a todas las
    peticiones que llegan a él.

    Se recorre en el orden en que Caddy ejecuta las rutas. Dentro de una ruta,
    la quita vale para los manejadores siguientes. Para las rutas siguientes,
    solo si la ruta que la hace no tiene condición (match): una quita con
    condición no cubre a todas. Lo que se quite dentro de una subruta no se
    hereda hacia fuera. Es conservador: ante la duda da "sin quita" y la
    prueba falla de forma visible.
    """
    hallados = []
    for ruta in rutas:
        local = quitado
        for manejador in ruta.get("handle", []):
            if quita_range(manejador):
                local = True
            elif manejador.get("handler") == "file_server":
                hallados.append(local)
            elif manejador.get("handler") == "subroute":
                hallados += file_servers(manejador.get("routes", []), local)
        if not ruta.get("match"):
            quitado = local
    return hallados


def transportes(nodo):
    """Todos los transportes de los manejadores, a cualquier profundidad."""
    if isinstance(nodo, dict):
        propios = [nodo["transport"] or {}] if "transport" in nodo else []
        return propios + [t for v in nodo.values() for t in transportes(v)]
    if isinstance(nodo, list):
        return [t for v in nodo for t in transportes(v)]
    return []


def condiciones_x509(configuracion):
    """Lista blanca de lo que mantiene a Caddy sin verificar nunca la cadena
    de un certificado ajeno (CVE-2026-111943). En Caddy 2.11.7 eso pasa en el
    admin remoto, en la instalación de la raíz local en el almacén del sistema
    (trusted() con las raíces del sistema), en los emisores que no son el CA
    interno (ACME es un cliente TLS), en la autenticación de clientes y en
    los transportes con TLS. Lo que no está en la lista falla: una política
    de emisión sin emisores usa ACME por defecto, así que no cuenta como
    internal."""
    apps = configuracion.get("apps", {})
    politicas = ((apps.get("tls") or {}).get("automation") or {}).get("policies") or []
    ca_local = ((apps.get("pki") or {}).get("certificate_authorities") or {}).get("local") or {}
    return {
        "admin desactivado": (configuracion.get("admin") or {}).get("disabled") is True,
        "install_trust en false": ca_local.get("install_trust") is False,
        "solo emisores internal": bool(politicas) and all(
            pol.get("issuers") and all(e.get("module") == "internal" for e in pol["issuers"]) for pol in politicas),
        "sin client_authentication": '"client_authentication"' not in json.dumps(configuracion),
        "sin tls en ningun transporte": all("tls" not in t for t in transportes(apps.get("http", {}))),
    }


def mailpit_sin_salida(extra=()):
    """Mailpit sin ninguna configuración (ni variables, ni fichero de
    entorno, ni orden propia) y solo en la red correo, que es interna."""
    r = ejecutar(BASE + list(extra) + ["--profile", "desarrollo", "config", "--format", "json"])
    configuracion = json_de_texto(r.out)
    if configuracion is None:
        raise Parada(f"docker compose config no devuelve JSON: {r.err.strip()[-300:]}")
    mailpit = configuracion["services"]["mailpit"]
    redes = sorted(mailpit.get("networks") or {})
    return {
        "sin configuracion": not any(mailpit.get(k) for k in ("environment", "env_file", "command", "entrypoint")),
        "solo en la red interna correo": redes == ["correo"]
        and configuracion["networks"]["correo"].get("internal") is True,
    }


def caddyfile_control(destino, cambios):
    """Copia en destino la configuración local de Caddy (el Caddyfile y lo que
    importa) con los cambios aplicados, y devuelve la ruta de su Caddyfile.
    Cada texto debe estar en uno solo de esos ficheros, donde se cambia su
    primera aparición: si no está en ninguno o está en varios, el control no
    se puede construir y se ve."""
    textos = {nombre: (RAIZ / "proxy" / nombre).read_text(encoding="utf-8") for nombre in FICHEROS_CADDY}
    for viejo, nuevo in cambios:
        donde = [nombre for nombre, texto in textos.items() if viejo in texto]
        if len(donde) != 1:
            raise Parada(f"{viejo.strip()!r} esta en {len(donde)} ficheros de proxy/ y se espera en 1: "
                         "el control no se puede construir")
        textos[donde[0]] = textos[donde[0]].replace(viejo, nuevo, 1)
    for nombre, texto in textos.items():
        escribir(pathlib.Path(destino) / nombre, texto)
    return pathlib.Path(destino) / "Caddyfile"


def adaptar(caddyfile=None, ruta="/etc/caddy/Caddyfile"):
    """Configuración que carga Caddy. Sin caddyfile, la de la imagen (ruta
    elige cuál de sus dos Caddyfile); con él, la de ese directorio de
    control, montado entero porque el Caddyfile importa sus vecinos."""
    montajes = []
    if caddyfile is not None:
        montajes, ruta = [montaje(caddyfile.parent, "/c")], f"/c/{caddyfile.name}"
    r = ejecutar(["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
                  *[x for m in montajes for x in m], "--entrypoint", "caddy", NOMBRES["caddy"], "adapt", "--config", ruta])
    configuracion = json_de_texto(r.out)
    if configuracion is None:
        raise Parada(f"caddy adapt falla: {r.err.strip()[-300:]}")
    servidores = configuracion["apps"]["http"]["servers"].values()
    # Las rutas normales y las de error de cada servidor, cada una desde cero.
    con_quita = [q for s in servidores
                 for rutas in (s.get("routes", []), (s.get("errors") or {}).get("routes", []))
                 for q in file_servers(rutas)]
    return {"protocolos": [s.get("protocols") for s in servidores],
            "escucha": sorted(d.rsplit(":", 1)[1] for s in servidores for d in s.get("listen", [])),
            "file_server": con_quita,
            # Recuento independiente del recorrido: si file_servers() se saltase
            # alguno, no coincidiría.
            "file_server_total": json.dumps(configuracion).count('"handler": "file_server"'),
            "ech": "encrypted_client_hello" in json.dumps(configuracion["apps"].get("tls", {})),
            # La app tls es la que gestiona certificados (emite, renueva y,
            # con ACME, verifica los del servidor ACME).
            "app_tls": "tls" in configuracion["apps"],
            # CVE-2026-116587: el servidor ACME de Caddy (el único sitio que
            # parsea JWK de clientes) es este manejador.
            "acme_server": '"handler": "acme_server"' in json.dumps(configuracion),
            "x509": condiciones_x509(configuracion)}


def seccion_f():
    p("=== f) alcanzabilidad en Caddy y en PostgreSQL (lo que sostiene el VEX)")
    real = adaptar()
    control = adaptar(caddyfile_control(TEMPORAL / "caddy_adapt", [
        ("\tprotocols h1\n", "\tprotocols h1 h2\n"),
        ("\tskip_install_trust\n", "\tskip_install_trust\n\tech ech.canario.invalid\n"),
        ("\trequest_header -Cookie\n", "\tacme_server\n\trequest_header -Cookie\n"),
        CONTROL_SIN_RANGE]))
    pasa(real["escucha"] == list(PUERTOS_CADDY), f"f) configuracion adaptada: servidores en {real['escucha']}")
    negativo(f"f) configuracion adaptada: todos los servidores con protocols {PROTOCOLOS_CADDY} (sin HTTP/2)",
             real["protocolos"] and all(x == PROTOCOLOS_CADDY for x in real["protocolos"]),
             control["protocolos"] and all(x == ["h1", "h2"] for x in control["protocolos"]), str(real["protocolos"]))
    # CVE-2026-78667: cada file_server con la quita de Range delante. Control: el
    # mismo Caddyfile sin importar sin_range en el sitio del file_server.
    negativo(f"f) configuracion adaptada: cada file_server detras de la quita de Range (CVE-2026-78667) {real['file_server']}",
             bool(real["file_server"]) and all(real["file_server"])
             and len(real["file_server"]) == real["file_server_total"],
             False in control["file_server"], f"control: {control['file_server']}")
    negativo("f) configuracion adaptada: sin encrypted_client_hello (CVE-2026-97031)", not real["ech"], control["ech"])
    # CVE-2026-116587: go-jose solo parsea JWK que llegan de fuera en el
    # servidor ACME (acme_server, que monta los endpoints ACME de smallstep).
    # El cliente ACME de Caddy (acmez) y el CA interno no la usan con datos
    # ajenos, y con admin off nadie puede añadir el manejador en caliente.
    # Control: el Caddyfile con acme_server en el sitio del 8443.
    negativo("f) configuracion adaptada: sin el manejador acme_server (CVE-2026-116587)", not real["acme_server"],
             control["acme_server"])
    # CVE-2026-111943: Caddy no verifica ningún certificado ajeno. Control: el
    # Caddyfile con un cambio que rompe cada condición. Sigue sin arreglo en
    # las imágenes de Caddy y mailpit: esto es lo que demuestra que no se
    # alcanza y lo que sostiene su declaración en el VEX.
    control_x509 = adaptar(caddyfile_control(TEMPORAL / "caddy_x509", CONTROL_X509))
    for condicion, cumple in real["x509"].items():
        negativo(f"f) configuracion adaptada: {condicion} (CVE-2026-111943)", cumple,
                 control_x509["x509"][condicion] is False)

    # El Caddyfile de producción (proxy/Caddyfile.produccion), de la misma
    # imagen: el VEX tiene que valer para lo que corre en producción, no solo
    # en local. Comparte con el local todo lo que aquí se mira (global.caddy,
    # servidor.caddy y comun.caddy), y los controles de arriba ya demostraron
    # que cada comprobación distingue.
    produccion = adaptar(ruta="/etc/caddy/Caddyfile.produccion")
    pasa(produccion["escucha"] == PUERTOS_CADDY_PRODUCCION,
         f"f) produccion: servidores en {produccion['escucha']}")
    negativo(f"f) produccion: todos los servidores con protocols {PROTOCOLOS_CADDY} (sin HTTP/2)",
             produccion["protocolos"] and all(x == PROTOCOLOS_CADDY for x in produccion["protocolos"]),
             control["protocolos"] and all(x == ["h1", "h2"] for x in control["protocolos"]),
             str(produccion["protocolos"]))
    negativo(f"f) produccion: cada file_server detras de la quita de Range (CVE-2026-78667) {produccion['file_server']}",
             bool(produccion["file_server"]) and all(produccion["file_server"])
             and len(produccion["file_server"]) == produccion["file_server_total"],
             False in control["file_server"], f"control: {control['file_server']}")
    negativo("f) produccion: sin encrypted_client_hello (CVE-2026-97031)", not produccion["ech"], control["ech"])
    negativo("f) produccion: sin el manejador acme_server (CVE-2026-116587)", not produccion["acme_server"],
             control["acme_server"])
    # Control: el local sí tiene app tls (tls internal), así que la
    # comprobación encuentra lo que busca.
    negativo("f) produccion: sin app tls, Caddy no gestiona ningun certificado (CVE-2026-111943)",
             not produccion["app_tls"], real["app_tls"])
    for condicion, cumple in produccion["x509"].items():
        if condicion == CONDICION_SOLO_INTERNAL:
            continue
        negativo(f"f) produccion: {condicion} (CVE-2026-111943)", cumple,
                 control_x509["x509"][condicion] is False)
    # CVE-2026-111943 en mailpit: sin configuración que le haga abrir TLS hacia
    # fuera y sin salida. Control: un compose adicional con una variable de
    # reenvío y la red edge.
    real_mailpit = mailpit_sin_salida()
    compose_control = escribir(TEMPORAL / "mailpit_control" / "compose.yml", COMPOSE_CONTROL_MAILPIT)
    control_mailpit = mailpit_sin_salida(["-f", str(compose_control)])
    for condicion, cumple in real_mailpit.items():
        negativo(f"f) mailpit: {condicion} (CVE-2026-111943)", cumple, control_mailpit[condicion] is False)

    # CVE-2026-92392 y CVE-2026-111497 en postgres: libcurl (y brotli-libs, que
    # solo usa libcurl) solo la enlaza el módulo OAuth del lado cliente de
    # libpq; ningún binario del servidor. Control: ese módulo sí aparece, así
    # que la búsqueda con ldd encuentra lo que busca.
    enlazan = enlazan_libcurl(NOMBRES["postgres"])
    control_ldd = LIBPQ_OAUTH in enlazan
    pasa(control_ldd, f"f) postgres: control: ldd encuentra libcurl en {LIBPQ_OAUTH}")
    negativo(f"f) postgres: solo {LIBPQ_OAUTH} enlaza libcurl, ningun binario del servidor ({enlazan})",
             enlazan == [LIBPQ_OAUTH], control_ldd)
    metodos = metodos_hba(PG_HBA.read_text(encoding="utf-8"))
    negativo(f"f) postgres: db/pg_hba.conf sin el metodo oauth ({sorted(metodos)})", "oauth" not in metodos,
             "oauth" in metodos_hba(PG_HBA_CONTROL))

    # ALPN real contra dos Caddy en marcha en una red interna: el de la imagen
    # y uno de control con "protocols h1 h2".
    red = NOMBRES["red"]
    if ejecutar(["docker", "network", "create", "--internal", red]).rc != 0:
        raise Parada("no se pudo crear la red de la prueba ALPN")
    control_h2 = caddyfile_control(TEMPORAL / "caddy_alpn", [("\tprotocols h1\n", "\tprotocols h1 h2\n")])
    comun = ["docker", "run", "-d", "--network", red, "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
             "--tmpfs", "/data:uid=10002,gid=10002", "--tmpfs", "/config:uid=10002,gid=10002"]
    for alias, extra in (("real", []), ("control", montaje(control_h2.parent, "/etc/caddy"))):
        r = ejecutar(comun + ["--name", f"{PROYECTO}_caddy_{alias}", "--network-alias", alias, *extra, NOMBRES["caddy"]])
        if r.rc != 0:
            raise Parada(f"no arranca el Caddy {alias}: {r.err.strip()[-200:]}")
    cliente = escribir(TEMPORAL / "alpn" / "alpn.py", CLIENTE_ALPN)
    r = ejecutar(["docker", "run", "--rm", "--network", red, "--read-only", "--cap-drop", "ALL", "--security-opt",
                  "no-new-privileges", "--user", "65534:65534", *montaje(cliente.parent, "/alpn"),
                  IMG_PYTHON, "python", "-I", "/alpn/alpn.py", *[f"real:{x}" for x in PUERTOS_CADDY], "control:8443"],
                 timeout=120)
    elegido = dict(l.split(" ", 1) for l in r.out.splitlines() if " " in l)
    for puerto in PUERTOS_CADDY:
        negativo(f"f) ALPN en {puerto}: ofreciendo h2 y http/1.1, Caddy elige {ALPN_REAL}",
                 elegido.get(f"real:{puerto}") == ALPN_REAL, elegido.get("control:8443") == ALPN_CONTROL,
                 f"real={elegido.get(f'real:{puerto}')} control={elegido.get('control:8443')}")


def enlazan_libcurl(imagen):
    """Los ficheros de la imagen que enlazan libcurl, según ldd: los de
    PostgreSQL (/usr/local) y los ejecutables del sistema."""
    orden = ("find /usr/local /bin /sbin /usr/bin /usr/sbin -type f 2>/dev/null | while read -r f; do "
             "ldd \"$f\" 2>/dev/null | grep -q libcurl && echo \"$f\"; done; true")
    r = ejecutar(["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--user", "70:70",
                  "--entrypoint", "sh", imagen, "-c", orden], timeout=300)
    return sorted(r.out.split())


def metodos_hba(texto):
    """Los métodos de autenticación de un pg_hba.conf: el cuarto campo en las
    reglas local y el quinto en las demás."""
    metodos = set()
    for linea in texto.splitlines():
        campos = linea.split("#", 1)[0].split()
        if campos:
            indice = 3 if campos[0] == "local" else 4
            if len(campos) > indice:
                metodos.add(campos[indice])
    return metodos


# ---------------------------------------------------------------------------
# g) Configuración de los Dockerfiles (Trivy config)
# ---------------------------------------------------------------------------
def seccion_g():
    p("=== g) configuracion de los Dockerfiles (Trivy config)")
    cfg = TEMPORAL / "dockerfiles"
    for nombre, origen in (("api", RAIZ / "Dockerfile"), ("proxy", RAIZ / "proxy" / "Dockerfile"), ("db", RAIZ / "db" / "Dockerfile")):
        (cfg / nombre).mkdir(parents=True)
        shutil.copyfile(origen, cfg / nombre / "Dockerfile")
    escribir(cfg / "control" / "Dockerfile", DOCKERFILE_CONTROL)
    # --skip-check-update: las comprobaciones que trae el binario fijado, sin
    # descargar otro artefacto que cambia.
    r = trivy(["config", "/cfg", "--severity", SEVERIDADES, "--skip-check-update", "--skip-version-check", "-q", "--format", "json"],
              montajes=[montaje(cfg, "/cfg")])
    informe = json_de_texto(r.out)
    if informe is None:
        raise Parada(f"trivy config no produjo JSON: {r.err.strip()[-300:]}")
    fallos = {res["Target"]: [m["ID"] for m in res.get("Misconfigurations") or []] for res in informe.get("Results") or []}
    control = CHECK_CONTROL_DOCKERFILE in fallos.get("control/Dockerfile", [])
    pasa(control, f"g) control: un Dockerfile sin USER da {CHECK_CONTROL_DOCKERFILE}")
    for nombre in ("api", "proxy", "db"):
        objetivo = f"{nombre}/Dockerfile"
        negativo(f"g) {objetivo if nombre != 'api' else 'Dockerfile'}: ningun fallo {SEVERIDADES}",
                 objetivo in fallos and not fallos[objetivo], control, str(fallos.get(objetivo)))


# ---------------------------------------------------------------------------
# j) Dependencias de npm de la SPA (Trivy fs sobre el lock)
# ---------------------------------------------------------------------------
def lock_npm(directorio, vex=None):
    """Trivy sobre el package-lock.json de un directorio, sin red, con las
    dependencias de desarrollo y todas las severidades: el criterio se aplica
    después, igual para el control y para el real. Con vex, también lo que
    suprime (--show-suppressed)."""
    args = ["fs", "/lock", "--scanners", "vuln", "--include-dev-deps", "--skip-db-update", "--offline-scan",
            "--skip-version-check", "--no-progress", "-q", "--format", "json"]
    montajes = [montaje(directorio, "/lock")]
    if vex is not None:
        montajes.append(montaje(vex.parent, "/vex"))
        args += ["--vex", f"/vex/{vex.name}", "--show-suppressed"]
    r = trivy(args, montajes=montajes)
    return r, json_de_texto(r.out)


def version(texto):
    """'8.3.0' -> (8, 3, 0); None si no es una versión exacta X.Y.Z."""
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", texto or "")
    return tuple(int(x) for x in m.groups()) if m else None


def override_necesario(lock, nombre):
    """True si el paquete que fija la dependencia declara una versión anterior
    a la arreglada: el override hace falta. False si ya la trae arreglada: el
    override sobra y se retira. None si el lock no permite decidirlo."""
    padre, arreglada, _ = OVERRIDES_MOTIVO[nombre]
    declarada = version(((lock.get("packages") or {}).get(f"node_modules/{padre}") or {})
                        .get("dependencies", {}).get(nombre))
    return None if declarada is None else declarada < arreglada


def entradas_cambiadas(lock, lock_antes):
    """(nombre, versión) de cada paquete del lock que es nuevo o cambia de
    versión o de integrity respecto a lock_antes."""
    antes = lock_antes.get("packages") or {}
    cambiadas = set()
    for ruta, datos in (lock.get("packages") or {}).items():
        if not ruta or "version" not in datos:
            continue
        previo = antes.get(ruta) or {}
        if (datos["version"], datos.get("integrity")) != (previo.get("version"), previo.get("integrity")):
            cambiadas.add((ruta.rsplit("node_modules/", 1)[1], datos["version"]))
    return sorted(cambiadas)


def publicada(nombre, numero):
    """Fecha de publicación de una versión en el registro de npm (solo los
    metadatos en JSON: no se descarga ni se ejecuta ningún paquete)."""
    url = REGISTRO_NPM + urllib.parse.quote(nombre, safe="@")
    try:
        with urllib.request.urlopen(url, timeout=60) as respuesta:
            fechas = json.loads(respuesta.read())["time"]
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError) as error:
        raise SinRed(f"no se pudo leer la fecha de {nombre} {numero} en el registro de npm: {error}") from None
    if numero not in fechas:
        raise Parada(f"el registro de npm no tiene {nombre} {numero}")
    return datetime.datetime.fromisoformat(fechas[numero])


def reciente(fecha, hoy):
    """Menos de DIAS_ESPERA días entre la publicación y hoy."""
    return hoy - fecha < datetime.timedelta(days=DIAS_ESPERA)


def seccion_j():
    p("=== j) dependencias de npm de la SPA (Trivy sobre spa/package-lock.json)")
    control_dir = TEMPORAL / "lock_control"
    escribir(control_dir / "package-lock.json", json.dumps(LOCK_CONTROL))
    _, informe = lock_npm(control_dir)
    # El control pasa por el mismo criterio que el real: HIGH o CRITICAL y con
    # arreglo publicado.
    control = any(v["VulnerabilityID"] == AVISO_CONTROL_NPM and v.get("Severity") in SEVERIDADES.split(",")
                  and v.get("FixedVersion") for _, v in hallazgos(informe)[0])
    pasa(control, f"j) control: Trivy detecta {AVISO_CONTROL_NPM} ({SEVERIDADES}, con arreglo) en un lock con "
                  "@angular/common 22.0.0")

    # Una copia: la herramienta no ve el repositorio.
    real_dir = TEMPORAL / "lock_spa"
    real_dir.mkdir()
    shutil.copyfile(RAIZ / "spa" / "package-lock.json", real_dir / "package-lock.json")
    # El VEX: sin él, Trivy reporta lo que declara (control), y movido a la
    # versión siguiente no suprime nada (atadura a la versión).
    def graves_de(informe):
        return {v["VulnerabilityID"] for _, v in hallazgos(informe)[0]
                if v.get("Severity") in SEVERIDADES.split(",") and v.get("FixedVersion")}

    # Sin declaraciones para el lock no hay nada que controlar: con el
    # conjunto vacío, "CVES_VEX_LOCK <= X" es cierto siempre y daría un PASA
    # que no prueba nada. Se dice que no aplica; que el VEX no tenga ninguna
    # declaración de más lo comprueba e).
    if CVES_VEX_LOCK:
        _, sin_vex = lock_npm(real_dir)
        control_vex_lock = CVES_VEX_LOCK <= graves_de(sin_vex)
        pasa(control_vex_lock, f"j) control: sin VEX, Trivy reporta en el lock {sorted(CVES_VEX_LOCK)}")
        _, movido = lock_npm(real_dir, vex=escribir_vex_movido())
        negativo("j) VEX atado a la version en el lock: con otra version del paquete no suprime nada",
                 CVES_VEX_LOCK <= graves_de(movido), control_vex_lock,
                 f"siguen {sorted(graves_de(movido) & CVES_VEX_LOCK)}")
    else:
        p("   j) VEX del lock: sin declaraciones, no aplica")
    r, informe = lock_npm(real_dir, vex=VEX)
    if informe is None:
        raise Parada(f"Trivy no produjo JSON para spa/package-lock.json: {r.err.strip()[-300:]}")
    if CVES_VEX_LOCK:
        suprimidas = {m["Finding"]["VulnerabilityID"] for m in hallazgos(informe)[1]
                      if m.get("Status") == "not_affected" and str(m.get("Source", "")).endswith(VEX.name)}
        for cve in sorted(CVES_VEX_LOCK):
            negativo(f"j) VEX {cve}: suprime el hallazgo en el lock (una declaracion sin efecto se revisa y se retira)",
                     cve in suprimidas, control_vex_lock)
    paquetes = sum(len(res.get("Packages") or []) for res in informe.get("Results") or [])
    objetivos = [res.get("Target") for res in informe.get("Results") or []]
    pasa(objetivos == ["package-lock.json"] and paquetes > 0, f"j) Trivy analiza el lock ({objetivos}, {paquetes} paquetes)")
    vulns = hallazgos(informe)[0]
    graves = sorted({(v["VulnerabilityID"], v["PkgName"], v.get("InstalledVersion"), v.get("FixedVersion"))
                     for _, v in vulns if v.get("Severity") in SEVERIDADES.split(",") and v.get("FixedVersion")})
    negativo(f"j) spa/package-lock.json: ninguna vulnerabilidad {SEVERIDADES} con arreglo publicado sin declarar "
             "en el VEX", not graves, control, str(graves))
    claves_graves = {g[:2] for g in graves}
    resto = sorted({(v["VulnerabilityID"], v["PkgName"], v.get("Severity")) for _, v in vulns
                    if (v["VulnerabilityID"], v["PkgName"]) not in claves_graves})
    p(f"   resto de avisos (otras severidades o sin arreglo): {len(resto)}" + (f" -> {resto}" if resto else ""))

    # Cada override: el de package.json, el instalado según el lock (una sola
    # copia), y que sigue haciendo falta. Control: un padre que ya declara la
    # versión arreglada hace que sobre.
    paquete = json_de(RAIZ / "spa" / "package.json") or {}
    lock = json_de(RAIZ / "spa" / "package-lock.json") or {}
    pasa(paquete.get("overrides") == OVERRIDES_SPA, f"j) spa/package.json: overrides exactamente {OVERRIDES_SPA}")
    for nombre, forzada in sorted(OVERRIDES_SPA.items()):
        padre, arreglada, declarada_control = OVERRIDES_MOTIVO[nombre]
        copias = sorted({datos.get("version") for ruta, datos in (lock.get("packages") or {}).items()
                         if ruta == f"node_modules/{nombre}" or ruta.endswith(f"/node_modules/{nombre}")})
        pasa(copias == [forzada], f"j) el lock instala solo el {nombre} del override ({copias})")
        lock_control = {"packages": {f"node_modules/{padre}": {"dependencies": {nombre: declarada_control}}}}
        negativo(f"j) el override de {nombre} sigue haciendo falta: {padre} declara una {nombre} anterior a la "
                 f"{'.'.join(map(str, arreglada))} (si no, se retira)",
                 override_necesario(lock, nombre) is True, override_necesario(lock_control, nombre) is False)

    # Lo que cambia en el lock respecto a HEAD, con su fecha, para revisarlo
    # en el commit, y la regla de los 14 días. Control: vite 8.3.4 evaluada
    # como si hoy fuera el día siguiente a su publicación.
    r = ejecutar(["git", "show", "HEAD:spa/package-lock.json"], cwd=RAIZ)
    lock_head = json_de_texto(r.out)
    if lock_head is None:
        raise Parada(f"git show HEAD:spa/package-lock.json falla: {r.err.strip()[-200:]}")
    nombre_ctl, numero_ctl, hoy_ctl = CONTROL_RECIENTE
    control_reciente = reciente(publicada(nombre_ctl, numero_ctl), hoy_ctl)
    pasa(control_reciente, f"j) control: {nombre_ctl} {numero_ctl} evaluada el {hoy_ctl.date()} tiene menos de {DIAS_ESPERA} dias")
    ahora = datetime.datetime.now(datetime.UTC)
    cambiadas = [(n, v, publicada(n, v)) for n, v in entradas_cambiadas(lock, lock_head)]
    p(f"   entradas del lock que cambian respecto a HEAD: {len(cambiadas)}")
    for n, v, fecha in cambiadas:
        p(f"     {n} {v} publicada el {fecha.date()}")
    recientes = [(n, v) for n, v, fecha in cambiadas if reciente(fecha, ahora)]
    negativo(f"j) ninguna entrada que cambia en el lock tiene menos de {DIAS_ESPERA} dias", not recientes,
             control_reciente, str(recientes))


# ---------------------------------------------------------------------------
# h) SBOM e i) reproducibilidad
# ---------------------------------------------------------------------------
def seccion_h():
    p("=== h) SBOM CycloneDX por imagen")
    salida = TEMPORAL / "sbom"
    salida.mkdir()
    shutil.rmtree(DIR_SBOM, ignore_errors=True)
    DIR_SBOM.mkdir()
    for nombre in IMAGENES:
        r = trivy(["image", "--input", f"/img/{nombre}.tar", "--format", "cyclonedx", "--output", f"/out/{nombre}.cdx.json",
                   "--skip-db-update", "--offline-scan", "--skip-version-check", "--no-progress", "-q"],
                  montajes=[montaje(TEMPORAL / "imagenes", "/img"), montaje(salida, "/out", escritura=True)])
        sbom = json_de(salida / f"{nombre}.cdx.json")
        componentes = (sbom or {}).get("components") or []
        pasa(r.rc == 0 and (sbom or {}).get("bomFormat") == "CycloneDX" and len(componentes) > 0,
             f"h) {nombre}: SBOM CycloneDX con {len(componentes)} componentes")
        if sbom is not None:
            shutil.copyfile(salida / f"{nombre}.cdx.json", DIR_SBOM / f"{nombre}.cdx.json")
        if nombre == "api":
            pasa(any((c.get("name"), c.get("version")) == SBOM_API_CONTROL for c in componentes),
                 f"h) api: el SBOM contiene {SBOM_API_CONTROL[0]} {SBOM_API_CONTROL[1]} (el de requirements.txt)")
    p(f"   SBOM guardados en {DIR_SBOM}")


def seccion_i():
    p("=== i) reproducibilidad")
    r = trivy(["version", "--format", "json"])
    datos = json_de_texto(r.out) or {}
    bd = datos.get("VulnerabilityDB") or {}
    p(f"   trivy {datos.get('Version')} ({IMG_TRIVY.split('@')[1][:19]}); base de datos {DB_TRIVY} "
      f"version {bd.get('Version')}, actualizada {bd.get('UpdatedAt')}, descargada {bd.get('DownloadedAt')}")
    p(f"   gitleaks {VERSION_GITLEAKS} ({IMG_GITLEAKS.split('@')[1][:19]}); {VERSION_PIP_AUDIT} (OSV); {VERSION_BANDIT}")
    pasa(bool(bd.get("UpdatedAt")), "i) la fecha de la base de datos de Trivy queda registrada")


# ---------------------------------------------------------------------------
# s) Limpieza y ejecución
# ---------------------------------------------------------------------------
def limpiar():
    for alias in ("real", "control"):
        ejecutar(["docker", "rm", "-f", f"{PROYECTO}_caddy_{alias}"])
    ejecutar(["docker", "network", "rm", NOMBRES["red"]])
    ejecutar(["docker", "volume", "rm", NOMBRES["cache"]])
    return dc("down", "-v", "--rmi", "local")


def seccion_s():
    p("=== s) limpieza")
    r = limpiar()
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


def terminar(parada=False):
    if parada:
        resultado = "NO OK (PARADA)"
    else:
        resultado = "NO OK (hay FALLA o SIN CONCLUSION)" if estado["falla"] or estado["sin_conclusion"] else "OK"
    p("RESULTADO GLOBAL: " + resultado)
    SALIDA.write_text("\n".join(lineas_salida) + "\n", encoding="utf-8", newline="\n")
    sys.exit(0 if resultado == "OK" else 1)


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
                  ["docker", "volume", "ls", "--format", "{{.Name}}"],
                  ["docker", "image", "ls", "--format", "{{.Repository}}"]):
        previos += [n for n in ejecutar(orden).out.split() if n.startswith(PROYECTO)]
    return previos


def main():
    global ESTADO_GIT_ARRANQUE, TEMPORAL
    ESTADO_GIT_ARRANQUE = estado_git()
    NOMBRES.update(cache=f"{PROYECTO}_trivy", red=f"{PROYECTO}_alpn")
    if ejecutar(["docker", "info", "--format", "{{.ServerVersion}}"]).rc != 0:
        p("PARADA: docker info falla")
        terminar(parada=True)
    previos = recursos_previos()
    if previos:
        p(f"PARADA: ya existen recursos con prefijo {PROYECTO}: {previos}")
        terminar(parada=True)
    # docker compose valida que los secretos existan; solo se comprueba con
    # is_file, nunca se leen.
    for fichero in ("contrasena_redis.txt", "redis_acl.conf", "contrasena_postgres_superusuario.txt",
                    "contrasena_migrador.txt", "contrasena_aplicacion.txt", "contrasena_plataforma.txt",
                    "clave_maestra.txt", "clave_hmac_codigos.txt", "clave_firma_tokens.txt",
                    "clave_hmac_identidades.txt", "clave_flujo_externo.txt",
                    "google_client_id.txt", "google_client_secret.txt"):
        if not (RAIZ / "secrets" / fichero).is_file():
            p(f"PARADA: secrets/{fichero} no existe (scripts/generar_secretos.py)")
            terminar(parada=True)
    TEMPORAL = pathlib.Path(tempfile.mkdtemp(prefix="canario_escaneos_"))
    parada = None
    try:
        for seccion in (seccion_a, seccion_b, seccion_c_d, seccion_e, seccion_f, seccion_g, seccion_h, seccion_i,
                        seccion_j):
            try:
                seccion()
            except SinRed as e:
                # Sin red no hay conclusión posible sobre lo que dependía de ella.
                sinc(f"{seccion.__name__}: {e}")
                if seccion is seccion_e:
                    break  # f) a j) dependen de las imágenes y de la base de datos
    except Parada as e:
        parada = str(e)
        p(f"PARADA: {parada}")
    except Exception:  # noqa: BLE001 - error inesperado del propio test: se informa y se limpia
        parada = "error inesperado en el test"
        p("ERROR INESPERADO:\n" + traceback.format_exc())
    finally:
        if parada is not None:
            limpiar()
        else:
            seccion_s()
        shutil.rmtree(TEMPORAL, ignore_errors=True)
    terminar(parada=parada is not None)


if __name__ == "__main__":
    main()
