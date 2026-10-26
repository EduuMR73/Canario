#!/usr/bin/env python3
"""Batería semimanual del canje con Google REAL a través del broker real
(app/broker.py y app/proveedores_externos.py, docs/threat-model.md, 6.19).

Por qué existe: la guía de Google para aplicaciones web no documenta PKCE
(su documento de descubrimiento sí anuncia S256), y RFC 9700, 2.1.1, exige
que, si el cliente manda code_challenge, el servidor de autorización
compruebe el code_verifier. verificar_login_externo.py lo prueba contra un
Google falso; esta batería comprueba que el Google real lo hace. Sin PKCE
aplicado, contra la inyección de un code robado (RFC 9700, 4.5) quedaría
solo el nonce del id_token.

Qué prueba:
a) Precondiciones: la pila canario parada (la subred de canje es fija y el
   8445 no debe escuchar, para que la vuelta no la gaste Canario) y el broker
   arrancado con Google configurado (su log lo dice con un literal).
b) Primer flujo: el broker da la URL de autorización; usted autoriza en el
   navegador y pega la URL de la vuelta. Se comprueba el state y que el iss
   de la vuelta es exactamente https://accounts.google.com (RFC 9207).
   Negativo: el canje con un verifier INCORRECTO pero bien formado (43
   caracteres, pasa el patrón del broker: el rechazo es de Google, no un 422
   nuestro) da 401 con el cuerpo fijo y deja EVENTO canje_fallido con
   motivo=rechazado (Google respondió 400 o 401).
c) Segundo flujo, control positivo: otro code (cada uno vale una vez) con
   su verifier correcto da 200, proveedor google y un sub con formato
   válido. Si el control falla, el negativo es SIN CONCLUSION, nunca PASA: el
   control es lo que separa "verifier rechazado" de "cliente mal
   configurado" (los dos son un 400 de Google y el broker los reduce a
   motivo=rechazado).
d) El log del broker no lleva ningún code ni verifier de la batería.
s) Limpieza y repositorio intacto.

Qué NO prueba: el resto del broker (verificar_externo.py) ni el flujo de la
API y la SPA (verificar_login_externo.py y verificar_spa.py). El negativo no
distingue invalid_grant de invalid_client; lo hace el control.

Secretos: la batería no abre ni monta secrets/. Levanta SOLO el broker del
compose real en un proyecto propio (canario_googlereal), que lee los dos
secretos de Google como en producción, y le habla desde un contenedor
desechable en la red canje con la IP de la API (como verificar_externo.py).
La URL de autorización lleva el client_id, que no es secreto (RFC 6749,
2.2): es la misma URL que la SPA pone en la barra del navegador. Aun así se
imprime solo en la terminal y no se guarda en el fichero de salida. La URL
de la vuelta (con el code) se pide con getpass, para que no quede a la vista
ni en una captura, y nunca se imprime ni se guarda.

Cómo se ejecuta (PowerShell, raíz del repositorio, Docker en marcha, las
credenciales reales de Google en secrets/ y la pila canario parada con
"docker compose --profile desarrollo down", SIN -v):

    python tests/security/verificar_google_real.py

Pide dos veces iniciar sesión en Google con un usuario de prueba de la
pantalla de consentimiento. Como el 8445 no escucha, el navegador acaba en
una página de error con la URL completa en la barra: esa es la que se pega.
Al terminar, borre esas dos entradas del historial del navegador (el code
ya está gastado, pero no tiene por qué quedarse ahí).

La salida se guarda en verificacion_google_real.txt dentro del directorio
temporal del sistema. El código de salida es 0 solo si el resultado global
es OK. Solo usa la biblioteca estándar.
"""
import base64
import getpass
import hashlib
import json
import pathlib
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import traceback
import urllib.parse

RAIZ = pathlib.Path.cwd()
PROYECTO = "canario_googlereal"
SALIDA = pathlib.Path(tempfile.gettempdir()) / "verificacion_google_real.txt"
# Sin override: el broker del compose real, con sus secretos y su red salida
# con internet. Es lo que se quiere probar.
BASE = ["docker", "compose", "-p", PROYECTO, "-f", "docker-compose.yml"]

lineas_salida = []
estado = {"falla": False, "sin_conclusion": False}

# ---------------------------------------------------------------------------
# Oráculos literales
# ---------------------------------------------------------------------------
SUBRED_CANJE = "10.88.2.0/28"
IP_API = "10.88.2.4"
RED_CANJE = f"{PROYECTO}_canje"
PUERTO_SPA = 8445
IMAGEN = f"{PROYECTO}-broker"

LOG_ACTIVADO = ("PROVEEDOR ACTIVADO: proveedor=google "
                "redirect_uri=https://localhost:8445/v1/personal/externo/google/vuelta")
LOG_RECHAZADO = "EVENTO canje_fallido: proveedor=google motivo=rechazado"
INICIO_URL = "https://accounts.google.com/o/oauth2/v2/auth?"
INICIO_VUELTA = "https://localhost:8445/v1/personal/externo/google/vuelta?"
REDIRECT = "https://localhost:8445/v1/personal/externo/google/vuelta"
ISS_GOOGLE = "https://accounts.google.com"
CUERPO_FALLIDO = '{"detalle":"canje fallido"}'
# sub de Google: hasta 255 caracteres ASCII, sensible a mayúsculas (OpenID
# Connect de Google, "sub"). Escrito aquí, no importado del código probado.
PATRON_SUB = re.compile(r"[\x21-\x7e]{1,255}")
# Un valor aleatorio de 32 bytes en base64url sin relleno: 43 caracteres.
PATRON_43 = re.compile(r"[A-Za-z0-9_-]{43}")

# Cliente del broker: corre en canje con la IP de la API. Lee una lista de
# peticiones por la entrada estándar y devuelve estado y cuerpo de cada una.
CLIENTE = r'''
import http.client, json, sys

respuestas = []
for p in json.load(sys.stdin):
    c = http.client.HTTPConnection("10.88.2.3", 8000, timeout=40)
    try:
        c.request("POST", p["ruta"], body=json.dumps(p["json"]).encode("utf-8"),
                  headers={"Content-Type": "application/json"})
        r = c.getresponse()
        respuestas.append({"estado": r.status, "cuerpo": r.read().decode("utf-8", "replace")})
    except (OSError, http.client.HTTPException) as error:
        respuestas.append({"error": type(error).__name__})
    finally:
        c.close()
print(json.dumps(respuestas))
'''


# ---------------------------------------------------------------------------
# Utilidades de ejecución y de informe
# ---------------------------------------------------------------------------
class R:
    """Resultado de un comando: código, stdout y stderr por separado."""

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


def solo_terminal(texto=""):
    """Para lo que no debe quedar en el fichero de salida (la URL con el
    client_id)."""
    print(texto, flush=True)


def ejecutar(args, timeout=900, entrada=None):
    # check=False explícito: el código de salida se comprueba en cada llamada.
    r = subprocess.run(args, capture_output=True, timeout=timeout, check=False, input=entrada)
    return R(r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace"))


def dc(*args, timeout=900):
    return ejecutar(BASE + list(args), timeout=timeout)


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


TEMPORAL = None


def cliente(peticiones):
    """Peticiones al broker desde un contenedor de canje con la IP de la API."""
    r = ejecutar(["docker", "run", "--rm", "--network", RED_CANJE, "--ip", IP_API, "-i", "--read-only",
                  "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                  "--mount", f"type=bind,src={TEMPORAL},dst=/prueba,readonly",
                  "--entrypoint", "python", IMAGEN, "-I", "/prueba/cliente.py"],
                 entrada=json.dumps(peticiones).encode("utf-8"), timeout=120)
    try:
        return json.loads(r.out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise Parada(f"el cliente no devolvio resultado: {r.err.strip()[-400:]!r}") from None


def logs_broker():
    return dc("logs", "--no-color", "--no-log-prefix", "broker").out


def aleatorio():
    return secrets.token_urlsafe(32)


def reto_s256(verifier):
    """code_challenge S256 (RFC 7636, 4.2): base64url sin relleno de
    SHA-256(verifier)."""
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------------------
# Comprobaciones
# ---------------------------------------------------------------------------
def seccion_a():
    p("=== a) el broker real con Google configurado")
    r = dc("build", "broker")
    if r.rc != 0:
        raise Parada(f"no se construye la imagen del broker: {r.todo.strip()[-500:]}")
    r = dc("up", "-d", "--wait", "--wait-timeout", "60", "broker")
    p(f"up -d --wait broker -> codigo {r.rc}")
    registro = logs_broker()
    if r.rc != 0:
        raise Parada(f"no arranca el broker: {r.todo.strip()[-500:]} {registro[-500:]}")
    # Sin este literal, el broker tiene Google sin configurar o con otra
    # redirect_uri: el resto no mediría nada.
    if LOG_ACTIVADO not in registro:
        raise Parada("el broker no tiene Google configurado con la redirect_uri esperada "
                     "(credenciales reales en secrets/google_client_id.txt y google_client_secret.txt)")
    pasa(True, f"a) el log del broker dice {LOG_ACTIVADO!r}")


def flujo(numero):
    """Abre un flujo en el broker, pide la vuelta y devuelve (code, verifier,
    nonce). Comprueba el state y el iss de la vuelta."""
    state, nonce, verifier = aleatorio(), aleatorio(), aleatorio()
    respuesta = cliente([{"ruta": "/autorizar", "json": {"proveedor": "google", "state": state,
                                                         "code_challenge": reto_s256(verifier), "nonce": nonce}}])[0]
    if respuesta.get("estado") != 200:
        raise Parada(f"/autorizar no da 200 en el flujo {numero}: {respuesta}")
    url = json.loads(respuesta["cuerpo"]).get("url", "")
    consulta = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
    pasa(url.startswith(INICIO_URL) and consulta.get("state") == [state]
         and consulta.get("code_challenge") == [reto_s256(verifier)]
         and consulta.get("code_challenge_method") == ["S256"] and consulta.get("redirect_uri") == [REDIRECT],
         f"{numero}) el broker da la URL de Google con el state, el reto S256 y la redirect_uri")
    solo_terminal()
    solo_terminal(f"--- Flujo {numero}: abra esta URL en el navegador e inicie sesion con su usuario de prueba ---")
    solo_terminal(url)
    solo_terminal("Al volver, el navegador dira que no puede conectar con localhost: es lo esperado.")
    # getpass: la URL de la vuelta lleva el code; no se ve al pegarla.
    vuelta = getpass.getpass("Pegue la URL completa de la barra de direcciones (no se vera) y pulse Enter: ").strip()
    if not vuelta.startswith(INICIO_VUELTA):
        # Solo el principio, sin llegar a la consulta: si fuera una vuelta mal
        # copiada, el code va detrás y no debe salir en la salida.
        raise Parada(f"la URL pegada en el flujo {numero} no es la de la vuelta (empieza por {vuelta[:30]!r})")
    datos = urllib.parse.parse_qs(urllib.parse.urlsplit(vuelta).query)
    if datos.get("error"):
        raise Parada(f"Google devolvio error en el flujo {numero}: {datos['error']}")
    if datos.get("state") != [state]:
        raise Parada(f"el state de la vuelta del flujo {numero} no es el de este flujo (¿URL de otro intento?)")
    pasa(datos.get("iss") == [ISS_GOOGLE],
         f"{numero}) la vuelta trae iss={ISS_GOOGLE} (RFC 9207) ({datos.get('iss')})")
    codes = datos.get("code") or []
    if len(codes) != 1 or not codes[0]:
        raise Parada(f"la vuelta del flujo {numero} no trae un code")
    return codes[0], verifier, nonce


def canjear(code, verifier, nonce):
    return cliente([{"ruta": "/canjear", "json": {"proveedor": "google", "code": code,
                                                  "verifier": verifier, "nonce": nonce}}])[0]


def secciones_b_c_d():
    p("=== b) flujo 1: el canje con un verifier incorrecto")
    code_1, verifier_1, nonce_1 = flujo("b")
    incorrecto = aleatorio()
    if incorrecto == verifier_1 or not PATRON_43.fullmatch(incorrecto):
        raise Parada("el verifier incorrecto no es valido para la prueba")
    rechazos_antes = logs_broker().count(LOG_RECHAZADO)
    negativa = canjear(code_1, incorrecto, nonce_1)
    rechazos_tras_negativo = logs_broker().count(LOG_RECHAZADO)

    p("=== c) flujo 2: control positivo con el verifier correcto")
    code_2, verifier_2, nonce_2 = flujo("c")
    positiva = canjear(code_2, verifier_2, nonce_2)
    rechazos_tras_control = logs_broker().count(LOG_RECHAZADO)
    try:
        cuerpo = json.loads(positiva.get("cuerpo", ""))
    except ValueError:
        cuerpo = {}
    sub = cuerpo.get("sub") if isinstance(cuerpo, dict) else None
    sub_valido = isinstance(sub, str) and PATRON_SUB.fullmatch(sub) is not None
    control_ok = (positiva.get("estado") == 200 and isinstance(cuerpo, dict) and cuerpo.get("proveedor") == "google"
                  and sub_valido and rechazos_tras_control == rechazos_tras_negativo)
    # Sin imprimir el sub: solo si tiene formato válido.
    pasa(control_ok, f"c) control: con el verifier correcto, 200, proveedor google y un sub con formato valido "
                     f"(estado {positiva.get('estado')}, sub valido {sub_valido})")
    negativo("b) Google rechaza el verifier incorrecto: 401 con el cuerpo fijo y EVENTO canje_fallido motivo=rechazado",
             negativa.get("estado") == 401 and negativa.get("cuerpo") == CUERPO_FALLIDO
             and rechazos_tras_negativo == rechazos_antes + 1,
             control_ok, f"(estado {negativa.get('estado')}, cuerpo {negativa.get('cuerpo')!r}, "
                         f"eventos {rechazos_antes} -> {rechazos_tras_negativo})")

    p("=== d) el log del broker")
    registro = logs_broker()
    filtrados = [nombre for nombre, valor in (("code 1", code_1), ("code 2", code_2), ("verifier 1", verifier_1),
                                              ("verifier incorrecto", incorrecto), ("verifier 2", verifier_2))
                 if valor in registro]
    pasa(not filtrados,
         f"d) el log del broker no lleva ningun code ni verifier de la bateria {filtrados or ''}".strip())


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
        sinc("s) no se pudo comparar el estado de Git (git no disponible, fallo o el directorio no es un repositorio)")
    else:
        iguales = final == ESTADO_GIT_ARRANQUE
        pasa(iguales, "s) la bateria no ha modificado el repo (git status igual al del arranque)")
        if not iguales:
            p(f"   al arrancar: {ESTADO_GIT_ARRANQUE}")
            p(f"   al terminar: {final}")


# ---------------------------------------------------------------------------
# Arranque, precondiciones y cierre
# ---------------------------------------------------------------------------
def terminar():
    if estado["falla"] or estado["sin_conclusion"]:
        resultado = "NO OK (hay FALLA o SIN CONCLUSION)"
    else:
        resultado = "OK"
    p("RESULTADO GLOBAL: " + resultado)
    p("Recuerde borrar del historial del navegador las dos URL de la vuelta (localhost:8445/...vuelta).")
    SALIDA.write_text("\n".join(lineas_salida) + "\n", encoding="utf-8", newline="\n")
    sys.exit(0 if resultado == "OK" else 1)


def terminar_con_parada():
    p("RESULTADO GLOBAL: NO OK (PARADA)")
    SALIDA.write_text("\n".join(lineas_salida) + "\n", encoding="utf-8", newline="\n")
    sys.exit(1)


def estado_git():
    """Líneas de "git status --short -uall", o None si git no está disponible o falla."""
    try:
        r = ejecutar(["git", "status", "--short", "-uall"], timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.rc != 0:
        return None
    return [linea.rstrip() for linea in r.out.splitlines() if linea.strip()]


def recursos_previos():
    previos = []
    for orden in (["docker", "ps", "-a", "--format", "{{.Names}}"],
                  ["docker", "network", "ls", "--format", "{{.Name}}"],
                  ["docker", "volume", "ls", "--format", "{{.Name}}"]):
        previos += [n for n in ejecutar(orden).out.split() if n.startswith(PROYECTO)]
    return previos


def subred_ocupada():
    """Redes ajenas que ya usan la subred fija de canje."""
    ocupadas = []
    for red in ejecutar(["docker", "network", "ls", "-q"]).out.split():
        r = ejecutar(["docker", "network", "inspect", "--format",
                      "{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}", red])
        partes = r.out.split()
        if partes and SUBRED_CANJE in partes[1:]:
            ocupadas.append(partes[0])
    return ocupadas


def escucha_8445():
    """True si algo atiende en 127.0.0.1:8445: la vuelta llegaría a esa pila
    y el code no se podría copiar de la barra (y esa pila lo gastaría o lo
    rechazaría por el state)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conexion:
        conexion.settimeout(2)
        return conexion.connect_ex(("127.0.0.1", PUERTO_SPA)) == 0


ESTADO_GIT_ARRANQUE = None


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
    ocupadas = subred_ocupada()
    if ocupadas:
        p(f"PARADA: la subred {SUBRED_CANJE} ya esta en uso por {ocupadas} "
          "(pare la pila: docker compose --profile desarrollo down, sin -v)")
        terminar_con_parada()
    if escucha_8445():
        p(f"PARADA: algo escucha en 127.0.0.1:{PUERTO_SPA}; parelo para que la vuelta no llegue a ninguna pila")
        terminar_con_parada()
    # Solo se comprueba que existen (is_file), nunca se leen: docker compose
    # valida que estén todos los ficheros de secretos del compose.
    for fichero in ("google_client_id.txt", "google_client_secret.txt"):
        if not (RAIZ / "secrets" / fichero).is_file():
            p(f"PARADA: secrets/{fichero} no existe")
            terminar_con_parada()
    r = dc("config", "--quiet")
    if r.rc != 0:
        p("PARADA: docker compose config falla (genere los secretos con scripts/generar_secretos.py): "
          f"{r.err.strip()[:300]}")
        terminar_con_parada()
    TEMPORAL = pathlib.Path(tempfile.mkdtemp(prefix="canario_googlereal_"))
    (TEMPORAL / "cliente.py").write_text(CLIENTE, encoding="utf-8", newline="\n")
    parada = None
    try:
        seccion_a()
        secciones_b_c_d()
    except Parada as e:
        parada = str(e)
        p(f"PARADA: {parada}")
    except KeyboardInterrupt:
        parada = "interrumpida por el usuario"
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
