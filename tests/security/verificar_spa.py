#!/usr/bin/env python3
"""Batería de pruebas de seguridad de la SPA del personal servida por Caddy en
el 8445 (spa/, proxy/Dockerfile y proxy/Caddyfile, docs/threat-model.md, 6.11).

La pila entera con la imagen real del proxy, que compila la SPA en su primera
etapa. Prueba:

* a) arranque de la pila (con Mailpit) y alta de una empresa y de la
  invitación de su primer admin;
* b) las cabeceras exactas de la página, del script, de la hoja de estilos y de
  un error, con su tipo de contenido;
* c) que index.html no lleva nada en línea (ni <script> sin src, ni <style>,
  ni atributos on* o style), que es lo que permite la CSP sin 'unsafe-inline',
  y que declara lang="es". Control: la etapa de compilación con un mutante
  (inlineCritical activado y una regla de CSS) sí lo lleva;
* d) que la imagen final no lleva Node ni npm (control: la imagen base de la
  compilación sí), y que /srv/spa solo contiene index.html, un main-*.js y un
  styles-*.css, de root y sin escritura para nadie más (control: /data/caddy,
  que es del usuario de Caddy, sale con su dueño);
* e) que el contexto de compilación está aislado: unos ficheros centinela
  puestos en una copia de spa/ (en node_modules/, en dist/ y en la raíz) no
  llegan a la etapa de compilación (control: package.json sí llega);
* f) el recorrido de rutas del 8445 (ficheros, rutas de la SPA, ficheros que
  no existen, intentos de salir de /srv, métodos y rangos), que el 8444 no
  sirve la SPA (control: sirve su CSS) y que el 8443 tampoco;
* g) la SPA en un Chromium real (imagen de Playwright fijada por digest): carga
  "/" (que lleva a /entrar) y una ruta profunda en recarga directa sin ninguna
  violación de la CSP, y Trusted Types bloquea un innerHTML con texto y la
  política 'angular#unsafe-bypass' (control: en about:blank el mismo
  innerHTML se permite). Chromium confía en el certificado de Caddy por el
  SPKI de la CA intermedia, que es lo que Caddy envía (control: con el SPKI de
  la raíz, que no envía, la carga falla con ERR_CERT_AUTHORITY_INVALID). Solo
  se leen los certificados públicos, nunca una clave;
* h) las pruebas unitarias de la SPA (Vitest, spa/src/app/nucleo/*.spec.ts)
  en la etapa de compilación, sin red (control: con red, el mismo contenedor
  sí sale). Control positivo de las pruebas: dos mutantes del interceptor de
  renovación (sin la marca RENOVABLE y sin la renovación compartida) hacen
  fallar la prueba que los vigila;
* i) el recorrido del personal en Chromium, con los formularios rellenados por
  su etiqueta (si un campo no la tiene, la prueba falla): activación desde el
  enlace con el token en el fragmento, que sale de la URL y no queda en la
  página ni en el almacenamiento (control: /no-existe#abc conserva su
  fragmento); QR y secreto; foco al cambiar de paso y de página; cookies
  __Host- con HttpOnly, Secure y SameSite=Strict y document.cookie vacío; un
  login fallido hace una sola petición y ninguna renovación (control: con el
  acceso caducado, /yo sí renueva); dos pestañas con el acceso caducado
  renuevan de una en una y la sesión sigue viva (control: dos renovaciones a
  la vez sí la cierran); cerrar la sesión borra sus cookies y deja la del
  dispositivo; la solicitud de registro muestra el mensaje fijo; ninguna
  violación de la CSP ni error de JavaScript (control: una conexión a otro
  origen sí deja su violación en la consola);
* j) la verificación del registro desde el enlace del correo (Mailpit): el
  token sale de la URL, se envía al pulsar el botón y, después, el admin ve
  la solicitud por la API.

Lo que no prueba: Trusted Types en Firefox y Safari, que no lo aplican de la
misma forma (docs/threat-model.md, 8); Web Locks y las cookies en otros
navegadores que no sean Chromium; accesibilidad completa (axe, bloque 6b-5).

Cada prueba negativa lleva su control positivo: si el control falla, el
resultado es SIN CONCLUSION, nunca PASA. Los oráculos son literales.

Cómo se ejecuta (desde la raíz del repositorio, en PowerShell, con Docker en
marcha, conexión a internet y los secretos generados con
scripts/generar_secretos.py):

    python tests/security/verificar_spa.py

Necesita red para compilar la SPA (npm ci y npm audit signatures), para
descargar la imagen de Playwright y para instalar el paquete playwright con
pip (versiones exactas y hashes de PyPI). La imagen de Playwright es para
linux/amd64. Las secciones i) y j) esperan a veces al siguiente código TOTP:
cada código vale una sola vez y cambia cada 30 segundos.

Usa un proyecto de Docker propio (canario_spa). Necesita que el proyecto
canario y las demás baterías estén parados: las subredes 10.88.0.0/28 y
10.88.1.0/28 y los puertos 127.0.0.1:8443, 127.0.0.1:8444 y 127.0.0.1:8445 son
fijos (si están en uso, PARADA). Al terminar lo borra todo (down -v, las
imágenes construidas, las de los mutantes y la de las pruebas unitarias). No
lee ningún secreto: el token de invitación es el que imprime gestion
alta-admin, como en las demás baterías. Los ficheros
auxiliares van a un directorio temporal del sistema, nunca al repositorio. La
salida completa se guarda en verificacion_spa.txt dentro del directorio
temporal del sistema. El código de salida es 0 solo si el resultado global es
OK.

Solo usa la biblioteca estándar.
"""
import base64
import hashlib
import hmac
import http.client
import json
import pathlib
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import traceback

RAIZ = pathlib.Path.cwd()
PROYECTO = "canario_spa"
SALIDA = pathlib.Path(tempfile.gettempdir()) / "verificacion_spa.txt"
# Con los perfiles gestion (alta de la empresa y del admin) y desarrollo
# (Mailpit, para el correo de verificación del registro). down solo actúa
# sobre los servicios de los perfiles activos: con los dos, no queda nada.
BASE = ["docker", "compose", "-p", PROYECTO, "-f", "docker-compose.yml", "--profile", "gestion",
        "--profile", "desarrollo"]

lineas_salida = []
estado = {"falla": False, "sin_conclusion": False}

# ---------------------------------------------------------------------------
# Oráculos literales
# ---------------------------------------------------------------------------
PUERTO_API = 8443
PUERTO_WEB = 8444
PUERTO_SPA = 8445
SUBRED_APP = "10.88.0.0/28"
SUBRED_EDGE = "10.88.1.0/28"
RAIZ_CA = "/data/caddy/pki/authorities/local/root.crt"
INTERMEDIA_CA = "/data/caddy/pki/authorities/local/intermediate.crt"

# La imagen base de la etapa de compilación (proxy/Dockerfile).
IMG_NODE = "node:24.20.0-alpine3.23@sha256:0388af2af070cd4736a1567cfed02469ba117848845b4165d87a333edb53d2ca"
# Playwright 1.63.0 (15 de septiembre de 2026). La imagen trae Python y los
# navegadores, pero no el paquete playwright (comprobado): se instala con pip,
# con versiones exactas y los hashes de los ficheros de PyPI. playwright exige
# pyee<14.
IMG_PLAYWRIGHT = ("mcr.microsoft.com/playwright/python:v1.63.0-noble"
                  "@sha256:72bd171a9ffc2b4b59532aaa6210e21014d07093120dc25528870c0b840da1f0")
USUARIO_PLAYWRIGHT = "1001:1001"  # pwuser
REQUISITOS_PLAYWRIGHT = (
    "playwright==1.63.0 --hash=sha256:ad21bc07516b187965a7521c5cf0df0bd657b17482eaad74335272d35a2b07de\n"
    "pyee==13.0.1 --hash=sha256:af2f8fede4171ef667dfded53f96e2ed0d6e6bd7ee3bb46437f77e3b57689228\n"
    "greenlet==3.5.6 --hash=sha256:975736b002ed080d124cf81a79cb7e05cb26d6b3f5c7a7b651c0fcce70353aa1\n"
    "typing-extensions==4.16.0 --hash=sha256:481caa481374e813c1b176ada14e97f1f67a4539ce9cfeb3f350d78d6370c2e8\n"
)

CSP_SPA = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
           "require-trusted-types-for 'script'; trusted-types angular; base-uri 'self'; "
           "form-action 'none'; frame-ancestors 'none'")
CABECERAS_SPA = {
    "strict-transport-security": "max-age=63072000",
    "x-content-type-options": "nosniff",
    "referrer-policy": "same-origin",
    "content-security-policy": CSP_SPA,
    "cache-control": "no-store",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
}
TIPO_HTML = "text/html; charset=utf-8"
TIPO_JS = "text/javascript; charset=utf-8"
TIPO_CSS = "text/css; charset=utf-8"
TIPO_JSON = "application/json"
CUERPO_404 = b'{"detalle": "recurso no encontrado"}'
CUERPO_405 = '{"detalle": "petición no válida"}'.encode()

# Lo que tiene que haber en index.html (spa/src/index.html y el build).
FRAGMENTO_SPA = b"<app-root><p>Cargando...</p></app-root>"
LANG_ES = b'<html lang="es">'
BASE_HREF = b'<base href="/">'
PATRON_MAIN = re.compile(rb'<script src="(main-[A-Z0-9]{8}\.js)" type="module"></script>')
PATRON_ESTILOS = re.compile(rb'<link rel="stylesheet" href="(styles-[A-Z0-9]{8}\.css)">')
# d) Los únicos ficheros de /srv/spa.
PATRON_FICHERO_SPA = re.compile(r"(index\.html|main-[A-Z0-9]{8}\.js|styles-[A-Z0-9]{8}\.css)")

# c) Lo que delata algo en línea en un HTML.
EN_LINEA = {
    "script sin src": re.compile(rb"<script\b(?![^>]*\ssrc=)[^>]*>", re.IGNORECASE),
    "style": re.compile(rb"<style\b", re.IGNORECASE),
    "atributo on*": re.compile(rb"\son[a-z]+\s*=", re.IGNORECASE),
    "atributo style": re.compile(rb"\sstyle\s*=", re.IGNORECASE),
    "javascript:": re.compile(rb"javascript:", re.IGNORECASE),
}
# Mutante de c): beasties solo pone algo en línea si hay CSS que inlinar.
CSS_MUTANTE = "body { margin: 0; }\n"
CENTINELAS = ("node_modules/centinela_spa.txt", "dist/centinela_spa.txt", "centinela_spa.txt")

# f) Recorrido de rutas del 8445: (método, ruta, estado, tipo, qué cuerpo).
# "spa" es la página de la SPA (FRAGMENTO_SPA); "404" y "405", los errores de
# Caddy en JSON.
RUTAS_SPA = [
    ("GET", "/", 200, TIPO_HTML, "spa"),
    ("GET", "/index.html", 200, TIPO_HTML, "spa"),
    ("GET", "/denuncias/abc", 200, TIPO_HTML, "spa"),
    ("GET", "/a/b/c/d", 200, TIPO_HTML, "spa"),
    ("GET", "/main-NOEXISTE.js", 404, TIPO_JSON, "404"),
    ("GET", "/favicon.ico", 404, TIPO_JSON, "404"),
    ("GET", "/3rdpartylicenses.txt", 404, TIPO_JSON, "404"),
    ("GET", "/package.json", 404, TIPO_JSON, "404"),
    ("GET", "/../etc/passwd", 200, TIPO_HTML, "spa"),
    ("GET", "/..%2f..%2fetc/passwd", 200, TIPO_HTML, "spa"),
    ("GET", "/%2e%2e/%2e%2e/etc/caddy/Caddyfile", 200, TIPO_HTML, "spa"),
    ("GET", "/%2e%2e/estatico/canario.css", 404, TIPO_JSON, "404"),
    ("POST", "/", 405, TIPO_JSON, "405"),
    ("DELETE", "/index.html", 405, TIPO_JSON, "405"),
]
# El 8444 no sirve la SPA aunque /srv/spa esté al lado de /srv/estatico.
RUTAS_SPA_DESDE_8444 = ["/spa/index.html", "/estatico/../spa/index.html", "/estatico/%2e%2e/spa/index.html",
                        "/estatico/..%2fspa/index.html"]
RUTA_CSS_8444 = "/estatico/canario.css"

# g) Lo que pinta la SPA (spa/src/app). "/" lleva a /entrar.
ORIGEN_SPA = "https://localhost:8445"
H1_ENTRAR = "Entrar"
TITULO_ENTRAR = "Entrar - Canario"
H1_NO_ENCONTRADA = "Página no encontrada"
TITULO_NO_ENCONTRADA = "Página no encontrada - Canario"
RUTA_PROFUNDA = "/denuncias/abc/def"
ERROR_TLS = "net::ERR_CERT_AUTHORITY_INVALID"
ERROR_TRUSTED_HTML = "This document requires 'TrustedHTML' assignment"
ERROR_POLITICA = "Policy \"angular#unsafe-bypass\" disallowed"

# h) Pruebas unitarias (spa/src/app/nucleo/*.spec.ts): sus nombres, tal cual.
PRUEBAS_UNITARIAS = (
    "con un 401 de sesión renueva una vez, dentro del cerrojo, y repite la petición una vez",
    "repite también una petición que cambia algo (el 401 llega antes de que la ruta haga nada)",
    "un login fallido no renueva, aunque su 401 traiga WWW-Authenticate: Bearer",
    "un 401 sin WWW-Authenticate: Bearer no renueva",
    "si la renovación falla con 401, no repite la petición y lleva a /entrar",
    "si la renovación falla por la red, no lleva a /entrar",
    "dos peticiones con 401 a la vez comparten una sola renovación",
    "en /activacion lo toma, lo borra de la URL y lo entrega una sola vez",
    "en /registro/verificacion conserva la consulta y quita solo el fragmento",
    "el token de una ruta no se entrega a la otra",
    "en otras rutas no toca la URL ni guarda nada",
    "sin fragmento no toca la URL",
    "429 dice cuánto esperar con Retry-After, en minutos si pasa de uno",
    "429 sin un Retry-After legible no inventa un número",
    "sin red, servicio caído y el texto propio de la página",
    "el detalle de la API solo si es un texto",
)
ORDEN_PRUEBAS = "npx ng test --watch=false --reporters=verbose"
# Mutantes del interceptor: (qué quita, fichero, texto original, texto mutado,
# la prueba que debe fallar).
MUTANTES_UNITARIOS = (
    ("sin la marca RENOVABLE", "src/app/nucleo/renovacion.ts",
     "  if (!peticion.context.get(RENOVABLE)) {", "  if (false) {",
     "un login fallido no renueva, aunque su 401 traiga WWW-Authenticate: Bearer"),
    ("sin la renovacion compartida", "src/app/nucleo/renovacion.ts",
     "    this.enCurso ??= this.cerrojo(", "    this.enCurso = this.cerrojo(",
     "dos peticiones con 401 a la vez comparten una sola renovación"),
)
# process.exit: el agente de Node mantiene viva la conexión y el proceso no
# terminaría solo.
PRUEBA_RED = ("require('https').get('https://registry.npmjs.org/', () => { console.log('CONECTA'); process.exit(0); })"
              ".on('error', (e) => { console.log('SIN_RED', e.code); process.exit(0); })")

# a), i) y j) La empresa, el admin y la solicitud de registro de la prueba.
PATRON_ALTA = re.compile(r"empresa creada: empresa_id=([0-9a-f-]{36}) identificador_publico=([0-9a-f]{32})")
PATRON_INVITACION = re.compile(r"token_invitacion=([0-9a-f]{32}\.[A-Za-z0-9_-]{43})\n")
EMAIL_ADMIN = "admin@spa.test"
EMAIL_REGISTRO = "nueva.persona@spa.test"
CONTRASENA_ADMIN = secrets.token_urlsafe(18)
PATRON_SECRETO_TOTP = re.compile(r"[A-Z2-7]{32}")
COOKIE_ACCESO = "__Host-canario_acceso"
COOKIE_RENOVACION = "__Host-canario_renovacion"
COOKIE_DISPOSITIVO = "__Host-canario_dispositivo"
RUTA_YO = "/v1/personal/yo"
RUTA_SESIONES = "/v1/personal/sesiones"
RUTA_RENOVACION = "/v1/personal/sesiones/renovacion"
RUTA_CIERRE = "/v1/personal/sesiones/actual"
PASO_CODIGO = "Paso 2 de 2: configure la aplicación de autenticación"
H1_INICIO = "Inicio"
NOMBRE_ROL_ADMIN = "Admin"
ALERTA_LOGIN = "No se ha podido entrar. Revise la empresa, el email, la contraseña y el código."
# app/rutas_personal.py, MENSAJE_REGISTRO.
MENSAJE_REGISTRO = ("si los datos son correctos, recibirá un correo en unos minutos; "
                    "si no le llega, vuelva a solicitarlo más tarde")
TEXTO_VERIFICADO = ("Email confirmado. Un admin de su empresa revisará la solicitud; si la aprueba, recibirá "
                    "otro correo para activar la cuenta.")
ASUNTO_VERIFICACION = "Confirme su email para registrarse en Canario"
PATRON_VERIFICACION = re.compile(r"https://localhost:8445/registro/verificacion#([0-9a-f]{32}\.[A-Za-z0-9_-]{43})")
# Lo que delata una violación de la CSP o de Trusted Types en la consola de
# Chromium.
SENALES_CSP = ("Content Security Policy", "TrustedHTML", "TrustedScript", "Trusted Type")

# Script del navegador (se escribe en el directorio temporal). Recibe los dos
# SPKI y escribe un JSON con lo que ve.
NAVEGADOR = r'''
import json, sys
sys.path.insert(0, "/tmp/pw")
from playwright.sync_api import Error, sync_playwright

spki_intermedia, spki_raiz = sys.argv[1], sys.argv[2]
ORIGEN = "https://localhost:8445"
res = {}


def intento(pagina, js):
    try:
        pagina.evaluate(js)
        return "permitido"
    except Error as e:
        return "bloqueado: " + str(e)


def visitar(pagina, ruta, recargar=False):
    pagina.goto(ORIGEN + ruta, wait_until="load")
    if recargar:
        pagina.reload(wait_until="load")
    pagina.wait_for_selector("main h1", timeout=15000)
    return {"h1": pagina.inner_text("main h1"), "titulo": pagina.title(), "url": pagina.url,
            "lang": pagina.evaluate("document.documentElement.lang"),
            "cargando": pagina.evaluate("document.body.innerText.includes('Cargando...')")}


with sync_playwright() as pw:
    navegador = pw.chromium.launch(args=[f"--ignore-certificate-errors-spki-list={spki_intermedia}"])
    pagina = navegador.new_page()
    consola, errores = [], []
    pagina.on("console", lambda m: consola.append(f"{m.type}: {m.text}"))
    pagina.on("pageerror", lambda e: errores.append(str(e)))
    res["inicio"] = visitar(pagina, "/")
    res["profunda"] = visitar(pagina, sys.argv[3], recargar=True)
    res["consola"], res["errores"] = list(consola), list(errores)
    res["innerHTML"] = intento(pagina, "document.body.innerHTML = '<b>x</b>'")
    res["politica"] = intento(pagina, "trustedTypes.createPolicy('angular#unsafe-bypass', {createHTML: s => s})")
    pagina.goto("about:blank")
    res["control_innerHTML"] = intento(pagina, "document.body.innerHTML = '<b>x</b>'")
    navegador.close()

    navegador = pw.chromium.launch(args=[f"--ignore-certificate-errors-spki-list={spki_raiz}"])
    pagina = navegador.new_page()
    try:
        pagina.goto(ORIGEN + "/", wait_until="load")
        res["con_spki_raiz"] = "cargada"
    except Error as e:
        res["con_spki_raiz"] = "error: " + str(e)
    navegador.close()
print(json.dumps(res, ensure_ascii=False))
'''

# Parte común de los scripts de i) y j): TOTP propio de la batería (RFC 6238
# sobre RFC 4226, independiente de app/cripto.py), el registro de peticiones y
# de mensajes de cada página, y las cookies sin su valor. Asíncrono: i) tiene
# que recargar dos pestañas a la vez y retrasar una respuesta.
NAVEGADOR_COMUN = r'''
import asyncio, base64, hashlib, hmac, json, sys, time
sys.path.insert(0, "/tmp/pw")
from playwright.async_api import async_playwright

ORIGEN = "https://localhost:8445"
CODIGO = "Código de la aplicación de autenticación"
res = {}
eventos, consola, errores = [], [], []
ultimo = {"paso": -1}


def totp(secreto, paso):
    mac = hmac.new(base64.b32decode(secreto), paso.to_bytes(8, "big"), hashlib.sha1).digest()
    o = mac[-1] & 0x0F
    return f"{(int.from_bytes(mac[o:o + 4], 'big') & 0x7FFFFFFF) % 10 ** 6:06d}"


async def codigo_libre(secreto):
    # Un código vale una sola vez: si el paso actual ya se usó, al siguiente.
    while True:
        actual = int(time.time()) // 30
        if actual > ultimo["paso"]:
            ultimo["paso"] = actual
            return totp(secreto, actual)
        await asyncio.sleep(30 - time.time() % 30 + 0.5)


def ruta(url):
    return url.removeprefix(ORIGEN).split("?")[0]


def vigilar(pagina, nombre):
    pagina.on("console", lambda m: consola.append(f"{nombre} {m.type}: {m.text}"))
    pagina.on("pageerror", lambda e: errores.append(f"{nombre}: {e}"))
    pagina.on("request", lambda r: eventos.append(
        {"tipo": "peticion", "metodo": r.method, "ruta": ruta(r.url), "t": time.monotonic(), "pagina": nombre}))
    pagina.on("response", lambda r: eventos.append(
        {"tipo": "respuesta", "metodo": r.request.method, "ruta": ruta(r.url), "estado": r.status,
         "t": time.monotonic(), "pagina": nombre}))


def api_desde(marca):
    return [e for e in eventos[marca:] if e["ruta"].startswith("/v1/")]


async def cookies(contexto):
    # Nunca el valor: solo el nombre y los atributos.
    return {c["name"]: {"httpOnly": c["httpOnly"], "secure": c["secure"], "sameSite": c["sameSite"],
                        "path": c["path"]} for c in await contexto.cookies()}


async def foco(pagina):
    return await pagina.evaluate("document.activeElement ? document.activeElement.textContent.trim() : null")


async def almacenamiento(pagina):
    return await pagina.evaluate("[localStorage.length, sessionStorage.length]")


async def ejecutar(spki, pasos):
    async with async_playwright() as pw:
        navegador = await pw.chromium.launch(args=[f"--ignore-certificate-errors-spki-list={spki}"])
        contexto = await navegador.new_context()
        try:
            await pasos(contexto)
        except Exception as e:
            res["excepcion"] = f"{type(e).__name__}: {e}"[:600]
        res["consola"], res["errores"] = consola, errores
        await navegador.close()
    print(json.dumps(res, ensure_ascii=False))
'''

# i) El recorrido del personal. Recibe el SPKI, el identificador de la
# empresa, el token de invitación, el email y la contraseña del admin y el
# email de la solicitud de registro.
NAVEGADOR_SESION = NAVEGADOR_COMUN + r'''
spki, identificador, invitacion, email, contrasena, email_registro = sys.argv[1:7]
RENOVACION = "/v1/personal/sesiones/renovacion"
ACCESO = "__Host-canario_acceso"


async def entrar(pagina, clave, codigo):
    await pagina.goto(ORIGEN + "/entrar")
    await pagina.get_by_label("Empresa").fill(identificador)
    await pagina.get_by_label("Email").fill(email)
    await pagina.get_by_label("Contraseña", exact=True).fill(clave)
    await pagina.get_by_label(CODIGO).fill(codigo)
    await pagina.get_by_role("button", name="Entrar", exact=True).click()


async def en_inicio(pagina):
    await pagina.wait_for_url(ORIGEN + "/inicio")
    await pagina.locator(".cuenta dd").first.wait_for()
    return await pagina.locator(".cuenta dd").all_inner_texts()


async def renovar_a_mano(pagina):
    return await pagina.evaluate(
        "fetch('" + RENOVACION + "', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: '{}'})"
        ".then(r => r.status)")


async def pasos(contexto):
    pagina = await contexto.new_page()
    vigilar(pagina, "A")

    # Control de las comprobaciones de la URL: en otra ruta, el fragmento se queda.
    await pagina.goto(ORIGEN + "/no-existe#abc")
    await pagina.wait_for_selector("main h1")
    res["control_fragmento"] = await pagina.evaluate("location.hash")

    # Activación desde el enlace del correo.
    await pagina.goto(ORIGEN + "/activacion#" + invitacion)
    await pagina.wait_for_selector("main h1")
    res["url_activacion"] = pagina.url
    res["token_en_pagina"] = await pagina.evaluate(
        "document.documentElement.outerHTML.includes(" + json.dumps(invitacion) + ")")
    res["almacen_activacion"] = await almacenamiento(pagina)
    await pagina.get_by_label("Contraseña nueva").fill(contrasena)
    await pagina.get_by_label("Repita la contraseña").fill(contrasena)
    await pagina.get_by_role("button", name="Continuar", exact=True).click()
    await pagina.get_by_role("heading", name="Paso 2 de 2: configure la aplicación de autenticación").wait_for()
    res["foco_paso"] = await foco(pagina)
    res["qr"] = await pagina.get_by_role("img", name="Código QR para la aplicación de autenticación").count()
    secreto = (await pagina.locator("#activacion-secreto").inner_text()).replace(" ", "")
    res["secreto"] = secreto
    await pagina.get_by_label(CODIGO).fill(await codigo_libre(secreto))
    await pagina.get_by_role("button", name="Activar la cuenta", exact=True).click()
    await pagina.get_by_role("heading", name="Cuenta activada").wait_for()
    res["activada"] = True
    res["cookies_activacion"] = await cookies(contexto)

    # Login fallido: una sola petición y ninguna renovación.
    marca = len(eventos)
    await entrar(pagina, contrasena + "-mal", "000000")
    alerta = pagina.get_by_role("alert")
    await alerta.wait_for()
    await asyncio.sleep(1)
    res["login_fallido"] = {"alerta": await alerta.inner_text(), "api": api_desde(marca)}

    # Login correcto.
    marca = len(eventos)
    await entrar(pagina, contrasena, await codigo_libre(secreto))
    res["inicio"] = await en_inicio(pagina)
    res["foco_inicio"] = await foco(pagina)
    res["document_cookie"] = await pagina.evaluate("document.cookie")
    res["cookies_sesion"] = await cookies(contexto)
    res["almacen_sesion"] = await almacenamiento(pagina)

    # Acceso caducado (sin su cookie): /yo da 401, se renueva y se repite.
    await contexto.clear_cookies(name=ACCESO)
    marca = len(eventos)
    await pagina.reload()
    res["inicio_renovado"] = await en_inicio(pagina)
    res["renovacion"] = api_desde(marca)

    # Dos pestañas con el acceso caducado a la vez. La renovación se retrasa
    # 1,5 s para que la segunda pestaña reciba su 401 mientras la primera
    # renueva.
    pagina_b = await contexto.new_page()
    vigilar(pagina_b, "B")
    await pagina_b.goto(ORIGEN + "/inicio")
    await en_inicio(pagina_b)
    await contexto.clear_cookies(name=ACCESO)

    async def lenta(peticion_retenida):
        await asyncio.sleep(1.5)
        await peticion_retenida.continue_()

    await contexto.route("**" + RENOVACION, lenta)
    marca = len(eventos)
    await asyncio.gather(pagina.reload(), pagina_b.reload())
    await asyncio.gather(en_inicio(pagina), en_inicio(pagina_b))
    await contexto.unroute("**" + RENOVACION, lenta)
    res["pestanas"] = api_desde(marca)
    res["pestanas_yo"] = [await p.evaluate("fetch('/v1/personal/yo').then(r => r.status)") for p in (pagina, pagina_b)]
    await pagina_b.close()

    # Cerrar la sesión.
    marca = len(eventos)
    await pagina.get_by_role("button", name="Cerrar la sesión", exact=True).click()
    await pagina.wait_for_url(ORIGEN + "/entrar")
    res["cookies_cierre"] = await cookies(contexto)
    await pagina.goto(ORIGEN + "/inicio")
    await pagina.wait_for_url(ORIGEN + "/entrar")
    res["cierre"] = api_desde(marca)

    # Control: con una sesión nueva, dos renovaciones a la vez la cierran.
    await entrar(pagina, contrasena, await codigo_libre(secreto))
    await en_inicio(pagina)
    res["control_paralelas"] = await pagina.evaluate(
        "Promise.all([1, 2].map(() => fetch('" + RENOVACION + "', {method: 'POST', "
        "headers: {'Content-Type': 'application/json'}, body: '{}'}).then(r => r.status)))")
    res["control_despues"] = await renovar_a_mano(pagina)

    # Solicitud de registro.
    await pagina.goto(ORIGEN + "/registro")
    await pagina.get_by_label("Empresa").fill(identificador)
    await pagina.get_by_label("Email").fill(email_registro)
    await pagina.get_by_role("button", name="Solicitar acceso", exact=True).click()
    estado_registro = pagina.get_by_role("status")
    await estado_registro.wait_for()
    res["registro"] = await estado_registro.inner_text()

    # Control de la consola: una conexión a otro origen sí deja su violación.
    res["consola_antes_del_control"] = len(consola)
    await pagina.evaluate("fetch('https://ejemplo.invalid/').catch(() => null)")
    await asyncio.sleep(1)
    res["ultimo_paso"] = ultimo["paso"]


asyncio.run(ejecutar(spki, pasos))
'''

# j) La verificación del registro desde el enlace del correo. Recibe el SPKI
# y el enlace.
NAVEGADOR_VERIFICACION = NAVEGADOR_COMUN + r'''
spki, enlace = sys.argv[1:3]


async def pasos(contexto):
    pagina = await contexto.new_page()
    vigilar(pagina, "A")
    await pagina.goto(enlace)
    await pagina.wait_for_selector("main h1")
    res["url"] = pagina.url
    res["fragmento"] = await pagina.evaluate("location.hash")
    res["token_en_pagina"] = await pagina.evaluate(
        "document.documentElement.outerHTML.includes(" + json.dumps(enlace.split("#", 1)[1]) + ")")
    res["almacen"] = await almacenamiento(pagina)
    marca = len(eventos)
    await asyncio.sleep(1)
    res["api_antes_del_boton"] = api_desde(marca)
    await pagina.get_by_role("button", name="Confirmar mi email", exact=True).click()
    estado = pagina.get_by_role("status")
    await estado.wait_for()
    res["texto"] = await estado.inner_text()
    res["api"] = api_desde(marca)


asyncio.run(ejecutar(spki, pasos))
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


def montaje(origen, destino):
    return ["--mount", f"type=bind,src={origen},dst={destino},readonly"]


TEMPORAL = None
CA_LOCAL = None
IMAGEN_PROXY = ""
IMAGEN_API = ""
IMAGEN_MUTANTE = f"{PROYECTO}_mutante"
IMAGEN_PRUEBAS = f"{PROYECTO}_pruebas"
SPKI_INTERMEDIA = ""
SPKI_RAIZ = ""
IDENTIFICADOR = ""
INVITACION = ""
# Lo que i) deja para j): el secreto TOTP del admin (nunca se escribe en la
# salida) y el último paso TOTP usado.
SECRETO_ADMIN = ""
ULTIMO_PASO = -1


def peticion(metodo, ruta, puerto=PUERTO_SPA, cabeceras=None, datos=None):
    """Petición al proxy publicado en 127.0.0.1 con SNI localhost y TLS
    validado contra la raíz de Caddy. Devuelve (estado, {cabecera en
    minúsculas: [valores]}, cuerpo). La ruta se envía tal cual. datos, si lo
    hay, va como cuerpo JSON."""
    cuerpo = b"" if datos is None else json.dumps(datos).encode("utf-8")
    contexto = ssl.create_default_context(cafile=str(CA_LOCAL))
    s = socket.create_connection(("127.0.0.1", puerto), timeout=30)
    c = http.client.HTTPConnection("localhost", puerto, timeout=30)
    c.sock = contexto.wrap_socket(s, server_hostname="localhost")
    c.putrequest(metodo, ruta, skip_host=True, skip_accept_encoding=True)
    c.putheader("Host", f"localhost:{puerto}")
    c.putheader("Content-Length", str(len(cuerpo)))
    if datos is not None:
        c.putheader("Content-Type", "application/json")
    for nombre, valor in (cabeceras or {}).items():
        c.putheader(nombre, valor)
    c.endheaders(cuerpo or None)
    r = c.getresponse()
    leido = r.read()
    valores = {}
    for nombre, valor in r.getheaders():
        valores.setdefault(nombre.lower(), []).append(valor)
    c.close()
    return r.status, valores, leido


def una(cabeceras, nombre):
    """El valor de una cabecera que debe aparecer una sola vez, o None."""
    lista = cabeceras.get(nombre) or []
    return lista[0] if len(lista) == 1 else None


def en_linea(html):
    """Lo que hay en línea en un HTML: [(qué, cuántas veces)]."""
    return [(nombre, len(patron.findall(html))) for nombre, patron in EN_LINEA.items() if patron.search(html)]


def spki_de(pem):
    """SHA-256 en base64 del SubjectPublicKeyInfo de un certificado PEM, el
    formato de --ignore-certificate-errors-spki-list. Recorre el DER a mano:
    Certificate > tbsCertificate > [version], serial, firma, emisor, validez,
    sujeto y, después, la clave pública."""
    der = base64.b64decode("".join(linea for linea in pem.splitlines() if linea and not linea.startswith("-----")))

    def elemento(i):
        longitud = der[i + 1]
        i += 2
        if longitud & 0x80:
            octetos = longitud & 0x7F
            longitud = int.from_bytes(der[i:i + octetos], "big")
            i += octetos
        return i, i + longitud

    i, _ = elemento(0)
    i, _ = elemento(i)
    if der[i] == 0xA0:
        i = elemento(i)[1]
    for _ in range(5):
        i = elemento(i)[1]
    fin = elemento(i)[1]
    return base64.b64encode(hashlib.sha256(der[i:fin]).digest()).decode()


def en_imagen(imagen, orden, timeout=120):
    """Una orden de shell en un contenedor desechable de la imagen, sin red y
    con la raíz de solo lectura."""
    return ejecutar(["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
                     "--security-opt", "no-new-privileges", "--entrypoint", "sh", imagen, "-c", orden], timeout=timeout)


def pruebas_unitarias(imagen, red="none"):
    """Vitest en la etapa de compilación. Sin red: un paquete de pruebas
    malicioso no puede sacar nada (docs/threat-model.md, 6.11). Sin --read-only:
    Angular y Vitest escriben su caché en /spa, que es del usuario node."""
    return ejecutar(["docker", "run", "--rm", "--network", red, "--cap-drop", "ALL", "--security-opt",
                     "no-new-privileges", "--entrypoint", "sh", imagen, "-c", ORDEN_PRUEBAS], timeout=900)


def compilacion(contexto_spa, etiqueta):
    """Construye la etapa de compilación del proxy con contexto_spa como
    contexto spa (el repositorio no se toca)."""
    r = ejecutar(["docker", "build", "-q", "--target", "compilacion", "--build-context", f"spa={contexto_spa}",
                  "-f", str(RAIZ / "proxy" / "Dockerfile"), "-t", etiqueta, str(RAIZ / "proxy")], timeout=1800)
    if r.rc != 0:
        raise Parada(f"no se pudo construir la etapa de compilacion ({etiqueta}): {r.err.strip()[-500:]}")


def copia_de_spa(nombre):
    """Copia de spa/ sin lo que genera un build o una instalación local."""
    copia = TEMPORAL / nombre
    shutil.copytree(RAIZ / "spa", copia, ignore=shutil.ignore_patterns("node_modules", "dist", ".angular"))
    return copia


def navegador(nombre, script, argumentos):
    """Ejecuta un script de Playwright en Chromium y devuelve su JSON, o None.
    El navegador comparte la red del contenedor de Caddy: localhost:8445 es
    Caddy, con el mismo Host y el mismo SNI que desde el host. Mínimo
    privilegio: pwuser, raíz de solo lectura y sin capacidades (Playwright
    lanza Chromium sin su sandbox por defecto). La red la usa pip. Si falla,
    solo se informa de stderr: stdout puede llevar el secreto TOTP de i)."""
    directorio = TEMPORAL / nombre
    directorio.mkdir()
    (directorio / "navegador.py").write_text(script, encoding="utf-8", newline="\n")
    (directorio / "requisitos.txt").write_text(REQUISITOS_PLAYWRIGHT, encoding="utf-8", newline="\n")
    caddy = dc("ps", "-q", "caddy").out.strip()
    r = ejecutar(["docker", "run", "--rm", "--network", f"container:{caddy}", "--user", USUARIO_PLAYWRIGHT,
                  "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--shm-size", "512m",
                  "--tmpfs", "/tmp:size=600m,exec", "-e", "HOME=/tmp", *montaje(directorio, "/prueba"),
                  "--entrypoint", "sh", IMG_PLAYWRIGHT, "-c",
                  ("pip install -q --disable-pip-version-check --no-deps --only-binary :all: --require-hashes "
                   "--target /tmp/pw -r /prueba/requisitos.txt && python3 -I /prueba/navegador.py \"$@\""),
                  "navegador", *argumentos], timeout=1200)
    try:
        return json.loads(r.out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        p(f"   el navegador no devolvio resultado (codigo {r.rc}): {r.err.strip()[-800:]!r}")
        return None


def totp(clave, paso, digitos=6):
    """TOTP propio de la batería (RFC 6238 sobre RFC 4226), independiente de
    app/cripto.py."""
    mac = hmac.new(clave, paso.to_bytes(8, "big"), hashlib.sha1).digest()
    o = mac[-1] & 0x0F
    return f"{(int.from_bytes(mac[o:o + 4], 'big') & 0x7FFFFFFF) % 10 ** digitos:0{digitos}d}"


def codigo_tras(secreto, paso_usado):
    """El código del primer paso posterior a paso_usado (un código solo vale
    una vez): espera si hace falta."""
    while int(time.time()) // 30 <= paso_usado:
        time.sleep(30 - time.time() % 30 + 0.5)
    return totp(base64.b32decode(secreto), int(time.time()) // 30)


def respuestas(eventos):
    """(método, ruta, estado) de las respuestas de la API, en orden."""
    return [(e["metodo"], e["ruta"], e["estado"]) for e in eventos if e["tipo"] == "respuesta"]


def senales_csp(mensajes):
    return [m for m in mensajes if any(s in m for s in SENALES_CSP)]


# Lector del buzón de Mailpit por su API HTTP, desde la red correo (la única
# donde está), como en tests/security/verificar_registro.py.
LECTOR_CORREO = r'''
import json, urllib.request
base = "http://mailpit:8025/api/v1"
lista = json.load(urllib.request.urlopen(base + "/messages?limit=1000", timeout=10))
salida = []
for m in lista.get("messages") or []:
    d = json.load(urllib.request.urlopen(base + "/message/" + m["ID"], timeout=10))
    salida.append({"para": [a["Address"] for a in d.get("To") or []], "asunto": d.get("Subject"),
                   "texto": d.get("Text")})
print(json.dumps(salida))
'''


def buzon():
    r = ejecutar(["docker", "run", "--rm", "--network", f"{PROYECTO}_correo", "--read-only", "--cap-drop", "ALL",
                  "--security-opt", "no-new-privileges", "--entrypoint", "python", IMAGEN_API, "-c", LECTOR_CORREO])
    try:
        return json.loads(r.out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise Parada(f"no se pudo leer el buzon de Mailpit: {r.err.strip()[-400:]!r}") from None


# ---------------------------------------------------------------------------
# Secciones
# ---------------------------------------------------------------------------
INDICE = b""
MAIN = ""
ESTILOS = ""


def imagen_de(servicio):
    return ejecutar(["docker", "inspect", "--format", "{{.Config.Image}}",
                     dc("ps", "-q", servicio).out.strip()]).out.strip()


def seccion_a():
    global CA_LOCAL, IMAGEN_PROXY, IMAGEN_API, IDENTIFICADOR, INVITACION
    p("=== a) arranque de la pila (la imagen del proxy compila la SPA) y alta de la empresa y su admin")
    pasa(totp(b"12345678901234567890", 59 // 30, 8) == "94287082", "a) el TOTP de la bateria cumple RFC 6238")
    r = dc("up", "-d", "--build", "--wait", "api", "caddy", "mailpit", timeout=1800)
    p(f"up -d --build --wait api caddy mailpit -> codigo {r.rc}")
    if r.rc != 0:
        p(r.todo.strip()[-1500:])
        raise Parada("no arranca la pila")
    IMAGEN_PROXY, IMAGEN_API = imagen_de("caddy"), imagen_de("api")
    p(f"imagen del proxy: {IMAGEN_PROXY}")
    CA_LOCAL = TEMPORAL / "root.crt"
    r = dc("cp", f"caddy:{RAIZ_CA}", str(CA_LOCAL))
    if r.rc != 0 or not CA_LOCAL.is_file():
        raise Parada(f"no se pudo copiar el certificado raiz del CA de Caddy: {r.err.strip()[:200]}")
    r = dc("run", "--rm", "-T", "gestion", "alta-empresa", "--nombre", "Empresa SPA", "--zona", "Europe/Madrid")
    alta = PATRON_ALTA.search(r.out)
    if r.rc != 0 or alta is None:
        raise Parada(f"no se pudo dar de alta la empresa de prueba: {r.err.strip()[-300:]!r}")
    IDENTIFICADOR = alta.group(2)
    r = dc("run", "--rm", "-T", "gestion", "alta-admin", "--identificador", IDENTIFICADOR, "--email", EMAIL_ADMIN)
    invitacion = PATRON_INVITACION.search(r.out)
    if r.rc != 0 or invitacion is None:
        raise Parada(f"no se pudo emitir la invitacion del admin: {r.err.strip()[-300:]!r}")
    INVITACION = invitacion.group(1)
    p(f"   empresa de prueba: {IDENTIFICADOR}")


def seccion_b():
    global INDICE, MAIN, ESTILOS
    p("=== b) cabeceras y tipos del 8445")
    codigo, cab, INDICE = peticion("GET", "/")
    main, estilos = PATRON_MAIN.search(INDICE), PATRON_ESTILOS.search(INDICE)
    if codigo != 200 or main is None or estilos is None:
        raise Parada(f"GET / no devuelve el index.html del build ({codigo}, {INDICE[:200]!r})")
    MAIN, ESTILOS = main.group(1).decode(), estilos.group(1).decode()
    p(f"   index.html carga {MAIN} y {ESTILOS}")
    for etiqueta, ruta, tipo in (("pagina", "/", TIPO_HTML), ("script", f"/{MAIN}", TIPO_JS),
                                 ("estilos", f"/{ESTILOS}", TIPO_CSS), ("error 404", "/main-NOEXISTE.js", TIPO_JSON)):
        _, cab, _ = peticion("GET", ruta)
        pasa(una(cab, "content-type") == tipo, f"b) {etiqueta}: content-type: {cab.get('content-type')!r}")
        for nombre, valor in CABECERAS_SPA.items():
            pasa(una(cab, nombre) == valor, f"b) {etiqueta}: {nombre}: {cab.get(nombre)!r}")
        pasa("server" not in cab and "accept-ranges" not in cab, f"b) {etiqueta}: sin Server ni Accept-Ranges")


def seccion_c_e():
    p("=== c) index.html sin nada en linea y e) contexto de compilacion aislado")
    pasa(LANG_ES in INDICE and BASE_HREF in INDICE and FRAGMENTO_SPA in INDICE,
         "c) index.html declara lang=\"es\", <base href=\"/\"> y el aviso de carga dentro de app-root")

    # Mutante y centinelas en una copia de spa/ sin lo que genera un build
    # local. La etapa de compilación se construye con esa copia como contexto
    # spa: el repositorio no se toca.
    copia = TEMPORAL / "spa"
    shutil.copytree(RAIZ / "spa", copia, ignore=shutil.ignore_patterns("node_modules", "dist", ".angular"))
    angular = json.loads((copia / "angular.json").read_text(encoding="utf-8"))
    optimizacion = angular["projects"]["canario-spa"]["architect"]["build"]["configurations"]["production"]["optimization"]
    if optimizacion["styles"].get("inlineCritical") is not False:
        raise Parada("spa/angular.json no tiene inlineCritical en false: el mutante no se puede construir")
    optimizacion["styles"]["inlineCritical"] = True
    (copia / "angular.json").write_text(json.dumps(angular, indent=2), encoding="utf-8", newline="\n")
    with (copia / "src" / "styles.css").open("a", encoding="utf-8", newline="\n") as f:
        f.write(CSS_MUTANTE)
    for centinela in CENTINELAS:
        (copia / centinela).parent.mkdir(parents=True, exist_ok=True)
        (copia / centinela).write_text("centinela\n", encoding="utf-8", newline="\n")
    r = ejecutar(["docker", "build", "-q", "--target", "compilacion", "--build-context", f"spa={copia}",
                  "-f", str(RAIZ / "proxy" / "Dockerfile"), "-t", IMAGEN_MUTANTE, str(RAIZ / "proxy")], timeout=1800)
    if r.rc != 0:
        raise Parada(f"no se pudo construir la etapa de compilacion del mutante: {r.err.strip()[-500:]}")
    mutante = en_imagen(IMAGEN_MUTANTE, "cat /spa/dist/canario-spa/browser/index.html").out.encode("utf-8")
    real = en_linea(INDICE)
    control = en_linea(mutante)
    p(f"   mutante: {control}")
    negativo(f"c) index.html servido: nada en linea {real}", not real, bool(control),
             f"control: el mutante no tiene nada en linea ({mutante[:200]!r})")

    r = en_imagen(IMAGEN_MUTANTE, "find /spa -name 'centinela*'; test -f /spa/package.json && echo PACKAGE_JSON")
    hallados = [linea for linea in r.out.splitlines() if "centinela" in linea]
    negativo(f"e) ningun centinela de la copia de spa/ llega a la compilacion {hallados}", not hallados,
             r.rc == 0 and "PACKAGE_JSON" in r.out, f"control: {r.todo.strip()[-200:]!r}")


def seccion_d():
    p("=== d) la imagen final: sin Node y /srv/spa solo con el build, de root")
    orden = "command -v node npm npx corepack; true"
    final, control = en_imagen(IMAGEN_PROXY, orden), en_imagen(IMG_NODE, orden)
    negativo(f"d) sin node, npm, npx ni corepack en la imagen final ({final.out.split()})", not final.out.split(),
             "/usr/local/bin/node" in control.out, f"control: {control.out.split()}")

    r = en_imagen(IMAGEN_PROXY, "find /srv/spa /data/caddy -maxdepth 1 -exec stat -c '%u:%g %a %n' {} +")
    filas = [linea.split(" ", 2) for linea in r.out.splitlines() if linea.count(" ") >= 2]
    datos = {nombre: (dueno, int(modo, 8)) for dueno, modo, nombre in filas}
    control = datos.get("/data/caddy", ("", 0))[0] == "10002:10002" and "/srv/spa/index.html" in datos
    spa = {nombre: v for nombre, v in datos.items() if nombre.startswith("/srv/spa/")}
    nombres = sorted(n.removeprefix("/srv/spa/") for n in spa)
    negativo(f"d) /srv/spa solo contiene index.html, un main-*.js y un styles-*.css ({nombres})",
             len(nombres) == 3 and all(PATRON_FICHERO_SPA.fullmatch(n) for n in nombres), control,
             f"control: {r.todo.strip()[-300:]!r}")
    de_otro = sorted(n for n, (dueno, modo) in {**spa, "/srv/spa": datos.get("/srv/spa", ("", 0))}.items()
                     if dueno != "0:0" or modo & 0o022)
    negativo(f"d) /srv/spa y sus ficheros son de root y solo root escribe {de_otro}", not de_otro, control,
             "; ".join(f"{n}: {spa.get(n, datos.get(n, ('?', 0)))[0]} {spa.get(n, datos.get(n, ('?', 0)))[1]:o}"
                       for n in de_otro))


def seccion_f():
    p("=== f) recorrido de rutas del 8445; el 8444 y el 8443 no sirven la SPA")
    codigo, _, cuerpo = peticion("GET", f"/{MAIN}")
    control = codigo == 200 and len(cuerpo) > 1000
    pasa(control, f"f) control: GET /{MAIN} -> {codigo}, {len(cuerpo)} bytes")
    esperados = {"spa": FRAGMENTO_SPA, "404": CUERPO_404, "405": CUERPO_405}
    for metodo, ruta, estado_esperado, tipo, cuerpo_esperado in RUTAS_SPA:
        codigo, cab, cuerpo = peticion(metodo, ruta)
        ok = (codigo == estado_esperado and una(cab, "content-type") == tipo
              and (esperados[cuerpo_esperado] in cuerpo if cuerpo_esperado == "spa"
                   else cuerpo == esperados[cuerpo_esperado])
              and b"root:" not in cuerpo and "via" not in cab)
        negativo(f"f) {metodo} {ruta} -> {estado_esperado} {cuerpo_esperado} ({codigo}, {una(cab, 'content-type')!r})",
                 ok, control, f"{cuerpo[:120]!r}")
    codigo, cab, cuerpo = peticion("GET", f"/{MAIN}", cabeceras={"Range": "bytes=0-1,3-4"})
    negativo(f"f) dos rangos sobre /{MAIN} -> 200 con el fichero entero ({codigo}, {len(cuerpo)} bytes)",
             codigo == 200 and una(cab, "content-type") == TIPO_JS and len(cuerpo) > 1000
             and "accept-ranges" not in cab, control)

    codigo, _, _ = peticion("GET", RUTA_CSS_8444, puerto=PUERTO_WEB)
    control_web = codigo == 200
    pasa(control_web, f"f) control: el 8444 sirve {RUTA_CSS_8444} ({codigo})")
    for ruta in RUTAS_SPA_DESDE_8444:
        codigo, cab, cuerpo = peticion("GET", ruta, puerto=PUERTO_WEB)
        negativo(f"f) 8444 GET {ruta} -> 404, sin la SPA ({codigo})",
                 codigo == 404 and una(cab, "content-type") == TIPO_HTML and FRAGMENTO_SPA not in cuerpo, control_web)
    codigo, cab, cuerpo = peticion("GET", "/index.html", puerto=PUERTO_API)
    negativo(f"f) 8443 GET /index.html -> 404 de la API, sin la SPA ({codigo})",
             codigo == 404 and cuerpo == CUERPO_404 and FRAGMENTO_SPA not in cuerpo, control)


def seccion_g():
    global SPKI_INTERMEDIA, SPKI_RAIZ
    p("=== g) la SPA en Chromium: CSP sin violaciones y Trusted Types")
    pem_intermedia = dc("exec", "-T", "caddy", "cat", INTERMEDIA_CA).out
    pem_raiz = CA_LOCAL.read_text(encoding="utf-8")
    if "BEGIN CERTIFICATE" not in pem_intermedia:
        raise Parada("no se pudo leer el certificado de la CA intermedia de Caddy")
    SPKI_INTERMEDIA, SPKI_RAIZ = spki_de(pem_intermedia), spki_de(pem_raiz)
    res = navegador("navegador_g", NAVEGADOR, [SPKI_INTERMEDIA, SPKI_RAIZ, RUTA_PROFUNDA])
    if res is None:
        sinc("g) no se pudo ejecutar el navegador")
        return
    inicio, profunda = res.get("inicio") or {}, res.get("profunda") or {}
    p(f"   inicio {inicio}; profunda {profunda}")
    control = inicio.get("h1") == H1_ENTRAR
    pasa(control, f"g) control: Chromium carga / y Angular pinta la entrada ({inicio.get('h1')!r})")
    negativo(f"g) Chromium sin el SPKI de la intermedia no acepta el certificado ({res.get('con_spki_raiz', '')[:80]!r})",
             ERROR_TLS in res.get("con_spki_raiz", ""), control)
    pasa(inicio.get("url") == ORIGEN_SPA + "/entrar" and inicio.get("titulo") == TITULO_ENTRAR
         and inicio.get("lang") == "es" and inicio.get("cargando") is False,
         f"g) / lleva a /entrar: url {inicio.get('url')!r}, titulo {inicio.get('titulo')!r}, "
         f"lang {inicio.get('lang')!r} y sin el aviso de carga")
    pasa(profunda.get("h1") == H1_NO_ENCONTRADA and profunda.get("titulo") == TITULO_NO_ENCONTRADA,
         f"g) {RUTA_PROFUNDA} en recarga directa: {profunda.get('h1')!r}, titulo {profunda.get('titulo')!r}")
    consola, errores = res.get("consola") or [], res.get("errores") or []
    negativo(f"g) ningun mensaje de consola ni error de JavaScript al cargar ({len(consola)}, {len(errores)})",
             not consola and not errores, control, f"consola {consola}; errores {errores}")
    control_tt = res.get("control_innerHTML") == "permitido"
    pasa(control_tt, f"g) control: en about:blank un innerHTML con texto se permite ({res.get('control_innerHTML')!r})")
    negativo("g) Trusted Types bloquea un innerHTML con texto en la SPA", ERROR_TRUSTED_HTML in res.get("innerHTML", ""),
             control_tt, res.get("innerHTML", "")[:200])
    negativo("g) Trusted Types no deja crear la politica 'angular#unsafe-bypass'",
             ERROR_POLITICA in res.get("politica", ""), control_tt, res.get("politica", "")[:200])


def falla_la_prueba(salida, nombre):
    """Si Vitest marca como fallida la prueba nombre: una línea con su nombre
    y la marca de fallo del reporter (FAIL o ×)."""
    return any(nombre in linea and ("FAIL" in linea or "×" in linea) for linea in salida.splitlines())


def seccion_h():
    p("=== h) pruebas unitarias de la SPA (Vitest) sin red, con mutantes del interceptor")
    compilacion(copia_de_spa("spa_pruebas"), IMAGEN_PRUEBAS)
    orden_red = ["docker", "run", "--rm", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                 "--entrypoint", "node", IMAGEN_PRUEBAS, "-e", PRUEBA_RED]
    sin_red = ejecutar(orden_red[:3] + ["--network", "none"] + orden_red[3:], timeout=60)
    con_red = ejecutar(orden_red, timeout=60)
    negativo(f"h) el contenedor de las pruebas no tiene red ({sin_red.out.strip()!r})",
             sin_red.out.startswith("SIN_RED"), con_red.out.strip() == "CONECTA",
             f"control con red: {con_red.todo.strip()[-200:]!r}")

    r = pruebas_unitarias(IMAGEN_PRUEBAS)
    salida = r.todo
    pasa(r.rc == 0, f"h) Vitest termina sin fallos (codigo {r.rc})")
    if r.rc != 0:
        p(salida.strip()[-2000:])
    faltan = [nombre for nombre in PRUEBAS_UNITARIAS if nombre not in salida]
    pasa(not faltan, f"h) se ejecutan las {len(PRUEBAS_UNITARIAS)} pruebas unitarias esperadas {faltan if faltan else ''}"
         .rstrip())

    for i, (que, fichero, original, mutado, vigilante) in enumerate(MUTANTES_UNITARIOS, start=1):
        copia = copia_de_spa(f"spa_mutante_unitario_{i}")
        ruta = copia / fichero
        texto = ruta.read_text(encoding="utf-8")
        if texto.count(original) != 1:
            sinc(f"h) mutante {que}: el texto original no aparece una sola vez en {fichero}")
            continue
        ruta.write_text(texto.replace(original, mutado), encoding="utf-8", newline="\n")
        etiqueta = f"{IMAGEN_MUTANTE}_unitario_{i}"
        compilacion(copia, etiqueta)
        m = pruebas_unitarias(etiqueta)
        pasa(m.rc != 0 and falla_la_prueba(m.todo, vigilante),
             f"h) mutante {que}: Vitest falla en \"{vigilante}\" (codigo {m.rc})")
        if not falla_la_prueba(m.todo, vigilante):
            p(m.todo.strip()[-1200:])


def seccion_i():
    global SECRETO_ADMIN, ULTIMO_PASO
    p("=== i) recorrido del personal en Chromium: activacion, login, renovacion, pestanas, cierre y registro")
    res = navegador("navegador_i", NAVEGADOR_SESION,
                    [SPKI_INTERMEDIA, IDENTIFICADOR, INVITACION, EMAIL_ADMIN, CONTRASENA_ADMIN, EMAIL_REGISTRO])
    if res is None:
        sinc("i) no se pudo ejecutar el navegador")
        return
    if "excepcion" in res:
        pasa(False, f"i) el recorrido se interrumpe: {res['excepcion']}")
    SECRETO_ADMIN, ULTIMO_PASO = res.get("secreto", ""), res.get("ultimo_paso", -1)

    # Activación.
    control_url = res.get("control_fragmento") == "#abc"
    pasa(control_url, f"i) control: en /no-existe#abc el fragmento se queda ({res.get('control_fragmento')!r})")
    negativo(f"i) tras abrir el enlace, la URL es /activacion sin el token ({res.get('url_activacion')!r})",
             res.get("url_activacion") == ORIGEN_SPA + "/activacion", control_url)
    pasa(res.get("token_en_pagina") is False and res.get("almacen_activacion") == [0, 0],
         f"i) el token no queda en la pagina ni en localStorage o sessionStorage "
         f"({res.get('token_en_pagina')}, {res.get('almacen_activacion')})")
    pasa(res.get("foco_paso") == PASO_CODIGO, f"i) el foco pasa al encabezado del paso 2 ({res.get('foco_paso')!r})")
    pasa(res.get("qr") == 1 and PATRON_SECRETO_TOTP.fullmatch(SECRETO_ADMIN) is not None,
         f"i) la activacion muestra el QR con su nombre accesible y el secreto en texto ({res.get('qr')})")
    dispositivo = (res.get("cookies_activacion") or {}).get(COOKIE_DISPOSITIVO)
    pasa(res.get("activada") is True and dispositivo == {"httpOnly": True, "secure": True, "sameSite": "Strict",
                                                         "path": "/"},
         f"i) la cuenta se activa y deja la cookie del dispositivo con HttpOnly, Secure y SameSite=Strict ({dispositivo})")

    # Login fallido frente a la renovación (su control).
    fallido = res.get("login_fallido") or {}
    renovacion = respuestas(res.get("renovacion") or [])
    control_renovacion = renovacion == [("GET", RUTA_YO, 401), ("POST", RUTA_RENOVACION, 200), ("GET", RUTA_YO, 200)]
    pasa(control_renovacion and res.get("inicio_renovado") == res.get("inicio"),
         f"i) control: sin la cookie de acceso, /yo da 401, se renueva una vez y se repite ({renovacion})")
    api_fallido = fallido.get("api") or []
    negativo(f"i) un login fallido hace una sola peticion y ninguna renovacion ({respuestas(api_fallido)})",
             respuestas(api_fallido) == [("POST", RUTA_SESIONES, 401)]
             and not any(e["ruta"] == RUTA_RENOVACION for e in api_fallido), control_renovacion)
    pasa(fallido.get("alerta") == ALERTA_LOGIN, f"i) el login fallido se anuncia con role=alert ({fallido.get('alerta')!r})")

    # Login correcto.
    pasa(res.get("inicio") == [EMAIL_ADMIN, NOMBRE_ROL_ADMIN], f"i) /inicio muestra el email y el rol ({res.get('inicio')})")
    pasa(res.get("foco_inicio") == H1_INICIO, f"i) al cambiar de pagina el foco va al h1 ({res.get('foco_inicio')!r})")
    sesion = res.get("cookies_sesion") or {}
    atributos = {"httpOnly": True, "secure": True, "sameSite": "Strict", "path": "/"}
    pasa(all(sesion.get(nombre) == atributos for nombre in (COOKIE_ACCESO, COOKIE_RENOVACION, COOKIE_DISPOSITIVO))
         and sorted(sesion) == sorted([COOKIE_ACCESO, COOKIE_RENOVACION, COOKIE_DISPOSITIVO]),
         f"i) las tres cookies de la sesion son __Host- con HttpOnly, Secure y SameSite=Strict ({sesion})")
    negativo(f"i) ningun script ve las cookies: document.cookie vacio ({res.get('document_cookie')!r})",
             res.get("document_cookie") == "", bool(sesion))
    pasa(res.get("almacen_sesion") == [0, 0], f"i) nada en localStorage ni sessionStorage ({res.get('almacen_sesion')})")

    # Dos pestañas frente a dos renovaciones a la vez (su control).
    eventos = res.get("pestanas") or []
    caducadas = [e for e in eventos if e["tipo"] == "respuesta" and e["ruta"] == RUTA_YO and e["estado"] == 401]
    renov_pet = [e for e in eventos if e["tipo"] == "peticion" and e["ruta"] == RUTA_RENOVACION]
    renov_resp = [e for e in eventos if e["tipo"] == "respuesta" and e["ruta"] == RUTA_RENOVACION]
    paralelas = sorted(res.get("control_paralelas") or [])
    control_pestanas = paralelas == [200, 401] and res.get("control_despues") == 401
    pasa(control_pestanas, f"i) control: dos renovaciones a la vez cierran la sesion ({paralelas}, despues "
                           f"{res.get('control_despues')})")
    if len(caducadas) != 2 or {e["pagina"] for e in caducadas} != {"A", "B"}:
        sinc(f"i) las dos pestanas no recibieron su 401 a la vez: no se ha probado el cerrojo ({respuestas(eventos)})")
    else:
        de_una_en_una = (len(renov_pet) == 2 and len(renov_resp) == 2
                         and all(r["estado"] == 200 for r in renov_resp) and renov_pet[1]["t"] >= renov_resp[0]["t"])
        negativo(f"i) dos pestanas con el acceso caducado renuevan de una en una ({respuestas(eventos)})",
                 de_una_en_una, control_pestanas)
        negativo(f"i) y la sesion sigue viva en las dos ({res.get('pestanas_yo')})",
                 res.get("pestanas_yo") == [200, 200], control_pestanas)

    # Cierre de la sesión.
    cierre = respuestas(res.get("cierre") or [])
    pasa(("DELETE", RUTA_CIERRE, 204) in cierre and sorted(res.get("cookies_cierre") or {}) == [COOKIE_DISPOSITIVO],
         f"i) cerrar la sesion borra el acceso y la renovacion y deja el dispositivo ({sorted(res.get('cookies_cierre') or {})})")
    pasa(cierre[-2:] == [("GET", RUTA_YO, 401), ("POST", RUTA_RENOVACION, 401)],
         f"i) tras cerrarla, /inicio lleva a /entrar sin sesion que renovar ({cierre[-2:]})")

    # Registro.
    pasa(res.get("registro") == MENSAJE_REGISTRO, f"i) la solicitud de registro muestra el mensaje fijo ({res.get('registro')!r})")

    # Consola: sin violaciones de la CSP ni errores de JavaScript.
    consola, errores = res.get("consola") or [], res.get("errores") or []
    corte = res.get("consola_antes_del_control", len(consola))
    control_csp = bool(senales_csp(consola[corte:]))
    pasa(control_csp, f"i) control: una conexion a otro origen deja su violacion de la CSP en la consola ({consola[corte:][:1]})")
    negativo(f"i) en todo el recorrido, ninguna violacion de la CSP ni error de JavaScript "
             f"({len(senales_csp(consola[:corte]))}, {len(errores)})",
             not senales_csp(consola[:corte]) and not errores, control_csp,
             f"{senales_csp(consola[:corte])[:3]} {errores[:3]}")


def seccion_j():
    p("=== j) verificacion del registro desde el enlace del correo")
    enlace = None
    for _ in range(30):
        for correo in buzon():
            encaje = PATRON_VERIFICACION.search(correo.get("texto") or "")
            if EMAIL_REGISTRO in correo.get("para", []) and correo.get("asunto") == ASUNTO_VERIFICACION and encaje:
                enlace = encaje.group(0)
        if enlace:
            break
        time.sleep(1)
    if enlace is None:
        raise Parada("no llego el correo de verificacion del registro")
    pasa(True, "j) llega el correo de verificacion con el enlace a la SPA")
    res = navegador("navegador_j", NAVEGADOR_VERIFICACION, [SPKI_INTERMEDIA, enlace])
    if res is None:
        sinc("j) no se pudo ejecutar el navegador")
        return
    if "excepcion" in res:
        pasa(False, f"j) la verificacion se interrumpe: {res['excepcion']}")
    pasa(res.get("url") == ORIGEN_SPA + "/registro/verificacion" and res.get("fragmento") == ""
         and res.get("token_en_pagina") is False and res.get("almacen") == [0, 0],
         f"j) tras abrir el enlace, el token no queda en la URL, la pagina ni el almacenamiento ({res.get('url')!r})")
    pasa(res.get("api_antes_del_boton") == [], f"j) abrir el enlace no envia nada ({res.get('api_antes_del_boton')})")
    pasa(respuestas(res.get("api") or []) == [("POST", "/v1/personal/registro/verificacion", 204)]
         and res.get("texto") == TEXTO_VERIFICADO,
         f"j) el boton confirma el email ({respuestas(res.get('api') or [])}, {res.get('texto')!r})")
    errores, csp = res.get("errores") or [], senales_csp(res.get("consola") or [])
    pasa(not errores and not csp, f"j) ninguna violacion de la CSP ni error de JavaScript ({csp[:2]} {errores[:2]})")

    # El admin ve la solicitud verificada (por la API del 8443, con Bearer).
    if not PATRON_SECRETO_TOTP.fullmatch(SECRETO_ADMIN):
        sinc("j) sin el secreto TOTP del admin (i no termino) no se puede comprobar la solicitud")
        return
    codigo, _, cuerpo = peticion("POST", RUTA_SESIONES, puerto=PUERTO_API, datos={
        "empresa": IDENTIFICADOR, "email": EMAIL_ADMIN, "contrasena": CONTRASENA_ADMIN,
        "codigo_totp": codigo_tras(SECRETO_ADMIN, ULTIMO_PASO)})
    acceso = (json.loads(cuerpo) if codigo == 201 else {}).get("token_acceso")
    if not acceso:
        sinc(f"j) el admin no pudo iniciar sesion por la API ({codigo})")
        return
    codigo, _, cuerpo = peticion("GET", "/v1/personal/solicitudes", puerto=PUERTO_API,
                                 cabeceras={"Authorization": f"Bearer {acceso}"})
    emails = [s.get("email") for s in (json.loads(cuerpo) if codigo == 200 else {}).get("solicitudes", [])]
    pasa(emails == [EMAIL_REGISTRO], f"j) el admin ve la solicitud verificada ({codigo}, {emails})")


# ---------------------------------------------------------------------------
# Limpieza, precondiciones y arranque
# ---------------------------------------------------------------------------
def limpiar():
    unitarios = [f"{IMAGEN_MUTANTE}_unitario_{i}" for i in range(1, len(MUTANTES_UNITARIOS) + 1)]
    ejecutar(["docker", "image", "rm", "-f", IMAGEN_MUTANTE, IMAGEN_PRUEBAS, *unitarios])
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
        sinc("s) no se pudo comparar el estado de Git (git no disponible, fallo o el directorio no es un repositorio)")
    else:
        iguales = final == ESTADO_GIT_ARRANQUE
        pasa(iguales, "s) la bateria no ha modificado el repo (git status igual al del arranque)")
        if not iguales:
            p(f"   al arrancar: {ESTADO_GIT_ARRANQUE}")
            p(f"   al terminar: {final}")


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
                  ["docker", "volume", "ls", "--format", "{{.Name}}"],
                  ["docker", "image", "ls", "--format", "{{.Repository}}"]):
        previos += [n for n in ejecutar(orden).out.split() if n.startswith(PROYECTO)]
    return previos


def subredes_ocupadas():
    """Redes ajenas que ya usan alguna de las subredes fijas del compose."""
    ocupadas = []
    for red in ejecutar(["docker", "network", "ls", "-q"]).out.split():
        r = ejecutar(["docker", "network", "inspect", "--format",
                      "{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}", red])
        partes = r.out.split()
        if partes and set(partes[1:]) & {SUBRED_APP, SUBRED_EDGE}:
            ocupadas.append(partes[0])
    return ocupadas


def puertos_ocupados():
    ocupados = []
    for puerto in (PUERTO_API, PUERTO_WEB, PUERTO_SPA):
        s = socket.socket()
        s.settimeout(2)
        try:
            if s.connect_ex(("127.0.0.1", puerto)) == 0:
                ocupados.append(puerto)
        finally:
            s.close()
    return ocupados


ESTADO_GIT_ARRANQUE = None


def main():
    global ESTADO_GIT_ARRANQUE, TEMPORAL
    # Estado de Git al arrancar, antes de levantar Docker: s) lo compara con el final.
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
        p(f"PARADA: las subredes {SUBRED_APP} o {SUBRED_EDGE} ya estan en uso por {ocupadas} (pare el proyecto canario)")
        terminar_con_parada()
    ocupados = puertos_ocupados()
    if ocupados:
        p(f"PARADA: 127.0.0.1:{ocupados} ya esta en uso (pare el proyecto canario)")
        terminar_con_parada()
    r = dc("config", "--quiet")
    if r.rc != 0:
        p(f"PARADA: docker compose config falla (genere los secretos con scripts/generar_secretos.py): {r.err.strip()[:300]}")
        terminar_con_parada()
    TEMPORAL = pathlib.Path(tempfile.mkdtemp(prefix="canario_spa_"))
    parada = None
    try:
        for seccion in (seccion_a, seccion_b, seccion_c_e, seccion_d, seccion_f, seccion_g, seccion_h, seccion_i,
                        seccion_j):
            seccion()
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
    if parada is not None:
        estado["falla"] = True
    terminar()


if __name__ == "__main__":
    main()
