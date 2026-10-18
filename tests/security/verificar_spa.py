#!/usr/bin/env python3
"""Batería de pruebas de seguridad de la SPA del personal servida por Caddy en
el 8445 (spa/, proxy/Dockerfile y proxy/Caddyfile, docs/threat-model.md, 6.11).

La pila entera con la imagen real del proxy, que compila la SPA en su primera
etapa. Prueba:

* a) arranque de la pila (con Mailpit) y alta de una empresa y de la
  invitación de su primer admin. La API arranca con límites de petición
  altos (CANARIO_LIMITES, en un compose adicional del directorio temporal) y
  el log debe decirlo: i) y l) hacen más de 10 accesos (login, activación y
  contraseña) en 5 minutos desde el mismo cliente, y el límite de producción
  los cortaría según dónde caiga el cambio de ventana. Los límites de
  producción los prueba verificar_denuncia.py, r);
* b) las cabeceras exactas de la página, del script, de la hoja de estilos, de
  la fuente y de un error, con su tipo de contenido, y que la fuente que
  sirve Caddy es, byte a byte, la del release fijado (sha256);
* c) que index.html no lleva nada en línea (ni <script> sin src, ni <style>,
  ni atributos on* o style), que es lo que permite la CSP sin 'unsafe-inline',
  y que declara lang="es". Control: la etapa de compilación con un mutante
  (inlineCritical activado y una regla de CSS) sí lo lleva;
* d) que la imagen final no lleva Node ni npm (control: la imagen base de la
  compilación sí), y que /srv/spa solo contiene index.html, un main-*.js, un
  styles-*.css y media/ con la fuente, de root y sin escritura para nadie más
  (control: /data/caddy, que es del usuario de Caddy, sale con su dueño);
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
* h) las pruebas unitarias de la SPA (Vitest, spa/src/app/**/*.spec.ts) en
  la etapa de compilación, sin red (control: con red, el mismo contenedor sí
  sale). Control positivo de las pruebas: siete mutantes (el interceptor de
  renovación sin la marca RENOVABLE y sin la renovación compartida, el guard
  de las páginas sin la comprobación del rol, el cliente de denuncias sin la
  comprobación del uuid, "no veraz" ofrecido al instructor y la auditoría
  con un hueco en vez del id de una cuenta que no se resuelve, en quién actúa
  y en sobre qué) hacen fallar la prueba que los vigila;
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
  la solicitud por la API;
* k) la base visual de spa/src/styles.css, sin Docker: el contraste de cada
  pareja de colores que usa, en el tema claro y en el oscuro (4,5:1 el texto
  y 3:1 bordes y foco, WCAG 2.2, 1.4.3 y 1.4.11), que el oscuro redefine
  todos los colores del claro, que no hay colores fuera de los dos :root y
  que toda variable usada existe. Control: la fórmula da 4,54:1 y 4,48:1 con
  los grises #767676 y #777777 sobre blanco, y cinco mutantes de la hoja (un
  gris claro en cada tema, un color que falta en el oscuro, un color suelto y
  una variable que no existe) hacen saltar cada comprobación. Y en
  spa/src/app, también sin Docker, que ningún botón lleva
  disabled ligado y que cada fichero lleva los aria-disabled de su
  inventario (control: entrar.ts con disabled hace saltar las dos);
* l) las pantallas por rol en Chromium (bloque 6b-3a): el menú de cada rol;
  una página de otro rol abierta por su URL lleva a /inicio (control: la del
  propio rol se abre) y la API responde 403 aunque la SPA se saltara
  (control: el admin, 200); el admin aprueba la solicitud de j con un rol
  elegido (sin rol no envía nada) y la invitación llega al correo, sin que el
  token pase por la página; invita a dos cuentas y el enlace se muestra como
  texto, nunca como enlace, sin quedar en la URL ni en el almacenamiento, y
  desaparece al salir de la página (control: antes de salir está); con esos
  enlaces se activan una instructora y un auditor; reinvitar avisa al titular
  en /inicio, anular quita el aviso, la baja pide confirmación y cierra la
  sesión del auditor (control: antes de la baja entraba) y la propia cuenta
  no tiene botón de baja; cambiar la contraseña con la actual mal da su
  aviso sin renovar la sesión, y con la buena la sesión sigue viva; ninguna
  violación de la CSP ni error de JavaScript;
* m) las denuncias en Chromium (bloque 6b-3b), con dos denuncias creadas por
  la API pública como un denunciante, con cargas XSS en el texto y en un
  mensaje (una con U+202E): el admin ve las dos y el instructor solo la suya;
  el admin asigna desde el listado y solo tiene enlace a las suyas (control:
  tras asignarse una, lo tiene); /denuncias/..%2Fusuarios, que el router
  decodifica a "../usuarios", es "no encontrada" sin pedir nada a la API
  (control: con un uuid, la página de la denuncia); la carga directa de la
  página no lee el expediente ni deja fila de auditoría (control: el botón lo
  lee una vez y deja una fila); las cargas salen como texto literal, sin
  crear elementos ni ejecutar nada (control: el main-*.js de un mutante con
  [innerHTML], con la página y su CSP reales, crea el <img> y la CSP bloquea
  su carga), con dir="auto", y el
  expediente no va al almacenamiento ni a la consola; el mensaje y los
  cambios de estado no vuelven a leer; cerrar sin mensaje final no envía
  nada (control: con él, sí); "no veraz" solo lo tiene el admin y pide
  confirmación; tras cerrar la sesión, "atrás" acaba en /entrar sin el
  expediente (control: antes estaba); ninguna violación de la CSP ni error de
  JavaScript;
* n) la auditoría en Chromium (bloque 6b-3c), con más de una página (lecturas
  de una denuncia por la API) y una cuenta invitada por la API con un email
  que es una carga XSS (validar_email admite cualquier ASCII imprimible): el
  admin y un auditor nuevo tienen la entrada en el menú; el instructor no, y
  /auditoria le lleva a /inicio y la API le da 403 (control: el auditor la
  abre por su URL y la API le da 200); la tabla empieza por la fila más
  reciente y dice quién y sobre qué con emails (la invitación del auditor, la
  del primer admin por la plataforma, la asignación de m y la baja de l), sin
  enlaces y sin ninguna acción sin traducir; "Cargar anteriores" completa la
  tabla sin huecos hasta la fila 1 y el foco acaba en el aviso; "Actualizar"
  trae la fila nueva y el foco sigue en el botón; la verificación dice que la
  cadena está intacta; el email sale como texto literal sin crear elementos ni
  ejecutar nada (control: el main-*.js de un mutante con [innerHTML] crea el
  <img> y la CSP bloquea su carga); ninguna violación de la CSP ni error de
  JavaScript;
* o) los botones ocupados en Chromium (bloque 6b-3d): tras un login fallido
  con Enter desde el botón, el foco sigue en "Entrar" (control: con el
  main-*.js de un mutante con disabled, acaba en el <body>); un doble clic en
  "Entrar" hace una sola petición (control: el mutante sin la guarda hace
  dos), con un email sin cuenta para no sumar fallos al bloqueo de ninguna;
  con más de 100 denuncias (creadas por la API pública), "Cargar más" trae la
  segunda página sin repetir ni perder filas (las mismas que lista la API) y
  el foco acaba en el aviso que dice que es el final; ninguna violación de la
  CSP ni error de JavaScript;
* p) la fuente y el tema oscuro en Chromium (bloque 6b-4a): Geist es la única
  fuente de la página y está cargada; con el sistema en oscuro el fondo es el
  del tema oscuro (control: en claro, el del claro); a 320 px de ancho (WCAG
  2.2, 1.4.10) ni la entrada ni las páginas del admin desbordan en
  horizontal (control: un elemento de 400 px sí desborda); la barra separa el
  email del rol con un espacio; ninguna violación
  de la CSP ni error de JavaScript (control: una fuente de otro origen sí
  deja su violación de font-src).

Lo que no prueba: Trusted Types en Firefox y Safari, que no lo aplican de la
misma forma (docs/threat-model.md, 8); Web Locks y las cookies en otros
navegadores que no sean Chromium; accesibilidad completa (axe, bloque 6b-5);
el botón "Copiar el enlace", porque el portapapeles de Chromium sin pantalla
necesita permisos que la prueba tendría que conceder a mano. De las
denuncias, en el navegador no prueba el aviso de 20 lecturas ni el 429 del
tope (harían falta 20 y 51 denuncias; el texto del aviso tiene su prueba
unitaria y el tope, la suya en verificar_personal.py), ni "Cargar más" en una
página intermedia (harían falta más de 200). De la auditoría, el aviso de una
cadena rota: romperla exige saltarse los triggers que la hacen inmutable; el
texto tiene su prueba unitaria y la detección, la suya en
verificar_esquema.py. De los botones ocupados, el doble clic solo en el login:
las guardas de las demás acciones no tienen prueba en el navegador; y el foco
al error cuando falla una acción (asignar, cuentas y solicitudes), porque
provocar cada 404 y 409 desde la pantalla exigiría cambiar los datos por
debajo a mitad del recorrido. Del tema oscuro, en el navegador solo el fondo:
el contraste de cada pareja lo comprueba k) sobre la hoja. Del ancho de 320
px, las páginas del instructor y del auditor y el expediente de una denuncia:
usan las mismas piezas que las del admin. Y que Geist tenga todos los
caracteres del castellano: si le falta uno, el navegador lo pinta con la
fuente del sistema.

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
import urllib.parse

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

# Límites altos para esta batería (ver a), en la cabecera), los mismos que las
# secciones funcionales de tests/security/verificar_denuncia.py, y la línea
# con la que la API los anuncia al arrancar (app/limitador.py).
LIMITES_PRUEBA = ("denuncia=1000/3600,seguimiento=1000/60,mensajes=1000/3600,acceso=1000/300,otras=1000/60,"
                  "cuenta=1000/60,registro=1000/3600,destinatario=1000/900,destinatario_dia=1000/86400")
TEXTO_LIMITES_PRUEBA = ("LIMITES (configurados): acceso=1000/300 cuenta=1000/60 denuncia=1000/3600 "
                        "destinatario=1000/900 destinatario_dia=1000/86400 mensajes=1000/3600 otras=1000/60 "
                        "registro=1000/3600 seguimiento=1000/60")

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

CSP_SPA = ("default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; connect-src 'self'; "
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
# b) La fuente (spa/src/fuentes): Geist[wght].woff2 del release v1.7.2 de
# github.com/vercel/geist-font (zip con sha256 7fc800d2...b04e2, el que
# publica GitHub). Su tipo lo da /etc/mime.types de la imagen de Caddy: Go no
# lo trae en su tabla propia.
TIPO_FUENTE = "font/woff2"
SHA256_FUENTE = "a369fcf5628ea2aa4e1b9e2ec6a5b3624e365bda588e1f0f2f12b564f728fbb8"
CUERPO_404 = b'{"detalle": "recurso no encontrado"}'
CUERPO_405 = '{"detalle": "petición no válida"}'.encode()

# Lo que tiene que haber en index.html (spa/src/index.html y el build).
FRAGMENTO_SPA = b"<app-root><p>Cargando...</p></app-root>"
LANG_ES = b'<html lang="es">'
BASE_HREF = b'<base href="/">'
PATRON_MAIN = re.compile(rb'<script src="(main-[A-Z0-9]{8}\.js)" type="module"></script>')
PATRON_ESTILOS = re.compile(rb'<link rel="stylesheet" href="(styles-[A-Z0-9]{8}\.css)">')
# b) La fuente, como la referencia la hoja del build (Angular la deja en
# media/ con un hash en el nombre).
PATRON_FUENTE = re.compile(rb'url\(\s*["\']?(?:\./)?(media/geist-variable-[A-Z0-9]{8}\.woff2)["\']?\s*\)')
# d) Los únicos ficheros de /srv/spa: cinco, contando el directorio media.
PATRON_FICHERO_SPA = re.compile(r"(index\.html|main-[A-Z0-9]{8}\.js|styles-[A-Z0-9]{8}\.css|media"
                                r"|media/geist-variable-[A-Z0-9]{8}\.woff2)")
FICHEROS_SPA = 5

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
    ("GET", "/media/NOEXISTE.woff2", 404, TIPO_JSON, "404"),
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

# h) Pruebas unitarias (spa/src/app/**/*.spec.ts): sus nombres, tal cual.
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
    "el menú de cada rol solo lleva sus páginas",
    "un instructor que pide /cuentas vuelve a /inicio",
    "un admin abre /cuentas, y la cuenta se pide una sola vez",
    "una página sin roles no se abre para nadie",
    "si /yo falla por la red, lleva a /no-disponible y recuerda la página",
    "con un 401 no deja pasar ni lleva a otra página (lo hace el interceptor)",
    "la situación: activa, sin activar o desactivada",
    "los avisos: invitación abierta y entrada desde navegadores nuevos",
    "el enlace de activación lleva el token en el fragmento",
    "429 con una espera de más de una hora la da en horas, redondeando hacia arriba",
    "un id que no es un uuid no llega a ninguna petición",
    "sin mensaje, el cambio de estado no envía el campo",
    "los cambios de estado que se ofrecen son los de la API, sin no veraz",
    "los estados cerrados, que exigen mensaje final y no admiten más mensajes",
    "el instructor no puede declarar no veraz; el admin sí",
    "las fechas de la API se leen como día, sin pasar por Date",
    "el aviso de lecturas sale a partir de 20",
    "el autor de un mensaje: denunciante, usted u otra persona del personal",
    "la categoría con su nombre, o tal cual si no se conoce",
    "la ruta de una denuncia solo casa con un uuid",
    "cada acción de la API tiene nombre, y una desconocida se enseña tal cual",
    "quién actúa: su email, plataforma, sistema o el id si la cuenta no se resuelve",
    "sobre qué: la cuenta por su email, la denuncia por su id y la asignación con las dos",
    "la verificación: intacta, o la fila donde se rompe",
    "la primera página va sin antes, las anteriores con él",
)
ORDEN_PRUEBAS = "npx ng test --watch=false --reporters=verbose"
# Mutantes del interceptor, del guard, del cliente de denuncias y de los
# permisos del expediente: (qué quita, fichero, texto original, texto mutado,
# la prueba que debe fallar).
MUTANTES_UNITARIOS = (
    ("sin la marca RENOVABLE", "src/app/nucleo/renovacion.ts",
     "  if (!peticion.context.get(RENOVABLE)) {", "  if (false) {",
     "un login fallido no renueva, aunque su 401 traiga WWW-Authenticate: Bearer"),
    ("sin la renovacion compartida", "src/app/nucleo/renovacion.ts",
     "    this.enCurso ??= this.cerrojo(", "    this.enCurso = this.cerrojo(",
     "dos peticiones con 401 a la vez comparten una sola renovación"),
    ("sin la comprobacion del rol", "src/app/nucleo/permisos.ts",
     "  if (!roles.includes(yo.rol)) {", "  if (false) {",
     "un instructor que pide /cuentas vuelve a /inicio"),
    ("sin la comprobacion del uuid en el cliente de denuncias", "src/app/nucleo/api-denuncias.ts",
     "  if (!esIdDenuncia(id)) {", "  if (false) {",
     "un id que no es un uuid no llega a ninguna petición"),
    ("no veraz tambien para el instructor", "src/app/denuncias/textos.ts",
     "  return rol === 'admin';", "  return true;",
     "el instructor no puede declarar no veraz; el admin sí"),
    ("un hueco en vez del id de quien actua", "src/app/auditoria/textos.ts",
     "    return fila.actor_email ?? fila.actor.slice(PREFIJO_PERSONAL.length);", "    return fila.actor_email ?? '';",
     "quién actúa: su email, plataforma, sistema o el id si la cuenta no se resuelve"),
    ("un hueco en vez del id de la cuenta afectada", "src/app/auditoria/textos.ts",
     "      return fila.cuenta_email ?? `Cuenta ${objeto}`;", "      return fila.cuenta_email ?? '';",
     "sobre qué: la cuenta por su email, la denuncia por su id y la asignación con las dos"),
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

# k) La base visual. Las parejas que usa spa/src/styles.css, por el nombre de
# sus variables: (primer plano, fondo, contraste mínimo). 4,5:1 para el texto
# (WCAG 2.2, 1.4.3) y 3:1 para bordes de controles y foco (1.4.11). El
# separador de las tablas no está: es decoración, la tabla se entiende sin él.
# Se comprueban en los dos temas: el claro (el :root de fuera) y el oscuro (el
# :root de @media (prefers-color-scheme: dark), sobre el claro).
ESTILOS_SPA = RAIZ / "spa" / "src" / "styles.css"
PAREJAS_CONTRASTE = (
    ("--color-texto", "--color-fondo", 4.5),
    ("--color-texto", "--color-superficie", 4.5),
    ("--color-texto", "--color-aviso-fondo", 4.5),
    ("--color-texto-suave", "--color-fondo", 4.5),
    ("--color-texto-suave", "--color-superficie", 4.5),
    ("--color-acento", "--color-fondo", 4.5),
    ("--color-acento", "--color-superficie", 4.5),
    ("--color-boton-texto", "--color-boton", 4.5),
    ("--color-peligro-texto", "--color-peligro", 4.5),
    ("--color-error-texto", "--color-error-fondo", 4.5),
    ("--color-etiqueta-texto", "--color-etiqueta-fondo", 4.5),
    ("--color-borde", "--color-fondo", 3.0),
    ("--color-acento", "--color-aviso-fondo", 3.0),
    ("--color-peligro", "--color-error-fondo", 3.0),
)
# Mutantes de la hoja para los controles de k).
MUTANTE_GRIS = ("--color-texto-suave: #4a4a4a;", "--color-texto-suave: #8a8a8a;")
# En el oscuro: el gris suave del claro sobre el fondo casi negro, y un color
# que se le olvida (heredaría el del claro).
MUTANTE_GRIS_OSCURO = ("    --color-texto-suave: #a1a1a1;", "    --color-texto-suave: #4a4a4a;")
MUTANTE_OLVIDADO = ("    --color-separador: #2e2e2e;\n", "")
PATRON_TEMA_OSCURO = re.compile(r"@media\s*\(\s*prefers-color-scheme\s*:\s*dark\s*\)\s*\{\s*:root\s*\{(.*?)\}\s*\}",
                                re.DOTALL)
MUTANTE_COLOR_SUELTO = "\n.mutante { color: #000000; }\n"
MUTANTE_VARIABLE = "\n.mutante { color: var(--color-que-no-existe); }\n"
# k) Los botones ocupados (spa/src/app): cuántos llevan aria-disabled en cada
# fichero, contados a mano en el bloque 6b-3d. Ninguno lleva disabled ligado:
# a un botón disabled Chromium le quita el foco y no se lo devuelve
# (docs/threat-model.md, 6.11). Un botón ocupado nuevo se añade aquí.
APP_SPA = RAIZ / "spa" / "src" / "app"
BOTONES_OCUPADOS = {
    "acceso/activacion/activacion.ts": 2,
    "acceso/entrar/entrar.ts": 1,
    "acceso/registro/registro.ts": 1,
    "acceso/verificacion/verificacion.ts": 1,
    "armazon/armazon.ts": 1,
    "auditoria/auditoria.ts": 3,
    "cuenta/cuenta.ts": 1,
    "cuentas/cuentas.ts": 5,
    "denuncias/denuncias.ts": 2,
    "denuncias/expediente.ts": 6,
    "solicitudes/solicitudes.ts": 3,
}
PATRON_DISABLED = re.compile(r"\[(?:attr\.)?disabled\]")
PATRON_ARIA_DISABLED = re.compile(r"\[attr\.aria-disabled\]")
# Mutante de entrar.ts: el botón con disabled, como antes del 6b-3d. Lo usan
# k), sobre el texto, y o), compilado.
FICHERO_ENTRAR = "acceso/entrar/entrar.ts"
MUTANTE_DISABLED = ('[attr.aria-disabled]="enviando() || null"', '[disabled]="enviando()"')

# l) Las pantallas por rol (spa/src/app).
EMAIL_INSTRUCTORA = "instructora@spa.test"
EMAIL_AUDITOR = "auditor@spa.test"
CONTRASENA_NUEVAS = secrets.token_urlsafe(18)
MENU_ADMIN = ["Inicio", "Denuncias", "Cuentas", "Solicitudes", "Auditoría", "Mi cuenta"]
MENU_INSTRUCTOR = ["Inicio", "Denuncias", "Mi cuenta"]
MENU_AUDITOR = ["Inicio", "Auditoría", "Mi cuenta"]
H1_MI_CUENTA = "Mi cuenta"
PATRON_ENLACE = re.compile(r"https://localhost:8445/activacion#[0-9a-f]{32}\.[A-Za-z0-9_-]{43}")
TEXTO_SIN_ROL = f"Elija el rol de {EMAIL_REGISTRO} antes de aprobar."
TEXTO_APROBADA = f"Aprobada: {EMAIL_REGISTRO} recibirá un correo para activar su cuenta como Auditor."
TEXTO_SIN_SOLICITUDES = "No hay solicitudes pendientes."
FOCO_ENLACE = f"Enlace de activación para {EMAIL_INSTRUCTORA}"
TEXTO_DUPLICADA = "Ya existe una cuenta con ese email."
AVISO_INVITACION = ("Hay una invitación abierta para su cuenta. Si no la ha pedido usted, avise a un admin de su "
                    "empresa para que la anule.")
TEXTO_ANULADA = f"Se ha anulado la invitación de {EMAIL_INSTRUCTORA}."
TEXTO_BAJA = f"{EMAIL_AUDITOR} está de baja: sus sesiones se han cerrado. Se puede reactivar con una invitación."
TEXTO_CONTRASENA_MAL = "La contraseña actual o el código no son correctos."
TEXTO_CONTRASENA_CAMBIADA = ("Contraseña cambiada. Se han cerrado sus otras sesiones y retirado los demás "
                             "dispositivos de confianza.")
ASUNTO_INVITACION = "Active su cuenta del personal en Canario"
PATRON_ENLACE_CORREO = re.compile(r"https://localhost:8445/activacion#([0-9a-f]{32}\.[A-Za-z0-9_-]{43})")
# Lo que delata una violación de la CSP o de Trusted Types en la consola de
# Chromium.
SENALES_CSP = ("Content Security Policy", "TrustedHTML", "TrustedScript", "Trusted Type")

# m) Las denuncias (spa/src/app/denuncias).
EMAIL_INSTRUCTOR_M = "instructor.m@spa.test"
H1_DENUNCIA = "Denuncia"
# Un id que el router decodifica a "../usuarios" (spa/src/app/nucleo/api-denuncias.ts).
RUTA_CSPT = "/denuncias/..%2Fusuarios"
# Lo que escribe un denunciante anónimo. Si algo se ejecutara, pondría
# window.canarioXss; MARCA_CARGA identifica las cargas en la página y en la
# consola.
MARCA_CARGA = "canario-carga-xss"
CARGA_DENUNCIA = ('<img src=x onerror="window.canarioXss=1"><script>window.canarioXss=2</script>'
                  '<svg onload="window.canarioXss=3"></svg> ' + MARCA_CARGA)
# Con U+202E (RIGHT-TO-LEFT OVERRIDE), que dir="auto" aísla (CWE-451).
CARGA_MENSAJE = "\u202e<b>negrita</b> <a href=\"javascript:window.canarioXss=4\">enlace</a> " + MARCA_CARGA
TEXTO_PERSONAL = "Gracias por su denuncia: la estamos revisando."
TEXTO_FINAL = "Hemos resuelto la denuncia y aplicado las medidas oportunas."
TEXTO_MENSAJE_ENVIADO = "Mensaje enviado."
TEXTO_EN_INSTRUCCION = "Estado cambiado a En instrucción."
TEXTO_CIERRE = "Estado cambiado a Resuelta. El mensaje final se ha enviado y saldrá numerado al volver a leer."
CABECERA_PENDIENTE = "Mensaje final · Usted · saldrá numerado al volver a leer"
FOCO_EXPEDIENTE = "Expediente"
FOCO_NO_VERAZ = "Confirmar: declarar no veraz"
# El control del XSS: el texto de la denuncia con [innerHTML] en vez de
# interpolación (spa/src/app/denuncias/contenido.ts). El sanitizador de
# Angular quita onerror, el <script> y el <svg>, pero deja el <img>.
MUTANTE_XSS = ('<p class="texto-libre" dir="auto" id="expediente-texto">{{ expediente().texto }}</p>',
               '<p class="texto-libre" dir="auto" id="expediente-texto" [innerHTML]="expediente().texto"></p>')

# n) La auditoría (spa/src/app/auditoria).
EMAIL_AUDITOR_N = "auditor.n@spa.test"
EMAIL_INSTRUCTOR_N = "instructor.n@spa.test"
EMAIL_OTRA_N = "otra.n@spa.test"
H1_AUDITORIA = "Auditoría"
# app/instruccion.py, TAMANO_PAGINA_AUDITORIA. La auditoría de la prueba se
# lleva por encima con lecturas, para que haya una segunda página.
TAMANO_PAGINA_AUDITORIA = 200
FILAS_AUDITORIA_N = TAMANO_PAGINA_AUDITORIA + 10
# Un email que validar_email admite (ASCII imprimible sin espacios) y que es
# HTML: sin espacios, "/" separa los atributos. Si se interpretara, pondría
# window.canarioxss (en minúsculas: el email se guarda así).
EMAIL_XSS = '<img/src="x"/onerror="window.canarioxss=5">@spa.test'
TEXTO_CADENA_INTACTA = "La cadena está intacta: ninguna fila se ha cambiado, borrado ni insertado."
TEXTO_PRINCIPIO = "Es el principio de la auditoría."
# Los nombres de las acciones en la pantalla (spa/src/app/auditoria/textos.ts):
# una celda "Qué" fuera de esta lista es una acción que la SPA no traduce.
NOMBRES_ACCION = {
    "Entrada", "Activación de la cuenta", "Cambio de contraseña", "Invitación", "Baja", "Anulación de la invitación",
    "Invitación del primer admin", "Nueva invitación del primer admin", "Aprobación de una solicitud de registro",
    "Rechazo de una solicitud de registro", "Lectura", "Mensaje al denunciante", "Asignación",
    "Cambio de estado a En instrucción", "Cambio de estado a Resuelta", "Cambio de estado a Archivada",
    "Cambio de estado a Inadmitida", "Declaración de no veraz", "Redacción del texto de la denuncia",
    "Redacción de un mensaje", "Supresión a los tres meses sin investigar (art. 32.4)",
    "Supresión a los diez años (art. 26.2)", "Supresión por no veraz (art. 32.3)",
}
PATRON_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
PATRON_DIA = re.compile(r"\d{2}/\d{2}/\d{4}")
# El control del XSS de la auditoría: "sobre qué" con [innerHTML] en vez de
# interpolación (spa/src/app/auditoria/auditoria.ts).
MUTANTE_XSS_AUDITORIA = ('<td class="dato">{{ sobre(fila) }}</td>', '<td class="dato" [innerHTML]="sobre(fila)"></td>')

# o) Los botones ocupados (spa/src/app). Un email sin cuenta: el login falla
# con el mismo 401 y ningún fallo suma al bloqueo de una cuenta de la prueba
# (app/personal.py, FALLOS_ANTES_DE_ESPERAR = 5; i ya gastó uno del admin).
EMAIL_SIN_CUENTA = "nadie.o@spa.test"
# El control del doble clic: entrar() sin su guarda.
MUTANTE_GUARDA = ("    if (this.enviando()) {\n      return;\n    }\n    this.enviando.set(true);",
                  "    this.enviando.set(true);")
# app/instruccion.py, TAMANO_PAGINA_DENUNCIAS. o) crea una página entera más
# por la API pública, para que haya una segunda.
TAMANO_PAGINA_DENUNCIAS = 100
DENUNCIAS_O = TAMANO_PAGINA_DENUNCIAS
TEXTO_FINAL_LISTA = "Es el final de la lista."

# p) La fuente y el tema oscuro. El fondo de la página en cada tema
# (spa/src/styles.css, --color-fondo), como lo da getComputedStyle.
FONDO_CLARO = "rgb(255, 255, 255)"
FONDO_OSCURO = "rgb(10, 10, 10)"
FUENTES_ESPERADAS = [["Geist", "loaded"]]
# Las páginas del admin que se miran a 320 px, además de /entrar.
RUTAS_ANCHO = ["/inicio", "/denuncias", "/cuentas", "/solicitudes", "/auditoria", "/cuenta"]

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

# Parte común de los scripts de l) y m): varias cuentas del personal, cada una
# en su contexto (con sus cookies). Las funciones usan spki, identificador y
# contrasena, que cada script define antes de llamarlas, y usados, donde cada
# script pone el último paso TOTP del admin.
NAVEGADOR_PERSONAL = NAVEGADOR_COMUN + r'''
import re
ENLACE = re.compile(r"https://localhost:8445/activacion#[0-9a-f]{32}\.[A-Za-z0-9_-]{43}")
# El último paso TOTP usado por cada secreto: cada cuenta lleva el suyo, así
# que no hay que esperar al código de otra.
usados = {}


async def codigo_de(secreto):
    while True:
        actual = int(time.time()) // 30
        if actual > usados.get(secreto, -1):
            usados[secreto] = actual
            return totp(secreto, actual)
        await asyncio.sleep(30 - time.time() % 30 + 0.5)


paginas = {}


async def pagina_nueva(navegador, nombre):
    contexto = await navegador.new_context()
    pagina = await contexto.new_page()
    vigilar(pagina, nombre)
    paginas[nombre] = pagina
    return pagina


async def avisos_visibles():
    # Si el recorrido se corta, lo que cada página enseña en role=alert (un
    # 429, un código no válido...): el informe dice qué ha pasado en vez de
    # dejar solo un timeout.
    vistos = {}
    for nombre, pagina in paginas.items():
        try:
            vistos[nombre] = await pagina.get_by_role("alert").all_inner_texts()
        except Exception as e:
            vistos[nombre] = [f"no se pudo leer: {type(e).__name__}"]
    return vistos


async def h1(pagina):
    await pagina.locator("main h1").wait_for()
    return await pagina.inner_text("main h1")


async def abrir(pagina, ruta_pedida):
    # Carga directa, como un enlace o la barra de direcciones; espera a que
    # el guard decida y la página se pinte.
    await pagina.goto(ORIGEN + ruta_pedida)
    titulo = await h1(pagina)
    await pagina.wait_for_load_state("networkidle")
    return {"ruta": ruta(pagina.url), "h1": titulo}


async def entrar(pagina, email, clave, secreto):
    await pagina.goto(ORIGEN + "/entrar")
    await pagina.get_by_label("Empresa").fill(identificador)
    await pagina.get_by_label("Email").fill(email)
    await pagina.get_by_label("Contraseña", exact=True).fill(clave)
    await pagina.get_by_label(CODIGO).fill(await codigo_de(secreto))
    await pagina.get_by_role("button", name="Entrar", exact=True).click()
    await pagina.wait_for_url(ORIGEN + "/inicio")
    await pagina.locator(".cuenta dd").first.wait_for()


async def menu(pagina):
    return await pagina.get_by_role("navigation", name="Principal").get_by_role("link").all_inner_texts()


async def ir_por_menu(pagina, texto):
    await pagina.get_by_role("navigation", name="Principal").get_by_role("link", name=texto, exact=True).click()
    return await h1(pagina)


async def activar(pagina, enlace):
    await pagina.goto(enlace)
    await pagina.get_by_label("Contraseña nueva").fill(contrasena)
    await pagina.get_by_label("Repita la contraseña").fill(contrasena)
    await pagina.get_by_role("button", name="Continuar", exact=True).click()
    await pagina.get_by_role("heading", name="Paso 2 de 2: configure la aplicación de autenticación").wait_for()
    secreto = (await pagina.locator("#activacion-secreto").inner_text()).replace(" ", "")
    await pagina.get_by_label(CODIGO).fill(await codigo_de(secreto))
    await pagina.get_by_role("button", name="Activar la cuenta", exact=True).click()
    await pagina.get_by_role("heading", name="Cuenta activada").wait_for()
    return secreto


async def estado_api(pagina, ruta_api):
    return await pagina.evaluate("fetch('" + ruta_api + "').then(r => r.status)")


async def html(pagina):
    return await pagina.evaluate("document.documentElement.outerHTML")


async def fila(pagina, email):
    return await pagina.get_by_role("row").filter(has_text=email).inner_text()


async def invitar(pagina, email, rol):
    await pagina.get_by_label("Email").fill(email)
    await pagina.get_by_label("Rol", exact=True).select_option(rol)
    await pagina.get_by_role("button", name="Invitar", exact=True).click()


async def esperar_texto(pagina, selector):
    elemento = pagina.locator(selector)
    await elemento.wait_for()
    return await elemento.inner_text()


async def esperar_otro(pagina, selector, anterior):
    # Un aviso de la acción anterior sigue a la vista hasta que llega el
    # nuevo: se espera a que cambie su texto.
    await pagina.wait_for_function(
        "([s, a]) => { const e = document.querySelector(s); return e !== null && e.textContent.trim() !== a; }",
        arg=[selector, anterior])
    return await pagina.locator(selector).inner_text()


async def ejecutar_personal(pasos):
    async with async_playwright() as pw:
        navegador = await pw.chromium.launch(args=[f"--ignore-certificate-errors-spki-list={spki}"])
        try:
            await pasos(navegador)
        except Exception as e:
            res["excepcion"] = f"{type(e).__name__}: {e}"[:600]
            res["avisos_visibles"] = await avisos_visibles()
        res["consola"], res["errores"] = consola, errores
        await navegador.close()
    print(json.dumps(res, ensure_ascii=False))
'''

# l) Las pantallas por rol, con tres cuentas. Recibe el SPKI, el
# identificador, el email, la contraseña, el secreto TOTP y el último paso
# usado del admin, el email de la solicitud de j), los emails de la
# instructora y del auditor y la contraseña de las dos. Nunca devuelve un
# token ni un secreto: solo si tienen la forma esperada.
NAVEGADOR_ROLES = NAVEGADOR_PERSONAL + r'''
(spki, identificador, email_admin, contrasena_admin, secreto_admin, paso_admin, email_registro,
 email_instructora, email_auditor, contrasena) = sys.argv[1:11]
USUARIOS = "/v1/personal/usuarios"
usados[secreto_admin] = int(paso_admin)


async def pasos_roles(navegador):
    admin = await pagina_nueva(navegador, "admin")
    await entrar(admin, email_admin, contrasena_admin, secreto_admin)
    res["menu_admin"] = await menu(admin)

    # Solicitudes: sin rol no se envía nada; con rol, se aprueba.
    res["h1_solicitudes"] = await ir_por_menu(admin, "Solicitudes")
    marca = len(eventos)
    await admin.get_by_role("button", name="Aprobar a " + email_registro, exact=True).click()
    res["sin_rol"] = await admin.get_by_role("alert").inner_text()
    await asyncio.sleep(1)
    res["sin_rol_api"] = api_desde(marca)
    await admin.get_by_label("Rol para " + email_registro).select_option("auditor")
    marca = len(eventos)
    await admin.get_by_role("button", name="Aprobar a " + email_registro, exact=True).click()
    res["aprobada"] = await esperar_texto(admin, "#solicitudes-hecho")
    await admin.get_by_text("No hay solicitudes pendientes.").wait_for()
    res["aprobada_api"] = api_desde(marca)
    res["aprobada_token"] = "/activacion#" in await html(admin)

    # Cuentas: dos invitaciones con su enlace a la vista.
    res["h1_cuentas"] = await ir_por_menu(admin, "Cuentas")
    await invitar(admin, email_instructora, "instructor")
    enlace_instructora = await esperar_texto(admin, "#cuentas-enlace")
    res["foco_enlace"] = await foco(admin)
    res["enlace_instructora"] = bool(ENLACE.fullmatch(enlace_instructora))
    res["enlaces_a"] = await admin.locator("a[href*='activacion']").count()
    res["ruta_con_enlace"] = ruta(admin.url) + ("#" if "#" in admin.url else "")
    res["almacen_admin"] = await almacenamiento(admin)
    await invitar(admin, email_auditor, "auditor")
    await admin.get_by_role("heading", name="Enlace de activación para " + email_auditor).wait_for()
    enlace_auditor = await admin.locator("#cuentas-enlace").inner_text()
    res["enlace_auditor"] = bool(ENLACE.fullmatch(enlace_auditor))
    token = enlace_auditor.split("#", 1)[-1]
    res["token_antes_de_salir"] = token in await html(admin)
    await ir_por_menu(admin, "Inicio")
    await ir_por_menu(admin, "Cuentas")
    await admin.get_by_role("row").filter(has_text=email_auditor).wait_for()
    res["token_tras_salir"] = token in await html(admin)
    await invitar(admin, email_instructora, "instructor")
    res["duplicada"] = await admin.get_by_role("alert").inner_text()
    res["usuarios_admin"] = await estado_api(admin, USUARIOS)

    # Instructora: activa la cuenta con su enlace y entra.
    instructora = await pagina_nueva(navegador, "instructora")
    secreto_instructora = await activar(instructora, enlace_instructora)
    await entrar(instructora, email_instructora, contrasena, secreto_instructora)
    res["menu_instructora"] = await menu(instructora)
    res["instructora_cuentas"] = await abrir(instructora, "/cuentas")
    res["instructora_solicitudes"] = await abrir(instructora, "/solicitudes")
    res["instructora_cuenta"] = await abrir(instructora, "/cuenta")
    res["usuarios_instructora"] = await estado_api(instructora, USUARIOS)

    # Auditor: igual.
    auditor = await pagina_nueva(navegador, "auditor")
    secreto_auditor = await activar(auditor, enlace_auditor)
    await entrar(auditor, email_auditor, contrasena, secreto_auditor)
    res["menu_auditor"] = await menu(auditor)
    res["auditor_cuentas"] = await abrir(auditor, "/cuentas")
    res["auditor_inicio_antes"] = await abrir(auditor, "/inicio")

    # Admin: reinvitar, anular y dar de baja.
    await abrir(admin, "/cuentas")
    res["fila_instructora"] = await fila(admin, email_instructora)
    res["baja_propia"] = await admin.get_by_role("button", name="Dar de baja a " + email_admin, exact=True).count()
    res["baja_otra"] = await admin.get_by_role("button", name="Dar de baja a " + email_auditor, exact=True).count()
    await admin.get_by_role("button", name="Reinvitar a " + email_instructora, exact=True).click()
    res["reinvitada_enlace"] = bool(ENLACE.fullmatch(await esperar_texto(admin, "#cuentas-enlace")))
    await admin.get_by_role("button", name="Anular la invitación de " + email_instructora, exact=True).wait_for()
    res["fila_reinvitada"] = await fila(admin, email_instructora)
    await abrir(instructora, "/inicio")
    res["aviso_instructora"] = [t for t in await instructora.get_by_role("alert").all_inner_texts()]
    await admin.get_by_role("button", name="Anular la invitación de " + email_instructora, exact=True).click()
    res["anulada"] = await esperar_texto(admin, "#cuentas-hecho")
    await admin.get_by_role("button", name="Anular la invitación de " + email_instructora, exact=True).wait_for(
        state="detached")
    res["fila_anulada"] = await fila(admin, email_instructora)
    await admin.get_by_role("button", name="Dar de baja a " + email_auditor, exact=True).click()
    # Leer el foco justo después del clic mide el DOM viejo: el botón pulsado
    # sigue ahí y tiene el foco. Angular repinta y ejecuta afterNextRender
    # (que mueve el foco) en la misma tarea (ApplicationRef, synchronizeOnce),
    # así que cuando el botón ha desaparecido el foco ya está donde lo dejó la
    # página.
    await admin.get_by_role("button", name="Dar de baja a " + email_auditor, exact=True).wait_for(state="detached")
    res["foco_confirmar"] = await foco(admin)
    await admin.get_by_role("button", name="Confirmar la baja", exact=True).click()
    # El aviso de la anulación sigue a la vista hasta que la baja lo cambia.
    await admin.wait_for_function(
        "([s, a]) => { const e = document.querySelector(s); return e !== null && e.textContent.trim() !== a; }",
        arg=["#cuentas-hecho", res["anulada"]])
    res["baja"] = await esperar_texto(admin, "#cuentas-hecho")
    await admin.get_by_role("button", name="Dar de baja a " + email_auditor, exact=True).wait_for(state="detached")
    res["fila_baja"] = await fila(admin, email_auditor)
    res["auditor_inicio_despues"] = await abrir(auditor, "/inicio")

    # Instructora: cambiar la contraseña, primero con la actual mal.
    await ir_por_menu(instructora, "Mi cuenta")
    await instructora.get_by_label("Contraseña actual").fill(contrasena + "-mal")
    await instructora.get_by_label("Contraseña nueva", exact=True).fill(contrasena + "-2")
    await instructora.get_by_label("Repita la contraseña nueva").fill(contrasena + "-2")
    await instructora.get_by_label(CODIGO).fill("000000")
    marca = len(eventos)
    await instructora.get_by_role("button", name="Cambiar la contraseña", exact=True).click()
    res["contrasena_mal"] = await instructora.get_by_role("alert").inner_text()
    await asyncio.sleep(1)
    res["contrasena_mal_api"] = api_desde(marca)
    await instructora.get_by_label("Contraseña actual").fill(contrasena)
    await instructora.get_by_label(CODIGO).fill(await codigo_de(secreto_instructora))
    await instructora.get_by_role("button", name="Cambiar la contraseña", exact=True).click()
    res["contrasena_cambiada"] = await esperar_texto(instructora, "#cuenta-hecho")
    res["yo_tras_cambio"] = await estado_api(instructora, "/v1/personal/yo")

    # Control de la consola: una conexión a otro origen sí deja su violación.
    res["consola_antes_del_control"] = len(consola)
    await admin.evaluate("fetch('https://ejemplo.invalid/').catch(() => null)")
    await asyncio.sleep(1)
    res["ultimo_paso_admin"] = usados[secreto_admin]


asyncio.run(ejecutar_personal(pasos_roles))
'''

# m) Las denuncias. Recibe el SPKI, el identificador, el email, la
# contraseña, el secreto TOTP y el último paso usado del admin, el email y la
# contraseña de un instructor nuevo y el nombre del main-*.js servido. Lee de
# /prueba/datos.json los ids de las dos denuncias, las cargas y sus textos (en
# un fichero y no en la línea de órdenes: llevan U+202E y comillas), y de
# /prueba/mutante.js el main-*.js del mutante con [innerHTML].
NAVEGADOR_DENUNCIAS = NAVEGADOR_PERSONAL + r'''
(spki, identificador, email_admin, contrasena_admin, secreto_admin, paso_admin, email_instructor, contrasena,
 principal) = sys.argv[1:10]
with open("/prueba/datos.json", encoding="utf-8") as fichero:
    datos = json.load(fichero)
D1, D2, MARCA = datos["d1"], datos["d2"], datos["marca"]
with open("/prueba/mutante.js", "rb") as fichero:
    MUTANTE = fichero.read()
usados[secreto_admin] = int(paso_admin)
RUTA_D1 = "/v1/personal/denuncias/" + D1
TEXTOS_LIBRES = """() => {
  const bloques = [...document.querySelectorAll('main .texto-libre')];
  return {
    textos: bloques.map((b) => b.textContent),
    hijos: bloques.reduce((n, b) => n + b.childElementCount, 0),
    dir: bloques.map((b) => b.getAttribute('dir')),
    peligrosos: document.querySelectorAll('main img, main script, main svg, main iframe, main a[href^="javascript"]').length,
    bandera: typeof window.canarioXss,
  };
}"""


def lecturas_d1(marca):
    return len([e for e in eventos[marca:] if e["tipo"] == "peticion" and e["metodo"] == "GET" and e["ruta"] == RUTA_D1])


async def auditadas(pagina, denuncia_id):
    # Filas lectura_denuncia de la auditoría sobre una denuncia, leídas por la
    # API como admin (la auditoría tiene una sola página en esta prueba).
    return await pagina.evaluate("""async (d) => {
      const r = await fetch('/v1/personal/auditoria');
      const j = await r.json();
      return j.filas.filter((f) => f.accion === 'lectura_denuncia' && f.objeto_id === d).length;
    }""", denuncia_id)


async def abrir_expediente(pagina):
    await pagina.get_by_role("button", name="Abrir el expediente", exact=True).click()
    await pagina.locator("#expediente-texto").wait_for()


async def enlaces_a(pagina, denuncia):
    return await pagina.get_by_role("link", name="Ir a la denuncia " + denuncia, exact=True).count()


async def pasos_denuncias(navegador):
    admin = await pagina_nueva(navegador, "admin")
    await entrar(admin, email_admin, contrasena_admin, secreto_admin)
    res["menu_admin"] = await menu(admin)

    # Un instructor propio de m: l no devuelve el secreto TOTP de los suyos.
    await ir_por_menu(admin, "Cuentas")
    await invitar(admin, email_instructor, "instructor")
    enlace = await esperar_texto(admin, "#cuentas-enlace")
    instructor = await pagina_nueva(navegador, "instructor")
    secreto_instructor = await activar(instructor, enlace)
    await entrar(instructor, email_instructor, contrasena, secreto_instructor)
    res["menu_instructor"] = await menu(instructor)

    # Admin: el listado entero; sin enlace a las que no tiene asignadas.
    res["h1_listado"] = await ir_por_menu(admin, "Denuncias")
    await admin.get_by_role("row").filter(has_text=D2).wait_for()
    res["filas_admin"] = sorted(await admin.locator("tbody th[scope=row]").all_inner_texts())
    res["enlaces_admin_antes"] = [await enlaces_a(admin, D1), await enlaces_a(admin, D2)]
    await admin.get_by_label("Asignar la denuncia " + D1 + " a", exact=True).select_option(label=email_instructor)
    marca = len(eventos)
    await admin.get_by_role("button", name="Asignar la denuncia " + D1, exact=True).click()
    res["asignada_d1"] = await esperar_texto(admin, "#denuncias-hecho")
    await admin.get_by_role("row").filter(has_text=D1).filter(has_text=email_instructor).wait_for()
    res["asignar_api"] = api_desde(marca)
    res["fila_d1_admin"] = await fila(admin, D1)
    await admin.get_by_label("Asignar la denuncia " + D2 + " a", exact=True).select_option(label=email_admin)
    await admin.get_by_role("button", name="Asignar la denuncia " + D2, exact=True).click()
    res["asignada_d2"] = await esperar_otro(admin, "#denuncias-hecho", res["asignada_d1"])
    await admin.get_by_role("link", name="Ir a la denuncia " + D2, exact=True).wait_for()
    res["enlaces_admin_despues"] = [await enlaces_a(admin, D1), await enlaces_a(admin, D2)]

    # Instructor: solo la suya.
    res["h1_listado_instructor"] = await ir_por_menu(instructor, "Denuncias")
    await instructor.get_by_role("link", name="Ir a la denuncia " + D1, exact=True).wait_for()
    res["filas_instructor"] = await instructor.locator("tbody th[scope=row]").all_inner_texts()

    # Un id que no es un uuid: "no encontrada" sin pedir nada a la API
    # (control: con el uuid, la página de la denuncia).
    marca = len(eventos)
    res["cspt"] = await abrir(instructor, "/denuncias/..%2Fusuarios")
    res["cspt_api"] = [e for e in api_desde(marca)
                       if e["ruta"].startswith(("/v1/personal/usuarios", "/v1/personal/denuncias"))]

    # Carga directa: la página no lee nada (control: el botón, una lectura y
    # una fila de auditoría).
    marca = len(eventos)
    res["directa"] = await abrir(instructor, "/denuncias/" + D1)
    res["directa_boton"] = await instructor.get_by_role("button", name="Abrir el expediente", exact=True).count()
    res["directa_lecturas"] = lecturas_d1(marca)
    res["auditadas_antes"] = await auditadas(admin, D1)
    marca_abrir = len(eventos)
    await abrir_expediente(instructor)
    res["foco_abrir"] = await foco(instructor)
    res["abrir_lecturas"] = lecturas_d1(marca_abrir)
    res["auditadas_despues"] = await auditadas(admin, D1)

    # Las cargas salen como texto.
    res["xss"] = await instructor.evaluate(TEXTOS_LIBRES)
    res["almacen_instructor"] = await almacenamiento(instructor)
    res["no_veraz_instructor"] = await instructor.get_by_role("button", name="Declarar no veraz", exact=True).count()

    # Un mensaje: se añade sin volver a leer.
    await instructor.get_by_label("Mensaje para el denunciante", exact=True).fill(datos["texto_personal"])
    marca = len(eventos)
    await instructor.get_by_role("button", name="Enviar el mensaje", exact=True).click()
    res["mensaje_hecho"] = await esperar_texto(instructor, "#expediente-hecho")
    await asyncio.sleep(1)
    res["mensaje_api"] = api_desde(marca)
    res["mensajes_vistos"] = await instructor.locator(".mensajes > li").all_inner_texts()

    # Estados: en instrucción, y cerrar sin mensaje final (no envía nada) y
    # con él.
    await instructor.get_by_label("Estado nuevo", exact=True).select_option("en_instruccion")
    marca = len(eventos)
    await instructor.get_by_role("button", name="Cambiar el estado", exact=True).click()
    res["estado_1"] = await esperar_otro(instructor, "#expediente-hecho", res["mensaje_hecho"])
    await asyncio.sleep(1)
    res["estado_1_api"] = api_desde(marca)
    res["estado_visto_1"] = await instructor.inner_text("#expediente-estado")
    await instructor.get_by_label("Estado nuevo", exact=True).select_option("resuelta")
    await instructor.get_by_label("Mensaje final para el denunciante", exact=True).wait_for()
    marca = len(eventos)
    await instructor.get_by_role("button", name="Cambiar el estado", exact=True).click()
    await asyncio.sleep(1)
    res["cierre_sin_mensaje_api"] = api_desde(marca)
    res["cierre_sin_mensaje_falta"] = await instructor.locator("#expediente-final").evaluate("e => e.validity.valueMissing")
    await instructor.get_by_label("Mensaje final para el denunciante", exact=True).fill(datos["texto_final"])
    marca = len(eventos)
    await instructor.get_by_role("button", name="Cambiar el estado", exact=True).click()
    res["cierre"] = await esperar_otro(instructor, "#expediente-hecho", res["estado_1"])
    await asyncio.sleep(1)
    res["cierre_api"] = api_desde(marca)
    res["estado_visto_2"] = await instructor.inner_text("#expediente-estado")
    res["mensajes_tras_cierre"] = await instructor.locator(".mensajes > li").all_inner_texts()
    res["formularios_tras_cierre"] = await instructor.locator("main textarea, #expediente-destino").count()
    res["lecturas_tras_acciones"] = lecturas_d1(marca_abrir)

    # Admin: la suya se abre, tiene "no veraz" y pide confirmación.
    await ir_por_menu(admin, "Denuncias")
    await admin.get_by_role("link", name="Ir a la denuncia " + D2, exact=True).click()
    await admin.get_by_role("button", name="Abrir el expediente", exact=True).wait_for()
    await abrir_expediente(admin)
    res["no_veraz_admin"] = await admin.get_by_role("button", name="Declarar no veraz", exact=True).count()
    await admin.get_by_role("button", name="Declarar no veraz", exact=True).click()
    await admin.get_by_role("button", name="Declarar no veraz", exact=True).wait_for(state="detached")
    res["foco_no_veraz"] = await foco(admin)
    marca = len(eventos)
    await admin.get_by_role("button", name="Confirmar: declarar no veraz", exact=True).click()
    res["no_veraz_hecho"] = await esperar_texto(admin, "#expediente-hecho")
    res["no_veraz_api"] = api_desde(marca)
    await ir_por_menu(admin, "Denuncias")
    await admin.get_by_role("row").filter(has_text=D1).wait_for()
    res["filas_admin_final"] = await admin.locator("tbody th[scope=row]").all_inner_texts()

    # Lo que sigue deja mensajes en la consola a propósito: el mutante (el
    # aviso del sanitizador y la violación de la CSP de su <img>) y el control
    # de la CSP. La comprobación de la consola mira solo hasta aquí.
    res["consola_antes_del_control"] = len(consola)

    # Control de la prueba del XSS: el mismo expediente con el main-*.js del
    # mutante ([innerHTML]). Solo se sustituye el script: la página
    # (index.html) llega de Caddy sin tocar, y la CSP y Trusted Types se
    # aplican con las cabeceras de la página, no con las del script. Sin
    # route.fetch: esa petición la hace Playwright fuera de Chromium, sin el
    # SPKI de la CA de Caddy, y el TLS falla (la primera versión de esta
    # prueba se quedaba colgada así).
    async def servir_mutante(peticion_ruta):
        await peticion_ruta.fulfill(status=200, content_type="text/javascript; charset=utf-8", body=MUTANTE)

    await instructor.context.route(ORIGEN + "/" + principal, servir_mutante)
    await abrir(instructor, "/denuncias/" + D1)
    await abrir_expediente(instructor)
    res["mutante"] = await instructor.evaluate(
        "() => { const t = document.querySelector('#expediente-texto'); "
        "return {img: t.querySelectorAll('img').length, hijos: t.childElementCount}; }")
    await asyncio.sleep(1)
    await instructor.context.unroute(ORIGEN + "/" + principal)
    # Que la CSP seguía puesta con el mutante: bloquea la carga de su <img>.
    # El texto es el que escribe Chromium (Playwright 1.63.0), visto en su
    # consola.
    res["mutante_csp"] = [m for m in consola[res["consola_antes_del_control"]:]
                          if "Loading the image" in m and "violates the following Content Security Policy directive" in m]

    # "Atrás" tras cerrar la sesión: no vuelve el expediente (control: antes
    # de cerrarla estaba en la página).
    await abrir(instructor, "/denuncias")
    await instructor.get_by_role("link", name="Ir a la denuncia " + D1, exact=True).click()
    await instructor.get_by_role("button", name="Abrir el expediente", exact=True).wait_for()
    await abrir_expediente(instructor)
    res["atras_antes"] = MARCA in await html(instructor)
    await instructor.get_by_role("button", name="Cerrar la sesión", exact=True).click()
    await instructor.wait_for_url(ORIGEN + "/entrar")
    # Las rutas por las que pasa la pestaña: "atrás" tiene que llevar de
    # verdad a /denuncias, o la prueba no demostraría nada.
    visitadas = []
    instructor.on("framenavigated", lambda marco: visitadas.append(ruta(marco.url)) if marco.parent_frame is None else None)
    await instructor.go_back()
    # Una función y no una expresión: Playwright evalúa las expresiones con
    # eval en la página, y la CSP sin 'unsafe-eval' lo bloquea (EvalError).
    await instructor.wait_for_function("() => location.pathname === '/entrar'")
    res["atras_visitadas"] = visitadas
    res["atras_h1"] = await h1(instructor)
    await instructor.wait_for_load_state("networkidle")
    res["atras_ruta"] = ruta(instructor.url)
    res["atras_marca"] = MARCA in await html(instructor)

    # Control de la consola: una conexión a otro origen sí deja su violación.
    await admin.evaluate("fetch('https://ejemplo.invalid/').catch(() => null)")
    await asyncio.sleep(1)
    # Para n), que vuelve a entrar como admin: un código TOTP vale una vez.
    res["ultimo_paso_admin"] = usados[secreto_admin]


asyncio.run(ejecutar_personal(pasos_denuncias))
'''

# n) La auditoría. Recibe el SPKI, el identificador, el email, la contraseña,
# el secreto TOTP y el último paso usado del admin, los emails de un auditor,
# un instructor y una tercera cuenta nuevos, su contraseña y el nombre del
# main-*.js servido. Lee de /prueba/mutante.js el main-*.js del mutante con
# [innerHTML]. Las filas de la tabla salen como texto: [nº, día, quién, qué,
# sobre qué].
NAVEGADOR_AUDITORIA = NAVEGADOR_PERSONAL + r'''
(spki, identificador, email_admin, contrasena_admin, secreto_admin, paso_admin, email_auditor, email_instructor,
 email_otra, contrasena, principal) = sys.argv[1:12]
with open("/prueba/mutante.js", "rb") as fichero:
    MUTANTE = fichero.read()
usados[secreto_admin] = int(paso_admin)
RECIENTES = "/v1/personal/auditoria/recientes"
FILAS = "() => [...document.querySelectorAll('main tbody tr')].map((tr) => [...tr.children].map((c) => c.textContent.trim()))"
EMAIL_COMO_TEXTO = """() => {
  const datos = [...document.querySelectorAll('main tbody td.dato')];
  return {
    celdas: datos.map((c) => c.textContent).filter((t) => t.includes('onerror')),
    hijos: datos.reduce((n, c) => n + c.childElementCount, 0),
    peligrosos: document.querySelectorAll('main img, main script, main svg, main iframe').length,
    bandera: typeof window.canarioxss,
  };
}"""


async def tabla(pagina):
    await pagina.locator("main tbody tr").first.wait_for()
    return await pagina.evaluate(FILAS)


async def pasos_auditoria(navegador):
    admin = await pagina_nueva(navegador, "admin")
    await entrar(admin, email_admin, contrasena_admin, secreto_admin)
    res["menu_admin"] = await menu(admin)

    # Un auditor y un instructor nuevos: el auditor de l está de baja.
    await ir_por_menu(admin, "Cuentas")
    await invitar(admin, email_auditor, "auditor")
    enlace_auditor = await esperar_texto(admin, "#cuentas-enlace")
    await invitar(admin, email_instructor, "instructor")
    await admin.get_by_role("heading", name="Enlace de activación para " + email_instructor).wait_for()
    enlace_instructor = await admin.locator("#cuentas-enlace").inner_text()
    auditor = await pagina_nueva(navegador, "auditor")
    await entrar(auditor, email_auditor, contrasena, await activar(auditor, enlace_auditor))
    res["menu_auditor"] = await menu(auditor)
    instructor = await pagina_nueva(navegador, "instructor")
    await entrar(instructor, email_instructor, contrasena, await activar(instructor, enlace_instructor))
    res["menu_instructor"] = await menu(instructor)

    # Por su URL: el instructor vuelve a /inicio y la API le da 403 (control:
    # el auditor la abre y la API le da 200).
    res["instructor_url"] = await abrir(instructor, "/auditoria")
    res["api_instructor"] = await estado_api(instructor, RECIENTES)
    res["auditor_url"] = await abrir(auditor, "/auditoria")
    res["api_auditor"] = await estado_api(auditor, RECIENTES)

    # Desde el menú: la primera página y, después, todas las anteriores.
    await abrir(auditor, "/inicio")
    res["h1_auditoria"] = await ir_por_menu(auditor, "Auditoría")
    res["pagina_1"] = await tabla(auditor)
    res["boton_anteriores"] = await auditor.get_by_role("button", name="Cargar anteriores", exact=True).count()
    hecho, clics = None, 0
    while clics < 5 and await auditor.get_by_role("button", name="Cargar anteriores", exact=True).count() == 1:
        await auditor.get_by_role("button", name="Cargar anteriores", exact=True).click()
        hecho = (await esperar_texto(auditor, "#auditoria-hecho") if hecho is None
                 else await esperar_otro(auditor, "#auditoria-hecho", hecho))
        clics += 1
    res["hecho_anteriores"], res["clics"] = hecho, clics
    try:
        # Una función y no una expresión: la CSP sin 'unsafe-eval' bloquea eval.
        await auditor.wait_for_function(
            "() => document.activeElement !== null && document.activeElement.id === 'auditoria-hecho'", timeout=5000)
    except Exception:
        pass
    res["foco_final"] = await foco(auditor)
    res["todas"] = await auditor.evaluate(FILAS)
    res["enlaces_tabla"] = await auditor.locator("main table a").count()
    res["email_como_texto"] = await auditor.evaluate(EMAIL_COMO_TEXTO)
    res["almacen_auditor"] = await almacenamiento(auditor)

    # Actualizar: una fila nueva del admin llega arriba, y el foco sigue en el botón.
    await ir_por_menu(admin, "Cuentas")
    await invitar(admin, email_otra, "instructor")
    await admin.get_by_role("heading", name="Enlace de activación para " + email_otra).wait_for()
    await auditor.get_by_role("button", name="Actualizar", exact=True).click()
    res["actualizada"] = await esperar_otro(auditor, "#auditoria-hecho", hecho or "")
    res["foco_actualizar"] = await foco(auditor)
    res["tras_actualizar"] = await auditor.evaluate(FILAS)

    # Verificar la cadena.
    await auditor.get_by_role("button", name="Verificar la cadena", exact=True).click()
    res["cadena"] = await auditor.get_by_role("status").filter(has_text="La cadena").inner_text()

    # El admin la ve igual, con su última acción arriba.
    res["h1_admin"] = await ir_por_menu(admin, "Auditoría")
    res["admin_primera"] = (await tabla(admin))[:1]
    res["ultimo_paso_admin"] = usados[secreto_admin]

    # Lo que sigue deja mensajes en la consola a propósito: el mutante y el
    # control de la CSP. La comprobación de la consola mira solo hasta aquí.
    res["consola_antes_del_control"] = len(consola)

    # Control del email como texto: la misma página con el main-*.js del
    # mutante ([innerHTML] en "sobre qué"), como en m).
    async def servir_mutante(peticion_ruta):
        await peticion_ruta.fulfill(status=200, content_type="text/javascript; charset=utf-8", body=MUTANTE)

    await auditor.context.route(ORIGEN + "/" + principal, servir_mutante)
    await abrir(auditor, "/auditoria")
    await auditor.locator("main tbody tr").first.wait_for()
    res["mutante"] = await auditor.evaluate("() => document.querySelectorAll('main tbody img').length")
    await asyncio.sleep(1)
    await auditor.context.unroute(ORIGEN + "/" + principal)
    res["mutante_csp"] = [m for m in consola[res["consola_antes_del_control"]:]
                          if "Loading the image" in m and "violates the following Content Security Policy directive" in m]

    # Control de la consola: una conexión a otro origen sí deja su violación.
    await admin.evaluate("fetch('https://ejemplo.invalid/').catch(() => null)")
    await asyncio.sleep(1)


asyncio.run(ejecutar_personal(pasos_auditoria))
'''

# o) Los botones ocupados. Recibe el SPKI, el identificador, el email, la
# contraseña, el secreto TOTP y el último paso usado del admin, el email sin
# cuenta y el nombre del main-*.js servido. Lee de /prueba/foco.js y
# /prueba/guarda.js los main-*.js de los mutantes de entrar.ts (con disabled y
# sin la guarda).
NAVEGADOR_BOTONES = NAVEGADOR_PERSONAL + r'''
(spki, identificador, email_admin, contrasena_admin, secreto_admin, paso_admin, email_sin_cuenta,
 principal) = sys.argv[1:9]
with open("/prueba/foco.js", "rb") as fichero:
    MUTANTE_FOCO = fichero.read()
with open("/prueba/guarda.js", "rb") as fichero:
    MUTANTE_GUARDA = fichero.read()
usados[secreto_admin] = int(paso_admin)
SESIONES = "/v1/personal/sesiones"
# El elemento con el foco, por su etiqueta y su texto (el del <body>, vacío:
# sería la página entera).
ACTIVO = ("() => { const e = document.activeElement; "
          "return e === null ? null : [e.tagName, e === document.body ? '' : e.textContent.trim()]; }")


async def con_mutante(pagina, cuerpo):
    # Solo se sustituye el main-*.js, como en m): la página y su CSP llegan
    # de Caddy sin tocar.
    async def servir(peticion_ruta):
        await peticion_ruta.fulfill(status=200, content_type="text/javascript; charset=utf-8", body=cuerpo)

    await pagina.context.route(ORIGEN + "/" + principal, servir)


async def login_fallido(pagina):
    # El formulario de /entrar con el email sin cuenta. Devuelve el botón.
    await pagina.goto(ORIGEN + "/entrar")
    await pagina.get_by_label("Empresa").fill(identificador)
    await pagina.get_by_label("Email").fill(email_sin_cuenta)
    await pagina.get_by_label("Contraseña", exact=True).fill("una-contrasena-que-no-vale")
    await pagina.get_by_label(CODIGO).fill("000000")
    return pagina.get_by_role("button", name="Entrar", exact=True)


async def foco_tras_enter(pagina):
    # Con el teclado: el foco en "Entrar" y Enter. El foco de antes es el
    # control (estaba en el botón); el de después se lee cuando la página ha
    # repintado con el error.
    boton = await login_fallido(pagina)
    await boton.focus()
    antes = await pagina.evaluate(ACTIVO)
    await pagina.keyboard.press("Enter")
    alerta = pagina.get_by_role("alert")
    await alerta.wait_for()
    await asyncio.sleep(0.5)
    return {"antes": antes, "despues": await pagina.evaluate(ACTIVO), "alerta": await alerta.inner_text()}


async def posts_al_pulsar(pagina, veces):
    # Los POST /sesiones que salen al pulsar "Entrar" una vez o con un doble
    # clic.
    boton = await login_fallido(pagina)
    marca = len(eventos)
    if veces == 2:
        await boton.dblclick()
    else:
        await boton.click()
    await pagina.get_by_role("alert").wait_for()
    await asyncio.sleep(1.5)
    return len([e for e in eventos[marca:]
                if e["tipo"] == "peticion" and e["metodo"] == "POST" and e["ruta"] == SESIONES])


async def pasos_botones(navegador):
    # El login con la SPA real.
    visita = await pagina_nueva(navegador, "visita")
    res["foco_real"] = await foco_tras_enter(visita)
    res["un_clic"] = await posts_al_pulsar(visita, 1)
    res["doble_clic"] = await posts_al_pulsar(visita, 2)

    # "Cargar más" con el teclado hasta el final, como admin, que ve todas.
    admin = await pagina_nueva(navegador, "admin")
    await entrar(admin, email_admin, contrasena_admin, secreto_admin)
    await ir_por_menu(admin, "Denuncias")
    await admin.locator("main tbody tr").first.wait_for()
    res["primera"] = await admin.locator("tbody th[scope=row]").all_inner_texts()
    boton = admin.get_by_role("button", name="Cargar más", exact=True)
    res["boton"] = await boton.count()
    hecho, pulsaciones = None, 0
    while pulsaciones < 3 and await boton.count() == 1:
        await boton.focus()
        await admin.keyboard.press("Enter")
        hecho = (await esperar_texto(admin, "#denuncias-hecho") if hecho is None
                 else await esperar_otro(admin, "#denuncias-hecho", hecho))
        pulsaciones += 1
    res["hecho"], res["pulsaciones"] = hecho, pulsaciones
    try:
        # Una función y no una expresión: la CSP sin 'unsafe-eval' bloquea eval.
        await admin.wait_for_function(
            "() => document.activeElement !== null && document.activeElement.id === 'denuncias-hecho'", timeout=5000)
    except Exception:
        pass
    res["foco_final"] = await admin.evaluate(ACTIVO)
    res["boton_final"] = await boton.count()
    res["todas"] = await admin.locator("tbody th[scope=row]").all_inner_texts()
    res["ultimo_paso_admin"] = usados[secreto_admin]

    # Lo que sigue deja mensajes en la consola a propósito: los mutantes y el
    # control de la CSP. La comprobación de la consola mira solo hasta aquí.
    res["consola_antes_del_control"] = len(consola)

    # Los controles, cada uno en su contexto con el main-*.js de su mutante.
    pagina_foco = await pagina_nueva(navegador, "mutante_foco")
    await con_mutante(pagina_foco, MUTANTE_FOCO)
    res["foco_mutante"] = await foco_tras_enter(pagina_foco)
    pagina_guarda = await pagina_nueva(navegador, "mutante_guarda")
    await con_mutante(pagina_guarda, MUTANTE_GUARDA)
    res["doble_clic_mutante"] = await posts_al_pulsar(pagina_guarda, 2)

    # Control de la consola: una conexión a otro origen sí deja su violación.
    await admin.evaluate("fetch('https://ejemplo.invalid/').catch(() => null)")
    await asyncio.sleep(1)


asyncio.run(ejecutar_personal(pasos_botones))
'''


# p) La fuente, el tema oscuro y el ancho de 320 px. Recibe el SPKI, el
# identificador, el email, la contraseña, el secreto TOTP y el último paso
# usado del admin, y las rutas que se miran. Cada contexto lleva su tema y su
# ancho: Playwright los emula como lo haría el sistema.
NAVEGADOR_ESTETICA = NAVEGADOR_PERSONAL + r'''
spki, identificador, email_admin, contrasena_admin, secreto_admin, paso_admin = sys.argv[1:7]
rutas_ancho = json.loads(sys.argv[7])
usados[secreto_admin] = int(paso_admin)
# La familia sin comillas, las ponga Chromium o no.
FUENTES = "() => [...document.fonts].map((f) => [f.family.replace(/[\"']/g, ''), f.status])"
FONDO = "() => getComputedStyle(document.body).backgroundColor"
ANCHO = "() => [document.documentElement.scrollWidth, document.documentElement.clientWidth]"


async def pagina_con(navegador, nombre, tema):
    contexto = await navegador.new_context(viewport={"width": 320, "height": 640}, color_scheme=tema)
    pagina = await contexto.new_page()
    vigilar(pagina, nombre)
    paginas[nombre] = pagina
    return pagina


async def pasos_estetica(navegador):
    claro = await pagina_con(navegador, "claro", "light")
    await claro.goto(ORIGEN + "/entrar")
    await h1(claro)
    # Una función que devuelve la promesa: Playwright espera a que se cumpla.
    await claro.evaluate("() => document.fonts.ready.then(() => null)")
    res["fuentes"] = await claro.evaluate(FUENTES)
    res["fondo_claro"] = await claro.evaluate(FONDO)
    anchos = {"/entrar": await claro.evaluate(ANCHO)}
    await entrar(claro, email_admin, contrasena_admin, secreto_admin)
    # El texto de la barra tal cual, sin depender del ancho: textContent.
    res["quien"] = await claro.evaluate("() => document.querySelector('.quien').textContent.trim()")
    for ruta_pedida in rutas_ancho:
        await abrir(claro, ruta_pedida)
        anchos[ruta_pedida] = await claro.evaluate(ANCHO)
    res["anchos"] = anchos
    res["ultimo_paso_admin"] = usados[secreto_admin]

    oscuro = await pagina_con(navegador, "oscuro", "dark")
    await oscuro.goto(ORIGEN + "/entrar")
    await h1(oscuro)
    res["fondo_oscuro"] = await oscuro.evaluate(FONDO)

    # Lo que sigue deja mensajes en la consola a propósito. La comprobación
    # de la consola mira solo hasta aquí.
    res["consola_antes_del_control"] = len(consola)
    # Control del ancho: un elemento de 400 px, puesto con el CSSOM, que la
    # CSP no limita (un atributo style sí lo bloquearía).
    await claro.evaluate("() => { const d = document.createElement('div'); d.style.width = '400px'; "
                         "d.style.height = '1px'; document.body.append(d); }")
    res["ancho_control"] = await claro.evaluate(ANCHO)
    # Control de la consola: una fuente de otro origen deja su violación de
    # font-src.
    await claro.evaluate("() => new FontFace('Ajena', 'url(https://ejemplo.invalid/ajena.woff2)')"
                         ".load().then(() => null, () => null)")
    await asyncio.sleep(1)


asyncio.run(ejecutar_personal(pasos_estetica))
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
IMAGEN_MUTANTE_XSS = f"{PROYECTO}_mutante_xss"
IMAGEN_MUTANTE_XSS_AUDITORIA = f"{PROYECTO}_mutante_xss_auditoria"
IMAGEN_MUTANTE_FOCO = f"{PROYECTO}_mutante_foco"
IMAGEN_MUTANTE_GUARDA = f"{PROYECTO}_mutante_guarda"
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


def navegador(nombre, script, argumentos, ficheros=None):
    """Ejecuta un script de Playwright en Chromium y devuelve su JSON, o None.
    El navegador comparte la red del contenedor de Caddy: localhost:8445 es
    Caddy, con el mismo Host y el mismo SNI que desde el host. Mínimo
    privilegio: pwuser, raíz de solo lectura y sin capacidades (Playwright
    lanza Chromium sin su sandbox por defecto). La red la usa pip. Si falla,
    solo se informa de stderr: stdout puede llevar el secreto TOTP de i).
    ficheros ({nombre: bytes}) van junto al script, en /prueba."""
    directorio = TEMPORAL / nombre
    directorio.mkdir()
    (directorio / "navegador.py").write_text(script, encoding="utf-8", newline="\n")
    (directorio / "requisitos.txt").write_text(REQUISITOS_PLAYWRIGHT, encoding="utf-8", newline="\n")
    for nombre_fichero, contenido in (ficheros or {}).items():
        (directorio / nombre_fichero).write_bytes(contenido)
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
    registro = dc("logs", "--no-color", "--no-log-prefix", "api").todo
    pasa(TEXTO_LIMITES_PRUEBA in registro,
         f"a) la API usa los limites de prueba y el log lo dice ({TEXTO_LIMITES_PRUEBA!r})")
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

    # La fuente: la referencia la hoja del build, y Caddy la sirve con su
    # tipo, las mismas cabeceras y los bytes del release fijado.
    _, _, hoja = peticion("GET", f"/{ESTILOS}")
    fuente = PATRON_FUENTE.search(hoja)
    if fuente is None:
        pasa(False, f"b) la hoja {ESTILOS} referencia media/geist-variable-*.woff2 "
                    f"({re.findall(rb'url[(][^)]*[)]', hoja)[:5]})")
        return
    ruta_fuente = "/" + fuente.group(1).decode()
    codigo, cab, cuerpo = peticion("GET", ruta_fuente)
    p(f"   la hoja carga {ruta_fuente}")
    pasa(codigo == 200 and una(cab, "content-type") == TIPO_FUENTE,
         f"b) fuente: {codigo}, content-type: {cab.get('content-type')!r}")
    for nombre, valor in CABECERAS_SPA.items():
        pasa(una(cab, nombre) == valor, f"b) fuente: {nombre}: {cab.get(nombre)!r}")
    pasa("server" not in cab and "accept-ranges" not in cab, "b) fuente: sin Server ni Accept-Ranges")
    huella = hashlib.sha256(cuerpo).hexdigest()
    pasa(huella == SHA256_FUENTE, f"b) fuente: es la del release fijado (sha256 {huella[:16]}..., {len(cuerpo)} bytes)")


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

    # /srv/spa con un nivel más (media/ y su fuente); de /data/caddy, solo él.
    r = en_imagen(IMAGEN_PROXY, "find /srv/spa -maxdepth 2 -exec stat -c '%u:%g %a %n' {} + ; "
                                "find /data/caddy -maxdepth 0 -exec stat -c '%u:%g %a %n' {} +")
    filas = [linea.split(" ", 2) for linea in r.out.splitlines() if linea.count(" ") >= 2]
    datos = {nombre: (dueno, int(modo, 8)) for dueno, modo, nombre in filas}
    control = datos.get("/data/caddy", ("", 0))[0] == "10002:10002" and "/srv/spa/index.html" in datos
    spa = {nombre: v for nombre, v in datos.items() if nombre.startswith("/srv/spa/")}
    nombres = sorted(n.removeprefix("/srv/spa/") for n in spa)
    negativo(f"d) /srv/spa solo contiene index.html, un main-*.js, un styles-*.css y media/ con la fuente "
             f"({nombres})",
             len(nombres) == FICHEROS_SPA and all(PATRON_FICHERO_SPA.fullmatch(n) for n in nombres), control,
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
    pasa(control_csp, f"i) control: una conexion a otro origen deja su violacion de la CSP en la consola ({senales_csp(consola[corte:])[:1]})")
    negativo(f"i) en todo el recorrido, ninguna violacion de la CSP ni error de JavaScript "
             f"({len(senales_csp(consola[:corte]))}, {len(errores)})",
             not senales_csp(consola[:corte]) and not errores, control_csp,
             f"{senales_csp(consola[:corte])[:3]} {errores[:3]}")


def seccion_j():
    global ULTIMO_PASO
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
    codigo_totp = codigo_tras(SECRETO_ADMIN, ULTIMO_PASO)
    # Para l): el paso de este código ya está usado. Leído después de
    # calcularlo, así que como mucho es el siguiente, nunca uno anterior.
    ULTIMO_PASO = int(time.time()) // 30
    codigo, _, cuerpo = peticion("POST", RUTA_SESIONES, puerto=PUERTO_API, datos={
        "empresa": IDENTIFICADOR, "email": EMAIL_ADMIN, "contrasena": CONTRASENA_ADMIN,
        "codigo_totp": codigo_totp})
    acceso = (json.loads(cuerpo) if codigo == 201 else {}).get("token_acceso")
    if not acceso:
        sinc(f"j) el admin no pudo iniciar sesion por la API ({codigo})")
        return
    codigo, _, cuerpo = peticion("GET", "/v1/personal/solicitudes", puerto=PUERTO_API,
                                 cabeceras={"Authorization": f"Bearer {acceso}"})
    emails = [s.get("email") for s in (json.loads(cuerpo) if codigo == 200 else {}).get("solicitudes", [])]
    pasa(emails == [EMAIL_REGISTRO], f"j) el admin ve la solicitud verificada ({codigo}, {emails})")


def luminancia(color):
    """Luminancia relativa de un #rrggbb (WCAG 2.2, definiciones)."""
    canales = [int(color[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    lineales = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in canales]
    return 0.2126 * lineales[0] + 0.7152 * lineales[1] + 0.0722 * lineales[2]


def contraste(a, b):
    claro, oscuro = sorted((luminancia(a), luminancia(b)), reverse=True)
    return (claro + 0.05) / (oscuro + 0.05)


def revisar_hoja(css):
    """Lo que k) comprueba de una hoja: (parejas sin contraste suficiente en
    algún tema, colores fuera de los dos :root, variables usadas que no
    existen, colores del claro que el oscuro no redefine). Sin comentarios,
    que pueden nombrar colores."""
    sin_comentarios = re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)
    oscuro = PATRON_TEMA_OSCURO.search(sin_comentarios)
    if oscuro is None:
        raise Parada("spa/src/styles.css no tiene el :root de @media (prefers-color-scheme: dark)")
    resto = sin_comentarios[:oscuro.start()] + sin_comentarios[oscuro.end():]
    raices = list(re.finditer(r":root\s*\{(.*?)\}", resto, re.DOTALL))
    if len(raices) != 1:
        raise Parada(f"spa/src/styles.css debe tener un solo :root fuera del tema oscuro (tiene {len(raices)})")
    raiz = raices[0]
    claro = dict(re.findall(r"(--[a-z0-9-]+)\s*:\s*([^;]+);", raiz.group(1)))
    propias = dict(re.findall(r"(--[a-z0-9-]+)\s*:\s*([^;]+);", oscuro.group(1)))
    flojas = []
    for tema, variables in (("claro", claro), ("oscuro", {**claro, **propias})):
        for frente, fondo, minimo in PAREJAS_CONTRASTE:
            a, b = variables.get(frente, ""), variables.get(fondo, "")
            if not (re.fullmatch(r"#[0-9a-f]{6}", a) and re.fullmatch(r"#[0-9a-f]{6}", b)):
                flojas.append(f"{tema} {frente}/{fondo}: no son #rrggbb ({a!r}, {b!r})")
            elif contraste(a, b) < minimo:
                flojas.append(f"{tema} {frente}/{fondo}: {contraste(a, b):.2f} < {minimo}")
    fuera = resto[:raiz.start()] + resto[raiz.end():]
    sueltos = re.findall(r"#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(", fuera)
    usadas = set(re.findall(r"var\((--[a-z0-9-]+)\)", sin_comentarios))
    olvidados = sorted(n for n in claro if n.startswith("--color-") and n not in propias)
    return flojas, sueltos, sorted(usadas - set(claro) - set(propias)), olvidados


def revisar_botones(textos):
    """Lo que k) comprueba de los componentes ({ruta relativa: texto}):
    (ficheros con disabled ligado, ficheros cuyo número de aria-disabled no es
    el de BOTONES_OCUPADOS)."""
    con_disabled = sorted(f for f, texto in textos.items() if PATRON_DISABLED.search(texto))
    cuentas = {f: len(PATRON_ARIA_DISABLED.findall(texto)) for f, texto in textos.items()}
    distintos = sorted(f for f in set(cuentas) | set(BOTONES_OCUPADOS)
                       if cuentas.get(f, 0) != BOTONES_OCUPADOS.get(f, 0))
    return con_disabled, distintos


def seccion_k():
    p("=== k) base visual: contraste de los colores en los dos temas, sin colores sueltos y sin variables que no existen; "
      "botones ocupados con aria-disabled")
    control = round(contraste("#767676", "#ffffff"), 2) == 4.54 and round(contraste("#777777", "#ffffff"), 2) == 4.48
    pasa(control, "k) control: la formula de contraste da 4,54:1 con #767676 y 4,48:1 con #777777 sobre blanco")
    css = ESTILOS_SPA.read_text(encoding="utf-8")
    flojas, sueltos, inexistentes, olvidados = revisar_hoja(css)
    # Cada mutante, con el índice de lo que debe hacer saltar en revisar_hoja.
    controles = {}
    for nombre, mutante, indice in (("gris claro", MUTANTE_GRIS, 0), ("gris del oscuro", MUTANTE_GRIS_OSCURO, 0),
                                    ("color olvidado", MUTANTE_OLVIDADO, 3)):
        if css.count(mutante[0]) != 1:
            sinc(f"k) el mutante del {nombre} no encuentra su texto en spa/src/styles.css")
            controles[nombre] = False
        else:
            controles[nombre] = bool(revisar_hoja(css.replace(*mutante))[indice])
    control_suelto = bool(revisar_hoja(css + MUTANTE_COLOR_SUELTO)[1])
    control_variable = bool(revisar_hoja(css + MUTANTE_VARIABLE)[2])
    negativo(f"k) las {len(PAREJAS_CONTRASTE)} parejas de colores llegan a su contraste minimo en los dos temas "
             f"{flojas}".rstrip(),
             not flojas, control and controles["gris claro"] and controles["gris del oscuro"],
             "control: con un gris claro en uno de los temas la comprobacion no salta")
    negativo(f"k) el tema oscuro redefine todos los colores del claro {olvidados}".rstrip(), not olvidados,
             controles["color olvidado"], "control: un color que falta en el oscuro no se detecta")
    negativo(f"k) ningun color fuera de los dos :root {sueltos}".rstrip(), not sueltos, control_suelto,
             "control: un color suelto no se detecta")
    negativo(f"k) toda variable usada esta definida {inexistentes}".rstrip(), not inexistentes, control_variable,
             "control: una variable que no existe no se detecta")

    # Los botones ocupados, con el mutante de entrar.ts como control.
    textos = {f.relative_to(APP_SPA).as_posix(): f.read_text(encoding="utf-8") for f in APP_SPA.rglob("*.ts")}
    con_disabled, distintos = revisar_botones(textos)
    if textos.get(FICHERO_ENTRAR, "").count(MUTANTE_DISABLED[0]) != 1:
        sinc(f"k) el mutante de los botones no encuentra su texto en {FICHERO_ENTRAR}")
        control_botones = False
    else:
        mutado = {**textos, FICHERO_ENTRAR: textos[FICHERO_ENTRAR].replace(*MUTANTE_DISABLED)}
        control_botones = revisar_botones(mutado) == ([FICHERO_ENTRAR], [FICHERO_ENTRAR])
    negativo(f"k) ningun boton de la SPA lleva disabled ligado {con_disabled}".rstrip(), not con_disabled,
             control_botones, "control: entrar.ts con disabled no se detecta")
    negativo(f"k) cada fichero lleva los aria-disabled de su inventario "
             f"({sum(BOTONES_OCUPADOS.values())} en {len(BOTONES_OCUPADOS)}) {distintos}".rstrip(),
             not distintos, control_botones, "control: entrar.ts sin aria-disabled no se detecta")


def seccion_l():
    global ULTIMO_PASO
    p("=== l) pantallas por rol en Chromium: menu, guard, solicitudes, cuentas y contrasena")
    if not PATRON_SECRETO_TOTP.fullmatch(SECRETO_ADMIN):
        sinc("l) sin el secreto TOTP del admin (i no termino) no se pueden probar las pantallas")
        return
    res = navegador("navegador_l", NAVEGADOR_ROLES,
                    [SPKI_INTERMEDIA, IDENTIFICADOR, EMAIL_ADMIN, CONTRASENA_ADMIN, SECRETO_ADMIN, str(ULTIMO_PASO),
                     EMAIL_REGISTRO, EMAIL_INSTRUCTORA, EMAIL_AUDITOR, CONTRASENA_NUEVAS])
    if res is None:
        sinc("l) no se pudo ejecutar el navegador")
        return
    if "excepcion" in res:
        pasa(False, f"l) el recorrido se interrumpe: {res['excepcion']}")
        p(f"   avisos a la vista en cada pagina: {res.get('avisos_visibles')}")
    ULTIMO_PASO = res.get("ultimo_paso_admin", ULTIMO_PASO)

    # Menú y guard por rol, con la página propia como control.
    pasa(res.get("menu_admin") == MENU_ADMIN, f"l) el menu del admin ({res.get('menu_admin')})")
    pasa(res.get("menu_instructora") == MENU_INSTRUCTOR and res.get("menu_auditor") == MENU_AUDITOR,
         f"l) el menu de la instructora y del auditor ({res.get('menu_instructora')}, {res.get('menu_auditor')})")
    propia = res.get("instructora_cuenta") or {}
    control_guard = propia == {"ruta": "/cuenta", "h1": H1_MI_CUENTA}
    pasa(control_guard, f"l) control: la instructora abre /cuenta por su URL ({propia})")
    for clave, ruta_pedida in (("instructora_cuentas", "/cuentas"), ("instructora_solicitudes", "/solicitudes"),
                               ("auditor_cuentas", "/cuentas")):
        negativo(f"l) {clave.split('_')[0]} pide {ruta_pedida} por su URL y vuelve a /inicio ({res.get(clave)})",
                 res.get(clave) == {"ruta": "/inicio", "h1": H1_INICIO}, control_guard)
    negativo(f"l) y la API responde 403 a la instructora en /usuarios ({res.get('usuarios_instructora')})",
             res.get("usuarios_instructora") == 403, res.get("usuarios_admin") == 200,
             f"control: el admin recibe {res.get('usuarios_admin')}")

    # Solicitudes.
    aprobada_api = res.get("aprobada_api") or []
    aprobacion = [e for e in aprobada_api if e["tipo"] == "respuesta" and e["ruta"].endswith("/aprobacion")]
    control_aprobar = [e["estado"] for e in aprobacion] == [201] and res.get("aprobada") == TEXTO_APROBADA
    pasa(control_aprobar, f"l) control: con el rol elegido, la solicitud se aprueba ({respuestas(aprobada_api)}, "
                          f"{res.get('aprobada')!r})")
    negativo(f"l) sin rol, aprobar no envia nada y lo dice ({res.get('sin_rol')!r}, {res.get('sin_rol_api')})",
             res.get("sin_rol") == TEXTO_SIN_ROL and res.get("sin_rol_api") == [], control_aprobar)
    negativo("l) el token de la invitacion aprobada no pasa por la pagina", res.get("aprobada_token") is False,
             control_aprobar)
    enlace_correo = None
    for _ in range(30):
        for correo in buzon():
            encaje = PATRON_ENLACE_CORREO.search(correo.get("texto") or "")
            if EMAIL_REGISTRO in correo.get("para", []) and correo.get("asunto") == ASUNTO_INVITACION and encaje:
                enlace_correo = encaje.group(0)
        if enlace_correo:
            break
        time.sleep(1)
    pasa(enlace_correo is not None, "l) la invitacion de la solicitud aprobada llega al correo verificado")

    # El enlace de una invitación.
    pasa(res.get("enlace_instructora") is True and res.get("enlace_auditor") is True
         and res.get("reinvitada_enlace") is True,
         "l) invitar y reinvitar muestran un enlace con la forma de la activacion")
    pasa(res.get("foco_enlace") == FOCO_ENLACE, f"l) el foco va al encabezado del enlace ({res.get('foco_enlace')!r})")
    pasa(res.get("enlaces_a") == 0, f"l) el enlace se muestra como texto, sin <a> que lo abra ({res.get('enlaces_a')})")
    pasa(res.get("ruta_con_enlace") == "/cuentas" and res.get("almacen_admin") == [0, 0],
         f"l) el token no va a la URL ni al almacenamiento ({res.get('ruta_con_enlace')!r}, {res.get('almacen_admin')})")
    negativo("l) al salir de la pagina y volver, el enlace ya no esta", res.get("token_tras_salir") is False,
             res.get("token_antes_de_salir") is True, "control: antes de salir no estaba en la pagina")
    pasa(res.get("duplicada") == TEXTO_DUPLICADA, f"l) invitar un email que ya tiene cuenta ({res.get('duplicada')!r})")

    # Reinvitar, anular y dar de baja.
    pasa("Activa" in (res.get("fila_instructora") or ""), f"l) la instructora sale activa ({res.get('fila_instructora')!r})")
    control_reinvitada = "Invitación abierta" in (res.get("fila_reinvitada") or "")
    pasa(control_reinvitada, f"l) control: tras reinvitar, la fila avisa de la invitacion ({res.get('fila_reinvitada')!r})")
    pasa(res.get("aviso_instructora") == [AVISO_INVITACION],
         f"l) y la instructora ve el aviso en /inicio ({res.get('aviso_instructora')})")
    negativo(f"l) anular quita el aviso de la fila ({res.get('anulada')!r})",
             res.get("anulada") == TEXTO_ANULADA and "Invitación abierta" not in (res.get("fila_anulada") or "x"),
             control_reinvitada)
    negativo(f"l) la propia cuenta no tiene boton de baja ({res.get('baja_propia')})", res.get("baja_propia") == 0,
             res.get("baja_otra") == 1, f"control: la del auditor tiene {res.get('baja_otra')}")
    pasa(res.get("foco_confirmar") == "Confirmar la baja",
         f"l) la baja pide confirmacion y el foco va a ella ({res.get('foco_confirmar')!r})")
    pasa(res.get("baja") == TEXTO_BAJA and "Desactivada" in (res.get("fila_baja") or ""),
         f"l) la baja se confirma y la cuenta sale desactivada ({res.get('baja')!r})")
    antes = res.get("auditor_inicio_antes") or {}
    control_baja = antes == {"ruta": "/inicio", "h1": H1_INICIO}
    negativo(f"l) tras la baja, el auditor no entra y va a /entrar ({res.get('auditor_inicio_despues')})",
             res.get("auditor_inicio_despues") == {"ruta": "/entrar", "h1": H1_ENTRAR}, control_baja,
             f"control: antes de la baja {antes}")

    # Cambiar la contraseña.
    control_cambio = res.get("contrasena_cambiada") == TEXTO_CONTRASENA_CAMBIADA and res.get("yo_tras_cambio") == 200
    pasa(control_cambio, f"l) control: con la contrasena actual, se cambia y la sesion sigue viva "
                         f"({res.get('contrasena_cambiada')!r}, {res.get('yo_tras_cambio')})")
    mal = respuestas(res.get("contrasena_mal_api") or [])
    negativo(f"l) con la actual mal, lo dice y no renueva la sesion ({res.get('contrasena_mal')!r}, {mal})",
             res.get("contrasena_mal") == TEXTO_CONTRASENA_MAL and mal == [("POST", "/v1/personal/contrasena", 401)],
             control_cambio)

    # Consola.
    consola, errores = res.get("consola") or [], res.get("errores") or []
    corte = res.get("consola_antes_del_control", len(consola))
    control_csp = bool(senales_csp(consola[corte:]))
    pasa(control_csp, f"l) control: una conexion a otro origen deja su violacion de la CSP ({senales_csp(consola[corte:])[:1]})")
    negativo(f"l) en todo el recorrido, ninguna violacion de la CSP ni error de JavaScript "
             f"({len(senales_csp(consola[:corte]))}, {len(errores)})",
             not senales_csp(consola[:corte]) and not errores, control_csp,
             f"{senales_csp(consola[:corte])[:3]} {errores[:3]}")


def ids_denuncias(acceso):
    """Los ids de las denuncias de la empresa, por la API del 8443 con el
    token del admin (Bearer)."""
    codigo, _, cuerpo = peticion("GET", "/v1/personal/denuncias", puerto=PUERTO_API,
                                 cabeceras={"Authorization": f"Bearer {acceso}"})
    if codigo != 200:
        raise Parada(f"m) el admin no puede listar las denuncias por la API ({codigo})")
    return {d["denuncia_id"] for d in json.loads(cuerpo)["denuncias"]}


def crear_denuncia(acceso, texto):
    """Crea una denuncia por la API pública del 8443, como un denunciante, y
    devuelve (id, código de seguimiento). La API no da el id al denunciante:
    sale del listado del admin, antes y después."""
    antes = ids_denuncias(acceso)
    codigo, _, cuerpo = peticion("POST", f"/v1/empresas/{IDENTIFICADOR}/denuncias", puerto=PUERTO_API,
                                 datos={"categoria": "fraude", "texto": texto})
    seguimiento = (json.loads(cuerpo) if codigo == 201 else {}).get("codigo_seguimiento")
    nuevas = ids_denuncias(acceso) - antes
    if not seguimiento or len(nuevas) != 1:
        raise Parada(f"m) no se pudo crear una denuncia de preparacion ({codigo})")
    return nuevas.pop(), seguimiento


def main_de_mutante(seccion, fichero_relativo, mutacion, imagen):
    """El main-*.js de la SPA con una mutación (texto original, texto mutado)
    en un fichero, de una copia de spa/ (el repositorio no se toca)."""
    copia = copia_de_spa(f"spa_{imagen.removeprefix(PROYECTO + '_')}")
    fichero = copia / fichero_relativo
    texto = fichero.read_text(encoding="utf-8")
    if texto.count(mutacion[0]) != 1:
        raise Parada(f"{seccion}) el mutante {imagen} no encuentra su texto en {fichero_relativo}")
    fichero.write_text(texto.replace(*mutacion), encoding="utf-8", newline="\n")
    compilacion(copia, imagen)
    r = en_imagen(imagen, "cat /spa/dist/canario-spa/browser/main-*.js")
    if r.rc != 0 or len(r.out) < 1000:
        raise Parada(f"{seccion}) no se pudo leer el main-*.js del mutante {imagen}: {r.err.strip()[-300:]!r}")
    return r.out.encode("utf-8")


def main_del_mutante_xss():
    """El main-*.js de la SPA con el texto de la denuncia en [innerHTML]."""
    return main_de_mutante("m", pathlib.Path("src", "app", "denuncias", "contenido.ts"), MUTANTE_XSS,
                           IMAGEN_MUTANTE_XSS)


def seccion_m():
    global ULTIMO_PASO
    p("=== m) denuncias en Chromium: listado, asignacion, expediente sin lectura automatica, XSS, mensajes y estados")
    if not PATRON_SECRETO_TOTP.fullmatch(SECRETO_ADMIN):
        sinc("m) sin el secreto TOTP del admin (i no termino) no se pueden probar las denuncias")
        return

    # Preparación por la API del 8443: el admin con Bearer (para saber los
    # ids) y el denunciante, que escribe las cargas en la denuncia y en un
    # mensaje.
    codigo_totp = codigo_tras(SECRETO_ADMIN, ULTIMO_PASO)
    ULTIMO_PASO = int(time.time()) // 30
    codigo, _, cuerpo = peticion("POST", RUTA_SESIONES, puerto=PUERTO_API, datos={
        "empresa": IDENTIFICADOR, "email": EMAIL_ADMIN, "contrasena": CONTRASENA_ADMIN, "codigo_totp": codigo_totp})
    acceso = (json.loads(cuerpo) if codigo == 201 else {}).get("token_acceso")
    if not acceso:
        raise Parada(f"m) el admin no pudo iniciar sesion por la API ({codigo})")
    d1, seguimiento = crear_denuncia(acceso, CARGA_DENUNCIA)
    d2, _ = crear_denuncia(acceso, "Denuncia sin cargas, para el admin.")
    codigo, _, _ = peticion("POST", "/v1/seguimiento/mensajes", puerto=PUERTO_API,
                            datos={"codigo": seguimiento, "texto": CARGA_MENSAJE})
    if codigo != 201:
        raise Parada(f"m) el denunciante no pudo escribir su mensaje ({codigo})")
    mutante = main_del_mutante_xss()

    datos = {"d1": d1, "d2": d2, "marca": MARCA_CARGA, "texto_personal": TEXTO_PERSONAL, "texto_final": TEXTO_FINAL}
    res = navegador("navegador_m", NAVEGADOR_DENUNCIAS,
                    [SPKI_INTERMEDIA, IDENTIFICADOR, EMAIL_ADMIN, CONTRASENA_ADMIN, SECRETO_ADMIN, str(ULTIMO_PASO),
                     EMAIL_INSTRUCTOR_M, CONTRASENA_NUEVAS, MAIN],
                    {"datos.json": json.dumps(datos, ensure_ascii=False).encode("utf-8"), "mutante.js": mutante})
    if res is None:
        sinc("m) no se pudo ejecutar el navegador")
        return
    if "excepcion" in res:
        pasa(False, f"m) el recorrido se interrumpe: {res['excepcion']}")
        p(f"   avisos a la vista en cada pagina: {res.get('avisos_visibles')}")
    ULTIMO_PASO = res.get("ultimo_paso_admin", ULTIMO_PASO)
    ruta_d1 = f"/v1/personal/denuncias/{d1}"

    # Menú y listado.
    pasa(res.get("menu_admin") == MENU_ADMIN and res.get("menu_instructor") == MENU_INSTRUCTOR,
         f"m) el menu del admin y del instructor lleva Denuncias ({res.get('menu_admin')}, {res.get('menu_instructor')})")
    control_listado = res.get("filas_admin") == sorted([d1, d2])
    pasa(control_listado, f"m) control: el admin ve las dos denuncias ({res.get('filas_admin')})")
    negativo(f"m) el instructor solo ve la que tiene asignada ({res.get('filas_instructor')})",
             res.get("filas_instructor") == [d1], control_listado)
    control_enlace = res.get("enlaces_admin_despues") == [0, 1]
    pasa(control_enlace, f"m) control: tras asignarse una, el admin tiene su enlace ({res.get('enlaces_admin_despues')})")
    negativo(f"m) sin asignar, el admin no tiene enlace a la denuncia ({res.get('enlaces_admin_antes')})",
             res.get("enlaces_admin_antes") == [0, 0], control_enlace)
    asignar = respuestas(res.get("asignar_api") or [])
    pasa(res.get("asignada_d1") == f"La denuncia {d1} está asignada a {EMAIL_INSTRUCTOR_M}."
         and ("PUT", f"{ruta_d1}/asignacion", 204) in asignar and EMAIL_INSTRUCTOR_M in (res.get("fila_d1_admin") or ""),
         f"m) el admin asigna desde el listado y la fila dice a quien ({res.get('asignada_d1')!r}, {asignar})")

    # Un id que no es un uuid y la carga directa.
    control_directa = (res.get("directa") == {"ruta": f"/denuncias/{d1}", "h1": H1_DENUNCIA}
                       and res.get("directa_boton") == 1)
    pasa(control_directa, f"m) control: /denuncias/<uuid> abre la pagina de la denuncia ({res.get('directa')})")
    negativo(f"m) {RUTA_CSPT} es 'no encontrada' y no pide nada a la API ({res.get('cspt')}, "
             f"{respuestas(res.get('cspt_api') or [])})",
             res.get("cspt") == {"ruta": RUTA_CSPT, "h1": H1_NO_ENCONTRADA} and res.get("cspt_api") == [], control_directa)
    control_lectura = res.get("abrir_lecturas") == 1 and res.get("auditadas_despues") == 1
    pasa(control_lectura, f"m) control: el boton lee una vez y deja una fila de auditoria "
                          f"({res.get('abrir_lecturas')}, {res.get('auditadas_despues')})")
    negativo(f"m) la carga directa no lee nada ni deja fila ({res.get('directa_lecturas')}, {res.get('auditadas_antes')})",
             res.get("directa_lecturas") == 0 and res.get("auditadas_antes") == 0, control_lectura)
    pasa(res.get("foco_abrir") == FOCO_EXPEDIENTE, f"m) al abrir, el foco va al expediente ({res.get('foco_abrir')!r})")

    # XSS almacenado, con el mutante como control.
    mutado = res.get("mutante") or {}
    control_xss = mutado.get("img") == 1 and bool(res.get("mutante_csp"))
    pasa(control_xss, f"m) control: con [innerHTML], la carga crea un <img> aunque la CSP siga puesta y bloquee su "
                      f"carga ({mutado}, {(res.get('mutante_csp') or [''])[0][:120]!r})")
    xss = res.get("xss") or {}
    negativo(f"m) las cargas salen como texto literal, sin crear ningun elemento ni ejecutar nada "
             f"({xss.get('hijos')}, {xss.get('peligrosos')}, {xss.get('bandera')})",
             xss.get("textos") == [CARGA_DENUNCIA, CARGA_MENSAJE] and xss.get("hijos") == 0
             and xss.get("peligrosos") == 0 and xss.get("bandera") == "undefined", control_xss,
             f"textos {xss.get('textos')}")
    pasa(xss.get("dir") == ["auto", "auto"], f"m) los textos libres llevan dir=\"auto\" ({xss.get('dir')})")
    consola, errores = res.get("consola") or [], res.get("errores") or []
    corte = res.get("consola_antes_del_control", len(consola))
    pasa(res.get("almacen_instructor") == [0, 0] and not any(MARCA_CARGA in m for m in consola[:corte]),
         f"m) el expediente no va al almacenamiento ni a la consola ({res.get('almacen_instructor')})")

    # Mensajes y estados, sin volver a leer.
    mensaje = respuestas(res.get("mensaje_api") or [])
    vistos = res.get("mensajes_vistos") or [""]
    pasa(res.get("mensaje_hecho") == TEXTO_MENSAJE_ENVIADO and mensaje == [("POST", f"{ruta_d1}/mensajes", 201)]
         and "Mensaje 2 · Usted" in vistos[-1] and TEXTO_PERSONAL in vistos[-1],
         f"m) el mensaje se envia y se anade con su numero, sin volver a leer ({mensaje}, {vistos[-1]!r})")
    estado_1 = respuestas(res.get("estado_1_api") or [])
    pasa(res.get("estado_1") == TEXTO_EN_INSTRUCCION and estado_1 == [("POST", f"{ruta_d1}/estado", 204)]
         and res.get("estado_visto_1") == "En instrucción",
         f"m) pasa a En instruccion ({res.get('estado_1')!r}, {estado_1})")
    cierre = respuestas(res.get("cierre_api") or [])
    control_cierre = cierre == [("POST", f"{ruta_d1}/estado", 204)]
    pasa(control_cierre, f"m) control: con el mensaje final, cerrar se envia ({cierre})")
    negativo(f"m) cerrar sin mensaje final no envia nada ({respuestas(res.get('cierre_sin_mensaje_api') or [])}, "
             f"falta {res.get('cierre_sin_mensaje_falta')})",
             res.get("cierre_sin_mensaje_api") == [] and res.get("cierre_sin_mensaje_falta") is True, control_cierre)
    tras_cierre = res.get("mensajes_tras_cierre") or [""]
    pasa(res.get("cierre") == TEXTO_CIERRE and res.get("estado_visto_2") == "Resuelta"
         and CABECERA_PENDIENTE in tras_cierre[-1] and TEXTO_FINAL in tras_cierre[-1]
         and res.get("formularios_tras_cierre") == 0,
         f"m) tras cerrar: el estado, el mensaje final pendiente de numero y sin formularios ({res.get('cierre')!r})")
    pasa(res.get("lecturas_tras_acciones") == 1,
         f"m) mensaje y estados no vuelven a leer el expediente ({res.get('lecturas_tras_acciones')} lectura)")

    # No veraz: solo el admin, con confirmación.
    control_no_veraz = res.get("no_veraz_admin") == 1
    pasa(control_no_veraz, f"m) control: el admin tiene 'Declarar no veraz' en la suya ({res.get('no_veraz_admin')})")
    negativo(f"m) el instructor no tiene 'Declarar no veraz' ({res.get('no_veraz_instructor')})",
             res.get("no_veraz_instructor") == 0, control_no_veraz)
    no_veraz = respuestas(res.get("no_veraz_api") or [])
    pasa(res.get("foco_no_veraz") == FOCO_NO_VERAZ and no_veraz == [("POST", f"/v1/personal/denuncias/{d2}/estado", 204)]
         and res.get("no_veraz_hecho") == (f"La denuncia {d2} está declarada no veraz: ya no existe para el canal y se "
                                           "suprimirá en la siguiente ejecución de la supresión.")
         and res.get("filas_admin_final") == [d1],
         f"m) no veraz pide confirmacion, se declara y sale del listado ({res.get('foco_no_veraz')!r}, {no_veraz}, "
         f"{res.get('filas_admin_final')})")

    # "Atrás" tras cerrar la sesión.
    control_atras = res.get("atras_antes") is True and "/denuncias" in (res.get("atras_visitadas") or [])
    pasa(control_atras, f"m) control: antes de cerrar la sesion el expediente esta en la pagina, y 'atras' pasa por "
                        f"/denuncias ({res.get('atras_visitadas')})")
    negativo(f"m) tras cerrar la sesion, 'atras' acaba en /entrar sin el expediente ({res.get('atras_ruta')!r}, "
             f"{res.get('atras_h1')!r})",
             res.get("atras_ruta") == "/entrar" and res.get("atras_h1") == H1_ENTRAR and res.get("atras_marca") is False,
             control_atras)

    # Consola.
    control_csp = bool(senales_csp(consola[corte:]))
    pasa(control_csp, f"m) control: el mutante y una conexion a otro origen dejan su violacion de la CSP "
                      f"({senales_csp(consola[corte:])[:1]})")
    negativo(f"m) en todo el recorrido, ninguna violacion de la CSP ni error de JavaScript "
             f"({len(senales_csp(consola[:corte]))}, {len(errores)})",
             not senales_csp(consola[:corte]) and not errores, control_csp,
             f"{senales_csp(consola[:corte])[:3]} {errores[:3]}")


def ultima_secuencia(cabeceras):
    """La secuencia más reciente de la auditoría de la empresa, por la API del
    8443 (la primera fila de /auditoria/recientes)."""
    codigo, _, cuerpo = peticion("GET", "/v1/personal/auditoria/recientes", puerto=PUERTO_API, cabeceras=cabeceras)
    filas = json.loads(cuerpo)["filas"] if codigo == 200 else []
    if not filas:
        raise Parada(f"n) el admin no puede leer la auditoria por la API ({codigo})")
    return filas[0]["secuencia"]


def seccion_n():
    global ULTIMO_PASO
    p("=== n) auditoria en Chromium: menu por rol, emails, paginas, actualizar, verificacion y un email con HTML")
    if not PATRON_SECRETO_TOTP.fullmatch(SECRETO_ADMIN):
        sinc("n) sin el secreto TOTP del admin (i no termino) no se puede probar la auditoria")
        return

    # Preparación por la API del 8443, con el admin (Bearer): más de una
    # página de auditoría, releyendo una denuncia que se asigna (cada lectura
    # deja una fila y releer no cuenta para el tope), y después la cuenta con
    # el email que es HTML, para que su fila quede en la primera página.
    codigo_totp = codigo_tras(SECRETO_ADMIN, ULTIMO_PASO)
    ULTIMO_PASO = int(time.time()) // 30
    codigo, _, cuerpo = peticion("POST", RUTA_SESIONES, puerto=PUERTO_API, datos={
        "empresa": IDENTIFICADOR, "email": EMAIL_ADMIN, "contrasena": CONTRASENA_ADMIN, "codigo_totp": codigo_totp})
    acceso = (json.loads(cuerpo) if codigo == 201 else {}).get("token_acceso")
    if not acceso:
        raise Parada(f"n) el admin no pudo iniciar sesion por la API ({codigo})")
    cabeceras = {"Authorization": f"Bearer {acceso}"}
    codigo, _, cuerpo = peticion("GET", RUTA_YO, puerto=PUERTO_API, cabeceras=cabeceras)
    if codigo != 200:
        raise Parada(f"n) el admin no puede leer su cuenta por la API ({codigo})")
    admin_id = json.loads(cuerpo)["usuario_id"]
    denuncia, _ = crear_denuncia(acceso, "Denuncia para llenar la auditoria.")
    ruta_denuncia = f"/v1/personal/denuncias/{denuncia}"
    codigo, _, _ = peticion("PUT", f"{ruta_denuncia}/asignacion", puerto=PUERTO_API, cabeceras=cabeceras,
                            datos={"usuario_id": admin_id})
    if codigo != 204:
        raise Parada(f"n) el admin no pudo asignarse la denuncia de relleno ({codigo})")
    for _ in range(max(0, FILAS_AUDITORIA_N - ultima_secuencia(cabeceras))):
        codigo, _, _ = peticion("GET", ruta_denuncia, puerto=PUERTO_API, cabeceras=cabeceras)
        if codigo != 200:
            raise Parada(f"n) no se pudo leer la denuncia de relleno ({codigo})")
    codigo, _, cuerpo = peticion("POST", "/v1/personal/usuarios", puerto=PUERTO_API, cabeceras=cabeceras,
                                 datos={"email": EMAIL_XSS, "rol": "instructor"})
    if codigo != 201:
        # Si la API lo rechaza, la suposición (validar_email admite este
        # email) es falsa y la prueba no tiene sentido: se para y se dice.
        raise Parada(f"n) la API no admite el email con HTML ({codigo}): revisar la suposicion de la prueba")
    mutante = main_de_mutante("n", pathlib.Path("src", "app", "auditoria", "auditoria.ts"), MUTANTE_XSS_AUDITORIA,
                              IMAGEN_MUTANTE_XSS_AUDITORIA)

    res = navegador("navegador_n", NAVEGADOR_AUDITORIA,
                    [SPKI_INTERMEDIA, IDENTIFICADOR, EMAIL_ADMIN, CONTRASENA_ADMIN, SECRETO_ADMIN, str(ULTIMO_PASO),
                     EMAIL_AUDITOR_N, EMAIL_INSTRUCTOR_N, EMAIL_OTRA_N, CONTRASENA_NUEVAS, MAIN],
                    {"mutante.js": mutante})
    if res is None:
        sinc("n) no se pudo ejecutar el navegador")
        return
    if "excepcion" in res:
        pasa(False, f"n) el recorrido se interrumpe: {res['excepcion']}")
        p(f"   avisos a la vista en cada pagina: {res.get('avisos_visibles')}")
    ULTIMO_PASO = res.get("ultimo_paso_admin", ULTIMO_PASO)

    # Menú y guard por rol, con el auditor como control.
    pasa(res.get("menu_admin") == MENU_ADMIN and res.get("menu_auditor") == MENU_AUDITOR,
         f"n) el menu del admin y del auditor lleva Auditoria ({res.get('menu_admin')}, {res.get('menu_auditor')})")
    pasa(res.get("menu_instructor") == MENU_INSTRUCTOR, f"n) el del instructor no ({res.get('menu_instructor')})")
    control_guard = (res.get("auditor_url") == {"ruta": "/auditoria", "h1": H1_AUDITORIA}
                     and res.get("api_auditor") == 200)
    pasa(control_guard, f"n) control: el auditor abre /auditoria por su URL y la API le da 200 "
                        f"({res.get('auditor_url')}, {res.get('api_auditor')})")
    negativo(f"n) el instructor vuelve a /inicio y la API le da 403 ({res.get('instructor_url')}, "
             f"{res.get('api_instructor')})",
             res.get("instructor_url") == {"ruta": "/inicio", "h1": H1_INICIO} and res.get("api_instructor") == 403,
             control_guard)

    # Páginas.
    pagina_1, todas = res.get("pagina_1") or [], res.get("todas") or []
    numeros_1 = [int(f[0]) for f in pagina_1 if f and f[0].isdigit()]
    numeros = [int(f[0]) for f in todas if f and f[0].isdigit()]
    control_paginas = (len(pagina_1) == TAMANO_PAGINA_AUDITORIA == len(numeros_1) and res.get("boton_anteriores") == 1
                       and numeros_1 == list(range(numeros_1[0], numeros_1[0] - TAMANO_PAGINA_AUDITORIA, -1)))
    pasa(control_paginas, f"n) la primera pagina son {TAMANO_PAGINA_AUDITORIA} filas, de la mas reciente hacia atras, "
                          f"con 'Cargar anteriores' ({len(pagina_1)}, {numeros_1[:1]})")
    negativo(f"n) 'Cargar anteriores' completa la tabla sin huecos hasta la fila 1 ({res.get('clics')} clics, "
             f"{len(todas)} filas)",
             len(numeros) == len(todas) and numeros == list(range(numeros_1[0] if numeros_1 else 0, 0, -1)),
             control_paginas)
    hecho = res.get("hecho_anteriores") or ""
    pasa(hecho.endswith(TEXTO_PRINCIPIO) and res.get("foco_final") == hecho,
         f"n) al llegar al principio lo dice y el foco va al aviso ({hecho!r}, foco {res.get('foco_final')!r})")
    pasa(all(len(f) == 5 and PATRON_DIA.fullmatch(f[1]) for f in todas),
         "n) cada fila tiene numero, dia (dd/mm/aaaa), quien, que y sobre que")

    # Quién y sobre qué, con emails.
    triples = [f[2:] for f in todas]
    pasa([EMAIL_ADMIN, "Invitación", EMAIL_AUDITOR_N] in triples,
         "n) la invitacion del auditor dice quien la hizo y a quien, por su email")
    pasa(["Plataforma", "Invitación del primer admin", EMAIL_ADMIN] in triples,
         "n) la invitacion del primer admin la hizo la plataforma y dice a quien")
    pasa(any(q == EMAIL_ADMIN and a == "Asignación" and s.startswith("Denuncia ") and s.endswith(f", a {EMAIL_INSTRUCTOR_M}")
             for q, a, s in triples), "n) la asignacion de m dice la denuncia y la cuenta, por su email")
    pasa([EMAIL_ADMIN, "Baja", EMAIL_AUDITOR] in triples, "n) la baja de l dice a quien se dio de baja, por su email")
    sin_traducir = sorted({a for _, a, _ in triples} - NOMBRES_ACCION)
    pasa(bool(triples) and not sin_traducir, f"n) ninguna accion sale sin traducir {sin_traducir if sin_traducir else ''}"
         .rstrip())
    sin_email = [q for q, _, _ in triples if not q or PATRON_UUID.fullmatch(q)]
    pasa(bool(triples) and not sin_email, f"n) quien actua sale siempre con su email o su nombre ({sin_email[:3]})")
    pasa(res.get("enlaces_tabla") == 0, f"n) la tabla no tiene enlaces ({res.get('enlaces_tabla')})")
    pasa(res.get("almacen_auditor") == [0, 0], f"n) nada va al almacenamiento ({res.get('almacen_auditor')})")

    # Actualizar y verificar.
    tras = res.get("tras_actualizar") or [[""] * 5]
    nueva = tras[0]
    pasa(len(tras) == TAMANO_PAGINA_AUDITORIA and nueva[2:] == [EMAIL_ADMIN, "Invitación", EMAIL_OTRA_N]
         and numeros_1 and int(nueva[0]) > numeros_1[0]
         and res.get("actualizada") == f"Auditoría actualizada: la fila más reciente es la nº {nueva[0]}.",
         f"n) 'Actualizar' vuelve a la primera pagina con la fila nueva arriba ({res.get('actualizada')!r}, {nueva})")
    pasa(res.get("foco_actualizar") == "Actualizar",
         f"n) y el foco sigue en el boton ({res.get('foco_actualizar')!r})")
    pasa(res.get("cadena") == TEXTO_CADENA_INTACTA, f"n) la verificacion dice que la cadena esta intacta "
                                                   f"({res.get('cadena')!r})")
    pasa(res.get("h1_admin") == H1_AUDITORIA and (res.get("admin_primera") or [[""] * 5])[0][2:]
         == [EMAIL_ADMIN, "Invitación", EMAIL_OTRA_N],
         f"n) el admin la ve igual, con su ultima accion arriba ({res.get('admin_primera')})")

    # El email con HTML, con el mutante como control.
    control_xss = (res.get("mutante") or 0) >= 1 and bool(res.get("mutante_csp"))
    pasa(control_xss, f"n) control: con [innerHTML], el email crea un <img> aunque la CSP siga puesta y bloquee su "
                      f"carga ({res.get('mutante')}, {(res.get('mutante_csp') or [''])[0][:120]!r})")
    como_texto = res.get("email_como_texto") or {}
    negativo(f"n) el email sale como texto literal, sin crear ningun elemento ni ejecutar nada "
             f"({como_texto.get('hijos')}, {como_texto.get('peligrosos')}, {como_texto.get('bandera')})",
             como_texto.get("celdas") == [EMAIL_XSS] and como_texto.get("hijos") == 0
             and como_texto.get("peligrosos") == 0 and como_texto.get("bandera") == "undefined", control_xss,
             f"celdas {como_texto.get('celdas')}")

    # Consola.
    consola, errores = res.get("consola") or [], res.get("errores") or []
    corte = res.get("consola_antes_del_control", len(consola))
    control_csp = bool(senales_csp(consola[corte:]))
    pasa(control_csp, f"n) control: el mutante y una conexion a otro origen dejan su violacion de la CSP "
                      f"({senales_csp(consola[corte:])[:1]})")
    negativo(f"n) en todo el recorrido, ninguna violacion de la CSP ni error de JavaScript "
             f"({len(senales_csp(consola[:corte]))}, {len(errores)})",
             not senales_csp(consola[:corte]) and not errores, control_csp,
             f"{senales_csp(consola[:corte])[:3]} {errores[:3]}")


def ids_paginados(cabeceras):
    """Los ids de todas las denuncias que ve el admin, página a página por la
    API del 8443: el oráculo de "Cargar más", que no pasa por la SPA."""
    ids, cursor = [], None
    for _ in range(20):
        ruta = "/v1/personal/denuncias"
        if cursor is not None:
            ruta += "?cursor=" + urllib.parse.quote(cursor, safe="")
        codigo, _, cuerpo = peticion("GET", ruta, puerto=PUERTO_API, cabeceras=cabeceras)
        if codigo != 200:
            raise Parada(f"o) el admin no puede listar las denuncias por la API ({codigo})")
        pagina = json.loads(cuerpo)
        ids += [d["denuncia_id"] for d in pagina["denuncias"]]
        cursor = pagina["siguiente"]
        if cursor is None:
            return ids
    raise Parada("o) el listado de denuncias de la API no termina en 20 paginas")


def seccion_o():
    global ULTIMO_PASO
    p("=== o) botones ocupados en Chromium: el foco tras un login fallido, el doble clic y 'Cargar mas' hasta el final")
    if not PATRON_SECRETO_TOTP.fullmatch(SECRETO_ADMIN):
        sinc("o) sin el secreto TOTP del admin (i no termino) no se pueden probar los botones")
        return

    # Preparación por la API del 8443: una página entera de denuncias más,
    # como un denunciante, y la lista completa que ve el admin (Bearer).
    codigo_totp = codigo_tras(SECRETO_ADMIN, ULTIMO_PASO)
    ULTIMO_PASO = int(time.time()) // 30
    codigo, _, cuerpo = peticion("POST", RUTA_SESIONES, puerto=PUERTO_API, datos={
        "empresa": IDENTIFICADOR, "email": EMAIL_ADMIN, "contrasena": CONTRASENA_ADMIN, "codigo_totp": codigo_totp})
    acceso = (json.loads(cuerpo) if codigo == 201 else {}).get("token_acceso")
    if not acceso:
        raise Parada(f"o) el admin no pudo iniciar sesion por la API ({codigo})")
    for i in range(DENUNCIAS_O):
        codigo, _, _ = peticion("POST", f"/v1/empresas/{IDENTIFICADOR}/denuncias", puerto=PUERTO_API,
                                datos={"categoria": "fraude", "texto": f"Denuncia {i + 1} para la segunda pagina."})
        if codigo != 201:
            raise Parada(f"o) no se pudo crear la denuncia de relleno {i + 1} ({codigo})")
    visibles = ids_paginados({"Authorization": f"Bearer {acceso}"})
    entrar = pathlib.Path("src", "app", *FICHERO_ENTRAR.split("/"))
    mutante_foco = main_de_mutante("o", entrar, MUTANTE_DISABLED, IMAGEN_MUTANTE_FOCO)
    mutante_guarda = main_de_mutante("o", entrar, MUTANTE_GUARDA, IMAGEN_MUTANTE_GUARDA)

    res = navegador("navegador_o", NAVEGADOR_BOTONES,
                    [SPKI_INTERMEDIA, IDENTIFICADOR, EMAIL_ADMIN, CONTRASENA_ADMIN, SECRETO_ADMIN, str(ULTIMO_PASO),
                     EMAIL_SIN_CUENTA, MAIN],
                    {"foco.js": mutante_foco, "guarda.js": mutante_guarda})
    if res is None:
        sinc("o) no se pudo ejecutar el navegador")
        return
    if "excepcion" in res:
        pasa(False, f"o) el recorrido se interrumpe: {res['excepcion']}")
        p(f"   avisos a la vista en cada pagina: {res.get('avisos_visibles')}")
    ULTIMO_PASO = res.get("ultimo_paso_admin", ULTIMO_PASO)

    # El foco tras un login fallido con Enter, con el mutante con disabled
    # como control.
    boton = ["BUTTON", "Entrar"]
    real, mutado = res.get("foco_real") or {}, res.get("foco_mutante") or {}
    control_foco = mutado.get("antes") == boton and mutado.get("despues") == ["BODY", ""]
    pasa(control_foco, f"o) control: con disabled, tras un login fallido con Enter el foco acaba en el <body> "
                       f"({mutado.get('antes')}, {mutado.get('despues')})")
    negativo(f"o) con aria-disabled, el foco sigue en 'Entrar' ({real.get('antes')}, {real.get('despues')})",
             real.get("antes") == boton and real.get("despues") == boton, control_foco)
    pasa(real.get("alerta") == ALERTA_LOGIN, f"o) el fallo se anuncia con role=alert ({real.get('alerta')!r})")

    # El doble clic, con el mutante sin la guarda como control.
    control_guarda = res.get("doble_clic_mutante") == 2
    pasa(control_guarda, f"o) control: sin la guarda, un doble clic en 'Entrar' hace dos peticiones "
                         f"({res.get('doble_clic_mutante')})")
    negativo(f"o) un doble clic en 'Entrar' hace una sola peticion ({res.get('doble_clic')}; con un clic, "
             f"{res.get('un_clic')})",
             res.get("doble_clic") == 1 and res.get("un_clic") == 1, control_guarda)

    # "Cargar más" hasta el final, contra la lista de la API.
    if len(visibles) <= TAMANO_PAGINA_DENUNCIAS:
        sinc(f"o) el admin ve {len(visibles)} denuncias: no hay segunda pagina que cargar")
    else:
        primera, todas = res.get("primera") or [], res.get("todas") or []
        control_paginas = primera == visibles[:TAMANO_PAGINA_DENUNCIAS] and res.get("boton") == 1
        pasa(control_paginas, f"o) control: la primera pagina son las {TAMANO_PAGINA_DENUNCIAS} primeras de la API, "
                              f"con 'Cargar mas' ({len(primera)}, {res.get('boton')})")
        negativo(f"o) 'Cargar mas' completa la lista con las mismas {len(visibles)} filas que la API, sin repetir "
                 f"({res.get('pulsaciones')} pulsaciones, {len(todas)} filas)",
                 todas == visibles, control_paginas)
        ultima = len(visibles) - TAMANO_PAGINA_DENUNCIAS * ((len(visibles) - 1) // TAMANO_PAGINA_DENUNCIAS)
        cargadas = "Se ha cargado 1 denuncia más." if ultima == 1 else f"Se han cargado {ultima} denuncias más."
        esperado = f"{cargadas} {TEXTO_FINAL_LISTA}"
        pasa(res.get("hecho") == esperado and res.get("foco_final") == ["P", esperado] and res.get("boton_final") == 0,
             f"o) al final lo dice, el boton desaparece y el foco va al aviso ({res.get('hecho')!r}, "
             f"foco {res.get('foco_final')})")

    # Consola.
    consola, errores = res.get("consola") or [], res.get("errores") or []
    corte = res.get("consola_antes_del_control", len(consola))
    control_csp = bool(senales_csp(consola[corte:]))
    pasa(control_csp, f"o) control: una conexion a otro origen deja su violacion de la CSP ({senales_csp(consola[corte:])[:1]})")
    negativo(f"o) en todo el recorrido, ninguna violacion de la CSP ni error de JavaScript "
             f"({len(senales_csp(consola[:corte]))}, {len(errores)})",
             not senales_csp(consola[:corte]) and not errores, control_csp,
             f"{senales_csp(consola[:corte])[:3]} {errores[:3]}")


def seccion_p():
    global ULTIMO_PASO
    p("=== p) la fuente y el tema oscuro en Chromium, y la SPA a 320 px sin desbordar")
    if not PATRON_SECRETO_TOTP.fullmatch(SECRETO_ADMIN):
        sinc("p) sin el secreto TOTP del admin (i no termino) no se pueden mirar sus paginas")
        return
    res = navegador("navegador_p", NAVEGADOR_ESTETICA,
                    [SPKI_INTERMEDIA, IDENTIFICADOR, EMAIL_ADMIN, CONTRASENA_ADMIN, SECRETO_ADMIN, str(ULTIMO_PASO),
                     json.dumps(RUTAS_ANCHO)])
    if res is None:
        sinc("p) no se pudo ejecutar el navegador")
        return
    if "excepcion" in res:
        pasa(False, f"p) el recorrido se interrumpe: {res['excepcion']}")
        p(f"   avisos a la vista en cada pagina: {res.get('avisos_visibles')}")
    ULTIMO_PASO = res.get("ultimo_paso_admin", ULTIMO_PASO)

    pasa(res.get("fuentes") == FUENTES_ESPERADAS,
         f"p) la pagina usa una sola fuente, Geist, y esta cargada ({res.get('fuentes')})")

    # El tema: el fondo en claro es el control de que se lee el de la hoja.
    control_tema = res.get("fondo_claro") == FONDO_CLARO
    pasa(control_tema, f"p) control: con el sistema en claro, el fondo es el del claro ({res.get('fondo_claro')!r})")
    negativo(f"p) con el sistema en oscuro, el fondo es el del oscuro ({res.get('fondo_oscuro')!r})",
             res.get("fondo_oscuro") == FONDO_OSCURO, control_tema)

    # La barra separa el email del rol: Angular quita los espacios entre
    # elementos y salían pegados.
    pasa(res.get("quien") == f"{EMAIL_ADMIN} {NOMBRE_ROL_ADMIN}",
         f"p) la barra separa el email del rol ({res.get('quien')!r})")

    # 320 px, con un elemento de 400 px como control.
    ancho_control = res.get("ancho_control") or [0, 0]
    control_ancho = ancho_control[0] > ancho_control[1] > 0
    pasa(control_ancho, f"p) control: un elemento de 400 px desborda a 320 px ({ancho_control})")
    anchos = res.get("anchos") or {}
    anchas = {r: a for r, a in anchos.items() if not 0 < a[0] <= a[1]}
    mirar = ["/entrar", *RUTAS_ANCHO]
    negativo(f"p) a 320 px ninguna pagina desborda en horizontal ({len(anchos)} de {len(mirar)}) "
             f"{anchas if anchas else ''}".rstrip(),
             sorted(anchos) == sorted(mirar) and not anchas, control_ancho, f"{anchos}")

    # Consola.
    consola, errores = res.get("consola") or [], res.get("errores") or []
    corte = res.get("consola_antes_del_control", len(consola))
    control_csp = any("font-src" in m for m in senales_csp(consola[corte:]))
    pasa(control_csp, f"p) control: una fuente de otro origen deja su violacion de font-src "
                      f"({senales_csp(consola[corte:])[:1]})")
    negativo(f"p) en todo el recorrido, ninguna violacion de la CSP ni error de JavaScript "
             f"({len(senales_csp(consola[:corte]))}, {len(errores)})",
             not senales_csp(consola[:corte]) and not errores, control_csp,
             f"{senales_csp(consola[:corte])[:3]} {errores[:3]}")


# ---------------------------------------------------------------------------
# Limpieza, precondiciones y arranque
# ---------------------------------------------------------------------------
def limpiar():
    unitarios = [f"{IMAGEN_MUTANTE}_unitario_{i}" for i in range(1, len(MUTANTES_UNITARIOS) + 1)]
    ejecutar(["docker", "image", "rm", "-f", IMAGEN_MUTANTE, IMAGEN_MUTANTE_XSS, IMAGEN_MUTANTE_XSS_AUDITORIA,
              IMAGEN_MUTANTE_FOCO, IMAGEN_MUTANTE_GUARDA, IMAGEN_PRUEBAS, *unitarios])
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
    # Los límites de prueba, solo para la API de este proyecto temporal: el
    # fichero vive en el directorio temporal y docker-compose.yml no cambia.
    limites = TEMPORAL / "limites_prueba.yml"
    limites.write_text(f"services:\n  api:\n    environment:\n      CANARIO_LIMITES: \"{LIMITES_PRUEBA}\"\n",
                       encoding="utf-8", newline="\n")
    BASE.extend(["-f", str(limites)])
    parada = None
    try:
        for seccion in (seccion_a, seccion_b, seccion_c_e, seccion_d, seccion_f, seccion_g, seccion_h, seccion_i,
                        seccion_j, seccion_k, seccion_l, seccion_m, seccion_n, seccion_o, seccion_p):
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
