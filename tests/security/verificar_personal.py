#!/usr/bin/env python3
"""Batería de pruebas de seguridad de la identidad del personal (bloque 4a).

Código probado: app/personal.py, app/rutas_personal.py, app/cripto.py (TOTP y
tokens), app/gestion.py (alta-admin y reinvitar-admin), la regla acceso de app/limitador.py y
las tablas del personal de db/init/02_esquema.sql (docs/threat-model.md, 6.3
y 6.9). Qué prueba:

* Alta del primer admin por gestion: solo sin admins activados, con una fila
  de auditoría de plataforma; después se niega.
* Activación: política de contraseñas, secreto TOTP con su URI, confirmación
  con un código, invitación de un solo uso, caducada o de otra empresa, y que
  en la base de datos solo hay Argon2id con los parámetros de OWASP, el
  secreto cifrado y el SHA-256 de cada token.
* Login: el mismo 401, byte a byte, para empresa inexistente o mal formada,
  email inexistente, contraseña o código erróneos, cuenta sin activar o dada
  de baja; tiempos comparables (con control de sensibilidad); un código TOTP
  solo vale una vez; cada login fallido deja un EVENTO login_fallido sin el
  email (ASVS 5.0.0, 16.3.1).
* Bloqueo sin denegación de servicio: los fallos sin dispositivo de confianza
  bloquean ese camino con esperas crecientes, y el titular sigue entrando con
  su dispositivo; los fallos con el dispositivo bloquean solo el dispositivo;
  20 lo retiran; 100 cierran el camino sin confianza hasta una reinvitación;
  un acierto con el dispositivo no reinicia el contador del otro camino;
  peticiones simultáneas no consiguen intentos extra.
* Sesiones: JWT de acceso Bearer obligatorio, con su forma exacta. Forjados
  con la clave falsa de la ejecución (control: uno bien formado se acepta),
  dan 401 los de alg none, typ JWT, kid, otra clave, caducados, de una hora,
  con aud o iss ajenos, con un rol, con un sid inexistente o de otra cuenta y
  con la empresa B. La renovación rota, y reutilizar una gastada revoca la
  sesión entera y deja un EVENTO; 15 minutos sin renovar, 8 horas en total y
  el tope de renovaciones dan 401; cerrar la sesión corta su JWT vivo al
  momento; empresa inactiva y renovación con el identificador de B.
* Administración: un instructor recibe 403; una cuenta de otra empresa da el
  mismo 404 que una inexistente; email duplicado 409; la baja del último
  admin 409; el cambio de contraseña revoca todas las sesiones, también la
  actual, y los demás dispositivos, y devuelve tokens nuevos (ASVS 7.2.4);
  la auditoría registra cada acción y su cadena es válida.
* Recuperación: una reinvitación se ve (invitacion_pendiente en /yo y en la
  lista) y un admin puede anularla; reinvitar-admin solo actúa sobre un admin
  activado de esa empresa, revoca en el acto su acceso (la sesión anterior ya
  no puede anular la recuperación) y el único admin de una empresa recupera
  su cuenta.
* Gestion: la verificación de la base de datos y la resolución del
  identificador corren en solo lectura y REPEATABLE READ, con el código real
  y preguntando a PostgreSQL; sus transacciones de escritura son el control.
* Instrucción (app/instruccion.py): el contenido de una denuncia solo lo lee
  quien la tiene asignada (también un admin: arts. 32.1 y 8.5 de la Ley
  2/2023); una denuncia ajena, inexistente o de otra empresa da el mismo 404
  byte a byte; solo un admin asigna, y solo a cuentas activas; la tabla de
  transiciones completa contra un oráculo literal; cerrar exige un mensaje
  final y deja la denuncia sin más mensajes; 'inadmitida' es un cierre; el
  denunciante ve los mensajes del personal sin saber quién los escribió; la
  cuenta de quien actúa se bloquea con FOR KEY SHARE (un login fallido no la
  retrasa, una baja sí) y una denuncia ajena no se bloquea nunca (con el SQL
  real, dentro de la API); una baja confirmada mientras la acción espera la
  deja sin actuar; cierre y mensaje simultáneos sin interbloqueo; la
  auditoría registra cada acción, con destino en la asignación, y los admins
  la leen por la API y verifican la cadena aparte; asignar dos veces a la
  misma cuenta no deja otra fila; el listado pagina sin huecos ni
  repeticiones.
* No veraz (art. 32.3): solo la declara un admin con la denuncia asignada,
  desde cualquier estado visible y sin mensaje (403 instructor, 404 sin
  asignación, 422 con mensaje); después no existe para nadie (el mismo 404
  para el personal y el denunciante, fuera del listado), deja su fila de
  auditoría y un EVENTO por declaración, y gestion suprimir-caducadas la
  destruye con sus mensajes y su código (art32_3) sin tocar el control.
* Redacción (art. 32.2): solo la hace un admin con la denuncia asignada (403
  instructor, 404 sin asignación, de otra empresa, no veraz o mensaje
  inexistente); cada tramo exige el texto exacto en su posición, y la
  posición contada en UTF-16 da 409 sin tachar nada desplazado; un tramo
  malo anula los demás; la forma inválida da 422. El personal y el
  denunciante leen el texto tachado exacto, queda una fila por redacción y un
  EVENTO con posiciones y longitudes, y tachar lo ya tachado no escribe nada.
  Cada 403 y 404 deja exactamente un EVENTO acceso_denegado (ASVS 5.0.0,
  16.3.2) con la plantilla de la ruta y el id solo si es un uuid; los 409,
  los 422 y las redacciones aceptadas no dejan ninguno, y un %0A en el id no
  inyecta ninguna línea.
* Rol auditor: un admin lo invita; lee la auditoría y verifica su cadena sin
  dejar filas; recibe 403 al listar, leer, escribir, cambiar de estado,
  asignar o redactar una denuncia, y al administrar cuentas o solicitudes,
  sin cambiar nada (control: el instructor asignado lee la denuncia); y no se
  le puede asignar una denuncia (409, sin fila; control: a un instructor sí).
* Tope de lecturas (app/instruccion.py), con sus valores de producción (20 y
  50): cada denuncia nueva suma y releer no; la vigésima y la quincuagésima
  dejan un EVENTO con la cuenta y sin ids, una sola vez; doce lecturas
  simultáneas con diez plazas dan exactamente diez 200 y dos 429; pasado el
  tope, una nueva da 429 con su mensaje y Retry-After hasta la medianoche de
  la empresa, sin fila; releer sigue permitido y otra cuenta no se ve
  afectada; un intento de aviso por cada admin y auditor (sin Mailpit, su
  EVENTO correo_fallido). Si el día de la empresa cambia a mitad, SIN
  CONCLUSION.
* Regla acceso del limitador con los límites de producción, y 503 sin Redis
  sin contar ningún intento. Regla cuenta (segunda capa, por identidad): la
  misma cuenta desde dos IPs agota su límite, otra cuenta desde la misma IP
  no; un token que no vale no consume el de ninguna cuenta; el primer
  exceso deja un único evento sin IP.
* Ni contraseñas, ni tokens, ni secretos TOTP, ni textos o códigos de
  denuncias en los logs ni en el volcado de la base de datos.

Cada prueba negativa lleva su control positivo: si el control falla, el
resultado es SIN CONCLUSION, nunca PASA. Los oráculos son literales; el TOTP
de la batería es una implementación propia, comprobada antes con los
vectores del RFC 6238 (apéndice B).

Cómo se ejecuta (desde la raíz del repositorio, en PowerShell, con Docker en
marcha y los secretos generados con scripts/generar_secretos.py):

    python tests/security/verificar_personal.py

Usa un proyecto de Docker propio (canario_personal) y levanta postgres, redis,
api y caddy, más ejecuciones sueltas de gestion. Necesita que el proyecto
canario y las otras baterías estén parados (las subredes de app y edge son
fijas). Al terminar lo borra todo (down -v y las imágenes construidas).
Claves de cifrado y secretos de Redis FALSOS, generados en cada ejecución,
como en tests/security/verificar_denuncia.py; de secrets/ solo se usan las
contraseñas de los roles, sin leerlas.

La salida completa se guarda en verificacion_personal.txt dentro del
directorio temporal del sistema. El código de salida es 0 solo si el
resultado global es OK. Solo usa la biblioteca estándar.
"""
import base64
import concurrent.futures
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
import uuid

RAIZ = pathlib.Path.cwd()
PROYECTO = "canario_personal"
SALIDA = pathlib.Path(tempfile.gettempdir()) / "verificacion_personal.txt"
BASE = ["docker", "compose", "-p", PROYECTO, "-f", "docker-compose.yml"]
BASE_PRODUCCION = []
CONTRASENAS_REDIS = {}
# Claves falsas de esta ejecución: con la de firma, la batería forja JWT.
CLAVES_FALSAS = {}
# JWT y renovaciones emitidos: la sección i) comprueba que no salen en los logs.
TOKENS_EMITIDOS = []

lineas_salida = []
estado = {"falla": False, "sin_conclusion": False}

# ---------------------------------------------------------------------------
# Oráculos literales
# ---------------------------------------------------------------------------
SUBREDES_FIJAS = {"10.88.0.0/28", "10.88.1.0/28"}
TEXTO_VERIFICADO = "ARRANQUE VERIFICADO"
TEXTO_BLOQUEADO = "ARRANQUE BLOQUEADO: "
PERMISOS_ACL_APLICACION = ("resetkeys ~limite:* resetchannels -@all "
                           "+ping +multi +exec +incr +expire +ttl +client|setinfo")
PERMISOS_ACL_INSPECTOR = "resetkeys ~* resetchannels -@all +ping +scan +get +pttl +dbsize +client|setinfo"
LIMITES_PRUEBA = ("denuncia=1000/3600,seguimiento=1000/60,mensajes=1000/3600,acceso=1000/300,otras=1000/60,"
                  "cuenta=1000/60,registro=1000/3600,destinatario=1000/900,destinatario_dia=1000/86400")
TEXTO_LIMITES_PRUEBA = ("LIMITES (configurados): acceso=1000/300 cuenta=1000/60 denuncia=1000/3600 "
                        "destinatario=1000/900 destinatario_dia=1000/86400 mensajes=1000/3600 otras=1000/60 registro=1000/3600 "
                        "seguimiento=1000/60")
TEXTO_LIMITES_PRODUCCION = ("LIMITES (por defecto): acceso=10/300 cuenta=60/60 denuncia=10/3600 destinatario=3/900 "
                            "destinatario_dia=10/86400 mensajes=30/3600 otras=60/60 registro=10/3600 seguimiento=60/60")
LIMITE_ACCESO = (10, 300)
LIMITE_CUENTA = (60, 60)
TEXTO_EVENTO_CUENTA = "EVENTO limite_cuenta: "
IP_CLIENTE_A = "10.88.1.3"
IP_CLIENTE_B = "10.88.1.4"

PATRON_ALTA = re.compile(r"empresa creada: empresa_id=([0-9a-f-]{36}) identificador_publico=([0-9a-f]{32})")
PATRON_INVITACION_GESTION = re.compile(r"invitacion creada: empresa_id=([0-9a-f-]{36}) usuario_id=([0-9a-f-]{36})\n"
                                       r"token_invitacion=([0-9a-f]{32}\.[A-Za-z0-9_-]{43})\n")
TEXTO_YA_HAY_ADMIN = "ERROR: la empresa ya tiene un admin activo: las cuentas las gestionan sus admins"
# Un token del personal: identificador de empresa, punto y 256 bits en base64url.
PATRON_TOKEN_COMPUESTO = r"[0-9a-f]{32}\.[A-Za-z0-9_-]{43}"
PATRON_TOKEN = r"[A-Za-z0-9_-]{43}"
PATRON_SECRETO_TOTP = r"[A-Z2-7]{32}"

# Respuestas, literales (app/rutas_personal.py y app/frontera_http.py).
CUERPO_401_CREDENCIALES = '{"detalle": "credenciales no válidas"}'.encode()
CUERPO_401_SESION = '{"detalle": "sesión no válida"}'.encode()
CUERPO_401_INVITACION = '{"detalle": "invitación no válida"}'.encode()
CUERPO_422_CODIGO = '{"detalle": "código no válido"}'.encode()
CUERPO_422_CORTA = '{"detalle": "la contraseña debe tener entre 12 y 128 caracteres"}'.encode()
CUERPO_422_CONTIENE = '{"detalle": "la contraseña no puede contener el email ni el nombre de la empresa"}'.encode()
CUERPO_422 = '{"detalle": "petición no válida"}'.encode()
CUERPO_403 = b'{"detalle": "permiso denegado"}'
# Tope de lecturas (app/instruccion.py): literales, no leídos del código.
LECTURAS_AVISO = 20
LECTURAS_TOPE = 50
CUERPO_429_LECTURAS = ('{"detalle": "ha abierto hoy el máximo de 50 denuncias distintas; '
                       'puede seguir con las que ya abrió y abrir otras mañana"}').encode()
TEXTO_EVENTO_LECTURAS = "EVENTO limite_lecturas_"
TEXTO_CORREO_LECTURAS = "EVENTO correo_fallido: tipo=aviso_lecturas "
CUERPO_404 = b'{"detalle": "recurso no encontrado"}'
CUERPO_409_DUPLICADO = b'{"detalle": "ya existe una cuenta con ese email"}'
CUERPO_409_ULTIMO = '{"detalle": "la empresa se quedaría sin ningún admin activo"}'.encode()
CUERPO_429 = '{"detalle": "demasiadas peticiones; inténtelo de nuevo más tarde"}'.encode()
CUERPO_503_OCUPADO = '{"detalle": "servicio ocupado; inténtelo de nuevo en unos segundos"}'.encode()
REINTENTAR_TRAS = "5"
CLAVES_ACTIVACION = ["secreto_totp", "uri_totp"]
CLAVES_LOGIN = ["expira_en", "token_acceso", "token_dispositivo", "token_renovacion"]
CLAVES_TOKENS = ["expira_en", "token_acceso", "token_renovacion"]
# JWT de acceso (app/tokens.py), literales.
CABECERA_JWT = {"alg": "HS256", "typ": "canario-acceso+jwt"}
CLAIMS_JWT = ["aud", "emp", "exp", "iat", "iss", "sid", "sub"]
DURACION_ACCESO = 300
LONGITUD_JWT = 377
TOPE_RENOVACIONES = 256
TEXTO_EVENTO_REUTILIZACION = "EVENTO reutilizacion_renovacion: "
TEXTO_EVENTO_LOGIN_FALLIDO = "EVENTO login_fallido: "
# Una sesión de la batería renueva su acceso al construir una petición si
# tiene más de 4 minutos: el acceso dura 5 y algunas secciones tardan más.
RENOVAR_TRAS = 240
CLAVES_YO = ["email", "invitacion_pendiente", "rol", "usuario_id"]
CLAVES_USUARIO = ["activado", "activo", "camino_sin_confianza_cerrado", "email", "en_espera", "invitacion_pendiente",
                  "rol", "usuario_id"]
TEXTO_SEGUNDO_ADMIN = ("recomendacion: cuando este admin active su cuenta, que invite a un segundo admin; "
                       "con dos, uno recupera al otro sin pasar por la plataforma")
TEXTO_NO_ES_ADMIN = ("ERROR: no hay ningun admin activado con ese email en la empresa "
                     "(primer admin: alta-admin; instructores: los reinvita su admin)")

# Instrucción (app/instruccion.py y app/rutas_personal.py), literales.
CUERPO_409_TRANSICION = b'{"detalle": "la denuncia no puede pasar a ese estado desde el actual"}'
CUERPO_409_CERRADA = '{"detalle": "la denuncia está cerrada"}'.encode()
CUERPO_409_CERRADA_DENUNCIANTE = '{"detalle": "la denuncia está cerrada y no admite mensajes"}'.encode()
CUERPO_409_DESTINO = '{"detalle": "la cuenta de destino no está activa o no instruye denuncias"}'.encode()
CUERPO_422_FINAL = b'{"detalle": "cerrar una denuncia exige un mensaje final para el denunciante"}'
ESTADOS = ["nueva", "en_instruccion", "resuelta", "archivada", "inadmitida"]
# Los destinos de un instructor (k5). 'no_veraz' es solo de admin y va en k10.
ESTADOS_DESTINO = ["en_instruccion", "resuelta", "archivada", "inadmitida"]
TRANSICIONES_ESPERADAS = {("nueva", "en_instruccion"), ("nueva", "inadmitida"),
                          ("en_instruccion", "resuelta"), ("en_instruccion", "archivada")}
# Art. 32.3: desde cualquier estado visible, incluidos los cerrados.
TRANSICIONES_NO_VERAZ = {("nueva", "no_veraz"), ("en_instruccion", "no_veraz"), ("resuelta", "no_veraz"),
                         ("archivada", "no_veraz"), ("inadmitida", "no_veraz")}
CUERPO_422_NO_VERAZ = b'{"detalle": "declarar una denuncia no veraz no admite mensaje"}'
CUERPO_404_CODIGO = '{"detalle": "código de seguimiento no válido"}'.encode()
TEXTO_EVENTO_NO_VERAZ = "EVENTO declaracion_no_veraz: "
# Redaccion (k11). Posiciones contadas a mano (en caracteres, es decir, code
# points): "diabetes" empieza en el 32; en UTF-16, como contaria un navegador,
# en el 33, porque el emoji ocupa dos unidades. "Pepe" empieza en el 27.
REDACCION_TEXTO = "Mi jefe \U0001F600 me acosa porque tengo diabetes; lo vio Ana."
REDACCION_TEXTO_TACHADO = "Mi jefe \U0001F600 me acosa porque tengo ████████; lo vio Ana."
REDACCION_FRAGMENTO = "diabetes"
REDACCION_DESDE = 32
REDACCION_DESDE_UTF16 = 33
REDACCION_MENSAJE = "Soy de Valencia y me llamo Pepe"
REDACCION_MENSAJE_TACHADO = "Soy de Valencia y me llamo ████"
REDACCION_DESDE_MENSAJE = 27
TEXTO_EVENTO_REDACCION = "EVENTO redaccion: "
TEXTO_EVENTO_ACCESO = "EVENTO acceso_denegado: "
# Un id de denuncia con un salto de linea codificado: si llegara tal cual al
# log, escribiria una linea "EVENTO redaccion" falsa.
ID_CON_SALTO = "x%0AEVENTO%20redaccion:%20falso"
CUERPO_409_FRAGMENTO = '{"detalle": "el texto indicado no está en esa posición"}'.encode()
CLAVES_LISTADO = ["denuncias", "siguiente"]
CLAVES_FILA_DENUNCIA = ["asignada_a", "asignada_activa", "denuncia_id", "estado", "fecha"]
CLAVES_EXPEDIENTE = ["categoria", "denuncia_id", "estado", "fecha", "lecturas", "mensajes", "texto"]
CLAVES_MENSAJE_PERSONAL = ["autor", "autor_id", "fecha", "secuencia", "texto"]
CLAVES_MENSAJE_SEGUIMIENTO = ["autor", "fecha", "secuencia", "texto"]
CLAVES_AUDITORIA = ["filas", "siguiente"]
CLAVES_VERIFICACION = ["cadena_intacta", "primera_rota"]
CLAVES_FILA_AUDITORIA = ["accion", "actor", "destino_id", "fecha", "objeto_id", "secuencia"]
TAMANO_PAGINA_DENUNCIAS = 100
# Textos y códigos de las denuncias de la sección k: no deben aparecer en
# los logs ni en el volcado (sección i).
TEXTOS_SENSIBLES = {}

# Argon2id con los parámetros de OWASP (m=19 MiB, t=2, p=1).
PREFIJO_ARGON2 = "$argon2id$v=19$m=19456,t=2,p=1$"
# Formato 1 + nonce 12 + secreto 20 + tag 16.
TAMANO_SECRETO_CIFRADO = 49
# Huellas de los tokens: SHA-256(etiqueta || 32 bytes) (docs/threat-model.md, 6.3).
ETIQUETAS = {"invitacion": b"canario/invitacion/v1", "dispositivo": b"canario/dispositivo/v1",
             "renovacion": b"canario/renovacion/v1"}
# Bloqueo (app/personal.py): esperas tras el fallo n (n >= 5) de 2^(n-5)
# minutos con tope de 60; tope de 20 fallos por dispositivo y 100 sin confianza.
ESPERA_TRAS = {5: 1, 6: 2, 8: 8, 10: 32, 11: 60, 30: 60}
TOPE_DISPOSITIVO = 20
TOPE_SIN_CONFIANZA = 100
EVENTOS = {"espera_sin_confianza": "EVENTO espera_sin_confianza: ",
           "cierre_sin_confianza": "EVENTO cierre_sin_confianza: ",
           "espera_dispositivo": "EVENTO espera_dispositivo: ",
           "retirada_dispositivo": "EVENTO retirada_dispositivo: "}
ACCIONES_AUDITADAS = {"invitacion_admin_plataforma", "activacion", "acceso", "invitacion", "baja",
                      "cambio_contrasena"}

# RFC 6238, apéndice B (SHA-1, 8 dígitos, secreto ASCII "12345678901234567890").
RFC6238_SECRETO = b"12345678901234567890"
RFC6238_VECTORES = {59: "94287082", 1111111109: "07081804", 1111111111: "14050471", 1234567890: "89005924",
                    2000000000: "69279037", 20000000000: "65353130"}

# Cliente HTTP de prueba: corre con la imagen de la API, directo a la API (red
# app) o a través de Caddy (red edge, TLS). Mide cada petición en
# milisegundos y puede lanzar copias simultáneas de una petición
# ("paralelo") o un grupo de peticiones distintas a la vez ("grupo").
CLIENTE_HTTP = r'''
import base64, concurrent.futures, http.client, json, socket, ssl, sys, time

def una(pt):
    conexion = None
    try:
        if pt.get("tls"):
            contexto = ssl.create_default_context()
            contexto.check_hostname = False
            contexto.verify_mode = ssl.CERT_NONE
            crudo = socket.create_connection((pt["host"], pt["puerto"]), timeout=30)
            conexion = http.client.HTTPConnection("localhost", pt["puerto"], timeout=30)
            conexion.sock = contexto.wrap_socket(crudo, server_hostname="localhost")
        else:
            conexion = http.client.HTTPConnection(pt["host"], pt["puerto"], timeout=30)
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
        # Solo el tipo: el mensaje de algunas excepciones de http.client
        # puede llevar parte de la respuesta. El método y la ruta van aquí
        # porque con "paralelo" o "grupo" una petición da varias respuestas.
        return {"error": type(error).__name__, "metodo": pt["metodo"], "ruta": pt["ruta"]}
    finally:
        if conexion is not None:
            conexion.close()

salida = []
for pt in json.load(sys.stdin):
    if pt.get("grupo"):
        with concurrent.futures.ThreadPoolExecutor(len(pt["grupo"])) as grupo:
            salida.extend(grupo.map(una, pt["grupo"]))
    elif pt.get("paralelo"):
        with concurrent.futures.ThreadPoolExecutor(pt["paralelo"]) as grupo:
            salida.extend(grupo.map(una, [pt] * pt["paralelo"]))
    else:
        salida.append(una(pt))
print(json.dumps(salida))
'''

# Se ejecuta dentro de la API, con el código real: TOTP frente a los vectores
# de RFC 6238 y la lectura estricta de tokens.
CRIPTO_DENTRO = f"""
import json
from app import cripto
s = {RFC6238_SECRETO!r}
res = {{"rfc6238": {{str(t): cripto.codigo_totp(s, t // 30, 8) for t in {sorted(RFC6238_VECTORES)}}}}}
texto, crudo = cripto.generar_token()
# El último de 43 caracteres lleva 4 bits de datos y 2 de relleno: invertir su
# bit más bajo solo toca relleno y da otra forma del MISMO token.
alfabeto = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
otro = texto[:-1] + alfabeto[alfabeto.index(texto[-1]) ^ 1]
res["mismos_bytes"] = __import__("base64").urlsafe_b64decode(otro + "=") == crudo
res["token_ida_vuelta"] = cripto.leer_token(texto) == crudo
res["token_no_canonico"] = cripto.leer_token(otro)
res["token_corto"] = cripto.leer_token(texto[:-1])
res["token_no_ascii"] = cripto.leer_token("\\u00e1" + texto[1:])
res["etiquetas_distintas"] = len({{cripto.huella_token(e, crudo) for e in
                                   (cripto.ETIQUETA_INVITACION, cripto.ETIQUETA_DISPOSITIVO, cripto.ETIQUETA_RENOVACION)}})
print(json.dumps(res, sort_keys=True))
"""


# Se ejecuta dentro de la API con el SQL real de app/instruccion.py: una
# conexión ejecuta la consulta con su bloqueo y, con esa transacción abierta,
# otra conexión pide un bloqueo con NOWAIT. "libre" = la segunda lo obtuvo.
BLOQUEOS_DENTRO = """
import json, sys, threading, time, types, uuid
from psycopg import errors
from app import bd, instruccion, personal
empresa, denuncia, asignado, otro = (uuid.UUID(x) for x in sys.argv[1:5])

def probar(sql, parametros, sonda, parametros_sonda):
    a = bd.conectar("aplicacion", bd.FICHERO_CONTRASENA)
    b = bd.conectar("aplicacion", bd.FICHERO_CONTRASENA)
    try:
        bd.fijar_contexto(a, empresa)
        filas = len(a.execute(sql, parametros).fetchall())
        bd.fijar_contexto(b, empresa)
        try:
            b.execute(sonda, parametros_sonda).fetchall()
            libre = True
        except errors.LockNotAvailable:
            libre = False
        return [filas, libre]
    finally:
        a.rollback()
        b.rollback()
        a.close()
        b.close()

def baja_real(confirmar):
    # A da de baja a la cuenta "otro" (FOR UPDATE y activo = false) sin
    # confirmar; un hilo ejecuta _bloquear_actor de app/instruccion.py con esa
    # cuenta y espera. Cuando se le ve esperando un bloqueo, A confirma o
    # deshace. Devuelve [se le vio esperando, que hizo la accion].
    a = bd.conectar("aplicacion", bd.FICHERO_CONTRASENA)
    b = bd.conectar("aplicacion", bd.FICHERO_CONTRASENA)
    vigia = bd.conectar("aplicacion", bd.FICHERO_CONTRASENA)
    resultado = {}
    try:
        bd.fijar_contexto(a, empresa)
        a.execute("select 1 from canal.usuario_personal where id = %s for update", [otro]).fetchall()
        a.execute("update canal.usuario_personal set activo = false where id = %s", [otro])
        bd.fijar_contexto(b, empresa)
        sesion = types.SimpleNamespace(usuario_id=otro)

        def actuar():
            try:
                instruccion._bloquear_actor(b, sesion)
                resultado["accion"] = "actua"
            except personal.SesionNoValida:
                resultado["accion"] = "SesionNoValida"
            except Exception as error:
                resultado["accion"] = type(error).__name__

        hilo = threading.Thread(target=actuar)
        hilo.start()
        esperando = False
        # Hasta 1,5 s: por debajo del lock_timeout de 2 s de app/bd.py.
        for _ in range(30):
            fila = vigia.execute("select count(*) from pg_stat_activity where pid = %s and wait_event_type = 'Lock'",
                                 [b.info.backend_pid]).fetchone()
            vigia.rollback()
            if fila[0] == 1:
                esperando = True
                break
            time.sleep(0.05)
        if confirmar:
            a.commit()
        else:
            a.rollback()
        hilo.join(10)
        return [esperando, resultado.get("accion")]
    finally:
        for conexion in (a, b, vigia):
            conexion.rollback()
            conexion.close()

ACTUALIZAR = "select 1 from canal.denuncia where id = %s for update nowait"
LOGIN = "select 1 from canal.usuario_personal where id = %s for no key update nowait"
BAJA = "select 1 from canal.usuario_personal where id = %s for update nowait"
res = {
    "escritura_ajena": probar(instruccion.SQL_ESCRIBIR_ASIGNADA, [denuncia, otro], ACTUALIZAR, [denuncia]),
    "escritura_propia": probar(instruccion.SQL_ESCRIBIR_ASIGNADA, [denuncia, asignado], ACTUALIZAR, [denuncia]),
    "lectura_ajena": probar(instruccion.SQL_LEER_ASIGNADA, [denuncia, otro], ACTUALIZAR, [denuncia]),
    "lectura_propia": probar(instruccion.SQL_LEER_ASIGNADA, [denuncia, asignado], ACTUALIZAR, [denuncia]),
    "actor_frente_login": probar(instruccion.SQL_BLOQUEAR_ACTOR, [asignado], LOGIN, [asignado]),
    "actor_frente_baja": probar(instruccion.SQL_BLOQUEAR_ACTOR, [asignado], BAJA, [asignado]),
    "baja_deshecha": baja_real(False),
    "baja_confirmada": baja_real(True),
}
print(json.dumps(res, sort_keys=True))
"""


# Se ejecuta con la imagen de gestion y el código real de app/gestion.py. En
# cada punto que interesa le pregunta a PostgreSQL el modo de la transacción en
# curso, sin cambiar el SQL que se prueba: las lecturas (verificación de la
# base de datos y resolución del identificador) y, como control, las dos
# transacciones de escritura (la de la invitación y la de nueva-clave). No
# escribe nada: la invitación espía aborta y nueva-clave recibe una empresa
# inexistente, que se rechaza antes del INSERT.
GESTION_DENTRO = """
import json, sys, uuid
import psycopg
from app import gestion, personal, verificacion_arranque

ESTADO = "select current_setting('transaction_read_only'), current_setting('transaction_isolation')"
res = {}
execute_real = psycopg.Connection.execute
comprobar_real = verificacion_arranque.comprobar

def anotar(clave, conexion):
    res.setdefault(clave, []).append("|".join(execute_real(conexion, ESTADO).fetchone()))

def execute(self, query, *args, **kwargs):
    cursor = execute_real(self, query, *args, **kwargs)
    if query == gestion.SQL_RESOLVER:
        anotar("resolver", self)
    elif query == gestion.SQL_EMPRESA_VISIBLE:
        anotar("clave", self)
    return cursor

def comprobar(conexion):
    anotar("verificacion", conexion)
    return comprobar_real(conexion)

def emitir(conexion, empresa_id, identificador, email):
    anotar("emision", conexion)
    raise personal.AltaAdminRechazada("espia")

psycopg.Connection.execute = execute
verificacion_arranque.comprobar = comprobar
try:
    gestion._invitacion_plataforma(emitir, sys.argv[1], "espia@alfa.test")
except gestion.ErrorGestion as error:
    res["fin_invitacion"] = str(error)
try:
    gestion.nueva_clave(uuid.uuid4(), bytes(32))
except gestion.ErrorGestion as error:
    res["fin_clave"] = str(error)
print(json.dumps(res, sort_keys=True))
"""
# Oráculos literales: show transaction_read_only y transaction_isolation.
MODO_SOLO_LECTURA = "on|repeatable read"
MODO_ESCRITURA = "off|read committed"


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


def dc_produccion(*args):
    return ejecutar(BASE_PRODUCCION + list(args))


def dc_con_gestion(*args):
    return ejecutar(BASE + ["--profile", "gestion"] + list(args))


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
    limite = time.monotonic() + maximo
    while time.monotonic() < limite:
        if condicion():
            return True
        time.sleep(1)
    return condicion()


def lineas_log(servicio):
    return dc("logs", "--no-color", "--no-log-prefix", servicio).todo.splitlines()


TEMPORAL = None
IMAGEN_API = ""
salidas_gestion = []


def texto_acl(aplicacion):
    hash_aplicacion = hashlib.sha256(CONTRASENAS_REDIS["aplicacion"].encode("ascii")).hexdigest()
    hash_inspector = hashlib.sha256(CONTRASENAS_REDIS["inspector"].encode("ascii")).hexdigest()
    return (f"user default off\nuser aplicacion on #{hash_aplicacion} {aplicacion}\n"
            f"user inspector on #{hash_inspector} {PERMISOS_ACL_INSPECTOR}\n")


def fichero_secreto(nombre, ruta):
    return [f"  {nombre}:", f"    file: \"{ruta.as_posix()}\""]


def preparar_secretos_falsos():
    """Claves de cifrado y secretos de Redis FALSOS, y los límites de prueba
    (como tests/security/verificar_denuncia.py). BASE_PRODUCCION queda sin
    los límites de prueba."""
    directorio = TEMPORAL / "secretos_compose"
    directorio.mkdir()
    lineas = ["secrets:"]
    for nombre in ("clave_maestra", "clave_hmac_codigos", "clave_firma_tokens"):
        CLAVES_FALSAS[nombre] = secrets.token_hex(32)
        (directorio / nombre).write_text(CLAVES_FALSAS[nombre], encoding="ascii", newline="")
        lineas += fichero_secreto(nombre, directorio / nombre)
    for usuario in ("aplicacion", "inspector"):
        CONTRASENAS_REDIS[usuario] = secrets.token_urlsafe(48)
    (directorio / "contrasena_redis").write_text(CONTRASENAS_REDIS["aplicacion"], encoding="ascii", newline="")
    (directorio / "redis_acl").write_text(texto_acl(PERMISOS_ACL_APLICACION), encoding="ascii", newline="\n")
    lineas += fichero_secreto("contrasena_redis", directorio / "contrasena_redis")
    lineas += fichero_secreto("redis_acl", directorio / "redis_acl")
    adicional = TEMPORAL / "secretos_falsos.yml"
    adicional.write_text("\n".join(lineas) + "\n", encoding="utf-8", newline="\n")
    BASE.extend(["-f", str(adicional)])
    BASE_PRODUCCION.extend(BASE)
    limites = TEMPORAL / "limites_prueba.yml"
    limites.write_text(f"services:\n  api:\n    environment:\n      CANARIO_LIMITES: \"{LIMITES_PRUEBA}\"\n",
                       encoding="utf-8", newline="\n")
    BASE.extend(["-f", str(limites)])


def gestion(*args):
    r = dc("run", "--rm", "-T", "gestion", *args)
    salidas_gestion.append(r.out + r.err)
    return r


# ---------------------------------------------------------------------------
# HTTP y TOTP de la batería
# ---------------------------------------------------------------------------
def http(peticiones, red="app", ip=None):
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
        # Diagnóstico: una petición sin respuesta deja un control SIN
        # CONCLUSION; se imprime el tipo de error para que la causa sea
        # visible en la salida y no haya que adivinarla. No cambia ningún
        # oráculo ni condición.
        if "error" in respuesta:
            p(f"  [cliente HTTP] {respuesta['error']} en {respuesta['metodo']} {respuesta['ruta']}")
        if "cuerpo" in respuesta:
            respuesta["cuerpo"] = base64.b64decode(respuesta["cuerpo"])
    return respuestas


def pt(metodo, ruta, datos=None, token=None, crudo=None, **extra):
    cabeceras = {"Content-Type": "application/json"}
    if isinstance(token, Sesion):
        token = token.vigente()
    if token is not None:
        cabeceras["Authorization"] = f"Bearer {token}"
    if crudo is None and datos is not None:
        crudo = json.dumps(datos, ensure_ascii=False).encode("utf-8")
    peticion = {"host": "api", "puerto": 8000, "metodo": metodo, "ruta": ruta, "cabeceras": cabeceras, **extra}
    if crudo is not None:
        peticion["cuerpo"] = base64.b64encode(crudo).decode("ascii")
    return peticion


def por_caddy(peticion):
    return {**peticion, "host": "caddy", "puerto": 8443, "tls": True}


def json_de(respuesta):
    try:
        return json.loads(respuesta["cuerpo"].decode("utf-8"))
    except (KeyError, ValueError, UnicodeDecodeError):
        return None


def una(peticion):
    return http([peticion])[0]


def totp(secreto_texto, paso, digitos=6):
    """TOTP propio de la batería (RFC 6238 sobre RFC 4226), independiente de
    app/cripto.py; se comprueba con los vectores del RFC antes de usarlo."""
    clave = base64.b32decode(secreto_texto + "=" * (-len(secreto_texto) % 8)) \
        if isinstance(secreto_texto, str) else secreto_texto
    mac = hmac.new(clave, paso.to_bytes(8, "big"), hashlib.sha1).digest()
    o = mac[-1] & 0x0F
    return f"{(int.from_bytes(mac[o:o + 4], 'big') & 0x7FFFFFFF) % 10 ** digitos:0{digitos}d}"


# Último paso TOTP aceptado por secreto: un código solo vale una vez.
ULTIMO_PASO = {}


def codigo_libre(secreto):
    """(código, paso) del paso actual, como lo usaría una persona con su
    aplicación; si ese paso ya se usó (un código solo vale una vez), espera
    al siguiente.

    Nunca el paso anterior ni el siguiente, aunque la API los acepte (±1):
    cada petición tarda más de un segundo en llegar (el cliente es un docker
    run), así que el anterior puede caducar mientras viaja, y el siguiente
    todavía no vale si el reloj del contenedor va algo por detrás. El actual
    vale tanto si la API verifica en ese paso como en el siguiente, con
    desfases de reloj en los dos sentidos."""
    while True:
        actual = int(time.time()) // 30
        if actual > ULTIMO_PASO.get(secreto, -1):
            return totp(secreto, actual), actual
        time.sleep(30 - time.time() % 30 + 0.5)


def codigo_erroneo(secreto):
    """Un código de 6 dígitos que no vale en ningún paso de la ventana."""
    actual = int(time.time()) // 30
    validos = {totp(secreto, actual + d) for d in (-2, -1, 0, 1, 2)}
    while True:
        codigo = f"{secrets.randbelow(10 ** 6):06d}"
        if codigo not in validos:
            return codigo


class Cuenta:
    def __init__(self, etiqueta, empresa, email):
        self.etiqueta, self.empresa, self.email = etiqueta, empresa, email
        self.contrasena = secrets.token_urlsafe(18)
        self.secreto = None
        self.dispositivo = None
        self.usuario_id = None
        self.invitacion = None


def login(cuenta, contrasena=None, codigo=None, dispositivo="propio", empresa=None, email=None):
    """Petición de login. dispositivo: "propio" (el de la cuenta), None (sin
    dispositivo) u otro texto."""
    if dispositivo == "propio":
        dispositivo = cuenta.dispositivo
    datos = {"empresa": empresa if empresa is not None else EMPRESAS[cuenta.empresa][1],
             "email": email if email is not None else cuenta.email,
             "contrasena": contrasena if contrasena is not None else cuenta.contrasena,
             "codigo_totp": codigo if codigo is not None else codigo_erroneo(cuenta.secreto or "A" * 32)}
    if dispositivo is not None:
        datos["token_dispositivo"] = dispositivo
    return pt("POST", "/v1/personal/sesiones", datos)


def login_correcto(cuenta, dispositivo="propio"):
    """Login con las credenciales buenas y un código libre. Devuelve la
    respuesta; si es 201, anota el paso usado."""
    codigo, paso = codigo_libre(cuenta.secreto)
    respuesta = una(login(cuenta, codigo=codigo, dispositivo=dispositivo))
    if respuesta.get("estado") == 201:
        ULTIMO_PASO[cuenta.secreto] = paso
    return respuesta


def fallo(cuenta, dispositivo="propio", veces=1):
    """Logins con la contraseña equivocada."""
    return http([login(cuenta, contrasena="equivocada-" + secrets.token_hex(6), dispositivo=dispositivo)] * veces)


class Sesion:
    """Los dos tokens de una sesión de la batería. pt() pide el acceso con
    vigente(): si tiene más de RENOVAR_TRAS segundos, lo renueva antes. Si la
    renovación falla (una sesión revocada a propósito por la prueba), sigue
    con el que tenía y lo anota: la petición dará 401 y lo juzgará la prueba,
    nunca se oculta."""

    def __init__(self, cuenta, datos):
        self.cuenta = cuenta
        self.jwt, self.renovacion = datos["token_acceso"], datos["token_renovacion"]
        self.desde = time.monotonic()
        TOKENS_EMITIDOS.extend((self.jwt, self.renovacion))

    def vigente(self):
        if time.monotonic() - self.desde > RENOVAR_TRAS:
            r = una(renovacion(self.renovacion))
            datos = json_de(r) or {}
            if r.get("estado") == 200 and sorted(datos) == CLAVES_TOKENS:
                self.jwt, self.renovacion = datos["token_acceso"], datos["token_renovacion"]
                self.desde = time.monotonic()
                TOKENS_EMITIDOS.extend((self.jwt, self.renovacion))
            else:
                p(f"  [sesion] no se pudo renovar la de {self.cuenta.etiqueta} ({r.get('estado')}): "
                  "se usa el acceso que habia")
        return self.jwt


def renovacion(token):
    return pt("POST", "/v1/personal/sesiones/renovacion", {"token_renovacion": token})


def sesion_de(cuenta, dispositivo="propio"):
    respuesta = login_correcto(cuenta, dispositivo)
    datos = json_de(respuesta)
    if respuesta.get("estado") != 201 or not datos:
        raise Parada(f"no se pudo iniciar sesion con {cuenta.etiqueta}: {respuesta}")
    return Sesion(cuenta, datos)


def parte_jwt(objeto):
    return base64.urlsafe_b64encode(json.dumps(objeto, separators=(",", ":")).encode()).rstrip(b"=").decode()


def leer_parte(parte):
    return json.loads(base64.urlsafe_b64decode(parte + "=" * (-len(parte) % 4)))


def forjar_jwt(claims, cabecera=None, clave=None):
    """JWT firmado con HMAC-SHA256 de la biblioteca estándar, con la clave de
    firma falsa de esta ejecución salvo que se pase otra."""
    clave = clave if clave is not None else bytes.fromhex(CLAVES_FALSAS["clave_firma_tokens"])
    entrada = parte_jwt(cabecera or CABECERA_JWT) + "." + parte_jwt(claims)
    firma = hmac.new(clave, entrada.encode("ascii"), hashlib.sha256).digest()
    return entrada + "." + base64.urlsafe_b64encode(firma).rstrip(b"=").decode()


def yo(token):
    return pt("GET", "/v1/personal/yo", token=token)


def activar(cuenta):
    """Activa la cuenta con su invitación. Devuelve las dos respuestas."""
    r1 = una(pt("POST", "/v1/personal/activacion", {"token": cuenta.invitacion, "contrasena": cuenta.contrasena}))
    datos = json_de(r1) or {}
    cuenta.secreto = datos.get("secreto_totp")
    if r1.get("estado") != 200 or not cuenta.secreto:
        return r1, None
    codigo, paso = codigo_libre(cuenta.secreto)
    r2 = una(pt("POST", "/v1/personal/activacion/confirmar", {"token": cuenta.invitacion, "codigo_totp": codigo}))
    if r2.get("estado") == 200:
        ULTIMO_PASO[cuenta.secreto] = paso
        cuenta.dispositivo = (json_de(r2) or {}).get("token_dispositivo")
    return r1, r2


def preparar_cuenta(cuenta):
    """Activa una cuenta que la sección solo necesita como preparación. Si no
    se activa, PARADA con el motivo: no es un resultado de la prueba, y sin
    parar se convertiría en una cascada de FALLA o, peor, en un PASA falso
    (una cuenta sin activar también da 401). Solo estados, nunca cuerpos: el
    del paso 1 lleva el secreto TOTP."""
    r1, r2 = activar(cuenta)
    if r2 is None or r2.get("estado") != 200:
        raise Parada(f"no se pudo activar la cuenta de preparacion {cuenta.etiqueta}: "
                     f"paso 1 {r1.get('estado')}, confirmacion {r2.get('estado') if r2 else None}")


def usuario_de(cuenta):
    empresa_id = EMPRESAS[cuenta.empresa][0]
    return valor(f"select id from canal.usuario_personal where empresa_id = '{empresa_id}' "
                 f"and email = '{cuenta.email}';")


def contadores(cuenta):
    """(intentos, segundos de espera restantes) del camino sin confianza."""
    fila = valor(f"select intentos_fallidos || '|' || coalesce(round(extract(epoch from bloqueado_hasta - now()))::text, '') "
                 f"from canal.usuario_personal where id = '{cuenta.usuario_id}';")
    intentos, espera = fila.split("|")
    return int(intentos), (int(espera) if espera else None)


def contadores_dispositivo(cuenta):
    huella = hashlib.sha256(ETIQUETAS["dispositivo"] + leer_token(cuenta.dispositivo)).hexdigest()
    fila = valor(f"select intentos_fallidos || '|' || coalesce(round(extract(epoch from bloqueado_hasta - now()))::text, '') "
                 f"|| '|' || revocado from canal.dispositivo_personal where token_sha256 = '\\x{huella}';")
    intentos, espera, revocado = fila.split("|")
    # Concatenado con texto, el booleano sale como true/false.
    return int(intentos), (int(espera) if espera else None), revocado == "true"


def leer_token(texto):
    return base64.urlsafe_b64decode(texto + "=")


def poner_sin_confianza(cuenta, intentos, bloqueado="null"):
    valor(f"update canal.usuario_personal set intentos_fallidos = {intentos}, bloqueado_hasta = {bloqueado} "
          f"where id = '{cuenta.usuario_id}'; select 1;")


def poner_dispositivo(cuenta, intentos, bloqueado="null"):
    huella = hashlib.sha256(ETIQUETAS["dispositivo"] + leer_token(cuenta.dispositivo)).hexdigest()
    valor(f"update canal.dispositivo_personal set intentos_fallidos = {intentos}, bloqueado_hasta = {bloqueado} "
          f"where token_sha256 = '\\x{huella}'; select 1;")


def es_201_login(respuesta, con_dispositivo_nuevo):
    datos = json_de(respuesta)
    if respuesta.get("estado") != 201 or not isinstance(datos, dict) or sorted(datos) != CLAVES_LOGIN:
        return False
    TOKENS_EMITIDOS.extend(v for v in (datos["token_acceso"], datos["token_renovacion"]) if isinstance(v, str))
    sesion_ok = (isinstance(datos["token_acceso"], str) and len(datos["token_acceso"]) == LONGITUD_JWT
                 and isinstance(datos["token_renovacion"], str)
                 and re.fullmatch(PATRON_TOKEN_COMPUESTO, datos["token_renovacion"])
                 and datos["expira_en"] == DURACION_ACCESO)
    nuevo = datos["token_dispositivo"]
    dispositivo_ok = (isinstance(nuevo, str) and re.fullmatch(PATRON_TOKEN, nuevo)) if con_dispositivo_nuevo \
        else nuevo is None
    return bool(sesion_ok and dispositivo_ok)


def eventos_login_fallido():
    return [linea for linea in lineas_log("api") if TEXTO_EVENTO_LOGIN_FALLIDO in linea]


def es_401(respuesta, cuerpo=CUERPO_401_CREDENCIALES):
    return respuesta.get("estado") == 401 and respuesta.get("cuerpo") == cuerpo


# ---------------------------------------------------------------------------
# Secciones
# ---------------------------------------------------------------------------
EMPRESAS = {}
CUENTAS = {}


def seccion_a():
    global IMAGEN_API
    p("=== a) arranque y empresas")
    r = dc("up", "-d", "--build", "--wait")
    p(f"up -d --build --wait -> codigo {r.rc}")
    if r.rc != 0:
        p(r.todo.strip()[-2000:])
        raise Parada("no arranca el proyecto")
    registro = "\n".join(lineas_log("api"))
    pasa(TEXTO_VERIFICADO in registro and TEXTO_BLOQUEADO not in registro, "a) la API arranca verificada")
    pasa(TEXTO_LIMITES_PRUEBA in registro, f"a) las secciones funcionales usan los limites de prueba ({TEXTO_LIMITES_PRUEBA!r})")
    IMAGEN_API = json.loads(ejecutar(["docker", "inspect", contenedor("api")]).out)[0]["Config"]["Image"]
    for etiqueta, nombre in (("A", "Empresa Alfa S.L."), ("B", "Empresa Beta S.L.")):
        r = gestion("alta-empresa", "--nombre", nombre, "--zona", "Europe/Madrid")
        m = PATRON_ALTA.search(r.out)
        if r.rc != 0 or not m:
            raise Parada(f"alta-empresa {etiqueta} fallo: {r.todo.strip()[-300:]!r}")
        EMPRESAS[etiqueta] = (m.group(1), m.group(2))
    r = dc("exec", "-T", "api", "python", "-c", CRIPTO_DENTRO)
    try:
        res = json.loads(r.out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise Parada(f"no se pudo ejecutar la prueba de cripto dentro de la API: {r.err.strip()[-400:]!r}") from None
    pasa(res["rfc6238"] == {str(t): c for t, c in RFC6238_VECTORES.items()},
         "a) cripto.codigo_totp coincide con los 6 vectores de RFC 6238 (apendice B)")
    pasa(all(totp(RFC6238_SECRETO, t // 30, 8) == c for t, c in RFC6238_VECTORES.items()),
         "a) el TOTP propio de la bateria coincide con los vectores de RFC 6238 (oraculo comprobado)")
    pasa(res["token_ida_vuelta"] is True and res["etiquetas_distintas"] == 3,
         "a) control: un token se lee de vuelta y cada tipo de token tiene su huella")
    # Control: la forma no canónica decodifica de verdad a los mismos bytes,
    # así que solo la comprobación de forma canónica la rechaza.
    negativo("a) leer_token rechaza la forma no canonica del mismo token, la corta y la no ASCII",
             res["token_no_canonico"] is None and res["token_corto"] is None and res["token_no_ascii"] is None,
             res["mismos_bytes"] is True, f"{res}")


def seccion_b():
    p("=== b) primer admin por gestion")
    admin = Cuenta("admin_a", "A", "admin@alfa.test")
    r1 = gestion("alta-admin", "--identificador", EMPRESAS["A"][1], "--email", admin.email)
    m1 = PATRON_INVITACION_GESTION.search(r1.out)
    pasa(r1.rc == 0 and m1 is not None, f"b) alta-admin emite la invitacion del primer admin (codigo {r1.rc})")
    if not m1:
        raise Parada(f"alta-admin no devolvio la invitacion: {r1.todo.strip()[-300:]!r}")
    pasa(TEXTO_SEGUNDO_ADMIN in r1.out, "b) alta-admin recomienda un segundo admin al emitir la invitacion")
    # Repetirlo antes de activar sustituye la invitación: la anterior deja de valer.
    r2 = gestion("alta-admin", "--identificador", EMPRESAS["A"][1], "--email", admin.email)
    m2 = PATRON_INVITACION_GESTION.search(r2.out)
    pasa(r2.rc == 0 and m2 is not None and m2.group(2) == m1.group(2) and m2.group(3) != m1.group(3),
         "b) repetir alta-admin antes de activar reutiliza la cuenta y emite otra invitacion")
    admin.invitacion = m2.group(3)
    vieja = una(pt("POST", "/v1/personal/activacion", {"token": m1.group(3), "contrasena": admin.contrasena}))
    r_act, r_conf = activar(admin)
    control = r_act.get("estado") == 200 and r_conf is not None and r_conf.get("estado") == 200
    pasa(control, "b) control: el admin activa su cuenta con la invitacion vigente")
    negativo("b) la invitacion sustituida da 401 'invitación no válida'", es_401(vieja, CUERPO_401_INVITACION),
             control, f"respuesta: {vieja}")
    if not control:
        raise Parada("el primer admin no se pudo activar")
    admin.usuario_id = usuario_de(admin)
    CUENTAS["admin_a"] = admin
    filas_antes = valor("select count(*) from canal.invitacion_personal;")
    r3 = gestion("alta-admin", "--identificador", EMPRESAS["A"][1], "--email", "intruso@alfa.test")
    negativo("b) con un admin activado, alta-admin se niega, sale con 1 y no crea nada",
             r3.rc == 1 and TEXTO_YA_HAY_ADMIN in r3.err
             and valor("select count(*) from canal.invitacion_personal;") == filas_antes
             and valor("select count(*) from canal.usuario_personal where email = 'intruso@alfa.test';") == "0",
             r1.rc == 0, f"salida: {r3.todo.strip()[-300:]!r}")
    filas = valor(f"select actor || '|' || accion || '|' || objeto_id from canal.registro_auditoria "
                  f"where empresa_id = '{EMPRESAS['A'][0]}' and actor = 'plataforma' order by secuencia;").split()
    pasa(filas == [f"plataforma|invitacion_admin_plataforma|{admin.usuario_id}"] * 2,
         f"b) cada invitacion de plataforma deja su fila en la auditoria de la empresa ({filas})")
    # Admin de B, para las pruebas entre empresas.
    admin_b = Cuenta("admin_b", "B", "admin@beta.test")
    r = gestion("alta-admin", "--identificador", EMPRESAS["B"][1], "--email", admin_b.email)
    m = PATRON_INVITACION_GESTION.search(r.out)
    if not m:
        raise Parada("alta-admin de B fallo")
    admin_b.invitacion = m.group(3)
    _, r_conf = activar(admin_b)
    if not r_conf or r_conf.get("estado") != 200:
        raise Parada("el admin de B no se pudo activar")
    admin_b.usuario_id = usuario_de(admin_b)
    CUENTAS["admin_b"] = admin_b


def invitar(admin_token, etiqueta, email, rol="instructor", empresa="A"):
    r = una(pt("POST", "/v1/personal/usuarios", {"email": email, "rol": rol}, token=admin_token))
    datos = json_de(r)
    if r.get("estado") != 201 or not datos:
        raise Parada(f"no se pudo invitar a {email}: {r}")
    cuenta = Cuenta(etiqueta, empresa, email)
    cuenta.invitacion = datos["token_invitacion"]
    cuenta.usuario_id = datos["usuario_id"]
    CUENTAS[etiqueta] = cuenta
    return cuenta, r


def seccion_c():
    p("=== c) invitacion y activacion por la API")
    admin = CUENTAS["admin_a"]
    token_admin = sesion_de(admin)
    instr, r = invitar(token_admin, "instructor", "instructor@alfa.test")
    pasa(sorted(json_de(r)) == ["token_invitacion", "usuario_id"]
         and re.fullmatch(PATRON_TOKEN_COMPUESTO, instr.invitacion) is not None
         and instr.invitacion.startswith(EMPRESAS["A"][1] + "."),
         "c) invitar devuelve 201 solo con usuario_id y un token <identificador>.<256 bits>")
    ruta = "/v1/personal/activacion"
    corta = una(pt("POST", ruta, {"token": instr.invitacion, "contrasena": "corta"}))
    con_email = una(pt("POST", ruta, {"token": instr.invitacion, "contrasena": "xx" + instr.email + "xx"}))
    con_empresa = una(pt("POST", ruta, {"token": instr.invitacion, "contrasena": "mi EMPRESA ALFA S.L. 2026"}))
    larga = una(pt("POST", ruta, {"token": instr.invitacion, "contrasena": "a" * 129}))
    # NFKC: 12 ligaduras "ﬀ" son 24 caracteres normalizados; 11 caracteres
    # que no cambian se quedan en 11.
    pasa(corta.get("estado") == 422 and corta.get("cuerpo") == CUERPO_422_CORTA
         and larga.get("cuerpo") == CUERPO_422_CORTA,
         "c) contrasena de menos de 12 o mas de 128 caracteres: 422 con el motivo")
    pasa(con_email.get("cuerpo") == CUERPO_422_CONTIENE and con_empresa.get("cuerpo") == CUERPO_422_CONTIENE,
         "c) contrasena con el email o el nombre de la empresa (sin distinguir mayusculas): 422 con el motivo")
    r_act = una(pt("POST", ruta, {"token": instr.invitacion, "contrasena": instr.contrasena}))
    datos = json_de(r_act) or {}
    instr.secreto = datos.get("secreto_totp")
    control = r_act.get("estado") == 200 and sorted(datos) == CLAVES_ACTIVACION
    pasa(control and re.fullmatch(PATRON_SECRETO_TOTP, instr.secreto or "") is not None,
         "c) activar devuelve 200 con el secreto TOTP (160 bits en base32) y su URI")
    uri = (f"otpauth://totp/Canario:instructor@alfa.test?secret={instr.secreto}&issuer=Canario"
           f"&algorithm=SHA1&digits=6&period=30")
    pasa(datos.get("uri_totp") == uri, f"c) la URI otpauth es la literal esperada ({datos.get('uri_totp')!r})")
    pendiente = valor(f"select totp_activo || '|' || (hash_contrasena is null) from canal.usuario_personal "
                      f"where id = '{instr.usuario_id}';")
    # Un booleano concatenado con texto sale como true/false (no t/f).
    pasa(pendiente == "false|true", f"c) antes de confirmar la cuenta sigue sin credenciales ({pendiente})")
    malo = una(pt("POST", "/v1/personal/activacion/confirmar",
                  {"token": instr.invitacion, "codigo_totp": codigo_erroneo(instr.secreto)}))
    codigo, paso = codigo_libre(instr.secreto)
    bueno = una(pt("POST", "/v1/personal/activacion/confirmar", {"token": instr.invitacion, "codigo_totp": codigo}))
    control = bueno.get("estado") == 200 and re.fullmatch(PATRON_TOKEN, (json_de(bueno) or {}).get(
        "token_dispositivo", "")) is not None
    if control:
        ULTIMO_PASO[instr.secreto] = paso
        instr.dispositivo = json_de(bueno)["token_dispositivo"]
    pasa(control, "c) confirmar con el codigo correcto devuelve 200 con el primer token de dispositivo")
    negativo("c) confirmar con un codigo erroneo da 422 'código no válido' y no consume la invitacion",
             malo.get("estado") == 422 and malo.get("cuerpo") == CUERPO_422_CODIGO, control, f"respuesta: {malo}")
    repetida = [una(pt("POST", ruta, {"token": instr.invitacion, "contrasena": instr.contrasena})),
                una(pt("POST", "/v1/personal/activacion/confirmar", {"token": instr.invitacion, "codigo_totp": "000000"}))]
    negativo("c) la invitacion usada da 401 'invitación no válida' en los dos pasos",
             all(es_401(x, CUERPO_401_INVITACION) for x in repetida), control, f"respuestas: {repetida}")
    otra_empresa = EMPRESAS["B"][1] + instr.invitacion[32:]
    malformadas = [instr.invitacion[:-1], "x" * 76, otra_empresa, EMPRESAS["A"][1] + "." + "A" * 43,
                   "0" * 32 + instr.invitacion[32:]]
    respuestas = http([pt("POST", ruta, {"token": t, "contrasena": "una contrasena valida"}) for t in malformadas])
    negativo("c) token mal formado, aleatorio, de otra empresa o de empresa inexistente: el mismo 401 byte a byte",
             all(es_401(x, CUERPO_401_INVITACION) for x in respuestas), control,
             f"estados: {[x.get('estado') for x in respuestas]}")
    # Base de datos: Argon2id con los parámetros de OWASP, secreto cifrado y
    # solo la huella de cada token.
    fila = valor(f"select hash_contrasena || '|' || octet_length(secreto_totp_cifrado) || '|' || "
                 f"encode(secreto_totp_cifrado, 'hex') from canal.usuario_personal where id = '{instr.usuario_id}';")
    hash_guardado, longitud, cifrado_hex = fila.split("|")
    crudo_secreto = base64.b32decode(instr.secreto).hex()
    pasa(hash_guardado.startswith(PREFIJO_ARGON2), f"c) la contrasena se guarda con Argon2id {PREFIJO_ARGON2}")
    pasa(int(longitud) == TAMANO_SECRETO_CIFRADO and crudo_secreto not in cifrado_hex and cifrado_hex[:2] == "01",
         f"c) el secreto TOTP se guarda cifrado (formato 1, {TAMANO_SECRETO_CIFRADO} bytes) y no en claro")
    huella = hashlib.sha256(ETIQUETAS["invitacion"] + leer_token(instr.invitacion.split(".")[1])).hexdigest()
    pasa(valor(f"select count(*) from canal.invitacion_personal where token_sha256 = '\\x{huella}' and cerrada;") == "1",
         "c) la invitacion se guarda como SHA-256(etiqueta || token) y queda cerrada")
    # Caducidad: control, una invitación nueva vale; la misma, caducada, no.
    caducar, _ = invitar(token_admin, "caducada", "caducada@alfa.test")
    huella = hashlib.sha256(ETIQUETAS["invitacion"] + leer_token(caducar.invitacion.split(".")[1])).hexdigest()
    control_cad = una(pt("POST", ruta, {"token": caducar.invitacion, "contrasena": caducar.contrasena})).get("estado")
    valor(f"update canal.invitacion_personal set caduca = now() - interval '1 second' "
          f"where token_sha256 = '\\x{huella}'; select 1;")
    caducada = una(pt("POST", ruta, {"token": caducar.invitacion, "contrasena": caducar.contrasena}))
    negativo("c) una invitacion caducada da 401 'invitación no válida'", es_401(caducada, CUERPO_401_INVITACION),
             control_cad == 200, f"respuesta: {caducada}")
    CUENTAS["token_admin_a"] = token_admin


def seccion_d():
    p("=== d) login: respuesta uniforme, tiempos y un solo uso del codigo")
    token_admin = CUENTAS["token_admin_a"]
    instr = CUENTAS["instructor"]
    eventos_inicio = len(eventos_login_fallido())
    control = login_correcto(instr)
    pasa(es_201_login(control, con_dispositivo_nuevo=False),
         "d) control: con su dispositivo, 201 con el JWT, la renovacion y sin dispositivo nuevo")
    sin = login_correcto(instr, dispositivo=None)
    pasa(es_201_login(sin, con_dispositivo_nuevo=True),
         "d) sin dispositivo de confianza, 201 con un dispositivo nuevo")
    pasa(len(eventos_login_fallido()) == eventos_inicio, "d) un login correcto no deja EVENTO login_fallido")
    pendiente, _ = invitar(token_admin, "pendiente", "pendiente@alfa.test")
    baja, _ = invitar(token_admin, "de_baja", "debaja@alfa.test")
    preparar_cuenta(baja)
    una(pt("POST", f"/v1/personal/usuarios/{baja.usuario_id}/baja", token=token_admin))
    codigo, _ = codigo_libre(instr.secreto)
    casos = {
        "empresa inexistente": login(instr, codigo=codigo, empresa="0123456789abcdef0123456789abcdef"),
        "empresa mal formada": login(instr, codigo=codigo, empresa="../" + "x" * 10),
        "empresa de otra cuenta (B)": login(instr, codigo=codigo, empresa=EMPRESAS["B"][1]),
        "email inexistente": login(instr, codigo=codigo, email="nadie@alfa.test"),
        "contrasena erronea": login(instr, contrasena="no es la buena 123", codigo=codigo),
        "codigo erroneo": login(instr),
        "codigo mal formado": login(instr, codigo="12a456"),
        "cuenta sin activar": login(pendiente, contrasena=pendiente.contrasena, dispositivo=None),
        "cuenta dada de baja": login(baja, codigo=codigo_libre(baja.secreto)[0]),
    }
    respuestas = dict(zip(casos, http(list(casos.values()))))
    distintos = {k: (v.get("estado"), v.get("cuerpo")) for k, v in respuestas.items() if not es_401(v)}
    pasa(not distintos, f"d) los 9 fallos responden el mismo 401 'credenciales no válidas' byte a byte {distintos or ''}")
    # OWASP ASVS 5.0.0, 16.3.1: cada fallo deja su EVENTO, con la cuenta si
    # existe y sin el email ni nada de lo enviado. La cuenta del instructor
    # aparece en los 3 fallos que la encuentran (contrasena y codigos); las
    # 2 empresas que no existen salen como "-".
    eventos = eventos_login_fallido()[eventos_inicio:]
    del_instructor = [e for e in eventos if f"usuario={instr.usuario_id}" in e]
    sin_empresa = [e for e in eventos if "empresa=- " in e]
    pasa(len(eventos) == 9 and len(del_instructor) == 3 and len(sin_empresa) == 2
         and not any("@" in e or instr.contrasena in e for e in eventos),
         f"d) los 9 fallos dejan 9 EVENTO login_fallido: 3 con la cuenta del instructor, 2 sin empresa, ninguno con "
         f"el email ni la contrasena ({len(eventos)}, {len(del_instructor)}, {len(sin_empresa)})")
    # El instructor solo ha fallado por el camino de su dispositivo: los
    # fallos cuentan ahí.
    poner_dispositivo(instr, 0)

    # Un código solo vale una vez: el mismo código, en dos logins seguidos.
    codigo, paso = codigo_libre(instr.secreto)
    primero, segundo = http([login(instr, codigo=codigo), login(instr, codigo=codigo)])
    if primero.get("estado") == 201:
        ULTIMO_PASO[instr.secreto] = paso
    negativo("d) el mismo codigo TOTP no vale dos veces (401 la segunda)", es_401(segundo),
             es_201_login(primero, False), f"respuestas: {primero.get('estado')}, {segundo.get('estado')}")
    poner_dispositivo(instr, 0)

    # Tiempos: email inexistente frente a cuenta real con la contraseña
    # equivocada y frente a cuenta en espera. Muestras intercaladas; los
    # contadores se reinician entre tandas para medir siempre la verificación
    # real. Control de sensibilidad: un 422 (sin Argon2) se distingue.
    tiempos = cuenta_tiempos(token_admin)
    muestras = {"inexistente": [], "erronea": [], "en_espera": [], "sin_hash": []}
    for _ in range(10):
        poner_sin_confianza(tiempos, 0)
        tanda = []
        for _ in range(4):
            tanda += [login(tiempos, email="nadie@alfa.test", dispositivo=None),
                      login(tiempos, dispositivo=None),
                      pt("POST", "/v1/personal/sesiones", {"empresa": EMPRESAS["A"][1]})]
        res = http(tanda)
        for i, nombre in enumerate(["inexistente", "erronea", "sin_hash"] * 4):
            if "ms" in res[i]:
                muestras[nombre].append(res[i]["ms"])
    poner_sin_confianza(tiempos, 10, "now() + interval '1 hour'")
    tanda = []
    for _ in range(40):
        tanda += [login(tiempos, email="nadie@alfa.test", dispositivo=None), login(tiempos, dispositivo=None)]
    res = http(tanda)
    en_espera_inexistente = [x["ms"] for x in res[0::2] if "ms" in x]
    muestras["en_espera"] = [x["ms"] for x in res[1::2] if "ms" in x]
    mediana = {k: statistics.median(v) for k, v in muestras.items() if v}
    mediana["inexistente_2"] = statistics.median(en_espera_inexistente)
    p("   medianas en ms: " + ", ".join(f"{k}={v:.1f}" for k, v in mediana.items()))
    control = mediana["inexistente"] - mediana["sin_hash"] >= 8
    negativo("d) tiempos: email inexistente y contrasena erronea de una cuenta real difieren menos de 3 ms",
             abs(mediana["inexistente"] - mediana["erronea"]) < 3, control,
             f"control: Argon2 no se distingue de un 422 ({mediana})")
    negativo("d) tiempos: email inexistente y cuenta en espera difieren menos de 3 ms",
             abs(mediana["inexistente_2"] - mediana["en_espera"]) < 3, control, f"{mediana}")
    poner_sin_confianza(tiempos, 0)


def cuenta_tiempos(token_admin):
    if "tiempos" not in CUENTAS:
        cuenta, _ = invitar(token_admin, "tiempos", "tiempos@alfa.test")
        preparar_cuenta(cuenta)
    return CUENTAS["tiempos"]


def seccion_e():
    p("=== e) bloqueo sin denegacion de servicio")
    token_admin = CUENTAS["token_admin_a"]
    victima, _ = invitar(token_admin, "victima", "victima@alfa.test")
    preparar_cuenta(victima)
    control = login_correcto(victima, dispositivo=None)
    pasa(es_201_login(control, True), "e) control: la victima entra sin dispositivo de confianza")
    # e1) Cinco fallos sin dispositivo bloquean ese camino 1 minuto.
    fallo(victima, dispositivo=None, veces=5)
    intentos, espera = contadores(victima)
    pasa(intentos == 5 and espera is not None and 50 <= espera <= 60,
         f"e1) 5 fallos sin dispositivo: intentos 5 y espera de 1 minuto ({intentos}, {espera} s)")
    sin = login_correcto(victima, dispositivo=None)
    con = login_correcto(victima)
    negativo("e1) con el camino sin confianza en espera, el titular ENTRA con su dispositivo (201)",
             es_201_login(con, False), es_401(sin), f"sin dispositivo: {sin.get('estado')}, con: {con}")
    negativo("e1) con el camino en espera, las credenciales buenas sin dispositivo dan 401 (no se verifican)",
             es_401(sin), es_201_login(con, False))
    pasa(contadores(victima)[0] == 5,
         "e1) ni el login en espera ni el acierto con el dispositivo cambian el contador sin confianza")
    eventos = "\n".join(lineas_log("api"))
    pasa(EVENTOS["espera_sin_confianza"] in eventos, "e1) el bloqueo deja EVENTO espera_sin_confianza en el log")
    # e2) Esperas crecientes con tope de 60 minutos.
    observadas = {}
    for n in sorted(ESPERA_TRAS):
        poner_sin_confianza(victima, n - 1)
        fallo(victima, dispositivo=None)
        observadas[n] = contadores(victima)
    pasa(all(o[0] == n and o[1] is not None and ESPERA_TRAS[n] * 60 - 10 <= o[1] <= ESPERA_TRAS[n] * 60
             for n, o in observadas.items()),
         f"e2) espera tras el fallo n: 2^(n-5) minutos con tope de 60 ({observadas})")
    # e3) Al acabar la espera, un acierto sin dispositivo entra y pone el contador a cero.
    poner_sin_confianza(victima, 7, "now() - interval '1 second'")
    r = login_correcto(victima, dispositivo=None)
    pasa(es_201_login(r, True) and contadores(victima) == (0, None),
         f"e3) terminada la espera, un acierto sin dispositivo entra y reinicia el contador ({contadores(victima)})")
    # e4) Un acierto con el dispositivo NO reinicia el contador del otro camino.
    fallo(victima, dispositivo=None, veces=3)
    r = login_correcto(victima)
    negativo("e4) tres fallos sin dispositivo y un acierto con el: el contador sin confianza sigue en 3",
             contadores(victima)[0] == 3, es_201_login(r, False), f"{contadores(victima)}")
    # e5) Un fallo de TOTP con la contraseña buena cuenta igual.
    poner_sin_confianza(victima, 0)
    una(login(victima, dispositivo=None))
    pasa(contadores(victima)[0] == 1, "e5) contrasena buena y codigo erroneo cuentan como fallo")
    # e6) 100 fallos cierran el camino sin confianza; el dispositivo sigue.
    poner_sin_confianza(victima, TOPE_SIN_CONFIANZA - 1)
    fallo(victima, dispositivo=None)
    poner_sin_confianza(victima, TOPE_SIN_CONFIANZA)
    cerrado = login_correcto(victima, dispositivo=None)
    con = login_correcto(victima)
    negativo("e6) con 100 fallos, el camino sin confianza queda cerrado aunque no haya espera (401)",
             es_401(cerrado), es_201_login(con, False), f"{cerrado.get('estado')}")
    negativo("e6) con el camino cerrado, el titular entra con su dispositivo (201)", es_201_login(con, False),
             es_401(cerrado))
    pasa(EVENTOS["cierre_sin_confianza"] in "\n".join(lineas_log("api")),
         "e6) el cierre deja EVENTO cierre_sin_confianza en el log")
    lista = json_de(una(pt("GET", "/v1/personal/usuarios", token=token_admin))) or {}
    fila = next((u for u in lista.get("usuarios", []) if u.get("email") == victima.email), {})
    pasa(fila.get("camino_sin_confianza_cerrado") is True and sorted(fila) == CLAVES_USUARIO,
         "e6) el admin ve el camino cerrado en la lista de cuentas (sin hashes ni contadores)")
    # e7) La reinvitación lo reabre.
    r = una(pt("POST", f"/v1/personal/usuarios/{victima.usuario_id}/invitacion", token=token_admin))
    victima.invitacion = (json_de(r) or {}).get("token_invitacion")
    activar(victima)
    r = login_correcto(victima, dispositivo=None)
    pasa(es_201_login(r, True) and contadores(victima)[0] == 0,
         "e7) tras reinvitar y activar, el camino sin confianza vuelve a funcionar desde cero")
    # e8) Fallos con el dispositivo: bloquean solo el dispositivo; un acierto
    # con él va entonces por el camino sin confianza (dispositivo nuevo).
    fallo(victima, veces=5)
    intentos, espera, _ = contadores_dispositivo(victima)
    pasa(intentos == 5 and espera is not None and 50 <= espera <= 60 and contadores(victima)[0] == 0,
         f"e8) 5 fallos con el dispositivo: cuentan en el dispositivo ({intentos}, {espera} s) y no en la cuenta")
    r = login_correcto(victima)
    pasa(es_201_login(r, True), "e8) con el dispositivo en espera, un acierto entra por el camino sin confianza "
                                "y recibe un dispositivo nuevo")
    pasa(EVENTOS["espera_dispositivo"] in "\n".join(lineas_log("api")), "e8) EVENTO espera_dispositivo en el log")
    # e9) 20 fallos retiran el dispositivo.
    poner_dispositivo(victima, TOPE_DISPOSITIVO - 1)
    fallo(victima)
    poner_sin_confianza(victima, 0)
    r = login_correcto(victima)
    pasa(contadores_dispositivo(victima)[0] == TOPE_DISPOSITIVO and es_201_login(r, True),
         "e9) con 20 fallos el dispositivo deja de ser de confianza (el acierto va por el otro camino)")
    pasa(EVENTOS["retirada_dispositivo"] in "\n".join(lineas_log("api")), "e9) EVENTO retirada_dispositivo en el log")
    victima.dispositivo = (json_de(r) or {}).get("token_dispositivo")
    # e10) El dispositivo de otra cuenta no da confianza ni cuenta en él.
    instr = CUENTAS["instructor"]
    antes = contadores_dispositivo(instr)[0]
    poner_sin_confianza(victima, 0)
    r = login_correcto(victima, dispositivo=instr.dispositivo)
    pasa(es_201_login(r, True) and contadores_dispositivo(instr)[0] == antes,
         "e10) con el dispositivo de otra cuenta, el login va por el camino sin confianza y no toca ese dispositivo")
    victima.dispositivo = (json_de(r) or {}).get("token_dispositivo")
    # e11) Peticiones simultáneas no consiguen intentos extra: 15 fallos a
    # la vez, solo 5 se verifican.
    poner_sin_confianza(victima, 0)
    paralelo = login(victima, contrasena="equivocada simultanea", dispositivo=None)
    respuestas = http([{**paralelo, "paralelo": 15}])
    pasa(all(es_401(x) for x in respuestas) and contadores(victima)[0] == 5,
         f"e11) 15 fallos simultaneos: todos 401 y el contador queda exactamente en 5 ({contadores(victima)[0]})")
    poner_sin_confianza(victima, 0)


def seccion_f():
    p("=== f) sesiones: JWT de acceso, renovacion y cierre")
    instr = CUENTAS["instructor"]
    sesion = sesion_de(instr)
    control = una(yo(sesion.jwt))
    datos = json_de(control) or {}
    pasa(control.get("estado") == 200 and sorted(datos) == CLAVES_YO and datos.get("email") == instr.email
         and datos.get("rol") == "instructor", "f) control: /yo con el JWT Bearer responde la cuenta")
    cabecera, cuerpo, _ = sesion.jwt.split(".")
    claims = leer_parte(cuerpo)
    pasa(len(sesion.jwt) == LONGITUD_JWT and leer_parte(cabecera) == CABECERA_JWT and sorted(claims) == CLAIMS_JWT
         and claims["iss"] == "canario" and claims["aud"] == "canario-personal"
         and claims["sub"] == str(instr.usuario_id) and claims["emp"] == EMPRESAS["A"][1]
         and claims["exp"] - claims["iat"] == DURACION_ACCESO,
         f"f) el JWT tiene la cabecera, los claims y la duracion exactos ({leer_parte(cabecera)}, {sorted(claims)})")
    sid = claims["sid"]
    pasa(valor(f"select count(*) from canal.sesion_personal where id = '{sid}' and usuario_id = '{instr.usuario_id}' "
               f"and not revocada;") == "1", "f) el sid del JWT es la fila de su sesion")

    # Forjados con la clave falsa de esta ejecucion. Control: uno bien formado,
    # con el sid y la cuenta reales, se acepta; asi los rechazos son por lo
    # que cambia cada uno y no por la forma de forjar.
    base = dict(claims)
    ahora = int(time.time())
    base.update(iat=ahora, exp=ahora + DURACION_ACCESO)
    forjado_ok = una(yo(forjar_jwt(base))).get("estado") == 200
    pasa(forjado_ok, "f) control: un JWT forjado con la clave de firma y los claims correctos se acepta")
    otra = CUENTAS["admin_a"]
    malos = {
        "sin cabecera": pt("GET", "/v1/personal/yo"),
        "esquema Basic": {**yo(sesion.jwt), "cabeceras": {"Authorization": f"Basic {sesion.jwt}"}},
        "JWT truncado": yo(sesion.jwt[:-1]),
        "token de renovacion como acceso": yo(sesion.renovacion),
        "token de dispositivo como acceso": yo(f"{EMPRESAS['A'][1]}.{instr.dispositivo}"),
        "alg none": yo(parte_jwt({"alg": "none", "typ": CABECERA_JWT["typ"]}) + "." + parte_jwt(base) + "."),
        "typ JWT": yo(forjar_jwt(base, {"alg": "HS256", "typ": "JWT"})),
        "con kid": yo(forjar_jwt(base, {**CABECERA_JWT, "kid": "1"})),
        "otra clave": yo(forjar_jwt(base, clave=secrets.token_bytes(32))),
        "caducado": yo(forjar_jwt({**base, "iat": ahora - 400, "exp": ahora - 100})),
        "dura una hora": yo(forjar_jwt({**base, "exp": ahora + 3600})),
        "aud ajena": yo(forjar_jwt({**base, "aud": "otra"})),
        "iss ajeno": yo(forjar_jwt({**base, "iss": "otro"})),
        "con un rol": yo(forjar_jwt({**base, "rol": "admin"})),
        "sid inexistente": yo(forjar_jwt({**base, "sid": str(uuid.uuid4())})),
        "sid propio con la cuenta de otro": yo(forjar_jwt({**base, "sub": str(otra.usuario_id)})),
        "emp de B con la sesion de A": yo(forjar_jwt({**base, "emp": EMPRESAS["B"][1]})),
    }
    respuestas = dict(zip(malos, http(list(malos.values()))))
    distintos = {k: v.get("estado") for k, v in respuestas.items()
                 if not (es_401(v, CUERPO_401_SESION) and v.get("cabeceras", {}).get("www-authenticate") == "Bearer")}
    negativo(f"f) {len(malos)} accesos no validos: 401 'sesión no válida' con WWW-Authenticate: Bearer "
             f"{distintos or ''}".strip(), not distintos, control.get("estado") == 200 and forjado_ok)

    # Renovacion (RFC 9700, 4.14.2).
    huella = hashlib.sha256(ETIQUETAS["renovacion"] + leer_token(sesion.renovacion.split(".")[1])).hexdigest()
    pasa(valor(f"select count(*) from canal.sesion_personal where id = '{sid}' and token_sha256 = '\\x{huella}';")
         == "1", "f) la renovacion se guarda como SHA-256(etiqueta || token)")
    vieja = sesion.renovacion
    r = una(renovacion(vieja))
    nueva = json_de(r) or {}
    nueva_ok = (r.get("estado") == 200 and sorted(nueva) == CLAVES_TOKENS and nueva.get("expira_en") == DURACION_ACCESO
                and nueva.get("token_renovacion") not in (None, vieja)
                and una(yo(nueva.get("token_acceso"))).get("estado") == 200)
    pasa(nueva_ok, "f) control: la renovacion devuelve un acceso que responde y otra renovacion distinta")
    TOKENS_EMITIDOS.extend(v for v in (nueva.get("token_acceso"), nueva.get("token_renovacion")) if v)
    eventos_antes = sum(TEXTO_EVENTO_REUTILIZACION in linea for linea in lineas_log("api"))
    reusada = una(renovacion(vieja))
    tras = http([yo(nueva.get("token_acceso", "")), renovacion(nueva.get("token_renovacion", ""))])
    eventos = [linea for linea in lineas_log("api") if TEXTO_EVENTO_REUTILIZACION in linea][eventos_antes:]
    estado_fila = valor(f"select revocada || '|' || cardinality(tokens_usados) from canal.sesion_personal "
                        f"where id = '{sid}';")
    negativo("f) reutilizar una renovacion ya gastada da 401 y revoca la sesion entera: su acceso nuevo y su "
             "renovacion nueva tambien dan 401",
             es_401(reusada, CUERPO_401_SESION) and all(es_401(x, CUERPO_401_SESION) for x in tras)
             and estado_fila == "true|1", nueva_ok,
             f"reusada {reusada.get('estado')}, tras {[x.get('estado') for x in tras]}, fila {estado_fila}")
    negativo("f) la reutilizacion deja un EVENTO con empresa, cuenta y sesion, sin el token",
             len(eventos) == 1 and f"usuario={instr.usuario_id}" in eventos[0] and f"sesion={sid}" in eventos[0]
             and vieja.split(".")[1] not in eventos[0], nueva_ok, f"eventos: {eventos}")

    # Inactividad (15 minutos sin renovar), maximo de 8 horas y tope de
    # renovaciones. Cada caso con su control en la misma sesion.
    sesion = sesion_de(instr)
    sid = leer_parte(sesion.jwt.split(".")[1])["sid"]

    def fila(cambio):
        valor(f"update canal.sesion_personal set {cambio} where id = '{sid}'; select 1;")

    def renovar_aqui():
        r = una(renovacion(sesion.renovacion))
        if r.get("estado") == 200:
            sesion.renovacion = json_de(r)["token_renovacion"]
            sesion.jwt = json_de(r)["token_acceso"]
            TOKENS_EMITIDOS.extend((sesion.jwt, sesion.renovacion))
        return r

    fila("ultimo_uso = now() - interval '14 minutes'")
    casi = renovar_aqui().get("estado")
    fila("ultimo_uso = now() - interval '16 minutes'")
    inactiva = renovar_aqui()
    negativo("f) 16 minutos sin renovar: la renovacion da 401 (control: con 14 minutos, 200)",
             es_401(inactiva, CUERPO_401_SESION), casi == 200, f"14 min: {casi}, 16 min: {inactiva.get('estado')}")
    sesion = sesion_de(instr)
    sid = leer_parte(sesion.jwt.split(".")[1])["sid"]
    antes = una(yo(sesion.jwt)).get("estado")
    fila("caduca = now() - interval '1 second'")
    caducada = http([yo(sesion.jwt), renovacion(sesion.renovacion)])
    negativo("f) pasadas las 8 horas, el acceso vivo y la renovacion dan 401",
             all(es_401(x, CUERPO_401_SESION) for x in caducada), antes == 200,
             f"estados: {[x.get('estado') for x in caducada]}")
    sesion = sesion_de(instr)
    sid = leer_parte(sesion.jwt.split(".")[1])["sid"]
    relleno = ", ".join(f"'\\x{i:064x}'::bytea" for i in range(TOPE_RENOVACIONES - 1))
    fila(f"tokens_usados = array[{relleno}]")
    ultima = renovar_aqui().get("estado")
    tope = renovar_aqui()
    negativo(f"f) con {TOPE_RENOVACIONES} renovaciones gastadas la siguiente da 401 (control: la numero "
             f"{TOPE_RENOVACIONES}, 200)", es_401(tope, CUERPO_401_SESION), ultima == 200,
             f"ultima {ultima}, tope {tope.get('estado')}")
    sesion = sesion_de(instr)
    de_b = f"{EMPRESAS['B'][1]}.{sesion.renovacion.split('.')[1]}"
    ajena = una(renovacion(de_b))
    propia = renovar_aqui().get("estado")
    negativo("f) la renovacion con el identificador de B da 401 (control: con el suyo, 200)",
             es_401(ajena, CUERPO_401_SESION), propia == 200, f"ajena {ajena.get('estado')}")

    # Cierre: el JWT vivo deja de valer al momento (OWASP ASVS 5.0.0, 7.4.1).
    sesion = sesion_de(instr)
    antes = una(yo(sesion.jwt)).get("estado")
    cierre = una(pt("DELETE", "/v1/personal/sesiones/actual", token=sesion.jwt))
    despues = http([yo(sesion.jwt), renovacion(sesion.renovacion)])
    negativo("f) tras cerrar la sesion (204), su JWT vivo y su renovacion dan 401 al momento",
             cierre.get("estado") == 204 and all(es_401(x, CUERPO_401_SESION) for x in despues), antes == 200,
             f"cierre {cierre.get('estado')}, despues {[x.get('estado') for x in despues]}")
    sesion = sesion_de(instr)
    valor(f"update canal.empresa set activa = false where id = '{EMPRESAS['A'][0]}'; select 1;")
    inactiva = http([yo(sesion.jwt), renovacion(sesion.renovacion)])
    valor(f"update canal.empresa set activa = true where id = '{EMPRESAS['A'][0]}'; select 1;")
    vuelta = una(yo(sesion.jwt)).get("estado")
    negativo("f) con la empresa inactiva, sus JWT y sus renovaciones dan 401 (control: al reactivarla, 200)",
             all(es_401(x, CUERPO_401_SESION) for x in inactiva), vuelta == 200,
             f"estados: {[x.get('estado') for x in inactiva]}")


def seccion_g():
    p("=== g) administracion de cuentas y auditoria")
    admin, admin_b = CUENTAS["admin_a"], CUENTAS["admin_b"]
    token_admin = sesion_de(admin)
    token_b = sesion_de(admin_b)
    instr = CUENTAS["instructor"]
    token_instr = sesion_de(instr)
    ctl_lista = una(pt("GET", "/v1/personal/usuarios", token=token_admin))
    prohibidas = http([pt("GET", "/v1/personal/usuarios", token=token_instr),
                       pt("POST", "/v1/personal/usuarios", {"email": "x@alfa.test", "rol": "admin"}, token=token_instr),
                       pt("POST", f"/v1/personal/usuarios/{admin.usuario_id}/invitacion", token=token_instr),
                       pt("POST", f"/v1/personal/usuarios/{admin.usuario_id}/baja", token=token_instr)])
    negativo("g) un instructor recibe 403 en las 4 rutas de administracion",
             all(x.get("estado") == 403 and x.get("cuerpo") == CUERPO_403 for x in prohibidas),
             ctl_lista.get("estado") == 200, f"estados: {[x.get('estado') for x in prohibidas]}")
    pasa(valor("select count(*) from canal.usuario_personal where email = 'x@alfa.test';") == "0",
         "g) el instructor no ha creado ninguna cuenta")
    ajeno = admin_b.usuario_id
    control = una(pt("POST", f"/v1/personal/usuarios/{instr.usuario_id}/invitacion", token=token_admin))
    instr_inv = (json_de(control) or {}).get("token_invitacion")
    respuestas = http([pt("POST", f"/v1/personal/usuarios/{ajeno}/invitacion", token=token_admin),
                       pt("POST", f"/v1/personal/usuarios/{ajeno}/baja", token=token_admin),
                       pt("POST", f"/v1/personal/usuarios/{uuid.uuid4()}/baja", token=token_admin),
                       pt("POST", "/v1/personal/usuarios/no-es-un-uuid/baja", token=token_admin)])
    negativo("g) una cuenta de otra empresa, una inexistente y un id mal formado dan el mismo 404",
             all(x.get("estado") == 404 and x.get("cuerpo") == CUERPO_404 for x in respuestas),
             control.get("estado") == 201, f"estados: {[x.get('estado') for x in respuestas]}")
    pasa(una(yo(token_b)).get("estado") == 200 and
         valor(f"select activo from canal.usuario_personal where id = '{ajeno}';") == "t",
         "g) el admin de B sigue activo y con sesion")
    # La reinvitación del control no cambia la cuenta hasta confirmarse.
    pasa(una(yo(token_instr)).get("estado") == 200, "g) reinvitar no desactiva la cuenta ni sus sesiones")
    valor(f"update canal.invitacion_personal set cerrada = true where cerrada = false "
          f"and usuario_id = '{instr.usuario_id}'; select 1;")
    del instr_inv
    duplicado = una(pt("POST", "/v1/personal/usuarios", {"email": instr.email, "rol": "instructor"}, token=token_admin))
    mayusculas = una(pt("POST", "/v1/personal/usuarios", {"email": instr.email.upper(), "rol": "admin"},
                        token=token_admin))
    invalidos = http([pt("POST", "/v1/personal/usuarios", {"email": e, "rol": "instructor"}, token=token_admin)
                      for e in ("sin-arroba", "@alfa.test", "con espacio@alfa.test", "ñ@alfa.test")]
                     + [pt("POST", "/v1/personal/usuarios", {"email": "rol@alfa.test", "rol": "superadmin"},
                           token=token_admin)])
    pasa(duplicado.get("estado") == 409 and duplicado.get("cuerpo") == CUERPO_409_DUPLICADO
         and mayusculas.get("cuerpo") == CUERPO_409_DUPLICADO,
         "g) un email ya usado en la empresa (tambien en mayusculas) da 409")
    pasa(all(x.get("estado") == 422 and x.get("cuerpo") == CUERPO_422 for x in invalidos),
         "g) emails mal formados o no ASCII y un rol desconocido dan 422 sin eco")
    # La baja del último admin activado se rechaza; con otro admin, se acepta.
    ultimo = una(pt("POST", f"/v1/personal/usuarios/{admin.usuario_id}/baja", token=token_admin))
    pasa(ultimo.get("estado") == 409 and ultimo.get("cuerpo") == CUERPO_409_ULTIMO,
         "g) la baja del unico admin activado da 409")
    admin2, _ = invitar(token_admin, "admin2", "admin2@alfa.test", rol="admin")
    preparar_cuenta(admin2)
    token_admin2 = sesion_de(admin2)
    baja = una(pt("POST", f"/v1/personal/usuarios/{admin.usuario_id}/baja", token=token_admin2))
    tras = http([yo(token_admin), login(admin, codigo=codigo_libre(admin.secreto)[0])])
    negativo("g) con otro admin activado, la baja se acepta (204), revoca sus sesiones y el login da 401",
             es_401(tras[0], CUERPO_401_SESION) and es_401(tras[1]), baja.get("estado") == 204,
             f"baja: {baja.get('estado')}, tras: {[x.get('estado') for x in tras]}")
    # Reactivar = reinvitar y activar.
    r = una(pt("POST", f"/v1/personal/usuarios/{admin.usuario_id}/invitacion", token=token_admin2))
    admin.invitacion = (json_de(r) or {}).get("token_invitacion")
    activar(admin)
    pasa(es_201_login(login_correcto(admin), False),
         "g) tras reinvitar y activar, la cuenta dada de baja vuelve a entrar con su dispositivo nuevo")
    # Cambio de contraseña.
    token_instr = sesion_de(instr)
    otra_sesion = sesion_de(instr, dispositivo=None)
    # login_correcto anota el paso TOTP usado: el cambio de contraseña
    # necesita uno posterior.
    otro_dispositivo = json_de(login_correcto(instr, dispositivo=None)) or {}
    ruta = "/v1/personal/contrasena"
    nueva = secrets.token_urlsafe(18)
    poner_dispositivo(instr, 0)
    debil = una(pt("POST", ruta, {"contrasena_actual": instr.contrasena, "contrasena_nueva": "corta",
                                  "codigo_totp": codigo_libre(instr.secreto)[0]}, token=token_instr))
    pasa(debil.get("cuerpo") == CUERPO_422_CORTA and contadores_dispositivo(instr)[0] == 0,
         "g) una contrasena nueva debil da 422 sin gastar un intento")
    mala = una(pt("POST", ruta, {"contrasena_actual": "no es la actual 1", "contrasena_nueva": nueva,
                                 "codigo_totp": codigo_libre(instr.secreto)[0]}, token=token_instr))
    pasa(es_401(mala) and contadores_dispositivo(instr)[0] == 1,
         "g) con la contrasena actual equivocada: 401 y el fallo cuenta en el dispositivo de la sesion")
    codigo, paso = codigo_libre(instr.secreto)
    jwt_anterior, renovacion_anterior = token_instr.jwt, token_instr.renovacion
    cambio = una(pt("POST", ruta, {"contrasena_actual": instr.contrasena, "contrasena_nueva": nueva,
                                   "codigo_totp": codigo}, token=token_instr))
    tokens_nuevos = json_de(cambio) or {}
    cambio_ok = cambio.get("estado") == 200 and sorted(tokens_nuevos) == CLAVES_TOKENS
    if cambio_ok:
        ULTIMO_PASO[instr.secreto] = paso
        TOKENS_EMITIDOS.extend((tokens_nuevos["token_acceso"], tokens_nuevos["token_renovacion"]))
    vieja = instr.contrasena
    instr.contrasena = nueva
    tras = http([yo(tokens_nuevos.get("token_acceso", "")), yo(jwt_anterior), renovacion(renovacion_anterior),
                 yo(otra_sesion.jwt), login(instr, contrasena=vieja, codigo=codigo_libre(instr.secreto)[0])])
    negativo("g) cambio de contrasena (200 con tokens nuevos, ASVS 7.2.4): los tokens nuevos responden; el JWT y la "
             "renovacion de la sesion que lo pidio, la otra sesion y la contrasena vieja dan 401",
             tras[0].get("estado") == 200 and all(es_401(x, CUERPO_401_SESION) for x in tras[1:4])
             and es_401(tras[4]), cambio_ok,
             f"cambio: {cambio.get('estado')}, tras: {[x.get('estado') for x in tras]}")
    dispositivo_viejo = otro_dispositivo.get("token_dispositivo")
    if dispositivo_viejo:
        huella = hashlib.sha256(ETIQUETAS["dispositivo"] + leer_token(dispositivo_viejo)).hexdigest()
        pasa(valor(f"select revocado from canal.dispositivo_personal where token_sha256 = '\\x{huella}';") == "t",
             "g) el cambio de contrasena revoca los demas dispositivos de la cuenta")
    pasa(es_201_login(login_correcto(instr), False), "g) la contrasena nueva entra con el dispositivo de la sesion")
    # Auditoría: cada acción con su actor, y la cadena es válida.
    filas = valor(f"select distinct accion from canal.registro_auditoria where empresa_id = '{EMPRESAS['A'][0]}';").split()
    pasa(ACCIONES_AUDITADAS <= set(filas), f"g) la auditoria registra {sorted(ACCIONES_AUDITADAS)} ({sorted(filas)})")
    actores = valor(f"select count(*) from canal.registro_auditoria where empresa_id = '{EMPRESAS['A'][0]}' "
                    f"and actor !~ '^(plataforma|personal:[0-9a-f-]{{36}})$';")
    pasa(actores == "0", "g) cada fila de auditoria del personal tiene como actor plataforma o personal:<uuid>")
    cadena = valor(f"begin; set local role aplicacion; select set_config('app.empresa_id', '{EMPRESAS['A'][0]}', true); "
                   f"select coalesce(canal.verificar_cadena_auditoria()::text, 'intacta'); commit;").split()[-1]
    pasa(cadena == "intacta", f"g) la cadena de auditoria de la empresa sigue intacta ({cadena})")
    CUENTAS["token_admin_a"] = token_admin2


def fila_lista(token, usuario_id):
    """La fila de una cuenta en GET /usuarios, o {}."""
    datos = json_de(una(pt("GET", "/v1/personal/usuarios", token=token))) or {}
    return next((u for u in datos.get("usuarios", []) if u.get("usuario_id") == str(usuario_id)), {})


def filas_auditoria(empresa, accion):
    return valor(f"select actor || '|' || accion || '|' || objeto_id from canal.registro_auditoria "
                 f"where empresa_id = '{EMPRESAS[empresa][0]}' and accion = '{accion}' order by secuencia;").split()


def recuento_plataforma():
    """Lo que reinvitar-admin podría crear o cambiar."""
    return valor("select (select count(*) from canal.invitacion_personal) || '|' || "
                 "(select count(*) from canal.invitacion_personal where not cerrada) || '|' || "
                 "(select count(*) from canal.usuario_personal where activo) || '|' || "
                 "(select count(*) from canal.usuario_personal) || '|' || "
                 "(select count(*) from canal.sesion_personal where not revocada) || '|' || "
                 "(select count(*) from canal.registro_auditoria);")


def seccion_j():
    p("=== j) recuperacion: aviso, anulacion y reinvitar-admin")
    admin2, instr, admin_b = CUENTAS["admin2"], CUENTAS["instructor"], CUENTAS["admin_b"]
    token_admin2 = sesion_de(admin2)
    token_instr = sesion_de(instr)
    rutas = f"/v1/personal/usuarios/{instr.usuario_id}/invitacion"

    # Aviso (NIST SP 800-63B-4, 4.2.3): el titular y los admins ven la reinvitación.
    antes = json_de(una(yo(token_instr))) or {}
    reinvitacion = una(pt("POST", rutas, token=token_admin2))
    token_inv = (json_de(reinvitacion) or {}).get("token_invitacion")
    despues = json_de(una(yo(token_instr))) or {}
    en_lista = fila_lista(token_admin2, instr.usuario_id)
    negativo("j) tras una reinvitacion, invitacion_pendiente pasa a true en /yo del titular y en la lista de cuentas",
             despues.get("invitacion_pendiente") is True and en_lista.get("invitacion_pendiente") is True,
             antes.get("invitacion_pendiente") is False and reinvitacion.get("estado") == 201,
             f"antes: {antes}, despues: {despues}, lista: {en_lista}")

    # Anulación: solo admin, mismo 404 fuera de la empresa, y deja la cuenta como estaba.
    prohibida = una(pt("DELETE", rutas, token=token_instr))
    fuera = http([pt("DELETE", f"/v1/personal/usuarios/{admin_b.usuario_id}/invitacion", token=token_admin2),
                  pt("DELETE", f"/v1/personal/usuarios/{uuid.uuid4()}/invitacion", token=token_admin2),
                  pt("DELETE", "/v1/personal/usuarios/no-es-un-uuid/invitacion", token=token_admin2)])
    abiertas = valor(f"select count(*) from canal.invitacion_personal where usuario_id = '{instr.usuario_id}' "
                     f"and not cerrada;")
    anulada = una(pt("DELETE", rutas, token=token_admin2))
    control = anulada.get("estado") == 204 and abiertas == "1"
    pasa(control, f"j) control: un admin anula la invitacion abierta (204; abiertas antes: {abiertas})")
    negativo("j) un instructor recibe 403 al anular", prohibida.get("estado") == 403
             and prohibida.get("cuerpo") == CUERPO_403, control, f"respuesta: {prohibida}")
    negativo("j) anular en una cuenta de otra empresa, inexistente o con id mal formado da el mismo 404",
             all(x.get("estado") == 404 and x.get("cuerpo") == CUERPO_404 for x in fuera), control,
             f"estados: {[x.get('estado') for x in fuera]}")
    usada = una(pt("POST", "/v1/personal/activacion", {"token": token_inv, "contrasena": instr.contrasena}))
    tras = una(yo(token_instr))
    negativo("j) tras anular, la invitacion da 401, el aviso vuelve a false y la sesion del titular sigue",
             es_401(usada, CUERPO_401_INVITACION) and tras.get("estado") == 200
             and (json_de(tras) or {}).get("invitacion_pendiente") is False, control,
             f"activacion: {usada.get('estado')}, yo: {tras}")
    otra = una(pt("DELETE", rutas, token=token_admin2))
    negativo("j) sin invitacion abierta, anular da 404", otra.get("estado") == 404
             and otra.get("cuerpo") == CUERPO_404, control, f"respuesta: {otra}")
    filas = filas_auditoria("A", "anulacion_invitacion")
    pasa(filas == [f"personal:{admin2.usuario_id}|anulacion_invitacion|{instr.usuario_id}"],
         f"j) la anulacion deja una fila con el admin que la hizo ({filas})")

    # reinvitar-admin: solo sobre un admin activado de esa empresa. Los
    # rechazos se ejecutan antes que el control, que cambia la cuenta de B.
    # Email propio: d) ya usa pendiente@alfa.test para un instructor sin activar.
    pendiente, _ = invitar(token_admin2, "admin_pendiente", "admin.pendiente@alfa.test", rol="admin")
    rechazos = {}
    for nombre, email in (("un instructor", instr.email), ("un email inexistente", "nadie@alfa.test"),
                          ("un admin sin activar", pendiente.email), ("el admin de otra empresa", admin_b.email)):
        previo = recuento_plataforma()
        r = gestion("reinvitar-admin", "--identificador", EMPRESAS["A"][1], "--email", email)
        rechazos[nombre] = (r.rc == 1 and TEXTO_NO_ES_ADMIN in r.err and recuento_plataforma() == previo,
                            f"codigo {r.rc}, salida: {r.todo.strip()[-200:]!r}")

    # El caso que motiva la orden: el único admin de B, con una sesión viva.
    token_b = sesion_de(admin_b)
    dispositivo_viejo = admin_b.dispositivo
    ctl_yo = una(yo(token_b)).get("estado")
    r = gestion("reinvitar-admin", "--identificador", EMPRESAS["B"][1], "--email", admin_b.email)
    m = PATRON_INVITACION_GESTION.search(r.out)
    control = r.rc == 0 and m is not None and m.group(2) == admin_b.usuario_id and ctl_yo == 200
    pasa(control, f"j) control: reinvitar-admin emite la invitacion del unico admin de B (codigo {r.rc}; "
                  f"su sesion respondia {ctl_yo})")
    for nombre, (ok, detalle) in rechazos.items():
        negativo(f"j) reinvitar-admin con {nombre} sale con 1, lo explica y no cambia nada", ok, control, detalle)
    if not m:
        raise Parada(f"reinvitar-admin no devolvio la invitacion: {r.todo.strip()[-300:]!r}")
    tras = http([yo(token_b), pt("DELETE", f"/v1/personal/usuarios/{admin_b.usuario_id}/invitacion", token=token_b),
                 login(admin_b, codigo=codigo_libre(admin_b.secreto)[0])])
    negativo("j) en el acto: la sesion anterior da 401 (tampoco puede anular la recuperacion) "
             "y las credenciales anteriores no entran",
             es_401(tras[0], CUERPO_401_SESION) and es_401(tras[1], CUERPO_401_SESION) and es_401(tras[2]), control,
             f"estados: {[x.get('estado') for x in tras]}")
    usuario_b = admin_b.usuario_id
    # Concatenado con texto, el booleano sale como true/false.
    estado_b = valor(f"select activo || '|' "
                     f"|| (select count(*) from canal.invitacion_personal where usuario_id = '{usuario_b}' "
                     f"and not cerrada) || '|' "
                     f"|| (select count(*) from canal.sesion_personal where usuario_id = '{usuario_b}' "
                     f"and not revocada) || '|' "
                     f"|| (select count(*) from canal.dispositivo_personal where usuario_id = '{usuario_b}' "
                     f"and not revocado) "
                     f"from canal.usuario_personal where id = '{usuario_b}';")
    pasa(estado_b == "false|1|0|0",
         f"j) la cuenta queda desactivada, con una invitacion abierta y sin sesiones ni dispositivos vivos ({estado_b})")
    filas = filas_auditoria("B", "reinvitacion_admin_plataforma")
    pasa(filas == [f"plataforma|reinvitacion_admin_plataforma|{usuario_b}"],
         f"j) la reinvitacion de plataforma deja su fila en la auditoria de B ({filas})")

    # Recuperación: el titular elige credenciales nuevas y vuelve a entrar.
    admin_b.invitacion = m.group(3)
    admin_b.contrasena = secrets.token_urlsafe(18)
    _, r_conf = activar(admin_b)
    entra = login_correcto(admin_b)
    token_nuevo = (json_de(entra) or {}).get("token_acceso")
    fila = fila_lista(token_nuevo, usuario_b) if token_nuevo else {}
    pasa(r_conf is not None and r_conf.get("estado") == 200 and es_201_login(entra, False)
         and fila.get("activo") is True and fila.get("activado") is True and fila.get("invitacion_pendiente") is False,
         f"j) el unico admin de B activa la invitacion, entra con su dispositivo nuevo y su cuenta vuelve a estar "
         f"activa y sin aviso ({fila})")
    huella = hashlib.sha256(ETIQUETAS["dispositivo"] + leer_token(dispositivo_viejo)).hexdigest()
    pasa(valor(f"select revocado from canal.dispositivo_personal where token_sha256 = '\\x{huella}';") == "t",
         "j) el dispositivo anterior sigue revocado tras la recuperacion")
    cadena = valor(f"begin; set local role aplicacion; select set_config('app.empresa_id', '{EMPRESAS['B'][0]}', true); "
                   f"select coalesce(canal.verificar_cadena_auditoria()::text, 'intacta'); commit;").split()[-1]
    pasa(cadena == "intacta", f"j) la cadena de auditoria de B sigue intacta ({cadena})")


# ---------------------------------------------------------------------------
# k) Instrucción
# ---------------------------------------------------------------------------
def rd(denuncia_id):
    return f"/v1/personal/denuncias/{denuncia_id}"


def ids_denuncias(empresa):
    return set(valor(f"select id from canal.denuncia where empresa_id = '{EMPRESAS[empresa][0]}';").split())


def crear_denuncia(empresa, texto=None):
    """Crea una denuncia por la API pública. Devuelve (id, código, texto). El
    id sale de la base de datos: la API nunca se lo da al denunciante."""
    texto = texto or f"texto de denuncia k {secrets.token_hex(12)}"
    antes = ids_denuncias(empresa)
    r = una(pt("POST", f"/v1/empresas/{EMPRESAS[empresa][1]}/denuncias", {"categoria": "fraude", "texto": texto}))
    codigo = (json_de(r) or {}).get("codigo_seguimiento")
    nuevas = ids_denuncias(empresa) - antes
    if r.get("estado") != 201 or not codigo or len(nuevas) != 1:
        raise Parada(f"no se pudo crear una denuncia de preparacion: {r.get('estado')}")
    TEXTOS_SENSIBLES[f"texto de la denuncia {len(TEXTOS_SENSIBLES)}"] = texto
    TEXTOS_SENSIBLES[f"codigo de la denuncia {len(TEXTOS_SENSIBLES)}"] = codigo
    return nuevas.pop(), codigo, texto


def fila_denuncia(denuncia_id):
    """estado|asignada_a|número de mensajes."""
    return valor(f"select estado || '|' || coalesce(asignada_a::text, '') || '|' || "
                 f"(select count(*) from canal.mensaje m where m.denuncia_id = d.id) "
                 f"from canal.denuncia d where id = '{denuncia_id}';")


def asignar_peticion(token, denuncia_id, usuario_id):
    return pt("PUT", rd(denuncia_id) + "/asignacion", {"usuario_id": str(usuario_id)}, token=token)


def estado_peticion(token, denuncia_id, estado_nuevo, mensaje=None):
    datos = {"estado": estado_nuevo}
    if mensaje is not None:
        datos["mensaje"] = mensaje
    return pt("POST", rd(denuncia_id) + "/estado", datos, token=token)


def mensaje_peticion(token, denuncia_id, texto):
    return pt("POST", rd(denuncia_id) + "/mensajes", {"texto": texto}, token=token)


def seguimiento(codigo):
    return pt("POST", "/v1/seguimiento", {"codigo": codigo})


def mensaje_denunciante(codigo, texto):
    return pt("POST", "/v1/seguimiento/mensajes", {"codigo": codigo, "texto": texto})


def preparar(peticion, nombre):
    """Una petición que la sección solo necesita como preparación: si falla,
    PARADA (no es un resultado, y seguir daría una cascada de FALLA)."""
    r = una(peticion)
    if r.get("estado") not in (200, 201, 204):
        raise Parada(f"preparacion fallida ({nombre}): {r.get('estado')} {r.get('cuerpo', b'')[:200]!r}")
    return r


def total_auditoria(empresa):
    return valor(f"select count(*) from canal.registro_auditoria where empresa_id = '{EMPRESAS[empresa][0]}';")


def ultima_secuencia(empresa):
    """Marca para acciones_desde: la última secuencia de la cadena de la
    empresa (la clave es empresa_id y secuencia, y crece de uno en uno)."""
    return int(valor(f"select coalesce(max(secuencia), 0) from canal.registro_auditoria "
                     f"where empresa_id = '{EMPRESAS[empresa][0]}';"))


def acciones_desde(empresa, marca):
    """Acciones auditadas después de la marca, en orden. Una lista dice qué
    entró; un recuento no."""
    return valor(f"select accion from canal.registro_auditoria where empresa_id = '{EMPRESAS[empresa][0]}' "
                 f"and secuencia > {marca} order by secuencia;").split()


def auditoria_de(empresa, accion, objeto_id):
    """actor|destino_id de las filas de una acción sobre un objeto."""
    return valor(f"select actor || '|' || coalesce(destino_id::text, '') from canal.registro_auditoria "
                 f"where empresa_id = '{EMPRESAS[empresa][0]}' and accion = '{accion}' "
                 f"and objeto_id = '{objeto_id}' order by secuencia;").split()


def fila_lista_denuncia(token, denuncia_id):
    """La fila de una denuncia en el listado (primera página), o {}."""
    datos = json_de(una(pt("GET", "/v1/personal/denuncias", token=token))) or {}
    return next((f for f in datos.get("denuncias", []) if f.get("denuncia_id") == str(denuncia_id)), {})


def mientras_se_bloquea(sql_bloqueo, accion, segundos=8):
    """Ejecuta accion() mientras una sesión de superusuario retiene el
    bloqueo de sql_bloqueo. Devuelve (resultado, el bloqueo se vio retenido)."""
    guion = (f"SET application_name = 'k_bloqueo';\nBEGIN;\n{sql_bloqueo}\n"
             f"select pg_sleep({segundos});\nCOMMIT;\n")
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as hilo:
        futuro = hilo.submit(sup, guion)
        visto = esperar(lambda: valor("select count(*) from pg_stat_activity where application_name = 'k_bloqueo' "
                                      "and wait_event = 'PgSleep';") == "1", 20)
        resultado = accion() if visto else {}
        sesion_bloqueo = futuro.result()
    return resultado, visto and sesion_bloqueo.rc == 0


def seccion_k():
    p("=== k) instruccion: acceso, asignacion, estados, mensajes, bloqueos y auditoria")
    admin2, instr, admin_b = CUENTAS["admin2"], CUENTAS["instructor"], CUENTAS["admin_b"]
    token_admin2 = sesion_de(admin2)
    # Email propio de esta sección (los de d y j ya están usados).
    instr2, _ = invitar(token_admin2, "instructor2", "instructor2@alfa.test")
    preparar_cuenta(instr2)
    tokens = {"admin2": token_admin2, "instr": sesion_de(instr), "instr2": sesion_de(instr2),
              "admin_b": sesion_de(admin_b)}
    den1, cod1, texto1 = crear_denuncia("A")
    den2, _, _ = crear_denuncia("A")
    den3, cod3, _ = crear_denuncia("A")
    den4, _, _ = crear_denuncia("A")
    den_b, _, _ = crear_denuncia("B")

    # k1) Listado y asignación.
    lista = una(pt("GET", "/v1/personal/denuncias", token=tokens["admin2"]))
    datos = json_de(lista) or {}
    filas = {f.get("denuncia_id"): f for f in datos.get("denuncias", [])}
    control_lista = (lista.get("estado") == 200 and sorted(datos) == CLAVES_LISTADO
                     and {den1, den2, den3, den4} <= set(filas))
    pasa(control_lista, "k1) control: un admin lista las denuncias de su empresa (200)")
    negativo("k1) el listado solo lleva fecha, estado y asignacion: ni texto ni categoria",
             all(sorted(f) == CLAVES_FILA_DENUNCIA for f in filas.values())
             and texto1.encode("utf-8") not in lista.get("cuerpo", b"") and b"categoria" not in lista.get("cuerpo", b""),
             control_lista)
    negativo("k1) el listado de A no incluye la denuncia de B", den_b not in filas, control_lista)
    vacia = json_de(una(pt("GET", "/v1/personal/denuncias", token=tokens["instr"]))) or {}
    negativo("k1) un instructor sin denuncias asignadas recibe un listado vacio",
             vacia.get("denuncias") == [] and vacia.get("siguiente") is None, control_lista, f"{vacia}")

    prohibida = una(asignar_peticion(tokens["instr"], den1, instr.usuario_id))
    sin_cambio = fila_denuncia(den1)
    asignada = una(asignar_peticion(tokens["admin2"], den1, instr.usuario_id))
    control_asig = asignada.get("estado") == 204 and fila_denuncia(den1) == f"nueva|{instr.usuario_id}|0"
    pasa(control_asig, "k1) control: un admin asigna una denuncia a un instructor (204)")
    negativo("k1) un instructor no puede asignar: 403 y la denuncia no cambia",
             prohibida.get("estado") == 403 and prohibida.get("cuerpo") == CUERPO_403 and sin_cambio == "nueva||0",
             control_asig, f"respuesta: {prohibida}, fila: {sin_cambio}")
    pasa(auditoria_de("A", "asignacion", den1) == [f"personal:{admin2.usuario_id}|{instr.usuario_id}"],
         "k1) la asignacion deja su fila con el admin como actor y el instructor como destino")
    repetida = una(asignar_peticion(tokens["admin2"], den1, instr.usuario_id))
    negativo("k1) asignar otra vez a la misma cuenta responde 204 sin cambiar nada ni dejar otra fila",
             repetida.get("estado") == 204 and fila_denuncia(den1) == f"nueva|{instr.usuario_id}|0"
             and auditoria_de("A", "asignacion", den1) == [f"personal:{admin2.usuario_id}|{instr.usuario_id}"],
             control_asig, f"respuesta: {repetida.get('estado')}")
    destinos = {"una cuenta dada de baja": (CUENTAS["de_baja"].usuario_id, 409, CUERPO_409_DESTINO),
                "una cuenta sin activar": (CUENTAS["pendiente"].usuario_id, 409, CUERPO_409_DESTINO),
                "una cuenta de otra empresa": (admin_b.usuario_id, 404, CUERPO_404),
                "una cuenta inexistente": (uuid.uuid4(), 404, CUERPO_404),
                "un id mal formado": ("no-es-un-uuid", 404, CUERPO_404)}
    respuestas = http([asignar_peticion(tokens["admin2"], den2, d[0]) for d in destinos.values()])
    for (nombre, (_, codigo, cuerpo)), r in zip(destinos.items(), respuestas):
        negativo(f"k1) asignar a {nombre} da {codigo}", r.get("estado") == codigo and r.get("cuerpo") == cuerpo,
                 control_asig, f"respuesta: {r}")
    otras = http([asignar_peticion(tokens["admin2"], den_b, instr.usuario_id),
                  asignar_peticion(tokens["admin2"], uuid.uuid4(), instr.usuario_id)])
    negativo("k1) asignar una denuncia de otra empresa o inexistente da el mismo 404, y ninguna cambia",
             all(r.get("estado") == 404 and r.get("cuerpo") == CUERPO_404 for r in otras)
             and fila_denuncia(den2) == "nueva||0" and fila_denuncia(den_b) == "nueva||0", control_asig,
             f"estados: {[r.get('estado') for r in otras]}")
    propia = json_de(una(pt("GET", "/v1/personal/denuncias", token=tokens["instr"]))) or {}
    negativo("k1) el instructor ve en su listado solo su denuncia asignada",
             [f.get("denuncia_id") for f in propia.get("denuncias", [])] == [den1], control_asig, f"{propia}")

    # k2) Quién lee el contenido.
    lectura = una(pt("GET", rd(den1), token=tokens["instr"]))
    expediente = json_de(lectura) or {}
    control_lectura = (lectura.get("estado") == 200 and sorted(expediente) == CLAVES_EXPEDIENTE
                       and expediente.get("texto") == texto1 and expediente.get("categoria") == "fraude"
                       and expediente.get("estado") == "nueva" and expediente.get("mensajes") == [])
    pasa(control_lectura, "k2) control: quien tiene la denuncia asignada lee su contenido (200)")
    pasa(auditoria_de("A", "lectura_denuncia", den1) == [f"personal:{instr.usuario_id}|"],
         "k2) la lectura deja una fila de auditoria con quien la leyo")
    ajenas = {
        "otro instructor": pt("GET", rd(den1), token=tokens["instr2"]),
        "un admin sin asignacion": pt("GET", rd(den1), token=tokens["admin2"]),
        "una denuncia sin asignar": pt("GET", rd(den2), token=tokens["instr"]),
        "una denuncia inexistente": pt("GET", rd(uuid.uuid4()), token=tokens["instr"]),
        "una denuncia de otra empresa": pt("GET", rd(den_b), token=tokens["instr"]),
        "el admin de otra empresa": pt("GET", rd(den1), token=tokens["admin_b"]),
        "un id mal formado": pt("GET", rd("no-es-un-uuid"), token=tokens["instr"]),
        "mensaje de otro instructor": mensaje_peticion(tokens["instr2"], den1, "intruso"),
        "estado de otro instructor": estado_peticion(tokens["instr2"], den1, "en_instruccion"),
        "mensaje de un admin sin asignacion": mensaje_peticion(tokens["admin2"], den1, "intruso"),
        "estado de un admin sin asignacion": estado_peticion(tokens["admin2"], den1, "en_instruccion"),
    }
    respuestas = dict(zip(ajenas, http(list(ajenas.values()))))
    distintas = {k: v.get("estado") for k, v in respuestas.items()
                 if not (v.get("estado") == 404 and v.get("cuerpo") == CUERPO_404)}
    negativo(f"k2) sin asignacion: el mismo 404 byte a byte en lectura, mensaje y estado {distintas or ''}".strip(),
             not distintas, control_lectura)
    # Diagnóstico de cada respuesta inesperada: cuerpo, Retry-After y tiempo.
    # El tiempo orienta la causa de un 503 (unos 2000 ms, lock_timeout de
    # app/bd.py; unos 200 ms, el plazo de Redis de app/limitador.py). No
    # cambia ningún oráculo.
    for nombre in distintas:
        r = respuestas[nombre]
        p(f"   {nombre}: {r.get('estado')} {r.get('cuerpo', b'')[:200]!r} "
          f"retry-after={(r.get('cabeceras') or {}).get('retry-after')!r} ms={round(r.get('ms') or 0)}"
          + (f" error={r['error']}" if "error" in r else ""))
    negativo("k2) los intentos sin asignacion no cambian la denuncia ni dejan auditoria de lectura",
             fila_denuncia(den1) == f"nueva|{instr.usuario_id}|0"
             and auditoria_de("A", "lectura_denuncia", den1) == [f"personal:{instr.usuario_id}|"], control_lectura)
    # Un admin clasifica asignándose la denuncia: entonces la lee, y queda a la vista.
    preparar(asignar_peticion(tokens["admin2"], den2, admin2.usuario_id), "autoasignacion")
    autoasignada = una(pt("GET", rd(den2), token=tokens["admin2"]))
    pasa(autoasignada.get("estado") == 200
         and auditoria_de("A", "asignacion", den2) == [f"personal:{admin2.usuario_id}|{admin2.usuario_id}"],
         "k2) un admin que se asigna la denuncia la lee, y la autoasignacion queda en la auditoria")

    # k3) Bloqueos, con el SQL real dentro de la API.
    preparar(asignar_peticion(tokens["admin2"], den4, instr.usuario_id), "asignar den4")
    r = dc("exec", "-T", "api", "python", "-c", BLOQUEOS_DENTRO, EMPRESAS["A"][0], den4, str(instr.usuario_id),
           str(instr2.usuario_id))
    try:
        b = json.loads(r.out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise Parada(f"no se pudo ejecutar la prueba de bloqueos dentro de la API: {r.err.strip()[-400:]!r}") from None
    control_den = b["escritura_propia"] == [1, False] and b["lectura_propia"] == [1, False]
    pasa(control_den, f"k3) control: con la asignacion, la escritura y la lectura bloquean la denuncia ({b})")
    negativo("k3) sin la asignacion, ni la escritura ni la lectura bloquean la denuncia (cero filas y libre)",
             b["escritura_ajena"] == [0, True] and b["lectura_ajena"] == [0, True], control_den, f"{b}")
    control_baja = b["actor_frente_baja"] == [1, False]
    pasa(control_baja, "k3) control: el bloqueo de la cuenta de quien actua choca con el de una baja (FOR UPDATE)")
    negativo("k3) y no choca con el de un login fallido (FOR NO KEY UPDATE, el del UPDATE de contadores)",
             b["actor_frente_login"] == [1, True], control_baja, f"{b}")
    control_real = b["baja_deshecha"] == [True, "actua"]
    pasa(control_real, f"k3) control: si la baja se deshace, la accion que esperaba actua ({b['baja_deshecha']})")
    negativo("k3) una baja confirmada mientras la accion espera: al soltarse, la accion no actua (SesionNoValida, "
             "401)", b["baja_confirmada"] == [True, "SesionNoValida"], control_real, f"{b['baja_confirmada']}")
    # La prueba dio de baja a instructor2 solo en la base de datos: se devuelve.
    valor(f"update canal.usuario_personal set activo = true where id = '{instr2.usuario_id}'; select 1;")
    # De extremo a extremo, con la fila de la cuenta retenida por otra sesión.
    id_instr = instr.usuario_id
    login_retenido, visto_login = mientras_se_bloquea(
        f"update canal.usuario_personal set intentos_fallidos = intentos_fallidos where id = '{id_instr}';",
        lambda: una(pt("GET", rd(den4), token=tokens["instr"])))
    baja_retenida, visto_baja = mientras_se_bloquea(
        f"select 1 from canal.usuario_personal where id = '{id_instr}' for update;",
        lambda: una(pt("GET", rd(den4), token=tokens["instr"])))
    control_e2e = (visto_baja and baja_retenida.get("estado") == 503
                   and baja_retenida.get("cuerpo") == CUERPO_503_OCUPADO)
    pasa(control_e2e, "k3) control: con la cuenta retenida como en una baja mas que lock_timeout, la accion "
                      "espera y da 503 (no actua)")
    negativo("k3) mientras un login fallido actualiza los contadores de la cuenta, la accion responde 200",
             visto_login and login_retenido.get("estado") == 200, control_e2e, f"{login_retenido.get('estado')}")

    # k4) Mensajes: el personal escribe y el denunciante lee sin saber quién.
    texto_personal = f"mensaje del personal k {secrets.token_hex(8)}"
    TEXTOS_SENSIBLES["mensaje del personal"] = texto_personal
    enviado = una(mensaje_peticion(tokens["instr"], den1, texto_personal))
    control_msj = enviado.get("estado") == 201 and (json_de(enviado) or {}).get("secuencia") == 1
    pasa(control_msj, "k4) control: quien tiene la denuncia asignada envia un mensaje (201, secuencia 1)")
    seg = json_de(una(seguimiento(cod1))) or {}
    msj = (seg.get("mensajes") or [{}])[0]
    negativo("k4) el denunciante ve el mensaje como del personal, sin autor_id ni id de la cuenta",
             sorted(msj) == CLAVES_MENSAJE_SEGUIMIENTO and msj.get("autor") == "personal"
             and msj.get("texto") == texto_personal and str(instr.usuario_id) not in json.dumps(seg), control_msj,
             f"{msj}")
    preparar(mensaje_denunciante(cod1, "respuesta del denunciante"), "respuesta del denunciante")
    vista = json_de(una(pt("GET", rd(den1), token=tokens["instr"]))) or {}
    mensajes = vista.get("mensajes", [])
    negativo("k4) el personal ve la conversacion con autor_id: el suyo en su mensaje, null en el del denunciante",
             len(mensajes) == 2 and all(sorted(m) == CLAVES_MENSAJE_PERSONAL for m in mensajes)
             and mensajes[0].get("autor_id") == str(instr.usuario_id) and mensajes[1].get("autor") == "denunciante"
             and mensajes[1].get("autor_id") is None, control_msj, f"{mensajes}")
    pasa(auditoria_de("A", "mensaje_personal", den1) == [f"personal:{instr.usuario_id}|"],
         "k4) el mensaje del personal deja su fila de auditoria")
    vacios = http([mensaje_peticion(tokens["instr"], den1, "   "), estado_peticion(tokens["instr"], den1, "nueva")])
    negativo("k4) un mensaje solo de espacios y el estado 'nueva' como destino dan 422",
             all(r.get("estado") == 422 and r.get("cuerpo") == CUERPO_422 for r in vacios), control_msj,
             f"estados: {[r.get('estado') for r in vacios]}")

    # k5) La tabla de transiciones completa, contra el oráculo literal.
    resultados = {}
    for origen in ESTADOS:
        for destino in ESTADOS_DESTINO:
            valor(f"update canal.denuncia set estado = '{origen}' where id = '{den4}'; select 1;")
            antes = fila_denuncia(den4)
            r = una(estado_peticion(tokens["instr"], den4, destino, "mensaje de la transicion"))
            resultados[(origen, destino)] = (r, antes, fila_denuncia(den4))
    validas = [k for k in resultados if k in TRANSICIONES_ESPERADAS]
    control_trans = len(validas) == 4 and all(
        resultados[k][0].get("estado") == 204 and resultados[k][2].split("|")[0] == k[1]
        and int(resultados[k][2].split("|")[2]) == int(resultados[k][1].split("|")[2]) + 1 for k in validas)
    pasa(control_trans, "k5) control: las 4 transiciones permitidas responden 204 y aplican el estado y el mensaje")
    rechazadas = {k: v for k, v in resultados.items() if k not in TRANSICIONES_ESPERADAS}
    malas = {f"{k[0]}->{k[1]}": v[0].get("estado") for k, v in rechazadas.items()
             if not (v[0].get("estado") == 409 and v[0].get("cuerpo") == CUERPO_409_TRANSICION and v[2] == v[1])}
    negativo(f"k5) las {len(rechazadas)} transiciones no permitidas dan 409 y no cambian estado ni mensajes "
             f"{malas or ''}".strip(), not malas and len(rechazadas) == 16, control_trans)
    valor(f"update canal.denuncia set estado = 'en_instruccion' where id = '{den4}'; select 1;")
    antes = fila_denuncia(den4)
    sin_final = http([estado_peticion(tokens["instr"], den4, e) for e in ("resuelta", "archivada")])
    tras_instruccion = fila_denuncia(den4)
    valor(f"update canal.denuncia set estado = 'nueva' where id = '{den4}'; select 1;")
    antes_nueva = fila_denuncia(den4)
    sin_final.append(una(estado_peticion(tokens["instr"], den4, "inadmitida")))
    negativo("k5) cerrar (resuelta, archivada o inadmitida) sin mensaje final da 422 y no cambia nada",
             all(r.get("estado") == 422 and r.get("cuerpo") == CUERPO_422_FINAL for r in sin_final)
             and tras_instruccion == antes and fila_denuncia(den4) == antes_nueva, control_trans,
             f"estados: {[r.get('estado') for r in sin_final]}")

    # k6) Cierre e inadmisión, vistos por el denunciante.
    preparar(estado_peticion(tokens["instr"], den1, "en_instruccion"), "iniciar instruccion")
    final = f"mensaje final k {secrets.token_hex(8)}"
    TEXTOS_SENSIBLES["mensaje final"] = final
    cierre = una(estado_peticion(tokens["instr"], den1, "resuelta", final))
    seg = json_de(una(seguimiento(cod1))) or {}
    control_cierre = cierre.get("estado") == 204 and seg.get("estado") == "resuelta"
    pasa(control_cierre, "k6) control: cerrar con mensaje final (204) deja la denuncia resuelta")
    ultimo = (seg.get("mensajes") or [{}])[-1]
    negativo("k6) el mensaje final es el ultimo de la conversacion, del personal",
             ultimo.get("texto") == final and ultimo.get("autor") == "personal", control_cierre, f"{ultimo}")
    tras = http([mensaje_denunciante(cod1, "despues del cierre"), mensaje_peticion(tokens["instr"], den1, "tarde"),
                 asignar_peticion(tokens["admin2"], den1, instr2.usuario_id)])
    negativo("k6) cerrada: el mensaje del denunciante, el del personal y la asignacion dan 409, sin cambios",
             tras[0].get("estado") == 409 and tras[0].get("cuerpo") == CUERPO_409_CERRADA_DENUNCIANTE
             and tras[1].get("estado") == 409 and tras[1].get("cuerpo") == CUERPO_409_CERRADA
             and tras[2].get("estado") == 409 and tras[2].get("cuerpo") == CUERPO_409_CERRADA
             and fila_denuncia(den1) == f"resuelta|{instr.usuario_id}|3", control_cierre,
             f"estados: {[r.get('estado') for r in tras]}, fila: {fila_denuncia(den1)}")
    pasa(auditoria_de("A", "estado_en_instruccion", den1) == [f"personal:{instr.usuario_id}|"]
         and auditoria_de("A", "estado_resuelta", den1) == [f"personal:{instr.usuario_id}|"],
         "k6) cada cambio de estado deja su fila de auditoria")
    preparar(asignar_peticion(tokens["admin2"], den3, instr.usuario_id), "asignar den3")
    inadmision = una(estado_peticion(tokens["instr"], den3, "inadmitida", "no se da curso a esta comunicacion"))
    seg3 = json_de(una(seguimiento(cod3))) or {}
    control_inad = inadmision.get("estado") == 204 and seg3.get("estado") == "inadmitida"
    pasa(control_inad, "k6) control: una denuncia nueva se inadmite con mensaje (204) y el denunciante lo ve")
    tarde = una(mensaje_denunciante(cod3, "despues de inadmitir"))
    negativo("k6) inadmitida es un cierre: el denunciante recibe 409", tarde.get("estado") == 409
             and tarde.get("cuerpo") == CUERPO_409_CERRADA_DENUNCIANTE, control_inad, f"{tarde}")

    # k7) Carrera: cierre con mensaje final y mensaje del denunciante a la vez.
    rondas = []
    for _ in range(3):
        den, cod, _ = crear_denuncia("A")
        preparar(asignar_peticion(tokens["admin2"], den, instr.usuario_id), "asignar carrera")
        preparar(estado_peticion(tokens["instr"], den, "en_instruccion"), "instruccion carrera")
        cerrar, escribir = http([{"grupo": [estado_peticion(tokens["instr"], den, "resuelta", "final de carrera"),
                                            mensaje_denunciante(cod, "mensaje en carrera")]}])
        orden = valor(f"select string_agg(autor, ',' order by secuencia) from canal.mensaje "
                      f"where denuncia_id = '{den}';")
        rondas.append((cerrar.get("estado"), escribir.get("estado"), orden, fila_denuncia(den).split("|")[0]))
    pasa(all(c == 204 and e in (201, 409) and estado_final == "resuelta" and orden.split(",")[-1] == "personal"
             and orden.count("denunciante") == (1 if e == 201 else 0) for c, e, orden, estado_final in rondas),
         f"k7) cierre y mensaje simultaneos: sin interbloqueo ni 5xx; el mensaje entra antes del final o recibe 409 "
         f"({rondas})")

    # k8) Auditoría por la API.
    antes = total_auditoria("A")
    auditoria = una(pt("GET", "/v1/personal/auditoria", token=tokens["admin2"]))
    verificacion = una(pt("GET", "/v1/personal/auditoria/verificacion", token=tokens["admin2"]))
    lista_otra = una(pt("GET", "/v1/personal/denuncias", token=tokens["admin2"]))
    datos = json_de(auditoria) or {}
    filas_aud = datos.get("filas", [])
    control_aud = (auditoria.get("estado") == 200 and sorted(datos) == CLAVES_AUDITORIA
                   and lista_otra.get("estado") == 200)
    pasa(control_aud and all(sorted(f) == CLAVES_FILA_AUDITORIA for f in filas_aud)
         and [f.get("secuencia") for f in filas_aud] == list(range(1, len(filas_aud) + 1)),
         "k8) un admin lee la auditoria de su empresa desde el principio, en orden y sin huecos")
    datos_ver = json_de(verificacion) or {}
    pasa(verificacion.get("estado") == 200 and sorted(datos_ver) == CLAVES_VERIFICACION
         and datos_ver.get("cadena_intacta") is True and datos_ver.get("primera_rota") is None,
         f"k8) la verificacion, aparte del listado, da la cadena intacta ({datos_ver})")
    negativo("k8) en ella se ve la autoasignacion del admin (actor y destino el mismo)",
             any(f.get("accion") == "asignacion" and f.get("objeto_id") == den2
                 and f.get("actor") == f"personal:{admin2.usuario_id}" and f.get("destino_id") == str(admin2.usuario_id)
                 for f in filas_aud), control_aud)
    negativo("k8) leer la auditoria, verificarla y el listado no dejan filas de auditoria",
             total_auditoria("A") == antes, control_aud)
    desde = json_de(una(pt("GET", "/v1/personal/auditoria?desde=3", token=tokens["admin2"]))) or {}
    negativo("k8) desde=3 empieza en la secuencia 3",
             [f.get("secuencia") for f in desde.get("filas", [])][:1] == [3], control_aud)
    malas = http([pt("GET", "/v1/personal/auditoria", token=tokens["instr"]),
                  pt("GET", "/v1/personal/auditoria/verificacion", token=tokens["instr"]),
                  pt("GET", "/v1/personal/auditoria?desde=0", token=tokens["admin2"]),
                  pt("GET", "/v1/personal/auditoria?desde=x", token=tokens["admin2"])])
    negativo("k8) un instructor recibe 403 en el listado y en la verificacion; desde=0 o no numerico da 422",
             all(r.get("estado") == 403 and r.get("cuerpo") == CUERPO_403 for r in malas[:2])
             and all(r.get("estado") == 422 and r.get("cuerpo") == CUERPO_422 for r in malas[2:]), control_aud,
             f"estados: {[r.get('estado') for r in malas]}")
    ajena = una(pt("GET", "/v1/personal/auditoria", token=tokens["admin_b"]))
    negativo("k8) el admin de B no ve ninguna fila de A", ajena.get("estado") == 200
             and den1.encode() not in ajena.get("cuerpo", b"") and den2.encode() not in ajena.get("cuerpo", b""),
             control_aud)

    # k9) Baja de una cuenta con denuncias asignadas, y paginación.
    preparar(asignar_peticion(tokens["admin2"], den2, instr2.usuario_id), "asignar den2 a instr2")
    activa = fila_lista_denuncia(tokens["admin2"], den2).get("asignada_activa")
    preparar(pt("POST", f"/v1/personal/usuarios/{instr2.usuario_id}/baja", token=tokens["admin2"]), "baja instr2")
    tras_baja = fila_lista_denuncia(tokens["admin2"], den2)
    negativo("k9) tras la baja de su instructor, la denuncia sigue asignada y el listado la marca como inactiva",
             tras_baja.get("asignada_a") == str(instr2.usuario_id) and tras_baja.get("asignada_activa") is False,
             activa is True, f"antes: {activa}, despues: {tras_baja}")
    # 101 denuncias más en B: 102 en total, dos páginas sin huecos ni repeticiones.
    peticion = pt("POST", f"/v1/empresas/{EMPRESAS['B'][1]}/denuncias", {"categoria": "otros", "texto": "lote k9"})
    creadas = http([peticion] * (TAMANO_PAGINA_DENUNCIAS + 1))
    esperadas = ids_denuncias("B")
    if not all(r.get("estado") == 201 for r in creadas) or len(esperadas) != TAMANO_PAGINA_DENUNCIAS + 2:
        raise Parada(f"no se pudieron crear las denuncias de la paginacion ({len(esperadas)})")
    p1 = json_de(una(pt("GET", "/v1/personal/denuncias", token=tokens["admin_b"]))) or {}
    siguiente = p1.get("siguiente") or ""
    p2 = json_de(una(pt("GET", f"/v1/personal/denuncias?cursor={siguiente}", token=tokens["admin_b"]))) or {}
    vistas = [f.get("denuncia_id") for f in p1.get("denuncias", []) + p2.get("denuncias", [])]
    control_pag = len(p1.get("denuncias", [])) == TAMANO_PAGINA_DENUNCIAS and bool(siguiente)
    pasa(control_pag, f"k9) control: la primera pagina trae {TAMANO_PAGINA_DENUNCIAS} denuncias y un cursor")
    negativo("k9) las dos paginas suman todas las denuncias de B, sin repetir, y la segunda no tiene siguiente",
             len(vistas) == len(set(vistas)) and set(vistas) == esperadas and p2.get("siguiente") is None,
             control_pag, f"{len(vistas)} vistas, {len(set(vistas))} distintas, {len(esperadas)} esperadas")
    filtro = json_de(una(pt("GET", "/v1/personal/denuncias?estado=resuelta", token=tokens["admin2"]))) or {}
    negativo("k9) el filtro por estado solo devuelve ese estado",
             bool(filtro.get("denuncias")) and all(f.get("estado") == "resuelta" for f in filtro["denuncias"]),
             control_pag, f"{filtro}")
    malos = http([pt("GET", f"/v1/personal/denuncias?cursor={c}", token=tokens["admin2"])
                  for c in ("20261012", "2026-10-12", f"2026-13-01.{den1}", f"2026-10-12.{den1}x")]
                 + [pt("GET", "/v1/personal/denuncias?estado=inventado", token=tokens["admin2"])])
    negativo("k9) un cursor mal formado o un estado desconocido dan 422",
             all(r.get("estado") == 422 and r.get("cuerpo") == CUERPO_422 for r in malos), control_pag,
             f"estados: {[r.get('estado') for r in malos]}")
    cadena = valor(f"begin; set local role aplicacion; select set_config('app.empresa_id', '{EMPRESAS['A'][0]}', true); "
                   f"select coalesce(canal.verificar_cadena_auditoria()::text, 'intacta'); commit;").split()[-1]
    pasa(cadena == "intacta", f"k9) la cadena de auditoria de A sigue intacta al terminar ({cadena})")


def seccion_k_no_veraz():
    p("=== k10) no veraz (art. 32.3): solo admin, sin mensaje, invisible para todos y suprimida por gestion")
    admin2, instr = CUENTAS["admin2"], CUENTAS["instructor"]
    token_admin, token_instr = sesion_de(admin2), sesion_de(instr)
    # Una denuncia por estado de origen, asignadas al admin; otra asignada al
    # instructor (403 y 404 del admin) y otra que no se toca (control).
    origenes = {}
    for origen in ESTADOS:
        den, cod, _ = crear_denuncia("A")
        preparar(asignar_peticion(token_admin, den, admin2.usuario_id), f"asignar {origen}")
        origenes[origen] = (den, cod)
    den_instr, _, _ = crear_denuncia("A")
    preparar(asignar_peticion(token_admin, den_instr, instr.usuario_id), "asignar al instructor")
    den_ctl, cod_ctl, _ = crear_denuncia("A")
    preparar(asignar_peticion(token_admin, den_ctl, admin2.usuario_id), "asignar el control")
    den_n, cod_n = origenes["nueva"]
    # La nueva lleva un mensaje de cada lado, para ver que la supresion los borra.
    preparar(mensaje_denunciante(cod_n, "mensaje antes de no veraz"), "mensaje del denunciante")
    preparar(mensaje_peticion(token_admin, den_n, "mensaje del personal antes de no veraz"), "mensaje del personal")
    for origen, (den, _) in origenes.items():
        valor(f"update canal.denuncia set estado = '{origen}' where id = '{den}'; select 1;")
    eventos_antes = sum(TEXTO_EVENTO_NO_VERAZ in l for l in lineas_log("api"))

    # k10a) Antes de declararla, todos la ven (control de los 404 de despues).
    antes = {"lectura del admin": una(pt("GET", rd(den_n), token=token_admin)),
             "seguimiento": una(seguimiento(cod_n))}
    control_vista = all(r.get("estado") == 200 for r in antes.values()) and den_n in {
        f.get("denuncia_id") for f in (json_de(una(pt("GET", "/v1/personal/denuncias", token=token_admin))) or {})
        .get("denuncias", [])}
    pasa(control_vista, "k10a) control: antes de declararla, el admin la lee y la lista y el denunciante la sigue")

    # k10b) Quien no puede declararla: instructor (403), admin sin la denuncia
    #       asignada (404) y con mensaje (422). Nada cambia ni deja rastro.
    antes_instr, antes_n = fila_denuncia(den_instr), fila_denuncia(den_n)
    rechazos = [una(estado_peticion(token_instr, den_instr, "no_veraz")),
                una(estado_peticion(token_admin, den_instr, "no_veraz")),
                una(estado_peticion(token_admin, den_n, "no_veraz", "mensaje que nadie leeria"))]
    tras_rechazos_instr, tras_rechazos_n = fila_denuncia(den_instr), fila_denuncia(den_n)
    # k10c) Desde cada estado visible, el admin con la denuncia asignada la
    #       declara no veraz (204), sin mensaje y sin cambiar los mensajes.
    resultados = {}
    for origen, (den, _) in origenes.items():
        previa = fila_denuncia(den)
        r = una(estado_peticion(token_admin, den, "no_veraz"))
        resultados[(origen, "no_veraz")] = (r.get("estado"), previa, fila_denuncia(den))
    control_decl = set(resultados) == TRANSICIONES_NO_VERAZ and all(
        codigo == 204 and despues.split("|")[0] == "no_veraz" and despues.split("|")[1:] == previa.split("|")[1:]
        for codigo, previa, despues in resultados.values())
    pasa(control_decl, f"k10c) control: desde los 5 estados visibles el admin la declara no veraz (204) sin "
                       f"mensaje y sin tocar los demas campos ({ {k[0]: v[0] for k, v in resultados.items()} })")
    negativo("k10b) un instructor no puede declararla: 403, y la denuncia no cambia",
             rechazos[0].get("estado") == 403 and rechazos[0].get("cuerpo") == CUERPO_403
             and tras_rechazos_instr == antes_instr, control_decl, f"{rechazos[0]}")
    negativo("k10b) un admin sin la denuncia asignada recibe el 404 generico, y no cambia",
             rechazos[1].get("estado") == 404 and rechazos[1].get("cuerpo") == CUERPO_404
             and fila_denuncia(den_instr) == antes_instr, control_decl, f"{rechazos[1]}")
    negativo("k10b) declararla con mensaje da 422 y no la cambia ni le anade el mensaje",
             rechazos[2].get("estado") == 422 and rechazos[2].get("cuerpo") == CUERPO_422_NO_VERAZ
             and tras_rechazos_n == antes_n, control_decl, f"{rechazos[2]}, fila: {tras_rechazos_n}")
    pasa(all(auditoria_de("A", "estado_no_veraz", den) == [f"personal:{admin2.usuario_id}|"]
             for den, _ in origenes.values()) and auditoria_de("A", "estado_no_veraz", den_instr) == [],
         "k10c) cada declaracion deja su fila estado_no_veraz con el admin; los rechazos no dejan ninguna")

    # k10d) Para la API ya no existe: el mismo 404 que una inexistente, para
    #       el personal (lectura, mensaje, estado y asignacion) y para el
    #       denunciante (seguimiento y mensaje). El listado no la muestra y el
    #       filtro por no_veraz no es un estado visible (422).
    personal_404 = http([pt("GET", rd(den_n), token=token_admin),
                         mensaje_peticion(token_admin, den_n, "despues"),
                         estado_peticion(token_admin, den_n, "en_instruccion"),
                         estado_peticion(token_admin, den_n, "no_veraz"),
                         asignar_peticion(token_admin, den_n, admin2.usuario_id)])
    denunciante_404 = http([seguimiento(cod_n), mensaje_denunciante(cod_n, "despues")])
    ctl_vivo = una(seguimiento(cod_ctl))
    control_vivo = control_vista and ctl_vivo.get("estado") == 200
    negativo("k10d) el personal recibe el 404 generico byte a byte en lectura, mensaje, estado y asignacion",
             all(r.get("estado") == 404 and r.get("cuerpo") == CUERPO_404 for r in personal_404), control_vivo,
             f"estados: {[r.get('estado') for r in personal_404]}")
    negativo("k10d) el denunciante recibe el 404 de codigo no valido en seguimiento y en mensaje",
             all(r.get("estado") == 404 and r.get("cuerpo") == CUERPO_404_CODIGO for r in denunciante_404),
             control_vivo, f"estados: {[r.get('estado') for r in denunciante_404]}")
    listado = json_de(una(pt("GET", "/v1/personal/denuncias", token=token_admin))) or {}
    vistas = {f.get("denuncia_id") for f in listado.get("denuncias", [])}
    filtro = una(pt("GET", "/v1/personal/denuncias?estado=no_veraz", token=token_admin))
    negativo("k10d) el listado no muestra ninguna no veraz (si el control) y filtrar por no_veraz da 422",
             not vistas & {den for den, _ in origenes.values()} and den_ctl in vistas
             and filtro.get("estado") == 422 and filtro.get("cuerpo") == CUERPO_422, control_vivo,
             f"filtro: {filtro.get('estado')}")
    negativo("k10d) los intentos posteriores no cambian la denuncia (sigue no_veraz con sus 2 mensajes)",
             fila_denuncia(den_n) == f"no_veraz|{admin2.usuario_id}|2", control_vivo, fila_denuncia(den_n))

    # k10e) Un evento por declaracion, con empresa, cuenta y denuncia; los
    #       rechazos no dejan ninguno.
    nuevos = [l for l in lineas_log("api") if TEXTO_EVENTO_NO_VERAZ in l][eventos_antes:]
    esperados = sorted(f"{TEXTO_EVENTO_NO_VERAZ}empresa={EMPRESAS['A'][0]} cuenta={admin2.usuario_id} denuncia={den}"
                       for den, _ in origenes.values())
    negativo("k10e) el log tiene exactamente un EVENTO declaracion_no_veraz por declaracion, sin contenido",
             sorted(l[l.index(TEXTO_EVENTO_NO_VERAZ):] for l in nuevos) == esperados, control_decl, f"{nuevos}")

    # k10f) gestion suprimir-caducadas las destruye (art32_3), con sus
    #       mensajes y sus codigos, y deja la evidencia; el control sigue.
    ids_nv = [den for den, _ in origenes.values()]
    lista_sql = ", ".join(f"'{d}'" for d in ids_nv)
    r = gestion("suprimir-caducadas")
    esperado = [f"suprimidas: empresa_id={EMPRESAS['A'][0]} articulo=art32_3 denuncias=5", "total suprimidas: 5",
                "solicitudes de registro podadas: 0"]
    control_sup = r.rc == 0 and r.out.strip().splitlines() == esperado
    pasa(control_sup, f"k10f) gestion suprimir-caducadas suprime las 5 por art32_3 y sale con 0 ({r.out.strip()!r})")
    restos = valor(f"select (select count(*) from canal.denuncia where id in ({lista_sql})) || '|' || "
                   f"(select count(*) from canal.mensaje where denuncia_id in ({lista_sql})) || '|' || "
                   f"(select count(*) from canal.busqueda_seguimiento where denuncia_id in ({lista_sql})) || '|' || "
                   f"(select count(*) from canal.denuncia where id = '{den_ctl}');")
    negativo("k10f) no queda ni la denuncia, ni sus mensajes, ni su codigo; la de control sigue",
             restos == "0|0|0|1", control_sup, restos)
    evidencia = sorted(valor(f"select actor || '|' || objeto_id from canal.registro_auditoria "
                             f"where accion = 'supresion_art32_3' and objeto_id in ({lista_sql});").split())
    negativo("k10f) una fila sistema|supresion_art32_3 por denuncia suprimida",
             evidencia == sorted(f"sistema|{d}" for d in ids_nv), control_sup, f"{evidencia}")
    tras = una(seguimiento(cod_n))
    negativo("k10f) tras la supresion el codigo sigue dando el mismo 404",
             tras.get("estado") == 404 and tras.get("cuerpo") == CUERPO_404_CODIGO, control_sup, f"{tras}")


def redaccion_peticion(token, denuncia_id, tramos, secuencia=None):
    ruta = rd(denuncia_id) + ("" if secuencia is None else f"/mensajes/{secuencia}") + "/redaccion"
    return pt("POST", ruta, {"tramos": tramos}, token=token)


def texto_personal(token, denuncia_id):
    """Texto de la denuncia y de sus mensajes tal como los lee el personal."""
    datos = json_de(una(pt("GET", rd(denuncia_id), token=token))) or {}
    return datos.get("texto"), [m.get("texto") for m in datos.get("mensajes", [])]


def texto_seguimiento(codigo):
    """Lo mismo, tal como lo ve el denunciante."""
    datos = json_de(una(seguimiento(codigo))) or {}
    return datos.get("texto"), [m.get("texto") for m in datos.get("mensajes", [])]


def seccion_k_redaccion():
    p("=== k11) redaccion (art. 32.2): solo admin asignado, texto exacto, tachado para todos y auditada")
    admin2, instr, admin_b = CUENTAS["admin2"], CUENTAS["instructor"], CUENTAS["admin_b"]
    token_admin, token_instr, token_b = sesion_de(admin2), sesion_de(instr), sesion_de(admin_b)
    den, cod, _ = crear_denuncia("A", REDACCION_TEXTO)
    preparar(asignar_peticion(token_admin, den, admin2.usuario_id), "asignar la denuncia al admin")
    preparar(mensaje_denunciante(cod, REDACCION_MENSAJE), "mensaje del denunciante")
    TEXTOS_SENSIBLES["mensaje que se redacta"] = REDACCION_MENSAJE
    den_instr, _, _ = crear_denuncia("A")
    preparar(asignar_peticion(token_admin, den_instr, instr.usuario_id), "asignar al instructor")
    den_nv, _, _ = crear_denuncia("A")
    preparar(asignar_peticion(token_admin, den_nv, admin2.usuario_id), "asignar la no veraz")
    preparar(estado_peticion(token_admin, den_nv, "no_veraz"), "declarar no veraz")
    eventos_antes = sum(TEXTO_EVENTO_REDACCION in l for l in lineas_log("api"))

    # k11a) Antes de redactar, el personal y el denunciante leen el original
    #       (control de lo que cambia despues).
    original = (REDACCION_TEXTO, [REDACCION_MENSAJE])
    control_original = texto_personal(token_admin, den) == original and texto_seguimiento(cod) == original
    pasa(control_original, "k11a) control: antes de redactar, el admin y el denunciante leen el texto original")

    # k11b) Rechazos: nada cambia ni deja fila ni evento. Leer una denuncia
    #       desde el personal deja su fila de lectura (instruccion.leer_denuncia),
    #       así que entre la marca y la lista de acciones solo van los rechazos:
    #       ninguna lectura.
    marca_rechazos = ultima_secuencia("A")
    lineas_antes = len(lineas_log("api"))
    tramo = [{"desde": REDACCION_DESDE, "texto": REDACCION_FRAGMENTO}]
    por_ruta = {
        "instructor (403)": (una(redaccion_peticion(token_instr, den_instr, tramo)), 403, CUERPO_403),
        "admin sin la denuncia asignada (404)": (una(redaccion_peticion(token_admin, den_instr, tramo)), 404,
                                                 CUERPO_404),
        "admin de otra empresa (404)": (una(redaccion_peticion(token_b, den, tramo)), 404, CUERPO_404),
        "denuncia no veraz (404)": (una(redaccion_peticion(token_admin, den_nv, tramo)), 404, CUERPO_404),
        "mensaje inexistente (404)": (una(redaccion_peticion(token_admin, den, tramo, secuencia=5)), 404, CUERPO_404),
        "id con un salto de linea codificado (404)": (una(redaccion_peticion(token_admin, ID_CON_SALTO, tramo)), 404,
                                                      CUERPO_404),
        # La posicion en UTF-16 (la de un navegador): el emoji ocupa dos
        # unidades y el tramo cae una despues. No se tacha nada desplazado.
        "posicion contada en UTF-16 (409)": (
            una(redaccion_peticion(token_admin, den, [{"desde": REDACCION_DESDE_UTF16, "texto": REDACCION_FRAGMENTO}])),
            409, CUERPO_409_FRAGMENTO),
        "texto que no esta en esa posicion (409)": (
            una(redaccion_peticion(token_admin, den, [{"desde": REDACCION_DESDE, "texto": "diabetis"}])),
            409, CUERPO_409_FRAGMENTO),
        "tramo que se sale del texto (409)": (
            una(redaccion_peticion(token_admin, den, [{"desde": 9990, "texto": "diabetes"}])), 409,
            CUERPO_409_FRAGMENTO),
        # Un tramo bueno y otro malo: no se aplica ninguno.
        "un tramo bueno y otro malo (409)": (
            una(redaccion_peticion(token_admin, den, tramo + [{"desde": 0, "texto": "Tu"}])), 409,
            CUERPO_409_FRAGMENTO),
    }
    forma = {
        "sin tramos": {"tramos": []},
        "51 tramos": {"tramos": tramo * 51},
        "desde negativo": {"tramos": [{"desde": -1, "texto": "M"}]},
        "desde como texto": {"tramos": [{"desde": str(REDACCION_DESDE), "texto": REDACCION_FRAGMENTO}]},
        "desde como booleano": {"tramos": [{"desde": True, "texto": "i"}]},
        "texto vacio": {"tramos": [{"desde": 0, "texto": ""}]},
        "campo de mas": {"tramos": [{"desde": REDACCION_DESDE, "texto": REDACCION_FRAGMENTO, "hasta": 40}]},
        "texto con NUL": {"tramos": [{"desde": 0, "texto": "M\u0000"}]},
    }
    rechazos_forma = {n: una(pt("POST", rd(den) + "/redaccion", c, token=token_admin)) for n, c in forma.items()}
    secuencia_0 = una(redaccion_peticion(token_admin, den, tramo, secuencia=0))
    acciones_rechazos = acciones_desde("A", marca_rechazos)
    sin_cambios = texto_personal(token_admin, den) == original and texto_seguimiento(cod) == original

    # k11c) Controles positivos: el admin con la denuncia asignada tacha un
    #       dato de salud del texto de la denuncia y un nombre del mensaje del
    #       denunciante. Lo ven tachado el personal y el denunciante.
    marca_redacciones = ultima_secuencia("A")
    r_den = una(redaccion_peticion(token_admin, den, tramo))
    r_men = una(redaccion_peticion(token_admin, den, [{"desde": REDACCION_DESDE_MENSAJE, "texto": "Pepe"}],
                                   secuencia=1))
    # Control de la medida de filas: las dos redacciones, y nada más, antes
    # de cualquier lectura (que dejaria su propia fila).
    acciones_redacciones = acciones_desde("A", marca_redacciones)
    control_filas = acciones_redacciones == ["redaccion_denuncia", "redaccion_mensaje"]
    pasa(control_filas, f"k11c) control: las dos redacciones dejan exactamente sus dos filas ({acciones_redacciones})")
    tachado = (REDACCION_TEXTO_TACHADO, [REDACCION_MENSAJE_TACHADO])
    # El detalle lleva solo estados y coincidencias, nunca el texto: es
    # contenido de una denuncia, y con el emoji tampoco se podria imprimir en
    # una consola cp1252.
    personal_ok = texto_personal(token_admin, den) == tachado
    seguimiento_ok = texto_seguimiento(cod) == tachado
    control = (control_original and r_den.get("estado") == 204 and r_men.get("estado") == 204
               and personal_ok and seguimiento_ok)
    pasa(control, f"k11c) control: 204 y el texto tachado exacto para el personal y para el denunciante "
                  f"(estados {r_den.get('estado')} y {r_men.get('estado')}, personal {personal_ok}, "
                  f"denunciante {seguimiento_ok})")
    for nombre, (r, codigo, cuerpo) in por_ruta.items():
        negativo(f"k11b) {nombre}", r.get("estado") == codigo and r.get("cuerpo") == cuerpo, control,
                 f"{r.get('estado')} {r.get('cuerpo', b'')[:120]!r}")
    for nombre, r in rechazos_forma.items():
        negativo(f"k11b) {nombre}: 422 generico", r.get("estado") == 422 and r.get("cuerpo") == CUERPO_422, control,
                 f"{r.get('estado')}")
    negativo("k11b) mensaje con secuencia 0: 422 generico",
             secuencia_0.get("estado") == 422 and secuencia_0.get("cuerpo") == CUERPO_422, control,
             f"{secuencia_0.get('estado')}")
    negativo("k11b) tras los rechazos el texto y los mensajes no habian cambiado", sin_cambios, control)
    negativo("k11b) los rechazos no dejan ninguna fila de auditoria", acciones_rechazos == [], control_filas,
             f"{acciones_rechazos}")

    # k11d) Cada redaccion deja su fila con el admin; la del mensaje, con el
    #       id del mensaje como destino. La cadena sigue intacta.
    mensaje_id = valor(f"select id from canal.mensaje where denuncia_id = '{den}' and secuencia = 1;")
    negativo("k11d) una fila redaccion_denuncia y una redaccion_mensaje (con el mensaje), con el admin",
             auditoria_de("A", "redaccion_denuncia", den) == [f"personal:{admin2.usuario_id}|"]
             and auditoria_de("A", "redaccion_mensaje", den) == [f"personal:{admin2.usuario_id}|{mensaje_id}"],
             control, f"{auditoria_de('A', 'redaccion_denuncia', den)} {auditoria_de('A', 'redaccion_mensaje', den)}")
    verificacion = json_de(una(pt("GET", "/v1/personal/auditoria/verificacion", token=token_admin))) or {}
    negativo("k11d) la cadena de auditoria sigue intacta", verificacion.get("cadena_intacta") is True, control,
             f"{verificacion}")

    # k11e) Idempotente: pedir que se tache lo que ya esta tachado responde
    #       204 sin escribir, sin fila y sin evento.
    marca = ultima_secuencia("A")
    cifrado = valor(f"select encode(contenido_cifrado, 'hex') from canal.denuncia where id = '{den}';")
    r = una(redaccion_peticion(token_admin, den, [{"desde": REDACCION_DESDE, "texto": "█" * 8}]))
    acciones = acciones_desde("A", marca)
    negativo("k11e) tachar lo ya tachado: 204 sin reescribir el contenido ni dejar fila",
             r.get("estado") == 204 and acciones == []
             and valor(f"select encode(contenido_cifrado, 'hex') from canal.denuncia where id = '{den}';") == cifrado,
             control and control_filas, f"{r.get('estado')} {acciones}")

    # k11f) Un evento por redaccion, con posiciones y longitudes y sin el
    #       texto tachado; los rechazos y la idempotente no dejan ninguno.
    nuevos = [l for l in lineas_log("api") if TEXTO_EVENTO_REDACCION in l][eventos_antes:]
    base = f"{TEXTO_EVENTO_REDACCION}empresa={EMPRESAS['A'][0]} cuenta={admin2.usuario_id} denuncia={den}"
    esperados = [f"{base} mensaje=- tramos={REDACCION_DESDE}+8", f"{base} mensaje=1 tramos={REDACCION_DESDE_MENSAJE}+4"]
    negativo("k11f) el log tiene exactamente un EVENTO redaccion por redaccion, sin el texto tachado",
             [l[l.index(TEXTO_EVENTO_REDACCION):] for l in nuevos] == esperados, control, f"{nuevos}")

    # k11g) Accesos denegados (ASVS 5.0.0, 16.3.2): desde la marca de k11b,
    #       una linea por cada 403 y 404, en el orden de las peticiones, y
    #       ninguna por los 409, los 422, las lecturas ni las redacciones
    #       aceptadas. El id solo aparece si es un uuid; el del salto de linea,
    #       como "invalido".
    lineas_nuevas = lineas_log("api")[lineas_antes:]
    denegados = [l[l.index(TEXTO_EVENTO_ACCESO):] for l in lineas_nuevas if TEXTO_EVENTO_ACCESO in l]
    ruta_den = "ruta=/v1/personal/denuncias/{denuncia_id}/redaccion"
    ruta_men = "ruta=/v1/personal/denuncias/{denuncia_id}/mensajes/{secuencia}/redaccion"
    en_a = f"{TEXTO_EVENTO_ACCESO}empresa={EMPRESAS['A'][0]}"
    esperados_acceso = [
        f"{en_a} cuenta={instr.usuario_id} codigo=403 metodo=POST {ruta_den} ids=denuncia_id={den_instr}",
        f"{en_a} cuenta={admin2.usuario_id} codigo=404 metodo=POST {ruta_den} ids=denuncia_id={den_instr}",
        (f"{TEXTO_EVENTO_ACCESO}empresa={EMPRESAS[admin_b.empresa][0]} cuenta={admin_b.usuario_id} codigo=404 "
         f"metodo=POST {ruta_den} ids=denuncia_id={den}"),
        f"{en_a} cuenta={admin2.usuario_id} codigo=404 metodo=POST {ruta_den} ids=denuncia_id={den_nv}",
        f"{en_a} cuenta={admin2.usuario_id} codigo=404 metodo=POST {ruta_men} ids=denuncia_id={den}",
        f"{en_a} cuenta={admin2.usuario_id} codigo=404 metodo=POST {ruta_den} ids=denuncia_id=invalido",
    ]
    negativo("k11g) cada 403 y 404 deja exactamente su EVENTO acceso_denegado, y los 409, 422 y aceptadas ninguno",
             denegados == esperados_acceso, control, f"{denegados}")
    salto = por_ruta["id con un salto de linea codificado (404)"][0]
    negativo("k11g) el salto de linea del id no inyecta ninguna linea en el log",
             not any("falso" in l for l in lineas_nuevas), salto.get("estado") == 404,
             f"estado {salto.get('estado')}")


def seccion_k_auditor():
    p("=== ka) rol auditor: lee la auditoria y la verifica, y nunca toca una denuncia")
    admin2, instr = CUENTAS["admin2"], CUENTAS["instructor"]
    token_admin2 = sesion_de(admin2)
    auditor, alta = invitar(token_admin2, "auditor", "auditor@alfa.test", rol="auditor")
    preparar_cuenta(auditor)
    tokens = {"admin2": token_admin2, "instr": sesion_de(instr), "auditor": sesion_de(auditor)}
    yo = json_de(una(pt("GET", "/v1/personal/yo", token=tokens["auditor"]))) or {}
    pasa(alta.get("estado") == 201 and yo.get("rol") == "auditor",
         f"ka1) un admin invita a un auditor y, activado, su sesion tiene ese rol ({yo.get('rol')!r})")

    # ka2) La auditoría: la lee y verifica su cadena, sin dejar filas (como un admin).
    antes = total_auditoria("A")
    auditoria = una(pt("GET", "/v1/personal/auditoria", token=tokens["auditor"]))
    verificacion = una(pt("GET", "/v1/personal/auditoria/verificacion", token=tokens["auditor"]))
    datos, datos_ver = json_de(auditoria) or {}, json_de(verificacion) or {}
    control_aud = (auditoria.get("estado") == 200 and sorted(datos) == CLAVES_AUDITORIA
                   and len(datos.get("filas", [])) > 0)
    pasa(control_aud and all(sorted(f) == CLAVES_FILA_AUDITORIA for f in datos.get("filas", [])),
         "ka2) el auditor lee la auditoria de su empresa (200)")
    pasa(verificacion.get("estado") == 200 and sorted(datos_ver) == CLAVES_VERIFICACION
         and datos_ver.get("cadena_intacta") is True, f"ka2) y verifica su cadena ({datos_ver})")
    negativo("ka2) leerla y verificarla no deja filas de auditoria", total_auditoria("A") == antes, control_aud)

    # ka3) Ninguna denuncia, ni nada de administración: 403 antes de tocar la
    #      base de datos. Control: el instructor asignado sí la lee.
    den, _, texto = crear_denuncia("A")
    preparar(asignar_peticion(tokens["admin2"], den, instr.usuario_id), "asignar la denuncia al instructor")
    fila_antes = fila_denuncia(den)
    control = una(pt("GET", rd(den), token=tokens["instr"]))
    control_ok = control.get("estado") == 200 and texto.encode("utf-8") in control.get("cuerpo", b"")
    pasa(control_ok, f"ka3) control: el instructor asignado lee la denuncia ({control.get('estado')})")
    tok = tokens["auditor"]
    prohibidas = {
        "listar las denuncias": pt("GET", "/v1/personal/denuncias", token=tok),
        "leer la denuncia": pt("GET", rd(den), token=tok),
        "escribir un mensaje": mensaje_peticion(tok, den, "mensaje del auditor"),
        "cambiar el estado": estado_peticion(tok, den, "en_instruccion"),
        "asignar": asignar_peticion(tok, den, auditor.usuario_id),
        "redactar": redaccion_peticion(tok, den, [{"desde": 0, "texto": texto[:4]}]),
        "listar las cuentas": pt("GET", "/v1/personal/usuarios", token=tok),
        "invitar": pt("POST", "/v1/personal/usuarios", {"email": "ka.invitada@alfa.test", "rol": "auditor"},
                      token=tok),
        "listar las solicitudes de registro": pt("GET", "/v1/personal/solicitudes", token=tok),
    }
    respuestas = http(list(prohibidas.values()))
    for nombre, r in zip(prohibidas, respuestas):
        negativo(f"ka3) el auditor no puede {nombre}: 403",
                 r.get("estado") == 403 and r.get("cuerpo") == CUERPO_403, control_ok, f"respuesta: {r.get('estado')}")
    invitadas = valor("select count(*) from canal.usuario_personal where email = 'ka.invitada@alfa.test';")
    negativo(f"ka3) y nada cambia: la denuncia igual, ninguna cuenta nueva y el texto en ninguna respuesta "
             f"({fila_denuncia(den)}, {invitadas})",
             fila_denuncia(den) == fila_antes and invitadas == "0"
             and all(texto.encode("utf-8") not in r.get("cuerpo", b"") for r in respuestas), control_ok)

    # ka4) A un auditor no se le asigna una denuncia: la asignación es la
    #      llave del contenido. Control: a un instructor, sí.
    den2, _, _ = crear_denuncia("A")
    rechazo = una(asignar_peticion(tokens["admin2"], den2, auditor.usuario_id))
    sin_cambio = fila_denuncia(den2)
    asignada = una(asignar_peticion(tokens["admin2"], den2, instr.usuario_id))
    control_ok = asignada.get("estado") == 204 and fila_denuncia(den2) == f"nueva|{instr.usuario_id}|0"
    pasa(control_ok, "ka4) control: el admin asigna la denuncia a un instructor (204)")
    negativo("ka4) asignarla a un auditor da 409, no cambia la denuncia y no deja fila de asignacion",
             rechazo.get("estado") == 409 and rechazo.get("cuerpo") == CUERPO_409_DESTINO and sin_cambio == "nueva||0"
             and auditoria_de("A", "asignacion", den2) == [f"personal:{admin2.usuario_id}|{instr.usuario_id}"],
             control_ok, f"respuesta: {rechazo.get('estado')}, fila: {sin_cambio}")


def crear_denuncias(empresa, cuantas):
    """cuantas denuncias por la API pública, una detrás de otra en una sola
    ejecución del cliente. Devuelve sus ids, de la base de datos."""
    antes = ids_denuncias(empresa)
    textos = [f"texto de denuncia lecturas {secrets.token_hex(12)}" for _ in range(cuantas)]
    respuestas = http([pt("POST", f"/v1/empresas/{EMPRESAS[empresa][1]}/denuncias",
                          {"categoria": "fraude", "texto": t}) for t in textos])
    codigos = [(json_de(r) or {}).get("codigo_seguimiento") for r in respuestas]
    nuevas = ids_denuncias(empresa) - antes
    if any(r.get("estado") != 201 for r in respuestas) or not all(codigos) or len(nuevas) != cuantas:
        raise Parada(f"no se pudieron crear las denuncias de preparacion: {[r.get('estado') for r in respuestas]}")
    for texto, codigo in zip(textos, codigos):
        TEXTOS_SENSIBLES[f"texto de la denuncia {len(TEXTOS_SENSIBLES)}"] = texto
        TEXTOS_SENSIBLES[f"codigo de la denuncia {len(TEXTOS_SENSIBLES)}"] = codigo
    return sorted(nuevas)


def lecturas_de(respuesta):
    """El campo lecturas de una lectura (hoy y tope), o None."""
    return (json_de(respuesta) or {}).get("lecturas")


def eventos_lecturas(usuario_id):
    """Los EVENTO limite_lecturas_* de una cuenta, desde "EVENTO" (sin el
    nivel ni el nombre del registrador que van delante)."""
    return [linea[linea.index(TEXTO_EVENTO_LECTURAS):] for linea in lineas_log("api")
            if TEXTO_EVENTO_LECTURAS in linea and f"cuenta={usuario_id}" in linea]


def intentos_aviso_lecturas():
    return sum(TEXTO_CORREO_LECTURAS in linea for linea in lineas_log("api"))


def seccion_k_lecturas():
    p("=== kl) tope de lecturas: denuncias distintas por cuenta y dia, avisos y lecturas simultaneas")
    admin2 = CUENTAS["admin2"]
    token_admin2 = sesion_de(admin2)
    # Un admin propio de la sección: empieza el día sin lecturas.
    lector, _ = invitar(token_admin2, "admin_lecturas", "admin.lecturas@alfa.test", rol="admin")
    preparar_cuenta(lector)
    token = sesion_de(lector)
    # 52 = el tope y dos más, que quedan fuera.
    ids = crear_denuncias("A", LECTURAS_TOPE + 2)
    asignadas = http([asignar_peticion(token, d, lector.usuario_id) for d in ids])
    if any(r.get("estado") != 204 for r in asignadas):
        raise Parada(f"no se pudieron autoasignar las denuncias: {[r.get('estado') for r in asignadas]}")
    actor = f"personal:{lector.usuario_id}"
    # Quién debe recibir los avisos, con una consulta propia de la batería:
    # admins y auditores activos y activados de A, salvo el lector.
    vigilantes = valor(f"select count(*) from canal.usuario_personal where empresa_id = '{EMPRESAS['A'][0]}' "
                       f"and rol in ('admin', 'auditor') and activo and totp_activo and id <> '{lector.usuario_id}';")
    correos_antes = intentos_aviso_lecturas()

    # kl1) Hasta el aviso: cada denuncia nueva suma una, y la vigésima avisa.
    primeras = http([pt("GET", rd(d), token=token) for d in ids[:LECTURAS_AVISO - 1]])
    control = (all(r.get("estado") == 200 for r in primeras)
               and [lecturas_de(r) for r in primeras] == [{"hoy": n, "tope": 50} for n in range(1, 20)])
    pasa(control, "kl1) control: las 19 primeras se leen (200) y cada una suma: lecturas 1 a 19 de 50")
    negativo("kl1) sin EVENTO de aviso antes de la vigesima", eventos_lecturas(lector.usuario_id) == [], control)
    vigesima = una(pt("GET", rd(ids[19]), token=token))
    releida = una(pt("GET", rd(ids[0]), token=token))
    eventos = eventos_lecturas(lector.usuario_id)
    pasa(vigesima.get("estado") == 200 and lecturas_de(vigesima) == {"hoy": 20, "tope": 50}
         and eventos == [(f"EVENTO limite_lecturas_aviso: empresa={EMPRESAS['A'][0]} cuenta={lector.usuario_id} "
                          f"lecturas=20 destinatarios={vigilantes}")],
         f"kl1) la vigesima avisa una vez, con la cuenta y sin ids de denuncias ({eventos})")
    negativo("kl1) releer una ya abierta no suma ni vuelve a avisar",
             releida.get("estado") == 200 and lecturas_de(releida) == {"hoy": 20, "tope": 50}
             and len(eventos_lecturas(lector.usuario_id)) == 1, control)

    # kl2) Hasta el tope, con las últimas doce a la vez: de las 40 abiertas,
    #      solo caben diez más. Escribir la fila espera al bloqueo de la
    #      auditoría, así que exactamente diez pasan y dos reciben el 429.
    medias = http([pt("GET", rd(d), token=token) for d in ids[20:40]])
    control_40 = all(r.get("estado") == 200 for r in medias) and lecturas_de(medias[-1]) == {"hoy": 40, "tope": 50}
    pasa(control_40, "kl2) control: las lecturas 21 a 40 se leen (200)")
    a_la_vez = http([{"grupo": [pt("GET", rd(d), token=token) for d in ids[40:]]}])
    estados = sorted(r.get("estado") for r in a_la_vez)
    pasa(control_40 and estados == [200] * 10 + [429] * 2,
         f"kl2) doce lecturas simultaneas con diez plazas: diez 200 y dos 429 ({estados})")
    rechazadas = [d for d, r in zip(ids[40:], a_la_vez) if r.get("estado") == 429]
    filas = valor(f"select count(*) || '|' || count(distinct objeto_id) from canal.registro_auditoria "
                  f"where actor = '{actor}' and accion = 'lectura_denuncia';")
    mismo_dia = valor(f"select count(distinct fecha) from canal.registro_auditoria where actor = '{actor}';") == "1"
    if not mismo_dia:
        sinc("kl2) el dia de la empresa cambio a mitad de la seccion: el conteo no tiene conclusion")
        return
    negativo(f"kl2) las rechazadas no dejan fila: 51 lecturas de 50 denuncias distintas ({filas})",
             filas == "51|50", control_40)
    eventos = eventos_lecturas(lector.usuario_id)
    pasa(len(eventos) == 2 and eventos[1] == (f"EVENTO limite_lecturas_tope: empresa={EMPRESAS['A'][0]} "
                                              f"cuenta={lector.usuario_id} lecturas=50 destinatarios={vigilantes}"),
         f"kl2) la quincuagesima avisa una vez del tope ({eventos[1:]})")
    negativo("kl2) ningun evento lleva el id de una denuncia",
             not any(d in linea for d in ids for linea in eventos), len(eventos) == 2)

    # kl3) Pasado el tope: una nueva da el 429 con su mensaje, el
    #      Retry-After hasta la medianoche de la empresa y nada de contenido.
    #      Releer sigue permitido y otra cuenta no se ve afectada.
    nueva = una(pt("GET", rd(rechazadas[0]), token=token)) if rechazadas else {}
    vieja = una(pt("GET", rd(ids[5]), token=token))
    control_vieja = vieja.get("estado") == 200 and lecturas_de(vieja) == {"hoy": 50, "tope": 50}
    pasa(control_vieja, "kl3) control: pasado el tope, releer una ya abierta sigue permitido (200)")
    # La medianoche, con otra fórmula que la de la API: date_trunc en la zona de la empresa.
    hasta = int(valor(f"select ceil(extract(epoch from date_trunc('day', now() + interval '1 day', e.zona_horaria) "
                      f"- now())) from canal.empresa e where e.id = '{EMPRESAS['A'][0]}';"))
    espera = (nueva.get("cabeceras") or {}).get("retry-after", "")
    negativo(f"kl3) una denuncia nueva da 429 con su mensaje y Retry-After hasta la medianoche de la empresa "
             f"({nueva.get('estado')}, {espera!r}, {hasta})",
             nueva.get("estado") == 429 and nueva.get("cuerpo") == CUERPO_429_LECTURAS and espera.isdigit()
             and 1 <= int(espera) <= 90_000 and abs(int(espera) - hasta) <= 10, control_vieja)
    negativo("kl3) y no deja fila ni otro evento",
             valor(f"select count(*) from canal.registro_auditoria where actor = '{actor}' "
                   f"and accion = 'lectura_denuncia' and objeto_id = '{rechazadas[0] if rechazadas else ids[0]}';") == "0"
             and len(eventos_lecturas(lector.usuario_id)) == 2, control_vieja)
    if rechazadas:
        preparar(asignar_peticion(token_admin2, rechazadas[0], admin2.usuario_id), "reasignar a admin2")
    otra = una(pt("GET", rd(rechazadas[0]), token=token_admin2)) if rechazadas else {}
    negativo("kl3) otra cuenta lee esa misma denuncia: el tope es de cada cuenta",
             otra.get("estado") == 200 and (lecturas_de(otra) or {}).get("tope") == 50, control_vieja,
             f"respuesta: {otra.get('estado')}")

    # kl4) Los avisos salen hacia quien vigila: sin Mailpit en esta batería,
    #      cada intento deja su EVENTO correo_fallido (el envío real, con quién
    #      lo recibe y quién no, lo prueba tests/security/verificar_registro.py).
    esperados = 2 * int(vigilantes)
    # Salen después de responder: se espera a que estén todos, y después se
    # comprueba que no hay de más.
    esperar(lambda: intentos_aviso_lecturas() - correos_antes >= esperados, 30)
    intentos = intentos_aviso_lecturas() - correos_antes
    pasa(int(vigilantes) >= 2 and intentos == esperados,
         f"kl4) un intento de aviso por vigilante en el aviso y en el tope ({intentos} de {esperados})")
    sin_destino = [l for l in lineas_log("api") if "EVENTO aviso_sin_destinatario: tipo=aviso_lecturas" in l]
    negativo("kl4) con vigilantes no sale EVENTO aviso_sin_destinatario", sin_destino == [], int(vigilantes) >= 2)


def seccion_l():
    p("=== l) gestion lee en solo lectura y con una sola foto")
    r = dc("run", "--rm", "-T", "--entrypoint", "python", "gestion", "-c", GESTION_DENTRO, EMPRESAS["A"][1])
    try:
        res = json.loads(r.out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise Parada(f"no se pudo ejecutar la prueba de gestion: {r.err.strip()[-400:]!r}") from None
    # Control: las transacciones de escritura de las mismas órdenes dan otro
    # modo, así que la consulta distingue uno de otro. Y las dos órdenes
    # llegaron hasta su final esperado sin escribir nada.
    control = (res.get("emision") == [MODO_ESCRITURA] and res.get("clave") == [MODO_ESCRITURA]
               and res.get("fin_invitacion") == "espia" and res.get("fin_clave") == "la empresa no existe")
    pasa(control, f"l) control: las transacciones de escritura de gestion estan en {MODO_ESCRITURA} "
                  f"(invitacion: {res.get('emision')}, nueva-clave: {res.get('clave')})")
    negativo("l) la verificacion de la base de datos de gestion (en las dos ordenes) es solo lectura en REPEATABLE READ",
             res.get("verificacion") == [MODO_SOLO_LECTURA, MODO_SOLO_LECTURA], control, f"{res.get('verificacion')}")
    negativo("l) la resolucion del identificador de alta-admin y reinvitar-admin es solo lectura en REPEATABLE READ",
             res.get("resolver") == [MODO_SOLO_LECTURA], control, f"{res.get('resolver')}")


def seccion_h():
    p("=== h) regla acceso del limitador (limites de produccion)")
    # Antes de recrear la API: después su log anterior ya no existe.
    guardar_log_api_anterior()
    r = dc_produccion("up", "-d", "--wait", "api")
    if r.rc != 0:
        raise Parada(f"no arranca la API con los limites de produccion: {r.todo.strip()[-500:]}")
    pasa(TEXTO_LIMITES_PRODUCCION in "\n".join(lineas_log("api")),
         f"h) la API arranca con los limites de produccion ({TEXTO_LIMITES_PRODUCCION!r})")
    maximo, ventana = LIMITE_ACCESO
    resto = ventana - int(time.time()) % ventana
    if resto < 60:
        p(f"   espera de {resto + 3} s a la ventana siguiente")
        time.sleep(resto + 3)
    victima = CUENTAS["victima"]
    poner_sin_confianza(victima, 0)
    peticion = por_caddy(login(victima, contrasena="rafaga equivocada", dispositivo=None,
                               empresa="0123456789abcdef0123456789abcdef"))
    respuestas = http([peticion] * (maximo + 1), red="edge", ip=IP_CLIENTE_A)
    control = all(es_401(x) for x in respuestas[:-1])
    pasa(control, f"h) las {maximo} primeras peticiones de login del cliente A responden 401")
    ultima = respuestas[-1]
    tras = ultima.get("cabeceras", {}).get("retry-after", "")
    negativo(f"h) la peticion {maximo + 1} es 429 con Retry-After entre 1 y {ventana}",
             ultima.get("estado") == 429 and ultima.get("cuerpo") == CUERPO_429 and tras.isdigit()
             and 1 <= int(tras) <= ventana, control, f"respuesta: {ultima}")
    otro = http([peticion], red="edge", ip=IP_CLIENTE_B)[0]
    negativo("h) el cliente B no comparte el contador de A", es_401(otro), control)
    # Sin Redis: 503 sin llegar a contar ningún intento en la base de datos.
    antes = contadores(victima)[0]
    dc("stop", "redis")
    try:
        sin_redis = http([por_caddy(login(victima, contrasena="sin redis", dispositivo=None)),
                          por_caddy(pt("GET", "/salud"))], red="edge", ip=IP_CLIENTE_B)
    finally:
        dc("start", "redis")
    negativo("h) con Redis parado, el login da 503 con Retry-After 5 y no cuenta ningun intento",
             sin_redis[0].get("estado") == 503 and sin_redis[0].get("cuerpo") == CUERPO_503_OCUPADO
             and sin_redis[0].get("cabeceras", {}).get("retry-after") == REINTENTAR_TRAS
             and contadores(victima)[0] == antes, sin_redis[1].get("estado") == 200, f"{sin_redis}")
    esperar(lambda: salud(contenedor("redis")) == "healthy", 60)
    seccion_h_cuenta()


def seccion_h_cuenta():
    """Regla cuenta (segunda capa, por identidad), con los límites de
    producción: la misma cuenta desde dos IPs agota su límite aunque ninguna
    IP agote el suyo (otras, 60/60 por IP); otra cuenta desde la misma IP no
    comparte el contador; un token que no vale no consume el de ninguna
    cuenta."""
    maximo, ventana = LIMITE_CUENTA
    cuenta, otra = CUENTAS["admin2"], CUENTAS["instructor"]
    token, token_otra = sesion_de(cuenta), sesion_de(otra)
    resto = ventana - int(time.time()) % ventana
    if resto < 40:
        p(f"   espera de {resto + 1} s a la ventana siguiente")
        time.sleep(resto + 1)
    lineas_antes = sum(TEXTO_EVENTO_CUENTA in l for l in lineas_log("api"))
    mitad = maximo // 2
    # El token que no vale lleva los claims reales de la cuenta (su sub, su sid
    # y su emp, vigentes) firmados con otra clave: es quien intenta agotar el
    # cupo de una víctima con su sub, y el limitador no debe contar por un sub
    # sin verificar. No se cambia el último carácter del JWT: en la firma (32
    # bytes, 43 caracteres) sus 2 bits más bajos son de relleno, y "A" y "B"
    # solo difieren en uno de ellos.
    claims = leer_parte(token.jwt.split(".")[1])
    ahora = int(time.time())
    falso = forjar_jwt({**claims, "iat": ahora, "exp": ahora + DURACION_ACCESO}, clave=secrets.token_bytes(32))
    invalidos = http([por_caddy(yo(falso))] * 10, red="edge", ip=IP_CLIENTE_A)
    desde_a = http([por_caddy(yo(token))] * mitad, red="edge", ip=IP_CLIENTE_A)
    desde_b = http([por_caddy(yo(token))] * (maximo - mitad + 2), red="edge", ip=IP_CLIENTE_B)
    de_otra = http([por_caddy(yo(token_otra))], red="edge", ip=IP_CLIENTE_A)[0]
    control = (all(r.get("estado") == 200 for r in desde_a + desde_b[:maximo - mitad])
               and de_otra.get("estado") == 200)
    pasa(control, f"h) control: la cuenta hace {maximo} peticiones repartidas entre dos IPs (200) y otra cuenta "
                  f"desde la misma IP sigue entrando")
    pasa(all(es_401(r, CUERPO_401_SESION) for r in invalidos),
         "h) 10 peticiones con un token que no vale dan 401 y no consumen el contador de la cuenta (las 60 "
         "siguientes entran)")
    excesos = desde_b[maximo - mitad:]
    tras = [r.get("cabeceras", {}).get("retry-after", "") for r in excesos]
    negativo(f"h) la peticion {maximo + 1} de la cuenta, desde una IP que no ha agotado el suyo, es 429 con "
             f"Retry-After entre 1 y {ventana}",
             all(r.get("estado") == 429 and r.get("cuerpo") == CUERPO_429 for r in excesos)
             and all(x.isdigit() and 1 <= int(x) <= ventana for x in tras), control,
             f"estados: {[r.get('estado') for r in excesos]}")
    nuevas = [l for l in lineas_log("api") if TEXTO_EVENTO_CUENTA in l][lineas_antes:]
    esperada = f"{TEXTO_EVENTO_CUENTA}empresa={EMPRESAS['A'][0]} cuenta={cuenta.usuario_id}"
    negativo("h) dos excesos dejan un unico evento limite_cuenta, con empresa y cuenta y sin IP",
             len(nuevas) == 1 and nuevas[0].endswith(esperada)
             and IP_CLIENTE_A not in nuevas[0] and IP_CLIENTE_B not in nuevas[0], control, f"{nuevas}")


def seccion_i():
    p("=== i) nada sensible en logs ni en el volcado")
    sensibles = {}
    for cuenta in CUENTAS.values():
        if not isinstance(cuenta, Cuenta):
            continue
        for nombre, v in (("contrasena", cuenta.contrasena), ("secreto_totp", cuenta.secreto),
                          ("dispositivo", cuenta.dispositivo), ("invitacion", cuenta.invitacion)):
            if v:
                sensibles[f"{nombre} de {cuenta.etiqueta}"] = v
        if cuenta.secreto:
            sensibles[f"secreto_hex de {cuenta.etiqueta}"] = base64.b32decode(cuenta.secreto).hex()
    sensibles.update(TEXTOS_SENSIBLES)
    for n, token in enumerate(TOKENS_EMITIDOS):
        sensibles[f"token emitido {n}"] = token
    sensibles["clave de firma"] = CLAVES_FALSAS["clave_firma_tokens"]
    textos = {s: dc("logs", "--no-color", "--no-log-prefix", s).todo for s in ("api", "postgres", "caddy", "redis")}
    volcado = dc("exec", "-T", "postgres", "pg_dump", "-U", "postgres", "-d", "canario", "--data-only",
                 "-n", "canal").out
    control = "usuario_personal" in volcado and "$argon2id$" in volcado and len(sensibles) > 10
    fugas = sorted({f"{n} en {s}" for s, t in {**textos, "volcado": volcado}.items()
                    for n, v in sensibles.items() if v in t})
    negativo(f"i) ni contrasenas, ni secretos TOTP, ni tokens, ni textos ni codigos de denuncias aparecen en "
             f"los logs ni en el volcado "
             f"({len(sensibles)} valores) {fugas if fugas else ''}".strip(), not fugas, control)
    ips = [s for s, t in textos.items() if IP_CLIENTE_A in t or IP_CLIENTE_B in t]
    pasa(not ips, f"i) ninguna IP de cliente en los logs {ips if ips else ''}".strip())
    salida = "\n".join(salidas_gestion)
    pasa(all(c.contrasena not in salida for c in CUENTAS.values() if isinstance(c, Cuenta)),
         "i) gestion nunca imprime contrasenas")


# Líneas del log de la API que explican un 503 o un 500. Hay una marca por
# cada camino que responde 503: Redis sin responder o un cliente sin IP en el
# limitador (app/limitador.py y app/rutas_personal.py), lock_timeout o
# statement_timeout (app/frontera_http.py), sin hueco para un hash de
# contraseña (app/personal.py) y una empresa sin clave (app/rutas_personal.py y
# app/rutas_denuncias.py). Un camino nuevo de 503 necesita aquí su marca. Solo
# llevan la clase del error y su SQLSTATE, nunca valores, y la sección i)
# comprueba que el log no tiene nada sensible.
MARCAS_DIAGNOSTICO = ("EVENTO limitador_no_disponible", "EVENTO limitador_cliente_invalido", "SATURACION:",
                      "EVENTO hashes_saturados", "EVENTO empresa_sin_clave", "ERROR INTERNO:")

# Log del contenedor de la API anterior a h). h) lo recrea con los límites de
# producción, y "docker compose logs" solo devuelve el del contenedor actual:
# sin esta copia, el diagnóstico no ve nada de lo que pasó antes de h).
log_api_anterior = []


def guardar_log_api_anterior():
    """Copia el log de la API antes de recrearla. Control: la copia tiene que
    llevar la línea de arranque con los límites de prueba, que solo escribe el
    contenedor anterior; si no la lleva, la copia no sirve y se ve."""
    log_api_anterior.extend(lineas_log("api"))
    pasa(any(TEXTO_LIMITES_PRUEBA in l for l in log_api_anterior),
         "h) control del diagnostico: guardado el log de la API anterior a h) (lleva los limites de prueba)")


def diagnostico_api():
    """Si algo falló, imprime esas líneas antes de la limpieza: down -v se
    lleva el log, y sin él un 503 no dice si fue Redis (el limitador falla
    cerrado si no responde en 0,2 s) o un bloqueo de PostgreSQL. Mira el log
    del contenedor anterior a h) y el del actual."""
    for etiqueta, origen in (("anterior a h)", log_api_anterior), ("actual", lineas_log("api"))):
        lineas = [l for l in origen if any(m in l for m in MARCAS_DIAGNOSTICO)]
        p(f"=== diagnostico: lineas de error del log de la API, contenedor {etiqueta}"
          + (" (las de limitador_no_disponible de h) son esperadas: para Redis a proposito)" if etiqueta == "actual" else ""))
        if etiqueta == "anterior a h)" and not origen:
            p("   (sin copia: la bateria se paro antes de h))")
            continue
        for linea in lineas or ["(ninguna)"]:
            p(f"   {linea}")


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


def main():
    global ESTADO_GIT_ARRANQUE, TEMPORAL
    ESTADO_GIT_ARRANQUE = estado_git()
    if ejecutar(["docker", "info", "--format", "{{.ServerVersion}}"]).rc != 0:
        p("PARADA: docker info falla")
        terminar_con_parada()
    previos = recursos_previos()
    if previos:
        p(f"PARADA: ya existen recursos con prefijo {PROYECTO}: {previos}")
        terminar_con_parada()
    ocupadas = subredes_ocupadas()
    if ocupadas:
        p(f"PARADA: las subredes fijas ya estan en uso por {ocupadas} (pare el proyecto canario y las otras baterias)")
        terminar_con_parada()
    # Solo se comprueba que existen (is_file), nunca se leen.
    for fichero in ("contrasena_redis.txt", "redis_acl.conf", "contrasena_postgres_superusuario.txt",
                    "contrasena_migrador.txt", "contrasena_aplicacion.txt", "contrasena_plataforma.txt",
                    "clave_maestra.txt", "clave_hmac_codigos.txt", "clave_firma_tokens.txt"):
        if not (RAIZ / "secrets" / fichero).is_file():
            p(f"PARADA: secrets/{fichero} no existe (scripts/generar_secretos.py)")
            terminar_con_parada()
    TEMPORAL = pathlib.Path(tempfile.mkdtemp(prefix="canario_personal_"))
    preparar_secretos_falsos()
    parada = None
    try:
        for seccion in (seccion_a, seccion_b, seccion_c, seccion_d, seccion_e, seccion_f, seccion_g, seccion_j,
                        seccion_k, seccion_k_no_veraz, seccion_k_redaccion, seccion_k_auditor, seccion_k_lecturas,
                        seccion_l, seccion_i,
                        seccion_h):
            seccion()
    except Parada as e:
        parada = str(e)
        p(f"PARADA: {parada}")
    except Exception:  # noqa: BLE001 - error inesperado del propio test: se informa y se limpia
        parada = "error inesperado en el test"
        p("ERROR INESPERADO:\n" + traceback.format_exc())
    finally:
        dc("start", "redis")
        if estado["falla"] or parada is not None:
            diagnostico_api()
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
