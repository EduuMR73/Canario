#!/usr/bin/env python3
"""Copias de seguridad cifradas de la base de Canario, fuera del VPS.

Por qué existe: sin copias, un disco perdido o un ransomware (ATT&CK T1486,
T1490) se llevarían las denuncias (docs/threat-model.md, 6.20 y 8). Este script
saca una copia cifrada de la base y de los eventos de la API a Backblaze B2, un
sitio donde el VPS escribe y oculta, pero no borra (docs/operacion.md, "Copias
de seguridad").

Lo lanzan dos timers de systemd como root, desde una copia en /usr/local/sbin
que solo root puede cambiar, nunca desde el repositorio: un fichero que un
usuario edita y root ejecuta es una vía de escalada (ATT&CK T1543.002), igual
que con despliegue/reconectar_traefik.py.

Dos subórdenes:

* base (cada día): pg_dump de la base con "docker exec" al contenedor fijo
  (por el socket Unix, con peer; nunca "docker compose" con el .env de un
  usuario), más un manifiesto con los recuentos por tabla y, por empresa, la
  última secuencia y el último hash de la cadena de auditoría. Volcado y
  manifiesto van en un tar, y el tar se cifra con age para DOS destinatarios
  poscuánticos (age1pq1...: la clave principal y la de respaldo). El manifiesto
  va dentro del cifrado, nunca en claro: sus recuentos son datos de negocio.
  Se sube SIEMPRE, como base/AAAAMMDDTHHMMSSZ.age (hora UTC). Si la base está
  vacía, la cadena de auditoría rota o no se estabiliza durante la copia, el
  objeto va a cuarentena/AAAAMMDDTHHMMSSZ.age, el manifiesto dice el motivo, el
  latido recibe /fail y el código es 6: nunca se niega a subir (una copia
  sospechosa sigue siendo evidencia) y nunca se hace pasar por buena.
* eventos (cada 15 minutos): exporta del log de la API las líneas
  "EVENTO <tipo>" de una lista cerrada (EVENTOS_PERMITIDOS), las cifra igual y
  sube eventos/AAAAMMDDTHHMMSSZ.age. Son el registro para volver a aplicar lo
  suprimido o tachado tras restaurar una copia (docs/operacion.md). Un cursor
  en un fichero de estado de root recuerda hasta dónde se exportó, y con qué
  contenedor (su Id): una API recreada no es una rotación del log.

Vigilancia desde fuera del VPS (healthchecks.io), una por suborden: el latido
de éxito es un POST con, en el cuerpo, el fileId, el SHA1 y los bytes de cada
objeto subido. Es el único registro de lo que subió el script legítimo que
queda fuera del VPS: la clave de B2 (writeFiles) incluye b2_upload_file y
b2_hide_file, y age no autentica a quien cifra, así que quien tome root puede
ocultar las copias buenas y subir otras falsas que descifran igual. El latido
no lo evita: permite descubrirlo y elegir al restaurar (docs/operacion.md).

El texto en claro nunca toca el disco: el volcado se lee a memoria, el tar se
escribe directamente a la entrada de age, y lo único que se guarda en el
directorio temporal (privado, 0700) es el resultado ya cifrado, porque
b2_upload_file exige conocer de antemano la longitud y el SHA1.

La clave de B2 solo puede escribir (capacidad writeFiles) en UN bucket, el
esperado (bucket_id). No se da por supuesto: al autorizar se lee de la
respuesta lo que la clave puede hacer y, si tiene cualquier cosa más o es de
otro bucket, el script se niega a seguir. Con más permisos, quien tomara el
VPS podría leer o borrar las copias.

Credenciales y configuración por LoadCredential= de systemd, en
$CREDENTIALS_DIRECTORY: b2_id, b2_clave, bucket_id y, según la suborden,
latido_url (base) o latido_eventos_url (eventos). Nunca por variables de
entorno ni por argumentos, y ningún mensaje de error incluye la clave ni la URL
completa de un latido.

Tiempo: cada suborden tiene un presupuesto total propio, por debajo del
TimeoutStartSec de su unidad, y un manejador de SIGTERM: si se agota o systemd
manda parar, falla con el código 10 y el /fail llega a salir (con SIGKILL no).

Códigos de salida: 0 bien; 1 error inesperado (o cursor dañado); 2 argumentos
no válidos; 3 destinatarios o credenciales no válidos; 4 B2 rechaza la clave,
esta tiene permisos de más o es de otro bucket; 5 hueco en el log de eventos
(la rotación se comió líneas; lo que había sí se subió; sigue fallando hasta
que alguien lo reconozca); 6 la base no es buena para copiar (vacía, con la
cadena de auditoría rota o cambiando durante la copia: se sube a cuarentena/);
7 falla un proceso de la tubería (docker, pg_dump, psql, age); 8 falla la
subida a B2; 9 la copia se subió pero falla el latido; 10 se agota el
presupuesto de tiempo o systemd manda parar (SIGTERM).

Las opciones --contenedor-bd, --contenedor-api, --b2-url, --credenciales,
--destinatarios, --estado, --age, --docker, --presupuesto, --temporal y
--conservar-temporal existen SOLO para las pruebas
(tests/security/verificar_copias.py): en producción se usan los valores por
defecto, que son los reales. Una --b2-url distinta de la real es también el
modo de prueba que admite http en lugar de https.

Solo usa la biblioteca estándar. Las órdenes van como lista de argumentos,
nunca por una shell.
"""
import argparse
import base64
import datetime
import hashlib
import io
import json
import os
import pathlib
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

# Valores de producción. El contenedor lleva el nombre que le da Compose al
# proyecto "canario" (name: canario en docker-compose.yml).
CONTENEDOR_BD = "canario-postgres-1"
CONTENEDOR_API = "canario-api-1"
B2_URL = "https://api.backblazeb2.com"
DESTINATARIOS = "/etc/canario-copias/destinatarios.txt"
ESTADO = "/var/lib/canario-copias/eventos.cursor"
AGE = "/usr/local/bin/age"
# Ruta absoluta: root no debe resolver "docker" por un PATH que otro pudiera tocar.
DOCKER = "/usr/bin/docker"

# Solo estos tipos salen del VPS. Son los que sirven para volver a aplicar lo
# destruido tras restaurar (declaración no veraz y redacción) y la señal de
# robo de sesión (reutilización de un token de renovación). El resto de EVENTO
# (limitadores, orígenes rechazados...) no hace falta fuera y es ruido.
EVENTOS_PERMITIDOS = ("declaracion_no_veraz", "redaccion", "reutilizacion_renovacion")

# Plazos: si algo no responde, se falla de forma visible en vez de colgar.
PLAZO = 60
PLAZO_VOLCADO = 3600
PLAZO_HTTP = 60
PLAZO_LATIDO = 20
# Un volcado de la base de un canal de denuncias es pequeño. Se lee a memoria
# para que el texto en claro no pase por el disco; un tope evita agotarla.
TOPE_VOLCADO = 512 * 1024 * 1024
INTENTOS_BASE = 3
INTENTOS_SUBIDA = 3
ESPERA = 2
# Presupuesto total de cada suborden, por debajo del TimeoutStartSec de su
# unidad (7200 y 1800): deja margen para que el /fail llegue a salir antes de
# que systemd mande SIGKILL.
PRESUPUESTO_BASE = 6600
PRESUPUESTO_EVENTOS = 1500
# healthchecks.io guarda hasta 100 kB del cuerpo de un ping: se queda por debajo.
TOPE_CUERPO_LATIDO = 90_000

# Prioridades de syslog (sd-daemon(3)): systemd las lee del principio de cada
# línea si la salida va al journal. AVISO e INFO se usan en el stdout.
ERROR = 3
AVISO = 4
INFO_NOTICE = 5

SALIDA_ERROR = 1
SALIDA_ARGUMENTOS = 2
SALIDA_CONFIG = 3
SALIDA_B2_CLAVE = 4
SALIDA_HUECO = 5
SALIDA_BASE_INVALIDA = 6
SALIDA_PROCESO = 7
SALIDA_SUBIDA = 8
SALIDA_LATIDO = 9
SALIDA_TIEMPO = 10

RE_DESTINATARIO = re.compile(r"^age1pq1[a-z0-9]+$")
# Id completo de un contenedor (docker inspect) y formato explícito del cursor:
# "v1 <id> <nanosegundos>". Cualquier otra cosa es un cursor dañado.
RE_ID_CONTENEDOR = re.compile(r"^[0-9a-f]{64}$")
RE_CURSOR = re.compile(r"^v1 ([0-9a-f]{64}) ([0-9]{1,20})$")
RE_LINEA_LOG = re.compile(r"^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d{1,9}))?Z (.*)$", re.DOTALL)
# El mensaje tiene que EMPEZAR por EVENTO: una línea de log que solo lo
# contuviera en medio (con texto que alguien controla) no entra.
RE_EVENTO = re.compile(r"^[A-Z]+ canario\.[a-z_]+: EVENTO ([a-z_]+)(?::| |$)")


class Fallo(Exception):
    """Un error que se informa y termina con el código indicado."""

    def __init__(self, mensaje, codigo=SALIDA_ERROR, objetos=()):
        super().__init__(mensaje)
        self.codigo = codigo
        # Lo que se llegó a subir antes de fallar: va en el cuerpo del /fail.
        self.objetos = list(objetos)


def escribir(prioridad, texto, flujo):
    # JOURNAL_STREAM solo existe si systemd conecta la salida al journal: así,
    # ejecutado a mano, el texto sale sin el prefijo <N>.
    prefijo = f"<{prioridad}>" if os.environ.get("JOURNAL_STREAM") else ""
    print(prefijo + texto, file=flujo, flush=True)


def aplanar(texto):
    """Una sola línea imprimible: los saltos de línea y los caracteres de
    control o invisibles se vuelven espacios. Un stderr con saltos de línea
    permitiría fabricar líneas falsas en el journal."""
    return " ".join("".join(c if c.isprintable() else " " for c in texto).split())


def cola_de(datos):
    """Las últimas palabras de un stderr, para un mensaje, aplanadas. Solo
    salen mensajes de docker (excepto "docker logs", cuyo stderr es el log de la
    API), pg_dump, psql o age, nunca datos ni credenciales."""
    return aplanar(datos.decode("utf-8", "replace"))[-300:]


# ---------------------------------------------------------------------------
# Presupuesto de tiempo y SIGTERM
# ---------------------------------------------------------------------------
_LIMITE = [None]  # instante (time.monotonic) en que se agota el presupuesto


def iniciar_presupuesto(segundos):
    _LIMITE[0] = time.monotonic() + segundos


def presupuesto_agotado():
    return _LIMITE[0] is not None and time.monotonic() >= _LIMITE[0]


def acotar(plazo):
    """El plazo de una operación, recortado a lo que queda de presupuesto. Si
    ya no queda nada, falla: ninguna operación empieza fuera de presupuesto."""
    if _LIMITE[0] is None:
        return plazo
    resto = _LIMITE[0] - time.monotonic()
    if resto <= 0:
        raise Fallo("se agotó el presupuesto de tiempo de la ejecución", SALIDA_TIEMPO)
    return min(plazo, resto)


def al_recibir_sigterm(numero, marco):
    # systemd manda SIGTERM al agotar TimeoutStartSec (o con systemctl stop).
    # Lanzar el Fallo deja que el manejador de cada suborden haga el /fail
    # antes del SIGKILL, que llega TimeoutStopSec (90 s) después.
    raise Fallo("systemd ha mandado parar la unidad (SIGTERM): plazo de la unidad agotado o parada manual",
                SALIDA_TIEMPO)


# ---------------------------------------------------------------------------
# Configuración: destinatarios y credenciales
# ---------------------------------------------------------------------------
def leer_destinatarios(ruta):
    """Exactamente dos destinatarios age poscuánticos distintos. Un fichero con
    uno solo dejaría las copias a merced de perder esa clave; uno clásico
    (age1...) rompería la protección poscuántica (age no mezcla los dos tipos)
    y las copias duran años (EDPB, Recomendaciones 01/2020)."""
    try:
        texto = pathlib.Path(ruta).read_text(encoding="utf-8")
    except OSError as e:
        raise Fallo(f"no se puede leer el fichero de destinatarios: {e.strerror}", SALIDA_CONFIG) from None
    lineas = [l.strip() for l in texto.splitlines() if l.strip() and not l.strip().startswith("#")]
    if len(lineas) != 2 or len(set(lineas)) != 2 or not all(RE_DESTINATARIO.match(l) for l in lineas):
        raise Fallo("el fichero de destinatarios tiene que contener exactamente dos destinatarios age1pq1... "
                    "distintos (la clave principal y la de respaldo)", SALIDA_CONFIG)
    return lineas


def leer_credencial(directorio, nombre):
    try:
        valor = (pathlib.Path(directorio) / nombre).read_text(encoding="utf-8").strip()
    except OSError as e:
        # Solo el nombre del fichero y el motivo, nunca el contenido.
        raise Fallo(f"no se puede leer la credencial {nombre}: {e.strerror}", SALIDA_CONFIG) from None
    if not valor:
        raise Fallo(f"la credencial {nombre} está vacía", SALIDA_CONFIG)
    return valor


def directorio_credenciales(args):
    d = args.credenciales or os.environ.get("CREDENTIALS_DIRECTORY")
    if not d:
        raise Fallo("no hay directorio de credenciales (CREDENTIALS_DIRECTORY lo pone LoadCredential= de systemd)",
                    SALIDA_CONFIG)
    return d


def comprobar_url_latido(url, permitir_http):
    exigir_https(url, permitir_http, "la URL del latido", SALIDA_CONFIG)
    return url.rstrip("/")


# ---------------------------------------------------------------------------
# Procesos
# ---------------------------------------------------------------------------
def ejecutar(orden, etiqueta, entrada=None, plazo=PLAZO):
    limite = acotar(plazo)
    try:
        return subprocess.run(orden, input=entrada, capture_output=True, timeout=limite, check=False)
    except FileNotFoundError:
        raise Fallo(f"no se encuentra la orden {orden[0]}", SALIDA_PROCESO) from None
    except subprocess.TimeoutExpired:
        if presupuesto_agotado():
            raise Fallo(f"{etiqueta} no termina dentro del presupuesto de tiempo", SALIDA_TIEMPO) from None
        raise Fallo(f"{etiqueta} no termina en {plazo} s", SALIDA_PROCESO) from None


def en_contenedor(contenedor, orden, etiqueta, entrada=None, plazo=PLAZO):
    """docker exec por peer: dentro del contenedor, el usuario es postgres (el
    del contenedor, user 70:70), que es el único que pg_hba.conf deja entrar
    por el socket. Se comprueba el código de salida de CADA proceso."""
    r = ejecutar([DOCKER, "exec", "-i", contenedor, *orden], etiqueta, entrada=entrada, plazo=plazo)
    if r.returncode != 0:
        raise Fallo(f"{etiqueta} falla (código {r.returncode}): {cola_de(r.stderr)}", SALIDA_PROCESO)
    return r.stdout


# Una sola consulta con todo lo que describe el estado de la base: recuentos
# por tabla y, por empresa, la última secuencia y el último hash de la cadena
# de auditoría (canal.registro_auditoria; la fórmula del hash está en
# canal.encadenar_auditoria). El superusuario se salta RLS: ve todas las
# empresas. verificar_cadena_auditoria devuelve NULL si la cadena está intacta
# o la primera secuencia que se rompe.
SQL_ESTADO = r"""
select json_build_object(
  'recuentos', (
    select coalesce(json_object_agg(t.nombre, t.n order by t.nombre), '{}'::json)
      from (select format('%I.%I', n.nspname, c.relname) as nombre,
                   (xpath('/row/n/text()',
                          query_to_xml(format('select count(*) as n from %I.%I', n.nspname, c.relname),
                                       false, true, '')))[1]::text::bigint as n
              from pg_class c
              join pg_namespace n on n.oid = c.relnamespace
             where c.relkind = 'r'
               and n.nspname not in ('pg_catalog', 'information_schema')
               and n.nspname not like 'pg_toast%') t),
  'auditoria', (
    select coalesce(json_agg(json_build_object('empresa', a.empresa_id,
                                               'ultima_secuencia', a.secuencia,
                                               'ultimo_hash', encode(a.hash, 'hex'))
                             order by a.empresa_id), '[]'::json)
      from (select distinct on (empresa_id) empresa_id, secuencia, hash
              from canal.registro_auditoria
             order by empresa_id, secuencia desc) a),
  'cadena_rota_en', canal.verificar_cadena_auditoria()
);
"""


def consultar_estado(bd):
    salida = en_contenedor(bd, ["psql", "-U", "postgres", "-d", "canario", "-X", "-q", "-A", "-t",
                                "-v", "ON_ERROR_STOP=1", "-f", "-"],
                           "psql (estado de la base)", entrada=SQL_ESTADO.encode("utf-8"))
    try:
        estado = json.loads(salida)
    except ValueError:
        raise Fallo("la consulta del estado de la base no devuelve JSON", SALIDA_PROCESO) from None
    if (not isinstance(estado, dict) or not isinstance(estado.get("recuentos"), dict)
            or not isinstance(estado.get("auditoria"), list) or "cadena_rota_en" not in estado):
        raise Fallo("la consulta del estado de la base no devuelve el JSON esperado", SALIDA_PROCESO)
    return estado


def motivos_de(estado, estable):
    """Por qué una copia no es buena (lista vacía si lo es). No se niega a
    subir ninguna: una copia sospechosa sigue siendo evidencia, y negarse dejaría
    sin copias a la vez que el problema. Va a cuarentena/ y el script falla."""
    motivos = []
    # Una base sin ninguna empresa es casi seguro un volumen nuevo o
    # equivocado: una copia "buena" de eso taparía que las denuncias ya no están.
    if estado["recuentos"].get("canal.empresa", 0) == 0:
        motivos.append("base_vacia")
    # Una cadena rota es una manipulación de la auditoría: con Object Lock esa
    # copia estaría 30 días como "buena" sin que nadie lo viera.
    if estado["cadena_rota_en"] is not None:
        motivos.append(f"cadena_rota_en={estado['cadena_rota_en']}")
    if not estable:
        motivos.append("base_inestable")
    return motivos


def volcar(bd):
    r = ejecutar([DOCKER, "exec", bd, "pg_dump", "-U", "postgres", "-w", "-Fc", "-d", "canario"],
                 "pg_dump", plazo=PLAZO_VOLCADO)
    if r.returncode != 0:
        raise Fallo(f"pg_dump falla (código {r.returncode}): {cola_de(r.stderr)}", SALIDA_PROCESO)
    if len(r.stdout) > TOPE_VOLCADO:
        raise Fallo(f"el volcado supera el tope de {TOPE_VOLCADO} bytes: hay que cambiar el diseño "
                    "(docs/operacion.md, Copias de seguridad)", SALIDA_PROCESO)
    # Todo volcado en formato custom empieza por PGDMP: una salida vacía o un
    # mensaje de error con código 0 no pasa por copia.
    if not r.stdout.startswith(b"PGDMP"):
        raise Fallo("la salida de pg_dump no es un volcado en formato custom", SALIDA_PROCESO)
    return r.stdout


def cifrar_tar(miembros, destinatarios, orden_age, ruta):
    """Escribe en ruta el tar de los miembros (nombre, bytes) cifrado con age
    para todos los destinatarios. El tar va directo a la entrada de age: el
    texto en claro no toca el disco."""
    orden = [*orden_age]
    for d in destinatarios:
        orden += ["-r", d]
    ruta_err = pathlib.Path(str(ruta) + ".err")
    with open(ruta, "wb") as salida, open(ruta_err, "wb") as errores:
        try:
            proceso = subprocess.Popen(orden, stdin=subprocess.PIPE, stdout=salida, stderr=errores)
        except FileNotFoundError:
            raise Fallo(f"no se encuentra la orden {orden[0]}", SALIDA_PROCESO) from None
        fallo_escritura = None
        try:
            with tarfile.open(fileobj=proceso.stdin, mode="w|", format=tarfile.PAX_FORMAT) as t:
                ahora = int(time.time())
                for nombre, datos in miembros:
                    info = tarfile.TarInfo(nombre)
                    info.size = len(datos)
                    info.mtime = ahora
                    info.mode = 0o600
                    t.addfile(info, io.BytesIO(datos))
        except OSError as e:
            # Normalmente, age ha muerto y la tubería está rota: la causa es
            # su código de salida, que se mira abajo.
            fallo_escritura = e
        except BaseException:
            # SIGTERM o presupuesto: no se deja un age huérfano.
            proceso.kill()
            proceso.wait()
            raise
        finally:
            try:
                proceso.stdin.close()
            except OSError:
                pass
        try:
            codigo = proceso.wait(timeout=acotar(PLAZO_VOLCADO))
        except subprocess.TimeoutExpired:
            proceso.kill()
            proceso.wait()
            if presupuesto_agotado():
                raise Fallo("age no termina de cifrar dentro del presupuesto de tiempo", SALIDA_TIEMPO) from None
            raise Fallo("age no termina de cifrar", SALIDA_PROCESO) from None
        except BaseException:
            proceso.kill()
            proceso.wait()
            raise
    if codigo != 0:
        raise Fallo(f"age falla (código {codigo}): {cola_de(ruta_err.read_bytes())}", SALIDA_PROCESO)
    if fallo_escritura is not None:
        raise Fallo(f"no se pudo escribir el tar hacia age: {fallo_escritura}", SALIDA_PROCESO)
    if ruta.stat().st_size == 0:
        raise Fallo("age no ha producido ningún dato cifrado", SALIDA_PROCESO)
    ruta_err.unlink()


# ---------------------------------------------------------------------------
# Backblaze B2 (API nativa v4, por urllib)
# ---------------------------------------------------------------------------
class SinRedireccion(urllib.request.HTTPRedirectHandler):
    """Una redirección con credenciales las llevaría a otro sitio: se rechaza."""

    def redirect_request(self, *args, **kwargs):
        return None


def _crear_abridor():
    """Un abridor con SOLO http y https. build_opener añadiría además FileHandler
    (file://), FTPHandler y DataHandler: una URL manipulada (la apiUrl o la
    uploadUrl que devuelve B2, o una credencial) no debe poder leer ficheros de
    root. ProxyHandler({}): ningún proxy del entorno se mete entre el script y B2."""
    abridor = urllib.request.OpenerDirector()
    for manejador in (urllib.request.ProxyHandler({}), urllib.request.UnknownHandler(),
                      urllib.request.HTTPHandler(), urllib.request.HTTPSHandler(),
                      urllib.request.HTTPDefaultErrorHandler(), urllib.request.HTTPErrorProcessor(),
                      SinRedireccion()):
        abridor.add_handler(manejador)
    return abridor


ABRIDOR = _crear_abridor()


def exigir_https(url, permitir_http, que, codigo):
    """https obligatorio: las credenciales y los datos no viajan en claro. Solo
    el modo de prueba (una --b2-url que no es la real) admite http."""
    try:
        p = urllib.parse.urlsplit(url)
    except ValueError:
        raise Fallo(f"{que} no es una URL válida", codigo) from None
    esquemas = ("https", "http") if permitir_http else ("https",)
    if p.scheme not in esquemas or not p.hostname:
        raise Fallo(f"{que} no es una URL https válida", codigo)
    return url


def pedir(url, cabeceras, datos=None, metodo="GET", plazo=PLAZO_HTTP, acotado=True):
    """(estado, cuerpo). Un estado de error HTTP no es excepción: lo decide quien
    llama. acotado=False solo para el /fail, que tiene que poder salir justo
    cuando el presupuesto se ha agotado."""
    if acotado:
        plazo = acotar(plazo)
    peticion = urllib.request.Request(url, data=datos, method=metodo,
                                      headers={"User-Agent": "canario-copias", **cabeceras})
    try:
        with ABRIDOR.open(peticion, timeout=plazo) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except (urllib.error.URLError, OSError) as e:
        # Sin la URL ni cabeceras: solo el motivo y el servidor.
        raise ErrorRed(f"sin conexión con {urllib.parse.urlsplit(url).hostname}: "
                       f"{getattr(e, 'reason', e)}") from None


class ErrorRed(Exception):
    pass


def codigo_b2(cuerpo):
    """El campo "code" de un error de B2, o "?" (nunca el mensaje entero)."""
    try:
        c = json.loads(cuerpo).get("code")
    except (ValueError, AttributeError):
        return "?"
    return c if isinstance(c, str) and re.fullmatch(r"[a-z_0-9]{1,40}", c) else "?"


def autorizar_b2(b2_url, b2_id, b2_clave, bucket_esperado, permitir_http):
    """b2_authorize_account v4. Devuelve (apiUrl, token, id del bucket) y se
    niega si la clave no es exactamente writeFiles sobre el bucket esperado."""
    basico = base64.b64encode(f"{b2_id}:{b2_clave}".encode()).decode()
    try:
        estado, cuerpo = pedir(f"{b2_url}/b2api/v4/b2_authorize_account", {"Authorization": f"Basic {basico}"})
    except ErrorRed as e:
        if presupuesto_agotado():
            raise Fallo("b2_authorize_account no responde dentro del presupuesto de tiempo", SALIDA_TIEMPO) from None
        raise Fallo(f"b2_authorize_account: {e}", SALIDA_SUBIDA) from None
    if estado != 200:
        raise Fallo(f"B2 rechaza la clave (b2_authorize_account, HTTP {estado}, code={codigo_b2(cuerpo)})",
                    SALIDA_B2_CLAVE)
    try:
        r = json.loads(cuerpo)
        almacen = r["apiInfo"]["storageApi"]
        permitido = almacen["allowed"]
        token = r["authorizationToken"]
        api_url = almacen["apiUrl"]
        capacidades = permitido["capabilities"]
        buckets = permitido["buckets"]
        prefijo = permitido.get("namePrefix")
    except (ValueError, KeyError, TypeError):
        raise Fallo("la respuesta de b2_authorize_account no tiene el formato v4 esperado", SALIDA_B2_CLAVE) from None
    # Mínimo privilegio comprobado, no supuesto: la copia es lo que queda si el
    # VPS cae, y con readFiles/deleteFiles/listBuckets... quien lo tomara
    # podría leerlas o borrarlas (si no hubiera Object Lock).
    if sorted(capacidades) != ["writeFiles"]:
        raise Fallo(f"la clave de B2 tiene capacidades {sorted(capacidades)}: tiene que tener exactamente "
                    "['writeFiles']. Crea otra clave y no sigo con esta", SALIDA_B2_CLAVE)
    if not isinstance(buckets, list) or len(buckets) != 1 or not isinstance(buckets[0], dict) or not buckets[0].get("id"):
        raise Fallo("la clave de B2 tiene que estar limitada a un solo bucket", SALIDA_B2_CLAVE)
    if prefijo is not None:
        raise Fallo("la clave de B2 está limitada a un prefijo de nombre: no es la prevista", SALIDA_B2_CLAVE)
    # El bucket esperado está en la configuración de root: una clave de otro
    # bucket (el de otro proyecto, o uno sin Object Lock) subiría las copias a un
    # sitio sin retención y nadie lo vería hasta restaurar.
    if buckets[0]["id"] != bucket_esperado:
        raise Fallo("la clave de B2 es de un bucket distinto del esperado (bucket_id de la configuración)",
                    SALIDA_B2_CLAVE)
    if not isinstance(api_url, str):
        raise Fallo("la respuesta de b2_authorize_account no tiene el formato v4 esperado", SALIDA_B2_CLAVE)
    exigir_https(api_url, permitir_http, "la apiUrl que devuelve B2", SALIDA_B2_CLAVE)
    return api_url, token, buckets[0]["id"]


def subir_a_b2(api_url, token, bucket_id, nombre, ruta, permitir_http):
    """b2_get_upload_url y b2_upload_file con X-Bz-Content-Sha1 y longitud. Sin
    ningún X-Bz-Info: nada de metadatos que revelen lo que hay dentro. Devuelve
    lo que B2 confirma (nombre, fileId, SHA1 y bytes): va al cuerpo del latido."""
    sha1 = hashlib.sha1(usedforsecurity=False)  # exigido por B2: integridad, no seguridad
    with open(ruta, "rb") as f:
        for bloque in iter(lambda: f.read(1 << 20), b""):
            sha1.update(bloque)
    sha1 = sha1.hexdigest()
    longitud = ruta.stat().st_size
    ultimo = "sin intentos"
    for intento in range(1, INTENTOS_SUBIDA + 1):
        acotar(0)  # falla si ya no queda presupuesto
        if intento > 1:
            time.sleep(acotar(ESPERA * (intento - 1)))
        try:
            estado, cuerpo = pedir(f"{api_url}/b2api/v4/b2_get_upload_url?bucketId={urllib.parse.quote(bucket_id)}",
                                   {"Authorization": token})
            if estado != 200:
                ultimo = f"b2_get_upload_url HTTP {estado} code={codigo_b2(cuerpo)}"
                if estado in (401, 429, 500, 502, 503, 504):
                    continue
                break
            destino = json.loads(cuerpo)
            exigir_https(destino["uploadUrl"], permitir_http, "la uploadUrl que devuelve B2", SALIDA_SUBIDA)
            with open(ruta, "rb") as f:
                estado, cuerpo = pedir(destino["uploadUrl"],
                                       {"Authorization": destino["authorizationToken"],
                                        "X-Bz-File-Name": urllib.parse.quote(nombre, safe="/"),
                                        "Content-Type": "application/octet-stream",
                                        "Content-Length": str(longitud),
                                        "X-Bz-Content-Sha1": sha1},
                                       datos=f, metodo="POST", plazo=PLAZO_VOLCADO)
        except ErrorRed as e:
            ultimo = str(e)
            continue
        except (ValueError, KeyError, TypeError):
            ultimo = "respuesta de B2 con formato inesperado"
            continue
        if estado == 200:
            try:
                r = json.loads(cuerpo)
                if r["fileName"] != nombre or r["contentSha1"] != sha1 or int(r["contentLength"]) != longitud:
                    raise Fallo("B2 confirma una subida distinta de la enviada (nombre, SHA1 o longitud)", SALIDA_SUBIDA)
                identificador = r["fileId"]
                if not isinstance(identificador, str) or not re.fullmatch(r"[A-Za-z0-9_\-]{1,200}", identificador):
                    raise ValueError
            except (ValueError, KeyError, TypeError):
                raise Fallo("la confirmación de b2_upload_file no tiene el formato esperado", SALIDA_SUBIDA) from None
            return {"objeto": nombre, "fileId": identificador, "sha1": sha1, "bytes": longitud}
        ultimo = f"b2_upload_file HTTP {estado} code={codigo_b2(cuerpo)}"
        if estado not in (401, 408, 429, 500, 502, 503, 504):
            break
    if presupuesto_agotado():
        raise Fallo(f"no se pudo subir {nombre} dentro del presupuesto de tiempo", SALIDA_TIEMPO)
    raise Fallo(f"no se pudo subir {nombre}: {ultimo}", SALIDA_SUBIDA)


# ---------------------------------------------------------------------------
# Latido (healthchecks.io): POST a la URL = éxito; POST a <URL>/fail = fallo
# ---------------------------------------------------------------------------
def cuerpo_latido(objetos, motivo=None, avisos=()):
    """Texto del cuerpo del ping: el motivo (solo en /fail), los avisos y, por
    objeto subido, una línea JSON con nombre, fileId, SHA1 y bytes. Es el
    registro de lo que subió el script legítimo, fuera del VPS. Nada de esto es
    secreto (el fileId solo sirve con una clave de lectura)."""
    partes = []
    if motivo:
        partes.append(f"motivo: {aplanar(motivo)}")
    partes += [f"aviso: {aplanar(a)}" for a in avisos]
    partes += [json.dumps(o, sort_keys=True) for o in objetos]
    texto = ("\n".join(partes) + "\n") if partes else ""
    return texto.encode("utf-8")[:TOPE_CUERPO_LATIDO]


def latido(url, sufijo="", cuerpo=b""):
    destino = url + sufijo
    try:
        # No acotado por el presupuesto: el /fail tiene que salir justo cuando
        # se agota. Tiene su propio plazo.
        estado, _ = pedir(destino, {"Content-Type": "text/plain; charset=utf-8"}, datos=cuerpo, metodo="POST",
                          plazo=PLAZO_LATIDO, acotado=False)
    except ErrorRed as e:
        raise Fallo(f"el latido falla: {e}", SALIDA_LATIDO) from None
    if not 200 <= estado < 300:
        # Solo el servidor y el estado, nunca la URL (el UUID es la clave).
        raise Fallo(f"el latido{sufijo} de {urllib.parse.urlsplit(url).hostname} responde HTTP {estado}",
                    SALIDA_LATIDO)


def avisar_fallo(url_latido, excepcion):
    """/fail con el motivo (y lo que se llegó a subir) en el cuerpo. Si el
    propio /fail falla, se dice, pero el error que cuenta es el primero."""
    if isinstance(excepcion, Fallo):
        motivo, objetos = str(excepcion), excepcion.objetos
    else:
        motivo, objetos = f"error inesperado: {type(excepcion).__name__}", []
    try:
        latido(url_latido, "/fail", cuerpo_latido(objetos, motivo=motivo))
    except Fallo as e:
        escribir(AVISO, f"AVISO: {e}", sys.stderr)


# ---------------------------------------------------------------------------
# base
# ---------------------------------------------------------------------------
def instante_utc():
    return datetime.datetime.now(datetime.UTC)


def directorio_privado(args):
    # mkdtemp crea el directorio con 0700 (y PrivateTmp= lo aísla en systemd).
    return pathlib.Path(tempfile.mkdtemp(prefix="canario-copia-", dir=args.temporal))


def limpiar(directorio, args):
    if args.conservar_temporal:
        return
    try:
        shutil.rmtree(directorio)
    except OSError as e:
        escribir(AVISO, f"AVISO: no se pudo borrar el temporal {directorio}: {e.strerror}", sys.stderr)


def hacer_base(args, destinatarios, b2_id, b2_clave, bucket_esperado, permitir_http):
    """Devuelve el objeto subido. Si la copia no es buena, la sube a cuarentena/
    y lanza un Fallo (código 6) que lleva ese objeto."""
    api_url, token, bucket = autorizar_b2(args.b2_url, b2_id, b2_clave, bucket_esperado, permitir_http)
    # Consulta, volcado y consulta otra vez: si el estado cambió entre las dos,
    # el manifiesto no describiría el volcado. Se repite; si no se estabiliza,
    # se sube igualmente, a cuarentena y diciéndolo en el manifiesto.
    estable = False
    for intento in range(1, INTENTOS_BASE + 1):
        antes = consultar_estado(args.contenedor_bd)
        volcado = volcar(args.contenedor_bd)
        despues = consultar_estado(args.contenedor_bd)
        if antes == despues:
            estable = True
            break
        escribir(AVISO, f"AVISO: la base cambió durante la copia (intento {intento}/{INTENTOS_BASE})", sys.stderr)
    motivos = motivos_de(antes, estable)
    ahora = instante_utc()
    manifiesto = {"formato": 1, "base": "canario", "instante_utc": ahora.strftime("%Y-%m-%dT%H:%M:%SZ"),
                  "volcado_bytes": len(volcado), "volcado_sha256": hashlib.sha256(volcado).hexdigest(),
                  "estable": estable, "motivos": motivos, **antes}
    miembros = [("manifiesto.json", json.dumps(manifiesto, indent=2, sort_keys=True).encode("utf-8")),
                ("volcado.dump", volcado)]
    # Nombre único con la hora (también en cuarentena): una copia nunca
    # sustituye a otra con el mismo nombre, y la hora del nombre cuenta lo mismo
    # que la de subida de B2 al elegir qué restaurar.
    prefijo = "cuarentena" if motivos else "base"
    nombre = f"{prefijo}/{ahora.strftime('%Y%m%dT%H%M%SZ')}.age"
    directorio = directorio_privado(args)
    try:
        ruta = directorio / "copia.age"
        cifrar_tar(miembros, destinatarios, args.age, ruta)
        del volcado, miembros
        objeto = subir_a_b2(api_url, token, bucket, nombre, ruta, permitir_http)
    finally:
        limpiar(directorio, args)
    if motivos:
        raise Fallo(f"la copia NO es buena y se ha subido a {prefijo}/ ({', '.join(motivos)}): objeto={nombre} "
                    f"bytes={objeto['bytes']}", SALIDA_BASE_INVALIDA, objetos=[objeto])
    escribir(INFO_NOTICE, f"COPIA SUBIDA: objeto={nombre} bytes={objeto['bytes']}", sys.stdout)
    return objeto


def leer_configuracion(args):
    """Lo común a las dos subórdenes. Devuelve (destinatarios, b2_id, b2_clave,
    bucket_esperado, directorio de credenciales, permitir_http)."""
    destinatarios = leer_destinatarios(args.destinatarios)
    directorio = directorio_credenciales(args)
    return (destinatarios, leer_credencial(directorio, "b2_id"), leer_credencial(directorio, "b2_clave"),
            leer_credencial(directorio, "bucket_id"), directorio, args.b2_url != B2_URL)


def cmd_base(args):
    destinatarios, b2_id, b2_clave, bucket, directorio, permitir_http = leer_configuracion(args)
    url_latido = comprobar_url_latido(leer_credencial(directorio, "latido_url"), permitir_http)
    try:
        objeto = hacer_base(args, destinatarios, b2_id, b2_clave, bucket, permitir_http)
    except Exception as e:
        # Cualquier fallo, también uno inesperado, y el SIGTERM: /fail acorta
        # el aviso y lleva el motivo.
        avisar_fallo(url_latido, e)
        raise
    latido(url_latido, "", cuerpo_latido([objeto]))


# ---------------------------------------------------------------------------
# eventos
# ---------------------------------------------------------------------------
def a_nanosegundos(texto):
    """RFC 3339 en UTC de docker logs --timestamps, a nanosegundos desde la
    época. Docker recorta los ceros finales de la fracción, así que comparar
    cadenas no sirve."""
    m = RE_LINEA_LOG.match(texto + " x")
    if m is None:
        raise ValueError(texto)
    a, mes, d, h, mi, s, fraccion, _ = m.groups()
    segundos = datetime.datetime(int(a), int(mes), int(d), int(h), int(mi), int(s),
                                 tzinfo=datetime.UTC).timestamp()
    return round(segundos) * 1_000_000_000 + int((fraccion or "0").ljust(9, "0"))


def de_nanosegundos(ns):
    return datetime.datetime.fromtimestamp(ns // 1_000_000_000, datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def leer_cursor(ruta):
    """(id del contenedor, nanosegundos) o None si no hay cursor. Formato
    explícito "v1 <id> <ns>". Un fichero que no lo cumple se rechaza: exportar
    desde un punto inventado escondería un hueco.

    El formato antiguo (solo la marca de tiempo) no se acepta, a propósito: el
    bloque nunca estuvo en producción, y sin el Id del contenedor no se puede
    distinguir una API recreada de una rotación del log. Si apareciera uno, se
    borra el fichero y la primera ejecución exporta todo el log."""
    try:
        texto = pathlib.Path(ruta).read_text(encoding="ascii").strip()
    except FileNotFoundError:
        return None
    except UnicodeDecodeError:
        raise Fallo("el fichero del cursor está dañado (no es ASCII): se para en vez de exportar desde un "
                    "punto inventado", SALIDA_ERROR) from None
    except OSError as e:
        raise Fallo(f"no se puede leer el cursor: {e.strerror}", SALIDA_ERROR) from None
    m = RE_CURSOR.match(texto)
    if m:
        return m.group(1), int(m.group(2))
    if texto.isdigit():
        raise Fallo("el cursor tiene el formato antiguo (solo una marca de tiempo, sin el Id del contenedor): "
                    "se para. Si no hay nada pendiente de exportar, se borra el fichero y la siguiente "
                    "ejecución exporta todo el log", SALIDA_ERROR)
    raise Fallo("el fichero del cursor está dañado: se para en vez de exportar desde un punto inventado",
                SALIDA_ERROR)


def escribir_atomico(ruta, texto):
    """Escribe a un temporal, fsync, os.replace y fsync del directorio: tras un
    corte de luz queda el contenido antiguo o el nuevo entero, nunca uno a
    medias ni un fichero vacío con el nombre definitivo."""
    ruta = pathlib.Path(ruta)
    ruta.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporal = ruta.with_name(ruta.name + ".nuevo")
    with open(temporal, "w", encoding="utf-8", newline="\n") as f:
        f.write(texto)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temporal, ruta)
    if os.name == "posix":  # Windows no abre directorios; el script real corre en Linux
        descriptor = os.open(ruta.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def guardar_cursor(ruta, id_contenedor_api, ns):
    escribir_atomico(ruta, f"v1 {id_contenedor_api} {ns}\n")


def ruta_hueco(ruta_cursor):
    """El fichero que recuerda un hueco hasta que alguien lo reconozca
    (borrándolo), junto al cursor: eventos.cursor -> eventos.hueco."""
    return pathlib.Path(ruta_cursor).with_suffix(".hueco")


def leer_hueco(ruta):
    try:
        return aplanar(pathlib.Path(ruta).read_text(encoding="utf-8", errors="replace"))[:500]
    except FileNotFoundError:
        return None
    except OSError as e:
        raise Fallo(f"no se puede leer el fichero del hueco: {e.strerror}", SALIDA_ERROR) from None


def id_contenedor(api):
    r = ejecutar([DOCKER, "inspect", "--type", "container", "--format", "{{.Id}}", api], "docker inspect")
    if r.returncode != 0:
        raise Fallo(f"docker inspect falla (código {r.returncode}): {cola_de(r.stderr)}", SALIDA_PROCESO)
    identificador = r.stdout.decode("utf-8", "replace").strip()
    if not RE_ID_CONTENEDOR.match(identificador):
        raise Fallo("docker inspect no devuelve un Id de contenedor válido", SALIDA_PROCESO)
    return identificador


def leer_log(api):
    r = ejecutar([DOCKER, "logs", "--timestamps", api], "docker logs", plazo=PLAZO_VOLCADO)
    if r.returncode != 0:
        # Sin stderr: en "docker logs" es el log de la API (con datos), no un
        # mensaje de docker.
        raise Fallo(f"docker logs falla (código {r.returncode})", SALIDA_PROCESO)
    # La API escribe en stderr (logging) y docker separa los dos flujos: se
    # juntan y se ordenan por la marca de tiempo.
    lineas, sin_marca = [], 0
    for flujo in (r.stdout, r.stderr):
        for cruda in flujo.decode("utf-8", "replace").splitlines():
            m = RE_LINEA_LOG.match(cruda)
            if m is None:
                sin_marca += 1
                continue
            lineas.append((a_nanosegundos(cruda.split(" ", 1)[0]), cruda))
    lineas.sort(key=lambda x: x[0])
    if sin_marca:
        escribir(AVISO, f"AVISO: {sin_marca} líneas del log sin marca de tiempo, ignoradas", sys.stderr)
    return lineas


def hacer_eventos(args, destinatarios, b2_id, b2_clave, bucket_esperado, permitir_http):
    """Devuelve (objetos subidos, avisos). Lanza Fallo con código 5 si hay un
    hueco, nuevo o todavía sin reconocer, después de subir lo que había."""
    cursor = leer_cursor(args.estado)
    fichero_hueco = ruta_hueco(args.estado)
    id_api = id_contenedor(args.contenedor_api)
    lineas = leer_log(args.contenedor_api)
    objetos, avisos = [], []
    hueco_pendiente = leer_hueco(fichero_hueco)
    if not lineas:
        # Sin ninguna línea no hay nada que exportar ni cursor que mover.
        escribir(INFO_NOTICE, "EVENTOS: el log está vacío", sys.stdout)
    else:
        # Contenedor nuevo: la API se recreó (una actualización). Su log empieza
        # de cero, así que su primera línea es posterior al cursor sin que la
        # rotación haya comido nada: no es el hueco, es otro aviso con su
        # propio evento. Lo que el contenedor anterior escribió después de la
        # última exportación se fue con él: por eso el procedimiento exporta
        # ANTES de recrear (docs/operacion.md) y este aviso dice desde cuándo.
        nuevo = cursor is not None and cursor[0] != id_api
        if nuevo:
            aviso = (f"EVENTO contenedor_nuevo: la API es un contenedor nuevo; última exportación previa en "
                     f"{de_nanosegundos(cursor[1])}. Se exporta todo el log nuevo")
            escribir(AVISO, f"AVISO: {aviso}", sys.stderr)
            avisos.append(aviso)
        desde = None if cursor is None or nuevo else cursor[1]
        # Hueco REAL: mismo contenedor y la línea más antigua que queda es
        # posterior al cursor, así que lo de en medio lo comió la rotación del
        # log (3 ficheros de 10 MB). No se puede recuperar. Se sube lo que hay y
        # se FALLA diciéndolo: una redacción perdida no se volvería a aplicar.
        hueco = desde is not None and lineas[0][0] > desde
        elegidas = []
        for t, linea in lineas:
            if desde is not None and t <= desde:
                continue
            m = RE_EVENTO.match(linea.split(" ", 1)[1])
            if m and m.group(1) in EVENTOS_PERMITIDOS:
                elegidas.append(linea)
        nuevo_cursor = lineas[-1][0]
        ahora = instante_utc()
        if elegidas:
            api_url, token, bucket = autorizar_b2(args.b2_url, b2_id, b2_clave, bucket_esperado, permitir_http)
            manifiesto = {"formato": 2, "instante_utc": ahora.strftime("%Y-%m-%dT%H:%M:%SZ"),
                          "desde_exclusivo_ns": desde, "hasta_inclusivo_ns": nuevo_cursor,
                          "lineas": len(elegidas), "hueco": hueco, "contenedor_nuevo": nuevo}
            miembros = [("manifiesto.json", json.dumps(manifiesto, indent=2, sort_keys=True).encode("utf-8")),
                        ("eventos.log", ("\n".join(elegidas) + "\n").encode("utf-8"))]
            nombre = f"eventos/{ahora.strftime('%Y%m%dT%H%M%SZ')}.age"
            directorio_t = directorio_privado(args)
            try:
                ruta = directorio_t / "eventos.age"
                cifrar_tar(miembros, destinatarios, args.age, ruta)
                objeto = subir_a_b2(api_url, token, bucket, nombre, ruta, permitir_http)
            finally:
                limpiar(directorio_t, args)
            objetos.append(objeto)
            escribir(INFO_NOTICE, f"EVENTOS SUBIDOS: objeto={nombre} lineas={len(elegidas)} bytes={objeto['bytes']}",
                     sys.stdout)
        # Primero el hueco y después el cursor: si el proceso muere entre los
        # dos, el cursor no se movió y el siguiente ciclo detecta el mismo
        # hueco otra vez (y repite la subida). Nunca se pierde el aviso.
        if hueco:
            hueco_pendiente = (f"HUECO detectado {ahora.strftime('%Y-%m-%dT%H:%M:%SZ')}: la última exportación "
                               f"llegó a {de_nanosegundos(desde)} y la línea más antigua del log es de "
                               f"{de_nanosegundos(lineas[0][0])}")
            escribir_atomico(fichero_hueco, hueco_pendiente + "\n")
        # El cursor solo avanza después de subir (si la subida falla, se lanza
        # antes y el siguiente ciclo vuelve a intentarlo).
        guardar_cursor(args.estado, id_api, nuevo_cursor)
    if hueco_pendiente:
        # Persiste hasta que alguien lo reconozca (borrando el fichero): sin
        # esto, el hueco falla una vez y a la siguiente ejecución todo parece
        # bien, aunque nadie lo haya visto.
        raise Fallo(f"HUECO en el log de eventos sin reconocer ({hueco_pendiente}). Lo perdido no se puede "
                    f"recuperar; tras investigarlo se reconoce borrando {fichero_hueco} "
                    "(docs/operacion.md, Copias de seguridad)", SALIDA_HUECO, objetos=objetos)
    return objetos, avisos


def cmd_eventos(args):
    destinatarios, b2_id, b2_clave, bucket, directorio, permitir_http = leer_configuracion(args)
    url_latido = comprobar_url_latido(leer_credencial(directorio, "latido_eventos_url"), permitir_http)
    try:
        objetos, avisos = hacer_eventos(args, destinatarios, b2_id, b2_clave, bucket, permitir_http)
    except Exception as e:
        avisar_fallo(url_latido, e)
        raise
    # Ping en CADA ejecución correcta, también sin nada que subir: es lo que
    # permite a healthchecks.io notar que los eventos dejaron de exportarse.
    latido(url_latido, "", cuerpo_latido(objetos, avisos=avisos))


# ---------------------------------------------------------------------------
def main():
    global DOCKER
    parser = argparse.ArgumentParser(description="Copias cifradas de Canario a Backblaze B2.")
    parser.add_argument("orden", choices=("base", "eventos"))
    # Solo para las pruebas: los valores por defecto son los de producción.
    parser.add_argument("--contenedor-bd", default=CONTENEDOR_BD)
    parser.add_argument("--contenedor-api", default=CONTENEDOR_API)
    parser.add_argument("--b2-url", default=B2_URL)
    parser.add_argument("--credenciales", default=None)
    parser.add_argument("--destinatarios", default=DESTINATARIOS)
    parser.add_argument("--estado", default=ESTADO)
    parser.add_argument("--age", default=AGE, type=shlex.split,
                        help="orden de age (puede llevar argumentos, como docker run ... age)")
    parser.add_argument("--docker", default=DOCKER, help="ruta de docker (en las pruebas, el docker del PC)")
    parser.add_argument("--presupuesto", default=None, type=int, help="segundos de presupuesto total")
    parser.add_argument("--temporal", default=None)
    parser.add_argument("--conservar-temporal", action="store_true")
    args = parser.parse_args()
    if not args.age:
        parser.error("--age vacío")
    if args.presupuesto is not None and args.presupuesto <= 0:
        parser.error("--presupuesto tiene que ser positivo")
    DOCKER = args.docker
    iniciar_presupuesto(args.presupuesto or (PRESUPUESTO_BASE if args.orden == "base" else PRESUPUESTO_EVENTOS))
    signal.signal(signal.SIGTERM, al_recibir_sigterm)
    try:
        if args.orden == "base":
            cmd_base(args)
        else:
            cmd_eventos(args)
    except Fallo as e:
        escribir(ERROR, f"ERROR: {e}", sys.stderr)
        return e.codigo
    except Exception as e:  # noqa: BLE001 - un fallo inesperado también se ve y da código distinto de 0
        escribir(ERROR, f"ERROR inesperado: {type(e).__name__}", sys.stderr)
        return SALIDA_ERROR
    return 0


if __name__ == "__main__":
    sys.exit(main())
