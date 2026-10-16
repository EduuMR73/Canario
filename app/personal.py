"""Identidad del personal: invitación, activación, login, sesiones y
dispositivos de confianza (docs/threat-model.md, 6.3 y 6.9).

Lógica sin HTTP: recibe y devuelve los tokens como texto y nunca sabe si
llegaron en una cabecera o en una cookie. El transporte vive solo en
app/rutas_personal.py, así que un frontend web (cookies HttpOnly y defensa
CSRF) cambiaría esa capa y no esta.

Sesiones (docs/threat-model.md, 6.3): el login entrega dos tokens.
* Acceso: un JWT de 5 minutos (app/tokens.py) que dice quién es el portador
  y cuál es su sesión (sid). Cada petición comprueba la firma y hace UNA
  lectura: la sesión sin revocar ni caducar, la cuenta activa y con TOTP y el
  dispositivo sin revocar. El rol sale de esa lectura, nunca del token. Así
  una baja, un cambio de contraseña o un cierre de sesión cortan el JWT al
  momento (OWASP ASVS 5.0.0, 7.4.1 y 7.4.2) sin escribir nada por petición.
* Renovación: opaco, de 256 bits, del que solo se guarda la huella. Cambia
  en cada uso (RFC 9700, 4.14.2) y el usado queda en tokens_usados:
  presentarlo otra vez es la señal de un robo (el ladrón o el titular ya lo
  gastó) y revoca la sesión entera, con un EVENTO en el log. Sin ventana de
  gracia: una ventana es justo el hueco que aprovecharía el ladrón. El coste
  es que dos renovaciones simultáneas del mismo cliente cierran su sesión;
  el cliente debe renovar de una en una. La inactividad de 15 minutos se mide
  entre renovaciones, y el máximo de 8 horas lo fija la base de datos.

Cuentas:
* Una cuenta nace por invitación, sin credenciales. Su titular fija la
  contraseña (Argon2id) y recibe un secreto TOTP; la cuenta solo se activa
  cuando confirma un código, y entonces recibe su primer dispositivo de
  confianza. Las credenciales pendientes esperan en la invitación: una
  reinvitación no deja la cuenta a medias.
* El login pide en una sola petición empresa, email, contraseña y código
  TOTP: no hay un estado "medio autenticado" que defender. Cualquier fallo
  (empresa, email, contraseña, código, cuenta bloqueada o desactivada) da la
  misma respuesta.

Recuperación (NIST SP 800-63B-4, 4.2): los contactos de recuperación son los
admins de la empresa (reinvitar) y, como último recurso, la plataforma
(reinvitar_admin_plataforma, con revocación inmediata). No hay códigos de
recuperación guardados: recuperarían un factor sin que la empresa se
enterase. Toda reinvitación se ve: fila de auditoría, invitacion_pendiente en
/yo y en la lista de cuentas, y un admin puede anularla (anular_invitacion).

Bloqueo sin denegación de servicio (OWASP, "Slow Down Online Guessing Attacks
with Device Cookies"; Microsoft Entra Smart Lockout; NIST SP 800-63B-4,
3.2.2):
* Con un dispositivo de confianza válido de esa cuenta, los fallos se cuentan
  en el dispositivo: con 5 seguidos espera (1, 2, 4... hasta 60 minutos) y
  con 20 deja de ser de confianza. Un atacante que falla a propósito sin ese
  dispositivo no bloquea al titular en los suyos.
* Sin dispositivo de confianza (o con uno bloqueado, retirado, caducado o de
  otra cuenta), los fallos se cuentan en la cuenta, con las mismas esperas.
  Con 100 seguidos (el máximo de NIST) este camino se cierra hasta que un
  admin reinvite al usuario; sus dispositivos de confianza siguen sirviendo.
  El contador solo vuelve a cero con un acierto por este mismo camino: que el
  titular entre desde su dispositivo no le regala intentos al atacante.
* El intento se reserva (se cuenta) ANTES de verificar, con un UPDATE
  atómico, y se libera al acertar: peticiones simultáneas no consiguen
  intentos extra. Mientras un camino espera, ni siquiera se verifica la
  contraseña: un acierto en ese tiempo no se distingue de un fallo.
* Un fallo de contraseña y uno de TOTP cuentan igual: quien tenga la
  contraseña no puede probar códigos gratis.

Respuestas y tiempos uniformes por construcción: todos los caminos del login
ejecutan las mismas sentencias (las que no aplican, con cero filas: empresa
o email inexistentes usan un contexto aleatorio), el mismo Argon2 (con un
hash ficticio si no hay cuenta) y el mismo cálculo de TOTP (con un secreto
aleatorio). El bloqueo deja un evento en el log y no en la auditoría: una
inserción más en ese intento lo haría medible. La reserva confirma sin
esperar al disco (synchronous_commit off): si no, escribir o no escribir la
fila del contador se notaría en el tiempo (ver SQL_RESERVA_ASINCRONA).

Argon2id con m=19 MiB, t=2, p=1 (OWASP Password Storage Cheat Sheet). El
perfil por defecto de argon2-cffi usa 64 MiB y la API tiene 256 MiB de
memoria (docker-compose.yml): un semáforo acota los hashes simultáneos y, si
no hay hueco, se responde 503 en vez de agotar la memoria. Argon2 se calcula
fuera de toda transacción, para no retener conexiones del pool.

Orden de bloqueos en las escrituras: cuenta, invitación, dispositivos,
sesiones y auditoría. La autenticación de una sesión es su propia
transacción y solo bloquea la fila de la sesión.

Registro: los eventos de seguridad (logins fallidos, bloqueos, cierre del
camino, retirada de un dispositivo, reutilización de una renovación,
saturación) llevan la empresa y la cuenta, nunca IPs, emails, contraseñas,
códigos ni tokens. Cada login fallido deja EVENTO login_fallido (OWASP ASVS
5.0.0, 16.3.1), con la misma llamada en todos los caminos de fallo; los
correctos quedan en la auditoría (ACCION_ACCESO).
"""
import logging
import secrets
import threading
import time
import unicodedata
import uuid
from contextlib import contextmanager
from dataclasses import dataclass

import psycopg
from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError

from app import bd, cripto, denuncias, tokens

registro = logging.getLogger("canario.personal")

ROLES = ("admin", "instructor")

# Argon2id, OWASP Password Storage Cheat Sheet (m=19 MiB, t=2, p=1).
MEMORIA_ARGON2_KIB = 19456
ITERACIONES_ARGON2 = 2
PARALELISMO_ARGON2 = 1
# Hashes de contraseña simultáneos: 2 x 19 MiB caben con margen en los 256
# MiB de la API. Si no hay hueco en ESPERA_HASH segundos, 503.
HASHES_SIMULTANEOS = 2
ESPERA_HASH = 2.0

# Bloqueo progresivo (ver la cabecera).
FALLOS_ANTES_DE_ESPERAR = 5
ESPERA_MAXIMA_MINUTOS = 60
TOPE_SIN_CONFIANZA = 100
TOPE_DISPOSITIVO = 20
# Sesión: 15 minutos sin renovar o 8 horas en total (la caducidad total la
# fija la base de datos al crearla).
INACTIVIDAD_SESION_MINUTOS = 15
# Tokens de renovación usados que caben en una sesión. Mismo valor que el
# CHECK de canal.sesion_personal.tokens_usados: si se llega, la renovación
# falla y hay que volver a entrar (con una renovación cada 5 minutos, 8 horas
# son 96).
TOPE_RENOVACIONES = 256

# Política de contraseñas (NIST SP 800-63B-4): con un segundo factor
# obligatorio, 12 como mínimo; 128 como máximo, para acotar lo que se
# procesa; NFKC, para que la misma contraseña escrita con otra forma Unicode
# sea la misma.
LONGITUD_MINIMA_CONTRASENA = 12
LONGITUD_MAXIMA_CONTRASENA = 128
# Las piezas más cortas que esto no se buscan dentro de la contraseña:
# rechazarían contraseñas buenas por casualidad.
LONGITUD_MINIMA_PROHIBIDA = 4

ACCION_ACCESO = "acceso"
ACCION_ACTIVACION = "activacion"
ACCION_CAMBIO_CONTRASENA = "cambio_contrasena"
ACCION_INVITACION = "invitacion"
ACCION_BAJA = "baja"
ACCION_ANULACION_INVITACION = "anulacion_invitacion"
ACCION_INVITACION_PLATAFORMA = "invitacion_admin_plataforma"
ACCION_REINVITACION_PLATAFORMA = "reinvitacion_admin_plataforma"
ACTOR_PLATAFORMA = "plataforma"

_hasher = PasswordHasher(time_cost=ITERACIONES_ARGON2, memory_cost=MEMORIA_ARGON2_KIB,
                         parallelism=PARALELISMO_ARGON2, hash_len=32, salt_len=16, type=Type.ID)
# Hash de una contraseña aleatoria que nadie conoce, con los mismos
# parámetros: cuando no hay cuenta, se verifica contra él y el tiempo es el
# mismo que con una cuenta real.
_HASH_FICTICIO = _hasher.hash(secrets.token_urlsafe(32))
_semaforo = threading.BoundedSemaphore(HASHES_SIMULTANEOS)


# Parámetros del bloqueo, enlazados en cada reserva como cualquier otro valor:
# el SQL es siempre texto fijo, nunca se construye con formato.
PARAMETROS_BLOQUEO = {"umbral": FALLOS_ANTES_DE_ESPERAR, "espera_maxima": ESPERA_MAXIMA_MINUTOS,
                      "tope_dispositivo": TOPE_DISPOSITIVO, "tope_sin_confianza": TOPE_SIN_CONFIANZA}

# Reserva de un intento con un dispositivo de confianza. Las tres reservas
# devuelven las mismas columnas: (dispositivo, cuenta, rol, hash, secreto
# cifrado, versión de su clave, intentos tras este). La espera tras el fallo
# n (ya contado) es de 2^(n - umbral) minutos con tope de espera_maxima, a
# partir del umbral; el exponente se acota a 6 para no calcular potencias
# enormes.
SQL_RESERVAR_DISPOSITIVO = """
    update canal.dispositivo_personal d
       set intentos_fallidos = d.intentos_fallidos + 1,
           bloqueado_hasta = case when d.intentos_fallidos + 1 >= %(umbral)s
               then now() + make_interval(mins => (least(%(espera_maxima)s,
                    2 ^ least(d.intentos_fallidos + 1 - %(umbral)s, 6)))::integer) end
      from canal.usuario_personal u
     where d.token_sha256 = %(huella)s
       and u.empresa_id = d.empresa_id and u.id = d.usuario_id and u.email = %(email)s
       and u.activo and u.totp_activo
       and not d.revocado and d.caduca > now()
       and d.intentos_fallidos < %(tope_dispositivo)s
       and (d.bloqueado_hasta is null or d.bloqueado_hasta <= now())
    returning d.id, u.id, u.rol, u.hash_contrasena, u.secreto_totp_cifrado, u.version_clave_totp,
              d.intentos_fallidos
"""
# Reserva por el camino sin confianza. %(sin_confianza)s es false si ya se
# reservó con el dispositivo: la sentencia se ejecuta igual (cero filas)
# para que todos los caminos hagan el mismo trabajo.
SQL_RESERVAR_CUENTA = """
    update canal.usuario_personal
       set intentos_fallidos = intentos_fallidos + 1,
           bloqueado_hasta = case when intentos_fallidos + 1 >= %(umbral)s
               then now() + make_interval(mins => (least(%(espera_maxima)s,
                    2 ^ least(intentos_fallidos + 1 - %(umbral)s, 6)))::integer) end
     where email = %(email)s and %(sin_confianza)s
       and activo and totp_activo
       and intentos_fallidos < %(tope_sin_confianza)s
       and (bloqueado_hasta is null or bloqueado_hasta <= now())
    returning null::uuid, id, rol, hash_contrasena, secreto_totp_cifrado, version_clave_totp, intentos_fallidos
"""
# Reserva al cambiar la contraseña: por el dispositivo de la sesión.
SQL_RESERVAR_DISPOSITIVO_SESION = """
    update canal.dispositivo_personal d
       set intentos_fallidos = d.intentos_fallidos + 1,
           bloqueado_hasta = case when d.intentos_fallidos + 1 >= %(umbral)s
               then now() + make_interval(mins => (least(%(espera_maxima)s,
                    2 ^ least(d.intentos_fallidos + 1 - %(umbral)s, 6)))::integer) end
      from canal.usuario_personal u
     where d.id = %(dispositivo)s and u.empresa_id = d.empresa_id and u.id = d.usuario_id
       and u.activo and u.totp_activo
       and not d.revocado
       and d.intentos_fallidos < %(tope_dispositivo)s
       and (d.bloqueado_hasta is null or d.bloqueado_hasta <= now())
    returning d.id, u.id, u.rol, u.hash_contrasena, u.secreto_totp_cifrado, u.version_clave_totp,
              d.intentos_fallidos
"""
# version = 0 nunca existe (CHECK version > 0): cero filas en los caminos sin
# cuenta, con la misma sentencia.
SQL_CLAVE_VERSION = "select clave_envuelta from canal.clave_empresa where version = %s"
SQL_CLAVE_ACTUAL = "select version, clave_envuelta from canal.clave_empresa order by version desc limit 1"
SQL_RESOLVER = "select canal.resolver_empresa(%s)"
# La reserva de un intento confirma sin esperar a que el WAL llegue a disco.
# Sin esto, el tiempo de respuesta revelaba si la cuenta existe: con cuenta,
# la reserva escribe una fila y el commit espera el fsync (unos 3 ms,
# medidos por tests/security/verificar_personal.py, d); sin cuenta, o en
# espera, no escribe nada y no espera. Con OFF ningún camino espera
# (documentación de PostgreSQL, synchronous_commit). Coste asumido: si
# PostgreSQL se cae, se pueden perder los fallos contados en sus últimos
# 600 ms como mucho (tres veces wal_writer_delay), sin inconsistencia.
SQL_RESERVA_ASINCRONA = "set local synchronous_commit to off"

# Acierto: el código solo vale una vez (paso posterior al último aceptado) y
# la cuenta tiene que seguir como estaba al verificar (mismo hash, activa).
SQL_CONFIRMAR_ACCESO = """
    update canal.usuario_personal
       set ultimo_paso_totp = %(paso)s,
           intentos_fallidos = case when %(sin_confianza)s then 0 else intentos_fallidos end,
           bloqueado_hasta = case when %(sin_confianza)s then null else bloqueado_hasta end
     where id = %(usuario)s and activo and totp_activo and hash_contrasena = %(hash)s
       and (ultimo_paso_totp is null or ultimo_paso_totp < %(paso)s)
    returning id
"""
SQL_LIBERAR_DISPOSITIVO = (
    "update canal.dispositivo_personal set intentos_fallidos = 0, bloqueado_hasta = null "
    "where id = %s and not revocado returning id"
)
SQL_NUEVO_DISPOSITIVO = (
    "insert into canal.dispositivo_personal (empresa_id, usuario_id, token_sha256) values (%s, %s, %s) returning id"
)
SQL_NUEVA_SESION = (
    "insert into canal.sesion_personal (empresa_id, usuario_id, dispositivo_id, token_sha256) "
    "values (%s, %s, %s, %s) returning id"
)
SQL_AUDITAR = (
    "insert into canal.registro_auditoria (empresa_id, actor, accion, objeto_id) values (%s, %s, %s, %s)"
)

# Autenticación de un JWT de acceso ya verificado: su sesión sigue viva, es
# de la cuenta del token, la cuenta está activa y con TOTP y el dispositivo
# no está revocado. Solo lectura: la inactividad se mide al renovar.
SQL_AUTENTICAR = """
    select s.dispositivo_id, u.rol, u.email, e.nombre
      from canal.sesion_personal s
      join canal.usuario_personal u on u.empresa_id = s.empresa_id and u.id = s.usuario_id
      join canal.dispositivo_personal d on d.empresa_id = s.empresa_id and d.id = s.dispositivo_id
      join canal.empresa e on e.id = s.empresa_id
     where s.id = %(sesion)s and s.usuario_id = %(usuario)s and not s.revocada and s.caduca > now()
       and u.activo and u.totp_activo and not d.revocado
"""
# Renovación: cambia la huella vigente por la nueva y guarda la usada, en una
# sola sentencia (la fila queda bloqueada: dos renovaciones simultáneas con
# el mismo token no pasan las dos). Mismas condiciones que SQL_AUTENTICAR más
# la inactividad y el tope de renovaciones.
SQL_RENOVAR = """
    update canal.sesion_personal s
       set token_sha256 = %(nueva)s, tokens_usados = array_append(s.tokens_usados, %(usada)s::bytea),
           ultimo_uso = now()
      from canal.usuario_personal u, canal.dispositivo_personal d
     where s.token_sha256 = %(usada)s and not s.revocada and s.caduca > now()
       and s.ultimo_uso > now() - make_interval(mins => %(inactividad)s)
       and cardinality(s.tokens_usados) < %(tope)s
       and u.empresa_id = s.empresa_id and u.id = s.usuario_id and u.activo and u.totp_activo
       and d.empresa_id = s.empresa_id and d.id = s.dispositivo_id and not d.revocado
    returning s.id, s.usuario_id
"""
# Reutilización: un token de renovación que ya se gastó revoca su sesión. El
# operador @> usa el índice GIN de tokens_usados.
SQL_REUTILIZACION = (
    "update canal.sesion_personal set revocada = true "
    "where tokens_usados @> array[%s::bytea] and not revocada returning id, usuario_id"
)
SQL_CERRAR_SESION = "update canal.sesion_personal set revocada = true where id = %s"

SQL_INVITACION_ABIERTA = """
    select i.id, i.usuario_id, u.email, e.nombre
      from canal.invitacion_personal i
      join canal.usuario_personal u on u.empresa_id = i.empresa_id and u.id = i.usuario_id
      join canal.empresa e on e.id = i.empresa_id
     where i.token_sha256 = %s and not i.cerrada and i.caduca > now()
"""
SQL_GUARDAR_PENDIENTE = """
    update canal.invitacion_personal
       set hash_contrasena = %s, secreto_totp_cifrado = %s, version_clave_totp = %s
     where id = %s and not cerrada and caduca > now()
    returning id
"""
SQL_INVITACION_PENDIENTE = """
    select i.id, i.usuario_id, i.hash_contrasena, i.secreto_totp_cifrado, i.version_clave_totp, k.clave_envuelta
      from canal.invitacion_personal i
      join canal.clave_empresa k on k.empresa_id = i.empresa_id and k.version = i.version_clave_totp
     where i.token_sha256 = %s and not i.cerrada and i.caduca > now() and i.hash_contrasena is not null
"""
SQL_BLOQUEAR_CUENTA = "select id from canal.usuario_personal where id = %s for update"
SQL_CERRAR_INVITACION = (
    "update canal.invitacion_personal set cerrada = true where id = %s and not cerrada and caduca > now() returning id"
)
SQL_ACTIVAR_CUENTA = """
    update canal.usuario_personal
       set hash_contrasena = %(hash)s, secreto_totp_cifrado = %(secreto)s, version_clave_totp = %(version)s,
           totp_activo = true, ultimo_paso_totp = %(paso)s, intentos_fallidos = 0, bloqueado_hasta = null,
           activo = true
     where id = %(usuario)s
"""
SQL_REVOCAR_DISPOSITIVOS = (
    "update canal.dispositivo_personal set revocado = true where usuario_id = %s and not revocado and id <> %s"
)
SQL_REVOCAR_SESIONES = (
    "update canal.sesion_personal set revocada = true where usuario_id = %s and not revocada and id <> %s"
)
SQL_CERRAR_INVITACIONES = (
    "update canal.invitacion_personal set cerrada = true where usuario_id = %s and not cerrada"
)
SQL_NUEVA_INVITACION = (
    "insert into canal.invitacion_personal (empresa_id, usuario_id, token_sha256) values (%s, %s, %s)"
)
SQL_CAMBIAR_CONTRASENA = """
    update canal.usuario_personal
       set hash_contrasena = %(nuevo)s, ultimo_paso_totp = %(paso)s
     where id = %(usuario)s and activo and totp_activo and hash_contrasena = %(hash)s
       and (ultimo_paso_totp is null or ultimo_paso_totp < %(paso)s)
    returning id
"""

SQL_LISTAR_USUARIOS = """
    select u.id, u.email, u.rol, u.activo, u.totp_activo,
           u.intentos_fallidos >= %(tope_sin_confianza)s as camino_cerrado,
           coalesce(u.bloqueado_hasta > now(), false) as en_espera,
           exists (select 1 from canal.invitacion_personal i
                    where i.empresa_id = u.empresa_id and i.usuario_id = u.id
                      and not i.cerrada and i.caduca > now()) as invitacion_pendiente
      from canal.usuario_personal u
     order by u.email, u.id
"""
# Aviso de recuperación (NIST SP 800-63B-4, 4.2.3): una invitación abierta
# de la propia cuenta. Sin correo, el titular lo ve en /yo y los admins en la
# lista de cuentas.
SQL_INVITACION_PENDIENTE_DE = """
    select exists (select 1 from canal.invitacion_personal
                    where usuario_id = %s and not cerrada and caduca > now())
"""
SQL_ANULAR_INVITACION = (
    "update canal.invitacion_personal set cerrada = true "
    "where usuario_id = %s and not cerrada and caduca > now() returning id"
)
SQL_NUEVO_USUARIO = "insert into canal.usuario_personal (empresa_id, email, rol) values (%s, %s, %s) returning id"
SQL_USUARIO = "select id, rol, activo, totp_activo from canal.usuario_personal where id = %s for update"
# Todos los admins activos, en orden de id: dos bajas simultáneas los
# bloquean en el mismo orden y no se interbloquean.
SQL_BLOQUEAR_ADMINS = (
    "select id, totp_activo from canal.usuario_personal where rol = 'admin' and activo order by id for update"
)
SQL_DAR_DE_BAJA = "update canal.usuario_personal set activo = false where id = %s"
SQL_ADMIN_ACTIVO = (
    "select count(*) from canal.usuario_personal where rol = 'admin' and activo and totp_activo"
)
SQL_USUARIO_POR_EMAIL = "select id, rol, totp_activo from canal.usuario_personal where email = %s for update"
SQL_EMPRESA_VISIBLE = "select count(*) from canal.empresa"

SQLSTATE_DUPLICADO = "23505"
SQLSTATE_CHECK = "23514"


class CredencialesNoValidas(Exception):
    """Cualquier fallo del login. Nunca dice cuál."""


class SesionNoValida(Exception):
    """Token de sesión ausente, mal formado, revocado o caducado."""


class InvitacionNoValida(Exception):
    """Token de invitación desconocido, usado, sustituido o caducado."""


class CodigoNoValido(Exception):
    """El código TOTP de la confirmación no corresponde al secreto."""


class ContrasenaNoValida(ValueError):
    """La contraseña no cumple la política. El motivo no contiene la contraseña."""


class Saturado(Exception):
    """No hay hueco para calcular un hash de contraseña: 503."""


class Prohibido(Exception):
    """La cuenta no tiene el rol necesario: 403."""


class NoEncontrado(Exception):
    """Cuenta inexistente o de otra empresa (invisible bajo RLS): 404."""


class EmailDuplicado(Exception):
    """Ya hay una cuenta con ese email en la empresa: 409."""


class UltimoAdmin(Exception):
    """La baja dejaría a la empresa sin ningún admin activo: 409."""


class EmpresaSinClave(Exception):
    """La empresa no tiene clave de cifrado para el secreto TOTP: 503."""


class AltaAdminRechazada(Exception):
    """gestion alta-admin no puede invitar (ver alta_admin_plataforma)."""


@dataclass(frozen=True)
class Sesion:
    empresa_id: uuid.UUID
    identificador: str
    sesion_id: uuid.UUID
    usuario_id: uuid.UUID
    dispositivo_id: uuid.UUID
    rol: str
    email: str
    nombre_empresa: str


@dataclass(frozen=True)
class Acceso:
    token_acceso: str
    token_renovacion: str
    # Solo si el login fue por el camino sin confianza: el dispositivo nuevo.
    token_dispositivo: str | None = None


@dataclass(frozen=True)
class ActivacionPendiente:
    secreto_totp: str
    uri_totp: str


@dataclass(frozen=True)
class Usuario:
    usuario_id: uuid.UUID
    email: str
    rol: str
    activo: bool
    activado: bool
    camino_sin_confianza_cerrado: bool
    en_espera: bool
    invitacion_pendiente: bool


@dataclass(frozen=True)
class Invitacion:
    usuario_id: uuid.UUID
    token_invitacion: str


# ---------------------------------------------------------------------------
# Piezas comunes
# ---------------------------------------------------------------------------

@contextmanager
def _hueco_hash():
    if not _semaforo.acquire(timeout=ESPERA_HASH):
        registro.warning("EVENTO hashes_saturados: no hay hueco para calcular un hash de contrasena")
        raise Saturado
    try:
        yield
    finally:
        _semaforo.release()


def _verificar_hash(hash_guardado, contrasena):
    """Siempre un Argon2 completo: contra el hash ficticio si no hay cuenta."""
    try:
        return _hasher.verify(hash_guardado or _HASH_FICTICIO, contrasena) and hash_guardado is not None
    except (VerificationError, InvalidHashError):
        return False


def normalizar_contrasena(texto):
    return unicodedata.normalize("NFKC", texto)


def validar_contrasena(texto, email, nombre_empresa):
    """Contraseña normalizada si cumple la política; si no, ContrasenaNoValida."""
    normal = normalizar_contrasena(texto)
    if not LONGITUD_MINIMA_CONTRASENA <= len(normal) <= LONGITUD_MAXIMA_CONTRASENA:
        raise ContrasenaNoValida(
            f"la contraseña debe tener entre {LONGITUD_MINIMA_CONTRASENA} y {LONGITUD_MAXIMA_CONTRASENA} caracteres")
    plegada = normal.casefold()
    piezas = (email, email.split("@", 1)[0], nombre_empresa)
    if any(len(p) >= LONGITUD_MINIMA_PROHIBIDA and p.casefold() in plegada for p in piezas):
        raise ContrasenaNoValida("la contraseña no puede contener el email ni el nombre de la empresa")
    return normal


def _actor(usuario_id):
    return f"personal:{usuario_id}"


def resolver_empresa(pool, identificador):
    """Empresa activa de un identificador público, o None. Se consulta
    siempre, también con un identificador mal formado: el trabajo es el
    mismo en todos los caminos."""
    with bd.transaccion_sin_contexto(pool, solo_lectura=True) as conexion:
        return conexion.execute(SQL_RESOLVER, [identificador]).fetchone()[0]


def leer_compuesto(texto):
    """(identificador, bytes) de un token "<identificador>.<token>", o None."""
    if not isinstance(texto, str) or texto.count(".") != 1:
        return None
    identificador, token = texto.split(".")
    if not denuncias.PATRON_IDENTIFICADOR.fullmatch(identificador):
        return None
    crudo = cripto.leer_token(token)
    return None if crudo is None else (identificador, crudo)


def token_compuesto(identificador, token):
    return f"{identificador}.{token}"


def _descifrar_secreto(claves, empresa_id, usuario_id, envuelta, version, cifrado):
    clave = cripto.desenvolver_clave(claves.maestra, bytes(envuelta), empresa_id, version)
    secreto = cripto.descifrar(clave, bytes(cifrado), cripto.aad_totp(empresa_id, usuario_id))
    if len(secreto) != cripto.LONGITUD_SECRETO_TOTP:
        raise cripto.ErrorIntegridad("secreto TOTP con longitud inesperada")
    return secreto


def _avisar_fallo(empresa_id, reservada, camino):
    """Evento de seguridad cuando un fallo abre una espera o cierra un camino."""
    if reservada is None:
        return
    dispositivo_id, usuario_id, intentos = reservada[0], reservada[1], reservada[6]
    if camino == "dispositivo":
        if intentos >= TOPE_DISPOSITIVO:
            registro.warning("EVENTO retirada_dispositivo: empresa=%s usuario=%s dispositivo=%s intentos=%d",
                             empresa_id, usuario_id, dispositivo_id, intentos)
        elif intentos >= FALLOS_ANTES_DE_ESPERAR:
            registro.warning("EVENTO espera_dispositivo: empresa=%s usuario=%s dispositivo=%s intentos=%d",
                             empresa_id, usuario_id, dispositivo_id, intentos)
    elif intentos >= TOPE_SIN_CONFIANZA:
        registro.warning("EVENTO cierre_sin_confianza: empresa=%s usuario=%s intentos=%d",
                         empresa_id, usuario_id, intentos)
    elif intentos >= FALLOS_ANTES_DE_ESPERAR:
        registro.warning("EVENTO espera_sin_confianza: empresa=%s usuario=%s intentos=%d",
                         empresa_id, usuario_id, intentos)


def _registrar_login_fallido(empresa_id, reservada, camino):
    """EVENTO login_fallido (OWASP ASVS 5.0.0, 16.3.1). La misma llamada en
    todos los caminos de fallo, haya cuenta o no. empresa_id es None si el
    identificador no es de ninguna empresa activa: el contexto aleatorio no se
    registra."""
    registro.warning("EVENTO login_fallido: empresa=%s usuario=%s camino=%s",
                     empresa_id or "-", reservada[1] if reservada else "-", camino)


def _nueva_sesion(conexion, claves, empresa_id, identificador, usuario_id, dispositivo_id, token_dispositivo=None):
    """Crea una sesión en la transacción abierta y devuelve sus dos tokens."""
    token_renovacion, crudo = cripto.generar_token()
    sesion_id = conexion.execute(SQL_NUEVA_SESION, [
        empresa_id, usuario_id, dispositivo_id, cripto.huella_token(cripto.ETIQUETA_RENOVACION, crudo)]).fetchone()[0]
    return Acceso(token_acceso=tokens.emitir(claves.firma_tokens, identificador, usuario_id, sesion_id),
                  token_renovacion=token_compuesto(identificador, token_renovacion),
                  token_dispositivo=token_dispositivo)


def _comprobar_factores(claves, empresa_id, reservada, envuelta, contrasena, codigo, instante):
    """Contraseña y TOTP, con el mismo trabajo haya cuenta o no. Devuelve el
    paso TOTP aceptado si los dos valen, o None."""
    with _hueco_hash():
        contrasena_ok = _verificar_hash(reservada[3] if reservada else None, normalizar_contrasena(contrasena))
    if reservada is not None and envuelta is not None:
        secreto = _descifrar_secreto(claves, empresa_id, reservada[1], envuelta[0], reservada[5], reservada[4])
    else:
        secreto = cripto.generar_secreto_totp()
    paso = cripto.verificar_totp(secreto, codigo, instante)
    if reservada is None or not contrasena_ok or paso is None:
        return None
    return paso


# ---------------------------------------------------------------------------
# Login, sesiones y cambio de contraseña
# ---------------------------------------------------------------------------

def iniciar_sesion(pool, claves, identificador, email, contrasena, codigo, token_dispositivo, instante=None):
    """Login en una petición. Devuelve Acceso o lanza CredencialesNoValidas."""
    instante = time.time() if instante is None else instante
    email = email.lower()
    # Sin empresa, un contexto aleatorio: las mismas sentencias con cero filas.
    resuelta = resolver_empresa(pool, identificador)
    empresa_id = resuelta or uuid.uuid4()
    crudo = cripto.leer_token(token_dispositivo) if token_dispositivo is not None else None
    huella = cripto.huella_token(cripto.ETIQUETA_DISPOSITIVO, crudo or secrets.token_bytes(cripto.LONGITUD_TOKEN))

    with bd.transaccion_empresa(pool, empresa_id) as conexion:
        conexion.execute(SQL_RESERVA_ASINCRONA)
        por_dispositivo = conexion.execute(
            SQL_RESERVAR_DISPOSITIVO, {**PARAMETROS_BLOQUEO, "huella": huella, "email": email}).fetchone()
        por_cuenta = conexion.execute(SQL_RESERVAR_CUENTA, {
            **PARAMETROS_BLOQUEO, "email": email, "sin_confianza": por_dispositivo is None}).fetchone()
        reservada = por_dispositivo or por_cuenta
        envuelta = conexion.execute(SQL_CLAVE_VERSION, [reservada[5] if reservada else 0]).fetchone()
    camino = "dispositivo" if por_dispositivo else "sin_confianza"

    paso = _comprobar_factores(claves, empresa_id, reservada, envuelta, contrasena, codigo, instante)
    if paso is None:
        _registrar_login_fallido(resuelta, reservada, camino)
        _avisar_fallo(empresa_id, reservada, camino)
        raise CredencialesNoValidas

    usuario_id = reservada[1]
    try:
        with bd.transaccion_empresa(pool, empresa_id) as conexion:
            confirmado = conexion.execute(SQL_CONFIRMAR_ACCESO, {
                "paso": paso, "sin_confianza": camino == "sin_confianza", "usuario": usuario_id,
                "hash": reservada[3]}).fetchone()
            # Código ya usado (reutilización) o cuenta cambiada entre la
            # reserva y ahora: el intento ya está contado.
            if confirmado is None:
                raise CredencialesNoValidas
            token_nuevo = None
            if camino == "dispositivo":
                dispositivo_id = reservada[0]
                if conexion.execute(SQL_LIBERAR_DISPOSITIVO, [dispositivo_id]).fetchone() is None:
                    raise CredencialesNoValidas
            else:
                token_nuevo, crudo_nuevo = cripto.generar_token()
                dispositivo_id = conexion.execute(SQL_NUEVO_DISPOSITIVO, [
                    empresa_id, usuario_id, cripto.huella_token(cripto.ETIQUETA_DISPOSITIVO, crudo_nuevo)]).fetchone()[0]
            acceso = _nueva_sesion(conexion, claves, empresa_id, identificador, usuario_id, dispositivo_id,
                                   token_nuevo)
            conexion.execute(SQL_AUDITAR, [empresa_id, _actor(usuario_id), ACCION_ACCESO, usuario_id])
    except CredencialesNoValidas:
        _registrar_login_fallido(resuelta, reservada, camino)
        raise
    return acceso


def autenticar(pool, claves, token):
    """Sesión de un JWT de acceso, o SesionNoValida. Primero la firma y los
    claims (app/tokens.py), sin tocar la base de datos; después una sola
    lectura (SQL_AUTENTICAR), en una transacción de solo lectura."""
    try:
        portador = tokens.verificar(claves.firma_tokens, token)
    except tokens.TokenNoValido:
        raise SesionNoValida from None
    # El identificador se resuelve en cada petición, como antes: una empresa
    # desactivada deja de resolverse y sus JWT dejan de valer al momento.
    empresa_id = resolver_empresa(pool, portador.identificador)
    if empresa_id is None:
        raise SesionNoValida
    with bd.transaccion_empresa(pool, empresa_id, solo_lectura=True) as conexion:
        fila = conexion.execute(SQL_AUTENTICAR, {"sesion": portador.sesion_id,
                                                 "usuario": portador.usuario_id}).fetchone()
    if fila is None:
        raise SesionNoValida
    dispositivo_id, rol, email, nombre = fila
    return Sesion(empresa_id=empresa_id, identificador=portador.identificador, sesion_id=portador.sesion_id,
                  usuario_id=portador.usuario_id, dispositivo_id=dispositivo_id, rol=rol, email=email,
                  nombre_empresa=nombre)


def renovar(pool, claves, token_renovacion):
    """Tokens nuevos a cambio de un token de renovación vigente, o
    SesionNoValida. Si el token ya se había usado, revoca su sesión antes
    de rechazarlo (RFC 9700, 4.14.2)."""
    leido = leer_compuesto(token_renovacion)
    if leido is None:
        raise SesionNoValida
    identificador, crudo = leido
    empresa_id = resolver_empresa(pool, identificador)
    if empresa_id is None:
        raise SesionNoValida
    usada = cripto.huella_token(cripto.ETIQUETA_RENOVACION, crudo)
    nuevo, crudo_nuevo = cripto.generar_token()
    with bd.transaccion_empresa(pool, empresa_id) as conexion:
        fila = conexion.execute(SQL_RENOVAR, {
            "nueva": cripto.huella_token(cripto.ETIQUETA_RENOVACION, crudo_nuevo), "usada": usada,
            "inactividad": INACTIVIDAD_SESION_MINUTOS, "tope": TOPE_RENOVACIONES}).fetchone()
        # La revocación por reutilización se confirma con esta transacción:
        # SesionNoValida se lanza después, fuera del with, para no deshacerla.
        revocada = None if fila else conexion.execute(SQL_REUTILIZACION, [usada]).fetchone()
    if revocada is not None:
        registro.warning("EVENTO reutilizacion_renovacion: empresa=%s usuario=%s sesion=%s",
                         empresa_id, revocada[1], revocada[0])
    if fila is None:
        raise SesionNoValida
    sesion_id, usuario_id = fila
    return Acceso(token_acceso=tokens.emitir(claves.firma_tokens, identificador, usuario_id, sesion_id),
                  token_renovacion=token_compuesto(identificador, nuevo))


def cerrar_sesion(pool, sesion):
    with bd.transaccion_empresa(pool, sesion.empresa_id) as conexion:
        conexion.execute(SQL_CERRAR_SESION, [sesion.sesion_id])


def cambiar_contrasena(pool, claves, sesion, actual, nueva, codigo, instante=None):
    """Cambia la contraseña de la cuenta de la sesión. Pide la actual y un
    código TOTP; los fallos cuentan en el dispositivo de la sesión. Revoca
    TODAS las sesiones de la cuenta, también la actual, y los demás
    dispositivos, y devuelve tokens de una sesión nueva en el mismo
    dispositivo: cambiar la contraseña es reautenticarse, y una
    reautenticación termina el token anterior y emite otro (OWASP ASVS
    5.0.0, 7.2.4)."""
    instante = time.time() if instante is None else instante
    # La política va antes de reservar: un error al escribir la nueva no
    # gasta un intento.
    nueva = validar_contrasena(nueva, sesion.email, sesion.nombre_empresa)
    with bd.transaccion_empresa(pool, sesion.empresa_id) as conexion:
        conexion.execute(SQL_RESERVA_ASINCRONA)
        reservada = conexion.execute(SQL_RESERVAR_DISPOSITIVO_SESION,
                                     {**PARAMETROS_BLOQUEO, "dispositivo": sesion.dispositivo_id}).fetchone()
        envuelta = conexion.execute(SQL_CLAVE_VERSION, [reservada[5] if reservada else 0]).fetchone()
    paso = _comprobar_factores(claves, sesion.empresa_id, reservada, envuelta, actual, codigo, instante)
    if paso is None:
        _avisar_fallo(sesion.empresa_id, reservada, "dispositivo")
        raise CredencialesNoValidas
    with _hueco_hash():
        hash_nuevo = _hasher.hash(nueva)
    with bd.transaccion_empresa(pool, sesion.empresa_id) as conexion:
        cambiada = conexion.execute(SQL_CAMBIAR_CONTRASENA, {
            "nuevo": hash_nuevo, "paso": paso, "usuario": sesion.usuario_id, "hash": reservada[3]}).fetchone()
        if cambiada is None:
            raise CredencialesNoValidas
        conexion.execute(SQL_LIBERAR_DISPOSITIVO, [sesion.dispositivo_id])
        conexion.execute(SQL_REVOCAR_DISPOSITIVOS, [sesion.usuario_id, sesion.dispositivo_id])
        conexion.execute(SQL_REVOCAR_SESIONES, [sesion.usuario_id, uuid.UUID(int=0)])
        acceso = _nueva_sesion(conexion, claves, sesion.empresa_id, sesion.identificador, sesion.usuario_id,
                               sesion.dispositivo_id)
        conexion.execute(SQL_AUDITAR, [sesion.empresa_id, _actor(sesion.usuario_id), ACCION_CAMBIO_CONTRASENA,
                                       sesion.usuario_id])
    return acceso


# ---------------------------------------------------------------------------
# Invitación y activación
# ---------------------------------------------------------------------------

def empresa_de_token(pool, token, etiqueta):
    """(empresa, huella) de un token compuesto con la etiqueta de su tipo, o
    None si está mal formado o su empresa no está activa."""
    leido = leer_compuesto(token)
    if leido is None:
        return None
    identificador, crudo = leido
    empresa_id = resolver_empresa(pool, identificador)
    if empresa_id is None:
        return None
    return empresa_id, cripto.huella_token(etiqueta, crudo)


def _empresa_de_invitacion(pool, token):
    resultado = empresa_de_token(pool, token, cripto.ETIQUETA_INVITACION)
    if resultado is None:
        raise InvitacionNoValida
    return resultado


def activar(pool, claves, token, contrasena):
    """Primer paso: fija la contraseña y el secreto TOTP pendientes de la
    invitación y devuelve el secreto para la aplicación de autenticación. La
    cuenta no cambia hasta confirmar. Repetirlo sustituye lo pendiente."""
    empresa_id, huella = _empresa_de_invitacion(pool, token)
    with bd.transaccion_empresa(pool, empresa_id) as conexion:
        fila = conexion.execute(SQL_INVITACION_ABIERTA, [huella]).fetchone()
        clave = conexion.execute(SQL_CLAVE_ACTUAL).fetchone()
    if fila is None:
        raise InvitacionNoValida
    if clave is None:
        raise EmpresaSinClave
    invitacion_id, usuario_id, email, nombre = fila
    version, envuelta = clave
    normal = validar_contrasena(contrasena, email, nombre)
    with _hueco_hash():
        hash_nuevo = _hasher.hash(normal)
    secreto = cripto.generar_secreto_totp()
    clave_empresa = cripto.desenvolver_clave(claves.maestra, bytes(envuelta), empresa_id, version)
    cifrado = cripto.cifrar(clave_empresa, secreto, cripto.aad_totp(empresa_id, usuario_id))
    with bd.transaccion_empresa(pool, empresa_id) as conexion:
        if conexion.execute(SQL_GUARDAR_PENDIENTE, [hash_nuevo, cifrado, version, invitacion_id]).fetchone() is None:
            raise InvitacionNoValida
    return ActivacionPendiente(secreto_totp=cripto.secreto_totp_texto(secreto),
                               uri_totp=cripto.uri_totp(secreto, email))


def confirmar_activacion(pool, claves, token, codigo, instante=None):
    """Segundo paso: con un código válido, las credenciales pendientes pasan a
    la cuenta, se revocan las sesiones y dispositivos anteriores y se emite
    el primer dispositivo de confianza. Devuelve su token."""
    instante = time.time() if instante is None else instante
    empresa_id, huella = _empresa_de_invitacion(pool, token)
    with bd.transaccion_empresa(pool, empresa_id) as conexion:
        fila = conexion.execute(SQL_INVITACION_PENDIENTE, [huella]).fetchone()
    if fila is None:
        raise InvitacionNoValida
    invitacion_id, usuario_id, hash_pendiente, cifrado, version, envuelta = fila
    secreto = _descifrar_secreto(claves, empresa_id, usuario_id, envuelta, version, cifrado)
    paso = cripto.verificar_totp(secreto, codigo, instante)
    if paso is None:
        raise CodigoNoValido
    token_dispositivo, crudo = cripto.generar_token()
    with bd.transaccion_empresa(pool, empresa_id) as conexion:
        conexion.execute(SQL_BLOQUEAR_CUENTA, [usuario_id])
        if conexion.execute(SQL_CERRAR_INVITACION, [invitacion_id]).fetchone() is None:
            raise InvitacionNoValida
        conexion.execute(SQL_ACTIVAR_CUENTA, {"hash": hash_pendiente, "secreto": cifrado, "version": version,
                                              "paso": paso, "usuario": usuario_id})
        # id <> uuid nulo: se revocan todos.
        conexion.execute(SQL_REVOCAR_DISPOSITIVOS, [usuario_id, uuid.UUID(int=0)])
        conexion.execute(SQL_REVOCAR_SESIONES, [usuario_id, uuid.UUID(int=0)])
        conexion.execute(SQL_NUEVO_DISPOSITIVO, [empresa_id, usuario_id,
                                                 cripto.huella_token(cripto.ETIQUETA_DISPOSITIVO, crudo)])
        conexion.execute(SQL_AUDITAR, [empresa_id, _actor(usuario_id), ACCION_ACTIVACION, usuario_id])
    return token_dispositivo


def _emitir_invitacion(conexion, empresa_id, identificador, usuario_id):
    """Cierra las invitaciones abiertas de la cuenta y crea una nueva."""
    token, crudo = cripto.generar_token()
    conexion.execute(SQL_CERRAR_INVITACIONES, [usuario_id])
    conexion.execute(SQL_NUEVA_INVITACION, [empresa_id, usuario_id,
                                            cripto.huella_token(cripto.ETIQUETA_INVITACION, crudo)])
    return token_compuesto(identificador, token)


# ---------------------------------------------------------------------------
# Administración de cuentas (solo admin)
# ---------------------------------------------------------------------------

def exigir_admin(sesion):
    if sesion.rol != "admin":
        raise Prohibido


def listar_usuarios(pool, sesion):
    exigir_admin(sesion)
    with bd.transaccion_empresa(pool, sesion.empresa_id, solo_lectura=True) as conexion:
        filas = conexion.execute(SQL_LISTAR_USUARIOS, {"tope_sin_confianza": TOPE_SIN_CONFIANZA}).fetchall()
    return [Usuario(usuario_id=f[0], email=f[1], rol=f[2], activo=f[3], activado=f[4],
                    camino_sin_confianza_cerrado=f[5], en_espera=f[6], invitacion_pendiente=f[7]) for f in filas]


def invitacion_pendiente(pool, sesion):
    """Si la cuenta de la sesión tiene una invitación abierta. Es el aviso de
    una reinvitación (NIST SP 800-63B-4, 4.2.3): quien la recibe sin haberla
    pedido sigue entrando hasta que alguien la confirme, y puede pedir a un
    admin que la anule."""
    with bd.transaccion_empresa(pool, sesion.empresa_id, solo_lectura=True) as conexion:
        return conexion.execute(SQL_INVITACION_PENDIENTE_DE, [sesion.usuario_id]).fetchone()[0]


def crear_cuenta_invitada(conexion, sesion, email, rol, accion):
    """Crea una cuenta sin credenciales y su invitación en la transacción
    abierta de un admin, y la audita con accion. El único camino por el que
    nace una cuenta desde la API: la invitación manual (invitar) y la
    aprobación de una solicitud de registro (app/solicitudes.py). Los errores de
    la base de datos se traducen al salir de la transacción (_traducir_alta)."""
    exigir_admin(sesion)
    if rol not in ROLES:
        raise ValueError("rol desconocido")
    usuario_id = conexion.execute(SQL_NUEVO_USUARIO, [sesion.empresa_id, email.lower(), rol]).fetchone()[0]
    token = _emitir_invitacion(conexion, sesion.empresa_id, sesion.identificador, usuario_id)
    conexion.execute(SQL_AUDITAR, [sesion.empresa_id, _actor(sesion.usuario_id), accion, usuario_id])
    return Invitacion(usuario_id=usuario_id, token_invitacion=token)


@contextmanager
def traducir_alta():
    """Email repetido -> EmailDuplicado; email que no cumple el CHECK ->
    ValueError. Envuelve la transacción entera: el error de PostgreSQL llega
    al ejecutar la sentencia, y la transacción ya está abortada."""
    try:
        yield
    except psycopg.Error as error:
        if error.sqlstate == SQLSTATE_DUPLICADO:
            raise EmailDuplicado from None
        if error.sqlstate == SQLSTATE_CHECK:
            raise ValueError("email no valido") from None
        raise


def invitar(pool, sesion, email, rol):
    """Crea una cuenta sin credenciales y su invitación."""
    exigir_admin(sesion)
    with traducir_alta(), bd.transaccion_empresa(pool, sesion.empresa_id) as conexion:
        return crear_cuenta_invitada(conexion, sesion, email, rol, ACCION_INVITACION)


def reinvitar(pool, sesion, usuario_id):
    """Nueva invitación para una cuenta (recuperar el acceso, cerrar el camino
    sin confianza o reactivarla tras una baja). La anterior se cierra. La
    cuenta sigue funcionando con sus credenciales hasta que se confirme."""
    exigir_admin(sesion)
    with bd.transaccion_empresa(pool, sesion.empresa_id) as conexion:
        if conexion.execute(SQL_USUARIO, [usuario_id]).fetchone() is None:
            raise NoEncontrado
        token = _emitir_invitacion(conexion, sesion.empresa_id, sesion.identificador, usuario_id)
        conexion.execute(SQL_AUDITAR, [sesion.empresa_id, _actor(sesion.usuario_id), ACCION_INVITACION, usuario_id])
    return Invitacion(usuario_id=usuario_id, token_invitacion=token)


def anular_invitacion(pool, sesion, usuario_id):
    """Cierra la invitación abierta de una cuenta: la respuesta a una
    reinvitación que nadie pidió. La cuenta queda como estaba (con sus
    credenciales, o sin ellas si nunca se activó). 404 si la cuenta no existe
    o no tiene ninguna invitación abierta."""
    exigir_admin(sesion)
    with bd.transaccion_empresa(pool, sesion.empresa_id) as conexion:
        if conexion.execute(SQL_USUARIO, [usuario_id]).fetchone() is None:
            raise NoEncontrado
        if conexion.execute(SQL_ANULAR_INVITACION, [usuario_id]).fetchone() is None:
            raise NoEncontrado
        conexion.execute(SQL_AUDITAR, [sesion.empresa_id, _actor(sesion.usuario_id), ACCION_ANULACION_INVITACION,
                                       usuario_id])


def dar_de_baja(pool, sesion, usuario_id):
    """Desactiva una cuenta y revoca sus sesiones, dispositivos e
    invitaciones. Nunca deja a la empresa sin un admin activado."""
    exigir_admin(sesion)
    with bd.transaccion_empresa(pool, sesion.empresa_id) as conexion:
        admins = conexion.execute(SQL_BLOQUEAR_ADMINS).fetchall()
        fila = conexion.execute(SQL_USUARIO, [usuario_id]).fetchone()
        if fila is None:
            raise NoEncontrado
        _, rol, activo, activado = fila
        otros = [a for a in admins if a[0] != usuario_id and a[1]]
        if rol == "admin" and activo and activado and not otros:
            raise UltimoAdmin
        conexion.execute(SQL_DAR_DE_BAJA, [usuario_id])
        conexion.execute(SQL_CERRAR_INVITACIONES, [usuario_id])
        conexion.execute(SQL_REVOCAR_DISPOSITIVOS, [usuario_id, uuid.UUID(int=0)])
        conexion.execute(SQL_REVOCAR_SESIONES, [usuario_id, uuid.UUID(int=0)])
        conexion.execute(SQL_AUDITAR, [sesion.empresa_id, _actor(sesion.usuario_id), ACCION_BAJA, usuario_id])


# ---------------------------------------------------------------------------
# Primer admin de una empresa (servicio gestion, app/gestion.py)
# ---------------------------------------------------------------------------

def alta_admin_plataforma(conexion, empresa_id, identificador, email):
    """Invitación del primer admin de una empresa, con el rol aplicacion y el
    contexto de la empresa ya fijado (transacción abierta por gestion).

    Solo si la empresa no tiene ningún admin activado: después, las cuentas
    las gestionan sus admins por la API. Deja una fila en la auditoría de la
    empresa (actor plataforma), así que la empresa ve cualquier invitación
    emitida desde la plataforma. Límite asumido: quien opera el servicio
    gestion tiene ya todos los secretos (docs/threat-model.md, 8); esto no
    impide que abuse de ellos, lo hace visible.
    """
    email = email.lower()
    if conexion.execute(SQL_EMPRESA_VISIBLE).fetchone()[0] != 1:
        raise AltaAdminRechazada("la empresa no existe")
    if conexion.execute(SQL_CLAVE_ACTUAL).fetchone() is None:
        raise AltaAdminRechazada("la empresa no tiene clave de cifrado (nueva-clave)")
    # Se bloquean los admins activos antes de mirar: dos ejecuciones
    # simultáneas no ven a la vez "ningún admin".
    conexion.execute(SQL_BLOQUEAR_ADMINS)
    if conexion.execute(SQL_ADMIN_ACTIVO).fetchone()[0] != 0:
        raise AltaAdminRechazada("la empresa ya tiene un admin activo: las cuentas las gestionan sus admins")
    existente = conexion.execute(SQL_USUARIO_POR_EMAIL, [email]).fetchone()
    if existente is None:
        usuario_id = conexion.execute(SQL_NUEVO_USUARIO, [empresa_id, email, "admin"]).fetchone()[0]
    elif existente[1] == "admin" and not existente[2]:
        usuario_id = existente[0]
    else:
        raise AltaAdminRechazada("ya existe una cuenta con ese email que no es un admin pendiente de activar")
    token = _emitir_invitacion(conexion, empresa_id, identificador, usuario_id)
    conexion.execute(SQL_AUDITAR, [empresa_id, ACTOR_PLATAFORMA, ACCION_INVITACION_PLATAFORMA, usuario_id])
    return Invitacion(usuario_id=usuario_id, token_invitacion=token)


def reinvitar_admin_plataforma(conexion, empresa_id, identificador, email):
    """Recuperación de emergencia ("break glass", como las cuentas de
    emergencia de Microsoft Entra) de un admin que ya estuvo activado: el
    caso en que nadie de la empresa puede reinvitarlo, porque es su único
    admin, o los demás tampoco pueden entrar. Mismo rol, contexto y
    transacción que alta_admin_plataforma.

    A diferencia de la reinvitación de la API, aquí la cuenta se desactiva y
    se revocan sus sesiones y dispositivos EN EL ACTO. El motivo: esta orden
    solo se usa cuando el titular ya no puede autenticarse, así que lo que
    siga autenticado en esa cuenta no es él (una cuenta comprometida); si
    siguiera dentro, podría anular la invitación (anular_invitacion) y la
    recuperación nunca llegaría. Al titular no le cuesta nada: no podía
    entrar. Las credenciales nuevas las elige él al activar, y la activación
    vuelve a dejar la cuenta activa (confirmar_activacion).

    Aquí se salta a propósito la regla de dar_de_baja que impide dejar a la
    empresa sin admins: la cuenta queda pendiente de su titular, no perdida.
    La empresa ve la fila de auditoría (actor plataforma) y el estado de la
    cuenta en la lista (activo false, invitación pendiente). Quien opere
    gestion debe verificar la petición fuera de banda antes de ejecutarla
    (docs/threat-model.md, 6.3); el límite es el de alta_admin_plataforma:
    quien tiene todos los secretos no queda impedido, queda a la vista.
    """
    email = email.lower()
    if conexion.execute(SQL_EMPRESA_VISIBLE).fetchone()[0] != 1:
        raise AltaAdminRechazada("la empresa no existe")
    if conexion.execute(SQL_CLAVE_ACTUAL).fetchone() is None:
        raise AltaAdminRechazada("la empresa no tiene clave de cifrado (nueva-clave)")
    # Mismo orden de bloqueos que alta_admin_plataforma y dar_de_baja: las
    # tres no se interbloquean entre sí.
    conexion.execute(SQL_BLOQUEAR_ADMINS)
    existente = conexion.execute(SQL_USUARIO_POR_EMAIL, [email]).fetchone()
    # Solo un admin que ya se activó alguna vez: un admin pendiente o una
    # empresa sin admins es el caso de alta-admin, y un instructor lo recupera
    # su admin por la API. Así las dos órdenes de plataforma no se solapan.
    if existente is None or existente[1] != "admin" or not existente[2]:
        raise AltaAdminRechazada("no hay ningun admin activado con ese email en la empresa "
                                 "(primer admin: alta-admin; instructores: los reinvita su admin)")
    usuario_id = existente[0]
    # Orden de bloqueos: cuenta, invitación, dispositivos, sesiones, auditoría.
    conexion.execute(SQL_DAR_DE_BAJA, [usuario_id])
    token = _emitir_invitacion(conexion, empresa_id, identificador, usuario_id)
    conexion.execute(SQL_REVOCAR_DISPOSITIVOS, [usuario_id, uuid.UUID(int=0)])
    conexion.execute(SQL_REVOCAR_SESIONES, [usuario_id, uuid.UUID(int=0)])
    conexion.execute(SQL_AUDITAR, [empresa_id, ACTOR_PLATAFORMA, ACCION_REINVITACION_PLATAFORMA, usuario_id])
    return Invitacion(usuario_id=usuario_id, token_invitacion=token)
