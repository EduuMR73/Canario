"""Solicitudes de registro del personal, "primero el email"
(docs/threat-model.md, 6.3).

El módulo no se llama registro porque en todo el proyecto "registro" es
el logger.

Flujo:
1. Quien quiere una cuenta da la empresa y su email, nada más
   (solicitar). No elige contraseña ni rol.
2. Le llega un enlace; al abrirlo, la SPA del personal manda el token por POST
   (verificar). Así demuestra que el email es suyo.
3. Un admin de la empresa ve solo las solicitudes verificadas (listar) y
   aprueba una con un rol (aprobar) o la rechaza (rechazar).
4. La aprobación crea la cuenta por el camino de siempre
   (personal.crear_cuenta_invitada) y la invitación va SOLO al email ya
   verificado, nunca al admin: el admin decide quién entra, no conoce el
   enlace con el que se fija la contraseña. El titular la activa como
   cualquier invitación (contraseña, TOTP y confirmación).

Por qué así (Sudhodanan y Paverd, "Pre-hijacked accounts", 2022): la causa
raíz del pre-hijacking es crear una cuenta sin verificar la propiedad del
identificador (6.2.1). Aquí no existe ninguna cuenta, ni credencial, hasta
que el dueño del email lo ha demostrado y un admin lo ha aprobado; el
atacante nunca elige la contraseña de nadie, y la invitación caduca y es de
un solo uso como las demás. Sin Argon2 en un camino sin autenticar: nada que
calcular para agotar la API.

Enumeración (OWASP Authentication Cheat Sheet, "Authentication and Error
Messages"; OWASP WSTG-IDNT-04): POST /registro responde siempre el mismo 202
con el mismo cuerpo, exista o no la empresa, tenga o no cuenta el email. Lo
que cambia es el CORREO, que solo lee el dueño del buzón:
* email nuevo: enlace de verificación;
* email con cuenta: aviso al titular (alguien lo ha intentado; si no puede
  entrar, que pida a un admin que le reinvite);
* email con una solicitud ya verificada: aviso de que sigue pendiente (no se
  toca: solo su dueño pudo verificarla);
* empresa inexistente o inactiva: nada.
Y el tiempo es el mismo por construcción, como en el login
(app/personal.py): todos los caminos ejecutan las mismas sentencias (sin
empresa, con un contexto aleatorio y cero filas), la transacción confirma sin
esperar al disco (SQL_RESERVA_ASINCRONA: si no, escribir o no una fila se
notaría en el tiempo) y el correo sale después de responder
(app/correo.py).

Una abierta por email y empresa (índice único parcial). Una solicitud sin
verificar se sustituye por la nueva: el enlace anterior deja de valer, y el
nuevo le llega igualmente al dueño del buzón, así que repetir la solicitud de
otro solo le obliga a usar el último correo. Ese abuso, y el de inundar un
buzón, lo acota la regla "destinatario" del limitador (app/limitador.py).

Límites asumidos:
* El rechazo no avisa a quien lo pidió: el admin decide sin explicaciones,
  y un correo de rechazo no aporta seguridad.
* Sin correo de salida en producción (app/correo.py) el registro no entrega
  nada: punto abierto del modelo de amenazas.
"""
import os
import uuid
from dataclasses import dataclass

import psycopg

from app import bd, correo, cripto, personal, rutas_web

VARIABLE_ORIGEN = "CANARIO_ORIGEN_PERSONAL"
# Rutas de la SPA del personal a las que apuntan los enlaces. El token va en
# el fragmento (app/correo.py, cabecera).
RUTA_VERIFICACION = "/registro/verificacion"
RUTA_ACTIVACION = "/activacion"

ACCION_APROBACION = "aprobacion_registro"
ACCION_RECHAZO = "rechazo_registro"

# Las solicitudes pendientes que ve un admin de una vez. Cada una exige un
# buzón propio y pasa por los dos límites del registro; el tope solo acota el
# trabajo de una petición. Si hay más, la respuesta lo dice (hay_mas).
MAXIMO_LISTADO = 200

SQL_NOMBRE_EMPRESA = "select nombre from canal.empresa"
SQL_CUENTA_EXISTE = "select exists (select 1 from canal.usuario_personal where email = %s)"
SQL_PENDIENTE_VERIFICADA = """
    select exists (select 1 from canal.solicitud_registro
                    where email = %s and not cerrada and verificada and caduca > now())
"""
# Lo que se sustituye: la abierta sin verificar y la que ya caducó (también
# la verificada que el admin dejó caducar), para que el índice de una
# abierta por email deje sitio a la nueva.
SQL_CERRAR_SUSTITUIBLES = """
    update canal.solicitud_registro set cerrada = true
     where email = %s and not cerrada and (not verificada or caduca <= now())
"""
# Insert condicional: con crear falso la sentencia se ejecuta igual y no
# inserta nada (ver la cabecera, tiempo uniforme).
SQL_NUEVA_SOLICITUD = """
    insert into canal.solicitud_registro (empresa_id, email, token_sha256)
    select %(empresa)s, %(email)s, %(huella)s where %(crear)s
    returning id
"""
SQL_VERIFICAR = """
    update canal.solicitud_registro set verificada = true
     where token_sha256 = %s and not cerrada and not verificada and caduca > now()
    returning id
"""
SQL_LISTAR = """
    select id, email from canal.solicitud_registro
     where verificada and not cerrada and caduca > now()
     order by email, id
     limit %s
"""
# Orden de bloqueos al aprobar: la solicitud y después lo de
# personal.crear_cuenta_invitada (cuenta, invitación, auditoría).
SQL_BLOQUEAR_SOLICITUD = """
    select email from canal.solicitud_registro
     where id = %s and verificada and not cerrada and caduca > now()
       for update
"""
SQL_CERRAR = "update canal.solicitud_registro set cerrada = true where id = %s"
SQL_AUDITAR = (
    "insert into canal.registro_auditoria (empresa_id, actor, accion, objeto_id) values (%s, %s, %s, %s)"
)


class SolicitudNoValida(Exception):
    """Token de verificación desconocido, usado, sustituido o caducado: 401."""


@dataclass(frozen=True)
class Solicitud:
    solicitud_id: uuid.UUID
    email: str


@dataclass(frozen=True)
class Listado:
    solicitudes: list
    hay_mas: bool


@dataclass(frozen=True)
class Aprobacion:
    usuario_id: uuid.UUID
    correo: correo.Correo


# ---------------------------------------------------------------------------
# Configuración
# ---------------------------------------------------------------------------

def cargar_origen(entorno=None):
    """Origen de la SPA del personal, al que apuntan los enlaces de los
    correos. OBLIGATORIO, sin valor por defecto: un enlace con un secreto que
    sale hacia el buzón de un tercero no puede apuntar a un sitio que nadie
    eligió. Sin él, o mal formado, la API no arranca (rutas_web.analizar_origen,
    las mismas reglas que CANARIO_ORIGEN_WEB)."""
    entorno = os.environ if entorno is None else entorno
    texto = entorno.get(VARIABLE_ORIGEN)
    if texto is None:
        raise rutas_web.ErrorConfiguracion(f"{VARIABLE_ORIGEN}: obligatoria (origen https de la SPA del personal)")
    return rutas_web.analizar_origen(texto, VARIABLE_ORIGEN)


# ---------------------------------------------------------------------------
# Correos
# ---------------------------------------------------------------------------

def _enlace(origen, ruta, token):
    return f"{origen}{ruta}#{token}"


def _correo_verificacion(email, nombre, enlace):
    return correo.Correo(
        tipo="verificacion", destinatario=email, asunto="Confirme su email para registrarse en Canario",
        cuerpo=(f"Ha pedido una cuenta del personal de {nombre} en Canario.\n\n"
                "Para confirmar que este email es suyo, abra este enlace en las próximas 24 horas:\n\n"
                f"{enlace}\n\n"
                f"Después, un administrador de {nombre} revisará la solicitud y le asignará un rol.\n\n"
                "Si no lo ha pedido usted, ignore este correo: sin confirmar, la solicitud caduca sola."))


def _correo_aviso_cuenta(email, nombre):
    return correo.Correo(
        tipo="aviso_cuenta", destinatario=email, asunto="Intento de registro con su email en Canario",
        cuerpo=(f"Alguien ha pedido registrarse en Canario, en {nombre}, con este email, que ya tiene una "
                "cuenta. No se ha cambiado nada.\n\n"
                f"Si no puede entrar, pida a un administrador de {nombre} que le envíe una invitación nueva.\n\n"
                "Si no ha sido usted, no tiene que hacer nada."))


def _correo_aviso_pendiente(email, nombre):
    return correo.Correo(
        tipo="aviso_pendiente", destinatario=email, asunto="Su solicitud de registro en Canario sigue pendiente",
        cuerpo=(f"Alguien ha pedido registrarse en Canario, en {nombre}, con este email. Ya tiene una "
                f"solicitud confirmada, pendiente de que un administrador de {nombre} la apruebe: no hace "
                "falta repetirla.\n\n"
                "Si no ha sido usted, no tiene que hacer nada."))


def _correo_invitacion(email, nombre, enlace):
    return correo.Correo(
        tipo="invitacion", destinatario=email, asunto="Active su cuenta del personal en Canario",
        cuerpo=(f"Un administrador de {nombre} ha aprobado su solicitud de registro en Canario.\n\n"
                "Para activar la cuenta, abra este enlace en las próximas 72 horas, elija su contraseña y "
                "configure el segundo factor:\n\n"
                f"{enlace}\n\n"
                "El enlace sirve una sola vez."))


# ---------------------------------------------------------------------------
# Camino sin autenticar
# ---------------------------------------------------------------------------

def solicitar(pool, origen, identificador, email):
    """Registra una solicitud y devuelve el correo que hay que enviar, o None
    si no hay ninguno. email llega validado y en minúsculas. Para quien
    llama, el resultado nunca cambia la respuesta (ver la cabecera)."""
    # Sin empresa, un contexto aleatorio: las mismas sentencias con cero
    # filas (como personal.iniciar_sesion).
    resuelta = personal.resolver_empresa(pool, identificador)
    empresa_id = resuelta or uuid.uuid4()
    token, crudo = cripto.generar_token()
    huella = cripto.huella_token(cripto.ETIQUETA_REGISTRO, crudo)
    try:
        with bd.transaccion_empresa(pool, empresa_id) as conexion:
            conexion.execute(personal.SQL_RESERVA_ASINCRONA)
            fila = conexion.execute(SQL_NOMBRE_EMPRESA).fetchone()
            cuenta = conexion.execute(SQL_CUENTA_EXISTE, [email]).fetchone()[0]
            pendiente = conexion.execute(SQL_PENDIENTE_VERIFICADA, [email]).fetchone()[0]
            conexion.execute(SQL_CERRAR_SUSTITUIBLES, [email])
            creada = conexion.execute(SQL_NUEVA_SOLICITUD, {
                "empresa": empresa_id, "email": email, "huella": huella,
                "crear": resuelta is not None and not cuenta and not pendiente}).fetchone()
    except psycopg.Error as error:
        # Dos solicitudes simultáneas del mismo email: la segunda choca con
        # el índice de una abierta. La primera ya envía su correo.
        if error.sqlstate == personal.SQLSTATE_DUPLICADO:
            return None
        raise
    if resuelta is None or fila is None:
        return None
    nombre = fila[0]
    if cuenta:
        return _correo_aviso_cuenta(email, nombre)
    if pendiente:
        return _correo_aviso_pendiente(email, nombre)
    if creada is None:
        return None
    return _correo_verificacion(email, nombre, _enlace(origen, RUTA_VERIFICACION,
                                                       personal.token_compuesto(identificador, token)))


def verificar(pool, token):
    """Marca como verificada la solicitud del token, o SolicitudNoValida."""
    resultado = personal.empresa_de_token(pool, token, cripto.ETIQUETA_REGISTRO)
    if resultado is None:
        raise SolicitudNoValida
    empresa_id, huella = resultado
    with bd.transaccion_empresa(pool, empresa_id) as conexion:
        if conexion.execute(SQL_VERIFICAR, [huella]).fetchone() is None:
            raise SolicitudNoValida


# ---------------------------------------------------------------------------
# Administración (solo admin)
# ---------------------------------------------------------------------------

def listar(pool, sesion):
    """Solicitudes verificadas, abiertas y sin caducar. Las no verificadas no
    se ven: no se sabe de quién son."""
    personal.exigir_admin(sesion)
    with bd.transaccion_empresa(pool, sesion.empresa_id, solo_lectura=True) as conexion:
        filas = conexion.execute(SQL_LISTAR, [MAXIMO_LISTADO + 1]).fetchall()
    return Listado(solicitudes=[Solicitud(solicitud_id=f[0], email=f[1]) for f in filas[:MAXIMO_LISTADO]],
                   hay_mas=len(filas) > MAXIMO_LISTADO)


def aprobar(pool, sesion, origen, solicitud_id, rol):
    """Crea la cuenta de una solicitud verificada con el rol que elige el
    admin y devuelve el correo de invitación para su email. NoEncontrado si
    la solicitud no existe, es de otra empresa (RLS), no está verificada o ya
    se cerró; EmailDuplicado si el email ya tiene cuenta."""
    personal.exigir_admin(sesion)
    if rol not in personal.ROLES:
        raise ValueError("rol desconocido")
    with personal.traducir_alta(), bd.transaccion_empresa(pool, sesion.empresa_id) as conexion:
        fila = conexion.execute(SQL_BLOQUEAR_SOLICITUD, [solicitud_id]).fetchone()
        if fila is None:
            raise personal.NoEncontrado
        email = fila[0]
        invitacion = personal.crear_cuenta_invitada(conexion, sesion, email, rol, ACCION_APROBACION)
        conexion.execute(SQL_CERRAR, [solicitud_id])
    enlace = _enlace(origen, RUTA_ACTIVACION, invitacion.token_invitacion)
    return Aprobacion(usuario_id=invitacion.usuario_id,
                      correo=_correo_invitacion(email, sesion.nombre_empresa, enlace))


def rechazar(pool, sesion, solicitud_id):
    """Cierra una solicitud verificada sin crear cuenta. NoEncontrado como en
    aprobar."""
    personal.exigir_admin(sesion)
    with bd.transaccion_empresa(pool, sesion.empresa_id) as conexion:
        if conexion.execute(SQL_BLOQUEAR_SOLICITUD, [solicitud_id]).fetchone() is None:
            raise personal.NoEncontrado
        conexion.execute(SQL_CERRAR, [solicitud_id])
        conexion.execute(SQL_AUDITAR, [sesion.empresa_id, f"personal:{sesion.usuario_id}", ACCION_RECHAZO,
                                       solicitud_id])
