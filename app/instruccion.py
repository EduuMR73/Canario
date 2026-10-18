"""Instrucción: el trabajo del personal sobre las denuncias de su empresa
(docs/threat-model.md, 6.15).

Lógica sin HTTP: las rutas viven en app/rutas_personal.py, que es el único
módulo que sabe cómo viajan los tokens. Las excepciones del personal
(SesionNoValida, Prohibido, NoEncontrado) son las de app/personal.py, para
que la misma situación dé siempre la misma respuesta.

Quién ve qué (Ley 2/2023, arts. 32.1 y 8.5):
* El contenido de una denuncia (categoría, texto y mensajes) solo lo lee
  quien la tiene asignada, sea instructor o admin. Gestionar cuentas no da
  acceso al contenido: el art. 32.1 limita el acceso al Responsable del
  Sistema y a quien lo gestione directamente, y el 8.5 pide evitar el
  conflicto de interés (la denuncia puede ser sobre un admin).
* Un admin ve el listado de todas las denuncias (fecha, estado y asignación,
  sin contenido) y asigna. Para clasificar una denuncia sin asignar se la
  asigna a sí mismo y, si procede, la reasigna: cada paso queda en la
  auditoría, que admins y auditores leen por la API (listar_auditoria y
  listar_auditoria_reciente) y cuya cadena verifican aparte
  (verificar_auditoria).
* Asignar es idempotente: asignar a la cuenta que ya la tiene no escribe ni
  deja fila. Un no-op auditado sería ruido y una forma de inundar una
  auditoría que no se puede borrar.
* Un instructor solo ve sus denuncias asignadas. Una que no es suya da el
  mismo 404 que una inexistente o de otra empresa: no puede saber si existe.
* Un auditor lee la auditoría y verifica su cadena, y nada más: ni el
  listado ni ninguna acción sobre una denuncia (403 antes de tocar la base de
  datos, personal.ROLES_INSTRUCCION). Su trabajo es revisar quién hizo qué,
  no el contenido (art. 32.1.e, el delegado de protección de datos). Son dos
  barreras independientes: la puerta por rol de cada función y que nunca
  puede tener una denuncia asignada (asignar y el trigger
  canal.controlar_asignacion_denuncia), porque la asignación es la llave del
  contenido. Leer la auditoría no deja fila, como para los admins: nadie
  audita al auditor, que no puede cambiar nada (docs/threat-model.md, 8).

Auditoría por la API (listar_auditoria y listar_auditoria_reciente):
* Cada fila trae, además de los ids, el email de quien actuó (actor_email) y
  el de la cuenta sobre la que actuó (cuenta_email), resueltos aquí en la
  misma transacción de solo lectura. Sin ellos el auditor no podría
  interpretar nada: la auditoría solo guarda ids, y él no puede leer las
  cuentas (403 en /usuarios). La tabla no cambia: el hash sigue cubriendo los
  ids, y el email de una cuenta no se puede cambiar ni borrar (la API no
  tiene UPDATE sobre esa columna ni DELETE en la tabla), así que un id lleva
  siempre al mismo email.
* Dónde está la cuenta depende de la acción: en objeto_id en las acciones
  sobre cuentas (ACCIONES_CUENTA_EN_OBJETO) y en destino_id en la asignación
  (ACCIONES_CUENTA_EN_DESTINO). No se cruza cualquier uuid con las cuentas:
  redaccion_mensaje lleva en destino_id un mensaje, y rechazo_registro lleva
  en objeto_id una solicitud. Una acción de cuenta nueva que no se añada a
  esas listas sale con cuenta_email null y el id a la vista: se nota, no
  engaña.
* actor_email es null para 'plataforma' y 'sistema', que no son cuentas.
* Dos órdenes, cada uno en su ruta: desde el principio (desde, ascendente:
  lo que recorre quien revisa o exporta) y desde lo más reciente (antes,
  descendente: lo que mira primero quien vigila). Un parámetro que cambiara
  el sentido de otro dejaría combinaciones sin sentido que habría que
  rechazar. Las dos paginan por la secuencia, que no se mueve: las filas que
  llegan mientras tanto no desplazan las páginas, como haría un OFFSET.
* Así el auditor ve los emails de casi todas las cuentas de su empresa (las
  que aparecen en la auditoría). Es lo que necesita para su trabajo, y se
  acepta (docs/threat-model.md, 8).

Estados (TRANSICIONES, literal): nueva -> en_instruccion | inadmitida;
en_instruccion -> resuelta | archivada; cualquiera -> no_veraz (abajo). Los
cerrados solo pueden pasar a no_veraz. 'inadmitida'
es la comunicación a la que no se da curso (art. 32.4): sigue sujeta a la
supresión de los tres meses (db/init/04_supresion.sql). Cerrar exige un
mensaje final para el denunciante (art. 9.2.d, dar respuesta): una denuncia
cerrada no admite mensajes, y sin él nunca sabría el resultado.

No veraz (art. 32.3: si se acredita que la información no es veraz, se
suprime inmediatamente):
* Se llega desde cualquier estado, incluidos los cerrados: la falta de
  veracidad puede acreditarse después de resolver. Es terminal.
* Solo un admin con la denuncia asignada (403 para un instructor, antes de
  tocar la base de datos). Es la decisión del Responsable del Sistema que
  destruye el expediente: no la toma quien solo instruye.
* Sin mensaje (422 si lo trae): nadie lo leería. Ni el denunciante ni el
  personal vuelven a ver la denuncia.
* Para la API, una denuncia no veraz no existe: todas las consultas de aquí
  y de app/denuncias.py la excluyen (404, igual que una suprimida) y el
  trigger de mensajes la rechaza como no visible. La destrucción la hace la
  siguiente ejecución de la supresión (db/init/04_supresion.sql, art32_3):
  el borrado sigue teniendo un único camino, con su evidencia.
* Si los hechos pueden ser delito, no se declara no veraz: la excepción del
  propio art. 32.3 obliga a conservarla para el procedimiento judicial.

Redacción (art. 32.2: los datos innecesarios y los de categorías especiales
se suprimen de inmediato; art. 29: los recopilados por accidente, sin
dilación indebida). Suprime una parte del texto, no la denuncia:
* Solo un admin con la denuncia asignada, como la declaración de no veraz:
  destruye una parte de la prueba sin vuelta atrás. Vale en cualquier estado
  salvo no_veraz, también en los cerrados (un dato sobrante puede verse
  después de resolver), y sobre el texto de la denuncia o de cualquier
  mensaje, sea del denunciante o del personal. La categoría no se redacta: es
  de una lista cerrada.
* Cada tramo dice dónde empieza (en caracteres de Python, es decir, code
  points) y qué texto exacto tacha. Si en esa posición no está ese texto, no
  se escribe nada (409). La redacción es destructiva: un cliente que contara
  en otra unidad (un navegador cuenta en UTF-16, y un emoji antes del tramo
  desplazaría la máscara y dejaría ver parte del dato, como advierte el código
  de GlobaLeaks) fallaría de forma visible, nunca en silencio.
* Cada carácter tachado pasa a ser U+2588: el texto conserva su longitud y
  las posiciones del resto no se mueven entre una redacción y la siguiente.
* Se vuelve a cifrar con la versión actual de la clave de la empresa y el
  mismo AAD. La escritura la hace canal.redactar_denuncia o
  canal.redactar_mensaje (db/init/05_redaccion.sql): la API no tiene UPDATE
  sobre el contenido, y la función escribe la fila de auditoría en la misma
  sentencia y solo si el contenido sigue siendo el que se leyó.
* Idempotente: si lo pedido ya está tachado, no se escribe ni se deja fila,
  como en la asignación.
* Se descifra y se vuelve a cifrar con la denuncia bloqueada (FOR NO KEY
  UPDATE, el bloqueo del trigger de mensajes): son milisegundos, y así nadie
  cambia el contenido entre leerlo y escribirlo.

Concurrencia: la autenticación de la sesión es su propia transacción
(app/personal.py), así que cada acción vuelve a comprobar, en su transacción
y con un bloqueo, que la cuenta sigue activa. Sin eso, una baja confirmada
entre autenticar y actuar dejaría actuar a una cuenta ya dada de baja.
* La cuenta se bloquea con FOR KEY SHARE, que solo choca con FOR UPDATE: el
  que toman la baja, el cambio de contraseña y la recuperación. No choca con
  el UPDATE de los contadores del login (FOR NO KEY UPDATE): unos logins
  fallidos contra el email de quien instruye no retrasan su trabajo
  (PostgreSQL, tabla 13.3 de bloqueos de fila).
* La denuncia se bloquea con la asignación DENTRO del WHERE: solo se
  bloquean las filas que la consulta devuelve, así que quien no la tiene
  asignada no retiene nunca una denuncia ajena (ni los mensajes del
  denunciante, que esperan a ese bloqueo).
* Orden de bloqueos: cuentas, denuncia y auditoría, el mismo que
  app/personal.py y la supresión (db/init/04_supresion.sql). Asignar bloquea
  varias cuentas: primero los admins activos en orden de id y después la de
  destino, igual que dar_de_baja y la recuperación; con otro orden, una
  asignación y una baja simultáneas podrían interbloquearse.
* La lectura toma FOR SHARE sobre la denuncia: choca con el bloqueo del
  trigger de mensajes y con el cambio de estado, así que la denuncia y sus
  mensajes salen de la misma foto sin pasar a REPEATABLE READ (que no
  serviría aquí: la lectura escribe su fila de auditoría y el encadenado
  necesita READ COMMITTED). Se descifra después de confirmar, para no
  retener la conexión.
* El mensaje del personal lo numera y lo valida el trigger
  canal.preparar_mensaje(), igual que el del denunciante. Al cerrar, el
  mensaje final se inserta antes de cambiar el estado, en la misma
  transacción.

Tope de lecturas (OWASP ASVS 5.0.0, 2.4.1: frenar las llamadas excesivas que
llevan a sacar datos; ATT&CK T1213). Un admin puede asignarse cualquier
denuncia y leerla: la auditoría lo registra, pero sin un límite podría
sacarlas todas en minutos. Por eso:
* Se cuentan las denuncias DISTINTAS que una cuenta abre en el día de la
  empresa, en la propia auditoría (filas lectura_denuncia). El día es el de
  la columna fecha, que no lleva hora a propósito: contar 24 horas móviles
  exigiría guardarla. Releer una denuncia ya abierta hoy no suma, y sigue
  permitido después del tope: quien instruye no pierde lo que ya tenía.
* Al llegar a LECTURAS_AVISO y a LECTURAS_TOPE, una sola vez cada uno por
  construcción (la cuenta solo pasa una vez por cada número), avisa a los
  admins y auditores (app/avisos.py) y deja un EVENTO. Pasado el tope, una
  denuncia nueva da LimiteLecturas (429) sin leer nada ni dejar fila.
* Primero se escribe la fila y después se cuenta, en la misma transacción.
  El trigger de encadenado bloquea la auditoría de la empresa hasta
  confirmar, así que dos lecturas simultáneas de la misma cuenta se cuentan
  una detrás de otra y nunca pasan las dos con la última plaza. Si se
  rechaza, la transacción se deshace entera, fila incluida.
* El mismo tope para admin e instructor: es la cuenta la que se limita.
  Repartir las lecturas entre cuentas exige activar cuentas nuevas, y cada
  activación también se avisa (app/avisos.py).

Registro (logs): nada en el flujo normal. Las acciones quedan en la
auditoría, que no lleva hora. Las excepciones las registra
app/rutas_personal.py:
* La declaración de no veraz y la redacción destruyen prueba sin vuelta
  atrás, y su abuso (un admin que entierra denuncias o tacha lo que le
  incrimina) debe dejar una señal fuera de la base de datos que la propia
  empresa administra. Esa señal es también el registro que permite volver a
  aplicarlas si se restaura una copia anterior (docs/threat-model.md, 8).
* Los dos avisos del tope de lecturas, por la misma razón: son la señal de
  una salida de datos, y no deben depender solo de la auditoría que el
  propio admin puede leer.
"""
import datetime
import re
import uuid
from dataclasses import dataclass

import psycopg

from app import avisos, bd, cripto, denuncias, personal, solicitudes

# Los estados visibles: los únicos que el listado admite como filtro.
# 'no_veraz' no está: para la API no existe (ver la cabecera).
ESTADOS = ("nueva", "en_instruccion", "resuelta", "archivada", "inadmitida")
ESTADOS_CERRADOS = ("resuelta", "archivada", "inadmitida")
ESTADO_NO_VERAZ = "no_veraz"
# Las únicas transiciones permitidas. Lo que no está aquí es un 409.
TRANSICIONES = {
    "nueva": ("en_instruccion", "inadmitida", "no_veraz"),
    "en_instruccion": ("resuelta", "archivada", "no_veraz"),
    "resuelta": ("no_veraz",),
    "archivada": ("no_veraz",),
    "inadmitida": ("no_veraz",),
}
ESTADOS_DESTINO = ("en_instruccion", "resuelta", "archivada", "inadmitida", "no_veraz")

ACCION_LECTURA = "lectura_denuncia"
ACCION_MENSAJE = "mensaje_personal"
ACCION_ASIGNACION = "asignacion"
PREFIJO_ACCION_ESTADO = "estado_"

# Dónde guarda la auditoría la cuenta sobre la que se actuó (ver la
# cabecera). Las demás acciones no tienen cuenta: lectura_denuncia,
# mensaje_personal, estado_*, redaccion_* y supresion_* actúan sobre una
# denuncia, y rechazo_registro sobre una solicitud.
ACCIONES_CUENTA_EN_OBJETO = frozenset({
    personal.ACCION_ACCESO, personal.ACCION_ACTIVACION, personal.ACCION_CAMBIO_CONTRASENA,
    personal.ACCION_INVITACION, personal.ACCION_BAJA, personal.ACCION_ANULACION_INVITACION,
    personal.ACCION_INVITACION_PLATAFORMA, personal.ACCION_REINVITACION_PLATAFORMA,
    solicitudes.ACCION_APROBACION,
})
ACCIONES_CUENTA_EN_DESTINO = frozenset({ACCION_ASIGNACION})

# Tope de lecturas (ver la cabecera): denuncias distintas por cuenta y día de
# la empresa. Son criterio, no una cifra de otra aplicación: no hay datos de
# uso con los que calibrarlos (docs/threat-model.md, 8). Quien instruye abre
# pocas denuncias nuevas al día; 20 ya es raro y merece que alguien lo mire,
# y 50 solo se alcanza clasificando una cola muy grande, que otro admin puede
# repartir. Cambiarlos es cambiar estos literales y los de las pruebas.
LECTURAS_AVISO = 20
LECTURAS_TOPE = 50
UMBRAL_AVISO = "aviso"
UMBRAL_TOPE = "tope"

# Filas por página. Fijas: un parámetro más sería una forma más de pedir
# respuestas grandes.
TAMANO_PAGINA_DENUNCIAS = 100
TAMANO_PAGINA_AUDITORIA = 200

# Cursor del listado: "<fecha>.<id>" de la última denuncia de la página. Solo
# esta forma exacta: date.fromisoformat admite otras (por ejemplo, 20261012).
PATRON_CURSOR = re.compile(r"(\d{4}-\d{2}-\d{2})\.([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})")

# La cuenta de quien actúa, activa y activada. FOR KEY SHARE: ver la cabecera.
SQL_BLOQUEAR_ACTOR = (
    "select 1 from canal.usuario_personal where id = %s and activo and totp_activo for key share"
)
# Mismo orden que SQL_BLOQUEAR_ADMINS de app/personal.py (todos los admins
# activos, en orden de id), con el bloqueo compartido.
SQL_BLOQUEAR_ADMINS = (
    "select id, totp_activo from canal.usuario_personal where rol = 'admin' and activo order by id for key share"
)
SQL_BLOQUEAR_DESTINO = (
    "select activo and totp_activo, rol from canal.usuario_personal where id = %s for key share"
)
# El trigger canal.controlar_asignacion_denuncia (02_esquema.sql) rechaza
# asignar una denuncia a un rol que no instruye. asignar lo comprueba antes;
# si esa comprobación fallara, la base de datos lo para igual y la respuesta
# es la misma (DestinoNoValido), no un 500.
SQLSTATE_DESTINO_NO_ASIGNABLE = "CN004"
# Para las lecturas sin escritura (listados), en una transacción de solo
# lectura: la comprobación y la consulta salen de la misma foto.
SQL_ACTOR_ACTIVO = "select count(*) from canal.usuario_personal where id = %s and activo and totp_activo"
# El email de quien lee, para el aviso del tope de lecturas (app/avisos.py).
SQL_EMAIL_ACTOR = "select email from canal.usuario_personal where id = %s"

# Cada consulta sobre una denuncia excluye 'no_veraz' en su propio WHERE: no
# la devuelve (404) ni la bloquea. Un filtro aparte que alguien olvidara en
# una consulta nueva la volvería visible; aquí cada una lo lleva escrito.
SQL_LEER_ASIGNADA = (
    "select fecha, estado, contenido_cifrado, version_clave from canal.denuncia "
    "where id = %s and asignada_a = %s and estado <> 'no_veraz' for share"
)
# Lecturas de hoy de la cuenta, después de escribir la de esta petición:
# denuncias distintas, veces que se ha leído esta (1 si es la primera de hoy)
# y segundos hasta el día siguiente de la empresa. El día se calcula igual
# que canal.encadenar_auditoria (now() es el mismo en toda la transacción),
# y la medianoche se pasa a timestamptz antes de restar: un día con cambio
# de hora dura 23 o 25 horas, y restar horas locales fallaría por una.
# 'lectura_denuncia' (ACCION_LECTURA) va como literal: con un parámetro,
# PostgreSQL no podría usar el índice parcial auditoria_lecturas.
SQL_LECTURAS_DEL_DIA = """
    select count(distinct a.objeto_id),
           count(*) filter (where a.objeto_id = %(denuncia)s),
           ceil(extract(epoch from ((e.hoy + 1)::timestamp at time zone e.zona_horaria) - now()))::integer
      from (select id, zona_horaria, (now() at time zone zona_horaria)::date as hoy from canal.empresa) e
      left join canal.registro_auditoria a
        on a.empresa_id = e.id and a.actor = %(actor)s and a.accion = 'lectura_denuncia' and a.fecha = e.hoy
     group by e.zona_horaria, e.hoy
"""
SQL_ESCRIBIR_ASIGNADA = (
    "select estado from canal.denuncia where id = %s and asignada_a = %s and estado <> 'no_veraz' "
    "for no key update"
)
SQL_BLOQUEAR_DENUNCIA = (
    "select estado, asignada_a from canal.denuncia where id = %s and estado <> 'no_veraz' for no key update"
)
SQL_INSERTAR_MENSAJE = (
    "insert into canal.mensaje (empresa_id, denuncia_id, id, autor, autor_id, contenido_cifrado, version_clave) "
    "values (%s, %s, %s, 'personal', %s, %s, %s) returning secuencia, fecha"
)
# La condición sobre el estado anterior es redundante con el bloqueo, a
# propósito: si alguna vez faltara el bloqueo, el cambio no se aplicaría en
# silencio sobre un estado distinto del comprobado (se comprueba rowcount).
SQL_CAMBIAR_ESTADO = "update canal.denuncia set estado = %s where id = %s and estado = %s"
SQL_ASIGNAR = "update canal.denuncia set asignada_a = %s where id = %s"
SQL_AUDITAR = (
    "insert into canal.registro_auditoria (empresa_id, actor, accion, objeto_id, destino_id) "
    "values (%s, %s, %s, %s, %s)"
)
SQL_LISTAR = """
    select d.id, d.fecha, d.estado, d.asignada_a, (u.activo and u.totp_activo)
      from canal.denuncia d
      left join canal.usuario_personal u on u.empresa_id = d.empresa_id and u.id = d.asignada_a
     where (%(todas)s or d.asignada_a = %(actor)s)
       and d.estado <> 'no_veraz'
       and (%(estado)s::text is null or d.estado = %(estado)s::text)
       and (%(cursor_fecha)s::date is null or (d.fecha, d.id) < (%(cursor_fecha)s::date, %(cursor_id)s::uuid))
     order by d.fecha desc, d.id desc
     limit %(limite)s
"""
# Las filas de la auditoría con los emails (ver la cabecera). El actor del
# personal es 'personal:<id>' (_actor); 'plataforma' y 'sistema' no cruzan
# con ninguna cuenta, y una acción que no está en ninguna de las dos listas
# deja el CASE en null y tampoco. La empresa va en cada join, como en
# SQL_LISTAR, aunque la RLS ya la limita.
_SQL_FILAS_AUDITORIA = """
    select a.secuencia, a.fecha, a.actor, a.accion, a.objeto_id, a.destino_id, ua.email, uc.email
      from canal.registro_auditoria a
      left join canal.usuario_personal ua
        on ua.empresa_id = a.empresa_id and a.actor = 'personal:' || ua.id::text
      left join canal.usuario_personal uc
        on uc.empresa_id = a.empresa_id and uc.id = case
             when a.accion = any(%(en_objeto)s) then a.objeto_id
             when a.accion = any(%(en_destino)s) then a.destino_id
           end
"""
SQL_AUDITORIA = _SQL_FILAS_AUDITORIA + """
     where a.secuencia >= %(desde)s
     order by a.secuencia
     limit %(limite)s
"""
# Desde lo más reciente: la primera página y las anteriores. Dos sentencias
# en vez de una con "%(antes)s is null or": cada una dice exactamente lo que
# pide.
SQL_AUDITORIA_RECIENTE = _SQL_FILAS_AUDITORIA + """
     order by a.secuencia desc
     limit %(limite)s
"""
SQL_AUDITORIA_ANTERIOR = _SQL_FILAS_AUDITORIA + """
     where a.secuencia < %(antes)s
     order by a.secuencia desc
     limit %(limite)s
"""
SQL_VERIFICAR_CADENA = "select canal.verificar_cadena_auditoria()"

# Redacción. Carácter con el que se tacha: U+2588 (FULL BLOCK), el mismo que
# GlobaLeaks.
MASCARA = "█"
SQL_REDACTAR_BLOQUEAR = (
    "select contenido_cifrado, version_clave from canal.denuncia "
    "where id = %s and asignada_a = %s and estado <> 'no_veraz' for no key update"
)
# Sin bloqueo propio: un mensaje solo se reescribe con su denuncia bloqueada
# (aquí y en canal.redactar_mensaje).
SQL_REDACTAR_MENSAJE_LEER = (
    "select id, autor, autor_id, contenido_cifrado, version_clave from canal.mensaje "
    "where denuncia_id = %s and secuencia = %s"
)
SQL_REDACTAR_DENUNCIA = "select canal.redactar_denuncia(%s, %s, %s, %s, %s)"
SQL_REDACTAR_MENSAJE = "select canal.redactar_mensaje(%s, %s, %s, %s, %s, %s)"


class TransicionNoValida(Exception):
    """El cambio de estado pedido no está en TRANSICIONES."""


class DenunciaCerrada(Exception):
    """La denuncia está cerrada: no admite mensajes ni asignación."""


class LimiteMensajes(Exception):
    """La denuncia ya tiene el máximo de mensajes."""


class DestinoNoValido(Exception):
    """La cuenta a la que se asigna está dada de baja, sin activar o con un
    rol que no instruye (personal.ROLES_INSTRUCCION)."""


class MensajeFinalObligatorio(Exception):
    """Se cierra una denuncia sin mensaje final para el denunciante."""


class MensajeNoPermitido(Exception):
    """Se declara no veraz una denuncia con un mensaje que nadie leería."""


class LimiteLecturas(Exception):
    """La cuenta ya ha abierto hoy LECTURAS_TOPE denuncias distintas y pide
    otra nueva. segundos: hasta el día siguiente de la empresa."""

    def __init__(self, segundos):
        super().__init__(segundos)
        self.segundos = segundos


class CursorNoValido(ValueError):
    """El cursor de paginación no tiene la forma exacta."""


class FragmentoNoCoincide(Exception):
    """Un tramo de la redacción no señala el texto que dice tachar."""


@dataclass(frozen=True)
class FilaDenuncia:
    denuncia_id: uuid.UUID
    fecha: datetime.date
    estado: str
    asignada_a: uuid.UUID | None
    # None si no está asignada; False si la cuenta asignada ya no está
    # activa (el admin debe reasignarla).
    asignada_activa: bool | None


@dataclass(frozen=True)
class PaginaDenuncias:
    denuncias: tuple
    siguiente: str | None


@dataclass(frozen=True)
class Expediente:
    denuncia_id: uuid.UUID
    fecha: datetime.date
    estado: str
    categoria: str
    texto: str
    mensajes: tuple


@dataclass(frozen=True)
class Lectura:
    expediente: Expediente
    # Denuncias distintas abiertas hoy por la cuenta, contando esta.
    lecturas_hoy: int
    # UMBRAL_AVISO o UMBRAL_TOPE si esta lectura acaba de llegar a uno; None si no.
    umbral: str | None
    # Avisos para los admins y auditores (app/avisos.py), vacío si no hay
    # umbral o no hay a quién avisar.
    correos: tuple


@dataclass(frozen=True)
class FilaAuditoria:
    secuencia: int
    fecha: datetime.date
    actor: str
    accion: str
    objeto_id: uuid.UUID | None
    destino_id: uuid.UUID | None
    # None si el actor no es una cuenta ('plataforma', 'sistema').
    actor_email: str | None
    # None si la acción no es sobre una cuenta (ver la cabecera).
    cuenta_email: str | None


@dataclass(frozen=True)
class PaginaAuditoria:
    filas: tuple
    siguiente: int | None


@dataclass(frozen=True)
class PaginaAuditoriaReciente:
    filas: tuple
    # Lo que se pasa como antes para la página siguiente, hacia el principio;
    # None si no hay más.
    anterior: int | None


# ---------------------------------------------------------------------------
# Piezas comunes
# ---------------------------------------------------------------------------

def _actor(sesion):
    # El mismo formato que app/personal.py: las filas de una cuenta se leen
    # juntas en la auditoría.
    return f"personal:{sesion.usuario_id}"


def _exigir_admin(sesion):
    # Antes de abrir ninguna transacción: un rol insuficiente no toca la base
    # de datos. El rol de una cuenta no cambia nunca (no tiene UPDATE).
    if sesion.rol != "admin":
        raise personal.Prohibido


def _bloquear_actor(conexion, sesion):
    if conexion.execute(SQL_BLOQUEAR_ACTOR, [sesion.usuario_id]).fetchone() is None:
        raise personal.SesionNoValida


def _comprobar_actor(conexion, sesion):
    if conexion.execute(SQL_ACTOR_ACTIVO, [sesion.usuario_id]).fetchone()[0] != 1:
        raise personal.SesionNoValida


def _auditar(conexion, sesion, accion, objeto_id, destino_id=None):
    conexion.execute(SQL_AUDITAR, [sesion.empresa_id, _actor(sesion), accion, objeto_id, destino_id])


def _insertar_mensaje(conexion, claves, sesion, denuncia_id, texto):
    """Cifra e inserta un mensaje del personal. El AAD lleva autor_id: un
    mensaje no puede cambiar de autor sin que el descifrado lo note. Las
    reglas de estado y tope las impone el trigger; sus SQLSTATE se traducen
    en quien llama (_traducir)."""
    mensaje_id = uuid.uuid4()
    version, clave = denuncias.clave_actual(conexion, claves, sesion.empresa_id)
    cifrado = cripto.cifrar_contenido(
        clave, denuncias.serializar(texto=texto),
        cripto.aad_mensaje(sesion.empresa_id, denuncia_id, mensaje_id, "personal", sesion.usuario_id))
    return conexion.execute(SQL_INSERTAR_MENSAJE, [sesion.empresa_id, denuncia_id, mensaje_id, sesion.usuario_id,
                                                   cifrado, version]).fetchone()


def _traducir(error):
    """SQLSTATE previstos del trigger de mensajes; cualquier otro sigue su
    camino (500 o 503 en app/frontera_http.py)."""
    if error.sqlstate == denuncias.SQLSTATE_DENUNCIA_CERRADA:
        return DenunciaCerrada()
    if error.sqlstate == denuncias.SQLSTATE_LIMITE_MENSAJES:
        return LimiteMensajes()
    # La denuncia se suprimió entre bloquearla e insertar: no puede pasar con
    # el bloqueo tomado, pero si pasara, es una denuncia que ya no existe.
    if error.sqlstate == denuncias.SQLSTATE_DENUNCIA_NO_VISIBLE:
        return personal.NoEncontrado()
    return None


def decidir_lecturas(distintas, primera):
    """(permitida, umbral) de una lectura, con distintas = denuncias distintas
    de hoy contando esta y primera = si es la primera vez que se abre hoy.

    Se rechaza solo por encima del tope, y eso solo puede pasar con una
    denuncia nueva: releer no cambia distintas. El umbral sale cuando una
    denuncia nueva hace llegar a la cuenta justo a ese número, así que cada
    aviso sale una vez al día por cuenta sin guardar nada más."""
    if distintas > LECTURAS_TOPE:
        return False, None
    if primera and distintas == LECTURAS_AVISO:
        return True, UMBRAL_AVISO
    if primera and distintas == LECTURAS_TOPE:
        return True, UMBRAL_TOPE
    return True, None


def leer_cursor(texto):
    """(fecha, id) de un cursor, o CursorNoValido."""
    coincidencia = PATRON_CURSOR.fullmatch(texto)
    if coincidencia is None:
        raise CursorNoValido("cursor no valido")
    try:
        return datetime.date.fromisoformat(coincidencia.group(1)), uuid.UUID(coincidencia.group(2))
    except ValueError:
        raise CursorNoValido("cursor no valido") from None


# ---------------------------------------------------------------------------
# Listados (solo lectura)
# ---------------------------------------------------------------------------

def listar_denuncias(pool, sesion, estado=None, cursor=None):
    """Metadatos, nunca contenido: todas para un admin, las asignadas para un
    instructor. Más recientes primero, por páginas."""
    personal.exigir_rol(sesion, personal.ROLES_INSTRUCCION)
    if estado is not None and estado not in ESTADOS:
        raise ValueError("estado desconocido")
    cursor_fecha, cursor_id = leer_cursor(cursor) if cursor is not None else (None, None)
    with bd.transaccion_empresa(pool, sesion.empresa_id, solo_lectura=True) as conexion:
        _comprobar_actor(conexion, sesion)
        filas = conexion.execute(SQL_LISTAR, {
            "todas": sesion.rol == "admin", "actor": sesion.usuario_id, "estado": estado,
            "cursor_fecha": cursor_fecha, "cursor_id": cursor_id, "limite": TAMANO_PAGINA_DENUNCIAS + 1,
        }).fetchall()
    pagina = [FilaDenuncia(denuncia_id=f[0], fecha=f[1], estado=f[2], asignada_a=f[3], asignada_activa=f[4])
              for f in filas[:TAMANO_PAGINA_DENUNCIAS]]
    siguiente = None
    if len(filas) > TAMANO_PAGINA_DENUNCIAS:
        ultima = pagina[-1]
        siguiente = f"{ultima.fecha.isoformat()}.{ultima.denuncia_id}"
    return PaginaDenuncias(denuncias=tuple(pagina), siguiente=siguiente)


def _leer_auditoria(pool, sesion, sql, parametros):
    """Una página más una fila de la auditoría de la empresa (la de más dice
    si hay otra página), con los emails. Admin y auditor."""
    personal.exigir_rol(sesion, personal.ROLES_AUDITORIA)
    with bd.transaccion_empresa(pool, sesion.empresa_id, solo_lectura=True) as conexion:
        _comprobar_actor(conexion, sesion)
        filas = conexion.execute(sql, {
            **parametros, "en_objeto": sorted(ACCIONES_CUENTA_EN_OBJETO),
            "en_destino": sorted(ACCIONES_CUENTA_EN_DESTINO), "limite": TAMANO_PAGINA_AUDITORIA + 1,
        }).fetchall()
    return [FilaAuditoria(*f) for f in filas]


def listar_auditoria(pool, sesion, desde=1):
    """Auditoría de la empresa, para admins y auditores, en orden de secuencia
    y por páginas. Es lo que hace visibles los controles que se apoyan en ella:
    quién se asignó una denuncia, quién la leyó y quién reinvitó una cuenta.
    No verifica la cadena: recorrerla entera es O(n) y cada página la
    recorrería otra vez (verificar_auditoria)."""
    filas = _leer_auditoria(pool, sesion, SQL_AUDITORIA, {"desde": desde})
    pagina = filas[:TAMANO_PAGINA_AUDITORIA]
    siguiente = pagina[-1].secuencia + 1 if len(filas) > TAMANO_PAGINA_AUDITORIA else None
    return PaginaAuditoria(filas=tuple(pagina), siguiente=siguiente)


def listar_auditoria_reciente(pool, sesion, antes=None):
    """La misma auditoría desde lo más reciente: sin antes, la última página;
    con antes, la página de secuencias menores. anterior es la secuencia más
    baja de la página si quedan más, para pedir la siguiente con ella."""
    if antes is None:
        filas = _leer_auditoria(pool, sesion, SQL_AUDITORIA_RECIENTE, {})
    else:
        filas = _leer_auditoria(pool, sesion, SQL_AUDITORIA_ANTERIOR, {"antes": antes})
    pagina = filas[:TAMANO_PAGINA_AUDITORIA]
    anterior = pagina[-1].secuencia if len(filas) > TAMANO_PAGINA_AUDITORIA else None
    return PaginaAuditoriaReciente(filas=tuple(pagina), anterior=anterior)


def verificar_auditoria(pool, sesion):
    """Primera secuencia rota de la cadena de auditoría de la empresa, o None
    si está intacta (canal.verificar_cadena_auditoria). Admin y auditor, como
    una acción explícita aparte del listado."""
    personal.exigir_rol(sesion, personal.ROLES_AUDITORIA)
    with bd.transaccion_empresa(pool, sesion.empresa_id, solo_lectura=True) as conexion:
        _comprobar_actor(conexion, sesion)
        return conexion.execute(SQL_VERIFICAR_CADENA).fetchone()[0]


# ---------------------------------------------------------------------------
# Acciones sobre una denuncia
# ---------------------------------------------------------------------------

def leer_denuncia(pool, claves, sesion, denuncia_id):
    """Contenido y mensajes de una denuncia asignada a quien la pide, con el
    tope de lecturas (ver la cabecera). Deja una fila de auditoría por lectura."""
    personal.exigir_rol(sesion, personal.ROLES_INSTRUCCION)
    correos = ()
    with bd.transaccion_empresa(pool, sesion.empresa_id) as conexion:
        _bloquear_actor(conexion, sesion)
        fila = conexion.execute(SQL_LEER_ASIGNADA, [denuncia_id, sesion.usuario_id]).fetchone()
        if fila is None:
            raise personal.NoEncontrado
        fecha, estado, cifrado, version = fila
        filas, envueltas = denuncias.leer_mensajes_y_claves(conexion, denuncia_id, version)
        # La fila antes que el conteo: escribirla espera al bloqueo de la
        # auditoría de la empresa, y el conteo ve ya las lecturas confirmadas
        # antes (ver la cabecera).
        _auditar(conexion, sesion, ACCION_LECTURA, denuncia_id)
        distintas, veces, segundos = conexion.execute(
            SQL_LECTURAS_DEL_DIA, {"denuncia": denuncia_id, "actor": _actor(sesion)}).fetchone()
        permitida, umbral = decidir_lecturas(distintas, veces == 1)
        if not permitida:
            # Sale de la transacción con una excepción: se deshace, fila incluida.
            raise LimiteLecturas(segundos)
        if umbral is not None:
            nombre, emails = avisos.destinatarios(conexion, sesion.usuario_id)
            cuenta = conexion.execute(SQL_EMAIL_ACTOR, [sesion.usuario_id]).fetchone()[0]
            correos = avisos.correos_lecturas(nombre, emails, cuenta, distintas, LECTURAS_TOPE)
    contenido, mensajes = denuncias.descifrar_expediente(claves, sesion.empresa_id, denuncia_id, cifrado, version,
                                                         filas, envueltas)
    expediente = Expediente(denuncia_id=denuncia_id, fecha=fecha, estado=estado, categoria=contenido["categoria"],
                            texto=contenido["texto"], mensajes=tuple(mensajes))
    return Lectura(expediente=expediente, lecturas_hoy=distintas, umbral=umbral, correos=correos)


def enviar_mensaje(pool, claves, sesion, denuncia_id, texto):
    """Mensaje del personal al denunciante, en una denuncia asignada."""
    personal.exigir_rol(sesion, personal.ROLES_INSTRUCCION)
    try:
        with bd.transaccion_empresa(pool, sesion.empresa_id) as conexion:
            _bloquear_actor(conexion, sesion)
            if conexion.execute(SQL_ESCRIBIR_ASIGNADA, [denuncia_id, sesion.usuario_id]).fetchone() is None:
                raise personal.NoEncontrado
            secuencia, fecha = _insertar_mensaje(conexion, claves, sesion, denuncia_id, texto)
            _auditar(conexion, sesion, ACCION_MENSAJE, denuncia_id)
    except psycopg.Error as error:
        traducida = _traducir(error)
        if traducida is None:
            raise
        raise traducida from None
    return denuncias.MensajeEnviado(secuencia=secuencia, fecha=fecha)


def cambiar_estado(pool, claves, sesion, denuncia_id, nuevo, mensaje):
    """Cambia el estado de una denuncia asignada según TRANSICIONES. Cerrar
    exige mensaje final, que se inserta antes del cambio. Declarar no veraz
    exige ser admin y no admite mensaje (ver la cabecera)."""
    personal.exigir_rol(sesion, personal.ROLES_INSTRUCCION)
    if nuevo not in ESTADOS_DESTINO:
        raise ValueError("estado desconocido")
    if nuevo == ESTADO_NO_VERAZ:
        _exigir_admin(sesion)
        if mensaje is not None:
            raise MensajeNoPermitido
    if nuevo in ESTADOS_CERRADOS and mensaje is None:
        raise MensajeFinalObligatorio
    try:
        with bd.transaccion_empresa(pool, sesion.empresa_id) as conexion:
            _bloquear_actor(conexion, sesion)
            fila = conexion.execute(SQL_ESCRIBIR_ASIGNADA, [denuncia_id, sesion.usuario_id]).fetchone()
            if fila is None:
                raise personal.NoEncontrado
            actual = fila[0]
            if nuevo not in TRANSICIONES.get(actual, ()):
                raise TransicionNoValida
            if mensaje is not None:
                _insertar_mensaje(conexion, claves, sesion, denuncia_id, mensaje)
            if conexion.execute(SQL_CAMBIAR_ESTADO, [nuevo, denuncia_id, actual]).rowcount != 1:
                raise RuntimeError("el cambio de estado no se aplico sobre la fila bloqueada")
            _auditar(conexion, sesion, PREFIJO_ACCION_ESTADO + nuevo, denuncia_id)
    except psycopg.Error as error:
        traducida = _traducir(error)
        if traducida is None:
            raise
        raise traducida from None


def asignar(pool, sesion, denuncia_id, destino_id):
    """Asigna una denuncia abierta a una cuenta activa de la empresa con un
    rol que instruye (ROLES_INSTRUCCION: asignarla da acceso al contenido).
    Solo admin. El destino puede ser el propio admin (así clasifica una
    denuncia: ver la cabecera)."""
    _exigir_admin(sesion)
    try:
        with bd.transaccion_empresa(pool, sesion.empresa_id) as conexion:
            admins = conexion.execute(SQL_BLOQUEAR_ADMINS).fetchall()
            if not any(admin_id == sesion.usuario_id and activado for admin_id, activado in admins):
                raise personal.SesionNoValida
            destino = conexion.execute(SQL_BLOQUEAR_DESTINO, [destino_id]).fetchone()
            if destino is None:
                raise personal.NoEncontrado
            activo, rol = destino
            if not activo or rol not in personal.ROLES_INSTRUCCION:
                raise DestinoNoValido
            fila = conexion.execute(SQL_BLOQUEAR_DENUNCIA, [denuncia_id]).fetchone()
            if fila is None:
                raise personal.NoEncontrado
            estado, asignada_a = fila
            if estado in ESTADOS_CERRADOS:
                raise DenunciaCerrada
            # Idempotente: ya la tiene esa cuenta, no hay nada que cambiar ni auditar.
            if asignada_a == destino_id:
                return
            conexion.execute(SQL_ASIGNAR, [destino_id, denuncia_id])
            _auditar(conexion, sesion, ACCION_ASIGNACION, denuncia_id, destino_id)
    except psycopg.Error as error:
        if error.sqlstate == SQLSTATE_DESTINO_NO_ASIGNABLE:
            raise DestinoNoValido from None
        raise


# ---------------------------------------------------------------------------
# Redacción (art. 32.2; ver la cabecera)
# ---------------------------------------------------------------------------

def tachar(texto, tramos):
    """El texto con cada tramo (desde, fragmento) sustituido por MASCARA, o
    FragmentoNoCoincide si alguno no señala exactamente su fragmento. Cada
    tramo se compara con el texto original, así que el orden y el solape
    entre tramos no cambian el resultado."""
    caracteres = list(texto)
    for desde, fragmento in tramos:
        hasta = desde + len(fragmento)
        if desde < 0 or not fragmento or hasta > len(texto) or texto[desde:hasta] != fragmento:
            raise FragmentoNoCoincide
        caracteres[desde:hasta] = MASCARA * len(fragmento)
    return "".join(caracteres)


def _clave_de_version(conexion, claves, empresa_id, version):
    # La clave foránea de version_clave garantiza que la versión existe.
    envuelta = conexion.execute(denuncias.SQL_CLAVES, [[version]]).fetchone()[1]
    return cripto.desenvolver_clave(claves.maestra, bytes(envuelta), empresa_id, version)


def _bloquear_para_redactar(conexion, sesion, denuncia_id):
    """Cifrado y versión de una denuncia asignada a quien la pide, con la fila
    bloqueada; NoEncontrado si no lo está (o es no_veraz)."""
    _bloquear_actor(conexion, sesion)
    fila = conexion.execute(SQL_REDACTAR_BLOQUEAR, [denuncia_id, sesion.usuario_id]).fetchone()
    if fila is None:
        raise personal.NoEncontrado
    return bytes(fila[0]), fila[1]


def redactar_denuncia(pool, claves, sesion, denuncia_id, tramos):
    """Tacha los tramos del texto de una denuncia. Devuelve True si ha
    escrito y False si ya estaba todo tachado (no deja fila)."""
    _exigir_admin(sesion)
    with bd.transaccion_empresa(pool, sesion.empresa_id) as conexion:
        cifrado, version = _bloquear_para_redactar(conexion, sesion, denuncia_id)
        aad = cripto.aad_denuncia(sesion.empresa_id, denuncia_id)
        contenido = denuncias.deserializar(
            cripto.descifrar_contenido(_clave_de_version(conexion, claves, sesion.empresa_id, version), cifrado, aad),
            ("categoria", "texto"))
        texto = tachar(contenido["texto"], tramos)
        if texto == contenido["texto"]:
            return False
        version_nueva, clave = denuncias.clave_actual(conexion, claves, sesion.empresa_id)
        nuevo = cripto.cifrar_contenido(clave, denuncias.serializar(categoria=contenido["categoria"], texto=texto),
                                        aad)
        conexion.execute(SQL_REDACTAR_DENUNCIA, [denuncia_id, sesion.usuario_id, cifrado, nuevo, version_nueva])
    return True


def redactar_mensaje(pool, claves, sesion, denuncia_id, secuencia, tramos):
    """Tacha los tramos de un mensaje, del denunciante o del personal, de una
    denuncia asignada. Mismo resultado que redactar_denuncia."""
    _exigir_admin(sesion)
    with bd.transaccion_empresa(pool, sesion.empresa_id) as conexion:
        _bloquear_para_redactar(conexion, sesion, denuncia_id)
        fila = conexion.execute(SQL_REDACTAR_MENSAJE_LEER, [denuncia_id, secuencia]).fetchone()
        if fila is None:
            raise personal.NoEncontrado
        mensaje_id, autor, autor_id, cifrado, version = fila
        cifrado = bytes(cifrado)
        aad = cripto.aad_mensaje(sesion.empresa_id, denuncia_id, mensaje_id, autor, autor_id)
        contenido = denuncias.deserializar(
            cripto.descifrar_contenido(_clave_de_version(conexion, claves, sesion.empresa_id, version), cifrado, aad),
            ("texto",))
        texto = tachar(contenido["texto"], tramos)
        if texto == contenido["texto"]:
            return False
        version_nueva, clave = denuncias.clave_actual(conexion, claves, sesion.empresa_id)
        nuevo = cripto.cifrar_contenido(clave, denuncias.serializar(texto=texto), aad)
        conexion.execute(SQL_REDACTAR_MENSAJE, [denuncia_id, secuencia, sesion.usuario_id, cifrado, nuevo,
                                                version_nueva])
    return True
