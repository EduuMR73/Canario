"""Avisos de seguridad a las personas que vigilan una empresa
(docs/threat-model.md, 6.15 y 8).

Un evento en el log que nadie mira está registrado, no detectado. Estos
avisos llevan la señal a una persona que puede actuar, como hacen los
productos equivalentes: Microsoft Defender for Cloud Apps alerta de una
descarga masiva por un solo usuario, y GlobaLeaks escribe a sus admins
cuando la falta de disco le hace dejar de aceptar denuncias.

Qué se avisa:
* Lecturas (app/instruccion.py): una cuenta llega al umbral de aviso o al
  tope de denuncias distintas abiertas en el día. Es la detección de la
  salida de datos en volumen (ATT&CK T1213).
* Activación (app/personal.py): una cuenta confirma su activación, sea
  nueva, reactivada o recuperada. Sin este aviso, el tope por cuenta se
  saltaría creando cuentas: un admin malicioso, o quien le haya robado la
  sesión, invita a una cuenta que controla y lee otras tantas con ella
  (ATT&CK T1136, crear una cuenta; T1098, cuando es una recuperación).

A quién: a los admins y auditores activos y activados de la empresa, nunca
a la cuenta de la que se avisa. Avisar al sospechoso no avisa a nadie. En la
activación sí llega a quien invitó: si le robaron la sesión, se entera el
titular (NIST SP 800-63B-4, 4.2.3, avisar de una recuperación).

Qué dice: la cuenta (su email) y el número, nunca un id ni un dato de una
denuncia. Quien lo recibe ya puede leer la auditoría, que lo detalla.

Si no hay a quién avisar (una empresa con un solo admin y sin auditor, o la
activación del primer admin), quien llama deja un EVENTO aviso_sin_destinatario:
el aviso que no llega a nadie se ve, no se pierde en silencio. El envío lo
hace app/correo.py después de responder, con sus límites y sus eventos de
fallo. Límite conocido: la salida SMTP de producción no está decidida
(app/correo.py), y hasta entonces estos correos solo llegan en desarrollo.
"""
from app import correo

# Los roles que vigilan: los que leen la auditoría (personal.ROLES_AUDITORIA).
# Literal aquí para que la consulta no dependa de cómo se escriba una tupla
# en SQL; tests/unit/test_avisos.py comprueba que coinciden.
SQL_DESTINATARIOS = (
    "select email from canal.usuario_personal "
    "where rol in ('admin', 'auditor') and activo and totp_activo and id <> %s order by email"
)
SQL_NOMBRE_EMPRESA = "select nombre from canal.empresa"


def destinatarios(conexion, excluida):
    """Emails de quienes reciben los avisos de la empresa del contexto, sin
    la cuenta excluida. En la transacción de quien avisa: la lista sale de
    la misma foto que el hecho que se avisa."""
    filas = conexion.execute(SQL_DESTINATARIOS, [excluida]).fetchall()
    nombre = conexion.execute(SQL_NOMBRE_EMPRESA).fetchone()[0]
    return nombre, tuple(fila[0] for fila in filas)


def correos_lecturas(nombre, emails, cuenta, lecturas, tope):
    """Un correo por destinatario: la cuenta ha llegado a lecturas denuncias
    distintas hoy. Si lecturas es el tope, dice que ya no puede abrir más."""
    final = (f"Ha llegado al tope de {tope}: hasta mañana no puede abrir ninguna denuncia nueva, "
             "solo las que ya abrió hoy." if lecturas >= tope else
             f"El tope es {tope} al día. Puede ser trabajo normal, por ejemplo al clasificar las denuncias "
             "pendientes.")
    return tuple(correo.Correo(
        tipo="aviso_lecturas", destinatario=email,
        asunto=f"Aviso de Canario: una cuenta ha abierto {lecturas} denuncias hoy",
        cuerpo=(f"La cuenta {cuenta} de {nombre} ha abierto hoy {lecturas} denuncias distintas en Canario.\n\n"
                f"{final}\n\n"
                "Si no lo esperaba, revise en la auditoría qué denuncias ha leído y quién se las asignó, y dé "
                "de baja la cuenta si no es de confianza.")) for email in emails)


def correos_activacion(nombre, emails, cuenta, rol):
    """Un correo por destinatario: la cuenta acaba de activarse con ese rol."""
    return tuple(correo.Correo(
        tipo="aviso_activacion", destinatario=email,
        asunto="Aviso de Canario: se ha activado una cuenta del personal",
        cuerpo=(f"La cuenta {cuenta} de {nombre} se ha activado en Canario con el rol {rol}. Puede ser "
                "una cuenta nueva, reactivada o recuperada.\n\n"
                "Si no lo esperaba, revise en la auditoría quién la invitó o aprobó su solicitud, y dé de "
                "baja la cuenta si no es de confianza.")) for email in emails)
