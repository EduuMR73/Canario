import { FilaAuditoria, Verificacion } from '../nucleo/api-auditoria';

// Lo que la pantalla de auditoría dice de cada fila. Funciones puras: se
// prueban sin navegador (textos.spec.ts).

type Objeto = 'cuenta' | 'denuncia' | 'solicitud';

// Cada acción que escribe la API, con su nombre y sobre qué actúa su
// objeto_id. Copia literal de las constantes ACCION_* de app/personal.py,
// app/solicitudes.py y app/instruccion.py, de los estados destino
// (TRANSICIONES) y de las funciones de db/init/04_supresion.sql y
// 05_redaccion.sql. Una acción que no esté aquí se enseña tal cual, con sus
// ids: se nota, no se esconde.
const ACCIONES: Record<string, { nombre: string; objeto: Objeto }> = {
  acceso: { nombre: 'Entrada', objeto: 'cuenta' },
  activacion: { nombre: 'Activación de la cuenta', objeto: 'cuenta' },
  cambio_contrasena: { nombre: 'Cambio de contraseña', objeto: 'cuenta' },
  invitacion: { nombre: 'Invitación', objeto: 'cuenta' },
  baja: { nombre: 'Baja', objeto: 'cuenta' },
  anulacion_invitacion: { nombre: 'Anulación de la invitación', objeto: 'cuenta' },
  invitacion_admin_plataforma: { nombre: 'Invitación del primer admin', objeto: 'cuenta' },
  reinvitacion_admin_plataforma: { nombre: 'Nueva invitación del primer admin', objeto: 'cuenta' },
  aprobacion_registro: { nombre: 'Aprobación de una solicitud de registro', objeto: 'cuenta' },
  rechazo_registro: { nombre: 'Rechazo de una solicitud de registro', objeto: 'solicitud' },
  lectura_denuncia: { nombre: 'Lectura', objeto: 'denuncia' },
  mensaje_personal: { nombre: 'Mensaje al denunciante', objeto: 'denuncia' },
  asignacion: { nombre: 'Asignación', objeto: 'denuncia' },
  estado_en_instruccion: { nombre: 'Cambio de estado a En instrucción', objeto: 'denuncia' },
  estado_resuelta: { nombre: 'Cambio de estado a Resuelta', objeto: 'denuncia' },
  estado_archivada: { nombre: 'Cambio de estado a Archivada', objeto: 'denuncia' },
  estado_inadmitida: { nombre: 'Cambio de estado a Inadmitida', objeto: 'denuncia' },
  estado_no_veraz: { nombre: 'Declaración de no veraz', objeto: 'denuncia' },
  redaccion_denuncia: { nombre: 'Redacción del texto de la denuncia', objeto: 'denuncia' },
  redaccion_mensaje: { nombre: 'Redacción de un mensaje', objeto: 'denuncia' },
  supresion_art32: { nombre: 'Supresión a los tres meses sin investigar (art. 32.4)', objeto: 'denuncia' },
  supresion_art26: { nombre: 'Supresión a los diez años (art. 26.2)', objeto: 'denuncia' },
  supresion_art32_3: { nombre: 'Supresión por no veraz (art. 32.3)', objeto: 'denuncia' },
};

function accionDe(accion: string): { nombre: string; objeto: Objeto } | undefined {
  return Object.hasOwn(ACCIONES, accion) ? ACCIONES[accion] : undefined;
}

export function nombreAccion(accion: string): string {
  return accionDe(accion)?.nombre ?? accion;
}

const PREFIJO_PERSONAL = 'personal:';

// Quién actuó. Si la cuenta no se resolviera, se enseña su id: nunca un
// hueco en silencio.
export function quienActua(fila: FilaAuditoria): string {
  if (fila.actor === 'plataforma') {
    return 'Plataforma';
  }
  if (fila.actor === 'sistema') {
    return 'Sistema';
  }
  if (fila.actor.startsWith(PREFIJO_PERSONAL)) {
    return fila.actor_email ?? fila.actor.slice(PREFIJO_PERSONAL.length);
  }
  return fila.actor;
}

// Sobre qué actuó. La denuncia va como texto, sin enlace: el auditor no puede
// abrirla, y para un admin abrirla deja una lectura en la auditoría; eso se
// hace desde Denuncias, a propósito.
export function sobreQue(fila: FilaAuditoria): string {
  const objeto = fila.objeto_id ?? '';
  switch (accionDe(fila.accion)?.objeto) {
    case 'cuenta':
      return fila.cuenta_email ?? `Cuenta ${objeto}`;
    case 'solicitud':
      return `Solicitud ${objeto}`;
    case 'denuncia':
      if (fila.accion === 'asignacion') {
        return `Denuncia ${objeto}, a ${fila.cuenta_email ?? `la cuenta ${fila.destino_id ?? ''}`}`;
      }
      return `Denuncia ${objeto}`;
    default:
      return [fila.objeto_id, fila.destino_id].filter((id) => id !== null).join(', ');
  }
}

export function textoCadena(verificacion: Verificacion): string {
  if (verificacion.cadena_intacta) {
    return 'La cadena está intacta: ninguna fila se ha cambiado, borrado ni insertado.';
  }
  return `La cadena se rompe en la fila nº ${verificacion.primera_rota}: desde ahí, el registro no es fiable ` +
    '(alguna fila se ha cambiado, borrado o insertado). Avise al responsable del sistema.';
}

export function textoCargadas(cuantas: number): string {
  return cuantas === 1 ? 'Se ha cargado 1 fila más.' : `Se han cargado ${cuantas} filas más.`;
}
