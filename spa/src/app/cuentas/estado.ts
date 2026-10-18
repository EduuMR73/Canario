import { Cuenta } from '../nucleo/api-cuentas';

// Lo que la lista de cuentas dice de cada una, a partir de los campos de la
// API (app/personal.py, SQL_LISTAR_USUARIOS). Funciones puras: se prueban sin
// navegador (estado.spec.ts).

// La situación de la cuenta, siempre una. "Desactivada" y no "de baja": una
// cuenta también se desactiva en la recuperación de emergencia
// (docs/threat-model.md, 6.3).
export function situacionDe(cuenta: Cuenta): string {
  if (!cuenta.activo) {
    return 'Desactivada';
  }
  return cuenta.activado ? 'Activa' : 'Sin activar';
}

// Lo que un admin tiene que mirar, además de la situación. La invitación
// abierta es el aviso de una reinvitación (NIST SP 800-63B-4, 4.2.3); el
// camino sin dispositivo de confianza, el bloqueo por intentos fallidos.
export function avisosDe(cuenta: Cuenta): string[] {
  const avisos: string[] = [];
  if (cuenta.invitacion_pendiente) {
    avisos.push('Invitación abierta');
  }
  if (cuenta.camino_sin_confianza_cerrado) {
    avisos.push('Entrada desde navegadores nuevos cerrada: se reabre con una invitación');
  } else if (cuenta.en_espera) {
    avisos.push('Entrada desde navegadores nuevos en espera por intentos fallidos');
  }
  return avisos;
}

// El enlace de activación que el admin entrega a mano. El token va en el
// fragmento, como en el correo (app/solicitudes.py, _enlace): el navegador no
// lo envía al servidor, y la SPA lo saca de la URL al abrirlo
// (nucleo/fragmento.ts).
export function enlaceDeActivacion(origen: string, token: string): string {
  return `${origen}/activacion#${token}`;
}
