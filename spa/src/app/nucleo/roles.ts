import { Rol } from './api';

// El nombre de cada rol para la persona. Lo usan el armazón, el inicio y las
// pantallas de cuentas y solicitudes.
export const NOMBRES_ROL: Record<Rol, string> = { admin: 'Admin', instructor: 'Instructor', auditor: 'Auditor' };

export function nombreRol(rol: Rol): string {
  return NOMBRES_ROL[rol];
}
