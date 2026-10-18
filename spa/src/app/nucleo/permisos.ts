import { HttpErrorResponse } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { CanActivateChildFn, Router } from '@angular/router';
import { Rol, Yo } from './api';
import { Sesion } from './sesion';

// Qué páginas ve cada rol en la SPA. Es solo la interfaz: quien decide es la
// API, que responde 403 a un rol sin permiso en cada petición
// (app/personal.py, ROLES_INSTRUCCION y ROLES_AUDITORIA). Aquí se evita
// enseñar pantallas que solo darían 403.
//
// Denegar por defecto, como la API: una página dentro del armazón que no
// declare sus roles (data.roles) no se abre para nadie. Si alguien la añade
// sin roles, se ve enseguida, en vez de quedar abierta a todos.

export const TODOS: readonly Rol[] = ['admin', 'instructor', 'auditor'];

export interface EntradaMenu {
  ruta: string;
  texto: string;
  roles: readonly Rol[];
}

// El menú del armazón, en este orden. Los roles de cada entrada son los de su
// ruta en app.routes.ts, que los toma de aquí: una sola lista.
export const MENU = {
  inicio: { ruta: '/inicio', texto: 'Inicio', roles: TODOS },
  cuentas: { ruta: '/cuentas', texto: 'Cuentas', roles: ['admin'] },
  solicitudes: { ruta: '/solicitudes', texto: 'Solicitudes', roles: ['admin'] },
  cuenta: { ruta: '/cuenta', texto: 'Mi cuenta', roles: TODOS },
} as const satisfies Record<string, EntradaMenu>;

export function menuDe(rol: Rol): EntradaMenu[] {
  return Object.values(MENU).filter((entrada) => (entrada.roles as readonly Rol[]).includes(rol));
}

// Adónde volver cuando la cuenta no se pudo cargar (ver la página
// NoDisponible). En memoria y no en la URL: un parámetro con una ruta sería
// una redirección que cualquiera podría escribir en un enlace.
@Injectable({ providedIn: 'root' })
export class Reintento {
  destino: string | null = null;
}

export const RUTA_NO_DISPONIBLE = '/no-disponible';

export const permitirPorRol: CanActivateChildFn = async (ruta, estado) => {
  // Todos los inject antes del primer await: después ya no hay contexto de
  // inyección (Angular lanza NG0203).
  const sesion = inject(Sesion);
  const router = inject(Router);
  const reintento = inject(Reintento);
  let yo: Yo;
  try {
    yo = await sesion.cargada();
  } catch (error: unknown) {
    // El 401 ya lo ha resuelto el interceptor (nucleo/renovacion.ts: a
    // /entrar). Cualquier otro fallo (la red, un 503) se explica en su página,
    // con un botón para volver aquí.
    if (error instanceof HttpErrorResponse && error.status === 401) {
      return false;
    }
    reintento.destino = estado.url;
    return router.createUrlTree([RUTA_NO_DISPONIBLE]);
  }
  const roles: readonly Rol[] = ruta.data['roles'] ?? [];
  if (!roles.includes(yo.rol)) {
    return router.createUrlTree([MENU.inicio.ruta]);
  }
  return true;
};
