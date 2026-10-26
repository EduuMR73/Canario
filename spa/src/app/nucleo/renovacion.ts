import { HttpClient, HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { Injectable, InjectionToken, inject } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, firstValueFrom, from, map, switchMap, throwError } from 'rxjs';
import { Caducidad, tiemposDe } from './caducidad';
import { RENOVABLE } from './contexto';
import { Sesion } from './sesion';

// Renovación de la sesión del personal (docs/threat-model.md, 6.3).
//
// El JWT de acceso dura 5 minutos (app/tokens.py) y viaja en una cookie
// HttpOnly que ningún script lee. Cuando caduca, la API responde 401 con
// WWW-Authenticate: Bearer; entonces se renueva UNA vez y se repite la
// petición UNA vez. Repetirla es seguro aunque cambie algo (un POST): ese 401
// sale de la dependencia _sesion de app/rutas_personal.py, antes de que la
// ruta haga nada.
//
// Solo se renueva cuando hace falta, sin temporizador: un temporizador
// mantendría viva la sesión de una pestaña olvidada y se saltaría la
// caducidad por inactividad de 15 minutos, que se mide entre renovaciones.
// La cuenta atrás que avisa antes del cierre (caducidad.ts) tampoco renueva:
// solo lo hace la persona, con "Seguir conectado".

// Solo las peticiones con la marca RENOVABLE (contexto.ts) pasan por aquí.

export const RUTA_RENOVACION = '/v1/personal/sesiones/renovacion';

// El token de renovación cambia en cada uso y presentar uno ya usado revoca la
// sesión entera (app/personal.py, renovar): dos renovaciones simultáneas con
// el mismo token cierran la sesión. Las pestañas comparten las cookies, así
// que basta con que renueven de una en una: la segunda ya envía el token
// nuevo. Web Locks lo garantiza entre pestañas del mismo origen. Está en
// Chrome 69, Firefox 96 y Safari 15.4 (MDN), anteriores a los navegadores con
// Fetch Metadata que exige la API; si faltara, falla de forma visible.
export type Cerrojo = <T>(nombre: string, trabajo: () => Promise<T>) => Promise<T>;

export const NOMBRE_CERROJO = 'canario-renovacion';

function cerrojoDelNavegador<T>(nombre: string, trabajo: () => Promise<T>): Promise<T> {
  if (!('locks' in navigator)) {
    return Promise.reject(new Error('el navegador no tiene Web Locks: no puede renovar la sesión sin riesgo'));
  }
  return navigator.locks.request(nombre, trabajo);
}

export const CERROJO = new InjectionToken<Cerrojo>('CERROJO', {
  providedIn: 'root',
  factory: () => cerrojoDelNavegador,
});

// Una renovación colgada retendría el cerrojo y las demás pestañas esperarían
// sin fin. Por debajo de los 30 s de escritura de Caddy (proxy/Caddyfile). Si
// se corta aquí pero la API ya había rotado el token, la siguiente renovación
// presenta el viejo y la sesión se cierra: un fallo visible, no silencioso.
const ESPERA_RENOVACION_MS = 15000;

@Injectable({ providedIn: 'root' })
export class Renovador {
  private readonly http = inject(HttpClient);
  private readonly cerrojo = inject(CERROJO);
  private readonly caducidad = inject(Caducidad);
  // Dentro de una pestaña, las peticiones que reciben 401 a la vez comparten
  // una sola renovación.
  private enCurso: Promise<void> | null = null;

  // La respuesta trae los segundos de la sesión renovada: la cuenta atrás de
  // esta pestaña y la de las demás vuelven a empezar (caducidad.ts).
  renovar(): Promise<void> {
    this.enCurso ??= this.cerrojo(NOMBRE_CERROJO, () =>
      firstValueFrom(this.http.post(RUTA_RENOVACION, {}, { timeout: ESPERA_RENOVACION_MS }).pipe(map(tiemposDe))),
    )
      .then((tiempos) => this.caducidad.actualizar(tiempos))
      .finally(() => {
        this.enCurso = null;
      });
    return this.enCurso;
  }
}

export function sesionCaducada(error: unknown): boolean {
  // El 401 de una sesión que no vale es el único con esta cabecera
  // (app/rutas_personal.py, instalar_errores).
  return error instanceof HttpErrorResponse && error.status === 401
    && error.headers.get('WWW-Authenticate') === 'Bearer';
}

export const renovarSesion: HttpInterceptorFn = (peticion, siguiente) => {
  if (!peticion.context.get(RENOVABLE)) {
    return siguiente(peticion);
  }
  const renovador = inject(Renovador);
  const sesion = inject(Sesion);
  const caducidad = inject(Caducidad);
  const router = inject(Router);
  return siguiente(peticion).pipe(
    catchError((error: unknown) => {
      if (!sesionCaducada(error)) {
        return throwError(() => error);
      }
      return from(renovador.renovar()).pipe(
        catchError((fallo: unknown) => {
          // Sin sesión que renovar: a la página de entrada. Otros fallos (la
          // red, un 503) llegan a la página tal cual, que los explica. Con la
          // cuenta cargada, la persona estaba dentro y /entrar le dice por
          // qué ya no lo está; sin ella (una pestaña recién abierta con una
          // cookie vieja), no había nada que cerrar.
          if (sesionCaducada(fallo)) {
            if (sesion.yo() !== null) {
              caducidad.anunciarCierre();
            }
            sesion.olvidar();
            void router.navigateByUrl('/entrar');
          }
          return throwError(() => fallo);
        }),
        // siguiente() no vuelve a pasar por este interceptor: un segundo 401
        // llega a la página como error, sin otra renovación ni un bucle.
        switchMap(() => siguiente(peticion)),
      );
    }),
  );
};
