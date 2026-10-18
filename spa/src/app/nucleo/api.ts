import { HttpClient, HttpContext } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { RENOVABLE } from './contexto';

// Cliente de la API del personal (app/rutas_personal.py). Es la única pieza
// que conoce las rutas y la forma de los cuerpos: las páginas no llaman a
// HttpClient. Las peticiones van al mismo origen (connect-src 'self'), así
// que el navegador añade solo las cookies __Host- de la sesión, y también
// Sec-Fetch-Site y Origin, que son la defensa CSRF de la API. Ningún token
// pasa por aquí: los guarda y los envía el navegador.

const BASE = '/v1/personal';

// Las rutas que usan la sesión llevan la marca RENOVABLE (contexto.ts).
function conSesion(): { context: HttpContext } {
  return { context: new HttpContext().set(RENOVABLE, true) };
}

export type Rol = 'admin' | 'instructor' | 'auditor';

// GET /v1/personal/yo
export interface Yo {
  usuario_id: string;
  email: string;
  rol: Rol;
  invitacion_pendiente: boolean;
}

export interface DatosLogin {
  empresa: string;
  email: string;
  contrasena: string;
  codigo_totp: string;
}

// POST /v1/personal/activacion
export interface ActivacionPendiente {
  secreto_totp: string;
  uri_totp: string;
}

// POST /v1/personal/registro
export interface RespuestaRegistro {
  mensaje: string;
}

@Injectable({ providedIn: 'root' })
export class ApiPersonal {
  private readonly http = inject(HttpClient);

  // En el navegador el token de dispositivo va en su cookie: el cuerpo no lo
  // lleva (la API respondería 422).
  iniciarSesion(datos: DatosLogin): Observable<unknown> {
    return this.http.post(`${BASE}/sesiones`, datos);
  }

  activar(token: string, contrasena: string): Observable<ActivacionPendiente> {
    return this.http.post<ActivacionPendiente>(`${BASE}/activacion`, { token, contrasena });
  }

  confirmarActivacion(token: string, codigoTotp: string): Observable<unknown> {
    return this.http.post(`${BASE}/activacion/confirmar`, { token, codigo_totp: codigoTotp });
  }

  solicitarRegistro(empresa: string, email: string): Observable<RespuestaRegistro> {
    return this.http.post<RespuestaRegistro>(`${BASE}/registro`, { empresa, email });
  }

  verificarRegistro(token: string): Observable<unknown> {
    return this.http.post(`${BASE}/registro/verificacion`, { token });
  }

  yo(): Observable<Yo> {
    return this.http.get<Yo>(`${BASE}/yo`, conSesion());
  }

  cerrarSesion(): Observable<unknown> {
    return this.http.delete(`${BASE}/sesiones/actual`, conSesion());
  }
}
