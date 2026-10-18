import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable, map } from 'rxjs';
import { BASE, Rol } from './api';
import { conSesion } from './contexto';

// Cliente de la administración de cuentas y de las solicitudes de registro
// (app/rutas_personal.py; solo admin, el resto recibe 403). Los ids van en la
// ruta tal como los da la API: un uuid no lleva nada que escapar, y uno que
// no lo sea es un 404 de la API.

// GET /v1/personal/usuarios: la lista explícita de campos de la API.
export interface Cuenta {
  usuario_id: string;
  email: string;
  rol: Rol;
  activo: boolean;
  activado: boolean;
  camino_sin_confianza_cerrado: boolean;
  en_espera: boolean;
  invitacion_pendiente: boolean;
}

// POST /v1/personal/usuarios y .../invitacion. El token es de un solo uso y
// solo lo recibe el admin: no hay correo (docs/threat-model.md, 6.3).
export interface Invitacion {
  usuario_id: string;
  token_invitacion: string;
}

// GET /v1/personal/solicitudes
export interface Solicitud {
  solicitud_id: string;
  email: string;
}

export interface ListadoSolicitudes {
  solicitudes: Solicitud[];
  hay_mas: boolean;
}

@Injectable({ providedIn: 'root' })
export class ApiCuentas {
  private readonly http = inject(HttpClient);

  cuentas(): Observable<Cuenta[]> {
    return this.http.get<{ usuarios: Cuenta[] }>(`${BASE}/usuarios`, conSesion()).pipe(map((r) => r.usuarios));
  }

  invitar(email: string, rol: Rol): Observable<Invitacion> {
    return this.http.post<Invitacion>(`${BASE}/usuarios`, { email, rol }, conSesion());
  }

  reinvitar(usuarioId: string): Observable<Invitacion> {
    return this.http.post<Invitacion>(`${BASE}/usuarios/${usuarioId}/invitacion`, {}, conSesion());
  }

  anularInvitacion(usuarioId: string): Observable<unknown> {
    return this.http.delete(`${BASE}/usuarios/${usuarioId}/invitacion`, conSesion());
  }

  darDeBaja(usuarioId: string): Observable<unknown> {
    return this.http.post(`${BASE}/usuarios/${usuarioId}/baja`, {}, conSesion());
  }

  solicitudes(): Observable<ListadoSolicitudes> {
    return this.http.get<ListadoSolicitudes>(`${BASE}/solicitudes`, conSesion());
  }

  // Sin token en la respuesta: la invitación va solo al email verificado.
  aprobar(solicitudId: string, rol: Rol): Observable<unknown> {
    return this.http.post(`${BASE}/solicitudes/${solicitudId}/aprobacion`, { rol }, conSesion());
  }

  rechazar(solicitudId: string): Observable<unknown> {
    return this.http.delete(`${BASE}/solicitudes/${solicitudId}`, conSesion());
  }
}
