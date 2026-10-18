import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { BASE } from './api';
import { conSesion } from './contexto';

// Cliente de la auditoría (app/rutas_personal.py y app/instruccion.py; admin y
// auditor, el instructor recibe 403). Leerla no deja fila: se puede pedir las
// veces que haga falta.

// Una fila tal como la da la API. Los emails los resuelve el servidor, porque
// el auditor no puede leer las cuentas (403 en /usuarios): null si quien
// actúa no es una cuenta ('plataforma', 'sistema') o si la acción no es sobre
// una cuenta.
export interface FilaAuditoria {
  secuencia: number;
  fecha: string;
  actor: string;
  actor_email: string | null;
  accion: string;
  objeto_id: string | null;
  destino_id: string | null;
  cuenta_email: string | null;
}

// anterior: lo que se pasa como antes para la página siguiente, hacia el
// principio; null si no hay más.
export interface PaginaAuditoria {
  filas: FilaAuditoria[];
  anterior: number | null;
}

export interface Verificacion {
  cadena_intacta: boolean;
  primera_rota: number | null;
}

@Injectable({ providedIn: 'root' })
export class ApiAuditoria {
  private readonly http = inject(HttpClient);

  // Desde lo más reciente: sin antes, la última página; con antes, la de
  // secuencias menores. Las filas que llegan mientras tanto no desplazan las
  // páginas (la API pagina por la secuencia).
  recientes(antes: number | null): Observable<PaginaAuditoria> {
    const params = antes === null ? new HttpParams() : new HttpParams().set('antes', antes);
    return this.http.get<PaginaAuditoria>(`${BASE}/auditoria/recientes`, { ...conSesion(), params });
  }

  // Recorre la cadena entera de la empresa: una acción explícita, aparte del
  // listado.
  verificar(): Observable<Verificacion> {
    return this.http.get<Verificacion>(`${BASE}/auditoria/verificacion`, conSesion());
  }
}
