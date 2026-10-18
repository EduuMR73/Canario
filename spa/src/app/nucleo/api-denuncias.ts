import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { BASE } from './api';
import { conSesion } from './contexto';

// Cliente de la instrucción de denuncias (app/rutas_personal.py y
// app/instruccion.py; admin e instructor, el auditor recibe 403).
//
// El id de una denuncia puede venir de la URL de la SPA (/denuncias/:id), es
// decir, de un enlace que cualquiera puede escribir. El router de Angular
// decodifica cada segmento (decodeURIComponent), así que /denuncias/..%2Fusuarios
// llega aquí como "../usuarios", y el navegador normaliza
// /v1/personal/denuncias/../usuarios a /v1/personal/usuarios: la petición iría
// a otra ruta de la API en nombre de quien pulsa (Client-Side Path Traversal,
// CWE-23). Escapar el id no basta: encodeURIComponent('..') sigue siendo '..'.
// Por eso ningún id llega a una ruta sin pasar por rutaDenuncia, que solo
// admite la forma exacta de un uuid tal como lo da la API. La ruta de la SPA
// comprueba lo mismo antes de abrir la página (app.routes.ts); esta es la
// barrera que no depende de ella.

const PATRON_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export function esIdDenuncia(texto: string): boolean {
  return PATRON_ID.test(texto);
}

// Falla de forma visible: un id que no es un uuid es un error del código que
// llama, no un caso que se pueda atender.
function rutaDenuncia(id: string): string {
  if (!esIdDenuncia(id)) {
    throw new Error('id de denuncia no valido');
  }
  return `${BASE}/denuncias/${id}`;
}

export type Estado = 'nueva' | 'en_instruccion' | 'resuelta' | 'archivada' | 'inadmitida';
export type EstadoDestino = Exclude<Estado, 'nueva'> | 'no_veraz';

// GET /v1/personal/denuncias: metadatos, nunca contenido.
export interface FilaDenuncia {
  denuncia_id: string;
  fecha: string;
  estado: Estado;
  asignada_a: string | null;
  // null sin asignar; false si la cuenta asignada ya no está activa.
  asignada_activa: boolean | null;
}

export interface PaginaDenuncias {
  denuncias: FilaDenuncia[];
  siguiente: string | null;
}

export interface Mensaje {
  secuencia: number;
  fecha: string;
  autor: 'denunciante' | 'personal';
  autor_id: string | null;
  texto: string;
}

// GET /v1/personal/denuncias/{id}
export interface Expediente {
  denuncia_id: string;
  fecha: string;
  estado: Estado;
  categoria: string;
  texto: string;
  mensajes: Mensaje[];
  lecturas: { hoy: number; tope: number };
}

// POST /v1/personal/denuncias/{id}/mensajes
export interface MensajeEnviado {
  secuencia: number;
  fecha: string;
}

@Injectable({ providedIn: 'root' })
export class ApiDenuncias {
  private readonly http = inject(HttpClient);

  // El cursor es opaco: se devuelve tal como llegó (HttpParams lo escapa).
  listar(estado: Estado | null, cursor: string | null): Observable<PaginaDenuncias> {
    let params = new HttpParams();
    if (estado !== null) {
      params = params.set('estado', estado);
    }
    if (cursor !== null) {
      params = params.set('cursor', cursor);
    }
    return this.http.get<PaginaDenuncias>(`${BASE}/denuncias`, { ...conSesion(), params });
  }

  // Cada llamada deja una fila en la auditoría y cuenta para el tope de
  // lecturas de la cuenta (app/instruccion.py): solo por una acción explícita
  // de la persona (denuncias/expediente.ts).
  leer(id: string): Observable<Expediente> {
    return this.http.get<Expediente>(rutaDenuncia(id), conSesion());
  }

  enviarMensaje(id: string, texto: string): Observable<MensajeEnviado> {
    return this.http.post<MensajeEnviado>(`${rutaDenuncia(id)}/mensajes`, { texto }, conSesion());
  }

  // Sin mensaje, el campo no va: la API distingue "sin mensaje" de un texto.
  cambiarEstado(id: string, estado: EstadoDestino, mensaje: string | null): Observable<unknown> {
    const cuerpo = mensaje === null ? { estado } : { estado, mensaje };
    return this.http.post(`${rutaDenuncia(id)}/estado`, cuerpo, conSesion());
  }

  asignar(id: string, usuarioId: string): Observable<unknown> {
    return this.http.put(`${rutaDenuncia(id)}/asignacion`, { usuario_id: usuarioId }, conSesion());
  }
}
