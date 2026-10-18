import { HttpErrorResponse } from '@angular/common/http';
import { Component, inject, signal } from '@angular/core';
import { Router } from '@angular/router';
import { ApiPersonal, Rol } from '../nucleo/api';
import { textoDeError } from '../nucleo/errores';
import { Sesion } from '../nucleo/sesion';

// Página de inicio con sesión: quién es y con qué rol. Las pantallas de cada
// rol llegan en el bloque 6b-3.
//
// Pide /yo al entrar. Sin sesión, el interceptor (nucleo/renovacion.ts) ya
// lleva a /entrar; cualquier otro fallo se explica aquí, con un botón para
// reintentar. Lo que se pinta es solo para mostrar: los permisos los
// comprueba la API en cada petición.

const NOMBRES_ROL: Record<Rol, string> = { admin: 'Admin', instructor: 'Instructor', auditor: 'Auditor' };

@Component({
  selector: 'app-inicio',
  template: `
    <main>
      <h1 tabindex="-1">Inicio</h1>
      @if (sesion.yo(); as yo) {
        @if (yo.invitacion_pendiente) {
          <p class="error" role="alert">Hay una invitación abierta para su cuenta. Si no la ha pedido usted, avise a un admin de su empresa para que la anule.</p>
        }
        <dl class="cuenta">
          <dt>Email</dt>
          <dd>{{ yo.email }}</dd>
          <dt>Rol</dt>
          <dd>{{ nombreRol(yo.rol) }}</dd>
        </dl>
        @if (error(); as texto) {
          <p class="error" role="alert">{{ texto }}</p>
        }
        <button type="button" (click)="cerrarSesion()" [disabled]="cerrando()">
          {{ cerrando() ? 'Cerrando la sesión...' : 'Cerrar la sesión' }}
        </button>
      } @else if (error(); as texto) {
        <p class="error" role="alert">{{ texto }}</p>
        <button type="button" (click)="cargar()">Reintentar</button>
      } @else {
        <p role="status">Cargando su cuenta...</p>
      }
    </main>
  `,
})
export class Inicio {
  protected readonly sesion = inject(Sesion);
  private readonly api = inject(ApiPersonal);
  private readonly router = inject(Router);

  readonly error = signal<string | null>(null);
  readonly cerrando = signal(false);

  constructor() {
    this.cargar();
  }

  cargar(): void {
    this.error.set(null);
    this.sesion.cargar().catch((error: unknown) => {
      // El 401 ya lo ha resuelto el interceptor (a /entrar).
      if (!(error instanceof HttpErrorResponse && error.status === 401)) {
        this.error.set(textoDeError(error));
      }
    });
  }

  nombreRol(rol: Rol): string {
    return NOMBRES_ROL[rol];
  }

  cerrarSesion(): void {
    if (this.cerrando()) {
      return;
    }
    this.cerrando.set(true);
    this.error.set(null);
    this.api.cerrarSesion().subscribe({
      next: () => this.salir(),
      error: (error: unknown) => {
        // Una sesión que ya no vale está cerrada a todos los efectos.
        if (error instanceof HttpErrorResponse && error.status === 401) {
          this.salir();
          return;
        }
        this.cerrando.set(false);
        this.error.set(textoDeError(error));
      },
    });
  }

  private salir(): void {
    this.sesion.olvidar();
    // replaceUrl: "atrás" no vuelve a una página de la sesión cerrada.
    void this.router.navigateByUrl('/entrar', { replaceUrl: true });
  }
}
