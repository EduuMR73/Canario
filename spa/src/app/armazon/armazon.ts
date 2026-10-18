import { HttpErrorResponse } from '@angular/common/http';
import { Component, computed, inject, signal } from '@angular/core';
import { Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { ApiPersonal } from '../nucleo/api';
import { textoDeError } from '../nucleo/errores';
import { menuDe } from '../nucleo/permisos';
import { Sesion } from '../nucleo/sesion';
import { nombreRol } from '../nucleo/roles';

// El armazón de las páginas con sesión: la barra con la cuenta, el menú del
// rol y el cierre de la sesión, y el único <main> de esas páginas, donde se
// pintan. Solo se llega aquí con la cuenta cargada (nucleo/permisos.ts,
// permitirPorRol); el @if es para el tipo, no un estado más.
//
// Sin enlace para saltar al menú: el menú son cuatro enlaces, y las páginas
// ya tienen sus regiones (header, nav, main) y su h1, que recibe el foco al
// cambiar de página (WCAG 2.2, 2.4.1, técnicas ARIA11 y H69). Un enlace
// href="#contenido" además no funcionaría aquí: con <base href="/"> lleva a
// "/#contenido", es decir, a otra página.
//
// &ngsp; entre el email y el rol: Angular quita al compilar los textos que
// solo tienen espacios (preserveWhitespaces es false por defecto), y la barra
// decía "admin@empresa.testAdmin", también para un lector de pantalla.
// &ngsp; es su forma de conservar un espacio.
@Component({
  selector: 'app-armazon',
  imports: [RouterLink, RouterLinkActive, RouterOutlet],
  template: `
    @if (sesion.yo(); as yo) {
      <header class="barra">
        <p class="marca">Canario</p>
        <nav aria-label="Principal">
          <ul class="menu">
            @for (entrada of menu(); track entrada.ruta) {
              <li><a [routerLink]="entrada.ruta" routerLinkActive="activo" ariaCurrentWhenActive="page">{{ entrada.texto }}</a></li>
            }
          </ul>
        </nav>
        <p class="quien"><span class="quien-email">{{ yo.email }}</span>&ngsp;<span class="quien-rol">{{ nombreRol(yo.rol) }}</span></p>
        <button type="button" class="secundario" (click)="cerrarSesion()" [attr.aria-disabled]="cerrando() || null">
          {{ cerrando() ? 'Cerrando la sesión...' : 'Cerrar la sesión' }}
        </button>
      </header>
      @if (error(); as texto) {
        <p class="error barra-error" role="alert">{{ texto }}</p>
      }
      <main class="ancho">
        <router-outlet />
      </main>
    }
  `,
})
export class Armazon {
  protected readonly sesion = inject(Sesion);
  private readonly api = inject(ApiPersonal);
  private readonly router = inject(Router);

  readonly menu = computed(() => {
    const yo = this.sesion.yo();
    return yo === null ? [] : menuDe(yo.rol);
  });
  readonly error = signal<string | null>(null);
  // Un cierre cada vez. El botón lleva aria-disabled y no disabled, para no
  // quitarle el foco si el cierre falla (acceso/entrar): la guarda de
  // cerrarSesion() es la barrera.
  readonly cerrando = signal(false);
  readonly nombreRol = nombreRol;

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
