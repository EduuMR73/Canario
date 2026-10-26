import { HttpErrorResponse } from '@angular/common/http';
import { Component, ElementRef, computed, effect, inject, signal, untracked, viewChild } from '@angular/core';
import { Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { Canario } from '../marca/canario';
import { ApiPersonal } from '../nucleo/api';
import { Caducidad } from '../nucleo/caducidad';
import { textoDeError } from '../nucleo/errores';
import { menuDe } from '../nucleo/permisos';
import { Renovador, sesionCaducada } from '../nucleo/renovacion';
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
//
// El aviso de la caducidad (nucleo/caducidad.ts) es un <dialog> nativo con
// showModal(): el navegador lleva el foco dentro, lo encierra ahí, deja el
// resto de la página inerte y lo anuncia como diálogo, sin ARIA a mano. Escape
// lo cierra sin renovar: la cuenta atrás sigue y, si llega a cero, la sesión
// se cierra igual. Va en el armazón porque solo las páginas con sesión tienen
// algo que avisar.
@Component({
  selector: 'app-armazon',
  imports: [Canario, RouterLink, RouterLinkActive, RouterOutlet],
  template: `
    @if (sesion.yo(); as yo) {
      <header class="barra">
        <p class="marca"><app-canario />Canario</p>
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
      <dialog #aviso class="tarjeta aviso-sesion" aria-labelledby="aviso-sesion-titulo"
              aria-describedby="aviso-sesion-texto">
        @if (caducidad.estado() === 'aviso_final') {
          <h2 id="aviso-sesion-titulo">Su sesión va a terminar</h2>
          <p id="aviso-sesion-texto">Su sesión llega a las 8 horas y se cerrará en menos de 2 minutos. Guarde lo que esté haciendo.</p>
          <p class="acciones">
            <button type="button" autofocus (click)="cerrarAviso()">Entendido</button>
            <button type="button" class="secundario" (click)="cerrarAviso(); cerrarSesion()">Cerrar la sesión</button>
          </p>
        } @else {
          <h2 id="aviso-sesion-titulo">¿Sigue ahí?</h2>
          <p id="aviso-sesion-texto">Por inactividad, su sesión se cerrará en menos de 2 minutos.</p>
          @if (errorAviso(); as texto) {
            <p class="error" role="alert">{{ texto }}</p>
          }
          <p class="acciones">
            <button type="button" autofocus (click)="seguir()" [attr.aria-disabled]="renovando() || null">
              {{ renovando() ? 'Renovando la sesión...' : 'Seguir conectado' }}
            </button>
            <button type="button" class="secundario" (click)="cerrarAviso(); cerrarSesion()">Cerrar la sesión</button>
          </p>
        }
      </dialog>
    }
  `,
})
export class Armazon {
  protected readonly sesion = inject(Sesion);
  protected readonly caducidad = inject(Caducidad);
  private readonly api = inject(ApiPersonal);
  private readonly renovador = inject(Renovador);
  private readonly router = inject(Router);
  private readonly dialogo = viewChild<ElementRef<HTMLDialogElement>>('aviso');

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
  // Una renovación cada vez, como el cierre: aria-disabled y la guarda de
  // seguir().
  readonly renovando = signal(false);
  readonly errorAviso = signal<string | null>(null);

  constructor() {
    // El diálogo sigue al estado: se abre al llegar el aviso y se cierra si
    // otra pestaña renueva o la sesión se renueva por una petición.
    effect(() => {
      const estado = this.caducidad.estado();
      const dialogo = this.dialogo()?.nativeElement;
      if (dialogo === undefined) {
        return;
      }
      const avisando = estado === 'aviso' || estado === 'aviso_final';
      if (avisando && !dialogo.open) {
        untracked(() => this.errorAviso.set(null));
        dialogo.showModal();
      } else if (!avisando && dialogo.open) {
        dialogo.close();
      }
    });
    // Al vencer, la cuenta se olvida y /entrar dice por qué
    // (nucleo/caducidad.ts, tomarAviso). No se llama a la API: el servidor ya
    // la cerró, y el acceso caducó hace al menos 10 minutos (5 de JWT frente
    // a 15 de inactividad), así que DELETE /sesiones/actual daría 401.
    effect(() => {
      if (this.caducidad.estado() === 'vencida') {
        untracked(() => this.salir());
      }
    });
  }

  // "Seguir conectado": la única renovación que no viene de un 401, y solo
  // porque la persona la pide (nucleo/renovacion.ts). Va por el mismo cerrojo
  // que las demás.
  seguir(): void {
    if (this.renovando()) {
      return;
    }
    this.renovando.set(true);
    this.errorAviso.set(null);
    this.renovador.renovar().then(
      () => this.renovando.set(false),
      (error: unknown) => {
        this.renovando.set(false);
        // La sesión ya no vale (se cerró en el servidor justo antes): como
        // cualquier otro 401 sin renovación.
        if (sesionCaducada(error)) {
          this.caducidad.anunciarCierre();
          this.salir();
          return;
        }
        this.errorAviso.set(textoDeError(error));
      },
    );
  }

  // Cerrar la sesión desde el aviso cierra antes el diálogo: si el cierre
  // fallara, su error sale en la barra, que con el diálogo abierto estaría
  // inerte y tapada.
  cerrarAviso(): void {
    this.dialogo()?.nativeElement.close();
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
