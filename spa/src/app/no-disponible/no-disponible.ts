import { Component, inject } from '@angular/core';
import { Router } from '@angular/router';
import { Leila } from '../marca/leila';
import { Reintento } from '../nucleo/permisos';

// La cuenta no se pudo cargar por un fallo que no es de la sesión (la red, un
// 503): nucleo/permisos.ts trae aquí en vez de dejar la página en blanco. El
// botón vuelve a la página que se pedía y, con ella, a la comprobación del
// rol. Sin sesión (401) no se llega aquí: el interceptor lleva a /entrar.
//
// Fuera del armazón, como la 404: se presenta como las páginas de acceso,
// con Leila (decorativa) donde llevan el canario.
@Component({
  selector: 'app-no-disponible',
  imports: [Leila],
  template: `
    <main class="acceso">
      <app-leila />
      <h1 tabindex="-1">No se ha podido cargar su cuenta</h1>
      <p class="error" role="alert">No hay conexión con el servidor o el servicio no está disponible ahora mismo. Compruebe la red e inténtelo de nuevo.</p>
      <button type="button" (click)="reintentar()">Reintentar</button>
    </main>
  `,
})
export class NoDisponible {
  private readonly router = inject(Router);
  private readonly reintento = inject(Reintento);

  reintentar(): void {
    const destino = this.reintento.destino ?? '/inicio';
    this.reintento.destino = null;
    void this.router.navigateByUrl(destino);
  }
}
