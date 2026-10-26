import { Component, Injector, inject } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { NavigationEnd, NavigationStart, Router, RouterOutlet } from '@angular/router';
import { FocoElegido, enfocarPagina } from './nucleo/foco';

@Component({
  selector: 'app-root',
  imports: [RouterOutlet],
  template: '<router-outlet />',
})
export class App {
  constructor() {
    const injector = inject(Injector);
    const foco = inject(FocoElegido);
    // Tras cada cambio de página, el foco va a su h1 o a lo que la página
    // haya elegido (nucleo/foco.ts). En la primera carga no: el navegador ya
    // empieza por el principio. Al empezar cada navegación se olvida lo que
    // eligiera la página anterior.
    inject(Router)
      .events.pipe(takeUntilDestroyed())
      .subscribe((evento) => {
        if (evento instanceof NavigationStart) {
          foco.porLaPagina = false;
        } else if (evento instanceof NavigationEnd && evento.id > 1) {
          enfocarPagina(injector);
        }
      });
  }
}
