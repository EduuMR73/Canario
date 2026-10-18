import { Component, Injector, inject } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { NavigationEnd, Router, RouterOutlet } from '@angular/router';
import { filter } from 'rxjs';
import { enfocarEncabezado } from './nucleo/foco';

@Component({
  selector: 'app-root',
  imports: [RouterOutlet],
  template: '<router-outlet />',
})
export class App {
  constructor() {
    const injector = inject(Injector);
    // Tras cada cambio de página, el foco va a su h1 (nucleo/foco.ts). En la
    // primera carga no: el navegador ya empieza por el principio.
    inject(Router)
      .events.pipe(
        filter((evento) => evento instanceof NavigationEnd && evento.id > 1),
        takeUntilDestroyed(),
      )
      .subscribe(() => enfocarEncabezado(injector));
  }
}
