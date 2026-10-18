import { DOCUMENT, Injector, afterNextRender } from '@angular/core';

// Lleva el foco al encabezado principal de lo que se acaba de pintar. En una
// SPA, cambiar de página o de paso no mueve el foco: quien navega con
// teclado o con lector de pantalla se quedaría en un botón que ya no existe
// (WCAG 2.2, 2.4.3 Focus Order). Los encabezados que lo reciben llevan
// tabindex="-1": se enfocan por código, pero no entran en el orden del
// tabulador.
export function enfocarEncabezado(injector: Injector, selector = 'main h1'): void {
  afterNextRender(() => injector.get(DOCUMENT).querySelector<HTMLElement>(selector)?.focus(), { injector });
}
