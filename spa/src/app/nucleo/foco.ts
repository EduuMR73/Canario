import { DOCUMENT, Injectable, Injector, afterNextRender } from '@angular/core';

// La página que se está abriendo ha elegido ella dónde va el foco. Tras cada
// cambio de página el foco va al h1 (app.ts, enfocarPagina), pero una página
// puede tener algo que debe leerse antes (el aviso de una sesión cerrada en
// /entrar): entonces decide ella. Se declara y no se deduce del DOM, porque
// los dos afterNextRender no tienen un orden garantizado entre sí y el último
// ganaría. app.ts lo borra al empezar cada navegación: lo que una página elija
// después, tras una acción, no afecta a la siguiente.
@Injectable({ providedIn: 'root' })
export class FocoElegido {
  porLaPagina = false;
}

// Lleva el foco al encabezado principal de lo que se acaba de pintar. En una
// SPA, cambiar de página o de paso no mueve el foco: quien navega con
// teclado o con lector de pantalla se quedaría en un botón que ya no existe
// (WCAG 2.2, 2.4.3 Focus Order). Los encabezados que lo reciben llevan
// tabindex="-1": se enfocan por código, pero no entran en el orden del
// tabulador.
export function enfocarEncabezado(injector: Injector, selector = 'main h1'): void {
  injector.get(FocoElegido).porLaPagina = true;
  afterNextRender(() => injector.get(DOCUMENT).querySelector<HTMLElement>(selector)?.focus(), { injector });
}

// El foco tras un cambio de página (app.ts): el h1 de la página nueva, salvo
// que ella haya elegido otro destino mientras se creaba.
export function enfocarPagina(injector: Injector): void {
  if (injector.get(FocoElegido).porLaPagina) {
    return;
  }
  afterNextRender(() => injector.get(DOCUMENT).querySelector<HTMLElement>('main h1')?.focus(), { injector });
}
