import { Component, computed, input } from '@angular/core';
import { avisoInvisibles, segmentar } from './invisibles';

// Un texto que escribe alguien de fuera (el denunciante, anónimo y sin
// cuenta) y que lee el personal con su sesión abierta: el de la denuncia y el
// de cada mensaje. Es el único sitio de la SPA que lo pinta.
//
// Siempre por interpolación ({{ }}), que Angular inserta como texto: un <img>
// o un <script> en la denuncia salen escritos tal cual y no crean ningún
// elemento. Nunca [innerHTML]: aunque el sanitizador quite los atributos
// peligrosos, deja etiquetas como <img>, y la CSP y Trusted Types serían la
// única barrera (tests/security/verificar_spa.py, m, prueba exactamente ese
// mutante).
//
// Los caracteres invisibles que reordenan o esconden texto (invisibles.ts) se
// pintan como una marca visible, con un aviso encima que dice cuántos hay. El
// aviso es texto estático, unido al párrafo con aria-describedby, y no una
// región viva: sale con el expediente, tras pulsar un botón, y una región viva
// creada a la vez que su texto puede no anunciarse.
//
// El @for va en una sola línea y sin espacios entre bloques: con white-space:
// pre-wrap, cualquier espacio de la plantilla se vería dentro del texto.

let siguiente = 0;

@Component({
  selector: 'app-texto-libre',
  host: { class: 'bloque-texto-libre' },
  template: `
    @if (segmentado().invisibles > 0) {
      <p class="aviso" [id]="idAviso">{{ aviso() }}</p>
    }
    <p class="texto-libre" dir="auto" [attr.id]="idTexto()" [attr.aria-describedby]="segmentado().invisibles > 0 ? idAviso : null">@for (segmento of segmentado().segmentos; track $index) {@if (segmento.marca === null) {<ng-container>{{ segmento.valor }}</ng-container>} @else {<span class="invisible-marcado" [attr.title]="segmento.codigos">{{ segmento.marca }}</span>}}</p>
  `,
})
export class TextoLibre {
  readonly texto = input.required<string>();
  // El id del párrafo, si la página lo necesita (el texto de la denuncia).
  readonly idTexto = input<string | null>(null);

  readonly idAviso = `aviso-invisibles-${++siguiente}`;
  readonly segmentado = computed(() => segmentar(this.texto()));
  readonly aviso = computed(() => avisoInvisibles(this.segmentado().invisibles));
}
