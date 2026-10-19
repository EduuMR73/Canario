import { Component } from '@angular/core';

// Leila, una gata carey, dormida sobre un cojín: la ilustración de las listas
// vacías. Decorativa (aria-hidden): el texto de al lado dice lo que pasa.
// Nunca junto a una denuncia.
//
// SVG en la plantilla, como el canario (marca/canario.ts) y por lo mismo. Sin
// clipPath ni id: las manchas ya caen dentro de la cabeza y del cuerpo, y el
// contorno se dibuja encima. Así puede salir dos veces en una página sin
// repetir un id. Los colores, en clases de styles.css: el contorno se aclara
// en el tema oscuro.
@Component({
  selector: 'app-leila',
  template: `
    <svg class="leila" aria-hidden="true" focusable="false" width="260" height="160" viewBox="0 0 260 160">
      <ellipse class="leila-cojin" cx="135" cy="145" rx="112" ry="12" />
      <path class="leila-pelo leila-borde"
            d="M222 112 Q230 146 170 147 Q120 148 98 140 Q96 132 104 131 Q130 137 168 136 Q212 134 210 112 Z" />
      <path class="leila-naranja" d="M150 136.5 Q160 136 170 135.8 L171 146.5 Q160 147 150 147 Z" />
      <ellipse class="leila-pelo" cx="140" cy="105" rx="88" ry="40" />
      <path class="leila-naranja" d="M118 68 Q160 60 186 79 Q172 100 140 95 Q118 88 118 68 Z" />
      <ellipse class="leila-canela" cx="200" cy="114" rx="22" ry="14" />
      <ellipse class="leila-naranja" cx="160" cy="132" rx="20" ry="9" />
      <ellipse class="leila-sin-relleno leila-borde" cx="140" cy="105" rx="88" ry="40" />
      <path class="leila-naranja leila-borde" d="M42 74 L44 44 L66 60 Z" />
      <path class="leila-rosa" d="M48 66 L49 53 L58 61 Z" />
      <path class="leila-pelo leila-borde" d="M78 60 L100 45 L104 74 Z" />
      <path class="leila-rosa" d="M86 60 L98 52 L100 66 Z" />
      <circle class="leila-pelo" cx="72" cy="96" r="38" />
      <path class="leila-naranja" d="M68 58.2 L68 100 Q58 112 44.4 122.1 A38 38 0 0 1 68 58.2 Z" />
      <path class="leila-crema" d="M68 58 Q72 55 76 58 L76 92 Q72 96 68 92 Z" />
      <ellipse class="leila-crema" cx="72" cy="108" rx="17" ry="11" />
      <circle class="leila-sin-relleno leila-borde" cx="72" cy="96" r="38" />
      <ellipse class="leila-crema leila-detalle" cx="59" cy="89" rx="10" ry="7" />
      <ellipse class="leila-crema leila-detalle" cx="85" cy="89" rx="10" ry="7" />
      <path class="leila-ojo" d="M50 89 Q59 95 68 89 M76 89 Q85 95 94 89" />
      <path class="leila-rosa leila-detalle" d="M68.5 101 L75.5 101 L72 105.5 Z" />
      <path class="leila-sin-relleno leila-detalle" d="M72 105.5 Q69 110 65 108 M72 105.5 Q75 110 79 108" />
      <ellipse class="leila-crema leila-borde" cx="74" cy="134" rx="17" ry="8" />
      <ellipse class="leila-pelo leila-borde" cx="58" cy="140" rx="14" ry="7" />
      <ellipse class="leila-naranja leila-borde" cx="90" cy="141" rx="13" ry="6.5" />
      <text class="leila-z" x="112" y="52" font-size="15">z</text>
      <text class="leila-z" x="126" y="38" font-size="19">z</text>
      <text class="leila-z" x="144" y="22" font-size="23">z</text>
    </svg>
  `,
})
export class Leila {}
