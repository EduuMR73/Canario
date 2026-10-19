import { Component } from '@angular/core';

// Leila, una gata carey con su collar rosa, dormida sobre un cojín: la
// ilustración de las listas vacías. Decorativa (aria-hidden): el texto de al
// lado dice lo que pasa. Nunca junto a una denuncia.
//
// SVG en la plantilla, como el canario (marca/canario.ts) y por lo mismo. Sin
// clipPath ni id: las manchas ya caen dentro de la cabeza y del cuerpo, y el
// contorno se dibuja encima. Así puede salir dos veces en una página sin
// repetir un id. Los colores, en clases de styles.css: el contorno se aclara
// en el tema oscuro; el collar y las líneas de la cara no, porque van sobre la
// crema y el rosa, no sobre el fondo.
@Component({
  selector: 'app-leila',
  template: `
    <svg class="leila" aria-hidden="true" focusable="false" width="260" height="160" viewBox="0 0 260 160">
      <ellipse class="leila-cojin" cx="135" cy="147" rx="110" ry="10" />
      <path class="leila-pelo leila-borde"
            d="M224 118 Q232 147 172 147 Q124 148 100 142 Q98 136 104 135.5 Q130 139.5 170 139 Q216 138 216 118 Z" />
      <path class="leila-naranja" d="M150 139.4 Q158 139.2 166 139.1 L166.5 146.7 Q158 146.9 150 146.9 Z" />
      <ellipse class="leila-pelo" cx="148" cy="112" rx="84" ry="29" />
      <path class="leila-naranja" d="M124 88 Q160 80 186 92 Q172 108 142 105 Q122 100 124 88 Z" />
      <ellipse class="leila-canela" cx="205" cy="118" rx="18" ry="10" />
      <ellipse class="leila-naranja" cx="160" cy="133" rx="18" ry="6" />
      <ellipse class="leila-sin-relleno leila-borde" cx="148" cy="112" rx="84" ry="29" />
      <ellipse class="leila-crema leila-borde-fino" cx="70" cy="133" rx="14" ry="6" />
      <path class="leila-naranja leila-borde" d="M45 82 L46 52 L65 69 Z" />
      <path class="leila-rosa" d="M50 75 L50 60 L59 70 Z" />
      <path class="leila-pelo leila-borde" d="M75 69.6 L94 51 L96 81 Z" />
      <path class="leila-rosa" d="M81 70 L91 61 L93 74.5 Z" />
      <circle class="leila-pelo" cx="70" cy="99" r="31" />
      <path class="leila-naranja" d="M66.7 68.2 L66.7 102 Q58.5 111.8 47.5 120.3 A31 31 0 0 1 66.7 68.2 Z" />
      <path class="leila-crema" d="M66.7 68.5 Q70 66 73.3 68.5 L73.3 96 Q70 99 66.7 96 Z" />
      <ellipse class="leila-crema" cx="70" cy="108.8" rx="14" ry="9" />
      <circle class="leila-sin-relleno leila-borde" cx="70" cy="99" r="31" />
      <ellipse class="leila-ojo-fondo" cx="59.4" cy="93.3" rx="8.2" ry="5.7" />
      <ellipse class="leila-ojo-fondo" cx="80.6" cy="93.3" rx="8.2" ry="5.7" />
      <path class="leila-ojo" d="M51.2 93.3 Q59.4 98 67.6 93.3 M72.4 93.3 Q80.6 98 88.8 93.3" />
      <path class="leila-nariz" d="M67.1 103.1 L72.9 103.1 L70 106.8 Z" />
      <path class="leila-boca" d="M70 106.8 Q67.5 110.5 64.3 108.8 M70 106.8 Q72.5 110.5 75.7 108.8" />
      <path class="leila-collar-borde" d="M52 124.2 Q70 133.5 88 124.2" />
      <path class="leila-collar" d="M52 124.2 Q70 133.5 88 124.2" />
      <ellipse class="leila-pelo leila-borde-fino" cx="56" cy="142" rx="12" ry="5.5" />
      <ellipse class="leila-naranja leila-borde-fino" cx="86" cy="143" rx="11" ry="5.5" />
      <path class="leila-anilla" d="M70 130.5 L70 133" />
      <circle class="leila-chapa" cx="70" cy="136.6" r="3.6" />
      <text class="leila-z" x="108" y="58" font-size="15">z</text>
      <text class="leila-z" x="122" y="44" font-size="19">z</text>
      <text class="leila-z" x="140" y="28" font-size="23">z</text>
    </svg>
  `,
})
export class Leila {}
