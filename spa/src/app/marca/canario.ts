import { Component } from '@angular/core';

// El canario, logo de Canario. Decorativo (aria-hidden): siempre va junto al
// nombre o a un título que ya lo dicen.
//
// SVG en la plantilla, como el QR (acceso/activacion): Angular crea cada nodo
// sin innerHTML, así que Trusted Types no interviene, y no hace falta img-src
// en la CSP del 8445. Sin colores en el SVG: van en clases de styles.css, con
// las variables de :root, y la batería (verificar_spa, k) cuenta los colores
// escritos en las plantillas. width y height reservan su sitio al cargar; el
// tamaño real lo pone la hoja.
//
// El viewBox empieza en y = 3.25 y no en 0: el dibujo va de la cabeza (y ≈ 9)
// al final de las patas (y ≈ 46), y con el marco en 0 quedaba 3.25 por debajo
// del centro de su caja. Junto a un texto centrado con flex (la barra), el
// pájaro se veía unos 2 px más bajo que las letras. Con el marco movido, el
// centro del dibujo es el de la caja, sin márgenes de corrección en la hoja.
@Component({
  selector: 'app-canario',
  template: `
    <svg class="canario" aria-hidden="true" focusable="false" width="48" height="48" viewBox="0 3.25 48 48">
      <path class="canario-cuerpo canario-trazo" d="M10 30 L3 38 L13 35 Z" />
      <ellipse class="canario-cuerpo canario-trazo" cx="22" cy="30" rx="13" ry="10" />
      <circle class="canario-cuerpo canario-trazo" cx="31" cy="18" r="8.5" />
      <path class="canario-pico canario-trazo" d="M38.5 16.5 L45 19 L38.5 21.5 Z" />
      <circle class="canario-ojo" cx="33" cy="16.5" r="1.8" />
      <path class="canario-ala canario-trazo" d="M14 28 Q21 24 27 30 Q20 34 14 28 Z" />
      <path class="canario-patas canario-trazo" d="M20 40 L19 45 M25 40 L26 45" />
    </svg>
  `,
})
export class Canario {}
