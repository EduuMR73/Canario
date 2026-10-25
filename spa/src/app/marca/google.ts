import { Component } from '@angular/core';

// La "G" de Google para el botón de acceso, con sus cuatro colores de la guía
// de marca de Google (Sign in with Google branding guidelines). Decorativa
// (aria-hidden): el botón ya dice "con Google" en su texto.
//
// Como el canario (marca/canario.ts): SVG en la plantilla, sin innerHTML ni
// img-src, y sin colores escritos aquí. Van en clases de styles.css, con sus
// variables en los dos :root, y la batería (verificar_spa, k) cuenta los
// colores de las plantillas.
@Component({
  selector: 'app-google',
  template: `
    <svg class="google-g" aria-hidden="true" focusable="false" width="18" height="18" viewBox="0 0 48 48">
      <path class="google-rojo" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z" />
      <path class="google-azul" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z" />
      <path class="google-amarillo" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z" />
      <path class="google-verde" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z" />
    </svg>
  `,
})
export class Google {}
