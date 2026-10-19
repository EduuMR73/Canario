import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';
import { Leila } from '../marca/leila';

// La SPA responde a cualquier ruta (el proxy sirve index.html): una que no
// existe se dice aquí, con el mismo texto que el sitio del denunciante.
//
// Está fuera del armazón, como las páginas de acceso, y se presenta como
// ellas (main.acceso), con Leila donde llevan el canario. Leila va antes del
// h1 pero es decorativa: no entra en la lectura, y el foco va al h1.
@Component({
  selector: 'app-no-encontrada',
  template: `
    <main class="acceso">
      <app-leila />
      <h1 tabindex="-1">Página no encontrada</h1>
      <p><a class="boton" routerLink="/entrar">Ir a la entrada</a></p>
    </main>
  `,
  imports: [Leila, RouterLink],
})
export class NoEncontrada {}
