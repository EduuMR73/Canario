import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';

// La SPA responde a cualquier ruta (el proxy sirve index.html): una que no
// existe se dice aquí, con el mismo texto que el sitio del denunciante.
@Component({
  selector: 'app-no-encontrada',
  template: '<main><h1 tabindex="-1">Página no encontrada</h1><p><a routerLink="/entrar">Ir a la entrada</a></p></main>',
  imports: [RouterLink],
})
export class NoEncontrada {}
