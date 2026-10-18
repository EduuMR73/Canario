import { Component } from '@angular/core';

// La SPA responde a cualquier ruta (el proxy sirve index.html): una que no
// existe se dice aquí, con el mismo texto que el sitio del denunciante.
@Component({
  selector: 'app-no-encontrada',
  template: '<main><h1>Página no encontrada</h1></main>',
})
export class NoEncontrada {}
