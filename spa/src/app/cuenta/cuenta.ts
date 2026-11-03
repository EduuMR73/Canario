import { Component } from '@angular/core';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';

// Mi cuenta: un menú lateral con sus secciones y, a la derecha, la sección
// abierta (app.routes.ts, hijas de /cuenta): la contraseña (contrasena.ts) y
// las cuentas externas (vinculos.ts). Cada sección es una página con su
// dirección y su título: se puede enlazar, recargar y volver atrás, y cada
// pantalla tiene un solo campo "Código de autenticación", así que no se
// escribe en el que no toca.
//
// Enlaces nativos con aria-current y no pestañas ARIA (role="tab"): el patrón
// de pestañas de WAI-ARIA es para paneles dentro de una misma página, y aquí
// cada sección cambia la URL. El h1 es el de la sección, después del menú: al
// cambiar de sección el foco va a él (nucleo/foco.ts) y el siguiente Tab entra
// en el formulario, sin volver a recorrer el menú.
@Component({
  selector: 'app-cuenta',
  imports: [RouterLink, RouterLinkActive, RouterOutlet],
  template: `
    <div class="cuenta">
      <nav class="cuenta-menu" aria-labelledby="cuenta-menu-titulo">
        <p id="cuenta-menu-titulo" class="cuenta-menu-titulo">Mi cuenta</p>
        <ul>
          @for (seccion of secciones; track seccion.ruta) {
            <li><a [routerLink]="seccion.ruta" routerLinkActive="activo" ariaCurrentWhenActive="page">{{ seccion.texto }}</a></li>
          }
        </ul>
      </nav>
      <div class="cuenta-seccion">
        <router-outlet />
      </div>
    </div>
  `,
})
export class Cuenta {
  // Las mismas rutas que las hijas de /cuenta en app.routes.ts.
  readonly secciones = [
    { ruta: '/cuenta/contrasena', texto: 'Contraseña' },
    { ruta: '/cuenta/externas', texto: 'Cuentas externas' },
  ] as const;
}
