import { Routes } from '@angular/router';
import { Inicio } from './inicio/inicio';
import { NoEncontrada } from './no-encontrada/no-encontrada';

// Ninguna ruta de la SPA lleva un punto: el proxy trata como fichero cualquier
// ruta con extensión y, si no existe, responde 404 en vez de index.html
// (proxy/Caddyfile, sitio del 8445).
export const routes: Routes = [
  { path: '', component: Inicio, title: 'Canario' },
  { path: '**', component: NoEncontrada, title: 'Página no encontrada - Canario' },
];
