import { Routes } from '@angular/router';
import { Activacion } from './acceso/activacion/activacion';
import { Entrar } from './acceso/entrar/entrar';
import { Registro } from './acceso/registro/registro';
import { Verificacion } from './acceso/verificacion/verificacion';
import { Inicio } from './inicio/inicio';
import { NoEncontrada } from './no-encontrada/no-encontrada';

// Ninguna ruta de la SPA lleva un punto: el proxy trata como fichero cualquier
// ruta con extensión y, si no existe, responde 404 en vez de index.html
// (proxy/Caddyfile, sitio del 8445).
//
// Sin carga diferida (loadComponent): la SPA es pequeña, y así el build es un
// solo main-*.js, que es lo que comprueba tests/security/verificar_spa.py.
//
// /activacion y /registro/verificacion son las rutas de los enlaces de los
// correos (app/solicitudes.py): si cambian aquí, cambian allí.
export const routes: Routes = [
  { path: '', pathMatch: 'full', redirectTo: 'entrar' },
  { path: 'entrar', component: Entrar, title: 'Entrar - Canario' },
  { path: 'registro', component: Registro, title: 'Solicitar acceso - Canario' },
  { path: 'registro/verificacion', component: Verificacion, title: 'Confirmar el email - Canario' },
  { path: 'activacion', component: Activacion, title: 'Activar la cuenta - Canario' },
  { path: 'inicio', component: Inicio, title: 'Inicio - Canario' },
  { path: '**', component: NoEncontrada, title: 'Página no encontrada - Canario' },
];
