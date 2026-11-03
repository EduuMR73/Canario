import { Routes } from '@angular/router';
import { Activacion } from './acceso/activacion/activacion';
import { Codigo } from './acceso/codigo/codigo';
import { Entrar } from './acceso/entrar/entrar';
import { Registro } from './acceso/registro/registro';
import { Verificacion } from './acceso/verificacion/verificacion';
import { Armazon } from './armazon/armazon';
import { Auditoria } from './auditoria/auditoria';
import { Contrasena } from './cuenta/contrasena';
import { Cuenta } from './cuenta/cuenta';
import { Vinculos } from './cuenta/vinculos';
import { Cuentas } from './cuentas/cuentas';
import { Denuncias } from './denuncias/denuncias';
import { Expediente } from './denuncias/expediente';
import { conIdDeDenuncia } from './denuncias/textos';
import { Inicio } from './inicio/inicio';
import { NoDisponible } from './no-disponible/no-disponible';
import { NoEncontrada } from './no-encontrada/no-encontrada';
import { MENU, RUTA_NO_DISPONIBLE, permitirPorRol } from './nucleo/permisos';
import { Solicitudes } from './solicitudes/solicitudes';

// Ninguna ruta de la SPA lleva un punto: el proxy trata como fichero cualquier
// ruta con extensión y, si no existe, responde 404 en vez de index.html
// (proxy/Caddyfile, sitio del 8445).
//
// Sin carga diferida (loadComponent): la SPA es pequeña, y así el build es un
// solo main-*.js, que es lo que comprueba tests/security/verificar_spa.py.
//
// /activacion y /registro/verificacion son las rutas de los enlaces de los
// correos (app/solicitudes.py): si cambian aquí, cambian allí. Lo mismo
// /entrar/codigo, /entrar y /cuenta/externas, los destinos de la vuelta de Google
// (app/rutas_externo.py, DESTINOS).
//
// Las páginas con sesión van dentro del armazón, y permitirPorRol comprueba
// en cada una sus roles (data.roles, de nucleo/permisos.ts, MENU). Una página
// sin roles no se abre para nadie. Una ruta que no casa con ninguna de ellas
// sigue hasta '**'.
export const routes: Routes = [
  { path: '', pathMatch: 'full', redirectTo: 'entrar' },
  { path: 'entrar', component: Entrar, title: 'Entrar - Canario' },
  { path: 'entrar/codigo', component: Codigo, title: 'Entrar con Google - Canario' },
  { path: 'registro', component: Registro, title: 'Solicitar acceso - Canario' },
  { path: 'registro/verificacion', component: Verificacion, title: 'Confirmar el email - Canario' },
  { path: 'activacion', component: Activacion, title: 'Activar la cuenta - Canario' },
  { path: RUTA_NO_DISPONIBLE.slice(1), component: NoDisponible, title: 'Cuenta no disponible - Canario' },
  {
    path: '',
    component: Armazon,
    canActivateChild: [permitirPorRol],
    children: [
      { path: 'inicio', component: Inicio, title: 'Inicio - Canario', data: { roles: MENU.inicio.roles } },
      {
        path: 'denuncias', component: Denuncias, title: 'Denuncias - Canario',
        data: { roles: MENU.denuncias.roles },
      },
      // Solo con un uuid (denuncias/textos.ts, conIdDeDenuncia): cualquier
      // otra cosa es "no encontrada" sin pedir nada a la API.
      {
        path: 'denuncias/:id', component: Expediente, title: 'Denuncia - Canario', canMatch: [conIdDeDenuncia],
        data: { roles: MENU.denuncias.roles },
      },
      { path: 'cuentas', component: Cuentas, title: 'Cuentas - Canario', data: { roles: MENU.cuentas.roles } },
      {
        path: 'solicitudes', component: Solicitudes, title: 'Solicitudes de registro - Canario',
        data: { roles: MENU.solicitudes.roles },
      },
      {
        path: 'auditoria', component: Auditoria, title: 'Auditoría - Canario',
        data: { roles: MENU.auditoria.roles },
      },
      // Mi cuenta (cuenta/cuenta.ts): el menú lateral y una sección hija por
      // tarea. Las hijas declaran sus roles: permitirPorRol corre también
      // para ellas, y Angular no les pasa la data de un padre con componente
      // (paramsInheritanceStrategy 'emptyOnly'); sin roles, no se abrirían
      // para nadie. /cuenta sola lleva a la primera sección.
      {
        path: 'cuenta', component: Cuenta, data: { roles: MENU.cuenta.roles },
        children: [
          { path: '', pathMatch: 'full', redirectTo: 'contrasena' },
          {
            path: 'contrasena', component: Contrasena, title: 'Contraseña - Mi cuenta - Canario',
            data: { roles: MENU.cuenta.roles },
          },
          // La vuelta de Google al vincular llega aquí (app/rutas_externo.py,
          // DESTINOS): si esta ruta cambia, cambia allí.
          {
            path: 'externas', component: Vinculos, title: 'Cuentas externas - Mi cuenta - Canario',
            data: { roles: MENU.cuenta.roles },
          },
        ],
      },
    ],
  },
  { path: '**', component: NoEncontrada, title: 'Página no encontrada - Canario' },
];
