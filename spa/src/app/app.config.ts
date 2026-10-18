import { provideHttpClient, withInterceptors, withNoXsrfProtection } from '@angular/common/http';
import { ApplicationConfig, provideBrowserGlobalErrorListeners } from '@angular/core';
import { provideRouter } from '@angular/router';
import { routes } from './app.routes';
import { renovarSesion } from './nucleo/renovacion';

export const appConfig: ApplicationConfig = {
  providers: [
    provideBrowserGlobalErrorListeners(),
    provideRouter(routes),
    // fetch es el backend por defecto en Angular 22. Sin la protección XSRF de
    // Angular: lee una cookie XSRF-TOKEN que la API no pone y no defiende
    // nada aquí. La defensa CSRF real está en la API: Sec-Fetch-Site y Origin,
    // que pone el navegador (app/rutas_personal.py, es_navegador).
    provideHttpClient(withInterceptors([renovarSesion]), withNoXsrfProtection()),
  ],
};
