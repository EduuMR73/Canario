import { bootstrapApplication } from '@angular/platform-browser';
import { appConfig } from './app/app.config';
import { App } from './app/app';
import { tomarTokenDelFragmento } from './app/nucleo/fragmento';

// Antes que nada: el token de un enlace de correo sale de la URL
// (app/nucleo/fragmento.ts).
tomarTokenDelFragmento();

bootstrapApplication(App, appConfig)
  .catch((err) => console.error(err));
