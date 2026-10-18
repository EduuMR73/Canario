import { HttpErrorResponse, HttpHeaders } from '@angular/common/http';
import { describe, expect, it } from 'vitest';
import { detalleDe, textoDeError } from './errores';

function error(status: number, cabeceras: Record<string, string> = {}, cuerpo: unknown = null): HttpErrorResponse {
  return new HttpErrorResponse({ status, headers: new HttpHeaders(cabeceras), error: cuerpo });
}

describe('textos de error', () => {
  it('429 dice cuánto esperar con Retry-After, en minutos si pasa de uno', () => {
    expect(textoDeError(error(429, { 'Retry-After': '120' }))).toBe(
      'Demasiadas peticiones seguidas. Espere 2 minutos y vuelva a intentarlo.');
    expect(textoDeError(error(429, { 'Retry-After': '61' }))).toBe(
      'Demasiadas peticiones seguidas. Espere 2 minutos y vuelva a intentarlo.');
    expect(textoDeError(error(429, { 'Retry-After': '30' }))).toBe(
      'Demasiadas peticiones seguidas. Espere 30 segundos y vuelva a intentarlo.');
  });

  it('429 con una espera de más de una hora la da en horas, redondeando hacia arriba', () => {
    expect(textoDeError(error(429, { 'Retry-After': '3600' }))).toBe(
      'Demasiadas peticiones seguidas. Espere 60 minutos y vuelva a intentarlo.');
    expect(textoDeError(error(429, { 'Retry-After': '3601' }))).toBe(
      'Demasiadas peticiones seguidas. Espere 2 horas y vuelva a intentarlo.');
    expect(textoDeError(error(429, { 'Retry-After': '86400' }))).toBe(
      'Demasiadas peticiones seguidas. Espere 24 horas y vuelva a intentarlo.');
  });

  it('429 sin un Retry-After legible no inventa un número', () => {
    expect(textoDeError(error(429, { 'Retry-After': 'mañana' }))).toBe(
      'Demasiadas peticiones seguidas. Espere unos minutos y vuelva a intentarlo.');
  });

  it('sin red, servicio caído y el texto propio de la página', () => {
    expect(textoDeError(error(0))).toBe('No hay conexión con el servidor. Compruebe la red e inténtelo de nuevo.');
    expect(textoDeError(error(503))).toBe(
      'El servicio no está disponible ahora mismo. Inténtelo de nuevo en unos minutos.');
    expect(textoDeError(error(401), { 401: 'propio' })).toBe('propio');
  });

  it('el detalle de la API solo si es un texto', () => {
    expect(detalleDe(error(422, {}, { detalle: 'la contraseña es demasiado corta' }))).toBe(
      'la contraseña es demasiado corta');
    expect(detalleDe(error(422, {}, { detalle: 3 }))).toBeNull();
    expect(detalleDe(error(422, {}, '<b>x</b>'))).toBeNull();
  });
});
