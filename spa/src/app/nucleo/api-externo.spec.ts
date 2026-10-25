import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { firstValueFrom } from 'rxjs';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ApiExterno, resultadoDe, urlPermitida } from './api-externo';

// Oráculos literales: las rutas, los cuerpos y los resultados de la vuelta de
// la API (app/rutas_externo.py) y el origen de autorización de Google
// (app/cliente_broker.py), no las constantes del código que se prueba.
const PROVEEDORES = '/v1/personal/externo/proveedores';
const INICIO = '/v1/personal/externo/google/inicio';
const SESION_EXTERNA = '/v1/personal/sesiones/externa';
const VINCULO = '/v1/personal/externo/google/vinculo';
const AUTORIZACION = 'https://accounts.google.com/o/oauth2/v2/auth?client_id=x&state=y';

describe('acceso con un proveedor externo', () => {
  let http: HttpTestingController;
  let api: ApiExterno;

  beforeEach(() => {
    TestBed.configureTestingModule({ providers: [provideHttpClient(), provideHttpClientTesting()] });
    http = TestBed.inject(HttpTestingController);
    api = TestBed.inject(ApiExterno);
  });

  afterEach(() => {
    http.verify();
    TestBed.resetTestingModule();
  });

  it('la URL del proveedor solo vale si es https, de su origen exacto y sin usuario', () => {
    // Control: la de Google sí vale; sin él, que todas fallen no diría nada.
    expect(urlPermitida('google', AUTORIZACION)).toBe(true);
    const ajenas = [
      'http://accounts.google.com/o/oauth2/v2/auth',
      'https://accounts.google.com.evil.test/o/oauth2/v2/auth',
      'https://accounts.google.com@evil.test/o/oauth2/v2/auth',
      'https://usuario@accounts.google.com/o/oauth2/v2/auth',
      'https://usuario:clave@accounts.google.com/o/oauth2/v2/auth',
      'https://accounts.google.com:444/o/oauth2/v2/auth',
      'https://evil.test/https://accounts.google.com/',
      '//accounts.google.com/o/oauth2/v2/auth',
      'javascript:alert(1)',
      '',
    ];
    expect(ajenas.filter((url) => urlPermitida('google', url))).toEqual([]);
  });

  it('el resultado de la vuelta sale de una lista cerrada', () => {
    expect(['cancelado', 'no_disponible', 'fallido'].map(resultadoDe)).toEqual(['cancelado', 'no_disponible', 'fallido']);
    const otros = ['<script>', 'pendiente', 'CANCELADO', 'toString', '__proto__', '', null];
    expect(otros.map(resultadoDe)).toEqual(otros.map(() => null));
  });

  it('solo pasan los proveedores que la SPA conoce, y las rutas y los cuerpos son los de la API', async () => {
    const lista = firstValueFrom(api.proveedores());
    http.expectOne(PROVEEDORES).flush({ proveedores: ['github', 'google', '__proto__'] });
    await expect(lista).resolves.toEqual(['google']);

    const url = firstValueFrom(api.iniciar('google', 'empresa-x'));
    const inicio = http.expectOne(INICIO);
    expect([inicio.request.method, inicio.request.body]).toEqual(['POST', { empresa: 'empresa-x' }]);
    inicio.flush({ url: AUTORIZACION });
    await expect(url).resolves.toBe(AUTORIZACION);

    void firstValueFrom(api.entrar('123456'));
    const entrada = http.expectOne(SESION_EXTERNA);
    expect([entrada.request.method, entrada.request.body]).toEqual(['POST', { codigo_totp: '123456' }]);
    entrada.flush({});

    void firstValueFrom(api.revocarVinculo('google', '654321'));
    const revocacion = http.expectOne(VINCULO);
    expect([revocacion.request.method, revocacion.request.body]).toEqual(['DELETE', { codigo_totp: '654321' }]);
    revocacion.flush(null, { status: 204, statusText: 'No Content' });
  });
});
