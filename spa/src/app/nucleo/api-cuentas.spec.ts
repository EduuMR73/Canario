import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { firstValueFrom } from 'rxjs';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ApiCuentas } from './api-cuentas';
import { RENOVABLE } from './contexto';

// Oráculos literales: las rutas y los cuerpos de la API (app/rutas_personal.py:
// NuevoUsuario, CodigoTotp y AprobacionSolicitud), no las constantes del
// código que se prueba.
const ID = '3f2b8c1e-0d4a-4e5b-9c6d-7a8b9c0d1e2f';

describe('acciones de admin con código', () => {
  let http: HttpTestingController;
  let api: ApiCuentas;

  beforeEach(() => {
    TestBed.configureTestingModule({ providers: [provideHttpClient(), provideHttpClientTesting()] });
    http = TestBed.inject(HttpTestingController);
    api = TestBed.inject(ApiCuentas);
  });

  afterEach(() => {
    http.verify();
    TestBed.resetTestingModule();
  });

  it('invitar, reinvitar, dar de baja y aprobar mandan el código, con la sesión renovable', () => {
    void firstValueFrom(api.invitar('persona@canario.test', 'instructor', '123456'));
    const invitacion = http.expectOne('/v1/personal/usuarios');
    expect([invitacion.request.method, invitacion.request.body, invitacion.request.context.get(RENOVABLE)])
      .toEqual(['POST', { email: 'persona@canario.test', rol: 'instructor', codigo_totp: '123456' }, true]);
    invitacion.flush({ usuario_id: ID, token_invitacion: 't' });

    void firstValueFrom(api.reinvitar(ID, '234567'));
    const reinvitacion = http.expectOne(`/v1/personal/usuarios/${ID}/invitacion`);
    expect([reinvitacion.request.method, reinvitacion.request.body, reinvitacion.request.context.get(RENOVABLE)])
      .toEqual(['POST', { codigo_totp: '234567' }, true]);
    reinvitacion.flush({ usuario_id: ID, token_invitacion: 't' });

    void firstValueFrom(api.darDeBaja(ID, '345678'));
    const baja = http.expectOne(`/v1/personal/usuarios/${ID}/baja`);
    expect([baja.request.method, baja.request.body, baja.request.context.get(RENOVABLE)])
      .toEqual(['POST', { codigo_totp: '345678' }, true]);
    baja.flush(null, { status: 204, statusText: 'No Content' });

    void firstValueFrom(api.aprobar(ID, 'auditor', '456789'));
    const aprobacion = http.expectOne(`/v1/personal/solicitudes/${ID}/aprobacion`);
    expect([aprobacion.request.method, aprobacion.request.body, aprobacion.request.context.get(RENOVABLE)])
      .toEqual(['POST', { rol: 'auditor', codigo_totp: '456789' }, true]);
    aprobacion.flush(null, { status: 204, statusText: 'No Content' });
  });

  it('anular y rechazar no llevan código: solo cierran', () => {
    void firstValueFrom(api.anularInvitacion(ID));
    const anulacion = http.expectOne(`/v1/personal/usuarios/${ID}/invitacion`);
    expect([anulacion.request.method, anulacion.request.body]).toEqual(['DELETE', null]);
    anulacion.flush(null, { status: 204, statusText: 'No Content' });

    void firstValueFrom(api.rechazar(ID));
    const rechazo = http.expectOne(`/v1/personal/solicitudes/${ID}`);
    expect([rechazo.request.method, rechazo.request.body]).toEqual(['DELETE', null]);
    rechazo.flush(null, { status: 204, statusText: 'No Content' });
  });
});
