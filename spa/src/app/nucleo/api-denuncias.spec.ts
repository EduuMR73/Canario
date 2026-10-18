import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { ApiDenuncias } from './api-denuncias';

// Oráculos literales: las rutas de la API (app/rutas_personal.py), no las
// del código que se prueba.
const ID = '0b6f3c1e-8d2a-4f5b-9c7e-1a2b3c4d5e6f';

describe('cliente de denuncias', () => {
  let http: HttpTestingController;
  let api: ApiDenuncias;

  beforeEach(() => {
    TestBed.configureTestingModule({ providers: [provideHttpClient(), provideHttpClientTesting()] });
    http = TestBed.inject(HttpTestingController);
    api = TestBed.inject(ApiDenuncias);
  });

  it('un id que no es un uuid no llega a ninguna petición', () => {
    // Control: con un uuid, la petición sale a su ruta.
    api.leer(ID).subscribe();
    http.expectOne(`/v1/personal/denuncias/${ID}`);
    for (const id of ['../usuarios', '..', '%2e%2e', `${ID}/../../usuarios`, '']) {
      expect(() => api.leer(id)).toThrow('id de denuncia no valido');
      expect(() => api.enviarMensaje(id, 'x')).toThrow('id de denuncia no valido');
      expect(() => api.cambiarEstado(id, 'resuelta', 'x')).toThrow('id de denuncia no valido');
      expect(() => api.asignar(id, ID)).toThrow('id de denuncia no valido');
    }
    http.verify();
  });

  it('sin mensaje, el cambio de estado no envía el campo', () => {
    api.cambiarEstado(ID, 'en_instruccion', null).subscribe();
    expect(http.expectOne(`/v1/personal/denuncias/${ID}/estado`).request.body).toEqual({ estado: 'en_instruccion' });
  });
});
