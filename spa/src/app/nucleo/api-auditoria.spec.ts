import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { ApiAuditoria } from './api-auditoria';

// Oráculos literales: las rutas de la API (app/rutas_personal.py), no las
// del código que se prueba.
describe('cliente de la auditoría', () => {
  let http: HttpTestingController;
  let api: ApiAuditoria;

  beforeEach(() => {
    TestBed.configureTestingModule({ providers: [provideHttpClient(), provideHttpClientTesting()] });
    http = TestBed.inject(HttpTestingController);
    api = TestBed.inject(ApiAuditoria);
  });

  it('la primera página va sin antes, las anteriores con él', () => {
    api.recientes(null).subscribe();
    expect(http.expectOne('/v1/personal/auditoria/recientes').request.params.keys()).toEqual([]);
    api.recientes(101).subscribe();
    expect(http.expectOne('/v1/personal/auditoria/recientes?antes=101').request.method).toBe('GET');
    api.verificar().subscribe();
    http.expectOne('/v1/personal/auditoria/verificacion');
    http.verify();
  });
});
