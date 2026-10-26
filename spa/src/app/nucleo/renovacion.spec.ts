import { HttpHeaders, provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiPersonal } from './api';
import { CANAL, Caducidad } from './caducidad';
import { CERROJO, Cerrojo, Renovador, renovarSesion } from './renovacion';
import { Sesion } from './sesion';

// Oráculos literales: las rutas y la cabecera de la API
// (app/rutas_personal.py), no las constantes del código que se prueba.
const YO = '/v1/personal/yo';
const SESIONES = '/v1/personal/sesiones';
const RENOVACION = '/v1/personal/sesiones/renovacion';
const CIERRE = '/v1/personal/sesiones/actual';
const CON_BEARER = new HttpHeaders({ 'WWW-Authenticate': 'Bearer' });
const CUENTA = { usuario_id: 'u', email: 'admin@canario.test', rol: 'admin', invitacion_pendiente: false,
                 enlace_canal: 'https://localhost:8444/empresas/0123456789abcdef0123456789abcdef', vinculos: [],
                 inactividad_en: 900, caduca_en: 28800 };
// Lo que responde la API al renovar en el navegador: solo los segundos, los
// tokens van en sus cookies (app/rutas_personal.py, respuesta_con_tokens).
const RENOVADA = { expira_en: 300, inactividad_en: 900, caduca_en: 28800 };
const LOGIN = { empresa: 'e', email: 'admin@canario.test', contrasena: 'x', codigo_totp: '000000' };

// Cerrojo falso con la misma semántica que Web Locks: un trabajo cada vez,
// en orden de llegada. Apunta los nombres que recibe.
function cerrojoFalso(nombres: string[]): Cerrojo {
  let cola: Promise<unknown> = Promise.resolve();
  return <T>(nombre: string, trabajo: () => Promise<T>): Promise<T> => {
    nombres.push(nombre);
    const turno = cola.then(trabajo);
    cola = turno.catch(() => undefined);
    return turno;
  };
}

// Deja correr las promesas pendientes (la renovación va por un cerrojo y una
// promesa compartida).
async function sinPendientes(): Promise<void> {
  for (let i = 0; i < 5; i++) {
    await new Promise((resolver) => setTimeout(resolver, 0));
  }
}

// Canal entre pestañas falso: apunta lo que se envía y no recibe nada.
function canalFalso(enviados: unknown[]): { enviar(m: unknown): void; alRecibir(): void; cerrar(): void } {
  return { enviar: (mensaje) => enviados.push(mensaje), alRecibir: () => undefined, cerrar: () => undefined };
}

function sesionCaducada(): { status: number; statusText: string; headers: HttpHeaders } {
  return { status: 401, statusText: 'Unauthorized', headers: CON_BEARER };
}

describe('renovación de la sesión', () => {
  let http: HttpTestingController;
  let api: ApiPersonal;
  let router: Router;
  let nombres: string[];
  let enviados: unknown[];

  beforeEach(() => {
    nombres = [];
    enviados = [];
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([renovarSesion])),
        provideHttpClientTesting(),
        provideRouter([]),
        { provide: CERROJO, useValue: cerrojoFalso(nombres) },
        { provide: CANAL, useValue: canalFalso(enviados) },
      ],
    });
    http = TestBed.inject(HttpTestingController);
    api = TestBed.inject(ApiPersonal);
    router = TestBed.inject(Router);
  });

  afterEach(() => {
    http.verify();
    TestBed.resetTestingModule();
  });

  it('con un 401 de sesión renueva una vez, dentro del cerrojo, y repite la petición una vez', async () => {
    const respuesta = firstValueFrom(api.yo());
    http.expectOne(YO).flush(null, sesionCaducada());
    await sinPendientes();
    const renovacion = http.expectOne(RENOVACION);
    expect(renovacion.request.method).toBe('POST');
    expect(renovacion.request.body).toEqual({});
    renovacion.flush(RENOVADA);
    await sinPendientes();
    http.expectOne(YO).flush(CUENTA);
    await expect(respuesta).resolves.toEqual(CUENTA);
    expect(nombres).toEqual(['canario-renovacion']);
  });

  it('repite también una petición que cambia algo (el 401 llega antes de que la ruta haga nada)', async () => {
    const respuesta = firstValueFrom(api.cerrarSesion());
    http.expectOne(CIERRE).flush(null, sesionCaducada());
    await sinPendientes();
    http.expectOne(RENOVACION).flush(RENOVADA);
    await sinPendientes();
    const repetida = http.expectOne(CIERRE);
    expect(repetida.request.method).toBe('DELETE');
    repetida.flush(null, { status: 204, statusText: 'No Content' });
    await expect(respuesta).resolves.toBeNull();
  });

  it('un login fallido no renueva, aunque su 401 traiga WWW-Authenticate: Bearer', async () => {
    const respuesta = firstValueFrom(api.iniciarSesion(LOGIN));
    http.expectOne(SESIONES).flush({ detalle: 'credenciales no válidas' }, sesionCaducada());
    await expect(respuesta).rejects.toMatchObject({ status: 401 });
    await sinPendientes();
    http.expectNone(RENOVACION);
    http.expectNone(SESIONES);
  });

  it('un 401 sin WWW-Authenticate: Bearer no renueva', async () => {
    const respuesta = firstValueFrom(api.yo());
    http.expectOne(YO).flush(null, { status: 401, statusText: 'Unauthorized' });
    await expect(respuesta).rejects.toMatchObject({ status: 401 });
    await sinPendientes();
    http.expectNone(RENOVACION);
  });

  it('si la renovación falla con 401, no repite la petición y lleva a /entrar', async () => {
    const navegar = vi.spyOn(router, 'navigateByUrl').mockResolvedValue(true);
    const respuesta = firstValueFrom(api.yo());
    http.expectOne(YO).flush(null, sesionCaducada());
    await sinPendientes();
    http.expectOne(RENOVACION).flush({ detalle: 'sesión no válida' }, sesionCaducada());
    await expect(respuesta).rejects.toMatchObject({ status: 401 });
    await sinPendientes();
    http.expectNone(YO);
    http.expectNone(RENOVACION);
    expect(navegar).toHaveBeenCalledWith('/entrar');
  });

  it('si la renovación falla por la red, no lleva a /entrar', async () => {
    const navegar = vi.spyOn(router, 'navigateByUrl').mockResolvedValue(true);
    const respuesta = firstValueFrom(api.yo());
    http.expectOne(YO).flush(null, sesionCaducada());
    await sinPendientes();
    http.expectOne(RENOVACION).error(new ProgressEvent('error'));
    await expect(respuesta).rejects.toMatchObject({ status: 0 });
    expect(navegar).not.toHaveBeenCalled();
  });

  it('dos peticiones con 401 a la vez comparten una sola renovación', async () => {
    const primera = firstValueFrom(api.yo());
    const segunda = firstValueFrom(api.yo());
    const caducadas = http.match(YO);
    expect(caducadas.length).toBe(2);
    caducadas.forEach((peticion) => peticion.flush(null, sesionCaducada()));
    await sinPendientes();
    http.expectOne(RENOVACION).flush(RENOVADA);
    await sinPendientes();
    const repetidas = http.match(YO);
    expect(repetidas.length).toBe(2);
    repetidas.forEach((peticion) => peticion.flush(CUENTA));
    await expect(primera).resolves.toEqual(CUENTA);
    await expect(segunda).resolves.toEqual(CUENTA);
    await sinPendientes();
    http.expectNone(RENOVACION);
    expect(nombres).toEqual(['canario-renovacion']);
  });

  it('la renovación pone en marcha de nuevo la cuenta atrás y se la cuenta a las demás pestañas', async () => {
    const renovada = TestBed.inject(Renovador).renovar();
    await sinPendientes();
    http.expectOne(RENOVACION).flush(RENOVADA);
    await renovada;
    expect(TestBed.inject(Caducidad).estado()).toBe('en_curso');
    expect(enviados).toEqual([{ tipo: 'tiempos', inactividad_en: 900, caduca_en: 28800 }]);
  });

  it('una renovación sin los segundos falla de forma visible', async () => {
    const renovada = TestBed.inject(Renovador).renovar();
    await sinPendientes();
    http.expectOne(RENOVACION).flush({ expira_en: 300 });
    await expect(renovada).rejects.toThrow('la respuesta no trae los tiempos de la sesión');
    expect(enviados).toEqual([]);
  });

  it('con la cuenta cargada, un 401 sin renovación deja en /entrar el aviso de sesión cerrada', async () => {
    vi.spyOn(router, 'navigateByUrl').mockResolvedValue(true);
    const carga = TestBed.inject(Sesion).cargar();
    http.expectOne(YO).flush(CUENTA);
    await carga;
    const respuesta = firstValueFrom(api.yo());
    http.expectOne(YO).flush(null, sesionCaducada());
    await sinPendientes();
    http.expectOne(RENOVACION).flush({ detalle: 'sesión no válida' }, sesionCaducada());
    await expect(respuesta).rejects.toMatchObject({ status: 401 });
    const caducidad = TestBed.inject(Caducidad);
    expect(caducidad.tomarAviso()).toBe('Su sesión se ha cerrado. Vuelva a entrar.');
    expect(caducidad.tomarAviso()).toBeNull();
    expect(caducidad.estado()).toBe('sin_sesion');
  });

  it('sin la cuenta cargada, el mismo 401 no deja ningún aviso (control del anterior)', async () => {
    vi.spyOn(router, 'navigateByUrl').mockResolvedValue(true);
    const respuesta = firstValueFrom(api.yo());
    http.expectOne(YO).flush(null, sesionCaducada());
    await sinPendientes();
    http.expectOne(RENOVACION).flush({ detalle: 'sesión no válida' }, sesionCaducada());
    await expect(respuesta).rejects.toMatchObject({ status: 401 });
    expect(TestBed.inject(Caducidad).tomarAviso()).toBeNull();
  });
});
