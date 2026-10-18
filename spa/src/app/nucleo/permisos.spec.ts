import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { ActivatedRouteSnapshot, Router, RouterStateSnapshot, UrlTree, provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { Rol } from './api';
import { Reintento, menuDe, permitirPorRol } from './permisos';

// Oráculos literales: la ruta de la API (app/rutas_personal.py), las rutas y
// los textos del menú, no las constantes del código que se prueba.
const YO = '/v1/personal/yo';

function cuenta(rol: Rol): object {
  return { usuario_id: 'u', email: 'persona@canario.test', rol, invitacion_pendiente: false };
}

function ruta(roles?: Rol[]): ActivatedRouteSnapshot {
  return { data: roles === undefined ? {} : { roles } } as unknown as ActivatedRouteSnapshot;
}

function estado(url: string): RouterStateSnapshot {
  return { url } as RouterStateSnapshot;
}

describe('permisos por rol', () => {
  let http: HttpTestingController;
  let router: Router;

  beforeEach(() => {
    TestBed.configureTestingModule({ providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])] });
    http = TestBed.inject(HttpTestingController);
    router = TestBed.inject(Router);
  });

  function comprobar(roles: Rol[] | undefined, url: string): Promise<unknown> {
    return TestBed.runInInjectionContext(() => permitirPorRol(ruta(roles), estado(url))) as Promise<unknown>;
  }

  function adonde(resultado: unknown): string | boolean {
    return resultado instanceof UrlTree ? router.serializeUrl(resultado) : (resultado as boolean);
  }

  it('el menú de cada rol solo lleva sus páginas', () => {
    expect(menuDe('admin').map((e) => e.texto))
      .toEqual(['Inicio', 'Denuncias', 'Cuentas', 'Solicitudes', 'Auditoría', 'Mi cuenta']);
    expect(menuDe('admin').map((e) => e.ruta))
      .toEqual(['/inicio', '/denuncias', '/cuentas', '/solicitudes', '/auditoria', '/cuenta']);
    expect(menuDe('instructor').map((e) => e.texto)).toEqual(['Inicio', 'Denuncias', 'Mi cuenta']);
    expect(menuDe('auditor').map((e) => e.texto)).toEqual(['Inicio', 'Auditoría', 'Mi cuenta']);
  });

  it('un instructor que pide /cuentas vuelve a /inicio', async () => {
    const resultado = comprobar(['admin'], '/cuentas');
    http.expectOne(YO).flush(cuenta('instructor'));
    expect(adonde(await resultado)).toBe('/inicio');
  });

  it('un admin abre /cuentas, y la cuenta se pide una sola vez', async () => {
    const primera = comprobar(['admin'], '/cuentas');
    http.expectOne(YO).flush(cuenta('admin'));
    expect(adonde(await primera)).toBe(true);
    expect(adonde(await comprobar(['admin'], '/solicitudes'))).toBe(true);
    http.expectNone(YO);
  });

  it('una página sin roles no se abre para nadie', async () => {
    const resultado = comprobar(undefined, '/nueva');
    http.expectOne(YO).flush(cuenta('admin'));
    expect(adonde(await resultado)).toBe('/inicio');
  });

  it('si /yo falla por la red, lleva a /no-disponible y recuerda la página', async () => {
    const resultado = comprobar(['admin'], '/cuentas');
    http.expectOne(YO).error(new ProgressEvent('error'));
    expect(adonde(await resultado)).toBe('/no-disponible');
    expect(TestBed.inject(Reintento).destino).toBe('/cuentas');
  });

  it('con un 401 no deja pasar ni lleva a otra página (lo hace el interceptor)', async () => {
    const resultado = comprobar(['admin'], '/cuentas');
    http.expectOne(YO).flush({ detalle: 'sesión no válida' }, { status: 401, statusText: 'Unauthorized' });
    expect(adonde(await resultado)).toBe(false);
    expect(TestBed.inject(Reintento).destino).toBeNull();
  });
});
