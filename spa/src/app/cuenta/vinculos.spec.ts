import { Location } from '@angular/common';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ActivatedRoute, convertToParamMap } from '@angular/router';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { NAVEGAR } from '../nucleo/api-externo';
import { Sesion } from '../nucleo/sesion';
import { Vinculos, diaDe } from './vinculos';

// Oráculos literales: las rutas de la API (app/rutas_personal.py y
// app/rutas_externo.py), la forma de /yo y los textos de la página, no las
// constantes del código que se prueba.
const YO = '/v1/personal/yo';
const PROVEEDORES = '/v1/personal/externo/proveedores';
const VINCULO = '/v1/personal/externo/google/vinculo';
const INICIO_VINCULO = '/v1/personal/externo/google/vinculo/inicio';
const CREADA = '2026-10-25T12:00:00+00:00';
const CUENTA = { usuario_id: 'u', email: 'persona@canario.test', rol: 'admin', invitacion_pendiente: false,
                 enlace_canal: 'https://localhost:8444/empresas/0123456789abcdef0123456789abcdef', vinculos: [] };
const VINCULADA = { ...CUENTA, vinculos: [{ proveedor: 'google', creada: CREADA }] };
// El 401 de las credenciales, sin WWW-Authenticate (app/rutas_externo.py).
const NO_VALIDO = { status: 401, statusText: 'Unauthorized' };

// Deja correr las promesas pendientes (releer /yo es una promesa).
async function sinPendientes(): Promise<void> {
  for (let i = 0; i < 5; i++) {
    await new Promise((resolver) => setTimeout(resolver, 0));
  }
}

interface Pagina {
  pagina: ComponentFixture<Vinculos>;
  raiz: HTMLElement;
  http: HttpTestingController;
  replaceState: ReturnType<typeof vi.fn>;
  navegar: ReturnType<typeof vi.fn>;
}

function crear(consulta: Record<string, string> = {}): Pagina {
  const replaceState = vi.fn();
  const navegar = vi.fn();
  TestBed.configureTestingModule({
    providers: [
      provideHttpClient(),
      provideHttpClientTesting(),
      { provide: ActivatedRoute, useValue: { snapshot: { queryParamMap: convertToParamMap(consulta) } } },
      { provide: Location, useValue: { replaceState } },
      { provide: NAVEGAR, useValue: navegar },
    ],
  });
  const http = TestBed.inject(HttpTestingController);
  const pagina = TestBed.createComponent(Vinculos);
  pagina.detectChanges();
  return { pagina, raiz: pagina.nativeElement as HTMLElement, http, replaceState, navegar };
}

// La cuenta que el armazón ya ha cargado antes de abrir /cuenta.
async function conCuenta(p: Pagina, cuenta: object): Promise<void> {
  const carga = TestBed.inject(Sesion).cargar();
  p.http.expectOne(YO).flush(cuenta);
  await carga;
  p.pagina.detectChanges();
}

function resultado(raiz: HTMLElement): (string | null | undefined)[] | null {
  const aviso = raiz.querySelector('#vinculos-resultado');
  return aviso === null ? null : [aviso.getAttribute('role'), aviso.textContent?.trim()];
}

describe('cuentas externas vinculadas', () => {
  afterEach(() => TestBed.resetTestingModule());

  it('al recargar ?vinculo=pendiente con el ticket gastado, relee /yo antes de dar el error', async () => {
    const p = crear({ vinculo: 'pendiente' });
    expect(p.replaceState).toHaveBeenCalledWith('/cuenta');
    const completar = p.http.expectOne(VINCULO);
    expect(completar.request.method).toBe('POST');
    completar.flush({ detalle: 'credenciales no válidas' }, NO_VALIDO);
    p.http.expectOne(PROVEEDORES).flush({ proveedores: ['google'] });
    await sinPendientes();
    // El vínculo se guardó en la carga anterior: /yo lo tiene.
    p.http.expectOne(YO).flush(VINCULADA);
    await sinPendientes();
    p.pagina.detectChanges();
    expect(resultado(p.raiz)).toEqual(['status', 'Su cuenta de Google está vinculada.']);
    p.http.expectNone(VINCULO);
    p.http.verify();

    // Control: si /yo no lo tiene, sí es un error.
    TestBed.resetTestingModule();
    const q = crear({ vinculo: 'pendiente' });
    q.http.expectOne(VINCULO).flush({ detalle: 'credenciales no válidas' }, NO_VALIDO);
    q.http.expectOne(PROVEEDORES).flush({ proveedores: ['google'] });
    await sinPendientes();
    q.http.expectOne(YO).flush(CUENTA);
    await sinPendientes();
    q.pagina.detectChanges();
    expect(resultado(q.raiz)).toEqual(['alert',
      'No se ha podido completar la vinculación: el acceso con Google ha caducado. Vuelva a vincularla.']);
    q.http.verify();
  });

  it('vincular no lleva a una URL que no sea de Google', async () => {
    const intentar = async (url: string): Promise<Pagina> => {
      TestBed.resetTestingModule();
      const p = crear();
      p.http.expectOne(PROVEEDORES).flush({ proveedores: ['google'] });
      await conCuenta(p, CUENTA);
      const codigo = p.raiz.querySelector<HTMLInputElement>('#vinculos-codigo-google');
      expect(codigo).not.toBeNull();
      codigo!.value = '123456';
      codigo!.dispatchEvent(new Event('input'));
      p.raiz.querySelector<HTMLFormElement>('form')!.dispatchEvent(new Event('submit'));
      const inicio = p.http.expectOne(INICIO_VINCULO);
      expect([inicio.request.method, inicio.request.body]).toEqual(['POST', { codigo_totp: '123456' }]);
      inicio.flush({ url });
      p.pagina.detectChanges();
      p.http.verify();
      return p;
    };

    const ajena = await intentar('https://evil.test/o/oauth2/v2/auth?state=x');
    expect(ajena.navegar).not.toHaveBeenCalled();
    expect(resultado(ajena.raiz)).toEqual(['alert', 'Ha ocurrido un error inesperado. Inténtelo de nuevo.']);
    // Control: la de Google sí navega.
    const buena = await intentar('https://accounts.google.com/o/oauth2/v2/auth?state=x');
    expect(buena.navegar).toHaveBeenCalledWith('https://accounts.google.com/o/oauth2/v2/auth?state=x');
  });

  it('sin proveedores avisa; vinculada enseña solo el proveedor y la fecha', async () => {
    const vacia = crear();
    vacia.http.expectOne(PROVEEDORES).flush({ proveedores: [] });
    await conCuenta(vacia, CUENTA);
    expect(vacia.raiz.querySelector('.aviso')?.textContent?.trim()).toBe(
      'El acceso con cuentas externas no está configurado en este servidor: se entra con la contraseña y el código.');
    expect(vacia.raiz.querySelector('form')).toBeNull();

    TestBed.resetTestingModule();
    const con = crear();
    con.http.expectOne(PROVEEDORES).flush({ proveedores: ['google'] });
    await conCuenta(con, VINCULADA);
    // Control del aviso: con Google configurado no sale.
    expect(con.raiz.querySelector('.aviso')).toBeNull();
    expect(con.raiz.querySelector('h3')?.textContent?.trim()).toBe('Google');
    expect(con.raiz.querySelector('h3 + p')?.textContent?.trim()).toBe(
      'Vinculada el 25/10/2026. Puede entrar con Google y su código desde un navegador de confianza.');
    expect(con.raiz.querySelector('button[type="submit"]')?.textContent?.trim()).toBe('Desvincular Google');
    expect(con.raiz.textContent).not.toContain('persona@canario.test');
    // Una fecha que no se puede leer se enseña tal cual.
    expect(diaDe('no-es-una-fecha')).toBe('no-es-una-fecha');
  });
});
