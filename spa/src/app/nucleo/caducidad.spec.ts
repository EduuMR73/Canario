import { TestBed } from '@angular/core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { CANAL, Caducidad, RELOJ, tiemposDe } from './caducidad';

// Oráculos literales: los segundos de una sesión recién creada o renovada
// (app/personal.py: 15 minutos y 8 horas) y los textos de /entrar, no las
// constantes del código que se prueba.
const RECIEN_RENOVADA = { inactividad_en: 900, caduca_en: 28800 };
const TEXTO_INACTIVIDAD = 'Su sesión se ha cerrado por inactividad. Vuelva a entrar.';
const TEXTO_MAXIMO = 'Su sesión ha llegado a las 8 horas y se ha cerrado. Vuelva a entrar.';

describe('cuenta atrás de la sesión', () => {
  let enviados: unknown[];
  let deOtra: (datos: unknown) => void;
  let caducidad: Caducidad;

  // Con los temporizadores falsos, Date.now avanza a la vez que ellos, como
  // el reloj de la página con la pestaña delante.
  function avanzar(segundos: number): void {
    vi.advanceTimersByTime(segundos * 1000);
  }

  // La pestaña en segundo plano: el reloj sigue y los temporizadores no.
  function enSegundoPlano(segundos: number): void {
    vi.setSystemTime(Date.now() + segundos * 1000);
  }

  beforeEach(() => {
    vi.useFakeTimers();
    enviados = [];
    deOtra = () => undefined;
    TestBed.configureTestingModule({
      providers: [
        { provide: RELOJ, useValue: () => Date.now() },
        { provide: CANAL, useValue: {
          enviar: (mensaje: unknown) => enviados.push(mensaje),
          alRecibir: (oyente: (datos: unknown) => void) => { deOtra = oyente; },
          cerrar: () => undefined,
        } },
      ],
    });
    caducidad = TestBed.inject(Caducidad);
  });

  afterEach(() => {
    TestBed.resetTestingModule();
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it('avisa 2 minutos antes del cierre por inactividad, y no antes', () => {
    expect(caducidad.estado()).toBe('sin_sesion');
    caducidad.actualizar(RECIEN_RENOVADA);
    expect(caducidad.estado()).toBe('en_curso');
    avanzar(779);
    expect(caducidad.estado()).toBe('en_curso');
    avanzar(1);
    expect(caducidad.estado()).toBe('aviso');
  });

  it('al cierre por inactividad vence y deja para /entrar su aviso, una sola vez', () => {
    caducidad.actualizar(RECIEN_RENOVADA);
    avanzar(899);
    expect(caducidad.estado()).toBe('aviso');
    expect(caducidad.tomarAviso()).toBeNull();
    avanzar(1);
    expect(caducidad.estado()).toBe('vencida');
    expect(caducidad.tomarAviso()).toBe(TEXTO_INACTIVIDAD);
    expect(caducidad.tomarAviso()).toBeNull();
  });

  it('el temporizador nunca renueva: ni en el aviso ni al vencer', () => {
    const red = vi.fn();
    vi.stubGlobal('fetch', red);
    vi.stubGlobal('XMLHttpRequest', vi.fn());
    caducidad.actualizar(RECIEN_RENOVADA);
    avanzar(780);
    expect(caducidad.estado()).toBe('aviso');
    avanzar(120);
    expect(caducidad.estado()).toBe('vencida');
    expect(red).not.toHaveBeenCalled();
    expect(XMLHttpRequest).not.toHaveBeenCalled();
  });

  it('renovar durante el aviso lo quita y la cuenta atrás vuelve a empezar', () => {
    caducidad.actualizar(RECIEN_RENOVADA);
    avanzar(800);
    expect(caducidad.estado()).toBe('aviso');
    caducidad.actualizar(RECIEN_RENOVADA);
    expect(caducidad.estado()).toBe('en_curso');
    avanzar(779);
    expect(caducidad.estado()).toBe('en_curso');
    expect(enviados).toEqual([{ tipo: 'tiempos', ...RECIEN_RENOVADA }, { tipo: 'tiempos', ...RECIEN_RENOVADA }]);
  });

  it('cerca de las 8 horas el aviso no ofrece ampliar, y al llegar dice por qué', () => {
    // Quedan 100 segundos de las 8 horas y 900 de inactividad: manda la
    // primera.
    caducidad.actualizar({ inactividad_en: 900, caduca_en: 100 });
    expect(caducidad.estado()).toBe('aviso_final');
    avanzar(100);
    expect(caducidad.estado()).toBe('vencida');
    expect(caducidad.tomarAviso()).toBe(TEXTO_MAXIMO);
  });

  it('los tiempos de otra pestaña valen; uno mal formado se descarta; sin cuenta no enciende nada', () => {
    deOtra({ tipo: 'tiempos', inactividad_en: 60, caduca_en: 28800 });
    expect(caducidad.estado()).toBe('sin_sesion');
    caducidad.actualizar(RECIEN_RENOVADA);
    // Más de 8 horas: no es de esta API.
    deOtra({ tipo: 'tiempos', inactividad_en: 60, caduca_en: 28801 });
    deOtra({ tipo: 'otro', inactividad_en: 60, caduca_en: 28800 });
    deOtra('tiempos');
    expect(caducidad.estado()).toBe('en_curso');
    // Control: uno bien formado sí cambia la cuenta atrás.
    deOtra({ tipo: 'tiempos', inactividad_en: 60, caduca_en: 28800 });
    expect(caducidad.estado()).toBe('aviso');
    // Lo recibido no se reenvía: solo el actualizar de esta pestaña.
    expect(enviados).toEqual([{ tipo: 'tiempos', ...RECIEN_RENOVADA }]);
  });

  it('al volver a la pestaña recalcula: si ya pasó la hora, vence sin esperar al temporizador', () => {
    caducidad.actualizar(RECIEN_RENOVADA);
    enSegundoPlano(1000);
    expect(caducidad.estado()).toBe('en_curso');
    document.dispatchEvent(new Event('visibilitychange'));
    expect(caducidad.estado()).toBe('vencida');
    expect(caducidad.tomarAviso()).toBe(TEXTO_INACTIVIDAD);
  });

  it('el 401 de una sesión que aún no vencía no se atribuye a la inactividad', () => {
    caducidad.actualizar(RECIEN_RENOVADA);
    avanzar(60);
    caducidad.anunciarCierre();
    expect(caducidad.tomarAviso()).toBe('Su sesión se ha cerrado. Vuelva a entrar.');
    // Control: pasada la hora, el mismo 401 sí es por inactividad.
    enSegundoPlano(1000);
    caducidad.anunciarCierre();
    expect(caducidad.tomarAviso()).toBe(TEXTO_INACTIVIDAD);
  });

  it('solo acepta como tiempos enteros de 0 a 8 horas', () => {
    expect(tiemposDe({ expira_en: 300, ...RECIEN_RENOVADA })).toEqual(RECIEN_RENOVADA);
    expect(tiemposDe({ inactividad_en: 0, caduca_en: 0 })).toEqual({ inactividad_en: 0, caduca_en: 0 });
    for (const malo of [null, 'x', {}, { inactividad_en: 900 }, { inactividad_en: -1, caduca_en: 100 },
                        { inactividad_en: 900, caduca_en: 28801 }, { inactividad_en: 1.5, caduca_en: 100 },
                        { inactividad_en: '900', caduca_en: 100 }]) {
      expect(() => tiemposDe(malo)).toThrow('la respuesta no trae los tiempos de la sesión');
    }
  });
});
