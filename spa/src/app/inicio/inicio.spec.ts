import { signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Rol } from '../nucleo/api';
import { Sesion } from '../nucleo/sesion';
import { Inicio } from './inicio';

// Oráculos literales: los textos y las rutas de los accesos de cada rol, no
// las constantes del código que se prueba (nucleo/permisos.ts, MENU).
const ENLACE = 'https://localhost:8444/empresas/0123456789abcdef0123456789abcdef';

function crear(rol: Rol, invitacion_pendiente = false): ComponentFixture<Inicio> {
  const yo = signal({ usuario_id: 'u', email: 'persona@canario.test', rol, invitacion_pendiente, enlace_canal: ENLACE });
  TestBed.configureTestingModule({ providers: [provideRouter([]), { provide: Sesion, useValue: { yo } }] });
  const pagina = TestBed.createComponent(Inicio);
  pagina.detectChanges();
  return pagina;
}

function pintar(rol: Rol, invitacion_pendiente = false): HTMLElement {
  return crear(rol, invitacion_pendiente).nativeElement as HTMLElement;
}

function accesos(raiz: HTMLElement): string[][] {
  return [...raiz.querySelectorAll('.accesos a')].map((a) => [a.textContent?.trim() ?? '', a.getAttribute('href') ?? '']);
}

describe('página de inicio', () => {
  it('los accesos del inicio son las páginas del rol, sin el propio inicio y cada una con su descripción', () => {
    const admin = pintar('admin', true);
    // Control: la página lee la cuenta y la pinta (el aviso de una invitación
    // abierta sale de ella). Sin él, una lista vacía no diría nada de los
    // accesos.
    expect([...admin.querySelectorAll('[role="alert"]')].map((a) => a.textContent?.trim())).toEqual([
      'Hay una invitación abierta para su cuenta. Si no la ha pedido usted, avise a un admin de su empresa para que la anule.',
    ]);
    // El email ya está en la barra del armazón: aquí no se repite.
    expect(admin.textContent).not.toContain('persona@canario.test');
    expect(accesos(admin)).toEqual([
      ['Denuncias', '/denuncias'],
      ['Cuentas', '/cuentas'],
      ['Solicitudes', '/solicitudes'],
      ['Auditoría', '/auditoria'],
      ['Mi cuenta', '/cuenta'],
    ]);
    const descripciones = [...admin.querySelectorAll('.accesos p')].map((p) => p.textContent?.trim() ?? '');
    expect(descripciones.length).toBe(5);
    expect(descripciones.every((texto) => texto.length > 0)).toBe(true);

    TestBed.resetTestingModule();
    expect(accesos(pintar('auditor'))).toEqual([['Auditoría', '/auditoria'], ['Mi cuenta', '/cuenta']]);
    TestBed.resetTestingModule();
    expect(accesos(pintar('instructor'))).toEqual([['Denuncias', '/denuncias'], ['Mi cuenta', '/cuenta']]);
  });

  it('los plazos de la Ley 2/2023 los ven quienes instruyen, y el auditor no', () => {
    // Textos literales: los de la ley (BOE-A-2023-4513, arts. 9.2.c, 9.2.d y
    // 32.4) tal como los aplica el canal, no los de la plantilla.
    const PLAZOS = [
      'Respuesta: como máximo tres meses desde la recepción, ampliable hasta tres meses más si el caso es especialmente complejo (art. 9.2.d).',
      'Supresión: una denuncia que sigue en "Nueva" o "Inadmitida" a los tres meses de su recepción se suprime (art. 32.4). Para conservarla hay que iniciar la investigación.',
    ];
    const plazos = (raiz: HTMLElement) => {
      const seccion = raiz.querySelector('section.plazos');
      return seccion === null ? null : {
        titulo: seccion.querySelector('h2')?.textContent?.trim(),
        nombre: seccion.getAttribute('aria-labelledby'),
        lista: [...seccion.querySelectorAll('li')].map((li) => li.textContent?.trim()),
        // La ley bajo el título y el acuse al final, en ese orden.
        ayudas: [...seccion.querySelectorAll('.ayuda')].map((p) => p.textContent?.trim()),
      };
    };
    const esperado = {
      titulo: 'Plazos legales de cada denuncia',
      nombre: 'inicio-plazos',
      lista: PLAZOS,
      ayudas: [
        'Ley 2/2023, de protección de las personas que informen sobre infracciones normativas.',
        'El acuse de recibo lo da el canal al recibir la denuncia (art. 9.2.c).',
      ],
    };

    const admin = pintar('admin');
    expect(plazos(admin)).toEqual(esperado);
    // Es información fija, no un aviso: sin role="alert".
    expect(admin.querySelector('section.plazos [role="alert"], section.plazos[role="alert"]')).toBeNull();
    TestBed.resetTestingModule();
    expect(plazos(pintar('instructor'))).toEqual(esperado);
    TestBed.resetTestingModule();
    // Control del negativo: el admin y la instructora de arriba sí lo ven.
    const auditor = pintar('auditor');
    expect(accesos(auditor)).toEqual([['Auditoría', '/auditoria'], ['Mi cuenta', '/cuenta']]);
    expect(plazos(auditor)).toBeNull();
  });

  describe('el canal de denuncias de la empresa', () => {
    // Solo el portapapeles, no el navigator entero: el resto lo usa Angular.
    const portapapeles = (escribir: (texto: string) => Promise<void>) =>
      Object.defineProperty(navigator, 'clipboard', { value: { writeText: escribir }, configurable: true });
    afterEach(() => Reflect.deleteProperty(navigator, 'clipboard'));

    const tarjeta = (raiz: HTMLElement) => {
      const seccion = raiz.querySelector('section.canal');
      const enlace = seccion?.querySelector('a');
      return seccion === null ? null : {
        titulo: seccion.querySelector('h2')?.textContent?.trim(),
        nombre: seccion.getAttribute('aria-labelledby'),
        texto: seccion.querySelector('code.enlace')?.textContent?.trim(),
        ayudas: [...seccion.querySelectorAll('.ayuda')].map((p) => p.textContent?.trim()),
        boton: seccion.querySelector('button')?.textContent?.trim(),
        abrir: [enlace?.textContent?.trim(), enlace?.getAttribute('href'), enlace?.getAttribute('target'),
                enlace?.getAttribute('rel')],
      };
    };
    const ESPERADA = {
      titulo: 'Canal de denuncias de su empresa',
      nombre: 'inicio-canal',
      texto: ENLACE,
      ayudas: [
        'La empresa debe publicar este enlace en la página de inicio de su web (art. 25 de la Ley 2/2023).',
        'Lo que envíe desde ahí llega como una denuncia real de su empresa.',
      ],
      boton: 'Copiar el enlace',
      abrir: ['Abrir el formulario (se abre en una pestaña nueva)', ENLACE, '_blank', 'noopener noreferrer'],
    };

    it('la ve todo el personal, con el enlace que da la API, y es la última de la página', () => {
      for (const rol of ['admin', 'instructor', 'auditor'] as const) {
        TestBed.resetTestingModule();
        const raiz = pintar(rol);
        expect(tarjeta(raiz)).toEqual(ESPERADA);
        // Dato de consulta: va después de los accesos y de los plazos.
        expect(raiz.lastElementChild?.matches('section.canal')).toBe(true);
      }
    });

    it('copiar avisa en una región viva que ya estaba en la página', async () => {
      const escribir = vi.fn().mockResolvedValue(undefined);
      portapapeles(escribir);
      const pagina = crear('auditor');
      const raiz = pagina.nativeElement as HTMLElement;
      const estado = () => raiz.querySelectorAll('section.canal [role="status"]');
      // Control: la región existe y está vacía antes de pulsar; sin ella, el
      // texto de después no diría si se anuncia.
      expect(estado().length).toBe(1);
      expect(estado()[0].textContent?.trim()).toBe('');
      const region = estado()[0];
      (raiz.querySelector('section.canal button') as HTMLButtonElement).click();
      await vi.waitFor(() => {
        pagina.detectChanges();
        expect(region.textContent?.trim()).toBe('Copiado.');
      });
      expect(escribir).toHaveBeenCalledWith(ENLACE);
      // El mismo nodo: solo ha cambiado su texto.
      expect(estado()[0]).toBe(region);
    });

    it('si el navegador no deja copiar, lo dice y cómo seguir', async () => {
      portapapeles(vi.fn().mockRejectedValue(new Error('denegado')));
      const pagina = crear('admin');
      const raiz = pagina.nativeElement as HTMLElement;
      (raiz.querySelector('section.canal button') as HTMLButtonElement).click();
      await vi.waitFor(() => {
        pagina.detectChanges();
        expect(raiz.querySelector('section.canal [role="status"]')?.textContent?.trim())
          .toBe('No se ha podido copiar: selecciónelo y cópielo a mano.');
      });
    });
  });
});
