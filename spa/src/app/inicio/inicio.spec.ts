import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { describe, expect, it } from 'vitest';
import { Rol } from '../nucleo/api';
import { Sesion } from '../nucleo/sesion';
import { Inicio } from './inicio';

// Oráculos literales: los textos y las rutas de los accesos de cada rol, no
// las constantes del código que se prueba (nucleo/permisos.ts, MENU).
function pintar(rol: Rol, invitacion_pendiente = false): HTMLElement {
  const yo = signal({ usuario_id: 'u', email: 'persona@canario.test', rol, invitacion_pendiente });
  TestBed.configureTestingModule({ providers: [provideRouter([]), { provide: Sesion, useValue: { yo } }] });
  const pagina = TestBed.createComponent(Inicio);
  pagina.detectChanges();
  return pagina.nativeElement as HTMLElement;
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
        acuse: seccion.querySelector('.ayuda')?.textContent?.trim(),
      };
    };
    const esperado = {
      titulo: 'Plazos de la Ley 2/2023',
      nombre: 'inicio-plazos',
      lista: PLAZOS,
      acuse: 'El acuse de recibo lo da el canal al recibir la denuncia (art. 9.2.c).',
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
});
