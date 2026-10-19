import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { describe, expect, it } from 'vitest';
import { NoDisponible } from './no-disponible';

// Ninguna batería llega a esta página en Chromium (haría falta cortar la red
// en mitad del recorrido): se pinta el componente aquí. Oráculos literales:
// la clase y el aria-hidden de Leila, el texto del botón.
describe('página no disponible', () => {
  it('lleva a Leila decorativa y conserva el aviso y el botón de reintentar', () => {
    TestBed.configureTestingModule({ providers: [provideRouter([])] });
    const pagina = TestBed.createComponent(NoDisponible);
    pagina.detectChanges();
    const raiz = pagina.nativeElement as HTMLElement;

    // Control: la página está entera. Sin el aviso o el botón, mirar a Leila
    // no diría nada de una página que ya no sirve.
    expect(raiz.querySelector('main [role="alert"]')?.textContent?.trim()).toBeTruthy();
    expect([...raiz.querySelectorAll('main button')].map((b) => b.textContent?.trim())).toEqual(['Reintentar']);

    expect([...raiz.querySelectorAll('svg')].map((s) => [s.getAttribute('class'), s.getAttribute('aria-hidden')]))
      .toEqual([['leila', 'true']]);
  });
});
