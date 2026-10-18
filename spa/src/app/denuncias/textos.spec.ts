import { PartialMatchRouteSnapshot, Route, UrlSegment } from '@angular/router';
import { describe, expect, it } from 'vitest';
import { Mensaje } from '../nucleo/api-denuncias';
import {
  autorDe, avisoLecturas, conIdDeDenuncia, destinosDe, esCerrado, fechaLegible, nombreCategoria, puedeDeclararNoVeraz,
} from './textos';

// Oráculos literales: las transiciones de app/instruccion.py (TRANSICIONES),
// los textos de la pantalla y las formas de la API, no las constantes del
// código que se prueba.
const ID = '0b6f3c1e-8d2a-4f5b-9c7e-1a2b3c4d5e6f';

function mensaje(cambios: Partial<Mensaje>): Mensaje {
  return { secuencia: 1, fecha: '2026-10-18', autor: 'personal', autor_id: 'u1', texto: 't', ...cambios };
}

function casa(...segmentos: string[]): unknown {
  return conIdDeDenuncia({} as Route, segmentos.map((s) => new UrlSegment(s, {})), {} as PartialMatchRouteSnapshot);
}

describe('textos de las denuncias', () => {
  it('los cambios de estado que se ofrecen son los de la API, sin no veraz', () => {
    expect(destinosDe('nueva')).toEqual(['en_instruccion', 'inadmitida']);
    expect(destinosDe('en_instruccion')).toEqual(['resuelta', 'archivada']);
    expect(destinosDe('resuelta')).toEqual([]);
    expect(destinosDe('archivada')).toEqual([]);
    expect(destinosDe('inadmitida')).toEqual([]);
  });

  it('los estados cerrados, que exigen mensaje final y no admiten más mensajes', () => {
    expect(['resuelta', 'archivada', 'inadmitida'].map(esCerrado)).toEqual([true, true, true]);
    expect(['nueva', 'en_instruccion', '', 'no_veraz'].map(esCerrado)).toEqual([false, false, false, false]);
  });

  it('el instructor no puede declarar no veraz; el admin sí', () => {
    expect(puedeDeclararNoVeraz('instructor')).toBe(false);
    expect(puedeDeclararNoVeraz('auditor')).toBe(false);
    expect(puedeDeclararNoVeraz('admin')).toBe(true);
  });

  it('las fechas de la API se leen como día, sin pasar por Date', () => {
    expect(fechaLegible('2026-10-18')).toBe('18/10/2026');
    expect(fechaLegible('2026-01-01')).toBe('01/01/2026');
    expect(fechaLegible('20261018')).toBe('20261018');
  });

  it('el aviso de lecturas sale a partir de 20', () => {
    expect(avisoLecturas(19, 50)).toBeNull();
    expect(avisoLecturas(20, 50)).toBe('Lleva 20 de 50 denuncias distintas abiertas hoy. Al llegar a 50 no podrá abrir ' +
      'otras nuevas hasta mañana; las que ya abrió las puede seguir leyendo.');
  });

  it('el autor de un mensaje: denunciante, usted u otra persona del personal', () => {
    expect(autorDe(mensaje({ autor: 'denunciante', autor_id: null }), 'u1')).toBe('Denunciante');
    expect(autorDe(mensaje({ autor_id: 'u1' }), 'u1')).toBe('Usted');
    expect(autorDe(mensaje({ autor_id: 'u2' }), 'u1')).toBe('Personal');
    expect(autorDe(mensaje({ autor_id: null }), undefined)).toBe('Personal');
  });

  it('la categoría con su nombre, o tal cual si no se conoce', () => {
    expect(nombreCategoria('corrupcion')).toBe('Corrupción');
    expect(nombreCategoria('nueva_categoria')).toBe('nueva_categoria');
    expect(nombreCategoria('constructor')).toBe('constructor');
  });

  it('la ruta de una denuncia solo casa con un uuid', () => {
    expect(casa('denuncias', ID)).toBe(true);
    expect(casa('denuncias', '../usuarios')).toBe(false);
    expect(casa('denuncias', '..')).toBe(false);
    expect(casa('denuncias', ID.toUpperCase())).toBe(false);
    expect(casa('denuncias', ID, 'mensajes')).toBe(false);
  });
});
