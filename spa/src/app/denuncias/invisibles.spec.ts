import { describe, expect, it } from 'vitest';
import { avisoInvisibles, segmentar } from './invisibles';

// Oráculos literales: los códigos de Unicode (UCD, Bidi_Control y la categoría
// Cc) y los textos de la pantalla, no las constantes del código que se prueba.
// Los invisibles se escriben como escapes: un carácter bidi literal en el
// fuente reordenaría lo que se lee de esta misma prueba.

// Los 12 de Bidi_Control (PropList.txt de Unicode): ALM, LRM, RLM, LRE, RLE,
// PDF, LRO, RLO, LRI, RLI, FSI y PDI.
const BIDI_CONTROL = [
  '\u061C', '\u200E', '\u200F', '\u202A', '\u202B', '\u202C',
  '\u202D', '\u202E', '\u2066', '\u2067', '\u2068', '\u2069',
];

describe('caracteres invisibles del texto libre', () => {
  it('un texto sin invisibles sale en un solo segmento, igual, con tabulador, saltos y CRLF', () => {
    const texto = 'Pagó 500 € el 21/03.\n\tSegunda línea.\r\nTercera.';
    expect(segmentar(texto)).toEqual({ segmentos: [{ valor: texto, marca: null, codigos: null }], invisibles: 0 });
    expect(segmentar('')).toEqual({ segmentos: [], invisibles: 0 });
  });

  it('el RLO se cambia por una marca que dice que invierte el texto', () => {
    expect(segmentar('pagó \u202E0051\u202C euros')).toEqual({
      segmentos: [
        { valor: 'pagó ', marca: null, codigos: null },
        { valor: '\u202E', marca: '[invisible: invierte el texto]', codigos: 'U+202E' },
        { valor: '0051', marca: null, codigos: null },
        { valor: '\u202C', marca: '[invisible: cambia la dirección]', codigos: 'U+202C' },
        { valor: ' euros', marca: null, codigos: null },
      ],
      invisibles: 2,
    });
  });

  it('se marcan los 12 de Bidi_Control, también el RLM y el LRM', () => {
    for (const caracter of BIDI_CONTROL) {
      const { segmentos, invisibles } = segmentar('a' + caracter + 'b');
      expect(invisibles).toBe(1);
      expect(segmentos[1].valor).toBe(caracter);
      expect(segmentos[1].marca).not.toBeNull();
    }
  });

  it('se marcan los de control salvo tabulador, LF y el CR de un CRLF; el CR suelto, sí', () => {
    expect(segmentar('a\rb').segmentos[1]).toEqual({ valor: '\r', marca: '[invisible: carácter de control]',
      codigos: 'U+000D' });
    expect(segmentar('a\u001Bb').segmentos[1].codigos).toBe('U+001B');
    expect(segmentar('a\u000Cb').segmentos[1].codigos).toBe('U+000C');
    expect(segmentar('a\u0085b').segmentos[1].codigos).toBe('U+0085');
    expect(segmentar('a\u007Fb').segmentos[1].codigos).toBe('U+007F');
    expect(segmentar('a\r\n\tb').invisibles).toBe(0);
    expect(segmentar('a\r\r\nb').invisibles).toBe(1);
  });

  it('se marcan los cuatro de ancho cero', () => {
    for (const caracter of ['\u200B', '\u2060', '\uFEFF', '\u180E']) {
      expect(segmentar('a' + caracter + 'b').segmentos[1].marca).toBe('[invisible: ancho cero]');
    }
  });

  it('no se marcan ZWJ, ZWNJ, el guion blando, las etiquetas ni los selectores de variación', () => {
    const familia = '\u{1F468}\u200D\u{1F469}\u200D\u{1F467}';
    const persa = '\u0645\u06CC\u200C\u062E\u0648\u0627\u0647\u0645';
    const escocia = '\u{1F3F4}\u{E0067}\u{E0062}\u{E0073}\u{E0063}\u{E0074}\u{E007F}';
    const otros = 'in\u00ADforme \u2764\uFE0F';
    for (const texto of [familia, persa, escocia, otros]) {
      expect(segmentar(texto)).toEqual({ segmentos: [{ valor: texto, marca: null, codigos: null }], invisibles: 0 });
    }
  });

  it('una racha de invisibles seguidos es una sola marca, con cada nombre una vez', () => {
    expect(segmentar('a\u202C\u200B\u200Fb').segmentos[1]).toEqual({
      valor: '\u202C\u200B\u200F',
      marca: '[3 invisibles: cambia la dirección, ancho cero]',
      codigos: 'U+202C U+200B U+200F',
    });
    const larga = segmentar('\u200B'.repeat(10000));
    expect(larga.segmentos.length).toBe(1);
    expect(larga.invisibles).toBe(10000);
    expect(larga.segmentos[0].marca).toBe('[10000 invisibles: ancho cero]');
    expect(larga.segmentos[0].codigos).toBe('U+200B U+200B U+200B U+200B U+200B U+200B U+200B U+200B U+200B U+200B ' +
      'y 9990 más');
  });

  it('una marca escrita a mano es texto: ni se cuenta ni se separa', () => {
    const falsa = 'Mire: [invisible: invierte el texto] y [U+202E].';
    expect(segmentar(falsa)).toEqual({ segmentos: [{ valor: falsa, marca: null, codigos: null }], invisibles: 0 });
  });

  it('un carácter fuera del plano básico no se parte', () => {
    expect(segmentar('\u{1F600}\u202E\u{1F600}').segmentos.map((s) => s.valor))
      .toEqual(['\u{1F600}', '\u202E', '\u{1F600}']);
  });

  it('el aviso dice cuántos hay, en singular o en plural, y que lo guardado no cambia', () => {
    expect(avisoInvisibles(1)).toBe('Este texto tiene 1 carácter invisible. Puede desordenar o esconder parte de ' +
      'lo que se lee, así que se muestra marcado entre corchetes. El texto guardado no cambia.');
    expect(avisoInvisibles(4)).toBe('Este texto tiene 4 caracteres invisibles. Pueden desordenar o esconder parte ' +
      'de lo que se lee, así que se muestran marcados entre corchetes. El texto guardado no cambia.');
  });
});
