// Los caracteres invisibles del texto libre de una denuncia (modelo de
// amenazas, 6.11). El texto lo escribe un denunciante anónimo y lo lee el
// personal, que decide con lo que ve. La API lo guarda tal cual, porque es una
// prueba (6.16), así que un U+202E (RIGHT-TO-LEFT OVERRIDE) llega a la SPA y
// da la vuelta a todo lo que le sigue dentro de su párrafo: "pagó 0051 euros"
// se lee "pagó 1500 euros" (CWE-451, como Trojan Source, CVE-2021-42574).
//
// dir="auto", <bdi> o unicode-bidi: isolate no lo evitan. Aíslan el párrafo de
// lo que hay alrededor, pero no frenan el control dentro de él (UAX #9, X8).
// Quitar el carácter tampoco sirve: escondería que alguien lo puso. Por eso
// cada racha de invisibles se cambia por una marca visible y se cuenta en un
// aviso. Lo que se pinta deja de llevar el carácter, y lo guardado no cambia.
//
// Qué se marca:
// * Los 12 caracteres con la propiedad Bidi_Control: cambian el orden o la
//   dirección. También LRM y RLM: con dir="auto", un RLM al principio pondría
//   todo el párrafo de derecha a izquierda.
// * Los de control (Cc), salvo el tabulador, el salto de línea y el retorno
//   de carro de un CRLF: los otros no se ven o se ven distinto según el
//   navegador. El formulario sin JS envía los saltos como CRLF (HTML, "form
//   submission"), así que un CR seguido de LF es un salto normal. Un CR suelto
//   se marca.
// * Cuatro de ancho cero que no forman nada legítimo en un texto como este:
//   U+200B, U+2060, U+FEFF y U+180E. Esconden texto y rompen las búsquedas.
//
// Qué no se marca, aunque sea invisible: ZWJ y ZWNJ (U+200D y U+200C), que
// forman los emojis compuestos y la escritura del persa y de las lenguas de la
// India; el guion blando (U+00AD), que llega al pegar desde un procesador de
// textos; las etiquetas (U+E0020 a U+E007F) de las banderas de subdivisión; y
// los selectores de variación, que son Mn y no Cf. Marcarlos daría falsos
// avisos en textos legítimos, y no reordenan nada. Los homoglifos (la "e"
// cirílica, U+0435) quedan fuera: no son invisibles (límite en el modelo de
// amenazas).

export interface Segmento {
  // El texto tal cual, o la racha de invisibles que la marca sustituye.
  readonly valor: string;
  // null para el texto normal; para una racha, lo que se pinta en su lugar.
  readonly marca: string | null;
  // Los códigos de la racha, para quien los necesite (atributo title).
  readonly codigos: string | null;
}

export interface TextoSegmentado {
  readonly segmentos: readonly Segmento[];
  // Cuántos caracteres invisibles hay, no cuántas rachas.
  readonly invisibles: number;
}

const BIDI = /^\p{Bidi_Control}$/u;
const CONTROL = /^\p{Cc}$/u;
const ANCHO_CERO: ReadonlySet<string> = new Set(['\u200B', '\u2060', '\uFEFF', '\u180E']);
// El title de una racha larga se corta: basta para saber de qué se trata.
const CODIGOS_MAXIMOS = 10;

// Qué hace un carácter invisible, en palabras de quien instruye, o null si no
// se marca. El siguiente carácter decide el del CR.
function nombreInvisible(caracter: string, siguiente: string | undefined): string | null {
  if (caracter === '\u202E') {
    return 'invierte el texto';
  }
  if (BIDI.test(caracter)) {
    return 'cambia la dirección';
  }
  if (ANCHO_CERO.has(caracter)) {
    return 'ancho cero';
  }
  if (caracter === '\t' || caracter === '\n' || (caracter === '\r' && siguiente === '\n')) {
    return null;
  }
  if (CONTROL.test(caracter)) {
    return 'carácter de control';
  }
  return null;
}

function codigo(caracter: string): string {
  return 'U+' + caracter.codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0');
}

function marcaDe(nombres: readonly string[]): string {
  if (nombres.length === 1) {
    return `[invisible: ${nombres[0]}]`;
  }
  return `[${nombres.length} invisibles: ${[...new Set(nombres)].join(', ')}]`;
}

function codigosDe(racha: readonly string[]): string {
  const vistos = racha.slice(0, CODIGOS_MAXIMOS).map(codigo).join(' ');
  return racha.length > CODIGOS_MAXIMOS ? `${vistos} y ${racha.length - CODIGOS_MAXIMOS} más` : vistos;
}

// Parte el texto en segmentos: el texto normal tal cual y cada racha de
// invisibles seguidos en uno solo, con su marca. Una racha es un solo
// elemento en la página: un texto de 10 000 invisibles no crea 10 000. Se
// recorre por puntos de código (Array.from), no por unidades UTF-16, para no
// partir un emoji ni un carácter fuera del plano básico.
export function segmentar(texto: string): TextoSegmentado {
  const caracteres = Array.from(texto);
  const segmentos: Segmento[] = [];
  let normal = '';
  let racha: string[] = [];
  let nombres: string[] = [];
  let invisibles = 0;

  const cerrarNormal = () => {
    if (normal !== '') {
      segmentos.push({ valor: normal, marca: null, codigos: null });
      normal = '';
    }
  };
  const cerrarRacha = () => {
    if (racha.length > 0) {
      segmentos.push({ valor: racha.join(''), marca: marcaDe(nombres), codigos: codigosDe(racha) });
      racha = [];
      nombres = [];
    }
  };

  caracteres.forEach((caracter, i) => {
    const nombre = nombreInvisible(caracter, caracteres[i + 1]);
    if (nombre === null) {
      cerrarRacha();
      normal += caracter;
    } else {
      cerrarNormal();
      racha.push(caracter);
      nombres.push(nombre);
      invisibles += 1;
    }
  });
  cerrarNormal();
  cerrarRacha();
  return { segmentos, invisibles };
}

// El aviso que va encima de un texto con invisibles. Dice que el texto
// guardado no cambia: es una prueba, y la marca es solo cómo se enseña.
export function avisoInvisibles(invisibles: number): string {
  if (invisibles === 1) {
    return 'Este texto tiene 1 carácter invisible. Puede desordenar o esconder parte de lo que se lee, así que ' +
      'se muestra marcado entre corchetes. El texto guardado no cambia.';
  }
  return `Este texto tiene ${invisibles} caracteres invisibles. Pueden desordenar o esconder parte de lo que se ` +
    'lee, así que se muestran marcados entre corchetes. El texto guardado no cambia.';
}
