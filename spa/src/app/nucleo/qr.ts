import qrcode from 'qrcode-generator';

// Código QR de la URI otpauth para la aplicación de autenticación.
//
// Se dibuja como un <path> de SVG en la plantilla, sin <img>: la CSP del 8445
// no tiene img-src (proxy/Caddyfile), y un data: obligaría a abrirla. De la
// biblioteca solo se usa la matriz (isDark); sus createImgTag y createSvgTag
// devuelven HTML como texto, que habría que meter con innerHTML, y Trusted
// Types lo bloquea.
//
// Un solo <path> con un cuadrado por módulo oscuro, no un <rect> por módulo:
// menos nodos en el DOM.

// Zona de silencio de 4 módulos alrededor (ISO/IEC 18004): sin ella, algunos
// lectores no encuentran el código.
const MARGEN = 4;

export interface Qr {
  lado: number;
  ruta: string;
}

export function qrDe(texto: string): Qr {
  // Versión automática (0) y corrección de errores M, la habitual.
  const codigo = qrcode(0, 'M');
  codigo.addData(texto);
  codigo.make();
  const modulos = codigo.getModuleCount();
  const trozos: string[] = [];
  for (let fila = 0; fila < modulos; fila++) {
    for (let columna = 0; columna < modulos; columna++) {
      if (codigo.isDark(fila, columna)) {
        trozos.push(`M${columna + MARGEN} ${fila + MARGEN}h1v1h-1z`);
      }
    }
  }
  return { lado: modulos + 2 * MARGEN, ruta: trozos.join('') };
}
