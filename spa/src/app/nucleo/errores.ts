import { HttpErrorResponse } from '@angular/common/http';

// Texto para la persona a partir de un error de la API. Los casos comunes
// (sin red, límite de peticiones, servicio caído) son iguales en todas las
// páginas; cada página da el texto de los suyos (401, 409, 422...). El
// mensaje del servidor solo se muestra cuando la página lo pide (por ejemplo,
// la política de contraseñas), y siempre por interpolación: Angular lo
// escapa.

export type TextosPropios = Partial<Record<number, string>>;

export const TEXTO_SIN_CONEXION = 'No hay conexión con el servidor. Compruebe la red e inténtelo de nuevo.';
export const TEXTO_NO_DISPONIBLE = 'El servicio no está disponible ahora mismo. Inténtelo de nuevo en unos minutos.';
export const TEXTO_INESPERADO = 'Ha ocurrido un error inesperado. Inténtelo de nuevo.';

export function textoDeError(error: unknown, propios: TextosPropios = {}): string {
  if (!(error instanceof HttpErrorResponse)) {
    return TEXTO_INESPERADO;
  }
  const propio = propios[error.status];
  if (propio !== undefined) {
    return propio;
  }
  if (error.status === 0) {
    return TEXTO_SIN_CONEXION;
  }
  if (error.status === 429) {
    return `Demasiadas peticiones seguidas. Espere ${esperaDe(error)} y vuelva a intentarlo.`;
  }
  if (error.status === 503) {
    return TEXTO_NO_DISPONIBLE;
  }
  return TEXTO_INESPERADO;
}

// El detalle que envía la API ({"detalle": "..."}, app/frontera_http.py), o
// null si no lo hay.
export function detalleDe(error: unknown): string | null {
  if (!(error instanceof HttpErrorResponse)) {
    return null;
  }
  const cuerpo: unknown = error.error;
  if (typeof cuerpo === 'object' && cuerpo !== null && 'detalle' in cuerpo && typeof cuerpo.detalle === 'string') {
    return cuerpo.detalle;
  }
  return null;
}

// La espera del Retry-After de un 429, en segundos (la API no envía fechas):
// en minutos si pasa de uno y en horas si pasa de una, porque el tope de
// lecturas (app/instruccion.py) espera hasta el día siguiente y "1440
// minutos" no se entiende. Se redondea hacia arriba: nunca antes de tiempo.
// Si no se puede leer, un texto genérico en vez de un número inventado.
export function esperaDe(error: HttpErrorResponse): string {
  const valor = error.headers.get('Retry-After');
  const segundos = valor !== null && /^\d+$/.test(valor) ? Number(valor) : NaN;
  if (Number.isNaN(segundos)) {
    return 'unos minutos';
  }
  if (segundos < 60) {
    return segundos === 1 ? '1 segundo' : `${segundos} segundos`;
  }
  if (segundos <= 3600) {
    const minutos = Math.ceil(segundos / 60);
    return minutos === 1 ? '1 minuto' : `${minutos} minutos`;
  }
  const horas = Math.ceil(segundos / 3600);
  return `${horas} horas`;
}
