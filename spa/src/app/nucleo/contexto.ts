import { HttpContext, HttpContextToken } from '@angular/common/http';

// Marca de las peticiones que pueden renovar la sesión (renovacion.ts): solo
// las que la usan. Por defecto false. El login, la activación y el registro
// también responden 401 cuando fallan, y renovar ahí repetiría la petición:
// un login fallido contaría dos fallos en el bloqueo de la cuenta
// (app/personal.py). Con la marca explícita, una ruta nueva no renueva por
// descuido. Va en su propio fichero para que los clientes de la API la usen
// sin depender del interceptor.
export const RENOVABLE = new HttpContextToken<boolean>(() => false);

// Las rutas que usan la sesión llevan la marca RENOVABLE. La comparten todos
// los clientes de la API (api.ts, api-cuentas.ts).
export function conSesion(): { context: HttpContext } {
  return { context: new HttpContext().set(RENOVABLE, true) };
}
