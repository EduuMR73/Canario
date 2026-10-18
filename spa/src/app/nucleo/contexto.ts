import { HttpContextToken } from '@angular/common/http';

// Marca de las peticiones que pueden renovar la sesión (renovacion.ts): solo
// las que la usan. Por defecto false. El login, la activación y el registro
// también responden 401 cuando fallan, y renovar ahí repetiría la petición:
// un login fallido contaría dos fallos en el bloqueo de la cuenta
// (app/personal.py). Con la marca explícita, una ruta nueva no renueva por
// descuido. Va en su propio fichero para que api.ts la use sin depender del
// interceptor.
export const RENOVABLE = new HttpContextToken<boolean>(() => false);
