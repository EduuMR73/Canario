// Los textos del código TOTP que piden las acciones de admin (cuentas y
// solicitudes; nucleo/api-cuentas.ts). Cada paso de 30 segundos vale una
// sola vez por cuenta (app/personal.py, transaccion_con_codigo): dos acciones
// seguidas no pueden usar el mismo código, y la ayuda lo dice antes de que
// falle.
//
// Un código malo o ya usado es un 401 sin WWW-Authenticate: no es la sesión
// (nucleo/renovacion.ts, sesionCaducada), así que no se renueva ni se sale a
// /entrar. El mismo texto vale para todos los casos, porque la API no dice
// cuál ha sido: tampoco si el dispositivo está en espera tras varios fallos
// (app/personal.py, _codigo_de_la_sesion), para no confirmar a quien prueba
// códigos que ha llegado al límite.

export const AYUDA_CODIGO_ACCION = 'Las 6 cifras de su aplicación. Cada código vale una vez: para otra acción, espere al siguiente.';

export const TEXTO_CODIGO_NO_VALE = 'El código no es correcto o ya se ha usado. Espere a que su aplicación muestre uno nuevo.';
