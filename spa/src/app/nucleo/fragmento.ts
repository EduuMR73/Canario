// Tokens que llegan en el fragmento (#...) de un enlace de correo: el de
// verificación del registro y el de activación de una cuenta
// (app/solicitudes.py, RUTA_VERIFICACION y RUTA_ACTIVACION). El fragmento no
// viaja al servidor ni en la cabecera Referer, pero se queda en la barra de
// direcciones y en la entrada del historial de la pestaña. Por eso main.ts lo
// lee y lo borra con history.replaceState ANTES de arrancar Angular: ni un
// fallo del arranque lo deja a la vista.
//
// Límite: no está garantizado que el historial global del navegador olvide la
// URL con la que se abrió el enlace. Lo que protege el token es que sirve una
// sola vez y caduca (docs/threat-model.md, 8).
//
// El token vive solo en memoria, nunca en localStorage ni en sessionStorage:
// un script de la página podría leerlo de ahí. Si se recarga la página a
// mitad, se vuelve a abrir el enlace (la activación se puede repetir hasta
// confirmarla, app/personal.py, activar).

export const RUTAS_CON_TOKEN = ['/activacion', '/registro/verificacion'] as const;
export type RutaConToken = (typeof RUTAS_CON_TOKEN)[number];

type Lugar = Pick<Location, 'pathname' | 'search' | 'hash'>;
type Historial = Pick<History, 'state' | 'replaceState'>;

let guardado: { ruta: RutaConToken; token: string } | null = null;

// El formato del token lo decide la API: aquí solo se toma lo que hay detrás
// de "#", en las dos rutas que lo esperan. Las demás no se tocan.
export function tomarTokenDelFragmento(lugar: Lugar = location, historial: Historial = history): void {
  const ruta = RUTAS_CON_TOKEN.find((r) => r === lugar.pathname);
  if (ruta === undefined || lugar.hash.length <= 1) {
    return;
  }
  guardado = { ruta, token: lugar.hash.slice(1) };
  historial.replaceState(historial.state, '', lugar.pathname + lugar.search);
}

// Entrega el token una sola vez y solo a la página de su ruta.
export function consumirToken(ruta: RutaConToken): string | null {
  if (guardado === null || guardado.ruta !== ruta) {
    return null;
  }
  const token = guardado.token;
  guardado = null;
  return token;
}
