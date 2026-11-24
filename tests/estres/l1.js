// L1 de docs/informe-pruebas.md: capacidad y codo de las rutas caras, para
// k6 v2.3.0 (imagen fijada por digest en tests/estres/lanzar.py).
//
// Cada ejecución de k6 mide UN escalón de UNA ruta. El lanzador decide la
// escalera (corte tras dos escalones seguidos fuera del SLO) entre una
// ejecución y la siguiente: k6 no puede parar un escenario según el
// resultado de los anteriores, y un umbral con abortOnFail pararía la
// prueba entera, no "dos escalones seguidos".
//
// Los datos de la ejecución (ruta, escalón, tasas, VUs, identificador de la
// empresa) llegan por /datos/ejecucion.json, montado de solo lectura: nada
// por argv ni por variables de entorno. Este script solo los transcribe;
// todo el cálculo (tasas, duraciones, maxVUs) está en el lanzador, en un
// solo sitio.
//
// Escenarios de una ejecución:
// * calentamiento (solo en el primer escalón de cada ruta): 30 s a la tasa
//   del escalón de control, fuera del análisis;
// * <ruta>__<escalon>: la ruta medida, constant-arrival-rate (modelo
//   abierto: la tasa no baja aunque Canario se frene);
// * sonda_salud__<ruta>__<escalon> y sonda_web__<ruta>__<escalon>: las dos
//   sondas de atribución a 1 petición por segundo, a la vez que la ruta.
//
// preAllocatedVUs = maxVUs en todos los escenarios: k6 no inicializa VUs a
// mitad de la prueba, así que una iteración descartada (dropped_iterations)
// solo puede significar que todos los VUs estaban ocupados esperando a
// Canario (comprobado en lib/executor/constant_arrival_rate.go de la v2.3.0:
// con remainingUnplannedVUs == 0, el descarte va con el aviso "Insufficient
// VUs"). El lanzador cruza los descartes con ese aviso.
//
// Protocolo: HTTP/1.1. Caddy solo sirve h1 (proxy/servidor.caddy, protocols
// h1), así que ALPN no puede negociar h2. El lanzador lo comprueba con la
// etiqueta proto de cada petición.

import http from 'k6/http';

const datos = JSON.parse(open('/datos/ejecucion.json'));

const API = 'https://localhost:8443';
const WEB = 'https://localhost:8444';

// Estado esperado de cada ruta. Literales: login con email o empresa
// inexistentes, 401 (app/rutas_personal.py, CredencialesNoValidas);
// seguimiento con un código inexistente de formato válido, 404
// (app/rutas_denuncias.py); denuncia válida, 201. Las sondas: POST /salud,
// que solo admite GET, 405; GET /seguimiento del 8444, 200.
const ESPERADO = {
  login_email: 401,
  login_empresa: 401,
  seguimiento: 404,
  denuncia: 201,
  sonda_salud: 405,
  sonda_web: 200,
};

// Plazo de cada petición: por encima de los 10 s de espera del pool de
// PostgreSQL y de los 2 s del semáforo de Argon2, para que esas esperas se
// vean como latencia o como 503, no como un plazo del cliente.
const PLAZO = '15s';

// Validación de lo que llega del lanzador: un fichero incompleto es un
// error visible al arrancar, no una prueba que mide otra cosa.
function exigir(condicion, texto) {
  if (!condicion) {
    throw new Error(`ejecucion.json no valido: ${texto}`);
  }
}

exigir(Object.prototype.hasOwnProperty.call(ESPERADO, datos.ruta) && !datos.ruta.startsWith('sonda_'),
  'ruta desconocida');
exigir(typeof datos.escalon === 'string' && /^e[0-9]+$/.test(datos.escalon), 'escalon');
exigir(typeof datos.identificador === 'string' && /^[0-9a-f]{32}$/.test(datos.identificador), 'identificador');

function escenario(funcion, tramo, ruta, escalon) {
  exigir(Number.isInteger(tramo.rate) && tramo.rate > 0, `${funcion}: rate`);
  exigir(Number.isInteger(tramo.time_unit_s) && tramo.time_unit_s > 0, `${funcion}: time_unit_s`);
  exigir(Number.isInteger(tramo.duracion_s) && tramo.duracion_s > 0, `${funcion}: duracion_s`);
  exigir(Number.isInteger(tramo.inicio_s) && tramo.inicio_s >= 0, `${funcion}: inicio_s`);
  exigir(Number.isInteger(tramo.vus) && tramo.vus > 0, `${funcion}: vus`);
  return {
    executor: 'constant-arrival-rate',
    rate: tramo.rate,
    timeUnit: `${tramo.time_unit_s}s`,
    duration: `${tramo.duracion_s}s`,
    startTime: `${tramo.inicio_s}s`,
    preAllocatedVUs: tramo.vus,
    maxVUs: tramo.vus,
    // Las peticiones en vuelo al acabar el escenario terminan (como mucho
    // el plazo de 15 s): cortarlas las contaría como errores falsos.
    gracefulStop: '20s',
    exec: funcion,
    tags: { escalon, ruta },
  };
}

const escenarios = {};
if (datos.calentamiento !== null) {
  escenarios[`calentamiento__${datos.ruta}`] = escenario(datos.ruta, datos.calentamiento, datos.ruta, 'calentamiento');
}
const nombre = `${datos.ruta}__${datos.escalon}`;
escenarios[nombre] = escenario(datos.ruta, datos.principal, datos.ruta, datos.escalon);
escenarios[`sonda_salud__${nombre}`] = escenario('sonda_salud', datos.sonda, 'sonda_salud', datos.escalon);
escenarios[`sonda_web__${nombre}`] = escenario('sonda_web', datos.sonda, 'sonda_web', datos.escalon);

export const options = {
  scenarios: escenarios,
  // Solo hacia localhost dentro del espacio de red del contenedor de Caddy
  // (--network container:<caddy>): el tráfico no sale de ese espacio de red
  // y lo que se mide es la capacidad, no la autenticidad del servidor, que
  // ya prueban las baterías de seguridad. Verificar contra la CA raíz de
  // Caddy obligaría a confiar en que k6 respete SSL_CERT_FILE (no lo
  // documenta), y un fallo ahí daría una escalera entera de errores TLS.
  // El coste del handshake es el mismo verificando o sin verificar.
  insecureSkipTLSVerify: true,
  // Solo importa el código de estado: sin cuerpos, menos memoria por VU.
  discardResponseBodies: true,
  // Sin la URL completa (lleva el identificador de la empresa) ni etiquetas
  // que no se analizan: el CSV pesa menos.
  systemTags: ['status', 'error', 'error_code', 'scenario', 'proto', 'method', 'name', 'expected_response'],
  summaryTrendStats: ['min', 'med', 'p(95)', 'p(99)', 'max', 'count'],
  userAgent: 'canario-estres-l1',
  // k6 envía por defecto un informe de uso a Grafana; el contenedor tiene
  // salida a internet por la red edge de Caddy.
  noUsageReport: true,
};

// El estado esperado de la ruta medida cuenta como respuesta esperada
// (métrica http_req_failed y etiqueta expected_response). Las sondas, que
// esperan otro estado, lo declaran en cada petición.
http.setResponseCallback(http.expectedStatuses(ESPERADO[datos.ruta]));

const CABECERAS = { 'Content-Type': 'application/json' };
const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const HEX = '0123456789abcdef';

function aleatorio(alfabeto, longitud) {
  let texto = '';
  for (let i = 0; i < longitud; i += 1) {
    texto += alfabeto[Math.floor(Math.random() * alfabeto.length)];
  }
  return texto;
}

// Código de seguimiento con el formato válido (8 grupos de 4 en base32, 160
// bits, como PATRON_CODIGO de tests/funcionales/test_circuito.py): pasa
// cripto.leer_codigo y llega al HMAC y al SELECT. Uno mal formado daría el
// mismo 404 sin tocar la base de datos y no mediría nada.
function codigoInexistente() {
  const crudo = aleatorio(BASE32, 32);
  return crudo.match(/.{4}/g).join('-');
}

function parametros(nombreRuta, esperado) {
  const p = { headers: CABECERAS, timeout: PLAZO, tags: { name: nombreRuta } };
  if (esperado !== undefined) {
    p.responseCallback = http.expectedStatuses(esperado);
  }
  return p;
}

// Contraseña y código TOTP de relleno, distintos en cada petición: no son
// credenciales de nadie. Con una cuenta inexistente el login hace el mismo
// Argon2 contra el hash ficticio (app/personal.py, _verificar_hash).
function cuerpoLogin(empresa, email) {
  return JSON.stringify({
    empresa,
    email,
    contrasena: aleatorio(HEX, 24),
    codigo_totp: aleatorio('0123456789', 6),
  });
}

export function login_email() {
  // Empresa real, email que no existe en ella (dominio .invalid, RFC 6761).
  const email = `estres-${aleatorio(HEX, 16)}@estres.invalid`;
  http.post(`${API}/v1/personal/sesiones`, cuerpoLogin(datos.identificador, email), parametros('login'));
}

export function login_empresa() {
  // Identificador con el formato válido (32 hexadecimales) que no existe:
  // resolver_empresa consulta la base de datos y no encuentra nada.
  const email = `estres-${aleatorio(HEX, 16)}@estres.invalid`;
  http.post(`${API}/v1/personal/sesiones`, cuerpoLogin(aleatorio(HEX, 32), email), parametros('login'));
}

export function seguimiento() {
  http.post(`${API}/v1/seguimiento`, JSON.stringify({ codigo: codigoInexistente() }), parametros('seguimiento'));
}

export function denuncia() {
  const cuerpo = JSON.stringify({
    categoria: 'otros',
    texto: `Denuncia de la prueba de estres L1 ${aleatorio(HEX, 16)}`,
  });
  http.post(`${API}/v1/empresas/${datos.identificador}/denuncias`, cuerpo, parametros('denuncia'));
}

// Sondas de atribución (docs/informe-pruebas.md, "Qué se registra"): /salud
// no toca la base de datos ni el limitador (exenta) y NO pasa por el pool de
// hilos: Starlette resuelve su 405 en Route.handle, con un _http_exception
// async. Si suben las dos sondas, es CPU, bucle o GIL; si solo sube sonda_web,
// son los hilos. GET /web/seguimiento es síncrona y barata, sin base de datos.
export function sonda_salud() {
  http.post(`${API}/salud`, null, parametros('sonda_salud', ESPERADO.sonda_salud));
}

export function sonda_web() {
  http.get(`${WEB}/seguimiento`, { timeout: PLAZO, tags: { name: 'sonda_web' },
    responseCallback: http.expectedStatuses(ESPERADO.sonda_web) });
}

// El resumen de fin de prueba, en JSON, junto al CSV. handleSummary
// sustituye al resumen de la terminal: el análisis lo hace el lanzador.
export function handleSummary(datosResumen) {
  return { '/salida/resumen.json': JSON.stringify(datosResumen, null, 1) };
}
