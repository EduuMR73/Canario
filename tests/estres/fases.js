// L2 (aislamiento) y L4 (pico y recuperación) de docs/informe-pruebas.md, para
// k6 v2.3.0 (imagen fijada por digest en tests/estres/lanzar.py).
//
// Una ejecución de k6 por repetición, con varias fases seguidas (calentamiento,
// BASE, carga y RECUPERACIÓN). El lanzador calcula TODO (tasas, duraciones,
// VUs, rangos, fases) y lo deja en /datos/ejecucion.json, montado de solo
// lectura: este script solo lo transcribe. Nada por argv ni por variables de
// entorno.
//
// Las funciones de petición DUPLICAN a propósito las de l1.js: l1.js es el
// script de la evidencia de L1 y va montado en vivo mientras se mide, así que
// no se toca ni se comparte. Se unificarán cuando L1 x 3 haya terminado.
//
// Escenarios (todos constant-arrival-rate, modelo abierto: la tasa no baja
// aunque Canario se frene; preAllocatedVUs = maxVUs, como en l1.js, para que
// un descarte solo pueda significar "todos los VUs ocupados" y salga con el
// aviso "Insufficient VUs"):
// * L2: una víctima por ruta durante toda la ejecución y el login inundado
//   solo en su fase (startTime). La fase de cada petición va en la etiqueta
//   `fase`, calculada con el reloj respecto al instante en que acaba setup().
// * L4: un escenario por ruta y fase (F1), para atribuir los descartes a su
//   ruta. Los VUs de cada escenario se reservan al empezar: el lanzador
//   comprueba que la suma cabe en la memoria de k6 (J12).
//
// setup() puede esperar hasta un instante absoluto (alinear_epoch_ms). Aquí no
// se usa (L2 y L4 no dependen de la hora del reloj); l3.js sí. Imprime
// T0_MS=<epoch en ms> para que el lanzador sepa cuándo empezó el reloj de las
// fases. No se usa exec.instance.currentTestRunDuration: no consta que cuente
// desde el final de setup y no desde el principio de la ejecución.

import http from 'k6/http';
import exec from 'k6/execution';
import { check, sleep } from 'k6';

const datos = JSON.parse(open('/datos/ejecucion.json'));

const API = 'https://localhost:8443';
const WEB = 'https://localhost:8444';
// Origen del sitio del denunciante (app/rutas_web.py, ORIGEN_POR_DEFECTO): el
// formulario de consulta exige Origin igual a este valor y rechaza con 403
// cualquier otro (origen_aceptado). Un navegador lo envía en todo POST.
const ORIGEN_WEB = 'https://localhost:8444';

// Plazo de cada petición: por encima de los 10 s de espera del pool de
// PostgreSQL y de los 2 s del semáforo de Argon2 (como en l1.js).
const PLAZO = '15s';

function exigir(condicion, texto) {
  if (!condicion) {
    throw new Error(`ejecucion.json no valido: ${texto}`);
  }
}

const FUNCIONES = ['login_email', 'denuncia', 'seguimiento', 'web_seguimiento', 'sonda_salud'];

exigir(datos.modo === 'l2' || datos.modo === 'pico', 'modo');
exigir(/^[0-9a-f]{32}$/.test(datos.identificador_a), 'identificador_a');
exigir(/^[0-9a-f]{32}$/.test(datos.identificador_b), 'identificador_b');
exigir(typeof datos.contrasena === 'string' && datos.contrasena.length >= 16, 'contrasena');
exigir(typeof datos.texto_humo === 'string' && datos.texto_humo.length > 0, 'texto_humo');
exigir(Array.isArray(datos.fases) && datos.fases.length > 0, 'fases');
exigir(Array.isArray(datos.escenarios) && datos.escenarios.length > 0, 'escenarios');
exigir(Array.isArray(datos.humos), 'humos');

function escenario(e) {
  exigir(typeof e.nombre === 'string' && e.nombre.length > 0, 'nombre');
  exigir(FUNCIONES.includes(e.funcion), `${e.nombre}: funcion`);
  exigir(Number.isInteger(e.rate) && e.rate > 0, `${e.nombre}: rate`);
  exigir(Number.isInteger(e.time_unit_s) && e.time_unit_s > 0, `${e.nombre}: time_unit_s`);
  exigir(Number.isInteger(e.duracion_s) && e.duracion_s > 0, `${e.nombre}: duracion_s`);
  exigir(Number.isInteger(e.inicio_s) && e.inicio_s >= 0, `${e.nombre}: inicio_s`);
  exigir(Number.isInteger(e.vus) && e.vus > 0, `${e.nombre}: vus`);
  return {
    executor: 'constant-arrival-rate',
    rate: e.rate,
    timeUnit: `${e.time_unit_s}s`,
    duration: `${e.duracion_s}s`,
    startTime: `${e.inicio_s}s`,
    preAllocatedVUs: e.vus,
    maxVUs: e.vus,
    // Las peticiones en vuelo al acabar el escenario terminan (como mucho el
    // plazo de 15 s): cortarlas las contaría como errores falsos.
    gracefulStop: '20s',
    exec: e.funcion,
    tags: { ruta: e.ruta },
  };
}

const escenarios = {};
for (const e of datos.escenarios) {
  exigir(escenarios[e.nombre] === undefined, `${e.nombre}: repetido`);
  escenarios[e.nombre] = escenario(e);
}
// El humo (L4): una sola iteración, en su momento. Sus peticiones llevan la
// etiqueta ruta=humo y se excluyen del p95. maxDuration y gracefulStop vienen
// del lanzador (humos_pico en lanzar.py, la única fuente, de la que sale también
// el plazo de docker wait): aquí no se escribe ninguna cifra. Sin gracefulStop
// explícito, k6 aplicaba su valor por defecto (30 s, medido en k6_salida.txt de
// L4, k6 v2.3.0, 24/11/2026), distinto del de los demás escenarios.
for (const h of datos.humos) {
  exigir(typeof h.nombre === 'string' && /^humo_[a-z]+$/.test(h.nombre), 'humo: nombre');
  exigir(Number.isInteger(h.inicio_s) && h.inicio_s >= 0, `${h.nombre}: inicio_s`);
  exigir(Number.isInteger(h.max_duracion_s) && h.max_duracion_s > 0, `${h.nombre}: max_duracion_s`);
  exigir(Number.isInteger(h.graceful_stop_s) && h.graceful_stop_s >= 0, `${h.nombre}: graceful_stop_s`);
  exigir(escenarios[h.nombre] === undefined, `${h.nombre}: repetido`);
  escenarios[h.nombre] = {
    executor: 'shared-iterations', vus: 1, iterations: 1, maxDuration: `${h.max_duracion_s}s`,
    gracefulStop: `${h.graceful_stop_s}s`, startTime: `${h.inicio_s}s`, exec: 'humo', tags: { ruta: 'humo' },
  };
}

export const options = {
  scenarios: escenarios,
  // Solo hacia localhost dentro del espacio de red del contenedor de Caddy
  // (--network container:<caddy>): ver l1.js.
  insecureSkipTLSVerify: true,
  // Solo importa el código de estado: sin cuerpos, menos memoria por VU. El
  // humo pide el cuerpo de sus respuestas con responseType: 'text'.
  discardResponseBodies: true,
  // 'check' hace falta para que las filas `checks` del CSV lleven el nombre de
  // cada check del humo: sin ella la columna no existe (cabecera real de L4 del
  // 24/11) y el lanzador no puede saber de qué etapa es cada check. Cabecera
  // medida con 'check' (M2 del plan v4.2, k6 v2.3.0, 25/11/2026): metric_name,
  // timestamp, metric_value, check, error_code, expected_response, method,
  // name, proto, scenario, status, extra_tags, metadata.
  systemTags: ['status', 'error_code', 'scenario', 'proto', 'method', 'name', 'expected_response', 'check'],
  summaryTrendStats: ['min', 'med', 'p(95)', 'p(99)', 'max', 'count'],
  userAgent: 'canario-estres-fases',
  noUsageReport: true,
  setupTimeout: '600s',
};

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

// Código de seguimiento con el formato válido (8 grupos de 4 en base32): llega
// al HMAC y al SELECT. Uno mal formado daría el mismo 404 sin tocar la base de
// datos y no mediría nada (como en l1.js).
function codigoInexistente() {
  const crudo = aleatorio(BASE32, 32);
  return crudo.match(/.{4}/g).join('-');
}

export function setup() {
  // Espera opcional hasta un instante absoluto (reloj de la VM, el mismo del
  // lanzador y de la API). Si cuando se llega ya pasó, no se espera: el
  // lanzador lo ve en el aviso.
  if (datos.alinear_epoch_ms) {
    while (Date.now() < datos.alinear_epoch_ms) {
      sleep(Math.min(1, Math.max(0.01, (datos.alinear_epoch_ms - Date.now()) / 1000)));
    }
    const tarde = Date.now() - datos.alinear_epoch_ms;
    if (tarde > 1500) {
      console.error(`ALINEACION_PERDIDA tarde_ms=${tarde}`);
    }
  }
  const t0 = Date.now();
  console.log(`T0_MS=${t0}`);
  return { t0 };
}

function faseDe(t0) {
  const t = (Date.now() - t0) / 1000;
  for (const f of datos.fases) {
    if (t >= f.desde_s && t < f.hasta_s) {
      return f.nombre;
    }
  }
  return 'fuera';
}

function parametros(nombre, fase, extra) {
  return { headers: CABECERAS, timeout: PLAZO, tags: { name: nombre, ruta: nombre, fase }, ...extra };
}

// Contraseña sintética del login: la MISMA en todas las peticiones de la
// ejecución (el coste de Argon2 no depende de ella) y distinta en cada
// ejecución. El lanzador la conoce y busca su rastro en los ficheros que
// guarda (A3): si aparece en un CSV o un log, algo la está filtrando.
function cuerpoLogin(empresa, email) {
  return JSON.stringify({
    empresa,
    email,
    contrasena: datos.contrasena,
    codigo_totp: aleatorio('0123456789', 6),
  });
}

export function login_email(datosSetup) {
  // Empresa A (la atacada), email que no existe en ella (dominio .invalid, RFC 6761).
  const email = `estres-${aleatorio(HEX, 16)}@estres.invalid`;
  http.post(`${API}/v1/personal/sesiones`, cuerpoLogin(datos.identificador_a, email),
    parametros('login_email', faseDe(datosSetup.t0)));
}

export function denuncia(datosSetup) {
  // Empresa B, la del denunciante: la inundación es contra A.
  const cuerpo = JSON.stringify({
    categoria: 'otros',
    texto: `Denuncia de la prueba de estres ${aleatorio(HEX, 16)}`,
  });
  http.post(`${API}/v1/empresas/${datos.identificador_b}/denuncias`, cuerpo,
    parametros('denuncia', faseDe(datosSetup.t0)));
}

export function seguimiento(datosSetup) {
  http.post(`${API}/v1/seguimiento`, JSON.stringify({ codigo: codigoInexistente() }),
    parametros('seguimiento', faseDe(datosSetup.t0)));
}

export function web_seguimiento(datosSetup) {
  http.get(`${WEB}/seguimiento`, { timeout: PLAZO, tags: { name: 'web_seguimiento', ruta: 'web_seguimiento',
    fase: faseDe(datosSetup.t0) } });
}

// Sonda de salud (atribución): POST /salud solo admite GET, así que responde
// 405 sin tocar la base de datos ni el limitador (frontera_http.py).
export function sonda_salud(datosSetup) {
  http.post(`${API}/salud`, null, parametros('sonda_salud', faseDe(datosSetup.t0)));
}

// Humo del denunciante (L4, sustituye a F1 tras el pico: F1 levanta su propia
// pila). Cuatro pasos encadenados con el código que devuelve el primero; el
// código y el texto sembrado nunca salen de memoria. Cada paso comprueba su
// estado y su contenido con check (fila `checks` del CSV, con la etiqueta
// check); el lanzador exige que TODAS valgan 1.
export function humo() {
  const etapa = exec.scenario.name; // humo_previo o humo_posterior
  const t = (nombre, extra) => ({ timeout: PLAZO, responseType: 'text',
    tags: { name: nombre, ruta: 'humo', etapa }, ...extra });
  const r1 = http.post(`${API}/v1/empresas/${datos.identificador_b}/denuncias`,
    JSON.stringify({ categoria: 'otros', texto: datos.texto_humo }),
    t('humo_denuncia', { headers: CABECERAS }));
  let codigo = null;
  if (r1.status === 201) {
    try {
      codigo = r1.json('codigo_seguimiento');
    } catch (e) {
      codigo = null;
    }
  }
  check(r1, { [`${etapa}: denuncia 201 con codigo`]: (r) => r.status === 201 && typeof codigo === 'string' });
  if (typeof codigo !== 'string') {
    return;
  }
  const r2 = http.post(`${API}/v1/seguimiento`, JSON.stringify({ codigo }),
    t('humo_seguimiento_api', { headers: CABECERAS }));
  let textoApi = null;
  try {
    textoApi = r2.status === 200 ? r2.json('texto') : null;
  } catch (e) {
    textoApi = null;
  }
  check(r2, { [`${etapa}: seguimiento 200 con el texto sembrado`]: (r) => r.status === 200
    && textoApi === datos.texto_humo });
  const r3 = http.get(`${WEB}/seguimiento`, t('humo_web_formulario', {}));
  check(r3, { [`${etapa}: formulario web 200`]: (r) => r.status === 200 });
  // Campos y origen del formulario de consulta (app/rutas_web.py, formulario):
  // application/x-www-form-urlencoded con el único campo `codigo` y Origin
  // igual al del sitio. El código (letras, dígitos 2-7 y guiones) no necesita
  // escapado.
  const r4 = http.post(`${WEB}/seguimiento/consulta`, `codigo=${codigo}`,
    t('humo_web_consulta', { headers: { 'Content-Type': 'application/x-www-form-urlencoded', Origin: ORIGEN_WEB } }));
  check(r4, { [`${etapa}: consulta web 200 con el texto sembrado`]: (r) => r.status === 200
    && typeof r.body === 'string' && r.body.includes(datos.texto_humo) });
}

export function handleSummary(datosResumen) {
  return { '/salida/resumen.json': JSON.stringify(datosResumen, null, 1) };
}
