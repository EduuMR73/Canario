// L3 (carga repartida con los límites de producción) y L3b (el coste del ataque
// de L2 con esos límites) de docs/informe-pruebas.md, para k6 v2.3.0 (imagen
// fijada por digest en tests/estres/lanzar.py).
//
// k6 hace de Traefik: corre en la red edge con la IP 10.88.1.2, la única en la
// que confía Caddy con Caddyfile.produccion (trusted_proxies static
// 10.88.1.2/32 y trusted_proxies_strict), contra http://caddy:8080 con el Host
// de producción de cada sitio. La IP de cada cliente simulado va como
// ÚLTIMO elemento de X-Forwarded-For, que es donde la pone Traefik: no hacen
// falta varias IPs de origen, y un atacante no puede suplantar a otro porque
// strict lee de derecha a izquierda. El lanzador lo comprueba antes de medir.
//
// Como en fases.js, el lanzador calcula todo y lo deja en
// /datos/ejecucion.json. Las funciones de petición duplican a propósito las
// de l1.js (que no se toca: va montado en vivo durante L1).
//
// Reparto de IPs: CIRCULAR por iteración (exec.scenario.iterationInTest módulo
// el número de IPs), nunca al azar: así ninguna IP pasa de su cuota por
// casualidad y el recuento por IP y ventana del lanzador es exacto.
//
// setup() espera hasta alinear_epoch_ms (reloj de la VM): el ataque o la carga
// debe empezar justo tras una frontera de minuto o de 5 minutos UTC, que es
// donde cambia de ventana el limitador (ventana fija, app/limitador.py). Los
// VUs ya están inicializados cuando setup() espera, así que el arranque de los
// escenarios es inmediato y la alineación no depende de cuánto tarde k6 en
// inicializar. Si la espera ya no es posible, avisa con ALINEACION_PERDIDA y
// el lanzador da SIN CONCLUSION.
//
// L6 y L7 (plan v3.2, 25/11/2026). L7 inunda GET /salud (salud_get) desde una
// IP con las víctimas de L2. L6 llena Redis: el relleno (denuncia_relleno) manda
// cuerpos {} a la ruta de denuncia, que el limitador cuenta antes de validar
// (422 sin base de datos), cada uno desde una IP distinta de 100.64.0.0/10
// calculada aquí con ipRelleno; el legítimo (legitimo) consulta un seguimiento
// inexistente desde una IP fija. El relleno se para solo cuando un mismo VU
// recibe 5 respuestas 503 seguidas con Retry-After 5: imprime RELLENO_PARADO y
// llama a exec.test.abort (k6 sale con 108). El lanzador decide los veredictos;
// aquí solo se mide y se anota.

import http from 'k6/http';
import exec from 'k6/execution';
import { Trend } from 'k6/metrics';
import { SharedArray } from 'k6/data';
import { sleep } from 'k6';

const datos = JSON.parse(open('/datos/ejecucion.json'));

const BASE = 'http://caddy:8080';
const PLAZO = '15s';

function exigir(condicion, texto) {
  if (!condicion) {
    throw new Error(`ejecucion.json no valido: ${texto}`);
  }
}

const FUNCIONES = ['seguimiento_ip', 'login_ataque', 'denuncia_ip', 'web_ip', 'sonda_salud', 'salud_get',
  'denuncia_relleno', 'legitimo'];
const IPV4 = /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/;

exigir(['l3', 'l3b', 'l6', 'l7'].includes(datos.modo), 'modo');
if (datos.modo === 'l6') {
  // El relleno necesita la empresa B (la ruta de denuncia) y la repetición,
  // que fija su bloque de IPs.
  exigir(datos.identificador_b !== null, 'identificador_b en l6');
  exigir(Number.isInteger(datos.repeticion) && datos.repeticion >= 1, 'repeticion');
}
exigir(typeof datos.host_api === 'string' && typeof datos.host_web === 'string', 'hosts');
exigir(Array.isArray(datos.fases) && datos.fases.length > 0, 'fases');
exigir(Array.isArray(datos.escenarios) && datos.escenarios.length > 0, 'escenarios');
exigir(typeof datos.contrasena === 'string' && datos.contrasena.length >= 16, 'contrasena');
exigir(datos.identificador_a === null || /^[0-9a-f]{32}$/.test(datos.identificador_a), 'identificador_a');
exigir(datos.identificador_b === null || /^[0-9a-f]{32}$/.test(datos.identificador_b), 'identificador_b');
exigir(datos.alinear_epoch_ms === null || Number.isInteger(datos.alinear_epoch_ms), 'alinear_epoch_ms');

function escenario(e) {
  exigir(typeof e.nombre === 'string' && e.nombre.length > 0, 'nombre');
  exigir(FUNCIONES.includes(e.funcion), `${e.nombre}: funcion`);
  exigir(Number.isInteger(e.rate) && e.rate > 0, `${e.nombre}: rate`);
  exigir(Number.isInteger(e.time_unit_s) && e.time_unit_s > 0, `${e.nombre}: time_unit_s`);
  exigir(Number.isInteger(e.duracion_s) && e.duracion_s > 0, `${e.nombre}: duracion_s`);
  exigir(Number.isInteger(e.inicio_s) && e.inicio_s >= 0, `${e.nombre}: inicio_s`);
  exigir(Number.isInteger(e.vus) && e.vus > 0, `${e.nombre}: vus`);
  // El relleno no trae lista de IPs: cada iteración calcula la suya (ipRelleno).
  if (e.funcion !== 'denuncia_relleno') {
    exigir(Number.isInteger(e.n_ips) && e.n_ips > 0, `${e.nombre}: n_ips`);
  }
  return {
    executor: 'constant-arrival-rate',
    rate: e.rate,
    timeUnit: `${e.time_unit_s}s`,
    duration: `${e.duracion_s}s`,
    startTime: `${e.inicio_s}s`,
    preAllocatedVUs: e.vus,
    maxVUs: e.vus,
    gracefulStop: '20s',
    exec: e.funcion,
    tags: { ruta: e.ruta },
  };
}

const escenarios = {};
const ips = {};
const etiquetarIp = {};
for (const e of datos.escenarios) {
  exigir(escenarios[e.nombre] === undefined, `${e.nombre}: repetido`);
  escenarios[e.nombre] = escenario(e);
  if (e.funcion === 'denuncia_relleno') {
    continue;
  }
  // Las listas de IPs (hasta 3402) viven en /datos/ips.json y en un
  // SharedArray: una sola copia en memoria para todos los VUs, no una por VU
  // dentro de ejecucion.json (PY-1). Se valida que sean IPv4 y que el
  // numero coincida con el que declara ejecucion.json.
  ips[e.nombre] = new SharedArray(`ips_${e.nombre}`, () => JSON.parse(open('/datos/ips.json'))[e.nombre]);
  exigir(ips[e.nombre].length === e.n_ips, `${e.nombre}: ips.json trae ${ips[e.nombre].length} IPs y se esperaban ${e.n_ips}`);
  exigir(ips[e.nombre].every((ip) => IPV4.test(ip)), `${e.nombre}: ips no IPv4`);
  etiquetarIp[e.nombre] = e.etiquetar_ip === true;
}

export const options = {
  scenarios: escenarios,
  // HTTP en claro: Traefik termina el TLS y reenvía en HTTP por la red edge.
  discardResponseBodies: true,
  systemTags: ['status', 'error_code', 'scenario', 'proto', 'method', 'name', 'expected_response'],
  summaryTrendStats: ['min', 'med', 'p(95)', 'p(99)', 'max', 'count'],
  userAgent: 'canario-estres-l3',
  noUsageReport: true,
  setupTimeout: '900s',
};

// Retry-After de cada 429, como métrica propia con la etiqueta ip: k6 no
// guarda las cabeceras de respuesta en el CSV. Un 429 sin la cabecera, o con
// un valor que no son dígitos, se anota como -1 (el lanzador lo da por fuera
// de rango).
const retryAfter = new Trend('retry_after_s');
// L6: el Retry-After de cada 503 del legítimo, con el texto TAL CUAL en la
// etiqueta ra ('ausente' si no viene): el lanzador lo compara con el literal
// "5"; el valor numérico es solo orientativo.
const retryAfter503 = new Trend('retry_after_503_s');
// L6 (D-8): Date.now() justo al volver cada petición del relleno. Su max sale en
// resumen.json y da el fin de la última petición del relleno sin CSV (plan B);
// el humo, con CSV, lo compara al milisegundo con el fin máximo del CSV.
const finRelleno = new Trend('fin_relleno_ms');

// IPs del relleno (D-L6-1): 100.64.0.0/10 sin .0 ni .255 de cada /24, un
// millón por repetición. La misma fórmula que ip_relleno de lanzar.py; los
// vectores literales de abajo los comprueba setup() y, como texto, la prueba
// U-IP-2. Fuera de rango, excepción: nunca una IP repetida en silencio.
const IPS_POR_REPETICION = 1000000;
const IPS_TOTAL = 16384 * 254;
function ipRelleno(i, rep) {
  if (!Number.isInteger(i) || !Number.isInteger(rep) || i < 0 || i >= IPS_POR_REPETICION || rep < 1) {
    throw new Error(`indice de IP del relleno fuera de rango: ${i} (repeticion ${rep})`);
  }
  const g = (rep - 1) * IPS_POR_REPETICION + i;
  if (g >= IPS_TOTAL) {
    throw new Error(`la repeticion ${rep} no cabe en 100.64.0.0/10`);
  }
  const bloque = Math.floor(g / 254);
  return `100.${64 + Math.floor(bloque / 256)}.${bloque % 256}.${(g % 254) + 1}`;
}
const VECTORES_IP = [
  [0, 1, '100.64.0.1'],
  [253, 1, '100.64.0.254'],
  [254, 1, '100.64.1.1'],
  [0, 2, '100.79.97.3'],
];

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const HEX = '0123456789abcdef';

function aleatorio(alfabeto, longitud) {
  let texto = '';
  for (let i = 0; i < longitud; i += 1) {
    texto += alfabeto[Math.floor(Math.random() * alfabeto.length)];
  }
  return texto;
}

function codigoInexistente() {
  const crudo = aleatorio(BASE32, 32);
  return crudo.match(/.{4}/g).join('-');
}

export function setup() {
  // Control de ipRelleno con vectores literales (y que fuera de rango lance): si
  // no cuadra, CONTROL_IP y aborta antes de medir nada.
  let fueraDeRango = false;
  try {
    ipRelleno(IPS_POR_REPETICION, 1);
  } catch (e) {
    fueraDeRango = true;
  }
  for (const [i, rep, ip] of VECTORES_IP) {
    if (ipRelleno(i, rep) !== ip || !fueraDeRango) {
      console.error('CONTROL_IP');
      exec.test.abort(`CONTROL_IP: ipRelleno(${i}, ${rep}) no da ${ip}`);
    }
  }
  // S10: control de que el Host de produccion llega a la API. Sin el Host
  // correcto, Caddy responde 421 a todo y la medida seria de un sitio por
  // defecto. Va desde 10.88.1.2 (la IP de Traefik) y a /salud (exenta del
  // limitador). POST /salud tiene que dar 405 (el endpoint existe y solo
  // admite GET): cualquier otro estado, no solo el 421, aborta. En L3b, ademas,
  // GET /seguimiento con el Host del sitio del denunciante tiene que dar 200.
  // El lanzador convierte CONTROL_421 y CONTROL_SETUP en PARADA.
  const control = http.post(`${BASE}/salud`, null, { headers: { Host: datos.host_api }, timeout: PLAZO });
  if (control.status === 421) {
    console.error('CONTROL_421');
    exec.test.abort('CONTROL_421: el Host de produccion no llega a la API');
  }
  if (control.status !== 405) {
    console.error('CONTROL_SETUP');
    exec.test.abort(`CONTROL_SETUP: POST /salud con el Host de la API da ${control.status} y debe dar 405`);
  }
  if (datos.modo === 'l3b') {
    const web = http.get(`${BASE}/seguimiento`, { headers: { Host: datos.host_web }, timeout: PLAZO });
    if (web.status !== 200) {
      console.error('CONTROL_SETUP');
      exec.test.abort(`CONTROL_SETUP: GET /seguimiento con el Host del sitio da ${web.status} y debe dar 200`);
    }
  }
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

// IP de esta iteración, circular, y los parámetros de la petición: Host del
// sitio y la IP como único elemento de X-Forwarded-For.
function parametros(host, nombre, t0, json, conIp) {
  const lista = ips[exec.scenario.name];
  const ip = lista[exec.scenario.iterationInTest % lista.length];
  const tags = { name: nombre, ruta: nombre, fase: faseDe(t0) };
  if (conIp) {
    tags.ip = ip;
  }
  const cabeceras = { Host: host, 'X-Forwarded-For': ip };
  if (json) {
    cabeceras['Content-Type'] = 'application/json';
  }
  return { headers: cabeceras, timeout: PLAZO, tags };
}

function registrar429(respuesta, p) {
  if (respuesta.status !== 429) {
    return;
  }
  const valor = respuesta.headers['Retry-After'];
  const etiquetas = { name: p.tags.name };
  if (p.tags.ip !== undefined) {
    etiquetas.ip = p.tags.ip;
  }
  retryAfter.add(typeof valor === 'string' && /^[0-9]+$/.test(valor) ? parseInt(valor, 10) : -1, etiquetas);
}

function enviar(metodo, url, cuerpo, p) {
  const respuesta = http.request(metodo, url, cuerpo, p);
  registrar429(respuesta, p);
}

export function seguimiento_ip(datosSetup) {
  const p = parametros(datos.host_api, 'seguimiento', datosSetup.t0, true, etiquetarIp[exec.scenario.name]);
  enviar('POST', `${BASE}/v1/seguimiento`, JSON.stringify({ codigo: codigoInexistente() }), p);
}

// Login con un email que no existe en la empresa A: solo consume la regla
// acceso (10 por 5 minutos y por IP); no toca cuentas ni bloqueos (D1).
export function login_ataque(datosSetup) {
  const p = parametros(datos.host_api, 'login_email', datosSetup.t0, true, etiquetarIp[exec.scenario.name]);
  const cuerpo = JSON.stringify({
    empresa: datos.identificador_a,
    email: `estres-${aleatorio(HEX, 16)}@estres.invalid`,
    contrasena: datos.contrasena,
    codigo_totp: aleatorio('0123456789', 6),
  });
  enviar('POST', `${BASE}/v1/personal/sesiones`, cuerpo, p);
}

export function denuncia_ip(datosSetup) {
  const p = parametros(datos.host_api, 'denuncia', datosSetup.t0, true, false);
  const cuerpo = JSON.stringify({
    categoria: 'otros',
    texto: `Denuncia de la prueba de estres L3b ${aleatorio(HEX, 16)}`,
  });
  enviar('POST', `${BASE}/v1/empresas/${datos.identificador_b}/denuncias`, cuerpo, p);
}

// Con el Host de producción del sitio del denunciante, la página es
// /seguimiento (proxy/comun.caddy:263, rewrite a /web/seguimiento), no
// /web/seguimiento.
export function web_ip(datosSetup) {
  const p = parametros(datos.host_web, 'web_seguimiento', datosSetup.t0, false, false);
  enviar('GET', `${BASE}/seguimiento`, null, p);
}

// /salud está exenta del limitador: no consume ningún contador. POST da 405.
export function sonda_salud(datosSetup) {
  const p = parametros(datos.host_api, 'sonda_salud', datosSetup.t0, true, false);
  enviar('POST', `${BASE}/salud`, null, p);
}

// GET /salud (L6 y L7): exenta del limitador, espera 200.
export function salud_get(datosSetup) {
  const p = parametros(datos.host_api, 'salud_get', datosSetup.t0, false, false);
  enviar('GET', `${BASE}/salud`, null, p);
}

// L6: el cliente legítimo, desde su IP fija (la única de su lista). Espera 404;
// con Redis lleno, 503 con Retry-After. Solo en el plan B imprime cada respuesta.
export function legitimo(datosSetup) {
  const p = parametros(datos.host_api, 'legitimo', datosSetup.t0, true, false);
  const respuesta = http.request('POST', `${BASE}/v1/seguimiento`, JSON.stringify({ codigo: codigoInexistente() }), p);
  const valor = respuesta.headers['Retry-After'];
  if (respuesta.status === 503) {
    const texto = typeof valor === 'string' ? valor : 'ausente';
    retryAfter503.add(/^[0-9]+$/.test(texto) ? parseInt(texto, 10) : -1, { name: 'legitimo', ra: texto });
  }
  if (datos.imprimir_legitimo === true) {
    console.log(`LEGITIMO t=${Date.now()} estado=${respuesta.status} ra=${typeof valor === 'string' ? valor : ''}`);
  }
}

// Racha de 503 seguidos con Retry-After 5 de ESTE VU: es una variable de
// módulo, y cada VU tiene su propia copia del módulo.
let rachaRelleno = 0;

// L6: el relleno. Cuerpo {} contra la ruta de denuncia de B: el limitador cuenta
// antes de validar (422 sin base de datos) y cada petición crea una clave nueva
// en Redis, porque la IP es distinta en cada iteración: el índice es
// exec.scenario.iterationInTest, único en todo el escenario.
export function denuncia_relleno(datosSetup) {
  const i = exec.scenario.iterationInTest;
  const ip = ipRelleno(i, datos.repeticion);
  if (i % 10000 === 0) {
    console.log(`IP_MUESTRA i=${i} ip=${ip}`);
  }
  const respuesta = http.post(`${BASE}/v1/empresas/${datos.identificador_b}/denuncias`, '{}', {
    headers: { Host: datos.host_api, 'X-Forwarded-For': ip, 'Content-Type': 'application/json' },
    timeout: PLAZO,
    tags: { name: 'denuncia_relleno', ruta: 'denuncia', fase: faseDe(datosSetup.t0) },
  });
  finRelleno.add(Date.now(), { name: 'denuncia_relleno' });
  if (respuesta.status === 503 && respuesta.headers['Retry-After'] === '5') {
    rachaRelleno += 1;
  } else {
    rachaRelleno = 0;
  }
  if (rachaRelleno >= 5) {
    console.log(`RELLENO_PARADO t=${Date.now()}`);
    exec.test.abort('RELLENO_PARADO: 5 respuestas 503 seguidas con Retry-After 5 en un VU');
  }
}

export function handleSummary(datosResumen) {
  return { '/salida/resumen.json': JSON.stringify(datosResumen, null, 1) };
}
