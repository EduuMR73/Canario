// Sonda de las marcas de dropped_iterations de k6 (E14 de docs/informe-pruebas.md).
//
// Un escenario constant-arrival-rate a 2/s con 1 VU contra un endpoint que
// tarda 2 s (sonda_descartes.py lo arranca): cada iteracion ocupa al unico VU
// 2 s, asi que k6 descarta las llegadas intermedias y deja una marca
// dropped_iterations por cada una. El lanzador comprueba que esas marcas
// salen separadas unos 0,5 s y que la primera cae cerca del inicio del
// escenario: sobre esa propiedad se apoya la regla de E14 (una ventana de
// 10 s con algun descarte no cumple), y si k6 no la cumple la regla no vale.
//
// Sin datos de Canario: ni contrasenas ni identificadores, solo el endpoint
// lento del contenedor auxiliar (alias "lento").

import http from 'k6/http';

export const options = {
  scenarios: {
    sonda: {
      executor: 'constant-arrival-rate',
      rate: 2,
      timeUnit: '1s',
      duration: '12s',
      preAllocatedVUs: 1,
      maxVUs: 1,
      gracefulStop: '5s',
    },
  },
  discardResponseBodies: true,
  noUsageReport: true,
  systemTags: ['status', 'scenario', 'name'],
};

// Instante en el que acaba setup(): el escenario empieza justo despues (sin
// startTime), igual que el T0_MS de fases.js y l3.js.
export function setup() {
  console.log(`T0_MS=${Date.now()}`);
}

export default function () {
  http.get('http://lento:8080/', { timeout: '10s', tags: { name: 'lento' } });
}
