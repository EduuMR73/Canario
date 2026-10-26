import { DOCUMENT, DestroyRef, Injectable, InjectionToken, inject, signal } from '@angular/core';

// Cuenta atrás de la sesión del personal (docs/threat-model.md, 6.3).
//
// La sesión se cierra a los 15 minutos sin renovarse o a las 8 horas
// (app/personal.py). La API dice cuántos segundos le quedan en cada
// respuesta que la crea o la renueva y en /yo (inactividad_en y caduca_en),
// y con ellos la SPA avisa 2 minutos antes y deja ampliarla (WCAG 2.2, 2.2.1
// Timing Adjustable, nivel A). Quien decide es siempre el servidor: esto solo
// avisa, y un reloj del cliente que vaya mal no abre nada.
//
// El temporizador NUNCA renueva solo: mantendría viva la sesión de una
// pestaña olvidada y se saltaría la caducidad por inactividad. Solo renueva
// la persona, con "Seguir conectado" (armazon/armazon.ts).
//
// Los vencimientos se guardan como instantes del reloj monótono de la página
// (performance.now), no de Date: un cambio de hora del equipo no los mueve.
// Chrome frena los temporizadores de las pestañas en segundo plano (hasta uno
// por minuto), así que al volver a la pestaña se recalcula todo
// (visibilitychange) y el interceptor también mira la hora (anunciarCierre).

export interface Tiempos {
  inactividad_en: number;
  caduca_en: number;
}

// Las 8 horas de la sesión (app/personal.py): un valor mayor, negativo o no
// entero no es de esta API.
const MAXIMO_SEGUNDOS = 8 * 60 * 60;
// El aviso sale 2 minutos antes del cierre: tiempo de sobra para leerlo y
// pulsar (WCAG pide al menos 20 segundos).
const AVISO_MS = 2 * 60 * 1000;

export const AVISO_INACTIVIDAD = 'Su sesión se ha cerrado por inactividad. Vuelva a entrar.';
export const AVISO_MAXIMO = 'Su sesión ha llegado a las 8 horas y se ha cerrado. Vuelva a entrar.';
export const AVISO_CERRADA = 'Su sesión se ha cerrado. Vuelva a entrar.';

function segundosValidos(valor: unknown): valor is number {
  return typeof valor === 'number' && Number.isSafeInteger(valor) && valor >= 0 && valor <= MAXIMO_SEGUNDOS;
}

// Los tiempos de una respuesta de la API, o un error visible si no los trae:
// sin ellos la SPA no podría avisar, y callarlo dejaría a la persona sin
// aviso.
export function tiemposDe(datos: unknown): Tiempos {
  if (typeof datos === 'object' && datos !== null) {
    const { inactividad_en, caduca_en } = datos as Record<string, unknown>;
    if (segundosValidos(inactividad_en) && segundosValidos(caduca_en)) {
      return { inactividad_en, caduca_en };
    }
  }
  throw new Error('la respuesta no trae los tiempos de la sesión');
}

// El reloj, inyectable para las pruebas.
export const RELOJ = new InjectionToken<() => number>('RELOJ', {
  providedIn: 'root',
  factory: () => () => performance.now(),
});

// Las pestañas comparten las cookies y, por tanto, la sesión: cuando una
// renueva, las demás tienen que enterarse o avisarían de un cierre que ya no
// va a llegar. BroadcastChannel solo llega a las pestañas del mismo origen y
// no guarda nada: ni almacenamiento ni tokens, solo los segundos. Está en
// Chrome 54, Firefox 38 y Safari 15.4 (MDN), anteriores a los navegadores con
// Fetch Metadata que exige la API.
export interface Canal {
  enviar(mensaje: unknown): void;
  alRecibir(oyente: (datos: unknown) => void): void;
  cerrar(): void;
}

export const NOMBRE_CANAL = 'canario-sesion';

export const CANAL = new InjectionToken<Canal>('CANAL', {
  providedIn: 'root',
  factory: () => {
    const canal = new BroadcastChannel(NOMBRE_CANAL);
    return {
      enviar: (mensaje) => canal.postMessage(mensaje),
      alRecibir: (oyente) => canal.addEventListener('message', (evento) => oyente(evento.data)),
      cerrar: () => canal.close(),
    };
  },
});

// sin_sesion: no hay cuenta cargada en esta pestaña. en_curso: falta más de
// 2 minutos. aviso: el cierre por inactividad está cerca y se puede ampliar.
// aviso_final: llegan las 8 horas y no se puede ampliar. vencida: se acabó;
// el armazón olvida la cuenta y lleva a /entrar.
export type Estado = 'sin_sesion' | 'en_curso' | 'aviso' | 'aviso_final' | 'vencida';

@Injectable({ providedIn: 'root' })
export class Caducidad {
  private readonly reloj = inject(RELOJ);
  private readonly canal = inject(CANAL);
  private readonly actual = signal<Estado>('sin_sesion');
  readonly estado = this.actual.asReadonly();
  // Instantes del reloj (ms) del cierre por inactividad y de las 8 horas.
  private inactividad: number | null = null;
  private final: number | null = null;
  private temporizador: ReturnType<typeof setTimeout> | null = null;
  // El aviso para /entrar, de un solo uso y solo en memoria: ni en la URL,
  // que se comparte y se queda en el historial, ni en almacenamiento.
  private aviso: string | null = null;

  constructor() {
    this.canal.alRecibir((datos) => this.deOtraPestana(datos));
    const documento = inject(DOCUMENT);
    const alVolver = (): void => this.programar();
    documento.addEventListener('visibilitychange', alVolver);
    // Con la aplicación (o el inyector de una prueba) se va todo: ni
    // temporizadores ni canales abiertos.
    inject(DestroyRef).onDestroy(() => {
      this.limpiarTemporizador();
      documento.removeEventListener('visibilitychange', alVolver);
      this.canal.cerrar();
    });
  }

  // Tiempos nuevos de esta pestaña (/yo, renovación, cambio de contraseña):
  // se aplican y se cuentan a las demás.
  actualizar(tiempos: Tiempos): void {
    this.fijar(tiempos);
    this.canal.enviar({ tipo: 'tiempos', ...tiempos });
  }

  // La cuenta se olvida (nucleo/sesion.ts): no queda nada que avisar.
  parar(): void {
    this.limpiarTemporizador();
    this.inactividad = null;
    this.final = null;
    this.actual.set('sin_sesion');
  }

  // Un 401 sin sesión que renovar con la cuenta cargada (nucleo/renovacion.ts):
  // si ya pasó la hora, el motivo se sabe; si no, la sesión se cerró por otra
  // causa (revocada, otra pestaña cerró la sesión) y no se inventa una.
  anunciarCierre(): void {
    const cierre = this.cierre();
    this.aviso = cierre !== null && cierre <= this.reloj() ? this.motivo() : AVISO_CERRADA;
  }

  // El aviso pendiente para /entrar; después de leerlo ya no está.
  tomarAviso(): string | null {
    const aviso = this.aviso;
    this.aviso = null;
    return aviso;
  }

  private deOtraPestana(datos: unknown): void {
    // Sin cuenta cargada aquí, otra pestaña no enciende la cuenta atrás: esta
    // no tiene nada que avisar.
    if (this.actual() === 'sin_sesion') {
      return;
    }
    // Un mensaje que no es de esta versión de la SPA (otra pestaña sin
    // recargar tras una actualización) se descarta: no hay forma de saber qué
    // significa.
    if (typeof datos !== 'object' || datos === null || (datos as Record<string, unknown>)['tipo'] !== 'tiempos') {
      return;
    }
    let tiempos: Tiempos;
    try {
      tiempos = tiemposDe(datos);
    } catch {
      return;
    }
    this.fijar(tiempos);
  }

  private fijar(tiempos: Tiempos): void {
    const ahora = this.reloj();
    this.inactividad = ahora + tiempos.inactividad_en * 1000;
    this.final = ahora + tiempos.caduca_en * 1000;
    this.programar();
  }

  private cierre(): number | null {
    return this.inactividad === null || this.final === null ? null : Math.min(this.inactividad, this.final);
  }

  private motivo(): string {
    return this.final !== null && this.inactividad !== null && this.final <= this.inactividad
      ? AVISO_MAXIMO
      : AVISO_INACTIVIDAD;
  }

  private programar(): void {
    this.limpiarTemporizador();
    const cierre = this.cierre();
    if (cierre === null) {
      return;
    }
    const restante = cierre - this.reloj();
    if (restante <= 0) {
      this.aviso = this.motivo();
      this.inactividad = null;
      this.final = null;
      this.actual.set('vencida');
      return;
    }
    if (restante <= AVISO_MS) {
      // Si las 8 horas llegan antes que la inactividad, renovar no amplía nada.
      this.actual.set(this.final !== null && this.final === cierre ? 'aviso_final' : 'aviso');
      this.temporizador = setTimeout(() => this.programar(), restante);
      return;
    }
    this.actual.set('en_curso');
    this.temporizador = setTimeout(() => this.programar(), restante - AVISO_MS);
  }

  private limpiarTemporizador(): void {
    if (this.temporizador !== null) {
      clearTimeout(this.temporizador);
      this.temporizador = null;
    }
  }
}
