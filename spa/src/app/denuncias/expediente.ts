import { HttpErrorResponse } from '@angular/common/http';
import { Component, DestroyRef, Injector, computed, inject, signal } from '@angular/core';
import { takeUntilDestroyed, toSignal } from '@angular/core/rxjs-interop';
import { NonNullableFormBuilder, ReactiveFormsModule } from '@angular/forms';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { Observable } from 'rxjs';
import { ApiDenuncias, EstadoDestino, Expediente as DatosExpediente } from '../nucleo/api-denuncias';
import { detalleDe, esperaDe, textoDeError } from '../nucleo/errores';
import { enfocarEncabezado } from '../nucleo/foco';
import { Sesion } from '../nucleo/sesion';
import { Contenido } from './contenido';
import { NOMBRES_ESTADO, avisoLecturas, destinosDe, esCerrado, puedeDeclararNoVeraz } from './textos';

// Una denuncia asignada: leerla, escribir al denunciante y cambiar su estado
// (app/instruccion.py).
//
// Leer no es gratis: cada GET deja una fila en la auditoría y cuenta para el
// tope de lecturas de la cuenta. Por eso:
// * Abrir la página no lee nada, ni con la carga directa de la URL. Solo lee
//   el botón "Abrir el expediente", y la orden nunca sale de la URL (un
//   ?abrir=1 dejaría que un enlace hiciera leer a otra persona en su nombre,
//   ATT&CK T1534). Si cambia el id de la URL, la página vuelve a "sin abrir".
// * Tras enviar un mensaje o cambiar el estado no se vuelve a leer: se pinta
//   lo que ha confirmado la API (la secuencia y la fecha del mensaje, o el
//   204 del cambio). "Volver a leer" es un botón aparte.
// El expediente vive solo en esta página, en memoria: no va a la URL, al
// almacenamiento ni a la consola, y desaparece al salir.

const TEXTO_NO_DISPONIBLE = 'La denuncia no existe o no la tiene asignada.';

@Component({
  selector: 'app-expediente',
  imports: [Contenido, ReactiveFormsModule, RouterLink],
  template: `
    <h1 tabindex="-1">Denuncia</h1>
    <p>Referencia: <span class="dato">{{ id() }}</span></p>
    <p><a routerLink="/denuncias">Volver al listado</a></p>

    @if (hecho(); as texto) {
      <p class="aviso" id="expediente-hecho" role="status" tabindex="-1">{{ texto }}</p>
    }
    @if (error(); as texto) {
      <p class="error" id="expediente-error" role="alert" tabindex="-1">{{ texto }}</p>
    }

    @if (expediente(); as datos) {
      <section aria-labelledby="expediente-titulo">
        <h2 id="expediente-titulo" tabindex="-1">Expediente</h2>
        @if (aviso(); as texto) {
          <p class="aviso" role="status">{{ texto }}</p>
        }
        <app-contenido [expediente]="datos" [propia]="propia()" [pendienteFinal]="pendienteFinal()" />
        <p class="acciones">
          <button type="button" class="secundario" (click)="leer()" [attr.aria-disabled]="ocupado() || null">Volver a leer</button>
        </p>

        @if (cerrada(datos.estado)) {
          <p>La denuncia está cerrada: no admite más mensajes.</p>
        } @else {
          <h3>Escribir al denunciante</h3>
          <form class="formulario" [formGroup]="formMensaje" (ngSubmit)="enviarMensaje()" ngNativeValidate>
            <p class="campo">
              <label for="expediente-mensaje">Mensaje para el denunciante</label>
              <textarea id="expediente-mensaje" formControlName="texto" required maxlength="10000" rows="5"
                        dir="auto"></textarea>
            </p>
            <button type="submit" [attr.aria-disabled]="ocupado() || null">Enviar el mensaje</button>
          </form>
        }

        @if (destinos(datos.estado).length > 0) {
          <h3>Cambiar el estado</h3>
          <form class="formulario" [formGroup]="formEstado" (ngSubmit)="cambiarEstado()" ngNativeValidate>
            <p class="campo">
              <label for="expediente-destino">Estado nuevo</label>
              <select id="expediente-destino" formControlName="destino" required>
                <option value="" disabled>Elija un estado</option>
                @for (destino of destinos(datos.estado); track destino) {
                  <option [value]="destino">{{ nombreEstado[destino] }}</option>
                }
              </select>
            </p>
            @if (cierra()) {
              <p class="campo">
                <label for="expediente-final">Mensaje final para el denunciante</label>
                <textarea id="expediente-final" formControlName="mensaje" required maxlength="10000" rows="5"
                          dir="auto" aria-describedby="expediente-final-ayuda"></textarea>
                <span id="expediente-final-ayuda" class="ayuda">Obligatorio al cerrar: el denunciante no podrá escribir más y es la única respuesta que recibirá.</span>
              </p>
            }
            <button type="submit" [attr.aria-disabled]="ocupado() || null">Cambiar el estado</button>
          </form>
        }

        @if (noVeraz()) {
          <h3>Declarar no veraz</h3>
          <p>Si se acredita que la información no es veraz, la denuncia deja de existir para el canal y se suprime en la siguiente ejecución de la supresión (art. 32.3 de la Ley 2/2023). No tiene vuelta atrás. Si los hechos pueden ser delito, no la declare no veraz: hay que conservarla.</p>
          @if (confirmando()) {
            <p class="acciones">
              <span>¿Declarar no veraz la denuncia {{ id() }}?</span>
              <button type="button" id="expediente-confirmar" class="peligro" (click)="declararNoVeraz()"
                      [attr.aria-disabled]="ocupado() || null">Confirmar: declarar no veraz</button>
              <button type="button" class="secundario" (click)="confirmando.set(false)">Cancelar</button>
            </p>
          } @else {
            <button type="button" class="peligro" (click)="pedirNoVeraz()"
                    [attr.aria-disabled]="ocupado() || null">Declarar no veraz</button>
          }
        }
      </section>
    } @else if (!declarada()) {
      <p>El expediente no se abre solo: abrirlo queda registrado en la auditoría y cuenta para su límite diario de denuncias distintas. Si recarga la página, tendrá que volver a abrirlo.</p>
      <button type="button" (click)="leer()" [attr.aria-disabled]="ocupado() || null">
        {{ ocupado() ? 'Abriendo...' : 'Abrir el expediente' }}
      </button>
    }
  `,
})
export class Expediente {
  private readonly api = inject(ApiDenuncias);
  private readonly injector = inject(Injector);
  private readonly sesion = inject(Sesion);
  private readonly formularios = inject(NonNullableFormBuilder);

  readonly nombreEstado = NOMBRES_ESTADO;
  readonly cerrada = esCerrado;
  readonly destinos = destinosDe;
  readonly propia = computed(() => this.sesion.yo()?.usuario_id);
  readonly noVeraz = computed(() => {
    const yo = this.sesion.yo();
    return yo !== null && puedeDeclararNoVeraz(yo.rol);
  });

  readonly id = signal('');
  readonly expediente = signal<DatosExpediente | null>(null);
  readonly pendienteFinal = signal<string | null>(null);
  readonly declarada = signal(false);
  // Una petición cada vez: un doble clic no lee dos veces (dos filas en la
  // auditoría) ni envía dos mensajes. Los botones llevan aria-disabled y no
  // disabled, para no quitarles el foco (denuncias.ts): la guarda de leer() y
  // de actuar() es la única barrera de la página, y la API, la autoridad.
  readonly ocupado = signal(false);
  readonly confirmando = signal(false);
  readonly hecho = signal<string | null>(null);
  readonly error = signal<string | null>(null);

  readonly aviso = computed(() => {
    const datos = this.expediente();
    return datos === null ? null : avisoLecturas(datos.lecturas.hoy, datos.lecturas.tope);
  });

  readonly formMensaje = this.formularios.group({ texto: '' });
  readonly formEstado = this.formularios.group({ destino: '', mensaje: '' });
  private readonly destinoElegido = toSignal(this.formEstado.controls.destino.valueChanges, { initialValue: '' });
  readonly cierra = computed(() => esCerrado(this.destinoElegido()));

  constructor() {
    // El mismo componente sirve /denuncias/a y /denuncias/b: al cambiar de id
    // se olvida todo lo de la anterior y no se lee nada.
    inject(ActivatedRoute).paramMap.pipe(takeUntilDestroyed(inject(DestroyRef))).subscribe((parametros) => {
      this.id.set(parametros.get('id') ?? '');
      this.expediente.set(null);
      this.pendienteFinal.set(null);
      this.declarada.set(false);
      this.confirmando.set(false);
      this.hecho.set(null);
      this.error.set(null);
      this.formMensaje.reset();
      this.formEstado.reset();
    });
  }

  leer(): void {
    if (this.ocupado()) {
      return;
    }
    this.empezar();
    this.api.leer(this.id()).subscribe({
      next: (datos) => {
        this.ocupado.set(false);
        this.expediente.set(datos);
        this.pendienteFinal.set(null);
        enfocarEncabezado(this.injector, '#expediente-titulo');
      },
      error: (error: unknown) => {
        this.ocupado.set(false);
        this.expediente.set(null);
        this.mostrarError(this.textoDeLectura(error));
      },
    });
  }

  enviarMensaje(): void {
    const texto = this.formMensaje.getRawValue().texto;
    this.actuar(this.api.enviarMensaje(this.id(), texto), (enviado) => {
      this.expediente.update((datos) => datos === null ? null : {
        ...datos,
        mensajes: [...datos.mensajes, {
          secuencia: enviado.secuencia, fecha: enviado.fecha, autor: 'personal', autor_id: this.propia() ?? null, texto,
        }],
      });
      this.formMensaje.reset();
      return 'Mensaje enviado.';
    }, 'No se ha enviado el mensaje');
  }

  cambiarEstado(): void {
    const { destino, mensaje } = this.formEstado.getRawValue();
    const datos = this.expediente();
    if (datos === null || !(destinosDe(datos.estado) as readonly string[]).includes(destino)) {
      return;
    }
    const final = esCerrado(destino) ? mensaje : null;
    const nuevo = destino as Exclude<EstadoDestino, 'no_veraz'>;
    this.actuar(this.api.cambiarEstado(this.id(), nuevo, final), () => {
      this.expediente.update((actual) => actual === null ? null : { ...actual, estado: nuevo });
      this.formEstado.reset();
      if (final === null) {
        return `Estado cambiado a ${NOMBRES_ESTADO[nuevo]}.`;
      }
      this.pendienteFinal.set(final);
      return `Estado cambiado a ${NOMBRES_ESTADO[nuevo]}. El mensaje final se ha enviado y saldrá numerado al volver a leer.`;
    }, 'No se ha cambiado el estado');
  }

  pedirNoVeraz(): void {
    // Con una petición en marcha no se abre la confirmación: al terminar,
    // actuar() la cerraría bajo el dedo de quien iba a confirmar.
    if (this.ocupado()) {
      return;
    }
    this.confirmando.set(true);
    // El botón pulsado desaparece: el foco pasa a la confirmación.
    enfocarEncabezado(this.injector, '#expediente-confirmar');
  }

  declararNoVeraz(): void {
    this.actuar(this.api.cambiarEstado(this.id(), 'no_veraz', null), () => {
      this.expediente.set(null);
      this.declarada.set(true);
      return `La denuncia ${this.id()} está declarada no veraz: ya no existe para el canal y se suprimirá en la siguiente ejecución de la supresión.`;
    }, 'No se ha declarado no veraz');
  }

  private empezar(): void {
    this.ocupado.set(true);
    this.hecho.set(null);
    this.error.set(null);
  }

  private actuar<T>(accion: Observable<T>, alTerminar: (respuesta: T) => string, fallo: string): void {
    if (this.ocupado()) {
      return;
    }
    this.empezar();
    accion.subscribe({
      next: (respuesta) => {
        this.ocupado.set(false);
        this.confirmando.set(false);
        this.hecho.set(alTerminar(respuesta));
        enfocarEncabezado(this.injector, '#expediente-hecho');
      },
      error: (error: unknown) => {
        this.ocupado.set(false);
        this.confirmando.set(false);
        // Ya no la tiene asignada (otro admin la ha reasignado) o ya no
        // existe: lo leído se deja de enseñar.
        if (error instanceof HttpErrorResponse && error.status === 404) {
          this.expediente.set(null);
          this.pendienteFinal.set(null);
        }
        this.mostrarError(this.textoDeAccion(error, fallo));
      },
    });
  }

  private mostrarError(texto: string): void {
    this.error.set(texto);
    enfocarEncabezado(this.injector, '#expediente-error');
  }

  // El detalle del servidor se enseña tal cual, sin compararlo con nada: así
  // la SPA no depende de su redacción (y Angular lo escapa al pintarlo).
  private textoDeLectura(error: unknown): string {
    if (error instanceof HttpErrorResponse && error.status === 429) {
      const detalle = detalleDe(error) ?? 'demasiadas peticiones';
      return `No se ha abierto: ${detalle}. Podrá volver a intentarlo dentro de ${esperaDe(error)}.`;
    }
    return textoDeError(error, { 404: TEXTO_NO_DISPONIBLE });
  }

  private textoDeAccion(error: unknown, fallo: string): string {
    if (error instanceof HttpErrorResponse && (error.status === 409 || error.status === 422)) {
      const detalle = detalleDe(error);
      if (detalle !== null) {
        return `${fallo}: ${detalle}.`;
      }
    }
    return textoDeError(error, { 404: TEXTO_NO_DISPONIBLE });
  }
}
