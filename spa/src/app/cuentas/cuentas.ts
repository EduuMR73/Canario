import { DOCUMENT } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, Injector, computed, inject, signal } from '@angular/core';
import { NonNullableFormBuilder, ReactiveFormsModule } from '@angular/forms';
import { Observable } from 'rxjs';
import { Rol } from '../nucleo/api';
import { ApiCuentas, Cuenta, Invitacion } from '../nucleo/api-cuentas';
import { AYUDA_CODIGO_ACCION, TEXTO_CODIGO_NO_VALE } from '../nucleo/codigo-admin';
import { textoDeError } from '../nucleo/errores';
import { enfocarEncabezado } from '../nucleo/foco';
import { NOMBRES_ROL, nombreRol } from '../nucleo/roles';
import { Sesion } from '../nucleo/sesion';
import { avisosDe, enlaceDeActivacion, situacionDe } from './estado';

// Cuentas de la empresa, solo para admins (app/personal.py): invitar,
// reinvitar, anular una invitación y dar de baja. Cada acción la audita la
// API.
//
// Invitar, reinvitar y dar de baja piden un código TOTP recién escrito
// (nucleo/codigo-admin.ts). Reinvitar y dar de baja lo piden en una
// confirmación en la propia fila, que dice a quién y qué pasa. Con un código
// que no vale, la confirmación sigue abierta y el error va junto al campo,
// con el foco en él (WCAG 2.2, 3.3.1): se escribe el siguiente sin volver a
// empezar. Cualquier otra respuesta la cierra, como antes.
//
// El enlace de una invitación (el token de un solo uso con el que su titular
// elige la contraseña) se enseña una vez, como texto y nunca como enlace: un
// clic lo abriría en el navegador del admin, que activaría allí la cuenta de
// otra persona y se quedaría con su dispositivo de confianza. Vive solo en
// esta página, en memoria: no va a la URL, ni al almacenamiento, ni a la
// consola, y desaparece al salir de la página o al pulsar "Ya lo he
// entregado".

const TEXTO_NO_EXISTE = 'La cuenta ya no existe o no tiene ninguna invitación abierta. Se ha actualizado la lista.';

// Las acciones de la fila que piden confirmación (y código). Anular no la
// pide: solo cierra una invitación, y se deshace reinvitando.
type Accion = 'reinvitar' | 'baja';

// Dónde se escribió el código de una acción en curso.
type Campo = 'invitar' | 'confirmacion';

interface EnlaceMostrado {
  email: string;
  enlace: string;
}

@Component({
  selector: 'app-cuentas',
  imports: [ReactiveFormsModule],
  template: `
    <h1 tabindex="-1">Cuentas</h1>

    <h2>Invitar a una persona</h2>
    <form class="invitar" [formGroup]="formulario" (ngSubmit)="invitar()" ngNativeValidate>
      <p class="campo">
        <label for="cuentas-email">Email</label>
        <input id="cuentas-email" type="email" formControlName="email" required autocomplete="off"
               autocapitalize="none" spellcheck="false">
      </p>
      <p class="campo">
        <label for="cuentas-rol">Rol</label>
        <select id="cuentas-rol" formControlName="rol" required>
          <option value="" disabled>Elija un rol</option>
          @for (rol of roles; track rol) {
            <option [value]="rol">{{ nombreRol(rol) }}</option>
          }
        </select>
      </p>
      <p class="campo">
        <label for="cuentas-invitar-codigo">Código de autenticación</label>
        <input id="cuentas-invitar-codigo" formControlName="codigo_totp" required inputmode="numeric"
               pattern="[0-9]{6}" title="Las 6 cifras, sin espacios." autocomplete="one-time-code"
               [attr.aria-invalid]="codigoMalo() === 'invitar' || null"
               [attr.aria-describedby]="codigoMalo() === 'invitar'
                 ? 'cuentas-invitar-codigo-error cuentas-invitar-codigo-ayuda' : 'cuentas-invitar-codigo-ayuda'">
      </p>
      <button type="submit" [attr.aria-disabled]="ocupado() !== null || null">
        {{ ocupado() === 'invitar' ? 'Invitando...' : 'Invitar' }}
      </button>
      @if (codigoMalo() === 'invitar') {
        <p class="error error-campo" id="cuentas-invitar-codigo-error">{{ textoCodigoNoVale }}</p>
      }
      <p class="ayuda" id="cuentas-invitar-codigo-ayuda">{{ ayudaCodigo }}</p>
    </form>

    @if (mostrado(); as invitacion) {
      <section class="aviso enlace-invitacion" aria-labelledby="cuentas-enlace-titulo">
        <h2 id="cuentas-enlace-titulo" tabindex="-1">Enlace de activación para {{ invitacion.email }}</h2>
        <p>Entrégueselo a esa persona por un canal de confianza. Vale una sola vez, durante 72 horas, y no se volverá a mostrar.</p>
        <p><code class="enlace" id="cuentas-enlace">{{ invitacion.enlace }}</code></p>
        <p class="acciones">
          <button type="button" class="secundario" (click)="copiar(invitacion.enlace)">Copiar el enlace</button>
          <button type="button" class="secundario" (click)="ocultarEnlace()">Ya lo he entregado</button>
        </p>
        @if (copiado(); as texto) {
          <p role="status">{{ texto }}</p>
        }
      </section>
    }

    @if (hecho(); as texto) {
      <p class="aviso" id="cuentas-hecho" role="status" tabindex="-1">{{ texto }}</p>
    }
    @if (errorAccion(); as texto) {
      <p class="error" id="cuentas-error" role="alert" tabindex="-1">{{ texto }}</p>
    }

    <h2 id="cuentas-lista">Cuentas de la empresa</h2>
    @if (cuentas(); as lista) {
      <div class="tabla" role="region" aria-labelledby="cuentas-lista" tabindex="0">
        <table>
          <thead>
            <tr><th scope="col">Email</th><th scope="col">Rol</th><th scope="col">Situación</th><th scope="col">Acciones</th></tr>
          </thead>
          <tbody>
            @for (cuenta of lista; track cuenta.usuario_id) {
              <tr>
                <th scope="row" class="dato">{{ cuenta.email }}</th>
                <td>{{ nombreRol(cuenta.rol) }}</td>
                <td>
                  {{ situacion(cuenta) }}
                  @for (aviso of avisos(cuenta); track aviso) {
                    <span class="etiqueta">{{ aviso }}</span>
                  }
                </td>
                <td class="acciones">
                  @if (abierta(cuenta); as accion) {
                    <!-- Un formulario por confirmación: Enter la envía y el
                         navegador comprueba el formato antes (ngNativeValidate).
                         Solo hay una abierta: los ids no se repiten. -->
                    <form class="confirmacion" [formGroup]="confirmacion" (ngSubmit)="confirmar(cuenta)" ngNativeValidate>
                      <p class="pregunta" id="cuentas-pregunta">
                        @if (accion === 'baja') {
                          ¿Dar de baja a {{ cuenta.email }}? Se cerrarán sus sesiones.
                        } @else {
                          ¿Reinvitar a {{ cuenta.email }}? Se generará un enlace de activación nuevo y el anterior dejará de valer.
                        }
                      </p>
                      <p class="campo">
                        <label for="cuentas-codigo">Código de autenticación</label>
                        <input id="cuentas-codigo" formControlName="codigo_totp" required inputmode="numeric"
                               pattern="[0-9]{6}" title="Las 6 cifras, sin espacios." autocomplete="one-time-code"
                               [attr.aria-invalid]="codigoMalo() === 'confirmacion' || null"
                               [attr.aria-describedby]="codigoMalo() === 'confirmacion'
                                 ? 'cuentas-pregunta cuentas-codigo-error cuentas-codigo-ayuda'
                                 : 'cuentas-pregunta cuentas-codigo-ayuda'">
                        @if (codigoMalo() === 'confirmacion') {
                          <span class="error error-campo" id="cuentas-codigo-error">{{ textoCodigoNoVale }}</span>
                        }
                        <span class="ayuda" id="cuentas-codigo-ayuda">{{ ayudaCodigo }}</span>
                      </p>
                      <p class="acciones">
                        <button type="submit" id="cuentas-confirmar" [class.peligro]="accion === 'baja'"
                                [attr.aria-disabled]="ocupado() !== null || null">
                          {{ accion === 'baja' ? 'Confirmar la baja' : 'Confirmar la reinvitación' }}
                        </button>
                        <button type="button" class="secundario" (click)="cancelar()">Cancelar</button>
                      </p>
                    </form>
                  } @else {
                    <button type="button" class="secundario" (click)="pedir(cuenta, 'reinvitar')"
                            [attr.aria-disabled]="ocupado() !== null || null">
                      Reinvitar<span class="visualmente-oculto"> a {{ cuenta.email }}</span>
                    </button>
                    @if (cuenta.invitacion_pendiente) {
                      <button type="button" class="secundario" (click)="anular(cuenta)"
                              [attr.aria-disabled]="ocupado() !== null || null">
                        Anular la invitación<span class="visualmente-oculto"> de {{ cuenta.email }}</span>
                      </button>
                    }
                    <!-- La propia cuenta no se da de baja desde aquí: cerraría
                         la sesión de quien la pide sin vuelta atrás. -->
                    @if (cuenta.activo && cuenta.usuario_id !== propia()) {
                      <button type="button" class="peligro" (click)="pedir(cuenta, 'baja')"
                              [attr.aria-disabled]="ocupado() !== null || null">
                        Dar de baja<span class="visualmente-oculto"> a {{ cuenta.email }}</span>
                      </button>
                    }
                  }
                </td>
              </tr>
            }
          </tbody>
        </table>
      </div>
    } @else if (errorCarga(); as texto) {
      <p class="error" role="alert">{{ texto }}</p>
      <button type="button" (click)="cargar()">Reintentar</button>
    } @else {
      <p role="status">Cargando las cuentas...</p>
    }
  `,
})
export class Cuentas {
  private readonly api = inject(ApiCuentas);
  private readonly injector = inject(Injector);
  private readonly origen = inject(DOCUMENT).location.origin;
  private readonly sesion = inject(Sesion);

  readonly roles = Object.keys(NOMBRES_ROL) as Rol[];
  readonly nombreRol = nombreRol;
  readonly situacion = situacionDe;
  readonly avisos = avisosDe;
  readonly propia = computed(() => this.sesion.yo()?.usuario_id);
  readonly ayudaCodigo = AYUDA_CODIGO_ACCION;
  readonly textoCodigoNoVale = TEXTO_CODIGO_NO_VALE;

  private readonly fb = inject(NonNullableFormBuilder);
  readonly formulario = this.fb.group({ email: '', rol: '', codigo_totp: '' });
  // Un solo control para la confirmación abierta: al abrir otra, empieza
  // vacío.
  readonly confirmacion = this.fb.group({ codigo_totp: '' });
  readonly cuentas = signal<Cuenta[] | null>(null);
  readonly errorCarga = signal<string | null>(null);
  // Una acción cada vez: un doble clic no repite una invitación ni una baja.
  // Los botones llevan aria-disabled y no disabled, para no quitarles el foco
  // (denuncias.ts): la guarda de actuar() es la única barrera de la página.
  readonly ocupado = signal<string | null>(null);
  readonly confirmando = signal<{ usuario_id: string; accion: Accion } | null>(null);
  // El campo cuyo último código no valió: lo marcan aria-invalid y su error.
  readonly codigoMalo = signal<Campo | null>(null);
  readonly hecho = signal<string | null>(null);
  readonly errorAccion = signal<string | null>(null);
  readonly mostrado = signal<EnlaceMostrado | null>(null);
  readonly copiado = signal<string | null>(null);

  constructor() {
    this.cargar();
  }

  cargar(): void {
    this.errorCarga.set(null);
    this.api.cuentas().subscribe({
      next: (cuentas) => this.cuentas.set(cuentas),
      error: (error: unknown) => {
        this.cuentas.set(null);
        this.errorCarga.set(textoDeError(error));
      },
    });
  }

  invitar(): void {
    const { email, rol, codigo_totp } = this.formulario.getRawValue();
    if (rol === '') {
      return;
    }
    this.actuar('invitar', this.api.invitar(email, rol as Rol, codigo_totp), (invitacion) => {
      this.formulario.reset();
      this.mostrarEnlace(email, invitacion);
    }, {
      409: 'Ya existe una cuenta con ese email.',
      422: 'Revise el email: no tiene un formato válido.',
    }, 'invitar');
  }

  anular(cuenta: Cuenta): void {
    this.actuar(cuenta.usuario_id, this.api.anularInvitacion(cuenta.usuario_id),
      () => this.terminar(`Se ha anulado la invitación de ${cuenta.email}.`), { 404: TEXTO_NO_EXISTE }, null);
  }

  // La acción con la confirmación abierta en la fila de esa cuenta, o null.
  abierta(cuenta: Cuenta): Accion | null {
    const confirmando = this.confirmando();
    return confirmando?.usuario_id === cuenta.usuario_id ? confirmando.accion : null;
  }

  pedir(cuenta: Cuenta, accion: Accion): void {
    // Con una acción en marcha no se abre la confirmación: al terminar,
    // actuar() la cerraría bajo el dedo de quien iba a confirmar.
    if (this.ocupado() !== null) {
      return;
    }
    this.confirmacion.reset();
    if (this.codigoMalo() === 'confirmacion') {
      this.codigoMalo.set(null);
    }
    this.confirmando.set({ usuario_id: cuenta.usuario_id, accion });
    // El botón pulsado desaparece: el foco pasa al campo, lo primero que hay
    // que hacer. La pregunta lo describe (aria-describedby): el lector de
    // pantalla dice a quién y qué pasa, no solo "Código de autenticación".
    enfocarEncabezado(this.injector, '#cuentas-codigo');
  }

  cancelar(): void {
    this.confirmando.set(null);
    this.confirmacion.reset();
    if (this.codigoMalo() === 'confirmacion') {
      this.codigoMalo.set(null);
    }
  }

  confirmar(cuenta: Cuenta): void {
    const accion = this.abierta(cuenta);
    const { codigo_totp } = this.confirmacion.getRawValue();
    if (accion === 'reinvitar') {
      this.actuar(cuenta.usuario_id, this.api.reinvitar(cuenta.usuario_id, codigo_totp),
        (invitacion) => this.mostrarEnlace(cuenta.email, invitacion), { 404: TEXTO_NO_EXISTE }, 'confirmacion');
    } else if (accion === 'baja') {
      this.actuar(cuenta.usuario_id, this.api.darDeBaja(cuenta.usuario_id, codigo_totp),
        () => this.terminar(`${cuenta.email} está de baja: sus sesiones se han cerrado. Se puede reactivar con una invitación.`), {
          404: TEXTO_NO_EXISTE,
          409: 'No se puede dar de baja: la empresa se quedaría sin ningún admin activo.',
        }, 'confirmacion');
    }
  }

  copiar(enlace: string): void {
    navigator.clipboard.writeText(enlace).then(
      () => this.copiado.set('Copiado. Bórrelo del portapapeles cuando lo haya entregado.'),
      () => this.copiado.set('No se ha podido copiar: selecciónelo y cópielo a mano.'),
    );
  }

  ocultarEnlace(): void {
    this.mostrado.set(null);
    this.copiado.set(null);
    enfocarEncabezado(this.injector);
  }

  private mostrarEnlace(email: string, invitacion: Invitacion): void {
    this.copiado.set(null);
    this.mostrado.set({ email, enlace: enlaceDeActivacion(this.origen, invitacion.token_invitacion) });
    this.terminar(null);
    enfocarEncabezado(this.injector, '#cuentas-enlace-titulo');
  }

  // Tras una acción, la lista se vuelve a pedir: lo que se pinta es siempre
  // lo que dice la API, no lo que la página supone que ha cambiado.
  private terminar(texto: string | null): void {
    this.hecho.set(texto);
    if (texto !== null) {
      enfocarEncabezado(this.injector, '#cuentas-hecho');
    }
    this.cargar();
  }

  // campo: dónde se escribió el código de la acción, o null si no lleva.
  private actuar<T>(quien: string, accion: Observable<T>, alTerminar: (respuesta: T) => void,
                    propios: Record<number, string>, campo: Campo | null): void {
    if (this.ocupado() !== null) {
      return;
    }
    this.ocupado.set(quien);
    this.hecho.set(null);
    this.errorAccion.set(null);
    this.codigoMalo.set(null);
    accion.subscribe({
      next: (respuesta) => {
        this.ocupado.set(null);
        this.confirmando.set(null);
        this.vaciarCodigo(campo);
        alTerminar(respuesta);
      },
      error: (error: unknown) => {
        this.ocupado.set(null);
        // El código cambia cada 30 segundos y uno usado no vuelve a valer:
        // se vacía tras cualquier respuesta.
        this.vaciarCodigo(campo);
        if (campo !== null && error instanceof HttpErrorResponse && error.status === 401) {
          // No ha cambiado nada (la API ni gasta el código ni hace la
          // acción): la confirmación sigue abierta y la lista no se pide.
          this.codigoMalo.set(campo);
          enfocarEncabezado(this.injector, campo === 'invitar' ? '#cuentas-invitar-codigo' : '#cuentas-codigo');
          return;
        }
        this.confirmando.set(null);
        this.errorAccion.set(textoDeError(error, propios));
        // El botón pulsado puede desaparecer (la confirmación se cierra, o la
        // fila con la lista nueva) y el foco con él: va al error.
        enfocarEncabezado(this.injector, '#cuentas-error');
        // La lista puede haber cambiado (otra persona actuó a la vez).
        this.cargar();
      },
    });
  }

  private vaciarCodigo(campo: Campo | null): void {
    if (campo === 'invitar') {
      this.formulario.controls.codigo_totp.reset();
    } else if (campo === 'confirmacion') {
      this.confirmacion.reset();
    }
  }
}
