import { HttpErrorResponse } from '@angular/common/http';
import { Component, Injector, inject, signal } from '@angular/core';
import { NonNullableFormBuilder, ReactiveFormsModule } from '@angular/forms';
import { Observable } from 'rxjs';
import { Leila } from '../marca/leila';
import { Rol } from '../nucleo/api';
import { ApiCuentas, ListadoSolicitudes, Solicitud } from '../nucleo/api-cuentas';
import { AYUDA_CODIGO_ACCION, TEXTO_CODIGO_NO_VALE } from '../nucleo/codigo-admin';
import { textoDeError } from '../nucleo/errores';
import { enfocarEncabezado } from '../nucleo/foco';
import { NOMBRES_ROL, nombreRol } from '../nucleo/roles';

// Solicitudes de registro con el email ya verificado, solo para admins
// (app/solicitudes.py). Aprobar crea la cuenta con el rol elegido y manda la
// invitación al email verificado: el admin decide quién entra, pero no ve el
// enlace con el que se fija la contraseña. Rechazar la cierra sin crear nada.
// Las dos quedan en la auditoría.
//
// El rol no viene elegido: aprobar con uno por defecto sería la forma más
// fácil de dar un rol que nadie ha decidido.
//
// Aprobar crea una cuenta: pide un código TOTP recién escrito
// (nucleo/codigo-admin.ts), en una confirmación en la fila que dice a quién y
// con qué rol. El rol se fija al abrirla: lo que se aprueba es lo que dice la
// pregunta, aunque después cambie el desplegable. Con un código que no vale,
// la confirmación sigue abierta y el error va junto al campo, con el foco en
// él (WCAG 2.2, 3.3.1). Rechazar no lo pide: solo cierra la solicitud.

const TEXTO_YA_CERRADA = 'La solicitud ya no está abierta: la ha resuelto otra persona o ha caducado. Se ha actualizado la lista.';

type Confirmacion =
  | { solicitud_id: string; accion: 'aprobar'; rol: Rol }
  | { solicitud_id: string; accion: 'rechazar' };

@Component({
  selector: 'app-solicitudes',
  imports: [Leila, ReactiveFormsModule],
  template: `
    <h1 tabindex="-1">Solicitudes de registro</h1>
    <p class="entradilla">Al aprobar una, la persona recibe el enlace para activar su cuenta.</p>

    @if (hecho(); as texto) {
      <p class="aviso" id="solicitudes-hecho" role="status" tabindex="-1">{{ texto }}</p>
    }
    @if (errorAccion(); as texto) {
      <p class="error" id="solicitudes-error" role="alert" tabindex="-1">{{ texto }}</p>
    }

    @if (listado(); as datos) {
      @if (datos.solicitudes.length === 0) {
        <div class="vacio">
          <app-leila />
          <p class="vacio-titulo">No hay solicitudes pendientes.</p>
          <p class="vacio-texto">Cuando alguien pida acceso y confirme su email, aparecerá aquí.</p>
        </div>
      } @else {
        <h2 id="solicitudes-lista">Pendientes</h2>
        <div class="tabla" role="region" aria-labelledby="solicitudes-lista" tabindex="0">
          <table>
            <thead>
              <tr><th scope="col">Email</th><th scope="col">Rol</th><th scope="col">Acciones</th></tr>
            </thead>
            <tbody>
              @for (solicitud of datos.solicitudes; track solicitud.solicitud_id) {
                <tr>
                  <th scope="row" class="dato">{{ solicitud.email }}</th>
                  <td>
                    <label class="visualmente-oculto" [for]="'rol-' + solicitud.solicitud_id">Rol para {{ solicitud.email }}</label>
                    <select [id]="'rol-' + solicitud.solicitud_id" #rol>
                      <option value="" selected>Elija un rol</option>
                      @for (opcion of roles; track opcion) {
                        <option [value]="opcion">{{ nombreRol(opcion) }}</option>
                      }
                    </select>
                  </td>
                  <td class="acciones">
                    @if (abierta(solicitud); as pendiente) {
                      @if (pendiente.accion === 'aprobar') {
                        <!-- Un formulario: Enter lo envía y el navegador
                             comprueba el formato antes (ngNativeValidate). Solo
                             hay una confirmación abierta: los ids no se repiten. -->
                        <form class="confirmacion" [formGroup]="confirmacion" (ngSubmit)="aprobar(solicitud)" ngNativeValidate>
                          <p class="pregunta" id="solicitudes-pregunta">
                            ¿Aprobar a {{ solicitud.email }} como {{ nombreRol(pendiente.rol) }}? Recibirá un correo para activar su cuenta.
                          </p>
                          <p class="campo">
                            <label for="solicitudes-codigo">Código de autenticación</label>
                            <input id="solicitudes-codigo" formControlName="codigo_totp" required inputmode="numeric"
                                   pattern="[0-9]{6}" title="Las 6 cifras, sin espacios." autocomplete="one-time-code"
                                   [attr.aria-invalid]="codigoMalo() || null"
                                   [attr.aria-describedby]="codigoMalo()
                                     ? 'solicitudes-pregunta solicitudes-codigo-error solicitudes-codigo-ayuda'
                                     : 'solicitudes-pregunta solicitudes-codigo-ayuda'">
                            @if (codigoMalo()) {
                              <span class="error error-campo" id="solicitudes-codigo-error">{{ textoCodigoNoVale }}</span>
                            }
                            <span class="ayuda" id="solicitudes-codigo-ayuda">{{ ayudaCodigo }}</span>
                          </p>
                          <p class="acciones">
                            <button type="submit" [attr.aria-disabled]="ocupado() !== null || null">Confirmar la aprobación</button>
                            <button type="button" class="secundario" (click)="cancelar()">Cancelar</button>
                          </p>
                        </form>
                      } @else {
                        <span>¿Rechazar la solicitud de {{ solicitud.email }}?</span>
                        <button type="button" id="solicitudes-confirmar" class="peligro" (click)="rechazar(solicitud)"
                                [attr.aria-disabled]="ocupado() !== null || null">Confirmar el rechazo</button>
                        <button type="button" class="secundario" (click)="cancelar()">Cancelar</button>
                      }
                    } @else {
                      <button type="button" (click)="pedirAprobacion(solicitud, rol.value)"
                              [attr.aria-disabled]="ocupado() !== null || null">
                        Aprobar<span class="visualmente-oculto"> a {{ solicitud.email }}</span>
                      </button>
                      <button type="button" class="peligro" (click)="pedirRechazo(solicitud)"
                              [attr.aria-disabled]="ocupado() !== null || null">
                        Rechazar<span class="visualmente-oculto"> a {{ solicitud.email }}</span>
                      </button>
                    }
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
        @if (datos.hay_mas) {
          <p class="aviso">Hay más solicitudes de las que caben aquí. Resuelva estas y se mostrarán las siguientes.</p>
        }
      }
    } @else if (errorCarga(); as texto) {
      <p class="error" role="alert">{{ texto }}</p>
      <button type="button" (click)="cargar()">Reintentar</button>
    } @else {
      <p role="status">Cargando las solicitudes...</p>
    }
  `,
})
export class Solicitudes {
  private readonly api = inject(ApiCuentas);
  private readonly injector = inject(Injector);

  readonly roles = Object.keys(NOMBRES_ROL) as Rol[];
  readonly nombreRol = nombreRol;
  readonly ayudaCodigo = AYUDA_CODIGO_ACCION;
  readonly textoCodigoNoVale = TEXTO_CODIGO_NO_VALE;

  readonly confirmacion = inject(NonNullableFormBuilder).group({ codigo_totp: '' });
  readonly listado = signal<ListadoSolicitudes | null>(null);
  readonly errorCarga = signal<string | null>(null);
  // Una acción cada vez. Los botones llevan aria-disabled y no disabled, para
  // no quitarles el foco (denuncias.ts): la guarda de actuar() es la única
  // barrera de la página.
  readonly ocupado = signal<string | null>(null);
  readonly confirmando = signal<Confirmacion | null>(null);
  // El último código de la confirmación no valió: lo marcan aria-invalid y
  // su error.
  readonly codigoMalo = signal(false);
  readonly hecho = signal<string | null>(null);
  readonly errorAccion = signal<string | null>(null);

  constructor() {
    this.cargar();
  }

  cargar(): void {
    this.errorCarga.set(null);
    this.api.solicitudes().subscribe({
      next: (listado) => this.listado.set(listado),
      error: (error: unknown) => {
        this.listado.set(null);
        this.errorCarga.set(textoDeError(error));
      },
    });
  }

  // La confirmación abierta en la fila de esa solicitud, o null.
  abierta(solicitud: Solicitud): Confirmacion | null {
    const confirmando = this.confirmando();
    return confirmando?.solicitud_id === solicitud.solicitud_id ? confirmando : null;
  }

  pedirAprobacion(solicitud: Solicitud, rol: string): void {
    if (this.ocupado() !== null) {
      return;
    }
    // Con la lista y no con "in": "constructor" in {} también es true.
    if (!(this.roles as string[]).includes(rol)) {
      this.hecho.set(null);
      this.errorAccion.set(`Elija el rol de ${solicitud.email} antes de aprobar.`);
      return;
    }
    // El aviso de un intento sin rol ya no vale: el rol está elegido.
    this.errorAccion.set(null);
    this.abrir({ solicitud_id: solicitud.solicitud_id, accion: 'aprobar', rol: rol as Rol }, '#solicitudes-codigo');
  }

  aprobar(solicitud: Solicitud): void {
    const abierta = this.abierta(solicitud);
    if (abierta?.accion !== 'aprobar') {
      return;
    }
    const { rol } = abierta;
    this.actuar(solicitud, this.api.aprobar(solicitud.solicitud_id, rol, this.confirmacion.getRawValue().codigo_totp),
      `Aprobada: ${solicitud.email} recibirá un correo para activar su cuenta como ${nombreRol(rol)}.`, {
        404: TEXTO_YA_CERRADA,
        409: 'Ya existe una cuenta con ese email. Se ha actualizado la lista.',
      }, true);
  }

  pedirRechazo(solicitud: Solicitud): void {
    if (this.ocupado() !== null) {
      return;
    }
    this.abrir({ solicitud_id: solicitud.solicitud_id, accion: 'rechazar' }, '#solicitudes-confirmar');
  }

  rechazar(solicitud: Solicitud): void {
    this.actuar(solicitud, this.api.rechazar(solicitud.solicitud_id),
      `Rechazada la solicitud de ${solicitud.email}.`, { 404: TEXTO_YA_CERRADA }, false);
  }

  cancelar(): void {
    this.confirmando.set(null);
    this.confirmacion.reset();
    this.codigoMalo.set(false);
  }

  // Con una acción en marcha no se abre ninguna confirmación (quien llama lo
  // comprueba): al terminar, actuar() la cerraría bajo el dedo de quien iba
  // a confirmar. El botón pulsado desaparece y el foco va a lo primero que
  // hay que hacer: el campo del código, o el botón del rechazo.
  private abrir(confirmacion: Confirmacion, foco: string): void {
    this.confirmacion.reset();
    this.codigoMalo.set(false);
    this.confirmando.set(confirmacion);
    enfocarEncabezado(this.injector, foco);
  }

  // conCodigo: la acción lleva el código de la confirmación.
  private actuar(solicitud: Solicitud, accion: Observable<unknown>, texto: string,
                 propios: Record<number, string>, conCodigo: boolean): void {
    if (this.ocupado() !== null) {
      return;
    }
    this.ocupado.set(solicitud.solicitud_id);
    this.hecho.set(null);
    this.errorAccion.set(null);
    this.codigoMalo.set(false);
    accion.subscribe({
      next: () => {
        this.ocupado.set(null);
        this.confirmando.set(null);
        this.confirmacion.reset();
        this.hecho.set(texto);
        enfocarEncabezado(this.injector, '#solicitudes-hecho');
        this.cargar();
      },
      error: (error: unknown) => {
        this.ocupado.set(null);
        // El código cambia cada 30 segundos y uno usado no vuelve a valer:
        // se vacía tras cualquier respuesta.
        this.confirmacion.reset();
        if (conCodigo && error instanceof HttpErrorResponse && error.status === 401) {
          // No ha cambiado nada (la API ni gasta el código ni aprueba): la
          // confirmación sigue abierta y la lista no se pide.
          this.codigoMalo.set(true);
          enfocarEncabezado(this.injector, '#solicitudes-codigo');
          return;
        }
        this.confirmando.set(null);
        this.errorAccion.set(textoDeError(error, propios));
        // El botón pulsado puede desaparecer (la confirmación se cierra, o la
        // fila con la lista nueva) y el foco con él: va al error.
        enfocarEncabezado(this.injector, '#solicitudes-error');
        this.cargar();
      },
    });
  }
}
