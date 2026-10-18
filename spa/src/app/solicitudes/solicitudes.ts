import { Component, Injector, inject, signal } from '@angular/core';
import { Observable } from 'rxjs';
import { Rol } from '../nucleo/api';
import { ApiCuentas, ListadoSolicitudes, Solicitud } from '../nucleo/api-cuentas';
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

const TEXTO_YA_CERRADA = 'La solicitud ya no está abierta: la ha resuelto otra persona o ha caducado. Se ha actualizado la lista.';

@Component({
  selector: 'app-solicitudes',
  template: `
    <h1 tabindex="-1">Solicitudes de registro</h1>
    <p>Personas que han pedido acceso y han confirmado su email. Si aprueba una, recibirá por correo el enlace para activar su cuenta.</p>

    @if (hecho(); as texto) {
      <p class="aviso" id="solicitudes-hecho" role="status" tabindex="-1">{{ texto }}</p>
    }
    @if (errorAccion(); as texto) {
      <p class="error" id="solicitudes-error" role="alert" tabindex="-1">{{ texto }}</p>
    }

    @if (listado(); as datos) {
      @if (datos.solicitudes.length === 0) {
        <p>No hay solicitudes pendientes.</p>
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
                    @if (confirmando() === solicitud.solicitud_id) {
                      <span>¿Rechazar la solicitud de {{ solicitud.email }}?</span>
                      <button type="button" id="solicitudes-confirmar" class="peligro" (click)="rechazar(solicitud)"
                              [attr.aria-disabled]="ocupado() !== null || null">Confirmar el rechazo</button>
                      <button type="button" class="secundario" (click)="confirmando.set(null)">Cancelar</button>
                    } @else {
                      <button type="button" (click)="aprobar(solicitud, rol.value)"
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

  readonly listado = signal<ListadoSolicitudes | null>(null);
  readonly errorCarga = signal<string | null>(null);
  // Una acción cada vez. Los botones llevan aria-disabled y no disabled, para
  // no quitarles el foco (denuncias.ts): la guarda de actuar() es la única
  // barrera de la página.
  readonly ocupado = signal<string | null>(null);
  readonly confirmando = signal<string | null>(null);
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

  aprobar(solicitud: Solicitud, rol: string): void {
    // Con la lista y no con "in": "constructor" in {} también es true.
    if (!(this.roles as string[]).includes(rol)) {
      this.hecho.set(null);
      this.errorAccion.set(`Elija el rol de ${solicitud.email} antes de aprobar.`);
      return;
    }
    this.actuar(solicitud, this.api.aprobar(solicitud.solicitud_id, rol as Rol),
      `Aprobada: ${solicitud.email} recibirá un correo para activar su cuenta como ${nombreRol(rol as Rol)}.`, {
        404: TEXTO_YA_CERRADA,
        409: 'Ya existe una cuenta con ese email. Se ha actualizado la lista.',
      });
  }

  pedirRechazo(solicitud: Solicitud): void {
    // Con una acción en marcha no se abre la confirmación: al terminar,
    // actuar() la cerraría bajo el dedo de quien iba a confirmar.
    if (this.ocupado() !== null) {
      return;
    }
    this.confirmando.set(solicitud.solicitud_id);
    enfocarEncabezado(this.injector, '#solicitudes-confirmar');
  }

  rechazar(solicitud: Solicitud): void {
    this.actuar(solicitud, this.api.rechazar(solicitud.solicitud_id),
      `Rechazada la solicitud de ${solicitud.email}.`, { 404: TEXTO_YA_CERRADA });
  }

  private actuar(solicitud: Solicitud, accion: Observable<unknown>, texto: string,
                 propios: Record<number, string>): void {
    if (this.ocupado() !== null) {
      return;
    }
    this.ocupado.set(solicitud.solicitud_id);
    this.hecho.set(null);
    this.errorAccion.set(null);
    accion.subscribe({
      next: () => {
        this.ocupado.set(null);
        this.confirmando.set(null);
        this.hecho.set(texto);
        enfocarEncabezado(this.injector, '#solicitudes-hecho');
        this.cargar();
      },
      error: (error: unknown) => {
        this.ocupado.set(null);
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
