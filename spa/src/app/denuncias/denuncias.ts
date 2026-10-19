import { Component, Injector, computed, inject, signal } from '@angular/core';
import { NonNullableFormBuilder, ReactiveFormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { Leila } from '../marca/leila';
import { ApiCuentas, Cuenta } from '../nucleo/api-cuentas';
import { ApiDenuncias, Estado, FilaDenuncia } from '../nucleo/api-denuncias';
import { textoDeError } from '../nucleo/errores';
import { enfocarEncabezado } from '../nucleo/foco';
import { Sesion } from '../nucleo/sesion';
import { CLASES_ESTADO, ESTADOS, ICONOS_ESTADO, NOMBRES_ESTADO, esCerrado, fechaLegible } from './textos';

// Listado de denuncias (app/instruccion.py, listar_denuncias): fecha, estado
// y asignación, nunca contenido. Un admin ve todas y asigna; un instructor
// solo ve las suyas. Pedir el listado no deja fila en la auditoría, así que
// tras cada acción se vuelve a pedir, como en las demás pantallas.
//
// El enlace a una denuncia solo sale en las asignadas a quien mira: la API
// solo enseña el contenido a quien la tiene asignada, y en las demás el
// enlace llevaría a un 404 seguro. Un admin que quiere leer una sin asignar
// se la asigna antes, y ese paso queda en la auditoría.

const TEXTO_YA_NO = 'La denuncia o la cuenta ya no existen. Se ha actualizado la lista.';
const TEXTO_NO_ASIGNABLE = 'No se puede asignar: la denuncia está cerrada o la cuenta ya no está activa. Se ha actualizado la lista.';

@Component({
  selector: 'app-denuncias',
  imports: [Leila, ReactiveFormsModule, RouterLink],
  template: `
    <h1 tabindex="-1">Denuncias</h1>
    <p>
      @if (esAdmin()) {
        Todas las denuncias de la empresa, las más recientes primero. Para leer una, asígnesela.
      } @else {
        Las denuncias que tiene asignadas, las más recientes primero.
      }
    </p>

    <form class="filtro" [formGroup]="filtro" (ngSubmit)="filtrar()">
      <p class="campo">
        <label for="denuncias-estado">Estado</label>
        <select id="denuncias-estado" formControlName="estado">
          <option value="">Todos</option>
          @for (estado of estados; track estado) {
            <option [value]="estado">{{ nombreEstado[estado] }}</option>
          }
        </select>
      </p>
      <button type="submit" class="secundario">Filtrar</button>
    </form>

    @if (hecho(); as texto) {
      <p class="aviso" id="denuncias-hecho" role="status" tabindex="-1">{{ texto }}</p>
    }
    @if (errorAccion(); as texto) {
      <p class="error" id="denuncias-error" role="alert" tabindex="-1">{{ texto }}</p>
    }
    @if (esAdmin() && errorCuentas(); as texto) {
      <p class="error" role="alert">No se han podido cargar las cuentas, así que no se puede ver ni cambiar a quién está asignada cada denuncia. {{ texto }}</p>
    }

    @if (filas(); as lista) {
      @if (lista.length === 0) {
        <div class="vacio">
          <app-leila />
          <p class="vacio-titulo">{{ filtrado() === null ? 'No hay denuncias.' : 'No hay denuncias en ese estado.' }}</p>
          <p class="vacio-texto">{{ textoVacio() }}</p>
        </div>
      } @else {
        <h2 id="denuncias-lista">{{ filtrado() === null ? 'Todas' : nombreEstado[filtrado()!] }}</h2>
        <div class="tabla" role="region" aria-labelledby="denuncias-lista" tabindex="0">
          <table>
            <thead>
              <tr>
                <th scope="col">Referencia</th><th scope="col">Fecha</th><th scope="col">Estado</th>
                @if (esAdmin()) {
                  <th scope="col">Asignada a</th>
                }
                <th scope="col">Acciones</th>
              </tr>
            </thead>
            <tbody>
              @for (fila of lista; track fila.denuncia_id) {
                <tr>
                  <th scope="row" class="dato mono">{{ fila.denuncia_id }}</th>
                  <td><time [attr.datetime]="fila.fecha">{{ fecha(fila.fecha) }}</time></td>
                  <td>
                    <span [class]="claseEstado[fila.estado]">
                      @switch (iconoEstado[fila.estado]) {
                        @case ('abierta') {
                          <svg aria-hidden="true" focusable="false" viewBox="0 0 16 16">
                            <circle cx="8" cy="8" r="6.5" fill="none" stroke="currentColor" stroke-width="1.5" />
                            <circle cx="8" cy="8" r="2" fill="currentColor" />
                          </svg>
                        }
                        @case ('resuelta') {
                          <svg aria-hidden="true" focusable="false" viewBox="0 0 16 16">
                            <circle cx="8" cy="8" r="6.5" fill="none" stroke="currentColor" stroke-width="1.5" />
                            <path d="M5 8.2 L7.2 10.4 L11 6" fill="none" stroke="currentColor" stroke-width="1.5"
                                  stroke-linecap="round" stroke-linejoin="round" />
                          </svg>
                        }
                        @case ('archivada') {
                          <svg aria-hidden="true" focusable="false" viewBox="0 0 16 16">
                            <rect x="1.75" y="2.5" width="12.5" height="3.5" rx="1" fill="none" stroke="currentColor" stroke-width="1.5" />
                            <path d="M3 6 V12.5 A1 1 0 0 0 4 13.5 H12 A1 1 0 0 0 13 12.5 V6 M6.5 8.75 H9.5" fill="none"
                                  stroke="currentColor" stroke-width="1.5" stroke-linecap="round" />
                          </svg>
                        }
                        @case ('inadmitida') {
                          <svg aria-hidden="true" focusable="false" viewBox="0 0 16 16">
                            <circle cx="8" cy="8" r="6.5" fill="none" stroke="currentColor" stroke-width="1.5" />
                            <path d="M3.5 12.5 L12.5 3.5" fill="none" stroke="currentColor" stroke-width="1.5" />
                          </svg>
                        }
                      }
                      {{ nombreEstado[fila.estado] }}
                    </span>
                  </td>
                  @if (esAdmin()) {
                    <td class="dato">{{ asignacion(fila) }}</td>
                  }
                  <td class="acciones">
                    @if (fila.asignada_a === propia()) {
                      <a [routerLink]="['/denuncias', fila.denuncia_id]">Ir a la denuncia<span class="visualmente-oculto"> {{ fila.denuncia_id }}</span></a>
                    }
                    @if (esAdmin() && !cerrada(fila.estado) && destinos(); as cuentas) {
                      <label class="visualmente-oculto" [for]="'asignar-' + fila.denuncia_id">Asignar la denuncia {{ fila.denuncia_id }} a</label>
                      <select [id]="'asignar-' + fila.denuncia_id" #destino>
                        <option value="" selected>Elija una cuenta</option>
                        @for (cuenta of cuentas; track cuenta.usuario_id) {
                          <option [value]="cuenta.usuario_id">{{ cuenta.email }}</option>
                        }
                      </select>
                      <button type="button" class="secundario" (click)="asignar(fila, destino.value)"
                              [attr.aria-disabled]="ocupado() || null">
                        Asignar<span class="visualmente-oculto"> la denuncia {{ fila.denuncia_id }}</span>
                      </button>
                    }
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
        @if (siguiente() !== null) {
          <button type="button" class="secundario" (click)="cargarMas()" [attr.aria-disabled]="ocupado() || null">
            {{ ocupado() ? 'Cargando...' : 'Cargar más' }}
          </button>
        }
      }
    } @else if (errorCarga(); as texto) {
      <p class="error" role="alert">{{ texto }}</p>
      <button type="button" (click)="cargar()">Reintentar</button>
    } @else {
      <p role="status">Cargando las denuncias...</p>
    }
  `,
})
export class Denuncias {
  private readonly api = inject(ApiDenuncias);
  private readonly apiCuentas = inject(ApiCuentas);
  private readonly injector = inject(Injector);
  private readonly sesion = inject(Sesion);

  readonly estados = ESTADOS;
  readonly nombreEstado = NOMBRES_ESTADO;
  readonly claseEstado = CLASES_ESTADO;
  readonly iconoEstado = ICONOS_ESTADO;
  readonly fecha = fechaLegible;
  readonly cerrada = esCerrado;
  readonly propia = computed(() => this.sesion.yo()?.usuario_id);
  readonly esAdmin = computed(() => this.sesion.yo()?.rol === 'admin');

  readonly filtro = inject(NonNullableFormBuilder).group({ estado: '' });
  // El filtro aplicado (el del formulario solo cuenta al pulsar Filtrar).
  readonly filtrado = signal<Estado | null>(null);
  readonly filas = signal<FilaDenuncia[] | null>(null);
  readonly siguiente = signal<string | null>(null);
  readonly errorCarga = signal<string | null>(null);
  readonly cuentas = signal<Cuenta[] | null>(null);
  readonly errorCuentas = signal<string | null>(null);
  // Una petición cada vez: un doble clic no asigna dos veces ni salta páginas.
  // Mientras tanto los botones llevan aria-disabled y no disabled: a un botón
  // disabled Chromium le quita el foco (pasa al <body> y no vuelve), y quien
  // lo pulsó con el teclado no sabría dónde está (WCAG 2.2, 2.4.3). La guarda
  // de cada acción es la que impide la segunda petición.
  readonly ocupado = signal(false);
  readonly hecho = signal<string | null>(null);
  readonly errorAccion = signal<string | null>(null);

  // Las cuentas a las que se puede asignar: activas, activadas y con un rol
  // que instruye (app/personal.py, ROLES_INSTRUCCION). null si no se pudieron
  // cargar: entonces no se ofrece asignar.
  readonly destinos = computed(() => this.cuentas()?.filter((c) => c.activo && c.activado && c.rol !== 'auditor') ?? null);

  // Qué esperar cuando la lista está vacía: depende del filtro y de quién
  // mira, porque al instructor solo le llegan las que le asignan.
  readonly textoVacio = computed(() => {
    if (this.filtrado() !== null) {
      return 'Pruebe con otro estado.';
    }
    return this.esAdmin() ? 'Cuando alguien presente una denuncia, aparecerá aquí.'
      : 'Cuando un admin le asigne una, aparecerá aquí.';
  });

  constructor() {
    this.cargar();
    if (this.esAdmin()) {
      this.cargarCuentas();
    }
  }

  // La primera página con el filtro aplicado.
  cargar(): void {
    this.errorCarga.set(null);
    this.api.listar(this.filtrado(), null).subscribe({
      next: (pagina) => {
        this.filas.set(pagina.denuncias);
        this.siguiente.set(pagina.siguiente);
      },
      error: (error: unknown) => {
        this.filas.set(null);
        this.siguiente.set(null);
        this.errorCarga.set(textoDeError(error));
      },
    });
  }

  filtrar(): void {
    const estado = this.filtro.getRawValue().estado;
    this.filtrado.set((ESTADOS as string[]).includes(estado) ? (estado as Estado) : null);
    this.hecho.set(null);
    this.errorAccion.set(null);
    this.filas.set(null);
    this.cargar();
  }

  // Añade la página siguiente. El foco se queda en el botón (aria-disabled,
  // arriba) y el aviso dice cuántas han llegado (WCAG 2.2, 4.1.3 Status
  // Messages). Con la última página el botón desaparece: el foco pasa al
  // aviso, que lo dice, en vez de perderse en el <body> (2.4.3 Focus Order),
  // como en la auditoría.
  cargarMas(): void {
    const cursor = this.siguiente();
    if (cursor === null || this.ocupado()) {
      return;
    }
    this.ocupado.set(true);
    this.hecho.set(null);
    this.errorAccion.set(null);
    this.api.listar(this.filtrado(), cursor).subscribe({
      next: (pagina) => {
        this.ocupado.set(false);
        this.filas.update((filas) => [...(filas ?? []), ...pagina.denuncias]);
        this.siguiente.set(pagina.siguiente);
        const texto = pagina.denuncias.length === 1 ? 'Se ha cargado 1 denuncia más.'
          : `Se han cargado ${pagina.denuncias.length} denuncias más.`;
        if (pagina.siguiente === null) {
          this.hecho.set(`${texto} Es el final de la lista.`);
          enfocarEncabezado(this.injector, '#denuncias-hecho');
        } else {
          this.hecho.set(texto);
        }
      },
      error: (error: unknown) => {
        this.ocupado.set(false);
        this.errorAccion.set(textoDeError(error));
      },
    });
  }

  asignacion(fila: FilaDenuncia): string {
    if (fila.asignada_a === null) {
      return 'Sin asignar';
    }
    const email = this.cuentas()?.find((c) => c.usuario_id === fila.asignada_a)?.email;
    let quien = email ?? 'Otra cuenta';
    if (fila.asignada_a === this.propia()) {
      quien = email === undefined ? 'Usted' : `${email} (usted)`;
    }
    return fila.asignada_activa === false ? `${quien}: la cuenta ya no está activa, reasígnela` : quien;
  }

  asignar(fila: FilaDenuncia, usuarioId: string): void {
    const cuenta = this.destinos()?.find((c) => c.usuario_id === usuarioId);
    if (cuenta === undefined) {
      this.hecho.set(null);
      this.errorAccion.set(`Elija la cuenta a la que asignar la denuncia ${fila.denuncia_id}.`);
      return;
    }
    if (this.ocupado()) {
      return;
    }
    this.ocupado.set(true);
    this.hecho.set(null);
    this.errorAccion.set(null);
    this.api.asignar(fila.denuncia_id, cuenta.usuario_id).subscribe({
      next: () => {
        this.ocupado.set(false);
        this.hecho.set(`La denuncia ${fila.denuncia_id} está asignada a ${cuenta.email}.`);
        enfocarEncabezado(this.injector, '#denuncias-hecho');
        this.cargar();
      },
      error: (error: unknown) => {
        this.ocupado.set(false);
        this.errorAccion.set(textoDeError(error, { 404: TEXTO_YA_NO, 409: TEXTO_NO_ASIGNABLE }));
        // Con la lista nueva, la fila o su botón pueden desaparecer (la
        // denuncia ya no existe o está cerrada) y el foco con ellos: va al error.
        enfocarEncabezado(this.injector, '#denuncias-error');
        this.cargar();
        this.cargarCuentas();
      },
    });
  }

  private cargarCuentas(): void {
    this.errorCuentas.set(null);
    this.apiCuentas.cuentas().subscribe({
      next: (cuentas) => this.cuentas.set(cuentas),
      error: (error: unknown) => {
        this.cuentas.set(null);
        this.errorCuentas.set(textoDeError(error));
      },
    });
  }
}
