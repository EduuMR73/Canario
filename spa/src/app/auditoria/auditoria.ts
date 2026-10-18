import { Component, Injector, inject, signal } from '@angular/core';
import { fechaLegible } from '../denuncias/textos';
import { ApiAuditoria, FilaAuditoria, Verificacion } from '../nucleo/api-auditoria';
import { textoDeError } from '../nucleo/errores';
import { enfocarEncabezado } from '../nucleo/foco';
import { nombreAccion, quienActua, sobreQue, textoCadena, textoCargadas } from './textos';

// Auditoría de la empresa, para admins y auditores (app/instruccion.py,
// listar_auditoria_reciente): quién hizo qué, lo más reciente primero.
//
// Mismo patrón que el listado de denuncias: "Cargar anteriores" añade la
// página siguiente hacia el principio y deja el foco en el botón, y
// "Actualizar" vuelve a pedir la primera sin vaciar la tabla mientras llega.
// Un solo sitio para el estado: las filas cargadas y el cursor de la API.
//
// Mientras hay una petición, los botones llevan aria-disabled y no disabled:
// un botón disabled deja de poder tener el foco, y quien lo acaba de pulsar
// con el teclado lo perdería (WAI-ARIA APG, "Focusability of disabled
// controls"). La guarda de cada acción (ocupado, verificando) es la que
// impide la segunda petición.
//
// fechaLegible viene de las denuncias: es la misma lectura de un día sin hora.

@Component({
  selector: 'app-auditoria',
  template: `
    <h1 tabindex="-1">Auditoría</h1>
    <p>
      Quién ha hecho qué en la empresa, lo más reciente primero. Cada fila está encadenada con la anterior: si
      alguien cambiara, borrara o insertara una, la verificación diría dónde.
    </p>

    <h2 id="auditoria-cadena">Verificación</h2>
    <p>
      <button type="button" class="secundario" (click)="verificar()" [attr.aria-disabled]="verificando() || null">
        {{ verificando() ? 'Verificando...' : 'Verificar la cadena' }}
      </button>
    </p>
    @if (verificacion(); as resultado) {
      @if (resultado.cadena_intacta) {
        <p class="aviso" role="status">{{ cadena(resultado) }}</p>
      } @else {
        <p class="error" role="alert">{{ cadena(resultado) }}</p>
      }
    }
    @if (errorVerificacion(); as texto) {
      <p class="error" role="alert">No se ha podido verificar la cadena. {{ texto }}</p>
    }

    <h2 id="auditoria-lista">Registro</h2>
    @if (filas(); as lista) {
      <p>
        <button type="button" class="secundario" (click)="actualizar()" [attr.aria-disabled]="ocupado() || null">
          {{ ocupado() ? 'Cargando...' : 'Actualizar' }}
        </button>
      </p>
      @if (hecho(); as texto) {
        <p class="aviso" id="auditoria-hecho" role="status" tabindex="-1">{{ texto }}</p>
      }
      @if (errorAccion(); as texto) {
        <p class="error" role="alert">{{ texto }}</p>
      }
      @if (lista.length === 0) {
        <p>Todavía no hay nada en la auditoría.</p>
      } @else {
        <div class="tabla" role="region" aria-labelledby="auditoria-lista" tabindex="0">
          <table>
            <thead>
              <tr>
                <th scope="col">Nº</th><th scope="col">Día</th><th scope="col">Quién</th><th scope="col">Qué</th>
                <th scope="col">Sobre qué</th>
              </tr>
            </thead>
            <tbody>
              @for (fila of lista; track fila.secuencia) {
                <tr>
                  <th scope="row">{{ fila.secuencia }}</th>
                  <td><time [attr.datetime]="fila.fecha">{{ fecha(fila.fecha) }}</time></td>
                  <td class="dato">{{ quien(fila) }}</td>
                  <td>{{ accion(fila.accion) }}</td>
                  <td class="dato">{{ sobre(fila) }}</td>
                </tr>
              }
            </tbody>
          </table>
        </div>
        @if (anterior() !== null) {
          <button type="button" class="secundario" (click)="cargarAnteriores()" [attr.aria-disabled]="ocupado() || null">
            {{ ocupado() ? 'Cargando...' : 'Cargar anteriores' }}
          </button>
        } @else {
          <p>Es el principio de la auditoría.</p>
        }
      }
    } @else if (errorCarga(); as texto) {
      <p class="error" role="alert">{{ texto }}</p>
      <button type="button" (click)="cargar()">Reintentar</button>
    } @else {
      <p role="status">Cargando la auditoría...</p>
    }
  `,
})
export class Auditoria {
  private readonly api = inject(ApiAuditoria);
  private readonly injector = inject(Injector);

  readonly fecha = fechaLegible;
  readonly accion = nombreAccion;
  readonly quien = quienActua;
  readonly sobre = sobreQue;
  readonly cadena = textoCadena;

  readonly filas = signal<FilaAuditoria[] | null>(null);
  readonly anterior = signal<number | null>(null);
  readonly errorCarga = signal<string | null>(null);
  // Una petición cada vez: un doble clic no salta páginas.
  readonly ocupado = signal(false);
  readonly hecho = signal<string | null>(null);
  readonly errorAccion = signal<string | null>(null);
  readonly verificando = signal(false);
  readonly verificacion = signal<Verificacion | null>(null);
  readonly errorVerificacion = signal<string | null>(null);

  constructor() {
    this.cargar();
  }

  // La primera página (al entrar y al reintentar).
  cargar(): void {
    this.errorCarga.set(null);
    this.api.recientes(null).subscribe({
      next: (pagina) => {
        this.filas.set(pagina.filas);
        this.anterior.set(pagina.anterior);
      },
      error: (error: unknown) => {
        this.filas.set(null);
        this.anterior.set(null);
        this.errorCarga.set(textoDeError(error));
      },
    });
  }

  // Vuelve a la primera página. La tabla anterior se queda hasta que llega la
  // nueva, así que el botón no desaparece y el foco sigue en él; el aviso
  // dice qué ha cambiado (WCAG 2.2, 4.1.3 Status Messages).
  actualizar(): void {
    if (this.ocupado()) {
      return;
    }
    this.ocupado.set(true);
    this.hecho.set(null);
    this.errorAccion.set(null);
    this.api.recientes(null).subscribe({
      next: (pagina) => {
        this.ocupado.set(false);
        this.filas.set(pagina.filas);
        this.anterior.set(pagina.anterior);
        this.hecho.set(pagina.filas.length === 0 ? 'Auditoría actualizada: todavía no hay nada.'
          : `Auditoría actualizada: la fila más reciente es la nº ${pagina.filas[0].secuencia}.`);
      },
      error: (error: unknown) => {
        this.ocupado.set(false);
        this.errorAccion.set(textoDeError(error));
      },
    });
  }

  // Añade la página siguiente hacia el principio. El foco se queda en el
  // botón y el aviso dice cuántas han llegado, como en Denuncias. Con la
  // última página el botón desaparece: el foco pasa al aviso, que lo dice,
  // en vez de perderse en el <body> (WCAG 2.2, 2.4.3 Focus Order).
  cargarAnteriores(): void {
    const antes = this.anterior();
    if (antes === null || this.ocupado()) {
      return;
    }
    this.ocupado.set(true);
    this.hecho.set(null);
    this.errorAccion.set(null);
    this.api.recientes(antes).subscribe({
      next: (pagina) => {
        this.ocupado.set(false);
        this.filas.update((filas) => [...(filas ?? []), ...pagina.filas]);
        this.anterior.set(pagina.anterior);
        if (pagina.anterior === null) {
          this.hecho.set(`${textoCargadas(pagina.filas.length)} Es el principio de la auditoría.`);
          enfocarEncabezado(this.injector, '#auditoria-hecho');
        } else {
          this.hecho.set(textoCargadas(pagina.filas.length));
        }
      },
      error: (error: unknown) => {
        this.ocupado.set(false);
        this.errorAccion.set(textoDeError(error));
      },
    });
  }

  verificar(): void {
    if (this.verificando()) {
      return;
    }
    this.verificando.set(true);
    this.verificacion.set(null);
    this.errorVerificacion.set(null);
    this.api.verificar().subscribe({
      next: (resultado) => {
        this.verificando.set(false);
        this.verificacion.set(resultado);
      },
      error: (error: unknown) => {
        this.verificando.set(false);
        this.errorVerificacion.set(textoDeError(error));
      },
    });
  }
}
