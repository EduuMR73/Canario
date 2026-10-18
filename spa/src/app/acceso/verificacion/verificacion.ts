import { Component, Injector, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ApiPersonal } from '../../nucleo/api';
import { textoDeError } from '../../nucleo/errores';
import { enfocarEncabezado } from '../../nucleo/foco';
import { consumirToken } from '../../nucleo/fragmento';

// Verificación del email de una solicitud de acceso, desde el enlace del
// correo: /registro/verificacion#<token> (app/solicitudes.py, verificar).
//
// Se envía al pulsar el botón, no al abrir la página: algunos filtros de
// correo abren los enlaces, y si ejecutan JavaScript gastarían un token de un
// solo uso sin que la persona hiciera nada.

type Estado = 'sin-enlace' | 'pendiente' | 'hecho';

@Component({
  selector: 'app-verificacion',
  imports: [RouterLink],
  template: `
    <main>
      <h1 tabindex="-1">Confirmar el email</h1>
      @switch (estado()) {
        @case ('sin-enlace') {
          <p>Para confirmar su email, abra el enlace del correo que le enviamos.</p>
          <p><a routerLink="/registro">Solicitar acceso</a></p>
        }
        @case ('pendiente') {
          <p>Pulse el botón para confirmar que este email es suyo.</p>
          @if (error(); as texto) {
            <p class="error" role="alert">{{ texto }}</p>
          }
          <button type="button" (click)="confirmar()" [disabled]="enviando()">
            {{ enviando() ? 'Confirmando...' : 'Confirmar mi email' }}
          </button>
        }
        @case ('hecho') {
          <p class="aviso" role="status">Email confirmado. Un admin de su empresa revisará la solicitud; si la aprueba, recibirá otro correo para activar la cuenta.</p>
        }
      }
    </main>
  `,
})
export class Verificacion {
  private readonly api = inject(ApiPersonal);
  private readonly injector = inject(Injector);
  private readonly token = consumirToken('/registro/verificacion');

  readonly estado = signal<Estado>(this.token === null ? 'sin-enlace' : 'pendiente');
  readonly enviando = signal(false);
  readonly error = signal<string | null>(null);

  confirmar(): void {
    if (this.token === null || this.enviando()) {
      return;
    }
    this.enviando.set(true);
    this.error.set(null);
    this.api.verificarRegistro(this.token).subscribe({
      next: () => {
        this.estado.set('hecho');
        enfocarEncabezado(this.injector);
      },
      error: (error: unknown) => {
        this.enviando.set(false);
        this.error.set(textoDeError(error, {
          401: 'El enlace no es válido o ha caducado. Puede solicitar el acceso de nuevo desde la entrada.',
        }));
      },
    });
  }
}
