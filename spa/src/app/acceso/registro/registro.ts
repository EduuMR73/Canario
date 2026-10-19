import { Component, Injector, inject, signal } from '@angular/core';
import { NonNullableFormBuilder, ReactiveFormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { Canario } from '../../marca/canario';
import { ApiPersonal } from '../../nucleo/api';
import { textoDeError } from '../../nucleo/errores';
import { enfocarEncabezado } from '../../nucleo/foco';

// Solicitud de acceso, "primero el email" (app/solicitudes.py): empresa y
// email. La API responde siempre lo mismo, exista o no la empresa o la
// cuenta, y aquí se muestra su mensaje tal cual: la página tampoco puede
// distinguir los casos. El rol lo elige un admin al aprobar.
@Component({
  selector: 'app-registro',
  imports: [Canario, ReactiveFormsModule, RouterLink],
  template: `
    <main class="acceso">
      <app-canario />
      <h1 tabindex="-1">Solicitar acceso</h1>
      @if (respuesta(); as mensaje) {
        <div class="tarjeta">
          <p role="status">{{ mensaje }}</p>
        </div>
        <p class="tarjeta-pie"><a routerLink="/entrar">Volver a la entrada</a></p>
      } @else {
        <form class="tarjeta" [formGroup]="formulario" (ngSubmit)="solicitar()" ngNativeValidate>
          <p>Le enviaremos un correo para confirmar que el email es suyo. Después, un admin de su empresa revisará la solicitud.</p>
          <p class="campo">
            <label for="registro-empresa">Empresa</label>
            <input id="registro-empresa" formControlName="empresa" required autocomplete="organization"
                   autocapitalize="none" spellcheck="false" aria-describedby="registro-empresa-ayuda">
            <span id="registro-empresa-ayuda" class="ayuda">El identificador de su empresa en Canario.</span>
          </p>
          <p class="campo">
            <label for="registro-email">Email</label>
            <input id="registro-email" type="email" formControlName="email" required autocomplete="email">
          </p>
          @if (error(); as texto) {
            <p class="error" role="alert">{{ texto }}</p>
          }
          <button type="submit" class="ancho-completo" [attr.aria-disabled]="enviando() || null">
            {{ enviando() ? 'Enviando...' : 'Solicitar acceso' }}
          </button>
        </form>
        <p class="tarjeta-pie">¿Ya tiene cuenta? <a routerLink="/entrar">Entrar</a></p>
      }
    </main>
  `,
})
export class Registro {
  private readonly api = inject(ApiPersonal);
  private readonly injector = inject(Injector);

  readonly formulario = inject(NonNullableFormBuilder).group({ empresa: '', email: '' });
  // Un envío cada vez. El botón lleva aria-disabled y no disabled, para no
  // quitarle el foco (acceso/entrar): la guarda de solicitar() es la barrera.
  readonly enviando = signal(false);
  readonly error = signal<string | null>(null);
  readonly respuesta = signal<string | null>(null);

  solicitar(): void {
    if (this.enviando()) {
      return;
    }
    this.enviando.set(true);
    this.error.set(null);
    const { empresa, email } = this.formulario.getRawValue();
    this.api.solicitarRegistro(empresa, email).subscribe({
      next: (respuesta) => {
        this.respuesta.set(respuesta.mensaje);
        enfocarEncabezado(this.injector);
      },
      error: (error: unknown) => {
        this.enviando.set(false);
        this.error.set(textoDeError(error, { 422: 'Revise los datos: alguno no tiene un formato válido.' }));
      },
    });
  }
}
