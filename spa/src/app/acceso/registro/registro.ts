import { Component, Injector, inject, signal } from '@angular/core';
import { NonNullableFormBuilder, ReactiveFormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { Canario } from '../../marca/canario';
import { ApiPersonal } from '../../nucleo/api';
import { textoDeError } from '../../nucleo/errores';
import { enfocarEncabezado } from '../../nucleo/foco';

// Solicitud de acceso, "primero el email" (app/solicitudes.py): empresa y
// email. La API responde siempre lo mismo, exista o no la empresa o la
// cuenta, así que la página enseña un texto fijo suyo (el de la API va en
// minúscula, pensado para cualquier cliente): no distingue los casos ni
// pierde nada. El rol lo elige un admin al aprobar.
//
// Sin entradilla: el correo de confirmación lo anuncia el aviso al enviar, y
// la revisión del admin, la página de confirmación del email (acceso/
// verificacion), cada cosa cuando pasa.
// El remitente se nombra por su nombre visible (Canario), que es el mismo en
// todos los entornos; la dirección cambia entre desarrollo y producción. La
// carpeta de spam, porque es donde suele estar un primer correo que no llega.
const TEXTO_SOLICITADO = 'Si los datos son correctos, recibirá un correo de Canario en unos minutos. ' +
  'Si no le llega, mire en la carpeta de spam y, si tampoco está, vuelva a solicitarlo más tarde.';

@Component({
  selector: 'app-registro',
  imports: [Canario, ReactiveFormsModule, RouterLink],
  template: `
    <main class="acceso">
      <app-canario />
      <h1 tabindex="-1">Solicitar acceso</h1>
      @if (solicitado()) {
        <div class="tarjeta">
          <p role="status">{{ texto }}</p>
        </div>
        <p class="tarjeta-pie"><a routerLink="/entrar">Volver a la entrada</a></p>
      } @else {
        <form class="tarjeta" [formGroup]="formulario" (ngSubmit)="solicitar()" ngNativeValidate>
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
  readonly solicitado = signal(false);
  readonly texto = TEXTO_SOLICITADO;

  solicitar(): void {
    if (this.enviando()) {
      return;
    }
    this.enviando.set(true);
    this.error.set(null);
    const { empresa, email } = this.formulario.getRawValue();
    this.api.solicitarRegistro(empresa, email).subscribe({
      next: () => {
        this.solicitado.set(true);
        enfocarEncabezado(this.injector);
      },
      error: (error: unknown) => {
        this.enviando.set(false);
        this.error.set(textoDeError(error, { 422: 'Revise los datos: alguno no tiene un formato válido.' }));
      },
    });
  }
}
