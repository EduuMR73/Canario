import { Component, inject, signal } from '@angular/core';
import { NonNullableFormBuilder, ReactiveFormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { Canario } from '../../marca/canario';
import { ApiExterno } from '../../nucleo/api-externo';
import { textoDeError } from '../../nucleo/errores';
import { Sesion } from '../../nucleo/sesion';

// Segundo paso del acceso con Google: /entrar/codigo, adonde lleva la vuelta
// cuando Google ha ido bien (app/rutas_externo.py, DESTINOS). El ticket de la
// vuelta está en una cookie __Host- HttpOnly que esta página no ve; aquí solo
// se escribe el código TOTP (docs/threat-model.md, 6.19: Google es el primer
// factor y el código, el segundo).
//
// La vuelta lleva aquí aunque la cuenta de Google no esté vinculada a
// ninguna cuenta de Canario: la API no lo dice hasta este paso, y entonces da
// el mismo 401 que un código malo o un ticket caducado, para no revelar qué
// cuentas de Google están vinculadas. Por eso el texto lo explica de entrada.
//
// Un código que falla no gasta el ticket: se puede repetir mientras viva
// (cinco minutos). Un envío cada vez y aria-disabled, como en acceso/entrar.
@Component({
  selector: 'app-codigo',
  imports: [Canario, ReactiveFormsModule, RouterLink],
  template: `
    <main class="acceso">
      <app-canario />
      <h1 tabindex="-1">Entrar con Google</h1>
      <form class="tarjeta" [formGroup]="formulario" (ngSubmit)="entrar()" ngNativeValidate>
        <p>Para terminar de entrar, escriba el código de su aplicación de autenticación.</p>
        <p class="ayuda">Si su cuenta de Google no está vinculada a su cuenta de Canario, entre con su contraseña y vincúlela en Mi cuenta.</p>
        <p class="campo">
          <label for="codigo-codigo">Código de autenticación</label>
          <input id="codigo-codigo" formControlName="codigo_totp" required inputmode="numeric"
                 pattern="[0-9]{6}" title="Las 6 cifras, sin espacios."
                 autocomplete="one-time-code" aria-describedby="codigo-codigo-ayuda">
          <span id="codigo-codigo-ayuda" class="ayuda">Las 6 cifras que muestra su aplicación.</span>
        </p>
        @if (error(); as texto) {
          <p class="error" role="alert">{{ texto }}</p>
        }
        <button type="submit" class="ancho-completo" [attr.aria-disabled]="enviando() || null">{{ enviando() ? 'Entrando...' : 'Entrar' }}</button>
      </form>
      <p class="tarjeta-pie"><a routerLink="/entrar">Volver a empezar</a></p>
    </main>
  `,
})
export class Codigo {
  private readonly api = inject(ApiExterno);
  private readonly router = inject(Router);
  private readonly sesion = inject(Sesion);

  readonly formulario = inject(NonNullableFormBuilder).group({ codigo_totp: '' });
  readonly enviando = signal(false);
  readonly error = signal<string | null>(null);

  entrar(): void {
    if (this.enviando()) {
      return;
    }
    this.enviando.set(true);
    this.error.set(null);
    this.api.entrar(this.formulario.getRawValue().codigo_totp).subscribe({
      // Como en acceso/entrar: enviando sigue en true hasta salir. Con
      // replaceUrl, "atrás" desde /inicio no vuelve a un paso que ya no vale.
      next: () => {
        this.sesion.olvidar();
        void this.router.navigateByUrl('/inicio', { replaceUrl: true });
      },
      error: (error: unknown) => {
        this.enviando.set(false);
        this.formulario.controls.codigo_totp.reset();
        this.error.set(textoDeError(error, {
          // Uno solo para el código malo, el ticket caducado o gastado y la
          // cuenta sin vincular: es el mismo 401 de la API.
          401: 'El código no es válido o el acceso con Google ha caducado. Si ha caducado, vuelva a empezar.',
          422: 'Revise el código: son 6 cifras.',
        }));
      },
    });
  }
}
