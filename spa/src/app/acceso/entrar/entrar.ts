import { Component, inject, signal } from '@angular/core';
import { NonNullableFormBuilder, ReactiveFormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { ApiPersonal } from '../../nucleo/api';
import { textoDeError } from '../../nucleo/errores';
import { Sesion } from '../../nucleo/sesion';

// Login del personal: empresa, email, contraseña y código TOTP en una sola
// petición (app/personal.py, iniciar_sesion). Cualquier fallo da el mismo
// 401 y aquí el mismo texto, sin decir qué dato falló.
//
// ngNativeValidate deja la validación al navegador (required, type="email"):
// el formulario no se envía incompleto y el aviso es el nativo, accesible.
// Un envío cada vez: cada intento cuenta en el bloqueo de la cuenta y gasta
// el código TOTP, y un doble clic gastaría dos. La guarda de entrar() descarta
// el segundo. Mientras se envía, el botón lleva aria-disabled y no disabled: a
// un botón disabled Chromium le quita el foco, y tras un fallo quien usa el
// teclado no sabría dónde está (WCAG 2.2, 2.4.3).
@Component({
  selector: 'app-entrar',
  imports: [ReactiveFormsModule, RouterLink],
  template: `
    <main>
      <h1 tabindex="-1">Entrar</h1>
      <form [formGroup]="formulario" (ngSubmit)="entrar()" ngNativeValidate>
        <p class="campo">
          <label for="entrar-empresa">Empresa</label>
          <input id="entrar-empresa" formControlName="empresa" required autocomplete="organization"
                 autocapitalize="none" spellcheck="false" aria-describedby="entrar-empresa-ayuda">
          <span id="entrar-empresa-ayuda" class="ayuda">El identificador de su empresa en Canario.</span>
        </p>
        <p class="campo">
          <label for="entrar-email">Email</label>
          <input id="entrar-email" type="email" formControlName="email" required autocomplete="username">
        </p>
        <p class="campo">
          <label for="entrar-contrasena">Contraseña</label>
          <input id="entrar-contrasena" type="password" formControlName="contrasena" required
                 autocomplete="current-password">
        </p>
        <p class="campo">
          <label for="entrar-codigo">Código de la aplicación de autenticación</label>
          <input id="entrar-codigo" formControlName="codigo_totp" required inputmode="numeric"
                 autocomplete="one-time-code" aria-describedby="entrar-codigo-ayuda">
          <span id="entrar-codigo-ayuda" class="ayuda">Las 6 cifras que muestra ahora la aplicación.</span>
        </p>
        @if (error(); as texto) {
          <p class="error" role="alert">{{ texto }}</p>
        }
        <button type="submit" [attr.aria-disabled]="enviando() || null">{{ enviando() ? 'Entrando...' : 'Entrar' }}</button>
      </form>
      <p>¿No tiene cuenta? <a routerLink="/registro">Solicitar acceso</a></p>
    </main>
  `,
})
export class Entrar {
  private readonly api = inject(ApiPersonal);
  private readonly router = inject(Router);
  private readonly sesion = inject(Sesion);

  readonly formulario = inject(NonNullableFormBuilder).group({
    empresa: '',
    email: '',
    contrasena: '',
    codigo_totp: '',
  });
  readonly enviando = signal(false);
  readonly error = signal<string | null>(null);

  entrar(): void {
    if (this.enviando()) {
      return;
    }
    this.enviando.set(true);
    this.error.set(null);
    this.api.iniciarSesion(this.formulario.getRawValue()).subscribe({
      // enviando sigue en true hasta salir de la página: nada que repetir.
      // La cuenta de una sesión anterior en esta pestaña ya no es la de esta:
      // se olvida y el armazón pide /yo de nuevo (nucleo/permisos.ts).
      next: () => {
        this.sesion.olvidar();
        void this.router.navigateByUrl('/inicio');
      },
      error: (error: unknown) => {
        this.enviando.set(false);
        // El código cambia cada 30 segundos y uno usado no vuelve a valer.
        this.formulario.controls.codigo_totp.reset();
        this.error.set(textoDeError(error, {
          401: 'No se ha podido entrar. Revise la empresa, el email, la contraseña y el código.',
          422: 'Revise los datos: alguno no tiene un formato válido.',
        }));
      },
    });
  }
}
