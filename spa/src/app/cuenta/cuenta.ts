import { Component, Injector, inject, signal } from '@angular/core';
import { NonNullableFormBuilder, ReactiveFormsModule } from '@angular/forms';
import { ApiPersonal } from '../nucleo/api';
import { detalleDe, textoDeError } from '../nucleo/errores';
import { enfocarEncabezado } from '../nucleo/foco';
import { MostrarContrasena } from '../nucleo/mostrar-contrasena';

// Mi cuenta: cambiar la contraseña (app/personal.py, cambiar_contrasena). Pide
// la actual y un código TOTP, y cierra todas las demás sesiones y
// dispositivos de confianza de la cuenta: es la respuesta a una contraseña
// que puede conocer otra persona. Este navegador sigue dentro con la sesión
// nueva que ponen las cookies de la respuesta.
@Component({
  selector: 'app-cuenta',
  imports: [MostrarContrasena, ReactiveFormsModule],
  template: `
    <h1 tabindex="-1">Mi cuenta</h1>
    <h2>Cambiar la contraseña</h2>
    <p>Al cambiarla se cierran sus sesiones en otros navegadores y se retiran los demás dispositivos de confianza.</p>
    <form class="formulario" [formGroup]="formulario" (ngSubmit)="cambiar()" ngNativeValidate>
      <p class="campo">
        <label for="cuenta-actual">Contraseña actual</label>
        <span class="con-mostrar">
          <input #campoActual id="cuenta-actual" type="password" formControlName="contrasena_actual" required
                 autocomplete="current-password">
          <button class="mostrar" [appMostrarContrasena]="campoActual" nombre="Mostrar la contraseña actual"></button>
        </span>
      </p>
      <p class="campo">
        <label for="cuenta-nueva">Contraseña nueva</label>
        <span class="con-mostrar">
          <input #campoNueva id="cuenta-nueva" type="password" formControlName="contrasena_nueva" required
                 autocomplete="new-password" aria-describedby="cuenta-nueva-ayuda">
          <button class="mostrar" [appMostrarContrasena]="campoNueva" nombre="Mostrar la contraseña nueva"></button>
        </span>
        <span id="cuenta-nueva-ayuda" class="ayuda">Entre 12 y 128 caracteres. Una frase larga es más fácil de recordar.</span>
      </p>
      <p class="campo">
        <label for="cuenta-repetir">Repita la contraseña nueva</label>
        <span class="con-mostrar">
          <input #campoRepetir id="cuenta-repetir" type="password" formControlName="repetir" required
                 autocomplete="new-password">
          <button class="mostrar" [appMostrarContrasena]="campoRepetir" nombre="Mostrar la contraseña nueva repetida"></button>
        </span>
      </p>
      <p class="campo">
        <label for="cuenta-codigo">Código de autenticación</label>
        <input id="cuenta-codigo" formControlName="codigo_totp" required inputmode="numeric"
               pattern="[0-9]{6}" title="Las 6 cifras, sin espacios."
               autocomplete="one-time-code" aria-describedby="cuenta-codigo-ayuda">
        <span id="cuenta-codigo-ayuda" class="ayuda">Las 6 cifras que muestra su aplicación.</span>
      </p>
      @if (error(); as texto) {
        <p class="error" role="alert">{{ texto }}</p>
      }
      <button type="submit" [attr.aria-disabled]="enviando() || null">
        {{ enviando() ? 'Cambiando...' : 'Cambiar la contraseña' }}
      </button>
    </form>
    @if (hecho()) {
      <p class="aviso" id="cuenta-hecho" role="status" tabindex="-1">Contraseña cambiada. Se han cerrado sus otras sesiones y retirado los demás dispositivos de confianza.</p>
    }
  `,
})
export class Cuenta {
  private readonly api = inject(ApiPersonal);
  private readonly injector = inject(Injector);

  readonly formulario = inject(NonNullableFormBuilder).group({
    contrasena_actual: '',
    contrasena_nueva: '',
    repetir: '',
    codigo_totp: '',
  });
  readonly enviando = signal(false);
  readonly error = signal<string | null>(null);
  readonly hecho = signal(false);

  cambiar(): void {
    const { contrasena_actual, contrasena_nueva, repetir, codigo_totp } = this.formulario.getRawValue();
    if (this.enviando()) {
      return;
    }
    this.hecho.set(false);
    if (contrasena_nueva !== repetir) {
      this.error.set('Las dos contraseñas nuevas no coinciden.');
      return;
    }
    // Un envío cada vez: cada fallo cuenta en el bloqueo del dispositivo, y
    // un doble clic gastaría dos. La guarda de arriba descarta el segundo; el
    // botón lleva aria-disabled y no disabled, para no quitarle el foco
    // (acceso/entrar).
    this.enviando.set(true);
    this.error.set(null);
    this.api.cambiarContrasena({ contrasena_actual, contrasena_nueva, codigo_totp }).subscribe({
      next: () => {
        this.enviando.set(false);
        this.formulario.reset();
        this.hecho.set(true);
        enfocarEncabezado(this.injector, '#cuenta-hecho');
      },
      error: (error: unknown) => {
        this.enviando.set(false);
        // El código cambia cada 30 segundos y uno usado no vuelve a valer.
        this.formulario.controls.codigo_totp.reset();
        this.error.set(textoDeError(error, {
          // Sin WWW-Authenticate: es el 401 de las credenciales, no el de la
          // sesión, y no renueva (nucleo/renovacion.ts).
          401: 'La contraseña actual o el código no son correctos.',
          // La política de contraseñas la aplica la API (app/personal.py): su
          // texto es fijo y nunca lleva la contraseña.
          422: detalleDe(error) ?? 'La contraseña nueva no cumple la política.',
        }));
      },
    });
  }
}
