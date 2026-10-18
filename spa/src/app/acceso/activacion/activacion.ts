import { Component, Injector, computed, inject, signal } from '@angular/core';
import { NonNullableFormBuilder, ReactiveFormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ActivacionPendiente, ApiPersonal } from '../../nucleo/api';
import { detalleDe, textoDeError } from '../../nucleo/errores';
import { enfocarEncabezado } from '../../nucleo/foco';
import { consumirToken } from '../../nucleo/fragmento';
import { qrDe } from '../../nucleo/qr';

// Activación de una cuenta invitada (app/personal.py, activar y
// confirmar_activacion), desde el enlace del correo: /activacion#<token>.
// Dos pasos con el mismo token: la contraseña, que devuelve el secreto TOTP,
// y el primer código, que activa la cuenta y deja la cookie del dispositivo
// de confianza. El token y el secreto solo viven en esta página, en memoria.

type Paso = 'sin-enlace' | 'contrasena' | 'codigo' | 'hecho';

const TEXTO_ENLACE_NO_VALIDO = 'El enlace no es válido o ha caducado. Pida a un admin de su empresa que le invite de nuevo.';

@Component({
  selector: 'app-activacion',
  imports: [ReactiveFormsModule, RouterLink],
  template: `
    <main>
      <h1 tabindex="-1">Activar la cuenta</h1>
      @switch (paso()) {
        @case ('sin-enlace') {
          <p>Para activar su cuenta, abra el enlace del correo de invitación.</p>
          <p>Si ha recargado la página, vuelva a abrir el enlace: sigue valiendo hasta que active la cuenta.</p>
        }
        @case ('contrasena') {
          <h2 class="paso" tabindex="-1">Paso 1 de 2: elija su contraseña</h2>
          <form [formGroup]="contrasenas" (ngSubmit)="fijarContrasena()" ngNativeValidate>
            <p class="campo">
              <label for="activacion-contrasena">Contraseña nueva</label>
              <input id="activacion-contrasena" type="password" formControlName="contrasena" required
                     autocomplete="new-password" aria-describedby="activacion-contrasena-ayuda">
              <span id="activacion-contrasena-ayuda" class="ayuda">Entre 12 y 128 caracteres. Una frase larga es más fácil de recordar.</span>
            </p>
            <p class="campo">
              <label for="activacion-repetir">Repita la contraseña</label>
              <input id="activacion-repetir" type="password" formControlName="repetir" required
                     autocomplete="new-password">
            </p>
            @if (error(); as texto) {
              <p class="error" role="alert">{{ texto }}</p>
            }
            <button type="submit" [attr.aria-disabled]="enviando() || null">{{ enviando() ? 'Guardando...' : 'Continuar' }}</button>
          </form>
        }
        @case ('codigo') {
          <h2 class="paso" tabindex="-1">Paso 2 de 2: configure la aplicación de autenticación</h2>
          <p>Escanee este código con su aplicación de autenticación (por ejemplo, la de su móvil).</p>
          @if (qr(); as codigo) {
            <svg class="qr" role="img" aria-label="Código QR para la aplicación de autenticación"
                 [attr.viewBox]="'0 0 ' + codigo.lado + ' ' + codigo.lado" shape-rendering="crispEdges">
              <rect width="100%" height="100%" fill="#ffffff" />
              <path [attr.d]="codigo.ruta" fill="#000000" />
            </svg>
          }
          <p>Si no puede escanearlo, escriba esta clave en la aplicación:</p>
          <p><code class="secreto" id="activacion-secreto">{{ secretoAgrupado() }}</code></p>
          <form [formGroup]="confirmacion" (ngSubmit)="confirmar()" ngNativeValidate>
            <p class="campo">
              <label for="activacion-codigo">Código de la aplicación de autenticación</label>
              <input id="activacion-codigo" formControlName="codigo_totp" required inputmode="numeric"
                     autocomplete="one-time-code" aria-describedby="activacion-codigo-ayuda">
              <span id="activacion-codigo-ayuda" class="ayuda">Las 6 cifras que muestra ahora la aplicación.</span>
            </p>
            @if (error(); as texto) {
              <p class="error" role="alert">{{ texto }}</p>
            }
            <button type="submit" [attr.aria-disabled]="enviando() || null">
              {{ enviando() ? 'Activando...' : 'Activar la cuenta' }}
            </button>
          </form>
        }
        @case ('hecho') {
          <h2 class="paso" tabindex="-1">Cuenta activada</h2>
          <p>Este navegador queda como dispositivo de confianza durante 90 días.</p>
          <p><a routerLink="/entrar">Entrar</a></p>
        }
      }
    </main>
  `,
})
export class Activacion {
  private readonly api = inject(ApiPersonal);
  private readonly injector = inject(Injector);
  private readonly formularios = inject(NonNullableFormBuilder);
  private readonly token = consumirToken('/activacion');

  readonly paso = signal<Paso>(this.token === null ? 'sin-enlace' : 'contrasena');
  // Un envío cada vez: un código TOTP vale una sola vez. Los botones llevan
  // aria-disabled y no disabled, para no quitarles el foco (acceso/entrar):
  // la guarda de cada paso es la que impide el segundo envío.
  readonly enviando = signal(false);
  readonly error = signal<string | null>(null);
  private readonly pendiente = signal<ActivacionPendiente | null>(null);
  readonly qr = computed(() => {
    const pendiente = this.pendiente();
    return pendiente === null ? null : qrDe(pendiente.uri_totp);
  });
  // En grupos de 4 para copiarla a mano sin perderse.
  readonly secretoAgrupado = computed(() => this.pendiente()?.secreto_totp.match(/.{1,4}/g)?.join(' ') ?? '');

  readonly contrasenas = this.formularios.group({ contrasena: '', repetir: '' });
  readonly confirmacion = this.formularios.group({ codigo_totp: '' });

  fijarContrasena(): void {
    const { contrasena, repetir } = this.contrasenas.getRawValue();
    if (this.token === null || this.enviando()) {
      return;
    }
    if (contrasena !== repetir) {
      this.error.set('Las dos contraseñas no coinciden.');
      return;
    }
    this.empezar();
    this.api.activar(this.token, contrasena).subscribe({
      next: (pendiente) => {
        this.pendiente.set(pendiente);
        this.contrasenas.reset();
        this.irA('codigo');
      },
      error: (error: unknown) => this.fallar(error, {
        401: TEXTO_ENLACE_NO_VALIDO,
        // La política de contraseñas la aplica la API (app/personal.py): su
        // texto es fijo y nunca lleva la contraseña.
        422: detalleDe(error) ?? 'La contraseña no cumple la política.',
      }),
    });
  }

  confirmar(): void {
    if (this.token === null || this.enviando()) {
      return;
    }
    this.empezar();
    this.api.confirmarActivacion(this.token, this.confirmacion.getRawValue().codigo_totp).subscribe({
      next: () => {
        // El secreto ya está en la aplicación: fuera de la página.
        this.pendiente.set(null);
        this.irA('hecho');
      },
      error: (error: unknown) => {
        this.confirmacion.reset();
        this.fallar(error, {
          401: TEXTO_ENLACE_NO_VALIDO,
          422: 'El código no es correcto. Espere a que la aplicación muestre uno nuevo y escríbalo.',
        });
      },
    });
  }

  private empezar(): void {
    this.enviando.set(true);
    this.error.set(null);
  }

  private fallar(error: unknown, propios: Record<number, string>): void {
    this.enviando.set(false);
    this.error.set(textoDeError(error, propios));
  }

  private irA(paso: Paso): void {
    this.enviando.set(false);
    this.paso.set(paso);
    enfocarEncabezado(this.injector, 'main h2.paso');
  }
}
