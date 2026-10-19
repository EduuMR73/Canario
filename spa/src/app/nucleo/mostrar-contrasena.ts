import { Component, DestroyRef, afterNextRender, inject, input, signal } from '@angular/core';

// El botón "Mostrar la contraseña" de un campo: escribir 12 caracteres o más
// a ciegas es fácil de equivocar (NIST SP 800-63B-4, 3.1.1.2: el verificador
// SHOULD ofrecer mostrar la contraseña en vez de puntos). Va en el mismo <button> que lo
// usa: <button class="mostrar" [appMostrarContrasena]="campo" nombre="...">,
// con #campo en el <input>.
//
// - type="button" lo pone aquí el propio componente, no quien lo usa: uno de
//   tipo submit enviaría el formulario, y en el login eso gasta un intento y
//   el código TOTP.
// - El nombre accesible no cambia al pulsarlo; el estado lo dice aria-pressed
//   (WAI-ARIA APG, patrón Button: o cambia el nombre o cambia el estado,
//   nunca las dos cosas). Cada campo lleva el suyo, para distinguirlos en la
//   lista de botones de un lector de pantalla.
// - Al enviar el formulario, el campo vuelve a type="password" antes que
//   nada (el oyente va en la fase de captura): el gestor de contraseñas y el
//   autocompletado del navegador miran el formulario al enviarlo, y un campo
//   de texto podría acabar guardado en claro en el historial de lo escrito.
//   Hay un límite: lo que hace Chrome por dentro no se puede ver desde una
//   prueba; tests/security/verificar_spa.py comprueba el tipo tras enviar.
// - Un botón sin formulario no podría volver a ocultar nada: falla al
//   pintarse, con un error en la consola, en vez de seguir sin avisar.
@Component({
  selector: 'button[appMostrarContrasena]',
  host: {
    type: 'button',
    '[attr.aria-controls]': 'campo().id',
    '[attr.aria-pressed]': 'visible()',
    '(click)': 'alternar()',
  },
  template: `
    <svg class="mostrar-ojo" aria-hidden="true" focusable="false" width="20" height="20" viewBox="0 0 20 20">
      <path d="M1.5 10 Q10 2.5 18.5 10 Q10 17.5 1.5 10 Z" />
      <circle cx="10" cy="10" r="2.75" />
      @if (visible()) {
        <path d="M3.5 16.5 L16.5 3.5" />
      }
    </svg>
    <span class="visualmente-oculto">{{ nombre() }}</span>
  `,
})
export class MostrarContrasena {
  readonly campo = input.required<HTMLInputElement>({ alias: 'appMostrarContrasena' });
  readonly nombre = input.required<string>();
  readonly visible = signal(false);

  constructor() {
    const destruccion = inject(DestroyRef);
    afterNextRender(() => {
      const formulario = this.campo().form;
      if (formulario === null) {
        throw new Error(`El campo ${this.campo().id} no está en un formulario: su contraseña no se ocultaría al enviarlo.`);
      }
      const ocultar = () => this.poner(false);
      formulario.addEventListener('submit', ocultar, { capture: true });
      destruccion.onDestroy(() => formulario.removeEventListener('submit', ocultar, { capture: true }));
    });
  }

  alternar(): void {
    this.poner(!this.visible());
  }

  private poner(visible: boolean): void {
    this.visible.set(visible);
    this.campo().type = visible ? 'text' : 'password';
  }
}
