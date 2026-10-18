import { Component, inject } from '@angular/core';
import { nombreRol } from '../nucleo/roles';
import { Sesion } from '../nucleo/sesion';

// Página de inicio con sesión: quién es y con qué rol. Se pinta dentro del
// armazón (armazon/armazon.ts), que ya tiene la cuenta cargada
// (nucleo/permisos.ts). Lo que se pinta es solo para mostrar: los permisos los
// comprueba la API en cada petición.
@Component({
  selector: 'app-inicio',
  template: `
    <h1 tabindex="-1">Inicio</h1>
    @if (sesion.yo(); as yo) {
      @if (yo.invitacion_pendiente) {
        <p class="error" role="alert">Hay una invitación abierta para su cuenta. Si no la ha pedido usted, avise a un admin de su empresa para que la anule.</p>
      }
      <dl class="cuenta">
        <dt>Email</dt>
        <dd>{{ yo.email }}</dd>
        <dt>Rol</dt>
        <dd>{{ nombreRol(yo.rol) }}</dd>
      </dl>
    }
  `,
})
export class Inicio {
  protected readonly sesion = inject(Sesion);
  readonly nombreRol = nombreRol;
}
