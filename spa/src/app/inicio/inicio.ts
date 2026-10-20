import { Component, computed, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { MENU, menuDe } from '../nucleo/permisos';
import { Sesion } from '../nucleo/sesion';

// Página de inicio con sesión: adónde puede ir cada rol. Se pinta dentro del
// armazón (armazon/armazon.ts), que ya tiene la cuenta cargada
// (nucleo/permisos.ts) y enseña en la barra el email y el rol: aquí no se
// repiten. Lo que se pinta es solo para mostrar: los permisos los comprueba
// la API en cada petición.
//
// El aviso de una invitación abierta sí va aquí, el primero: es lo que avisa
// al titular de que alguien ha reinvitado su cuenta.
//
// Los accesos salen del mismo menú que la barra (menuDe), sin el propio
// inicio: una sola lista de páginas y roles. Sin resúmenes de lo pendiente:
// la API no da recuentos, y contarlo aquí obligaría a pedir los listados
// enteros, con sus emails, en una página que no los enseña.
//
// Quien instruye (los roles con acceso a las denuncias) ve además los plazos
// de la Ley 2/2023 que le afectan: es el contenido propio de la página, y el
// de la supresión lo aplica el sistema solo (6.14), así que tiene que
// saberlo. El acuse de recibo no es tarea suya: el canal lo da al recibir la
// denuncia (art. 9.2.c, la respuesta con el código y la fecha).
//
// El título dice a qué se aplican los plazos y no solo el número de la ley,
// que no dice nada a quien no la conoce; debajo, la ley con un nombre corto
// (el oficial, con la fecha y "de lucha contra la corrupción", está en el
// modelo de amenazas).
//
// Al final, para todo el personal, el enlace del canal de denuncias de la
// empresa: la ley obliga a la empresa a publicarlo (art. 25), y si lo viera
// solo el admin, una sola persona decidiría si se conoce. Va el último
// porque es un dato de consulta; los accesos son lo de cada día. Lo da la
// API en /yo (la SPA no conoce el origen del sitio del denunciante).
// "Abrir el formulario" dice en su texto visible que abre una pestaña nueva
// (WCAG, G201): quien ve la pantalla también tiene que saberlo.
type Ruta = (typeof MENU)[keyof typeof MENU]['ruta'];

// Una descripción por página, con la ruta como clave: si alguien añade una
// página al menú sin su descripción, no compila. Una línea cada una: el
// título ya dice qué es.
const DESCRIPCIONES: Record<Exclude<Ruta, '/inicio'>, string> = {
  '/denuncias': 'Su estado y los mensajes con el denunciante.',
  '/cuentas': 'Invitar, repetir una invitación o dar de baja.',
  '/solicitudes': 'Aprobar o rechazar las peticiones de acceso.',
  '/auditoria': 'Quién hizo qué y si el registro está intacto.',
  '/cuenta': 'Cambiar su contraseña.',
};

@Component({
  selector: 'app-inicio',
  imports: [RouterLink],
  template: `
    <h1 tabindex="-1">Inicio</h1>
    @if (sesion.yo(); as yo) {
      @if (yo.invitacion_pendiente) {
        <p class="error" role="alert">Hay una invitación abierta para su cuenta. Si no la ha pedido usted, avise a un admin de su empresa para que la anule.</p>
      }
      <ul class="accesos">
        @for (acceso of accesos(); track acceso.ruta) {
          <li>
            <a [routerLink]="acceso.ruta">{{ acceso.texto }}</a>
            <p>{{ acceso.descripcion }}</p>
          </li>
        }
      </ul>
      @if (instruye()) {
        <section class="plazos" aria-labelledby="inicio-plazos">
          <h2 id="inicio-plazos">Plazos legales de cada denuncia</h2>
          <p class="ayuda">Ley 2/2023, de protección de las personas que informen sobre infracciones normativas.</p>
          <ul>
            <li><strong>Respuesta:</strong> como máximo tres meses desde la recepción, ampliable hasta tres meses más si el caso es especialmente complejo (art. 9.2.d).</li>
            <li><strong>Supresión:</strong> una denuncia que sigue en "Nueva" o "Inadmitida" a los tres meses de su recepción se suprime (art. 32.4). Para conservarla hay que iniciar la investigación.</li>
          </ul>
          <p class="ayuda">El acuse de recibo lo da el canal al recibir la denuncia (art. 9.2.c).</p>
        </section>
      }
      <section class="canal" aria-labelledby="inicio-canal">
        <h2 id="inicio-canal">Canal de denuncias de su empresa</h2>
        <p class="ayuda">La empresa debe publicar este enlace en la página de inicio de su web (art. 25 de la Ley 2/2023).</p>
        <p><code class="enlace">{{ yo.enlace_canal }}</code></p>
        <p class="acciones">
          <button type="button" class="secundario" (click)="copiar(yo.enlace_canal)">Copiar el enlace</button>
        </p>
        <p role="status">{{ copiado() }}</p>
        <p class="ayuda">Lo que envíe desde ahí llega como una denuncia real de su empresa.</p>
        <p><a [href]="yo.enlace_canal" target="_blank" rel="noopener noreferrer">Abrir el formulario (se abre en una pestaña nueva)</a></p>
      </section>
    }
  `,
})
export class Inicio {
  protected readonly sesion = inject(Sesion);

  // Derivado de la cuenta, no guardado aparte: cambia solo si cambia ella.
  readonly accesos = computed(() => {
    const yo = this.sesion.yo();
    if (yo === null) {
      return [];
    }
    return menuDe(yo.rol)
      .filter((entrada) => entrada.ruta !== MENU.inicio.ruta)
      .map((entrada) => ({ ...entrada, descripcion: DESCRIPCIONES[entrada.ruta as Exclude<Ruta, '/inicio'>] }));
  });

  // Los mismos roles que la entrada de las denuncias del menú: si cambian
  // allí, cambian aquí.
  readonly instruye = computed(() => this.accesos().some((acceso) => acceso.ruta === MENU.denuncias.ruta));

  // Lo lee el <p role="status"> de la tarjeta, que está siempre en la
  // página aunque vacío: una región viva que se crea a la vez que su texto
  // puede no anunciarse (MDN, ARIA live regions). Solo cambia el texto.
  readonly copiado = signal('');

  // Sin "bórrelo del portapapeles", a diferencia del enlace de activación
  // (cuentas.ts): este enlace no es secreto, es el que se publica.
  copiar(enlace: string): void {
    navigator.clipboard.writeText(enlace).then(
      () => this.copiado.set('Copiado.'),
      () => this.copiado.set('No se ha podido copiar: selecciónelo y cópielo a mano.'),
    );
  }
}
