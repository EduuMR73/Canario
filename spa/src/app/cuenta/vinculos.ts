import { HttpErrorResponse } from '@angular/common/http';
import { Location } from '@angular/common';
import { Component, Injector, computed, inject, signal } from '@angular/core';
import { NonNullableFormBuilder, ReactiveFormsModule } from '@angular/forms';
import { ActivatedRoute } from '@angular/router';
import { ApiExterno, NAVEGAR, PROVEEDORES, Proveedor, Resultado, resultadoDe, urlPermitida } from '../nucleo/api-externo';
import { TEXTO_INESPERADO, TEXTO_NO_DISPONIBLE, detalleDe, textoDeError } from '../nucleo/errores';
import { enfocarEncabezado } from '../nucleo/foco';
import { Sesion } from '../nucleo/sesion';

// Mi cuenta: las cuentas externas vinculadas (docs/threat-model.md, 6.19).
// Vincular y desvincular piden un código TOTP recién escrito: la sesión sola
// (un token robado) no basta. La API avisa por correo al titular y a quienes
// vigilan la cuenta (app/rutas_externo.py).
//
// /yo es la única fuente de lo que está vinculado (nucleo/sesion.ts): tras
// cada cambio se vuelve a pedir, y la página no lleva su propia copia.
//
// Vincular sale a Google y vuelve a /cuenta?vinculo=<resultado>. Con
// "pendiente", el ticket de la vuelta está en su cookie y esta página lo
// completa una sola vez. La URL se limpia con replaceState antes de nada: al
// recargar no se repite. Si aun así llega un 401 (otra pestaña, o el ticket
// ya gastado), se relee /yo antes de dar el error: el vínculo puede haberse
// guardado ya, y decir que falló sería falso.
//
// La vuelta no dice el proveedor: hoy solo existe la de Google
// (app/rutas_externo.py, DESTINOS). Con un segundo proveedor, el destino
// tendrá que llevarlo.

type Tipo = 'aviso' | 'error';

const PROVEEDOR_VUELTA: Proveedor = 'google';

const TEXTOS_VUELTA: Record<Resultado, string> = {
  cancelado: 'Ha cancelado la vinculación con Google: no se ha vinculado nada.',
  no_disponible: 'La vinculación con Google no está disponible ahora mismo. Inténtelo más tarde.',
  fallido: 'No se ha podido vincular la cuenta de Google. Vuelva a intentarlo.',
};

// La fecha del vínculo en la hora de quien mira. La API da un instante con
// zona (ISO 8601), así que aquí sí vale Date: no es un día sin hora como los
// de las denuncias (denuncias/textos.ts, fechaLegible). Si no se puede leer,
// se enseña tal cual en vez de inventar.
export function diaDe(iso: string): string {
  const fecha = new Date(iso);
  return Number.isNaN(fecha.getTime())
    ? iso
    : fecha.toLocaleDateString('es-ES', { day: '2-digit', month: '2-digit', year: 'numeric' });
}

@Component({
  selector: 'app-vinculos',
  imports: [ReactiveFormsModule],
  host: { '(window:pageshow)': 'alMostrar($event)' },
  template: `
    <h2>Entrar con una cuenta externa</h2>
    @if (resultado(); as r) {
      <p id="vinculos-resultado" tabindex="-1" [class]="r.tipo" [attr.role]="r.tipo === 'aviso' ? 'status' : 'alert'">{{ r.texto }}</p>
    }
    @if (errorLista(); as texto) {
      <p class="error" id="vinculos-lista">{{ texto }}</p>
    } @else if (proveedores(); as lista) {
      @if (lista.length === 0) {
        <p class="aviso">El acceso con cuentas externas no está configurado en este servidor: se entra con la contraseña y el código.</p>
      }
      @for (proveedor of lista; track proveedor) {
        <h3>{{ registro[proveedor].nombre }}</h3>
        @if (vinculoDe(proveedor); as vinculo) {
          <p>Vinculada el {{ dia(vinculo.creada) }}. Puede entrar con {{ registro[proveedor].nombre }} y su código desde un navegador de confianza.</p>
        } @else {
          <p>Sin vincular. Al vincularla podrá entrar con {{ registro[proveedor].nombre }} y su código, sin escribir la contraseña, desde un navegador de confianza.</p>
        }
        <p class="ayuda">Al vincularla o desvincularla le avisaremos por correo, y también a los admins y auditores de su empresa.</p>
        <form class="formulario" [formGroup]="formularios[proveedor]" (ngSubmit)="cambiar(proveedor)" ngNativeValidate>
          <p class="campo">
            <label [for]="'vinculos-codigo-' + proveedor">Código de autenticación</label>
            <input [id]="'vinculos-codigo-' + proveedor" formControlName="codigo_totp" required inputmode="numeric"
                   pattern="[0-9]{6}" title="Las 6 cifras, sin espacios."
                   autocomplete="one-time-code" [attr.aria-describedby]="'vinculos-codigo-ayuda-' + proveedor">
            <span [id]="'vinculos-codigo-ayuda-' + proveedor" class="ayuda">Las 6 cifras que muestra su aplicación.</span>
          </p>
          @if (vinculoDe(proveedor)) {
            <button type="submit" class="peligro" [attr.aria-disabled]="enviando() || null">
              {{ enviando() ? 'Desvinculando...' : 'Desvincular ' + registro[proveedor].nombre }}
            </button>
          } @else {
            <button type="submit" [attr.aria-disabled]="enviando() || null">
              {{ enviando() ? 'Abriendo ' + registro[proveedor].nombre + '...' : 'Vincular ' + registro[proveedor].nombre }}
            </button>
          }
        </form>
      }
    }
  `,
})
export class Vinculos {
  private readonly api = inject(ApiExterno);
  private readonly sesion = inject(Sesion);
  private readonly navegar = inject(NAVEGAR);
  private readonly injector = inject(Injector);
  private readonly fb = inject(NonNullableFormBuilder);

  readonly registro = PROVEEDORES;
  readonly dia = diaDe;
  readonly formularios = Object.fromEntries(
    Object.keys(PROVEEDORES).map((clave) => [clave, this.fb.group({ codigo_totp: '' })]));
  // null mientras se pide la lista.
  readonly proveedores = signal<Proveedor[] | null>(null);
  readonly errorLista = signal<string | null>(null);
  private readonly vinculos = computed(() => this.sesion.yo()?.vinculos ?? []);
  // Un cambio cada vez: cada uno gasta un código TOTP. aria-disabled y no
  // disabled, como en acceso/entrar.
  readonly enviando = signal(false);
  readonly resultado = signal<{ tipo: Tipo; texto: string } | null>(null);

  constructor() {
    const consulta = inject(ActivatedRoute).snapshot.queryParamMap;
    if (consulta.has('vinculo')) {
      const valor = consulta.get('vinculo');
      inject(Location).replaceState('/cuenta');
      if (valor === 'pendiente') {
        this.completar(PROVEEDOR_VUELTA);
      } else {
        const resultado = resultadoDe(valor);
        if (resultado !== null) {
          this.terminar(resultado === 'cancelado' ? 'aviso' : 'error', TEXTOS_VUELTA[resultado]);
        }
      }
    }
    // Aquí la lista sí se dice si falla: es la sección que la usa. Visible,
    // pero sin role="alert": no responde a nada que haya hecho la persona, y
    // anunciarlo al abrir la página interrumpiría el formulario de la
    // contraseña, que va antes.
    this.api.proveedores().subscribe({
      next: (lista) => this.proveedores.set(lista),
      error: (error: unknown) => this.errorLista.set(textoDeError(error)),
    });
  }

  vinculoDe(proveedor: Proveedor) {
    return this.vinculos().find((vinculo) => vinculo.proveedor === proveedor);
  }

  cambiar(proveedor: Proveedor): void {
    if (this.enviando()) {
      return;
    }
    const codigo = this.formularios[proveedor].getRawValue().codigo_totp;
    this.empezar();
    if (this.vinculoDe(proveedor)) {
      this.desvincular(proveedor, codigo);
    } else {
      this.vincular(proveedor, codigo);
    }
  }

  // Restaurada de la caché del navegador (bfcache) al volver desde Google sin
  // terminar: ningún cambio sigue en curso en esta página. $event llega como
  // Event; el de pageshow es un PageTransitionEvent.
  alMostrar(evento: Event): void {
    if ((evento as PageTransitionEvent).persisted) {
      this.enviando.set(false);
    }
  }

  private vincular(proveedor: Proveedor, codigo: string): void {
    const nombre = PROVEEDORES[proveedor].nombre;
    this.api.iniciarVinculo(proveedor, codigo).subscribe({
      next: (url) => {
        if (urlPermitida(proveedor, url)) {
          // enviando sigue en true hasta salir de la página.
          this.navegar(url);
          return;
        }
        this.terminar('error', TEXTO_INESPERADO);
      },
      error: (error: unknown) => this.terminar('error', textoDeError(error, {
        401: 'El código no es correcto.',
        404: `La vinculación con ${nombre} no está disponible.`,
        422: 'Revise el código: son 6 cifras.',
        // El código ya se gastó antes de pedir la URL al broker
        // (app/rutas_externo.py, iniciar_vinculo_google).
        503: `${TEXTO_NO_DISPONIBLE} Para volver a intentarlo, espere a un código nuevo.`,
      })),
    });
  }

  private desvincular(proveedor: Proveedor, codigo: string): void {
    const nombre = PROVEEDORES[proveedor].nombre;
    this.api.revocarVinculo(proveedor, codigo).subscribe({
      next: () => void this.releerYTerminar('aviso', `Cuenta de ${nombre} desvinculada. Le hemos avisado por correo.`),
      error: (error: unknown) => {
        if (error instanceof HttpErrorResponse && error.status === 404) {
          // Ya no estaba vinculada (otra pestaña): /yo lo pondrá al día.
          void this.releerYTerminar('error', `Su cuenta no tenía ${nombre} vinculado.`);
          return;
        }
        this.terminar('error', textoDeError(error, {
          401: 'El código no es correcto.',
          422: 'Revise el código: son 6 cifras.',
        }));
      },
    });
  }

  private completar(proveedor: Proveedor): void {
    const nombre = PROVEEDORES[proveedor].nombre;
    this.empezar();
    this.api.completarVinculo(proveedor).subscribe({
      next: () => void this.releerYTerminar('aviso', `Cuenta de ${nombre} vinculada. Le hemos avisado por correo.`),
      error: (error: unknown) => {
        if (error instanceof HttpErrorResponse && error.status === 401) {
          void this.comprobarTrasFallo(proveedor);
          return;
        }
        this.terminar('error', textoDeError(error, {
          // Un texto fijo por motivo (app/rutas_externo.py, MENSAJES_DUPLICADO).
          409: detalleDe(error) ?? `Esa cuenta de ${nombre} no se puede vincular.`,
        }));
      },
    });
  }

  // El 401 al completar: el ticket no vale (caducado, gastado o de otra
  // sesión). Si /yo ya tiene el vínculo, se guardó en un intento anterior.
  private async comprobarTrasFallo(proveedor: Proveedor): Promise<void> {
    const nombre = PROVEEDORES[proveedor].nombre;
    try {
      const yo = await this.sesion.cargar();
      if (yo.vinculos.some((vinculo) => vinculo.proveedor === proveedor)) {
        this.terminar('aviso', `Su cuenta de ${nombre} está vinculada.`);
        return;
      }
    } catch (error: unknown) {
      this.terminar('error', textoDeError(error));
      return;
    }
    this.terminar('error', `No se ha podido completar la vinculación: el acceso con ${nombre} ha caducado. ` +
      'Vuelva a vincularla.');
  }

  private async releerYTerminar(tipo: Tipo, texto: string): Promise<void> {
    try {
      await this.sesion.cargar();
    } catch {
      // El cambio está hecho, pero la lista de arriba es la de antes: se dice.
      this.terminar(tipo, `${texto} No se ha podido actualizar la página: recárguela para ver el estado.`);
      return;
    }
    this.terminar(tipo, texto);
  }

  private empezar(): void {
    this.enviando.set(true);
    this.resultado.set(null);
  }

  private terminar(tipo: Tipo, texto: string): void {
    this.enviando.set(false);
    // El código cambia cada 30 segundos y uno usado no vuelve a valer.
    Object.values(this.formularios).forEach((formulario) => formulario.reset());
    this.resultado.set({ tipo, texto });
    enfocarEncabezado(this.injector, '#vinculos-resultado');
  }
}
