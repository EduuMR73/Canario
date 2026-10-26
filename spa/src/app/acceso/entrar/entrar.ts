import { Location } from '@angular/common';
import { Component, Injector, inject, signal } from '@angular/core';
import { NonNullableFormBuilder, ReactiveFormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { Canario } from '../../marca/canario';
import { Google } from '../../marca/google';
import { ApiPersonal } from '../../nucleo/api';
import { ApiExterno, NAVEGAR, PROVEEDORES, Proveedor, Resultado, resultadoDe, urlPermitida } from '../../nucleo/api-externo';
import { Caducidad } from '../../nucleo/caducidad';
import { TEXTO_INESPERADO, textoDeError } from '../../nucleo/errores';
import { enfocarEncabezado } from '../../nucleo/foco';
import { MostrarContrasena } from '../../nucleo/mostrar-contrasena';
import { Sesion } from '../../nucleo/sesion';

// Lo que dice la vuelta del proveedor en /entrar?externo=<resultado>
// (app/rutas_externo.py). Cancelar es una decisión de la persona y va como
// aviso; los otros dos son fallos.
const TEXTOS_VUELTA: Record<Resultado, string> = {
  cancelado: 'Ha cancelado el acceso con Google. Puede entrar con su contraseña o volver a intentarlo.',
  no_disponible: 'El acceso con Google no está disponible ahora mismo. Entre con su contraseña o inténtelo más tarde.',
  fallido: 'No se ha podido completar el acceso con Google. Vuelva a intentarlo o entre con su contraseña.',
};

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
//
// Entrar con Google (docs/threat-model.md, 6.19): solo se pinta el botón de
// los proveedores que anuncia la API y la SPA conoce (nucleo/api-externo.ts).
// Pide solo la empresa, porque Google nunca crea la confianza: hace falta un
// dispositivo de confianza vigente de esa empresa en este navegador, y la
// API responde 409 si no lo hay. Es type="button" y va después de "Entrar":
// Enter en un campo envía el formulario con su primer botón de envío (envío
// implícito), y así nunca lleva a Google por sorpresa. Cuando se vuelve con
// "atrás" desde Google, el navegador puede restaurar la página de su caché
// (bfcache) con el botón todavía ocupado: pageshow con persisted lo libera.
//
// Si la sesión se acaba de cerrar sola (inactividad, las 8 horas o un 401
// inesperado), el aviso dice por qué (nucleo/caducidad.ts). Es un aviso y no
// un error: no lo ha causado la persona. Recibe el foco, como el de la vuelta
// del proveedor, para que se lea antes que el formulario.
@Component({
  selector: 'app-entrar',
  imports: [Canario, Google, MostrarContrasena, ReactiveFormsModule, RouterLink],
  host: { '(window:pageshow)': 'alMostrar($event)' },
  template: `
    <main class="acceso">
      <app-canario />
      <h1 tabindex="-1">Entrar</h1>
      @if (cierre(); as texto) {
        <p id="entrar-cierre" tabindex="-1" class="aviso" role="status">{{ texto }}</p>
      }
      @if (vuelta(); as resultado) {
        <p id="entrar-vuelta" tabindex="-1" [class]="resultado === 'cancelado' ? 'aviso' : 'error'"
           [attr.role]="resultado === 'cancelado' ? 'status' : 'alert'">{{ textosVuelta[resultado] }}</p>
      }
      <form class="tarjeta" [formGroup]="formulario" (ngSubmit)="entrar()" ngNativeValidate>
        <p class="campo">
          <label for="entrar-empresa">Empresa</label>
          <input #campoEmpresa id="entrar-empresa" formControlName="empresa" required autocomplete="organization"
                 autocapitalize="none" spellcheck="false" aria-describedby="entrar-empresa-ayuda">
          <span id="entrar-empresa-ayuda" class="ayuda">El identificador de su empresa en Canario.</span>
        </p>
        <p class="campo">
          <label for="entrar-email">Email</label>
          <input id="entrar-email" type="email" formControlName="email" required autocomplete="username">
        </p>
        <p class="campo">
          <label for="entrar-contrasena">Contraseña</label>
          <span class="con-mostrar">
            <input #campoContrasena id="entrar-contrasena" type="password" formControlName="contrasena" required
                   autocomplete="current-password">
            <button class="mostrar" [appMostrarContrasena]="campoContrasena" nombre="Mostrar la contraseña"></button>
          </span>
        </p>
        <p class="campo">
          <label for="entrar-codigo">Código de autenticación</label>
          <input id="entrar-codigo" formControlName="codigo_totp" required inputmode="numeric"
                 pattern="[0-9]{6}" title="Las 6 cifras, sin espacios."
                 autocomplete="one-time-code" aria-describedby="entrar-codigo-ayuda">
          <span id="entrar-codigo-ayuda" class="ayuda">Las 6 cifras que muestra su aplicación.</span>
        </p>
        @if (error(); as texto) {
          <p class="error" role="alert">{{ texto }}</p>
        }
        <button type="submit" class="ancho-completo" [attr.aria-disabled]="enviando() || null">{{ enviando() ? 'Entrando...' : 'Entrar' }}</button>
        @for (proveedor of proveedores(); track proveedor) {
          <p class="separador">o</p>
          <button type="button" class="externo ancho-completo" (click)="conProveedor(proveedor, campoEmpresa)"
                  [attr.aria-disabled]="yendo() || null">
            @if (proveedor === 'google') {
              <app-google />
            }
            <span>{{ yendo() ? 'Abriendo ' + registro[proveedor].nombre + '...' : 'Iniciar sesión con ' + registro[proveedor].nombre }}</span>
          </button>
        }
      </form>
      <p class="tarjeta-pie">¿No tiene cuenta? <a routerLink="/registro">Solicitar acceso</a></p>
    </main>
  `,
})
export class Entrar {
  private readonly api = inject(ApiPersonal);
  private readonly router = inject(Router);
  private readonly sesion = inject(Sesion);
  private readonly externo = inject(ApiExterno);
  private readonly navegar = inject(NAVEGAR);

  readonly registro = PROVEEDORES;
  readonly textosVuelta = TEXTOS_VUELTA;
  readonly proveedores = signal<Proveedor[]>([]);
  readonly vuelta = signal<Resultado | null>(null);
  // De un solo uso: recargar la página no lo repite.
  readonly cierre = signal(inject(Caducidad).tomarAviso());
  // Un inicio cada vez, como el login: cada uno abre un flujo en la API.
  readonly yendo = signal(false);

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
          401: 'Empresa, email, contraseña o código incorrectos.',
          422: 'Revise los datos: alguno no tiene un formato válido.',
        }));
      },
    });
  }

  constructor() {
    const injector = inject(Injector);
    // La vuelta del proveedor: el texto sale de la lista cerrada y la URL se
    // limpia siempre, también con un valor desconocido, para que recargar o
    // compartir el enlace no repita el aviso. replaceState no navega: la
    // página no se vuelve a crear.
    const consulta = inject(ActivatedRoute).snapshot.queryParamMap;
    if (consulta.has('externo')) {
      this.vuelta.set(resultadoDe(consulta.get('externo')));
      inject(Location).replaceState('/entrar');
      if (this.vuelta() !== null) {
        enfocarEncabezado(injector, '#entrar-vuelta');
      }
    } else if (this.cierre() !== null) {
      enfocarEncabezado(injector, '#entrar-cierre');
    }
    // Sin la lista, no hay botones: la entrada con contraseña no depende de
    // ella, y un error aquí sería un aviso rojo en la puerta por algo que no
    // impide entrar. La caída del broker la registra la API
    // (EVENTO broker_no_disponible).
    this.externo.proveedores().subscribe({
      next: (lista) => this.proveedores.set(lista),
      error: () => this.proveedores.set([]),
    });
  }

  conProveedor(proveedor: Proveedor, campoEmpresa: HTMLInputElement): void {
    if (this.enviando() || this.yendo()) {
      return;
    }
    // Solo la empresa: el email, la contraseña y el código no se usan aquí, y
    // el aviso nativo de un campo vacío que no hace falta confundiría.
    if (!campoEmpresa.reportValidity()) {
      return;
    }
    this.yendo.set(true);
    this.error.set(null);
    const nombre = PROVEEDORES[proveedor].nombre;
    this.externo.iniciar(proveedor, this.formulario.controls.empresa.value).subscribe({
      next: (url) => {
        if (urlPermitida(proveedor, url)) {
          // yendo sigue en true hasta salir de la página.
          this.navegar(url);
          return;
        }
        this.yendo.set(false);
        this.error.set(TEXTO_INESPERADO);
      },
      error: (error: unknown) => {
        this.yendo.set(false);
        this.error.set(textoDeError(error, {
          // El mismo 409 si la empresa no existe o si el navegador no es de
          // confianza (app/rutas_externo.py): el texto nombra las dos causas.
          409: `No se puede entrar con ${nombre} en esa empresa desde este navegador. Revise la empresa o, ` +
            'la primera vez, entre con su contraseña y su código.',
          404: `El acceso con ${nombre} no está disponible.`,
          422: 'Revise la empresa: no tiene un formato válido.',
        }));
      },
    });
  }

  // Restaurada de la caché del navegador (bfcache) al volver desde Google:
  // ningún inicio sigue en curso en esta página. $event llega como Event; el
  // de pageshow es un PageTransitionEvent.
  alMostrar(evento: Event): void {
    if ((evento as PageTransitionEvent).persisted) {
      this.yendo.set(false);
    }
  }
}
