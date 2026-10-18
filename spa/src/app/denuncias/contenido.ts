import { Component, input } from '@angular/core';
import { Expediente } from '../nucleo/api-denuncias';
import { NOMBRES_ESTADO, autorDe, fechaLegible, nombreCategoria } from './textos';

// El contenido de una denuncia ya leída: los datos, el texto y los mensajes.
// Solo pinta; leer, escribir y cambiar el estado lo hace expediente.ts.
//
// Aquí se pinta el único texto que escribe alguien de fuera (el denunciante,
// anónimo y sin cuenta) y que lee el personal con su sesión abierta. Siempre
// por interpolación ({{ }}), que Angular inserta como texto: un <img> o un
// <script> en la denuncia salen escritos tal cual y no crean ningún elemento.
// Nunca [innerHTML]: aunque el sanitizador quite los atributos peligrosos,
// deja etiquetas como <img>, y la CSP y Trusted Types serían la única barrera
// (tests/security/verificar_spa.py, m, prueba exactamente ese mutante).
//
// dir="auto" en cada texto libre: un carácter de control bidireccional
// (U+202E) en una denuncia no puede dar la vuelta a lo que hay alrededor
// (CWE-451); el texto queda aislado y con su propia dirección. Los emails no
// lo necesitan: la API solo los admite en ASCII imprimible.
@Component({
  selector: 'app-contenido',
  template: `
    <dl class="ficha">
      <dt>Fecha</dt>
      <dd><time [attr.datetime]="expediente().fecha">{{ fecha(expediente().fecha) }}</time></dd>
      <dt>Categoría</dt>
      <dd>{{ categoria(expediente().categoria) }}</dd>
      <dt>Estado</dt>
      <dd id="expediente-estado">{{ nombreEstado[expediente().estado] }}</dd>
    </dl>

    <h3>Texto de la denuncia</h3>
    <p class="texto-libre" dir="auto" id="expediente-texto">{{ expediente().texto }}</p>

    <h3>Mensajes</h3>
    @if (expediente().mensajes.length === 0 && pendienteFinal() === null) {
      <p>Todavía no hay mensajes.</p>
    } @else {
      <ol class="mensajes">
        @for (mensaje of expediente().mensajes; track mensaje.secuencia) {
          <li>
            <p class="mensaje-cabecera">Mensaje {{ mensaje.secuencia }} · {{ autor(mensaje, propia()) }} ·
              <time [attr.datetime]="mensaje.fecha">{{ fecha(mensaje.fecha) }}</time></p>
            <p class="texto-libre" dir="auto">{{ mensaje.texto }}</p>
          </li>
        }
        @if (pendienteFinal(); as texto) {
          <li>
            <p class="mensaje-cabecera">Mensaje final · Usted · saldrá numerado al volver a leer</p>
            <p class="texto-libre" dir="auto">{{ texto }}</p>
          </li>
        }
      </ol>
    }
  `,
})
export class Contenido {
  readonly expediente = input.required<Expediente>();
  readonly propia = input<string | undefined>(undefined);
  // El mensaje final de un cierre: la API responde 204 sin su número ni su
  // fecha, así que se enseña aparte hasta la siguiente lectura.
  readonly pendienteFinal = input<string | null>(null);

  readonly nombreEstado = NOMBRES_ESTADO;
  readonly fecha = fechaLegible;
  readonly categoria = nombreCategoria;
  readonly autor = autorDe;
}
