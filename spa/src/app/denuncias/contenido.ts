import { Component, input } from '@angular/core';
import { Expediente } from '../nucleo/api-denuncias';
import { TextoLibre } from './texto-libre';
import { NOMBRES_ESTADO, autorDe, fechaLegible, nombreCategoria } from './textos';

// El contenido de una denuncia ya leída: los datos, el texto y los mensajes.
// Solo pinta; leer, escribir y cambiar el estado lo hace expediente.ts.
//
// El texto de la denuncia y el de cada mensaje los escribe alguien de fuera:
// se pintan siempre con TextoLibre (texto-libre.ts), que los inserta como
// texto y marca los caracteres invisibles. Los emails no lo necesitan: la API
// solo los admite en ASCII imprimible.
@Component({
  selector: 'app-contenido',
  imports: [TextoLibre],
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
    <app-texto-libre [texto]="expediente().texto" idTexto="expediente-texto" />

    <h3>Mensajes</h3>
    @if (expediente().mensajes.length === 0 && pendienteFinal() === null) {
      <p>Todavía no hay mensajes.</p>
    } @else {
      <ol class="mensajes">
        @for (mensaje of expediente().mensajes; track mensaje.secuencia) {
          <li>
            <p class="mensaje-cabecera">Mensaje {{ mensaje.secuencia }} · {{ autor(mensaje, propia()) }} ·
              <time [attr.datetime]="mensaje.fecha">{{ fecha(mensaje.fecha) }}</time></p>
            <app-texto-libre [texto]="mensaje.texto" />
          </li>
        }
        @if (pendienteFinal(); as texto) {
          <li>
            <p class="mensaje-cabecera">Mensaje final · Usted · saldrá numerado al volver a leer</p>
            <app-texto-libre [texto]="texto" />
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
