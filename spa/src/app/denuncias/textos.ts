import { CanMatchFn } from '@angular/router';
import { Rol } from '../nucleo/api';
import { Estado, EstadoDestino, Mensaje, esIdDenuncia } from '../nucleo/api-denuncias';

// Lo que las pantallas de denuncias dicen de cada dato de la API. Funciones
// puras: se prueban sin navegador (textos.spec.ts). Qué se puede hacer lo
// decide siempre la API; aquí solo se evita ofrecer lo que daría un 403 o un
// 409.

export const NOMBRES_ESTADO: Record<Estado, string> = {
  nueva: 'Nueva',
  en_instruccion: 'En instrucción',
  resuelta: 'Resuelta',
  archivada: 'Archivada',
  inadmitida: 'Inadmitida',
};

export const ESTADOS = Object.keys(NOMBRES_ESTADO) as Estado[];

// La clase de styles.css que da su color a cada estado, de un mapa fijo y no
// compuesta con el valor de la API: un estado que la SPA no conoce se queda
// sin color en vez de inventarse una clase.
export const CLASES_ESTADO: Record<Estado, string> = {
  nueva: 'estado estado-nueva',
  en_instruccion: 'estado estado-en-instruccion',
  resuelta: 'estado estado-resuelta',
  archivada: 'estado estado-archivada',
  inadmitida: 'estado estado-inadmitida',
};

// El icono de cada estado: el color no es la única señal (WCAG 2.2, 1.4.1),
// y abiertas, resuelta, archivada e inadmitida tienen formas distintas.
export type IconoEstado = 'abierta' | 'resuelta' | 'archivada' | 'inadmitida';

export const ICONOS_ESTADO: Record<Estado, IconoEstado> = {
  nueva: 'abierta',
  en_instruccion: 'abierta',
  resuelta: 'resuelta',
  archivada: 'archivada',
  inadmitida: 'inadmitida',
};

// app/denuncias.py, CATEGORIAS.
const NOMBRES_CATEGORIA: Record<string, string> = {
  acoso: 'Acoso',
  fraude: 'Fraude',
  corrupcion: 'Corrupción',
  seguridad_laboral: 'Seguridad laboral',
  proteccion_datos: 'Protección de datos',
  medio_ambiente: 'Medio ambiente',
  otros: 'Otros',
};

// Una categoría que la SPA no conoce se enseña tal cual, en vez de esconderla.
export function nombreCategoria(categoria: string): string {
  return Object.hasOwn(NOMBRES_CATEGORIA, categoria) ? NOMBRES_CATEGORIA[categoria] : categoria;
}

// Copia literal de app/instruccion.py, TRANSICIONES, sin 'no_veraz', que va
// aparte (puedeDeclararNoVeraz). Si la API cambia, la SPA ofrece de menos o de
// más y la API responde 409: nunca se salta la regla.
const TRANSICIONES: Record<Estado, readonly Exclude<EstadoDestino, 'no_veraz'>[]> = {
  nueva: ['en_instruccion', 'inadmitida'],
  en_instruccion: ['resuelta', 'archivada'],
  resuelta: [],
  archivada: [],
  inadmitida: [],
};

const CERRADOS: readonly string[] = ['resuelta', 'archivada', 'inadmitida'];

export function destinosDe(estado: Estado): readonly Exclude<EstadoDestino, 'no_veraz'>[] {
  return TRANSICIONES[estado];
}

// Cerrar exige un mensaje final para el denunciante (art. 9.2.d de la Ley
// 2/2023; la API responde 422 sin él). Una denuncia cerrada no admite más
// mensajes.
export function esCerrado(estado: string): boolean {
  return CERRADOS.includes(estado);
}

// La declaración de no veraz es de un admin con la denuncia asignada, desde
// cualquier estado (app/instruccion.py, cabecera). Al instructor no se le
// ofrece: la API le respondería 403.
export function puedeDeclararNoVeraz(rol: Rol): boolean {
  return rol === 'admin';
}

// app/instruccion.py, LECTURAS_AVISO: a partir de aquí la API avisa a quien
// vigila. La SPA avisa a la propia persona en el mismo momento, antes de que
// llegue al tope y no después. El tope lo da la API en cada lectura.
const LECTURAS_AVISO = 20;

export function avisoLecturas(hoy: number, tope: number): string | null {
  if (hoy < LECTURAS_AVISO) {
    return null;
  }
  return `Lleva ${hoy} de ${tope} denuncias distintas abiertas hoy. Al llegar a ${tope} no podrá abrir otras nuevas ` +
    'hasta mañana; las que ya abrió las puede seguir leyendo.';
}

// La API da días sin hora (AAAA-MM-DD). Se pasan a texto a mano: new Date de
// esa forma es la medianoche UTC, que en Canarias o en América sería el día
// anterior. Si no tiene esa forma, se enseña tal cual en vez de inventar.
export function fechaLegible(fecha: string): string {
  const partes = /^(\d{4})-(\d{2})-(\d{2})$/.exec(fecha);
  return partes === null ? fecha : `${partes[3]}/${partes[2]}/${partes[1]}`;
}

// Quién escribió un mensaje. El personal se ve a sí mismo como "Usted"; quién
// del personal escribió los demás está en la auditoría.
export function autorDe(mensaje: Mensaje, propia: string | undefined): string {
  if (mensaje.autor === 'denunciante') {
    return 'Denunciante';
  }
  return mensaje.autor_id !== null && mensaje.autor_id === propia ? 'Usted' : 'Personal';
}

// /denuncias/:id solo casa si el id es un uuid (nucleo/api-denuncias.ts,
// cabecera): si no, el router sigue buscando y la página es "no encontrada",
// sin pedir nada a la API. Los segmentos son los que quedan por casar desde el
// armazón: ['denuncias', id].
export const conIdDeDenuncia: CanMatchFn = (_ruta, segmentos) =>
  segmentos.length === 2 && esIdDenuncia(segmentos[1].path);
