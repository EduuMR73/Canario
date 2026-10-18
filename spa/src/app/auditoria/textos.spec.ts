import { describe, expect, it } from 'vitest';
import { FilaAuditoria } from '../nucleo/api-auditoria';
import { nombreAccion, quienActua, sobreQue, textoCadena } from './textos';

// Oráculos literales: las acciones que escribe la API (app/personal.py,
// app/solicitudes.py, app/instruccion.py y db/init), los textos de la
// pantalla y las formas de la API, no las constantes del código que se prueba.
const CUENTA = '3f2a1b0c-9d8e-4f7a-8b6c-5d4e3f2a1b0c';
const DENUNCIA = '0b6f3c1e-8d2a-4f5b-9c7e-1a2b3c4d5e6f';
const OTRA = '7c6b5a49-3827-4161-8a0f-9e8d7c6b5a49';

function fila(cambios: Partial<FilaAuditoria>): FilaAuditoria {
  return {
    secuencia: 1, fecha: '2026-10-18', actor: `personal:${CUENTA}`, actor_email: 'admin@empresa.test',
    accion: 'lectura_denuncia', objeto_id: DENUNCIA, destino_id: null, cuenta_email: null, ...cambios,
  };
}

describe('textos de la auditoría', () => {
  it('cada acción de la API tiene nombre, y una desconocida se enseña tal cual', () => {
    const acciones = [
      'acceso', 'activacion', 'cambio_contrasena', 'invitacion', 'baja', 'anulacion_invitacion',
      'invitacion_admin_plataforma', 'reinvitacion_admin_plataforma', 'aprobacion_registro', 'rechazo_registro',
      'lectura_denuncia', 'mensaje_personal', 'asignacion', 'estado_en_instruccion', 'estado_resuelta',
      'estado_archivada', 'estado_inadmitida', 'estado_no_veraz', 'redaccion_denuncia', 'redaccion_mensaje',
      'supresion_art32', 'supresion_art26', 'supresion_art32_3',
    ];
    expect(acciones.filter((accion) => nombreAccion(accion) === accion)).toEqual([]);
    expect(nombreAccion('estado_resuelta')).toBe('Cambio de estado a Resuelta');
    expect(nombreAccion('accion_nueva')).toBe('accion_nueva');
    expect(nombreAccion('toString')).toBe('toString');
  });

  it('quién actúa: su email, plataforma, sistema o el id si la cuenta no se resuelve', () => {
    expect(quienActua(fila({}))).toBe('admin@empresa.test');
    expect(quienActua(fila({ actor: 'plataforma', actor_email: null }))).toBe('Plataforma');
    expect(quienActua(fila({ actor: 'sistema', actor_email: null }))).toBe('Sistema');
    expect(quienActua(fila({ actor_email: null }))).toBe(CUENTA);
    expect(quienActua(fila({ actor: 'otro', actor_email: null }))).toBe('otro');
  });

  it('sobre qué: la cuenta por su email, la denuncia por su id y la asignación con las dos', () => {
    expect(sobreQue(fila({}))).toBe(`Denuncia ${DENUNCIA}`);
    expect(sobreQue(fila({ accion: 'baja', objeto_id: OTRA, cuenta_email: 'baja@empresa.test' })))
      .toBe('baja@empresa.test');
    expect(sobreQue(fila({ accion: 'baja', objeto_id: OTRA }))).toBe(`Cuenta ${OTRA}`);
    expect(sobreQue(fila({ accion: 'asignacion', destino_id: OTRA, cuenta_email: 'instructora@empresa.test' })))
      .toBe(`Denuncia ${DENUNCIA}, a instructora@empresa.test`);
    expect(sobreQue(fila({ accion: 'asignacion', destino_id: OTRA }))).toBe(`Denuncia ${DENUNCIA}, a la cuenta ${OTRA}`);
    expect(sobreQue(fila({ accion: 'rechazo_registro', objeto_id: OTRA }))).toBe(`Solicitud ${OTRA}`);
    expect(sobreQue(fila({ accion: 'redaccion_mensaje', destino_id: OTRA }))).toBe(`Denuncia ${DENUNCIA}`);
    expect(sobreQue(fila({ accion: 'accion_nueva', destino_id: OTRA }))).toBe(`${DENUNCIA}, ${OTRA}`);
  });

  it('la verificación: intacta, o la fila donde se rompe', () => {
    expect(textoCadena({ cadena_intacta: true, primera_rota: null }))
      .toBe('La cadena está intacta: ninguna fila se ha cambiado, borrado ni insertado.');
    expect(textoCadena({ cadena_intacta: false, primera_rota: 42 })).toBe(
      'La cadena se rompe en la fila nº 42: desde ahí, el registro no es fiable (alguna fila se ha cambiado, ' +
      'borrado o insertado). Avise al responsable del sistema.');
  });
});
