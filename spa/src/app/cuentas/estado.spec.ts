import { describe, expect, it } from 'vitest';
import { Cuenta } from '../nucleo/api-cuentas';
import { avisosDe, enlaceDeActivacion, situacionDe } from './estado';

// Oráculos literales: los textos de la pantalla y la forma del enlace del
// correo (app/solicitudes.py, _enlace), no las funciones que se prueban.
function cuenta(cambios: Partial<Cuenta> = {}): Cuenta {
  return {
    usuario_id: 'u', email: 'a@b.test', rol: 'instructor', activo: true, activado: true,
    camino_sin_confianza_cerrado: false, en_espera: false, invitacion_pendiente: false, ...cambios,
  };
}

describe('estado de una cuenta', () => {
  it('la situación: activa, sin activar o desactivada', () => {
    expect(situacionDe(cuenta())).toBe('Activa');
    expect(situacionDe(cuenta({ activado: false }))).toBe('Sin activar');
    expect(situacionDe(cuenta({ activo: false }))).toBe('Desactivada');
    expect(situacionDe(cuenta({ activo: false, activado: false }))).toBe('Desactivada');
  });

  it('los avisos: invitación abierta y entrada desde navegadores nuevos', () => {
    expect(avisosDe(cuenta())).toEqual([]);
    expect(avisosDe(cuenta({ invitacion_pendiente: true, en_espera: true }))).toEqual([
      'Invitación abierta', 'Entrada desde navegadores nuevos en espera por intentos fallidos']);
    expect(avisosDe(cuenta({ camino_sin_confianza_cerrado: true, en_espera: true }))).toEqual([
      'Entrada desde navegadores nuevos cerrada: se reabre con una invitación']);
  });

  it('el enlace de activación lleva el token en el fragmento', () => {
    expect(enlaceDeActivacion('https://localhost:8445', 'abc.def')).toBe('https://localhost:8445/activacion#abc.def');
  });
});
