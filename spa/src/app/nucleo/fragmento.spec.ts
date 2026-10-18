import { describe, expect, it, vi } from 'vitest';
import { consumirToken, tomarTokenDelFragmento } from './fragmento';

// Un token con la forma de los de la API (app/cripto.py): empresa, punto y
// 43 caracteres.
const TOKEN = '0123456789abcdef0123456789abcdef.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

function historialFalso() {
  return { state: { navigationId: 1 }, replaceState: vi.fn() };
}

describe('token del fragmento', () => {
  it('en /activacion lo toma, lo borra de la URL y lo entrega una sola vez', () => {
    const historial = historialFalso();
    tomarTokenDelFragmento({ pathname: '/activacion', search: '', hash: `#${TOKEN}` }, historial);
    expect(historial.replaceState).toHaveBeenCalledWith({ navigationId: 1 }, '', '/activacion');
    expect(consumirToken('/activacion')).toBe(TOKEN);
    expect(consumirToken('/activacion')).toBeNull();
  });

  it('en /registro/verificacion conserva la consulta y quita solo el fragmento', () => {
    const historial = historialFalso();
    tomarTokenDelFragmento({ pathname: '/registro/verificacion', search: '?a=1', hash: `#${TOKEN}` }, historial);
    expect(historial.replaceState).toHaveBeenCalledWith({ navigationId: 1 }, '', '/registro/verificacion?a=1');
    expect(consumirToken('/registro/verificacion')).toBe(TOKEN);
  });

  it('el token de una ruta no se entrega a la otra', () => {
    tomarTokenDelFragmento({ pathname: '/activacion', search: '', hash: `#${TOKEN}` }, historialFalso());
    expect(consumirToken('/registro/verificacion')).toBeNull();
    expect(consumirToken('/activacion')).toBe(TOKEN);
  });

  it('en otras rutas no toca la URL ni guarda nada', () => {
    const historial = historialFalso();
    tomarTokenDelFragmento({ pathname: '/entrar', search: '', hash: `#${TOKEN}` }, historial);
    expect(historial.replaceState).not.toHaveBeenCalled();
    expect(consumirToken('/activacion')).toBeNull();
  });

  it('sin fragmento no toca la URL', () => {
    const historial = historialFalso();
    tomarTokenDelFragmento({ pathname: '/activacion', search: '', hash: '#' }, historial);
    expect(historial.replaceState).not.toHaveBeenCalled();
    expect(consumirToken('/activacion')).toBeNull();
  });
});
