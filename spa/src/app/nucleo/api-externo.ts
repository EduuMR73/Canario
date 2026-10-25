import { HttpClient } from '@angular/common/http';
import { InjectionToken, Injectable, inject } from '@angular/core';
import { Observable, map } from 'rxjs';
import { BASE } from './api';
import { conSesion } from './contexto';

// Cliente del acceso con un proveedor externo y de los vínculos
// (app/rutas_externo.py, docs/threat-model.md, 6.19). El flujo y el ticket
// viajan en cookies __Host- HttpOnly que pone y lee la API: la SPA no los ve
// nunca, ni en la URL ni en la memoria.
//
// La CSP del 8445 lleva form-action 'none' (proxy/Caddyfile), así que el
// inicio no puede ser un formulario que vaya al proveedor: es un fetch que
// devuelve {url}, y la SPA navega a ella con location.assign. Antes comprueba
// que la URL es del proveedor (urlPermitida): si la API o el broker
// devolvieran otra, por un fallo o por un ataque, la SPA no llevaría a nadie a
// una página que imitara la de Google.

// Un solo registro de los proveedores que la SPA sabe pintar: nombre visible
// y el único origen al que puede llevar su inicio. El origen es el del
// endpoint de autorización (app/cliente_broker.py, ENDPOINTS_AUTORIZACION).
// Un proveedor que la API anuncie y no esté aquí no se pinta.
export const PROVEEDORES = {
  google: { nombre: 'Google', origen: 'https://accounts.google.com' },
} as const;

export type Proveedor = keyof typeof PROVEEDORES;

export function esProveedor(nombre: string): nombre is Proveedor {
  return Object.hasOwn(PROVEEDORES, nombre);
}

// La URL del proveedor solo vale si es https, de su origen exacto y sin
// usuario ni contraseña delante del host. new URL normaliza antes de
// comparar: "https://accounts.google.com.evil.test" y
// "https://accounts.google.com@evil.test" tienen otro origen.
export function urlPermitida(proveedor: Proveedor, url: string): boolean {
  let destino: URL;
  try {
    destino = new URL(url);
  } catch {
    return false;
  }
  return destino.origin === PROVEEDORES[proveedor].origen && destino.username === '' && destino.password === '';
}

// Cómo se sale de la SPA hacia el proveedor. Va en un token para que las
// pruebas comprueben adónde se iría sin salir de la página.
export const NAVEGAR = new InjectionToken<(url: string) => void>('navegar', {
  providedIn: 'root',
  factory: () => (url: string) => window.location.assign(url),
});

// Lo que dice la vuelta del proveedor (app/rutas_externo.py, RESULTADOS):
// /entrar?externo=<resultado> y /cuenta?vinculo=<resultado>. Lista cerrada:
// un valor que no esté aquí no pinta nada, y ningún texto de la URL llega a
// la página.
export type Resultado = 'cancelado' | 'no_disponible' | 'fallido';

const RESULTADOS: readonly string[] = ['cancelado', 'no_disponible', 'fallido'] satisfies Resultado[];

export function resultadoDe(valor: string | null): Resultado | null {
  return valor !== null && RESULTADOS.includes(valor) ? valor as Resultado : null;
}

interface ConUrl {
  url: string;
}

@Injectable({ providedIn: 'root' })
export class ApiExterno {
  private readonly http = inject(HttpClient);

  // Público: la entrada lo pide sin sesión. Los que la SPA no conoce se
  // quedan fuera.
  proveedores(): Observable<Proveedor[]> {
    return this.http.get<{ proveedores: string[] }>(`${BASE}/externo/proveedores`)
      .pipe(map((r) => r.proveedores.filter(esProveedor)));
  }

  // Sin RENOVABLE: es un acceso, como el login con contraseña.
  iniciar(proveedor: Proveedor, empresa: string): Observable<string> {
    return this.http.post<ConUrl>(`${BASE}/externo/${proveedor}/inicio`, { empresa }).pipe(map((r) => r.url));
  }

  // Con el ticket de su cookie. Las cookies de la sesión las pone la
  // respuesta, como en el login con contraseña.
  entrar(codigoTotp: string): Observable<unknown> {
    return this.http.post(`${BASE}/sesiones/externa`, { codigo_totp: codigoTotp });
  }

  // Las tres de los vínculos usan la sesión. Un código que no vale da 401 sin
  // WWW-Authenticate, que no renueva (nucleo/renovacion.ts).
  iniciarVinculo(proveedor: Proveedor, codigoTotp: string): Observable<string> {
    return this.http.post<ConUrl>(`${BASE}/externo/${proveedor}/vinculo/inicio`, { codigo_totp: codigoTotp },
                                  conSesion()).pipe(map((r) => r.url));
  }

  completarVinculo(proveedor: Proveedor): Observable<unknown> {
    return this.http.post(`${BASE}/externo/${proveedor}/vinculo`, {}, conSesion());
  }

  revocarVinculo(proveedor: Proveedor, codigoTotp: string): Observable<unknown> {
    return this.http.delete(`${BASE}/externo/${proveedor}/vinculo`, { ...conSesion(), body: { codigo_totp: codigoTotp } });
  }
}
