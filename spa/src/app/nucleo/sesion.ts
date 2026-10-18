import { Injectable, inject, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import { ApiPersonal, Yo } from './api';

// La cuenta de la sesión, una sola fuente de verdad para todas las páginas.
// Es solo para pintar: quién puede hacer qué lo decide siempre la API, que
// lee el rol de la base de datos en cada petición (app/personal.py,
// autenticar).
@Injectable({ providedIn: 'root' })
export class Sesion {
  private readonly api = inject(ApiPersonal);
  private readonly cuenta = signal<Yo | null>(null);
  readonly yo = this.cuenta.asReadonly();

  async cargar(): Promise<Yo> {
    const yo = await firstValueFrom(this.api.yo());
    this.cuenta.set(yo);
    return yo;
  }

  olvidar(): void {
    this.cuenta.set(null);
  }
}
