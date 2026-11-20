# Pruebas funcionales

Las pruebas funcionales de Canario con pytest y Playwright ([informe de pruebas](../../docs/informe-pruebas.md), sección 2). De momento, F1 en Chromium.

## Qué prueban y qué no

Las baterías de `tests/security/` prueban **controles**: `verificar_spa.py` ya recorre en un Chromium real el sitio del denunciante (q) y las pantallas del personal con denuncias creadas por la API (m). Lo nuevo aquí es **el circuito entre los dos actores en el mismo escenario**, y después los otros motores:

- **F1**: el denunciante presenta una denuncia en el 8444 sin JavaScript (como lo usa de verdad) y recibe su código; el admin la asigna a una instructora; la instructora entra en el 8445 con contraseña y TOTP, abre el expediente, ve el texto, responde y cambia el estado a "En instrucción"; el denunciante consulta con su código, ve el estado y la respuesta y escribe; la instructora vuelve a abrir el expediente y ve su mensaje.
- Cada texto sembrado lleva un nonce de la ejecución, y cada oráculo es un literal escrito en la prueba y acotado a su elemento (el `<dd>` del estado, un `<li>` de los mensajes, el aviso de la acción), nunca "aparece en la página". Cada envío comprueba también que se aceptó (201 y su aviso).
- F2 (errores del 8444), F3 (JavaScript desactivado de verdad) y los motores Firefox y WebKit llegan después.

## Cómo ejecutarlas

En PowerShell, desde la raíz del repositorio, con Docker en marcha, los secretos generados (`scripts\generar_secretos.py`) y **la pila local de Canario parada** (las pruebas levantan su propia copia con las mismas subredes y puertos):

```powershell
docker compose -p canario down
python tests\funcionales\lanzar.py
```

`down` va **sin `-v`**: los volúmenes de la pila local no se tocan. Si quedan restos de una ejecución anterior (`canario_funcionales*`), las subredes o los puertos 8443 a 8445 están ocupados, el lanzador se detiene con `PARADA` sin tocar nada.

Necesita internet: construye las imágenes, descarga la imagen de Playwright 1.63.0 por digest (unos 2 GB la primera vez) y, dentro del contenedor, los paquetes de `requisitos.txt` con versiones exactas y sus hashes. En el Python del host solo hace falta `cryptography` (de `requirements.txt`), para la CA del correo de la pila.

Termina con `RESULTADO GLOBAL: OK` o `NO OK`, y el código de salida es 0 solo si es OK. Una prueba saltada, un fallo esperado o un `SIN CONCLUSION` impiden el OK. La salida queda también en `%TEMP%\verificacion_funcionales.txt`.

## Cómo funciona

- `lanzar.py` (host): comprobaciones previas, pila propia (proyecto `canario_funcionales`) con límites relajados (comprobados con la línea entera `LIMITES (configurados): ...` del log), empresa y admin con `gestion`, y el contenedor de Playwright endurecido (solo lectura, sin capacidades, `no-new-privileges`, usuario 1001). El token de invitación del admin no se imprime: va en `datos.json`, montado de solo lectura, y nunca por la línea de órdenes ni por variables de entorno; mientras el contenedor corre, se comprueba que `docker inspect` no lo contiene.
- `conftest.py` (contenedor): Chromium con el SPKI de la CA intermedia de Caddy, una fábrica única de contextos que aborta todo lo que no vaya a `https://localhost:8444` o `:8445` (con su control positivo) y la preparación de las cuentas (activación del admin, invitación y activación de la instructora). Cada secreto se anota en `secretos.json` antes de usarse.
- Anti-fuga: al terminar, el lanzador busca en el informe HTML y en la salida del contenedor cada secreto de la ejecución (código de seguimiento, contraseñas, token del admin, enlace de la instructora y secretos TOTP, con sus formas escapadas). Si aparece alguno, `NO OK`. El control positivo es un centinela aleatorio que `conftest.py` escribe a propósito en el informe: si el escáner no lo encuentra, `SIN CONCLUSION`. El informe publicable (`informe.html`) se genera de nuevo sin el centinela.
- `paginas.py`: los objetos de página del 8444 y de la SPA, con los selectores reales.

## Qué queda en el host

- El directorio de salida, cuya ruta se imprime al final (`%TEMP%\canario_funcionales_salida_*`): `informe.html` (publicable) y, solo si algo falla, las trazas de Playwright en `trazas\`. **Las trazas llevan códigos, contraseñas y textos de la ejecución: no se publican.** Bórrelas cuando termine de revisarlas. Si el escáner encuentra una fuga, queda `informe_bruto.html` con el aviso de no publicarlo.
- `secretos.json` se borra siempre al terminar.
- La pila monta los ficheros reales de `secrets/` como las baterías (no se leen ni se exponen); los de Google y del correo se sustituyen por marcadores y por una CA de la prueba.

## Modo `--conservar` (solo para desarrollar)

```powershell
python tests\funcionales\lanzar.py --conservar
```

No hace `down` ni borra los temporales. Imprime la orden exacta de `docker compose -p canario_funcionales ... down -v --rmi local` y las rutas de los temporales. **Las credenciales de la ejecución siguen vivas en la pila y `datos.json` guarda el token del admin**: bórrelo todo con esas órdenes en cuanto termine. La evidencia sale de una ejecución limpia, sin `--conservar`.
