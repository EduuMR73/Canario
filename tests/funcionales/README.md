# Pruebas funcionales

Las pruebas funcionales de Canario con pytest y Playwright ([informe de pruebas](../../docs/informe-pruebas.md), sección 2): F1, F2 y F3, en Chromium, Firefox y WebKit.

## Qué prueban y qué no

Las baterías de `tests/security/` prueban **controles**: `verificar_spa.py` ya recorre en un Chromium real el sitio del denunciante (q) y las pantallas del personal con denuncias creadas por la API (m). Lo nuevo aquí es **el circuito entre los dos actores en el mismo escenario**, los errores del sitio del denunciante en un navegador real y los tres motores:

- **F1**: el denunciante presenta una denuncia en el 8444 sin JavaScript (como lo usa de verdad) y recibe su código; el admin la asigna a una instructora; la instructora entra en el 8445 con contraseña y TOTP, abre el expediente, ve el texto, responde y cambia el estado a "En instrucción"; el denunciante consulta con su código, ve el estado y la respuesta y escribe; la instructora vuelve a abrir el expediente y ve su mensaje.
- Cada texto sembrado lleva un nonce de la ejecución, y cada oráculo es un literal escrito en la prueba y acotado a su elemento (el `<dd>` del estado, un `<li>` de los mensajes, el aviso de la acción), nunca "aparece en la página". Cada envío comprueba también que se aceptó (201 y su aviso).
- **F2** (errores del 8444, sin JavaScript): un texto solo de espacios con categoría válida da 422 con `aria-invalid` y `role="alert"` (control: el mismo formulario con texto válido da 201 y "Denuncia enviada"); sin categoría el navegador no envía ningún POST (control: con categoría sí, con el mismo listener y la misma ventana fija); un código mal formado, inexistente (generado al azar, no derivado del real), no ASCII y más largo que el máximo dan el mismo 404, con "código de seguimiento no válido" y el mismo cuerpo byte a byte (control: el código real, y en minúsculas, abre su expediente).
- **F3** (JavaScript desactivado de verdad): en el mismo contexto que después usa el 8444, una página de control servida con `page.route` desde un host `.invalid` lleva un marcador estático y un `<script>` en línea. Debe estar el estático y no el del script (controles: con JavaScript están los dos, el estático cargó y otra petición de esa página sigue abortada). Después, en ese contexto, el denunciante presenta una denuncia y consulta con su código.
- **Motores**: `lanzar.py` lanza pytest una vez por motor. Chromium corre F1, F2 y F3 (3 pruebas), Firefox F1, F2 y F3 (3) y WebKit F2 y F3 (2): los recuentos esperados están escritos a mano en `lanzar.py`. La selección deselecciona (`@pytest.mark.motores`) y no usa `skip`, que impediría el OK. Cada motor tiene su empresa, su contenedor y su carpeta de salida; el admin solo se da de alta en los motores que corren F1, para no dejar un token vivo que nadie usa.

## Cómo ejecutarlas

En PowerShell, desde la raíz del repositorio, con Docker en marcha, los secretos generados (`scripts\generar_secretos.py`) y **la pila local de Canario parada** (las pruebas levantan su propia copia con las mismas subredes y puertos):

```powershell
docker compose -p canario down
python tests\funcionales\lanzar.py
```

`down` va **sin `-v`**: los volúmenes de la pila local no se tocan. Si quedan restos de una ejecución anterior (`canario_funcionales*`), las subredes o los puertos 8443 a 8445 están ocupados, el lanzador se detiene con `PARADA` sin tocar nada.

Necesita internet: construye las imágenes, descarga la imagen de Playwright 1.63.0 por digest (unos 2 GB la primera vez) y, dentro del contenedor, los paquetes de `requisitos.txt` con versiones exactas y sus hashes. En el Python del host solo hace falta `cryptography` (de `requirements.txt`), para la CA del correo de la pila.

Hay que ejecutarlo con la pila local parada y después de la regresión de `tests/security` (comparten subredes). Termina con `RESULTADO GLOBAL: OK` o `NO OK`, y el código de salida es 0 solo si es OK. Una prueba saltada, un fallo esperado o un `SIN CONCLUSION` impiden el OK. La salida queda también en `%TEMP%\verificacion_funcionales.txt`.

## Cómo funciona

- `lanzar.py` (host): comprobaciones previas, pila propia (proyecto `canario_funcionales`) con límites relajados (comprobados con la línea entera `LIMITES (configurados): ...` del log), empresa y admin con `gestion`, y el contenedor de Playwright endurecido (solo lectura, sin capacidades, `no-new-privileges`, usuario 1001). El token de invitación del admin no se imprime: va en `datos.json`, montado de solo lectura, y nunca por la línea de órdenes ni por variables de entorno; mientras el contenedor corre, se comprueba que `docker inspect` no lo contiene.
- `conftest.py` (contenedor): el motor elegido (Chromium con el SPKI de la CA intermedia de Caddy), una fábrica única de contextos que aborta todo lo que no vaya a `https://localhost:8444` o `:8445` (con su control positivo; bloquea además los service workers) y la preparación de las cuentas (activación del admin, invitación y activación de la instructora). Cada secreto se anota en `secretos.json` antes de usarse.
- Anti-fuga: al terminar todos los motores, el lanzador busca en el informe HTML y en la salida de cada motor los secretos de **todas** las ejecuciones (códigos de seguimiento con sus variantes en minúsculas y sin guiones, contraseñas, tokens de admin, enlace de la instructora y secretos TOTP, con sus formas escapadas). Si aparece alguno, `NO OK`. El control positivo es un centinela aleatorio por motor que `conftest.py` escribe a propósito en el informe: si el escáner no lo encuentra, `SIN CONCLUSION`. El informe publicable (`informe.html`) se genera de nuevo sin el centinela.
- `paginas.py`: los objetos de página del 8444 y de la SPA, con los selectores reales.

## Humo, TLS de Firefox y WebKit, y límites aceptados

- **Humo por motor** (antes de las pruebas, `humo.json` en la salida): el motor arranca, abre una página y carga `about:blank` dentro del contenedor endurecido tal como está; `/tmp` (con `/tmp/pw` y el perfil) no ocupa más de la mitad del tmpfs de 600 MB; y un contexto de la fábrica carga el 8444 y devuelve `security_details()`. Si algo falla, `PARADA`. El endurecimiento (usuario no root, raíz de solo lectura, `cap_drop: ALL`, `no-new-privileges`) no se relaja para que un motor arranque.
- **Confianza TLS**: Chromium sigue con el SPKI. Firefox y WebKit no tienen ese mecanismo y usan `ignore_https_errors=True` solo en sus contextos, con estos controles. (1) Identidad: `lanzar.py` lee la hoja que Caddy sirve en 8444 y 8445 con un handshake TLS desde el host, y la primera respuesta de cada origen de cada contexto debe traer exactamente esa validez (`validFrom` y `validTo`) y su CN si lo lleva, con `server_addr()` en 127.0.0.1 (o `[::1]`) y el puerto exacto. No se usa el emisor, que WebKit en Linux no da. Sin datos, `SIN CONCLUSION`; con otra hoja u otra dirección, `FALLA`. (2) Control negativo: el mismo motor, en un contexto de la fábrica sin el flag, debe fallar al cargar el 8444 con el error de certificado fijado en `ERROR_TLS_ESPERADO` (`conftest.py`); un fallo por otra causa o un literal sin fijar es `SIN CONCLUSION`. El control positivo es la misma URL con el flag.
- **Límite del control de identidad: no es criptográfico.** Se acepta porque el navegador comparte el espacio de red de Caddy y en esos puertos de localhost solo puede estar Caddy.
- **Salida a internet (riesgo aceptado)**: el contenedor sigue teniendo salida (pip instala los requisitos al arrancar y la red de Caddy está en `edge`). Se reduce lo que el navegador hace por su cuenta, pero no se elimina: los contextos bloquean los service workers y Firefox lleva preferencias contra la telemetría, las actualizaciones y el portal cautivo (`PREFS_FIREFOX`, lista literal que se **suma** a las que ya trae Playwright y no sustituye ninguna). Lo que el navegador haga fuera de `route()` (por ejemplo, tráfico propio del motor) no está controlado. Quitarlo exigiría vendorizar las ruedas y otro espacio de red, y va a otro bloque.
- **Fallos esperados de WebKit**: solo se admite un `xfail(strict=True)`, condicionado al motor, si la misma prueba pasa en Chromium y Firefox y la traza señala al motor, con la evidencia en la sección 5 del informe de pruebas. Si no, es un defecto de Canario y se corrige el producto. Con un `xfail` el resultado es `NO OK` por diseño.

## Qué queda en el host

- El directorio de salida, cuya ruta se imprime al final (`%TEMP%\canario_funcionales_salida_*`), con una carpeta por motor (`chromium`, `firefox`, `webkit`): `informe.html` (publicable), `humo.json` y, solo si algo falla, las trazas de Playwright en `trazas\`. **Las trazas llevan códigos, contraseñas y textos de la ejecución: no se publican.** Bórrelas cuando termine de revisarlas. Si el escáner encuentra una fuga, queda `informe_bruto.html` con el aviso de no publicarlo.
- `secretos.json` se borra siempre al terminar.
- La pila monta los ficheros reales de `secrets/` como las baterías (no se leen ni se exponen); los de Google y del correo se sustituyen por marcadores y por una CA de la prueba.

## Modo `--conservar` (solo para desarrollar)

```powershell
python tests\funcionales\lanzar.py --conservar
```

No hace `down` ni borra los temporales. Imprime la orden exacta de `docker compose -p canario_funcionales ... down -v --rmi local` y las rutas de los temporales. **Las credenciales de la ejecución siguen vivas en la pila y `datos.json` guarda el token del admin**: bórrelo todo con esas órdenes en cuanto termine. La evidencia sale de una ejecución limpia, sin `--conservar`.
