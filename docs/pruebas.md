# Pruebas

Las baterías de seguridad, las pruebas unitarias y el análisis estático. Las decisiones que prueban están en el [modelo de amenazas](threat-model.md).

## Pruebas de seguridad

Trece baterías, una por área. Cada prueba negativa lleva su control positivo: si el control falla, el resultado es `SIN CONCLUSION`, nunca `PASA`. Los resultados esperados están escritos como literales en la propia batería, no derivados del código que se prueba.

| Batería | Qué prueba |
|---|---|
| `verificar_esqueleto.py` | Proxy y API: sin salida a internet, solo los tres puertos del proxy, cabeceras, 421, estáticos del denunciante (sin rangos ni salir de `/srv`), logs sin IP, endurecimiento de los contenedores |
| `verificar_web.py` | Sitio del denunciante: lo que el 8444 reenvía a la API (con una aplicación de eco; las cookies, solo por el 8445) y las páginas con la API real: escapado, formularios de otro origen, cuerpo estricto, NUL y logs sin rastro |
| `verificar_arranque.py` | Conexión a PostgreSQL con secretos y el arranque verificado de la API |
| `verificar_esquema.py` | Esquema, RLS entre empresas, permisos, auditoría encadenada, supresión legal y vínculos con identidades externas en la base de datos |
| `verificar_denuncia.py` | Cifrado, denuncia anónima, seguimiento, mensajes, limitador y supresión por la API y `gestion` |
| `verificar_personal.py` | Identidad del personal, login, bloqueos, sesiones, administración, instrucción, no veraz (art. 32.3) y la auditoría por la API (emails y páginas) |
| `verificar_sesion.py` | La sesión del personal en el navegador por el 8445: tokens solo en cookies con sus atributos exactos, CSRF desde otro puerto, rotación y reutilización, cierre, cookies que no salen por el 8443 y logs sin tokens |
| `verificar_spa.py` | La SPA del personal en el 8445: cabeceras y CSP exactas, nada en línea (con un mutante), imagen sin Node, contexto de compilación aislado, rutas, las pruebas unitarias sin red (con siete mutantes), el contraste de la base visual en los dos temas, la fuente servida con su sha256, los botones ocupados con `aria-disabled` (con un mutante), las plantillas sin colores fuera del inventario y todo SVG decorativo o con nombre (con dos mutantes), y en un Chromium real la carga sin violaciones de la CSP, Trusted Types, la activación, el login, la renovación entre pestañas, el cierre, el registro con su correo, las pantallas por rol (menú, páginas de otro rol, solicitudes, cuentas y contraseña), las denuncias (listado y asignación, expediente que no se lee solo, XSS almacenado con un mutante, id con `..`, mensajes, estados, no veraz y "atrás" tras cerrar la sesión) la auditoría (emails, páginas, actualizar, verificación y un email con HTML con un mutante) y los botones ocupados (el foco tras un login fallido y un solo envío con un doble clic, con dos mutantes, y "Cargar más" hasta el final), y la fuente cargada, el tema oscuro, las páginas a 320 px sin desbordar y Leila decorativa en la lista vacía y en la 404 (en "no disponible", con una prueba unitaria), y el pulido de la barra, los títulos y las patas del canario (con tres reglas de antes como control), y el de la base de estilos: alto de los controles, peso y margen de los títulos, canario centrado con el nombre en la barra, filas centradas, botón de peligro, emails enteros al confirmar una baja y la pregunta que describe la confirmación, texto de la lista vacía, medida de la entradilla y botón principal de la verificación (con la regla de antes, o un botón sin la clase, como control), y el de las pantallas de acceso: clave del QR plegada, enlace con aspecto de botón, error dentro de la tarjeta sin caja y código de 5 cifras que no se envía (con su control), y el botón "Mostrar" de cada campo de contraseña, que vuelve a ocultarla al enviar (con su control), y el select sin la apariencia nativa: a 38 px como los campos, nativo en los colores forzados y con sitio para su flecha en las tablas, y la fila de invitar de Cuentas (cada uno con la regla de antes como control); y el sitio del denunciante: su hoja con los mismos valores que la de la SPA y sin `url()`, sus plantillas sin colores (con sus mutantes), y en Chromium sus cinco páginas a 320 px, con el aviso del dispositivo, la fuente del sistema y los controles de 38 px |
| `verificar_inyeccion.py` | Inyección SQL y validación de la frontera de entrada |
| `verificar_registro.py` | Registro del personal con Mailpit: de extremo a extremo, enumeración (respuesta, correo y tiempo, sin base de datos antes de responder), verificación, administración de solicitudes, límites por destinatario (15 minutos y día), logs sin rastro, el origen obligatorio, el registro con PostgreSQL parado y la herramienta del buzón (el enlace entero, o un error visible con Mailpit parado) |
| `verificar_externo.py` | El broker de canje con un Google falso (el nombre real por alias de red y una CA de prueba): definición del compose, endurecimiento, solo escucha en canje y solo atiende a la IP de la API, la URL de autorización exacta, el canje bueno y cada id_token o respuesta que no vale (401 o 503 con su EVENTO), redirecciones que no se siguen, certificado de otra CA, plazo total, saturación, entradas mal formadas, log sin datos sensibles, y Google sin configurar o a medias |
| `verificar_escaneos.py` | Secretos en Git, dependencias de Python y de npm, análisis estático, imágenes y SBOM |
| `verificar_unitarios.py` | Las pruebas unitarias (`tests/unit/`) en la imagen de la API, y mutantes que demuestran que fallan cuando deben |

Para ejecutarlas:

- Docker en marcha y los secretos generados.
- **La pila de Canario parada** (`docker compose down`, nunca con `-v`): esqueleto, arranque, denuncia, web, personal, sesión, SPA, inyección, registro y externo arrancan su propia copia con las mismas subredes fijas, y si están ocupadas se detienen con `PARADA`. `verificar_externo.py` no sale a internet: en su copia, la red `salida` es interna.
- `verificar_escaneos.py` necesita internet: descarga las herramientas fijadas y la base de datos de vulnerabilidades, y lee del registro de npm la fecha de publicación de lo que cambia en `spa/package-lock.json`.
- Todas las que construyen la imagen del proxy necesitan internet para compilar la SPA (`npm ci`). `verificar_spa.py` descarga además la imagen de Playwright (unos 2 GB la primera vez) y el paquete `playwright` con sus hashes.
- `verificar_unitarios.py` no necesita los secretos ni la pila parada: solo construye la imagen de la API.

```powershell
python tests\security\verificar_esquema.py
```

Cada batería usa un proyecto de Docker propio (`canario_<nombre>`), lo borra entero al terminar (contenedores, redes, volúmenes e imágenes locales) y comprueba que no ha modificado el repositorio. Termina con `RESULTADO GLOBAL: OK` o `NO OK`, y su código de salida es 0 solo si es OK.

### Pruebas unitarias

`tests/unit/` (19 ficheros, 248 pruebas, con `unittest` de la biblioteca estándar) prueba la lógica pura de `app/` sin base de datos, sin Redis y sin red: el cifrado y sus AAD, el relleno, el código de seguimiento, el TOTP con los vectores de RFC 4226 y RFC 6238, los tokens, la validación de la entrada, la redacción, el cursor y la máquina de estados, el limitador, las claves, la frontera HTTP, la traducción de errores a códigos HTTP, el contexto de empresa, la lógica del arranque verificado, el login uniforme, el JWT, las páginas del denunciante (origen, formulario y plantillas) y el registro del personal (mismas sentencias en todos los caminos, el trabajo después de responder con su fallo al log sin el email, origen obligatorio y correo sin inyección de cabeceras ni datos en el log) y la decisión con varias reglas del limitador, y el adaptador de Google del broker (configuración, URL de autorización exacta, cada comprobación del id_token y cada respuesta del token endpoint). Son la base de la pirámide: responden en segundos sobre la lógica, y las baterías comprueban el comportamiento con la imagen, PostgreSQL y Redis reales. El solape entre las dos capas es a propósito.

```powershell
python tests\security\verificar_unitarios.py
```

La batería ejecuta las pruebas dentro de la imagen de la API (el mismo Python y las mismas dependencias que en producción), sin red, de solo lectura y sin capacidades, y exige el número exacto de pruebas de cada fichero: un fichero que `unittest` no encuentre se saltaría en silencio. Antes comprueba sus controles (una prueba que falla da código 1 y un directorio vacío, 5). Después aplica 57 mutantes: copias de `app/` con una medida de seguridad rota a propósito (por ejemplo, que la redacción acepte posiciones negativas o que una conexión vuelva al pool con el contexto de otra empresa), y cada una debe hacer fallar la prueba exacta que la cubre. Una prueba que nunca se ha visto fallar no demuestra nada. Al añadir o quitar una prueba hay que actualizar a mano su número en la batería.

Para ejecutar solo las pruebas, sin controles ni mutantes (la imagen se borra al final; si se queda, la batería se detiene con `PARADA` al encontrarla):

```powershell
docker build -q -t canario_unitarios-api:rapido .
docker run --rm --network none --read-only --tmpfs /tmp --cap-drop ALL --mount "type=bind,src=$PWD\tests\unit,dst=/pruebas,readonly" --entrypoint python canario_unitarios-api:rapido -m unittest discover -s /pruebas -t /pruebas -v
docker image rm canario_unitarios-api:rapido
```

### Análisis estático: ruff

`ruff.toml` fija la versión de Python y el ancho de línea del proyecto, y explica la única regla desactivada. ruff no se instala en el equipo: se ejecuta con su imagen oficial fijada por versión y digest, sin red, de solo lectura y montando solo el código (nunca `secrets/`). Debe terminar con `All checks passed!`:

```powershell
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --user 10001:10001 --mount "type=bind,src=$PWD\app,dst=/io/app,readonly" --mount "type=bind,src=$PWD\tests,dst=/io/tests,readonly" --mount "type=bind,src=$PWD\scripts,dst=/io/scripts,readonly" --mount "type=bind,src=$PWD\ruff.toml,dst=/io/ruff.toml,readonly" -w /io ghcr.io/astral-sh/ruff:0.16.9@sha256:fd4a00e8f586c07495822a1c93702737b9a98d826b76d460caa514df7794f259 check --no-cache app tests scripts
```
