# Referencia técnica: API, SPA y sitio del denunciante

Detalle de las interfaces de Canario. La puesta en marcha y el manual de uso están en el [README](../README.md); las decisiones y sus porqués, en el [modelo de amenazas](threat-model.md).

## La API

Sin `/docs`, `/redoc` ni `/openapi.json`: no se publica el esquema de la API.

| Ruta | Quién | Para qué |
|---|---|---|
| `GET /salud` | cualquiera | Vivacidad |
| `POST /v1/empresas/{identificador}/denuncias` | denunciante | Presentar una denuncia; devuelve el código de seguimiento |
| `POST /v1/seguimiento` | denunciante | Consultar el estado y la conversación con el código |
| `POST /v1/seguimiento/mensajes` | denunciante | Enviar un mensaje con el código |
| `POST /v1/personal/activacion` y `/activacion/confirmar` | personal | Activar la cuenta con la invitación: contraseña y TOTP |
| `POST /v1/personal/sesiones`, `POST /v1/personal/sesiones/renovacion`, `DELETE /v1/personal/sesiones/actual` | personal | Entrar (JWT de acceso de 5 minutos y token de renovación), renovar y salir |
| `GET /v1/personal/yo`, `POST /v1/personal/contrasena` | personal | Datos de la propia cuenta, con el enlace del canal de su empresa, y cambio de contraseña (devuelve tokens nuevos) |
| `/v1/personal/usuarios...` | admin | Invitar, reinvitar, anular invitaciones y dar de baja; invitar, reinvitar y dar de baja llevan `codigo_totp` en el cuerpo |
| `/v1/personal/denuncias...` | admin e instructor (asignar, solo admin) | Listar, leer, asignar, cambiar de estado y escribir mensajes |
| `POST /v1/personal/denuncias/{id}/redaccion` y `.../mensajes/{secuencia}/redaccion` | admin con la denuncia asignada | Tachar datos que no deben conservarse (art. 32.2) |
| `GET /v1/personal/auditoria`, `/auditoria/recientes` y `/auditoria/verificacion` | admin y auditor | Leer la auditoría desde el principio (`desde`) o desde lo más reciente (`antes`), con el email de quien actúa y de la cuenta afectada, y verificar su cadena |
| `POST /v1/personal/registro` y `/registro/verificacion` | cualquiera | Pedir una cuenta del personal (empresa y email; siempre el mismo 202) y confirmar el email con el token del enlace |
| `GET /v1/personal/solicitudes`, `POST .../{id}/aprobacion`, `DELETE .../{id}` | admin | Ver las solicitudes verificadas, aprobarlas con un rol y `codigo_totp` (la invitación va solo al email) o rechazarlas |
| `GET /v1/personal/externo/proveedores` | cualquiera (solo navegador) | Los proveedores externos configurados en el broker; la SPA solo pinta el botón de esos |
| `POST /v1/personal/externo/google/inicio` y `GET .../google/vuelta` | personal (solo navegador) | Ir a Google con un dispositivo de confianza vigente de la empresa (sin él, 409) y volver: la vuelta comprueba el flujo de su cookie, canjea por medio del broker y responde siempre un 303 a una página fija de la SPA |
| `POST /v1/personal/sesiones/externa` | personal (solo navegador) | Entrar con el ticket de la vuelta, el dispositivo y un código TOTP; las mismas cookies que el login con contraseña |
| `POST /v1/personal/externo/google/vinculo/inicio`, `POST .../google/vinculo` y `DELETE .../google/vinculo` | personal con sesión (solo navegador) | Vincular la cuenta de Google (pide un código) y desvincularla (también); los dos avisan por correo al titular y a quienes vigilan |

El código de seguimiento es lo único que identifica al denunciante: va en el cuerpo, nunca en la URL, para que no quede en ningún log.

### La sesión del personal en el navegador (8445)

La SPA del personal entra por `https://localhost:8445`, que solo reenvía `/v1/personal/*` a la API (modelo de amenazas, 6.3 y 6.11). Ahí los tokens no viajan en el cuerpo ni en `Authorization`, sino en tres cookies `__Host-` con `HttpOnly`, `Secure` y `SameSite=Strict`: ningún script de la página las lee. El cuerpo del login y de la renovación solo lleva segundos: cuánto dura el acceso (`expira_en`) y cuánto le queda a la sesión hasta el cierre por inactividad y hasta las 8 horas (`inactividad_en`, `caduca_en`), para avisar antes. `/yo` y el cambio de contraseña también dan estos dos últimos. Para la SPA:

- Toda petición lleva `Sec-Fetch-Site: same-origin` (la pone el navegador) y, si no es GET ni HEAD, `Origin: https://localhost:8445`. Sin ellas, 403.
- La renovación se pide con `{}` en el cuerpo: el token va en su cookie. De una en una, también entre pestañas.
- Bearer y cookie a la vez dan 401.

Por el 8443 todo sigue igual: Bearer y los tokens en el cuerpo. El 8443 y el 8444 quitan las cookies en los dos sentidos, porque las cookies no se aíslan por puerto.

### La SPA del personal (`spa/`)

La imagen del proxy compila la SPA en una primera etapa con Node y copia solo el resultado a la imagen de Caddy, que no lleva Node (modelo de amenazas, 6.11). No hace falta Node en el anfitrión para arrancar Canario: `docker compose up -d --build` la compila. Lo que conviene saber al tocarla:

- Las dependencias se instalan sin scripts (`spa/.npmrc`) y con versiones exactas. npm nunca se ejecuta en el equipo de desarrollo: ahí están `secrets/` y Docker Desktop, y el código de un paquete correría con ese alcance (`docs/threat-model.md`, 6.17). Para cambiar una versión se trabaja sobre una copia de `package.json`, `package-lock.json` y `.npmrc` en un directorio temporal, con la imagen de Node de `proxy/Dockerfile`, y solo se resuelve el lock (`--package-lock-only`, sin `node_modules`). `--before` con una fecha de hace al menos 14 días hace que tampoco entre ninguna transitiva más nueva. En PowerShell, desde ese directorio:

  ```powershell
  docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges --user 1000:1000 -e HOME=/tmp -e npm_config_cache=/tmp/npm --tmpfs /tmp:size=512m --mount "type=bind,src=$PWD,dst=/spa" -w /spa node:24.20.0-alpine3.23@sha256:0388af2af070cd4736a1567cfed02469ba117848845b4165d87a333edb53d2ca npm install --ignore-scripts --package-lock-only --no-audit --no-fund --before=<AAAA-MM-DD> <paquete>@<versión exacta>
  ```

  Después se copian `package.json` y `package-lock.json` a `spa/` y se commitean. `verificar_escaneos.py` (j) lista lo que cambió en el lock con su fecha y falla si algo tiene menos de 14 días.
- `overrides` de `spa/package.json` fuerza vite 8.3.4 y zod 4.6.6: `@angular/build` 22.2.x fija vite 8.3.0, con CVE-2026-112942, y `@angular/cli` 22.2.x fija zod 4.6.5, con CVE-2023-54404. Cada uno se retira cuando una versión estable del paquete que lo fija traiga la versión arreglada (la batería falla para avisarlo).
- Ningún componente declara estilos: todo el CSS va en `spa/src/styles.css`. Angular inyectaría los estilos de un componente con `<style>`, y la CSP lo bloquea.
- Ninguna ruta de la SPA lleva un punto: el proxy trata como fichero cualquier ruta con extensión y, si no existe, responde 404.
- Nada de `bypassSecurityTrust*` ni de asignar texto a `innerHTML`: Trusted Types lo bloquea en el navegador.
- Las páginas no llaman a `HttpClient`: todo pasa por los clientes de `spa/src/app/nucleo/` (`api.ts` para el acceso y la cuenta propia, `api-cuentas.ts` para las cuentas y las solicitudes, `api-denuncias.ts` para las denuncias). Un id que llega de la URL de la SPA no se pone en una ruta de la API sin comprobar que es un uuid: el router lo decodifica, y `..%2Fusuarios` llevaría la petición a otra ruta (modelo de amenazas, 6.11).
- Nada que gaste una lectura del expediente (`GET /v1/personal/denuncias/{id}`) se hace al cargar una página ni sale de la URL: cada lectura queda en la auditoría y cuenta para el tope diario de la cuenta. Una ruta que usa la sesión lleva la marca `RENOVABLE` (`conSesion()`, `nucleo/contexto.ts`); sin ella, un 401 no renueva. Así un login fallido no se repite ni cuenta doble en el bloqueo de la cuenta.
- Una página con sesión va dentro del armazón (`spa/src/app/app.routes.ts`) y declara sus roles en `nucleo/permisos.ts` (`MENU`). Sin roles no se abre para nadie. Es solo la interfaz: los permisos los decide la API.
- Un botón ocupado (con su petición en marcha) lleva `[attr.aria-disabled]="ocupado() || null"`, nunca `[disabled]`: a un botón `disabled` Chromium le quita el foco y no se lo devuelve. Sigue recibiendo clics, así que su acción empieza con una guarda (`if (ocupado()) return`). Si se añade uno, se suma a `BOTONES_OCUPADOS` en `tests/security/verificar_spa.py`, que cuenta los de cada fichero (modelo de amenazas, 6.11).
- Todo campo de contraseña va dentro de un `<span class="con-mostrar">` con su botón "Mostrar": `<button class="mostrar" [appMostrarContrasena]="campo" nombre="Mostrar la contraseña ...">`, con `#campo` en el `<input>` (`nucleo/mostrar-contrasena.ts`). El componente pone `type="button"` y `aria-pressed`, y al enviar el formulario devuelve el campo a `type="password"`, para que el navegador no guarde la contraseña en claro. Si se añade uno, se añade también a `MOSTRAR_*` en `tests/security/verificar_spa.py`.
- Los colores solo se escriben en `:root` de `spa/src/styles.css`, como variables, y cada color va en los dos temas: el claro y el `:root` de `@media (prefers-color-scheme: dark)`. Si se añade una pareja de texto y fondo, se añade también a `PAREJAS_CONTRASTE` en `tests/security/verificar_spa.py`, que comprueba su contraste en los dos.
- Las plantillas tampoco escriben colores: los dibujos (`spa/src/app/marca/`: el canario y Leila) son SVG en la plantilla, nunca `<img>` (la CSP no tiene `img-src`), con sus colores en clases de la hoja. La única excepción es el QR, negro sobre blanco en los dos temas, y `COLORES_EN_PLANTILLAS` lleva la cuenta. Todo `<svg>` lleva `aria-hidden="true"` si es decorativo, o `role="img"` con `aria-label` si dice algo.
- El aspecto toma como referencia el de github.com (Primer, licencia MIT) sin copiar su código, sus iconos ni su marca: tarjeta estrecha en las páginas de acceso, barra oscura, tablas en una caja, el estado de cada denuncia como etiqueta con icono y Leila en las listas vacías y en las páginas fuera del armazón (no encontrada y no disponible). Los títulos tienen su escala explícita en la hoja (h1, h2 y h3); en la barra, cada párrafo quita su margen en su clase, sin reseteos por elemento que ganen por especificidad. El sitio del denunciante (8444) tiene el mismo aspecto desde su propia hoja, con la fuente del sistema (más abajo).
- La fuente es Geist 1.7.2 (licencia SIL OFL 1.1, en `spa/src/fuentes/OFL.txt`), autoalojada. Para cambiarla: el fichero nuevo del release oficial y su sha256 en `SHA256_FUENTE` de `tests/security/verificar_spa.py`.
- Las pruebas unitarias (Vitest, `spa/src/app/**/*.spec.ts`) las ejecuta `tests/security/verificar_spa.py`, sin red, en la misma etapa de compilación del proxy.

| Página | Para qué |
|---|---|
| `/entrar` | Login: empresa, email, contraseña y código TOTP. `/` lleva aquí |
| `/activacion#<token>` | Activar una cuenta invitada: contraseña, QR para la aplicación de autenticación y primer código |
| `/registro` | Solicitar el acceso con la empresa y el email |
| `/registro/verificacion#<token>` | Confirmar el email desde el enlace del correo, al pulsar el botón |
| `/inicio` | Con sesión, para todos los roles: los accesos de su rol, en tarjetas con una descripción, y el aviso si tiene una invitación abierta. El admin y el instructor ven además los plazos de la Ley 2/2023 (respuesta, art. 9.2.d, y supresión, art. 32.4). El email, el rol y cerrar la sesión van en la barra de todas las páginas con sesión |
| `/cuentas` | Solo admin: invitar (el enlace de activación se muestra una vez, para entregarlo a mano), reinvitar, anular una invitación y dar de baja |
| `/solicitudes` | Solo admin: aprobar con un rol o rechazar las solicitudes con el email confirmado |
| `/denuncias` | Admin e instructor: el listado con filtro por estado. El admin ve todas y las asigna; el instructor, las suyas |
| `/denuncias/<id>` | Admin e instructor, con la denuncia asignada: abrir el expediente con un botón (cada lectura queda en la auditoría y cuenta para el tope diario), escribir al denunciante, cambiar el estado y, solo el admin, declararla no veraz |
| `/auditoria` | Admin y auditor: quién hizo qué, lo más reciente primero, con emails; cargar las anteriores, actualizar y verificar la cadena |
| `/cuenta` | Con sesión, para todos los roles: cambiar la contraseña, que cierra las demás sesiones |

Invitar, reinvitar, dar de baja y aprobar una solicitud piden en el cuerpo un código TOTP recién escrito (`codigo_totp`): con la sesión del admin sola ya no se crea un admin propio ni se da de baja al legítimo (modelo de amenazas, 6.3). Cada código vale una sola vez, así que dos operaciones seguidas esperan al código siguiente. Un código malo o repetido da 401 sin `WWW-Authenticate` (no falla la sesión, sino el código) y cuenta para el bloqueo del dispositivo.

El token de los enlaces de correo sale de la URL en cuanto se abre la página y solo vive en memoria: si se recarga a mitad de la activación, hay que volver a abrir el enlace. Lo mismo el expediente de una denuncia: al recargar, hay que volver a abrirlo. La redacción (tachar una parte del texto, modelo de amenazas, 6.18) no tiene pantalla todavía: se hace por la API.

El personal tiene tres roles: `admin` (gestiona las cuentas y asigna las denuncias), `instructor` (instruye las denuncias que tiene asignadas) y `auditor` (lee la auditoría y verifica su cadena, nunca el contenido). El contenido de una denuncia solo lo lee quien la tiene asignada, y a un auditor no se le puede asignar ninguna: lo impide la API y, por debajo, un trigger de la base de datos (modelo de amenazas, 6.15).

Cada cuenta puede abrir **50 denuncias distintas al día** (el día de la empresa); releer una ya abierta no cuenta y sigue permitido después. La lectura devuelve `lecturas: {hoy, tope}`. Pasado el tope, una denuncia nueva da 429 con un mensaje que lo explica y `Retry-After` hasta la medianoche de la empresa. Al llegar a la 20.ª y a la 50.ª, los demás admins y los auditores de la empresa reciben un correo, y también cada vez que se activa una cuenta (nueva, reactivada o recuperada). Si una cola grande de denuncias nuevas hace llegar a un admin al tope, otro admin puede repartirla. Lo que queda en el log de la API, sin ids de denuncias:

```
EVENTO limite_lecturas_aviso: empresa=<uuid> cuenta=<uuid> lecturas=20 destinatarios=<n>
EVENTO limite_lecturas_tope: empresa=<uuid> cuenta=<uuid> lecturas=50 destinatarios=<n>
EVENTO aviso_sin_destinatario: tipo=<aviso_lecturas o aviso_activacion> empresa=<uuid>
```

`aviso_sin_destinatario` es normal al activar el primer admin de una empresa. En otro caso, significa que la empresa no tiene a nadie más que vigile: conviene invitar a un auditor o a un segundo admin.

### Las páginas del denunciante (8444)

Formularios HTML sin JavaScript. Las genera la API bajo `/web` (`app/rutas_web.py`) con las mismas funciones que `/v1`, y Caddy las sirve en el 8444 sin el prefijo; desde el 8443, `/web` da 404.

| Página | Para qué |
|---|---|
| `GET /` | Inicio |
| `GET /empresas/{identificador}` y `POST .../denuncias` | Formulario de denuncia de una empresa; al enviarlo, el código de seguimiento |
| `GET /seguimiento` y `POST /seguimiento/consulta` | Consultar una denuncia con su código |
| `POST /seguimiento/mensajes` | Enviar un mensaje desde la consulta |

El inicio, el formulario y la consulta llevan los consejos de anonimato en una lista: un dispositivo y una conexión que no sean de la empresa, Tor Browser si se puede y no escribir datos que identifiquen, porque desde un equipo o una red de la empresa se puede saber que alguien ha entrado en el canal (modelo de amenazas, 6.1). El texto está una sola vez, en `app/plantillas/macros.html`. El inicio dice además que se puede informar ante la Autoridad Independiente de Protección del Informante, el canal externo de la ley, con un enlace a su dominio oficial.

En la SPA, todo el personal (admin, instructor y auditor) ve en su inicio el enlace del canal de su empresa, con un botón para copiarlo y un enlace que abre el formulario en una pestaña nueva: la empresa debe publicarlo en la página de inicio de su web (art. 25 de la Ley 2/2023).

El aspecto es el de la SPA (`proxy/estatico/canario.css`): la barra oscura con el canario, los mismos colores en los dos temas, los botones y el select de 38 px. Las variables se llaman igual que en `spa/src/styles.css` y valen lo mismo; si se cambia un color en la SPA, hay que cambiarlo aquí, y la batería de la SPA (k) falla si no. La fuente es la del sistema, no Geist: estas páginas no se guardan en caché, Tor Browser desactiva algunas fuentes y la CSP del sitio no cambia (modelo de amenazas, 6.11).

### Registro del personal y correo de desarrollo

Quien quiere una cuenta del personal la pide con su email; le llega un enlace para confirmarlo y, cuando un admin la aprueba con un rol, la invitación para activarla (modelo de amenazas, 6.3). Los enlaces apuntan a la SPA del personal, cuyo origen fija `CANARIO_ORIGEN_PERSONAL` en `docker-compose.yml` (obligatoria: sin ella la API no arranca). El token va en el fragmento (`#...`), así que la SPA lo lee y lo envía por `POST`.

En desarrollo los correos van a Mailpit, que no los entrega a nadie. Está en su propio perfil, en una red interna sin salida a internet y sin puertos publicados:

```powershell
docker compose --profile desarrollo up -d --build --wait
```

Para leer el buzón, en PowerShell desde la raíz del repositorio:

```powershell
python scripts/buzon.py
```

Enseña los 10 últimos correos, del más nuevo al más antiguo, con la fecha, el destinatario, el asunto y cada enlace en su propia línea (en Windows Terminal se abre con Ctrl+clic); `--limite 30` enseña más, y `--texto` añade el texto entero de cada correo, para los avisos, que no llevan enlace. Antes de imprimir cambia por `?` cualquier carácter de control que traiga un correo, para que no llegue a la terminal (modelo de amenazas, 8). Los lee desde un contenedor desechable en esa red, con la imagen de la API, de solo lectura y sin capacidades, y no borra nada. Si Mailpit no está en marcha, lo dice y sale con código 1. Los enlaces llevan tokens de un solo uso: la salida es para la terminal de quien la pide. La interfaz web de Mailpit no se publica a propósito (modelo de amenazas, 8).

Para parar la pila con Mailpit, hay que nombrar el perfil: `docker compose down` sin él deja Mailpit en marcha.

```powershell
docker compose --profile desarrollo down
```

`POST /v1/personal/registro` responde el 202 en el acto: guardar la solicitud y enviar el correo se hace después de responder, para que el tiempo no diga si la empresa existe o el email tiene cuenta. Por email caben 3 solicitudes cada 15 minutos y 10 al día (UTC); pasado eso, 429 con `Retry-After`. Si alguien agota el cupo de un email ajeno, su dueño puede esperar o pedir a un admin que le invite (`POST /v1/personal/usuarios`).

**Antes de aprobar una solicitud**, el admin confirma por un canal interno de la empresa (su directorio, el responsable de esa persona) que quien la pide trabaja allí y debe tener ese rol; si no puede confirmarlo, la rechaza. Que alguien controle un email no demuestra que sea de la empresa (modelo de amenazas, 6.3).

Lo que el registro deja en el log de la API, siempre sin el email:

```
EVENTO limite_destinatario: regla=<destinatario o destinatario_dia>
EVENTO registro_fallido: error=<clase del error>
EVENTO correo_fallido: tipo=<tipo de correo> error=<clase del error>
EVENTO correo_descartado: tipo=<tipo de correo> motivo=envios_simultaneos
```

`registro_fallido` significa que alguien recibió su 202 y no le llegará nada (por ejemplo, PostgreSQL no respondía); el mensaje del 202 le dice que lo vuelva a pedir. Hoy nadie revisa estas líneas: en producción, el log tiene que salir del anfitrión y alguien tiene que mirarlo (modelo de amenazas, 8).

Sin Mailpit, el registro responde igual y cada correo deja `EVENTO correo_fallido`, también los avisos de lecturas y de activación (`tipo=aviso_lecturas` y `tipo=aviso_activacion`). La salida SMTP de producción no es parte de esta entrega; su diseño está en el modelo de amenazas (8).

### Origen del sitio del denunciante

Cada formulario solo se acepta desde el propio sitio (cabecera `Origin`). Si el sitio se publica con otro nombre, la variable `CANARIO_ORIGEN_WEB` de la API debe llevar su origen exacto (por ejemplo `https://canal.ejemplo.org`); la API lo registra al arrancar (`ORIGEN WEB (configurado): ...`) y no arranca con un valor que un navegador nunca enviaría (modelo de amenazas, 6.11).
