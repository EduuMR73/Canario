# Canario

Canario es un canal de denuncias anónimo multiempresa, pensado para cumplir la Ley 2/2023, reguladora de la protección de las personas que informen sobre infracciones normativas y de lucha contra la corrupción. Este repositorio contiene el backend: una API REST con FastAPI, PostgreSQL y Redis, detrás de un proxy Caddy, todo con Docker Compose. El denunciante tiene sus páginas, en HTML generado por la propia API y sin JavaScript. El personal tiene su propio frontend, separado del backend: una SPA en Angular (`spa/`) que Caddy sirve en su propio puerto y que habla con la API por JSON. Hoy permite entrar, activar una cuenta invitada y solicitar el acceso; las pantallas de trabajo de cada rol están en construcción.

Las amenazas consideradas, las decisiones de diseño y sus límites están en el [modelo de amenazas](docs/threat-model.md). Este README explica cómo ponerlo en marcha, operarlo y verificarlo.

## Qué hay en el repositorio

| Ruta | Contenido |
|---|---|
| `app/` | La API (`principal.py` y las rutas), las páginas del denunciante (`rutas_web.py` y `plantillas/`) y la herramienta de administración `gestion.py` |
| `db/` | Imagen de PostgreSQL, `pg_hba.conf` y el esquema, que se aplica al crear la base de datos (`db/init/`) |
| `proxy/` | Imagen y `Caddyfile` del proxy, el único punto de entrada, y los estáticos del sitio del denunciante (`proxy/estatico/`) |
| `spa/` | La SPA del personal (Angular 22.2.2), que la imagen del proxy compila y sirve en el 8445 |
| `scripts/generar_secretos.py` | Crea los secretos que faltan y comprueba el conjunto |
| `tests/security/` | Las doce baterías de pruebas de seguridad |
| `tests/unit/` | Las pruebas unitarias de la lógica pura de `app/` |
| `ruff.toml` | Configuración del análisis estático (ruff) |
| `docs/threat-model.md` | El modelo de amenazas |

## Requisitos

- Docker con el plugin `docker compose`. Se ha desarrollado y probado con Docker Desktop en Windows y Docker Compose v5.1.4.
- Python 3.12 en el anfitrión, para generar los secretos y ejecutar las baterías. Solo usan la biblioteca estándar.

Las imágenes están fijadas por versión y digest, así que no se descarga nada distinto de lo probado.

## Puesta en marcha

Las órdenes se ejecutan en PowerShell desde la raíz del repositorio. Como la ruta puede tener espacios, va siempre entre comillas.

1. Generar los secretos:

   ```powershell
   python scripts\generar_secretos.py
   ```

   Crea en `secrets/` solo los que faltan y nunca sobrescribe uno existente (si actualizas desde una versión anterior, vuelve a ejecutarlo: crea solo `clave_firma_tokens.txt`, la clave que firma los JWT del personal): una clave maestra regenerada dejaría ilegibles los datos ya cifrados. No imprime ningún valor. `secrets/` está fuera de Git; haz copia de seguridad de la clave maestra por un canal seguro, porque sin ella los datos no se pueden descifrar. Guárdala **separada** de las copias de la base de datos: una copia de la base de datos junto con la clave maestra descifra todo lo que contenga, también lo ya suprimido o tachado (modelo de amenazas, 8).

2. Arrancar:

   ```powershell
   docker compose up -d --build --wait
   ```

   `--wait` espera a que todos los servicios estén sanos. La API verifica la base de datos al arrancar y se niega a servir si algo no coincide con lo esperado (modelo de amenazas, 6.10).

3. Comprobar que responde. Caddy usa su propia autoridad de certificación (`tls internal`), sin internet ni ACME. Se copia su certificado raíz y se usa para validar la conexión, en lugar de desactivar la validación:

   ```powershell
   docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt "$env:TEMP\canario-ca.crt"
   python -c "import ssl, urllib.request; c = ssl.create_default_context(cafile=r'$env:TEMP\canario-ca.crt'); print(urllib.request.urlopen('https://localhost:8443/salud', context=c).read().decode())"
   ```

   El certificado se copia fuera del repositorio. Dentro del código de Python solo hay comillas simples, porque PowerShell 5 pierde las dobles internas al pasar argumentos a un programa.

Hay tres puertos publicados, todos solo en `127.0.0.1` y solo con el nombre `localhost` (cualquier otro `Host` recibe 421):

- `8443`: la API.
- `8444`: el sitio del denunciante, en otro origen: `https://localhost:8444/` (las páginas, más abajo) y su hoja de estilos.
- `8445`: la SPA del personal, en el suyo: `https://localhost:8445/`. Hoy tiene el acceso (entrar, activar una cuenta y solicitar el acceso, más abajo), el menú de cada rol, las pantallas del admin para las cuentas y las solicitudes, las de las denuncias para el admin y el instructor y la de la auditoría para el admin y el auditor, y reenvía la API del personal con la sesión en cookies.
 Para servir a internet hace falta un proxy o balanceador delante, que es decisión de cada despliegue (modelo de amenazas, 6.11 y 8).

Para parar sin perder datos:

```powershell
docker compose down
```

Nunca `docker compose down -v` en una instalación con datos: `-v` borra los volúmenes, es decir, la base de datos y la autoridad de certificación de Caddy.

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
| `GET /v1/personal/yo`, `POST /v1/personal/contrasena` | personal | Datos de la propia cuenta y cambio de contraseña (devuelve tokens nuevos) |
| `/v1/personal/usuarios...` | admin | Invitar, reinvitar, anular invitaciones y dar de baja |
| `/v1/personal/denuncias...` | admin e instructor (asignar, solo admin) | Listar, leer, asignar, cambiar de estado y escribir mensajes |
| `POST /v1/personal/denuncias/{id}/redaccion` y `.../mensajes/{secuencia}/redaccion` | admin con la denuncia asignada | Tachar datos que no deben conservarse (art. 32.2) |
| `GET /v1/personal/auditoria`, `/auditoria/recientes` y `/auditoria/verificacion` | admin y auditor | Leer la auditoría desde el principio (`desde`) o desde lo más reciente (`antes`), con el email de quien actúa y de la cuenta afectada, y verificar su cadena |
| `POST /v1/personal/registro` y `/registro/verificacion` | cualquiera | Pedir una cuenta del personal (empresa y email; siempre el mismo 202) y confirmar el email con el token del enlace |
| `GET /v1/personal/solicitudes`, `POST .../{id}/aprobacion`, `DELETE .../{id}` | admin | Ver las solicitudes verificadas, aprobarlas con un rol (la invitación va solo al email) o rechazarlas |

El código de seguimiento es lo único que identifica al denunciante: va en el cuerpo, nunca en la URL, para que no quede en ningún log.

### La sesión del personal en el navegador (8445)

La SPA del personal entra por `https://localhost:8445`, que solo reenvía `/v1/personal/*` a la API (modelo de amenazas, 6.3 y 6.11). Ahí los tokens no viajan en el cuerpo ni en `Authorization`, sino en tres cookies `__Host-` con `HttpOnly`, `Secure` y `SameSite=Strict`: ningún script de la página las lee. El cuerpo del login y de la renovación solo dice cuánto dura el acceso (`expira_en`). Para la SPA:

- Toda petición lleva `Sec-Fetch-Site: same-origin` (la pone el navegador) y, si no es GET ni HEAD, `Origin: https://localhost:8445`. Sin ellas, 403.
- La renovación se pide con `{}` en el cuerpo: el token va en su cookie. De una en una, también entre pestañas.
- Bearer y cookie a la vez dan 401.

Por el 8443 todo sigue igual: Bearer y los tokens en el cuerpo. El 8443 y el 8444 quitan las cookies en los dos sentidos, porque las cookies no se aíslan por puerto.

### La SPA del personal (`spa/`)

La imagen del proxy compila la SPA en una primera etapa con Node y copia solo el resultado a la imagen de Caddy, que no lleva Node (modelo de amenazas, 6.11). No hace falta Node en el anfitrión para arrancar Canario: `docker compose up -d --build` la compila. Lo que conviene saber al tocarla:

- Las dependencias se instalan sin scripts (`spa/.npmrc`) y con versiones exactas. Para cambiar una versión, en PowerShell desde `spa\`: `npm install --ignore-scripts <paquete>@<versión exacta>`, con una versión publicada hace al menos 14 días, y se commitean `package.json` y `package-lock.json`.
- Ningún componente declara estilos: todo el CSS va en `spa/src/styles.css`. Angular inyectaría los estilos de un componente con `<style>`, y la CSP lo bloquea.
- Ninguna ruta de la SPA lleva un punto: el proxy trata como fichero cualquier ruta con extensión y, si no existe, responde 404.
- Nada de `bypassSecurityTrust*` ni de asignar texto a `innerHTML`: Trusted Types lo bloquea en el navegador.
- Las páginas no llaman a `HttpClient`: todo pasa por los clientes de `spa/src/app/nucleo/` (`api.ts` para el acceso y la cuenta propia, `api-cuentas.ts` para las cuentas y las solicitudes, `api-denuncias.ts` para las denuncias). Un id que llega de la URL de la SPA no se pone en una ruta de la API sin comprobar que es un uuid: el router lo decodifica, y `..%2Fusuarios` llevaría la petición a otra ruta (modelo de amenazas, 6.11).
- Nada que gaste una lectura del expediente (`GET /v1/personal/denuncias/{id}`) se hace al cargar una página ni sale de la URL: cada lectura queda en la auditoría y cuenta para el tope diario de la cuenta. Una ruta que usa la sesión lleva la marca `RENOVABLE` (`conSesion()`, `nucleo/contexto.ts`); sin ella, un 401 no renueva. Así un login fallido no se repite ni cuenta doble en el bloqueo de la cuenta.
- Una página con sesión va dentro del armazón (`spa/src/app/app.routes.ts`) y declara sus roles en `nucleo/permisos.ts` (`MENU`). Sin roles no se abre para nadie. Es solo la interfaz: los permisos los decide la API.
- Un botón ocupado (con su petición en marcha) lleva `[attr.aria-disabled]="ocupado() || null"`, nunca `[disabled]`: a un botón `disabled` Chromium le quita el foco y no se lo devuelve. Sigue recibiendo clics, así que su acción empieza con una guarda (`if (ocupado()) return`). Si se añade uno, se suma a `BOTONES_OCUPADOS` en `tests/security/verificar_spa.py`, que cuenta los de cada fichero (modelo de amenazas, 6.11).
- Los colores solo se escriben en `:root` de `spa/src/styles.css`, como variables, y cada color va en los dos temas: el claro y el `:root` de `@media (prefers-color-scheme: dark)`. Si se añade una pareja de texto y fondo, se añade también a `PAREJAS_CONTRASTE` en `tests/security/verificar_spa.py`, que comprueba su contraste en los dos.
- Las plantillas tampoco escriben colores: los dibujos (`spa/src/app/marca/`: el canario y Leila) son SVG en la plantilla, nunca `<img>` (la CSP no tiene `img-src`), con sus colores en clases de la hoja. La única excepción es el QR, negro sobre blanco en los dos temas, y `COLORES_EN_PLANTILLAS` lleva la cuenta. Todo `<svg>` lleva `aria-hidden="true"` si es decorativo, o `role="img"` con `aria-label` si dice algo.
- El aspecto toma como referencia el de github.com (Primer, licencia MIT) sin copiar su código, sus iconos ni su marca: tarjeta estrecha en las páginas de acceso, barra oscura, tablas en una caja, el estado de cada denuncia como etiqueta con icono y Leila en las listas vacías y en las páginas fuera del armazón (no encontrada y no disponible). El sitio del denunciante (8444) tiene su propia hoja y no cambia.
- La fuente es Geist 1.7.2 (licencia SIL OFL 1.1, en `spa/src/fuentes/OFL.txt`), autoalojada. Para cambiarla: el fichero nuevo del release oficial y su sha256 en `SHA256_FUENTE` de `tests/security/verificar_spa.py`.
- Las pruebas unitarias (Vitest, `spa/src/app/**/*.spec.ts`) las ejecuta `tests/security/verificar_spa.py`, sin red, en la misma etapa de compilación del proxy.

| Página | Para qué |
|---|---|
| `/entrar` | Login: empresa, email, contraseña y código TOTP. `/` lleva aquí |
| `/activacion#<token>` | Activar una cuenta invitada: contraseña, QR para la aplicación de autenticación y primer código |
| `/registro` | Solicitar el acceso con la empresa y el email |
| `/registro/verificacion#<token>` | Confirmar el email desde el enlace del correo, al pulsar el botón |
| `/inicio` | Con sesión, para todos los roles: la cuenta y su rol, y el aviso si tiene una invitación abierta |
| `/cuentas` | Solo admin: invitar (el enlace de activación se muestra una vez, para entregarlo a mano), reinvitar, anular una invitación y dar de baja |
| `/solicitudes` | Solo admin: aprobar con un rol o rechazar las solicitudes con el email confirmado |
| `/denuncias` | Admin e instructor: el listado con filtro por estado. El admin ve todas y las asigna; el instructor, las suyas |
| `/denuncias/<id>` | Admin e instructor, con la denuncia asignada: abrir el expediente con un botón (cada lectura queda en la auditoría y cuenta para el tope diario), escribir al denunciante, cambiar el estado y, solo el admin, declararla no veraz |
| `/auditoria` | Admin y auditor: quién hizo qué, lo más reciente primero, con emails; cargar las anteriores, actualizar y verificar la cadena |
| `/cuenta` | Con sesión, para todos los roles: cambiar la contraseña, que cierra las demás sesiones |
| `/inicio` | Con sesión: el email, el rol y el aviso de una reinvitación; cerrar la sesión |

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

### Registro del personal y correo de desarrollo

Quien quiere una cuenta del personal la pide con su email; le llega un enlace para confirmarlo y, cuando un admin la aprueba con un rol, la invitación para activarla (modelo de amenazas, 6.3). Los enlaces apuntan a la SPA del personal, cuyo origen fija `CANARIO_ORIGEN_PERSONAL` en `docker-compose.yml` (obligatoria: sin ella la API no arranca). El token va en el fragmento (`#...`), así que la SPA lo lee y lo envía por `POST`.

En desarrollo los correos van a Mailpit, que no los entrega a nadie. Está en su propio perfil, en una red interna sin salida a internet y sin puertos publicados:

```powershell
docker compose --profile desarrollo up -d --build --wait
```

Para leer el buzón, desde un contenedor en esa red (con la imagen de la API, que trae Python):

```powershell
docker run --rm --network canario_correo --entrypoint python canario-api -c "import urllib.request; print(urllib.request.urlopen('http://mailpit:8025/api/v1/messages').read().decode())"
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

## Operación: `gestion`

Las operaciones de plataforma no están en la API. Las hace `gestion`, que es la misma imagen con otro punto de entrada, solo en la red de la base de datos y el único servicio con el secreto de `plataforma`. `docker compose up` no lo arranca nunca; se ejecuta a mano:

```powershell
docker compose run --rm gestion alta-empresa --nombre "Empresa S.L." --zona Europe/Madrid
docker compose run --rm gestion nueva-clave --empresa-id <uuid>
docker compose run --rm gestion alta-admin --identificador <32 hex> --email admin@empresa.es
docker compose run --rm gestion reinvitar-admin --identificador <32 hex> --email admin@empresa.es
docker compose run --rm gestion suprimir-caducadas
```

- **`alta-empresa`** da de alta la empresa con su clave de cifrado e imprime su identificador público, el que va en la ruta de las denuncias. La zona horaria es obligatoria: fija el calendario de las fechas y de los plazos legales. Si el segundo paso falla, la salida da la orden exacta para completarlo con `nueva-clave`.
- **`nueva-clave`** crea la versión siguiente de la clave de una empresa: completa un alta a medias o rota la clave.
- **`alta-admin`** emite la invitación del primer admin de una empresa, solo si no tiene ningún admin activado.
- **`suprimir-caducadas`** aplica la supresión legal y, en la misma ejecución, poda las solicitudes de registro cerradas o caducadas (más abajo).
- **`reinvitar-admin`** es la recuperación de emergencia de un admin activado: revoca en el acto sus sesiones y dispositivos y emite una invitación nueva. Solo se ejecuta tras verificar la petición fuera de banda, con el contacto que consta en el contrato y nunca con el que da quien la pide (modelo de amenazas, 6.3).

**El token de invitación es una credencial.** `alta-admin` y `reinvitar-admin` lo imprimen una sola vez, porque no hay correo. Caduca a las 72 horas y sirve una sola vez. Se entrega al titular por un canal seguro y distinto del de la petición, y no se pega en tickets, chats ni correos. Si el titular lo encuentra ya usado, alguien se le adelantó, y la auditoría de su empresa lo muestra.

### Códigos de salida

| Código | Significado | Qué hacer |
|---|---|---|
| 0 | Hecho | Nada |
| 75 | Solo `suprimir-caducadas`: quedaron denuncias que estaban en uso | Nada: la ejecución siguiente las suprime |
| 1 | Error (`ERROR:` en la salida de errores) o una orden que se niega a actuar | Leer el mensaje e investigar |
| 2 | Argumentos no válidos | Corregir la orden |

El 75 existe para que un programador de tareas avise solo de lo que hay que investigar: si "denuncia en uso" diera el mismo 1 que un error, el aviso saltaría también con lo normal y acabaría ignorado (modelo de amenazas, 6.14).

## Supresión legal: programarla cada hora

La ley obliga a borrar las denuncias a los tres meses si no se ha iniciado la investigación (art. 32.4), en todo caso a los diez años (art. 26.2) y, de inmediato, las que se declaran no veraces (art. 32.3). `suprimir-caducadas` es el único camino de borrado del sistema y **no se ejecuta sola**: hay que programarla cada hora. La frecuencia es el retraso máximo entre declarar una denuncia no veraz y destruirla; mientras tanto, la API ya no la muestra a nadie. Sin programarla, los plazos no se cumplen y el art. 32.3 se queda en un bloqueo.

La orden lleva `-f` con la ruta absoluta del `docker-compose.yml`, para que el proyecto sea siempre el `name: canario` del fichero, se lance desde donde se lance. **No se debe fijar `COMPOSE_PROJECT_NAME`** ni en el anfitrión ni en el entorno del programador: tiene prioridad sobre ese nombre, y con otro nombre Compose usaría volúmenes nuevos y vacíos, así que la supresión actuaría sobre otra base de datos sin dar ningún error (modelo de amenazas, 8).

### En producción: timer de systemd

Con la instalación en `/opt/canario` (ajusta la ruta, y la de `docker` con `command -v docker`):

`/etc/systemd/system/canario-supresion.service`

```ini
[Unit]
Description=Canario: supresion legal de denuncias (arts. 32.4, 26.2 y 32.3 de la Ley 2/2023)
# Unidad que avisa a quien opera; la define cada despliegue.
OnFailure=canario-aviso.service

[Service]
Type=oneshot
ExecStart=/usr/bin/docker compose -f /opt/canario/docker-compose.yml run --rm -T gestion suprimir-caducadas
# 75: quedaron denuncias en uso; la ejecución siguiente las suprime.
SuccessExitStatus=75
```

`/etc/systemd/system/canario-supresion.timer`

```ini
[Unit]
Description=Canario: supresion legal cada hora

[Timer]
OnCalendar=hourly
# Si la máquina estuvo apagada, lanza al arrancar la ejecución perdida.
# Solo funciona con OnCalendar=.
Persistent=true

[Install]
WantedBy=timers.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now canario-supresion.timer
systemctl list-timers canario-supresion.timer
```

- `-T` porque no hay terminal: Compose lo detecta solo, pero se pone explícito.
- `OnFailure=` no avisa por sí mismo: activa `canario-aviso.service`, que cada despliegue escribe con su sistema de avisos. Salta con cualquier código que no sea 0 ni 75.
- Quien puede ejecutar `docker` equivale a root. Los dos ficheros de las unidades solo pueden ser editables por root: si otro usuario pudiera cambiar `ExecStart`, tendría una vía de escalada.
- Con cron también se puede, pero cron no distingue códigos de salida: hace falta un envoltorio que trate el 75 como éxito y avise del resto. Por eso se recomienda systemd.

**Lo que esto no cubre:** vigilar el código de salida detecta la ejecución que falla, no la que nunca llega a correr (anfitrión caído, Docker parado, timer deshabilitado). En producción hace falta además una alerta por ausencia, que salte cuando deja de llegar la señal de éxito, desde fuera del anfitrión. Depende de la monitorización de cada despliegue y este repositorio no la trae (modelo de amenazas, 8).

### En desarrollo: Windows

En Windows se ejecuta a mano cuando haga falta:

```powershell
docker compose run --rm gestion suprimir-caducadas
```

El Programador de tareas de Windows no sirve para producción: según el foro y el roadmap de Docker, Docker Desktop necesita una sesión de usuario abierta, y sin Docker la tarea no corre. No hay documentación oficial que lo confirme ni lo desmienta.

## Protección de datos: log y copias de seguridad

Dos acciones del personal destruyen datos sin vuelta atrás: declarar una denuncia no veraz (art. 32.3) y tachar una parte de su texto (art. 32.2). Cada una deja una línea en el log de la API, sin contenido:

```
EVENTO declaracion_no_veraz: empresa=<uuid> cuenta=<uuid> denuncia=<uuid>
EVENTO redaccion: empresa=<uuid> cuenta=<uuid> denuncia=<uuid> mensaje=<secuencia o -> tramos=<desde>+<longitud>,...
```

Si se restaura una copia de la base de datos, todo lo declarado no veraz o tachado después de la copia vuelve a aparecer (modelo de amenazas, 8). Esas líneas son el registro para volver a aplicarlo, así que en producción:

- **El log de la API sale del anfitrión** y se conserva al menos tanto como las copias. El compose lo rota en 3 ficheros de 10 MB: sin enviarlo fuera, se pierde antes que la copia. Cómo enviarlo depende de cada despliegue.
- **Tras restaurar una copia**, antes de nada:
  1. Busca en ese log las líneas `EVENTO declaracion_no_veraz` y `EVENTO redaccion` posteriores a la fecha de la copia.
  2. Por cada declaración, un admin se asigna la denuncia y la vuelve a declarar no veraz.
  3. Por cada redacción, el admin asignado vuelve a tachar los mismos tramos: el evento da la posición y la longitud, y el texto lo ve al leer la denuncia.
  4. Ejecuta `suprimir-caducadas`. Las denuncias caducadas se suprimen solas; las no veraces, con esta ejecución.

## Pruebas de seguridad

Doce baterías, una por área. Cada prueba negativa lleva su control positivo: si el control falla, el resultado es `SIN CONCLUSION`, nunca `PASA`. Los resultados esperados están escritos como literales en la propia batería, no derivados del código que se prueba.

| Batería | Qué prueba |
|---|---|
| `verificar_esqueleto.py` | Proxy y API: sin salida a internet, solo los tres puertos del proxy, cabeceras, 421, estáticos del denunciante (sin rangos ni salir de `/srv`), logs sin IP, endurecimiento de los contenedores |
| `verificar_web.py` | Sitio del denunciante: lo que el 8444 reenvía a la API (con una aplicación de eco; las cookies, solo por el 8445) y las páginas con la API real: escapado, formularios de otro origen, cuerpo estricto, NUL y logs sin rastro |
| `verificar_arranque.py` | Conexión a PostgreSQL con secretos y el arranque verificado de la API |
| `verificar_esquema.py` | Esquema, RLS entre empresas, permisos, auditoría encadenada y supresión legal en la base de datos |
| `verificar_denuncia.py` | Cifrado, denuncia anónima, seguimiento, mensajes, limitador y supresión por la API y `gestion` |
| `verificar_personal.py` | Identidad del personal, login, bloqueos, sesiones, administración, instrucción, no veraz (art. 32.3) y la auditoría por la API (emails y páginas) |
| `verificar_sesion.py` | La sesión del personal en el navegador por el 8445: tokens solo en cookies con sus atributos exactos, CSRF desde otro puerto, rotación y reutilización, cierre, cookies que no salen por el 8443 y logs sin tokens |
| `verificar_spa.py` | La SPA del personal en el 8445: cabeceras y CSP exactas, nada en línea (con un mutante), imagen sin Node, contexto de compilación aislado, rutas, las pruebas unitarias sin red (con siete mutantes), el contraste de la base visual en los dos temas, la fuente servida con su sha256, los botones ocupados con `aria-disabled` (con un mutante), las plantillas sin colores fuera del inventario y todo SVG decorativo o con nombre (con dos mutantes), y en un Chromium real la carga sin violaciones de la CSP, Trusted Types, la activación, el login, la renovación entre pestañas, el cierre, el registro con su correo, las pantallas por rol (menú, páginas de otro rol, solicitudes, cuentas y contraseña), las denuncias (listado y asignación, expediente que no se lee solo, XSS almacenado con un mutante, id con `..`, mensajes, estados, no veraz y "atrás" tras cerrar la sesión) la auditoría (emails, páginas, actualizar, verificación y un email con HTML con un mutante) y los botones ocupados (el foco tras un login fallido y un solo envío con un doble clic, con dos mutantes, y "Cargar más" hasta el final), y la fuente cargada, el tema oscuro, las páginas a 320 px sin desbordar y Leila decorativa en la lista vacía y en la 404 (en "no disponible", con una prueba unitaria) |
| `verificar_inyeccion.py` | Inyección SQL y validación de la frontera de entrada |
| `verificar_registro.py` | Registro del personal con Mailpit: de extremo a extremo, enumeración (respuesta, correo y tiempo, sin base de datos antes de responder), verificación, administración de solicitudes, límites por destinatario (15 minutos y día), logs sin rastro, el origen obligatorio y el registro con PostgreSQL parado |
| `verificar_escaneos.py` | Secretos en Git, dependencias de Python y de npm, análisis estático, imágenes y SBOM |
| `verificar_unitarios.py` | Las pruebas unitarias (`tests/unit/`) en la imagen de la API, y mutantes que demuestran que fallan cuando deben |

Para ejecutarlas:

- Docker en marcha y los secretos generados.
- **La pila de Canario parada** (`docker compose down`, nunca con `-v`): esqueleto, arranque, denuncia, web, personal, sesión, SPA, inyección y registro arrancan su propia copia con las mismas subredes fijas, y si están ocupadas se detienen con `PARADA`.
- `verificar_escaneos.py` necesita internet: descarga las herramientas fijadas y la base de datos de vulnerabilidades.
- Todas las que construyen la imagen del proxy necesitan internet para compilar la SPA (`npm ci`). `verificar_spa.py` descarga además la imagen de Playwright (unos 2 GB la primera vez) y el paquete `playwright` con sus hashes.
- `verificar_unitarios.py` no necesita los secretos ni la pila parada: solo construye la imagen de la API.

```powershell
python tests\security\verificar_esquema.py
```

Cada batería usa un proyecto de Docker propio (`canario_<nombre>`), lo borra entero al terminar (contenedores, redes, volúmenes e imágenes locales) y comprueba que no ha modificado el repositorio. Termina con `RESULTADO GLOBAL: OK` o `NO OK`, y su código de salida es 0 solo si es OK.

### Pruebas unitarias

`tests/unit/` (16 ficheros, 195 pruebas, con `unittest` de la biblioteca estándar) prueba la lógica pura de `app/` sin base de datos, sin Redis y sin red: el cifrado y sus AAD, el relleno, el código de seguimiento, el TOTP con los vectores de RFC 4226 y RFC 6238, los tokens, la validación de la entrada, la redacción, el cursor y la máquina de estados, el limitador, las claves, la frontera HTTP, la traducción de errores a códigos HTTP, el contexto de empresa, la lógica del arranque verificado, el login uniforme, el JWT, las páginas del denunciante (origen, formulario y plantillas) y el registro del personal (mismas sentencias en todos los caminos, el trabajo después de responder con su fallo al log sin el email, origen obligatorio y correo sin inyección de cabeceras ni datos en el log) y la decisión con varias reglas del limitador. Son la base de la pirámide: responden en segundos sobre la lógica, y las baterías comprueban el comportamiento con la imagen, PostgreSQL y Redis reales. El solape entre las dos capas es a propósito.

```powershell
python tests\security\verificar_unitarios.py
```

La batería ejecuta las pruebas dentro de la imagen de la API (el mismo Python y las mismas dependencias que en producción), sin red, de solo lectura y sin capacidades, y exige el número exacto de pruebas de cada fichero: un fichero que `unittest` no encuentre se saltaría en silencio. Antes comprueba sus controles (una prueba que falla da código 1 y un directorio vacío, 5). Después aplica 44 mutantes: copias de `app/` con una medida de seguridad rota a propósito (por ejemplo, que la redacción acepte posiciones negativas o que una conexión vuelva al pool con el contexto de otra empresa), y cada una debe hacer fallar la prueba exacta que la cubre. Una prueba que nunca se ha visto fallar no demuestra nada. Al añadir o quitar una prueba hay que actualizar a mano su número en la batería.

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
