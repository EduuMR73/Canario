# Operación

Cómo se opera Canario fuera de la demo: la puesta en marcha completa (sin el perfil de desarrollo), la herramienta `gestion`, la supresión legal programada y el log y las copias de seguridad. La instalación básica está en el [README](../README.md).

## Puesta en marcha

Las órdenes se ejecutan en PowerShell desde la raíz del repositorio. Como la ruta puede tener espacios, va siempre entre comillas.

1. Generar los secretos:

   ```powershell
   python scripts\generar_secretos.py
   ```

   Crea en `secrets/` solo los que faltan y nunca sobrescribe uno existente (si actualizas desde una versión anterior, vuelve a ejecutarlo: crea solo los que falten, como `clave_hmac_identidades.txt` y `clave_flujo_externo.txt`, las dos claves del login externo, o `smtp_usuario.txt` y `smtp_contrasena.txt`, la credencial del cartero con su marcador; sin ellas, `docker compose` no arranca): una clave maestra regenerada dejaría ilegibles los datos ya cifrados. No imprime ningún valor. `secrets/` está fuera de Git; haz copia de seguridad de la clave maestra por un canal seguro, porque sin ella los datos no se pueden descifrar. Guárdala **separada** de las copias de la base de datos: una copia de la base de datos junto con la clave maestra descifra todo lo que contenga, también lo ya suprimido o tachado (modelo de amenazas, 8).

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
- `8444`: el sitio del denunciante, en otro origen: `https://localhost:8444/` (las páginas, en [api.md](api.md)) y su hoja de estilos.
- `8445`: la SPA del personal, en el suyo: `https://localhost:8445/`. Hoy tiene el acceso (entrar, también con Google si está configurado, activar una cuenta y solicitar el acceso, en [api.md](api.md)), el menú de cada rol, las pantallas del admin para las cuentas y las solicitudes, las de las denuncias para el admin y el instructor y la de la auditoría para el admin y el auditor, y reenvía la API del personal con la sesión en cookies.
 Para servir a internet hace falta un proxy delante: el despliegue de producción, detrás del Traefik de Dokploy, está en [Producción en el VPS](#producción-en-el-vps-dokploy).

Para parar sin perder datos:

```powershell
docker compose down
```

Nunca `docker compose down -v` en una instalación con datos: `-v` borra los volúmenes, es decir, la base de datos y la autoridad de certificación de Caddy.

**Actualizar una instalación existente.** Canario no tiene migraciones: el esquema de `db/init/` solo se aplica con el volumen de la base de datos vacío. Si una versión nueva cambia el esquema (por ejemplo, la tabla `identidad_externa` del login externo), la API no arranca con la base de datos anterior y su log dice qué falta (`ARRANQUE BLOQUEADO: tablas: ...`, modelo de amenazas, 6.10): falla de forma visible, no a medias. Una instalación de prueba se pone al día recreando el volumen (`docker compose down -v` y arrancar), con lo que pierde sus datos. Para una con datos haría falta aplicar a mano la parte nueva del esquema como superusuario; ese procedimiento no está preparado (modelo de amenazas, 8).

## Producción en el VPS (Dokploy)

Canario corre en el VPS con su propio compose, fuera de Dokploy. Dokploy solo pone la entrada: su Traefik termina el TLS con Let's Encrypt y reenvía a Caddy por la red `edge` de Canario. Así los secretos nunca pasan por el panel (Dokploy guarda la configuración de cada servicio en su base de datos y escribe un `.env` en disco), y el compose que corre es el mismo que prueban las baterías. Los motivos y los riesgos, en el modelo de amenazas (6.20).

| Nombre | Sitio |
|---|---|
| `canario.eduumr.dev` | el del denunciante |
| `canario-personal.eduumr.dev` | la SPA del personal |
| `canario-api.eduumr.dev` | la API |

Lo que cambia respecto a local lo dicen tres ficheros: `compose.produccion.yaml` (los orígenes, el Caddyfile, sin puertos publicados, `edge` interna y el cartero entregando a Mailjet con el almacén de certificados de la imagen), `proxy/Caddyfile.produccion` (confía solo en Traefik) y `despliegue/traefik/canario.yml` (el enrutado de Traefik). `tests/security/verificar_despliegue.py` los prueba juntos con un Traefik de la misma versión que el de Dokploy (v3.6.25 en Dokploy v0.30.10).

### Primera vez

En el **PC** (PowerShell, desde la raíz del repositorio), con las baterías en verde, incluida `python tests\security\verificar_despliegue.py`:

1. Construir las imágenes y guardarlas en un fichero. El VPS no construye nada: arranca exactamente lo que se probó.

   ```powershell
   docker compose build postgres api broker gestion caddy
   docker image inspect canario-api --format "{{.Architecture}}"
   docker save canario-postgres canario-api canario-broker canario-gestion canario-caddy -o "$env:TEMP\canario-imagenes.tar"
   scp "$env:TEMP\canario-imagenes.tar" ovh:canario-imagenes.tar
   ```

   La arquitectura tiene que ser la del VPS (`amd64`; en el VPS, `uname -m` da `x86_64`). El cartero no lleva imagen propia: en producción usa `canario-api`, que es la misma con otro punto de entrada.

En el **VPS** (`ssh ovh`, bash):

2. Cargar las imágenes y traer el código (el compose, los scripts y la configuración de Traefik):

   ```bash
   docker load -i ~/canario-imagenes.tar && rm ~/canario-imagenes.tar
   git clone https://github.com/EduuMR73/Canario.git ~/apps/canario
   cd ~/apps/canario
   ```

3. Generar los secretos **en el VPS**. No se copian del PC: cada instalación tiene los suyos. Después, copia de la clave maestra fuera del VPS, como en la puesta en marcha.

   ```bash
   python3 scripts/generar_secretos.py
   ```

4. Arrancar con el compose de producción encima del de siempre:

   ```bash
   docker compose -f docker-compose.yml -f compose.produccion.yaml up -d --wait
   ```

   Si falta alguna imagen, falla y lo dice: no la construye ni la descarga (`pull_policy: never`).

5. Conectar Traefik a la red `edge` con la IP fija en la que confía Caddy, y darle el enrutado:

   ```bash
   docker network connect --ip 10.88.1.2 canario_edge dokploy-traefik
   sudo cp despliegue/traefik/canario.yml /etc/dokploy/traefik/dynamic/canario.yml
   ```

   Traefik vigila ese directorio y carga el fichero sin reiniciar. **Sin la IP fija**, Caddy no confía en Traefik y responde 403 a todo: el fallo se ve, en vez de meter a todos los clientes en el mismo contador del limitador.

6. En Cloudflare, tres registros A a la IP del VPS, **solo DNS** (nube gris), como el resto de `eduumr.dev`: `canario`, `canario-personal` y `canario-api`. Con el proxy de Cloudflare habría un tercer salto delante de Traefik y la IP del cliente sería la de Cloudflare.

7. Comprobar desde el **PC** (PowerShell; `curl.exe`, no el alias `curl` de PowerShell 5):

   ```powershell
   curl.exe -sI https://canario-api.eduumr.dev/salud
   curl.exe -sI http://canario.eduumr.dev/
   ```

   La primera, `200` con una sola `strict-transport-security: max-age=63072000` y el certificado de Let's Encrypt; la segunda, `301` a `https://canario.eduumr.dev/` (a un GET; a un POST Traefik responde `308`, que conserva el método).

8. Dar de alta la empresa y el primer admin como en el README, con los dos ficheros de compose:

   ```bash
   docker compose -f docker-compose.yml -f compose.produccion.yaml run --rm gestion alta-empresa --nombre "Demo S.L." --zona Europe/Madrid
   ```

   El enlace de activación se abre en `https://canario-personal.eduumr.dev/activacion#<token>`.

### Actualizar

Cada cambio se prueba en el PC y se despliega igual: los pasos 1 y 2 (con `git pull --ff-only` en vez de `git clone`) y el 4. Si cambia `despliegue/traefik/canario.yml`, también el `cp` del paso 5. Los secretos y la conexión de Traefik se quedan como están. El límite del esquema sin migraciones (arriba, "Actualizar una instalación existente") vale igual aquí.

### Lo que hay que vigilar

- **Si Dokploy recrea su Traefik** (al actualizarlo o al cambiar sus ajustes), pierde la conexión a `edge`: los tres nombres dan 502 hasta repetir el `docker network connect` del paso 5. Le pasa lo mismo a Inmunia. Volver a conectarlo solo es pendiente del bloque B (modelo de amenazas, 6.20).
- **El correo sale solo con la credencial de Mailjet puesta.** Mientras `secrets/smtp_usuario.txt` tenga el marcador, el cartero lo dice al arrancar (`EVENTO correo_sin_credenciales`) y Mailjet rechaza cada correo (`EVENTO correo_fallido` en su log): el registro y los avisos no llegan. Se configura en [Correo en producción](#correo-en-producción-mailjet). Mientras tanto, las cuentas se crean por invitación desde **Cuentas** (el enlace se muestra una vez) o con `gestion alta-admin`.
- **El log del cartero** (`docker compose ... logs cartero`) es donde se ve si el correo sale: `correo_aplazado` repetido es un proveedor que no responde, y `motivo=certificado` es que el certificado de quien contesta no vale, que es lo que se vería si alguien se hiciera pasar por Mailjet.
- **El login con Google** sigue apagado mientras `secrets/google_client_id.txt` tenga el marcador. Para activarlo, el URI de redirección registrado en Google pasa a ser el de `canario-personal.eduumr.dev`.

### Correo en producción (Mailjet)

El cartero (`app/cartero.py`) entrega a Mailjet por TLS implícito en el 465 (`in-v3.mailjet.com`), con el certificado verificado, desde `no-responder@canario.eduumr.dev` y sin el seguimiento de enlaces de Mailjet: con él, Mailjet reescribiría cada enlace por uno suyo y el token de las invitaciones acabaría en sus registros (modelo de amenazas, 6.3). Se configura una vez:

1. **La cuenta de Mailjet**, con segundo factor (una aplicación, no SMS). Quien entre en ella puede leer el historial de envíos y mandar correos con el nombre de Canario.
2. **El dominio** `canario.eduumr.dev` como remitente en Mailjet. Mailjet da los registros DNS que tiene que haber: el de SPF y el de DKIM. Se añaden en Cloudflare **tal cual los da Mailjet** (TXT, en `canario.eduumr.dev` el de SPF y en el nombre que indique el de DKIM) y se espera a que Mailjet los dé por buenos. DKIM es el que importa para DMARC: firma con `d=canario.eduumr.dev`, que es el dominio del remitente.
3. **El seguimiento, apagado también en la cuenta** (Account settings, tracking). El cartero ya manda `X-Mailjet-TrackClick: 0` y `X-Mailjet-TrackOpen: 0` en cada correo, y Mailjet documenta que mandan sobre la cuenta; apagarlo en la cuenta es la segunda capa.
4. **La credencial, en el VPS** (bash, en `~/apps/canario`). Es la clave API y la clave secreta de Mailjet (su sección SMTP). `read -s` no la enseña ni la deja en el historial, y `printf '%s'` la escribe sin salto de línea, como exige el cartero:

   ```bash
   read -rs -p "Clave API de Mailjet: " u; printf '%s' "$u" > secrets/smtp_usuario.txt; echo
   read -rs -p "Clave secreta de Mailjet: " c; printf '%s' "$c" > secrets/smtp_contrasena.txt; echo
   unset u c
   sudo docker compose -f docker-compose.yml -f compose.produccion.yaml up -d --wait cartero
   ```

   Hay que cambiar las dos: con una sola, el cartero no arranca (`ARRANQUE BLOQUEADO`). Con las dos, el log ya no dice `correo_sin_credenciales`.
5. **Comprobar con un correo real**: pedir el registro con un email propio en `https://canario-personal.eduumr.dev/registro`. En el log del cartero, `EVENTO correo_entregado: tipo=verificacion`. En el correo recibido, "ver original" (Gmail: "Mostrar original"):
   - `dkim=pass` con `header.d=canario.eduumr.dev` y `dmarc=pass`;
   - el enlace es exactamente `https://canario-personal.eduumr.dev/registro/verificacion#...`, sin pasar por ningún dominio de Mailjet. Si el enlace está reescrito, **se para aquí**: el seguimiento no está apagado y los tokens llegarían a Mailjet.
6. **DMARC** solo después de ver `dkim=pass` alineado en el paso anterior: un registro TXT en `_dmarc.canario.eduumr.dev` con `v=DMARC1; p=reject`. Desde ese momento, un correo que diga venir de `canario.eduumr.dev` sin la firma de DKIM se rechaza. El de `eduumr.dev` (`p=none`) no se toca: es de las demás aplicaciones, y el de un subdominio manda sobre él.

El plan gratuito de Mailjet son 200 correos al día; el cartero reparte 150 para el registro y las invitaciones y 50 para los avisos de seguridad, y lo que pase de ahí lo descarta con su evento.

## Acceso con Google (opcional)

Sin configurar nada, Google está desactivado: `generar_secretos.py` deja un marcador en `secrets/google_client_id.txt` y `secrets/google_client_secret.txt`, el log del broker lo dice al arrancar (`EVENTO proveedor_desactivado`) y la SPA no pinta el botón (modelo de amenazas, 6.19).

Para activarlo:

1. En Google Cloud Console, la pantalla de consentimiento (Google Auth Platform) de tipo Externo. Mientras esté en modo de pruebas, solo entran las cuentas añadidas como usuarios de prueba. Sin permisos extra: Canario solo pide `openid`, ni el email. Después, un cliente OAuth de tipo "Aplicación web" con la URI de redirección exacta `https://localhost:8445/v1/personal/externo/google/vuelta` (en otro despliegue, el origen de `CANARIO_ORIGEN_PERSONAL`) y sin orígenes de JavaScript.

2. Escribir los dos valores en `secrets/`, sin que queden en el historial de PowerShell:

   ```powershell
   $id = Read-Host "Client ID"
   [IO.File]::WriteAllText((Join-Path (Get-Location) "secrets\google_client_id.txt"), $id.Trim())
   $secreto = Read-Host "Client secret"
   [IO.File]::WriteAllText((Join-Path (Get-Location) "secrets\google_client_secret.txt"), $secreto.Trim())
   Remove-Variable id, secreto
   ```

   `WriteAllText` escribe UTF-8 sin BOM y sin salto de línea; el broker solo acepta ASCII imprimible, de 1 a 255 caracteres, y `Set-Content` de PowerShell 5 añadiría un BOM. La ruta va completa porque `[IO.File]` usa el directorio del proceso y no el de PowerShell. El secreto se ve en pantalla al pegarlo. Hay que cambiar los dos: con uno solo, el broker no arranca (`ARRANQUE BLOQUEADO`), porque es un error de quien opera.

3. Arrancar como siempre (`docker compose up -d --build --wait`). El log del broker dice `PROVEEDOR ACTIVADO` con la URI de redirección que usa.

4. Usarlo: la primera vez se entra con contraseña y código, que deja el dispositivo de confianza en ese navegador. En **Mi cuenta**, "Vincular Google" pide un código y lleva a Google. Desde entonces, en ese navegador, "Iniciar sesión con Google" y el código. Google nunca sustituye al código ni crea la confianza.

La cuenta de Google Cloud que administra el cliente necesita un segundo factor resistente (passkey o una aplicación, no SMS): quien la controle puede cambiar la URI de redirección y llevarse los códigos. Para comprobar el canje contra el Google real, `verificar_google_real.py` ([pruebas.md](pruebas.md)).

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
- **No hay orden para cambiar el nombre de una empresa**, y la API tampoco lo permite. Si hiciera falta, sería una orden de `gestion` con verificación fuera de banda, nunca una acción de la SPA (modelo de amenazas, 8).
- **`alta-admin`** emite la invitación del primer admin de una empresa, solo si no tiene ningún admin activado.
- **`suprimir-caducadas`** aplica la supresión legal y, en la misma ejecución, poda las solicitudes de registro cerradas o caducadas (más abajo).
- **`reinvitar-admin`** es la recuperación de emergencia de un admin activado: revoca en el acto sus sesiones y dispositivos y emite una invitación nueva. Solo se ejecuta tras verificar la petición fuera de banda, con el contacto que consta en el contrato y nunca con el que da quien la pide (modelo de amenazas, 6.3).

**El token de invitación es una credencial.** `alta-admin` y `reinvitar-admin` lo imprimen una sola vez: son la vía de emergencia y no dependen del correo. Caduca a las 72 horas y sirve una sola vez. Se entrega al titular por un canal seguro y distinto del de la petición, y no se pega en tickets, chats ni correos. Si el titular lo encuentra ya usado, alguien se le adelantó, y la auditoría de su empresa lo muestra.

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
