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

En el **VPS** (`ssh ovh`, bash). Todo lo de Docker va con `sudo`: el usuario del VPS no está en el grupo `docker`, a propósito. Estar en ese grupo equivale a ser root sin contraseña (cualquiera de sus procesos puede arrancar un contenedor que monte `/`), y así cada orden con privilegios la pide y queda en el registro de `sudo`.

2. Cargar las imágenes, comprobar que están y traer el código (el compose, los scripts y la configuración de Traefik):

   ```bash
   sudo docker load -i ~/canario-imagenes.tar
   sudo docker image ls --format '{{.Repository}} {{.CreatedSince}}' | grep '^canario-'
   ```

   Tienen que salir las cinco (`canario-postgres`, `canario-api`, `canario-broker`, `canario-gestion` y `canario-caddy`) con la fecha de la construcción del paso 1. El fichero **no se borra**: es la versión desplegada, y es lo que se vuelve a cargar si hay que revertir (más abajo, "Revertir"). Si la carga falló a medias, sin él habría que repetir la copia desde el PC.

   ```bash
   git clone https://github.com/EduuMR73/Canario.git ~/apps/canario
   cd ~/apps/canario
   ```

3. Generar los secretos **en el VPS**. No se copian del PC: cada instalación tiene los suyos. Después, copia de la clave maestra fuera del VPS, como en la puesta en marcha.

   ```bash
   python3 scripts/generar_secretos.py
   ```

4. Arrancar con el compose de producción encima del de siempre:

   ```bash
   sudo docker compose -f docker-compose.yml -f compose.produccion.yaml up -d --wait
   ```

   Si falta alguna imagen, falla y lo dice: no la construye ni la descarga (`pull_policy: never`).

5. En Cloudflare, tres registros A a la IP del VPS, **solo DNS** (nube gris), como el resto de `eduumr.dev`: `canario`, `canario-personal` y `canario-api`. Con el proxy de Cloudflare habría un tercer salto delante de Traefik y la IP del cliente sería la de Cloudflare.

   Comprobar desde el **PC** (PowerShell) que ya resuelven, por DNS sobre HTTPS y no con `nslookup`: en algunas redes el puerto 53 está interceptado y una caché devuelve "no existe" durante minutos aunque el registro ya esté en Cloudflare. Por lo mismo, no se consulta un nombre **antes** de crearlo: la respuesta negativa también se queda en caché.

   ```powershell
   curl.exe -sS -H "accept: application/dns-json" "https://cloudflare-dns.com/dns-query?name=canario.eduumr.dev&type=A"
   curl.exe -sS -H "accept: application/dns-json" "https://cloudflare-dns.com/dns-query?name=canario-personal.eduumr.dev&type=A"
   curl.exe -sS -H "accept: application/dns-json" "https://cloudflare-dns.com/dns-query?name=canario-api.eduumr.dev&type=A"
   ```

   Cada una tiene que traer `"Status":0` y un `Answer` con la IP del VPS.

6. Solo con los tres nombres resolviendo, conectar Traefik a la red `edge` con la IP fija en la que confía Caddy, y darle el enrutado (en el VPS):

   ```bash
   sudo docker network connect --ip 10.88.1.2 canario_edge dokploy-traefik
   sudo cp despliegue/traefik/canario.yml /etc/dokploy/traefik/dynamic/canario.yml
   ```

   Traefik vigila ese directorio y carga el fichero sin reiniciar. **Sin la IP fija**, Caddy no confía en Traefik y responde 403 a todo: el fallo se ve, en vez de meter a todos los clientes en el mismo contador del limitador.

   **El orden importa.** Al cargar el fichero, Traefik pide los certificados a Let's Encrypt; si los nombres aún no existen, Let's Encrypt responde NXDOMAIN y Traefik no lo vuelve a intentar por su cuenta. Si ya pasó, se retira el fichero, se espera a que Traefik lo descargue y se vuelve a poner:

   ```bash
   sudo rm /etc/dokploy/traefik/dynamic/canario.yml
   sleep 10
   sudo cp despliegue/traefik/canario.yml /etc/dokploy/traefik/dynamic/canario.yml
   ```

7. Comprobar desde el **PC** (PowerShell; `curl.exe`, no el alias `curl` de PowerShell 5). Con `-D - -o NUL` hace un GET y enseña solo las cabeceras. `-I` no sirve aquí: manda HEAD, y `/salud` solo admite GET (responde `405`) y Traefik redirige un HEAD con `308`, así que la comprobación fallaría sin que nada estuviera mal.

   ```powershell
   curl.exe -sS -D - -o NUL https://canario-api.eduumr.dev/salud
   curl.exe -sS -D - -o NUL http://canario.eduumr.dev/
   ```

   La primera, `200` con una sola `strict-transport-security: max-age=63072000` y el certificado de Let's Encrypt; la segunda, `301` a `https://canario.eduumr.dev/` (a un GET; a cualquier otro método Traefik responde `308`, que lo conserva).

8. Dar de alta la empresa y el primer admin como en el README, con los dos ficheros de compose:

   ```bash
   sudo docker compose -f docker-compose.yml -f compose.produccion.yaml run --rm gestion alta-empresa --nombre "Demo S.L." --zona Europe/Madrid
   ```

   El enlace de activación se abre en `https://canario-personal.eduumr.dev/activacion#<token>`.

### Actualizar

Cada cambio se prueba en el PC y se despliega igual: el paso 1, el 2 (en vez de `git clone`, `cd ~/apps/canario` y `git pull --ff-only`), el 3 y el 4, todos desde `~/apps/canario`. Tres cambios respecto a la primera vez, los dos primeros para poder revertir (más abajo, "Revertir"):

1. **En el paso 1, el `scp` va a `ovh:canario-imagenes-nueva.tar`** y el paso 2 carga ese fichero (`sudo docker load -i ~/canario-imagenes-nueva.tar`): `~/canario-imagenes.tar` es la versión que corre, y no se pisa.
2. **Antes de ese `docker load`** (en el VPS, bash), se etiquetan las cinco imágenes actuales como `:anterior`:

   ```bash
   for i in postgres api broker gestion caddy; do sudo docker tag "canario-$i:latest" "canario-$i:anterior"; done
   ```

   Si el bucle falla porque falta alguna imagen, o no está `~/canario-imagenes.tar`, **se para antes del `docker load`**: sin eso no hay a qué volver. Se guarda lo que corre a partir de las `:anterior` que sí se crearon (`sudo docker save canario-postgres:anterior canario-api:anterior ... -o ~/canario-imagenes-anterior.tar` y `chown` al usuario), y lo que falta se apunta: esa imagen no se podrá revertir. Pasó el 20 de noviembre de 2026. Cada `docker load` se había seguido de un `rm` del fichero, en contra del paso 2, y además faltaba `canario-gestion`. `gestion` no corre como servicio y esa versión no cambiaba `db/init/`, así que se siguió sin su `:anterior`.

   El `docker load` mueve `:latest` a las imágenes nuevas y deja las viejas sin nombre, y una limpieza de imágenes sin usar las borraría. Con `:anterior` siguen ahí. Los ficheros **nunca se borran** tras cargarlos. Solo cuando la carga ha ido bien (las cinco imágenes con la fecha nueva, como en el paso 2) se rotan los ficheros:

   ```bash
   mv -f ~/canario-imagenes.tar ~/canario-imagenes-anterior.tar
   mv ~/canario-imagenes-nueva.tar ~/canario-imagenes.tar
   ```

   En el VPS quedan siempre dos ficheros: el de la versión que corre y el de la anterior (sustituye al de la actualización previa).

3. **El paso 4 va con `--force-recreate`** (`up -d --wait --force-recreate`). Sin él, Compose puede dejar un contenedor con la imagen de antes aunque `:latest` ya apunte a la nueva, y no avisa. El 20 de noviembre de 2026 solo recreó `caddy`: `postgres`, `api`, `broker` y `cartero` siguieron con la imagen anterior, con todos `Healthy`. Recrear lo para todo unos segundos (unos 15 s medidos); los datos están en los volúmenes. Después, la comprobación de `.Image` contra `.Id` que describe "Revertir".

El paso 3 se repite siempre: `generar_secretos.py` nunca sobrescribe un fichero existente, solo crea los que una versión nueva necesita y aún no están (como `smtp_usuario.txt` y `smtp_contrasena.txt`), y sin ellos el paso 4 no arranca. Los que ya existen, incluida la clave maestra, se quedan como están. Si cambia `despliegue/traefik/canario.yml`, también el `cp` del paso 6; la conexión de Traefik se queda como está. El límite del esquema sin migraciones (arriba, "Actualizar una instalación existente") vale igual aquí.

La API (imagen `canario-api`) y la SPA (va dentro de `canario-caddy`) se despliegan y se revierten juntas, siempre de la misma versión del repositorio: el paso 1 construye las dos y el 4 las arranca a la vez (el procedimiento para revertir, abajo). Nunca se cambia una sola de esas imágenes. Hay contratos entre las dos que no se comprueban en marcha. Por ejemplo, la vuelta de Google al vincular una cuenta va a `/cuenta/externas` (`app/rutas_externo.py`, `DESTINOS`); con una API nueva y una SPA vieja, o al revés, esa vuelta cae en una página que no completa el vínculo, y la persona no ve ningún error.

Después de cada `git pull`, la copia instalada del reconciliador tiene que ser igual a la del repositorio (más abajo). `cmp` no dice nada si son iguales:

```bash
sudo cmp despliegue/reconectar_traefik.py /usr/local/sbin/canario-reconectar-traefik.py
sudo cmp despliegue/systemd/canario-reconectar-traefik.service /etc/systemd/system/canario-reconectar-traefik.service
sudo cmp despliegue/systemd/canario-reconectar-traefik.timer /etc/systemd/system/canario-reconectar-traefik.timer
```

Si alguno difiere, o el cambio es del repositorio y se reinstala como en la primera vez, o alguien tocó la copia instalada, y eso se investiga antes de nada.

Lo mismo con las copias de seguridad: sus comprobaciones con `cmp` están en "Copias de seguridad" (más abajo).

### Revertir

Si la versión nueva falla, se vuelve a la anterior con las imágenes que se guardaron al actualizar. **Las cinco juntas, API y SPA incluidas**: nunca una sola (arriba). En el VPS (bash), desde `~/apps/canario`:

```bash
for i in postgres api broker gestion caddy; do sudo docker tag "canario-$i:anterior" "canario-$i:latest"; done
sudo docker compose -f docker-compose.yml -f compose.produccion.yaml up -d --wait --force-recreate
```

`--force-recreate` por lo mismo que al actualizar: sin él, Compose puede dejar contenedores con la imagen que se quiere quitar. Si a alguna imagen le falta `:anterior` (arriba), se quita del bucle y se apunta que esa no vuelve atrás. Si las etiquetas `:anterior` ya no existen (por ejemplo, tras limpiar imágenes), se carga el fichero de la versión anterior, que deja sus imágenes como `:latest`, y se ejecuta la misma segunda orden:

```bash
sudo docker load -i ~/canario-imagenes-anterior.tar
```

Se comprueba, igual que tras cada actualización, que cada contenedor corre la imagen que lleva ahora `:latest`: el `.Image` del contenedor tiene que ser el `.Id` de la imagen. Un `up -d` que no recrea un contenedor lo deja con la versión de antes sin avisar. El cartero no tiene imagen propia: se compara con `canario-api`. En una sola línea, porque al pegar varias en la sesión SSH se cuelan caracteres de control (`^[[200~`):

```bash
for s in postgres api broker caddy cartero; do i=$s; [ "$s" = cartero ] && i=api; c=$(sudo docker compose -f docker-compose.yml -f compose.produccion.yaml ps -q "$s"); echo "$s $(sudo docker inspect --format '{{.Image}}' "$c") $(sudo docker image inspect --format '{{.Id}}' "canario-$i")"; done
```

Las dos columnas de cada fila tienen que ser iguales. Revertir no deshace datos ni esquema: sin migraciones, solo vale si la versión nueva no cambió `db/init/` (arriba, "Actualizar una instalación existente"). La etiqueta `:anterior` se pisa en la siguiente actualización: guarda una sola versión atrás.

### Reconexión automática de Traefik

Dokploy, cada vez que recrea su Traefik (al actualizarse o al cambiar sus ajustes), lo crea solo en su red, sin `canario_edge`, y no tiene ninguna opción para añadir redes (`traefik-setup.ts` de Dokploy v0.30.10). Sin esa conexión, los tres nombres dejan de responder. `despliegue/reconectar_traefik.py` compara cada minuto el estado real con el deseado y, si hace falta, vuelve a conectar Traefik con `10.88.1.2`. Si otro contenedor tiene esa IP, no toca nada y falla: podría ser alguien haciéndose pasar por Traefik ante Caddy. Los motivos, en el modelo de amenazas (6.20); las pruebas, en `verificar_despliegue.py`, g.

Se instala **una copia** con dueño root. Nunca se ejecuta desde `~/apps/canario`: esa carpeta la puede cambiar el usuario del VPS, y un fichero que un usuario edita y root ejecuta es una vía de escalada.

En el VPS (bash, en `~/apps/canario`):

1. Comprobar antes que el vigía (la vigilancia del VPS, que avisa por Telegram y no está en este repositorio) está vivo: es lo que avisará de que se tocan `/usr/local/sbin` y `/etc/systemd/system`.

   ```bash
   systemctl list-timers 'vigia*'
   ```

2. Instalar y comprobar las unidades:

   ```bash
   sudo install -o root -g root -m 0755 despliegue/reconectar_traefik.py /usr/local/sbin/canario-reconectar-traefik.py
   sudo install -o root -g root -m 0644 despliegue/systemd/canario-reconectar-traefik.service despliegue/systemd/canario-reconectar-traefik.timer /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemd-analyze verify /etc/systemd/system/canario-reconectar-traefik.service /etc/systemd/system/canario-reconectar-traefik.timer
   sudo systemd-analyze security canario-reconectar-traefik.service
   ```

   `verify` no tiene que decir nada. `security` da una nota de exposición; si una directiva de endurecimiento rompe la unidad en el paso 3, se quita esa sola y se anota el motivo en el comentario de la unidad.

3. Una ejecución con todo bien, antes de activar el timer. `systemctl start` espera a que termine; tiene que dar `rc=0`:

   ```bash
   sudo systemctl start canario-reconectar-traefik.service; echo "rc=$?"
   ```

   Aquí `systemctl status` no sirve: una unidad inactiva que nada referencia se descarga de memoria (`CollectMode=` en `systemd.unit`) y `status` la enseña sin historia, como si nunca hubiera corrido. El journal también queda vacío: con todo bien el script no escribe nada y `LogLevelMax=notice` calla el inicio y el fin.

4. Activar el timer y, pasado un minuto y medio, ver su última ejecución. Con el timer, la unidad queda referenciada y `status` ya la enseña: tiene que decir `status=0/SUCCESS` con la hora de hace un momento. Si dice `failed`, el endurecimiento de la unidad rompe algo: se para aquí y se mira el journal.

   ```bash
   sudo systemctl enable --now canario-reconectar-traefik.timer
   systemctl list-timers canario-reconectar-traefik.timer --no-pager
   systemctl status canario-reconectar-traefik.service --no-pager
   ```

5. El vigía avisa por Telegram de los ficheros nuevos, en uno o dos avisos. Se mira que digan **exactamente** estos cuatro y, solo entonces, se rehace su foto para que no los vuelva a contar como cambio:

   - `/usr/local/sbin/canario-reconectar-traefik.py`
   - `/etc/systemd/system/canario-reconectar-traefik.service`
   - `/etc/systemd/system/canario-reconectar-traefik.timer`
   - `/etc/systemd/system/timers.target.wants/canario-reconectar-traefik.timer` (el enlace que crea `enable`)

   ```bash
   sudo /usr/local/sbin/vigia.sh base
   ```

6. Probarlo de verdad, con un corte controlado que solo afecta a Canario. En el **PC** (PowerShell), un bucle que pregunta cada 5 s:

   ```powershell
   while ($true) { (Get-Date -Format HH:mm:ss) + " " + (curl.exe -s -o NUL -w "%{http_code}" https://canario-api.eduumr.dev/salud); Start-Sleep 5 }
   ```

   En el **VPS**:

   ```bash
   sudo docker network disconnect canario_edge dokploy-traefik
   ```

   El bucle tiene que dejar de dar `200` justo después (un plazo agotado, que `curl.exe` enseña como `000`, o un `502`) y volver a `200` en 70 s como mucho. No se espera un estado concreto: con el Traefik de la batería, la primera petición tras el corte no recibe respuesta en 15 s, aunque se suponía un `502` (`verificar_despliegue.py`, g). En el VPS, el 3 de noviembre de 2026: un `000`, cuatro `502` y `200` a los 40 s, más o menos. Si a los 70 s no ha vuelto el `200`, **se para aquí** y se mira el journal. En el journal queda la reconexión:

   ```bash
   sudo journalctl -u canario-reconectar-traefik.service --no-pager -p warning -n 5
   ```

   Tiene que salir `RECONECTADO: contenedor=dokploy-traefik red=canario_edge ip=10.88.1.2 antes=desconectado`.

**Lo que esto no cubre.** Que Traefik se recree es una señal y, de momento, solo queda en el journal: nadie avisa al momento. Lo verá el vigía cuando lea esa línea (pendiente con fecha, modelo de amenazas, 6.20). Un fallo del reconciliador sí se ve: deja la unidad fallida, el vigía avisa de las unidades fallidas y los monitores externos (abajo) ven el sitio caído.

### Monitores externos

El vigía vive dentro del VPS: si se cae el VPS entero, o Traefik, el vigía no puede avisar. Por eso hay dos monitores de tipo **Keyword** en UptimeRobot (plan gratuito, cada 5 minutos, aviso por correo y por notificación del móvil), que sondean desde fuera:

| Monitor | URL | Palabra que tiene que estar |
|---|---|---|
| API Canario | `https://canario-api.eduumr.dev/salud` | `"estado":"ok"` |
| Web Canario | `https://canario.eduumr.dev` | `Canal de denuncias anónimo` |

Keyword y no HTTP: el monitor HTTP de UptimeRobot pregunta con `HEAD`, Canario responde `405` a `HEAD` y el monitor lo daría por caído; elegir el método es de los planes de pago. El Keyword pregunta con `GET` y además comprueba que la respuesta es la de Canario. Si cambia el título de la página del denunciante, hay que cambiar su palabra.

Sondean desde fuera en vez de esperar un ping que salga del VPS, así que no añaden ninguna salida desde el VPS.

### Copias de seguridad

Sin copias, un disco perdido o un ransomware (ATT&CK T1486 y T1490) se llevarían las denuncias. `despliegue/copias.py` saca dos cosas del VPS, cifradas con age para dos claves poscuánticas, a un bucket de Backblaze B2 donde el VPS **escribe y oculta, pero no borra**: la capacidad `writeFiles` incluye `b2_upload_file` y `b2_hide_file` (documentación de B2, capacidades de las claves), no `deleteFiles`, y el Object Lock en compliance impide borrar lo ya subido.

- **`base`, cada día (03:30 UTC):** un `pg_dump` de la base y un manifiesto (recuento de filas por tabla y, por empresa, la última secuencia y el último hash de la cadena de auditoría) en un tar, cifrado entero. Va a `base/AAAAMMDDTHHMMSSZ.age` (nombre único, con la hora UTC). Se sube **siempre**: si la base está vacía, la cadena de auditoría está rota o la base no se estabiliza durante la copia, el objeto va a `cuarentena/AAAAMMDDTHHMMSSZ.age` (con el motivo en el manifiesto cifrado: `cadena_rota_en`, `estable`, `motivos`), el latido recibe `/fail` y el código es 6. Una copia sospechosa sigue siendo evidencia y negarse a subirla dejaría sin copia a la vez que el problema; lo que no hace nunca es hacerse pasar por buena.
- **`eventos`, cada 15 minutos:** las líneas `EVENTO declaracion_no_veraz`, `EVENTO redaccion` y `EVENTO reutilizacion_renovacion` del log de la API, a `eventos/AAAAMMDDTHHMMSSZ.age`. Son el registro para volver a aplicar lo suprimido o tachado tras restaurar (más abajo). Un cursor (`/var/lib/canario-copias/eventos.cursor`) guarda hasta dónde se exportó y el Id del contenedor de la API.

**Latidos (healthchecks.io), uno por suborden.** El de la base avisa si falta el ping del día; el de los eventos, si faltan los de 15 minutos. Cada ping de éxito es un `POST` con, en el cuerpo, una línea JSON por objeto subido (`objeto`, `fileId`, `sha1`, `bytes`). Ese cuerpo es el **único registro, fuera del VPS, de lo que subió el script legítimo**. Hace falta porque `writeFiles` deja a quien tome root ocultar las copias buenas y subir otras falsas, y age no lo impide: cifra un fichero ya existente y falla si se altera, pero no autentica a quien lo cifró (los destinatarios son públicos y están en el VPS). El latido no lo evita; permite descubrirlo y elegir bien al restaurar (más abajo).

**Eventos: qué es un hueco y qué no.**

- **Hueco (código 5).** En el mismo contenedor, la línea más antigua del log es posterior al cursor: la rotación (3 ficheros de 10 MB) se comió líneas. Se sube lo que queda y se escribe `/var/lib/canario-copias/eventos.hueco`. **Mientras ese fichero exista, cada ejecución sigue fallando con el código 5 y `/fail`** (sigue subiendo lo nuevo), para que nadie lo dé por bueno sin haberlo visto. Se reconoce así, tras investigar qué se perdió (las `EVENTO` de ese intervalo, si se recuperan de otro sitio, se anotan a mano):

  ```bash
  sudo cat /var/lib/canario-copias/eventos.hueco
  sudo rm /var/lib/canario-copias/eventos.hueco
  sudo systemctl start canario-copia-eventos.service; echo "rc=$?"
  ```

- **Contenedor nuevo (aviso, código 0).** Si cambia el Id del contenedor de la API (una actualización la recrea), su log empieza de cero y eso no es una rotación: el script registra `EVENTO contenedor_nuevo: ... última exportación previa en <T>` (en el journal con prioridad warning y en el cuerpo del latido) y exporta todo el log nuevo. Lo que el contenedor anterior escribió después de esa última exportación se fue con él: por eso **antes de recrear la API** se exporta, y se mira que `<T>` sea de ese momento:

  ```bash
  sudo systemctl start canario-copia-eventos.service; echo "rc=$?"     # antes de recrear: tiene que dar rc=0
  # ... se recrea la API (Actualizar, arriba) ...
  sudo systemctl start canario-copia-eventos.service; echo "rc=$?"     # rc=0 y el aviso contenedor_nuevo
  sudo journalctl -u canario-copia-eventos.service --no-pager -n 5
  ```

  Si `<T>` es muy anterior a la recreación, la exportación previa no se hizo y hay eventos perdidos: se trata como un hueco.

Se instala **una copia** con dueño root, como el reconciliador: nunca se ejecuta desde `~/apps/canario`. Solo usa la biblioteca estándar de Python y `age` 1.3.2, instalado a mano y no con `apt`: las claves poscuánticas son de la 1.3.0 y no hay garantía de que el paquete de Ubuntu 24.04 las traiga (modelo de amenazas, 8). `docker` se llama por ruta absoluta (`/usr/bin/docker`).

Las pruebas están en `verificar_copias.py`. No prueban Backblaze ni healthchecks.io reales, ni las unidades de systemd, ni el `SIGTERM`: eso se comprueba aquí, en el VPS y en las consolas de los dos servicios.

**Límites operativos que hay que conocer.**

- **Si las copias fallan más de 30 días, no queda ninguna.** El ciclo de vida caduca los objetos por antigüedad (~31 días) y no mira si hay otros más recientes. Un `/fail` o un latido que no llega se atiende en horas, no en semanas: no es un aviso para ver cuando haya tiempo.
- **Con el tope de gasto en 0 $, basura subida desde un VPS comprometido puede agotar el almacenamiento gratuito y bloquear las copias legítimas durante 30 días** (Object Lock en compliance: no se puede borrar). La respuesta es subir el tope en Caps & Alerts, no intentar borrar. El latido lo hace visible: las subidas legítimas empiezan a fallar con el código 8.

**1. Preparar Backblaze B2** (una vez, desde el PC):

1. Cuenta de B2 con segundo factor TOTP (no SMS) y, en Caps & Alerts, límite de gasto de 0 $ con alerta por correo (ver el límite de arriba).
2. Un bucket **privado** con **Object Lock activado en modo compliance, 30 días**, de retención por defecto. Object Lock hay que activarlo al crear el bucket. En modo compliance la retención no la puede quitar ni acortar ningún usuario (documentación de B2, Object Lock; en governance sí, con la capacidad adecuada): es lo que sostiene la copia frente a un atacante con root en el VPS (T1485.001, borrado por ciclo de vida, también), y frente a nosotros.
3. Ciclo de vida del bucket: `daysFromUploadingToHiding` 30 y `daysFromHidingToDeleting` 1. Los objetos desaparecen a los ~31 días, cuando ya se pueden borrar. Un cambio de ciclo de vida que intente borrar antes de que acabe la retención falla (documentación de B2); cómo se combinan exactamente esas dos reglas con un objeto bloqueado no está comprobado: se mira en la consola, pasados 31 días de la primera copia, que los objetos antiguos desaparecen y los recientes no.
4. Una application key limitada a **ese bucket** y con **solo la capacidad `writeFiles`** (ni `listBuckets`, ni `readFiles`, ni `deleteFiles`, ni prefijo de nombre). Con la CLI `b2` v4, desde el PC (necesita una clave con `writeKeys`, la maestra de la cuenta):

   ```powershell
   b2 key create --bucket NOMBRE_DEL_BUCKET canario-copias-vps writeFiles
   ```

   La orden se ha tomado del código fuente de la CLI (`KeyCreateBase` en `b2/_internal/console_tool.py`: los argumentos son el nombre de la clave y la lista de capacidades separadas por comas, y `--bucket` lleva el nombre del bucket); las páginas de documentación de Backblaze que se han podido leer no documentan `b2 key create`, así que `b2 key create --help` manda si difiere. Imprime el `keyID` y el `applicationKey` (solo se ven una vez). **La consola web es la alternativa**, pero no está comprobado que el tipo de acceso "Write Only" dé solo `writeFiles`: si se usa, hay que mirar las capacidades que muestra. En cualquier caso el script se niega a seguir si la clave tiene algo más (se ve en la primera ejecución a mano, paso 5).

   El **`bucketId`** (en los detalles del bucket de la consola) se guarda en la configuración del VPS (paso 4): el script lo compara con el de la clave autorizada y, si no coincide, falla con el código 4. Así una clave de otro bucket (por ejemplo sin Object Lock) no sube copias a un sitio sin retención.
5. Una segunda key, **para el PC**, con `listFiles` y `readFiles` en ese bucket (y `listBuckets` si la herramienta que se use lo pide), para la restauración y el simulacro. Nunca va al VPS.

**2. Dos latidos en healthchecks.io**, con aviso al correo (y al móvil). Dos checks distintos, cada uno con su URL de ping (`https://hc-ping.com/<uuid>`):

| Check | Periodo | Gracia | Lo pinga |
|---|---|---|---|
| Copia de la base | 1 día | 3 horas | `canario-copia-base.service` |
| Copia de los eventos | 15 minutos | 30 minutos | `canario-copia-eventos.service` |

Cada URL es una credencial: quien la conoce puede avisar de que todo va bien. La semántica, de la documentación de healthchecks.io: un `POST` a la URL señala éxito, un `POST` a `<url>/fail` señala fallo y avisa al momento sin esperar al plazo, las dos aceptan GET, HEAD y POST, y en un `POST` el cuerpo (hasta 100 kB) se guarda. Aquí el cuerpo del éxito es el registro de lo subido y el del `/fail` es el motivo.

**3. Las dos claves age, en el PC** (PowerShell). **No en Descargas**: se sincroniza, se indexa y entra en copias. Las claves se generan en un directorio temporal, se pasan a Bitwarden y al papel, y se borran. age para Windows va a un directorio de herramientas que no guarda secretos y se queda. De la release oficial, con su sha256 comprobado:

```powershell
$T = Join-Path $env:LOCALAPPDATA 'canario-claves-tmp'
$H = Join-Path $env:LOCALAPPDATA 'canario-herramientas'
New-Item -ItemType Directory -Path $T, $H | Out-Null
cd $H
curl.exe -fsSLO https://github.com/FiloSottile/age/releases/download/v1.3.2/age-v1.3.2-windows-amd64.zip
(Get-FileHash age-v1.3.2-windows-amd64.zip -Algorithm SHA256).Hash.ToLower()   # tiene que ser f48d8f8f9ebe903ab5027ed067652f2cc1db94bc206976430133b905dcd8e8c7
Expand-Archive age-v1.3.2-windows-amd64.zip -DestinationPath age
cd $T
& "$H\age\age\age-keygen.exe" -pq -o principal.key
& "$H\age\age\age-keygen.exe" -pq -o respaldo.key
& "$H\age\age\age-keygen.exe" -y principal.key | Set-Clipboard    # destinatario principal: se pega en el VPS (paso 4)
& "$H\age\age\age-keygen.exe" -y respaldo.key | Set-Clipboard     # destinatario de respaldo: ídem, en otra línea
```

Los destinatarios (`age1pq1...`, de unos 2000 caracteres) no son secretos; los dos ficheros `.key` son las claves privadas: custodia al final de esta sección. Nunca van al VPS. Cuando las dos estén en su sitio (la principal en Bitwarden y la de respaldo impresa), se borra todo lo temporal y se vacía el portapapeles:

```powershell
Set-Clipboard -Value $null
Remove-Item -Recurse -Force $T
```

`Remove-Item` no sobrescribe el contenido: la protección real es que el disco esté cifrado (BitLocker). Si no lo está, `cipher /w:$env:LOCALAPPDATA` sobrescribe el espacio libre (tarda).

**4. En el VPS** (bash, en `~/apps/canario`, después del `git pull`):

```bash
# age 1.3.2: solo el binario "age" (age-keygen no hace falta: las claves privadas no están en el VPS)
cd "$(mktemp -d)"
curl -fsSLO https://github.com/FiloSottile/age/releases/download/v1.3.2/age-v1.3.2-linux-amd64.tar.gz
echo "cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10  age-v1.3.2-linux-amd64.tar.gz" | sha256sum -c -
tar -xzf age-v1.3.2-linux-amd64.tar.gz
sudo install -o root -g root -m 0755 age/age /usr/local/bin/age
/usr/local/bin/age --version
cd ~/apps/canario

# configuración de root: directorio 0700, ficheros 0600
sudo install -d -o root -g root -m 0700 /etc/canario-copias
sudo sh -c 'umask 077; cat > /etc/canario-copias/destinatarios.txt'    # pegar los dos age1pq1..., uno por línea, y Ctrl-D
sudo sh -c 'umask 077; cat > /etc/canario-copias/b2_id'                 # pegar el keyID y Ctrl-D
sudo sh -c 'umask 077; cat > /etc/canario-copias/b2_clave'              # pegar el applicationKey y Ctrl-D
sudo sh -c 'umask 077; cat > /etc/canario-copias/bucket_id'             # pegar el bucketId esperado y Ctrl-D
sudo sh -c 'umask 077; cat > /etc/canario-copias/latido_url'            # pegar la URL del latido de la base y Ctrl-D
sudo sh -c 'umask 077; cat > /etc/canario-copias/latido_eventos_url'    # pegar la URL del latido de los eventos y Ctrl-D
```

`sha256sum -c` tiene que decir `OK`. Las credenciales se pegan por la entrada estándar y no con `echo`: así no quedan en el historial de la shell ni en `ps`.

Instalar y comprobar el script y las unidades, como con el reconciliador:

```bash
sudo install -o root -g root -m 0755 despliegue/copias.py /usr/local/sbin/canario-copias.py
sudo install -o root -g root -m 0644 despliegue/systemd/canario-copia-base.service despliegue/systemd/canario-copia-base.timer despliegue/systemd/canario-copia-eventos.service despliegue/systemd/canario-copia-eventos.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemd-analyze verify /etc/systemd/system/canario-copia-base.service /etc/systemd/system/canario-copia-base.timer /etc/systemd/system/canario-copia-eventos.service /etc/systemd/system/canario-copia-eventos.timer
systemd-analyze calendar '*-*-* 03:30:00 UTC' '*-*-* *:0/15:00 UTC'
sudo systemd-analyze security canario-copia-base.service
```

`verify` no tiene que decir nada y `calendar` tiene que mostrar la hora siguiente de cada timer. Las unidades llevan `SystemCallFilter=@system-service`, `MemorySwapMax=0`, `LimitCORE=0` y `PrivateIPC=yes` (esta última pide systemd 248 o posterior; Ubuntu 24.04 trae la 255). No llevan `ProtectProc=invisible` ni `ProcSubset=pid`: la página de `systemd.exec(5)` dice que el primero no afecta a root y que el segundo no es adecuado para la mayoría de los programas no triviales, y no se ha comprobado que Python, docker y age lo toleren. Si una directiva rompe la unidad (el filtro de llamadas mata con `SIGSYS`; se ve en el journal), se quita esa sola y se anota el motivo en la unidad. El endurecimiento no cuenta como control frente a root: el control es que solo root cambie el script, las unidades y `/etc/canario-copias`, y que la clave de B2 solo pueda escribir.

Después de cada `git pull`, `cmp` no dice nada si las copias instaladas son iguales a las del repositorio:

```bash
sudo cmp despliegue/copias.py /usr/local/sbin/canario-copias.py
for u in canario-copia-base.service canario-copia-base.timer canario-copia-eventos.service canario-copia-eventos.timer; do sudo cmp despliegue/systemd/$u /etc/systemd/system/$u; done
```

**5. Primera ejecución a mano**, antes de activar los timers. `systemctl start` espera a que termine; tiene que dar `rc=0`:

```bash
sudo systemctl start canario-copia-base.service; echo "rc=$?"
sudo journalctl -u canario-copia-base.service --no-pager -n 5
```

Tiene que salir `COPIA SUBIDA: objeto=base/AAAAMMDDTHHMMSSZ.age bytes=...`. Se comprueba en la consola de B2 que el objeto existe y tiene retención (candado, hasta 30 días), y en la de healthchecks.io que llegó el latido con el `fileId` y el `sha1` en su registro. Si dice que la clave tiene capacidades de más o es de otro bucket, se crea otra clave y no se sigue con esta. Después, los eventos (la primera vez exportan todo el log que haya; si no hay ningún `EVENTO` de los tres tipos, no suben nada, el rc es 0 y el latido de los eventos llega igual), y se activan los timers:

```bash
sudo systemctl start canario-copia-eventos.service; echo "rc=$?"
sudo systemctl enable --now canario-copia-base.timer canario-copia-eventos.timer
systemctl list-timers 'canario-copia-*' --no-pager
```

El vigía avisa de los ficheros nuevos. Se mira que digan solo esto, y entonces se rehace su foto: `/usr/local/sbin/canario-copias.py`, las cuatro unidades de `/etc/systemd/system`, los enlaces de `timers.target.wants` y `/etc/canario-copias`.

```bash
sudo /usr/local/sbin/vigia.sh base
```

**Códigos de salida de `copias.py`** (la unidad queda fallida con cualquiera distinto de 0, y el vigía avisa de las unidades fallidas): 0 bien; 1 error inesperado (o cursor dañado); 2 argumentos; 3 destinatarios o credenciales no válidos (tiene que haber exactamente dos destinatarios `age1pq1...` distintos); 4 B2 rechaza la clave, esta tiene permisos de más o es de otro bucket; 5 hueco en el log de eventos (persiste hasta reconocerlo); 6 la base no sirve para copiar (sin ninguna empresa, con la cadena de auditoría rota o cambiando durante la copia: **se sube a `cuarentena/`**); 7 falla un proceso (docker, pg_dump, psql o age); 8 falla la subida a B2; 9 la copia se subió pero falla el latido; 10 se agota el presupuesto de tiempo (6600 s en la base, 1500 s en los eventos, por debajo del `TimeoutStartSec` de la unidad) o systemd manda parar (`SIGTERM`): con 10 el `/fail` llega a salir; con `SIGKILL`, no.

Una base sin ninguna empresa va a cuarentena, a propósito: una copia "buena" de un volcado vacío taparía que las denuncias ya no están. Por eso la primera ejecución se hace después de dar de alta la primera empresa. Un objeto en `cuarentena/` nunca se restaura sin haber entendido por qué está ahí: sirve, sobre todo, para saber cuándo empezó el problema.

El volcado se lee a memoria, para que el texto en claro no pase por el disco, con tope de 512 MiB. La base de un canal de denuncias queda muy por debajo; si algún día se acercara, hay que cambiar el diseño, no subir el tope.

#### Restaurar

Todo en el PC, nunca con la clave de age en el VPS, y **todo fuera del repositorio**: el volcado descifrado es texto en claro (emails del personal, nombres de empresa y metadatos de auditoría, ver el simulacro) y un directorio del repo está a un `git add .` de un commit. Se trabaja en `$R`, y del repo solo se montan, en solo lectura, `db/init/01_roles.sh` y `db/pg_hba.conf`. Una copia restaurada **deshace las supresiones y redacciones posteriores a ella**: por eso el último paso (reaplicar los eventos) no es opcional.

```powershell
$R = Join-Path $env:LOCALAPPDATA 'canario-restauracion'
$REPO = 'C:\ruta\al\repositorio'     # la raíz del repositorio (la ruta real, con sus espacios)
New-Item -ItemType Directory -Path $R, "$R\copia", "$R\secretos" | Out-Null
```

(`restauracion/` está además en `.gitignore`, como segunda capa por si alguien lo crea dentro del repo.)

1. **Elegir y descargar.** La clave de B2 del VPS escribe y oculta: root en el VPS puede haber ocultado las copias buenas y subido otras falsas que descifran bien (age no autentica a quien cifra). Por eso no se coge "la más reciente" sin más. Con la clave de **lectura del PC** se listan **todas las versiones**, con la hora de subida que pone B2 (no la del nombre, que la escribe el script), y se elige el objeto de `base/` más reciente que cumpla las tres condiciones: (a) subido **antes del corte de confianza**, que es anterior a la fecha en que se sospecha el compromiso del VPS; (b) su `fileId` y su `sha1` **aparecen en el registro del latido de la base** en healthchecks.io (cuerpos de los pings, desde la pestaña del check), con los mismos valores; (c) su manifiesto, una vez descifrado, es coherente (paso 5). Un objeto de `base/` que el registro no explica, o una acción `hide` que nadie hizo, es la señal de que alguien actuó con la clave del VPS. Lo mismo vale para `eventos/`, contra el registro del latido de los eventos. Estas órdenes siguen la documentación de la API nativa v4 de B2 (`b2_authorize_account`, `b2_list_file_versions`, `b2_download_file_by_id`); no se han ejecutado contra B2 real, y el primer simulacro las ensaya:

   ```powershell
   $cred = Get-Credential -Message 'keyID y applicationKey de LECTURA de B2'
   $basico = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($cred.UserName + ':' + $cred.GetNetworkCredential().Password))
   $auth = Invoke-RestMethod -Uri https://api.backblazeb2.com/b2api/v4/b2_authorize_account -Headers @{ Authorization = "Basic $basico" }
   $api = $auth.apiInfo.storageApi.apiUrl; $token = $auth.authorizationToken; $bucket = $auth.apiInfo.storageApi.allowed.buckets[0].id
   $lista = Invoke-RestMethod -Uri "$api/b2api/v4/b2_list_file_versions?bucketId=$bucket&prefix=base/&maxFileCount=1000" -Headers @{ Authorization = $token }
   $lista.files | Sort-Object uploadTimestamp | ForEach-Object { '{0:u} {1} {2} {3} {4}' -f [DateTimeOffset]::FromUnixTimeMilliseconds($_.uploadTimestamp), $_.action, $_.fileName, $_.fileId, $_.contentSha1 }
   # elegido el fileId (y comprobado contra el registro del latido):
   Invoke-WebRequest -Uri "$($auth.apiInfo.storageApi.downloadUrl)/b2api/v4/b2_download_file_by_id?fileId=$fileId" -Headers @{ Authorization = $token } -OutFile "$R\objeto.age"
   (Get-FileHash "$R\objeto.age" -Algorithm SHA1).Hash.ToLower()   # tiene que ser el sha1 del registro
   ```

2. **Descifrar** con la clave principal (la de respaldo da lo mismo; se saca de Bitwarden a `$R\principal.key`, que se borra con todo `$R` al final) y desempaquetar:

   ```powershell
   & "$env:LOCALAPPDATA\canario-herramientas\age\age\age.exe" -d -i "$R\principal.key" -o "$R\copia.tar" "$R\objeto.age"
   if ($LASTEXITCODE -ne 0) { Remove-Item -Force "$R\copia.tar" -ErrorAction SilentlyContinue; throw 'age -d ha fallado: no se sigue con una salida parcial' }
   tar -xf "$R\copia.tar" -C "$R\copia"
   (Get-FileHash "$R\copia\volcado.dump" -Algorithm SHA256).Hash.ToLower()   # tiene que ser el volcado_sha256 de manifiesto.json
   ```

   age protege un fichero existente: si se ha tocado, falla en vez de entregar basura, y por eso se comprueba `$LASTEXITCODE` y se borra la salida parcial. No impide que alguien fabrique un fichero nuevo: eso lo cubre el registro del paso 1.
3. **Instancia nueva con solo `01_roles.sh`**, sin red (`--network none`). No se aplican `02_esquema.sql` ni los demás: el volcado trae el esquema y los datos. Los secretos de esta instancia son los de la base que se restaura.

   **Simulacro:** secretos inventados con el generador del repo (criptográfico, `secrets.token_urlsafe`), nunca con `Get-Random`, y en `$R`, no en `secrets/` (el generador avisa de que no puede comprobar Git fuera del repositorio; es esperable). Postgres lee los secretos sin extensión:

   ```powershell
   python "$REPO\scripts\generar_secretos.py" --directorio "$R\generados"
   foreach ($n in 'contrasena_postgres_superusuario','contrasena_migrador','contrasena_aplicacion','contrasena_plataforma') { Copy-Item "$R\generados\$n.txt" "$R\secretos\$n" }
   $secretos = @(); foreach ($n in 'contrasena_postgres_superusuario','contrasena_migrador','contrasena_aplicacion','contrasena_plataforma') { $secretos += '--mount', "type=bind,src=$R\secretos\$n,dst=/run/secrets/$n,readonly" }
   ```

   **Producción:** los secretos reales se montan **directamente** desde `secrets/`, solo lectura y solo esos cuatro ficheros, sin copiarlos a ningún sitio (nunca con `-v`):

   ```powershell
   $secretos = @(); foreach ($n in 'contrasena_postgres_superusuario','contrasena_migrador','contrasena_aplicacion','contrasena_plataforma') { $secretos += '--mount', "type=bind,src=$REPO\secrets\$n.txt,dst=/run/secrets/$n,readonly" }
   ```

   Después, igual en los dos casos (del repo solo `01_roles.sh` y `pg_hba.conf`, de solo lectura):

   ```powershell
   docker run -d --name canario-restauracion --network none --user 70:70 --read-only --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=64m --tmpfs /var/run/postgresql:rw,noexec,nosuid,uid=70,gid=70,size=8m -e POSTGRES_DB=canario -e POSTGRES_PASSWORD_FILE=/run/secrets/contrasena_postgres_superusuario --mount type=volume,src=canario-restauracion,dst=/var/lib/postgresql @secretos --mount "type=bind,src=$REPO\db\init\01_roles.sh,dst=/docker-entrypoint-initdb.d/01_roles.sh,readonly" --mount "type=bind,src=$R\copia,dst=/copia,readonly" --mount "type=bind,src=$REPO\db\pg_hba.conf,dst=/etc/postgresql/pg_hba.conf,readonly" canario-postgres postgres -c hba_file=/etc/postgresql/pg_hba.conf -c listen_addresses=* -c unix_socket_permissions=0700 -c password_encryption=scram-sha-256 -c ssl=off
   ```

   Se espera a que `docker logs canario-restauracion` diga que el servidor está listo para aceptar conexiones. Si la imagen no se llama `canario-postgres`, se mira con `docker image ls`. Para restaurar en producción, la instancia es el servicio `postgres` de siempre con un volumen vacío y ese mismo montaje de `init` (un fichero de Compose añadido con `-f` que sustituya el montaje de `/docker-entrypoint-initdb.d`). Ese camino no está ensayado todavía: el primer simulacro en el VPS lo ensaya antes de que haga falta.
4. **Restaurar.** `01_roles.sh` deja la base `canario` creada, así que `pg_restore` la borra y la crea de nuevo (`--clean --if-exists`). `--single-transaction` no se puede combinar con `--create` (`pg_restore.c`, PostgreSQL 18): con `--exit-on-error`, ante cualquier error se **descarta la instancia entera** y se empieza de cero; no se sigue con una a medias.

   ```powershell
   docker exec canario-restauracion pg_restore -U postgres -d postgres --create --clean --if-exists --exit-on-error /copia/volcado.dump; echo "rc=$LASTEXITCODE"
   ```

5. **Comprobar** contra el `manifiesto.json`: los recuentos por tabla y, por empresa, la última secuencia y el último hash, y que la cadena está intacta. Y que el manifiesto dice `"cadena_rota_en": null`, `"estable": true` y `"motivos": []`.

   ```powershell
   docker exec canario-restauracion psql -U postgres -d canario -X -A -t -c "select coalesce(canal.verificar_cadena_auditoria()::text, 'NULL')"
   docker exec canario-restauracion psql -U postgres -d canario -X -A -t -c "select empresa_id, max(secuencia), (array_agg(encode(hash, 'hex') order by secuencia desc))[1] from canal.registro_auditoria group by 1 order by 1"
   docker exec canario-restauracion psql -U postgres -d canario -X -A -t -c "select count(*) from canal.empresa"
   ```

   La primera tiene que dar `NULL`. Si da otra cosa, esa copia está manipulada: se prueba con la anterior (y se investiga).
6. **Reaplicar los eventos**, con el procedimiento de "Protección de datos" (más abajo). Los `eventos/` posteriores a la copia, elegidos con el mismo criterio del paso 1 y descifrados igual (`eventos.log` dentro del tar), son las líneas que ese procedimiento manda buscar en el log. Mientras no se haga, las denuncias declaradas no veraces y los textos tachados desde la copia vuelven a verse.
7. **Borrar todo lo del PC** cuando se acabe (simulacro o restauración de prueba):

   ```powershell
   docker rm -f canario-restauracion; docker volume rm canario-restauracion
   Remove-Item -Recurse -Force $R
   ```

#### Simulacro mensual

Una vez al mes, en el PC: descargar la última copia (elegida como en el paso 1 de "Restaurar": por la hora de subida de B2 y contra el registro del latido), descifrar, restaurar en una instancia desechable (pasos 2 a 4, con secretos inventados) y comprobar la estructura (las tablas, y `select count(*) from pg_policies where schemaname = 'canal'` igual que en la base viva) y la cadena de auditoría (paso 5). Se anota la fecha y el resultado. Después se borra todo (paso 7).

**El simulacro es un tratamiento de datos personales.** Sin la clave maestra no se lee el contenido de las denuncias ni de los mensajes (van cifrados con la clave de cada empresa), pero **no es verdad que no se lea ningún contenido**: el volcado lleva en claro los emails del personal (`usuario_personal.email` y `solicitud_registro.email`, `db/init/02_esquema.sql`), los nombres de empresa (`empresa.nombre`) y los metadatos de auditoría (actor, acción, fecha, ids de objeto y destino). Por eso: se hace en un disco cifrado (BitLocker) y por una sola persona; no se consultan filas con emails ni nombres, solo recuentos y la cadena; no se hacen capturas ni se pega ninguna salida con datos en chats o tickets; el volcado descifrado no sale de `$R` y se borra al acabar; y el simulacro se anota en el registro de actividades del tratamiento (RGPD, art. 30) con su finalidad (comprobar que la copia existe, se descifra, se restaura y no está manipulada) y su plazo (el tiempo que dura). Es, junto con los latidos, el control frente a un VPS comprometido: alguien con root puede parar, envenenar u ocultar las copias, y solo se ve desde fuera.

#### Custodia de las claves

| Qué | Dónde | Por qué |
|---|---|---|
| Clave age principal (`principal.key`) | Bitwarden, con 2FA | Es la que se usa cada mes en el simulacro |
| Clave age de respaldo (`respaldo.key`) | Impresa en papel, en casa | Si se pierde la principal, las copias siguen abriéndose |
| Clave de **lectura** de B2 del PC (`keyID` y `applicationKey`, con `listFiles` y `readFiles`) | Bitwarden, con 2FA | Es la única forma de listar versiones y descargar para el simulacro y las restauraciones; no va al VPS, y si se pierde se crea otra en la consola de B2 |
| Clave maestra y `clave_hmac_codigos` (de `secrets/`) | USB cifrado con BitLocker, en otro lugar | La clave maestra desenvuelve las claves de cada empresa; sin `clave_hmac_codigos`, los códigos de seguimiento dejan de valer |

**Nunca la clave de age junto a la maestra**: quien tenga las dos lee todas las denuncias de todas las copias (modelo de amenazas, 6.4 y 8). Y sin `clave_hmac_codigos`, una restauración completa deja a los denunciantes sin poder seguir su denuncia.

**Pendiente de Eduardo (RGPD):** Backblaze es un encargado del tratamiento en EE. UU.: falta el contrato de encargado (DPA) y anotarlo en el registro de actividades. Lo que ve Backblaze son datos cifrados, su tamaño y la hora de subida.

### Lo que hay que vigilar

- **Si Dokploy recrea su Traefik** (al actualizarlo o al cambiar sus ajustes), pierde la conexión a `edge` y el reconciliador la repone en un minuto como mucho (arriba). A Inmunia le pasa lo mismo y este reconciliador no la cubre.
- **El correo sale solo con la credencial de Mailjet puesta.** Mientras `secrets/smtp_usuario.txt` tenga el marcador, el cartero lo dice al arrancar (`EVENTO correo_sin_credenciales`) y Mailjet rechaza cada correo (`EVENTO correo_fallido` en su log): el registro y los avisos no llegan. Se configura en [Correo en producción](#correo-en-producción-mailjet). Mientras tanto, las cuentas se crean por invitación desde **Cuentas** (el enlace se muestra una vez) o con `gestion alta-admin`.
- **El log del cartero** (`sudo docker compose -f docker-compose.yml -f compose.produccion.yaml logs cartero`) es donde se ve si el correo sale: `correo_aplazado` repetido es un proveedor que no responde, y `motivo=certificado` es que el certificado de quien contesta no vale, que es lo que se vería si alguien se hiciera pasar por Mailjet.
- **El login con Google** sigue apagado mientras `secrets/google_client_id.txt` tenga el marcador. Para activarlo, el URI de redirección registrado en Google pasa a ser el de `canario-personal.eduumr.dev`.

### Correo en producción (Mailjet)

El cartero (`app/cartero.py`) entrega a Mailjet por TLS implícito en el 465 (`in-v3.mailjet.com`), con el certificado verificado, desde `no-responder@canario.eduumr.dev` y sin el seguimiento de enlaces de Mailjet: con él, Mailjet reescribiría cada enlace por uno suyo y el token de las invitaciones acabaría en sus registros (modelo de amenazas, 6.3). Se configura una vez, en este orden: los pasos 1 a 3 en Mailjet y en Cloudflare; después, desplegar en el VPS una versión que ya tenga el cartero (como en [Actualizar](#actualizar)); y solo entonces los pasos 4 a 6, que lo necesitan en marcha.

1. **La cuenta de Mailjet**, con segundo factor (una aplicación, no SMS). Quien entre en ella puede leer el historial de envíos y mandar correos con el nombre de Canario.
2. **El dominio** `canario.eduumr.dev` como remitente en Mailjet. Mailjet da los registros DNS que tiene que haber: el de SPF y el de DKIM. Se añaden en Cloudflare **tal cual los da Mailjet** (TXT, en `canario.eduumr.dev` el de SPF y en el nombre que indique el de DKIM) y se espera a que Mailjet los dé por buenos. DKIM es el que importa para DMARC: firma con `d=canario.eduumr.dev`, que es el dominio del remitente.

   Dos trampas de la pantalla de Mailjet. Enseña el SPF con Hostname `@`, que para Mailjet es el propio `canario.eduumr.dev`; en Cloudflare la zona es `eduumr.dev`, así que el nombre que se escribe es `canario` (con `@` el registro acabaría en `eduumr.dev`, el dominio de las demás aplicaciones). Y no se usan "Continue with Cloudflare" ni "Configure automatically": delegan en Mailjet la escritura en los DNS de `eduumr.dev`, que también son los de las demás aplicaciones, cuando basta con copiar dos registros a mano y revisarlos. Para comprobarlos, DNS sobre HTTPS como en el paso 5 de la primera vez, con `type=TXT`.

3. **El seguimiento, apagado también en la cuenta** (Account settings, tracking). El cartero ya manda `X-Mailjet-TrackClick: 0` y `X-Mailjet-TrackOpen: 0` en cada correo, y Mailjet documenta que mandan sobre la cuenta; apagarlo en la cuenta es la segunda capa.
4. **La credencial, en el VPS** (bash, en `~/apps/canario`), con el cartero ya desplegado. Es la clave API y la clave secreta de Mailjet (su sección SMTP). `read -s` no la enseña ni la deja en el historial, y `printf '%s'` la escribe sin salto de línea, como exige el cartero:

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

1. En Google Cloud Console, la pantalla de consentimiento (Google Auth Platform) de tipo Externo. Sin permisos extra: Canario solo pide `openid`, ni el email. Por eso no hace falta añadir usuarios de prueba, aunque la aplicación siga en modo de pruebas: Google exime de esa lista, del aviso de aplicación no verificada y de la caducidad a los 7 días a las aplicaciones que solo piden `openid`, `email` o `profile` ([Manage App Audience](https://support.google.com/cloud/answer/15549945)); que Canario pide solo `openid` lo comprueba `verificar_externo.py` (d). La barrera no es esa lista: en Canario solo entra con Google quien fue invitado, tiene el segundo factor y vinculó su cuenta (paso 4). Después, un cliente OAuth de tipo "Aplicación web" con la URI de redirección exacta `https://localhost:8445/v1/personal/externo/google/vuelta` (en otro despliegue, el origen de `CANARIO_ORIGEN_PERSONAL`) y sin orígenes de JavaScript.

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

4. Usarlo: la primera vez se entra con contraseña y código, que deja el dispositivo de confianza en ese navegador. En **Mi cuenta**, sección **Cuentas externas**, "Vincular Google" pide un código y lleva a Google. Desde entonces, en ese navegador, "Iniciar sesión con Google" y el código. Google nunca sustituye al código ni crea la confianza.

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

- **El log de la API sale del anfitrión** y se conserva al menos tanto como las copias. El compose lo rota en 3 ficheros de 10 MB: sin enviarlo fuera, se pierde antes que la copia. Lo hace `canario-copia-eventos.timer` ("Copias de seguridad", más arriba): exporta cifradas, cada 15 minutos, solo las líneas `declaracion_no_veraz`, `redaccion` y `reutilizacion_renovacion`, y falla de forma visible si la rotación se come líneas. Esos objetos se conservan los mismos ~31 días que las copias de la base.
- **Tras restaurar una copia**, antes de nada:
  1. Busca en ese log las líneas `EVENTO declaracion_no_veraz` y `EVENTO redaccion` posteriores a la fecha de la copia.
  2. Por cada declaración, un admin se asigna la denuncia y la vuelve a declarar no veraz.
  3. Por cada redacción, el admin asignado vuelve a tachar los mismos tramos: el evento da la posición y la longitud, y el texto lo ve al leer la denuncia.
  4. Ejecuta `suprimir-caducadas`. Las denuncias caducadas se suprimen solas; las no veraces, con esta ejecución.
