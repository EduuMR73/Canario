# Operación

Cómo se opera Canario fuera de la demo: la puesta en marcha completa (sin el perfil de desarrollo), la herramienta `gestion`, la supresión legal programada y el log y las copias de seguridad. La instalación básica está en el [README](../README.md).

## Puesta en marcha

Las órdenes se ejecutan en PowerShell desde la raíz del repositorio. Como la ruta puede tener espacios, va siempre entre comillas.

1. Generar los secretos:

   ```powershell
   python scripts\generar_secretos.py
   ```

   Crea en `secrets/` solo los que faltan y nunca sobrescribe uno existente (si actualizas desde una versión anterior, vuelve a ejecutarlo: crea solo los que falten, como `clave_hmac_identidades.txt` y `clave_flujo_externo.txt`, las dos claves del login externo; sin ellas, `docker compose` no arranca): una clave maestra regenerada dejaría ilegibles los datos ya cifrados. No imprime ningún valor. `secrets/` está fuera de Git; haz copia de seguridad de la clave maestra por un canal seguro, porque sin ella los datos no se pueden descifrar. Guárdala **separada** de las copias de la base de datos: una copia de la base de datos junto con la clave maestra descifra todo lo que contenga, también lo ya suprimido o tachado (modelo de amenazas, 8).

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
- `8445`: la SPA del personal, en el suyo: `https://localhost:8445/`. Hoy tiene el acceso (entrar, activar una cuenta y solicitar el acceso, en [api.md](api.md)), el menú de cada rol, las pantallas del admin para las cuentas y las solicitudes, las de las denuncias para el admin y el instructor y la de la auditoría para el admin y el auditor, y reenvía la API del personal con la sesión en cookies.
 Para servir a internet hace falta un proxy o balanceador delante, que es decisión de cada despliegue (modelo de amenazas, 6.11 y 8).

Para parar sin perder datos:

```powershell
docker compose down
```

Nunca `docker compose down -v` en una instalación con datos: `-v` borra los volúmenes, es decir, la base de datos y la autoridad de certificación de Caddy.

**Actualizar una instalación existente.** Canario no tiene migraciones: el esquema de `db/init/` solo se aplica con el volumen de la base de datos vacío. Si una versión nueva cambia el esquema (por ejemplo, la tabla `identidad_externa` del login externo), la API no arranca con la base de datos anterior y su log dice qué falta (`ARRANQUE BLOQUEADO: tablas: ...`, modelo de amenazas, 6.10): falla de forma visible, no a medias. Una instalación de prueba se pone al día recreando el volumen (`docker compose down -v` y arrancar), con lo que pierde sus datos. Para una con datos haría falta aplicar a mano la parte nueva del esquema como superusuario; ese procedimiento no está preparado (modelo de amenazas, 8).

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
