# Canario

Canario es un canal de denuncias anónimo multiempresa, pensado para cumplir la Ley 2/2023, reguladora de la protección de las personas que informen sobre infracciones normativas y de lucha contra la corrupción. Este repositorio contiene el backend: una API REST con FastAPI, PostgreSQL y Redis, detrás de un proxy Caddy, todo con Docker Compose. No tiene frontend.

Las amenazas consideradas, las decisiones de diseño y sus límites están en el [modelo de amenazas](docs/threat-model.md). Este README explica cómo ponerlo en marcha, operarlo y verificarlo.

## Qué hay en el repositorio

| Ruta | Contenido |
|---|---|
| `app/` | La API (`principal.py` y las rutas) y la herramienta de administración `gestion.py` |
| `db/` | Imagen de PostgreSQL, `pg_hba.conf` y el esquema, que se aplica al crear la base de datos (`db/init/`) |
| `proxy/` | Imagen y `Caddyfile` del proxy, el único punto de entrada |
| `scripts/generar_secretos.py` | Crea los secretos que faltan y comprueba el conjunto |
| `tests/security/` | Las siete baterías de pruebas de seguridad |
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

   Crea en `secrets/` solo los que faltan y nunca sobrescribe uno existente: una clave maestra regenerada dejaría ilegibles los datos ya cifrados. No imprime ningún valor. `secrets/` está fuera de Git; haz copia de seguridad de la clave maestra por un canal seguro, porque sin ella los datos no se pueden descifrar. Guárdala **separada** de las copias de la base de datos: una copia de la base de datos junto con la clave maestra descifra todo lo que contenga, también lo ya suprimido o tachado (modelo de amenazas, 8).

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

El único puerto publicado es `127.0.0.1:8443`, y solo con el nombre `localhost`: cualquier otro `Host` recibe 421. Para servir a internet hace falta un proxy o balanceador delante, que es decisión de cada despliegue (modelo de amenazas, 6.11 y 8).

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
| `POST /v1/personal/sesiones`, `DELETE /v1/personal/sesiones/actual` | personal | Entrar y salir |
| `GET /v1/personal/yo`, `POST /v1/personal/contrasena` | personal | Datos de la propia cuenta y cambio de contraseña |
| `/v1/personal/usuarios...` | admin | Invitar, reinvitar, anular invitaciones y dar de baja |
| `/v1/personal/denuncias...` | personal | Listar, leer, asignar, cambiar de estado y escribir mensajes |
| `POST /v1/personal/denuncias/{id}/redaccion` y `.../mensajes/{secuencia}/redaccion` | admin con la denuncia asignada | Tachar datos que no deben conservarse (art. 32.2) |
| `GET /v1/personal/auditoria` y `/auditoria/verificacion` | admin | Leer la auditoría y verificar su cadena |

El código de seguimiento es lo único que identifica al denunciante: va en el cuerpo, nunca en la URL, para que no quede en ningún log.

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

Siete baterías, una por área. Cada prueba negativa lleva su control positivo: si el control falla, el resultado es `SIN CONCLUSION`, nunca `PASA`. Los resultados esperados están escritos como literales en la propia batería, no derivados del código que se prueba.

| Batería | Qué prueba |
|---|---|
| `verificar_esqueleto.py` | Proxy y API: sin salida a internet, único puerto, cabeceras, 421, logs sin IP, endurecimiento de los contenedores |
| `verificar_arranque.py` | Conexión a PostgreSQL con secretos y el arranque verificado de la API |
| `verificar_esquema.py` | Esquema, RLS entre empresas, permisos, auditoría encadenada y supresión legal en la base de datos |
| `verificar_denuncia.py` | Cifrado, denuncia anónima, seguimiento, mensajes, limitador y supresión por la API y `gestion` |
| `verificar_personal.py` | Identidad del personal, login, bloqueos, sesiones, administración, instrucción y no veraz (art. 32.3) |
| `verificar_inyeccion.py` | Inyección SQL y validación de la frontera de entrada |
| `verificar_escaneos.py` | Secretos en Git, dependencias, análisis estático, imágenes y SBOM |

Para ejecutarlas:

- Docker en marcha y los secretos generados.
- **La pila de Canario parada** (`docker compose down`, nunca con `-v`): esqueleto, arranque, denuncia, personal e inyección arrancan su propia copia con las mismas subredes fijas, y si están ocupadas se detienen con `PARADA`.
- `verificar_escaneos.py` necesita internet: descarga las herramientas fijadas y la base de datos de vulnerabilidades.

```powershell
python tests\security\verificar_esquema.py
```

Cada batería usa un proyecto de Docker propio (`canario_<nombre>`), lo borra entero al terminar (contenedores, redes, volúmenes e imágenes locales) y comprueba que no ha modificado el repositorio. Termina con `RESULTADO GLOBAL: OK` o `NO OK`, y su código de salida es 0 solo si es OK.
