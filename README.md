# Canario

Canal de denuncias anónimo para varias empresas, pensado para cumplir la Ley 2/2023, de 20 de febrero, reguladora de la protección de las personas que informen sobre infracciones normativas y de lucha contra la corrupción.

Quien denuncia no se registra ni da su nombre: escribe la denuncia y recibe un código para seguirla. El personal de la empresa la gestiona desde una aplicación con tres roles.

| Parte | Dirección | Para quién |
|---|---|---|
| Sitio del denunciante (HTML sin JavaScript) | `https://localhost:8444` | Quien denuncia |
| SPA del personal (Angular) | `https://localhost:8445` | Admin, instructor y auditor |
| API REST (FastAPI) | `https://localhost:8443` | Clientes de la API, con el token en la cabecera `Authorization` |

Todo corre en Docker Compose detrás de un proxy Caddy, solo en `127.0.0.1`.

## Cómo cumple el enunciado

| Requisito | Cómo se cumple | Más detalle |
|---|---|---|
| Backend y frontend separados, backend en Python | API REST con FastAPI. La SPA en Angular solo habla con ella por JSON, desde otro origen | [api.md](docs/api.md) |
| Registro de usuarios, con cuidado al guardar las claves | El personal pide acceso con su email, lo confirma y un admin lo aprueba. Las contraseñas se guardan con Argon2id (nunca en claro ni cifradas) y el segundo factor TOTP es obligatorio | [modelo de amenazas, 6.3](docs/threat-model.md) |
| Al menos tres roles | `admin` (cuentas y asignación), `instructor` (las denuncias que tiene asignadas) y `auditor` (la auditoría, nunca el contenido). Quien decide es la API (403), no la SPA | [api.md](docs/api.md) |
| JWT, con cuidado en el refresco | JWT de acceso HS256 de 5 minutos y un token de renovación de un solo uso que rota en cada renovación: si alguien reutiliza uno ya gastado, se cierra la sesión. En el navegador, los tokens van en cookies `__Host-` con `HttpOnly`, y ningún script los lee | [modelo de amenazas, 6.3 y 6.11](docs/threat-model.md) |

El enunciado recomienda React o Vue. Se usa Angular porque trae de serie lo que necesita una SPA con datos sensibles: el sanitizado del HTML y Trusted Types (que permiten una CSP sin `unsafe-inline`), y el router, los formularios y el cliente HTTP del propio proyecto. En ejecución solo depende de tres paquetes de terceros.

## Tecnologías

| Capa | Tecnología |
|---|---|
| Backend | Python 3.12, FastAPI 0.143.0, uvicorn 0.54.0, Jinja2 (páginas del denunciante) |
| Base de datos | PostgreSQL 18.6, con seguridad por filas (RLS) entre empresas |
| Límites de peticiones | Redis 8.10.2 |
| Frontend | Angular 22.2.2, TypeScript 6.0.3 |
| Proxy y TLS | Caddy 2.11.7, con su propia autoridad de certificación |
| Criptografía | Argon2id (argon2-cffi), JWT (PyJWT), AES-GCM para el contenido de las denuncias (cryptography) |
| Correo en desarrollo | Mailpit, en una red sin salida a internet |
| Pruebas | Baterías propias en Python, unittest, Vitest, Playwright con Chromium, ruff, bandit, pip-audit, gitleaks y Trivy |
| Despliegue | Docker Compose. Imágenes fijadas por versión y digest, contenedores de solo lectura, sin capacidades y sin root |

## Puesta en marcha

**Requisitos:** Docker Desktop con `docker compose` (probado con Docker Compose v5.1.4 en Windows) y Python 3.12 (solo la biblioteca estándar). Para el manual de uso, además, una aplicación de autenticación en el móvil (Google Authenticator, Microsoft Authenticator o similar): el segundo factor es obligatorio. Las órdenes son de PowerShell, desde la raíz del repositorio.

```powershell
# 1. Crear los secretos (solo los que faltan; no imprime ninguno)
python scripts\generar_secretos.py

# 2. Arrancar, con el correo de desarrollo (Mailpit)
docker compose --profile desarrollo up -d --build --wait

# 3. Parar sin perder los datos
docker compose --profile desarrollo down
```

> **Nunca `docker compose down -v`** si hay datos que conservar: borra la base de datos y la autoridad de certificación de Caddy.

La puesta en marcha completa (sin Mailpit, cómo comprobar el certificado y la copia de la clave maestra) está en [operacion.md](docs/operacion.md).

## Manual de uso

Un recorrido completo en local. No hay cuentas ni contraseñas de ejemplo: cada cuenta elige la suya al activarse y configura el segundo factor en una aplicación de autenticación del móvil. Conviene ir apuntando el identificador de la empresa, los códigos de seguimiento y las contraseñas que se elijan.

Antes de empezar:

- **El aviso del navegador.** La primera vez que se abre la demo (y quizá de nuevo en otro puerto), el navegador muestra "La conexión no es privada" (`NET::ERR_CERT_AUTHORITY_INVALID`). Es lo esperado: el certificado lo firma la autoridad propia de Caddy, que el navegador no conoce. La conexión va cifrada igual. En Chrome se acepta con **Avanzado** y después **Acceder a localhost (sitio no seguro)**. No conviene instalar esa autoridad como raíz de confianza del sistema: podría firmar un certificado para cualquier dominio.
- **Son dos sitios separados.** El denunciante usa el 8444 y el personal entra por `https://localhost:8445`, que lleva a `/entrar`. Ningún enlace del sitio del denunciante lleva al del personal (el canario de su barra vuelve a su propio inicio): es a propósito.
- **Los correos no llegan a ningún buzón real.** En la demo se quedan en Mailpit y se leen con `python scripts\buzon.py`, que enseña cada enlace en su línea (la hora sale en UTC). La pantalla dirá "recibirá un correo": es lo que pasaría en producción.

### 1. Dar de alta una empresa

```powershell
docker compose run --rm gestion alta-empresa --nombre "Demo S.L." --zona Europe/Madrid
```

En la salida, la línea `empresa creada: ...` termina en `identificador_publico=` y 32 caracteres hexadecimales: es el identificador de la empresa.

> **Cópialo ahora.** Hace falta para todo lo demás, y hasta que el admin entre en la SPA es el único sitio donde aparece: no hay una orden para listar empresas.

### 2. Crear y activar el primer admin

```powershell
docker compose run --rm gestion alta-admin --identificador <identificador> --email admin@demo.test
```

Imprime `token_invitacion=` una sola vez. Abre `https://localhost:8445/activacion#<token>` (con todo lo que va después de `token_invitacion=`) y:

1. Elige una contraseña de 12 caracteres o más, que no contenga el nombre de la empresa.
2. Escanea el código QR con la aplicación de autenticación. Aparece la entrada `Canario: admin@demo.test`.
3. Escribe el código de 6 cifras que muestra la aplicación y pulsa "Activar la cuenta".

Si el móvil no lee el QR, "¿No puede escanear el código QR?" muestra la clave secreta. **No es el código de 6 cifras:** se escribe en la aplicación, y es la aplicación la que da el código.

### 3. Presentar una denuncia (8444)

> **El sitio del denunciante no tiene botón ni buscador de empresas.** Se entra por el enlace del canal de cada empresa, que se forma con su identificador.

El enlace es `https://localhost:8444/empresas/` seguido del identificador del paso 1. Por ejemplo, con un identificador inventado:

```text
https://localhost:8444/empresas/0123456789abcdef0123456789abcdef
```

1. En una ventana privada, abre el enlace, escribe la denuncia y envíala.
2. Apunta el **código de seguimiento** que da la página (un clic lo selecciona entero): es lo único que identifica al denunciante y no se puede recuperar.
3. Con ese código, en `https://localhost:8444/seguimiento`, se consulta el estado y se escriben mensajes.

Si se abre `https://localhost:8444/` sin el enlace, la página pide usar el que da la empresa. Un identificador mal copiado da 404.

**Por qué no hay una lista de empresas:** dejaría a cualquiera averiguar qué empresas usan Canario. En un despliegue real, cada empresa publica el enlace en la página de inicio de su web (art. 25 de la Ley 2/2023).

### 4. Gestionar la denuncia como admin (8445)

1. Entra en `https://localhost:8445/entrar` con el identificador de la empresa, el email, la contraseña y el código de la aplicación.
2. En el **Inicio** está el enlace del canal de la empresa, con el botón "Copiar el enlace" y el enlace "Abrir el formulario".
3. En **Denuncias**, asígnate la denuncia (el desplegable de su fila y "Asignar"). Solo entonces aparece su enlace: el contenido solo lo lee quien la tiene asignada.
4. Abre la denuncia, pulsa "Abrir el expediente", cambia su estado y escribe al denunciante. La respuesta se ve en el 8444 al consultar con el código de seguimiento. Mejor a "En instrucción": si se cierra (resuelta, archivada o inadmitida), en la sección 5 el instructor ya no puede escribir al denunciante.

**Por qué se entra con el identificador y no con el nombre de la empresa:** el nombre no es único, cambia (una fusión, una nueva razón social) y se escribe de varias formas ("S.L." o "SL"). Buscar por nombre, además, dejaría averiguar qué empresas usan Canario. El identificador no es secreto: es el mismo del enlace público del canal.

> **Una cuenta por ventana.** La sesión va en cookies del 8445, así que entrar con otra cuenta en la misma ventana sustituye a la anterior. Lo más cómodo: el admin en una ventana normal y el instructor o el auditor en una ventana de incógnito, que tiene sus propias cookies. Para cambiar de cuenta en la misma ventana, "Cerrar la sesión" en la barra. Cada cuenta añade su propia entrada en la aplicación de autenticación (`Canario: <email>`), que puede guardar varias.

### 5. El instructor: se registra e instruye

1. En `https://localhost:8445/registro`, pide acceso con el identificador y otro email (por ejemplo `instructor@demo.test`).
2. Lee el correo de confirmación con `python scripts\buzon.py` y abre el enlace.
3. Como admin, en **Solicitudes**, apruébala con el rol de instructor.
4. Con `python scripts\buzon.py`, abre la invitación y activa la cuenta como en el paso 2.
5. Como admin, en **Denuncias**, asigna la denuncia al instructor. Desde ese momento el admin ya no puede abrirla: solo la lee quien la tiene asignada.
6. Entra como instructor. Su menú solo tiene Inicio, Denuncias y Mi cuenta. En Denuncias ve solo las suyas: abre la asignada, cambia su estado y escribe al denunciante.

Al activarse una cuenta, los admins y los auditores reciben un aviso sin enlace, que se lee con `python scripts\buzon.py --texto`.

### 6. El auditor: revisa sin leer el contenido

1. Como admin, en **Cuentas**, invita a `auditor@demo.test` con el rol de auditor. El enlace de activación se muestra una sola vez, para entregarlo a mano: cópialo.
2. Abre ese enlace y activa la cuenta como en el paso 2.
3. Entra como auditor. Su menú solo tiene Inicio, Auditoría y Mi cuenta: no ve Denuncias, y a un auditor no se le puede asignar ninguna.
4. En **Auditoría** está todo lo hecho en los pasos anteriores, lo más reciente primero, con el email de quien lo hizo: Entrada, Activación de la cuenta, Invitación, Asignación, Lectura, Mensaje al denunciante, Cambio de estado... El botón "Verificar la cadena" comprueba que ningún registro se ha alterado.

### 7. Cuentas

En **Cuentas**, el admin ve todo el personal con su rol y su estado, invita, reinvita y da de baja.

Invitar, reinvitar, dar de baja y aprobar una solicitud piden además un código de la aplicación de autenticación: con la sesión sola, alguien que la robara no podría crear cuentas ni quitar el acceso a nadie. Cada código vale una sola vez, así que para dos acciones seguidas hay que esperar al siguiente (hasta 30 segundos). Si el código no vale, la página lo dice junto al campo y deja la confirmación abierta para escribir otro. Anular una invitación y rechazar una solicitud no lo piden: solo cierran.

### 8. Entrar con Google (opcional)

Solo si se ha configurado ([operacion.md](docs/operacion.md)); si no, el botón no aparece. En **Mi cuenta**, "Vincular Google" con un código. Después, en el mismo navegador, "Iniciar sesión con Google" en `/entrar` y el código: Google sustituye a la contraseña, no al código.

### Qué más se puede comprobar

| Rol | Ve | No ve |
|---|---|---|
| Admin | Inicio, Denuncias (todas, y abre las asignadas), Cuentas, Solicitudes, Auditoría, Mi cuenta | El contenido de una denuncia asignada a otra cuenta |
| Instructor | Inicio, Denuncias (solo las suyas), Mi cuenta | Cuentas, Solicitudes y Auditoría |
| Auditor | Inicio, Auditoría, Mi cuenta | Denuncias, Cuentas y Solicitudes |

- Quien decide es la API, no la SPA: un instructor o un auditor que pide a la API una ruta de otro rol recibe 403.
- Un código de seguimiento inventado da 404, sin decir si alguna parte era correcta.
- **Declarar no veraz (art. 32.3).** Con una segunda denuncia, porque no tiene vuelta atrás: el admin se la asigna, abre el expediente y pulsa "Declarar no veraz" y después "Confirmar: declarar no veraz". La denuncia desaparece del listado, y su código da en el 8444 el mismo "código de seguimiento no válido" que uno inventado. La destruye la siguiente supresión, que en producción se programa cada hora y en la demo se lanza a mano: `docker compose run --rm gestion suprimir-caducadas`, que responde con una línea `suprimidas: ... articulo=art32_3 denuncias=1`. En Auditoría quedan la declaración y la supresión.
- Cinco intentos de entrada fallidos hacen esperar un minuto a quien entra desde un navegador nuevo, pero el titular sigue entrando desde el suyo.
- Tras 13 minutos sin actividad, la SPA avisa de que la sesión se cerrará en menos de 2 minutos y deja seguir conectado. Si nadie responde, a los 15 lleva a `/entrar` y dice por qué.

## Fallos conocidos

Errores reconocidos que no se han corregido antes de la entrega:

- **Texto bidireccional sin aislar en la SPA.** El texto libre de una denuncia se guarda tal cual, también los caracteres de formato como U+202E, que invierte lo que le sigue. La SPA lo escapa, pero no lo aísla, así que un texto preparado se puede ver desordenado (ATT&CK T1036.002).
- **Avisos que un lector de pantalla puede no anunciar.** Algunos mensajes de la SPA (por ejemplo "Copiado" en Cuentas o la confirmación del registro) se crean a la vez que su región viva. No se ha comprobado con un lector de pantalla real.
- **La redacción no tiene pantalla.** Tachar una parte de una denuncia (art. 32.2) solo se puede hacer por la API.
- **Renovación fallida una vez.** En una prueba a mano, "Seguir conectado" respondió "No hay conexión con el servidor" con el servicio en marcha. No se ha vuelto a reproducir ni se sabe la causa. Si ocurre, basta con volver a entrar.

## Límites aceptados

Decisiones tomadas a sabiendas, con su motivo en la [sección 8 del modelo de amenazas](docs/threat-model.md):

- **Un admin malicioso** puede crear cuentas y dar de baja con su propio código: contra él solo hay detección (aviso por correo y auditoría).
- **El TOTP no resiste el phishing con un proxy en medio**, porque el código no está atado al origen.
- **El código de seguimiento no se puede recuperar.** Es el precio del anonimato.
- **Los correos solo salen a Mailpit.** No hay salida SMTP de producción en esta entrega.
- **La supresión legal no se ejecuta sola:** hay que programarla cada hora ([operacion.md](docs/operacion.md)).
- **No se puede cambiar el nombre de una empresa.**
- **Probado solo en Chromium.** Trusted Types y las pruebas del navegador no se ejecutan en Firefox ni Safari.
- **Sin adjuntos y sin avisos al personal de una denuncia nueva:** diseñados, no implementados (modelo de amenazas, 6.6 y 10).

## Mejoras futuras

1. **Aislar el texto libre** en la SPA (`<bdi>` o `unicode-bidi: isolate`).
2. **Regiones vivas** que existan antes que su texto, para los lectores de pantalla.
3. **Pantalla de redacción** en la SPA.
4. **Adjuntos** y **avisos al personal** de las denuncias nuevas.
5. **Salida de correo de producción**, con SPF, DKIM y DMARC.
6. **Autenticación resistente al phishing** (WebAuthn o passkeys).
7. **Cuatro ojos** para declarar una denuncia no veraz y para tachar, que hoy hace un solo admin.
8. **Cambiar el nombre de una empresa** desde `gestion`, con verificación fuera de banda.
9. **Cifrado de extremo a extremo** y borrado criptográfico, una clave por denuncia.

## Documentación

| Documento | Contenido |
|---|---|
| [docs/api.md](docs/api.md) | Rutas de la API, sesión del navegador, páginas de la SPA y del denunciante, registro y correo de desarrollo |
| [docs/operacion.md](docs/operacion.md) | Puesta en marcha completa, `gestion`, supresión legal programada, log y copias de seguridad |
| [docs/pruebas.md](docs/pruebas.md) | Las doce baterías de seguridad, las pruebas unitarias y ruff, y cómo ejecutarlas |
| [docs/threat-model.md](docs/threat-model.md) | Modelo de amenazas: decisiones de diseño, tabla de amenazas y límites |

## Estructura del repositorio

| Ruta | Contenido |
|---|---|
| `app/` | La API, las páginas del denunciante (`rutas_web.py` y `plantillas/`) y la herramienta `gestion.py` |
| `db/` | Imagen de PostgreSQL y el esquema (`db/init/`) |
| `proxy/` | Imagen y `Caddyfile` del proxy, el único punto de entrada |
| `spa/` | La SPA del personal, que la imagen del proxy compila y sirve |
| `scripts/` | `generar_secretos.py` y `buzon.py` (los correos de Mailpit) |
| `tests/` | Baterías de seguridad (`security/`) y pruebas unitarias (`unit/`) |
| `docs/` | La documentación de la tabla anterior |
