# Modelo de amenazas

Canario: canal de denuncias anónimo multi-empresa. Backend API REST (FastAPI, PostgreSQL).

Estado del documento: borrador 3. Las decisiones técnicas de infraestructura y de base de datos se han contrastado con documentación (sección 11), y la frontera con el exterior (proxy y API) además con pruebas reales (`tests/security/verificar_esqueleto.py`). Lo que sigue pendiente está marcado como **[VERIFICAR]**.

## 1. Objetivo y alcance

El sistema permite que una persona denuncie de forma anónima irregularidades en una organización y mantenga una conversación con quien instruye el caso, sin que su identidad quede registrada en ningún punto del sistema.

Dentro del alcance: la API, la base de datos, el almacenamiento de adjuntos, el proxy inverso, Redis y el envío de avisos al personal.

Fuera del alcance: el frontend, el cliente del denunciante, la red del usuario y el sistema operativo del servidor anfitrión.

## 2. Actores

| Actor | Descripción | Nivel de confianza |
|---|---|---|
| Denunciante anónimo | Solo posee un código de seguimiento | Ninguno, solo su código |
| Atacante externo | Sin cuenta ni código | Nulo |
| Instructor | Personal que gestiona denuncias asignadas de su empresa | Parcial, limitado a su empresa y rol |
| Admin de empresa | Gestiona usuarios y configuración de su empresa | Parcial, limitado a su empresa |
| Superadmin de plataforma | Da de alta empresas | No puede leer denuncias |
| Empresa hostil | Un tenant que intenta acceder a datos de otro | Nulo fuera de su empresa |
| Empresa denunciada | Intenta identificar al denunciante | Nulo |
| Acceso a BD o backups | Persona con volcado o copia de la base de datos | Nulo sobre el contenido |

## 3. Activos, por criticidad

1. Identidad del denunciante (incluye cualquier dato que permita inferirla).
2. Contenido de denuncias, mensajes y adjuntos.
3. Claves de cifrado (clave maestra y claves por empresa).
4. Credenciales del personal y secretos TOTP.
5. Log de auditoría.

## 4. Fronteras de confianza

```
Internet -> proxy (Caddy) -> API (FastAPI) -> PostgreSQL
                                           -> Redis (sin persistencia)
                                           -> SMTP (avisos al personal)
                                           -> Volumen de adjuntos (cifrado)
```

Cada flecha es una frontera: lo que cruza se valida, se limita y se registra sin datos identificativos.

## 5. Principios de diseño

- **Defensa en profundidad:** el aislamiento entre empresas se aplica en la aplicación y de nuevo en la base de datos (Row Level Security).
- **Falla cerrado (fail securely):** ante un error en un control de seguridad se deniega, nunca se permite. Sin contexto de empresa, las consultas devuelven cero filas. Sin limitador, se rechaza.
- **Mínimo privilegio:** la API nunca conecta como superusuario ni como dueño del esquema.
- **Explícito sobre implícito:** los permisos se conceden uno a uno, no se heredan por defecto.
- **Lo que no se guarda no se puede filtrar:** no se almacenan IPs ni horas exactas.
- **Los fallos son visibles:** los errores de seguridad se registran (sin datos personales) y no se silencian.

## 6. Decisiones de diseño relevantes

### 6.1 Anonimato real

El denunciante no tiene cuenta. La única credencial es un código aleatorio de 128 bits generado con `secrets`. Solo se guarda su HMAC, calculado con una clave del servidor. Si se pierde el código no hay recuperación: es el precio del anonimato.

El anonimato no depende solo de la aplicación. También exige que el proxy no registre IPs, que Redis no persista nada y que los contadores de rate limit usen IP hasheada con una sal que rota y vive solo en memoria (ver 6.8).

### 6.2 Aislamiento entre empresas

- `ENABLE` y `FORCE ROW LEVEL SECURITY` en todas las tablas con datos de empresa. Sin `FORCE`, el dueño de la tabla se salta las políticas; superusuarios y roles con `BYPASSRLS` las saltan siempre. Sin política, el acceso se deniega.
- La política compara `company_id` con una variable de sesión fijada con `set_config(..., true)` dentro de cada transacción, con parámetro enlazado (nunca concatenado). Tras la transacción, `current_setting(..., true)` devuelve cadena vacía y no NULL, por eso la política usa `nullif(..., '')`. Es imprescindible con pool de conexiones.
- Roles de base de datos separados: `migrator` (dueño del esquema), `app_rw` (API, sin `BYPASSRLS`, sin `TRUNCATE` ni `REFERENCES`), `platform_ops` (alta de empresas, sin acceso a denuncias).
- Las comprobaciones de unicidad y de claves foráneas se saltan RLS. Para que un error de duplicado no revele datos de otra empresa, las restricciones `UNIQUE` incluyen `company_id` y las claves foráneas son compuestas (`company_id`, `id`).
- Tablas de búsqueda sin RLS y sin permisos directos para la API: `tracking_lookup` (HMAC del código, `report_id`, `company_id`) y `company_directory` (`public_id`, `company_id`). Solo se leen a través de funciones.
- Funciones `SECURITY DEFINER` (`resolve_company`, búsqueda de código): `search_path` fijado sin esquemas escribibles y con `pg_temp` al final; `REVOKE EXECUTE ... FROM PUBLIC` explícito y `GRANT EXECUTE` solo al rol que corresponda. Las funciones pertenecen a un rol propio sin `BYPASSRLS`.

### 6.3 Login del personal

Identificador público de empresa más email. El contexto de empresa se resuelve antes de consultar usuarios. El `public_id` no es un secreto, solo un identificador. Las respuestas son uniformes (empresa inexistente, email inexistente y contraseña errónea producen el mismo error y un tiempo comparable, con un hash Argon2id ficticio cuando el usuario no existe).

### 6.4 Cifrado

Envelope encryption: clave maestra fuera de la base de datos, clave por empresa envuelta por la maestra. AES-256-GCM con datos asociados (`company_id`, `report_id`) para impedir mover un texto cifrado de una fila a otra. Campo `key_version` para permitir rotación.

### 6.5 Metadatos

- La fecha de la denuncia se guarda redondeada al día; la hora exacta no se almacena.
- Los mensajes usan un número de secuencia, no marca de tiempo.
- Los avisos al personal se agrupan con retraso aleatorio y no incluyen contenido.
- Al denunciante no se le notifica nunca: pedirle un email rompería el anonimato.

### 6.6 Adjuntos

Solo imágenes (re-codificadas, lo que elimina EXIF) y PDF limpiados de metadatos. Se rechazan formatos Office por los metadatos de autor. Validación por magic bytes, tamaño máximo, nombre UUID, cifrado, almacenamiento fuera de cualquier ruta servida y descarga forzada.

### 6.7 Auditoría

La API tiene `INSERT` y `SELECT` (este último bajo RLS) sobre el log, nunca `UPDATE` ni `DELETE`. El hash encadenado lo calcula un trigger en la base de datos, con bloqueo por empresa para evitar carreras.

### 6.8 Infraestructura sin rastro de IP

- **Caddy:** no se declara la directiva `log` en ningún sitio, de modo que no hay logs de acceso. Los logs de runtime sí están activos y pueden contener IPs (por ejemplo errores de handshake TLS y errores de upstream). El campo `msg` no se puede filtrar, así que se excluye el logger `http.stdlib` en la opción global `log` y en el resto se borran los campos de IP con el filtro `delete`. No se usan `hash` ni `ip_mask` como anonimización: `hash` conserva solo 4 bytes de SHA-256 y es invertible por fuerza bruta sobre IPv4. Caddy no confía en ningún proxy por defecto y reemplaza el `X-Forwarded-For` entrante.
- **Uvicorn:** `--no-access-log`, sin `--log-config`. Si algún día se usa `--log-config`, el logger `uvicorn.access` debe desactivarse dentro de esa configuración. `--forwarded-allow-ips` se limita a la IP fija del proxy en la red interna `app` (`10.88.0.2`), no a toda la subred; nunca `*`. Sin esto, todos los clientes parecerían la IP del proxy y compartirían un único contador de rate limit.
- **Redis:** `save ""` y `appendonly no`, sin réplicas, `/data` en tmpfs, contenedor de solo lectura, red interna y comandos peligrosos restringidos. `SAVE` y `BGSAVE` crean un RDB aunque la persistencia automática esté apagada, de ahí la restricción.
- **IP en memoria:** la API usa la IP del cliente solo para derivar el contador de rate limit (hash con sal rotatoria en memoria). No se escribe en base de datos, logs ni disco.

### 6.9 Comportamiento ante fallos

Si Redis no responde, los endpoints con límite (login del personal, seguimiento y creación de denuncia) devuelven 503 con `Retry-After`. Es la regla única, por el principio de fallar cerrado: no existe ningún camino que se salte el limitador. Consecuencia asumida: durante una caída de Redis, un denunciante debe reintentar. No se expone nada, porque no se almacena nada. Cada rechazo por este motivo genera un evento de seguridad visible, sin IP.

Alternativa descartada por ahora: un limitador local en memoria, más estricto, como plan B. Es menos seguro que el 503 (contadores por proceso, se pierden al reiniciar) y añade código poco ejercitado. Queda como "diseñado, no implementado".

Nota de defensa en capas: el bloqueo progresivo de una cuenta del personal vive en PostgreSQL, no en Redis, y se suma al 2FA. Aunque el limitador no esté disponible, adivinar la contraseña de una cuenta concreta sigue frenado.

### 6.10 Secretos y arranque verificado

- Los secretos se pasan como ficheros (Docker secrets), no como variables de entorno. La imagen de PostgreSQL acepta `POSTGRES_PASSWORD_FILE` para el superusuario; las contraseñas del resto de roles se establecen en un script de inicialización que lee los secretos.
- Los scripts de inicialización solo se ejecutan con el directorio de datos vacío, y si uno falla y el contenedor se reinicia, el resto se salta sin aviso. Para que ese fallo no sea silencioso, al arrancar la API comprueba roles (`rolsuper` y `rolbypassrls` en falso), RLS y `FORCE` en cada tabla y permisos, y se niega a arrancar si algo no coincide.
- La rotación de contraseñas no pasa por el script de inicialización y requiere un procedimiento propio, documentado.

### 6.11 Frontera con el exterior: proxy y API

- **Redes:** la API solo está en la red `app` (interna, `10.88.0.0/28`); se conectará a `data` y `cache` cuando el núcleo las use. Caddy está en `app`, con la IP fija `10.88.0.2`, y en `edge` (`10.88.1.0/28`), la única red no interna, porque una red interna no puede publicar puertos. Las subredes están fuera de los rangos que Docker asigna por defecto. `ip_range` (`.8/29`) limita las IPs automáticas y reserva de `.2` a `.7` para IPs fijas: sin ello, la API arranca primero, recibe la `.2` y el proxy no puede tomarla.
- **Puertos:** el único puerto publicado es el de Caddy, `127.0.0.1:8443`, nunca `0.0.0.0` y sin puerto 80. Caddy escucha en 8443, que no es privilegiado, así que no necesita `NET_BIND_SERVICE`.
- **Caddy:** `admin off` (sin API de administración), `persist_config off` (`admin off` no desactiva el autosave de la configuración en `/config`), `auto_https disable_redirects`, `tls internal` (CA local, sin ACME), `protocols h1 h2` (sin listener UDP de HTTP/3) y `strict_sni_host on`: un `Host` distinto del SNI recibe 421. Sin esto, una petición con un `Host` desconocido no casa con ninguna ruta y Caddy responde 200 vacío.
- **Imagen de Caddy:** la oficial trae el binario con la file capability `cap_net_bind_service=ep`. Con `cap_drop: ALL` el kernel rechaza el `execve`. Se elimina con `setcap -r` en una imagen propia, en vez de devolver la capability al contenedor. `/data/caddy` (CA y clave privada) pasa de `1777` a `0700`, propiedad del usuario de Caddy. Es el único estado persistente (volumen `caddy_datos`); `/config` no se monta y queda en solo lectura.
- **API:** solo `GET /salud` (vivacidad, sin tocar base de datos ni Redis), sin `/docs`, `/redoc` ni `/openapi.json` y sin redirección de barra final. `--no-server-header`. El healthcheck no usa curl: solo da sano con 200 y el cuerpo exacto.
- **Contenedores:** usuarios no root con uid fijo (API 10001, Caddy 10002), `read_only`, `cap_drop: ALL`, `no-new-privileges`, `mem_limit` y `pids_limit`, sin tmpfs.
- **Cabeceras:** `Strict-Transport-Security: max-age=63072000` (sin `includeSubDomains` ni `preload` mientras el nombre sea `localhost`), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, `Cache-Control: no-store`, y sin cabecera `Server`.
- **Dependencias:** versión exacta y `sha256` de todos los ficheros publicados en PyPI, instaladas con `--require-hashes` y `--only-binary :all:`. Se resuelven en un contenedor de `python:3.12-slim`, no en Windows, porque los marcadores de plataforma darían otro resultado. La imagen final no lleva pip. `fastapi` exige `opentelemetry-api`: sin SDK es una implementación vacía que no registra ni envía nada (comprobado). Imágenes base fijadas por versión y digest.
- **Límite asumido:** la red `edge` da a Caddy salida a internet; es inevitable para publicar el puerto. **[VERIFICAR]** Que Caddy funcione sin esa salida (`tls internal` no usa ACME, pero no se ha probado con la red cortada).

## 7. Tabla de amenazas

| Amenaza | Mitigación | Test que lo demuestra |
|---|---|---|
| Fuerza bruta del código | 128 bits, HMAC, rate limit, respuesta uniforme | Ráfaga de intentos devuelve 429 |
| IDOR entre empresas | RLS con `FORCE`, rol sin `BYPASSRLS`, filtro también en la app | Token de A pide recurso de B y recibe 404 |
| Arrastre de contexto entre peticiones | `set_config` local a la transacción, `nullif` en la política | Dos peticiones seguidas de empresas distintas no se mezclan; sin contexto devuelve cero filas |
| Fuga de existencia entre empresas | `UNIQUE` con `company_id`, claves foráneas compuestas | Insertar un dato duplicado de otra empresa no produce un error distinguible |
| Abuso de funciones `SECURITY DEFINER` | `search_path` fijado, `REVOKE` de PUBLIC, `GRANT` mínimo | Un rol no autorizado no puede ejecutar la función |
| Escalada de rol | Permisos por rol, denegar por defecto | Instructor llama a endpoint de admin y recibe 403 |
| Inyección SQL | Consultas parametrizadas, usuario de BD de mínimo privilegio | Payloads clásicos no alteran nada |
| Robo de cuenta del personal | Argon2id, tokens cortos, 2FA TOTP, bloqueo progresivo | Login sin segundo factor falla |
| Relleno de credenciales | Rate limit por empresa y por cliente | Ráfaga contra una empresa se bloquea |
| Redis caído o manipulado | Rechazo con 503, sin camino alternativo sin límite | Con Redis parado, login, seguimiento y denuncia devuelven 503 |
| Desanonimización por metadatos | Sin IP, fecha a día, secuencia en vez de hora, avisos diferidos | Revisión de filas: no hay IP ni hora exacta |
| IP en logs de proxy, API o Redis | Sin logs de acceso, logger excluido, campos borrados, Redis sin persistencia | Tras una ráfaga de peticiones, ningún log ni volumen contiene la IP de prueba (proxy y API comprobados; Redis pendiente) |
| IP falsificada con `X-Forwarded-For` | Caddy sin `trusted_proxies`; uvicorn solo confía en la IP fija del proxy | Un XFF falso no llega a la API; directo a la API, uvicorn ignora el XFF |
| Exposición de servicios internos | API solo en red interna; único puerto publicado el del proxy, en `127.0.0.1` | La API no sale a internet; `docker inspect` solo muestra `127.0.0.1:8443` |
| Superficie de la API sin autenticar | Solo `/salud`, sin documentación ni OpenAPI, `Host` distinto del SNI rechazado | Otras rutas dan 404; `Host` distinto da 421 |
| Escalada dentro de un contenedor | No root, `read_only`, `cap_drop: ALL`, `no-new-privileges`, sin file capabilities | `CapEff`, `CapPrm` y `CapBnd` a cero; `NoNewPrivs` a 1 |
| Pérdida del CA local de Caddy | Volumen con nombre en `/data`, sin estado en `/config` | El CA es el mismo tras `restart` y tras `down` y `up` |
| Fichero malicioso | Magic bytes, tamaño, UUID, cifrado, fuera de ruta servida | Ejecutable renombrado a `.jpg` rechazado |
| Fuga de BD o backup | Envelope encryption con AAD | El volcado no contiene texto en claro |
| Enumeración de empresas y usuarios | Identificadores aleatorios, errores y tiempos uniformes | Empresa inexistente y prohibida responden igual |
| Spam en el endpoint anónimo | Rate limit y tamaño máximo | Ráfaga de denuncias bloqueada |
| Manipulación de la auditoría | Sin `UPDATE`/`DELETE`, hash encadenado por trigger | Un `UPDATE` o `DELETE` desde la app falla |
| Inicialización de BD incompleta y silenciosa | Comprobación de arranque de roles, RLS y permisos | Con un rol mal creado la API no arranca |
| Secretos y dependencias | `.env` fuera de Git, secretos como ficheros, gitleaks, `pip-audit`, contenedores sin root | Escaneo limpio |

## 8. Límites asumidos

Estos límites se documentan, no se esconden:

- **Servidor completamente comprometido** con acceso a la clave maestra: el atacante puede descifrar.
- **Inyección SQL completa:** RLS por variable de sesión protege de errores de lógica y de filtros olvidados, pero quien lograra ejecutar SQL arbitrario podría fijar él mismo la variable de empresa. La defensa real es no permitir esa inyección (consultas parametrizadas) y limitar los privilegios del rol de la API.
- **Observador de red:** la IP del denunciante es visible para su proveedor y para el servidor en la conexión. La mitigación real es acceder por Tor, fuera del alcance de esta API.
- **Cifrado de extremo a extremo:** no implementado. El servidor descifra contenido para servirlo al personal. Plataformas como GlobaLeaks usan cifrado de cliente; aquí queda como mejora futura.
- **Autoidentificación:** si el denunciante escribe datos que lo identifican en el texto, el sistema no puede evitarlo.
- **Pérdida del código:** sin recuperación.
- **Disponibilidad:** una caída de Redis implica rechazo temporal de peticiones (6.9).

## 9. Cumplimiento normativo

**[VERIFICAR]** Se contrastará con el texto oficial antes de la entrega: obligaciones de la Ley 2/2023 sobre canal interno y comunicaciones anónimas, y plazos de conservación y tratamiento de datos según el RGPD.

## 10. Orden de sacrificio

Si el tiempo aprieta, se recorta en este orden: primero notificaciones, después adjuntos. RLS, auditoría y tests de seguridad no se recortan. Lo no implementado queda documentado como "diseñado, no implementado".

## 11. Verificación de decisiones técnicas

**Contrastado con documentación oficial:** opciones de logging y filtros de Caddy, comportamiento de las cabeceras de reenvío, opciones de Uvicorn, uso de `POSTGRES_PASSWORD_FILE` y de los scripts de inicialización de la imagen de PostgreSQL, comportamiento de RLS (`FORCE`, `BYPASSRLS`, denegación por defecto, exclusiones de integridad referencial), `set_config` local a la transacción y recomendaciones para funciones `SECURITY DEFINER`.

**Contrastado con fuentes secundarias:** desactivación de persistencia de Redis (`save ""`, `appendonly no`), con la salvedad de `SAVE`/`BGSAVE` y la replicación.

**Contrastado con documentación oficial y código fuente (frontera exterior):** opciones globales de Caddy `admin`, `persist_config`, `auto_https`, `skip_install_trust`, `servers` (`protocols`, `strict_sni_host`, `trusted_proxies`) y `log` (`exclude`, filtro `delete`); en el código de Caddy, que `admin off` no desactiva el autosave y que el directorio de configuración solo se usa para `autosave.json`; en el repositorio `caddy-docker`, que la imagen no declara `VOLUME` desde 2022 y que hace `setcap` sobre el binario; opciones de uvicorn `--proxy-headers`, `--forwarded-allow-ips` y `--no-server-header`.

**Comprobado con pruebas reales (`tests/security/verificar_esqueleto.py`, cada negativo con su control):** que la API no tiene salida a internet; que el único puerto publicado es `127.0.0.1:8443`; rutas, cabeceras y 421; que la IP del cliente y el `X-Forwarded-For` falso no aparecen en los logs de Caddy ni de la API ni en el volumen de Caddy tras una ráfaga (control: un Caddy con la directiva `log` sí los registra); que un XFF falso no llega a la API y que uvicorn solo confía en el proxy; usuarios, solo lectura, capacidades y límites; healthcheck sano y roto; ausencia de file capability, de volúmenes anónimos, de autosave y de HTTP/3; y que el CA sobrevive a reinicios. La imagen sin `VOLUME` se confirmó también con `docker image inspect`.

**Pendiente, se cubrirá con tests:**
- Valor por defecto de `password_encryption` y `pg_hba` de la imagen de PostgreSQL.
- Si la imagen de Redis declara un volumen en `/data`, y la sintaxis exacta de las ACL de Redis.
- Ausencia real de IPs en Redis tras una ráfaga de peticiones (proxy y API ya comprobados).
- Escaneo de vulnerabilidades de las imágenes completas (Trivy o similar): `pip-audit` solo cubre las dependencias de `requirements.txt`.
- Que Caddy arranque y sirva sin salida a internet.
