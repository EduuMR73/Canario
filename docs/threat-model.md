# Modelo de amenazas

Canario: canal de denuncias anónimo multi-empresa. Backend API REST (FastAPI, PostgreSQL).

Estado del documento: borrador 6. Las decisiones técnicas de infraestructura y de base de datos se han contrastado con documentación (sección 11), y la frontera con el exterior (proxy y API), la conexión de la API a la base de datos, el cifrado con sus claves y la denuncia anónima con su seguimiento además con pruebas reales (`tests/security/verificar_esquema.py`, `tests/security/verificar_esqueleto.py`, `tests/security/verificar_arranque.py` y `tests/security/verificar_denuncia.py`). Lo que sigue pendiente está marcado como **[VERIFICAR]**.

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

El denunciante no tiene cuenta. La única credencial es un código aleatorio de 160 bits generado con `secrets`. Solo se guarda su HMAC, calculado con una clave del servidor. Si se pierde el código no hay recuperación: es el precio del anonimato.

- **Formato:** 160 bits son 32 caracteres exactos en base32 (RFC 4648), sin relleno ni bits sobrantes, que se muestran en 8 grupos de 4 separados por guiones. Con 128 bits saldrían 26 caracteres con 2 bits sobrantes, y habría que rechazar a mano las formas no canónicas. Al leerlo se admiten minúsculas, guiones y espacios; todo lo demás se rechaza sin distinguir el motivo. Se comprueba que el texto es ASCII antes de pasarlo a mayúsculas: si no, un carácter como la ligadura "ﬀ" se convertiría en dos letras válidas.
- **HMAC:** HMAC-SHA256 con la clave `clave_hmac_codigos`, de uso exclusivo, y una etiqueta de dominio (`canario/seguimiento/v1`) delante del código. No hace falta un hash lento como el de una contraseña: con 160 bits de entropía la fuerza bruta es inviable. La clave del servidor impide además comprobar códigos con un volcado de la base de datos y sin ella. GlobaLeaks hace lo contrario: un recibo de 16 dígitos (unos 53 bits), compensado con Argon2 y prueba de trabajo.
- Implementado en `app/cripto.py`; lo usan `app/denuncias.py` y `app/rutas_denuncias.py`.
- **Alta:** `POST /v1/empresas/{identificador}/denuncias` devuelve 201 con el código y la fecha, y nada más (nunca el id interno de la denuncia). El código se muestra una sola vez. La denuncia y el HMAC de su código se guardan en la misma transacción: o los dos o ninguno.
- **Seguimiento:** `POST /v1/seguimiento` con el código en el cuerpo, nunca en la URL, para que no quede en historiales, en la cabecera `Referer` ni en ningún registro de rutas. Lee en una transacción de solo lectura.
- **Respuestas uniformes:** una empresa desconocida, mal formada o inactiva da exactamente el mismo 404 que cualquier ruta inexistente, así que no se puede distinguir "esa empresa no existe" de "esa URL no existe". Un código mal formado o inexistente da siempre el mismo 404 del seguimiento.
- **Sin sesión:** el código viaja en cada petición, por TLS y sin quedar en ningún log, y la API no guarda estado. GlobaLeaks abre una sesión tras el recibo; aquí queda como alternativa, porque exige estado en el servidor.

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

Envelope encryption: clave maestra fuera de la base de datos, clave por empresa envuelta por la maestra. AES-256-GCM con datos asociados (AAD) para impedir mover un texto cifrado de una fila a otra. Campo `version_clave` para permitir rotación. Implementado en `app/cripto.py` con la biblioteca `cryptography` (la estándar de Python no trae cifrado autenticado).

- **Claves del servidor:** `clave_maestra` (solo envuelve claves de empresa) y `clave_hmac_codigos` (solo calcula el HMAC de los códigos, 6.1). Son Docker secrets, nunca variables de entorno: 32 bytes como 64 hexadecimales en minúscula, generados por `scripts/generar_secretos.py`. La API las lee una vez, al arrancar (`app/claves.py`), y no arranca si alguna falta, no tiene ese formato exacto o las dos son iguales (6.10).
- **Clave de cada empresa:** 32 bytes aleatorios por versión. En `clave_empresa` solo está envuelta con la clave maestra. Quien tenga un volcado de la base de datos no tiene ninguna clave.
- **Formato de todo lo cifrado:** versión del formato (1 byte), nonce (12 bytes), cifrado y tag (16 bytes). El byte de formato permite cambiar de algoritmo en el futuro sin ambigüedad sobre cómo leer lo antiguo. Cualquier fallo al descifrar (tag, formato o longitud) es el mismo error, sin detalles.
- **AAD:** el AAD no se cifra, pero se autentica, y ata cada cifrado a su sitio. Es lo que recomienda Google Tink para el cifrado por celda: atar el cifrado a la fila y a la columna. Cada AAD empieza por una etiqueta distinta por tipo y versión, seguida de campos binarios de longitud fija, así que dos AAD distintos nunca coinciden:
  - clave de empresa: etiqueta, `empresa_id` y versión;
  - denuncia: etiqueta, `empresa_id` y `denuncia_id`;
  - mensaje: etiqueta, `empresa_id`, `denuncia_id`, el id del propio mensaje (columna `id` de `mensaje`, con `UNIQUE (empresa_id, denuncia_id, id)`), el autor y `autor_id`. Sin el id del mensaje, un mensaje se podría duplicar en otra fila o intercambiar con otro de la misma denuncia sin que GCM lo notara. Sin el autor, un mensaje del denunciante podría pasar por uno del personal.
- **Qué se cifra de una denuncia:** `{"v": 1, "categoria", "texto"}`. La categoría va cifrada y no en una columna: "acoso" con la fecha, en una empresa pequeña, ya apunta a alguien (GlobaLeaks cifra también los metadatos). En claro solo queda lo que el flujo necesita: estado, fecha (día) y asignación. La categoría es una lista cerrada que valida la API; como va cifrada, se puede cambiar sin migrar la base de datos. Se pierde filtrar por categoría en SQL, y con el volumen de una empresa se filtra en la aplicación. El campo `v` permite cambiar el formato sin ambigüedad.
- **Relleno:** antes de cifrar, el contenido se rellena hasta un múltiplo de 256 bytes, con su longitud en una cabecera de 4 bytes. El tamaño del cifrado solo revela el tramo de 256 bytes, no la longitud exacta del texto. Al quitarlo se rechaza cualquier desviación.
- **Nonce:** aleatorio de 96 bits en cada cifrado. NIST SP 800-38D, sección 8.3, exige que con nonces aleatorios una misma clave no cifre más de 2^32 veces. El código no lleva esa cuenta (8, límites asumidos); la rotación da una clave nueva con su propia cuenta.
- **Rotación de la clave de una empresa:** se crea la versión siguiente (6.12). Lo nuevo se cifra con ella y lo antiguo se sigue leyendo con la suya.
- **Rotación de la clave maestra:** diseñada, no implementada. Exige volver a envolver las claves de todas las empresas con la nueva.

### 6.5 Metadatos

- La fecha de la denuncia se guarda redondeada al día; la hora exacta no se almacena.
- **El día es el del calendario de la empresa.** La Ley 2/2023 (art. 9.2.c) cuenta el acuse de recibo desde la recepción, y quien recibe es la organización. Cada empresa tiene su zona horaria (`empresa.zona_horaria`, con un `CHECK` que solo admite las de España: `Europe/Madrid`, `Atlantic/Canary` y `Africa/Ceuta`), obligatoria en el alta. Un trigger calcula la fecha de la denuncia y de cada fila de auditoría con `now() AT TIME ZONE` esa zona, y sobrescribe lo que traiga el `INSERT`: ni la API ni una sesión con otra `TimeZone` pueden elegir el día. Con UTC, una denuncia enviada entre las 00:00 y las 02:00 en España quedaría fechada el día anterior; con `Europe/Madrid` para toda la plataforma, una empresa canaria tendría fechas desplazadas entre las 23:00 y las 24:00. El patrón de los sistemas multiempresa (instante en UTC, presentado en la zona de cada empresa) no se puede usar sin guardar el instante; esto es su traducción: el día de la empresa, calculado al recibir.
- Los mensajes usan un número de secuencia, no marca de tiempo.
- **Logs del camino anónimo:** una línea de log lleva la hora, y "denuncia creada a las 10:32" desharía la fecha al día. Por eso crear, consultar, un 404 o un 422 no dejan ninguna línea. Los fallos que sí se registran (empresa sin clave, error de integridad, error interno) llevan solo el tipo de evento, sin empresa, denuncia ni código. Es la misma regla que GlobaLeaks: "avoid logging sensitive metadata that could lead to the identification of whistleblowers".
- Los avisos al personal se agrupan con retraso aleatorio y no incluyen contenido.
- Al denunciante no se le notifica nunca: pedirle un email rompería el anonimato.

### 6.6 Adjuntos

Solo imágenes (re-codificadas, lo que elimina EXIF) y PDF limpiados de metadatos. Se rechazan formatos Office por los metadatos de autor. Validación por magic bytes, tamaño máximo, nombre UUID, cifrado, almacenamiento fuera de cualquier ruta servida y descarga forzada.

### 6.7 Auditoría

La API tiene `INSERT` y `SELECT` (este último bajo RLS) sobre el log, nunca `UPDATE` ni `DELETE`. El hash encadenado lo calcula un trigger en la base de datos, con bloqueo por empresa para evitar carreras.

Las acciones del denunciante **no** se auditan. La auditoría numera los eventos de cada empresa con una secuencia: un "denuncia recibida" entre dos acciones del personal, cuya hora sí se conoce, situaría la denuncia en una franja de minutos y desharía la fecha al día. El libro-registro de la Ley 2/2023 (art. 26) es la propia tabla `denuncia`. Las acciones del personal sí se auditarán (login del personal).

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

- Los secretos se pasan como ficheros (Docker secrets), no como variables de entorno. La imagen de PostgreSQL acepta `POSTGRES_PASSWORD_FILE` para el superusuario; las contraseñas del resto de roles se establecen en un script de inicialización que lee los secretos. La API monta exactamente tres: la contraseña de `aplicacion`, `clave_maestra` y `clave_hmac_codigos`. Nunca la de `plataforma`, que solo tiene el servicio `gestion` (6.12).
- Los scripts de inicialización solo se ejecutan con el directorio de datos vacío, y si uno falla y el contenedor se reinicia, el resto se salta sin aviso. Para que ese fallo no sea silencioso, al arrancar la API comprueba la base de datos con el propio rol `aplicacion`, en una transacción de solo lectura, contra valores esperados escritos como literales (`app/verificacion_arranque.py`). Si algo no coincide registra `ARRANQUE BLOQUEADO: <comprobación>` y no arranca; Caddy, que depende de que la API esté sana, tampoco. Son 17 comprobaciones de arranque: 3 previas a abrir el pool (secreto, claves de cifrado y conexión) y 14 sobre la base de datos. 16 de las 17 tienen prueba de desviación: la de claves en `tests/security/verificar_denuncia.py` y el resto en `tests/security/verificar_arranque.py`. La comprobación de identidad no tiene prueba de desviación. Cada prueba provoca una desviación representativa (como superusuario en las de base de datos, con secretos de prueba en las previas), comprueba que el arranque se bloquea y, en las de base de datos, que al revertirla la API vuelve a arrancar:
  - `search_path` del rol (`pg_catalog, canal`). Qué prueba: que `search_path = canal, pg_catalog` bloquea el arranque y, al revertirlo, la API vuelve a arrancar. Qué no prueba: otros valores, por ejemplo uno que incluya `public`.
  - Identidad (`current_user`, `session_user`, base de datos). La comprobación de identidad no tiene prueba de desviación.
  - Atributos del rol: sin superusuario, `BYPASSRLS`, `CREATEROLE`, `CREATEDB` ni replicación. Qué prueba: que `ALTER ROLE aplicacion BYPASSRLS` bloquea el arranque y, al revertirlo, la API vuelve a arrancar. Qué no prueba: superusuario, `CREATEROLE`, `CREATEDB` ni replicación.
  - Sin pertenencia a ningún otro rol. `pg_read_all_data` no salta la RLS, pero daría lectura de `directorio_empresas` y `busqueda_seguimiento`, que no tienen RLS. Qué prueba: que `GRANT pg_read_all_data TO aplicacion` bloquea el arranque (también como `privilegios_tabla`, por esa lectura) y, al revertirlo, la API vuelve a arrancar. Qué no prueba: la pertenencia a otros roles.
  - Sin propiedad de ningún objeto: el dueño de una tabla puede desactivar su RLS con `ALTER TABLE`, y `FORCE` no lo impide. Qué prueba: que un esquema propiedad de `aplicacion` bloquea el arranque y, al borrarlo, la API vuelve a arrancar. Qué no prueba: la propiedad de tablas, funciones, tipos ni de la base de datos.
  - Sin `CREATE` en `canal` ni `public` y sin `CREATE` ni `TEMPORARY` en la base de datos: las tablas temporales se buscan antes que cualquier esquema del `search_path`. Qué prueba: que `GRANT TEMPORARY ON DATABASE canario` bloquea el arranque y, al revertirlo, la API vuelve a arrancar. Qué no prueba: `CREATE` en `canal`, en `public` ni en la base de datos.
  - Exactamente las 8 relaciones esperadas en `canal`. Qué prueba: que una tabla nueva en `canal` bloquea el arranque y, al borrarla, la API vuelve a arrancar. Qué no prueba: que falte una relación esperada, ni una vista nueva.
  - `ENABLE` y `FORCE ROW LEVEL SECURITY` en las 6 tablas con datos de empresa. Qué prueba: que `NO FORCE ROW LEVEL SECURITY` en `denuncia` bloquea el arranque y, al revertirlo, la API vuelve a arrancar. Qué no prueba: `DISABLE ROW LEVEL SECURITY` ni el resto de tablas.
  - Exactamente los privilegios esperados de tabla. Qué prueba: que `GRANT DELETE ON canal.denuncia` bloquea el arranque y, al revertirlo, la API vuelve a arrancar. Qué no prueba: otros privilegios u otras tablas, ni que falte un privilegio esperado.
  - Exactamente los privilegios esperados por columna. Qué prueba: que `GRANT UPDATE (contenido_cifrado) ON canal.denuncia` bloquea el arranque y, al revertirlo, la API vuelve a arrancar. Qué no prueba: otras columnas, ni que falte un privilegio esperado.
  - `EXECUTE` exactamente sobre las 5 funciones esperadas (nunca `alta_empresa`). Qué prueba: que `GRANT EXECUTE` sobre `alta_empresa` bloquea el arranque y, al revertirlo, la API vuelve a arrancar. Qué no prueba: que falte `EXECUTE` sobre una función esperada.
  - Funciones de definidor propiedad de `propietario_funciones`. Qué prueba: que `resolver_empresa` con dueño `migrador` bloquea el arranque y, al devolverla a `propietario_funciones`, la API vuelve a arrancar. Qué no prueba: una función de definidor nueva.
  - `propietario_funciones` sin superusuario, `BYPASSRLS` ni login. Qué prueba: que `ALTER ROLE propietario_funciones BYPASSRLS` bloquea el arranque y, al revertirlo, la API vuelve a arrancar. Qué no prueba: superusuario ni login.
  - Exactamente las 15 políticas esperadas, con su comando, roles, `USING` y `WITH CHECK`. Qué prueba: que una política añadida con `USING (true)` sobre `denuncia` bloquea el arranque y, al borrarla, la API vuelve a arrancar. Qué no prueba: que falte una política esperada o que cambie su condición.
  - Previa: el secreto existe y tiene formato válido. Qué prueba: que un secreto de prueba con salto de línea final bloquea el arranque como `secreto`. Qué no prueba: que la API vuelva a arrancar al corregir el secreto (solo el bloqueo, sin reinicio).
  - Previa: las claves de cifrado (`clave_maestra` y `clave_hmac_codigos`) existen, tienen exactamente 64 hexadecimales en minúscula y son distintas (6.4). Se comprueban antes de conectar, y el motivo del bloqueo nunca lleva su valor. Qué prueba: que sin `clave_maestra`, sin `clave_hmac_codigos`, con la maestra con salto de línea final, en mayúsculas o corta, y con las dos iguales, la API no arranca y registra `ARRANQUE BLOQUEADO: claves: <motivo>`, sin la clave en el log. Control: con claves falsas bien formadas, la API pasa esta comprobación y llega a la conexión. Qué no prueba: que la API vuelva a arrancar al corregirlas (solo el bloqueo, sin reinicio).
  - Previa: la conexión se abre en 15 s. Qué prueba: que una contraseña falsa generada por la prueba (nunca la real) bloquea el arranque como `conexion`. Qué no prueba: que la API vuelva a arrancar con la contraseña correcta (solo el bloqueo, sin reinicio).
- La comprobación se hace solo al arrancar: un cambio posterior exige superusuario y se detecta en el siguiente reinicio.
- **Conexión de la API:** psycopg 3 con pool (máximo 5 conexiones, por debajo del `CONNECTION LIMIT 10` del rol). La contraseña se lee del fichero del secreto al abrir cada conexión; un secreto con espacios o saltos de línea es un error de configuración y bloquea el arranque, no se corrige en silencio. Cada sesión tiene `statement_timeout` de 5 s, `lock_timeout` de 2 s e `idle_in_transaction_session_timeout` de 10 s: los triggers de auditoría y de mensajes toman bloqueos consultivos por empresa, y una transacción colgada bloquearía a toda la empresa. Prueba de cada límite, con su control:
  - `statement_timeout`: una consulta de 7 s se cancela (`QueryCanceled`); control: una de 1 s termina.
  - `lock_timeout`: esperar un bloqueo consultivo ocupado falla con `LockNotAvailable` a los 2 s; control: un bloqueo consultivo libre se obtiene sin esperar. Confirma que el límite se aplica también a los bloqueos consultivos.
  - `idle_in_transaction_session_timeout`: una transacción inactiva 12 s se corta; control: una inactiva 3 s sigue abierta.
- **Contexto de empresa:** el único camino con contexto es `transaccion_empresa()`, que exige un `uuid.UUID` (un texto se rechaza antes de llegar al SQL) y lo fija con `select set_config(..., true)` y parámetro enlazado. psycopg no enlaza parámetros en `SET`, por eso no se usa. Al devolver una conexión al pool se comprueba que no lleva contexto; si lo lleva, se descarta y se registra (`error resetting connection: conexion devuelta al pool con contexto de empresa: se descarta`, sin cadena de conexión ni valor del contexto).
- **Concurrencia:** los endpoints síncronos corren en el pool de hilos de AnyIO, con un límite por defecto de 40 hilos (comprobado en el código fuente de FastAPI 0.143.0, Starlette 1.7.0 y AnyIO 4.15.1). Con 300 peticiones concurrentes el proceso no pasó de 33 hilos, por debajo de `pids_limit: 64`.
- **Límites asumidos de la conexión (decisiones conscientes):**
  - El pool no comprueba cada conexión antes de entregarla, para no añadir una ida y vuelta a la base de datos en cada petición. Si PostgreSQL se reinicia, la primera petición que reciba una conexión rota falla de forma visible y el pool la sustituye.
  - La cola de espera del pool no tiene límite: si las peticiones llegan más rápido de lo que se liberan conexiones, esperan hasta 10 s cada una. La acotará el rate limit con Redis (6.8 y 6.9), aún no implementado.
- La rotación de contraseñas no pasa por el script de inicialización y requiere un procedimiento propio (ver sección 11).

### 6.11 Frontera con el exterior: proxy y API

- **Redes:** la API está en la red `app` (interna, `10.88.0.0/28`) y en `data` (interna, con PostgreSQL); se conectará a `cache` cuando use Redis. Caddy está en `app`, con la IP fija `10.88.0.2`, y en `edge` (`10.88.1.0/28`), la única red no interna, porque una red interna no puede publicar puertos. Las subredes están fuera de los rangos que Docker asigna por defecto. `ip_range` (`.8/29`) limita las IPs automáticas y reserva de `.2` a `.7` para IPs fijas: sin ello, la API arranca primero, recibe la `.2` y el proxy no puede tomarla.
- **Puertos:** el único puerto publicado es el de Caddy, `127.0.0.1:8443`, nunca `0.0.0.0` y sin puerto 80. Caddy escucha en 8443, que no es privilegiado, así que no necesita `NET_BIND_SERVICE`.
- **Caddy:** `admin off` (sin API de administración), `persist_config off` (`admin off` no desactiva el autosave de la configuración en `/config`), `auto_https disable_redirects`, `tls internal` (CA local, sin ACME) y `protocols h1 h2` (sin listener UDP de HTTP/3).
- **Host distinto de `localhost`:** responde 421 un sitio por defecto (`https://:8443`), por las rutas y con las mismas cabeceras y el mismo JSON que el resto. Sin él, la petición no casaría con ninguna ruta y Caddy respondería 200 vacío. Sustituye a `strict_sni_host on`, cuyo 421 lo genera el servidor antes de entrar en las rutas y salía con `Server: Caddy` y sin cabeceras de seguridad (comprobado). Un SNI distinto de `localhost` ni siquiera completa el TLS, porque no hay certificado para él (comprobado).
- **Límite de cuerpo en Caddy:** `request_body max_size 128KiB`, igual que la API. `max_size` solo falla al leer el cuerpo, y por defecto `reverse_proxy` lo reenvía mientras lo lee: una petición demasiado grande llegaba a la API (comprobado: el 413 era el de la API). Con `request_buffers 129KiB`, Caddy lee el cuerpo antes de contactar con la API y corta él mismo con 413, como `client_max_body_size` en nginx. La documentación avisa de que el buffer es ineficiente con cuerpos grandes; aquí el máximo es 128 KiB por petición.
- **Plazos de Caddy:** `read_header 10s`, `read_body 30s`, `write 30s` e `idle 2m`. Por defecto, Caddy no limita la lectura del cuerpo ni la escritura ("Defaults to no timeout"): una subida que se detiene retendría la conexión, y con el buffer también su memoria (slowloris). Los 30 s dan margen a un denunciante por Tor, con poco ancho de banda, para subir 128 KiB.
- **Errores que genera Caddy** (413, 502 con la API caída, 421): `handle_errors` y el sitio por defecto importan el mismo fragmento de cabeceras de seguridad que las respuestas normales, sin `Server`, y responden con el mismo formato JSON (`{"detalle": ...}`) que la API. Es el equivalente de `add_header ... always` en nginx.
- **Imagen de Caddy:** la oficial trae el binario con la file capability `cap_net_bind_service=ep`. Con `cap_drop: ALL` el kernel rechaza el `execve`. Se elimina con `setcap -r` en una imagen propia, en vez de devolver la capability al contenedor. `/data/caddy` (CA y clave privada) pasa de `1777` a `0700`, propiedad del usuario de Caddy. Es el único estado persistente (volumen `caddy_datos`); `/config` no se monta y queda en solo lectura.
- **API:** `GET /salud` (vivacidad, sin tocar base de datos ni Redis) y las dos rutas del denunciante (6.1). Sin `/docs`, `/redoc` ni `/openapi.json` y sin redirección de barra final. `--no-server-header`. El healthcheck no usa curl: solo da sano con 200 y el cuerpo exacto.
- **Frontera HTTP de la API** (`app/frontera_http.py`):
  - **Límite de cuerpo de 128 KiB** (segunda capa, por si la API quedara expuesta sin proxy: uvicorn no tiene límite propio). Lo aplica un middleware que lee el cuerpo entero, con la memoria acotada por el límite: rechaza por el `Content-Length` declarado sin leer nada, y cuenta los bytes reales en un envío por trozos. No depende de cómo lea FastAPI el cuerpo, que convierte en 400 cualquier excepción al leerlo salvo `HTTPException` (comprobado en el código de la versión fijada). 10 000 caracteres de texto caben con el peor escapado JSON (12 bytes por carácter fuera del plano básico).
  - **Errores no previstos:** 500 genérico, y en el log solo la clase y el SQLSTATE. Hace falta un middleware propio porque el `ServerErrorMiddleware` de Starlette, aunque haya un manejador de 500, siempre vuelve a lanzar la excepción, y uvicorn volcaría el traceback con el mensaje, que puede llevar valores de la fila (comprobado en el código).
  - **422 sin eco:** el de FastAPI devuelve el campo `input` con lo que envió el cliente; el propio responde siempre `{"detalle": "petición no válida"}`. Los modelos son estrictos (`extra="forbid"`, `strict=True`) y FastAPI 0.143.0 solo interpreta como JSON un cuerpo con `Content-Type` JSON (`strict_content_type`, por defecto `True`).
  - **Formato de error único** en castellano para todas las respuestas de error, que conserva las cabeceras del error (por ejemplo `Allow` en un 405).
- **PostgreSQL:** `log_error_verbosity=terse`: el log del servidor no lleva `DETAIL`, que repetiría valores de la fila (por ejemplo `Key (codigo_hmac)=(...)` en un duplicado).
- **Contenedores:** usuarios no root con uid fijo (API 10001, Caddy 10002), `read_only`, `cap_drop: ALL`, `no-new-privileges`, `mem_limit` y `pids_limit`, sin tmpfs.
- **Cabeceras:** `Strict-Transport-Security: max-age=63072000` (sin `includeSubDomains` ni `preload` mientras el nombre sea `localhost`), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, `Cache-Control: no-store`, y sin cabecera `Server`.
- **Dependencias:** versión exacta y `sha256` de todos los ficheros publicados en PyPI, instaladas con `--require-hashes` y `--only-binary :all:`. Se resuelven en un contenedor de `python:3.12-slim`, no en Windows, porque los marcadores de plataforma darían otro resultado. La imagen final no lleva pip. `fastapi` exige `opentelemetry-api`: sin SDK es una implementación vacía que no registra ni envía nada (comprobado). Imágenes base fijadas por versión y digest.
- **Límite asumido:** la red `edge` da a Caddy salida a internet; es inevitable para publicar el puerto. **[VERIFICAR]** Que Caddy funcione sin esa salida (`tls internal` no usa ACME, pero no se ha probado con la red cortada).

### 6.12 Alta de empresas y gestión de claves

Es una operación de administración, fuera de la API pública, como el alta de inquilinos en cualquier plataforma multiempresa. La hace el servicio `gestion` de `docker-compose.yml` (`app/gestion.py`). Tiene un perfil propio, así que `docker compose up` nunca lo arranca: se ejecuta a mano con `docker compose run --rm gestion <orden>`. Está solo en la red `data` y con el mismo endurecimiento que la API.

- **Separación de roles:** `gestion` es el único servicio con el secreto de `plataforma`. La API no lo tiene, y por tanto no puede dar de alta empresas.
- **`alta-empresa`:** exige `--zona`, sin valor por defecto: quien da de alta decide el calendario de la empresa (6.5). Primero da de alta la empresa y su entrada del directorio con `plataforma` (`canal.alta_empresa(nombre, zona)`, que no toca claves). Después, con `aplicacion` y el contexto de la empresa nueva, genera su clave, la envuelve con la clave maestra y la guarda como versión 1. Son dos roles en dos sesiones, así que no hay una transacción común. Si el segundo paso falla, la salida lo dice ("NO tiene clave") y da el comando exacto para completarlo. La empresa no acepta denuncias mientras tanto.
- **`nueva-clave`:** crea la versión siguiente de la clave de una empresa. Sirve para completar un alta a medias y para rotar. Si dos ejecuciones calcularan a la vez la misma versión, la clave primaria rechazaría la segunda.
- **Antes de guardar una clave:** `gestion` aplica las mismas comprobaciones literales que el arranque de la API (6.10), en solo lectura, y no escribe en una base de datos que no sea la esperada. Además desenvuelve todas las claves anteriores de la empresa con la clave maestra montada. Si alguna falla, porque la clave maestra es otra o porque la clave guardada está alterada, se aborta sin crear nada.
- **Salida:** nunca imprime claves, envueltas o no. Solo identificadores y versiones. De los errores de la base de datos solo muestra la clase y el SQLSTATE, porque su texto puede incluir valores de la fila.

## 7. Tabla de amenazas

| Amenaza | Mitigación | Test que lo demuestra |
|---|---|---|
| Fuerza bruta del código | 160 bits, HMAC, rate limit, respuesta uniforme | Ráfaga de intentos devuelve 429 |
| IDOR entre empresas | RLS con `FORCE`, rol sin `BYPASSRLS`, filtro también en la app | Token de A pide recurso de B y recibe 404 |
| Arrastre de contexto entre peticiones | `set_config` local a la transacción, `nullif` en la política | Dos peticiones seguidas de empresas distintas no se mezclan; sin contexto devuelve cero filas |
| Fuga de existencia entre empresas | `UNIQUE` con `company_id`, claves foráneas compuestas | Insertar un dato duplicado de otra empresa no produce un error distinguible |
| Abuso de funciones `SECURITY DEFINER` | `search_path` fijado, `REVOKE` de PUBLIC, `GRANT` mínimo | Un rol no autorizado no puede ejecutar la función |
| Escalada de rol | Permisos por rol, denegar por defecto | Instructor llama a endpoint de admin y recibe 403 |
| Inyección SQL | Consultas parametrizadas, usuario de BD de mínimo privilegio | Payloads clásicos no alteran nada |
| Robo de cuenta del personal | Argon2id, tokens cortos, 2FA TOTP, bloqueo progresivo | Login sin segundo factor falla |
| Relleno de credenciales | Rate limit por empresa y por cliente | Ráfaga contra una empresa se bloquea |
| Redis caído o manipulado | Rechazo con 503, sin camino alternativo sin límite | Con Redis parado, login, seguimiento y denuncia devuelven 503 |
| Desanonimización por metadatos | Sin IP, fecha a día, secuencia en vez de hora, avisos diferidos, categoría cifrada | Sin columnas con hora (`verificar_esquema.py`); el volcado no contiene la categoría en claro |
| Desanonimización por logs del camino anónimo | Ni éxitos ni errores de cliente en el log; los fallos, sin empresa, denuncia ni código | Crear, consultar, un 404 y un 422 no dejan ninguna línea (control: una empresa sin clave sí deja una); ningún texto, código ni HMAC en los logs de la API, PostgreSQL y Caddy (control: un testigo escrito en el log se encuentra) |
| Fecha de recepción manipulada o desplazada | Trigger con la zona horaria de cada empresa, independiente de la sesión y del `INSERT`; zonas limitadas por `CHECK` | La fecha falsa del `INSERT` y la `TimeZone` de la sesión no cambian el día (control: en esa sesión es otro día); con la empresa en otra zona, el día es el de su zona y no el de Madrid (control: los días difieren); zona fuera de la lista rechazada |
| IP en logs de proxy, API o Redis | Sin logs de acceso, logger excluido, campos borrados, Redis sin persistencia | Tras una ráfaga de peticiones, ningún log ni volumen contiene la IP de prueba (proxy y API comprobados; Redis pendiente) |
| IP falsificada con `X-Forwarded-For` | Caddy sin `trusted_proxies`; uvicorn solo confía en la IP fija del proxy | Un XFF falso no llega a la API; directo a la API, uvicorn ignora el XFF |
| Exposición de servicios internos | API solo en red interna; único puerto publicado el del proxy, en `127.0.0.1` | La API no sale a internet; `docker inspect` solo muestra `127.0.0.1:8443` |
| Superficie de la API sin autenticar | `/salud` y las dos rutas del denunciante, sin documentación ni OpenAPI, `Host` distinto de `localhost` rechazado | Otras rutas dan 404; `Host` distinto da 421 con las cabeceras de seguridad |
| Eco de datos y detalles en los errores | 422 propio sin `input`; 500 genérico con solo clase y SQLSTATE en el log; `log_error_verbosity=terse` | 11 peticiones inválidas dan el mismo 422 sin el marcador enviado; un error de la BD provocado da 500 y en el log ni mensaje, ni traceback, ni tabla (control: sí la clase); un duplicado no deja `DETAIL` en el log de PostgreSQL (control: sí su línea de error) |
| Cuerpo sobredimensionado | 128 KiB en Caddy (`request_buffers`) y en la API (middleware) | Directo a la API: un byte por encima, por trozos o con `Content-Length` declarado, 413 de la API; a través de Caddy, 413 de Caddy sin llegar a la API (control: 128 KiB exactos se aceptan en los dos casos) |
| Subida lenta (slowloris) | Plazos de lectura y escritura explícitos en Caddy | Una subida parada 35 s se corta sin crear la denuncia (control: con 2 s de pausa se acepta) |
| Errores del proxy sin cabeceras de seguridad | `handle_errors` y el sitio por defecto con el mismo fragmento de cabeceras, sin `Server` | El 413 de Caddy, el 502 con la API parada y el 421 llevan todas las cabeceras, JSON y ninguna `Server` |
| Escalada dentro de un contenedor | No root, `read_only`, `cap_drop: ALL`, `no-new-privileges`, sin file capabilities | `CapEff`, `CapPrm` y `CapBnd` a cero; `NoNewPrivs` a 1 |
| Pérdida del CA local de Caddy | Volumen con nombre en `/data`, sin estado en `/config` | El CA es el mismo tras `restart` y tras `down` y `up` |
| Fichero malicioso | Magic bytes, tamaño, UUID, cifrado, fuera de ruta servida | Ejecutable renombrado a `.jpg` rechazado |
| Fuga de BD o backup | Envelope encryption con AAD, categoría dentro del cifrado, solo el HMAC del código | `pg_dump` de los datos sin ningún texto, código ni categoría en claro (control: contiene los HMAC, y cada uno es el de la fórmula de 6.1) |
| Cifrado movido de sitio o alterado | AES-256-GCM con AAD por tipo (empresa, fila, mensaje y autor) y formato versionado | Vector del NIST cumplido; cifrado, tag o AAD alterados, contenido movido a otra denuncia, empresa, tabla, mensaje o autor, y clave de empresa movida a otra empresa o versión: no se descifran (control: en su sitio sí). De punta a punta: con el cifrado de otra denuncia de la misma empresa o de otra empresa, el seguimiento da 500 y un evento de integridad sin datos (control: al restaurar, 200) |
| Claves del servidor ausentes o mal formadas | Comprobación al arrancar, antes de conectar; formato exacto y claves distintas | Sin una clave, con salto de línea, en mayúsculas, corta o repetida, la API no arranca (control: con claves bien formadas pasa la comprobación) |
| Claves en logs o salidas | Ningún log ni salida imprime claves; errores de la BD resumidos en clase y SQLSTATE | Ninguna de las claves (maestra, HMAC y las de empresa desenvueltas) aparece en los logs de la API, PostgreSQL y Caddy ni en las salidas de `gestion`, en hex, mayúsculas, base64 o bytes (control: la maestra escrita a propósito en el log de la API se encuentra) |
| Clave nueva incompatible con las existentes | `gestion` desenvuelve las claves anteriores antes de crear otra y verifica la BD como el arranque | Con otra clave maestra, con una clave alterada o con la BD desviada, `nueva-clave` no crea nada (control: con la maestra correcta crea la versión siguiente) |
| Alta de empresa a medias y silenciosa | El alta avisa de que la empresa no tiene clave y da el comando exacto | Con la BD desviada, el alta crea la empresa, avisa y nombra el comando; al revertir, ese comando la completa |
| Alta de empresas desde la API | El secreto de `plataforma` solo existe en el servicio `gestion`, que `up` no arranca | La API no tiene `/run/secrets/contrasena_plataforma` (control: sí tiene el de `aplicacion`); `gestion` solo aparece con su perfil |
| Enumeración de empresas y usuarios | Identificadores aleatorios, errores y tiempos uniformes | Una empresa desconocida, mal formada, inactiva o con caracteres de ruta da el mismo 404, byte a byte, que una ruta inexistente; un código cambiado, aleatorio o mal formado, el mismo 404 del seguimiento |
| Spam en el endpoint anónimo | Rate limit y tamaño máximo | Tamaño máximo comprobado (fila "Cuerpo sobredimensionado"); ráfaga de denuncias bloqueada: pendiente del rate limit |
| Manipulación de la auditoría | Sin `UPDATE`/`DELETE`, hash encadenado por trigger | Un `UPDATE` o `DELETE` desde la app falla |
| Inicialización de BD incompleta y silenciosa | Comprobación de arranque de roles, RLS y permisos | Con un rol mal creado la API no arranca. 16 de las 17 comprobaciones de arranque tienen prueba de desviación. La comprobación de identidad no tiene prueba de desviación. |
| Arrastre de contexto en el pool de conexiones | `set_config` local, comprobación al devolver cada conexión | Con A, B y A en la misma conexión no se mezclan filas y el contexto queda vacío tras cada transacción (control: las transacciones reutilizan la misma conexión); una conexión devuelta con contexto de sesión se descarta y queda registrada |
| Contraseña de la base de datos expuesta | Solo como Docker secret, nunca en entorno ni en logs | Variables de entorno exactamente las esperadas y sin credenciales en la línea de comandos; con una contraseña falsa de prueba, generada por la batería (nunca la real), la API no arranca y no la muestra en sus logs (control: el log muestra el fallo de autenticación) |
| Conexiones retenidas o bloqueos colgados | Límites de tiempo de sentencia, de bloqueo y de transacción inactiva | Consulta de 7 s cancelada (control: 1 s termina); bloqueo ocupado falla a los 2 s (control: bloqueo libre sin esperar); transacción inactiva 12 s cortada (control: 3 s sigue abierta) |
| Secretos y dependencias | `.env` fuera de Git, secretos como ficheros, gitleaks, `pip-audit`, contenedores sin root | Escaneo limpio |

## 8. Límites asumidos

Estos límites se documentan, no se esconden:

- **Servidor completamente comprometido** con acceso a la clave maestra: el atacante puede descifrar.
- **Claves en memoria:** Python no permite borrar con garantías un valor de la memoria. La clave maestra, la del HMAC y las claves de empresa desenvueltas viven en el proceso de la API mientras está en marcha.
- **Límite de cifrados por clave:** NIST SP 800-38D (8.3) limita cada clave a 2^32 cifrados con nonce aleatorio. El código no lleva la cuenta; si una empresa se acercara, se rota su clave (6.12).
- **Alta con otra clave maestra:** en el alta no hay claves anteriores con las que contrastar la clave maestra. Si la del servicio `gestion` fuera distinta de la de la API (los dos montan el mismo fichero de `secrets/`, así que exige un error manual), la empresa nueva tendría una clave que la API no puede desenvolver. No pasaría en silencio: la primera denuncia fallaría con un error de integridad visible.
- **Relleno:** el tamaño del cifrado revela el tramo de 256 bytes en que cae el texto, no su longitud exacta.
- **Orden de inserción en la base de datos:** la fecha al día protege a quien lee las filas, no frente a un análisis forense con acceso directo a PostgreSQL: `xmin` y el orden físico de las filas permiten reconstruir en qué orden se insertaron.
- **Sin rate limit todavía:** los dos endpoints anónimos no limitan el número de peticiones hasta que llegue el limitador con Redis. La fuerza bruta de un código de 160 bits es inviable igualmente, pero el spam de denuncias no está frenado.
- **El 503 revela que el identificador existe:** una empresa sin clave responde 503 y no 404. El identificador público no es secreto (lo reparte la empresa, 6.3) y es un estado operativo anómalo; un "inténtelo más tarde" es mejor para quien intenta denunciar que un "no existe".
- **Tiempo de respuesta:** un código o identificador mal formado se rechaza sin consultar la base de datos. El tiempo distingue "mal formado" de "bien formado pero inexistente", y eso solo revela si el formato es válido, que es público.
- **Rotar `clave_hmac_codigos` invalida todos los códigos:** sus HMAC ya no coincidirían. Diseñado, no implementado: varias claves de HMAC con versión.
- **Reintentos:** si la conexión se corta después de crear la denuncia y antes de recibir el código, el denunciante puede reintentar y crear otra con otro código.
- **El texto se guarda tal cual:** es una prueba y no se modifica (incluidos caracteres de control como U+202E). Escaparlo al mostrarlo es tarea del cliente.
- **Memoria del buffer de Caddy:** cada petición en vuelo puede retener hasta 129 KiB en Caddy (`mem_limit` de 128 MB), y como mucho 30 s (`read_body`). El rate limit lo acotará.
- **Lectura del cuerpo en uvicorn:** uvicorn no tiene plazo propio para leer el cuerpo. Detrás de Caddy no importa (Caddy lo lee entero antes de reenviarlo); si la API quedara expuesta sin proxy, una subida lenta retendría un hilo.
- **Inyección SQL completa:** RLS por variable de sesión protege de errores de lógica y de filtros olvidados, pero quien lograra ejecutar SQL arbitrario podría fijar él mismo la variable de empresa. La defensa real es no permitir esa inyección (consultas parametrizadas) y limitar los privilegios del rol de la API.
- **Observador de red:** la IP del denunciante es visible para su proveedor y para el servidor en la conexión. La mitigación real es acceder por Tor, fuera del alcance de esta API.
- **Cifrado de extremo a extremo:** no implementado. El servidor descifra contenido para servirlo al personal. Plataformas como GlobaLeaks usan cifrado de cliente; aquí queda como mejora futura.
- **Autoidentificación:** si el denunciante escribe datos que lo identifican en el texto, el sistema no puede evitarlo.
- **Pérdida del código:** sin recuperación.
- **Disponibilidad:** una caída de Redis implica rechazo temporal de peticiones (6.9).

## 9. Cumplimiento normativo

Contrastado con el texto consolidado de la Ley 2/2023 en el BOE (BOE-A-2023-4513):

- **Art. 9.2.c**, acuse de recibo "en el plazo de siete días naturales": la respuesta 201 con el código y la fecha es un acuse inmediato.
- **Art. 9.2.e**, "posibilidad de mantener la comunicación con el informante": el seguimiento por código; los mensajes llegan con el paso siguiente del bloque.
- **Art. 26**, libro-registro "de las informaciones recibidas", que "no será público": la tabla `denuncia`, con RLS por empresa. Los datos no pueden conservarse "por un período superior a diez años".
- **Art. 32**, supresión de los datos "transcurridos tres meses desde la recepción de la comunicación sin que se hubiesen iniciado actuaciones de investigación", salvo para "dejar evidencia". **Choca con el diseño actual ("ningún DELETE en el sistema", 02_esquema.sql)**. Diseñado, no implementado: una función de definidor `suprimir_denuncia`, auditada, como único camino de borrado.

**[VERIFICAR]** Plazos de conservación y tratamiento de datos según el RGPD.

## 10. Orden de sacrificio

Si el tiempo aprieta, se recorta en este orden: primero notificaciones, después adjuntos. RLS, auditoría y tests de seguridad no se recortan. Lo no implementado queda documentado como "diseñado, no implementado".

## 11. Verificación de decisiones técnicas

**Contrastado con documentación oficial:** opciones de logging y filtros de Caddy, comportamiento de las cabeceras de reenvío, opciones de Uvicorn, uso de `POSTGRES_PASSWORD_FILE` y de los scripts de inicialización de la imagen de PostgreSQL, comportamiento de RLS (`FORCE`, `BYPASSRLS`, denegación por defecto, exclusiones de integridad referencial), `set_config` local a la transacción y recomendaciones para funciones `SECURITY DEFINER`.

**Contrastado con fuentes secundarias:** desactivación de persistencia de Redis (`save ""`, `appendonly no`), con la salvedad de `SAVE`/`BGSAVE` y la replicación.

**Contrastado con documentación oficial y código fuente (frontera exterior):** opciones globales de Caddy `admin`, `persist_config`, `auto_https`, `skip_install_trust`, `servers` (`protocols`, `strict_sni_host`, después sustituido por un sitio por defecto, y `trusted_proxies`) y `log` (`exclude`, filtro `delete`); en el código de Caddy, que `admin off` no desactiva el autosave y que el directorio de configuración solo se usa para `autosave.json`; en el repositorio `caddy-docker`, que la imagen no declara `VOLUME` desde 2022 y que hace `setcap` sobre el binario; opciones de uvicorn `--proxy-headers`, `--forwarded-allow-ips` y `--no-server-header`.

**Comprobado con pruebas reales (`tests/security/verificar_esqueleto.py`, cada negativo con su control):** que la API no tiene salida a internet; que el único puerto publicado es `127.0.0.1:8443`; rutas, cabeceras y 421; que la IP del cliente y el `X-Forwarded-For` falso no aparecen en los logs de Caddy ni de la API ni en el volumen de Caddy tras una ráfaga (control: un Caddy con la directiva `log` sí los registra); que un XFF falso no llega a la API y que uvicorn solo confía en el proxy; usuarios, solo lectura, capacidades y límites; healthcheck sano y roto; ausencia de file capability, de volúmenes anónimos, de autosave y de HTTP/3; y que el CA sobrevive a reinicios. La imagen sin `VOLUME` se confirmó también con `docker image inspect`.

**Contrastado con documentación oficial y código fuente (conexión y arranque verificado):** psycopg 3 envía consulta y parámetros por separado en `SELECT` y DML, pero no en `SET`; `psycopg_pool` hace rollback de una conexión devuelta dentro de una transacción y descarta la que el callback `reset` deja en mal estado o con error; `pg_read_all_data` y `pg_write_all_data` no saltan la RLS; la tabla temporal de la sesión se busca antes que `pg_catalog` para relaciones y tipos; definiciones de `statement_timeout`, `lock_timeout` e `idle_in_transaction_session_timeout`; límite por defecto de 40 hilos de AnyIO para los endpoints síncronos (`fastapi/routing.py`, `starlette/concurrency.py` y `anyio/_backends/_asyncio.py` en las versiones fijadas).

**Comprobado con pruebas reales (`tests/security/verificar_arranque.py`, cada negativo con su control):** que la API arranca y verifica la base de datos; que la contraseña no está en el entorno ni en la línea de comandos y que, con una contraseña falsa de prueba (nunca la real), la API no arranca y no la muestra (control: el log muestra el fallo de autenticación); que 15 de las 17 comprobaciones de arranque bloquean el arranque ante su desviación (la de claves de cifrado, que completa las 16 con prueba, está en `verificar_denuncia.py`), y que al revertir las de base de datos la API vuelve a arrancar; que el contexto de empresa aísla filas en la misma conexión, queda vacío tras la transacción y no admite valores sin validar; que el pool descarta y registra una conexión devuelta con contexto; los tres límites de tiempo de la sesión, su valor y su efecto, cada uno con su control (incluido que `lock_timeout` se aplica a los bloqueos consultivos); y que 300 peticiones concurrentes caben en `pids_limit` (máximo observado: 33 hilos). La comprobación de identidad no tiene prueba de desviación.

**Contrastado con fuentes primarias (cifrado y claves):** el límite de 2^32 cifrados por clave con nonce aleatorio (NIST SP 800-38D, sección 8.3, texto del PDF oficial); el vector de AES-256-GCM (NIST CAVP, `gcmEncryptExtIV256.rsp`, Count 0 de Keylen 256, IVlen 96, PTlen 128, AADlen 128, descargado literal del espejo de pyca/cryptography); el vector de HMAC-SHA256 (RFC 4231, caso 2); la recomendación de atar cada cifrado a su fila y columna con el AAD (Google Tink, "Bind ciphertext to its context"); y el diseño de GlobaLeaks (recibo de 16 dígitos con Argon2 y prueba de trabajo, clave por denuncia y metadatos cifrados) como referencia de comparación.

**Comprobado con pruebas reales (`tests/security/verificar_denuncia.py`, cada negativo con su control):** que AES-256-GCM coincide con el vector del NIST y que el formato propio lo lee; que un cifrado con el tag, el cifrado o el AAD alterados, con formato desconocido o demasiado corto no se descifra; que un contenido movido a otra denuncia, empresa, tabla, mensaje o autor, o con otra clave, no se descifra; que una clave de empresa no se desenvuelve con otra empresa, versión o clave maestra; el HMAC frente a RFC 4231 y su etiqueta de dominio; el relleno y su rechazo estricto; el formato de 1000 códigos y su lectura (incluida la ligadura U+FB00); que la API no arranca sin sus claves o con claves mal formadas, sin mostrarlas; el servicio `gestion` (alta, rotación, rechazo con otra clave maestra, con una clave alterada, con una empresa inexistente y con la BD desviada, y alta a medias visible con su comando); que la API no tiene el secreto de `plataforma`; y que ninguna clave aparece en los logs de la API y de PostgreSQL ni en las salidas de `gestion`. La batería usa claves de cifrado falsas generadas en cada ejecución, y comprueba por su sha256, dentro del contenedor, que la API usa esas y no las reales.

**Contrastado con documentación oficial y código fuente (denuncia y seguimiento):** en Caddy, los valores por defecto de `timeouts` (`read_body` y `write` sin plazo, `read_header` de 1 minuto), `request_buffers` y `handle_errors`; en el código de FastAPI 0.143.0, `strict_content_type` (por defecto `True`) y que una excepción al leer el cuerpo se convierte en 400 salvo `HTTPException`; en el de Starlette 1.7.0, que `ServerErrorMiddleware` siempre vuelve a lanzar la excepción; que la imagen fijada de PostgreSQL usa los datos de zona del sistema (`--with-system-tzdata`) y trae `Europe/Madrid`, `Atlantic/Canary` y `Africa/Ceuta`; y los artículos 9.2, 26 y 32 de la Ley 2/2023 (sección 9).

**Comprobado con pruebas reales (`tests/security/verificar_esquema.py`, ampliada):** columnas y restricciones nuevas (zona horaria con su `CHECK`, `mensaje.id` con su `UNIQUE`, `denuncia` sin `categoria`), el trigger de fecha y la firma `alta_empresa(text, text)`; que la fecha de una denuncia y de una fila de auditoría es el día en la zona de su empresa, aunque el `INSERT` traiga otra fecha y la sesión tenga otra zona (con una zona de control en la que es otro día, para que la prueba distinga); y que un `INSERT` con el `empresa_id` de otra empresa sigue fallando por RLS y no por `NOT NULL` (la política se comprueba antes).

**Comprobado con pruebas reales (`tests/security/verificar_denuncia.py`, denuncia y seguimiento):** respuestas, fechas por zona, 404 uniformes, 503 y 422 sin eco (sección 7); que el texto vuelve exacto, también con caracteres especiales y con el máximo de 10 000 caracteres; el volcado sin datos en claro; integridad de punta a punta; errores internos sin detalles; límite de cuerpo en las dos capas; subida lenta cortada; cabeceras en los errores de Caddy (413, 421 y 502, este con la API parada); y logs del camino anónimo sin líneas ni datos.

**Pendiente, se cubrirá con tests:**
- Procedimiento de rotación de contraseñas: pendiente de escribir y de probar. Hasta entonces no se afirma que una contraseña pueda cambiarse sin reiniciar la API.
- Valor por defecto de `password_encryption` y `pg_hba` de la imagen de PostgreSQL.
- Si la imagen de Redis declara un volumen en `/data`, y la sintaxis exacta de las ACL de Redis.
- Ausencia real de IPs en Redis tras una ráfaga de peticiones (proxy y API ya comprobados).
- Escaneo de vulnerabilidades de las imágenes completas (Trivy o similar): `pip-audit` solo cubre las dependencias de `requirements.txt`.
- Que Caddy arranque y sirva sin salida a internet.
