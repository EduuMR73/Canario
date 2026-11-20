# Pruebas funcionales y de estrés

Informe de la tarea de pruebas funcionales y de estrés. Hilo conductor: **¿puede alguien impedir que un denunciante denuncie?** Las pruebas funcionales demuestran que el circuito entre el denunciante y el personal funciona; las de estrés, qué cede primero con carga y si una ruta inundada arrastra a las demás; las de producción, que las defensas están de verdad en el despliegue real.

Las baterías de seguridad (`tests/security/`, [pruebas.md](pruebas.md)) ya recorren partes de la aplicación en un Chromium real: `verificar_spa.py` recorre el sitio del denunciante de punta a punta (q) y las pantallas del personal con denuncias creadas por la API (m). Lo nuevo aquí es el circuito entre los dos actores en el mismo escenario, los motores Firefox y WebKit, y el comportamiento bajo carga.

## 1. Matriz de trazabilidad

Cada frase del enunciado, la pregunta que responde, la prueba que la cubre y la evidencia que se entrega. Una fila sin prueba o sin evidencia es un hueco, no un "hecho".

| Enunciado | Pregunta | Pruebas | Evidencia |
|---|---|---|---|
| "Crear test funcionales de la aplicación web" | ¿Funciona el circuito completo entre los dos actores? | F1, F2 | Informe HTML de pytest, GIF con dos navegadores |
| "Se pueden usar librerías como Selenium, Playwright, etc." | ¿Por qué esa herramienta y no otra? | F3 y la sección 4 | Tabla razonada de la sección 4 |
| "Crear test de estrés de la aplicación" | ¿Cuánto aguanta, qué cede primero y cómo se recupera? | L1, L4 | Exportado de k6, gráficas del p95 con la línea del SLO, tabla de SLO con PASA / NO PASA (sección 3) |
| "pueden estar repartidos entre el despliegue local y el despliegue de producción" | ¿Las defensas medidas en local están también en producción? | L1 a L7 (local), P1 a P6 (producción) | Salidas guardadas, tabla de SLO |
| "Se pueden introducir pruebas para evitar ataques DDOS" (opcional) | ¿Una ruta inundada deja sin servicio a las demás? ¿Qué no frena el límite por IP? ¿Se puede tumbar el limitador? | L2, L3, L5, L6, L7, P6 | Gráfica de L2 con y sin inundación (salga lo que salga), antes y después si hay mitigación; sección 5 |

Las defensas de producción que solo comprueban que un control está (P1 a P5) cubren la frase del despliegue de producción, no la del DDoS.

### Técnicas de ATT&CK (comprobadas en attack.mitre.org el 20/11/2026)

| Técnica | Dónde se ejercita |
|---|---|
| T1499.003 Endpoint Denial of Service: Application Exhaustion Flood | L1 y L2 (login con Argon2, la función más cara), L6 (el contador por IP del limitador, usado para agotar la memoria de Redis) |
| T1499.002 Endpoint Denial of Service: Service Exhaustion Flood | L3, L7 (`/salud`, la ruta más barata) y P6 |
| T1498 Network Denial of Service | No se prueba (sección 5) |

La mitigación que ATT&CK propone para las tres, M1037 (Filter Network Traffic), queda fuera de la aplicación: corresponde al proveedor del VPS y a Traefik.

## 2. Pruebas

### Reglas comunes

- Cada prueba negativa lleva su control positivo. Si el control falla, el resultado es `SIN CONCLUSION`, nunca `PASA`.
- Los oráculos son literales escritos en la prueba, no se derivan del código que se prueba.
- La ejecución termina con `RESULTADO GLOBAL: OK` o `NO OK`, y el código de salida es 0 solo si es OK. Un `SIN CONCLUSION`, una prueba saltada o un fallo esperado (`xfail`, siempre con `strict=True` y su motivo) impiden el OK: en pytest lo fuerza `pytest_sessionfinish`, porque un *skip* y un *xfail* devuelven 0.
- Cada ejecución usa su propia pila de Docker temporal, la borra con `down -v` y comprueba que no ha modificado el repositorio.
- Cada prueba declara qué límites usa y lo comprueba con la línea entera que escribe la API al arrancar (`app/principal.py`): `LIMITES (por defecto): ...` o `LIMITES (configurados): ...`, con las 9 reglas en orden alfabético.
- Ventana fija: el limitador cuenta por ventanas alineadas al reloj UTC (`app/limitador.py`). Una prueba que cuenta hasta un límite empieza justo después de una frontera y comprueba que todas sus peticiones cayeron en la misma ventana; si no, `SIN CONCLUSION`. Es la técnica `esperar_ventana` de `verificar_denuncia.py`.
- El log de la API se captura en streaming durante la prueba, no al final: la rotación (3 ficheros de 10 MB) y las líneas `EVENTO login_fallido` de una inundación de login podrían echar fuera las señales que se buscan.

### Funcionales (`tests/funcionales/`, pytest y Playwright)

Límites relajados (todo sale de la misma IP y un circuito supera las 10 denuncias por hora), comprobados con `LIMITES (configurados)`. El denunciante usa siempre el 8444 sin JavaScript, que es como lo usa de verdad.

| Id | Prueba | Oráculo | Control positivo | Motores |
|---|---|---|---|---|
| F1 | Circuito entre actores con dos contextos de navegador: el denunciante presenta en el 8444, el personal entra en el 8445 (contraseña y TOTP), abre el expediente, responde y cambia el estado; el denunciante consulta con su código, ve el estado y la respuesta y escribe; el personal ve el mensaje | El texto sembrado por un actor aparece literal en el otro; el 8444 muestra la etiqueta del estado escrita a mano en la prueba (por ejemplo, "En instrucción") | Es el propio camino feliz: cada paso comprueba el anterior | Chromium y Firefox |
| F2 | Errores del 8444: formulario no válido, código de seguimiento mal formado y código inexistente | Formulario no válido: 422, `aria-invalid="true"` en el campo y `role="alert"`. Mal formado e inexistente: el mismo 404 con el mismo texto, "código de seguimiento no válido", sin revelar si el código existe | El mismo formulario, válido, se acepta; un código real muestra su denuncia | Chromium, Firefox y WebKit |
| F3 | JavaScript desactivado de verdad en el contexto del denunciante | Una página de control servida con `page.route` desde otro origen sin CSP carga (su marcador estático está en el DOM) y no ejecuta su script en ese contexto | El mismo script se ejecuta en un contexto con JavaScript. Si el marcador no aparece, `SIN CONCLUSION` | Los tres |

Por HTTP, `verificar_web.py` (k, m, r) ya prueba los errores del 8444. F2 aporta el navegador real y los tres motores, no el control de seguridad.

Detalles de ejecución: en serie, una empresa nueva por ejecución, una cuenta por rol y navegador (activada con el cartero y Mailpit), el contexto del navegador vivo entre pasos y un TOTP que recuerda el último paso usado, porque un código es de un solo uso (como `verificar_spa.py`, i). Un fallo de WebKit se marca como fallo esperado con su motivo, se apunta en la sección 5 y deja el resultado en `NO OK`. Trazas de Playwright solo al fallar, guardadas fuera del repositorio (no se publican: llevan códigos y textos). Un modo conserva la pila mientras se desarrolla; la evidencia sale de una ejecución limpia final.

### Estrés en local (`tests/estres/`, k6 v2.3.0 por digest)

**Recursos.** Ningún servicio declara `cpus` en los compose: en producción, Canario no tiene tope de CPU. En la pila de estrés se fijan `cpus` en la API y en PostgreSQL con los núcleos del VPS, y k6 corre aislado con `--cpuset-cpus` en otros núcleos, para no medir el generador. Aun así, los resultados son **relativos**: describen el comportamiento y el orden en que cede cada pieza, no la capacidad del VPS. Modelo abierto (tasa de llegada constante), con calentamiento, 3 repeticiones (se toma la mediana) y una duración que da al menos 600 muestras por ruta medida.

**Qué se registra en todas.** Latencias p50, p95 y p99 por ruta; códigos de estado; y aparte, las conexiones cortadas, los fin de fichero inesperados y los plazos agotados, que no dejan línea en el log de la API (por ejemplo, si se agotan los hilos de trabajo, la petición espera al limitador de hilos de AnyIO dentro del bucle de eventos, y la corta el plazo `write 30s` del servidor de Caddy). Los 429 los cuenta k6, porque la API no los registra (una línea con hora situaría al denunciante). CPU y memoria de cada contenedor (`docker stats`).

**Cota para los vecinos.** Con `cpus` fijados, la CPU de la pila mide los topes de la propia prueba. Por eso hay una pasada extra de L1 **sin topes de CPU**, como en producción: su CPU total en el codo es la cota de lo que Canario puede quitar a las aplicaciones vecinas del VPS.

**Control del generador.** Si k6 descarta iteraciones (`dropped_iterations` > 0) o su CPU se satura, el resultado es `SIN CONCLUSION`: se habría medido el generador, no Canario.

| Id | Prueba | Qué se mide | Control positivo | Límites |
|---|---|---|---|---|
| L1 | Capacidad y codo de las rutas caras: login con empresa o email inexistentes (el mismo trabajo de Argon2 que uno real, sin tocar cuentas ni bloqueos), presentar denuncia y seguimiento | Tasa sostenida con p95 bajo el SLO hasta el codo, y qué cede primero: `SIN CONEXION: PoolTimeout`, `SATURACION`, `EVENTO hashes_saturados`, `EVENTO limitador_no_disponible`, contenedor `OOMKilled` o reiniciado, o cola de hilos (conexiones cortadas sin línea en el log) | El primer escalón, a tasa baja, cumple el SLO; si no, `SIN CONCLUSION` (la pila de prueba está mal) | Relajados |
| L2 | **Aislamiento** (la prueba principal): se inunda el login y, a la vez, se mide el p95 de presentar denuncia, de seguimiento y de una ruta síncrona barata (`GET /web/seguimiento`) a una tasa baja constante | p95 de cada ruta con y sin la inundación, frente al SLO. La ruta barata separa "falta CPU o base de datos" de "faltan hilos". Si se rompe, es el hallazgo: se mitiga y se vuelve a medir | La medida de las mismas rutas sin inundación, en la misma ejecución | Relajados: representan una carga repartida entre muchas IPs, cada una bajo su límite (20 logins por segundo sostenidos equivalen a unas 600 IPs a 10 cada 5 minutos) |
| L3 | Carga repartida: k6 en el lugar de Traefik (10.88.1.2, red `edge`) con `Caddyfile.produccion` y la cabecera `Host` de producción, cada IP simulada al final de `X-Forwarded-For` (sin relajar `trusted_proxies`), con 200 IPs | El caudal agregado que llega a la API (200 IPs a 60 seguimientos por minuto son 12 000 por minuto) frente al codo de L1. Oráculo por IP y ventana: como mucho 60 respuestas que no son 429 (hasta 120 si la ráfaga cruza la frontera, el defecto conocido de la ventana fija, que aquí se mide) | Las 60 primeras peticiones de cada IP en su ventana no son 429 | **Producción** |
| L4 | Pico de 10 veces la tasa base durante 30 s y recuperación | Segundos hasta volver al p95 base, y F1 en verde después de la carga | El p95 base medido justo antes del pico | Relajados |
| L5 | IP compartida (Tor o NAT, coste asumido en `docs/threat-model.md`, 8), con la ventana alineada: un cliente presenta 10 denuncias desde una IP | La 11.ª, que en la práctica sería otro denunciante detrás de la misma IP (el servidor no puede distinguirlos), recibe 429 con `Retry-After`. Se documenta como coste asumido, no como fallo | Las 10 primeras dan 201 | **Producción** |
| L6 | Agotar el limitador: con el arnés de L3, denuncias con cuerpo no válido desde IPs simuladas siempre nuevas (el limitador cuenta antes de validar y cada IP crea una clave que vive 3600 s desde su creación, con `EXPIRE ... NX`). Hipótesis de tasa en H5, con una duración máxima de 75 minutos: si Redis no se llena en ese tiempo, el resultado es "no se llenó", que refuta H5, no `SIN CONCLUSION`. La ACL de Redis no permite `INFO`, así que se mide por el efecto | Aparece `EVENTO limitador_no_disponible` con la clase del error; un cliente legítimo recibe 503 con `Retry-After: 5`; `/salud`, exenta, sigue dando 200 (un monitor externo vería el sitio sano durante la caída); se anotan las IPs y el tiempo necesarios. Recuperación, con la carga parada en cuanto aparece el 503: gradual a partir del inicio de la carga + 3600 s, a medida que caducan las claves más antiguas, y completa como mucho 3600 s después de la última clave creada; se mide el instante en que el cliente legítimo deja de recibir 503 (el cambio de hora UTC no libera nada) | El mismo cliente legítimo no recibe 503 antes de empezar a llenar | **Producción** |
| L7 | Inundación de `/salud`: es pública por el puerto de la API, la consulta un monitor externo y está exenta del limitador | El criterio de degradación de la sección 3 sobre denuncia, seguimiento y `GET /web/seguimiento`, con `/salud` como ruta inundada | La medida de las mismas rutas sin inundación, en la misma ejecución | **Producción** |

Lo que L3 demuestra ya está escrito en el diseño: **el límite por IP no frena una carga repartida**. Lo que protege la capacidad es el pool de 5 conexiones, el semáforo de 2 hashes de Argon2 y el fallo cerrado. Que el límite se aplica por IP ya lo prueban `verificar_denuncia.py` (r5, límites de producción) y `verificar_despliegue.py` (c, a través de un Traefik real).

Límites de producción (`LIMITES_POR_DEFECTO`, `app/limitador.py`), con ventana fija: por IP, denuncia 10/h, seguimiento 60/min, mensajes 30/h, acceso 10/5 min, registro 10/h y otras 60/min; por cuenta del personal, 60/min; por email de registro, 3/15 min y 10/día.

### En producción (VPS compartido)

El VPS aloja otras aplicaciones con usuarios reales. Por eso, en producción **no se busca el punto de rotura**: se comprueba que las defensas están. Reglas:

- Cero datos creados.
- Topes fijos dentro del script: se niega a superarlos.
- El destino por defecto es la pila local; producción hay que pedirla de forma explícita.
- Franja acordada con los dueños de las aplicaciones vecinas.
- Antes de empezar se lee, sin tocarla, la configuración de Traefik (log de acceso, `forwardedHeaders` y plazos).
- Dos redes con IPv4 distintas: A, la fibra de casa; B, los datos del móvil, forzando IPv4. Se anota la IP pública de cada una antes de empezar. Dos IPv6 de la misma red compartirían contador (el limitador agrupa IPv6 por /64).

| Id | Prueba | Oráculo | Control positivo |
|---|---|---|---|
| P1 | Dos clientes se distinguen a través de Traefik: A agota su cupo de seguimiento | B sigue recibiendo respuesta que no es 429 | A recibe 429 a partir de la petición 61 de su ventana |
| P1b | A no puede inventarse IPs: 70 seguimientos con un `X-Forwarded-For` distinto en cada uno, todas de los rangos de documentación (192.0.2.0/24, 198.51.100.0/24 y 203.0.113.0/24), para no gastar el cupo de IPs reales de terceros si la cabecera se tuviera en cuenta. Confirma en producción la lectura estricta de Caddy que prueba `verificar_despliegue.py` (c) | 429 a partir de la 61 | Sin la cabecera, en otra ventana posterior a P1, también 429 a partir de la 61 (el límite está activo) |
| P2 | Denuncia no válida repetida. Solo arranca si quedan más de 10 minutos de la hora UTC en curso; gasta el cupo de denuncias de la IP hasta el fin de esa hora (el 8444 y la API comparten contador) | 10 respuestas 422 y la 11.ª, 429 con `Retry-After` entre 1 y 3600 | Las 10 primeras son 422, no 429 |
| P3 | Cuerpo real de 128 KiB + 1 byte | 413 de Caddy en menos de 0,5 s, con `Connection: close` | `POST /salud` con 128 KiB justos da 405 con `Via` (como `verificar_despliegue.py`, b) |
| P4 | Límites efectivos | El log de arranque de la API contiene la línea entera de los límites por defecto, con las 9 reglas | La misma comprobación en la pila local con límites relajados da otra línea. Si la rotación ya borró la línea de arranque: `SIN CONCLUSION` |
| P5 | Línea base: seguimiento con un código inexistente a 0,5 peticiones por segundo durante 10 minutos | p50, p95 y máximo, que sirven de referencia a P6 | Ninguna respuesta es 429 |
| P6 | Rampa de hasta 20 peticiones por segundo durante 2 minutos desde A contra seguimiento inexistente, de noche (23:00 a 00:00), con B a 0,5 por segundo y sondas a las aplicaciones vecinas cada 1 a 2 s | A recibe como mucho 60 respuestas que no son 429 por ventana (120 si cruza la frontera): mide el ataque realista desde una IP, que absorben Traefik, Caddy y el limitador. B, frente a P5: ningún error y p50 ≤ 2 × p50 de P5 (con unas 60 muestras es un indicio, no un SLO, y así se presenta). Sondas a cada vecina, con 5 minutos de línea base justo antes: parada automática si dos sondas seguidas fallan (respuesta que no es 2xx ni 3xx, o más de 5 s) o si su latencia supera 3 × su p95 de línea base | A recibe 429 |

**Observación, no prueba:** un `Content-Length` declarado sin cuerpo, a través de Traefik, dejó al cliente 40 s sin respuesta en la medida del 20/11. La duración real la deciden los plazos de Traefik, que no están en el repositorio. No se repite en producción (las conexiones lentas también ocupan el Traefik compartido); en local se prueba contra Caddy, con sus plazos de 10 s para las cabeceras y 30 s para el cuerpo.

## 3. Hipótesis y SLO

Se congelan en dos commits propios, cada uno **con push a GitHub antes de medir**: la fecha del push la pone el servidor, no quien hace el commit.

1. **Primera congelación**, antes de L1 y de P5: los SLO, el criterio de degradación, la definición de error y las hipótesis. Incluye el tiempo de un hash de Argon2 medido dentro del contenedor de la API de la pila de prueba (mediana de 20 hashes), que necesita H1. Medir un hash no es una prueba de carga.
2. **Segunda congelación**, antes de L2, L4, L7 y P6: la tasa baja de L2 y L7, la tasa base de L4 y las líneas base de P5, todas sacadas de L1 y P5.

### Definición de error

Cuenta como error: un 5xx, una conexión cortada, un fin de fichero inesperado o un plazo agotado. No cuentan: los 404 y 422 que la prueba espera, ni los 429. En L2, los 503 del login inundado tampoco cuentan: un 503 rápido cuando no hay hueco para un hash es el diseño.

### SLO de la pila de prueba (L1)

Son umbrales de esta pila, con `cpus` fijados, no del VPS. Definen el codo de L1: la primera tasa con un p95 por encima del umbral o con un 1 % o más de errores.

| Ruta | p95 | Errores |
|---|---|---|
| Presentar denuncia | ≤ 1000 ms | < 1 % |
| Seguimiento | ≤ 500 ms | < 1 % |
| `GET /web/seguimiento` | ≤ 300 ms | < 1 % |
| Login (empresa o email inexistentes) | ≤ 1500 ms | < 1 % |

### Criterio de degradación (L2, L4 y L7)

Relativo a la línea base de la misma ejecución, con un suelo absoluto para que el ruido sobre una base de pocos milisegundos no dé un NO PASA falso: una ruta está degradada si su p95 supera **max(2 × p95 base, p95 base + 100 ms)**, con la mediana de las 3 repeticiones. Además, el p95 nunca puede superar el SLO de L1 de esa ruta.

En producción (P5 y P6) los umbrales son absolutos, porque es la máquina real: los de P6.

### Hipótesis

- **H1 (L1, login).** Con 2 hashes simultáneos, el login sostiene 2 / t logins por segundo (t, el tiempo de un hash de la primera congelación), con una tolerancia de ±25 %. Por encima, 503 con `EVENTO hashes_saturados` tras 2 s de espera.
- **H2 (L1, denuncia y seguimiento).** El codo lo marca el pool de 5 conexiones con PostgreSQL: por encima aparece `SIN CONEXION: PoolTimeout` tras 10 s de espera, antes que cualquier otra señal.
- **H3 (L2).** La inundación del login degrada denuncia, seguimiento y `GET /web/seguimiento` según el criterio de degradación, sin que esas rutas víctima dejen ninguna línea en el log (la inundación sí deja `EVENTO login_fallido` y `EVENTO hashes_saturados`). Mecanismo: las rutas son síncronas y comparten un pool de hilos limitado, y un login retiene su hilo hasta 2 s esperando el semáforo y hasta 10 s esperando una conexión.
- **H4 (L7).** `/salud` es síncrona pero responde al momento: pasa por el pool de hilos de AnyIO en cada petición, pero no retiene un hilo. Si degrada algo, es por la CPU del único proceso de uvicorn (sin `--workers`), que el GIL limita a un núcleo. Predicción: no hay degradación mientras el proceso de la API está por debajo de un núcleo y de su tope de `cpus`, y sí la hay cuando llega a uno de los dos, lo que ocurra antes. La ruta barata de L7 distingue además si se encolan hilos.
- **H5 (L6).** Con la regla de denuncia (cada clave vive 3600 s desde su creación) y unos 100 B por clave (supuesto sin medir), en 64 MB caben unas 500 000 claves: a 150 peticiones por segundo desde IPs siempre nuevas, el 503 para los clientes legítimos aparece antes de 60 minutos (unos 55), y `/salud` sigue en 200. Sin intervención, el servicio vuelve de forma gradual a partir de una hora después del inicio de la carga.
- **H6 (L4).** Tras el pico, el p95 calculado en ventanas deslizantes de 10 s vuelve a cumplir el criterio de degradación frente a la base en menos de 60 s, sin reinicios de ningún contenedor.

## 4. Por qué Playwright y no Selenium

| Criterio | Playwright | Selenium |
|---|---|---|
| Ya en el proyecto | Sí: imagen 1.63.0 fijada por digest y paquete con hashes en `verificar_spa.py` | No: dependencias nuevas que verificar y fijar |
| Varios motores | Chromium, Firefox y WebKit con la misma API y los navegadores dentro de la imagen fijada | Un driver por navegador. Selenium Manager los descarga al ejecutar, lo que choca con fijar versiones |
| Dos actores a la vez | Contextos aislados en el mismo navegador, cada uno con sus cookies | Una sesión de navegador por actor |
| JavaScript desactivado por contexto | Una opción del contexto | Depende del navegador y del driver |
| Interceptar la red (control de F3) | `page.route` | No en WebDriver clásico; WebDriver BiDi, según navegador |
| Esperas | Automáticas en cada acción | Explícitas, a mano |
| Diagnóstico de un fallo | Traza con capturas, DOM y red | Capturas a mano |

Selenium sigue siendo la referencia histórica y el estándar W3C (WebDriver). Aquí no aporta nada que falte y obligaría a fijar y verificar otra cadena de dependencias.

## 5. Lo que no se prueba y los límites aceptados

- Ataques volumétricos de red (T1498): los absorbe, o no, el proveedor del VPS, no la aplicación. Ninguna prueba de esta tarea demuestra que Canario "resiste un DDoS".
- El punto de rotura de producción: no se busca ni se publica.
- Conexiones lentas contra el Traefik compartido en producción.
- El login con cuentas reales en producción.
- IPv6 en producción: un atacante con un /48 tendría 65 536 contadores /64. Se anota si producción atiende por IPv6.
- Accesibilidad automática, móvil e integración continua.
- Los fallos esperados de WebKit, con su motivo, si los hay.

## 6. Evidencia

- Informe HTML de pytest de la ejecución limpia final.
- Exportado HTML del panel de k6 de cada prueba de estrés.
- Salidas de las pruebas de producción.
- GIF de 10 a 15 s con el circuito en dos navegadores y vídeo de 2 a 3 minutos.
- Los dos commits de congelación con su push, y el tag de Git de la versión entregada.

No se publican trazas de Playwright, HAR ni scripts con producción como destino por defecto.
