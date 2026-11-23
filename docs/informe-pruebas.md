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

**Recursos.** Ningún servicio declara `cpus` en los compose: en producción, Canario no tiene tope de CPU. En la pila de estrés todos los servicios de Canario comparten un cpuset de 2 núcleos, los del VPS (las mismas 2 CPU lógicas, sin hermanas de hiperhilo), y k6 corre aislado con `--cpuset-cpus` en otros núcleos, para no medir el generador. Aun así, los resultados son **relativos**: describen el comportamiento y el orden en que cede cada pieza, no la capacidad del VPS. Modelo abierto (tasa de llegada constante), con calentamiento, 3 repeticiones (se toma la mediana) y una duración que da al menos 600 muestras por ruta medida.

**Qué se registra en todas.** Latencias p50, p95 y p99 por ruta; códigos de estado; y aparte, las conexiones cortadas, los fin de fichero inesperados y los plazos agotados, que no dejan línea en el log de la API (por ejemplo, si se agotan los hilos de trabajo, la petición espera al limitador de hilos de AnyIO dentro del bucle de eventos, y la corta el plazo `write 30s` del servidor de Caddy). Los 429 los cuenta k6, porque la API no los registra (una línea con hora situaría al denunciante). CPU y memoria de cada contenedor (`docker stats`). En cada escalón, dos sondas de atribución a 1 petición por segundo: `POST /salud` (sin base de datos ni limitador) y `GET /web/seguimiento` (síncrona y barata). Si sube solo la de `/web/seguimiento`, faltan hilos; si suben las dos, falta CPU; si no sube ninguna y aparece `SIN CONEXION`, el límite es el pool de 5 conexiones.

**Cota para los vecinos.** Con el cpuset de 2 núcleos, la CPU de la pila mide los topes de la propia prueba. Por eso hay una pasada extra de L1 **sin topes de CPU**, como en producción: su CPU total en el codo es la cota de lo que Canario puede quitar a las aplicaciones vecinas del VPS.

**Control del generador.** Si k6 descarta iteraciones (`dropped_iterations` > 0) o su CPU se satura, el resultado es `SIN CONCLUSION`: se habría medido el generador, no Canario.

| Id | Prueba | Qué se mide | Control positivo | Límites |
|---|---|---|---|---|
| L1 | Capacidad y codo de las rutas caras: login con empresa o email inexistentes (el mismo trabajo de Argon2 que uno real, sin tocar cuentas ni bloqueos), presentar denuncia y seguimiento. El login mide Argon2 más lecturas, no las escrituras de un fallo con cuenta real ni la sesión de un login correcto; el seguimiento inexistente solo calcula el HMAC y hace un SELECT, sin descifrar | Tasa sostenida con p95 bajo el SLO hasta el codo, y qué cede primero: `SIN CONEXION: PoolTimeout`, `SATURACION`, `EVENTO hashes_saturados`, `EVENTO limitador_no_disponible`, contenedor `OOMKilled` o reiniciado, o cola de hilos (conexiones cortadas sin línea en el log) | El primer escalón, a tasa baja, cumple el SLO; si no, `SIN CONCLUSION` (la pila de prueba está mal) | Relajados |
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

1. **Primera congelación**, antes de L1 y de P5: los SLO, el criterio de degradación, la definición de error y las hipótesis. Incluye el tiempo de un hash de Argon2 medido dentro del contenedor de la API de la pila de prueba (mediana de 20 `verify()` en serie, el mismo trabajo que hace un login), que necesita H1. Medir un hash no es una prueba de carga.
2. **Segunda congelación**, antes de L2, L4, L7 y P6: la tasa baja de L2 y L7, la tasa base de L4 y las líneas base de P5, todas sacadas de L1 y P5.

### Tiempo de un hash (t)

Medido el 21/11/2026 con `python tests\estres\lanzar.py --hash`, en la pila de prueba con el cpuset de 2 núcleos, con Argon2id m=19456 KiB, t=2, p=1 (comprobado como literal en `app/personal.py`):

| Medida | Valor |
|---|---|
| `hash()`, una vez | 45,4 ms |
| `verify()`, 20 en serie: mediana | 19,6 ms |
| `verify()`, 20 en serie: mínimo y máximo | 18,5 ms y 33,7 ms |

**t = 0,0196 s**, y 2 / t = 101,91 logins por segundo. H1 predice, por tanto, un codo del login entre 76,4 y 127,4 logins por segundo (±25 %).

### Definición de error

Cuenta como error: un 5xx, una conexión cortada, un fin de fichero inesperado o un plazo agotado. No cuentan: los 404 y 422 que la prueba espera, ni los 429. En L2, los 503 del login inundado tampoco cuentan: un 503 rápido cuando no hay hueco para un hash es el diseño.

### SLO de la pila de prueba (L1)

Son umbrales de esta pila, con el cpuset de 2 núcleos, no del VPS. Definen el codo de L1: la primera tasa con un p95 por encima del umbral o con un 1 % o más de errores.

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
- **H2 (L1, denuncia y seguimiento).** El codo lo marca el pool de 5 conexiones con PostgreSQL: por encima aparece `SIN CONEXION: PoolTimeout` tras 10 s de espera, antes que cualquier otra señal. En local, el disco virtual de WSL2 puede adelantarse al pool: por eso se anota el BlockIO de PostgreSQL en cada escalón.
- **H3 (L2).** La inundación del login degrada denuncia, seguimiento y `GET /web/seguimiento` según el criterio de degradación, sin que esas rutas víctima dejen ninguna línea en el log (la inundación sí deja `EVENTO login_fallido` y `EVENTO hashes_saturados`). Mecanismo: las rutas son síncronas y comparten un pool de hilos limitado, y un login retiene su hilo hasta 2 s esperando el semáforo y hasta 10 s esperando una conexión.
- **H4 (L7).** `/salud` es síncrona pero responde al momento: pasa por el pool de hilos de AnyIO en cada petición, pero no retiene un hilo. Si degrada algo, es por la CPU del único proceso de uvicorn (sin `--workers`), que el GIL limita a un núcleo. Predicción: no hay degradación mientras el proceso de la API está por debajo de un núcleo y del cpuset de 2 núcleos, y sí la hay cuando llega a uno de los dos, lo que ocurra antes. La ruta barata de L7 distingue además si se encolan hilos.
- **H5 (L6).** Con la regla de denuncia (cada clave vive 3600 s desde su creación) y unos 100 B por clave (supuesto sin medir), en 64 MB caben unas 500 000 claves: a 150 peticiones por segundo desde IPs siempre nuevas, el 503 para los clientes legítimos aparece antes de 60 minutos (unos 55), y `/salud` sigue en 200. Sin intervención, el servicio vuelve de forma gradual a partir de una hora después del inicio de la carga.
- **H6 (L4).** Tras el pico, el p95 calculado en ventanas deslizantes de 10 s vuelve a cumplir el criterio de degradación frente a la base en menos de 60 s, sin reinicios de ningún contenedor.

### Segunda congelación (22/11/2026): L2, L3, L3b y L4

Se congela en su propio commit, con push antes de ejecutar L2, L3, L3b o L4. L7 y P6 no entran: sus tasas se congelarán en otro commit antes de medirlas.

**Fe de erratas de la primera congelación.** Donde dice "2 / t = 101,91 logins por segundo", con t = 0,0196 s el valor correcto es **2 / t = 102,04** (la salida de L1 ya lo calcula bien: "0.5 x 2/t=51.02/s"). Se deja el texto original sin tocar y se corrige aquí. La predicción de H1, ±25 %, pasa a ser de 76,5 a 127,6 logins por segundo. El codo medido, 76/s, queda justo por debajo del límite inferior: H1 sigue refutada, igual que con la cifra errónea.

**Regla de las tasas y por qué.** Todas las tasas salen de t = 0,0196 s, el valor que se pasa con `--t`, y no del codo de L1. Es una desviación de la lista de arriba ("todas sacadas de L1 y P5"). El motivo es que t se congeló antes de cualquier carga, mientras que el codo es un resultado (de una sola repetición el 22/11; L1 × 3 aún no se ha ejecutado). Si las tasas se eligieran viendo los resultados, se podría sospechar que se ajustaron para que la prueba saliera de una forma concreta. Para que se pueda comparar, esto es lo que habría salido con el codo de 76/s:

| Prueba | Con t (lo que se congela) | Con el codo de L1 (no se usa) |
|---|---|---|
| L2, inundación del login | 1,5 × 2/t = **153,06/s** (el último escalón de L1) | 1,5 × 76 = 114/s |
| L4, login en el pico | 2/t = **102,04/s** (la capacidad que predice H1) | 76/s |
| L4, login en la base | 0,1 × 2/t = **10,20/s** | 7,6/s |
| L3b, IPs del ataque | ceil(102,04 × 300 / 9) = **3402** | ceil(76 × 300 / 9) = 2534 |

La base del login de L4 se eligió hacia atrás: el pico es 10 veces la base, así que la base es una décima parte del pico.

**Escenarios congelados.**

- **L2** (límites relajados de estrés, Caddyfile local). Hay dos empresas: A, la atacada, y B, la del denunciante. Las víctimas van a 5/s cada una: denuncia contra B, seguimiento inexistente y `GET /web/seguimiento`, con 50 VUs por víctima. La inundación es `login_email` contra A a 153,06/s, con un máximo de 600 VUs. Además, `POST /salud` a 1/s. Fases: calentamiento de 30 s, BASE de 120 s, INUNDACIÓN de 120 s y RECUPERACIÓN de 120 s. La inundación termina en su fin programado (inicio más duración); los 20 s siguientes no se cuentan.
- **L4** (límites relajados). Un escenario `constant-arrival-rate` por ruta y fase, para saber a qué ruta corresponde cada descarte. En la BASE: denuncia contra B, seguimiento y `GET /web/seguimiento` a 5/s cada una, y login a 10,20/s, en total 25,20/s. En el PICO, durante 30 s, todo por 10: 50/s en cada víctima y 102,04/s en el login. Fases: calentamiento de 30 s, BASE de 120 s, PICO de 30 s y RECUPERACIÓN de 180 s. Además, `POST /salud` a 1/s.
- **L3** (límites de producción). Se usa `Caddyfile.produccion` y la red `edge` va con `internal: true`. k6 se pone en 10.88.1.2 con la cabecera `Host` de producción y la IP simulada al final de `X-Forwarded-For`. Hay 200 IPs de 198.18.0.0/15, que se turnan por iteración, a 1,5/s por IP: 300/s contra seguimiento inexistente durante 300 s. Empieza justo después de una frontera de minuto UTC, según el reloj de la VM. Con el Host de producción, la página web es `/seguimiento`.
- **L3b** (el mismo montaje que L3). El ataque es `login_email` contra A a 102,04/s desde 3402 IPs: 9 peticiones por IP en cada ventana de 300 s, por debajo del límite de 10 de `acceso`. El email inexistente solo consume `acceso`. El ataque dura como mínimo 300 s y empieza justo después de una frontera de 5 minutos UTC. Las víctimas son las de L2, con rangos de IPs que no se solapan con el ataque ni entre sí, calculados con su regla y un margen de 1,5: 428 IPs para la denuncia y 8 para cada una de las otras dos. Fases: calentamiento de 30 s, BASE de 120 s, ATAQUE de 300 s y RECUPERACIÓN de 120 s. Hay 10 IPs de control, distintas de todas las demás, que reciben 11 peticiones en la misma ventana. El resultado es una **cota superior** de lo que le cuesta el ataque a un atacante a esa tasa y durante ese tiempo, no el mínimo. Se da en función de la duración del corte; para un corte de 30 s se calcula a mano (unas 306 IPs, o 153 aprovechando la frontera de la ventana), sin medirlo. Solo cubre IPv4: el dominio no tiene registro AAAA. La comparación con las unas 2300 IPs de `docs/threat-model.md` es 0,75 × 102,04 × 300 / 10 = 2296.
- **Tras el pico de L4, un humo HTTP en vez de F1** (es una desviación de la matriz, fila L4). F1 levanta su propia pila, con las mismas subredes, así que no puede comprobar que la pila de estrés se ha recuperado. El humo se lanza en la misma pila 120 s después del fin del pico: denuncia en B (201 y código), `POST /v1/seguimiento` con ese código (200 y el texto sembrado), `GET /web/seguimiento` (200) y el formulario de consulta del 8444 con el código (200 y el texto). El control es el mismo humo justo antes del pico. Las peticiones de los dos humos llevan su propia etiqueta y no cuentan para el p95.

**Reglas comunes de veredicto (J1).** Hay dos clases de control:

- **Validez:** la CPU de k6 por encima del 320 %, descartes sin el aviso `Insufficient VUs`, un OOM o un código de salida de k6 distinto de 0, la BASE fuera del SLO, un hueco del lector de más de 3 s, un protocolo distinto de HTTP/1.1, una repetición que cruza las 00:00 UTC, una línea de límites distinta de la literal o un fallo del control del detector. Cualquiera de ellos da `SIN CONCLUSION`, y `SIN CONCLUSION` **gana a FALLA**. Basta con una repetición `SIN CONCLUSION` por validez para que toda la prueba sea `SIN CONCLUSION`.
- **Control de que el ataque existe:** solo puede convertir un PASA en `SIN CONCLUSION`. Nunca toca una FALLA.
- **La muerte de un servicio de Canario es FALLA**, y ningún fallo de validez la anula, salvo el OOM global de la VM, que da `SIN CONCLUSION`. Un hueco del lector o un fallo del detector durante una muerte ya identificada no cuenta como fallo de validez.
- Hacen falta 3 repeticiones válidas. El p95 y la degradación se evalúan sobre la mediana de las tres, y se publica también el veredicto de cada repetición.
- **Comprobación de que no se filtran datos:** al final, en cada fichero guardado (incluidos los de una ejecución abortada) se buscan los valores sembrados, tal cual y codificados para URL o JSON. Si aparece alguno, `SIN CONCLUSION`. El control es un valor centinela que la batería planta a propósito en un fichero y que la búsqueda tiene que encontrar.

**Oráculos.**

- **B1, cada víctima de L2 y L3b durante la inundación o el ataque.** FALLA si está degradada (según el criterio de degradación), si su p95 supera el SLO, si tiene un 1 % o más de errores (incluidos los plazos agotados y las respuestas con un estado distinto del esperado) o si hay descartes con el aviso en su escenario. Si no, PASA. El 99 % del estado esperado solo da `SIN CONCLUSION` en la BASE: una víctima caída es FALLA. El veredicto de la prueba es el de la peor víctima.
- **B2, control de que el ataque existe en L2 y L3b.** Se cumple si el p95 del login supera 1500 ms, si el login tiene un 1 % o más de errores o si hay descartes con el aviso en el escenario del login. La CPU de la API y la tasa realmente atendida solo se informan. Predicciones informativas de la espera de las víctimas: 560 / 102,04 = 5,5 s y 560 / 73 (lo que la API sirvió en L1) = 7,7 s.
- **C1, por IP y ventana en L3.** Una petición es ambigua si el intervalo entre su inicio y su fin (marca menos duración, marca) cruza una frontera de minuto UTC. Solo cuentan como aceptadas las respuestas 404 (J3); los 503 se cuentan aparte y se comparan uno a uno con las líneas `EVENTO`. FALLA si en algún par IP-ventana hay más de 60 aceptadas no ambiguas. `SIN CONCLUSION` si solo se pasa de 60 al contar también las ambiguas. PASA en el resto de casos. Todo 429 debe llevar `Retry-After` entre 1 y 60.
- **J2, control positivo de L3.** No pueden ser 429 las primeras peticiones no ambiguas de cada par, en número de 60 menos las ambiguas del principio del par y menos las anteriores del mismo par con estado 0 o 503.
- **Desviación de la tabla de arriba, fila L3** ("hasta 120 si la ráfaga cruza la frontera"). El defecto de la ventana fija ya no forma parte del oráculo. Se mide aparte, como información: el máximo de aceptadas por IP en cualquier tramo de 60 s, que se espera que sea como mucho 120.
- **Controles de configuración de L3 y L3b.** Si alguno falla, la ejecución para:
  - una petición desde 10.88.1.3 con el Host de producción debe recibir el 403 literal de `Caddyfile.produccion`;
  - 70 peticiones con `X-Forwarded-For: <IP falsa que cambia en cada una>, 198.19.255.254` deben contar todas para 198.19.255.254, así que dan 429 a partir de la 61. Si cruzan la frontera de minuto, el resultado es `SIN CONCLUSION`;
  - entre repeticiones se recrea la API, y la primera petición de una IP usada en la repetición anterior no puede ser 429.
- **D3, control de que el límite está activo en L3b.** La 11.ª petición de cada una de las 10 IPs de control tiene que ser 429; si no, `SIN CONCLUSION`.
- **D6, L3b.** (a) Por IP y ventana, como C1 pero con un límite de 10 en una ventana de 300 s, contando solo los 401 como aceptados, y con el control J2 calculado sobre 10. (b) Las víctimas, con B1 y el control B2. Lo que espera el diseño: (a) PASA, y (b) FALLA.
- **F2, recuperación en L4.** Se calcula el p95 en ventanas de 10 s que avanzan de 1 en 1 s, con cada petición asignada a la ventana de su inicio. Solo cuentan las ventanas que empiezan después del fin programado del pico. El tiempo de recuperación es el inicio de la primera ventana a partir de la cual todas las rutas cumplen el criterio de degradación frente a su BASE durante 30 s seguidos. El control es el mismo cálculo sobre la propia BASE: debe encadenar 30 s seguidos dentro del criterio, y al menos el 95 % de sus ventanas tiene que cumplirlo. Si no, `SIN CONCLUSION`.
- **F3, L4.** PASA si se recupera en menos de 60 s, sin reinicios y con el humo correcto. FALLA si tarda 60 s o más o no se recupera en los 180 s (H6 refutada), si se reinicia algún contenedor o si el humo falla.

**Severidad de los hallazgos: la escala OWASP Risk Rating.** La probabilidad y el impacto se puntúan de 0 a 9, cada uno como la media de sus factores:

- **Probabilidad:** habilidad, motivo, oportunidad y tamaño del atacante; facilidad para descubrir la vulnerabilidad y para explotarla, cuánto se conoce y cómo de fácil es detectar el ataque.
- **Impacto:** técnico (confidencialidad, integridad, disponibilidad y trazabilidad) y de negocio (daño económico, reputación, incumplimiento normativo y privacidad).

Cada media es BAJA si va de 0 a menos de 3, MEDIA de 3 a menos de 6 y ALTA de 6 a 9. La severidad final sale de esta tabla:

| Impacto \ Probabilidad | BAJA | MEDIA | ALTA |
|---|---|---|---|
| ALTO | Media | Alta | Crítica |
| MEDIO | Baja | Media | Alta |
| BAJO | Nota | Baja | Media |

Si L2 da FALLA, se registra en `docs/threat-model.md` §8 con esta escala, en estado ABIERTO, y el `RESULTADO GLOBAL` queda en NO OK.

### Erratas y aclaraciones de la segunda congelación (22/11/2026)

La segunda congelación (commit `d1432c1`) se subió antes de que terminara su revisión independiente. Su texto no se toca. Lo que corrige o concreta esa revisión va aquí, en un commit propio y también con push antes de medir. Ninguna de estas aclaraciones cambia una tasa ni el sentido de un oráculo: corrigen la redacción o eligen una de las dos lecturas posibles de un texto ambiguo.

**E1. De dónde sale el 101,91.** No fue un error de cálculo. La salida de `lanzar.py --hash` del 21/11 imprime "t = 0.0196 s; 2/t = 101.91": el 2/t se calculó con la mediana sin redondear (unos 0,019625 s), y el t se mostró redondeado. L1 se ejecuta con `--t 0.0196`, que da 102,04, y ese es el valor que se congela. En la segunda congelación, donde dice "el valor correcto es" debe leerse "el valor con t = 0,0196 s es".

**E2. H1 y el codo.** El codo de `login_email` en la L1 del 22/11 (una repetición) es el escalón e2, a 0,75 × 2/t = **76,53/s**: es la primera tasa con un p95 por encima del SLO (9120 ms). No es "76/s", y no cae por debajo del intervalo: queda exactamente en su borde inferior. La frase "queda justo por debajo del límite inferior" de la segunda congelación es incorrecta. H1 se evalúa con la regla que ya estaba en `lanzar.py` cuando se obtuvo la evidencia de L1 (commit `ef85f28`): solo se confirma si el codo cae en 1,0 o 1,25 × 2/t y en ese escalón aparece `EVENTO hashes_saturados`. La ejecución del 22/11 la refuta. La refutación se apoya en que no hay ninguna línea `hashes_saturados`, no en dónde cae el codo: estar en el borde inferior solo pone la tolerancia del ±25 % al límite. El veredicto definitivo de H1 lo da L1 × 3. En la tabla de la regla de las tasas, la columna "con el codo de L1" queda así: 1,5 × 76,53 = 114,80/s; 76,53/s en el pico; 7,65/s en la base; y 2551 IPs (76,53 × 300 / 9, con 76,53 redondeado a dos decimales). Siguen sin usarse.

**E3. L7 y P6 (desviación de la lista de congelaciones).** La lista de arriba metía L7 y P6 en la segunda congelación. Se sacan, y esta es la desviación que lo declara. Hay dos motivos. Para L7 no hay todavía un plan revisado. La tasa de P6 depende de la línea base de P5, que aún no se ha medido en producción. Las dos tendrán su propio commit de congelación, con push antes de medirlas. Por eso los commits de congelación serán más de los "dos" que dice el principio de esta sección 3.

**E4. Rangos de IPs de las víctimas de L3b (D4 y J5).** Cada rango se calcula así: peticiones de la víctima en los 570 s con tráfico, divididas entre su límite y multiplicadas por 1,5 de margen, redondeando hacia arriba.
- Denuncia (10 por hora): 5/s × 570 s = 2850 peticiones; 2850 / 10 = 285; × 1,5 = 428.
- Seguimiento y `/seguimiento` (60 por minuto): 5/s son 300 por minuto; 300 / 60 = 5; × 1,5 = 8.

Dentro de cada rango, las IPs se reparten de forma circular por iteración, nunca al azar, para que ninguna pase de su límite. Los rangos del ataque, de las víctimas y de los controles no se solapan entre sí, y cambian en cada repetición. Los bloques concretos de 198.18.0.0/15 los fija el código, y la batería comprueba al arrancar que no se solapan; si se solapan, la ejecución para.

**E5. Clase de cada control (J1).** El control de que el ataque existe (B2) es el único que solo rebaja un PASA. Todos los demás son controles de **validez**: si fallan, dan `SIN CONCLUSION` y ganan a FALLA. La excepción es la de J1: la muerte de un servicio de Canario es FALLA y ningún fallo de validez la anula, salvo el OOM global de la VM.
- Por J1, son de validez los controles que el plan termina con "si no, SIN CONCLUSION": el control positivo de L3 y L3b (J2), el de las IPs de control de L3b (D3), el de la propia BASE en L4 (F2, con sus 30 s seguidos y su 95 %) y el humo previo de L4.
- El plan no da clase a la comprobación de J5 (la petición desde una IP ya usada después de recrear la API). Esta aclaración la clasifica como de validez, por decisión propia.
- Como en L1, también es de validez un 429 donde no toca.

**E6. D3 cuando alguna petición no cuenta.** Las 11 peticiones de cada IP de control tienen que caer en la misma ventana de 300 s, sin ser ambiguas. Las 10 primeras tienen que ser 401 aceptados, y entonces la 11.ª tiene que ser 429. Si alguna de las 10 primeras no es un 401 (estado 0, 503 u otro) o si alguna es ambigua, el control da `SIN CONCLUSION`: la 11.ª ya no demuestra nada.

**E7. `Retry-After`.** En L3, todo 429 lleva `Retry-After` entre 1 y 60; en L3b, entre 1 y 300, porque su ventana es de 300 s. Si falta o está fuera de rango, el oráculo por IP y ventana da FALLA.

**E8. Errores del login en B2.** B2 usa la palabra "errores" sin redefinirla, así que vale la definición de error de la primera congelación. Esa definición solo habla de L2; esta aclaración la extiende a L3b, por el mismo motivo (un 503 rápido cuando no hay hueco para un hash es el diseño). En L2 y L3b, los 503 del login inundado no cuentan como errores. Por tanto, B2 se cumple si el p95 del login supera 1500 ms, si un 1 % o más de las peticiones del login acaban en conexión cortada, fin de fichero inesperado, plazo agotado o un 5xx que no sea 503, o si hay descartes con el aviso en su escenario. Los 503 del login se informan aparte.

**E9. Recuperación de L4 (F2 y F3).**
- Cada petición cuenta en todas las ventanas [s, s + 10) que contienen el instante en que empezó.
- "30 s seguidos" quiere decir 30 ventanas consecutivas, con inicios de s₀ a s₀ + 29, todas dentro del criterio. El tiempo de recuperación es s₀ menos el fin programado del pico.
- Se calcula el tiempo de recuperación de cada repetición, y F3 se evalúa sobre la mediana de los tres. Si una repetición no se recupera en los 180 s, su tiempo cuenta como infinito. Se publican los tres tiempos.

**E10. El humo de L4.** Se lanza 120 s después del fin programado del pico. Si el humo previo falla, la prueba da `SIN CONCLUSION` por validez (E5).

**E11. Otros detalles.**
- En L2 y L3b, los 20 s que no se cuentan son los primeros de la RECUPERACIÓN (B4), justo después del fin programado de la inundación o del ataque.
- El control del 403 compara el estado y el cuerpo JSON literales de `handle_errors` en `proxy/Caddyfile.produccion`.
- El control de `trusted_proxies_strict` se hace desde 10.88.1.2, contra seguimiento inexistente.
- La IP 198.19.255.254 queda fuera de todos los rangos de L3 y L3b.
- La batería comprueba además que una petición con el Host de producción no da 421; si lo da, la ejecución para.
- La tasa literal del login es 102,04/s en el pico de L4 y en L3b; 10,20/s en la base de L4 es su décima parte, redondeada.
- Donde dice "ceil", léase "redondeo hacia arriba".
- IPv4: la comprobación del 22/11 (`Resolve-DnsName -Type AAAA`) es para `canario-api.eduumr.dev`, el único nombre que reciben los denunciantes en producción.

**E12. Qué espera el diseño en el resto de pruebas** (de la v1 del plan). L2, FALLA (H3). L3, PASA por IP: la carga agregada pasa igualmente, a ráfagas al principio de cada minuto. L4, PASA (H6).

**E13. Escala OWASP.** Si se conoce el impacto de negocio, se usa ese; si no, el técnico. No se promedian todos los factores de impacto juntos.

**E14 y E15 no son aclaraciones, son desviaciones.** Las dos cambian un oráculo de la segunda congelación: E14 le añade una condición al de F2, y E15 cambia cómo cuenta L3b en el RESULTADO GLOBAL. Por eso no les vale la frase de la introducción de este anexo ("Ninguna de estas aclaraciones cambia una tasa ni el sentido de un oráculo"). Salieron de la revisión de la implementación y se congelan en su propio commit, con push, antes de medir.

**E14. Descartes de k6 en L4 (F2).** La dictaminó el QA. El motivo es que, si se miraran solo las peticiones que k6 llegó a enviar, una ventana podría parecer recuperada justo porque las más lentas no se enviaron.
- Las rutas de F2 son cuatro: denuncia, seguimiento, `GET /web/seguimiento` y login. `POST /salud` no cuenta.
- Un descarte es una fila `dropped_iterations` del CSV de k6 en el escenario de una de esas cuatro rutas, en cualquier fase. Su instante es la marca de esa fila. Igual que en E9, cuenta en todas las ventanas [s, s + 10) que contienen ese instante.
- **Comprobación previa en la sonda de k6, antes de medir.** Se lanza un escenario `constant-arrival-rate` a 2/s, con 1 VU, contra un endpoint que tarda 2 s. Las marcas de `dropped_iterations` tienen que quedar separadas unos 0,5 s y la primera tiene que caer a menos de 0,5 s del inicio del escenario. Si no es así, la ejecución para y se revisa E14.
- Una ventana en la que una ruta tiene algún descarte no cumple el criterio para esa ruta, lleve o no el descarte el aviso `Insufficient VUs`. Los descartes sin el aviso son además un fallo de validez (J1).
- En la RECUPERACIÓN, esa ventana cuenta como no recuperada (es un resultado).
- En la BASE de L4, un solo descarte en cualquiera de las cuatro rutas, con su instante entre el inicio y el fin programados de la BASE, da `SIN CONCLUSION` por validez, como en L2, sea cual sea el 95 % de F2.
- En el PICO no se evalúa ningún oráculo: sus descartes solo se informan, ruta por ruta.

**E15. L3b da dos veredictos, y una FALLA de L3b-b impide el OK.** La segunda congelación no decía cómo se combinan los dos oráculos de D6, que esperan resultados opuestos. Esta aclaración lo fija:
- **Dos veredictos separados**, cada uno con su línea en la salida:
  - **L3b-a**, el oráculo por IP y ventana, con su validez propia: J2, D3, J5 y el control de strict.
  - **L3b-b**, las víctimas, con su validez propia: la BASE y el control B2, que solo actúa sobre L3b-b.
  - La validez común (generador, detector, muertes y 00:00 UTC) se aplica a los dos. Ninguna línea junta los dos en un único veredicto de L3b.
- **Una FALLA de L3b-b da NO OK aunque el diseño la espere,** por la regla común de la sección 2 (Reglas comunes): "Un `SIN CONCLUSION`, una prueba saltada o un fallo esperado (`xfail`, ...) impiden el OK". El threat model (§8, l.693) acepta que el límite sea por cliente, pero no que el denunciante se quede sin canal. Esa consecuencia es la amenaza ABIERTA de l.760-764 ("Agotar los hilos de la API con logins"). La salida lo dice tal cual: "L3b-b: FALLA (esperada por el diseño; NO OK; misma amenaza que L2, threat-model §8, ABIERTA)".
- Una FALLA de L3b-b da NO OK **también si L2 da PASA**. Una FALLA de L3b-a o cualquier `SIN CONCLUSION` dan NO OK.
- Si L3b-b da PASA con B2 cumplido, la diferencia con L2 se explica en el informe. No sirve para cerrar la amenaza.
- Debajo de L3b-b se da la cifra del coste solo si L3b-b es FALLA y B2 se cumple. Es una cota superior, no el mínimo: 3402 IPs IPv4 durante 300 s a 102,04/s. Para un corte de 30 s, unas 306 IPs (153 aprovechando la frontera de la ventana), calculadas a mano y sin medir.
- En el threat model, L3b no abre una entrada nueva. Entra en l.760-764 como factor de probabilidad de la escala OWASP (B6). En l.693 solo se remite a esa entrada y se dice que la amenaza está medida, no cerrada.
- L3b-b solo podría pasar a ser informativa con una aceptación explícita del riesgo, con responsable y fecha, en una congelación posterior. Nunca después de ver el resultado.

**E16. Criterio de la sonda de E14 (corrige E14; es una desviación).** El criterio que se congeló en E14 ("separadas unos 0,5 s" y "la primera a menos de 0,5 s del inicio") haría parar la sonda siempre, aunque k6 se comporte como se espera. Lo detectó la revisión de la implementación, y lo confirmaron después el QA, el revisor de seguridad y el de Python. Python lo comprobó en el fuente de k6 v2.3.0 (`lib/executor/constant_arrival_rate.go`, líneas 328-347).
- Parámetros de la sonda, también congelados: escenario `constant-arrival-rate` de 12 s, a 2/s, con 1 VU (`preAllocatedVUs` y `maxVUs` a 1), `gracefulStop` de 5 s y un endpoint que tarda 2 s.
- Con `constant-arrival-rate`, cada llegada intenta lanzar su iteración sin esperar. Si el VU está libre, la iteración se lanza y no deja marca. Si está ocupado, la llegada se descarta y deja una marca `dropped_iterations` con la hora del momento del descarte.
- Con 2/s, 1 VU y 2 s por petición: k6 lanza la iteración de 0 s y descarta las de 0,5, 1,0, 1,5 y 2,0 s. Lanza la de 2,5 s, descarta de nuevo y así sucesivamente. Por eso la primera marca cae hacia los 0,5 s y, después de cada llegada lanzada, hay un hueco de 1,0 s entre marcas.
- **El criterio que sustituye al de E14** es este. Sea T0 el fin de `setup()`, y para cada marca, k = redondeo((marca − T0) / 0,5). La sonda pasa si se cumplen las seis condiciones; si falla alguna, la ejecución para y se revisa E14:
  1. hay al menos 5 marcas;
  2. cada marca está a ±0,2 s de T0 + 0,5·k, con k ≥ 0;
  3. no hay dos marcas con el mismo k;
  4. la primera marca tiene k = 0 o k = 1 (cae antes de 0,7 s después de T0). Tiene k = 0 solo si la llegada de 0 s se descartó porque el VU todavía no estaba esperando: k6 manda cada llegada sin esperar a un canal sin buffer (`ramping_arrival_rate.go`, líneas 528-535), así que puede haber esa carrera al arrancar;
  5. entre dos marcas consecutivas, k aumenta en 1 o en 2;
  6. las marcas más las filas `iterations` del CSV suman **24 llegadas (12 s × 2/s), ±1**. `iterations` cuenta las iteraciones que terminan. La última que se lanza, hacia los 10,0 s, termina hacia los 12 s, antes de que se agote el `gracefulStop`.
- La propiedad que necesita E14 es la (2): la marca coincide con el instante programado de la llegada, con un error de ±0,2 s. En ventanas de 10 s que avanzan de 1 en 1 s, ese error no importa.
- Las condiciones (3) y (4) descartan dos fallos: que las marcas se emitan cuando el VU queda libre (se amontonarían en el mismo k) o todas al final. La (6) comprueba que ninguna llegada se queda sin contar. La tolerancia de 0,2 s es menor que 0,25 s, así que el k de cada marca nunca es ambiguo.

**E17. La línea de L3b-b cuando da PASA (completa E15).** La propusieron el revisor de seguridad y el QA. Se imprime **solo** si L3b-b da PASA y B2 se cumple; si da `SIN CONCLUSION`, no se imprime. Es una línea literal, sin ninguna cifra de IPs, para que no se lea como una cota del coste:

"L3b-b: PASA con B2 cumplido: en este montaje (IPv4, 102,04/s, 300 s) las víctimas no se degradaron; no se da cifra de coste (E15); no cierra threat-model §8 l.760-764, que sigue ABIERTA; la diferencia con L2 se explica en el informe".

En el mismo sentido, el literal de FALLA de E15 ("esperada por el diseño") solo se usa cuando la FALLA de L3b-b sale del oráculo de las víctimas (B1). Si muere un servicio de Canario, la línea es "L3b-b: FALLA (murió un servicio de Canario; NO OK)", con sus motivos y sin cifra de coste. ¿Y por qué? Porque el diseño espera que las víctimas se degraden, no que se caiga un servicio.

**E18. L1 construye una sola vez y comprueba que la imagen es la misma en todas las repeticiones (control de validez nuevo; no es una desviación de ningún oráculo).** Lo propusieron los revisores tras un fallo de la ejecución de L1 del 23/11.
- **Síntoma observado.** Con 3 repeticiones, la 1 se completó. Al empezar la 2, `lanzar.py --l1` dio `PARADA: el lector de cgroup no da su linea de inicio`, y el `.err` del lector decía `No such image: sha256:e830c91b8c28e06ee560d56d618113a56de4a0fed87c8e8ca02607f1b339c671`.
- **Causa observada.** Cada repetición hacía `up -d --build --wait`. Con el almacén containerd de Docker Desktop, en la comprobación del 23/11 dos builds seguidas, enteras de la caché, dieron ids de imagen distintos: el manifest y el config salieron iguales y el manifest list, distinto (lo cambia el attestation de provenance). El lector y el control usaban el id de la imagen de la API fijado en la repetición 1. No se afirma por qué mecanismo concreto la imagen vieja dejó de estar disponible: no está demostrado.
- **Qué cambia.**
  - Solo la repetición 1 construye (`up -d --build --wait api caddy`). Las siguientes usan `--no-build`, y siguen siendo independientes: `down -v`, BD y Redis nuevos.
  - En cada repetición, tras leer los ids de los contenedores, se lee la imagen de `api` y de `caddy`. La de la repetición 1 es la referencia. Si en otra repetición alguna difiere, o su id está vacío o no es `sha256:<64 hex>`, hay `PARADA` antes de lanzar ningún lector. Si coinciden, se imprime una línea `PASA` por repetición.
  - El control positivo inicial depende ahora de `rep == 1`, no de que la imagen no estuviera fijada.
  - La `PARADA` del lector que no da su línea de inicio incluye el código de salida de su proceso y la cola del `.err`. Si el proceso ya terminó, no se esperan los 60 s enteros (el plazo no cambia).
- **Qué no cambia.** Es un control de validez nuevo. No cambia ninguna tasa, escalera, SLO ni oráculo, ni la regla de H1. Se comprueba con `git show` del commit que añade esta E18, o con `git diff` entre `ef85f28` y ese commit limitado a `tests/estres/lanzar.py` (`lanzar.py` no cambió entre `ef85f28` y este arreglo).
- **De dónde sale la evidencia de L1 x3.** Del commit de este arreglo, sobre la pila de `70c8bee`. Esa pila lleva otro PostgreSQL que la L1 del 22/11, así que es relevante para H2 y para comparar con E2.
- **La ejecución del 23/11** (salida `canario_estres_salida_lau1808z`) queda abortada, es solo informativa y no se usa como evidencia.

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
