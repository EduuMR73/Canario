# Prueba de estrés L1: capacidad y codo

L1 de [docs/informe-pruebas.md](../../docs/informe-pruebas.md) (secciones 2 y 3). Mide, en una pila local con un cpuset de 2 núcleos, qué tasa sostiene cada ruta cara con el p95 bajo el SLO y qué cede primero cuando deja de sostenerla:

- **Login con email inexistente** (empresa real) y **login con empresa inexistente**: el mismo Argon2 que un login real más las lecturas de la reserva, sin tocar cuentas ni bloqueos. No mide las escrituras de un fallo con cuenta real ni la creación de la sesión de un login correcto.
- **Seguimiento con un código inexistente** de formato válido: el HMAC del código y un SELECT, sin descifrar nada.
- **Presentar denuncia**: cifrado y escritura reales.

Cada escalón lleva dos sondas a 1 petición por segundo: `POST /salud` por el 8443 (espera 405, sin base de datos ni limitador) y `GET /seguimiento` por el 8444 (espera 200, síncrona y barata). Si sube solo la de `/seguimiento`, faltan hilos; si suben las dos, falta CPU; si ninguna sube y el log dice `SIN CONEXION`, el límite es el pool de 5 conexiones.

## Es un modelo relativo

Todos los servicios de Canario comparten las mismas 2 CPU lógicas de núcleos distintos de la VM de Docker (override `cpuset`, con los `mem_limit` de producción). Faltan el TLS de Traefik, las aplicaciones vecinas del VPS y el dockerd del VPS. Los resultados describen el orden en que cede cada pieza y su comportamiento, no la capacidad del VPS.

## Cómo funciona

`lanzar.py` (en el host, solo biblioteca estándar) sigue el patrón de `tests/funcionales/lanzar.py`: comprobaciones previas con `PARADA`, proyecto propio `canario_estres`, overrides en un directorio temporal, `down -v --rmi local`, `git status` igual al del arranque y `RESULTADO GLOBAL`. Además:

- **CPU.** Lee `/sys/devices/system/cpu/cpu*/topology/thread_siblings_list` en un contenedor efímero de la imagen de Redis ya fijada, da a Canario la primera CPU de dos núcleos distintos (sin el de la CPU 0) y a k6 cuatro CPU de otros núcleos con `--cpuset-cpus`. Imprime la elección y comprueba el cpuset con `docker inspect`.
- **Límites.** Las 9 reglas de `LIMITES_POR_DEFECTO` a 1 000 000 por su misma ventana (toda la carga sale de una IP), comprobadas con la línea entera `LIMITES (configurados): ...` del log.
- **`--hash`.** Comprueba como literales sobre el texto de `app/personal.py` los parámetros de Argon2id (19456 KiB, 2 iteraciones, paralelismo 1, `hash_len=32`, `salt_len=16`) y, dentro del contenedor de la API, mide un `hash()` y la mediana, el mínimo y el máximo de 20 `verify()` en serie. Imprime t y 2/t. No toca la base de datos ni los secretos.
- **`--l1 --t <t> [--repeticiones N]`.** Una ejecución de k6 v2.3.0 (por digest) **por escalón**: k6 no puede cortar un escenario según el resultado de los anteriores, y el lanzador corta la escalera de una ruta tras 2 escalones seguidos fuera del SLO. k6 corre endurecido (usuario 12345, raíz de solo lectura, sin capacidades, `no-new-privileges`, tmpfs, 4 GiB) en el espacio de red de Caddy, con `l1.js` montado de solo lectura y los datos del escalón en un fichero montado (nunca por argv). Durante la carga guarda en streaming los logs de la API, Redis y PostgreSQL (`docker compose logs -f -t`) y `docker stats` continuo con la hora del host; al final, `docker inspect` para reinicios y `OOMKilled`.

Orden: login con email inexistente (0,5, 0,75, 1, 1,25 y 1,5 × 2/t), login con empresa inexistente (0,5, 1 y 1,25 × 2/t), seguimiento (25, 50, 100, 200, 300 y 400/s) y denuncia (10, 25, 50, 100, 150 y 200/s). 30 s de calentamiento por ruta a la tasa del control, escalones de max(60 s, 600/tasa) y 30 s de reposo. El primer escalón de cada ruta es el control y debe cumplir el SLO.

### Decisiones

- **TLS.** `insecureSkipTLSVerify` solo hacia `localhost` dentro del espacio de red de Caddy: el tráfico no sale de ahí y se mide capacidad, no autenticidad (eso lo prueban las baterías). k6 no documenta cómo confiar en una CA propia, y un fallo ahí daría una escalera entera de errores TLS. El coste del handshake es el mismo.
- **HTTP/1.1, no HTTP/2.** Caddy declara `protocols h1` (`proxy/servidor.caddy`), así que ALPN solo puede negociar HTTP/1.1. El análisis comprueba que todas las peticiones llevan `proto=HTTP/1.1`; si no, `SIN CONCLUSION`.
- **VUs.** `maxVUs = min(tasa × 15, 600)` y `preAllocatedVUs = maxVUs`. Con todos los VUs preasignados, k6 solo descarta una iteración cuando todos están ocupados, y entonces avisa con `Insufficient VUs` (comprobado en el código de k6 v2.3.0). El tope de 600 parte de un **supuesto sin medir** de unos 5 MiB por VU (3 GiB de los 4 GiB de k6). Antes de cada escalón se comprueba que maxVUs/tasa supera el p95 del SLO de la ruta; si no, ese escalón no se lanza y queda `SIN CONCLUSION`.
- **Tiempo.** Con 1 repetición y sin cortes, la carga dura unos **36,5 minutos** si t está entre 0,03 y 0,1 s (20 ejecuciones de k6 con 15 s de sobrecoste cada una, un supuesto), más el arranque de la pila. Con t = 0,2 s sube a 38,8 minutos. Si la estimación supera los 45 minutos, el lanzador se detiene con `PARADA` antes de medir. Cada corte de escalera ahorra tiempo.

### Muertes, puerta de memoria, controles y repeticiones

El 21/11 la API murió 33 veces con código 137 sin que el lanzador lo notara. Ahora `--l1` vigila desde fuera y decide la puerta de R1 (0 reinicios y memoria de 160 MiB como mucho en el login):

- **Detector de muertes.** `docker events --filter type=container` en streaming (instante del motor tomado antes, `--since`), clasificado en Python por etiquetas: `canario.estres=k6|lector|control` y la etiqueta de compose para los 4 servicios. Un `die` de Canario que el lanzador no provocó es **FALLA** de la puerta por reinicio, en toda la ejecución y no solo en los escalones. Los `die` esperados son los del id que el lanzador para a propósito (el id viejo de la API en la recreación y todos en `down -v`), hasta su `destroy`; un `die` de PostgreSQL en esa misma ventana no es esperado. El evento `oom` de Docker es información, no oráculo.
- **Causa de la muerte.** Con los contadores `oom` y `oom_kill` del cgroup **padre** común (el lector los lee a 4 Hz; el cgroup del hijo puede borrarse antes de la siguiente muestra): si sube `oom` sin que muera otro contenedor, "OOM por su propio límite"; si sube `oom_kill` sin `oom`, "OOM global de la VM" y entonces la puerta es **SIN CONCLUSION**; si no sube nada, "no atribuible" (FALLA). Si en la ventana sube también el `oom` de k6, se anota "atribución dudosa". Las latencias y el codo de un escalón con muerte quedan NO EVALUABLE, y H1 también si fue en el login. Al arrancar se lista lo que cuelga del padre: un contenedor ajeno es `PARADA` con su nombre.
- **Vida del detector.** El `start` y el `die` de k6 de cada escalón deben llegar al stream, y todos los streamers (eventos, lector, `docker stats`, logs) se comprueban con `poll()` e `is_alive()` antes y después de cada escalón; si no, el escalón es SIN CONCLUSION. Los streamers van en su propio grupo de procesos y se paran con CTRL_BREAK, plazo y `taskkill /T /F`.
- **Lector de cgroup.** Un contenedor efímero de la imagen de la API (`--cgroupns host`, sin `-v`, endurecido) imprime cada 0,25 s `anon`, `swapcached`, `file`, `kernel`, `swap.current`, `pids`, `oom`, `oom_kill` e inode de los 4 servicios. Exige exactamente una ruta por id y los literales `memory.max = memory.swap.max = 268435456` de la API. Una ruta ausente en la carga es un hueco registrado; un hueco de más de 3 s fuera de una muerte registrada es SIN CONCLUSION. Un inode nuevo o un contador que baja abre una encarnación nueva.
- **Puerta de memoria.** Oráculo: el máximo muestreado a 4 Hz de `anon + swap.current - swapcached` (la fórmula de `diag_memoria_contenedor.py`) es de 167772160 bytes (160 MiB) como mucho en cada escalón de login **cubierto** y en su calentamiento. Comprobación de coherencia: solo si hay indicio de picos no muestreados (el mínimo retenido del reposo siguiente, en la misma encarnación, queda más de 19456 KiB por debajo del máximo) o no hay reposo válido, el máximo más 2 x 19456 KiB también debe caber, y si no, SIN CONCLUSION. El reposo de un escalón es el tramo hasta el siguiente escalón lanzado de la ruta o, en el último, el reposo final de la ruta con el lector vivo; solo vale con muestras de la misma encarnación hasta al menos `REPOSO_S` - 0,5 s después del fin del escalón, sin huecos de más de `HUECO_MAXIMO_S` (contando el del principio y el del final) y con el lector vivo; si no, se aplica el margen y la nota dice por qué ("sin reposo valido: ..."). El calentamiento no tiene reposo: lleva el margen siempre. Si lo retenido se mantiene, se anota "retenido estable: sin margen". El margen supone que lo único que vive menos de 250 ms son las reservas de Argon2; no se presenta como garantía. `memory.peak` y `memory.swap.peak` son información (la salida dice "sin cota medida" si el kernel no tiene el segundo), y el veredicto dice siempre "PASA por muestreo a 4 Hz". Los literales `HASHES_SIMULTANEOS = 2` y `MEMORIA_ARGON2_KIB = 19456` se comprueban al arrancar sobre `app/personal.py`.
- **Cobertura.** Un escalón de login está cubierto si las iteraciones lanzadas son al menos el 95 % de las planificadas, o si sus descartes llevan el aviso `Insufficient VUs`; en los dos casos sin descartes sin el aviso y con la CPU de k6 bajo el umbral. Si 1,5 x 2/t de `login_email` no está cubierto, la puerta es SIN CONCLUSION. La salida dice lo que demuestra: hasta 600 peticiones de login en vuelo ofrecidas a 1,5 x 2/t, no que se sostenga esa tasa. En las dos rutas de login, si el corte por el SLO o el control cortarían la escalera, los escalones que quedan se lanzan igual, marcados "solo memoria": cuentan para la puerta, no para el codo ni para H1.
- **Control positivo en sándwich.** Al principio (tras levantar la pila, antes de medir) y al final, el contenedor `canario_estres_control` (imagen de la API, `--restart on-failure:1`, `--memory 64m --memory-swap 128m`, endurecido, sin red) reserva memoria en trozos de 4 MiB con pausas de 0,1 s hasta que el OOM lo mata, dos veces. Debe verse: el lector arrancado antes con al menos 5 muestras crecientes y `swap.current` mayor que 0, los literales de su cgroup (67108864 y 67108864), dos `die` con código 137 y dos `start`, la segunda encarnación con inode nuevo y contadores a 0, y el OOM, con la misma fuente que la puerta: el contador `oom` del `memory.events` del cgroup **padre** (jerárquico, sobrevive a que el hijo se borre) debe subir al menos 2 veces durante el control. El `oom_kill` del hijo y los eventos `oom` de Docker son solo información. El centinela (su `start` en el stream) debe llegar en 10 s, o `PARADA`. Si el control inicial falla, `PARADA`; si falla el final, toda la ejecución es SIN CONCLUSION.
- **Relojes.** Eventos, k6 y lector usan el reloj de la VM. La hora del motor (`docker info --format {{.SystemTime}}`) se acepta con `Z` o con desfase explícito; si falla, `PARADA`, nunca un 0. Para la CPU de `docker stats` (hora del host) el desfase se mide al inicio y al final de cada escalón; si no se puede medir o difiere en más de 1 s, la CPU de ese escalón es SIN CONCLUSION.
- **Conciliación.** Los `start` no esperados (los que no son el primero de su id) deben coincidir con `RestartCount`, y los eventos `oom` no pueden ser menos que los incrementos de `oom` vistos en los cgroups.
- **PostgreSQL.** El override de estrés añade `-c log_checkpoints=on -c log_autovacuum_min_duration=0` al `command` (sin `docker exec`). Antes de arrancar se compara con `docker compose config --format json`: si difiere en algo más que esos dos `-c`, `PARADA`; después se comprueban en `docker inspect` (Args). Cambia el logging del sistema medido; los checkpoints y autovacuum de cada ventana entran en la tabla.
- **Repeticiones independientes** (`--repeticiones N`, 3 por defecto). Cada una hace `down -v`, `up -d --wait` (con `--build` solo en la repetición 1 y `--no-build` en las siguientes, que siguen siendo independientes: `down -v`, BD y Redis nuevos), alta de una empresa nueva y las 4 rutas. Desde la repetición 2, la imagen de `api` y la de `caddy` tienen que ser las de la repetición 1 (`PASA` por repetición, `PARADA` si no, antes de lanzar ningún lector): con el almacén containerd de Docker Desktop cada build cambia el id de la imagen, y el 23/11 el lector no la encontró al empezar la repetición 2. Si el lector no da su línea de inicio, la `PARADA` incluye el código de salida de su proceso y la cola de su `.err`. Entre rutas, `up -d --force-recreate --no-deps --wait api`, comprobando que los ids de PostgreSQL, Redis y Caddy no cambian, `RestartCount` 0, la línea de límites y la memoria base. Lector, `docker stats` y el log de la API se relanzan con los ids nuevos y cubren la ruta entera. La puerta toma el **peor caso** entre repeticiones, nunca la mediana. La latencia sale en una tabla por repetición, con mediana, mínimo y máximo del p95 por escalón, el codo de cada repetición sin promediar y si la repetición 1 sale sistemáticamente distinta.
- **Tiempo.** Con 3 repeticiones, unas 2 horas (unos 37 minutos de carga por repetición con t entre 0,03 y 0,1 s, más unos 4 minutos de arranque y recreaciones por repetición y los dos controles). El lanzador imprime la estimación; `TIEMPO_MAXIMO_S` (45 min) sigue siendo el tope **por repetición**.
- **Ctrl+C.** Da `PARADA` visible, limpia y escribe lo medido hasta ese momento; un segundo Ctrl+C durante la limpieza se avisa en la salida. Los contenedores efímeros llevan el prefijo `canario_estres_` y la limpieza final los busca por él.
- **Protocolo.** Las filas con estado 0 se excluyen del control de protocolo (siguen contando como error); si no hay ninguna respuesta con protocolo, SIN CONCLUSION.

Pruebas del análisis (sin Docker): `python -m unittest tests/estres/test_lanzar.py`. Los oráculos son literales y cada negativo lleva su control positivo.

### Análisis y controles

Por escalón y ruta: p50, p95 y p99; recuento; errores según la sección 3 (5xx o estado 0, que es conexión cortada, fin de fichero inesperado o plazo), agrupados por el `error_code` literal de k6 (1050 = plazo agotado) y por el texto de error; VUs en uso estimados por la ley de Little (con los VUs preasignados, la métrica `vus` siempre vale maxVUs); CPU media y máxima de cada contenedor, Redis incluido; BlockIO de PostgreSQL; y las señales del log de la API en la ventana del escalón, con su primera aparición: `SIN CONEXION: PoolTimeout`, `SATURACION:`, `EVENTO hashes_saturados`, `EVENTO limitador_no_disponible: <clase>`, `ERROR INTERNO: <clase>` y `EVENTO login_fallido` (solo se cuenta). El codo de cada ruta es el primer escalón con p95 por encima del SLO, un 1 % o más de errores o maxVUs alcanzados.

Cada uno de estos casos da `SIN CONCLUSION`:

- Entre las respuestas que no son error, menos del 99 % con el estado esperado (login 401, denuncia 201, seguimiento 404; sondas 405 y 200), o alguna 429.
- El escalón de control no cumple el SLO. Entonces la ruta no sigue.
- El generador se satura: CPU de k6 por encima del 80 % de su cpuset, o descartes sin el aviso de VUs insuficientes.
- k6 termina con un código distinto de 0 o queda `OOMKilled`.
- Alguna petición usa un protocolo distinto de HTTP/1.1.

H1 y H2 se evalúan al final a título informativo: una hipótesis refutada es un hallazgo, no un fallo de la prueba.

## Cómo ejecutar (PowerShell, desde la raíz del repo)

Requisitos: Docker en marcha, los secretos generados (`scripts/generar_secretos.py`) e internet (construcción de la SPA, imagen de k6). **La pila local, parada**, sin borrar sus datos:

```powershell
docker compose -p canario down
```

**1. govulncheck v1.9.0 sobre el binario de k6 de la imagen fijada.** Imagen de Go `golang:1.27.3-alpine`, fijada por el digest que da Docker Hub para la etiqueta, publicada el 6/11/2026 (cumple la regla de 14 días; la 1.27.4, del 16/11, todavía no la cumple). govulncheck v1.9.0 se publicó el 11/10/2026. `go run` descarga el módulo comprobando su hash con sum.golang.org y consulta la base de datos de vuln.go.dev:

```powershell
$bin = Join-Path $env:TEMP "canario_k6_binario"
New-Item -ItemType Directory -Force $bin | Out-Null
docker create --name canario_k6_binario grafana/k6:2.3.0@sha256:2dd4756ec6e14e62778916e1eb850108e4b499304c02df56760fa0bdb0fba0b8
docker cp canario_k6_binario:/usr/bin/k6 "$bin\k6"
docker rm canario_k6_binario
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges --user 65534:65534 --tmpfs /tmp:size=2g,exec -e HOME=/tmp -e GOPATH=/tmp/go -e GOCACHE=/tmp/cache -e GOTOOLCHAIN=local --mount "type=bind,src=$bin,dst=/binario,readonly" golang:1.27.3-alpine@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 -mode=binary /binario/k6
Remove-Item -Recurse -Force $bin
```

k6 v2.3.0 se compila con Go 1.27.1 (su Dockerfile), así que es esperable que aparezcan vulnerabilidades de la biblioteca estándar corregidas en versiones posteriores. Anota el resultado. Si alguna tiene un camino alcanzable desde lo que hace L1 (un cliente HTTP contra `localhost`), decide antes de seguir.

**2. Medir t:**

```powershell
python tests\estres\lanzar.py --hash
```

**3. Primera congelación:** escribe t en la sección 3 de `docs/informe-pruebas.md` y haz commit y push antes de medir. La fecha del push la pone GitHub.

**4. L1 con la t congelada:**

```powershell
python tests\estres\lanzar.py --l1 --t <t>
```

`--conservar` deja la pila y los temporales para desarrollar. La evidencia sale de una ejecución sin él.

## Qué queda en %TEMP%

- `verificacion_estres.txt`: la salida entera, con la tabla y el `RESULTADO GLOBAL`.
- `canario_estres_salida_*` (su ruta sale al final):
  - Con `--hash`: `hash.json`.
  - Con `--l1`: `resultados.json`, `resultados.csv`, `log_api.txt`, `log_redis.txt` y `log_postgres.txt`, y una carpeta por escalón (`<ruta>__e<n>`) con `k6.csv`, `resumen.json`, `panel.html` (el panel exportado de k6), `stats.txt` (docker stats con la hora del host) y `k6_salida.txt`.

Los CSV de los escalones rápidos pesan decenas de MB. Los logs llevan el identificador de la empresa de prueba y nada más sensible: la pila se borra al terminar.

# Banco D1: diagnóstico de la memoria de la API bajo login

En L1, la API recién arrancada muere a los 14 s de login a 51/s (33 salidas con código 137, sin `oom_kill` registrado). D1 comprueba, sin HTTP ni base de datos, si la causa es la que predice el plan (causa 1): cada hilo de AnyIO que calcula un Argon2 de 19 MiB deja su arena de glibc con unos 19 MiB que no se devuelven, porque el import ya subió el umbral dinámico de mmap a unos 19 MiB (glibc 2.41, `malloc.c:3457-3462`) y el top de un heap de hilo no se recorta (`malloc.c:5255`). Las predicciones están escritas como constantes literales al principio de `diagnosticar_memoria.py`, antes de medir.

## Piezas

- **`diagnosticar_memoria.py`** (host, solo biblioteca estándar): comprobaciones previas con `PARADA`, la imagen `canario_diag_api` (`docker build` del Dockerfile de la raíz), las 22 ejecuciones, el análisis (funciones puras, separadas de la recogida), la tabla por variante, un veredicto por oráculo con su motivo, la limpieza, `git status` igual al del arranque y `RESULTADO GLOBAL`.
- **`diag_memoria_contenedor.py`** (dentro del contenedor, montado de solo lectura, con `python -I -B -u`): no tiene oráculos, solo mide y emite líneas JSON. Su PID 1 (supervisor) lanza la carga como hijo y muestrea cada 0,5 s `memory.current`, `memory.peak`, las claves fijas de `memory.stat`, `memory.swap.current`, `memory.events`, `memory.pressure` y `VmRSS`, `RssAnon` y `VmSwap` del hijo. El hijo importa el módulo real `app.personal` y llama, desde `anyio.to_thread.run_sync` con el limitador por defecto, a `with _hueco_hash(): _verificar_hash(None, normalizar_contrasena(...))`, como la ruta del login. Cada 0,5 s y al final de cada fase toma `mallinfo2` y `malloc_info` (por `ctypes`, en un `open_memstream`, nunca en disco).

## Contenedor

El mismo endurecimiento que el servicio `api` del compose: `--read-only`, `--cap-drop ALL`, `no-new-privileges`, `--pids-limit 64`, `--memory 256m` sin `--memory-swap` (dentro se comprueba `memory.swap.max = 268435456`), el usuario de la imagen (10001) y el cpuset de 2 CPU que `lanzar.py` da a Canario. Además, `--network none`. Sin `--rm` ni política de reinicio: un OOM mata al hijo (con `memory.oom.group = 0` el contenedor sigue vivo) y el supervisor registra su código (-9) y `memory.events`. Desde fuera, `docker events --filter event=oom`. `OOMKilled` de `docker inspect` no se usa, porque con `oom.group = 0` no se activa.

Diferencias con L1, declaradas: sin HTTP, uvicorn ni Caddy, sin base de datos, Redis ni secretos, sin healthcheck y sin red.

## Protocolo

Fases de cada ejecución: F1, 60 s a 51/s (la reproducción de L1); R1, 15 s de reposo; F2, 10 s de ráfaga a 150/s; R2, 15 s de reposo; y `malloc_trim(0)` al final (informativo). La llegada es abierta, por reloj absoluto, con un tope de 3000 tareas pendientes; cada fase se drena antes del reposo, y las muestras de los oráculos son solo las de fin de fase, con 0 hashes en curso.

| Variante | Qué cambia | Para qué |
|---|---|---|
| P | Reserva `memory.max + swap.max + 88 MiB` en trozos de 16 MiB | Control positivo: debe dar `oom_kill`, el evento oom y -9 con las muestras subiendo. Si no, todo es `SIN CONCLUSION` |
| D | El limitador por defecto con 1 hilo | Línea base: retenido de 60 MiB o menos y `uordblks` sin pendiente. Si no, `SIN CONCLUSION`. También mide la causa 3 (fuga) |
| A | Nada | F1: retenido de 9 × 19 MiB o más (la meseta de L1) o un `oom_kill` |
| A2 | `--memory 1g --memory-swap 1g` | La predicción de la causa 1 sin OOM, y la referencia de tiempos |
| A-t | A2 con `tracemalloc` (una sola vez) | Causa 2 (objetos de Python), informativa |
| E | Argon2 con m = 64 KiB y t ajustada a unos 18 ms | Si A se dispara y E también, la causa 1 no es la única |
| B | `MALLOC_ARENA_MAX=2` | Arreglo candidato |
| C2 | `MALLOC_MMAP_THRESHOLD_=4194304` | Arreglo candidato |

Retenido = `anon + swap.current - swapcached - base`, con la base tomada tras el import y antes de la carga. Tres rondas con el orden rotado; un veredicto por variante solo si las tres coinciden. Plazo de 360 s por ejecución (el plan decía 240; D, con 1 hilo, se estima en unos 218 s) y tope global de 90 min (estimación: unos 60 min).

## Cómo ejecutar (PowerShell, desde la raíz del repo)

Requisitos: Docker en marcha. No necesita los secretos: no levanta PostgreSQL ni Redis, y solo crea recursos con el prefijo `canario_diag`. **La pila local, parada** (sin borrar sus datos), para que no compita por las 2 CPU del cpuset y no altere los tiempos de `verify()`:

```powershell
docker compose -p canario down
python tests\estres\diagnosticar_memoria.py
```

Si encuentra restos de una ejecución anterior con el prefijo `canario_diag`, se detiene con `PARADA` sin tocarlos. Para borrarlos a mano:

```powershell
docker ps -a --filter "name=canario_diag" --format "{{.Names}}" | ForEach-Object { docker rm -f $_ }
docker image rm canario_diag_api
```

## Qué queda en %TEMP%

- `verificacion_diag_memoria.txt`: la salida entera, con las tablas, los veredictos y el `RESULTADO GLOBAL`.
- `canario_diag_salida_*` (su ruta sale al final): el JSON crudo de cada ejecución (`<contenedor>.jsonl`), su stderr y `resultados.json`.

## Modo `--regresion`: el arreglo R1

El arreglo R1 (`app/personal.py`, "Argon2 en un ejecutor propio") calcula todos los Argon2 de la API en los 2 hilos de un ejecutor, `argon2_0` y `argon2_1`, en vez de en los hilos de AnyIO. `--regresion` mide su memoria con la misma infraestructura de D1 (imagen, contenedor endurecido, supervisor, fases y análisis) sobre la imagen ya arreglada. El modo normal es el diagnóstico de la API de antes (commit `c1eaa13`): sobre la arreglada, `_hueco_hash` ya no existe y su `PARADA` previa lo detiene.

| Variante | Qué es | Oráculo (literal, fijado antes de ejecutar) |
|---|---|---|
| P | El control positivo de D1, sin cambios | `oom_kill`, el evento oom y -9 con las muestras subiendo; si no, todo es `SIN CONCLUSION` |
| D | La línea base de D1 (1 hilo, 256 MiB) con el camino viejo reconstruido: el semáforo real y `personal._hasher.verify` en el hilo de AnyIO | El de D1: retenido de 60 MiB o menos y `uordblks` sin pendiente; si no, `SIN CONCLUSION` |
| V | El camino viejo con 40 hilos y `--memory 1g --memory-swap 1g`, como A2 | Control: `a >= 30` en `fin_F2`; si no, todo es `SIN CONCLUSION`. Es además la referencia de tiempos de la sesión |
| R | El arreglo con 256 MiB, como producción: el ejecutor creado con la misma `iniciar_ejecutor_hashes()` de la API y la función real del login, `_verificar_en_ejecutor` | Precondición: 40 hilos vivos o más en F2, el ejecutor con `argon2_0` y `argon2_1` y `verify()` solo en ellos (si no, `SIN CONCLUSION`). Memoria: sin `oom_kill`, `a <= 2`, cada arena de hilo crece 1,3 × 19 MiB como mucho y retenido de 60 MiB o menos en cada fin de fase y en el máximo de cada fase. Tiempos de `verify()` dentro del hilo argon2: p50 y p95 de 1,25 × los de V de la misma ronda como mucho y de 1,25 × los de A2 en D1 (18,5 y 23,7 ms); si las dos referencias discrepan, `SIN CONCLUSION` |

Decisiones:

- **V es el control del camino viejo.** Llama directamente a `personal._hasher.verify` desde el hilo de AnyIO, como hacía la API antes: si en esta misma sesión e imagen no reproduce las arenas de D1, la mejora de R no tendría con qué compararse.
- **Los tiempos de R se miden dentro del hilo argon2**, el mismo intervalo que en D1: el banco envuelve `_verificar_hash` con un cronómetro y `_verificar_en_ejecutor` devuelve lo que devuelve el ejecutor. La espera total del llamante sale aparte, informativa.
- **"Cada arena del ejecutor" se aplica a todas las arenas de hilo**, porque `malloc_info` no dice de qué hilo es cada una. Es más estricto, no más blando.
- **R es la prueba del arreglo, no un hallazgo:** un `NO PASA` es `FALLA` y cambia el `RESULTADO GLOBAL`. En memoria basta un `NO PASA` en una ronda, aunque otra no concluya; los tiempos, como en D1, exigen las 3 rondas iguales.
- **12 ejecuciones** (4 variantes × 3 rondas, con el orden rotado), unos 35 minutos.

Se ejecuta igual que D1, con la pila local parada:

```powershell
docker compose -p canario down
python tests\estres\diagnosticar_memoria.py --regresion
```

Deja en %TEMP% `verificacion_diag_memoria_regresion.txt` (sin pisar la salida de D1) y la carpeta `canario_diag_salida_*` con el JSON crudo y `resultados.json`. Hasta que L1 cumpla su predicción, un `PASA` se resume como "mitigación de la causa 1 demostrada en el banco, pendiente de L1", nunca como "arreglado".
