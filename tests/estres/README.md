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

- **Detector de muertes.** `docker events --filter type=container` en streaming (instante del motor tomado antes, `--since`), clasificado en Python por etiquetas: un contenedor con la clave `canario.estres` es propio y nunca se clasifica por compose (`k6|lector|control|sonda`; un valor desconocido da la clase `instrumento_desconocido`, y cualquier evento suyo deja la repetición en SIN CONCLUSION con su nombre), porque los que salen de la imagen de la API heredan sus etiquetas de compose; sin esa clave, la etiqueta de compose para los 4 servicios. La línea de cada muerte lleva el nombre y la clase del contenedor, y los eventos parseados de cada repetición quedan en `rep<N>/eventos_docker.json`. Un `die` de Canario que el lanzador no provocó es **FALLA** de la puerta por reinicio, en toda la ejecución y no solo en los escalones. Los `die` esperados son los del id que el lanzador para a propósito (el id viejo de la API en la recreación y todos en `down -v`), hasta su `destroy`; un `die` de PostgreSQL en esa misma ventana no es esperado. El evento `oom` de Docker es información, no oráculo.
- **Causa de la muerte.** Con los contadores `oom` y `oom_kill` del cgroup **padre** común (el lector los lee a 4 Hz; el cgroup del hijo puede borrarse antes de la siguiente muestra): si sube `oom` sin que muera otro contenedor, "OOM por su propio límite"; si sube `oom_kill` sin `oom`, "OOM global de la VM" y entonces la puerta es **SIN CONCLUSION**; si no sube nada, "no atribuible" (FALLA). Si en la ventana sube también el `oom` de k6, se anota "atribución dudosa". Las latencias y el codo de un escalón con muerte quedan NO EVALUABLE, y H1 también si fue en el login. Al arrancar se lista lo que cuelga del padre: un contenedor ajeno es `PARADA` con su nombre.
- **Vida del detector.** El `start` y el `die` de k6 de cada escalón deben llegar al stream, y todos los streamers (eventos, lector, `docker stats`, logs) se comprueban con `poll()` e `is_alive()` antes y después de cada escalón; si no, el escalón es SIN CONCLUSION. Los streamers van en su propio grupo de procesos y se paran con CTRL_BREAK, plazo y `taskkill /T /F`.
- **Lector de cgroup.** Un contenedor efímero de la imagen de la API (`--cgroupns host`, sin `-v`, endurecido) imprime cada 0,25 s `anon`, `swapcached`, `file`, `kernel`, `swap.current`, `pids`, `oom`, `oom_kill` e inode de los 4 servicios. Exige exactamente una ruta por id y los literales `memory.max = memory.swap.max = 268435456` de la API. Una ruta ausente en la carga es un hueco registrado; un hueco de más de 3 s fuera de una muerte registrada es SIN CONCLUSION. Un inode nuevo o un contador que baja abre una encarnación nueva.
- **Puerta de memoria.** Oráculo: el máximo muestreado a 4 Hz de `anon + swap.current - swapcached` (la fórmula de `diag_memoria_contenedor.py`) es de 167772160 bytes (160 MiB) como mucho en cada escalón de login **cubierto** y en su calentamiento. Comprobación de coherencia: solo si hay indicio de picos no muestreados (el mínimo retenido del reposo siguiente, en la misma encarnación, queda más de 19456 KiB por debajo del máximo) o no hay reposo válido, el máximo más 2 x 19456 KiB también debe caber, y si no, SIN CONCLUSION. El reposo de un escalón es el tramo hasta el siguiente escalón lanzado de la ruta o, en el último, el reposo final de la ruta con el lector vivo; solo vale con muestras de la misma encarnación hasta al menos `REPOSO_S` - 0,5 s después del fin del escalón, sin huecos de más de `HUECO_MAXIMO_S` (contando el del principio y el del final) y con el lector vivo; si no, se aplica el margen y la nota dice por qué ("sin reposo valido: ..."). El calentamiento no tiene reposo: lleva el margen siempre. Si lo retenido se mantiene, se anota "retenido estable: sin margen". El margen supone que lo único que vive menos de 250 ms son las reservas de Argon2; no se presenta como garantía. `memory.peak` y `memory.swap.peak` son información (la salida dice "sin cota medida" si el kernel no tiene el segundo), y el veredicto dice siempre "PASA por muestreo a 4 Hz". Los literales `HASHES_SIMULTANEOS = 2` y `MEMORIA_ARGON2_KIB = 19456` se comprueban al arrancar sobre `app/personal.py`.
- **Cobertura.** Un escalón de login está cubierto si las iteraciones lanzadas son al menos el 95 % de las planificadas, o si sus descartes llevan el aviso `Insufficient VUs`; en los dos casos sin descartes sin el aviso y con la CPU de k6 bajo el umbral. Si 1,5 x 2/t de `login_email` no está cubierto, la puerta es SIN CONCLUSION. La salida dice lo que demuestra: hasta 600 peticiones de login en vuelo ofrecidas a 1,5 x 2/t, no que se sostenga esa tasa. En las dos rutas de login, si el corte por el SLO o el control cortarían la escalera, los escalones que quedan se lanzan igual, marcados "solo memoria": cuentan para la puerta, no para el codo ni para H1.
- **Control positivo en sándwich.** Al principio (tras levantar la pila, antes de medir) y al final, el contenedor `canario_estres_control` (imagen de la API, `--restart on-failure:1`, `--memory 64m --memory-swap 128m`, endurecido, sin red) reserva memoria en trozos de 4 MiB con pausas de 0,1 s hasta que el OOM lo mata, dos veces. Debe verse: el lector arrancado antes con al menos 5 muestras crecientes y `swap.current` mayor que 0, los literales de su cgroup (67108864 y 67108864), dos `die` con código 137 y dos `start`, la segunda encarnación con inode nuevo y contadores a 0, y el OOM, con la misma fuente que la puerta: el contador `oom` del `memory.events` del cgroup **padre** (jerárquico, sobrevive a que el hijo se borre) debe subir al menos 2 veces durante el control. El `oom_kill` del hijo y los eventos `oom` de Docker son solo información. El centinela (su `start` en el stream) debe llegar en 10 s, o `PARADA`. Si el control inicial falla, `PARADA`; si falla el final, toda la ejecución es SIN CONCLUSION.
- **Relojes.** Eventos, k6 y lector usan el reloj de la VM. La hora del motor (`docker info --format {{.SystemTime}}`) se acepta con `Z` o con desfase explícito; si falla, `PARADA`, nunca un 0. Para la CPU de `docker stats` (hora del host) el desfase se mide al inicio y al final de cada escalón; si no se puede medir o difiere en más de 1 s, la CPU de ese escalón es SIN CONCLUSION.
- **Conciliación.** Los `start` no esperados (los que no son el primero de su id) deben coincidir con `RestartCount`, y los eventos `oom` no pueden ser menos que los incrementos de `oom` vistos en los cgroups.
- **PostgreSQL.** El override de estrés añade `-c log_checkpoints=on -c log_autovacuum_min_duration=0` al `command` (sin `docker exec`). Antes de arrancar se compara con `docker compose config --format json`: si difiere en algo más que esos dos `-c`, `PARADA`; después se comprueban en `docker inspect` (Args). Cambia el logging del sistema medido; los checkpoints y autovacuum de cada ventana entran en la tabla.
- **Repeticiones independientes** (`--repeticiones N`, 3 por defecto). Cada una hace `down -v`, `up -d --wait` (con `--build` solo en la repetición 1 y `--no-build` en las siguientes, que siguen siendo independientes: `down -v`, BD y Redis nuevos), alta de una empresa nueva y las 4 rutas. Desde la repetición 2, la imagen de `api` y la de `caddy` tienen que ser las de la repetición 1 (`PASA` por repetición, `PARADA` si no, antes de lanzar ningún lector): con el almacén containerd de Docker Desktop cada build cambia el id de la imagen, y el 23/11 el lector no la encontró al empezar la repetición 2. Si el lector no da su línea de inicio, la `PARADA` incluye el código de salida de su proceso y la cola de su `.err`. Entre rutas, `up -d --force-recreate --no-deps --no-build --wait api`, comprobando que los ids de PostgreSQL, Redis y Caddy no cambian, `RestartCount` 0, la línea de límites, la memoria base y que la imagen de la API recreada es la de la repetición 1 (`PARADA` si no). Lector, `docker stats` y el log de la API se relanzan con los ids nuevos y cubren la ruta entera. La puerta toma el **peor caso** entre repeticiones, nunca la mediana. La latencia sale en una tabla por repetición, con mediana, mínimo y máximo del p95 por escalón, el codo de cada repetición sin promediar y si la repetición 1 sale sistemáticamente distinta.
- **Tiempo.** Con 3 repeticiones, unas 2 horas (unos 37 minutos de carga por repetición con t entre 0,03 y 0,1 s, más unos 4 minutos de arranque y recreaciones por repetición y los dos controles). El lanzador imprime la estimación; `TIEMPO_MAXIMO_S` (45 min) sigue siendo el tope **por repetición**.
- **Ctrl+C.** Da `PARADA` visible, limpia y escribe lo medido hasta ese momento; un segundo Ctrl+C durante la limpieza se avisa en la salida. Los contenedores efímeros llevan el prefijo `canario_estres_` y la limpieza final los busca por él.
- **Protocolo.** Las filas con estado 0 se excluyen del control de protocolo (siguen contando como error); si no hay ninguna respuesta con protocolo, SIN CONCLUSION.

Pruebas del análisis (sin Docker): `python -m unittest tests/estres/test_lanzar.py`. Los oráculos son literales y cada negativo lleva su control positivo.

### Análisis y controles

Por escalón y ruta: p50, p95 y p99; recuento; errores según la sección 3 (5xx o estado 0, que es conexión cortada, fin de fichero inesperado o plazo), agrupados por el `error_code` literal de k6 (1050 = plazo agotado) y por el texto de error; VUs en uso estimados por la ley de Little (con los VUs preasignados, la métrica `vus` siempre vale maxVUs); CPU media y máxima de cada contenedor, Redis incluido; BlockIO de PostgreSQL; y las señales del log de la API en la ventana del escalón, con su primera aparición: `SIN CONEXION: PoolTimeout`, `SATURACION:`, `EVENTO hashes_saturados`, `EVENTO limitador_no_disponible: <clase> causa=<causa> espera=<tramo>`, `ERROR INTERNO: <clase>` y `EVENTO login_fallido` (solo se cuenta). El codo de cada ruta es el primer escalón con p95 por encima del SLO, un 1 % o más de errores o maxVUs alcanzados.

**Causa del limitador (información, no oráculo).** Por escalón, el lanzador agrega la causa y la espera de cada `EVENTO limitador_no_disponible` y las cruza con lo que ya mide (`sonda_salud_p95_ms`, `cpu_redis_media`). No cambia el codo, ningún `PASA` o `FALLA` ni el RESULTADO GLOBAL, y no calcula ningún veredicto: el criterio de H7 (`docs/informe-pruebas.md`) se evalúa a mano con estas cifras. La causa dice qué excepción impidió contar, no de quién es la culpa, y la espera solo se interpreta con `pool_agotado` (`<0.25`: pool lleno y temporizador del pool sin retraso apreciable; más: bucle o CPU con cola; la salud del bucle la da la sonda de `/salud`). Los conjuntos cerrados son literales del lanzador: causa `pool_agotado`, `permiso`, `plazo`, `conexion`, `otra`; espera `<0.25`, `0.25-0.5`, `>0.5` segundos. Un campo ausente (imagen anterior) cuenta como `sin_dato` y un valor que no es de esos conjuntos, o texto de más tras los campos, como `fuera_de_conjunto`. Cada uno tiene su columna (la espera anómala de cualquier causa, en `limitador_espera_anomala`) y, si hay alguno, el resumen añade una línea `AVISO limitador` con el total de campos ajenos y una muestra de hasta 5 valores. La ventana de arranque son los 10 s que siguen (semiabierta, `[start, start + 10 s)`) al evento `start` de Redis de la repetición, recogido del stream de `docker events`. Es información que separa los errores de `conexion` y `permiso` que siguen a un arranque de Redis de los demás, sin presentarlos como legítimos: en L1 el único `start` esperado es el de la preparación de la repetición, antes del primer escalón, y un `start` dentro de la medida es un reinicio tras una muerte, o sea un incidente. Columnas nuevas del CSV (`resultados.csv`, antes de `sin_conclusion`). Salen vacías si el escalón no tiene `ventana_ms` (no se lanzó) y en ceros si se lanzó pero el log no trae eventos:

| Columna | Contenido |
|---|---|
| `limitador_pool_agotado`, `limitador_permiso`, `limitador_plazo`, `limitador_conexion`, `limitador_otra` | eventos por causa |
| `limitador_sin_dato`, `limitador_fuera_de_conjunto` | líneas sin causa y con una causa ajena al conjunto |
| `limitador_espera_anomala` | eventos de CUALQUIER causa con la espera ausente o ajena al conjunto (no entra en el reparto de `pool_agotado`) |
| `pool_espera_menos_025`, `pool_espera_025_a_05`, `pool_espera_mas_05` | espera de los `pool_agotado` por tramo (`<0.25`, `0.25-0.5`, `>0.5`) |
| `pool_espera_sin_dato`, `pool_espera_fuera_de_conjunto` | `pool_agotado` sin espera o con una espera ajena al conjunto |
| `conexion_fuera_arranque`, `conexion_dentro_arranque` | `conexion` fuera y dentro de los 10 s tras el `start` de Redis |
| `permiso_fuera_arranque`, `permiso_dentro_arranque` | `permiso` fuera y dentro de esa ventana |
| `arranques_redis_vistos` | eventos `start` de Redis de la repetición; 0 deja todo "fuera" y se ve aquí |

En la tabla de cada escalón sale una línea `limitador (causa, informacion): n=... pool_agotado=... plazo=... conexion=... permiso=... otra=... sin_dato=... fuera_de_conjunto=... espera_anomala=...; espera de pool_agotado: ...; conexion fuera/dentro de los 10 s tras el arranque de Redis a/b; permiso fuera/dentro a/b; arranques de Redis vistos n`.

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

# Pruebas de estrés L2, L3, L3b y L4

Las cuatro salen de la segunda congelación de [docs/informe-pruebas.md](../../docs/informe-pruebas.md) (sección 3, con sus erratas E1 a E18; E14, E15 y E16 son desviaciones, no aclaraciones). Comparten el montaje de L1 (proyecto `canario_estres`, cpuset de 2 núcleos para Canario y 4 CPU aparte para k6, detector de muertes, lector de cgroup, control positivo en sándwich, `down -v --rmi local`) y añaden `fases.js` (L2 y L4) y `l3.js` (L3 y L3b). Duplican a propósito las funciones de petición de `l1.js`, que no se toca. Todas las cifras son literales de la congelación (153,06/s, 102,04/s, 10,20/s, 3402 IPs, 428 y 8 IPs de víctimas): el lanzador las deriva de `t` y de las reglas y las compara con esos literales al arrancar, y `--t` tiene que ser **0.0196** (otro valor, o una cifra que no coincide, es `PARADA`). **Construcción de la imagen (E18).** L2, L3, L3b y L4 construyen la pila solo en la repetición 1 (`--build`); en L2 y L4 las siguientes arrancan con `--no-build` y, antes de lanzar ningún lector, comprueban que la imagen de `api` y la de `caddy` son las de la repetición 1 (`PARADA` si no). En las repeticiones 2 y siguientes de L3 y L3b la pila sigue en pie y solo se recrea la API, con `--no-build`; la imagen recreada se compara con la de la repetición 1, no con la API anterior (`PARADA` si no, o si no hay referencia).

| Modo | Qué mide | Límites y Caddy | Duración con 3 repeticiones |
|---|---|---|---|
| `--l2` | ¿Puede alguien impedir que un denunciante denuncie? Inundación de `login_email` contra la empresa A a 153,06/s (1,5 × 2/t, 600 VUs) y, a la vez, denuncia contra B, seguimiento inexistente y `GET /web/seguimiento` a 5/s cada una. 30 s de calentamiento, BASE 120 s, INUNDACIÓN 120 s y RECUPERACIÓN 120 s. Esperado (H3): FALLA | Estrés, Caddyfile local | unos 40 min |
| `--pico` | L4: base de 5/s por víctima y login a 10,20/s; pico de 30 s con todo por 10 (login a 102,04/s); 180 s de recuperación. Tiempo hasta volver al criterio de degradación (ventanas de 10 s cada 1 s, 30 seguidas) y humo HTTP a los 120 s del fin programado del pico, con su control justo antes. Un descarte de k6 en una ruta invalida las ventanas que lo contienen (E14), y antes de medir una sonda (`sonda_descartes.py` y `.js`, criterio de seis condiciones de E16) comprueba en k6 que las marcas de `dropped_iterations` coinciden con el instante programado de cada llegada (2/s, 1 VU, 12 s, endpoint de 2 s). Su CSV y su resumen JSON quedan en la salida y entran en el anti-fuga. Esperado (H6): PASA | Estrés, Caddyfile local | unos 37 min |
| `--l3` | 200 IPs simuladas a 1,5/s cada una (300/s) contra seguimiento inexistente durante 300 s, alineadas con una frontera de minuto UTC. Oráculo por IP y ventana. Esperado: PASA por IP | Producción (sin `CANARIO_LIMITES`), `Caddyfile.produccion`, red `edge` interna | unos 60 min en el peor caso (el sándwich de J5 añade unos 18 min) |
| `--l3b` | Cuántas IPs necesita el ataque de L2 con los límites de producción: `login_email` a 102,04/s desde 3402 IPs (9 por IP en cada ventana de 300 s) con las víctimas de L2, cada una desde su rango. 30 + 120 + 300 + 120 s, con el ataque alineado a una frontera de 5 minutos UTC. Dos veredictos separados (E15): L3b-a, el oráculo por IP y ventana (esperado PASA), y L3b-b, las víctimas (esperado FALLA, y una FALLA da NO OK) | Producción, como L3 | unos 86 min en el peor caso (hasta 5 minutos de espera a la frontera por repetición; el sándwich de J5 añade unos 18 min) |

Se ejecutan **en este orden y no a la vez que L1**: L2, L4, L3 y L3b (≈ 3 h 40 min en el peor caso, la estimación del lanzador; unos 36 min más de lo que sale sin el sándwich de J5). Comparten subredes fijas, CPU y el `git status` final, y L1 monta `tests/estres` en vivo.

## Cómo ejecutar (PowerShell 5, desde la raíz del repo)

Requisitos: los de L1 (Docker en marcha, secretos generados, internet para construir la SPA y bajar k6) y la pila local parada (`docker compose -p canario down`, sin `-v`).

```powershell
python tests\estres\lanzar.py --l2 --t 0.0196
python tests\estres\lanzar.py --pico --t 0.0196
python tests\estres\lanzar.py --l3 --t 0.0196
python tests\estres\lanzar.py --l3b --t 0.0196
```

`--repeticiones N` (3 por defecto; con menos de 3 el veredicto es `SIN CONCLUSION`, A1) y `--conservar` (solo para depurar) funcionan igual que en L1. Las pruebas de las funciones puras no necesitan Docker:

```powershell
python -m unittest tests/estres/test_lanzar.py
```

## Cómo se decide un veredicto

- **Dos clases de control (J1, E5).** Los de **validez** dan `SIN CONCLUSION` y ganan a FALLA: CPU de k6 por encima de 320 %, descartes sin el aviso `Insufficient VUs`, OOM o código de k6, BASE fuera del SLO, hueco del lector, protocolo distinto de HTTP/1.1, 429 donde no toca, cruce de las 00:00 UTC, línea de límites distinta de la literal, control final del detector, control positivo por IP y ventana (J2), IPs de control de L3b (D3, E6), control de la BASE de F2 (30 ventanas seguidas y 95 %), humo previo de L4 y la IP reutilizada tras recrear la API (J5). El control de que el ataque existe (B2) **solo rebaja un PASA**. Una muerte de un servicio de Canario es FALLA y gana a todo fallo de validez; solo si todas las muertes son el OOM global de la VM es `SIN CONCLUSION`. La función es `veredicto_con_validez`; `peor_estado` combina solo los resultados de los oráculos de las repeticiones y nunca la validez con un resultado.
- **Tres repeticiones válidas (A1).** Cualquier `SIN CONCLUSION` de validez en una repetición da `SIN CONCLUSION` a la prueba. El p95 y la degradación se evalúan sobre la mediana de las tres (un p95 sin respuestas cuenta como infinito); el veredicto de cada una se publica.
- **L2 y L3b, víctimas (B1).** FALLA si está degradada (p95 > max(2 × base, base + 100 ms)), supera su SLO, tiene un 1 % o más de errores (estado distinto del esperado) o descartes con aviso. B2: p95 del login por encima de 1500 ms, un 1 % o más de errores (conexión cortada, fin de fichero, plazo agotado o 5xx que no sea 503; los 503 se informan aparte, E8) o descartes con aviso. Los 20 primeros segundos de la RECUPERACIÓN no cuentan (E11).
- **L3 y L3b, por IP y ventana (C1, J2, J3, E7).** Una petición es ambigua si `[marca - duración, marca]` cruza una frontera de ventana. Solo cuenta el estado aceptado (404 en L3, 401 en L3b); los 503 van aparte. FALLA si un par IP-ventana pasa del límite con peticiones no ambiguas o si algún 429 no lleva `Retry-After` entre 1 y 60 (L3) o 1 y 300 (L3b). `SIN CONCLUSION` si solo pasa contando las ambiguas.
- **L4 (F2, F3, E9).** Cada petición cuenta en todas las ventanas `[s, s + 10)` que contienen su inicio. El tiempo de recuperación de una repetición es `s0` menos el fin programado del pico, con `s0` el primer inicio con 30 ventanas consecutivas dentro del criterio en todas las rutas; una repetición que no se recupera cuenta como infinito. F3 se evalúa sobre la mediana de los tres tiempos: PASA si es menor de 60 s, sin reinicios y con el humo posterior correcto.
- **Descartes de k6 en L4 (E14).** Las rutas de F2 son cuatro (denuncia, seguimiento, `GET /web/seguimiento` y login; `POST /salud` no cuenta). Cada fila `dropped_iterations` de una de ellas, en cualquier fase y lleve o no el aviso `Insufficient VUs`, cuenta en todas las ventanas `[s, s + 10)` que contienen su marca, y esas ventanas no cumplen el criterio para esa ruta; en la RECUPERACIÓN son ventanas no recuperadas. En la BASE, un solo descarte en cualquiera de las cuatro rutas da `SIN CONCLUSION` por validez aunque se cumpla el 95 %. Los descartes del PICO solo se informan, ruta por ruta.
- **L3b da dos veredictos (E15).** L3b-a (oráculo por IP y ventana; validez propia: J2, D3, J5 y el control de strict) y L3b-b (víctimas; validez propia: la BASE y B2, que solo actúa sobre este). La validez común (generador, detector, muertes y 00:00 UTC) se aplica a los dos y ninguna línea los junta. Una FALLA de L3b-b da NO OK aunque el diseño la espere, y la salida lo dice así: `L3b-b: FALLA (esperada por el diseño; NO OK; misma amenaza que L2, threat-model §8, ABIERTA)`. La cifra del coste (3402 IPs, una cota superior, no el mínimo) solo se da con L3b-b en FALLA y B2 cumplido. L3b-a solo muestra que el ataque, repartido, no recibió ningún 429; que el límite está activo lo muestra D3, no L3b-a.

## Controles de configuración de L3 y L3b (antes de medir, en cada repetición)

Desde contenedores efímeros `canario_estres_cliente_*` en la red `edge` con IP fija (10.88.1.2 hace de Traefik, 10.88.1.3 de ajeno): una petición con el Host de producción no da 421 (`PARADA`); desde 10.88.1.3, el 403 con el cuerpo JSON literal de `handle_errors` (`PARADA`); 71 peticiones contra seguimiento inexistente, diferenciales (S1): 70 con `X-Forwarded-For: <IP falsa que rota>, 198.19.255.254` cuentan todas para la última IP (60 × 404 y 10 × 429) y una 71.ª con `198.19.255.254, <otra IP reservada>` cuenta para la otra IP y da 404; cualquier otro patrón es `PARADA` (sin strict, las 70 dan 404; sin confianza en 10.88.1.2, la 71.ª da 429), y si cruzan un minuto, `SIN CONCLUSION`; **J5 como sándwich (H6)**: entre repeticiones se recrea la API (sal nueva, contadores de la API a cero) y, con la misma IP y en la misma ventana de 300 s, antes de recrearla da 429 (control positivo) y después 401. En L3 y en L3b es la regla `acceso` (login con una empresa que no existe en L3: el limitador cuenta por ruta antes de leer el cuerpo); se imprime cuánto tarda y empieza solo si quedan 120 s de la ventana (`MARGEN_SANDWICH_J5_S`: recrear la API con `--wait` y su healthcheck de 10 s se cronometra con la línea `recrear_api: <s> s`, y el sándwich completo tardó 11 s en las repeticiones 2 y 3 de L3b). La estimación del lanzador suma, a partir de la repetición 2, 541 s de peor caso por sándwich (121 s de espera máxima, 120 s de plazo para recrear la API, que tardó de 7,7 a 8,1 s en la L1 × 1 del 24/11 y la L3b del 25/11, y los plazos de los dos clientes de control), unos 18 min por prueba con 3 repeticiones. El plazo y la estimación son el peor caso y no cambian con la medida; si el positivo no da 429, `SIN CONCLUSION`; y, en L3b, 11 peticiones de login desde cada una de 10 IPs de control en la misma ventana de 300 s (D3). Las IPs reservadas quedan fuera de todos los rangos. Al arrancar L3 y L3b (S8) se registra el commit, se exige que `proxy/`, `compose.produccion.yaml` y `docker-compose.yml` no tengan cambios, y se compara el `command` de Caddy y `networks.edge.internal` del override con lo que resuelve `docker compose` con `compose.produccion.yaml` (`PARADA` si difieren). `l3.js` comprueba en `setup()` que `POST /salud` con el Host de la API da 405 (no solo que no dé 421) y, en L3b, que `GET /seguimiento` con el Host del sitio da 200 (`CONTROL_421` y `CONTROL_SETUP`, `PARADA`). Las repeticiones de L3 y L3b comparten Redis, PostgreSQL y Caddy: solo se recrea la API entre ellas (J5).

## Rangos de IPs (E4)

IPv4 de `198.18.0.0/15` sin las direcciones `.0` y `.255` de cada `/24`. Al final del espacio quedan reservadas 198.19.255.254 (control de strict), 198.19.255.253 (sonda de salud), 198.19.255.252 (la otra IP del 71.º del control de strict) y un bloque con nombre de 70 IPs falsas que rotan en ese control. Cada repetición usa un bloque distinto de 4096 índices; dentro del bloque, ataque, control y víctimas no se solapan (si se solapan, `PARADA`). L3b: 3402 IPs del ataque, 10 de control y 428, 8 y 8 de las víctimas (peticiones en 570 s / límite × 1,5, redondeado hacia arriba). El reparto es circular por iteración (`iterationInTest` módulo el número de IPs), nunca al azar.

## Anti-fuga (A3, J7)

Al terminar, también tras Ctrl+C o con `--conservar`, se buscan en todos los ficheros de la salida la contraseña sintética del login (la misma en toda la ejecución, distinta en cada una), el texto sembrado del humo, cualquier código de seguimiento (con guiones, en cualquier combinación de mayúsculas y minúsculas, o 32 caracteres seguidos en mayúsculas; el del humo solo existe dentro de k6) y, en los ficheros que no los necesitan, los identificadores de empresa. Se buscan tal cual y codificados (URL y JSON escapado). El **centinela** se planta a propósito dentro de la propia salida (literal, URL, JSON, un código y un identificador en un fichero `k6.csv`) y el mismo recorrido tiene que encontrarlo todo: si no, `SIN CONCLUSION`. El escaneo corre antes de emitir los veredictos de la prueba y, al final, también se escanea el texto que sale por pantalla (PARADA, traceback y veredictos). **`--conservar` deja en `datos/` la contraseña sintética y los identificadores de empresa** (`ejecucion.json`, `ips.json`): no se sube ni se comparte esa carpeta.

## Qué queda en %TEMP%

`verificacion_estres.txt` (la salida entera) y `canario_estres_salida_*` con `resultados.json` y, por repetición, `rep<n>/` con los logs de la API, Redis y PostgreSQL, el `docker stats` de la pila y la carpeta de k6 (`k6.csv`, `resumen.json`, `panel.html`, `stats.txt`, `k6_salida.txt`). El CSV de L3 pesa unos 200 MB por repetición.

## Lo que no demuestran

Un modelo relativo: no hay TLS de Traefik, ni vecinos del VPS, ni Traefik real (eso es `verificar_despliegue.py`). Solo se simulan IPv4: lo que se mide es el límite por IPv4 y no se extrapola a IPv6. La duda de IPv6 de threat-model l.762 sigue abierta. El login también entra por `canario-personal` (`/v1/personal/*`), no solo por `canario-api`. La IP de cada cliente simulado va al final de `X-Forwarded-For`, igual que en producción si Traefik es el primer salto y entrega la IP de la conexión al final del XFF. Si k6 pierde una conexión, el texto del error (que puede citar una URL) queda en `k6_salida.txt`. Los VUs de k6 se estiman a 5 MiB cada uno (supuesto sin medir, como en L1); el lanzador calcula la memoria por VUs preasignados antes de cada repetición (L2 y L3b, 765 VUs; L4, 747; L3, 615), con el tamaño de `ejecucion.json` por VU (4 copias, supuesto sin medir; las listas de IPs van aparte, en `ips.json` y en un `SharedArray`), y se detiene si pasa de los 4 GiB. Sin Docker no se han podido comprobar: `internal: true` de `edge`, que k6 inicialice los VUs dentro de los 120 s de margen de la frontera, la cardinalidad de la etiqueta `ip`, `exec.test.abort` del control 421 y `sonda_descartes.py`.

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
