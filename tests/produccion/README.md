# Pruebas de producción (P0 a P6)

`lanzar.py` implementa el plan v3 de las pruebas de producción de `docs/informe-pruebas.md` (§2, "En producción"). Solo biblioteca estándar de Python 3.12. Todos los comandos son de **PowerShell 5, desde la raíz del repo**, salvo los marcados como **sesión `ssh ovh`**.

## Qué impone el script

- **Destino local por defecto.** Producción solo con `--destino produccion --franja-autorizada HH:MM-HH:MM` (UTC). Fuera de la franja, `PARADA`. P6 exige además empezar entre las 22:00:00 y las 22:47:00 UTC del servidor y caber entero (12,6 min) en la franja.
- **Topes fijos** (no se cambian por argumentos): A 20/s, 120 s, 2400 peticiones y 10 en vuelo en P6; B 0,5/s; sondas cada 1 s como mínimo; P1 70 + 5; P1b 70; P2 11; P3 2; P5 600 s; A1 10 peticiones de CSS.
- **Antes de cualquier prueba de producción:** árbol limpio (`git status --porcelain` vacío) y `git ls-remote origin refs/heads/main` igual a `HEAD` (el push hecho, comprobado contra el remoto y no contra la referencia local `origin/main`), `--p0-revisado` (salvo en P0, P4 y Q-12) y `ssh -G ovh` legible (solo se leen `user` y `hostname`, para el anti-fuga; nunca se imprimen).
- **Nunca** ejecuta `sudo` ni abre `ssh` hacia el VPS, ni recibe contraseñas. Lo que necesita `sudo` se hace en el modo manual de abajo.
- **Salida** en `%TEMP%\canario_produccion_salida_<UTC>_<prueba>\`: `salida.txt`, `peticiones.csv` y `resumen.json`. La ruta se imprime solo por consola. El anti-fuga (con centinela) busca las IP públicas y locales de A y B, la IP del VPS, `user` y `hostname` de `ssh -G ovh`, las URL de las vecinas y su sal (hexadecimal en minúsculas y mayúsculas), `[sudo]`, el patrón de los códigos de seguimiento y la carpeta personal de Windows. Si no da `PASA`, la salida dice `NO PUBLICAR`.
- **Carpeta privada** `%TEMP%\canario_produccion_privado\`: IP completas (`ips.txt`), bloques pegados del VPS, fichero de vecinas y su sal. **No se publica nada de aquí.**
- `RESULTADO GLOBAL: OK` (código 0) solo si todas las pruebas pedidas dan `PASA` (o `HECHO` en P0), el anti-fuga da `PASA` y `git status --short -uall` no ha cambiado.

## Unitarias (sin red ni Docker)

```powershell
python -m unittest tests.produccion.test_lanzar -v
```

## Ensayo local (pila `canario` en marcha)

La CA local de Caddy (dato público) para verificar el TLS de `localhost`, como en `docs/operacion.md:28`. El script nunca desactiva la verificación:

```powershell
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt "$env:TEMP\canario-ca.crt"
python tests\produccion\lanzar.py --prueba p3 --ca-local "$env:TEMP\canario-ca.crt"
python tests\produccion\lanzar.py --prueba p2 --ca-local "$env:TEMP\canario-ca.crt"
python tests\produccion\lanzar.py --prueba p5 --duracion-p5 60 --ca-local "$env:TEMP\canario-ca.crt"
```

**Control de P4** (pila temporal `canario_produccion_p4`: solo `api`, `postgres` y `redis`, con `CANARIO_LIMITES` relajado, y `down -v --rmi local` al final). Necesita los secretos generados (`scripts/generar_secretos.py`) y **la pila `canario` parada** (`docker compose -p canario down`, sin `-v`), porque comparten subredes fijas:

```powershell
python tests\produccion\lanzar.py --prueba p4
```

Anote la carpeta de salida: P4 en producción la pide con `--p4-control`. El control solo vale para el mismo `lanzar.py` (se comprueba su SHA-256).

P1, P1b, P0 y P6 no tienen ensayo local: con un solo origen, A y B compartirían contador.

## Modo manual de `sudo` (P4, relectura antes de P6 y Q-12)

1. **Portapapeles.** Antes de copiar nada: Configuración > Sistema > Portapapeles, apagar el **historial** (Win+V) y la **sincronización entre dispositivos**. Se confirma con `--portapapeles-sin-historial`, que queda escrito en la salida. Además, el script lee con `winreg` lo único que Microsoft documenta: las políticas `AllowClipboardHistory` (Experience Policy CSP) y `AllowCrossDeviceClipboard` (Privacy Policy CSP), en `HKLM\Software\Policies\Microsoft\Windows\System`, donde 0 es "no permitido". Si las dos valen 0, lo da por comprobado. Si no existen (lo normal en Windows Home, donde esas políticas no se aplican) o valen 1, escribe un `AVISO PORTAPAPELES` visible y queda solo la declaración del autor. El interruptor de usuario de Configuración no tiene clave documentada, así que no se lee.
2. **Sesión `ssh ovh`** propia, con `ForwardAgent no` (compruébelo antes en PowerShell: `ssh -G ovh | Select-String '^forwardagent'`). Primero `sudo -v` (así el aviso de contraseña no cae dentro del bloque) y después el comando fijo:

   **Sesión `ssh ovh`:**
   ```bash
   cd ~/apps/canario && c=$(sudo docker compose -f docker-compose.yml -f compose.produccion.yaml ps -q api) && echo CANARIO_P4_INICIO && sudo docker inspect --format 'API {{.State.StartedAt}} {{.RestartCount}} {{.Image}}' "$c" && echo "PRIMERA_MARCA $(sudo docker logs --timestamps "$c" 2>&1 | head -n 1 | cut -d' ' -f1)" && sudo docker logs --timestamps "$c" 2>&1 | grep -F 'canario.arranque: LIMITES ('; echo CANARIO_P4_FIN
   ```
   El filtro se aplica en el VPS: las líneas `EVENTO` con UUID no salen nunca.
3. Copie **solo** el bloque, de `CANARIO_P4_INICIO` a `CANARIO_P4_FIN`, y guárdelo:

   ```powershell
   New-Item -ItemType Directory -Force "$env:TEMP\canario_produccion_privado" | Out-Null
   Get-Clipboard | Set-Content -Encoding ascii "$env:TEMP\canario_produccion_privado\p4.txt"
   ```
   **Aviso:** `-Encoding ascii` cambia cualquier carácter no ASCII por `?`. El bloque esperado es ASCII puro, así que un `?` delata texto ajeno y el analizador da `SIN CONCLUSION`. Cualquier línea fuera de formato (el aviso de `sudo`, "Sorry, try again") también da `SIN CONCLUSION`, y ese bloque no se publica. Un bloque con el formato exacto se publica tal cual en `salida.txt` (solo lleva marcas, `StartedAt`, `RestartCount`, `Image` y líneas `LIMITES`). En §7 del informe constará que P4 se basa en un bloque pegado a mano.

**Q-12.** Tras cada bloque de pruebas, el script construye el segundo comando a partir de las ventanas del servidor de cada salida (marcas validadas como `AAAA-MM-DDTHH:MM:SSZ`, 5 s de margen y `grep -F` fijo). Se imprime con `--salidas` y se analiza con `--q12-entrada`:

```powershell
python tests\produccion\lanzar.py --prueba q12 --destino produccion --franja-autorizada <F> --salidas <dir P3> <dir P1> <dir P1b> <dir P2>
# pegar el comando impreso en la sesión ssh ovh (tras sudo -v), copiar el bloque y:
Get-Clipboard | Set-Content -Encoding ascii "$env:TEMP\canario_produccion_privado\q12.txt"
python tests\produccion\lanzar.py --prueba q12 --destino produccion --franja-autorizada <F> --salidas <dir P3> <dir P1> <dir P1b> <dir P2> --q12-entrada "$env:TEMP\canario_produccion_privado\q12.txt" --portapapeles-sin-historial
```

**Solución de fondo (bloque posterior, no ahora):** un script fijo `/usr/local/sbin/canario-leer-arranque` de root, modo 0755, sin argumentos, con una regla `NOPASSWD` solo para él, llamado con `ssh -T ovh sudo -n /usr/local/sbin/canario-leer-arranque`. Toca la configuración del VPS: necesita el visto bueno del autor.

## Traefik, antes de P0 (§5.3)

La configuración completa **no sale del VPS** (puede traer `basicAuth`, el email de ACME o tokens de las vecinas). **Sesión `ssh ovh`:**

```bash
sudo less <ruta de la configuración estática de Traefik>      # parámetro T, por confirmar
sudo less /etc/dokploy/traefik/dynamic/<cada fichero>.yml
sudo docker inspect --format '{{.Config.Image}} {{json .Args}}' dokploy-traefik
sudo sha256sum /etc/dokploy/traefik/dynamic/canario.yml ~/apps/canario/despliegue/traefik/canario.yml
```

Busque los middlewares del entrypoint `websecure`, `rateLimit`, `forwardedHeaders` (`trustedIPs`, `insecure`), `respondingTimeouts`, `proxyProtocol` y `accessLog`. Al PC solo llegan las claves relevantes, anotadas a mano o con este filtro fijo, y por el portapapeles con las mismas precauciones a `canario_produccion_privado\traefik.txt`:

```bash
sudo grep -n -E '(entryPoints|websecure|middlewares|rateLimit|forwardedHeaders|trustedIPs|insecure|respondingTimeouts|readTimeout|writeTimeout|idleTimeout|proxyProtocol|accessLog)' <ficheros> | grep -v -i -E '(users|password|token|email)'
```

El autor decide P0 a mano: `--p0-revisado` y, si quiere, `--p0-nota "<texto>"` (lo único de Traefik que se publica). Si hay un `rateLimit` delante de Canario, no se sigue.

## Producción, en orden (dentro de la franja F)

`<A>` y `<B>` son las IPv4 **locales** de la fibra y del móvil por USB (`Get-NetIPAddress -AddressFamily IPv4 | Format-Table InterfaceAlias, IPAddress`). `<F>` es la franja acordada, por ejemplo `19:00-21:00`.

```powershell
python tests\produccion\lanzar.py --prueba p0 --destino produccion --franja-autorizada <F> --origen-a <A> --origen-b <B> --p0-revisado --p0-nota "<nota>"
python tests\produccion\lanzar.py --prueba p4 --destino produccion --franja-autorizada <F> --p4-entrada "$env:TEMP\canario_produccion_privado\p4.txt" --p4-control <dir del control local> --portapapeles-sin-historial
python tests\produccion\lanzar.py --prueba p3 --destino produccion --franja-autorizada <F> --origen-a <A> --p0-revisado
python tests\produccion\lanzar.py --prueba p1 --destino produccion --franja-autorizada <F> --origen-a <A> --origen-b <B> --p0-revisado
python tests\produccion\lanzar.py --prueba p1b --destino produccion --franja-autorizada <F> --origen-a <A> --p0-revisado
python tests\produccion\lanzar.py --prueba p2 --destino produccion --franja-autorizada <F> --origen-a <A> --p0-revisado
# Q-12 del bloque (arriba)
python tests\produccion\lanzar.py --prueba p5 --destino produccion --franja-autorizada <F> --origen-b <B> --p0-revisado
```

`p1b` ejecuta P1b-c y P1b en dos ventanas seguidas (el control de P1b es P1b-c en `PASA`). P2 deja la IP de A sin cupo de denuncias hasta el fin de la hora UTC.

### Antes de P6

1. **Vecinas** (parámetro V). Una por línea, `<URL https> <estado esperado 2xx o 3xx>`, en UTF-8 **sin BOM** y con LF (PowerShell 5 pone BOM con `-Encoding utf8`; use esto):

   ```powershell
   [IO.File]::WriteAllText("$env:TEMP\canario_produccion_privado\vecinas.txt", "https://<vecina>/<ruta barata> 200`n", (New-Object Text.UTF8Encoding $false))
   python tests\produccion\lanzar.py --prueba hmac-vecinas --vecinas "$env:TEMP\canario_produccion_privado\vecinas.txt"
   ```
   La sal (32 bytes) se crea una vez en la carpeta privada y no se pisa nunca. El HMAC impreso va al commit de congelación.
2. **Commit de congelación** (abajo), con push. Antes de las 23:00, compruebe las constantes sin red: `python tests\produccion\lanzar.py --prueba verificar-congelacion` (`CONGELACION PASA` y código 0, o `PARADA` con el motivo).
3. **Relectura de la API (Q-5)**, a las 22:40 de Madrid: el mismo comando fijo de P4 en la sesión `ssh ovh`, guardado en `p4_relectura.txt`.

### P6 (22:00-22:47 UTC; termina a las 22:59:36 UTC como tarde)

```powershell
python tests\produccion\lanzar.py --prueba p6 --destino produccion --franja-autorizada 22:00-23:00 --origen-a <A> --origen-b <B> --p0-revisado --vecinas "$env:TEMP\canario_produccion_privado\vecinas.txt" --p4-anterior "$env:TEMP\canario_produccion_privado\p4.txt" --p4-entrada "$env:TEMP\canario_produccion_privado\p4_relectura.txt" --portapapeles-sin-historial
```

Después, la lectura de Q-12 con `--salidas <dir P6>`.

## Plan B: dos máquinas (Q-15, si el PC no puede tener las dos redes)

Cada máquina con su A1 y su `--rol`. P1 y P6 necesitan una frontera común `--frontera-utc HH:MM` (UTC del servidor; en P6, después de la línea base de 5 min). En P1, B envía en la segunda mitad del minuto de A. Cada rol da `SIN CONCLUSION: el veredicto sale de --combinar`; el veredicto lo da:

```powershell
python tests\produccion\lanzar.py --combinar <dir rol a> <dir rol b> --ips-a <ips.txt privado de A> --ips-b <ips.txt privado de B> --p0-revisado
```

`--combinar` se niega si los dos roles no están en el mismo commit o algún árbol no estaba limpio.

## Commit de congelación de P6 (texto propuesto)

Lo hace Eduardo, con push **antes** de medir (E3). Mensaje:

```
docs: congelacion de p6 con las cifras de p5, d10 y el hmac de las vecinas
```

Cambios:

1. En `tests/produccion/lanzar.py`, las constantes literales que imprime P5 al dar `PASA` y el HMAC de `--prueba hmac-vecinas`:
   ```python
   P5_P50_MS = <p50 de P5>
   P5_P95_MS = <p95 de P5>
   P5_MAX_MS = <máximo de P5>
   P6_P50_B_MAX_MS = <2 x p50 de P5, escrito como literal>
   HMAC_VECINAS = "<hexadecimal>"
   ```
   Mientras alguna valga `None`, P6 da `PARADA`. Las cifras van con un decimal como mucho, y `P6_P50_B_MAX_MS` tiene que ser exactamente 2 × `P5_P50_MS` ya redondeado (p50 de 41,26 ms: `P5_P50_MS = 41.3` y `P6_P50_B_MAX_MS = 82.6`, no 82.5). P5 imprime las constantes ya así.
2. En `docs/informe-pruebas.md`, la desviación D10:

   > **D10, guarda de frontera.** En P6, A solo lanza una llegada en el instante local t si t + d_min >= F_anterior y t + d_max + 1,0 s + 0,001 s <= F_siguiente, con F las fronteras de minuto del servidor y [d_min, d_max] el desfase medido con el `Date` de Caddy (A1). Las llegadas omitidas se registran, no se reenvían y no cuentan como descartes ni en el control de retraso. Es una desviación del perfil de "2 minutos" de l.100: la pausa es de unos 1 + (d_max - d_min) s por minuto. Una aceptada (404) ambigua da `SIN CONCLUSION`; un 429 ambiguo no invalida. En producción **no se mide el caso "120 si cruza la frontera"** de l.100: la guarda lo evita a propósito. Ese defecto de la ventana fija lo mide L3 en local (`maximo_deslizante`, l.192 y l.448); en P6 `maximo_deslizante` se da como información. Las vecinas se fijan con HMAC-SHA256(sal, bytes del fichero), con la sal de 32 bytes fuera del repositorio; quien evalúe puede recibir del autor la sal y el fichero para recalcularlo.

## Interpretaciones del plan

- **Error en el oráculo de P1b y P2.** El plan dice "FALLA si no" para las peticiones 61 a 70 de P1b y para la 11.ª de P2. Un estado 0 (sin respuesta) o un 5xx ahí da `SIN CONCLUSION`, no `FALLA`: no es un fallo del límite ni del `X-Forwarded-For`, porque no se sabe qué habría contestado el limitador. Cualquier otra respuesta que no sea el 429 literal sigue siendo `FALLA`.
- **FALLA de A en P6.** Más de 60 aceptadas no ambiguas en una ventana es `FALLA` en cualquier ventana, también en la que corta una parada. El control (`control_l3` y un `es_429` en cada ventana con más de 60 no ambiguas) solo se exige en las ventanas completas. Una `FALLA` gana a la parada.
- **P5, mínimo de muestras.** P5 da `SIN CONCLUSION` si no se lanzaron las 300 llegadas o hubo menos de 290 respuestas (en el ensayo local corto, la misma proporción).
- **Redondeo al microsegundo.** El intervalo del servidor de cada petición (`[t_inicio + d_min, t_fin + d_max]`) y la guarda D10 se redondean al microsegundo antes de compararlos con la frontera. Así la coma flotante no decide si 119,99999999999999 cruza la de las 120 (el borde de QA6: 1,000 s lanzada en el último instante no es ambigua y 1,001 s sí). Ningún reloj de aquí resuelve por debajo del microsegundo.
- **Q-12.** El evento `limitador_no_disponible` lo escriben tres loggers, y se aceptan los tres: `canario.limitador` (`app/limitador.py:96`), `canario.personal` (`app/rutas_personal.py:126`, en la l.936) y `canario.externo` (`app/rutas_externo.py:70`, en la l.323).

## Lo que no se comprueba

- `Connection: close` del 413 a través de Traefik (D1): P3 lo anota como información.
- El caso "120 si cruza la frontera" de l.100 (D10): lo cubre L3 en local.
- Que el log de acceso del Traefik de Dokploy no guarde las IP de A y B (S11): se deriva a `docs/threat-model.md`.
