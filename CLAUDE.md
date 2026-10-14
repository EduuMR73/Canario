# Reglas de trabajo para Claude Code (proyecto Canario)

## Proyecto
Canal de denuncias anónimo multi-empresa. Backend con API REST: FastAPI, PostgreSQL, Redis y Docker Compose, con Caddy como proxy. Sin frontend. Entrega el miércoles 21 de octubre (pendiente de confirmar). Objetivo: seguro, limpio y profesional, sin parches. Las decisiones de diseño y las amenazas están en `docs/threat-model.md`. No repitas lo que ya se probó: lee el código y las baterías existentes antes de proponer nada.

## Cómo trabajar
- Antes de un bloque grande: lee los ficheros afectados y propón un plan corto (qué ficheros tocas, qué pruebas añades). Espera el visto bueno de Eduardo.
- Implementa por bloques coherentes (por ejemplo, denuncia anónima con seguimiento), no todo de golpe.
- Cada cambio de seguridad lleva su prueba. Cada prueba negativa lleva su control positivo: si el control falla, el resultado es `SIN CONCLUSION`, nunca `PASA`. Los oráculos se escriben como literales, no se derivan del código que se prueba.
- Si algo no se puede hacer como se pidió, o una suposición resulta falsa, PARA y explícalo. No sustituyas la comprobación ni ajustes la prueba para que cuadre. No reconstruyas de memoria lo que puedes leer en el repo.
- Al terminar un bloque, escribe en `%TEMP%` un informe de máximo 30 líneas, sin código: suposiciones de memoria (confirmadas o falsas), desviaciones, paradas y lo que no se ejecutó.

## Prohibido
- `git add`, `git commit`, `git push`, `git stash`, `git checkout` y `git restore`. Los commits los hace Eduardo. Propón un mensaje corto, en castellano, sin tildes ni eñes, con prefijo (`feat:`, `docs:`, `chore:`) y espera su confirmación.
- Abrir, leer o imprimir ficheros de `secrets/`. Para saber si existen, usa `is_file()`. Los secretos reales solo se montan en contenedores con `--mount`, nunca con `-v`.
- Tocar ficheros que no sean los del bloque. Al terminar, comprueba con `git status --short -uall`.
- Poner contraseñas o claves en el código, los logs, las variables de entorno o los mensajes de error.

## Estilo
- Todo en castellano: comentarios, documentación, README y mensajes de la API. Los nombres del código (tablas, columnas, funciones, rutas, variables) en castellano, ASCII y sin `ñ`. Lo que imponen las herramientas se queda tal cual.
- Ficheros UTF-8 sin BOM y saltos LF. Comentarios con tildes. Sin em-dashes.
- Comenta el porqué de cada medida de seguridad. Prefiere lo explícito a lo implícito, la causa raíz al síntoma, y que un fallo sea visible y no silencioso.

## Pruebas
- Las baterías viven en `tests/security/`. La de base de datos: `python tests/security/verificar_esquema.py`, con Docker en marcha y los secretos generados con `scripts/generar_secretos.py`. No debe modificar el repo.
- Cada batería usa un proyecto Docker temporal con prefijo propio y limpia con `down -v`. Eduardo la vuelve a ejecutar él mismo antes de dar nada por bueno.
- En Python, `subprocess` con argumentos en lista, nunca cadenas de shell (PowerShell 5 pierde las comillas dobles internas).

## Entorno
- Windows con PowerShell 5, Docker Desktop y Python 3.12. La ruta del proyecto tiene espacios. Indica siempre en qué terminal se ejecuta cada comando.
- Imágenes fijadas por versión y digest. Redes internas, `read_only`, `cap_drop: ALL`, `no-new-privileges` y usuario no root.
