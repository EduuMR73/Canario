# Imagen de PostgreSQL de Canario: la oficial, fijada por versión y por digest
# (índice multiarquitectura), sin gosu.
# 18.7 se adopta con la excepción de los 14 días de docs/threat-model.md (6.17):
# su manifiesto linux/amd64 se subió el 18 de noviembre de 2026 y a la fecha de
# adopción (24 de noviembre) tenía 5 días cumplidos. Motivo: 18.6 lleva CVE de PostgreSQL
# arregladas en 18.7 (entre ellas, ejecución de código con un rol autenticado)
# que Trivy no ve, porque el servidor se compila en /usr/local y no consta como
# paquete. Con ejecución de código como uid 70 se entra como
# superusuario por el socket (peer), así que esperar a los 14 días era peor.
FROM postgres:18.7-alpine@sha256:0115267ab5a509022df9319c77be365cef335adb71556c75f60f5360ee247e71

# gosu solo sirve para que el entrypoint baje de root al usuario postgres: lo
# ejecuta únicamente si el contenedor arranca como root (docker-entrypoint.sh,
# comprobación de "id -u" igual a 0). Aquí arranca siempre con user 70:70 y
# nunca lo usa. El binario de la imagen está compilado con Go 1.24.6 y el
# escaneo de la imagen (tests/security/verificar_escaneos.py) le encuentra
# vulnerabilidades de la biblioteca estándar de Go con arreglo publicado, sin
# una imagen oficial nueva que lo traiga. Se quita la causa en vez de aceptar
# la excepción. Efecto secundario buscado: si alguien arranca el contenedor
# como root, el entrypoint falla de forma visible en lugar de bajar de
# privilegios en silencio.
# El fichero sigue en la capa de la imagen base, pero no existe en el sistema
# de ficheros del contenedor, que es lo que se ejecuta y lo que escanea Trivy.
RUN rm /usr/local/bin/gosu

# Usuario sin privilegios por defecto en la propia imagen (70 es postgres en la
# imagen alpine), no solo en docker-compose.yml: quien la arranque sin el user
# del compose tampoco obtiene root. La imagen oficial no declara USER porque
# cuenta con bajar de privilegios con gosu, que aquí ya no existe.
USER 70:70
