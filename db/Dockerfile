# Imagen de PostgreSQL de Canario: la oficial, fijada por versión y por digest
# (índice multiarquitectura), sin gosu.
FROM postgres:18.6-alpine@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873

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
