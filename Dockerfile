# Imagen de la API de Canario.
#
# Imagen base fijada por versión y por digest (índice multiarquitectura): la
# versión es legible y el digest garantiza el contenido exacto aunque alguien
# republique la etiqueta. Python 3.12.15.

# --- Etapa de construcción: crea el entorno virtual con las dependencias ---
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1 AS construccion

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY requirements.txt /tmp/requirements.txt

# El entorno virtual se crea sin pip: en ejecución no hace falta instalar nada.
# Lo llena el pip de esta etapa con --python.
# --require-hashes: cualquier fichero cuyo sha256 no esté en requirements.txt se
# rechaza, y también cualquier dependencia sin fijar.
# --only-binary :all: solo wheels; nunca se ejecuta un setup.py de terceros.
RUN python -m venv --without-pip /opt/venv \
 && python -m pip --python /opt/venv/bin/python install \
        --require-hashes --only-binary :all: -r /tmp/requirements.txt

# --- Etapa final: solo el intérprete, el entorno virtual y el código ---
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

# Se quita el pip de la imagen base: en ejecución no se instala nada, y así un
# atacante con ejecución de código no tiene un instalador a mano.
# Usuario y grupo propios con uid y gid fijos, sin shell ni directorio personal.
RUN python -m pip uninstall --yes --no-cache-dir pip \
 && groupadd --system --gid 10001 canario \
 && useradd --system --uid 10001 --gid 10001 --no-create-home \
        --home-dir /nonexistent --shell /usr/sbin/nologin canario

COPY --from=construccion /opt/venv /opt/venv
# El código pertenece a root: el usuario de la API puede leerlo, no modificarlo.
COPY app/ /srv/app/

WORKDIR /srv

# PYTHONDONTWRITEBYTECODE: no intenta escribir .pyc (el sistema de ficheros es
# de solo lectura). PYTHONUNBUFFERED: los logs salen al momento.
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER 10001:10001

EXPOSE 8000

# Opciones de seguridad invariables, fijas en la imagen:
# --no-access-log: uvicorn no registra peticiones (ni IPs). No se usa
#   --log-config, que podría reactivar el logger uvicorn.access.
# --no-server-header: no anuncia el servidor ni su versión.
# Sin --proxy-headers ni --forwarded-allow-ips aquí: en qué proxy se confía
# depende del despliegue y lo fija docker-compose.yml (command). Sin ellas,
# uvicorn solo confía en 127.0.0.1, que es el valor seguro.
ENTRYPOINT ["uvicorn", "app.principal:aplicacion", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "--no-server-header"]
