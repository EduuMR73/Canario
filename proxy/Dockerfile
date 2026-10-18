# Imagen del proxy de Canario, en dos etapas. La primera compila la SPA del
# personal con Node; la segunda es la oficial de Caddy con los ficheros ya
# compilados y sin Node: lo que se ejecuta no lleva ni el compilador ni los
# paquetes de npm. Las dos imágenes base, fijadas por versión y por digest
# (índice multiarquitectura).

# Etapa 1: compilación de la SPA (spa/, contexto adicional "spa" del compose).
FROM node:24.20.0-alpine3.23@sha256:0388af2af070cd4736a1567cfed02469ba117848845b4165d87a333edb53d2ca AS compilacion

# Sin telemetría del CLI de Angular ni preguntas interactivas.
ENV NG_CLI_ANALYTICS=false CI=true

# Usuario sin privilegios de la imagen (node, uid 1000): ni npm ni el
# compilador necesitan root.
WORKDIR /spa
RUN chown node:node /spa
USER node

# Solo los ficheros que hacen falta, nombrados uno a uno: el node_modules, el
# dist o la caché de un build local nunca entran en la imagen, sin depender de
# un .dockerignore.
COPY --from=spa --chown=node:node package.json package-lock.json .npmrc ./

# npm ci instala exactamente el lock y falla si no cuadra con package.json.
# --ignore-scripts repite lo que dice .npmrc: si alguien lo quitara de ahí, la
# imagen seguiría sin ejecutar scripts de instalación. audit signatures
# comprueba la firma del registro de cada paquete instalado: falla si alguno
# no la tiene o no cuadra (Angular no publica attestations de procedencia).
RUN npm ci --ignore-scripts --no-audit --no-fund  && npm audit signatures

COPY --from=spa --chown=node:node angular.json tsconfig.json tsconfig.app.json ./
COPY --from=spa --chown=node:node src/ src/
RUN npx ng build

# Etapa 2: la imagen que se ejecuta.
FROM caddy:2.11.7-alpine@sha256:d8542f48d34a9cf4e4c11a478865229840e87e4c96ea3f439101f31a5d35f75f

# 1. setcap -r: el binario oficial lleva la file capability
#    cap_net_bind_service=ep para poder escuchar en 80 y 443 sin root. Aquí
#    Caddy escucha en 8443 (no privilegiado) y no la necesita. Además, con
#    cap_drop ALL el kernel no puede concederla y rechaza el execve
#    ("operation not permitted", comprobado). Se quita la causa en vez de
#    devolver la capability al contenedor.
# 2. /data/caddy guarda el CA local y su clave privada. La imagen lo deja en
#    1777 (escribible por cualquiera); aquí pasa a ser del usuario de Caddy con
#    0700. Un volumen con nombre nuevo hereda el dueño y el modo de la imagen.
# 3. /config/caddy queda de root en 0755: con persist_config off nadie escribe
#    ahí, y el sistema de ficheros raíz además es de solo lectura.
RUN setcap -r /usr/bin/caddy \
 && chown 10002:10002 /data/caddy \
 && chmod 0700 /data/caddy \
 && chown root:root /config/caddy \
 && chmod 0755 /config/caddy

# La configuración va dentro de la imagen, de root y de solo lectura para Caddy:
# no hay montaje que alguien pueda cambiar en caliente.
COPY Caddyfile /etc/caddy/Caddyfile

# Estáticos del sitio del denunciante, por el mismo motivo: dentro de la imagen,
# de root (COPY sin --chown) y, con el sistema de ficheros raíz de solo lectura,
# nadie los puede cambiar en caliente. /srv solo contiene estatico/ y spa/, que
# es lo único que file_server puede servir.
COPY estatico/ /srv/estatico/

# La SPA compilada, igual: de root y de solo lectura. --chown=0:0 es necesario:
# COPY --from conserva el dueño de la etapa de origen (node, 1000:1000;
# comprobado), no lo pone a root como COPY desde el contexto. Solo browser/:
# 3rdpartylicenses.txt, que el build deja al lado, no se sirve.
COPY --from=compilacion --chown=0:0 /spa/dist/canario-spa/browser/ /srv/spa/

# Usuario sin privilegios con uid y gid fijos, distinto del de la API.
USER 10002:10002

# 8443: la API. 8444: el sitio del denunciante. 8445: la SPA del personal.
EXPOSE 8443 8444 8445
