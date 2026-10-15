# Imagen del proxy de Canario: la oficial de Caddy, fijada por versión y por
# digest (índice multiarquitectura), con tres ajustes de mínimo privilegio.
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
# nadie los puede cambiar en caliente. /srv solo contiene estatico/, que es lo
# único que file_server puede servir.
COPY estatico/ /srv/estatico/

# Usuario sin privilegios con uid y gid fijos, distinto del de la API.
USER 10002:10002

# 8443: la API. 8444: el sitio del denunciante.
EXPOSE 8443 8444
