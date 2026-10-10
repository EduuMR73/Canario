#!/bin/sh
# Inicialización de roles y privilegios de la base de datos de Canario.
#
# Qué hace: crea los tres roles de login (migrador, aplicacion, plataforma) y
# el rol sin login propietario_funciones, deja la base canario en manos de
# migrador y cierra los permisos por defecto de PUBLIC.
#
# Cuándo corre: el entrypoint de la imagen ejecuta los scripts de
# /docker-entrypoint-initdb.d SOLO cuando el volumen de datos está vacío, es
# decir, en el primer arranque. Si el volumen ya existe, se los salta sin
# aviso. Por eso el healthcheck del compose comprueba que existen los cuatro
# roles: la lista de roles está también allí y debe mantenerse igual.
#
# Contraseñas: se leen de /run/secrets con \set y comillas invertidas dentro
# de psql, y se interpolan con :'variable'. Así no pasan como argumento de
# ningún proceso (no salen en `ps` ni en /proc/*/cmdline) y tampoco quedan en
# el entorno. Ninguna contraseña, ni literal ni de ejemplo, aparece en este
# fichero.
#
# \set VERBOSITY terse: un error de sintaxis de psql repite la sentencia
# entera con la contraseña ya interpolada. En modo terse solo se muestra el
# mensaje de error, sin la línea de la sentencia.
#
# Por qué "set -e" y no "set -u" ni "exec": según el bit de ejecución del
# fichero, el entrypoint lo ejecuta como proceso aparte o lo carga con source
# dentro de su propio shell. Con source, un "exec" sustituiría el shell del
# entrypoint y la inicialización se cortaría; y "set -u" dejaría activo en el
# entrypoint un ajuste que él no espera. "set -e" es válido en ambos casos.
#
# Privilegios: aquí no hay ningún GRANT sobre tablas ni sobre esquemas
# propios. Eso llega con el esquema, en el paso siguiente.
set -e

psql -v ON_ERROR_STOP=1 -q --no-psqlrc --no-password -U "$POSTGRES_USER" -d "$POSTGRES_DB" <<'SQL'
\set VERBOSITY terse

\set contrasena_migrador `cat /run/secrets/contrasena_migrador`
\set contrasena_aplicacion `cat /run/secrets/contrasena_aplicacion`
\set contrasena_plataforma `cat /run/secrets/contrasena_plataforma`

CREATE ROLE migrador LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2 PASSWORD :'contrasena_migrador';
CREATE ROLE aplicacion LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 10 PASSWORD :'contrasena_aplicacion';
CREATE ROLE plataforma LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 3 PASSWORD :'contrasena_plataforma';

-- Será dueña de las funciones SECURITY DEFINER. Sin LOGIN no necesita regla
-- en pg_hba.conf: nadie puede conectarse con ella.
CREATE ROLE propietario_funciones NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

ALTER DATABASE canario OWNER TO migrador;

REVOKE ALL ON DATABASE canario FROM PUBLIC;
REVOKE ALL ON DATABASE postgres FROM PUBLIC;
REVOKE ALL ON DATABASE template1 FROM PUBLIC;
GRANT CONNECT ON DATABASE canario TO migrador, aplicacion, plataforma;

REVOKE ALL ON SCHEMA public FROM PUBLIC;
SQL
