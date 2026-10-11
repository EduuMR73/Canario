-- Funciones de definidor del esquema "canal" y los permisos mínimos que
-- necesitan.
--
-- Por qué existen: el denunciante llega a la página de su empresa o con su
-- código de seguimiento sin saber a qué empresa pertenece, y por tanto sin
-- contexto de empresa. Las tablas directorio_empresas y busqueda_seguimiento
-- no tienen permisos directos para nadie (la API no puede listarlas ni
-- consultarlas a mano), así que el único camino es un puñado de funciones
-- pequeñas y fijas que se ejecutan con los permisos de su dueño,
-- propietario_funciones, y no con los de quien las llama.
--
-- Diseño y límites:
-- * propietario_funciones es un rol sin LOGIN: nadie puede conectarse con él.
--   Ve todas las filas de empresa (políticas con true) y puede escribir en
--   directorio_empresas y busqueda_seguimiento, pero solo dentro de las
--   funciones, que son las que fijan qué consulta se ejecuta. No tiene ningún
--   permiso sobre clave_empresa, usuario_personal, denuncia, mensaje ni
--   registro_auditoria. El rol plataforma no recibe ningún permiso sobre
--   tablas: solo EXECUTE sobre alta_empresa.
-- * buscar_codigo IGNORA el contexto de empresa por diseño: el denunciante
--   aún no sabe a qué empresa pertenece, y la función es lo que se lo dice.
--   Conocer el par (empresa, denuncia) no da acceso a nada: para leer la
--   denuncia sigue haciendo falta el contexto de esa empresa, y la RLS lo
--   comprueba.
-- * registrar_codigo toma la empresa SOLO de empresa_actual(), nunca de un
--   parámetro, y deja que las claves foráneas compuestas, el CHECK de longitud
--   y los UNIQUE decidan, sin capturar sus errores: así una denuncia ajena y
--   una inexistente dan exactamente el mismo error. Si el mismo HMAC se
--   repitiera en otra empresa, daría clave duplicada; es despreciable con 256
--   bits.
-- * alta_empresa no crea la clave de la empresa ni su administrador: eso lo
--   hace la API con el rol aplicacion y el contexto de la empresa nueva.
-- * Cada función fija su search_path (con pg_temp al final, para que nadie
--   pueda suplantar tablas con una temporal) y cualifica todos los objetos con
--   canal. Eso las protege del ataque clásico contra las funciones de
--   definidor.
-- * ALTER DEFAULT PRIVILEGES de 02_esquema.sql solo cubre los objetos que cree
--   migrador. Estas funciones las crea el superusuario, así que NO heredan ese
--   ajuste y nacen con EXECUTE para PUBLIC: el REVOKE explícito en cada una es
--   obligatorio, y va antes de cambiar el dueño y de conceder lo mínimo.
--
-- Todo va en una sola transacción y sin cambiar de rol: el entrypoint ejecuta
-- este fichero como superusuario, que crea las funciones y les cambia el dueño
-- (el superusuario puede hacerlo aunque el nuevo dueño no tenga CREATE en el
-- esquema).

\set ON_ERROR_STOP on
BEGIN;

-- ---------------------------------------------------------------------------
-- Permisos y políticas de propietario_funciones (nada más)
-- ---------------------------------------------------------------------------

-- Las políticas de empresa llaman a empresa_actual(), y una función de
-- definidor ejecuta registrar_codigo con los permisos de su dueño: por eso el
-- dueño necesita EXECUTE sobre empresa_actual().
GRANT EXECUTE ON FUNCTION canal.empresa_actual() TO propietario_funciones;

-- alta_empresa inserta una empresa (nombre y zona horaria) y devuelve su id, y
-- resolver_empresa lee si está activa. Solo esas columnas, y políticas
-- explícitas porque la tabla tiene RLS con FORCE.
GRANT SELECT (id, activa) ON canal.empresa TO propietario_funciones;
GRANT INSERT (nombre, zona_horaria) ON canal.empresa TO propietario_funciones;
CREATE POLICY empresa_select_definidor ON canal.empresa
    FOR SELECT TO propietario_funciones
    USING (true);
CREATE POLICY empresa_insert_definidor ON canal.empresa
    FOR INSERT TO propietario_funciones
    WITH CHECK (true);

-- El identificador público lo genera la base de datos (valor por defecto), así
-- que alta_empresa solo escribe empresa_id.
GRANT SELECT ON canal.directorio_empresas TO propietario_funciones;
GRANT INSERT (empresa_id) ON canal.directorio_empresas TO propietario_funciones;

GRANT SELECT, INSERT ON canal.busqueda_seguimiento TO propietario_funciones;

-- ---------------------------------------------------------------------------
-- Funciones
-- ---------------------------------------------------------------------------

-- Devuelve el id de la empresa con ese identificador público, o NULL en
-- cualquier otro caso (desconocido, mal formado, NULL o empresa inactiva), sin
-- lanzar errores por la entrada: la respuesta no distingue por qué no hay
-- empresa, para que nadie pueda sondear el directorio.
CREATE FUNCTION canal.resolver_empresa(p_identificador text) RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, canal, pg_temp
AS $$
    select d.empresa_id
      from canal.directorio_empresas d
      join canal.empresa e on e.id = d.empresa_id
     where d.identificador_publico = p_identificador
       and e.activa
$$;
REVOKE EXECUTE ON FUNCTION canal.resolver_empresa(text) FROM PUBLIC;
ALTER FUNCTION canal.resolver_empresa(text) OWNER TO propietario_funciones;
GRANT EXECUTE ON FUNCTION canal.resolver_empresa(text) TO aplicacion;

-- Traduce el HMAC de un código de seguimiento a (empresa, denuncia). Sin filas
-- si no existe. No mira el contexto de empresa (ver la cabecera).
CREATE FUNCTION canal.buscar_codigo(p_codigo_hmac bytea)
RETURNS TABLE (empresa_id uuid, denuncia_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, canal, pg_temp
AS $$
    select b.empresa_id, b.denuncia_id
      from canal.busqueda_seguimiento b
     where b.codigo_hmac = p_codigo_hmac
$$;
REVOKE EXECUTE ON FUNCTION canal.buscar_codigo(bytea) FROM PUBLIC;
ALTER FUNCTION canal.buscar_codigo(bytea) OWNER TO propietario_funciones;
GRANT EXECUTE ON FUNCTION canal.buscar_codigo(bytea) TO aplicacion;

-- Registra el HMAC del código de seguimiento de una denuncia de la empresa del
-- contexto. La empresa sale solo de empresa_actual(): sin contexto no hay
-- empresa y se rechaza con un error propio. El resto de errores (clave
-- foránea, longitud del HMAC, duplicados) son los de la tabla, sin capturar.
CREATE FUNCTION canal.registrar_codigo(p_codigo_hmac bytea, p_denuncia_id uuid)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, canal, pg_temp
AS $$
DECLARE
    v_empresa uuid;
BEGIN
    v_empresa := canal.empresa_actual();
    IF v_empresa IS NULL THEN
        RAISE EXCEPTION 'registrar_codigo requiere contexto de empresa'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    INSERT INTO canal.busqueda_seguimiento (codigo_hmac, empresa_id, denuncia_id)
    VALUES (p_codigo_hmac, v_empresa, p_denuncia_id);
END
$$;
REVOKE EXECUTE ON FUNCTION canal.registrar_codigo(bytea, uuid) FROM PUBLIC;
ALTER FUNCTION canal.registrar_codigo(bytea, uuid) OWNER TO propietario_funciones;
GRANT EXECUTE ON FUNCTION canal.registrar_codigo(bytea, uuid) TO aplicacion;

-- Da de alta una empresa y su entrada en el directorio, y devuelve el id y el
-- identificador público. Una sola sentencia con CTE: la clave foránea se
-- comprueba al final, con las dos filas ya insertadas. Solo la ejecuta
-- plataforma. No crea clave ni administrador (ver la cabecera).
-- La zona horaria es obligatoria y explícita, sin valor por defecto en la
-- firma: quien da de alta decide el calendario de la empresa. El CHECK de la
-- tabla rechaza cualquier zona que no sea de España, y NULL lo rechaza NOT
-- NULL.
CREATE FUNCTION canal.alta_empresa(p_nombre text, p_zona_horaria text)
RETURNS TABLE (empresa_id uuid, identificador_publico text)
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, canal, pg_temp
AS $$
    with nueva as (
        insert into canal.empresa (nombre, zona_horaria)
        values (p_nombre, p_zona_horaria)
        returning id
    ),
    registrada as (
        insert into canal.directorio_empresas as d (empresa_id)
        select nueva.id from nueva
        returning d.empresa_id, d.identificador_publico
    )
    select r.empresa_id, r.identificador_publico from registrada r
$$;
REVOKE EXECUTE ON FUNCTION canal.alta_empresa(text, text) FROM PUBLIC;
ALTER FUNCTION canal.alta_empresa(text, text) OWNER TO propietario_funciones;
GRANT EXECUTE ON FUNCTION canal.alta_empresa(text, text) TO plataforma;

COMMIT;
