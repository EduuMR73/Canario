-- Supresión de denuncias caducadas: el único camino de borrado del sistema.
--
-- Por qué existe: la Ley 2/2023 obliga a borrar.
-- * Art. 32.4: transcurridos tres meses desde la recepción sin que se hayan
--   iniciado actuaciones de investigación, los datos se suprimen; las
--   comunicaciones a las que no se ha dado curso solo pueden constar de forma
--   anonimizada.
-- * Art. 26.2: en ningún caso se conservan más de diez años.
-- El resto del esquema no tiene ningún permiso ni política de DELETE: esta
-- función es la única excepción, con un dueño propio y un criterio fijo.
--
-- Diseño:
-- * El criterio vive en un solo sitio, canal.articulo_supresion(), que recibe
--   las columnas de la fila (estado, fecha) y la zona horaria de su empresa.
--   "Iniciar la investigación" es salir del estado 'nueva'. "Hoy" es el día
--   en la zona de la empresa, con el mismo cálculo que las fechas de
--   recepción (02_esquema.sql): los plazos se cuentan en su calendario.
-- * Lotes acotados (p_lote): todas las sesiones tienen statement_timeout, y un
--   lote pequeño retiene pocos bloqueos y poco tiempo. Quien la invoca repite
--   lotes hasta que uno vuelve vacío (app/gestion.py).
-- * Bloquear antes de borrar, con FOR UPDATE SKIP LOCKED, en su propia
--   sentencia:
--   - Una denuncia en uso (el personal la está cambiando, o llega un mensaje)
--     no se espera: se salta y entra en la ejecución siguiente. La supresión
--     nunca aborta por concurrencia normal ni retiene a la API.
--   - En READ COMMITTED, FOR UPDATE vuelve a evaluar el WHERE sobre la versión
--     actual de la fila. Por eso el criterio se aplica sobre las columnas de
--     la propia fila y no sobre una lista calculada aparte: una denuncia que
--     acaba de pasar a en_instruccion deja de cumplirlo y no se borra.
--   - Cada sentencia posterior toma una foto nueva, ya con los bloqueos
--     puestos: un mensaje confirmado justo antes del bloqueo se ve y se borra
--     con su denuncia, y uno posterior espera al bloqueo (preparar_mensaje) y
--     después no encuentra la denuncia. Por eso se exige READ COMMITTED: con
--     una foto fija para toda la transacción, ese mensaje quedaría huérfano y
--     la clave foránea abortaría el lote.
-- * Orden de borrado: mensajes, código de seguimiento y denuncia, por las
--   claves foráneas (todas NO ACTION).
-- * Evidencia anonimizada (art. 32.4, "dejar evidencia del funcionamiento del
--   sistema"): una fila de auditoría por denuncia suprimida, con actor
--   'sistema', la acción supresion_art32 o supresion_art26 y el id de la
--   denuncia. El id es un uuid aleatorio que, tras el borrado, no apunta a
--   ningún dato; sin esa fila, un borrado legítimo no se distinguiría de una
--   manipulación.
-- * Orden de bloqueos: primero las filas de las denuncias y después el
--   bloqueo consultivo de la auditoría de cada empresa. Cualquier transacción
--   del personal que toque una denuncia y la auditoría debe seguir el mismo
--   orden (denuncia antes que auditoría), o podría interbloquearse con esta.
--
-- Permisos de propietario_supresion (nada más):
-- * Bloquear una fila exige UPDATE sobre alguna columna (comprobado en la
--   imagen fijada: con SELECT y DELETE, FOR UPDATE da "permission denied").
--   Recibe UPDATE (estado) y una política de UPDATE con WITH CHECK (false):
--   puede bloquear, pero cualquier UPDATE real lo rechaza la RLS. Sin esa
--   política, FOR UPDATE no da error: devuelve cero filas en silencio (también
--   comprobado), y la supresión no borraría nada.
-- * Solo las columnas que lee, DELETE en las tres tablas que borra e INSERT
--   en la auditoría (el trigger de encadenado lee la última fila y la zona de
--   la empresa con los permisos de quien inserta).
-- * plataforma, el rol del servicio gestion, es el único con EXECUTE. La API
--   (aplicacion) no puede borrar nada.
--
-- Límites asumidos:
-- * La auditoría es inmutable: conserva los ids del personal que actuó sobre
--   una denuncia más allá de los diez años. Anonimizarlos rompería la cadena
--   de hashes.
-- * La función no se programa sola: hay que ejecutarla periódicamente (por
--   ejemplo, cada día) con docker compose run --rm gestion suprimir-caducadas.
--
-- Como 03_funciones.sql: lo ejecuta el superusuario, en una sola transacción.
-- Estas funciones no heredan el ALTER DEFAULT PRIVILEGES de migrador, así que
-- cada una lleva su REVOKE explícito antes de cambiar el dueño.

\set ON_ERROR_STOP on
BEGIN;

-- ---------------------------------------------------------------------------
-- Permisos y políticas de propietario_supresion
-- ---------------------------------------------------------------------------

GRANT USAGE ON SCHEMA canal TO propietario_supresion;

-- Zona horaria de cada empresa, para calcular su "hoy".
GRANT SELECT (id, zona_horaria) ON canal.empresa TO propietario_supresion;
CREATE POLICY empresa_select_supresion ON canal.empresa
    FOR SELECT TO propietario_supresion
    USING (true);

-- Denuncia: leer el criterio, bloquear y borrar.
GRANT SELECT (empresa_id, id, fecha, estado) ON canal.denuncia TO propietario_supresion;
GRANT UPDATE (estado) ON canal.denuncia TO propietario_supresion;
GRANT DELETE ON canal.denuncia TO propietario_supresion;
CREATE POLICY denuncia_select_supresion ON canal.denuncia
    FOR SELECT TO propietario_supresion
    USING (true);
-- Solo para poder bloquear con FOR UPDATE: WITH CHECK (false) rechaza
-- cualquier UPDATE real.
CREATE POLICY denuncia_bloqueo_supresion ON canal.denuncia
    FOR UPDATE TO propietario_supresion
    USING (true)
    WITH CHECK (false);
CREATE POLICY denuncia_delete_supresion ON canal.denuncia
    FOR DELETE TO propietario_supresion
    USING (true);

GRANT SELECT (empresa_id, denuncia_id) ON canal.mensaje TO propietario_supresion;
GRANT DELETE ON canal.mensaje TO propietario_supresion;
CREATE POLICY mensaje_select_supresion ON canal.mensaje
    FOR SELECT TO propietario_supresion
    USING (true);
CREATE POLICY mensaje_delete_supresion ON canal.mensaje
    FOR DELETE TO propietario_supresion
    USING (true);

-- Sin RLS (nadie tiene permisos directos): solo los privilegios.
GRANT SELECT (empresa_id, denuncia_id) ON canal.busqueda_seguimiento TO propietario_supresion;
GRANT DELETE ON canal.busqueda_seguimiento TO propietario_supresion;

-- Auditoría: insertar la evidencia. encadenar_auditoria lee la última fila de
-- la empresa (secuencia y hash) con los permisos de quien inserta.
GRANT SELECT (empresa_id, secuencia, hash) ON canal.registro_auditoria TO propietario_supresion;
GRANT INSERT (empresa_id, actor, accion, objeto_id) ON canal.registro_auditoria TO propietario_supresion;
CREATE POLICY registro_auditoria_select_supresion ON canal.registro_auditoria
    FOR SELECT TO propietario_supresion
    USING (true);
CREATE POLICY registro_auditoria_insert_supresion ON canal.registro_auditoria
    FOR INSERT TO propietario_supresion
    WITH CHECK (true);

-- ---------------------------------------------------------------------------
-- Funciones
-- ---------------------------------------------------------------------------

-- Artículo por el que una denuncia debe suprimirse hoy, o NULL si se
-- conserva. Diez años (art. 26.2) se aplica en cualquier estado y tiene
-- prioridad; tres meses (art. 32.4), solo si sigue en 'nueva'. Los plazos
-- vencen el mismo día del mes (fecha + 3 meses <= hoy): una denuncia del 15 de
-- enero se suprime desde el 15 de abril. Si ese día no existe, PostgreSQL usa
-- el último del mes (31 de agosto + 3 meses = 30 de noviembre).
-- "Hoy" se calcula como las fechas de recepción (02_esquema.sql): el día en la
-- zona de la empresa, sin depender de la zona de la sesión.
-- No es de definidor: la usan las dos funciones de abajo con los permisos de
-- su dueño, que es también el de esta.
CREATE FUNCTION canal.articulo_supresion(p_estado text, p_fecha date, p_zona_horaria text)
RETURNS text
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
    select case
        when (p_fecha + interval '10 years')::date <= (now() AT TIME ZONE p_zona_horaria)::date
            then 'art26'
        when p_estado = 'nueva'
             and (p_fecha + interval '3 months')::date <= (now() AT TIME ZONE p_zona_horaria)::date
            then 'art32'
    end
$$;
REVOKE EXECUTE ON FUNCTION canal.articulo_supresion(text, date, text) FROM PUBLIC;
ALTER FUNCTION canal.articulo_supresion(text, date, text) OWNER TO propietario_supresion;

-- Suprime como mucho p_lote denuncias caducadas, con sus mensajes y su código
-- de seguimiento, y deja una fila de auditoría por cada una. Devuelve cuántas
-- ha suprimido por empresa y artículo; nunca contenido. Ver la cabecera para
-- el porqué de cada paso.
CREATE FUNCTION canal.suprimir_denuncias_caducadas(p_lote integer)
RETURNS TABLE (empresa_id uuid, articulo text, suprimidas bigint)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, canal, pg_temp
AS $$
-- Las columnas de salida (empresa_id, articulo) se llaman como columnas de
-- las tablas: ante la duda, el nombre es siempre la columna, nunca la
-- variable. Todas las referencias van además cualificadas.
#variable_conflict use_column
DECLARE
    v_empresas uuid[];
    v_ids uuid[];
    v_articulos text[];
    v_borradas bigint;
BEGIN
    IF p_lote IS NULL OR p_lote NOT BETWEEN 1 AND 500 THEN
        RAISE EXCEPTION 'el lote debe estar entre 1 y 500'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'la supresion exige el nivel de aislamiento READ COMMITTED'
            USING ERRCODE = 'invalid_transaction_state';
    END IF;

    -- 1. Bloquear las candidatas, saltando las que están en uso. El criterio
    --    va en el WHERE, sobre las columnas de la fila bloqueada.
    SELECT array_agg(c.empresa_id), array_agg(c.id), array_agg(c.articulo)
      INTO v_empresas, v_ids, v_articulos
      FROM (SELECT d.empresa_id, d.id,
                   canal.articulo_supresion(d.estado, d.fecha, e.zona_horaria) AS articulo
              FROM canal.denuncia d
              JOIN canal.empresa e ON e.id = d.empresa_id
             WHERE canal.articulo_supresion(d.estado, d.fecha, e.zona_horaria) IS NOT NULL
             ORDER BY d.empresa_id, d.fecha, d.id
             LIMIT p_lote
               FOR UPDATE OF d SKIP LOCKED) c;

    IF v_ids IS NULL THEN
        RETURN;
    END IF;

    -- 2. Hijos primero, en sentencias separadas: cada una ve lo confirmado
    --    hasta que se tomaron los bloqueos.
    DELETE FROM canal.mensaje m
     USING unnest(v_empresas, v_ids) AS c(empresa_id, id)
     WHERE m.empresa_id = c.empresa_id AND m.denuncia_id = c.id;

    DELETE FROM canal.busqueda_seguimiento b
     USING unnest(v_empresas, v_ids) AS c(empresa_id, id)
     WHERE b.empresa_id = c.empresa_id AND b.denuncia_id = c.id;

    DELETE FROM canal.denuncia d
     USING unnest(v_empresas, v_ids) AS c(empresa_id, id)
     WHERE d.empresa_id = c.empresa_id AND d.id = c.id;
    GET DIAGNOSTICS v_borradas = ROW_COUNT;
    -- Las filas están bloqueadas por esta transacción: si no se borraran
    -- todas, algo no es como se espera y se aborta el lote entero.
    IF v_borradas <> cardinality(v_ids) THEN
        RAISE EXCEPTION 'la supresion no ha borrado todas las denuncias bloqueadas'
            USING ERRCODE = 'internal_error';
    END IF;

    -- 3. Evidencia anonimizada, en orden estable.
    INSERT INTO canal.registro_auditoria (empresa_id, actor, accion, objeto_id)
    SELECT c.empresa_id, 'sistema', 'supresion_' || c.articulo, c.id
      FROM unnest(v_empresas, v_ids, v_articulos) AS c(empresa_id, id, articulo)
     ORDER BY c.empresa_id, c.id;

    RETURN QUERY
    SELECT c.empresa_id, c.articulo, count(*)
      FROM unnest(v_empresas, v_articulos) AS c(empresa_id, articulo)
     GROUP BY c.empresa_id, c.articulo
     ORDER BY c.empresa_id, c.articulo;
END
$$;
REVOKE EXECUTE ON FUNCTION canal.suprimir_denuncias_caducadas(integer) FROM PUBLIC;
ALTER FUNCTION canal.suprimir_denuncias_caducadas(integer) OWNER TO propietario_supresion;
GRANT EXECUTE ON FUNCTION canal.suprimir_denuncias_caducadas(integer) TO plataforma;

-- Cuántas denuncias cumplen hoy el criterio de supresión, con el mismo
-- criterio. Tras vaciar los lotes, lo que quede son denuncias que estaban en
-- uso: gestion lo informa para que no pase en silencio.
CREATE FUNCTION canal.contar_denuncias_caducadas()
RETURNS bigint
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, canal, pg_temp
AS $$
    select count(*)
      from canal.denuncia d
      join canal.empresa e on e.id = d.empresa_id
     where canal.articulo_supresion(d.estado, d.fecha, e.zona_horaria) is not null
$$;
REVOKE EXECUTE ON FUNCTION canal.contar_denuncias_caducadas() FROM PUBLIC;
ALTER FUNCTION canal.contar_denuncias_caducadas() OWNER TO propietario_supresion;
GRANT EXECUTE ON FUNCTION canal.contar_denuncias_caducadas() TO plataforma;

COMMIT;
