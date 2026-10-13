-- Redacción: tachar una parte del texto de una denuncia o de un mensaje.
--
-- Por qué existe: la Ley 2/2023 obliga a suprimir datos concretos dentro de
-- una comunicación, no la comunicación entera.
-- * Art. 32.2: los datos personales que no sean necesarios para conocer e
--   investigar los hechos se suprimen de inmediato; los de categorías
--   especiales, también de inmediato, "sin que se proceda al registro y
--   tratamiento de los mismos"; y los que se refieran a conductas fuera del
--   ámbito de la ley se suprimen.
-- * Art. 29: los datos recopilados por accidente se eliminan sin dilación
--   indebida.
-- El texto se guarda cifrado y entero (02_esquema.sql), así que la base de
-- datos no puede borrar una parte: lo hace la API, que descifra, sustituye
-- cada carácter del fragmento por U+2588 y vuelve a cifrar
-- (app/instruccion.py). Es el modelo de GlobaLeaks (redacción permanente por
-- rangos, con su entrada en el registro).
--
-- Por qué una función y no un permiso de UPDATE para aplicacion:
-- * aplicacion sigue sin poder cambiar el contenido cifrado de nada
--   (02_esquema.sql). La única forma es esta función, que en la misma
--   sentencia escribe la fila de auditoría: una API con un error, o
--   comprometida, no puede reescribir un contenido sin dejar rastro.
-- * La función comprueba por su cuenta lo que la API ya comprobó: que quien
--   actúa es un admin activo y activado y que tiene la denuncia asignada, y
--   que la denuncia no es 'no_veraz'. Es defensa en profundidad frente a un
--   error de lógica de la API, no frente a una API comprometida (que puede
--   pasar el id del admin asignado; entonces queda la fila de auditoría).
-- * Compare-and-swap: solo escribe si el contenido sigue siendo exactamente el
--   que la API leyó (p_anterior). Así una redacción no puede pisar otra
--   concurrente ni aplicarse sobre un contenido distinto del que se tachó.
-- * Lo que la base de datos NO puede comprobar: que el contenido nuevo sea el
--   antiguo con el fragmento tachado, porque está cifrado. Límite documentado
--   en docs/threat-model.md (8).
--
-- Errores: CN003 (clase CN, propia, como en preparar_mensaje) si la denuncia
-- o el mensaje no existen, no están asignados al actor, son 'no_veraz' o su
-- contenido ha cambiado; insufficient_privilege si el actor no es un admin
-- activo y activado. La API los ha comprobado antes con la fila bloqueada, así
-- que cualquiera de los dos indica un error propio y llega como 500.
--
-- Orden de bloqueos: la denuncia (la ha bloqueado ya la API, en la misma
-- transacción) y después el bloqueo consultivo de la auditoría. Es el orden
-- de todo lo demás: cuentas, denuncia y auditoría (02_esquema.sql y
-- 04_supresion.sql).
--
-- Como 04_supresion.sql: lo ejecuta el superusuario, en una sola transacción,
-- y cada función lleva su REVOKE explícito antes de cambiar el dueño.

\set ON_ERROR_STOP on
BEGIN;

-- ---------------------------------------------------------------------------
-- Permisos y políticas de propietario_redaccion
-- ---------------------------------------------------------------------------

-- Todas las políticas comparan con canal.empresa_actual(): a diferencia de la
-- supresión, que recorre todas las empresas, la redacción actúa siempre dentro
-- del contexto de la empresa de quien la pide.
GRANT USAGE ON SCHEMA canal TO propietario_redaccion;
GRANT EXECUTE ON FUNCTION canal.empresa_actual() TO propietario_redaccion;

-- La zona horaria de la empresa: la lee encadenar_auditoria con los permisos
-- de quien inserta, para fechar la fila.
GRANT SELECT (id, zona_horaria) ON canal.empresa TO propietario_redaccion;
CREATE POLICY empresa_select_redaccion ON canal.empresa
    FOR SELECT TO propietario_redaccion
    USING (id = canal.empresa_actual());

-- Quién actúa: admin, activo y activado.
GRANT SELECT (empresa_id, id, rol, activo, totp_activo) ON canal.usuario_personal TO propietario_redaccion;
CREATE POLICY usuario_personal_select_redaccion ON canal.usuario_personal
    FOR SELECT TO propietario_redaccion
    USING (empresa_id = canal.empresa_actual());

-- Denuncia: leer el criterio y el contenido anterior, bloquear y reescribir
-- solo el contenido y su versión de clave.
GRANT SELECT (empresa_id, id, estado, asignada_a, contenido_cifrado) ON canal.denuncia TO propietario_redaccion;
GRANT UPDATE (contenido_cifrado, version_clave) ON canal.denuncia TO propietario_redaccion;
CREATE POLICY denuncia_select_redaccion ON canal.denuncia
    FOR SELECT TO propietario_redaccion
    USING (empresa_id = canal.empresa_actual());
CREATE POLICY denuncia_update_redaccion ON canal.denuncia
    FOR UPDATE TO propietario_redaccion
    USING (empresa_id = canal.empresa_actual())
    WITH CHECK (empresa_id = canal.empresa_actual());

-- Mensaje: lo mismo, por su secuencia dentro de la denuncia.
GRANT SELECT (empresa_id, denuncia_id, secuencia, id, contenido_cifrado) ON canal.mensaje TO propietario_redaccion;
GRANT UPDATE (contenido_cifrado, version_clave) ON canal.mensaje TO propietario_redaccion;
CREATE POLICY mensaje_select_redaccion ON canal.mensaje
    FOR SELECT TO propietario_redaccion
    USING (empresa_id = canal.empresa_actual());
CREATE POLICY mensaje_update_redaccion ON canal.mensaje
    FOR UPDATE TO propietario_redaccion
    USING (empresa_id = canal.empresa_actual())
    WITH CHECK (empresa_id = canal.empresa_actual());

-- Auditoría: insertar la fila de la redacción. encadenar_auditoria lee la
-- última fila de la empresa (secuencia y hash) con los permisos de quien
-- inserta.
GRANT SELECT (empresa_id, secuencia, hash) ON canal.registro_auditoria TO propietario_redaccion;
GRANT INSERT (empresa_id, actor, accion, objeto_id, destino_id) ON canal.registro_auditoria TO propietario_redaccion;
CREATE POLICY registro_auditoria_select_redaccion ON canal.registro_auditoria
    FOR SELECT TO propietario_redaccion
    USING (empresa_id = canal.empresa_actual());
CREATE POLICY registro_auditoria_insert_redaccion ON canal.registro_auditoria
    FOR INSERT TO propietario_redaccion
    WITH CHECK (empresa_id = canal.empresa_actual());

-- ---------------------------------------------------------------------------
-- Funciones
-- ---------------------------------------------------------------------------

-- Sustituye el contenido cifrado de una denuncia asignada a p_actor por
-- p_nuevo (cifrado con la versión p_version) si sigue siendo p_anterior, y
-- deja la fila redaccion_denuncia. Ver la cabecera.
CREATE FUNCTION canal.redactar_denuncia(p_denuncia_id uuid, p_actor uuid, p_anterior bytea, p_nuevo bytea,
                                        p_version integer)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, canal, pg_temp
AS $$
DECLARE
    v_empresa uuid := canal.empresa_actual();
    v_filas bigint;
BEGIN
    PERFORM 1
       FROM canal.usuario_personal u
      WHERE u.empresa_id = v_empresa AND u.id = p_actor
        AND u.rol = 'admin' AND u.activo AND u.totp_activo;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'la redaccion exige un admin activo de la empresa'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    UPDATE canal.denuncia d
       SET contenido_cifrado = p_nuevo, version_clave = p_version
     WHERE d.empresa_id = v_empresa AND d.id = p_denuncia_id
       AND d.asignada_a = p_actor AND d.estado <> 'no_veraz'
       AND d.contenido_cifrado = p_anterior;
    GET DIAGNOSTICS v_filas = ROW_COUNT;
    IF v_filas <> 1 THEN
        RAISE EXCEPTION 'la denuncia no se puede redactar: no esta asignada al actor o su contenido ha cambiado'
            USING ERRCODE = 'CN003';
    END IF;

    INSERT INTO canal.registro_auditoria (empresa_id, actor, accion, objeto_id)
    VALUES (v_empresa, 'personal:' || p_actor, 'redaccion_denuncia', p_denuncia_id);
END
$$;
REVOKE EXECUTE ON FUNCTION canal.redactar_denuncia(uuid, uuid, bytea, bytea, integer) FROM PUBLIC;
ALTER FUNCTION canal.redactar_denuncia(uuid, uuid, bytea, bytea, integer) OWNER TO propietario_redaccion;
GRANT EXECUTE ON FUNCTION canal.redactar_denuncia(uuid, uuid, bytea, bytea, integer) TO aplicacion;

-- Lo mismo para el mensaje p_secuencia de una denuncia asignada a p_actor. La
-- fila redaccion_mensaje lleva la denuncia como objeto y el id del mensaje
-- como destino: los dos entran en el hash encadenado. La denuncia se bloquea
-- antes (FOR NO KEY UPDATE, como preparar_mensaje), para que el orden de
-- bloqueos sea el de siempre aunque la API no lo hubiera hecho.
CREATE FUNCTION canal.redactar_mensaje(p_denuncia_id uuid, p_secuencia integer, p_actor uuid, p_anterior bytea,
                                       p_nuevo bytea, p_version integer)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, canal, pg_temp
AS $$
DECLARE
    v_empresa uuid := canal.empresa_actual();
    v_mensaje uuid;
BEGIN
    PERFORM 1
       FROM canal.usuario_personal u
      WHERE u.empresa_id = v_empresa AND u.id = p_actor
        AND u.rol = 'admin' AND u.activo AND u.totp_activo;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'la redaccion exige un admin activo de la empresa'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    PERFORM 1
       FROM canal.denuncia d
      WHERE d.empresa_id = v_empresa AND d.id = p_denuncia_id
        AND d.asignada_a = p_actor AND d.estado <> 'no_veraz'
        FOR NO KEY UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'el mensaje no se puede redactar: la denuncia no esta asignada al actor'
            USING ERRCODE = 'CN003';
    END IF;

    UPDATE canal.mensaje m
       SET contenido_cifrado = p_nuevo, version_clave = p_version
     WHERE m.empresa_id = v_empresa AND m.denuncia_id = p_denuncia_id
       AND m.secuencia = p_secuencia AND m.contenido_cifrado = p_anterior
    RETURNING m.id INTO v_mensaje;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'el mensaje no se puede redactar: no existe o su contenido ha cambiado'
            USING ERRCODE = 'CN003';
    END IF;

    INSERT INTO canal.registro_auditoria (empresa_id, actor, accion, objeto_id, destino_id)
    VALUES (v_empresa, 'personal:' || p_actor, 'redaccion_mensaje', p_denuncia_id, v_mensaje);
END
$$;
REVOKE EXECUTE ON FUNCTION canal.redactar_mensaje(uuid, integer, uuid, bytea, bytea, integer) FROM PUBLIC;
ALTER FUNCTION canal.redactar_mensaje(uuid, integer, uuid, bytea, bytea, integer) OWNER TO propietario_redaccion;
GRANT EXECUTE ON FUNCTION canal.redactar_mensaje(uuid, integer, uuid, bytea, bytea, integer) TO aplicacion;

COMMIT;
