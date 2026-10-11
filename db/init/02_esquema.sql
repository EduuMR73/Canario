-- Esquema "canal" de Canario: tablas, restricciones, RLS, permisos por columna
-- y auditoría encadenada.
--
-- Diseño:
-- * Aislamiento entre empresas por RLS (Row Level Security) con contexto de
--   sesión: la API fija app.empresa_id con set_config(..., true) al abrir cada
--   transacción, y todas las políticas comparan empresa_id con
--   canal.empresa_actual(). Sin contexto, la función devuelve NULL y no se ve
--   ninguna fila: el sistema falla cerrado. Todas las tablas con RLS llevan
--   también FORCE, para que ni siquiera su dueño se salte las políticas.
-- * Claves compuestas (empresa_id, id): las claves foráneas llevan siempre el
--   empresa_id, así que una fila nunca puede apuntar a datos de otra empresa y
--   el error de una referencia ajena es idéntico al de una inexistente (no hay
--   forma de averiguar si un id existe en otra empresa).
-- * Sin marcas de tiempo: las fechas llegan a nivel de día y el orden lo da una
--   secuencia, para no dejar rastro horario que ayude a correlacionar
--   denunciantes. La única excepción es bloqueado_hasta, de las cuentas del
--   personal, que necesita hora para el bloqueo temporal por intentos fallidos.
-- * La fecha es la del calendario de la empresa: cada empresa tiene su zona
--   horaria (solo las de España) y los triggers calculan el día con
--   now() AT TIME ZONE esa zona. La Ley 2/2023 cuenta los plazos desde la
--   recepción por la organización, y su día es el de su calendario, no el de
--   UTC. El cálculo no depende de la zona horaria de la sesión, y lo que traiga
--   el INSERT en la columna fecha se sobrescribe: ni la API ni una sesión
--   manipulada pueden elegir la fecha.
-- * Lo que describe una denuncia (categoría y texto) va cifrado. En claro solo
--   queda lo que el flujo necesita: estado, fecha (día) y asignación.
-- * Auditoría encadenada e inmutable: cada fila de registro_auditoria incluye el
--   hash de la anterior, de modo que cualquier alteración posterior rompe la
--   cadena y verificar_cadena_auditoria() señala dónde. Los triggers rechazan
--   UPDATE, DELETE y TRUNCATE.
-- * Ningún DELETE en el sistema: no hay política ni permiso de borrado, y las
--   claves foráneas son ON DELETE NO ACTION.
--
-- Límites asumidos:
-- * La RLS por variable de sesión no protege frente a una inyección SQL
--   completa: quien pueda ejecutar SQL arbitrario con el rol aplicacion puede
--   fijar app.empresa_id a otra empresa. La defensa es no construir SQL con
--   texto del usuario (consultas parametrizadas) en la API.
-- * "El instructor solo ve sus denuncias asignadas" no se aplica aquí, sino en
--   la API: la base de datos solo garantiza el aislamiento entre empresas.
-- * La inmutabilidad de la auditoría no frena a quien pueda desactivar el
--   trigger (dueño de la tabla o superusuario). Lo que sí garantiza es que
--   modificar una fila, o borrar filas al principio o en medio de la cadena,
--   queda detectable con verificar_cadena_auditoria(). NO detecta que se
--   borren las últimas filas (la cadena restante sigue siendo válida): para
--   eso habría que anclar el último hash fuera de la base de datos (por
--   ejemplo en un registro externo o en una copia firmada), diseño que queda
--   como diseñado, no implementado.
-- * El bloqueo consultivo de encadenar_auditoria se toma en un trigger BEFORE
--   INSERT, es decir, antes de que la RLS compruebe la fila (WITH CHECK). Una
--   sesión con contexto de la empresa A que intente insertar con empresa_id
--   de B toma el bloqueo de B hasta cerrar su transacción, aunque su INSERT
--   falle, y puede retrasar los inserts de auditoría de B. Requiere código de
--   la API comprometido. Los mensajes no tienen este problema: preparar_mensaje
--   no usa bloqueo consultivo, sino el de la fila de su denuncia, que bajo RLS
--   solo se puede tomar sobre denuncias de la empresa del contexto.
--
-- Este paso no crea funciones de definidor, ni políticas para
-- propietario_funciones, ni permisos para plataforma: eso llega en el paso
-- siguiente.
--
-- Todo va en una sola transacción: o se aplica entero o no se aplica nada. El
-- entrypoint de la imagen ejecuta este fichero como superusuario, en orden
-- alfabético y solo con el volumen vacío.

\set ON_ERROR_STOP on
BEGIN;
SET ROLE migrador;

-- ---------------------------------------------------------------------------
-- Esquema
-- ---------------------------------------------------------------------------

-- Dueño migrador. Nadie recibe CREATE: las tablas solo las cambia migrador.
CREATE SCHEMA canal AUTHORIZATION migrador;
REVOKE ALL ON SCHEMA canal FROM PUBLIC;
GRANT USAGE ON SCHEMA canal TO aplicacion, plataforma, propietario_funciones;

-- Por defecto PostgreSQL da EXECUTE a PUBLIC en cada función nueva. Se quita
-- aquí, para todo lo que cree migrador (sin IN SCHEMA: con IN SCHEMA no se
-- puede quitar el valor global). Además, cada función lleva su propio REVOKE
-- explícito, para que el fichero se entienda sin conocer este ajuste.
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- Contexto de empresa
-- ---------------------------------------------------------------------------

-- Si el contexto no está fijado (o es cadena vacía) devuelve NULL: las
-- políticas no encajan con ninguna fila y el resultado son cero filas (falla
-- cerrado). Si es un texto que no es un uuid, el cast falla con un error
-- visible en lugar de dejar pasar en silencio.
CREATE FUNCTION canal.empresa_actual() RETURNS uuid
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
    select nullif(current_setting('app.empresa_id', true), '')::uuid
$$;
REVOKE EXECUTE ON FUNCTION canal.empresa_actual() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION canal.empresa_actual() TO aplicacion;

-- ---------------------------------------------------------------------------
-- Tablas
-- ---------------------------------------------------------------------------

-- zona_horaria: lista cerrada con las zonas de España (península y Baleares,
-- Canarias, Ceuta y Melilla). Un valor que no esté aquí nunca llega a la base
-- de datos, y los triggers de fecha pueden confiar en él.
CREATE TABLE canal.empresa (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    nombre text NOT NULL CHECK (length(btrim(nombre)) BETWEEN 1 AND 200),
    activa boolean NOT NULL DEFAULT true,
    fecha_alta date NOT NULL DEFAULT current_date,
    zona_horaria text NOT NULL DEFAULT 'Europe/Madrid'
        CONSTRAINT empresa_zona_horaria_check
        CHECK (zona_horaria IN ('Europe/Madrid', 'Atlantic/Canary', 'Africa/Ceuta'))
);

-- Traduce el identificador público de la URL de cada empresa a su id interno.
-- Sin RLS y sin permisos para nadie: solo se consultará mediante una función,
-- en el paso siguiente, para que la API no pueda listar empresas.
CREATE TABLE canal.directorio_empresas (
    identificador_publico text PRIMARY KEY
        DEFAULT replace(gen_random_uuid()::text, '-', '')
        CHECK (identificador_publico ~ '^[0-9a-f]{32}$'),
    empresa_id uuid NOT NULL UNIQUE REFERENCES canal.empresa (id)
);

-- Claves de cifrado de cada empresa, siempre envueltas (cifradas con la clave
-- maestra). La versión permite rotarlas sin perder lo cifrado con las antiguas.
CREATE TABLE canal.clave_empresa (
    empresa_id uuid NOT NULL REFERENCES canal.empresa (id),
    version integer NOT NULL CHECK (version > 0),
    clave_envuelta bytea NOT NULL CHECK (octet_length(clave_envuelta) > 0),
    PRIMARY KEY (empresa_id, version)
);

CREATE TABLE canal.usuario_personal (
    empresa_id uuid NOT NULL REFERENCES canal.empresa (id),
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    email text NOT NULL CHECK (
        email = lower(email)
        AND length(email) BETWEEN 3 AND 254
        AND position('@' in email) > 1
    ),
    hash_contrasena text NOT NULL,
    rol text NOT NULL CHECK (rol IN ('admin', 'instructor')),
    secreto_totp_cifrado bytea,
    totp_activo boolean NOT NULL DEFAULT false,
    intentos_fallidos integer NOT NULL DEFAULT 0 CHECK (intentos_fallidos >= 0),
    bloqueado_hasta timestamptz,
    activo boolean NOT NULL DEFAULT true,
    PRIMARY KEY (empresa_id, id),
    UNIQUE (empresa_id, email)
);

-- El id lo genera la API: lo necesita antes de cifrar, porque forma parte del
-- AAD (app/cripto.py). fecha la fija siempre el trigger denuncia_fecha, sin
-- valor por defecto: si el trigger no pudiera calcularla, NOT NULL lo
-- rechazaría en vez de guardar otra fecha en silencio. La categoría va dentro
-- de contenido_cifrado.
CREATE TABLE canal.denuncia (
    empresa_id uuid NOT NULL REFERENCES canal.empresa (id),
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    fecha date NOT NULL,
    estado text NOT NULL DEFAULT 'nueva'
        CHECK (estado IN ('nueva', 'en_instruccion', 'resuelta', 'archivada')),
    asignada_a uuid,
    contenido_cifrado bytea NOT NULL CHECK (octet_length(contenido_cifrado) > 0),
    version_clave integer NOT NULL,
    PRIMARY KEY (empresa_id, id),
    -- Compuestas: la asignación y la clave tienen que ser de la misma empresa.
    FOREIGN KEY (empresa_id, asignada_a) REFERENCES canal.usuario_personal (empresa_id, id),
    FOREIGN KEY (empresa_id, version_clave) REFERENCES canal.clave_empresa (empresa_id, version)
);

-- id: identifica el mensaje en el AAD de su cifrado (app/cripto.py). La
-- secuencia no sirve, porque la asigna el trigger después de cifrar. Sin un id
-- dentro del AAD, un mensaje se podría duplicar en otra fila o intercambiar con
-- otro de la misma denuncia sin que el descifrado lo notara. UNIQUE con
-- empresa_id, como el resto: un duplicado nunca revela datos de otra empresa.
-- secuencia y fecha las fija siempre el trigger mensaje_preparar, sin valor
-- por defecto: si no pudiera calcularlas, NOT NULL lo rechazaría. El trigger
-- también impone que la denuncia esté abierta y el tope de mensajes.
CREATE TABLE canal.mensaje (
    empresa_id uuid NOT NULL,
    denuncia_id uuid NOT NULL,
    secuencia integer NOT NULL,
    fecha date NOT NULL,
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    autor text NOT NULL CHECK (autor IN ('denunciante', 'personal')),
    autor_id uuid,
    contenido_cifrado bytea NOT NULL CHECK (octet_length(contenido_cifrado) > 0),
    version_clave integer NOT NULL,
    PRIMARY KEY (empresa_id, denuncia_id, secuencia),
    UNIQUE (empresa_id, denuncia_id, id),
    -- El personal siempre tiene autor_id; el denunciante, nunca (es anónimo).
    CHECK ((autor = 'personal') = (autor_id IS NOT NULL)),
    FOREIGN KEY (empresa_id, denuncia_id) REFERENCES canal.denuncia (empresa_id, id),
    FOREIGN KEY (empresa_id, autor_id) REFERENCES canal.usuario_personal (empresa_id, id),
    FOREIGN KEY (empresa_id, version_clave) REFERENCES canal.clave_empresa (empresa_id, version)
);

-- Traduce el código de seguimiento (solo su HMAC) a la denuncia. Sin RLS y sin
-- permisos para nadie: solo se consultará mediante una función, en el paso
-- siguiente, porque el denunciante llega sin saber a qué empresa pertenece.
CREATE TABLE canal.busqueda_seguimiento (
    codigo_hmac bytea PRIMARY KEY CHECK (octet_length(codigo_hmac) = 32),
    empresa_id uuid NOT NULL,
    denuncia_id uuid NOT NULL,
    UNIQUE (empresa_id, denuncia_id),
    FOREIGN KEY (empresa_id, denuncia_id) REFERENCES canal.denuncia (empresa_id, id)
);

-- secuencia, fecha, hash_anterior y hash los fija siempre el trigger de
-- encadenado; lo que traiga el INSERT en esas columnas se sobrescribe.
CREATE TABLE canal.registro_auditoria (
    empresa_id uuid NOT NULL REFERENCES canal.empresa (id),
    secuencia bigint NOT NULL,
    fecha date NOT NULL,
    actor text NOT NULL CHECK (length(actor) BETWEEN 1 AND 100),
    accion text NOT NULL CHECK (length(accion) BETWEEN 1 AND 100),
    objeto_id uuid,
    hash_anterior bytea,
    hash bytea NOT NULL,
    PRIMARY KEY (empresa_id, secuencia)
);

-- ---------------------------------------------------------------------------
-- Row Level Security
-- ---------------------------------------------------------------------------

-- ENABLE activa las políticas y FORCE las aplica también al dueño de la tabla.
-- directorio_empresas y busqueda_seguimiento no llevan RLS porque nadie tiene
-- permisos sobre ellas: el acceso será solo por funciones.
ALTER TABLE canal.empresa ENABLE ROW LEVEL SECURITY;
ALTER TABLE canal.empresa FORCE ROW LEVEL SECURITY;
ALTER TABLE canal.clave_empresa ENABLE ROW LEVEL SECURITY;
ALTER TABLE canal.clave_empresa FORCE ROW LEVEL SECURITY;
ALTER TABLE canal.usuario_personal ENABLE ROW LEVEL SECURITY;
ALTER TABLE canal.usuario_personal FORCE ROW LEVEL SECURITY;
ALTER TABLE canal.denuncia ENABLE ROW LEVEL SECURITY;
ALTER TABLE canal.denuncia FORCE ROW LEVEL SECURITY;
ALTER TABLE canal.mensaje ENABLE ROW LEVEL SECURITY;
ALTER TABLE canal.mensaje FORCE ROW LEVEL SECURITY;
ALTER TABLE canal.registro_auditoria ENABLE ROW LEVEL SECURITY;
ALTER TABLE canal.registro_auditoria FORCE ROW LEVEL SECURITY;

-- Una política por comando y ninguna de DELETE ni ALL: lo que no tiene política
-- queda denegado. SELECT lleva USING, INSERT lleva WITH CHECK y UPDATE lleva
-- ambos (la fila antigua y la nueva tienen que ser de la empresa del contexto).
CREATE POLICY empresa_select ON canal.empresa
    FOR SELECT TO aplicacion
    USING (id = canal.empresa_actual());

CREATE POLICY clave_empresa_select ON canal.clave_empresa
    FOR SELECT TO aplicacion
    USING (empresa_id = canal.empresa_actual());
CREATE POLICY clave_empresa_insert ON canal.clave_empresa
    FOR INSERT TO aplicacion
    WITH CHECK (empresa_id = canal.empresa_actual());

CREATE POLICY usuario_personal_select ON canal.usuario_personal
    FOR SELECT TO aplicacion
    USING (empresa_id = canal.empresa_actual());
CREATE POLICY usuario_personal_insert ON canal.usuario_personal
    FOR INSERT TO aplicacion
    WITH CHECK (empresa_id = canal.empresa_actual());
CREATE POLICY usuario_personal_update ON canal.usuario_personal
    FOR UPDATE TO aplicacion
    USING (empresa_id = canal.empresa_actual())
    WITH CHECK (empresa_id = canal.empresa_actual());

CREATE POLICY denuncia_select ON canal.denuncia
    FOR SELECT TO aplicacion
    USING (empresa_id = canal.empresa_actual());
CREATE POLICY denuncia_insert ON canal.denuncia
    FOR INSERT TO aplicacion
    WITH CHECK (empresa_id = canal.empresa_actual());
CREATE POLICY denuncia_update ON canal.denuncia
    FOR UPDATE TO aplicacion
    USING (empresa_id = canal.empresa_actual())
    WITH CHECK (empresa_id = canal.empresa_actual());

CREATE POLICY mensaje_select ON canal.mensaje
    FOR SELECT TO aplicacion
    USING (empresa_id = canal.empresa_actual());
CREATE POLICY mensaje_insert ON canal.mensaje
    FOR INSERT TO aplicacion
    WITH CHECK (empresa_id = canal.empresa_actual());

CREATE POLICY registro_auditoria_select ON canal.registro_auditoria
    FOR SELECT TO aplicacion
    USING (empresa_id = canal.empresa_actual());
CREATE POLICY registro_auditoria_insert ON canal.registro_auditoria
    FOR INSERT TO aplicacion
    WITH CHECK (empresa_id = canal.empresa_actual());

-- ---------------------------------------------------------------------------
-- Permisos sobre tablas
-- ---------------------------------------------------------------------------

-- REVOKE explícito a PUBLIC en cada tabla, y después solo lo imprescindible
-- para aplicacion. Nunca DELETE, TRUNCATE ni REFERENCES a nadie. UPDATE va por
-- columna: así, por ejemplo, nadie puede cambiar el contenido cifrado de una
-- denuncia ni el rol o el email de un usuario, ni mover filas de empresa.
REVOKE ALL ON TABLE canal.empresa FROM PUBLIC;
REVOKE ALL ON TABLE canal.directorio_empresas FROM PUBLIC;
REVOKE ALL ON TABLE canal.clave_empresa FROM PUBLIC;
REVOKE ALL ON TABLE canal.usuario_personal FROM PUBLIC;
REVOKE ALL ON TABLE canal.denuncia FROM PUBLIC;
REVOKE ALL ON TABLE canal.mensaje FROM PUBLIC;
REVOKE ALL ON TABLE canal.busqueda_seguimiento FROM PUBLIC;
REVOKE ALL ON TABLE canal.registro_auditoria FROM PUBLIC;

GRANT SELECT ON canal.empresa TO aplicacion;
GRANT SELECT, INSERT ON canal.clave_empresa TO aplicacion;
GRANT SELECT, INSERT ON canal.usuario_personal TO aplicacion;
GRANT UPDATE (hash_contrasena, secreto_totp_cifrado, totp_activo, intentos_fallidos, bloqueado_hasta, activo)
    ON canal.usuario_personal TO aplicacion;
GRANT SELECT, INSERT ON canal.denuncia TO aplicacion;
GRANT UPDATE (estado, asignada_a) ON canal.denuncia TO aplicacion;
GRANT SELECT, INSERT ON canal.mensaje TO aplicacion;
GRANT SELECT, INSERT ON canal.registro_auditoria TO aplicacion;

-- ---------------------------------------------------------------------------
-- Funciones de trigger y de verificación
-- ---------------------------------------------------------------------------

-- Todas son de migrador, se ejecutan con los permisos de quien las invoca
-- (no de su dueño) y fijan su search_path para que nadie pueda suplantar
-- objetos del sistema. Un trigger no necesita EXECUTE para dispararse, así que
-- solo verificar_cadena_auditoria, que se llama a mano, se concede a aplicacion.

-- Encadena cada fila de auditoría con la anterior de su empresa. El bloqueo
-- consultivo por empresa serializa los INSERT concurrentes de esa empresa (si
-- no, dos transacciones leerían la misma "última fila" y bifurcarían la
-- cadena) sin frenar a las demás empresas. Sobrescribe siempre secuencia,
-- hash_anterior, fecha y hash, aunque el INSERT los traiga: nadie puede
-- falsificarlos desde fuera.
CREATE FUNCTION canal.encadenar_auditoria() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, canal
AS $$
DECLARE
    v_ultima_secuencia bigint;
    v_ultimo_hash bytea;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('auditoria:' || NEW.empresa_id::text, 0));

    SELECT r.secuencia, r.hash
      INTO v_ultima_secuencia, v_ultimo_hash
      FROM canal.registro_auditoria r
     WHERE r.empresa_id = NEW.empresa_id
     ORDER BY r.secuencia DESC
     LIMIT 1;

    NEW.secuencia := coalesce(v_ultima_secuencia, 0) + 1;
    NEW.hash_anterior := v_ultimo_hash;
    -- Mismo cálculo que fijar_fecha_denuncia y preparar_mensaje (si se cambia
    -- uno, hay que cambiar los otros): el día en la zona de la empresa, sin
    -- depender de la zona de la sesión.
    NEW.fecha := (SELECT (now() AT TIME ZONE e.zona_horaria)::date
                    FROM canal.empresa e
                   WHERE e.id = NEW.empresa_id);
    NEW.hash := sha256(convert_to(
        jsonb_build_array(
            encode(NEW.hash_anterior, 'hex'),
            NEW.empresa_id,
            NEW.secuencia,
            NEW.fecha,
            NEW.actor,
            NEW.accion,
            NEW.objeto_id
        )::text,
        'UTF8'
    ));
    RETURN NEW;
END
$$;

-- La auditoría es de solo añadir: se rechaza cualquier UPDATE, DELETE o
-- TRUNCATE, incluso del superusuario (que se salta permisos y RLS, pero no los
-- triggers). Quien pueda desactivar el trigger sí podría saltárselo, y por eso
-- existe la verificación de la cadena.
CREATE FUNCTION canal.rechazar_modificacion_auditoria() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, canal
AS $$
BEGIN
    RAISE EXCEPTION 'registro_auditoria es inmutable: no se permite UPDATE, DELETE ni TRUNCATE'
        USING ERRCODE = 'insufficient_privilege';
END
$$;

-- Prepara cada mensaje nuevo. Es un solo trigger, y no uno por regla, porque
-- el orden de los pasos importa y PostgreSQL ejecuta los triggers BEFORE de
-- una tabla por orden alfabético de nombre: que la corrección dependiera de
-- cómo se llaman sería frágil.
--
-- 1. Bloquea la fila de la denuncia (FOR NO KEY UPDATE) y lee su estado. Es
--    el único bloqueo, y hace tres cosas:
--    * Serializa los mensajes de una misma denuncia, para que dos simultáneos
--      no reciban el mismo número (paso 3).
--    * Choca con el UPDATE que cambia el estado. Si el personal está cerrando
--      la denuncia, el mensaje espera a que confirme y entonces ve el estado
--      nuevo: no hay ventana entre comprobar el estado e insertar.
--    * Al ser el único, no hay orden de bloqueos que pueda cruzarse. Con dos
--      (la fila y uno consultivo para la secuencia) habría interbloqueo entre
--      un mensaje del denunciante y el personal que, en una transacción,
--      escribe su mensaje y cierra la denuncia.
--    La lectura va con los permisos de quien inserta y bajo RLS: una denuncia
--    de otra empresa es invisible, igual que una inexistente, y las dos dan el
--    mismo error sin bloquear nada. FOR NO KEY UPDATE y no FOR UPDATE: no
--    choca con el FOR KEY SHARE que toman las claves foráneas.
-- 2. Una denuncia resuelta o archivada no admite mensajes (SQLSTATE CN001): el
--    expediente está cerrado y nadie leería lo que llegue, que sería un fallo
--    silencioso. El personal que cierre con un mensaje final lo inserta antes
--    de cambiar el estado, en la misma transacción.
-- 3. Numera los mensajes de cada denuncia (1, 2, 3...) sin huecos, ignorando
--    la secuencia que traiga el INSERT. Así no hace falta una hora para
--    ordenar la conversación. Requiere READ COMMITTED (el nivel por defecto,
--    el de la API al escribir): cada consulta del trigger ve lo confirmado
--    por el mensaje que esperaba delante. Con un nivel superior, el número
--    repetido lo rechazaría la clave primaria, nunca en silencio.
-- 4. Tope de 200 mensajes por denuncia (SQLSTATE CN002): acota lo que guarda
--    la base de datos y lo que devuelve el seguimiento, que los lee todos. La
--    velocidad de envío la limita la API (límite de peticiones).
-- 5. Fecha: el día en la zona de la empresa, con el mismo cálculo que
--    fijar_fecha_denuncia y encadenar_auditoria (si se cambia uno, hay que
--    cambiar los otros; las baterías comprueban los tres por zona).
--
-- Los SQLSTATE propios (clase CN, que no usa PostgreSQL) permiten a la API
-- distinguir cada caso sin leer el texto del error.
CREATE FUNCTION canal.preparar_mensaje() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, canal
AS $$
DECLARE
    v_estado text;
BEGIN
    SELECT d.estado
      INTO v_estado
      FROM canal.denuncia d
     WHERE d.empresa_id = NEW.empresa_id
       AND d.id = NEW.denuncia_id
       FOR NO KEY UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'el mensaje no corresponde a ninguna denuncia visible'
            USING ERRCODE = 'foreign_key_violation';
    END IF;

    IF v_estado IN ('resuelta', 'archivada') THEN
        RAISE EXCEPTION 'la denuncia esta cerrada y no admite mensajes'
            USING ERRCODE = 'CN001';
    END IF;

    SELECT coalesce(max(m.secuencia), 0) + 1
      INTO NEW.secuencia
      FROM canal.mensaje m
     WHERE m.empresa_id = NEW.empresa_id
       AND m.denuncia_id = NEW.denuncia_id;

    IF NEW.secuencia > 200 THEN
        RAISE EXCEPTION 'la denuncia ha alcanzado el maximo de 200 mensajes'
            USING ERRCODE = 'CN002';
    END IF;

    NEW.fecha := (SELECT (now() AT TIME ZONE e.zona_horaria)::date
                    FROM canal.empresa e
                   WHERE e.id = NEW.empresa_id);
    RETURN NEW;
END
$$;

-- Fecha de recepción de una denuncia: el día en la zona horaria de su empresa,
-- ignorando la fecha que traiga el INSERT y la zona de la sesión.
-- La empresa se lee con los permisos de quien inserta: bajo RLS, la API solo
-- ve la de su contexto. Si inserta con el empresa_id de otra, el SELECT no
-- devuelve fila y la fecha queda NULL; la política de INSERT, que PostgreSQL
-- comprueba antes que NOT NULL, rechaza la fila con su error de RLS de siempre
-- (verificar_esquema.py, i).
CREATE FUNCTION canal.fijar_fecha_denuncia() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, canal
AS $$
BEGIN
    NEW.fecha := (SELECT (now() AT TIME ZONE e.zona_horaria)::date
                    FROM canal.empresa e
                   WHERE e.id = NEW.empresa_id);
    RETURN NEW;
END
$$;

-- Recorre la cadena de auditoría visible (con RLS, la de la empresa del
-- contexto) y devuelve la primera secuencia que se rompe, o NULL si está
-- intacta. Se rompe si la secuencia no es consecutiva, si hash_anterior no es
-- el hash de la fila previa, o si el hash guardado no coincide con el
-- recalculado con la misma fórmula que usa encadenar_auditoria (si se cambia
-- una, hay que cambiar la otra).
CREATE FUNCTION canal.verificar_cadena_auditoria() RETURNS bigint
LANGUAGE plpgsql STABLE
SET search_path = pg_catalog, canal
AS $$
DECLARE
    r record;
    v_empresa_previa uuid;
    v_secuencia_previa bigint := 0;
    v_hash_previo bytea;
    v_hash_recalculado bytea;
BEGIN
    FOR r IN
        SELECT a.empresa_id, a.secuencia, a.fecha, a.actor, a.accion,
               a.objeto_id, a.hash_anterior, a.hash
          FROM canal.registro_auditoria a
         ORDER BY a.empresa_id, a.secuencia
    LOOP
        IF v_empresa_previa IS DISTINCT FROM r.empresa_id THEN
            v_empresa_previa := r.empresa_id;
            v_secuencia_previa := 0;
            v_hash_previo := NULL;
        END IF;

        IF r.secuencia <> v_secuencia_previa + 1 THEN
            RETURN r.secuencia;
        END IF;
        IF r.hash_anterior IS DISTINCT FROM v_hash_previo THEN
            RETURN r.secuencia;
        END IF;

        v_hash_recalculado := sha256(convert_to(
            jsonb_build_array(
                encode(r.hash_anterior, 'hex'),
                r.empresa_id,
                r.secuencia,
                r.fecha,
                r.actor,
                r.accion,
                r.objeto_id
            )::text,
            'UTF8'
        ));
        IF r.hash IS DISTINCT FROM v_hash_recalculado THEN
            RETURN r.secuencia;
        END IF;

        v_secuencia_previa := r.secuencia;
        v_hash_previo := r.hash;
    END LOOP;
    RETURN NULL;
END
$$;

REVOKE EXECUTE ON FUNCTION canal.encadenar_auditoria() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION canal.rechazar_modificacion_auditoria() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION canal.preparar_mensaje() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION canal.fijar_fecha_denuncia() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION canal.verificar_cadena_auditoria() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION canal.verificar_cadena_auditoria() TO aplicacion;

CREATE TRIGGER auditoria_encadenar
    BEFORE INSERT ON canal.registro_auditoria
    FOR EACH ROW EXECUTE FUNCTION canal.encadenar_auditoria();
CREATE TRIGGER auditoria_inmutable_fila
    BEFORE UPDATE OR DELETE ON canal.registro_auditoria
    FOR EACH ROW EXECUTE FUNCTION canal.rechazar_modificacion_auditoria();
CREATE TRIGGER auditoria_inmutable_truncate
    BEFORE TRUNCATE ON canal.registro_auditoria
    FOR EACH STATEMENT EXECUTE FUNCTION canal.rechazar_modificacion_auditoria();
CREATE TRIGGER mensaje_preparar
    BEFORE INSERT ON canal.mensaje
    FOR EACH ROW EXECUTE FUNCTION canal.preparar_mensaje();
CREATE TRIGGER denuncia_fecha
    BEFORE INSERT ON canal.denuncia
    FOR EACH ROW EXECUTE FUNCTION canal.fijar_fecha_denuncia();

-- ---------------------------------------------------------------------------
-- Ruta de búsqueda del rol de la aplicación
-- ---------------------------------------------------------------------------

-- Fuera del SET ROLE: este ajuste requiere superusuario. Con él, la API puede
-- escribir nombres sin cualificar y pg_catalog va siempre primero.
RESET ROLE;
ALTER ROLE aplicacion IN DATABASE canario SET search_path = pg_catalog, canal;
COMMIT;
