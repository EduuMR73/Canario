"""Arranque verificado de la API (docs/threat-model.md, 6.10).

Los scripts de inicialización de PostgreSQL solo corren con el volumen vacío,
y si uno falla y el contenedor se reinicia, el resto se salta sin aviso. Antes
de servir, la API comprueba con el rol con el que va a trabajar que la base de
datos es exactamente la esperada, y se niega a arrancar si algo no coincide:
falla cerrado y de forma visible.

Los valores esperados son literales escritos aquí, no se derivan de la base de
datos. Si una migración cambia el esquema, esta lista se actualiza a mano a la
vez: una tabla, un permiso o una política nuevos no pueden aparecer sin que
alguien lo decida.

Límite asumido: la comprobación se hace solo al arrancar. Un cambio posterior
exige superusuario y se detecta en el siguiente reinicio.
"""
import logging

from app import bd

registro = logging.getLogger("canario.arranque")

ROL = "aplicacion"
BASE_DATOS = "canario"
SEARCH_PATH = "pg_catalog, canal"

# Todas las relaciones del esquema canal (tablas, vistas, etc.) con su RLS:
# nombre -> (ENABLE, FORCE).
RELACIONES = {
    "empresa": (True, True),
    "clave_empresa": (True, True),
    "usuario_personal": (True, True),
    "invitacion_personal": (True, True),
    "dispositivo_personal": (True, True),
    "sesion_personal": (True, True),
    "denuncia": (True, True),
    "mensaje": (True, True),
    "registro_auditoria": (True, True),
    # Sin RLS a propósito: nadie tiene permisos directos sobre ellas, solo
    # se consultan mediante funciones de definidor.
    "directorio_empresas": (False, False),
    "busqueda_seguimiento": (False, False),
}

# Privilegios efectivos de tabla (incluye los heredados de PUBLIC).
PRIVILEGIOS_TABLA = {
    "empresa|SELECT",
    "clave_empresa|SELECT", "clave_empresa|INSERT",
    "usuario_personal|SELECT",
    "invitacion_personal|SELECT",
    "dispositivo_personal|SELECT",
    "sesion_personal|SELECT",
    "denuncia|SELECT", "denuncia|INSERT",
    "mensaje|SELECT", "mensaje|INSERT",
    "registro_auditoria|SELECT", "registro_auditoria|INSERT",
}

# Privilegios concedidos solo por columna (sin el privilegio de tabla). En las
# tablas del personal también INSERT: la API no puede crear una cuenta ya
# activada ni elegir una caducidad.
PRIVILEGIOS_COLUMNA = {
    "usuario_personal|empresa_id|INSERT",
    "usuario_personal|email|INSERT",
    "usuario_personal|rol|INSERT",
    "usuario_personal|hash_contrasena|UPDATE",
    "usuario_personal|secreto_totp_cifrado|UPDATE",
    "usuario_personal|version_clave_totp|UPDATE",
    "usuario_personal|totp_activo|UPDATE",
    "usuario_personal|ultimo_paso_totp|UPDATE",
    "usuario_personal|intentos_fallidos|UPDATE",
    "usuario_personal|bloqueado_hasta|UPDATE",
    "usuario_personal|activo|UPDATE",
    "invitacion_personal|empresa_id|INSERT",
    "invitacion_personal|usuario_id|INSERT",
    "invitacion_personal|token_sha256|INSERT",
    "invitacion_personal|cerrada|UPDATE",
    "invitacion_personal|hash_contrasena|UPDATE",
    "invitacion_personal|secreto_totp_cifrado|UPDATE",
    "invitacion_personal|version_clave_totp|UPDATE",
    "dispositivo_personal|empresa_id|INSERT",
    "dispositivo_personal|usuario_id|INSERT",
    "dispositivo_personal|token_sha256|INSERT",
    "dispositivo_personal|intentos_fallidos|UPDATE",
    "dispositivo_personal|bloqueado_hasta|UPDATE",
    "dispositivo_personal|revocado|UPDATE",
    "sesion_personal|empresa_id|INSERT",
    "sesion_personal|usuario_id|INSERT",
    "sesion_personal|dispositivo_id|INSERT",
    "sesion_personal|token_sha256|INSERT",
    "sesion_personal|ultimo_uso|UPDATE",
    "sesion_personal|revocada|UPDATE",
    "denuncia|estado|UPDATE",
    "denuncia|asignada_a|UPDATE",
}

# Funciones del esquema canal que el rol puede ejecutar.
FUNCIONES_EJECUTABLES = {
    "canal.empresa_actual()",
    "canal.verificar_cadena_auditoria()",
    "canal.resolver_empresa(text)",
    "canal.buscar_codigo(bytea)",
    "canal.registrar_codigo(bytea,uuid)",
    "canal.redactar_denuncia(uuid,uuid,bytea,bytea,integer)",
    "canal.redactar_mensaje(uuid,integer,uuid,bytea,bytea,integer)",
}

# Funciones SECURITY DEFINER del esquema canal y su dueño. Las de supresión
# tienen un dueño propio, el único rol con permiso de borrar (04_supresion.sql),
# y las de redacción otro, el único que puede reescribir contenido cifrado
# (05_redaccion.sql).
FUNCIONES_DEFINIDOR = {
    "alta_empresa|propietario_funciones",
    "buscar_codigo|propietario_funciones",
    "registrar_codigo|propietario_funciones",
    "resolver_empresa|propietario_funciones",
    "suprimir_denuncias_caducadas|propietario_supresion",
    "contar_denuncias_caducadas|propietario_supresion",
    "redactar_denuncia|propietario_redaccion",
    "redactar_mensaje|propietario_redaccion",
}

# Todas las políticas del esquema canal:
# tabla|política|comando|permisiva|roles|USING|WITH CHECK
# Comandos: r = SELECT, a = INSERT, w = UPDATE, d = DELETE.
# La condición de todas las políticas de aplicacion salvo la de empresa (que
# compara id), tal como la devuelve PostgreSQL con search_path = pg_catalog.
_MISMA_EMPRESA = "(empresa_id = canal.empresa_actual())"
POLITICAS = {
    "empresa|empresa_select|r|t|aplicacion|(id = canal.empresa_actual())|",
    f"clave_empresa|clave_empresa_select|r|t|aplicacion|{_MISMA_EMPRESA}|",
    f"clave_empresa|clave_empresa_insert|a|t|aplicacion||{_MISMA_EMPRESA}",
    f"usuario_personal|usuario_personal_select|r|t|aplicacion|{_MISMA_EMPRESA}|",
    f"usuario_personal|usuario_personal_insert|a|t|aplicacion||{_MISMA_EMPRESA}",
    f"usuario_personal|usuario_personal_update|w|t|aplicacion|{_MISMA_EMPRESA}|{_MISMA_EMPRESA}",
    f"invitacion_personal|invitacion_personal_select|r|t|aplicacion|{_MISMA_EMPRESA}|",
    f"invitacion_personal|invitacion_personal_insert|a|t|aplicacion||{_MISMA_EMPRESA}",
    f"invitacion_personal|invitacion_personal_update|w|t|aplicacion|{_MISMA_EMPRESA}|{_MISMA_EMPRESA}",
    f"dispositivo_personal|dispositivo_personal_select|r|t|aplicacion|{_MISMA_EMPRESA}|",
    f"dispositivo_personal|dispositivo_personal_insert|a|t|aplicacion||{_MISMA_EMPRESA}",
    f"dispositivo_personal|dispositivo_personal_update|w|t|aplicacion|{_MISMA_EMPRESA}|{_MISMA_EMPRESA}",
    f"sesion_personal|sesion_personal_select|r|t|aplicacion|{_MISMA_EMPRESA}|",
    f"sesion_personal|sesion_personal_insert|a|t|aplicacion||{_MISMA_EMPRESA}",
    f"sesion_personal|sesion_personal_update|w|t|aplicacion|{_MISMA_EMPRESA}|{_MISMA_EMPRESA}",
    f"denuncia|denuncia_select|r|t|aplicacion|{_MISMA_EMPRESA}|",
    f"denuncia|denuncia_insert|a|t|aplicacion||{_MISMA_EMPRESA}",
    f"denuncia|denuncia_update|w|t|aplicacion|{_MISMA_EMPRESA}|{_MISMA_EMPRESA}",
    f"mensaje|mensaje_select|r|t|aplicacion|{_MISMA_EMPRESA}|",
    f"mensaje|mensaje_insert|a|t|aplicacion||{_MISMA_EMPRESA}",
    f"registro_auditoria|registro_auditoria_select|r|t|aplicacion|{_MISMA_EMPRESA}|",
    f"registro_auditoria|registro_auditoria_insert|a|t|aplicacion||{_MISMA_EMPRESA}",
    "empresa|empresa_select_definidor|r|t|propietario_funciones|true|",
    "empresa|empresa_insert_definidor|a|t|propietario_funciones||true",
    # Supresión: la de UPDATE solo permite bloquear (WITH CHECK false).
    "empresa|empresa_select_supresion|r|t|propietario_supresion|true|",
    "denuncia|denuncia_select_supresion|r|t|propietario_supresion|true|",
    "denuncia|denuncia_bloqueo_supresion|w|t|propietario_supresion|true|false",
    "denuncia|denuncia_delete_supresion|d|t|propietario_supresion|true|",
    "mensaje|mensaje_select_supresion|r|t|propietario_supresion|true|",
    "mensaje|mensaje_delete_supresion|d|t|propietario_supresion|true|",
    "registro_auditoria|registro_auditoria_select_supresion|r|t|propietario_supresion|true|",
    "registro_auditoria|registro_auditoria_insert_supresion|a|t|propietario_supresion||true",
    # Redacción: todas dentro del contexto de la empresa.
    "empresa|empresa_select_redaccion|r|t|propietario_redaccion|(id = canal.empresa_actual())|",
    f"usuario_personal|usuario_personal_select_redaccion|r|t|propietario_redaccion|{_MISMA_EMPRESA}|",
    f"denuncia|denuncia_select_redaccion|r|t|propietario_redaccion|{_MISMA_EMPRESA}|",
    f"denuncia|denuncia_update_redaccion|w|t|propietario_redaccion|{_MISMA_EMPRESA}|{_MISMA_EMPRESA}",
    f"mensaje|mensaje_select_redaccion|r|t|propietario_redaccion|{_MISMA_EMPRESA}|",
    f"mensaje|mensaje_update_redaccion|w|t|propietario_redaccion|{_MISMA_EMPRESA}|{_MISMA_EMPRESA}",
    f"registro_auditoria|registro_auditoria_select_redaccion|r|t|propietario_redaccion|{_MISMA_EMPRESA}|",
    f"registro_auditoria|registro_auditoria_insert_redaccion|a|t|propietario_redaccion||{_MISMA_EMPRESA}",
}

# Consultas. Se ejecutan con search_path = pg_catalog (SET LOCAL), para que
# los nombres salgan siempre cualificados con canal. sin depender de la
# sesión.
SQL_RELACIONES = """
    select c.relname, c.relrowsecurity, c.relforcerowsecurity
      from pg_class c join pg_namespace n on n.oid = c.relnamespace
     where n.nspname = 'canal' and c.relkind in ('r', 'p', 'v', 'm', 'f')
"""
SQL_PROPIEDAD = """
    select (select count(*) from pg_class where relowner = r.oid)
         + (select count(*) from pg_proc where proowner = r.oid)
         + (select count(*) from pg_namespace where nspowner = r.oid)
         + (select count(*) from pg_type where typowner = r.oid)
         + (select count(*) from pg_database where datdba = r.oid)
      from pg_roles r where r.rolname = current_user
"""
SQL_PRIVILEGIOS_TABLA = """
    select c.relname || '|' || p.priv
      from pg_class c join pg_namespace n on n.oid = c.relnamespace
      cross join unnest(array['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE',
                              'REFERENCES', 'TRIGGER', 'MAINTAIN']) as p(priv)
     where n.nspname = 'canal' and c.relkind in ('r', 'p', 'v', 'm', 'f')
       and has_table_privilege(c.oid, p.priv)
"""
SQL_PRIVILEGIOS_COLUMNA = """
    select c.relname || '|' || a.attname || '|' || p.priv
      from pg_class c join pg_namespace n on n.oid = c.relnamespace
      join pg_attribute a on a.attrelid = c.oid and a.attnum > 0 and not a.attisdropped
      cross join unnest(array['SELECT', 'INSERT', 'UPDATE', 'REFERENCES']) as p(priv)
     where n.nspname = 'canal' and c.relkind in ('r', 'p', 'v', 'm', 'f')
       and has_column_privilege(c.oid, a.attnum, p.priv)
       and not has_table_privilege(c.oid, p.priv)
"""
SQL_FUNCIONES_EJECUTABLES = """
    select p.oid::regprocedure::text
      from pg_proc p join pg_namespace n on n.oid = p.pronamespace
     where n.nspname = 'canal' and has_function_privilege(p.oid, 'EXECUTE')
"""
SQL_FUNCIONES_DEFINIDOR = """
    select p.proname || '|' || r.rolname
      from pg_proc p join pg_namespace n on n.oid = p.pronamespace
      join pg_roles r on r.oid = p.proowner
     where n.nspname = 'canal' and p.prosecdef
"""
SQL_SEARCH_PATH = "select current_setting('search_path')"
SQL_PERTENENCIA = """
    select count(*) from pg_auth_members
     where member = (select oid from pg_roles where rolname = current_user)
"""
SQL_ESQUEMA_BD = """
    select has_schema_privilege('canal', 'USAGE'),
           has_schema_privilege('canal', 'CREATE'),
           has_schema_privilege('public', 'CREATE'),
           has_database_privilege(current_database(), 'CREATE'),
           has_database_privilege(current_database(), 'TEMPORARY')
"""
SQL_POLITICAS = """
    select c.relname || '|' || pol.polname || '|' || pol.polcmd::text || '|'
           || case when pol.polpermissive then 't' else 'f' end || '|'
           || coalesce((select string_agg(r.rolname, ',' order by r.rolname)
                          from pg_roles r where r.oid = any(pol.polroles)),
                       'public') || '|'
           || coalesce(pg_get_expr(pol.polqual, pol.polrelid), '') || '|'
           || coalesce(pg_get_expr(pol.polwithcheck, pol.polrelid), '')
      from pg_policy pol join pg_class c on c.oid = pol.polrelid
      join pg_namespace n on n.oid = c.relnamespace
     where n.nspname = 'canal'
"""


class ArranqueBloqueado(Exception):
    """La base de datos no es la esperada: la API no debe arrancar."""


def _filas(conexion, sql):
    return conexion.execute(sql).fetchall()


def _conjunto(conexion, sql):
    return {fila[0] for fila in _filas(conexion, sql)}


def _diferencia(real, esperado):
    """Describe lo que sobra y lo que falta, sin datos sensibles (solo nombres)."""
    sobra = sorted(real - esperado)
    falta = sorted(esperado - real)
    return f"sobra {sobra}, falta {falta}"


def comprobar(conexion):
    """Ejecuta todas las comprobaciones. Devuelve la lista de fallos (id, detalle)."""
    fallos = []

    def exigir(identificador, condicion, detalle):
        if not condicion:
            fallos.append((identificador, detalle))

    # Antes de fijar el search_path local: el del rol tal como lo configuró la
    # inicialización (pg_catalog primero, sin public).
    search_path = conexion.execute(SQL_SEARCH_PATH).fetchone()[0]
    exigir("search_path", search_path == SEARCH_PATH, f"search_path = {search_path!r}")
    conexion.execute("set local search_path = pg_catalog")

    usuario, sesion, base = conexion.execute(
        "select current_user, session_user, current_database()").fetchone()
    exigir("identidad", (usuario, sesion, base) == (ROL, ROL, BASE_DATOS),
           f"current_user = {usuario}, session_user = {sesion}, base = {base}")

    atributos = conexion.execute(
        "select rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolreplication "
        "from pg_roles where rolname = current_user").fetchone()
    exigir("rol_atributos", atributos == (False, False, False, False, False),
           f"super, bypassrls, createrole, createdb, replication = {atributos}")

    # Un rol heredado (por ejemplo pg_read_all_data) daría permisos sin tocar
    # los atributos del propio rol. pg_read_all_data no salta la RLS, pero sí
    # daría lectura de directorio_empresas y busqueda_seguimiento.
    miembros = conexion.execute(SQL_PERTENENCIA).fetchone()[0]
    exigir("pertenencia", miembros == 0, f"el rol pertenece a {miembros} rol(es)")

    # El dueño de una tabla puede desactivar su RLS con ALTER TABLE: FORCE no
    # lo impide. El rol no debe poseer nada.
    propios = conexion.execute(SQL_PROPIEDAD).fetchone()[0]
    exigir("propiedad", propios == 0, f"el rol es dueno de {propios} objeto(s)")

    # Sin CREATE no puede crear objetos con los que suplantar otros. Sin TEMP
    # no puede crear tablas temporales, que se buscan antes que cualquier
    # esquema del search_path.
    esquemas = conexion.execute(SQL_ESQUEMA_BD).fetchone()
    exigir("esquema_bd", esquemas == (True, False, False, False, False),
           f"usage canal, create canal, create public, create bd, temp bd = {esquemas}")

    relaciones = {
        nombre: (rls, force) for nombre, rls, force in _filas(conexion, SQL_RELACIONES)
    }
    exigir("tablas", set(relaciones) == set(RELACIONES),
           _diferencia(set(relaciones), set(RELACIONES)))
    rls_mal = sorted(n for n, esperado in RELACIONES.items()
                     if n in relaciones and relaciones[n] != esperado)
    exigir("rls", not rls_mal, f"RLS o FORCE distintos de lo esperado en {rls_mal}")

    tabla = _conjunto(conexion, SQL_PRIVILEGIOS_TABLA)
    exigir("privilegios_tabla", tabla == PRIVILEGIOS_TABLA,
           _diferencia(tabla, PRIVILEGIOS_TABLA))
    columna = _conjunto(conexion, SQL_PRIVILEGIOS_COLUMNA)
    exigir("privilegios_columna", columna == PRIVILEGIOS_COLUMNA,
           _diferencia(columna, PRIVILEGIOS_COLUMNA))

    funciones = _conjunto(conexion, SQL_FUNCIONES_EJECUTABLES)
    exigir("funciones", funciones == FUNCIONES_EJECUTABLES,
           _diferencia(funciones, FUNCIONES_EJECUTABLES))
    definidor = _conjunto(conexion, SQL_FUNCIONES_DEFINIDOR)
    exigir("funciones_definidor", definidor == FUNCIONES_DEFINIDOR,
           _diferencia(definidor, FUNCIONES_DEFINIDOR))
    # El dueño de las funciones de definidor tampoco puede saltarse la RLS ni
    # conectarse.
    duenio = conexion.execute(
        "select rolsuper, rolbypassrls, rolcanlogin from pg_roles "
        "where rolname = 'propietario_funciones'").fetchone()
    exigir("propietario_funciones", duenio == (False, False, False),
           f"super, bypassrls, login = {duenio}")
    # Lo mismo para el dueño de la supresión, el único rol que puede borrar:
    # con BYPASSRLS o login, ese permiso dejaría de estar encerrado en su
    # función.
    supresion = conexion.execute(
        "select rolsuper, rolbypassrls, rolcanlogin from pg_roles "
        "where rolname = 'propietario_supresion'").fetchone()
    exigir("propietario_supresion", supresion == (False, False, False),
           f"super, bypassrls, login = {supresion}")
    # Y para el de la redacción, el único que puede reescribir contenido
    # cifrado: con BYPASSRLS, sus funciones cruzarían empresas.
    redaccion = conexion.execute(
        "select rolsuper, rolbypassrls, rolcanlogin from pg_roles "
        "where rolname = 'propietario_redaccion'").fetchone()
    exigir("propietario_redaccion", redaccion == (False, False, False),
           f"super, bypassrls, login = {redaccion}")

    politicas = _conjunto(conexion, SQL_POLITICAS)
    exigir("politicas", politicas == POLITICAS, _diferencia(politicas, POLITICAS))
    return fallos


def verificar(pool):
    """Verifica la base de datos y lanza ArranqueBloqueado si algo no coincide.

    Corre en una transacción de solo lectura: la comprobación no puede
    modificar nada aunque tuviera un error.
    """
    with bd.transaccion_sin_contexto(pool, solo_lectura=True) as conexion:
        fallos = comprobar(conexion)
    for identificador, detalle in fallos:
        registro.error("ARRANQUE BLOQUEADO: %s: %s", identificador, detalle)
    if fallos:
        raise ArranqueBloqueado(f"{len(fallos)} comprobacion(es) fallida(s)")
    registro.info("ARRANQUE VERIFICADO")
