#!/usr/bin/env python3
"""Batería de pruebas de seguridad del esquema "canal" (db/init/02_esquema.sql).

Qué prueba: que el esquema se aplica entero al arrancar, que la estructura, las
políticas RLS y los permisos coinciden con unos oráculos escritos aquí como
literales (no derivados del SQL), que una empresa no puede ver ni tocar los
datos de otra, que los permisos por columna se cumplen, que la auditoría es
encadenada e inmutable (con recálculo independiente del hash en Python) y que
el bloqueo por empresa y el healthcheck se comportan como se espera. Cada
prueba negativa lleva su control positivo: si el control falla, el resultado es
SIN CONCLUSION, nunca PASA.

Cómo se ejecuta (desde la raíz del repositorio, con Docker en marcha):

    python tests/security/verificar_esquema.py

Usa un proyecto de Docker propio (canario_esquema), con su red y su volumen, y
solo levanta el servicio postgres. Nunca toca el proyecto canario. Al terminar
lo borra todo (down -v). Necesita que existan secrets/contrasena_*.txt (solo
comprueba que son ficheros; el único que llega a un contenedor es el de la
aplicación, montado en solo lectura, y nunca se lee ni se imprime).

La salida completa se guarda en verificacion_esquema.txt dentro del directorio
temporal del sistema (nunca dentro del repositorio). El código de salida es 0
solo si el resultado global es OK.

Solo usa la biblioteca estándar.
"""
import concurrent.futures
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import time
import traceback
import uuid

RAIZ = pathlib.Path.cwd()
PROYECTO = "canario_esquema"
SALIDA = pathlib.Path(tempfile.gettempdir()) / "verificacion_esquema.txt"
BASE = ["docker", "compose", "-p", PROYECTO, "-f", "docker-compose.yml"]

lineas_salida = []
estado = {"falla": False, "sin_conclusion": False}

# ---------------------------------------------------------------------------
# Datos de prueba (fixture) con UUID fijos
# ---------------------------------------------------------------------------
EMPRESA_A = "a0000000-0000-4000-8000-000000000001"
EMPRESA_B = "b0000000-0000-4000-8000-000000000002"
ADMIN_A = "a0000000-0000-4000-8000-0000000000a1"
INSTR_A = "a0000000-0000-4000-8000-0000000000a2"
ADMIN_B = "b0000000-0000-4000-8000-0000000000b1"
INSTR_B = "b0000000-0000-4000-8000-0000000000b2"
DEN_A1 = "a0000000-0000-4000-8000-0000000000d1"
DEN_A2 = "a0000000-0000-4000-8000-0000000000d2"
DEN_A3 = "a0000000-0000-4000-8000-0000000000d3"  # solo para la prueba de mensajes
DEN_B1 = "b0000000-0000-4000-8000-0000000000d1"
DEN_B2 = "b0000000-0000-4000-8000-0000000000d2"
BYTES_FALSOS = r"'\xdeadbeef'"

# ---------------------------------------------------------------------------
# Oráculos literales
# ---------------------------------------------------------------------------
TABLAS = ["busqueda_seguimiento", "clave_empresa", "denuncia", "directorio_empresas",
          "empresa", "mensaje", "registro_auditoria", "usuario_personal"]
TABLAS_RLS = ["clave_empresa", "denuncia", "empresa", "mensaje", "registro_auditoria", "usuario_personal"]
TABLAS_SIN_RLS = ["busqueda_seguimiento", "directorio_empresas"]

CLAVES_PRIMARIAS = [
    "busqueda_seguimiento|PRIMARY KEY (codigo_hmac)",
    "clave_empresa|PRIMARY KEY (empresa_id, version)",
    "denuncia|PRIMARY KEY (empresa_id, id)",
    "directorio_empresas|PRIMARY KEY (identificador_publico)",
    "empresa|PRIMARY KEY (id)",
    "mensaje|PRIMARY KEY (empresa_id, denuncia_id, secuencia)",
    "registro_auditoria|PRIMARY KEY (empresa_id, secuencia)",
    "usuario_personal|PRIMARY KEY (empresa_id, id)",
]
# tabla|columnas|tabla referenciada|columnas referenciadas|accion al borrar (a = NO ACTION)
CLAVES_FORANEAS = [
    "busqueda_seguimiento|empresa_id,denuncia_id|denuncia|empresa_id,id|a",
    "clave_empresa|empresa_id|empresa|id|a",
    "denuncia|empresa_id|empresa|id|a",
    "denuncia|empresa_id,asignada_a|usuario_personal|empresa_id,id|a",
    "denuncia|empresa_id,version_clave|clave_empresa|empresa_id,version|a",
    "directorio_empresas|empresa_id|empresa|id|a",
    "mensaje|empresa_id,autor_id|usuario_personal|empresa_id,id|a",
    "mensaje|empresa_id,denuncia_id|denuncia|empresa_id,id|a",
    "mensaje|empresa_id,version_clave|clave_empresa|empresa_id,version|a",
    "registro_auditoria|empresa_id|empresa|id|a",
    "usuario_personal|empresa_id|empresa|id|a",
]
# tabla|politica|comando
POLITICAS = [
    "empresa|empresa_select|SELECT",
    "clave_empresa|clave_empresa_select|SELECT",
    "clave_empresa|clave_empresa_insert|INSERT",
    "usuario_personal|usuario_personal_select|SELECT",
    "usuario_personal|usuario_personal_insert|INSERT",
    "usuario_personal|usuario_personal_update|UPDATE",
    "denuncia|denuncia_select|SELECT",
    "denuncia|denuncia_insert|INSERT",
    "denuncia|denuncia_update|UPDATE",
    "mensaje|mensaje_select|SELECT",
    "mensaje|mensaje_insert|INSERT",
    "registro_auditoria|registro_auditoria_select|SELECT",
    "registro_auditoria|registro_auditoria_insert|INSERT",
]
# Privilegios de tabla de aplicacion (UPDATE solo por columna, nunca a nivel de tabla)
PRIVILEGIOS_TABLA_APLICACION = {
    "empresa": {"SELECT"},
    "clave_empresa": {"SELECT", "INSERT"},
    "usuario_personal": {"SELECT", "INSERT"},
    "denuncia": {"SELECT", "INSERT"},
    "mensaje": {"SELECT", "INSERT"},
    "registro_auditoria": {"SELECT", "INSERT"},
    "directorio_empresas": set(),
    "busqueda_seguimiento": set(),
}
TABLAS_CON_UPDATE_POR_COLUMNA = {"usuario_personal", "denuncia"}
COLUMNAS_UPDATE = {
    "usuario_personal": {"hash_contrasena", "secreto_totp_cifrado", "totp_activo",
                         "intentos_fallidos", "bloqueado_hasta", "activo"},
    "denuncia": {"estado", "asignada_a"},
}
PRIVILEGIOS = ["SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"]
FUNCIONES = ["asignar_secuencia_mensaje", "empresa_actual", "encadenar_auditoria",
             "rechazar_modificacion_auditoria", "verificar_cadena_auditoria"]
FUNCIONES_EXECUTE_APLICACION = {"empresa_actual", "verificar_cadena_auditoria"}
TRIGGERS = [
    "mensaje|mensaje_secuencia|O",
    "registro_auditoria|auditoria_encadenar|O",
    "registro_auditoria|auditoria_inmutable_fila|O",
    "registro_auditoria|auditoria_inmutable_truncate|O",
]
# Conteos esperados con contexto A y B
CONTEOS = {
    "empresa": (1, 1), "clave_empresa": (1, 1), "usuario_personal": (2, 2),
    "denuncia": (2, 2), "mensaje": (2, 1), "registro_auditoria": (2, 1),
}


# ---------------------------------------------------------------------------
# Utilidades de ejecución y de informe
# ---------------------------------------------------------------------------
class R:
    """Resultado de un comando: código, stdout y stderr por separado."""

    def __init__(self, rc, out, err):
        self.rc, self.out, self.err = rc, out, err

    @property
    def todo(self):
        return self.out + self.err

    def lineas(self):
        return [l.strip() for l in self.out.splitlines() if l.strip()]


class Parada(Exception):
    pass


def p(texto=""):
    print(texto, flush=True)
    lineas_salida.append(texto)


def ejecutar(args, entrada=None, timeout=900):
    r = subprocess.run(args, input=entrada, capture_output=True, timeout=timeout)
    return R(r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace"))


def dc(*args, entrada=None):
    return ejecutar(BASE + list(args), entrada=entrada)


PSQL = ["exec", "-T", "postgres", "psql", "-U", "postgres", "-d", "canario",
        "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=0", "-f", "-"]


def sup(sql):
    """SQL como superusuario por el socket (stdin)."""
    return dc(*PSQL, entrada=sql.encode("utf-8"))


SIN = None  # sin contexto de empresa


def sql_app(cuerpo, ctx=SIN, final="COMMIT"):
    partes = ["SET ROLE aplicacion;"]
    if ctx is not SIN:
        partes += ["BEGIN;", f"SELECT set_config('app.empresa_id', '{ctx}', true) \\gset"]
        partes.append(cuerpo)
        partes.append(final + ";")
    else:
        partes.append(cuerpo)
    return "\n".join(partes) + "\n"


def app(cuerpo, ctx=SIN, final="COMMIT"):
    """SQL como aplicacion (SET ROLE desde el superusuario), con o sin contexto."""
    return sup(sql_app(cuerpo, ctx, final))


def pasa(cond, texto):
    p(("PASA  " if cond else "FALLA ") + texto)
    if not cond:
        estado["falla"] = True


def sinc(texto):
    p("SIN CONCLUSION " + texto)
    estado["sin_conclusion"] = True


def sin_error(r):
    return r.rc == 0 and "ERROR" not in r.err and "FATAL" not in r.err


def comparar(nombre, real, esperado):
    ok = sorted(real) == sorted(esperado)
    pasa(ok, nombre)
    if not ok:
        p(f"   real:     {sorted(real)}")
        p(f"   esperado: {sorted(esperado)}")


def negativo(nombre, r, texto, control_ok, no_texto=None):
    """Prueba negativa con control: si el control falla, SIN CONCLUSION."""
    if not control_ok:
        sinc(f"{nombre}: el control positivo fallo")
        return
    cond = texto in r.err and (no_texto is None or no_texto not in r.err)
    pasa(cond, f"{nombre} -> {texto!r}" + (f" y no {no_texto!r}" if no_texto else ""))
    if not cond:
        p(f"   stderr: {r.err.strip()[:400]!r}")


def valor(r):
    """Primera línea no vacía de la salida."""
    ls = r.lineas()
    return ls[0] if ls else ""


# ---------------------------------------------------------------------------
# Comprobaciones
# ---------------------------------------------------------------------------
IMAGEN = ""
CID = ""


def seccion_a():
    p("=== a) arranque")
    r = dc("up", "-d", "--wait", "postgres")
    p(f"up -d --wait postgres -> codigo {r.rc}\n{r.todo.strip()}")
    pasa(r.rc == 0, "a) up -d --wait postgres termina con codigo 0")
    registro = dc("logs", "--no-log-prefix", "postgres").todo
    if r.rc != 0:
        p("--- log completo de postgres ---")
        p(registro)
        raise Parada("el SQL no se aplico o el servicio no llego a healthy")
    pasa("running /docker-entrypoint-initdb.d/02_esquema.sql" in registro,
         "a) el log contiene 'running /docker-entrypoint-initdb.d/02_esquema.sql'")
    malas = [l for l in registro.splitlines() if "ERROR" in l or "FATAL" in l]
    pasa(not malas, f"a) el log del arranque no tiene lineas con ERROR ni FATAL ({len(malas)})")
    for l in malas:
        p(f"   {l}")


def seccion_b():
    p("=== b) estaticas de db/init/02_esquema.sql")
    datos = (RAIZ / "db" / "init" / "02_esquema.sql").read_bytes()
    pasa(not datos.startswith(b"\xef\xbb\xbf"), "b) sin BOM")
    pasa(b"\r" not in datos, "b) sin CR")
    codigo = [l.strip() for l in datos.decode("utf-8").split("\n")
              if l.strip() and not l.strip().startswith("--")]
    pasa(codigo[:3] == ["\\set ON_ERROR_STOP on", "BEGIN;", "SET ROLE migrador;"],
         f"b) empieza por \\set ON_ERROR_STOP on, BEGIN; y SET ROLE migrador; ({codigo[:3]})")
    pasa(codigo[-1] == "COMMIT;", f"b) termina en COMMIT; ({codigo[-1]!r})")
    unido = "\n".join(codigo).upper()
    for prohibido in ("TO PUBLIC", "BYPASSRLS", "SECURITY DEFINER", "PASSWORD"):
        pasa(prohibido not in unido, f"b) no contiene {prohibido!r}")


def seccion_c():
    p("=== c) catalogo estructural")
    r = sup("select pg_get_userbyid(nspowner) from pg_namespace where nspname = 'canal';")
    comparar("c) esquema canal de migrador", r.lineas(), ["migrador"])
    r = sup("select c.relname, pg_get_userbyid(c.relowner) from pg_class c join pg_namespace n on n.oid = c.relnamespace "
            "where n.nspname = 'canal' and c.relkind in ('r', 'p');")
    comparar("c) exactamente las 8 tablas, todas de migrador", r.lineas(), [f"{t}|migrador" for t in TABLAS])
    r = sup("select count(*) from pg_class c join pg_namespace n on n.oid = c.relnamespace "
            "where n.nspname = 'public' and c.relkind in ('r', 'p', 'v', 'm', 'f', 'S');")
    comparar("c) ninguna tabla ni objeto en public", r.lineas(), ["0"])
    r = sup("select c.relname || '|' || pg_get_constraintdef(co.oid) from pg_constraint co "
            "join pg_class c on c.oid = co.conrelid join pg_namespace n on n.oid = c.relnamespace "
            "where co.contype = 'p' and n.nspname = 'canal';")
    comparar("c) claves primarias", r.lineas(), CLAVES_PRIMARIAS)
    r = sup("""
select c.relname,
       (select string_agg(a.attname, ',' order by k.ord) from unnest(co.conkey) with ordinality k(attnum, ord)
          join pg_attribute a on a.attrelid = co.conrelid and a.attnum = k.attnum),
       f.relname,
       (select string_agg(a.attname, ',' order by k.ord) from unnest(co.confkey) with ordinality k(attnum, ord)
          join pg_attribute a on a.attrelid = co.confrelid and a.attnum = k.attnum),
       co.confdeltype
  from pg_constraint co
  join pg_class c on c.oid = co.conrelid
  join pg_class f on f.oid = co.confrelid
  join pg_namespace n on n.oid = c.relnamespace
 where co.contype = 'f' and n.nspname = 'canal';
""")
    comparar("c) conjunto exacto de claves foraneas (todas ON DELETE NO ACTION)", r.lineas(), CLAVES_FORANEAS)
    r = sup("select pg_get_constraintdef(oid) from pg_constraint where contype = 'u' and conrelid = 'canal.usuario_personal'::regclass;")
    comparar("c) UNIQUE (empresa_id, email) en usuario_personal", r.lineas(), ["UNIQUE (empresa_id, email)"])
    r = sup("select c.relname, c.relrowsecurity, c.relforcerowsecurity from pg_class c "
            "join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'canal' and c.relkind = 'r';")
    esperado = [f"{t}|t|t" for t in TABLAS_RLS] + [f"{t}|f|f" for t in TABLAS_SIN_RLS]
    comparar("c) RLS ENABLE y FORCE en las 6 tablas y ninguna en directorio_empresas ni busqueda_seguimiento", r.lineas(), esperado)


def seccion_d():
    p("=== d) politicas")
    r = sup("select tablename, policyname, cmd, roles, coalesce(qual, ''), coalesce(with_check, '') "
            "from pg_policies where schemaname = 'canal' order by 1, 2;")
    filas = [l.split("|") for l in r.lineas()]
    comparar("d) conjunto exacto de politicas (tabla, nombre, comando)",
             ["|".join(f[:3]) for f in filas], POLITICAS)
    pasa(all(f[3] == "{aplicacion}" for f in filas), "d) todas son TO aplicacion y nadie mas")
    pasa(all(f[2] not in ("DELETE", "ALL") for f in filas), "d) ninguna con comando DELETE ni ALL")
    ok = True
    for f in filas:
        tabla, nombre, cmd, _roles, qual, check = f
        esperado_qual = cmd in ("SELECT", "UPDATE")
        esperado_check = cmd in ("INSERT", "UPDATE")
        if esperado_qual != ("empresa_actual" in qual) or (not esperado_qual and qual):
            ok = False
            p(f"   {nombre}: qual inesperado {qual!r}")
        if esperado_check != ("empresa_actual" in check) or (not esperado_check and check):
            ok = False
            p(f"   {nombre}: with_check inesperado {check!r}")
    pasa(ok, "d) todas usan empresa_actual y SELECT solo qual, INSERT solo with_check, UPDATE ambos")


def seccion_e():
    p("=== e) privilegios")
    roles = ["aplicacion", "plataforma", "propietario_funciones"]
    consultas = []
    for rol in roles:
        for t in TABLAS:
            for pr in PRIVILEGIOS:
                consultas.append(f"select '{rol}|{t}|{pr}|' || has_table_privilege('{rol}', 'canal.{t}', '{pr}')::text;")
            consultas.append(f"select '{rol}|{t}|COLUMNA_UPDATE|' || has_any_column_privilege('{rol}', 'canal.{t}', 'UPDATE')::text;")
    r = sup("\n".join(consultas))
    real = set(r.lineas())
    esperado = set()
    for rol in roles:
        for t in TABLAS:
            for pr in PRIVILEGIOS:
                da = rol == "aplicacion" and pr in PRIVILEGIOS_TABLA_APLICACION[t]
                esperado.add(f"{rol}|{t}|{pr}|{'true' if da else 'false'}")
            col = rol == "aplicacion" and t in TABLAS_CON_UPDATE_POR_COLUMNA
            esperado.add(f"{rol}|{t}|COLUMNA_UPDATE|{'true' if col else 'false'}")
    pasa(real == esperado, "e) matriz de privilegios de tabla de los 3 roles (UPDATE solo por columna)")
    if real != esperado:
        p(f"   sobran: {sorted(real - esperado)[:10]}")
        p(f"   faltan: {sorted(esperado - real)[:10]}")
    # UPDATE por columna
    for t, permitidas in COLUMNAS_UPDATE.items():
        r = sup(f"select a.attname || '|' || has_column_privilege('aplicacion', 'canal.{t}', a.attname, 'UPDATE')::text "
                f"from pg_attribute a where a.attrelid = 'canal.{t}'::regclass and a.attnum > 0 and not a.attisdropped;")
        real = set(r.lineas())
        columnas = {l.split("|")[0] for l in real}
        esperado = {f"{c}|{'true' if c in permitidas else 'false'}" for c in columnas}
        pasa(real == esperado and permitidas <= columnas,
             f"e) UPDATE por columna en {t} exactamente en {sorted(permitidas)}")
    # ACL: nada para PUBLIC (grantee 0)
    r = sup("select c.relname from pg_class c join pg_namespace n on n.oid = c.relnamespace "
            "join lateral aclexplode(c.relacl) a on true where n.nspname = 'canal' and a.grantee = 0;")
    comparar("e) ninguna tabla del esquema tiene entrada de ACL para PUBLIC", r.lineas(), [])
    r = sup("select p.proname from pg_proc p join pg_namespace n on n.oid = p.pronamespace "
            "join lateral aclexplode(p.proacl) a on true where n.nspname = 'canal' and a.grantee = 0;")
    comparar("e) ninguna funcion del esquema tiene entrada de ACL para PUBLIC", r.lineas(), [])
    r = sup("select p.proname from pg_proc p join pg_namespace n on n.oid = p.pronamespace "
            "where n.nspname = 'canal' and p.proacl is null;")
    comparar("e) toda funcion tiene proacl no nulo", r.lineas(), [])
    r = sup("select count(*) from pg_class c join pg_namespace n on n.oid = c.relnamespace "
            "join lateral aclexplode(c.relacl) a on true join pg_roles ro on ro.oid = a.grantee "
            "where n.nspname = 'canal' and ro.rolname = 'aplicacion';")
    pasa(valor(r).isdigit() and int(valor(r)) > 0, "e) control: la consulta de ACL si ve las entradas de aplicacion")
    for rol in roles:
        r = sup(f"select has_schema_privilege('{rol}', 'canal', 'USAGE')::text || '|' || has_schema_privilege('{rol}', 'canal', 'CREATE')::text;")
        pasa(valor(r) == "true|false", f"e) {rol}: USAGE sobre canal true y CREATE false ({valor(r)})")


def seccion_f():
    p("=== f) funciones y triggers")
    r = sup("select p.proname, pg_get_userbyid(p.proowner), p.prosecdef from pg_proc p "
            "join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'canal';")
    comparar("f) las 5 funciones, de migrador y sin SECURITY DEFINER", r.lineas(), [f"{f}|migrador|f" for f in FUNCIONES])
    consultas = []
    for rol in ["aplicacion", "plataforma", "propietario_funciones"]:
        consultas.append(
            f"select '{rol}|' || p.proname || '|' || has_function_privilege('{rol}', p.oid, 'EXECUTE')::text "
            "from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'canal';")
    r = sup("\n".join(consultas))
    esperado = []
    for rol in ["aplicacion", "plataforma", "propietario_funciones"]:
        for f in FUNCIONES:
            da = rol == "aplicacion" and f in FUNCIONES_EXECUTE_APLICACION
            esperado.append(f"{rol}|{f}|{'true' if da else 'false'}")
    comparar("f) EXECUTE solo para aplicacion y solo en empresa_actual y verificar_cadena_auditoria", r.lineas(), esperado)
    r = sup("select c.relname, t.tgname, t.tgenabled from pg_trigger t join pg_class c on c.oid = t.tgrelid "
            "join pg_namespace n on n.oid = c.relnamespace where not t.tgisinternal and n.nspname = 'canal';")
    comparar("f) los 4 triggers esperados, todos con tgenabled = 'O'", r.lineas(), TRIGGERS)
    # control de privilegios por defecto: una funcion nueva de migrador no hereda EXECUTE de PUBLIC
    try:
        r = sup("SET ROLE migrador;\n"
                "CREATE FUNCTION canal.prueba_privilegios() RETURNS integer LANGUAGE sql AS 'select 1';\n"
                "RESET ROLE;\n"
                "select (proacl is not null)::text || '|' || (select count(*) from aclexplode(proacl) a where a.grantee = 0) "
                "from pg_proc where proname = 'prueba_privilegios' and pronamespace = 'canal'::regnamespace;")
        pasa(valor(r) == "true|0" and sin_error(r), f"f) una funcion nueva de migrador nace sin EXECUTE para PUBLIC ({valor(r)}) {r.err.strip()[:200]}")
    finally:
        sup("DROP FUNCTION IF EXISTS canal.prueba_privilegios();")


def seccion_g():
    p("=== g) fixture y control de datos")
    sql = f"""
INSERT INTO canal.empresa (id, nombre) VALUES ('{EMPRESA_A}', 'Empresa A'), ('{EMPRESA_B}', 'Empresa B');
INSERT INTO canal.clave_empresa (empresa_id, version, clave_envuelta) VALUES
    ('{EMPRESA_A}', 1, '\\x01'), ('{EMPRESA_B}', 1, '\\x02');
INSERT INTO canal.usuario_personal (empresa_id, id, email, hash_contrasena, rol) VALUES
    ('{EMPRESA_A}', '{ADMIN_A}', 'ana@ejemplo.test', 'x', 'admin'),
    ('{EMPRESA_A}', '{INSTR_A}', 'luis@ejemplo.test', 'x', 'instructor'),
    ('{EMPRESA_B}', '{ADMIN_B}', 'ana@ejemplo.test', 'x', 'admin'),
    ('{EMPRESA_B}', '{INSTR_B}', 'eva@ejemplo.test', 'x', 'instructor');
INSERT INTO canal.denuncia (empresa_id, id, categoria, contenido_cifrado, version_clave, asignada_a) VALUES
    ('{EMPRESA_A}', '{DEN_A1}', 'acoso', {BYTES_FALSOS}, 1, '{INSTR_A}'),
    ('{EMPRESA_A}', '{DEN_A2}', 'fraude', {BYTES_FALSOS}, 1, NULL),
    ('{EMPRESA_B}', '{DEN_B1}', 'acoso', {BYTES_FALSOS}, 1, NULL),
    ('{EMPRESA_B}', '{DEN_B2}', 'fraude', {BYTES_FALSOS}, 1, NULL);
INSERT INTO canal.mensaje (empresa_id, denuncia_id, autor, contenido_cifrado, version_clave) VALUES
    ('{EMPRESA_A}', '{DEN_A1}', 'denunciante', {BYTES_FALSOS}, 1),
    ('{EMPRESA_A}', '{DEN_A1}', 'denunciante', {BYTES_FALSOS}, 1),
    ('{EMPRESA_B}', '{DEN_B1}', 'denunciante', {BYTES_FALSOS}, 1);
"""
    r = dc(*PSQL[:-4], "-v", "ON_ERROR_STOP=1", "-f", "-", entrada=sql.encode())
    pasa(sin_error(r), f"g) fixture insertado como superusuario {r.err.strip()[:300]}")
    for empresa, rol_ctx in ((EMPRESA_A, "A"), (EMPRESA_B, "B")):
        r = app(f"INSERT INTO canal.registro_auditoria (empresa_id, actor, accion, objeto_id) VALUES "
                f"('{empresa}', 'sistema', 'crear_denuncia', '{DEN_A1 if rol_ctx == 'A' else DEN_B1}');"
                + (f"\nINSERT INTO canal.registro_auditoria (empresa_id, actor, accion, objeto_id) VALUES "
                   f"('{empresa}', 'sistema', 'asignar_denuncia', '{DEN_A1}');" if rol_ctx == "A" else ""),
                ctx=empresa)
        pasa(sin_error(r), f"g) auditoria del fixture insertada como aplicacion con contexto {rol_ctx} {r.err.strip()[:200]}")
    r = sup("select count(*) from canal.denuncia;")
    pasa(valor(r) == "4", f"g) superusuario sin filtro ve {valor(r)} denuncias (esperado 4)")
    for nombre, ctx in (("A", EMPRESA_A), ("B", EMPRESA_B)):
        r = app("select count(*) from canal.denuncia;", ctx=ctx)
        pasa(valor(r) == "2", f"g) con contexto {nombre} se ven {valor(r)} denuncias (esperado 2)")


def conteos_contexto(ctx):
    consultas = "\n".join(f"select '{t}|' || count(*) from canal.{t};" for t in TABLAS_RLS)
    return sorted(app(consultas, ctx=ctx).lineas())


def seccion_h():
    p("=== h) aislamiento")
    for nombre, ctx, idx in (("A", EMPRESA_A, 0), ("B", EMPRESA_B, 1)):
        esperado = sorted(f"{t}|{CONTEOS[t][idx]}" for t in TABLAS_RLS)
        real = conteos_contexto(ctx)
        pasa(real == esperado, f"h) conteos con contexto {nombre}: {real}")
    esperado_cero = sorted(f"{t}|0" for t in TABLAS_RLS)
    consultas = "\n".join(f"select '{t}|' || count(*) from canal.{t};" for t in TABLAS_RLS)
    real = sorted(app(consultas).lineas())
    pasa(real == esperado_cero, "h) sin contexto (sesion nueva) todas las tablas devuelven 0")
    real = conteos_contexto("")
    pasa(real == esperado_cero, "h) con contexto vacio todas las tablas devuelven 0")
    real = conteos_contexto(str(uuid.uuid4()))
    pasa(real == esperado_cero, "h) con un uuid aleatorio todas las tablas devuelven 0")


def seccion_i():
    p("=== i) IDOR")
    r = app(f"select count(*) from canal.denuncia where id = '{DEN_B1}';", ctx=EMPRESA_A)
    ctl = app(f"select count(*) from canal.denuncia where id = '{DEN_A1}';", ctx=EMPRESA_A)
    if valor(ctl) != "1":
        sinc("i) el control (A1 devuelve 1) fallo")
    else:
        pasa(valor(r) == "0", f"i) con contexto A, SELECT de la denuncia B1 devuelve {valor(r)} filas (esperado 0)")
    cuerpo = "with a as (update canal.denuncia set estado = 'en_instruccion' where id = '{}' returning 1) select count(*) from a;"
    r = app(cuerpo.format(DEN_B1), ctx=EMPRESA_A, final="ROLLBACK")
    ctl = app(cuerpo.format(DEN_A1), ctx=EMPRESA_A, final="ROLLBACK")
    if valor(ctl) != "1":
        sinc("i) el control (UPDATE de A1 afecta 1) fallo")
    else:
        pasa(valor(r) == "0", f"i) con contexto A, UPDATE de B1 afecta {valor(r)} filas (esperado 0)")
    inserciones = {
        "denuncia": lambda e, d: f"insert into canal.denuncia (empresa_id, categoria, contenido_cifrado, version_clave) values ('{e}', 'c', {BYTES_FALSOS}, 1);",
        "mensaje": lambda e, d: f"insert into canal.mensaje (empresa_id, denuncia_id, autor, contenido_cifrado, version_clave) values ('{e}', '{d}', 'denunciante', {BYTES_FALSOS}, 1);",
        "usuario_personal": lambda e, d: f"insert into canal.usuario_personal (empresa_id, email, hash_contrasena, rol) values ('{e}', 'nuevo@ejemplo.test', 'x', 'admin');",
        "clave_empresa": lambda e, d: f"insert into canal.clave_empresa (empresa_id, version, clave_envuelta) values ('{e}', 2, {BYTES_FALSOS});",
        "registro_auditoria": lambda e, d: f"insert into canal.registro_auditoria (empresa_id, actor, accion) values ('{e}', 'prueba', 'accion');",
    }
    for tabla, f in inserciones.items():
        neg = app(f(EMPRESA_B, DEN_B1), ctx=EMPRESA_A)
        ctl = app(f(EMPRESA_A, DEN_A1), ctx=EMPRESA_A, final="ROLLBACK")
        negativo(f"i) INSERT en {tabla} con empresa_id = B", neg, "row-level security", sin_error(ctl))
    neg = app(f"update canal.denuncia set empresa_id = '{EMPRESA_B}' where id = '{DEN_A1}';", ctx=EMPRESA_A)
    ctl = app(f"update canal.denuncia set estado = 'resuelta' where id = '{DEN_A1}';", ctx=EMPRESA_A, final="ROLLBACK")
    negativo("i) cambiar empresa_id de una denuncia propia a B", neg, "permission denied", sin_error(ctl))


def seccion_j():
    p("=== j) contexto arrastrado en una misma sesion")
    def tx(ctx, etiqueta):
        fijar = f"SELECT set_config('app.empresa_id', '{ctx}', true) \\gset\n" if ctx is not None else ""
        return (f"BEGIN;\n{fijar}select '{etiqueta}|' || count(*) from canal.denuncia;\n"
                f"select '{etiqueta}ids|' || string_agg(id::text, ',' order by id) from canal.denuncia;\nCOMMIT;\n")
    sql = "SET ROLE aplicacion;\n" + tx(EMPRESA_A, "tx1") + tx(None, "tx2") + tx(EMPRESA_B, "tx3") + tx(None, "tx4")
    r = sup(sql)
    real = r.lineas()
    pasa(sin_error(r), f"j) la sesion no da errores {r.err.strip()[:200]}")
    pasa("tx1|2" in real and "tx2|0" in real and "tx3|2" in real and "tx4|0" in real,
         f"j) tx1 con A=2, tx2 sin fijar=0, tx3 con B=2, tx4 sin fijar=0 ({real})")
    pasa(f"tx3ids|{DEN_B1},{DEN_B2}" in real, "j) en tx3 las filas son las de B (ids de B)")
    pasa(not any(l.startswith("tx2ids|") and l != "tx2ids|" for l in real) and not any(l.startswith("tx4ids|") and l != "tx4ids|" for l in real),
         "j) tx2 y tx4 no devuelven ningun id")
    r = app("select count(*) from canal.denuncia;", ctx="esto-no-es-un-uuid")
    pasa("invalid input syntax for type uuid" in r.err and not r.lineas(),
         f"j) contexto no uuid: falla visible con 'invalid input syntax for type uuid' y sin filas ({r.err.strip()[:120]!r})")


def normalizar_uuid(texto):
    return re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "<UUID>", texto)


def seccion_k():
    p("=== k) fugas por duplicados y claves foraneas")
    def usuario(empresa, email):
        return f"insert into canal.usuario_personal (empresa_id, email, hash_contrasena, rol) values ('{empresa}', '{email}', 'x', 'admin');"
    neg = app(usuario(EMPRESA_B, "ana@ejemplo.test"), ctx=EMPRESA_A)
    ctl1 = app(usuario(EMPRESA_A, "ana@ejemplo.test"), ctx=EMPRESA_A)
    if "duplicate key" not in ctl1.err:
        sinc("k1) el control 1 (duplicar un email dentro de A) no dio 'duplicate key'")
    else:
        pasa("row-level security" in neg.err and "duplicate key" not in neg.err,
             "k1) INSERT en B con el email que ya existe en B -> 'row-level security' y no 'duplicate key'")
    # control 2: eva@ejemplo.test existe solo en B (instr_b); crearlo en A funciona
    ctl2 = app(usuario(EMPRESA_A, "eva@ejemplo.test"), ctx=EMPRESA_A, final="ROLLBACK")
    if sin_error(ctl2):
        pasa(True, "k1) control 2: crear en A un usuario con el email eva@ejemplo.test (solo existe en B) funciona")
    else:
        sinc("k1) el control 2 (crear en A un usuario con eva@ejemplo.test) fallo")
        p(f"   stderr: {ctl2.err.strip()[:200]!r}")
    # el error no debe distinguir un email que existe en B de uno que no existe
    existente = app(usuario(EMPRESA_B, "ana@ejemplo.test"), ctx=EMPRESA_A)
    nuevo = app(usuario(EMPRESA_B, "nuevo@ejemplo.test"), ctx=EMPRESA_A)
    if "duplicate key" not in ctl1.err or not sin_error(ctl2):
        sinc("k1) los controles (duplicado dentro de A y email de B creado en A) fallaron: no se puede comparar")
    else:
        def normalizar_email(texto):
            return re.sub(r"[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+", "<EMAIL>", normalizar_uuid(texto))
        a, b = normalizar_email(existente.err), normalizar_email(nuevo.err)
        pasa("row-level security" in existente.err and "row-level security" in nuevo.err and a == b,
             "k1) INSERT con empresa_id = B: el email existente en B y uno nuevo dan el mismo error 'row-level security'")
        if a != b or "row-level security" not in a:
            p(f"   existente: {a.strip()!r}\n   nuevo:     {b.strip()!r}")
    # k2: mensajes con denuncia ajena frente a inexistente
    def mensaje(den):
        return f"insert into canal.mensaje (empresa_id, denuncia_id, autor, contenido_cifrado, version_clave) values ('{EMPRESA_A}', '{den}', 'denunciante', {BYTES_FALSOS}, 1);"
    ajena = app(mensaje(DEN_B1), ctx=EMPRESA_A)
    inexistente = app(mensaje(str(uuid.uuid4())), ctx=EMPRESA_A)
    ctl = app(mensaje(DEN_A1), ctx=EMPRESA_A, final="ROLLBACK")
    if not sin_error(ctl):
        sinc("k2) el control (mensaje en una denuncia propia) fallo")
    else:
        a, b = normalizar_uuid(ajena.err), normalizar_uuid(inexistente.err)
        pasa("violates foreign key constraint" in a and a == b,
             "k2) mensaje con denuncia de B y con uuid aleatorio: mismo error de clave foranea")
        if a != b:
            p(f"   ajena:       {a.strip()!r}\n   inexistente: {b.strip()!r}")
    # k2 bis: denuncia.asignada_a
    def denuncia(asignada):
        return f"insert into canal.denuncia (empresa_id, categoria, contenido_cifrado, version_clave, asignada_a) values ('{EMPRESA_A}', 'c', {BYTES_FALSOS}, 1, '{asignada}');"
    ajena = app(denuncia(INSTR_B), ctx=EMPRESA_A)
    inexistente = app(denuncia(str(uuid.uuid4())), ctx=EMPRESA_A)
    ctl = app(denuncia(INSTR_A), ctx=EMPRESA_A, final="ROLLBACK")
    if not sin_error(ctl):
        sinc("k2) el control (asignar a un usuario propio) fallo")
    else:
        a, b = normalizar_uuid(ajena.err), normalizar_uuid(inexistente.err)
        pasa("violates foreign key constraint" in a and a == b,
             "k2) asignada_a de B y uuid aleatorio: mismo error de clave foranea")
        if a != b:
            p(f"   ajena:       {a.strip()!r}\n   inexistente: {b.strip()!r}")


def seccion_l():
    p("=== l) permisos por columna y negativos como aplicacion (contexto A)")
    def actualizar(sentencia):
        return app(sentencia, ctx=EMPRESA_A)
    ctl_den = app(f"update canal.denuncia set estado = 'resuelta' where id = '{DEN_A1}';", ctx=EMPRESA_A, final="ROLLBACK")
    ctl_usr = app(f"update canal.usuario_personal set intentos_fallidos = 1 where id = '{INSTR_A}';", ctx=EMPRESA_A, final="ROLLBACK")
    negativo("l) UPDATE de denuncia.contenido_cifrado",
             actualizar(f"update canal.denuncia set contenido_cifrado = '\\x09' where id = '{DEN_A1}';"), "permission denied", sin_error(ctl_den))
    negativo("l) UPDATE de denuncia.empresa_id",
             actualizar(f"update canal.denuncia set empresa_id = '{EMPRESA_A}' where id = '{DEN_A1}';"), "permission denied", sin_error(ctl_den))
    negativo("l) UPDATE de usuario_personal.rol",
             actualizar(f"update canal.usuario_personal set rol = 'admin' where id = '{INSTR_A}';"), "permission denied", sin_error(ctl_usr))
    negativo("l) UPDATE de usuario_personal.email",
             actualizar(f"update canal.usuario_personal set email = 'otro@ejemplo.test' where id = '{INSTR_A}';"), "permission denied", sin_error(ctl_usr))
    negativo("l) estado = 'inventado'",
             actualizar(f"update canal.denuncia set estado = 'inventado' where id = '{DEN_A1}';"), "violates check constraint", sin_error(ctl_den))
    ctl_select = app("select count(*) from canal.empresa;", ctx=EMPRESA_A)
    for t in TABLAS:
        negativo(f"l) DELETE sobre {t}", app(f"delete from canal.{t};", ctx=EMPRESA_A), "permission denied", sin_error(ctl_select))
        negativo(f"l) TRUNCATE sobre {t}", app(f"truncate canal.{t};", ctx=EMPRESA_A), "permission denied", sin_error(ctl_select))
    for t in ("directorio_empresas", "busqueda_seguimiento"):
        negativo(f"l) SELECT sobre {t}", app(f"select count(*) from canal.{t};", ctx=EMPRESA_A), "permission denied", sin_error(ctl_select))
    ctl_migrador = sup("SET ROLE migrador;\nBEGIN;\nCREATE TABLE canal.prueba_ctl (a int);\nCREATE FUNCTION canal.prueba_ctl_f() RETURNS int LANGUAGE sql AS 'select 1';\nROLLBACK;\n")
    negativo("l) CREATE TABLE en canal", actualizar("create table canal.prueba_x (a int);"), "permission denied for schema canal", sin_error(ctl_migrador))
    negativo("l) CREATE FUNCTION en canal",
             actualizar("create function canal.prueba_x() returns int language sql as 'select 1';"), "permission denied for schema canal", sin_error(ctl_migrador))
    ctl_dueno = sup("SET ROLE migrador;\nBEGIN;\nALTER TABLE canal.denuncia DISABLE ROW LEVEL SECURITY;\nROLLBACK;\n")
    negativo("l) ALTER TABLE ... DISABLE ROW LEVEL SECURITY",
             actualizar("alter table canal.denuncia disable row level security;"), "must be owner", sin_error(ctl_dueno))


def cliente_red(sql):
    """psql como aplicacion por la red data, con el secreto real montado sin leerlo."""
    ruta = (RAIZ / "secrets" / "contrasena_aplicacion.txt").resolve()
    return ejecutar([
        "docker", "run", "--rm", "-i", "--network", f"{PROYECTO}_data",
        "-e", "PGCONNECT_TIMEOUT=5",
        "--mount", f"type=bind,source={ruta},target=/s,readonly",
        "--entrypoint", "sh", IMAGEN,
        "-c", 'PGPASSWORD=$(cat /s) exec psql -h postgres -U aplicacion -d canario -X -q -A -t -v ON_ERROR_STOP=0 -f -',
    ], entrada=sql.encode("utf-8"))


def seccion_m():
    p("=== m) login real como aplicacion por red")
    r = cliente_red("show search_path;\nselect current_setting('is_superuser');\nselect count(*) from denuncia;\nSET ROLE migrador;\nSET ROLE postgres;\n")
    p(f"salida: {r.lineas()}\nerrores: {r.err.strip()[:400]!r}")
    pasa(r.lineas()[:1] == ["pg_catalog, canal"], "m) show search_path = 'pg_catalog, canal'")
    pasa(r.lineas()[1:2] == ["off"], "m) is_superuser = off")
    control = valor(sup("select count(*) from canal.denuncia;"))
    if control != "4":
        sinc(f"m) el control (superusuario ve 4 denuncias) dio {control!r}")
    else:
        pasa(r.lineas()[2:3] == ["0"], "m) select count(*) from denuncia (sin cualificar, sin contexto) = 0")
    pasa(r.err.count("permission denied") >= 2 and 'SET ROLE' not in r.out and len(r.lineas()) == 3,
         "m) SET ROLE migrador y SET ROLE postgres fallan con 'permission denied'")


def seccion_n():
    p("=== n) mensajes")
    cuerpo = f"""
insert into canal.denuncia (empresa_id, id, categoria, contenido_cifrado, version_clave) values ('{EMPRESA_A}', '{DEN_A3}', 'c', {BYTES_FALSOS}, 1);
insert into canal.mensaje (empresa_id, denuncia_id, autor, contenido_cifrado, version_clave) values ('{EMPRESA_A}', '{DEN_A2}', 'denunciante', {BYTES_FALSOS}, 1) returning secuencia;
insert into canal.mensaje (empresa_id, denuncia_id, autor, contenido_cifrado, version_clave) values ('{EMPRESA_A}', '{DEN_A2}', 'denunciante', {BYTES_FALSOS}, 1) returning secuencia;
insert into canal.mensaje (empresa_id, denuncia_id, autor, contenido_cifrado, version_clave) values ('{EMPRESA_A}', '{DEN_A2}', 'denunciante', {BYTES_FALSOS}, 1) returning secuencia;
insert into canal.mensaje (empresa_id, denuncia_id, secuencia, autor, contenido_cifrado, version_clave) values ('{EMPRESA_A}', '{DEN_A2}', 99, 'denunciante', {BYTES_FALSOS}, 1) returning secuencia;
insert into canal.mensaje (empresa_id, denuncia_id, autor, contenido_cifrado, version_clave) values ('{EMPRESA_A}', '{DEN_A3}', 'denunciante', {BYTES_FALSOS}, 1) returning secuencia;
"""
    r = app(cuerpo, ctx=EMPRESA_A, final="ROLLBACK")
    pasa(sin_error(r) and r.lineas() == ["1", "2", "3", "4", "1"],
         f"n) secuencias 1, 2, 3 en A2; la de 99 se ignora (4); la primera de otra denuncia es 1 ({r.lineas()}) {r.err.strip()[:200]}")

    def mensaje(autor, autor_id):
        columnas = "empresa_id, denuncia_id, autor, contenido_cifrado, version_clave" + (", autor_id" if autor_id else "")
        valores = f"'{EMPRESA_A}', '{DEN_A2}', '{autor}', {BYTES_FALSOS}, 1" + (f", '{autor_id}'" if autor_id else "")
        return f"insert into canal.mensaje ({columnas}) values ({valores});"
    ctl_personal = app(mensaje("personal", INSTR_A), ctx=EMPRESA_A, final="ROLLBACK")
    ctl_denunciante = app(mensaje("denunciante", None), ctx=EMPRESA_A, final="ROLLBACK")
    negativo("n) autor 'personal' sin autor_id", app(mensaje("personal", None), ctx=EMPRESA_A),
             "violates check constraint", sin_error(ctl_personal) and sin_error(ctl_denunciante))
    negativo("n) autor 'denunciante' con autor_id", app(mensaje("denunciante", INSTR_A), ctx=EMPRESA_A),
             "violates check constraint", sin_error(ctl_personal) and sin_error(ctl_denunciante))


def filas_auditoria(empresa):
    r = sup("select secuencia, coalesce(encode(hash_anterior, 'hex'), ''), encode(hash, 'hex'), fecha::text, actor, accion, "
            f"coalesce(objeto_id::text, '') from canal.registro_auditoria where empresa_id = '{empresa}' order by secuencia;")
    return [l.split("|") for l in r.lineas()]


def recalcular(empresa, f):
    secuencia, anterior, _hash, fecha, actor, accion, objeto = f
    elementos = [anterior or None, empresa, int(secuencia), fecha, actor, accion, objeto or None]
    serializado = json.dumps(elementos, separators=(", ", ": "), ensure_ascii=False)
    return hashlib.sha256(serializado.encode("utf-8")).hexdigest(), serializado


def verificar_cadena(ctx):
    return valor(app("select coalesce(canal.verificar_cadena_auditoria()::text, 'NULL');", ctx=ctx))


def comprobar_python(empresa, nombre):
    filas = filas_auditoria(empresa)
    previo = ""
    for i, f in enumerate(filas, 1):
        if int(f[0]) != i or f[1] != previo:
            pasa(False, f"o) {nombre}: la cadena no es consecutiva o enlazada en la fila {f[0]}")
            return False
        calculado, serializado = recalcular(empresa, f)
        if calculado != f[2]:
            p(f"   PARADA: el recalculo en Python no coincide en la fila {f[0]} de {nombre}")
            p(f"   serializacion usada: {serializado}")
            p(f"   hash calculado:      {calculado}")
            p(f"   hash guardado:       {f[2]}")
            raise Parada("el hash recalculado en Python difiere del de la base de datos (no se ajusta el test)")
        previo = f[2]
    pasa(True, f"o) {nombre}: {len(filas)} filas consecutivas, enlazadas y con el hash recalculado en Python identico")
    return True


def seccion_o():
    p("=== o) auditoria")
    antes = filas_auditoria(EMPRESA_A)
    pasa(len(antes) == 2 and antes[0][1] == "" and antes[1][1] == antes[0][2],
         f"o) fixture de A: 2 filas, la primera sin hash_anterior y la segunda enlazada ({len(antes)})")
    accion_original = antes[1][5]
    ins = lambda accion: f"insert into canal.registro_auditoria (empresa_id, actor, accion) values ('{EMPRESA_A}', 'prueba', '{accion}') returning secuencia;"
    r = app(ins("a1") + "\n" + ins("a2") + "\n" + ins("a3"), ctx=EMPRESA_A)
    pasa(r.lineas() == ["3", "4", "5"], f"o) tres INSERT continuan la secuencia sin huecos ({r.lineas()}) {r.err.strip()[:200]}")
    r = app(f"insert into canal.registro_auditoria (empresa_id, secuencia, fecha, actor, accion, hash) values "
            f"('{EMPRESA_A}', 999, '2001-01-01', 'prueba', 'falsificada', '\\x00') "
            "returning secuencia, fecha = current_date, hash <> '\\x00'::bytea;", ctx=EMPRESA_A)
    pasa(r.lineas() == ["6|t|t"], f"o) INSERT con secuencia, fecha y hash falsos queda con secuencia 6, fecha de hoy y otro hash ({r.lineas()})")
    pasa(verificar_cadena(EMPRESA_A) == "NULL", f"o) verificar_cadena_auditoria() con contexto A = NULL ({verificar_cadena(EMPRESA_A)})")
    comprobar_python(EMPRESA_A, "empresa A")
    comprobar_python(EMPRESA_B, "empresa B")
    # Inmutabilidad como aplicacion
    ctl = app("select count(*) from canal.registro_auditoria;", ctx=EMPRESA_A)
    for orden in ("update canal.registro_auditoria set accion = 'x';", "delete from canal.registro_auditoria;", "truncate canal.registro_auditoria;"):
        negativo(f"o) aplicacion: {orden.split()[0].upper()}", app(orden, ctx=EMPRESA_A), "permission denied", sin_error(ctl))
    # Inmutabilidad como superusuario (el caso de manipulacion hace de control)
    inmut = {}
    for orden in ("update canal.registro_auditoria set accion = 'x' where empresa_id = '{}' and secuencia = 2;".format(EMPRESA_A),
                  "delete from canal.registro_auditoria where empresa_id = '{}' and secuencia = 1;".format(EMPRESA_A),
                  "truncate canal.registro_auditoria;"):
        inmut[orden.split()[0].upper()] = sup(orden)
    # Manipulacion con el trigger desactivado
    control_antes = verificar_cadena(EMPRESA_A)
    manip = None
    try:
        sup("ALTER TABLE canal.registro_auditoria DISABLE TRIGGER auditoria_inmutable_fila;")
        manip = sup(f"update canal.registro_auditoria set accion = 'manipulada' where empresa_id = '{EMPRESA_A}' and secuencia = 2 returning secuencia;")
        roto = verificar_cadena(EMPRESA_A)
    finally:
        sup(f"update canal.registro_auditoria set accion = '{accion_original}' where empresa_id = '{EMPRESA_A}' and secuencia = 2;\n"
            "ALTER TABLE canal.registro_auditoria ENABLE TRIGGER auditoria_inmutable_fila;")
    control_ok = manip is not None and manip.lineas() == ["2"] and control_antes == "NULL"
    if not control_ok:
        sinc(f"o) el control de manipulacion fallo (UPDATE con trigger desactivado: {manip.lineas() if manip else None}; antes={control_antes})")
    else:
        pasa(roto == "2", f"o) tras manipular la fila 2, verificar_cadena_auditoria() devuelve {roto} (esperado 2; antes {control_antes})")
        for orden, r in inmut.items():
            pasa("inmutable" in r.err, f"o) superusuario: {orden} -> 'inmutable'")
    pasa(verificar_cadena(EMPRESA_A) == "NULL", "o) tras restaurar, verificar_cadena_auditoria() vuelve a NULL")
    r = sup("select c.relname, t.tgname, t.tgenabled from pg_trigger t join pg_class c on c.oid = t.tgrelid "
            "where c.relname = 'registro_auditoria' and not t.tgisinternal;")
    comparar("o) los tres triggers de auditoria en tgenabled = 'O'", r.lineas(), [t for t in TRIGGERS if t.startswith("registro_auditoria")])
    comprobar_python(EMPRESA_A, "empresa A tras restaurar")


def seccion_p():
    p("=== p) concurrencia")
    def insertar_tres(empresa, hilo):
        sentencias = "\n".join(
            f"BEGIN;\nSELECT set_config('app.empresa_id', '{empresa}', true) \\gset\n"
            f"insert into canal.registro_auditoria (empresa_id, actor, accion) values ('{empresa}', 'hilo{hilo}', 'concurrente{k}');\nCOMMIT;"
            for k in range(3))
        return sup("SET ROLE aplicacion;\n" + sentencias + "\n")
    antes_a, antes_b = len(filas_auditoria(EMPRESA_A)), len(filas_auditoria(EMPRESA_B))
    with concurrent.futures.ThreadPoolExecutor(max_workers=9) as pool:
        futuros = [pool.submit(insertar_tres, EMPRESA_A, i) for i in range(6)]
        futuros += [pool.submit(insertar_tres, EMPRESA_B, 10 + i) for i in range(3)]
        resultados = [f.result() for f in futuros]
    pasa(all(sin_error(x) for x in resultados), "p1) los 9 hilos terminan sin errores " + " ".join(x.err.strip()[:100] for x in resultados if not sin_error(x)))
    for empresa, nombre, antes, nuevos in ((EMPRESA_A, "A", antes_a, 18), (EMPRESA_B, "B", antes_b, 9)):
        filas = filas_auditoria(empresa)
        secuencias = [int(f[0]) for f in filas]
        pasa(secuencias == list(range(1, antes + nuevos + 1)),
             f"p1) empresa {nombre}: {len(secuencias)} secuencias consecutivas, sin duplicados ni huecos")
        pasa(verificar_cadena(empresa) == "NULL", f"p1) empresa {nombre}: verificar_cadena_auditoria() = NULL")
        comprobar_python(empresa, f"empresa {nombre} tras la concurrencia")
    # p2: bloqueo por empresa
    def medir(empresa):
        return app("SELECT clock_timestamp() AS t0 \\gset\n"
                   f"INSERT INTO canal.registro_auditoria (empresa_id, actor, accion) VALUES ('{empresa}', 'medida', 'espera');\n"
                   "SELECT round(extract(epoch FROM clock_timestamp() - :'t0'::timestamptz)::numeric, 3);",
                   ctx=empresa)
    def sesion_larga():
        return sup(sql_app(f"INSERT INTO canal.registro_auditoria (empresa_id, actor, accion) VALUES ('{EMPRESA_A}', 'larga', 'retiene');\n"
                           "select pg_sleep(5);", ctx=EMPRESA_A))
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        larga = pool.submit(sesion_larga)
        time.sleep(2)
        segunda = pool.submit(medir, EMPRESA_A)
        tercera = pool.submit(medir, EMPRESA_B)
        r2, r3, r1 = segunda.result(), tercera.result(), larga.result()
    try:
        t2, t3 = float(valor(r2)), float(valor(r3))
    except ValueError:
        sinc(f"p2) no se pudieron leer los tiempos: sesion2={r2.todo.strip()[:150]!r} sesion3={r3.todo.strip()[:150]!r}")
        return
    p(f"   tiempos medidos: sesion 2 (misma empresa) = {t2} s; sesion 3 (otra empresa) = {t3} s")
    if not sin_error(r1):
        sinc(f"p2) la sesion larga fallo: {r1.err.strip()[:200]!r}")
    elif t2 >= 1.0 and t3 < 0.5:
        pasa(True, "p2) el INSERT de la misma empresa espera >= 1,0 s y el de otra empresa tarda < 0,5 s")
    else:
        sinc(f"p2) los margenes no se cumplen (sesion 2 = {t2} s, esperado >= 1,0; sesion 3 = {t3} s, esperado < 0,5); no se ajustan umbrales")
    pasa(verificar_cadena(EMPRESA_A) == "NULL" and verificar_cadena(EMPRESA_B) == "NULL", "p2) las cadenas siguen intactas")


def seccion_q():
    p("=== q) healthcheck")
    test = json.loads(ejecutar(["docker", "inspect", CID]).out)[0]["Config"]["Healthcheck"]["Test"]
    p(f"Test: {json.dumps(test)}")
    texto = " ".join(test)
    pasa("$$" not in texto, "q) el Test no contiene '$$'")
    pasa("*|4|true" in texto and not re.search(r"\*\|4(?!\|true)", texto), "q) el Test acepta solo '*|4|true'")
    orden = test[-1]
    control = dc("exec", "-T", "postgres", "sh", "-c", orden)
    if control.rc != 0:
        sinc(f"q) el control del Test no da 0 (codigo {control.rc})")
        return
    pasa(True, "q) control: el Test da 0")
    try:
        sup("ALTER TABLE canal.registro_auditoria RENAME TO registro_auditoria_x;")
        r = dc("exec", "-T", "postgres", "sh", "-c", orden)
        pasa(r.rc == 1, f"q) con la tabla centinela renombrada el Test da {r.rc} (esperado 1)")
    finally:
        sup("ALTER TABLE canal.registro_auditoria_x RENAME TO registro_auditoria;")
    r = dc("exec", "-T", "postgres", "sh", "-c", orden)
    pasa(r.rc == 0, f"q) tras renombrar de vuelta el Test da {r.rc} (esperado 0)")
    r = dc("exec", "-T", "postgres", "sh", "-c", orden.replace("-U postgres", "-U nadie"))
    pasa(r.rc == 1, f"q) con -U nadie el Test da {r.rc} (esperado 1)")


def esperar_healthy(cid, maximo=60):
    estado_salud = ""
    for _ in range(maximo):
        estado_salud = ejecutar(["docker", "inspect", "--format", "{{.State.Health.Status}}", cid]).out.strip()
        if estado_salud == "healthy":
            break
        time.sleep(1)
    return estado_salud


def seccion_r():
    global CID
    p("=== r) persistencia")
    dc("down")
    r = dc("up", "-d", "--wait", "postgres")
    p(f"down (sin -v) y up -d --wait postgres -> codigo {r.rc}")
    CID = dc("ps", "-q", "postgres").out.strip()
    registro = dc("logs", "--no-log-prefix", "postgres").todo
    pasa("Skipping initialization" in registro, "r) el log del contenedor nuevo contiene 'Skipping initialization'")
    comparar("r) siguen las 8 tablas", sup("select c.relname from pg_class c join pg_namespace n on n.oid = c.relnamespace "
                                         "where n.nspname = 'canal' and c.relkind = 'r';").lineas(), TABLAS)
    politicas = sup("select tablename, policyname, cmd from pg_policies where schemaname = 'canal';").lineas()
    tablas_con_politicas = {l.split("|")[0] for l in politicas}
    comparar("r) siguen las 13 politicas definidas en d)", politicas, POLITICAS)
    pasa(len(politicas) == 13 and len(tablas_con_politicas) == 6,
         f"r) exactamente 13 politicas repartidas en exactamente 6 tablas ({len(politicas)} politicas, {len(tablas_con_politicas)} tablas)")
    pasa(esperar_healthy(CID) == "healthy", "r) el contenedor esta healthy")


def seccion_s():
    p("=== s) limpieza")
    r = dc("down", "-v")
    p(f"down -v -> codigo {r.rc}")
    for etiqueta, orden in [
        ("contenedor", ["docker", "ps", "-a", "--format", "{{.Names}}"]),
        ("red", ["docker", "network", "ls", "--format", "{{.Name}}"]),
        ("volumen", ["docker", "volume", "ls", "--format", "{{.Name}}"]),
    ]:
        restos = [n for n in ejecutar(orden).out.split() if n.startswith(PROYECTO)]
        pasa(not restos, f"s) ningun {etiqueta} con prefijo {PROYECTO} {restos if restos else ''}".strip())
    for nombre in ("contrasena_postgres_superusuario", "contrasena_migrador", "contrasena_aplicacion", "contrasena_plataforma"):
        ruta = RAIZ / "secrets" / f"{nombre}.txt"
        pasa(ruta.is_file() and not ruta.is_dir(), f"s) secrets/{nombre}.txt sigue siendo un fichero")
    r = ejecutar(["git", "status", "--short", "-uall"])
    esperado = [" M docker-compose.yml", "?? db/init/02_esquema.sql", "?? tests/security/verificar_esquema.py"]
    comparar("s) git status solo muestra los tres cambios esperados", [l.rstrip() for l in r.out.splitlines() if l.strip()], esperado)


def terminar():
    if estado["falla"] or estado["sin_conclusion"]:
        resultado = "NO OK (hay FALLA o SIN CONCLUSION)"
    else:
        resultado = "OK"
    p("RESULTADO GLOBAL: " + resultado)
    SALIDA.write_text("\n".join(lineas_salida) + "\n", encoding="utf-8", newline="\n")
    sys.exit(0 if resultado == "OK" else 1)


def recursos_previos():
    previos = []
    for orden in (["docker", "ps", "-a", "--format", "{{.Names}}"],
                  ["docker", "network", "ls", "--format", "{{.Name}}"],
                  ["docker", "volume", "ls", "--format", "{{.Name}}"]):
        previos += [n for n in ejecutar(orden).out.split() if n.startswith(PROYECTO)]
    return previos


def main():
    global IMAGEN, CID
    # Precondiciones: si fallan, no se limpia nada (podrian ser recursos ajenos).
    if ejecutar(["docker", "info", "--format", "{{.ServerVersion}}"]).rc != 0:
        p("PARADA: docker info falla")
        terminar_con_parada()
    previos = recursos_previos()
    if previos:
        p(f"PARADA: ya existen recursos con prefijo {PROYECTO}: {previos}")
        terminar_con_parada()
    for nombre in ("contrasena_aplicacion",):
        if not (RAIZ / "secrets" / f"{nombre}.txt").is_file():
            p(f"PARADA: secrets/{nombre}.txt no existe como fichero")
            terminar_con_parada()
    imagenes = [l.strip() for l in dc("config", "--images").out.splitlines() if l.strip().startswith("postgres")]
    IMAGEN = imagenes[0] if imagenes else ""
    p(f"imagen de postgres: {IMAGEN}")
    parada = None
    try:
        if not IMAGEN:
            raise Parada("no hay imagen que empiece por postgres")
        seccion_a()
        CID = dc("ps", "-q", "postgres").out.strip()
        for seccion in (seccion_b, seccion_c, seccion_d, seccion_e, seccion_f, seccion_g, seccion_h, seccion_i,
                        seccion_j, seccion_k, seccion_l, seccion_m, seccion_n, seccion_o, seccion_p, seccion_q,
                        seccion_r):
            seccion()
    except Parada as e:
        parada = str(e)
        p(f"PARADA: {parada}")
    except Exception:  # error inesperado del propio test: se informa y se limpia
        parada = "error inesperado en el test"
        p("ERROR INESPERADO:\n" + traceback.format_exc())
    finally:
        if parada is not None:
            dc("down", "-v")
        else:
            seccion_s()
    if parada is not None:
        estado["falla"] = True
    terminar()


def terminar_con_parada():
    p("RESULTADO GLOBAL: NO OK (PARADA)")
    SALIDA.write_text("\n".join(lineas_salida) + "\n", encoding="utf-8", newline="\n")
    sys.exit(1)


if __name__ == "__main__":
    main()
