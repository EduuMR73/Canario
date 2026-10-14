#!/usr/bin/env python3
"""Batería de pruebas de seguridad del esquema "canal" (db/init/02_esquema.sql,
db/init/03_funciones.sql, db/init/04_supresion.sql y db/init/05_redaccion.sql).

Qué prueba: que el esquema y las funciones de definidor se aplican enteros al
arrancar, que la estructura, las políticas RLS y los permisos coinciden con
unos oráculos escritos aquí como literales (no derivados del SQL), que una
empresa no puede ver ni tocar los datos de otra, que los permisos por columna
se cumplen, que la auditoría es encadenada e inmutable (con recálculo
independiente del hash en Python), que la fecha de una denuncia, de un mensaje
y de una fila de auditoría es el día en la zona horaria de su empresa (sin
depender de la fecha del INSERT ni de la zona de la sesión), que una denuncia
cerrada no admite mensajes, que una no veraz da el error de una inexistente,
y que hay un tope de mensajes por denuncia, que el
cierre de una denuncia y un mensaje simultáneos no se interbloquean y que un
mensaje rechazado entre empresas no bloquea a la otra, que el bloqueo por
empresa y el healthcheck se comportan como se espera, que las funciones de
definidor hacen solo lo que deben (también frente a un search_path hostil), y
que la supresión legal (arts. 32.4 y 26.2 de la Ley 2/2023) borra solo lo
caducado, con sus bordes (también la denuncia inadmitida, a la que no se dio
curso), borra sin plazo la declarada no veraz (art. 32.3, con prioridad sobre
los otros dos artículos), salta lo que está en uso sin esperar, respeta una
denuncia que pasa a instrucción en carrera y deja su evidencia en la
auditoría. Que la redacción (art. 32.2) solo reescribe el contenido de una
denuncia o de un mensaje asignado a un admin activo de la empresa del
contexto, solo si sigue siendo el que se leyó, con su fila de auditoría en la
misma sentencia, y que aplicacion sigue sin poder cambiar ningún contenido
cifrado por su cuenta. También la autenticación: el pg_hba.conf que manda es el del
repositorio, sin trust; el superusuario solo entra por el socket con peer;
las contraseñas se guardan en SCRAM-SHA-256 y un cliente que exige md5 no
entra; y los roles de Canario solo llegan a la base canario.
Cada prueba negativa lleva su
control positivo: si el control falla, el resultado es SIN CONCLUSION, nunca
PASA.

Cómo se ejecuta (desde la raíz del repositorio, con Docker en marcha):

    python tests/security/verificar_esquema.py

Usa un proyecto de Docker propio (canario_esquema), con su red y su volumen, y
solo levanta el servicio postgres (con su imagen, db/Dockerfile). Nunca toca el
proyecto canario. Al terminar lo borra todo (down -v y la imagen construida).
Necesita que existan secrets/contrasena_*.txt (solo
comprueba que son ficheros; los de aplicacion y plataforma llegan a un
contenedor temporal montados en solo lectura, y nunca se leen ni se imprimen).

Requisitos: Docker en marcha, Python 3, y que existan
secrets/contrasena_aplicacion.txt y secrets/contrasena_plataforma.txt (se
generan con scripts/generar_secretos.py). La batería no modifica el repo y se
puede ejecutar con el árbol de Git limpio o sucio: la comprobación s) compara
el estado de Git al terminar con el que había al arrancar.

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
IDENT_A = "a" * 32  # identificador publico de la empresa A en directorio_empresas
IDENT_B = "b" * 32
IDENT_FALSO = "f" * 32  # solo existe en la tabla temporal de la prueba w
IDENT_DESCONOCIDO = "0123456789abcdef0123456789abcdef"
HMAC1 = "ab" * 32  # HMAC de prueba de 32 bytes (hexadecimal)
HMAC2 = "cd" * 32
HMAC3 = "ef" * 32
HMAC31 = "ab" * 31  # 31 bytes: demasiado corto
# Supresion (seccion su): una empresa propia, para no tocar los conteos de A y B
EMPRESA_C = "c0000000-0000-4000-8000-000000000003"
# caso -> (id, antiguedad respecto a hoy en la zona de C como expresion SQL, estado).
# Los bordes: un dia menos que el plazo (hoy - 3 meses + 1 dia) se conserva.
SU = {
    "art32": ("c0000000-0000-4000-8000-0000000000e1", "interval '3 months'", "nueva"),
    "art32_borde": ("c0000000-0000-4000-8000-0000000000e2", "(interval '3 months' - interval '1 day')", "nueva"),
    "instruccion": ("c0000000-0000-4000-8000-0000000000e3", "interval '4 months'", "en_instruccion"),
    "art26": ("c0000000-0000-4000-8000-0000000000e4", "interval '10 years'", "archivada"),
    "art26_borde": ("c0000000-0000-4000-8000-0000000000e5", "(interval '10 years' - interval '1 day')", "resuelta"),
    "en_uso": ("c0000000-0000-4000-8000-0000000000e6", "interval '5 months'", "nueva"),
    "carrera": ("c0000000-0000-4000-8000-0000000000e7", "interval '5 months'", "nueva"),
    "carrera_ctl": ("c0000000-0000-4000-8000-0000000000e8", "interval '5 months'", "nueva"),
    # Comunicacion a la que no se dio curso (art. 32.4): se suprime a los 3
    # meses como 'nueva'; con un dia menos se conserva.
    "inadmitida": ("c0000000-0000-4000-8000-0000000000e9", "interval '3 months'", "inadmitida"),
    "inadmitida_borde": ("c0000000-0000-4000-8000-0000000000ea", "(interval '3 months' - interval '1 day')",
                         "inadmitida"),
    # Declarada no veraz (art. 32.3): se suprime sin plazo, aunque sea de hoy.
    # La de 10 anos comprueba la prioridad: sale como art32_3, no art26 (y,
    # con la misma fecha que "art26", va detras por id en el orden del lote).
    # Control: una nueva de hoy se conserva.
    "no_veraz": ("c0000000-0000-4000-8000-0000000000eb", "interval '0 days'", "no_veraz"),
    "no_veraz_10": ("c0000000-0000-4000-8000-0000000000ec", "interval '10 years'", "no_veraz"),
    "nueva_hoy": ("c0000000-0000-4000-8000-0000000000ed", "interval '0 days'", "nueva"),
}
HMAC_SU_ART32 = "a1" * 32
HMAC_SU_ART26 = "a2" * 32
HMAC_SU_BORDE = "a3" * 32
HMAC_SU_NO_VERAZ = "a4" * 32
# Comprobado en postgres:18.6-alpine con pg_get_constraintdef (13 oct).
CHECK_ESTADO = ("CHECK ((estado = ANY (ARRAY['nueva'::text, 'en_instruccion'::text, 'resuelta'::text, "
                "'archivada'::text, 'inadmitida'::text, 'no_veraz'::text])))")
# Redaccion (seccion re): una empresa propia, como la supresion.
EMPRESA_D = "d0000000-0000-4000-8000-000000000004"
ADMIN_D = "d0000000-0000-4000-8000-0000000000a1"
ADMIN2_D = "d0000000-0000-4000-8000-0000000000a2"
INSTR_D = "d0000000-0000-4000-8000-0000000000a3"
BAJA_D = "d0000000-0000-4000-8000-0000000000a4"  # admin activado y dado de baja
RE_D1 = "d0000000-0000-4000-8000-0000000000d1"  # asignada a ADMIN_D
RE_D2 = "d0000000-0000-4000-8000-0000000000d2"  # asignada a INSTR_D
RE_D3 = "d0000000-0000-4000-8000-0000000000d3"  # asignada a ADMIN_D, no veraz
RE_D4 = "d0000000-0000-4000-8000-0000000000d4"  # asignada a BAJA_D
RE_M1 = "d0000000-0000-4000-8000-0000000000e1"  # mensaje 1 de RE_D1
# Errores de 05_redaccion.sql con VERBOSITY verbose.
TEXTO_REDACCION_ACTOR = "42501: la redaccion exige un admin activo de la empresa"
TEXTO_REDACCION_DENUNCIA = ("CN003: la denuncia no se puede redactar: no esta asignada al actor "
                            "o su contenido ha cambiado")
TEXTO_REDACCION_MENSAJE_DENUNCIA = "CN003: el mensaje no se puede redactar: la denuncia no esta asignada al actor"
TEXTO_REDACCION_MENSAJE = "CN003: el mensaje no se puede redactar: no existe o su contenido ha cambiado"
TEXTO_LOTE = "el lote debe estar entre 1 y 500"
TEXTO_AISLAMIENTO = "la supresion exige el nivel de aislamiento READ COMMITTED"

# ---------------------------------------------------------------------------
# Oráculos literales
# ---------------------------------------------------------------------------
TABLAS = ["busqueda_seguimiento", "clave_empresa", "denuncia", "directorio_empresas", "dispositivo_personal",
          "empresa", "invitacion_personal", "mensaje", "registro_auditoria", "sesion_personal", "usuario_personal"]
TABLAS_RLS = ["clave_empresa", "denuncia", "dispositivo_personal", "empresa", "invitacion_personal", "mensaje",
              "registro_auditoria", "sesion_personal", "usuario_personal"]
TABLAS_SIN_RLS = ["busqueda_seguimiento", "directorio_empresas"]
COLUMNAS = {
    "empresa": ["id", "nombre", "activa", "fecha_alta", "zona_horaria"],
    "directorio_empresas": ["identificador_publico", "empresa_id"],
    "clave_empresa": ["empresa_id", "version", "clave_envuelta"],
    "usuario_personal": ["empresa_id", "id", "email", "hash_contrasena", "rol", "secreto_totp_cifrado",
                         "totp_activo", "intentos_fallidos", "bloqueado_hasta", "activo", "version_clave_totp",
                         "ultimo_paso_totp"],
    "invitacion_personal": ["empresa_id", "id", "usuario_id", "token_sha256", "caduca", "cerrada", "hash_contrasena",
                            "secreto_totp_cifrado", "version_clave_totp"],
    "dispositivo_personal": ["empresa_id", "id", "usuario_id", "token_sha256", "caduca", "intentos_fallidos",
                             "bloqueado_hasta", "revocado"],
    "sesion_personal": ["empresa_id", "id", "usuario_id", "dispositivo_id", "token_sha256", "ultimo_uso", "caduca",
                        "revocada"],
    # Sin categoria: va dentro de contenido_cifrado.
    "denuncia": ["empresa_id", "id", "fecha", "estado", "asignada_a", "contenido_cifrado", "version_clave"],
    "mensaje": ["empresa_id", "denuncia_id", "secuencia", "fecha", "id", "autor", "autor_id", "contenido_cifrado",
                "version_clave"],
    "busqueda_seguimiento": ["codigo_hmac", "empresa_id", "denuncia_id"],
    "registro_auditoria": ["empresa_id", "secuencia", "fecha", "actor", "accion", "objeto_id", "destino_id",
                           "hash_anterior", "hash"],
}

CLAVES_PRIMARIAS = [
    "busqueda_seguimiento|PRIMARY KEY (codigo_hmac)",
    "clave_empresa|PRIMARY KEY (empresa_id, version)",
    "denuncia|PRIMARY KEY (empresa_id, id)",
    "directorio_empresas|PRIMARY KEY (identificador_publico)",
    "empresa|PRIMARY KEY (id)",
    "mensaje|PRIMARY KEY (empresa_id, denuncia_id, secuencia)",
    "registro_auditoria|PRIMARY KEY (empresa_id, secuencia)",
    "usuario_personal|PRIMARY KEY (empresa_id, id)",
    "invitacion_personal|PRIMARY KEY (empresa_id, id)",
    "dispositivo_personal|PRIMARY KEY (empresa_id, id)",
    "sesion_personal|PRIMARY KEY (empresa_id, id)",
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
    "usuario_personal|empresa_id,version_clave_totp|clave_empresa|empresa_id,version|a",
    "invitacion_personal|empresa_id,usuario_id|usuario_personal|empresa_id,id|a",
    "invitacion_personal|empresa_id,version_clave_totp|clave_empresa|empresa_id,version|a",
    "dispositivo_personal|empresa_id,usuario_id|usuario_personal|empresa_id,id|a",
    "sesion_personal|empresa_id,usuario_id|usuario_personal|empresa_id,id|a",
    # La sesión exige que su dispositivo sea de su mismo usuario.
    "sesion_personal|empresa_id,usuario_id,dispositivo_id|dispositivo_personal|empresa_id,usuario_id,id|a",
]
# tabla|politica|comando (22 de aplicacion + 2 de propietario_funciones + 8 de propietario_supresion
# + 8 de propietario_redaccion)
POLITICAS_APLICACION = [
    "empresa|empresa_select|SELECT",
    "clave_empresa|clave_empresa_select|SELECT",
    "clave_empresa|clave_empresa_insert|INSERT",
    "usuario_personal|usuario_personal_select|SELECT",
    "usuario_personal|usuario_personal_insert|INSERT",
    "usuario_personal|usuario_personal_update|UPDATE",
    "invitacion_personal|invitacion_personal_select|SELECT",
    "invitacion_personal|invitacion_personal_insert|INSERT",
    "invitacion_personal|invitacion_personal_update|UPDATE",
    "dispositivo_personal|dispositivo_personal_select|SELECT",
    "dispositivo_personal|dispositivo_personal_insert|INSERT",
    "dispositivo_personal|dispositivo_personal_update|UPDATE",
    "sesion_personal|sesion_personal_select|SELECT",
    "sesion_personal|sesion_personal_insert|INSERT",
    "sesion_personal|sesion_personal_update|UPDATE",
    "denuncia|denuncia_select|SELECT",
    "denuncia|denuncia_insert|INSERT",
    "denuncia|denuncia_update|UPDATE",
    "mensaje|mensaje_select|SELECT",
    "mensaje|mensaje_insert|INSERT",
    "registro_auditoria|registro_auditoria_select|SELECT",
    "registro_auditoria|registro_auditoria_insert|INSERT",
]
POLITICAS_DEFINIDOR = [
    "empresa|empresa_select_definidor|SELECT",
    "empresa|empresa_insert_definidor|INSERT",
]
# Las unicas con DELETE del esquema: las del dueno de la supresion. La de UPDATE
# solo sirve para bloquear (USING true, WITH CHECK false).
# tabla|politica|comando|USING|WITH CHECK
POLITICAS_SUPRESION_COMPLETAS = [
    "empresa|empresa_select_supresion|SELECT|true|",
    "denuncia|denuncia_select_supresion|SELECT|true|",
    "denuncia|denuncia_bloqueo_supresion|UPDATE|true|false",
    "denuncia|denuncia_delete_supresion|DELETE|true|",
    "mensaje|mensaje_select_supresion|SELECT|true|",
    "mensaje|mensaje_delete_supresion|DELETE|true|",
    "registro_auditoria|registro_auditoria_select_supresion|SELECT|true|",
    "registro_auditoria|registro_auditoria_insert_supresion|INSERT||true",
]
POLITICAS_SUPRESION = ["|".join(l.split("|")[:3]) for l in POLITICAS_SUPRESION_COMPLETAS]
# Las del dueno de la redaccion: todas dentro del contexto de la empresa (a
# diferencia de las de supresion, que recorren todas). Sin DELETE.
POLITICAS_REDACCION_COMPLETAS = [
    "empresa|empresa_select_redaccion|SELECT|(id = canal.empresa_actual())|",
    "usuario_personal|usuario_personal_select_redaccion|SELECT|(empresa_id = canal.empresa_actual())|",
    "denuncia|denuncia_select_redaccion|SELECT|(empresa_id = canal.empresa_actual())|",
    ("denuncia|denuncia_update_redaccion|UPDATE|(empresa_id = canal.empresa_actual())"
     "|(empresa_id = canal.empresa_actual())"),
    "mensaje|mensaje_select_redaccion|SELECT|(empresa_id = canal.empresa_actual())|",
    ("mensaje|mensaje_update_redaccion|UPDATE|(empresa_id = canal.empresa_actual())"
     "|(empresa_id = canal.empresa_actual())"),
    "registro_auditoria|registro_auditoria_select_redaccion|SELECT|(empresa_id = canal.empresa_actual())|",
    "registro_auditoria|registro_auditoria_insert_redaccion|INSERT||(empresa_id = canal.empresa_actual())",
]
POLITICAS_REDACCION = ["|".join(l.split("|")[:3]) for l in POLITICAS_REDACCION_COMPLETAS]
POLITICAS = POLITICAS_APLICACION + POLITICAS_DEFINIDOR + POLITICAS_SUPRESION + POLITICAS_REDACCION
NOMBRES_POLITICAS_DEFINIDOR = {"empresa_select_definidor", "empresa_insert_definidor"}
NOMBRES_POLITICAS_SUPRESION = {l.split("|")[1] for l in POLITICAS_SUPRESION_COMPLETAS}
NOMBRES_POLITICAS_REDACCION = {l.split("|")[1] for l in POLITICAS_REDACCION_COMPLETAS}

# Privilegios de tabla por rol (UPDATE solo por columna, nunca a nivel de tabla)
PRIVILEGIOS_TABLA = {
    # En las tablas del personal, INSERT solo por columna: la API no puede
    # crear una cuenta ya activada ni elegir una caducidad.
    "aplicacion": {
        "empresa": {"SELECT"},
        "clave_empresa": {"SELECT", "INSERT"},
        "usuario_personal": {"SELECT"},
        "invitacion_personal": {"SELECT"},
        "dispositivo_personal": {"SELECT"},
        "sesion_personal": {"SELECT"},
        "denuncia": {"SELECT", "INSERT"},
        "mensaje": {"SELECT", "INSERT"},
        "registro_auditoria": {"SELECT", "INSERT"},
        "directorio_empresas": set(),
        "busqueda_seguimiento": set(),
    },
    "plataforma": {t: set() for t in TABLAS},
    "propietario_funciones": {
        "empresa": set(), "clave_empresa": set(), "usuario_personal": set(), "denuncia": set(),
        "mensaje": set(), "registro_auditoria": set(),
        "invitacion_personal": set(), "dispositivo_personal": set(), "sesion_personal": set(),
        "directorio_empresas": {"SELECT"},
        "busqueda_seguimiento": {"SELECT", "INSERT"},
    },
    # El unico rol con DELETE, y solo en lo que suprime. SELECT, UPDATE e
    # INSERT solo por columna.
    "propietario_supresion": {
        "empresa": set(), "clave_empresa": set(), "usuario_personal": set(),
        "invitacion_personal": set(), "dispositivo_personal": set(), "sesion_personal": set(),
        "denuncia": {"DELETE"}, "mensaje": {"DELETE"}, "busqueda_seguimiento": {"DELETE"},
        "registro_auditoria": set(), "directorio_empresas": set(),
    },
    # Nada a nivel de tabla: todo por columna.
    "propietario_redaccion": {t: set() for t in TABLAS},
}
# Privilegios concedidos solo en algunas columnas: rol -> (tabla, privilegio) -> columnas
PRIVILEGIOS_COLUMNA = {
    "aplicacion": {
        ("usuario_personal", "INSERT"): {"empresa_id", "email", "rol"},
        ("usuario_personal", "UPDATE"): {"hash_contrasena", "secreto_totp_cifrado", "version_clave_totp",
                                         "totp_activo", "ultimo_paso_totp", "intentos_fallidos", "bloqueado_hasta",
                                         "activo"},
        ("invitacion_personal", "INSERT"): {"empresa_id", "usuario_id", "token_sha256"},
        ("invitacion_personal", "UPDATE"): {"cerrada", "hash_contrasena", "secreto_totp_cifrado",
                                            "version_clave_totp"},
        ("dispositivo_personal", "INSERT"): {"empresa_id", "usuario_id", "token_sha256"},
        ("dispositivo_personal", "UPDATE"): {"intentos_fallidos", "bloqueado_hasta", "revocado"},
        ("sesion_personal", "INSERT"): {"empresa_id", "usuario_id", "dispositivo_id", "token_sha256"},
        ("sesion_personal", "UPDATE"): {"ultimo_uso", "revocada"},
        ("denuncia", "UPDATE"): {"estado", "asignada_a"},
    },
    "plataforma": {},
    "propietario_funciones": {
        ("empresa", "SELECT"): {"id", "activa"},
        ("empresa", "INSERT"): {"nombre", "zona_horaria"},
        ("directorio_empresas", "INSERT"): {"empresa_id"},
    },
    "propietario_supresion": {
        ("empresa", "SELECT"): {"id", "zona_horaria"},
        ("denuncia", "SELECT"): {"empresa_id", "id", "fecha", "estado"},
        # Solo para poder bloquear con FOR UPDATE (la politica lo deja en eso).
        ("denuncia", "UPDATE"): {"estado"},
        ("mensaje", "SELECT"): {"empresa_id", "denuncia_id"},
        ("busqueda_seguimiento", "SELECT"): {"empresa_id", "denuncia_id"},
        ("registro_auditoria", "SELECT"): {"empresa_id", "secuencia", "hash"},
        ("registro_auditoria", "INSERT"): {"empresa_id", "actor", "accion", "objeto_id"},
    },
    # El unico rol que puede reescribir contenido cifrado, y solo eso (con su
    # version de clave). Lee lo que comprueba antes de escribir.
    "propietario_redaccion": {
        ("empresa", "SELECT"): {"id", "zona_horaria"},
        ("usuario_personal", "SELECT"): {"empresa_id", "id", "rol", "activo", "totp_activo"},
        ("denuncia", "SELECT"): {"empresa_id", "id", "estado", "asignada_a", "contenido_cifrado"},
        ("denuncia", "UPDATE"): {"contenido_cifrado", "version_clave"},
        ("mensaje", "SELECT"): {"empresa_id", "denuncia_id", "secuencia", "id", "contenido_cifrado"},
        ("mensaje", "UPDATE"): {"contenido_cifrado", "version_clave"},
        ("registro_auditoria", "SELECT"): {"empresa_id", "secuencia", "hash"},
        ("registro_auditoria", "INSERT"): {"empresa_id", "actor", "accion", "objeto_id", "destino_id"},
    },
}
COLUMNAS_UPDATE = {
    "usuario_personal": {"hash_contrasena", "secreto_totp_cifrado", "version_clave_totp", "totp_activo",
                         "ultimo_paso_totp", "intentos_fallidos", "bloqueado_hasta", "activo"},
    "invitacion_personal": {"cerrada", "hash_contrasena", "secreto_totp_cifrado", "version_clave_totp"},
    "dispositivo_personal": {"intentos_fallidos", "bloqueado_hasta", "revocado"},
    "sesion_personal": {"ultimo_uso", "revocada"},
    "denuncia": {"estado", "asignada_a"},
}
PRIVILEGIOS = ["SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"]
PRIVILEGIOS_COLUMNA_COMPROBADOS = ["SELECT", "INSERT", "UPDATE", "REFERENCES"]
ROLES = ["aplicacion", "plataforma", "propietario_funciones", "propietario_supresion", "propietario_redaccion"]

# funcion -> (dueno, SECURITY DEFINER, volatilidad, firma)
FUNCIONES_CATALOGO = {
    "preparar_mensaje": ("migrador", "f", "v", "canal.preparar_mensaje()"),
    "empresa_actual": ("migrador", "f", "s", "canal.empresa_actual()"),
    "encadenar_auditoria": ("migrador", "f", "v", "canal.encadenar_auditoria()"),
    "fijar_fecha_denuncia": ("migrador", "f", "v", "canal.fijar_fecha_denuncia()"),
    "rechazar_modificacion_auditoria": ("migrador", "f", "v", "canal.rechazar_modificacion_auditoria()"),
    "verificar_cadena_auditoria": ("migrador", "f", "s", "canal.verificar_cadena_auditoria()"),
    "resolver_empresa": ("propietario_funciones", "t", "s", "canal.resolver_empresa(text)"),
    "buscar_codigo": ("propietario_funciones", "t", "s", "canal.buscar_codigo(bytea)"),
    "registrar_codigo": ("propietario_funciones", "t", "v", "canal.registrar_codigo(bytea,uuid)"),
    "alta_empresa": ("propietario_funciones", "t", "v", "canal.alta_empresa(text,text)"),
    "articulo_supresion": ("propietario_supresion", "f", "s", "canal.articulo_supresion(text,date,text)"),
    "suprimir_denuncias_caducadas": ("propietario_supresion", "t", "v", "canal.suprimir_denuncias_caducadas(integer)"),
    "contar_denuncias_caducadas": ("propietario_supresion", "t", "s", "canal.contar_denuncias_caducadas()"),
    "redactar_denuncia": ("propietario_redaccion", "t", "v", "canal.redactar_denuncia(uuid,uuid,bytea,bytea,integer)"),
    "redactar_mensaje": ("propietario_redaccion", "t", "v",
                         "canal.redactar_mensaje(uuid,integer,uuid,bytea,bytea,integer)"),
}
FUNCIONES_DEFINIDOR = ["resolver_empresa", "buscar_codigo", "registrar_codigo", "alta_empresa",
                       "suprimir_denuncias_caducadas", "contar_denuncias_caducadas",
                       "redactar_denuncia", "redactar_mensaje"]
CONFIG_DEFINIDOR = "search_path=pg_catalog, canal, pg_temp"
# funcion -> roles con EXECUTE. propietario_funciones tiene EXECUTE sobre las suyas por ser su dueno
# (es el privilegio implicito del dueno; no se le revoca).
EXECUTE_ESPERADO = {
    "preparar_mensaje": set(),
    "empresa_actual": {"aplicacion", "propietario_funciones", "propietario_redaccion"},
    "encadenar_auditoria": set(),
    "fijar_fecha_denuncia": set(),
    "rechazar_modificacion_auditoria": set(),
    "verificar_cadena_auditoria": {"aplicacion"},
    "resolver_empresa": {"aplicacion", "propietario_funciones"},
    "buscar_codigo": {"aplicacion", "propietario_funciones"},
    "registrar_codigo": {"aplicacion", "propietario_funciones"},
    "alta_empresa": {"plataforma", "propietario_funciones"},
    # articulo_supresion solo la ejecuta su dueno (desde las otras dos).
    "articulo_supresion": {"propietario_supresion"},
    "suprimir_denuncias_caducadas": {"plataforma", "propietario_supresion"},
    "contar_denuncias_caducadas": {"plataforma", "propietario_supresion"},
    # La API las ejecuta; su dueno, por serlo.
    "redactar_denuncia": {"aplicacion", "propietario_redaccion"},
    "redactar_mensaje": {"aplicacion", "propietario_redaccion"},
}
TRIGGERS = [
    "denuncia|denuncia_fecha|O",
    "mensaje|mensaje_preparar|O",
    "registro_auditoria|auditoria_encadenar|O",
    "registro_auditoria|auditoria_inmutable_fila|O",
    "registro_auditoria|auditoria_inmutable_truncate|O",
]
# Errores de canal.preparar_mensaje(). Los de estado y tope con su SQLSTATE
# propio, tal como los muestra psql con VERBOSITY verbose.
TEXTO_MENSAJE_SIN_DENUNCIA = "el mensaje no corresponde a ninguna denuncia visible"
TEXTO_DENUNCIA_CERRADA = "CN001: la denuncia esta cerrada y no admite mensajes"
TEXTO_LIMITE_MENSAJES = "CN002: la denuncia ha alcanzado el maximo de 200 mensajes"
MAXIMO_MENSAJES = 200
TEXTO_PLAZO_BLOQUEO = "canceling statement due to lock timeout"
# Conteos esperados con contexto A y B
CONTEOS = {
    "empresa": (1, 1), "clave_empresa": (1, 1), "usuario_personal": (2, 2),
    "denuncia": (2, 2), "mensaje": (2, 1), "registro_auditoria": (2, 1),
    "invitacion_personal": (1, 1), "dispositivo_personal": (1, 2), "sesion_personal": (1, 1),
}
# Fixture del personal (g): huellas de token de 32 bytes y uuid fijos.
DISP_A = "a0000000-0000-4000-8000-0000000000f1"
DISP_B = "b0000000-0000-4000-8000-0000000000f1"
DISP_B2 = "b0000000-0000-4000-8000-0000000000f2"
TOKEN_INV_A = "11" * 32
TOKEN_INV_B = "12" * 32
TOKEN_DISP_A = "21" * 32
TOKEN_DISP_B = "22" * 32
TOKEN_DISP_B2 = "23" * 32
TOKEN_SES_A = "31" * 32
TOKEN_SES_B = "32" * 32
ADMIN_DE = {EMPRESA_A: ADMIN_A, EMPRESA_B: ADMIN_B}
DISP_DE = {EMPRESA_A: DISP_A, EMPRESA_B: DISP_B}
TEXTO_CREDENCIALES = "usuario_personal_credenciales_check"
TEXTO_PENDIENTE = "invitacion_personal_pendiente_check"

# Autenticación (db/pg_hba.conf y docker-compose.yml), seccion au. Literales
# comprobados contra postgres:18.6-alpine con el pg_hba.conf del repositorio.
HBA_FILE = "/etc/postgresql/pg_hba.conf"
# rule_number|type|database|user_name|address|netmask|auth_method|options
REGLAS_HBA = [
    "1|local|{all}|{postgres}|||peer|",
    "2|host|{canario}|{migrador,aplicacion,plataforma}|samenet||scram-sha-256|",
    "3|local|{all}|{all}|||reject|",
    "4|host|{all}|{all}|all||reject|",
]
ROLES_CON_CONTRASENA = ["aplicacion", "migrador", "plataforma", "postgres"]
PREFIJO_SCRAM = "SCRAM-SHA-256$4096:"
TEXTO_RECHAZO_TCP_SUPERUSUARIO = 'pg_hba.conf rejects connection for host "127.0.0.1", user "postgres"'
TEXTO_RECHAZO_SOCKET = 'pg_hba.conf rejects connection for host "[local]", user "aplicacion"'
TEXTO_RECHAZO_OTRA_BASE = 'user "aplicacion", database "postgres"'
TEXTO_RECHAZO_HBA = "pg_hba.conf rejects connection for host"
TEXTO_REQUIERE_MD5 = 'authentication method requirement "md5" failed: server requested SASL authentication'
# Una regla activa (no comentario) cuyo método es trust.
PATRON_TRUST = re.compile(r"^\s*(local|host\w*)\s.*\strust\s*$")


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
    # check=False explícito: el código de salida se comprueba en cada llamada.
    r = subprocess.run(args, input=entrada, capture_output=True, timeout=timeout, check=False)
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


def bytea_hex(hexa):
    return f"'\\x{hexa}'::bytea"


# ---------------------------------------------------------------------------
# Comprobaciones
# ---------------------------------------------------------------------------
IMAGEN = ""
CID = ""
# Conteos por contexto tomados al comienzo de v), antes de alta_empresa; los usa x)
FOTO_PREVIA = None
# Salida de "git status --short -uall" al arrancar (None si git no está disponible); la usa s)
ESTADO_GIT_ARRANQUE = None


def seccion_a():
    p("=== a) arranque")
    r = dc("up", "-d", "--build", "--wait", "postgres")
    p(f"up -d --build --wait postgres -> codigo {r.rc}\n{r.todo.strip()}")
    pasa(r.rc == 0, "a) up -d --build --wait postgres termina con codigo 0")
    registro = dc("logs", "--no-log-prefix", "postgres").todo
    if r.rc != 0:
        p("--- log completo de postgres ---")
        p(registro)
        raise Parada("el SQL no se aplico o el servicio no llego a healthy")
    for fichero in ("02_esquema.sql", "03_funciones.sql", "04_supresion.sql", "05_redaccion.sql"):
        pasa(f"running /docker-entrypoint-initdb.d/{fichero}" in registro,
             f"a) el log contiene 'running /docker-entrypoint-initdb.d/{fichero}'")
    malas = [l for l in registro.splitlines() if "ERROR" in l or "FATAL" in l]
    pasa(not malas, f"a) el log del arranque no tiene lineas con ERROR ni FATAL ({len(malas)})")
    for l in malas:
        p(f"   {l}")


def lineas_de_codigo(datos):
    return [l.strip() for l in datos.decode("utf-8").split("\n")
            if l.strip() and not l.strip().startswith("--")]


def seccion_b():
    p("=== b) estaticas de db/init/02_esquema.sql")
    datos = (RAIZ / "db" / "init" / "02_esquema.sql").read_bytes()
    pasa(not datos.startswith(b"\xef\xbb\xbf"), "b) sin BOM")
    pasa(b"\r" not in datos, "b) sin CR")
    codigo = lineas_de_codigo(datos)
    pasa(codigo[:3] == ["\\set ON_ERROR_STOP on", "BEGIN;", "SET ROLE migrador;"],
         f"b) empieza por \\set ON_ERROR_STOP on, BEGIN; y SET ROLE migrador; ({codigo[:3]})")
    pasa(codigo[-1] == "COMMIT;", f"b) termina en COMMIT; ({codigo[-1]!r})")
    unido = "\n".join(codigo).upper()
    for prohibido in ("TO PUBLIC", "BYPASSRLS", "SECURITY DEFINER", "PASSWORD"):
        pasa(prohibido not in unido, f"b) no contiene {prohibido!r}")
    p("=== b) estaticas de db/init/03_funciones.sql")
    datos = (RAIZ / "db" / "init" / "03_funciones.sql").read_bytes()
    pasa(not datos.startswith(b"\xef\xbb\xbf"), "b) 03: sin BOM")
    pasa(b"\r" not in datos, "b) 03: sin CR")
    codigo = lineas_de_codigo(datos)
    pasa(codigo[:2] == ["\\set ON_ERROR_STOP on", "BEGIN;"], f"b) 03: empieza por \\set ON_ERROR_STOP on y BEGIN; ({codigo[:2]})")
    pasa(codigo[-1] == "COMMIT;", f"b) 03: termina en COMMIT; ({codigo[-1]!r})")
    unido = "\n".join(codigo)
    for prohibido in ("TO PUBLIC", "BYPASSRLS", "PASSWORD", "SET ROLE"):
        pasa(prohibido not in unido.upper(), f"b) 03: no contiene {prohibido!r}")
    for texto in ("SECURITY DEFINER", "SET search_path = pg_catalog, canal, pg_temp", "REVOKE EXECUTE ON FUNCTION"):
        pasa(unido.count(texto) == 4, f"b) 03: contiene exactamente 4 veces {texto!r} ({unido.count(texto)})")
    p("=== b) estaticas de db/init/04_supresion.sql")
    datos = (RAIZ / "db" / "init" / "04_supresion.sql").read_bytes()
    pasa(not datos.startswith(b"\xef\xbb\xbf"), "b) 04: sin BOM")
    pasa(b"\r" not in datos, "b) 04: sin CR")
    codigo = lineas_de_codigo(datos)
    pasa(codigo[:2] == ["\\set ON_ERROR_STOP on", "BEGIN;"], f"b) 04: empieza por \\set ON_ERROR_STOP on y BEGIN; ({codigo[:2]})")
    pasa(codigo[-1] == "COMMIT;", f"b) 04: termina en COMMIT; ({codigo[-1]!r})")
    unido = "\n".join(codigo)
    for prohibido in ("TO PUBLIC", "BYPASSRLS", "PASSWORD", "SET ROLE", "TO APLICACION"):
        pasa(prohibido not in unido.upper(), f"b) 04: no contiene {prohibido!r}")
    for texto, veces in (("SECURITY DEFINER", 2), ("SET search_path = pg_catalog, canal, pg_temp", 2),
                         ("REVOKE EXECUTE ON FUNCTION", 3), ("OWNER TO propietario_supresion", 3)):
        pasa(unido.count(texto) == veces, f"b) 04: contiene exactamente {veces} veces {texto!r} ({unido.count(texto)})")
    p("=== b) estaticas de db/init/05_redaccion.sql")
    datos = (RAIZ / "db" / "init" / "05_redaccion.sql").read_bytes()
    pasa(not datos.startswith(b"\xef\xbb\xbf"), "b) 05: sin BOM")
    pasa(b"\r" not in datos, "b) 05: sin CR")
    codigo = lineas_de_codigo(datos)
    pasa(codigo[:2] == ["\\set ON_ERROR_STOP on", "BEGIN;"], f"b) 05: empieza por \\set ON_ERROR_STOP on y BEGIN; ({codigo[:2]})")
    pasa(codigo[-1] == "COMMIT;", f"b) 05: termina en COMMIT; ({codigo[-1]!r})")
    unido = "\n".join(codigo)
    # Sin DELETE ni TRUNCATE: la redaccion reescribe, no borra (el unico
    # borrado es 04_supresion.sql).
    for prohibido in ("TO PUBLIC", "BYPASSRLS", "PASSWORD", "SET ROLE", "DELETE", "TRUNCATE"):
        pasa(prohibido not in unido.upper(), f"b) 05: no contiene {prohibido!r}")
    for texto, veces in (("SECURITY DEFINER", 2), ("SET search_path = pg_catalog, canal, pg_temp", 2),
                         ("REVOKE EXECUTE ON FUNCTION", 2), ("OWNER TO propietario_redaccion", 2),
                         ("TO aplicacion", 2)):
        pasa(unido.count(texto) == veces, f"b) 05: contiene exactamente {veces} veces {texto!r} ({unido.count(texto)})")


def seccion_c():
    p("=== c) catalogo estructural")
    r = sup("select pg_get_userbyid(nspowner) from pg_namespace where nspname = 'canal';")
    comparar("c) esquema canal de migrador", r.lineas(), ["migrador"])
    r = sup("select c.relname, pg_get_userbyid(c.relowner) from pg_class c join pg_namespace n on n.oid = c.relnamespace "
            "where n.nspname = 'canal' and c.relkind in ('r', 'p');")
    comparar("c) exactamente las 11 tablas, todas de migrador", r.lineas(), [f"{t}|migrador" for t in TABLAS])
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
    r = sup("select pg_get_constraintdef(oid) from pg_constraint where contype = 'u' and conrelid = 'canal.mensaje'::regclass;")
    comparar("c) UNIQUE (empresa_id, denuncia_id, id) en mensaje", r.lineas(), ["UNIQUE (empresa_id, denuncia_id, id)"])
    r = sup("select pg_get_constraintdef(oid) from pg_constraint "
            "where conname = 'empresa_zona_horaria_check' and conrelid = 'canal.empresa'::regclass;")
    comparar("c) CHECK de zona_horaria en empresa: solo las zonas de Espana", r.lineas(),
             ["CHECK ((zona_horaria = ANY (ARRAY['Europe/Madrid'::text, 'Atlantic/Canary'::text, 'Africa/Ceuta'::text])))"])
    r = sup("select c.relname, c.relrowsecurity, c.relforcerowsecurity from pg_class c "
            "join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'canal' and c.relkind = 'r';")
    esperado = [f"{t}|t|t" for t in TABLAS_RLS] + [f"{t}|f|f" for t in TABLAS_SIN_RLS]
    comparar("c) RLS ENABLE y FORCE en las 9 tablas y ninguna en directorio_empresas ni busqueda_seguimiento", r.lineas(), esperado)
    # Personal: tokens unicos por empresa y como mucho una invitacion abierta
    # por cuenta (indice parcial).
    r = sup("select c.relname || '|' || pg_get_constraintdef(co.oid) from pg_constraint co "
            "join pg_class c on c.oid = co.conrelid join pg_namespace n on n.oid = c.relnamespace "
            "where co.contype = 'u' and n.nspname = 'canal' "
            "and c.relname in ('invitacion_personal', 'dispositivo_personal', 'sesion_personal');")
    comparar("c) UNIQUE de las tablas del personal", r.lineas(), [
        "invitacion_personal|UNIQUE (empresa_id, token_sha256)",
        "dispositivo_personal|UNIQUE (empresa_id, token_sha256)",
        "dispositivo_personal|UNIQUE (empresa_id, usuario_id, id)",
        "sesion_personal|UNIQUE (empresa_id, token_sha256)"])
    r = sup("select pg_get_indexdef('canal.invitacion_personal_una_abierta'::regclass);")
    comparar("c) una sola invitacion abierta por cuenta (indice unico parcial)", r.lineas(), [
        ("CREATE UNIQUE INDEX invitacion_personal_una_abierta ON canal.invitacion_personal "
         "USING btree (empresa_id, usuario_id) WHERE (NOT cerrada)")])
    r = sup("select pg_get_constraintdef(oid) from pg_constraint "
            f"where conname = '{TEXTO_CREDENCIALES}' and conrelid = 'canal.usuario_personal'::regclass;")
    comparar("c) una cuenta esta activada si y solo si tiene hash, secreto TOTP y version de clave", r.lineas(), [
        ("CHECK ((totp_activo = ((hash_contrasena IS NOT NULL) AND (secreto_totp_cifrado IS NOT NULL) "
         "AND (version_clave_totp IS NOT NULL))))")])
    r = sup("select c.relname || '.' || a.attname || '|' || pg_get_expr(d.adbin, d.adrelid) from pg_attrdef d "
            "join pg_class c on c.oid = d.adrelid join pg_namespace n on n.oid = c.relnamespace "
            "join pg_attribute a on a.attrelid = d.adrelid and a.attnum = d.adnum "
            "where n.nspname = 'canal' and a.attname = 'caduca';")
    comparar("c) las caducidades las fija la base de datos: 72 horas, 90 dias y 8 horas", r.lineas(), [
        "invitacion_personal.caduca|(now() + '72:00:00'::interval)",
        "dispositivo_personal.caduca|(now() + '90 days'::interval)",
        "sesion_personal.caduca|(now() + '08:00:00'::interval)"])


def seccion_d():
    p("=== d) politicas")
    r = sup("select tablename, policyname, cmd, roles, coalesce(qual, ''), coalesce(with_check, '') "
            "from pg_policies where schemaname = 'canal' order by 1, 2;")
    filas = [l.split("|") for l in r.lineas()]
    comparar("d) conjunto exacto de las 40 politicas (tabla, nombre, comando)",
             ["|".join(f[:3]) for f in filas], POLITICAS)

    def rol_esperado(nombre):
        if nombre in NOMBRES_POLITICAS_DEFINIDOR:
            return "{propietario_funciones}"
        if nombre in NOMBRES_POLITICAS_SUPRESION:
            return "{propietario_supresion}"
        if nombre in NOMBRES_POLITICAS_REDACCION:
            return "{propietario_redaccion}"
        return "{aplicacion}"
    pasa(all(f[3] == rol_esperado(f[1]) for f in filas),
         "d) las 22 de aplicacion son TO aplicacion, las 2 del definidor solo TO propietario_funciones, "
         "las 8 de supresion solo TO propietario_supresion y las 8 de redaccion solo TO propietario_redaccion")
    pasa(all(f[2] != "ALL" for f in filas), "d) ninguna con comando ALL")
    con_delete = sorted(f[1] for f in filas if f[2] == "DELETE")
    comparar("d) las unicas politicas de DELETE son las 2 de supresion (denuncia y mensaje)", con_delete,
             ["denuncia_delete_supresion", "mensaje_delete_supresion"])
    comparar("d) las 8 de supresion: comando, USING y WITH CHECK exactos (la de UPDATE con WITH CHECK false)",
             ["|".join(f[:3] + f[4:]) for f in filas if f[1] in NOMBRES_POLITICAS_SUPRESION],
             POLITICAS_SUPRESION_COMPLETAS)
    comparar("d) las 8 de redaccion: comando, USING y WITH CHECK exactos (todas con el contexto de la empresa)",
             ["|".join(f[:3] + f[4:]) for f in filas if f[1] in NOMBRES_POLITICAS_REDACCION],
             POLITICAS_REDACCION_COMPLETAS)
    ok = True
    for f in filas:
        _tabla, nombre, cmd, _roles, qual, check = f
        if nombre in NOMBRES_POLITICAS_SUPRESION or nombre in NOMBRES_POLITICAS_REDACCION:
            continue
        esperado_qual = cmd in ("SELECT", "UPDATE")
        esperado_check = cmd in ("INSERT", "UPDATE")
        if nombre in NOMBRES_POLITICAS_DEFINIDOR:
            # las del definidor no dependen del contexto: llevan true
            if qual != ("true" if esperado_qual else "") or check != ("true" if esperado_check else ""):
                ok = False
                p(f"   {nombre}: qual={qual!r} with_check={check!r} (se esperaba true donde corresponde)")
            continue
        if esperado_qual != ("empresa_actual" in qual) or (not esperado_qual and qual):
            ok = False
            p(f"   {nombre}: qual inesperado {qual!r}")
        if esperado_check != ("empresa_actual" in check) or (not esperado_check and check):
            ok = False
            p(f"   {nombre}: with_check inesperado {check!r}")
    pasa(ok, "d) las 22 de aplicacion usan empresa_actual (SELECT solo qual, INSERT solo with_check, UPDATE ambos) y las 2 del definidor llevan true")


def seccion_e():
    p("=== e) privilegios")
    consultas = []
    for rol in ROLES:
        for t in TABLAS:
            for pr in PRIVILEGIOS:
                consultas.append(f"select '{rol}|{t}|{pr}|' || has_table_privilege('{rol}', 'canal.{t}', '{pr}')::text;")
    r = sup("\n".join(consultas))
    real = set(r.lineas())
    esperado = set()
    for rol in ROLES:
        for t in TABLAS:
            for pr in PRIVILEGIOS:
                da = pr in PRIVILEGIOS_TABLA[rol][t]
                esperado.add(f"{rol}|{t}|{pr}|{'true' if da else 'false'}")
    pasa(real == esperado, f"e) matriz de privilegios de tabla de los {len(ROLES)} roles (UPDATE solo por columna)")
    if real != esperado:
        p(f"   sobran: {sorted(real - esperado)[:10]}")
        p(f"   faltan: {sorted(esperado - real)[:10]}")
    # privilegios de columna (SELECT, INSERT, UPDATE, REFERENCES) de cada columna de cada tabla
    for rol in ROLES:
        r = sup(
            f"select '{rol}|' || c.relname || '|' || a.attname || '|' || q.priv || '|' || "
            f"has_column_privilege('{rol}', c.oid, a.attnum, q.priv)::text "
            "from pg_class c join pg_namespace n on n.oid = c.relnamespace "
            "join pg_attribute a on a.attrelid = c.oid and a.attnum > 0 and not a.attisdropped "
            "cross join (values ('SELECT'), ('INSERT'), ('UPDATE'), ('REFERENCES')) q(priv) "
            "where n.nspname = 'canal' and c.relkind = 'r';")
        real = set(r.lineas())
        esperado = set()
        for t, columnas in COLUMNAS.items():
            for col in columnas:
                for pr in PRIVILEGIOS_COLUMNA_COMPROBADOS:
                    da = pr in PRIVILEGIOS_TABLA[rol][t] or col in PRIVILEGIOS_COLUMNA[rol].get((t, pr), set())
                    esperado.add(f"{rol}|{t}|{col}|{pr}|{'true' if da else 'false'}")
        pasa(real == esperado, f"e) {rol}: privilegios SELECT, INSERT, UPDATE y REFERENCES en cada una de las {sum(len(c) for c in COLUMNAS.values())} columnas")
        if real != esperado:
            p(f"   sobran: {sorted(real - esperado)[:10]}")
            p(f"   faltan: {sorted(esperado - real)[:10]}")
    # UPDATE por columna de aplicacion
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
    for rol in ROLES:
        r = sup(f"select has_schema_privilege('{rol}', 'canal', 'USAGE')::text || '|' || has_schema_privilege('{rol}', 'canal', 'CREATE')::text;")
        pasa(valor(r) == "true|false", f"e) {rol}: USAGE sobre canal true y CREATE false ({valor(r)})")


def seccion_f():
    p("=== f) funciones y triggers")
    r = sup("select p.proname, pg_get_userbyid(p.proowner), p.prosecdef, p.provolatile, p.oid::regprocedure::text "
            "from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'canal';")
    esperado = [f"{f}|{d}|{s}|{v}|{firma}" for f, (d, s, v, firma) in FUNCIONES_CATALOGO.items()]
    comparar("f) exactamente las 15 funciones: dueno, SECURITY DEFINER, volatilidad y firma", r.lineas(), esperado)
    r = sup("select p.proname, c from pg_proc p join pg_namespace n on n.oid = p.pronamespace, unnest(p.proconfig) c "
            "where n.nspname = 'canal' and p.prosecdef;")
    comparar("f) las 8 de definidor tienen exactamente search_path=pg_catalog, canal, pg_temp",
             r.lineas(), [f"{f}|{CONFIG_DEFINIDOR}" for f in FUNCIONES_DEFINIDOR])
    r = sup("select array_to_string(proconfig, ',') from pg_proc "
            "where proname = 'articulo_supresion' and pronamespace = 'canal'::regnamespace;")
    comparar("f) articulo_supresion fija search_path=pg_catalog", r.lineas(), ["search_path=pg_catalog"])
    consultas = []
    for rol in ROLES:
        consultas.append(
            f"select '{rol}|' || p.proname || '|' || has_function_privilege('{rol}', p.oid, 'EXECUTE')::text "
            "from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'canal';")
    r = sup("\n".join(consultas))
    esperado = []
    for rol in ROLES:
        for f in FUNCIONES_CATALOGO:
            esperado.append(f"{rol}|{f}|{'true' if rol in EXECUTE_ESPERADO[f] else 'false'}")
    comparar(f"f) matriz de EXECUTE de los {len(ROLES)} roles sobre las 15 funciones", r.lineas(), esperado)
    r = sup("select c.relname, t.tgname, t.tgenabled from pg_trigger t join pg_class c on c.oid = t.tgrelid "
            "join pg_namespace n on n.oid = c.relnamespace where not t.tgisinternal and n.nspname = 'canal';")
    comparar("f) los 5 triggers esperados, todos con tgenabled = 'O'", r.lineas(), TRIGGERS)
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
INSERT INTO canal.directorio_empresas (identificador_publico, empresa_id) VALUES
    ('{IDENT_A}', '{EMPRESA_A}'), ('{IDENT_B}', '{EMPRESA_B}');
INSERT INTO canal.clave_empresa (empresa_id, version, clave_envuelta) VALUES
    ('{EMPRESA_A}', 1, '\\x01'), ('{EMPRESA_B}', 1, '\\x02');
INSERT INTO canal.usuario_personal (empresa_id, id, email, hash_contrasena, rol) VALUES
    ('{EMPRESA_A}', '{ADMIN_A}', 'ana@ejemplo.test', 'x', 'admin'),
    ('{EMPRESA_A}', '{INSTR_A}', 'luis@ejemplo.test', 'x', 'instructor'),
    ('{EMPRESA_B}', '{ADMIN_B}', 'ana@ejemplo.test', 'x', 'admin'),
    ('{EMPRESA_B}', '{INSTR_B}', 'eva@ejemplo.test', 'x', 'instructor');
INSERT INTO canal.invitacion_personal (empresa_id, usuario_id, token_sha256) VALUES
    ('{EMPRESA_A}', '{INSTR_A}', '\\x{TOKEN_INV_A}'), ('{EMPRESA_B}', '{INSTR_B}', '\\x{TOKEN_INV_B}');
INSERT INTO canal.dispositivo_personal (empresa_id, id, usuario_id, token_sha256) VALUES
    ('{EMPRESA_A}', '{DISP_A}', '{ADMIN_A}', '\\x{TOKEN_DISP_A}'),
    ('{EMPRESA_B}', '{DISP_B}', '{ADMIN_B}', '\\x{TOKEN_DISP_B}'),
    ('{EMPRESA_B}', '{DISP_B2}', '{INSTR_B}', '\\x{TOKEN_DISP_B2}');
INSERT INTO canal.sesion_personal (empresa_id, usuario_id, dispositivo_id, token_sha256) VALUES
    ('{EMPRESA_A}', '{ADMIN_A}', '{DISP_A}', '\\x{TOKEN_SES_A}'),
    ('{EMPRESA_B}', '{ADMIN_B}', '{DISP_B}', '\\x{TOKEN_SES_B}');
INSERT INTO canal.denuncia (empresa_id, id, contenido_cifrado, version_clave, asignada_a) VALUES
    ('{EMPRESA_A}', '{DEN_A1}', {BYTES_FALSOS}, 1, '{INSTR_A}'),
    ('{EMPRESA_A}', '{DEN_A2}', {BYTES_FALSOS}, 1, NULL),
    ('{EMPRESA_B}', '{DEN_B1}', {BYTES_FALSOS}, 1, NULL),
    ('{EMPRESA_B}', '{DEN_B2}', {BYTES_FALSOS}, 1, NULL);
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
        "denuncia": lambda e, d: f"insert into canal.denuncia (empresa_id, contenido_cifrado, version_clave) values ('{e}', {BYTES_FALSOS}, 1);",
        "mensaje": lambda e, d: f"insert into canal.mensaje (empresa_id, denuncia_id, autor, contenido_cifrado, version_clave) values ('{e}', '{d}', 'denunciante', {BYTES_FALSOS}, 1);",
        "usuario_personal": lambda e, d: f"insert into canal.usuario_personal (empresa_id, email, rol) values ('{e}', 'nuevo@ejemplo.test', 'admin');",
        # Personal: con la cuenta admin de cada empresa (sin invitacion en el
        # fixture) y su dispositivo.
        "invitacion_personal": lambda e, d: f"insert into canal.invitacion_personal (empresa_id, usuario_id, token_sha256) values ('{e}', '{ADMIN_DE[e]}', '\\x{'41' * 32}');",
        "dispositivo_personal": lambda e, d: f"insert into canal.dispositivo_personal (empresa_id, usuario_id, token_sha256) values ('{e}', '{ADMIN_DE[e]}', '\\x{'42' * 32}');",
        "sesion_personal": lambda e, d: f"insert into canal.sesion_personal (empresa_id, usuario_id, dispositivo_id, token_sha256) values ('{e}', '{ADMIN_DE[e]}', '{DISP_DE[e]}', '\\x{'43' * 32}');",
        "clave_empresa": lambda e, d: f"insert into canal.clave_empresa (empresa_id, version, clave_envuelta) values ('{e}', 2, {BYTES_FALSOS});",
        "registro_auditoria": lambda e, d: f"insert into canal.registro_auditoria (empresa_id, actor, accion) values ('{e}', 'prueba', 'accion');",
    }
    # mensaje: canal.preparar_mensaje() busca su denuncia bajo RLS antes de que
    # se compruebe la política de INSERT. Con contexto A la de B es invisible
    # y el rechazo llega antes, con su propio error y sin bloquear nada (y).
    esperados = {"mensaje": TEXTO_MENSAJE_SIN_DENUNCIA}
    for tabla, f in inserciones.items():
        neg = app(f(EMPRESA_B, DEN_B1), ctx=EMPRESA_A)
        ctl = app(f(EMPRESA_A, DEN_A1), ctx=EMPRESA_A, final="ROLLBACK")
        negativo(f"i) INSERT en {tabla} con empresa_id = B", neg, esperados.get(tabla, "row-level security"),
                 sin_error(ctl))
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
        return f"insert into canal.usuario_personal (empresa_id, email, rol) values ('{empresa}', '{email}', 'admin');"
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
    # k2: mensajes con denuncia ajena frente a inexistente. El error lo da
    # canal.preparar_mensaje(), antes que la clave foránea, y tiene que ser el
    # mismo en los dos casos.
    def mensaje(den):
        return f"insert into canal.mensaje (empresa_id, denuncia_id, autor, contenido_cifrado, version_clave) values ('{EMPRESA_A}', '{den}', 'denunciante', {BYTES_FALSOS}, 1);"
    ajena = app(mensaje(DEN_B1), ctx=EMPRESA_A)
    inexistente = app(mensaje(str(uuid.uuid4())), ctx=EMPRESA_A)
    ctl = app(mensaje(DEN_A1), ctx=EMPRESA_A, final="ROLLBACK")
    if not sin_error(ctl):
        sinc("k2) el control (mensaje en una denuncia propia) fallo")
    else:
        a, b = normalizar_uuid(ajena.err), normalizar_uuid(inexistente.err)
        pasa(TEXTO_MENSAJE_SIN_DENUNCIA in a and a == b,
             f"k2) mensaje con denuncia de B y con uuid aleatorio: mismo error {TEXTO_MENSAJE_SIN_DENUNCIA!r}")
        if a != b:
            p(f"   ajena:       {a.strip()!r}\n   inexistente: {b.strip()!r}")
    # k2 bis: denuncia.asignada_a
    def denuncia(asignada):
        return f"insert into canal.denuncia (empresa_id, contenido_cifrado, version_clave, asignada_a) values ('{EMPRESA_A}', {BYTES_FALSOS}, 1, '{asignada}');"
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
    # Lista cerrada de estados, literal: 'no_veraz' (art. 32.3) y ninguno mas.
    r = sup("select pg_get_constraintdef(oid) from pg_constraint "
            "where conname = 'denuncia_estado_check' and conrelid = 'canal.denuncia'::regclass;")
    comparar("l) CHECK de denuncia.estado: exactamente los 6 estados", r.lineas(), [CHECK_ESTADO])
    ctl_no_veraz = app(f"update canal.denuncia set estado = 'no_veraz' where id = '{DEN_A1}';",
                       ctx=EMPRESA_A, final="ROLLBACK")
    pasa(sin_error(ctl_no_veraz), "l) aplicacion puede pasar una denuncia a no_veraz (se deshace)")
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

    # Personal: la API no puede crear una cuenta ya activada, elegir una
    # caducidad ni cambiar un token o una caducidad. Cada negativo con su
    # control: la misma operacion con solo las columnas permitidas.
    def en_a(sentencia):
        return app(sentencia, ctx=EMPRESA_A, final="ROLLBACK")
    ctl = en_a(f"insert into canal.usuario_personal (empresa_id, email, rol) values ('{EMPRESA_A}', 'l@ejemplo.test', 'instructor');")
    for columna, v in (("totp_activo", "true"), ("hash_contrasena", "'x'"), ("intentos_fallidos", "0"), ("activo", "true")):
        negativo(f"l) INSERT de usuario_personal con {columna}",
                 en_a(f"insert into canal.usuario_personal (empresa_id, email, rol, {columna}) values ('{EMPRESA_A}', 'l@ejemplo.test', 'instructor', {v});"),
                 "permission denied", sin_error(ctl))
    ctl = en_a(f"insert into canal.invitacion_personal (empresa_id, usuario_id, token_sha256) values ('{EMPRESA_A}', '{ADMIN_A}', '\\x{'51' * 32}');")
    for columna, v in (("caduca", "now() + interval '10 years'"), ("cerrada", "false"), ("hash_contrasena", "'x'")):
        negativo(f"l) INSERT de invitacion_personal con {columna}",
                 en_a(f"insert into canal.invitacion_personal (empresa_id, usuario_id, token_sha256, {columna}) values ('{EMPRESA_A}', '{ADMIN_A}', '\\x{'51' * 32}', {v});"),
                 "permission denied", sin_error(ctl))
    ctl = en_a(f"insert into canal.dispositivo_personal (empresa_id, usuario_id, token_sha256) values ('{EMPRESA_A}', '{ADMIN_A}', '\\x{'52' * 32}');")
    negativo("l) INSERT de dispositivo_personal con caduca",
             en_a(f"insert into canal.dispositivo_personal (empresa_id, usuario_id, token_sha256, caduca) values ('{EMPRESA_A}', '{ADMIN_A}', '\\x{'52' * 32}', now() + interval '10 years');"),
             "permission denied", sin_error(ctl))
    ctl = en_a(f"insert into canal.sesion_personal (empresa_id, usuario_id, dispositivo_id, token_sha256) values ('{EMPRESA_A}', '{ADMIN_A}', '{DISP_A}', '\\x{'53' * 32}');")
    for columna, v in (("caduca", "now() + interval '10 years'"), ("ultimo_uso", "now()")):
        negativo(f"l) INSERT de sesion_personal con {columna}",
                 en_a(f"insert into canal.sesion_personal (empresa_id, usuario_id, dispositivo_id, token_sha256, {columna}) values ('{EMPRESA_A}', '{ADMIN_A}', '{DISP_A}', '\\x{'53' * 32}', {v});"),
                 "permission denied", sin_error(ctl))
    ctl = en_a("update canal.sesion_personal set revocada = true;")
    for columna, v in (("caduca", "now() + interval '10 years'"), ("token_sha256", f"'\\x{'54' * 32}'"), ("usuario_id", f"'{INSTR_A}'")):
        negativo(f"l) UPDATE de sesion_personal.{columna}", en_a(f"update canal.sesion_personal set {columna} = {v};"),
                 "permission denied", sin_error(ctl))
    ctl = en_a("update canal.dispositivo_personal set revocado = true;")
    for columna, v in (("caduca", "now() + interval '10 years'"), ("token_sha256", f"'\\x{'55' * 32}'")):
        negativo(f"l) UPDATE de dispositivo_personal.{columna}", en_a(f"update canal.dispositivo_personal set {columna} = {v};"),
                 "permission denied", sin_error(ctl))
    ctl = en_a("update canal.invitacion_personal set cerrada = true;")
    for columna, v in (("caduca", "now() + interval '10 years'"), ("token_sha256", f"'\\x{'56' * 32}'")):
        negativo(f"l) UPDATE de invitacion_personal.{columna}", en_a(f"update canal.invitacion_personal set {columna} = {v};"),
                 "permission denied", sin_error(ctl))

    # Invariantes del personal en la propia tabla (como superusuario, que se
    # salta permisos y RLS pero no los CHECK ni los indices).
    def como_sup(sentencia):
        return sup(f"BEGIN;\n{sentencia}\nROLLBACK;\n")
    ctl = como_sup(f"update canal.usuario_personal set secreto_totp_cifrado = '\\x01', version_clave_totp = 1, "
                   f"totp_activo = true where id = '{INSTR_A}';")
    negativo("l) cuenta activada sin secreto TOTP (CHECK de credenciales)",
             como_sup(f"update canal.usuario_personal set totp_activo = true where id = '{INSTR_A}';"),
             TEXTO_CREDENCIALES, sin_error(ctl))
    negativo("l) cuenta con credenciales completas sin activar (CHECK de credenciales)",
             como_sup(f"update canal.usuario_personal set secreto_totp_cifrado = '\\x01', version_clave_totp = 1 "
                      f"where id = '{INSTR_A}';"), TEXTO_CREDENCIALES, sin_error(ctl))
    ctl = como_sup(f"update canal.invitacion_personal set hash_contrasena = 'x', secreto_totp_cifrado = '\\x01', "
                   f"version_clave_totp = 1 where usuario_id = '{INSTR_A}';")
    negativo("l) invitacion con credenciales pendientes a medias (CHECK de pendientes)",
             como_sup(f"update canal.invitacion_personal set hash_contrasena = 'x' where usuario_id = '{INSTR_A}';"),
             TEXTO_PENDIENTE, sin_error(ctl))
    otra = f"insert into canal.invitacion_personal (empresa_id, usuario_id, token_sha256) values ('{EMPRESA_A}', '{INSTR_A}', '\\x{'57' * 32}');"
    ctl = como_sup(f"update canal.invitacion_personal set cerrada = true where usuario_id = '{INSTR_A}';\n{otra}")
    negativo("l) dos invitaciones abiertas para la misma cuenta (indice parcial)", como_sup(otra),
             "invitacion_personal_una_abierta", sin_error(ctl))
    ctl = como_sup(f"insert into canal.sesion_personal (empresa_id, usuario_id, dispositivo_id, token_sha256) "
                   f"values ('{EMPRESA_A}', '{ADMIN_A}', '{DISP_A}', '\\x{'58' * 32}');")
    negativo("l) sesion con el dispositivo de otra cuenta (clave foranea de tres columnas)",
             como_sup(f"insert into canal.sesion_personal (empresa_id, usuario_id, dispositivo_id, token_sha256) "
                      f"values ('{EMPRESA_A}', '{INSTR_A}', '{DISP_A}', '\\x{'58' * 32}');"),
             "violates foreign key constraint", sin_error(ctl))


def cliente_red(sql, rol="aplicacion", base="canario", requerir=None):
    """psql como un rol de login por la red data, con su secreto real montado sin leerlo.

    requerir: método que el cliente exige al servidor (require_auth de libpq,
    variable PGREQUIREAUTH). El psql de la imagen de postgres 18 lo soporta.
    """
    ruta = (RAIZ / "secrets" / f"contrasena_{rol}.txt").resolve()
    entorno = ["-e", "PGCONNECT_TIMEOUT=5"] + (["-e", f"PGREQUIREAUTH={requerir}"] if requerir else [])
    return ejecutar([
        "docker", "run", "--rm", "-i", "--network", f"{PROYECTO}_data", *entorno,
        "--mount", f"type=bind,source={ruta},target=/s,readonly",
        "--entrypoint", "sh", IMAGEN,
        "-c", 'PGPASSWORD=$(cat /s) exec psql -h postgres -U "$1" -d "$2" -X -q -A -t -v ON_ERROR_STOP=0 -f -',
        "sh", rol, base,
    ], entrada=sql.encode("utf-8"))


def cliente_literal(usuario, sql, contrasena="x"):
    """psql por la red data con una contraseña literal ficticia (para roles sin secreto)."""
    return ejecutar([
        "docker", "run", "--rm", "-i", "--network", f"{PROYECTO}_data",
        "-e", f"PGPASSWORD={contrasena}", "-e", "PGCONNECT_TIMEOUT=5",
        "--entrypoint", "psql", IMAGEN,
        "-h", "postgres", "-U", usuario, "-d", "canario", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=0", "-f", "-",
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


def psql_en_postgres(usuario, *conexion):
    """psql dentro del contenedor de postgres, sin contraseña (-w: nunca la pide)."""
    return dc("exec", "-T", "-e", "PGCONNECT_TIMEOUT=5", "postgres", "psql", *conexion, "-U", usuario,
              "-d", "canario", "-w", "-X", "-q", "-A", "-t", "-c", "select 1")


def seccion_au():
    p("=== au) autenticacion de PostgreSQL")
    # El fichero que manda es el del repositorio, no el de PGDATA.
    pasa(valor(sup("show hba_file;")) == HBA_FILE, f"au) hba_file = {HBA_FILE}")
    pasa(valor(sup("show password_encryption;")) == "scram-sha-256", "au) password_encryption = scram-sha-256")

    # Las reglas leídas por el servidor, contra el oráculo. OJO: la vista
    # refleja el fichero en disco, no lo que el servidor cargó (docs de
    # PostgreSQL 18, pg_hba_file_rules); las pruebas de comportamiento de
    # abajo son las que demuestran lo cargado.
    r = sup("select rule_number, type, database, user_name, address, netmask, auth_method, options "
            "from pg_hba_file_rules order by rule_number;\n"
            "select count(*) from pg_hba_file_rules where error is not null;")
    lineas = r.lineas()
    comparar("au) pg_hba_file_rules coincide exactamente con las 4 reglas esperadas", lineas[:-1], REGLAS_HBA)
    pasa(lineas[-1:] == ["0"], f"au) ninguna regla de pg_hba.conf con error ({lineas[-1:]})")
    # Control: el pg_hba.conf que la imagen deja en PGDATA (inerte) sí tiene
    # trust; así se ve que el patrón lo detecta.
    inerte = sup("select pg_read_file('pg_hba.conf');").out.splitlines()
    control_trust = sum(1 for l in inerte if PATRON_TRUST.match(l)) >= 1
    if not control_trust:
        sinc("au) ninguna regla trust: el control (pg_hba.conf inerte de PGDATA con trust) fallo")
    else:
        activo = [l for l in sup(f"select pg_read_file('{HBA_FILE}');").out.splitlines() if PATRON_TRUST.match(l)]
        pasa(not activo, f"au) ninguna regla trust en el pg_hba.conf activo {activo or ''}")

    # Comportamiento: el superusuario solo entra por el socket con peer.
    control_peer = valor(sup("select 1;")) == "1"
    negativo("au) el superusuario por TCP a 127.0.0.1 se rechaza",
             psql_en_postgres("postgres", "-h", "127.0.0.1"), TEXTO_RECHAZO_TCP_SUPERUSUARIO, control_peer)
    negativo("au) otro rol por el socket se rechaza",
             psql_en_postgres("aplicacion"), TEXTO_RECHAZO_SOCKET, control_peer)

    # Las contraseñas guardadas son SCRAM-SHA-256 con 4096 iteraciones. Solo
    # se imprime el prefijo, nunca el resto del verificador.
    r = sup("select rolname || '|' || coalesce(left(rolpassword, 19), 'NULL') from pg_authid "
            f"where rolname in ({', '.join(repr(x) for x in ROLES_CON_CONTRASENA)}) order by rolname;")
    # Control: un rol temporal con password_encryption = md5 sí deja otro
    # prefijo, así que la consulta distingue uno de otro. Se borra al acabar.
    ctl = sup("SET password_encryption = 'md5';\nCREATE ROLE prueba_md5_au PASSWORD 'no-es-secreta';\n"
              "select left(rolpassword, 3) from pg_authid where rolname = 'prueba_md5_au';\n"
              "DROP ROLE prueba_md5_au;")
    borrado = valor(sup("select count(*) from pg_roles where rolname = 'prueba_md5_au';")) == "0"
    if not (valor(ctl) == "md5" and borrado):
        sinc(f"au) contrasenas SCRAM: el control (rol md5 temporal) fallo ({ctl.lineas()}, borrado: {borrado})")
    else:
        comparar("au) migrador, aplicacion, plataforma y postgres guardan SCRAM-SHA-256$4096:",
                 r.lineas(), [f"{x}|{PREFIJO_SCRAM}" for x in ROLES_CON_CONTRASENA])

    # Desde la red data: un cliente que exige md5 no entra (el servidor pide
    # SASL, es decir SCRAM); el mismo cliente exigiendo scram-sha-256 sí.
    ctl = cliente_red("select 1;", requerir="scram-sha-256")
    negativo("au) un cliente que exige md5 se rechaza",
             cliente_red("select 1;", requerir="md5"), TEXTO_REQUIERE_MD5, ctl.lineas() == ["1"])
    # aplicacion solo entra a la base canario.
    ctl = cliente_red("select 1;")
    otra = cliente_red("select 1;", base="postgres")
    negativo("au) aplicacion a la base postgres por red se rechaza", otra, TEXTO_RECHAZO_OTRA_BASE,
             ctl.lineas() == ["1"] and TEXTO_RECHAZO_HBA in otra.err)


def seccion_n():
    p("=== n) mensajes")
    cuerpo = f"""
insert into canal.denuncia (empresa_id, id, contenido_cifrado, version_clave) values ('{EMPRESA_A}', '{DEN_A3}', {BYTES_FALSOS}, 1);
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

    # Una denuncia resuelta, archivada o inadmitida no admite mensajes, ni del
    # denunciante ni del personal. Control: nueva y en_instruccion sí. Todo se
    # deshace.
    def con_estado(estado_denuncia, autor, autor_id):
        return app("\\set VERBOSITY verbose\n"
                   f"update canal.denuncia set estado = '{estado_denuncia}' where id = '{DEN_A2}';\n"
                   + mensaje(autor, autor_id), ctx=EMPRESA_A, final="ROLLBACK")
    autores = (("denunciante", None), ("personal", INSTR_A))
    controles = [con_estado(e, a, i) for e in ("nueva", "en_instruccion") for a, i in autores]
    for e in ("resuelta", "archivada", "inadmitida"):
        for a, i in autores:
            negativo(f"n) mensaje del {a} en una denuncia {e}", con_estado(e, a, i), TEXTO_DENUNCIA_CERRADA,
                     all(sin_error(c) for c in controles))
    # Una denuncia no veraz (art. 32.3) no existe para quien escribe: el error
    # es el de una inexistente, con su SQLSTATE (23503, que la API traduce a
    # 404), y no el de cerrada. Mismos controles.
    for a, i in autores:
        negativo(f"n) mensaje del {a} en una denuncia no_veraz", con_estado("no_veraz", a, i),
                 f"23503: {TEXTO_MENSAJE_SIN_DENUNCIA}", all(sin_error(c) for c in controles),
                 no_texto=TEXTO_DENUNCIA_CERRADA)

    # Tope de mensajes por denuncia, en una denuncia nueva que se deshace. El
    # último que cabe se acepta (control) y el siguiente no; el SAVEPOINT
    # permite contar después del error.
    den = str(uuid.uuid4())
    insertar = (f"insert into canal.mensaje (empresa_id, denuncia_id, autor, contenido_cifrado, version_clave) "
                f"values ('{EMPRESA_A}', '{den}', 'denunciante', {BYTES_FALSOS}, 1)")
    cuerpo = ("\\set VERBOSITY verbose\n"
              f"insert into canal.denuncia (empresa_id, id, contenido_cifrado, version_clave) "
              f"values ('{EMPRESA_A}', '{den}', {BYTES_FALSOS}, 1);\n"
              + f"{insertar};\n" * (MAXIMO_MENSAJES - 1)
              + f"{insertar} returning 'ultimo|' || secuencia;\n"
              + "savepoint antes_del_tope;\n"
              + f"{insertar} returning 'sobra|' || secuencia;\n"
              + "rollback to savepoint antes_del_tope;\n"
              + f"select 'total|' || count(*) from canal.mensaje where denuncia_id = '{den}';\n")
    r = app(cuerpo, ctx=EMPRESA_A, final="ROLLBACK")
    control = f"ultimo|{MAXIMO_MENSAJES}" in r.lineas()
    negativo(f"n) el mensaje numero {MAXIMO_MENSAJES + 1} de una denuncia se rechaza", r, TEXTO_LIMITE_MENSAJES, control)
    negativo_valor(f"n) tras el rechazo la denuncia sigue con {MAXIMO_MENSAJES} mensajes",
                   f"total|{MAXIMO_MENSAJES}" in r.lineas() and not any(l.startswith("sobra|") for l in r.lineas()),
                   control)


def filas_auditoria(empresa):
    r = sup("select secuencia, coalesce(encode(hash_anterior, 'hex'), ''), encode(hash, 'hex'), fecha::text, actor, accion, "
            "coalesce(objeto_id::text, ''), coalesce(destino_id::text, '') "
            f"from canal.registro_auditoria where empresa_id = '{empresa}' order by secuencia;")
    return [l.split("|") for l in r.lineas()]


def recalcular(empresa, f):
    secuencia, anterior, _hash, fecha, actor, accion, objeto, destino = f
    elementos = [anterior or None, empresa, int(secuencia), fecha, actor, accion, objeto or None, destino or None]
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
            "returning secuencia, fecha = (now() at time zone 'Europe/Madrid')::date, hash <> '\\x00'::bytea;", ctx=EMPRESA_A)
    pasa(r.lineas() == ["6|t|t"],
         f"o) INSERT con secuencia, fecha y hash falsos queda con secuencia 6, el dia de hoy en la zona de A "
         f"(Europe/Madrid) y otro hash ({r.lineas()})")
    pasa(verificar_cadena(EMPRESA_A) == "NULL", f"o) verificar_cadena_auditoria() con contexto A = NULL ({verificar_cadena(EMPRESA_A)})")
    comprobar_python(EMPRESA_A, "empresa A")
    comprobar_python(EMPRESA_B, "empresa B")
    # Inmutabilidad como aplicacion
    ctl = app("select count(*) from canal.registro_auditoria;", ctx=EMPRESA_A)
    for orden in ("update canal.registro_auditoria set accion = 'x';", "delete from canal.registro_auditoria;", "truncate canal.registro_auditoria;"):
        negativo(f"o) aplicacion: {orden.split()[0].upper()}", app(orden, ctx=EMPRESA_A), "permission denied", sin_error(ctl))
    # Inmutabilidad como superusuario (el caso de manipulacion hace de control)
    inmut = {}
    for orden in (f"update canal.registro_auditoria set accion = 'x' where empresa_id = '{EMPRESA_A}' and secuencia = 2;",
                  f"delete from canal.registro_auditoria where empresa_id = '{EMPRESA_A}' and secuencia = 1;",
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


def zona_con_otro_dia():
    """Una zona horaria en la que ahora mismo es otro día que en Madrid.

    now() no se puede fijar, así que la prueba busca un instante en que los
    días difieran: Kiritimati (UTC+14) va por delante y Pago Pago (UTC-11) por
    detrás. En cualquier instante, al menos una de las dos está en un día
    distinto del de Madrid (UTC+1 o UTC+2). Devuelve (zona, None) o
    (None, motivo) si no se pudo determinar.
    """
    r = sup("select (now() at time zone 'Europe/Madrid')::date || '|' || "
            "(now() at time zone 'Pacific/Kiritimati')::date || '|' || "
            "(now() at time zone 'Pacific/Pago_Pago')::date;")
    partes = valor(r).split("|")
    if len(partes) != 3:
        return None, f"no se pudieron leer las fechas: {r.todo.strip()[:200]!r}"
    madrid, kiritimati, pago_pago = partes
    if kiritimati != madrid:
        return "Pacific/Kiritimati", None
    if pago_pago != madrid:
        return "Pacific/Pago_Pago", None
    return None, f"ninguna zona da otro dia ({partes})"


def seccion_z():
    p("=== z) fecha de recepcion: el dia en la zona horaria de la empresa")
    zona, motivo = zona_con_otro_dia()
    if zona is None:
        sinc(f"z) no hay zona de control: {motivo}")
        return
    p(f"   zona de control (otro dia que Madrid ahora mismo): {zona}")

    # 1) Como aplicacion, con la zona de la sesion cambiada y una fecha falsa
    #    en el INSERT: la fecha guardada de la denuncia y de su mensaje es la
    #    de Madrid (zona de A). Control: en esa sesion current_date es otro
    #    dia, asi que la prueba distingue.
    den = str(uuid.uuid4())
    resto = "fecha::text || '|' || current_date::text || '|' || (now() at time zone 'Europe/Madrid')::date::text;"
    r = app(f"SET LOCAL TIME ZONE '{zona}';\n"
            f"insert into canal.denuncia (empresa_id, id, fecha, contenido_cifrado, version_clave) "
            f"values ('{EMPRESA_A}', '{den}', '2001-01-01', {BYTES_FALSOS}, 1) returning 'denuncia|' || {resto}\n"
            f"insert into canal.mensaje (empresa_id, denuncia_id, fecha, autor, contenido_cifrado, version_clave) "
            f"values ('{EMPRESA_A}', '{den}', '2001-01-01', 'denunciante', {BYTES_FALSOS}, 1) "
            f"returning 'mensaje|' || {resto}", ctx=EMPRESA_A, final="ROLLBACK")
    filas = {l.split("|")[0]: l.split("|")[1:] for l in r.lineas() if "|" in l}
    for tabla in ("denuncia", "mensaje"):
        datos = filas.get(tabla)
        if not datos or len(datos) != 3 or not sin_error(r):
            sinc(f"z) {tabla}: no se pudo insertar la fila de prueba: {r.err.strip()[:300]!r}")
            continue
        fecha, dia_sesion, dia_madrid = datos
        negativo_valor(f"z) la fecha del {tabla} es el dia de Madrid: ignora la fecha del INSERT y la zona "
                       f"de la sesion (fecha {fecha}, Madrid {dia_madrid}, sesion {dia_sesion})",
                       fecha == dia_madrid and fecha != "2001-01-01", dia_sesion != dia_madrid)

    # 2) La zona que manda es la de la empresa. Como superusuario y en una
    #    transaccion que se deshace: se quita el CHECK, se pone a B la zona de
    #    control y se inserta una denuncia, un mensaje y una fila de auditoria
    #    de B. Control: en esa zona es otro dia que en Madrid. Las tres tablas
    #    calculan el dia con su propia copia de la expresion: si una se
    #    desviara, esta prueba lo veria.
    den = str(uuid.uuid4())
    resto = (f"fecha::text || '|' || (now() at time zone '{zona}')::date::text"
             " || '|' || (now() at time zone 'Europe/Madrid')::date::text;")
    r = sup(f"""BEGIN;
ALTER TABLE canal.empresa DROP CONSTRAINT empresa_zona_horaria_check;
UPDATE canal.empresa SET zona_horaria = '{zona}' WHERE id = '{EMPRESA_B}';
INSERT INTO canal.denuncia (empresa_id, id, contenido_cifrado, version_clave)
     VALUES ('{EMPRESA_B}', '{den}', {BYTES_FALSOS}, 1)
  RETURNING 'denuncia|' || {resto}
INSERT INTO canal.mensaje (empresa_id, denuncia_id, autor, contenido_cifrado, version_clave)
     VALUES ('{EMPRESA_B}', '{den}', 'denunciante', {BYTES_FALSOS}, 1)
  RETURNING 'mensaje|' || {resto}
INSERT INTO canal.registro_auditoria (empresa_id, actor, accion)
     VALUES ('{EMPRESA_B}', 'prueba', 'zona')
  RETURNING 'auditoria|' || {resto}
ROLLBACK;
""")
    filas = {l.split("|")[0]: l.split("|")[1:] for l in r.lineas() if "|" in l}
    for tabla in ("denuncia", "mensaje", "auditoria"):
        datos = filas.get(tabla)
        if not datos or len(datos) != 3:
            sinc(f"z) {tabla}: no se pudo insertar con la zona de control: {r.err.strip()[:300]!r}")
            continue
        fecha, dia_zona, dia_madrid = datos
        negativo_valor(f"z) {tabla}: con la empresa en {zona}, la fecha es el dia de esa zona y no el de Madrid "
                       f"(fecha {fecha}, zona {dia_zona}, Madrid {dia_madrid})",
                       fecha == dia_zona, dia_zona != dia_madrid)

    # 3) Tras el ROLLBACK, el CHECK y la zona de B vuelven a ser los de antes.
    r = sup("select count(*) from pg_constraint where conname = 'empresa_zona_horaria_check';\n"
            f"select zona_horaria from canal.empresa where id = '{EMPRESA_B}';")
    pasa(r.lineas() == ["1", "Europe/Madrid"],
         f"z) tras el ROLLBACK siguen el CHECK y la zona Europe/Madrid de B ({r.lineas()})")

    # 4) El CHECK rechaza una zona fuera de la lista, incluso al superusuario.
    #    Control: una zona de la lista se acepta (y se deshace).
    ctl = sup(f"BEGIN;\nUPDATE canal.empresa SET zona_horaria = 'Atlantic/Canary' WHERE id = '{EMPRESA_B}';\nROLLBACK;\n")
    for zona_mala in ("UTC", "Europe/London", "europe/madrid", ""):
        negativo(f"z) zona horaria {zona_mala!r}",
                 sup(f"UPDATE canal.empresa SET zona_horaria = '{zona_mala}' WHERE id = '{EMPRESA_B}';"),
                 "violates check constraint", sin_error(ctl))


def negativo_valor(nombre, cond, control_ok):
    """Como negativo(), pero sobre una condición ya evaluada."""
    if not control_ok:
        sinc(f"{nombre}: el control positivo fallo")
        return
    pasa(cond, nombre)


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


def sesion_en(nombre, condicion):
    """Cierto si la sesión con ese application_name cumple la condición SQL
    sobre pg_stat_activity (leída como superusuario, que ve todas)."""
    return valor(sup(f"select count(*) from pg_stat_activity where application_name = '{nombre}' "
                     f"and {condicion};")) == "1"


def esperar_sesion(nombre, condicion, maximo=20):
    limite = time.monotonic() + maximo
    while time.monotonic() < limite:
        if sesion_en(nombre, condicion):
            return True
        time.sleep(0.2)
    return sesion_en(nombre, condicion)


def sql_esperar_bloqueo_de(nombre, maximo_decimas=150):
    """SQL que, dentro de la transacción en curso, espera (como superusuario)
    a que la sesión `nombre` esté esperando un bloqueo, y deja la línea
    visto|true o visto|false. pg_stat_clear_snapshot(): dentro de una
    transacción, pg_stat_activity se lee una vez y se cachea."""
    hay_espera = (f"EXISTS (SELECT 1 FROM pg_stat_activity WHERE application_name = '{nombre}' "
                  "AND wait_event_type = 'Lock')")
    return ("RESET ROLE;\n"
            f"DO $$ BEGIN FOR i IN 1..{maximo_decimas} LOOP PERFORM pg_stat_clear_snapshot(); "
            f"EXIT WHEN {hay_espera}; PERFORM pg_sleep(0.1); END LOOP; END $$;\n"
            "SELECT pg_stat_clear_snapshot();\n"
            f"SELECT 'visto|' || ({hay_espera})::text;\n"
            "SET ROLE aplicacion;\n")


def seccion_y():
    # Va después de x): y1 confirma una denuncia y un mensaje de A (el cierre
    # del personal tiene que hacer COMMIT de verdad), y x) compara los
    # conteos de A con los literales de h).
    p("=== y) mensajes: cierre simultaneo y rechazo entre empresas sin bloqueos")
    # y1) El personal, en una transacción, escribe su mensaje y archiva la
    #     denuncia; a la vez, el denunciante envía otro. Con un solo bloqueo
    #     (la fila de la denuncia) no hay interbloqueo: el denunciante espera
    #     a que el personal confirme y recibe CN001. Control: el denunciante
    #     llegó a esperar de verdad (visto|true), es decir, hubo contención.
    den = str(uuid.uuid4())
    r = sup(f"insert into canal.denuncia (empresa_id, id, contenido_cifrado, version_clave) "
            f"values ('{EMPRESA_A}', '{den}', {BYTES_FALSOS}, 1);")
    if not sin_error(r):
        sinc(f"y1) no se pudo crear la denuncia de prueba: {r.err.strip()[:200]!r}")
        return
    contexto = f"BEGIN;\nSELECT set_config('app.empresa_id', '{EMPRESA_A}', true) \\gset\n"

    def insertar(autor, autor_id, etiqueta):
        columnas = "empresa_id, denuncia_id, autor, contenido_cifrado, version_clave" + (", autor_id" if autor_id else "")
        valores = f"'{EMPRESA_A}', '{den}', '{autor}', {BYTES_FALSOS}, 1" + (f", '{autor_id}'" if autor_id else "")
        return f"insert into canal.mensaje ({columnas}) values ({valores}) returning '{etiqueta}|' || secuencia;\n"

    personal = ("SET application_name = 'y_personal';\n\\set VERBOSITY verbose\nSET ROLE aplicacion;\n" + contexto
                + insertar("personal", INSTR_A, "personal") + sql_esperar_bloqueo_de("y_denunciante")
                + f"update canal.denuncia set estado = 'archivada' where id = '{den}';\nCOMMIT;\n")
    denunciante = ("SET application_name = 'y_denunciante';\n\\set VERBOSITY verbose\nSET ROLE aplicacion;\n"
                   + contexto + insertar("denunciante", None, "denunciante") + "COMMIT;\n")
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futuro_personal = pool.submit(sup, personal)
        # El personal ya tiene su mensaje (y el bloqueo) cuando está en el
        # pg_sleep de la espera.
        listo = esperar_sesion("y_personal", "wait_event = 'PgSleep'")
        futuro_denunciante = pool.submit(sup, denunciante) if listo else None
        r_personal = futuro_personal.result()
        r_denunciante = futuro_denunciante.result() if futuro_denunciante else None
    if r_denunciante is None:
        sinc(f"y1) la sesion del personal no llego a su espera: {r_personal.err.strip()[:300]!r}")
    else:
        control = "visto|true" in r_personal.lineas() and "personal|1" in r_personal.lineas()
        p(f"   personal: {r_personal.lineas()} {r_personal.err.strip()[:200]!r}")
        p(f"   denunciante: {r_denunciante.lineas()} {r_denunciante.err.strip()[:200]!r}")
        negativo_valor("y1) ninguna de las dos sesiones termina en interbloqueo",
                       "deadlock" not in r_personal.err + r_denunciante.err, control)
        negativo_valor("y1) el personal escribe su mensaje y archiva la denuncia sin errores",
                       sin_error(r_personal), control)
        negativo("y1) el mensaje del denunciante, que esperaba, se rechaza al ver la denuncia archivada",
                 r_denunciante, TEXTO_DENUNCIA_CERRADA, control)
        final = sup(f"select estado || '|' || (select count(*) from canal.mensaje where denuncia_id = '{den}') "
                    f"from canal.denuncia where id = '{den}';")
        negativo_valor(f"y1) la denuncia queda archivada con solo el mensaje del personal ({valor(final)})",
                       valor(final) == "archivada|1", control)

    # y2) Un mensaje de la empresa A que apunta a una denuncia de B se rechaza
    #     sin tomar ningún bloqueo: con la transacción de A abierta (abortada
    #     por el error, que retendría lo bloqueado hasta el ROLLBACK), B
    #     escribe en su denuncia sin esperar. Control: si la denuncia de B
    #     está bloqueada de verdad, la misma medida falla por lock_timeout.
    def medir_b():
        return sup(f"\\set VERBOSITY verbose\nSET ROLE aplicacion;\nBEGIN;\n"
                   f"SELECT set_config('app.empresa_id', '{EMPRESA_B}', true) \\gset\n"
                   "SET LOCAL lock_timeout = '1s';\n"
                   f"insert into canal.mensaje (empresa_id, denuncia_id, autor, contenido_cifrado, version_clave) "
                   f"values ('{EMPRESA_B}', '{DEN_B1}', 'denunciante', {BYTES_FALSOS}, 1) returning 'b|' || secuencia;\n"
                   "ROLLBACK;\n")

    def con_sesion_abierta(nombre, sql, estado_sesion):
        """Ejecuta sql (que acaba en una pausa de 6 s con la transacción
        abierta), mide a B mientras tanto y devuelve (medida, sesión)."""
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            futuro = pool.submit(sup, f"SET application_name = '{nombre}';\n" + sql)
            listo = esperar_sesion(nombre, f"state = '{estado_sesion}'")
            medida = medir_b() if listo else None
            return medida, futuro.result()

    retiene = (f"BEGIN;\nselect 1 from canal.denuncia where id = '{DEN_B1}' for no key update;\n"
               "\\! sleep 6\nROLLBACK;\n")
    ctl_medida, ctl_sesion = con_sesion_abierta("y_retiene", retiene, "idle in transaction")
    control = ctl_medida is not None and TEXTO_PLAZO_BLOQUEO in ctl_medida.err
    if not control:
        p(f"   control: medida {ctl_medida.todo.strip()[:200] if ctl_medida else None!r}; "
          f"sesion {ctl_sesion.err.strip()[:200]!r}")
    ajena = (f"SET ROLE aplicacion;\nBEGIN;\nSELECT set_config('app.empresa_id', '{EMPRESA_A}', true) \\gset\n"
             f"insert into canal.mensaje (empresa_id, denuncia_id, autor, contenido_cifrado, version_clave) "
             f"values ('{EMPRESA_B}', '{DEN_B1}', 'denunciante', {BYTES_FALSOS}, 1);\n"
             "\\! sleep 6\nROLLBACK;\n")
    medida, sesion = con_sesion_abierta("y_ajena", ajena, "idle in transaction (aborted)")
    if medida is None:
        sinc(f"y2) la sesion de A no quedo abierta tras el error: {sesion.err.strip()[:300]!r}")
        return
    negativo_valor("y2) la sesion de A recibe el rechazo de la denuncia ajena",
                   TEXTO_MENSAJE_SIN_DENUNCIA in sesion.err, control)
    negativo_valor(f"y2) con esa transaccion de A abierta, B escribe en su denuncia sin esperar "
                   f"({medida.lineas()} {medida.err.strip()[:150]!r})",
                   sin_error(medida) and "b|" in " ".join(medida.lineas()), control)


def seccion_q():
    p("=== q) healthcheck")
    test = json.loads(ejecutar(["docker", "inspect", CID]).out)[0]["Config"]["Healthcheck"]["Test"]
    p(f"Test: {json.dumps(test)}")
    texto = " ".join(test)
    pasa("$$" not in texto, "q) el Test no contiene '$$'")
    pasa("*|6|true" in texto and not re.search(r"\*\|6(?!\|true)", texto), "q) el Test acepta solo '*|6|true'")
    orden = test[-1]
    control = dc("exec", "-T", "postgres", "sh", "-c", orden)
    if control.rc != 0:
        sinc(f"q) el control del Test no da 0 (codigo {control.rc})")
        return
    pasa(True, "q) control: el Test da 0")
    # El centinela es la ultima funcion del ultimo script (05_redaccion.sql):
    # si no existe, la inicializacion no llego al final.
    try:
        sup("ALTER FUNCTION canal.redactar_mensaje(uuid,integer,uuid,bytea,bytea,integer) "
            "RENAME TO redactar_centinela_x;")
        r = dc("exec", "-T", "postgres", "sh", "-c", orden)
        pasa(r.rc == 1, f"q) con la funcion centinela renombrada el Test da {r.rc} (esperado 1)")
    finally:
        sup("ALTER FUNCTION canal.redactar_centinela_x(uuid,integer,uuid,bytea,bytea,integer) "
            "RENAME TO redactar_mensaje;")
    r = dc("exec", "-T", "postgres", "sh", "-c", orden)
    pasa(r.rc == 0, f"q) tras renombrar de vuelta el Test da {r.rc} (esperado 0)")
    # Sin el rol de supresion (renombrado), tampoco es sano.
    try:
        sup("ALTER ROLE propietario_supresion RENAME TO propietario_supresion_x;")
        r = dc("exec", "-T", "postgres", "sh", "-c", orden)
        pasa(r.rc == 1, f"q) con propietario_supresion renombrado el Test da {r.rc} (esperado 1)")
    finally:
        sup("ALTER ROLE propietario_supresion_x RENAME TO propietario_supresion;")
    r = dc("exec", "-T", "postgres", "sh", "-c", orden)
    pasa(r.rc == 0, f"q) tras devolver el nombre al rol el Test da {r.rc} (esperado 0)")
    # Ni sin el de redaccion, el sexto.
    try:
        sup("ALTER ROLE propietario_redaccion RENAME TO propietario_redaccion_x;")
        r = dc("exec", "-T", "postgres", "sh", "-c", orden)
        pasa(r.rc == 1, f"q) con propietario_redaccion renombrado el Test da {r.rc} (esperado 1)")
    finally:
        sup("ALTER ROLE propietario_redaccion_x RENAME TO propietario_redaccion;")
    r = dc("exec", "-T", "postgres", "sh", "-c", orden)
    pasa(r.rc == 0, f"q) tras devolver el nombre al rol de redaccion el Test da {r.rc} (esperado 0)")
    r = dc("exec", "-T", "postgres", "sh", "-c", orden.replace("-U postgres", "-U nadie"))
    pasa(r.rc == 1, f"q) con -U nadie el Test da {r.rc} (esperado 1)")


def seccion_t():
    p("=== t) resolver_empresa")
    def resolver(texto):
        literal = "NULL" if texto is None else "'" + texto.replace("'", "''") + "'"
        return app(f"select coalesce(canal.resolver_empresa({literal})::text, 'NULL');")
    a, b = resolver(IDENT_A), resolver(IDENT_B)
    controles = sin_error(a) and sin_error(b) and valor(a) == EMPRESA_A and valor(b) == EMPRESA_B
    pasa(controles, f"t) controles: el identificador de A devuelve el uuid de A y el de B el de B ({valor(a)}, {valor(b)})")
    desconocido = resolver(IDENT_DESCONOCIDO)
    malformados = [("vacio", ""), ("x", "x"), ("64 caracteres", "a" * 64),
                   ("inyeccion SQL", "'; drop table canal.empresa; --"), ("mayusculas", "A" * 32), ("NULL", None)]
    if not controles:
        sinc("t) los controles fallaron: no se puede afirmar nada sobre los negativos")
        return
    pasa(valor(desconocido) == "NULL" and sin_error(desconocido), f"t) identificador valido desconocido -> NULL ({valor(desconocido)})")
    resultados = {}
    for nombre, texto in malformados:
        r = resolver(texto)
        resultados[nombre] = r
        pasa(valor(r) == "NULL" and sin_error(r) and not r.err.strip(), f"t) entrada mal formada ({nombre}) -> NULL sin error")
    # empresa A desactivada por el superusuario; se reactiva siempre
    try:
        sup(f"update canal.empresa set activa = false where id = '{EMPRESA_A}';")
        inactiva = resolver(IDENT_A)
    finally:
        sup(f"update canal.empresa set activa = true where id = '{EMPRESA_A}';")
    reactivada = resolver(IDENT_A)
    pasa(valor(inactiva) == "NULL" and sin_error(inactiva), f"t) empresa A desactivada -> NULL ({valor(inactiva)})")
    pasa(valor(reactivada) == EMPRESA_A, f"t) empresa A reactivada -> uuid de A otra vez ({valor(reactivada)})")
    huellas = {"desconocido": (desconocido.out, desconocido.err), "mal formado": (resultados["x"].out, resultados["x"].err),
               "inactiva": (inactiva.out, inactiva.err)}
    pasa(len(set(huellas.values())) == 1, f"t) salida y stderr identicos para desconocido, mal formado e inactiva ({huellas})")


def seccion_u():
    p("=== u) registrar_codigo y buscar_codigo")
    def registrar(hmac, den, ctx, final="COMMIT"):
        return app(f"select canal.registrar_codigo({bytea_hex(hmac)}, '{den}');", ctx=ctx, final=final)
    def contar():
        return valor(sup("select count(*) from canal.busqueda_seguimiento;"))
    ctl = registrar(HMAC1, DEN_A1, EMPRESA_A)
    pasa(sin_error(ctl), f"u) control: registrar_codigo(hmac1, A1) con contexto A funciona {ctl.err.strip()[:200]}")
    r = app(f"select * from canal.buscar_codigo({bytea_hex(HMAC1)});")
    pasa(r.lineas() == [f"{EMPRESA_A}|{DEN_A1}"], f"u) buscar_codigo(hmac1) sin contexto devuelve (A, A1) ({r.lineas()})")
    ctl_propia = registrar(HMAC2, DEN_A2, EMPRESA_A, final="ROLLBACK")
    ctl_ok = sin_error(ctl) and sin_error(ctl_propia)
    pasa(sin_error(ctl_propia), "u) control: una denuncia propia sin codigo (A2) se puede registrar (ROLLBACK)")
    ajena = registrar(HMAC3, DEN_B1, EMPRESA_A)
    inexistente = registrar(HMAC3, str(uuid.uuid4()), EMPRESA_A)
    if not ctl_ok:
        sinc("u) el control fallo: no se puede comparar el error de denuncia ajena e inexistente")
    else:
        a, b = normalizar_uuid(ajena.err), normalizar_uuid(inexistente.err)
        pasa("violates foreign key constraint" in a and a == b, "u) denuncia de B y uuid aleatorio: mismo error de clave foranea")
        if a != b:
            p(f"   ajena:       {a.strip()!r}\n   inexistente: {b.strip()!r}")
    antes = contar()
    sin_ctx = registrar(HMAC3, DEN_A2, SIN)
    vacio = registrar(HMAC3, DEN_A2, "")
    despues = contar()
    negativo("u) registrar_codigo sin contexto", sin_ctx, "registrar_codigo requiere contexto de empresa", ctl_ok)
    negativo("u) registrar_codigo con contexto vacio", vacio, "registrar_codigo requiere contexto de empresa", ctl_ok)
    pasa(antes == despues, f"u) sin contexto no se crean filas en busqueda_seguimiento ({antes} antes, {despues} despues)")
    negativo("u) HMAC de 31 bytes", registrar(HMAC31, DEN_A2, EMPRESA_A), "violates check constraint", ctl_ok)
    negativo("u) HMAC repetido (hmac1 con A2)", registrar(HMAC1, DEN_A2, EMPRESA_A), "duplicate key", ctl_ok)
    negativo("u) segundo codigo para la misma denuncia (A1)", registrar(HMAC3, DEN_A1, EMPRESA_A), "duplicate key", ctl_ok)
    inexistente_hmac = app(f"select count(*) from canal.buscar_codigo({bytea_hex(HMAC2)});")
    corto = app(f"select count(*) from canal.buscar_codigo({bytea_hex(HMAC31)});")
    control_buscar = app(f"select count(*) from canal.buscar_codigo({bytea_hex(HMAC1)});")
    if valor(control_buscar) != "1":
        sinc(f"u) el control de buscar_codigo (hmac1 devuelve 1 fila) dio {valor(control_buscar)!r}")
    else:
        pasa(valor(inexistente_hmac) == "0" and sin_error(inexistente_hmac), "u) buscar_codigo con HMAC inexistente -> 0 filas sin error")
        pasa(valor(corto) == "0" and sin_error(corto), "u) buscar_codigo con HMAC de 31 bytes -> 0 filas sin error")
    r = app(f"select * from canal.buscar_codigo({bytea_hex(HMAC1)});\n"
            f"select count(*) from canal.denuncia where id = '{DEN_A1}';", ctx=EMPRESA_B)
    pasa(r.lineas() == [f"{EMPRESA_A}|{DEN_A1}", "0"],
         f"u) con contexto B, buscar_codigo(hmac1) devuelve (A, A1) (ignora el contexto) y leer A1 devuelve 0 filas ({r.lineas()})")
    # suposicion 5: dentro de una funcion de definidor, empresa_actual() exige EXECUTE al dueno
    r = sup("BEGIN;\nREVOKE EXECUTE ON FUNCTION canal.empresa_actual() FROM propietario_funciones;\nSET ROLE aplicacion;\n"
            f"SELECT set_config('app.empresa_id', '{EMPRESA_A}', true) \\gset\n"
            f"select canal.registrar_codigo({bytea_hex(HMAC2)}, '{DEN_A2}');\nRESET ROLE;\nROLLBACK;\n")
    negativo("u) suposicion 5: sin EXECUTE sobre empresa_actual() para el dueno, registrar_codigo falla",
             r, "permission denied for function empresa_actual", ctl_ok)
    # suposicion 3: una funcion de definidor no se expande en linea
    r = sup(f"explain (verbose, costs off) select canal.resolver_empresa('{IDENT_A}');")
    p(f"   plan: {r.lineas()}")
    pasa("resolver_empresa" in r.out and "directorio_empresas" not in r.out,
         "u) suposicion 3: el plan llama a resolver_empresa y no la expande en linea")


def seccion_v():
    global FOTO_PREVIA
    p("=== v) alta_empresa y roles plataforma y propietario_funciones")
    # foto previa de los conteos, antes de dar de alta ninguna empresa
    foto = {"A": conteos_contexto(EMPRESA_A), "B": conteos_contexto(EMPRESA_B)}
    FOTO_PREVIA = foto if all(len(v) == len(TABLAS_RLS) for v in foto.values()) else None
    p(f"   foto previa de conteos: {FOTO_PREVIA}")
    alta = cliente_red("select * from canal.alta_empresa('Empresa Nueva', 'Atlantic/Canary');", "plataforma")
    p(f"alta_empresa por login real de plataforma: {len(alta.lineas())} fila(s); stderr={alta.err.strip()[:200]!r}")
    fila = alta.lineas()[0] if alta.lineas() else ""
    encaje = re.fullmatch(r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\|([0-9a-f]{32})", fila)
    pasa(len(alta.lineas()) == 1 and encaje is not None and sin_error(alta), "v) alta_empresa devuelve (uuid, 32 hexadecimales)")
    if encaje:
        r = app(f"select coalesce(canal.resolver_empresa('{encaje.group(2)}')::text, 'NULL');")
        pasa(valor(r) == encaje.group(1), "v) control: resolver_empresa(identificador) como aplicacion devuelve ese uuid")
        r = sup(f"select zona_horaria from canal.empresa where id = '{encaje.group(1)}';")
        pasa(valor(r) == "Atlantic/Canary", f"v) la empresa nueva guarda la zona pedida, no la de por defecto ({valor(r)})")
    control_alta = encaje is not None and sin_error(alta)
    negativo("v) nombre vacio", cliente_red("select * from canal.alta_empresa('', 'Europe/Madrid');", "plataforma"),
             "violates check constraint", control_alta)
    negativo("v) nombre de 201 caracteres",
             cliente_red(f"select * from canal.alta_empresa('{'x' * 201}', 'Europe/Madrid');", "plataforma"),
             "violates check constraint", control_alta)
    negativo("v) zona horaria fuera de Espana (UTC)",
             cliente_red("select * from canal.alta_empresa('Empresa UTC', 'UTC');", "plataforma"),
             "violates check constraint", control_alta)
    negativo("v) zona horaria NULL",
             cliente_red("select * from canal.alta_empresa('Empresa sin zona', NULL);", "plataforma"),
             "violates not-null constraint", control_alta)
    negativo("v) la firma antigua alta_empresa(text) ya no existe",
             cliente_red("select * from canal.alta_empresa('Empresa antigua');", "plataforma"),
             "function canal.alta_empresa(unknown) does not exist", control_alta)
    # plataforma no puede leer ninguna tabla ni ejecutar las funciones de la aplicacion
    r = cliente_red("\n".join(f"select count(*) from canal.{t};" for t in TABLAS), "plataforma")
    for t in TABLAS:
        negativo(f"v) plataforma: select de {t}", r, f"permission denied for table {t}", control_alta)
    r = cliente_red("select canal.resolver_empresa('x');\nselect * from canal.buscar_codigo('\\x00'::bytea);\n"
                    "select canal.registrar_codigo('\\x00'::bytea, gen_random_uuid());\n"
                    "select canal.verificar_cadena_auditoria();\nselect canal.empresa_actual();\n", "plataforma")
    for f in ("resolver_empresa", "buscar_codigo", "registrar_codigo", "verificar_cadena_auditoria", "empresa_actual"):
        negativo(f"v) plataforma: ejecutar {f}", r, f"permission denied for function {f}", control_alta)
    negativo("v) aplicacion: ejecutar alta_empresa", app("select * from canal.alta_empresa('Intrusa', 'Europe/Madrid');"),
             "permission denied for function alta_empresa", control_alta)
    negativo("v) login de red como propietario_funciones", cliente_literal("propietario_funciones", "select 1;"),
             "rejects connection", control_alta)
    # propietario_funciones (SET ROLE desde el superusuario): sin acceso a las demas tablas
    def como_propietario(sentencia):
        return sup(f"SET ROLE propietario_funciones;\n{sentencia}\n")
    ctl = como_propietario("select count(id) from canal.empresa;")
    ctl_ok = sin_error(ctl) and valor(ctl).isdigit() and int(valor(ctl)) >= 3
    pasa(ctl_ok, f"v) control: propietario_funciones si puede leer empresa(id) ({valor(ctl)} empresas)")
    for t in ("denuncia", "mensaje", "usuario_personal", "clave_empresa", "registro_auditoria",
              "invitacion_personal", "dispositivo_personal", "sesion_personal"):
        negativo(f"v) propietario_funciones: select de {t}", como_propietario(f"select count(*) from canal.{t};"),
                 "permission denied", ctl_ok)
    # suposicion 2: INSERT ... RETURNING bajo RLS exige privilegio y politica de SELECT.
    # Cada prueba va en su propia transaccion terminada en ROLLBACK.
    insercion = "insert into canal.empresa (nombre) values ('prueba_s2') returning id;"
    def prueba_s2(preparacion):
        return sup(f"BEGIN;\n{preparacion}SET ROLE propietario_funciones;\n{insercion}\nROLLBACK;\n")
    control = prueba_s2("")
    control_s2 = sin_error(control) and re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", valor(control)) is not None
    pasa(control_s2, f"v) suposicion 2, control: propietario_funciones inserta en empresa y recibe el id ({valor(control)!r}) {control.err.strip()[:200]}")
    negativo("v) suposicion 2: sin la politica empresa_select_definidor el INSERT ... RETURNING falla",
             prueba_s2("DROP POLICY empresa_select_definidor ON canal.empresa;\n"), "row-level security", control_s2)
    negativo("v) suposicion 2: sin SELECT sobre empresa(id) el INSERT ... RETURNING falla",
             prueba_s2("REVOKE SELECT (id) ON canal.empresa FROM propietario_funciones;\n"), "permission denied", control_s2)
    r = sup("select count(*) from pg_policies where schemaname = 'canal' and policyname = 'empresa_select_definidor';")
    pasa(valor(r) == "1", f"v) tras las pruebas la politica empresa_select_definidor sigue existiendo ({valor(r)} fila)")
    r = sup("select has_column_privilege('propietario_funciones', 'canal.empresa', 'id', 'SELECT')::text;")
    pasa(valor(r) == "true", f"v) tras las pruebas propietario_funciones sigue teniendo SELECT en empresa(id) ({valor(r)})")


def seccion_w():
    p("=== w) search_path hostil")
    sql = f"""BEGIN;
CREATE TEMP TABLE directorio_empresas (identificador_publico text, empresa_id uuid);
INSERT INTO pg_temp.directorio_empresas VALUES ('{IDENT_FALSO}', '{uuid.uuid4()!s}');
GRANT ALL ON pg_temp.directorio_empresas TO PUBLIC;
CREATE FUNCTION canal.control_inseguro(p text) RETURNS uuid LANGUAGE sql SECURITY DEFINER
AS $$ select empresa_id from directorio_empresas where identificador_publico = p $$;
GRANT EXECUTE ON FUNCTION canal.control_inseguro(text) TO aplicacion;
SET ROLE aplicacion;
SET search_path = pg_temp, canal;
select 'control|' || coalesce(canal.control_inseguro('{IDENT_FALSO}')::text, 'NULL');
select 'falso|' || coalesce(canal.resolver_empresa('{IDENT_FALSO}')::text, 'NULL');
select 'real|' || coalesce(canal.resolver_empresa('{IDENT_A}')::text, 'NULL');
RESET ROLE;
ROLLBACK;
"""
    r = sup(sql)
    p(f"   salida: {r.lineas()}; stderr: {r.err.strip()[:200]!r}")
    datos = dict(l.split("|", 1) for l in r.lineas() if "|" in l)
    control = datos.get("control", "NULL")
    if control == "NULL" or not sin_error(r):
        sinc("w) el control no devuelve el uuid FALSO: la tecnica de suplantacion no funciona en este entorno")
    else:
        pasa(datos.get("falso") == "NULL", f"w) con search_path = pg_temp, canal, resolver_empresa('{IDENT_FALSO}') -> NULL ({datos.get('falso')})")
        pasa(datos.get("real") == EMPRESA_A, f"w) y resolver_empresa del identificador real de A -> uuid real de A ({datos.get('real')})")
    r = sup("select count(*) from pg_proc where proname = 'control_inseguro';\n"
            "select count(*) from pg_class c join pg_namespace n on n.oid = c.relnamespace "
            "where c.relname = 'directorio_empresas' and n.nspname like 'pg_temp%';\n"
            "select count(*) from pg_class c join pg_namespace n on n.oid = c.relnamespace "
            "where c.relname = 'directorio_empresas' and n.nspname = 'canal';")
    pasa(r.lineas() == ["0", "0", "1"], f"w) tras el ROLLBACK no quedan ni la funcion de control ni la tabla temporal ({r.lineas()})")


def seccion_x():
    p("=== x) aislamiento tras las funciones (regresion)")
    if FOTO_PREVIA is None:
        sinc("x) no se pudo tomar la foto previa de conteos al comienzo de v)")
        return
    for nombre, ctx, idx in (("A", EMPRESA_A, 0), ("B", EMPRESA_B, 1)):
        real = conteos_contexto(ctx)
        pasa(real == FOTO_PREVIA[nombre],
             f"x) contexto {nombre}: las 6 tablas (incluida registro_auditoria) iguales a la foto previa: real={real} foto={FOTO_PREVIA[nombre]}")
        fijas = sorted(l for l in real if not l.startswith("registro_auditoria|"))
        esperado = sorted(f"{t}|{CONTEOS[t][idx]}" for t in TABLAS_RLS if t != "registro_auditoria")
        pasa(fijas == esperado, f"x) contexto {nombre}: las 5 tablas sin registro_auditoria coinciden con los literales de h): real={fijas} esperado={esperado}")
        cadena = verificar_cadena(ctx)
        pasa(cadena == "NULL", f"x) contexto {nombre}: verificar_cadena_auditoria() = {cadena} (esperado NULL)")
    esperado_cero = sorted(f"{t}|0" for t in TABLAS_RLS)
    consultas = "\n".join(f"select '{t}|' || count(*) from canal.{t};" for t in TABLAS_RLS)
    pasa(sorted(app(consultas).lineas()) == esperado_cero, "x) sin contexto todas las tablas siguen devolviendo 0")
    r = sup("select count(*) from canal.empresa;")
    pasa(valor(r) == "3", f"x) el superusuario ve 3 empresas (A, B y la creada por alta_empresa): {valor(r)}")


def seccion_su():
    # Va despues de y) y antes de r): borra filas, asi que usa su propia
    # empresa C y comprueba al final que A y B no han cambiado.
    p("=== su) supresion legal (arts. 32.4, 26.2 y 32.3)")
    ids = {caso: datos[0] for caso, datos in SU.items()}
    hoy = "(now() AT TIME ZONE 'Europe/Madrid')::date"
    filas = ",\n    ".join(f"('{EMPRESA_C}', '{i}', ({hoy} - {intervalo})::date, '{e}', {BYTES_FALSOS}, 1)"
                           for i, intervalo, e in SU.values())
    mensajes = ",\n    ".join(f"('{EMPRESA_C}', '{ids[c]}', {s}, current_date, 'denunciante', {BYTES_FALSOS}, 1)"
                               for c, s in (("art32", 1), ("art32", 2), ("art26", 1), ("instruccion", 1),
                                            ("no_veraz", 1)))
    codigos = ",\n    ".join(f"({bytea_hex(h)}, '{EMPRESA_C}', '{ids[c]}')"
                              for c, h in (("art32", HMAC_SU_ART32), ("art26", HMAC_SU_ART26),
                                           ("art32_borde", HMAC_SU_BORDE), ("no_veraz", HMAC_SU_NO_VERAZ)))
    # Fechas forzadas como superusuario con los triggers de fecha y de
    # mensajes desactivados solo dentro de esta transaccion.
    sql = f"""BEGIN;
INSERT INTO canal.empresa (id, nombre, zona_horaria) VALUES ('{EMPRESA_C}', 'Empresa C', 'Europe/Madrid');
INSERT INTO canal.clave_empresa (empresa_id, version, clave_envuelta) VALUES ('{EMPRESA_C}', 1, '\\x03');
ALTER TABLE canal.denuncia DISABLE TRIGGER denuncia_fecha;
ALTER TABLE canal.mensaje DISABLE TRIGGER mensaje_preparar;
INSERT INTO canal.denuncia (empresa_id, id, fecha, estado, contenido_cifrado, version_clave) VALUES
    {filas};
INSERT INTO canal.mensaje (empresa_id, denuncia_id, secuencia, fecha, autor, contenido_cifrado, version_clave) VALUES
    {mensajes};
INSERT INTO canal.busqueda_seguimiento (codigo_hmac, empresa_id, denuncia_id) VALUES
    {codigos};
ALTER TABLE canal.denuncia ENABLE TRIGGER denuncia_fecha;
ALTER TABLE canal.mensaje ENABLE TRIGGER mensaje_preparar;
COMMIT;
"""
    r = dc(*PSQL[:-4], "-v", "ON_ERROR_STOP=1", "-f", "-", entrada=sql.encode())
    if not sin_error(r):
        sinc(f"su) no se pudieron preparar los datos de prueba: {r.err.strip()[:300]!r}")
        return
    r = sup("select count(*) from pg_trigger where not tgisinternal and tgenabled <> 'O' "
            "and tgrelid in ('canal.denuncia'::regclass, 'canal.mensaje'::regclass);")
    pasa(valor(r) == "0", f"su) los triggers de fecha y de mensajes vuelven a estar activos ({valor(r)} desactivados)")
    foto = {"A": conteos_contexto(EMPRESA_A), "B": conteos_contexto(EMPRESA_B)}

    def plataforma(sql_plataforma):
        return cliente_red(sql_plataforma, "plataforma")

    def suprimir(lote):
        return plataforma(f"select empresa_id || '|' || articulo || '|' || suprimidas "
                          f"from canal.suprimir_denuncias_caducadas({lote});")
    contar = "select canal.contar_denuncias_caducadas();"

    # su1) Antes de borrar nada: plataforma ve las 8 a suprimir (art32, art26,
    #      en_uso, carrera, carrera_ctl, inadmitida y las 2 no veraces), y no
    #      las 4 de los bordes, la de instruccion ni la nueva de hoy. Es tambien
    #      el control de los negativos: sin una politica de bloqueo, FOR UPDATE
    #      devolveria cero filas en silencio.
    r = plataforma(contar)
    control = sin_error(r) and valor(r) == "8"
    pasa(control, f"su1) contar_denuncias_caducadas como plataforma = {valor(r)!r} (esperado 8) {r.err.strip()[:200]}")
    negativo("su1) aplicacion no puede ejecutar suprimir_denuncias_caducadas",
             app("select * from canal.suprimir_denuncias_caducadas(1);"),
             "permission denied for function suprimir_denuncias_caducadas", control)
    negativo("su1) aplicacion no puede ejecutar contar_denuncias_caducadas",
             app("select canal.contar_denuncias_caducadas();"),
             "permission denied for function contar_denuncias_caducadas", control)
    negativo("su1) plataforma no puede ejecutar articulo_supresion directamente",
             plataforma("select canal.articulo_supresion('nueva', current_date, 'Europe/Madrid');"),
             "permission denied for function articulo_supresion", control)
    for lote in ("0", "501", "NULL"):
        negativo(f"su1) lote {lote} rechazado", suprimir(lote), TEXTO_LOTE, control)
    negativo("su1) en REPEATABLE READ se rechaza",
             plataforma("BEGIN ISOLATION LEVEL REPEATABLE READ;\n"
                        "select * from canal.suprimir_denuncias_caducadas(1);\nROLLBACK;"),
             TEXTO_AISLAMIENTO, control)
    r = plataforma(contar)
    negativo_valor(f"su1) tras los rechazos no se ha borrado nada (contar = {valor(r)})", valor(r) == "8", control)
    negativo("su1) login de red como propietario_supresion", cliente_literal("propietario_supresion", "select 1;"),
             "rejects connection", control)

    # su2) propietario_supresion puede bloquear pero no modificar; no lee el
    #      contenido ni toca otras tablas. Control: bloquea la fila.
    def como_supresion(sentencia):
        return sup(f"SET ROLE propietario_supresion;\n{sentencia}\n")
    ctl = como_supresion(f"BEGIN;\nselect count(*) from (select id from canal.denuncia "
                         f"where id = '{ids['art32_borde']}' for update) s;\nROLLBACK;")
    ctl_ok = sin_error(ctl) and valor(ctl) == "1"
    pasa(ctl_ok, f"su2) control: propietario_supresion bloquea una denuncia con FOR UPDATE ({valor(ctl)!r})")
    negativo("su2) propietario_supresion no puede cambiar el estado (WITH CHECK false)",
             como_supresion(f"update canal.denuncia set estado = 'archivada' where id = '{ids['art32_borde']}';"),
             "new row violates row-level security policy", ctl_ok)
    negativo("su2) propietario_supresion no lee el contenido cifrado",
             como_supresion("select contenido_cifrado from canal.denuncia limit 1;"),
             "permission denied for table denuncia", ctl_ok)
    for t in ("clave_empresa", "usuario_personal", "empresa", "registro_auditoria", "directorio_empresas",
              "invitacion_personal", "dispositivo_personal", "sesion_personal"):
        negativo(f"su2) propietario_supresion no borra en {t}", como_supresion(f"delete from canal.{t};"),
                 "permission denied", ctl_ok)
    # Suposicion comprobada: sin la politica de bloqueo, FOR UPDATE no da
    # error sino cero filas (por eso existe denuncia_bloqueo_supresion).
    r = sup(f"BEGIN;\nDROP POLICY denuncia_bloqueo_supresion ON canal.denuncia;\nSET ROLE propietario_supresion;\n"
            f"select count(*) from (select id from canal.denuncia where id = '{ids['art32_borde']}' for update) s;\n"
            "RESET ROLE;\nROLLBACK;")
    negativo_valor(f"su2) suposicion: sin la politica de bloqueo, FOR UPDATE devuelve 0 filas sin error ({valor(r)!r})",
                   sin_error(r) and valor(r) == "0", ctl_ok)
    r = sup("select count(*) from pg_policies where schemaname = 'canal' and policyname = 'denuncia_bloqueo_supresion';")
    pasa(valor(r) == "1", f"su2) tras la prueba la politica de bloqueo sigue existiendo ({valor(r)})")

    # su3) Con dos sesiones del personal abiertas: una pasa "carrera" a
    #      en_instruccion y retiene "en_uso" (confirmara); otra pasa
    #      "carrera_ctl" a en_instruccion (deshara). La supresion las salta sin
    #      esperar y borra el resto, por lotes y la mas antigua primero.
    contexto = f"SET ROLE aplicacion;\nBEGIN;\nSELECT set_config('app.empresa_id', '{EMPRESA_C}', true) \\gset\n"
    confirma = ("SET application_name = 'su_confirma';\n" + contexto
                + f"update canal.denuncia set estado = 'en_instruccion' where id = '{ids['carrera']}';\n"
                + f"select 1 from canal.denuncia where id = '{ids['en_uso']}' for no key update;\n"
                + "\\! sleep 20\nCOMMIT;\n")
    deshace = ("SET application_name = 'su_deshace';\n" + contexto
               + f"update canal.denuncia set estado = 'en_instruccion' where id = '{ids['carrera_ctl']}';\n"
               + "\\! sleep 20\nROLLBACK;\n")
    abiertas = "state = 'idle in transaction'"
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        f_confirma, f_deshace = pool.submit(sup, confirma), pool.submit(sup, deshace)
        listas = esperar_sesion("su_confirma", abiertas) and esperar_sesion("su_deshace", abiertas)
        if listas:
            nowait = sup(f"BEGIN;\nselect 1 from canal.denuncia where id in ('{ids['en_uso']}', '{ids['carrera']}', "
                         f"'{ids['carrera_ctl']}') for update nowait;\nROLLBACK;")
            lote1, lote2, durante = suprimir(1), suprimir(100), plataforma(contar)
            siguen = sesion_en("su_confirma", abiertas) and sesion_en("su_deshace", abiertas)
        r_confirma, r_deshace = f_confirma.result(), f_deshace.result()
    if not listas:
        sinc(f"su3) las sesiones del personal no quedaron abiertas: {r_confirma.err.strip()[:200]!r} "
             f"{r_deshace.err.strip()[:200]!r}")
        return
    control = "could not obtain lock" in nowait.err and siguen and sin_error(r_confirma) and sin_error(r_deshace)
    pasa(control, f"su3) control: las tres filas estaban bloqueadas de verdad y las dos sesiones seguian abiertas "
                  f"al terminar la supresion ({siguen})")
    negativo_valor(f"su3) lote de 1: solo la mas antigua, la de 10 anos ({lote1.lineas()})",
                   lote1.lineas() == [f"{EMPRESA_C}|art26|1"] and sin_error(lote1), control)
    negativo_valor(f"su3) lote de 100: las dos de 3 meses justos (nueva e inadmitida) y las dos no veraces (una de "
                   f"hoy y una de 10 anos, ambas art32_3); las tres en uso se saltan sin esperar ({lote2.lineas()})",
                   lote2.lineas() == [f"{EMPRESA_C}|art32|2", f"{EMPRESA_C}|art32_3|2"] and sin_error(lote2),
                   control)
    negativo_valor(f"su3) mientras tanto, contar ve las 3 en uso ({valor(durante)})", valor(durante) == "3", control)

    # su4) Ya sin sesiones: "carrera" se confirmo en instruccion y se conserva;
    #      "carrera_ctl" se deshizo y se suprime con "en_uso".
    lote3, lote4, despues = suprimir(100), suprimir(100), plataforma(contar)
    negativo_valor(f"su4) la siguiente ejecucion suprime en_uso y carrera_ctl ({lote3.lineas()})",
                   lote3.lineas() == [f"{EMPRESA_C}|art32|2"], control)
    negativo_valor(f"su4) despues no queda nada que suprimir ({lote4.lineas()}, contar = {valor(despues)})",
                   lote4.lineas() == [] and sin_error(lote4) and valor(despues) == "0", control)

    # su5) Lo que queda y la evidencia.
    r = sup(f"select id || '|' || estado from canal.denuncia where empresa_id = '{EMPRESA_C}';")
    comparar("su5) quedan exactamente los tres bordes, la de instruccion, la que paso a instruccion en carrera y "
             "la nueva de hoy",
             sorted(r.lineas()), sorted([f"{ids['art32_borde']}|nueva", f"{ids['instruccion']}|en_instruccion",
                                         f"{ids['art26_borde']}|resuelta", f"{ids['carrera']}|en_instruccion",
                                         f"{ids['inadmitida_borde']}|inadmitida", f"{ids['nueva_hoy']}|nueva"]))
    r = sup(f"select denuncia_id || '|' || secuencia from canal.mensaje where empresa_id = '{EMPRESA_C}';")
    comparar("su5) de los mensajes solo queda el de la denuncia en instruccion", r.lineas(), [f"{ids['instruccion']}|1"])
    r = sup(f"select denuncia_id from canal.busqueda_seguimiento where empresa_id = '{EMPRESA_C}';")
    comparar("su5) de los codigos solo queda el de la denuncia del borde", r.lineas(), [ids["art32_borde"]])
    r = sup(f"select secuencia || '|' || actor || '|' || accion || '|' || objeto_id from canal.registro_auditoria "
            f"where empresa_id = '{EMPRESA_C}' order by secuencia;")
    comparar("su5) auditoria: una fila de sistema por denuncia suprimida, con su articulo y su id", r.lineas(), [
        f"1|sistema|supresion_art26|{ids['art26']}",
        f"2|sistema|supresion_art32|{ids['art32']}",
        f"3|sistema|supresion_art32|{ids['inadmitida']}",
        f"4|sistema|supresion_art32_3|{ids['no_veraz']}",
        f"5|sistema|supresion_art32_3|{ids['no_veraz_10']}",
        f"6|sistema|supresion_art32|{ids['en_uso']}",
        f"7|sistema|supresion_art32|{ids['carrera_ctl']}",
    ])
    pasa(verificar_cadena(EMPRESA_C) == "NULL", "su5) la cadena de auditoria de C sigue intacta")
    comprobar_python(EMPRESA_C, "empresa C tras la supresion")
    for nombre, ctx in (("A", EMPRESA_A), ("B", EMPRESA_B)):
        real = conteos_contexto(ctx)
        pasa(real == foto[nombre], f"su5) las 6 tablas de la empresa {nombre} no han cambiado: {real}")


def seccion_re():
    # Va despues de su) y antes de r): usa su propia empresa D y comprueba al
    # final que A y B no han cambiado.
    p("=== re) redaccion (art. 32.2)")
    usuarios = ",\n    ".join(
        f"('{EMPRESA_D}', '{u}', '{correo}@ejemplo.test', '{rol}', 'x', '\\x01', 1, true, {activo})"
        for u, correo, rol, activo in ((ADMIN_D, "ana", "admin", "true"), (ADMIN2_D, "eva", "admin", "true"),
                                       (INSTR_D, "luis", "instructor", "true"), (BAJA_D, "baja", "admin", "false")))
    sql = f"""BEGIN;
INSERT INTO canal.empresa (id, nombre, zona_horaria) VALUES ('{EMPRESA_D}', 'Empresa D', 'Europe/Madrid');
INSERT INTO canal.clave_empresa (empresa_id, version, clave_envuelta) VALUES
    ('{EMPRESA_D}', 1, '\\x04'), ('{EMPRESA_D}', 2, '\\x05');
INSERT INTO canal.usuario_personal (empresa_id, id, email, rol, hash_contrasena, secreto_totp_cifrado,
                                    version_clave_totp, totp_activo, activo) VALUES
    {usuarios};
INSERT INTO canal.denuncia (empresa_id, id, contenido_cifrado, version_clave, asignada_a, estado) VALUES
    ('{EMPRESA_D}', '{RE_D1}', '\\x0d01', 1, '{ADMIN_D}', 'nueva'),
    ('{EMPRESA_D}', '{RE_D2}', '\\x0d02', 1, '{INSTR_D}', 'nueva'),
    ('{EMPRESA_D}', '{RE_D3}', '\\x0d03', 1, '{ADMIN_D}', 'no_veraz'),
    ('{EMPRESA_D}', '{RE_D4}', '\\x0d04', 1, '{BAJA_D}', 'nueva');
INSERT INTO canal.mensaje (empresa_id, denuncia_id, id, autor, contenido_cifrado, version_clave) VALUES
    ('{EMPRESA_D}', '{RE_D1}', '{RE_M1}', 'denunciante', '\\x0d0a', 1);
COMMIT;
"""
    r = dc(*PSQL[:-4], "-v", "ON_ERROR_STOP=1", "-f", "-", entrada=sql.encode())
    if not sin_error(r):
        sinc(f"re) no se pudieron preparar los datos de prueba: {r.err.strip()[:300]!r}")
        return
    foto = {"A": conteos_contexto(EMPRESA_A), "B": conteos_contexto(EMPRESA_B)}

    def como_app(cuerpo, ctx=EMPRESA_D):
        return app("\\set VERBOSITY verbose\n" + cuerpo, ctx=ctx)

    def redactar_denuncia(denuncia, actor, anterior, nuevo, version=2, ctx=EMPRESA_D):
        return como_app(f"select canal.redactar_denuncia('{denuncia}', '{actor}', '\\x{anterior}', "
                        f"'\\x{nuevo}', {version});", ctx)

    def redactar_mensaje(secuencia, actor, anterior, nuevo, denuncia=RE_D1):
        return como_app(f"select canal.redactar_mensaje('{denuncia}', {secuencia}, '{actor}', '\\x{anterior}', "
                        f"'\\x{nuevo}', 2);")

    def contenido(tabla, condicion):
        return valor(sup(f"select encode(contenido_cifrado, 'hex') || '|' || version_clave "
                         f"from canal.{tabla} where {condicion};"))

    def auditoria():
        return sup(f"select secuencia || '|' || actor || '|' || accion || '|' || objeto_id || '|' "
                   f"|| coalesce(destino_id::text, '') from canal.registro_auditoria "
                   f"where empresa_id = '{EMPRESA_D}' order by secuencia;").lineas()

    # re1) Controles: el admin con la denuncia asignada reescribe el texto de
    #      la denuncia y el de un mensaje, con la version de clave nueva, y
    #      cada redaccion deja su fila con el actor y, en el mensaje, su id.
    r = redactar_denuncia(RE_D1, ADMIN_D, "0d01", "0d11")
    actual = contenido("denuncia", f"id = '{RE_D1}'")
    control = sin_error(r) and actual == "0d11|2"
    pasa(control, f"re1) control: redactar_denuncia reescribe la denuncia asignada ({actual}) {r.err.strip()[:200]}")
    r = redactar_mensaje(1, ADMIN_D, "0d0a", "0d1a")
    actual = contenido("mensaje", f"id = '{RE_M1}'")
    control_mensaje = sin_error(r) and actual == "0d1a|2"
    pasa(control_mensaje, f"re1) control: redactar_mensaje reescribe el mensaje 1 ({actual}) {r.err.strip()[:200]}")
    filas_esperadas = [f"1|personal:{ADMIN_D}|redaccion_denuncia|{RE_D1}|",
                       f"2|personal:{ADMIN_D}|redaccion_mensaje|{RE_D1}|{RE_M1}"]
    comparar("re1) una fila de auditoria por redaccion, con actor, denuncia y mensaje", auditoria(), filas_esperadas)

    # re2) Rechazos de la funcion. Ninguno escribe nada ni deja fila.
    negativo("re2) contenido anterior distinto (compare-and-swap)",
             redactar_denuncia(RE_D1, ADMIN_D, "0d01", "0dff"), TEXTO_REDACCION_DENUNCIA, control)
    negativo("re2) un instructor, aunque tenga la denuncia asignada",
             redactar_denuncia(RE_D2, INSTR_D, "0d02", "0dff"), TEXTO_REDACCION_ACTOR, control)
    negativo("re2) un admin sin la denuncia asignada",
             redactar_denuncia(RE_D1, ADMIN2_D, "0d11", "0dff"), TEXTO_REDACCION_DENUNCIA, control)
    negativo("re2) una denuncia no veraz",
             redactar_denuncia(RE_D3, ADMIN_D, "0d03", "0dff"), TEXTO_REDACCION_DENUNCIA, control)
    negativo("re2) un admin dado de baja con la denuncia asignada",
             redactar_denuncia(RE_D4, BAJA_D, "0d04", "0dff"), TEXTO_REDACCION_ACTOR, control)
    negativo("re2) con el contexto de otra empresa",
             redactar_denuncia(RE_D1, ADMIN_D, "0d11", "0dff", ctx=EMPRESA_A), TEXTO_REDACCION_ACTOR, control)
    negativo("re2) sin contexto de empresa",
             redactar_denuncia(RE_D1, ADMIN_D, "0d11", "0dff", ctx=SIN), TEXTO_REDACCION_ACTOR, control)
    negativo("re2) mensaje con contenido anterior distinto",
             redactar_mensaje(1, ADMIN_D, "0d0a", "0dff"), TEXTO_REDACCION_MENSAJE, control_mensaje)
    negativo("re2) mensaje inexistente",
             redactar_mensaje(2, ADMIN_D, "0d1a", "0dff"), TEXTO_REDACCION_MENSAJE, control_mensaje)
    negativo("re2) mensaje de una denuncia no asignada a quien redacta",
             redactar_mensaje(1, ADMIN2_D, "0d1a", "0dff"), TEXTO_REDACCION_MENSAJE_DENUNCIA, control_mensaje)
    pasa(contenido("denuncia", f"id = '{RE_D1}'") == "0d11|2" and contenido("mensaje", f"id = '{RE_M1}'") == "0d1a|2"
         and contenido("denuncia", f"id = '{RE_D2}'") == "0d02|1"
         and contenido("denuncia", f"id = '{RE_D3}'") == "0d03|1"
         and contenido("denuncia", f"id = '{RE_D4}'") == "0d04|1",
         "re2) los rechazos no han cambiado ningun contenido")
    comparar("re2) los rechazos no han dejado filas de auditoria", auditoria(), filas_esperadas)

    # re3) Sin la funcion no hay camino: aplicacion no reescribe contenido,
    #      plataforma no ejecuta la funcion y propietario_redaccion no borra,
    #      no cambia el estado ni entra por la red. Control: re1.
    negativo("re3) aplicacion no puede hacer UPDATE del contenido de una denuncia",
             como_app(f"update canal.denuncia set contenido_cifrado = '\\x00' where id = '{RE_D1}';"),
             "permission denied for table denuncia", control)
    negativo("re3) aplicacion no puede hacer UPDATE del contenido de un mensaje",
             como_app(f"update canal.mensaje set contenido_cifrado = '\\x00' where id = '{RE_M1}';"),
             "permission denied for table mensaje", control_mensaje)
    negativo("re3) plataforma no puede ejecutar redactar_denuncia",
             cliente_red(f"select canal.redactar_denuncia('{RE_D1}', '{ADMIN_D}', '\\x0d11', '\\x00', 2);",
                         "plataforma"),
             "permission denied for function redactar_denuncia", control)

    def como_redaccion(sentencia):
        return sup(f"SET ROLE propietario_redaccion;\nBEGIN;\n"
                   f"SELECT set_config('app.empresa_id', '{EMPRESA_D}', true) \\gset\n{sentencia}\nROLLBACK;\n")
    ctl = como_redaccion(f"select count(*) from canal.denuncia where id = '{RE_D1}';")
    ctl_ok = sin_error(ctl) and valor(ctl) == "1"
    pasa(ctl_ok, f"re3) control: propietario_redaccion ve la denuncia con el contexto de D ({valor(ctl)!r})")
    negativo("re3) propietario_redaccion no cambia el estado",
             como_redaccion(f"update canal.denuncia set estado = 'archivada' where id = '{RE_D1}';"),
             "permission denied for table denuncia", ctl_ok)
    for t in ("denuncia", "mensaje", "registro_auditoria", "usuario_personal"):
        negativo(f"re3) propietario_redaccion no borra en {t}", como_redaccion(f"delete from canal.{t};"),
                 "permission denied", ctl_ok)
    negativo("re3) login de red como propietario_redaccion", cliente_literal("propietario_redaccion", "select 1;"),
             "rejects connection", ctl_ok)

    pasa(verificar_cadena(EMPRESA_D) == "NULL", "re4) la cadena de auditoria de D sigue intacta")
    comprobar_python(EMPRESA_D, "empresa D tras la redaccion")
    for nombre, ctx in (("A", EMPRESA_A), ("B", EMPRESA_B)):
        real = conteos_contexto(ctx)
        pasa(real == foto[nombre], f"re4) las tablas de la empresa {nombre} no han cambiado: {real}")


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
    comparar("r) siguen las 11 tablas", sup("select c.relname from pg_class c join pg_namespace n on n.oid = c.relnamespace "
                                         "where n.nspname = 'canal' and c.relkind = 'r';").lineas(), TABLAS)
    politicas = sup("select tablename, policyname, cmd from pg_policies where schemaname = 'canal';").lineas()
    tablas_con_politicas = {l.split("|")[0] for l in politicas}
    comparar("r) siguen las 40 politicas definidas en d)", politicas, POLITICAS)
    pasa(len(politicas) == 40 and len(tablas_con_politicas) == 9,
         f"r) exactamente 40 politicas repartidas en exactamente 9 tablas ({len(politicas)} politicas, {len(tablas_con_politicas)} tablas)")
    funciones = sup("select p.proname from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'canal';").lineas()
    comparar("r) siguen las 15 funciones", funciones, list(FUNCIONES_CATALOGO))
    pasa(esperar_healthy(CID) == "healthy", "r) el contenedor esta healthy")


def seccion_s():
    p("=== s) limpieza")
    # --rmi local: la imagen de postgres se construye (db/Dockerfile) y lleva el
    # prefijo del proyecto; sin esto quedaría huérfana tras cada ejecución.
    r = dc("down", "-v", "--rmi", "local")
    p(f"down -v --rmi local -> codigo {r.rc}")
    for etiqueta, orden in [
        ("contenedor", ["docker", "ps", "-a", "--format", "{{.Names}}"]),
        ("red", ["docker", "network", "ls", "--format", "{{.Name}}"]),
        ("volumen", ["docker", "volume", "ls", "--format", "{{.Name}}"]),
        ("imagen", ["docker", "image", "ls", "--format", "{{.Repository}}"]),
    ]:
        restos = [n for n in ejecutar(orden).out.split() if n.startswith(PROYECTO)]
        pasa(not restos, f"s) ningun {etiqueta} con prefijo {PROYECTO} {restos if restos else ''}".strip())
    for nombre in ("contrasena_postgres_superusuario", "contrasena_migrador", "contrasena_aplicacion", "contrasena_plataforma"):
        ruta = RAIZ / "secrets" / f"{nombre}.txt"
        pasa(ruta.is_file() and not ruta.is_dir(), f"s) secrets/{nombre}.txt sigue siendo un fichero")
    final = estado_git()
    if ESTADO_GIT_ARRANQUE is None or final is None:
        sinc("s) no se pudo comparar el estado de Git (git no disponible, fallo o el directorio no es un repositorio)")
    else:
        iguales = final == ESTADO_GIT_ARRANQUE
        pasa(iguales, "s) la bateria no ha modificado el repo (git status igual al del arranque)")
        if not iguales:
            p(f"   al arrancar: {ESTADO_GIT_ARRANQUE}")
            p(f"   al terminar: {final}")


def terminar():
    if estado["falla"] or estado["sin_conclusion"]:
        resultado = "NO OK (hay FALLA o SIN CONCLUSION)"
    else:
        resultado = "OK"
    p("RESULTADO GLOBAL: " + resultado)
    SALIDA.write_text("\n".join(lineas_salida) + "\n", encoding="utf-8", newline="\n")
    sys.exit(0 if resultado == "OK" else 1)


def estado_git():
    """Líneas de "git status --short -uall", o None si git no está disponible o falla."""
    try:
        r = ejecutar(["git", "status", "--short", "-uall"], timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.rc != 0:
        return None
    return [l.rstrip() for l in r.out.splitlines() if l.strip()]


def recursos_previos():
    previos = []
    for orden in (["docker", "ps", "-a", "--format", "{{.Names}}"],
                  ["docker", "network", "ls", "--format", "{{.Name}}"],
                  ["docker", "volume", "ls", "--format", "{{.Name}}"],
                  ["docker", "image", "ls", "--format", "{{.Repository}}"]):
        previos += [n for n in ejecutar(orden).out.split() if n.startswith(PROYECTO)]
    return previos


def main():
    global IMAGEN, CID, ESTADO_GIT_ARRANQUE
    # Estado de Git al arrancar, antes de levantar Docker: s) lo compara con el final.
    ESTADO_GIT_ARRANQUE = estado_git()
    # Precondiciones: si fallan, no se limpia nada (podrian ser recursos ajenos).
    if ejecutar(["docker", "info", "--format", "{{.ServerVersion}}"]).rc != 0:
        p("PARADA: docker info falla")
        terminar_con_parada()
    previos = recursos_previos()
    if previos:
        p(f"PARADA: ya existen recursos con prefijo {PROYECTO}: {previos}")
        terminar_con_parada()
    for nombre in ("contrasena_aplicacion", "contrasena_plataforma"):
        if not (RAIZ / "secrets" / f"{nombre}.txt").is_file():
            p(f"PARADA: secrets/{nombre}.txt no existe como fichero")
            terminar_con_parada()
    parada = None
    try:
        seccion_a()
        CID = dc("ps", "-q", "postgres").out.strip()
        # La imagen se lee del contenedor en marcha: es la que se construyó con
        # db/Dockerfile y la que usan los clientes temporales de m) y r).
        IMAGEN = ejecutar(["docker", "inspect", "--format", "{{.Config.Image}}", CID]).out.strip() if CID else ""
        p(f"imagen de postgres: {IMAGEN}")
        if not IMAGEN:
            raise Parada("no se pudo leer la imagen del contenedor postgres")
        for seccion in (seccion_b, seccion_c, seccion_d, seccion_e, seccion_f, seccion_g, seccion_h, seccion_i,
                        seccion_j, seccion_k, seccion_l, seccion_m, seccion_au, seccion_n, seccion_o, seccion_z, seccion_p,
                        seccion_q,
                        seccion_t, seccion_u, seccion_v, seccion_w, seccion_x, seccion_y, seccion_su, seccion_re,
                        seccion_r):
            seccion()
    except Parada as e:
        parada = str(e)
        p(f"PARADA: {parada}")
    except Exception:  # noqa: BLE001 - error inesperado del propio test: se informa y se limpia
        parada = "error inesperado en el test"
        p("ERROR INESPERADO:\n" + traceback.format_exc())
    finally:
        if parada is not None:
            dc("down", "-v", "--rmi", "local")
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
