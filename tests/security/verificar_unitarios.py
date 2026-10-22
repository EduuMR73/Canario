#!/usr/bin/env python3
"""Batería de las pruebas unitarias (tests/unit/): la lógica pura de app/ sin
base de datos, sin Redis y sin red.

Qué comprueba:
a) Controles del propio ejecutor: un directorio con una prueba que falla a
   propósito debe salir con código 1 y uno vacío con 5 (unittest en Python
   3.12 sale con 5 si no ejecuta nada). Si alguno no se cumple, el resto no
   tendría conclusión.
b) Las pruebas unitarias pasan dentro de la imagen de la API (Python y
   dependencias exactos de producción), con el número EXACTO de pruebas por
   fichero: un fichero que unittest no descubra se saltaría en silencio y los
   demás seguirían pasando.
c) Mutantes: una copia de app/ con un cambio que rompe una medida de
   seguridad debe hacer fallar la prueba que la cubre. Una prueba que nunca
   se ha visto fallar no demuestra nada. Antes, dos controles: la copia sin
   mutar pasa (el montaje de la copia no rompe nada) y una copia que no se
   puede importar falla (la copia montada es la que se usa). Si el texto que
   se muta no aparece exactamente una vez, SIN CONCLUSION: un mutante que no
   cambia nada no prueba nada.
s) Limpieza: la imagen construida se borra y el repositorio queda igual.

Cómo se ejecuta (desde la raíz del repositorio, en PowerShell, con Docker en
marcha):

    python tests/security/verificar_unitarios.py

No necesita los secretos ni levanta servicios: construye la imagen de la API
con la etiqueta canario_unitarios-api:prueba y ejecuta cada pasada en un
contenedor efímero sin red, de solo lectura (con /tmp en memoria), sin
capacidades y con el código montado en solo lectura. Las copias de app/ y los
controles se escriben en un directorio temporal del sistema, nunca dentro del
repositorio, y se borran al terminar. La salida completa se guarda en
verificacion_unitarios.txt dentro del directorio temporal del sistema. El
código de salida es 0 solo si el resultado global es OK.

Solo usa la biblioteca estándar.
"""
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import traceback

RAIZ = pathlib.Path.cwd()
PROYECTO = "canario_unitarios"
IMAGEN = f"{PROYECTO}-api:prueba"
SALIDA = pathlib.Path(tempfile.gettempdir()) / "verificacion_unitarios.txt"

lineas_salida = []
estado = {"falla": False, "sin_conclusion": False}

# ---------------------------------------------------------------------------
# Oráculos literales
# ---------------------------------------------------------------------------
# Pruebas por fichero de tests/unit/. Al añadir o quitar una prueba hay que
# cambiar este número a mano: es lo que hace visible un fichero que no corre.
PRUEBAS_POR_FICHERO = {
    "test_arranque": 4,
    "test_avisos": 5,
    "test_bd": 9,
    "test_claves": 7,
    "test_correo": 8,
    "test_cripto": 38,
    "test_denuncias": 10,
    "test_errores": 11,
    "test_frontera": 11,
    "test_instruccion": 33,
    "test_limitador": 16,
    "test_login": 8,
    "test_personal": 8,
    "test_proveedores_externos": 18,
    "test_solicitudes": 9,
    "test_tokens": 10,
    "test_transporte": 18,
    "test_validacion": 8,
    "test_web": 17,
}
TOTAL_PRUEBAS = 248
SALIDA_SIN_PRUEBAS = 5  # unittest de Python 3.12: "NO TESTS RAN"

B = chr(92)  # barra invertida, para escribir el texto exacto del fuente sin escapes
# Mutantes: (fichero de app/, texto exacto, sustituto, prueba que debe fallar, qué rompe).
# La prueba va con su identificador completo (fichero.Clase.metodo): hay
# métodos con el mismo nombre en ficheros distintos.
MUTANTES = [
    ("instruccion.py", "if desde < 0 or not fragmento", "if not fragmento",
     "test_instruccion.Tachar.test_desde_negativo", "tachar acepta posiciones negativas (contadas desde el final)"),
    ("validacion.py", B + "x7f-" + B + "x9f", B + "x7f",
     "test_validacion.TextoLinea.test_bordes_rechazados", "texto_linea admite los controles C1"),
    ("limitador.py", "LIMITE_MAXIMO = 1_000_000", "LIMITE_MAXIMO = 10_000_000",
     "test_limitador.CargarLimites.test_errores", "CANARIO_LIMITES admite mas de un millon de peticiones"),
    ("claves.py", "if leidas[primero] == leidas[segundo]:", "if False:",
     "test_claves.Carga.test_iguales", "dos claves del servidor iguales"),
    ("tokens.py", 'if completo["header"] != CABECERA or set(claims)', 'if set(claims)',
     "test_tokens.Verificar.test_cabecera_exacta", "el JWT se acepta con cualquier typ y con kid o jku"),
    ("tokens.py", ' or set(claims) != set(CLAIMS):', ':',
     "test_tokens.Verificar.test_claims_exactos", "el JWT se acepta con claims de mas (un rol)"),
    ("tokens.py", " or exp != iat + DURACION_ACCESO:", ":",
     "test_tokens.Verificar.test_caducidad_y_duracion", "el JWT se acepta aunque dure una hora"),
    ("tokens.py", '"strict_aud": True', '"strict_aud": False',
     "test_tokens.Verificar.test_audiencia_y_emisor", "el JWT se acepta con aud en una lista"),
    ("cripto.py", "BLOQUE_RELLENO = 256", "BLOQUE_RELLENO = 128",
     "test_cripto.Relleno.test_literales", "relleno en tramos de 128 bytes"),
    ("denuncias.py", '            or type(contenido["v"]) is not int\n', "",
     "test_denuncias.Deserializar.test_formato_desconocido", 'deserializar admite {"v": true}'),
    ("bd.py", "SQL_FIJAR_CONTEXTO = \"select set_config('app.empresa_id', %s, true)\"",
     "SQL_FIJAR_CONTEXTO = \"select set_config('app.empresa_id', %s, false)\"",
     "test_bd.FijarContexto.test_local_a_la_transaccion_y_enlazado",
     "el contexto de empresa dura toda la sesion y pasa a la peticion siguiente"),
    ("bd.py", '    if valor not in (None, ""):', "    if False:",
     "test_bd.ConexionDevueltaAlPool.test_con_contexto_se_descarta",
     "una conexion con contexto de empresa vuelve al pool"),
    ("verificacion_arranque.py", "atributos == (False, False, False, False, False)", "atributos[0] is False",
     "test_arranque.Comprobar.test_cada_desviacion_su_identificador", "el arranque acepta un rol con BYPASSRLS"),
    ("personal.py", "if reservada is None or not contrasena_ok or paso is None:", "if reservada is None or paso is None:",
     "test_login.ComprobarFactores.test_contrasena_incorrecta", "el login no exige la contrasena"),
    ("personal.py", "    paso = cripto.verificar_totp(secreto, codigo, instante)\n    if reservada is None",
     ("    paso = cripto.verificar_totp(secreto, codigo, instante) if reservada is not None else None\n"
      "    if reservada is None"),
     "test_login.ComprobarFactores.test_mismo_trabajo_en_todos_los_caminos",
     "sin cuenta no se calcula el TOTP (el tiempo delata si la cuenta existe)"),
    ("rutas_personal.py", "    peticion.state.sesion_personal = sesion\n", "",
     "test_errores.AccesoDenegadoPorLaAplicacion.test_instructor_en_ruta_de_admin",
     "la sesion no llega al manejador: un 403 del personal no deja evento"),
    ("rutas_personal.py", 'f"{nombre}={_id_para_registro(valor)}"', 'f"{nombre}={valor}"',
     "test_errores.AccesoDenegadoPorLaAplicacion.test_salto_de_linea_en_la_ruta_no_llega_al_log",
     "el id de la ruta llega tal cual al log (un %0A inyecta una linea)"),
    # Páginas del denunciante (app/rutas_web.py).
    ("rutas_web.py", "    autoescape=True,\n", "    autoescape=False,\n",
     "test_web.Plantillas.test_autoescape", "las plantillas no escapan lo que escribe el usuario (XSS)"),
    ("rutas_web.py", '    if cabeceras.get("origin") != origen_web:\n        return False\n', "",
     "test_web.Origen.test_comprobacion", "un formulario enviado desde otro sitio se acepta (CSRF)"),
    ("rutas_web.py", 'sitio is None or sitio == "same-origin"', 'sitio is None or sitio != "cross-site"',
     "test_web.Origen.test_comprobacion", "se acepta un envio same-site, como el del 8443"),
    ("rutas_web.py", ("        if not origen_aceptado(peticion.headers, peticion.app.state.origen_web):\n"
                      "            raise HTTPException(403)\n"), "",
     "test_web.Dependencia.test_origen_antes_del_cuerpo", "el POST no comprueba el origen antes de leer el cuerpo"),
    ("rutas_web.py", "    if not _CUERPO_URLENCODED.fullmatch(cuerpo):\n        return None\n", "",
     "test_web.Formulario.test_rechazos", "un cuerpo que no genera un navegador (un % suelto) se acepta"),
    ("rutas_web.py", 'valor.replace("' + B + 'r' + B + 'n", "' + B + 'n")', "valor",
     "test_web.Formulario.test_valido", "el CRLF de la codificacion del envio se guarda en la denuncia"),
    ("rutas_web.py", 'or puerto == "443")', ")",
     "test_web.Origen.test_cargar_rechazos", "se acepta un origen con :443, que ningun navegador envia"),
    ("limitador.py", 're.compile(r"/(?:v1|web)/empresas/[^/]+/denuncias")', 're.compile(r"/v1/empresas/[^/]+/denuncias")',
     "test_limitador.ReglaDeCadaRuta.test_reglas", "una denuncia por formulario no gasta el cupo de denuncias"),
    ("limitador.py", 'RUTAS_MENSAJES = {"/v1/seguimiento/mensajes", "/web/seguimiento/mensajes"}',
     'RUTAS_MENSAJES = {"/v1/seguimiento/mensajes"}',
     "test_limitador.ReglaDeCadaRuta.test_reglas", "un mensaje por formulario no gasta el cupo de mensajes"),
    # Registro "primero el email" (app/solicitudes.py y app/correo.py).
    ("limitador.py", 'RUTAS_REGISTRO = {"/v1/personal/registro"}', "RUTAS_REGISTRO = set()",
     "test_limitador.ReglaDeCadaRuta.test_reglas", "una solicitud de registro solo gasta el cupo de otras"),
    ("solicitudes.py", "            conexion.execute(personal.SQL_RESERVA_ASINCRONA)\n", "",
     "test_solicitudes.Solicitar.test_mismas_sentencias_en_todos_los_caminos",
     "el registro espera al disco al crear la solicitud (el tiempo delata si el email tiene cuenta)"),
    ("solicitudes.py", '"crear": resuelta is not None and not cuenta and not pendiente}', '"crear": not cuenta}',
     "test_solicitudes.Solicitar.test_mismas_sentencias_en_todos_los_caminos",
     "un nuevo registro sustituye la solicitud que su dueno ya verifico"),
    ("solicitudes.py", "    if texto is None:\n        raise rutas_web.ErrorConfiguracion(",
     ("    if texto is None:\n        texto = \"https://localhost:8445\"\n    if False:\n"
      "        raise rutas_web.ErrorConfiguracion("),
     "test_solicitudes.Origen.test_obligatorio", "sin CANARIO_ORIGEN_PERSONAL los enlaces usan un origen por defecto"),
    ("correo.py", "tipo, type(error).__name__)", "tipo, correo.destinatario)",
     "test_correo.Enviar.test_fallo_al_log_sin_datos", "un fallo de envio escribe el email en el log"),
    ("correo.py", "    if not _semaforo.acquire(blocking=False):\n",
     "    if not _semaforo.acquire(blocking=False) and False:\n",
     "test_correo.Enviar.test_sin_hueco_se_descarta_sin_esperar",
     "los envios simultaneos no tienen tope (un SMTP lento agota los hilos de la API)"),
    # Registro en segundo plano y las dos reglas del destinatario (bloque 5a-bis).
    ("limitador.py", 're.compile(r"([a-z]+(?:_[a-z]+)*)=', 're.compile(r"([a-z_]+)=',
     "test_limitador.CargarLimites.test_errores", "CANARIO_LIMITES admite guiones bajos sueltos en el nombre"),
    ("limitador.py", "if cuenta > limite.peticiones]", "if cuenta >= limite.peticiones]",
     "test_limitador.DecidirVariasReglas.test_en_el_limite_se_permite",
     "la peticion que llega justo al limite ya se rechaza"),
    ("limitador.py", "max(segundos for *_, segundos in superadas)", "min(segundos for *_, segundos in superadas)",
     "test_limitador.DecidirVariasReglas.test_retry_after_el_mayor_y_un_solo_primer_exceso",
     "el Retry-After invita a repetir antes de que se pueda (429 seguro)"),
    ("solicitudes.py", 'registro.error("EVENTO registro_fallido: error=%s", type(error).__name__)',
     'registro.error("EVENTO registro_fallido: error=%s", error)',
     "test_solicitudes.Procesar.test_fallo_al_log_sin_email_y_sin_correo",
     "un fallo del registro en segundo plano escribe el email en el log"),
    ("solicitudes.py", "    except Exception as error:  # noqa: BLE001",
     "    except psycopg.IntegrityError as error:  # noqa: BLE001",
     "test_solicitudes.Procesar.test_fallo_al_log_sin_email_y_sin_correo",
     "un error de la base de datos sale de la tarea sin pasar por el log (traceback de uvicorn)"),
    ("solicitudes.py", "        correo.enviar(mensaje)\n", "        pass\n",
     "test_solicitudes.Procesar.test_envia_el_correo_que_toca", "el registro en segundo plano no envia el correo"),
    # Rol auditor: lee la auditoria y nunca el contenido (bloque 5b).
    ("personal.py", 'ROLES_INSTRUCCION = ("admin", "instructor")', 'ROLES_INSTRUCCION = ("admin", "instructor", "auditor")',
     "test_instruccion.GuardasPreviasALaBaseDeDatos.test_el_auditor_no_toca_ninguna_denuncia",
     "el auditor entra en las denuncias"),
    ("personal.py", "    if sesion.rol not in permitidos:", "    if False:",
     "test_instruccion.GuardasPreviasALaBaseDeDatos.test_el_auditor_no_toca_ninguna_denuncia",
     "la puerta por rol deja pasar a cualquiera"),
    ("instruccion.py", 'una fila de auditoría por lectura."""\n    personal.exigir_rol(sesion, personal.ROLES_INSTRUCCION)\n',
     'una fila de auditoría por lectura."""\n',
     "test_instruccion.GuardasPreviasALaBaseDeDatos.test_el_auditor_no_toca_ninguna_denuncia",
     "leer una denuncia no comprueba el rol (solo la asignacion)"),
    ("instruccion.py", 'una acción explícita aparte del listado."""\n    personal.exigir_rol(sesion, personal.ROLES_AUDITORIA)',
     'una acción explícita aparte del listado."""\n    _exigir_admin(sesion)',
     "test_instruccion.GuardasPreviasALaBaseDeDatos.test_auditoria_para_admin_y_auditor",
     "el auditor no puede verificar la cadena de auditoria"),
    ("instruccion.py", "if not activo or rol not in personal.ROLES_INSTRUCCION:", "if not activo:",
     "test_instruccion.Asignar.test_a_un_auditor_no_y_sin_escribir_nada",
     "una denuncia se puede asignar a un auditor (y leer su contenido)"),
    ("instruccion.py", "if error.sqlstate == SQLSTATE_DESTINO_NO_ASIGNABLE:", "if False:",
     "test_instruccion.Asignar.test_el_rechazo_de_la_base_de_datos_es_el_mismo_409",
     "el rechazo del trigger de asignacion acaba en un 500"),
    # Tope de lecturas y avisos a quien vigila (bloque A2).
    ("instruccion.py", "    if distintas > LECTURAS_TOPE:\n", "    if distintas > LECTURAS_TOPE + 1:\n",
     "test_instruccion.DecidirLecturas.test_fronteras", "el tope deja abrir una denuncia de mas"),
    ("instruccion.py", "    if primera and distintas == LECTURAS_AVISO:", "    if distintas == LECTURAS_AVISO:",
     "test_instruccion.DecidirLecturas.test_fronteras", "releer la vigesima denuncia vuelve a avisar"),
    ("instruccion.py", "            raise LimiteLecturas(segundos)\n", "            pass\n",
     "test_instruccion.LeerConTope.test_por_encima_del_tope_rechaza_sin_avisar", "pasado el tope se sigue leyendo"),
    ("instruccion.py",
     ("        _auditar(conexion, sesion, ACCION_LECTURA, denuncia_id)\n"
      "        distintas, veces, segundos = conexion.execute(\n"
      "            SQL_LECTURAS_DEL_DIA, {\"denuncia\": denuncia_id, \"actor\": _actor(sesion)}).fetchone()\n"),
     ("        distintas, veces, segundos = conexion.execute(\n"
      "            SQL_LECTURAS_DEL_DIA, {\"denuncia\": denuncia_id, \"actor\": _actor(sesion)}).fetchone()\n"
      "        _auditar(conexion, sesion, ACCION_LECTURA, denuncia_id)\n"),
     "test_instruccion.LeerConTope.test_la_fila_se_escribe_antes_de_contar",
     "se cuenta antes de escribir: dos lecturas simultaneas pasan con la ultima plaza"),
    ("avisos.py", "and totp_activo and id <> %s order by email", "and totp_activo and %s is not null order by email",
     "test_avisos.Destinatarios.test_los_roles_que_leen_la_auditoria", "el aviso tambien le llega a la cuenta sospechosa"),
    ("correo.py", "    for uno in correos:\n        enviar(uno)\n", "    for uno in correos[:1]:\n        enviar(uno)\n",
     "test_correo.Enviar.test_enviar_todos_sigue_tras_un_fallo", "un aviso a varias personas solo le llega a la primera"),
    # Sesión del navegador con cookies (bloque 6a).
    ("rutas_personal.py", '    if sitio != "same-origin":\n        raise OrigenNoPermitido(sitio)\n',
     '    if sitio == "cross-site":\n        raise OrigenNoPermitido(sitio)\n',
     "test_transporte.EsNavegador.test_rechazos_y_su_sitio_para_el_log",
     "una peticion same-site (otro puerto de localhost) entra con las cookies (CSRF)"),
    ("rutas_personal.py", 'if metodo not in METODOS_SEGUROS and cabeceras.get("origin") != origen_personal:',
     "if False:",
     "test_transporte.EsNavegador.test_rechazos_y_su_sitio_para_el_log",
     "un POST con cookies se acepta sin el Origin de la SPA"),
    ("rutas_personal.py", '    if "authorization" in cabeceras:\n        raise personal.SesionNoValida\n', "",
     "test_transporte.EsNavegador.test_bearer_en_el_navegador_es_ambiguo", "Bearer y cookie a la vez se aceptan"),
    ("rutas_personal.py", "if nombre in encontradas or len(valor)", "if len(valor)",
     "test_transporte.CookiesCanario.test_repetida_o_demasiado_larga_no_vale_ninguna",
     "con una cookie de Canario repetida vale la ultima (cookie inyectada desde otro puerto)"),
    ("rutas_personal.py", 'max_age=segundos, path="/", secure=True, httponly=True',
     'max_age=segundos, path="/", secure=True, httponly=False',
     "test_transporte.Respuestas.test_login_en_el_navegador_pone_las_tres_cookies",
     "las cookies de sesion se leen desde JavaScript (un XSS se lleva la sesion)"),
    ("rutas_personal.py", '    respuesta.delete_cookie(nombre, path="/", secure=True,',
     '    respuesta.delete_cookie(nombre, path="/", secure=False,',
     "test_transporte.Respuestas.test_cierre_en_el_navegador_borra_acceso_y_renovacion",
     "el cierre de sesion no borra las cookies __Host- (el navegador ignora un borrado sin Secure)"),
    # Sin conexión a PostgreSQL (app/frontera_http.py).
    ("frontera_http.py", "    aplicacion.add_exception_handler(PoolTimeout, _sin_conexion)\n", "",
     "test_frontera.SinConexion.test_pool_agotado_503_con_retry_after",
     "sin conexion a PostgreSQL la API responde 500 en vez de 503 con Retry-After"),
    # Proveedor externo: el adaptador de Google del broker (app/proveedores_externos.py).
    ("proveedores_externos.py", 'if claims.get("aud") != client_id:', "if False:",
     "test_proveedores_externos.IdToken.test_audiencia", "se acepta un id_token emitido para otra aplicacion"),
    ("proveedores_externos.py", "not hmac.compare_digest(recibido.encode(), nonce.encode())", "False",
     "test_proveedores_externos.IdToken.test_nonce", "se acepta un id_token de otro flujo (sin nonce o con otro)"),
    ("proveedores_externos.py", "if type(exp) is not int or ahora() >= exp:", "if type(exp) is not int or ahora() > exp:",
     "test_proveedores_externos.IdToken.test_caducidad", "se acepta un id_token en el segundo exacto en que caduca"),
    ("proveedores_externos.py", '        "code_challenge_method": "S256",\n', "",
     "test_proveedores_externos.Autorizacion.test_url_exacta",
     "la URL de autorizacion no fija S256 y el proveedor tomaria plain (RFC 7636, 4.3)"),
]

PRUEBA_QUE_FALLA = '''import unittest


class Control(unittest.TestCase):
    def test_falla_a_proposito(self):
        self.assertEqual(1, 2)
'''


class R:
    """Resultado de un comando: código, stdout y stderr por separado."""

    def __init__(self, rc, out, err):
        self.rc, self.out, self.err = rc, out, err

    @property
    def todo(self):
        return self.out + self.err


class Parada(Exception):
    pass


def p(texto=""):
    print(texto, flush=True)
    lineas_salida.append(texto)


def ejecutar(args, timeout=900):
    # check=False explícito: el código de salida se comprueba en cada llamada.
    r = subprocess.run(args, capture_output=True, timeout=timeout, check=False)
    return R(r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace"))


def pasa(cond, texto):
    p(("PASA  " if cond else "FALLA ") + texto)
    if not cond:
        estado["falla"] = True


def sinc(texto):
    p("SIN CONCLUSION " + texto)
    estado["sin_conclusion"] = True


def negativo(nombre, cond, control_ok, detalle=""):
    """Prueba negativa con control: si el control falla, SIN CONCLUSION."""
    if not control_ok:
        sinc(f"{nombre}: el control positivo fallo {detalle}".rstrip())
        return
    pasa(cond, nombre)
    if not cond and detalle:
        p(f"   {detalle}")


def unittest_en_imagen(pruebas, app=None):
    """Ejecuta unittest sobre el directorio pruebas dentro de la imagen de la
    API. Con app, monta esa copia en lugar del app/ de la imagen."""
    orden = ["docker", "run", "--rm", "--network", "none", "--read-only",
             "--tmpfs", "/tmp:size=16m,mode=1777", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
             "--mount", f"type=bind,src={pruebas},dst=/pruebas,readonly"]
    if app is not None:
        orden += ["--mount", f"type=bind,src={app},dst=/srv/app,readonly"]
    orden += ["--entrypoint", "python", IMAGEN, "-m", "unittest", "discover", "-s", "/pruebas", "-t", "/pruebas", "-v"]
    return ejecutar(orden)


def recuento(salida):
    """Pruebas ejecutadas por fichero, leídas de la salida de unittest -v."""
    cuentas = {}
    for linea in salida.splitlines():
        encaje = re.match(r"test_\w+ \((test_\w+)\.", linea)
        if encaje:
            cuentas[encaje.group(1)] = cuentas.get(encaje.group(1), 0) + 1
    return cuentas


def pruebas_falladas(salida):
    """Identificadores (fichero.Clase.metodo) de las pruebas con FAIL o ERROR
    en la salida de unittest, por ejemplo "FAIL: test_x (fichero.Clase.test_x)"."""
    return set(re.findall(r"^(?:FAIL|ERROR): test_\w+ \(([\w.]+)\)", salida, re.MULTILINE))


def seccion_a(temporal):
    p("=== a) controles del ejecutor")
    con_fallo = temporal / "control_fallo"
    con_fallo.mkdir()
    (con_fallo / "test_control.py").write_text(PRUEBA_QUE_FALLA, encoding="utf-8", newline="\n")
    vacio = temporal / "control_vacio"
    vacio.mkdir()
    r_fallo = unittest_en_imagen(con_fallo)
    r_vacio = unittest_en_imagen(vacio)
    ok_fallo = r_fallo.rc == 1 and "test_control.Control.test_falla_a_proposito" in pruebas_falladas(r_fallo.err)
    ok_vacio = r_vacio.rc == SALIDA_SIN_PRUEBAS
    pasa(ok_fallo, f"a) una prueba que falla da codigo 1 (codigo {r_fallo.rc})")
    pasa(ok_vacio, f"a) un directorio sin pruebas da codigo {SALIDA_SIN_PRUEBAS} (codigo {r_vacio.rc})")
    if not (ok_fallo and ok_vacio):
        raise Parada("los controles del ejecutor fallan: ninguna otra conclusion es fiable")


def seccion_b():
    p("=== b) pruebas unitarias en la imagen de la API")
    r = unittest_en_imagen(RAIZ / "tests" / "unit")
    cuentas = recuento(r.err)
    pasa(r.rc == 0 and re.search(r"^OK$", r.err, re.MULTILINE) is not None,
         f"b) todas las pruebas pasan (codigo {r.rc})")
    if r.rc != 0:
        for nombre in sorted(pruebas_falladas(r.err)):
            p(f"   falla: {nombre}")
        p("   " + "\n   ".join(r.err.strip().splitlines()[-40:]))
    pasa(f"Ran {TOTAL_PRUEBAS} tests" in r.err, f"b) se ejecutan exactamente {TOTAL_PRUEBAS} pruebas")
    pasa(cuentas == PRUEBAS_POR_FICHERO, "b) cada fichero ejecuta su numero exacto de pruebas")
    if cuentas != PRUEBAS_POR_FICHERO:
        p(f"   esperado: {PRUEBAS_POR_FICHERO}")
        p(f"   real:     {cuentas}")
    return r.rc == 0


def copia_de_app(temporal, nombre):
    destino = temporal / nombre / "app"
    shutil.copytree(RAIZ / "app", destino, ignore=shutil.ignore_patterns("__pycache__"))
    return destino


def seccion_c(temporal, base_ok):
    p("=== c) mutantes: cada medida rota hace fallar su prueba")
    pruebas = RAIZ / "tests" / "unit"
    sana = copia_de_app(temporal, "copia_sana")
    rota = copia_de_app(temporal, "copia_rota")
    fichero = rota / "cripto.py"
    fichero.write_bytes(fichero.read_bytes() + b"\nraise ImportError('copia rota a proposito')\n")
    r_sana = unittest_en_imagen(pruebas, sana)
    r_rota = unittest_en_imagen(pruebas, rota)
    control_sana = r_sana.rc == 0 and f"Ran {TOTAL_PRUEBAS} tests" in r_sana.err
    control_rota = r_rota.rc != 0
    pasa(control_sana, f"c) control: la copia sin mutar de app/ pasa entera (codigo {r_sana.rc})")
    pasa(control_rota, f"c) control: una copia que no se puede importar falla (codigo {r_rota.rc})")
    controles = base_ok and control_sana and control_rota
    for i, (nombre, viejo, nuevo, prueba, rompe) in enumerate(MUTANTES, 1):
        etiqueta = f"c) mutante {i} ({nombre}: {rompe}) lo detecta {prueba}"
        app = copia_de_app(temporal, f"mutante_{i}")
        ruta = app / nombre
        texto = ruta.read_bytes().decode("utf-8")
        apariciones = texto.count(viejo)
        if apariciones != 1:
            sinc(f"{etiqueta}: el texto a mutar aparece {apariciones} veces, no 1")
            continue
        ruta.write_bytes(texto.replace(viejo, nuevo).encode("utf-8"))
        r = unittest_en_imagen(pruebas, app)
        falladas = pruebas_falladas(r.err)
        negativo(etiqueta, r.rc == 1 and prueba in falladas, controles,
                 f"codigo {r.rc}, fallan {sorted(falladas)}")


def estado_git():
    """Líneas de "git status --short -uall", o None si git no está disponible o falla."""
    try:
        r = ejecutar(["git", "status", "--short", "-uall"], timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.rc != 0:
        return None
    return [l.rstrip() for l in r.out.splitlines() if l.strip()]


def imagenes_propias():
    r = ejecutar(["docker", "image", "ls", "--format", "{{.Repository}}:{{.Tag}}"])
    return [n for n in r.out.split() if n.startswith(PROYECTO)]


def seccion_s(estado_git_arranque):
    p("=== s) limpieza")
    r = ejecutar(["docker", "image", "rm", IMAGEN])
    p(f"docker image rm {IMAGEN} -> codigo {r.rc}")
    restos = imagenes_propias()
    pasa(not restos, f"s) ninguna imagen con prefijo {PROYECTO} {restos if restos else ''}".strip())
    final = estado_git()
    if estado_git_arranque is None or final is None:
        sinc("s) no se pudo comparar el estado de Git (git no disponible, fallo o el directorio no es un repositorio)")
    else:
        iguales = final == estado_git_arranque
        pasa(iguales, "s) la bateria no ha modificado el repo (git status igual al del arranque)")
        if not iguales:
            p(f"   al arrancar: {estado_git_arranque}")
            p(f"   al terminar: {final}")


def terminar():
    if estado["falla"] or estado["sin_conclusion"]:
        resultado = "NO OK (hay FALLA o SIN CONCLUSION)"
    else:
        resultado = "OK"
    p("RESULTADO GLOBAL: " + resultado)
    SALIDA.write_text("\n".join(lineas_salida) + "\n", encoding="utf-8", newline="\n")
    sys.exit(0 if resultado == "OK" else 1)


def terminar_con_parada():
    p("RESULTADO GLOBAL: NO OK (PARADA)")
    SALIDA.write_text("\n".join(lineas_salida) + "\n", encoding="utf-8", newline="\n")
    sys.exit(1)


def main():
    # Estado de Git al arrancar: s) lo compara con el final.
    estado_git_arranque = estado_git()
    # Precondiciones: si fallan, no se limpia nada (podrían ser recursos ajenos).
    if ejecutar(["docker", "info", "--format", "{{.ServerVersion}}"]).rc != 0:
        p("PARADA: docker info falla")
        terminar_con_parada()
    previas = imagenes_propias()
    if previas:
        p(f"PARADA: ya existen imagenes con prefijo {PROYECTO}: {previas}")
        terminar_con_parada()
    temporal = pathlib.Path(tempfile.mkdtemp(prefix=f"{PROYECTO}_"))
    parada = None
    try:
        r = ejecutar(["docker", "build", "-q", "-t", IMAGEN, "."])
        if r.rc != 0:
            raise Parada(f"no se puede construir la imagen de la API: {r.err.strip()[-300:]}")
        seccion_a(temporal)
        base_ok = seccion_b()
        seccion_c(temporal, base_ok)
    except Parada as e:
        parada = str(e)
        p(f"PARADA: {parada}")
    except Exception:  # noqa: BLE001 - error inesperado del propio test: se informa y se limpia
        parada = "error inesperado en el test"
        p("ERROR INESPERADO:\n" + traceback.format_exc())
    finally:
        seccion_s(estado_git_arranque)
        shutil.rmtree(temporal, ignore_errors=True)
    if parada is not None:
        estado["falla"] = True
    terminar()


if __name__ == "__main__":
    main()
