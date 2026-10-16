"""Páginas HTML del denunciante (docs/threat-model.md, 6.1, 6.5 y 6.11).

Adaptador sobre app/denuncias.py, como app/rutas_denuncias.py pero con HTML y
formularios sin JavaScript. Las sirve Caddy en el 8444 (proxy/Caddyfile), que
reescribe /x a /web/x: la persona ve /seguimiento y aquí llega
/web/seguimiento. Mismas reglas que la API JSON: los mismos modelos de
validación, el código siempre en el cuerpo y nunca en la URL, el mismo 404
para una empresa desconocida que para una ruta inexistente y el mismo
contador del limitador (app/limitador.py).

* GET  /web/                         inicio.
* GET  /web/empresas/{identificador} formulario de denuncia de una empresa.
* POST /web/empresas/{identificador}/denuncias  crea la denuncia y muestra el
  código una sola vez.
* GET  /web/seguimiento              formulario del código.
* POST /web/seguimiento/consulta     estado, contenido y mensajes.
* POST /web/seguimiento/mensajes     añade un mensaje del denunciante.

Errores: aquí solo se generan en HTML los que la persona puede corregir (un
texto vacío, un código que no existe, una denuncia cerrada), con el
formulario y lo que escribió. El resto (404, 403, 400, 500...) sale como el
JSON de la API y Caddy lo convierte en la página de error del sitio: del
backend solo deja pasar HTML (lista blanca en proxy/Caddyfile).

Formularios (CSRF, OWASP Cross-Site Request Forgery Prevention Cheat Sheet):
no hay cookies ni sesión, pero una página de otro sitio podría hacer que el
navegador de alguien envíe una denuncia falsa con su IP, o gaste su cupo del
limitador. Cada POST exige la cabecera Origin igual al origen del sitio
(CANARIO_ORIGEN_WEB) y, si llega Sec-Fetch-Site, que sea same-origin. Los
navegadores envían Origin en todo POST (especificación Fetch); con la
Referrer-Policy same-origin del sitio (proxy/Caddyfile) es el origen real y
no "null". Un origen mal configurado se ve en el primer envío: todos se
rechazan. El rechazo no se registra: como un 422 o un 429, es una petición
del cliente, y el camino anónimo no deja líneas (6.5).

El cuerpo se lee de forma estricta, antes de validar nada: solo
application/x-www-form-urlencoded, solo la gramática que genera un navegador
(sin "%" sueltos, que urllib.parse dejaría pasar), UTF-8 válido, exactamente
los campos del formulario y ninguno repetido. Lo que no cumple es un 400: un
navegador nunca lo envía. Los saltos de línea llegan como CRLF porque la
codificación del envío los convierte así (HTML, 4.10.22.6, paso 2.3); se
vuelven a LF para que el texto sea el mismo que escribió la persona y el
mismo que guardaría la API JSON. Es deshacer la codificación, no tocar el
contenido: lo demás se guarda tal cual (app/rutas_denuncias.py).

Plantillas (OWASP Cross Site Scripting Prevention Cheat Sheet): Jinja2 con
autoescape explícito, porque su valor por defecto es False. Ninguna plantilla
marca nada como seguro (|safe, Markup ni autoescape false: lo comprueba
tests/unit/test_web.py), y los saltos de línea se muestran con CSS
(white-space: pre-wrap), no convirtiéndolos en <br>. Se compilan todas al
importar el módulo: una plantilla rota impide arrancar, no da un 500 al
primer visitante.

Límite conocido: recargar la página tras enviar una denuncia la vuelve a
enviar (el navegador avisa antes). No se usa el patrón POST/redirección/GET
porque obligaría a guardar el código para mostrarlo en la página siguiente.
"""
import logging
import os
import pathlib
import re
from typing import Annotated
from urllib.parse import parse_qsl

import jinja2
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import ValidationError

from app import cripto, denuncias
from app.rutas_denuncias import (
    LONGITUD_MAXIMA_TEXTO,
    MENSAJE_CERRADA,
    MENSAJE_CODIGO,
    MENSAJE_LIMITE,
    MENSAJE_SIN_CLAVE,
    ConsultaSeguimiento,
    NuevaDenuncia,
    NuevoMensaje,
)

registro = logging.getLogger("canario.web")

router = APIRouter(prefix="/web")

# ---------------------------------------------------------------------------
# Origen del sitio
# ---------------------------------------------------------------------------
VARIABLE_ORIGEN = "CANARIO_ORIGEN_WEB"
ORIGEN_POR_DEFECTO = "https://localhost:8444"
# Como lo serializa un navegador en la cabecera Origin: https, el host en
# minúsculas y el puerto solo si no es el 443. Sin ruta ni barra final.
_PATRON_ORIGEN = re.compile(r"https://([a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?)(?::([1-9][0-9]{0,4}))?")


class ErrorConfiguracion(Exception):
    """Un origen configurado (CANARIO_ORIGEN_WEB o CANARIO_ORIGEN_PERSONAL)
    no es válido: la API no debe arrancar."""


def analizar_origen(texto, variable):
    """El origen tal cual si tiene la forma exacta que serializa un navegador;
    si no, ErrorConfiguracion con el nombre de la variable. Lo usan los dos
    orígenes de la configuración: este y el de la SPA del personal
    (app/solicitudes.py)."""
    encaje = _PATRON_ORIGEN.fullmatch(texto)
    if not encaje:
        raise ErrorConfiguracion(f"{variable}: se espera https://host o https://host:puerto, en minusculas")
    puerto = encaje.group(2)
    if puerto is not None and (int(puerto) > 65535 or puerto == "443"):
        # El navegador omite el 443: "https://x:443" no coincidiría nunca.
        raise ErrorConfiguracion(f"{variable}: puerto no valido (el 443 se omite)")
    return texto


def cargar_origen(entorno=None):
    """Origen del sitio del denunciante y de dónde sale ("por defecto" o
    "configurado"). Se analiza de forma estricta: un origen que el navegador
    nunca enviaría haría que se rechazaran todos los formularios, y eso debe
    verse al arrancar."""
    entorno = os.environ if entorno is None else entorno
    texto = entorno.get(VARIABLE_ORIGEN)
    if texto is None:
        return ORIGEN_POR_DEFECTO, "por defecto"
    return analizar_origen(texto, VARIABLE_ORIGEN), "configurado"


def origen_aceptado(cabeceras, origen_web):
    """Origin obligatorio e igual al del sitio; Sec-Fetch-Site, si llega,
    same-origin. Las dos las pone el navegador y una página no las puede
    cambiar. same-site no basta: el 8443 de la API es del mismo sitio."""
    if cabeceras.get("origin") != origen_web:
        return False
    sitio = cabeceras.get("sec-fetch-site")
    return sitio is None or sitio == "same-origin"


# ---------------------------------------------------------------------------
# Lectura del formulario
# ---------------------------------------------------------------------------
TIPO_FORMULARIO = "application/x-www-form-urlencoded"
# Lo que genera el serializador urlencoded de un navegador: alfanuméricos,
# "*-._", "+" (espacio), "=" y "&", y el resto como %XX.
_CUERPO_URLENCODED = re.compile(rb"(?:[A-Za-z0-9*._+=&-]|%[0-9A-Fa-f]{2})*")


def leer_formulario(cuerpo, campos):
    """Valores del formulario, o None si el cuerpo no es exactamente un
    formulario de un navegador con esos campos."""
    if not _CUERPO_URLENCODED.fullmatch(cuerpo):
        return None
    try:
        pares = parse_qsl(cuerpo.decode("ascii"), keep_blank_values=True, strict_parsing=True,
                          errors="strict", max_num_fields=len(campos))
    except ValueError:  # incluye UnicodeDecodeError: UTF-8 no válido
        return None
    nombres = [nombre for nombre, _ in pares]
    if sorted(nombres) != sorted(campos):
        return None
    return {nombre: valor.replace("\r\n", "\n") for nombre, valor in pares}


def formulario(*campos):
    """Dependencia de cada POST: primero el origen, después el cuerpo. En
    una sola función para que el orden no dependa de cómo FastAPI ordene sus
    dependencias: un envío de otro sitio se rechaza sin leer ni analizar
    nada."""
    async def dependencia(peticion: Request):
        if not origen_aceptado(peticion.headers, peticion.app.state.origen_web):
            raise HTTPException(403)
        tipo = peticion.headers.get("content-type", "").partition(";")[0].strip().lower()
        if tipo != TIPO_FORMULARIO:
            raise HTTPException(415)
        valores = leer_formulario(await peticion.body(), campos)
        if valores is None:
            raise HTTPException(400)
        return valores
    return dependencia


FormularioDenuncia = Annotated[dict, Depends(formulario("categoria", "texto"))]
FormularioCodigo = Annotated[dict, Depends(formulario("codigo"))]
FormularioMensaje = Annotated[dict, Depends(formulario("codigo", "texto"))]


# ---------------------------------------------------------------------------
# Plantillas
# ---------------------------------------------------------------------------
DIRECTORIO_PLANTILLAS = pathlib.Path(__file__).parent / "plantillas"
entorno_plantillas = jinja2.Environment(
    loader=jinja2.FileSystemLoader(DIRECTORIO_PLANTILLAS),
    # Explícito: el valor por defecto de Jinja2 es False.
    autoescape=True,
    # Una variable que falta es un error, no un texto vacío en la página.
    undefined=jinja2.StrictUndefined,
    # Las plantillas están en la imagen, de solo lectura: no se vuelven a leer.
    auto_reload=False,
)
for _nombre in entorno_plantillas.list_templates():
    entorno_plantillas.get_template(_nombre)

# Textos para la persona. Las claves deben ser exactamente las de
# denuncias.CATEGORIAS y los estados que el denunciante puede ver
# (tests/unit/test_web.py): una categoría o un estado nuevos sin texto hacen
# fallar la prueba, y en ejecución, un KeyError (500), no una página vacía.
CATEGORIAS = {
    "acoso": "Acoso",
    "fraude": "Fraude",
    "corrupcion": "Corrupción",
    "seguridad_laboral": "Seguridad laboral",
    "proteccion_datos": "Protección de datos",
    "medio_ambiente": "Medio ambiente",
    "otros": "Otros",
}
ESTADOS = {
    "nueva": "Recibida",
    "en_instruccion": "En instrucción",
    "resuelta": "Resuelta",
    "archivada": "Archivada",
    "inadmitida": "Inadmitida",
}
AUTORES = {"denunciante": "Usted", "personal": "Personal de la empresa"}

ERROR_TEXTO = (f"Escriba el texto. No puede estar vacío ni superar los {LONGITUD_MAXIMA_TEXTO} "
               "caracteres.")
ERROR_CATEGORIA = "Elija una categoría de la lista."


def pagina(plantilla, codigo_http=200, **datos):
    # codigo_http y no "estado": "estado" es un dato de la plantilla (el de la
    # denuncia) y lo habría capturado este parámetro.
    contenido = entorno_plantillas.get_template(plantilla).render(
        longitud_maxima=LONGITUD_MAXIMA_TEXTO, categorias=CATEGORIAS, **datos)
    return HTMLResponse(contenido, status_code=codigo_http)


def errores_por_campo(error, mensajes):
    """Un mensaje fijo por campo con error: nunca el texto de Pydantic, que
    puede llevar lo que envió la persona."""
    campos = {detalle["loc"][0] for detalle in error.errors() if detalle.get("loc")}
    return {campo: mensajes[campo] for campo in campos if campo in mensajes}


def _expediente(denuncia, codigo):
    # "texto_denuncia" y no "texto": "texto" es el borrador del mensaje.
    return {
        "codigo": codigo,
        "estado": ESTADOS[denuncia.estado],
        "fecha": denuncia.fecha,
        "categoria": CATEGORIAS[denuncia.categoria],
        "texto_denuncia": denuncia.texto,
        "mensajes": [{"fecha": m.fecha, "autor": AUTORES[m.autor], "texto": m.texto} for m in denuncia.mensajes],
    }


# ---------------------------------------------------------------------------
# Rutas. Las que acceden a la base de datos son síncronas (def), como en
# app/rutas_denuncias.py: FastAPI las ejecuta en su pool de hilos. El cuerpo
# lo lee antes la dependencia asíncrona.
# ---------------------------------------------------------------------------
@router.get("/")
def inicio():
    return pagina("inicio.html")


@router.get("/empresas/{identificador}")
def formulario_denuncia(identificador: str, peticion: Request):
    try:
        denuncias.resolver_empresa(peticion.app.state.pool, identificador)
    except denuncias.EmpresaNoEncontrada:
        # El 404 de la API, que Caddy convierte en su página: igual que una
        # ruta que no existe.
        raise HTTPException(404) from None
    return pagina("denuncia.html", identificador=identificador, categoria="", texto="", errores={})


@router.post("/empresas/{identificador}/denuncias")
def crear_denuncia(identificador: str, peticion: Request, valores: FormularioDenuncia):
    estado = peticion.app.state
    repetir = {"identificador": identificador, "categoria": valores["categoria"], "texto": valores["texto"]}
    try:
        datos = NuevaDenuncia.model_validate(valores)
    except ValidationError as error:
        errores = errores_por_campo(error, {"categoria": ERROR_CATEGORIA, "texto": ERROR_TEXTO})
        return pagina("denuncia.html", 422, errores=errores, **repetir)
    try:
        creada = denuncias.crear(estado.pool, estado.claves, identificador, datos.categoria, datos.texto)
    except denuncias.EmpresaNoEncontrada:
        raise HTTPException(404) from None
    except denuncias.EmpresaSinClave:
        registro.error("EVENTO empresa_sin_clave: una empresa activa no tiene clave de cifrado")
        # Con el formulario y el texto: la persona no pierde lo que escribió.
        return pagina("denuncia.html", 503, errores={"general": MENSAJE_SIN_CLAVE}, **repetir)
    except cripto.ErrorIntegridad:
        registro.error("INTEGRIDAD: una clave de empresa no se puede desenvolver")
        raise HTTPException(500) from None
    return pagina("creada.html", 201, codigo=creada.codigo_seguimiento, fecha=creada.fecha)


@router.get("/seguimiento")
def formulario_seguimiento():
    return pagina("seguimiento.html", errores={})


@router.post("/seguimiento/consulta")
def consultar(peticion: Request, valores: FormularioCodigo):
    estado = peticion.app.state
    try:
        codigo = ConsultaSeguimiento.model_validate(valores).codigo
        denuncia = denuncias.consultar(estado.pool, estado.claves, codigo)
    except (ValidationError, denuncias.CodigoNoEncontrado):
        # Mal formado o inexistente: el mismo 404 y el mismo mensaje, como en
        # la API. El código no se repite en la página.
        return pagina("seguimiento.html", 404, errores={"codigo": MENSAJE_CODIGO})
    except cripto.ErrorIntegridad:
        registro.error("INTEGRIDAD: un contenido cifrado no se puede descifrar en su sitio")
        raise HTTPException(500) from None
    return pagina("expediente.html", **_expediente(denuncia, codigo), errores={}, aviso="", texto="")


@router.post("/seguimiento/mensajes")
def enviar_mensaje(peticion: Request, valores: FormularioMensaje):
    estado = peticion.app.state
    codigo = valores["codigo"]

    def expediente(codigo_http, **extra):
        # Se vuelve a leer la denuncia para mostrarla con el resultado. Si el
        # código no vale, la misma respuesta que en la consulta.
        try:
            ConsultaSeguimiento.model_validate({"codigo": codigo})
            denuncia = denuncias.consultar(estado.pool, estado.claves, codigo)
        except (ValidationError, denuncias.CodigoNoEncontrado):
            return pagina("seguimiento.html", 404, errores={"codigo": MENSAJE_CODIGO})
        except cripto.ErrorIntegridad:
            registro.error("INTEGRIDAD: un contenido cifrado no se puede descifrar en su sitio")
            raise HTTPException(500) from None
        datos = {"errores": {}, "aviso": "", "texto": "", **extra}
        return pagina("expediente.html", codigo_http, **_expediente(denuncia, codigo), **datos)

    try:
        datos = NuevoMensaje.model_validate(valores)
    except ValidationError as error:
        errores = errores_por_campo(error, {"texto": ERROR_TEXTO})
        if "texto" not in errores:
            # Solo puede fallar el código: el mismo 404 que la consulta.
            return pagina("seguimiento.html", 404, errores={"codigo": MENSAJE_CODIGO})
        return expediente(422, errores=errores, texto=valores["texto"])
    try:
        denuncias.enviar_mensaje(estado.pool, estado.claves, datos.codigo, datos.texto)
    except denuncias.CodigoNoEncontrado:
        return pagina("seguimiento.html", 404, errores={"codigo": MENSAJE_CODIGO})
    except denuncias.DenunciaCerrada:
        return expediente(409, errores={"general": MENSAJE_CERRADA}, texto=datos.texto)
    except denuncias.LimiteMensajes:
        return expediente(409, errores={"general": MENSAJE_LIMITE}, texto=datos.texto)
    except denuncias.EmpresaSinClave:
        registro.error("EVENTO empresa_sin_clave: una empresa activa no tiene clave de cifrado")
        return expediente(503, errores={"general": MENSAJE_SIN_CLAVE}, texto=datos.texto)
    except cripto.ErrorIntegridad:
        registro.error("INTEGRIDAD: una clave de empresa no se puede desenvolver")
        raise HTTPException(500) from None
    return expediente(201, aviso="Mensaje enviado.")
