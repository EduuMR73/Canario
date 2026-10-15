"""Limitador de peticiones por cliente con Redis (docs/threat-model.md, 6.8 y 6.9).

Qué hace:

* Cada petición, salvo GET /salud, consume una unidad del contador de su
  regla para su cliente: denuncia, seguimiento, mensajes, acceso (login,
  activación y cambio de contraseña del personal) u otras. Lo que no
  tiene regla propia cae en "otras": una ruta nueva queda limitada sin que
  nadie tenga que acordarse (cerrado por construcción).
* Ventana fija: el número de ventana va dentro de la clave, y INCR y
  EXPIRE NX van en un MULTI/EXEC, que Redis ejecuta entero o no ejecuta. Una
  clave sin TTL no bloquearía a nadie (la ventana siguiente usa otra clave),
  solo ocuparía memoria; aun así, EXPIRE NX se lo pone en cuanto llega la
  siguiente petición. Defecto conocido: en la frontera entre dos ventanas se
  admite hasta el doble del límite.
* El cliente nunca llega a Redis: la clave lleva un HMAC-SHA256 de su
  dirección con una sal aleatoria que solo vive en la memoria de este
  proceso. Sin la sal, un volcado de Redis no permite recorrer las 2^32
  direcciones IPv4 para encontrar la de una clave. La sal cambia cada día a
  las 00:00 UTC. Las ventanas dividen el día, así que el cambio cae siempre
  en una frontera de ventana y nunca parte un contador. IPv6 se agrupa por
  /64, porque un cliente con un /64 tendría 2^64 direcciones. Una IPv4
  escrita como IPv6 (::ffff:a.b.c.d) cuenta como la IPv4.
* Falla cerrado: si Redis no responde (200 ms de plazo para conectar y para
  cada respuesta; solo se reintenta una vez un error de conexión, para
  sustituir una conexión muerta), no hay conexión libre o devuelve un
  error (por ejemplo, sin memoria con noeviction), la respuesta es 503 con
  Retry-After y un evento sin IP. No existe ningún camino que se salte el
  limitador.
* 429 con Retry-After (los segundos hasta el fin de la ventana) cuando se
  supera el límite. No se registra: un 429 es flujo normal del camino
  anónimo, y una línea con hora situaría la petición (6.5).
* Segunda capa, por cuenta (OWASP API4:2023, consumo de recursos sin
  restricción): las rutas con sesión del personal consumen además la regla
  "cuenta" con la identidad autenticada, después de autenticar
  (app/rutas_personal.py, la única forma de obtener una sesión). Frena a una
  cuenta concreta aunque reparta sus peticiones entre varias IPs o sesiones.
  La clave lleva un HMAC de empresa y cuenta con la misma sal del día y su
  propia etiqueta. Esta capa no puede ir en el middleware: ahí todavía no se
  sabe de quién es la petición.

Configuración: los límites de producción son los literales de
LIMITES_POR_DEFECTO. La variable de entorno CANARIO_LIMITES los sustituye
enteros (por ejemplo, para que una batería de pruebas funcionales no choque
con ellos). Se analiza de forma estricta y, si no es válida, la API no
arranca. Los límites efectivos y su origen quedan en el log al arrancar:
un límite relajado en producción es visible, nunca silencioso.

La contraseña del usuario de Redis se lee del Docker secret al abrir cada
conexión, igual que la de PostgreSQL (app/bd.py): una rotación no exige
reconstruir la imagen.
"""
import asyncio
import hashlib
import hmac
import ipaddress
import logging
import os
import pathlib
import re
import secrets
import time
from dataclasses import dataclass

from redis.asyncio import BlockingConnectionPool, Redis
from redis.asyncio.retry import Retry
from redis.backoff import NoBackoff
from redis.credentials import CredentialProvider
from redis.exceptions import AuthenticationError, NoPermissionError, RedisError
from redis.exceptions import ConnectionError as ErrorConexion

from app.frontera_http import REINTENTAR_TRAS, responder

registro = logging.getLogger("canario.limitador")

HOST = "redis"
PUERTO = 6379
USUARIO = "aplicacion"
FICHERO_CONTRASENA = pathlib.Path("/run/secrets/contrasena_redis")
# El formato exacto que genera scripts/generar_secretos.py
# (secrets.token_urlsafe(48)): un secreto distinto es un error de
# configuración y no se corrige en silencio.
PATRON_CONTRASENA = re.compile(r"[A-Za-z0-9_-]{64}")

# Plazos en segundos. Dentro de la red interna, Redis responde en menos de
# un milisegundo: 200 ms solo se agotan si algo va mal, y un Redis lento no
# retiene las peticiones (comprobado con el contenedor en pausa: el plazo
# corta a los 0,2 s).
PLAZO = 0.2
# Conexiones simultáneas con Redis. Si no queda ninguna libre en PLAZO, la
# petición falla cerrada como si Redis no respondiera.
CONEXIONES_MAXIMAS = 20
# Al arrancar se espera a Redis como a PostgreSQL (app/principal.py).
ESPERA_ARRANQUE_SEGUNDOS = 15

SEGUNDOS_DIA = 86_400
ETIQUETA_CLIENTE = b"canario/limite/v1"
ETIQUETA_CUENTA = b"canario/limite/cuenta/v1"

VARIABLE_LIMITES = "CANARIO_LIMITES"
# Topes de lo que admite CANARIO_LIMITES: un valor fuera de ellos es un error
# de configuración, no un límite.
LIMITE_MAXIMO = 1_000_000


@dataclass(frozen=True)
class Limite:
    peticiones: int
    ventana: int  # segundos; divide SEGUNDOS_DIA

    def __str__(self):
        return f"{self.peticiones}/{self.ventana}"


# Límites de producción, por cliente. Moderados a propósito: muchos usuarios
# de Tor salen por el mismo nodo y comparten IP (docs/threat-model.md, 8).
# "seguimiento" cuenta también los códigos inexistentes; con 160 bits la
# enumeración ya es inviable, el límite protege la capacidad.
# "acceso" (login, activación y cambio de contraseña del personal) es la
# primera capa contra el relleno de credenciales y protege la capacidad de
# Argon2. No es la única: el bloqueo por cuenta y por dispositivo vive en
# PostgreSQL (app/personal.py) y sigue frenando a quien cambia de IP.
# La renovación de la sesión (/v1/personal/sesiones/renovacion) va a
# propósito en "otras": no calcula Argon2 y su token tiene 256 bits, así que
# no hay nada que adivinar. En "acceso", el personal de una oficina que sale
# por la misma IP (una renovación cada 5 minutos por persona) agotaría el
# límite entre todos.
# "cuenta" no es una regla de ruta: es la segunda capa de las rutas con
# sesión, por identidad. Una persona no sostiene más de una petición por
# segundo; un frontend que haga varias llamadas por pantalla sigue holgado.
LIMITES_POR_DEFECTO = {
    "denuncia": Limite(10, 3600),
    "seguimiento": Limite(60, 60),
    "mensajes": Limite(30, 3600),
    "acceso": Limite(10, 300),
    "otras": Limite(60, 60),
    "cuenta": Limite(60, 60),
}

RUTAS_ACCESO = {"/v1/personal/sesiones", "/v1/personal/activacion", "/v1/personal/activacion/confirmar",
                "/v1/personal/contrasena"}
# El denunciante tiene dos entradas a las mismas acciones: la API JSON (/v1) y
# los formularios del sitio (/web, app/rutas_web.py). Cada acción tiene la
# misma regla por las dos, y la regla es la clave del contador, así que
# comparten contador: entrar por la otra puerta no da más intentos. Las
# páginas que solo muestran un formulario (GET) van en "otras": leer el
# formulario no gasta el cupo de denuncias.
RUTAS_SEGUIMIENTO = {"/v1/seguimiento", "/web/seguimiento/consulta"}
RUTAS_MENSAJES = {"/v1/seguimiento/mensajes", "/web/seguimiento/mensajes"}

# Rutas exentas: solo la vivacidad, que usa el healthcheck desde dentro del
# contenedor y no toca ninguna dependencia.
EXENTAS = {"/salud"}
_RUTA_DENUNCIAS = re.compile(r"/(?:v1|web)/empresas/[^/]+/denuncias")
_ELEMENTO_LIMITES = re.compile(r"([a-z]+)=([1-9][0-9]{0,6})/([1-9][0-9]{0,5})")


class ErrorConfiguracion(Exception):
    """La configuración del limitador no es válida: la API no debe arrancar."""


class NoDisponible(Exception):
    """Redis no ha podido contar la petición: se rechaza (falla cerrado)."""

    def __init__(self, clase):
        super().__init__(clase)
        self.clase = clase


def regla_de(ruta):
    """Regla que limita una ruta, o None si está exenta.

    La ruta es la de scope["path"], ya decodificada: un "%2F" es una barra y
    no casa con un solo segmento, igual que en el enrutado de Starlette.
    """
    if ruta in EXENTAS:
        return None
    if ruta in RUTAS_SEGUIMIENTO:
        return "seguimiento"
    if ruta in RUTAS_MENSAJES:
        return "mensajes"
    if ruta in RUTAS_ACCESO:
        return "acceso"
    if _RUTA_DENUNCIAS.fullmatch(ruta):
        return "denuncia"
    return "otras"


def cargar_limites(entorno=None):
    """Límites efectivos y su origen ("por defecto" o "configurados").

    CANARIO_LIMITES tiene la forma "denuncia=10/3600,mensajes=30/3600,..."
    y debe traer exactamente las mismas reglas que LIMITES_POR_DEFECTO, sin
    repetir ninguna. Cada ventana debe dividir el día, para que el cambio
    diario de la sal no parta ningún contador.
    """
    entorno = os.environ if entorno is None else entorno
    texto = entorno.get(VARIABLE_LIMITES)
    if texto is None:
        return dict(LIMITES_POR_DEFECTO), "por defecto"
    limites = {}
    for elemento in texto.split(","):
        encaje = _ELEMENTO_LIMITES.fullmatch(elemento)
        if not encaje:
            raise ErrorConfiguracion(f"{VARIABLE_LIMITES}: elemento mal formado")
        nombre, peticiones, ventana = encaje.group(1), int(encaje.group(2)), int(encaje.group(3))
        if nombre in limites:
            raise ErrorConfiguracion(f"{VARIABLE_LIMITES}: la regla {nombre} se repite")
        if peticiones > LIMITE_MAXIMO:
            raise ErrorConfiguracion(f"{VARIABLE_LIMITES}: {nombre} supera {LIMITE_MAXIMO} peticiones")
        if ventana > SEGUNDOS_DIA or SEGUNDOS_DIA % ventana:
            raise ErrorConfiguracion(f"{VARIABLE_LIMITES}: la ventana de {nombre} no divide el dia")
        limites[nombre] = Limite(peticiones, ventana)
    if set(limites) != set(LIMITES_POR_DEFECTO):
        raise ErrorConfiguracion(
            f"{VARIABLE_LIMITES}: reglas {sorted(limites)}, se esperan {sorted(LIMITES_POR_DEFECTO)}")
    return limites, "configurados"


def describir_limites(limites):
    return " ".join(f"{nombre}={limites[nombre]}" for nombre in sorted(limites))


def leer_contrasena():
    """Contraseña de Redis. El motivo del error nunca incluye su valor."""
    try:
        contrasena = FICHERO_CONTRASENA.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError) as error:
        raise ErrorConfiguracion(f"no se puede leer el secreto de Redis ({type(error).__name__})") from None
    if not PATRON_CONTRASENA.fullmatch(contrasena):
        raise ErrorConfiguracion("el secreto de Redis tiene un formato inesperado")
    return contrasena


class _Credenciales(CredentialProvider):
    """Usuario y contraseña al abrir cada conexión, leídos del secreto."""

    def get_credentials(self):
        return USUARIO, leer_contrasena()

    async def get_credentials_async(self):
        return self.get_credentials()


def _bytes_cliente(direccion):
    """Bytes que identifican al cliente: la IPv4 entera o el /64 de una IPv6."""
    ip = ipaddress.ip_address(direccion)
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.version == 4:
        return b"\x04" + ip.packed
    return b"\x06" + ip.packed[:8]


def huella_cliente(sal, direccion):
    """HMAC-SHA256 del cliente con la sal, truncado a 128 bits en hexadecimal.

    Lanza ValueError si la dirección no es una IP.
    """
    return hmac.new(sal, ETIQUETA_CLIENTE + _bytes_cliente(direccion), hashlib.sha256).hexdigest()[:32]


def huella_cuenta(sal, empresa_id, usuario_id):
    """HMAC-SHA256 de una cuenta del personal con la sal, truncado a 128 bits.
    Etiqueta propia: una cuenta y un cliente nunca comparten huella."""
    return hmac.new(sal, ETIQUETA_CUENTA + empresa_id.bytes + usuario_id.bytes, hashlib.sha256).hexdigest()[:32]


class _Sal:
    """Sal aleatoria del día (UTC). Solo existe en la memoria del proceso."""

    def __init__(self):
        self._dia = None
        self._valor = b""

    def del_instante(self, instante):
        dia = int(instante) // SEGUNDOS_DIA
        if dia != self._dia:
            # La anterior se descarta: las claves que firmó caducan con su
            # ventana y ya nadie puede asociarlas a un cliente.
            self._dia, self._valor = dia, secrets.token_bytes(32)
        return self._valor


def _opciones_conexion():
    # redis-py reintenta por defecto varias veces, con espera exponencial,
    # ante errores de conexión y plazos agotados. Aquí, un solo reintento,
    # inmediato y solo ante un error de conexión: tras reiniciarse Redis,
    # las conexiones del pool están muertas y el reintento abre una nueva en
    # vez de devolver un 503 por cada una. Un plazo agotado (TimeoutError,
    # que en redis-py no es un ConnectionError) no se reintenta: Redis está
    # lento y la petición se rechaza en PLAZO. Si al reintentar se cuenta dos
    # veces (EXEC ejecutado y respuesta perdida), el límite es más estricto,
    # nunca más laxo.
    return {"host": HOST, "port": PUERTO, "socket_timeout": PLAZO, "socket_connect_timeout": PLAZO,
            "retry": Retry(NoBackoff(), 1, (ErrorConexion,))}


class Limitador:
    def __init__(self, limites):
        self.limites = limites
        self._sal = _Sal()
        self._cliente = Redis(connection_pool=BlockingConnectionPool(
            max_connections=CONEXIONES_MAXIMAS, timeout=PLAZO, credential_provider=_Credenciales(),
            **_opciones_conexion()))

    async def cerrar(self):
        await self._cliente.aclose()

    async def consumir(self, regla, direccion, instante=None):
        """Cuenta una petición. Devuelve (permitida, segundos hasta el fin de la ventana).

        Lanza NoDisponible si Redis no la ha contado y ValueError si la
        dirección no es una IP.
        """
        instante = time.time() if instante is None else instante
        huella = huella_cliente(self._sal.del_instante(instante), direccion)
        cuenta, limite, segundos = await self._contar(regla, huella, instante)
        return cuenta <= limite.peticiones, segundos

    async def consumir_cuenta(self, empresa_id, usuario_id, instante=None):
        """Cuenta una petición de una cuenta autenticada en la regla "cuenta".
        Devuelve (permitida, segundos hasta el fin de la ventana, primer
        exceso de la ventana). Lanza NoDisponible si Redis no la ha contado."""
        instante = time.time() if instante is None else instante
        huella = huella_cuenta(self._sal.del_instante(instante), empresa_id, usuario_id)
        cuenta, limite, segundos = await self._contar("cuenta", huella, instante)
        return cuenta <= limite.peticiones, segundos, cuenta == limite.peticiones + 1

    async def _contar(self, regla, huella, instante):
        limite = self.limites[regla]
        segundo = int(instante)
        clave = f"limite:{regla}:{segundo // limite.ventana}:{huella}"
        try:
            # Los comandos se envían por su nombre exacto: Redis.incr() envía
            # INCRBY, que la ACL no permite (comprobado con redis-py 8.1.0).
            async with self._cliente.pipeline(transaction=True) as tubo:
                tubo.execute_command("INCR", clave)
                tubo.execute_command("EXPIRE", clave, limite.ventana, "NX")
                cuenta, _ = await tubo.execute()
        except (RedisError, OSError) as error:
            raise NoDisponible(type(error).__name__) from None
        return cuenta, limite, limite.ventana - segundo % limite.ventana

    async def verificar(self):
        """Comprueba Redis al arrancar. Devuelve la lista de fallos (sin secretos).

        Literales, no derivados de Redis: el usuario default no responde sin
        autenticar, aplicacion puede contar en limite:* y no puede hacer nada
        más (una ACL permisiva no debe pasar desapercibida).
        """
        fallos = []
        limite = time.monotonic() + ESPERA_ARRANQUE_SEGUNDOS
        while True:
            try:
                await self._cliente.execute_command("PING")
                break
            except (RedisError, OSError) as error:
                if time.monotonic() >= limite:
                    return [f"sin conexion con Redis en {ESPERA_ARRANQUE_SEGUNDOS} s ({type(error).__name__})"]
                await asyncio.sleep(0.5)

        anonimo = Redis(**_opciones_conexion())
        try:
            await anonimo.execute_command("PING")
            fallos.append("Redis responde sin autenticar (usuario default activo)")
        except AuthenticationError:
            pass
        except (RedisError, OSError) as error:
            fallos.append(f"sin autenticar se esperaba AuthenticationError ({type(error).__name__})")
        finally:
            await anonimo.aclose()

        clave = f"limite:arranque:{secrets.token_hex(8)}"
        try:
            async with self._cliente.pipeline(transaction=True) as tubo:
                tubo.execute_command("INCR", clave)
                tubo.execute_command("EXPIRE", clave, 60, "NX")
                resultado = await tubo.execute()
            if resultado != [1, True]:
                fallos.append(f"INCR y EXPIRE NX devuelven {resultado}")
        except (RedisError, OSError) as error:
            fallos.append(f"no se puede contar en limite:* ({type(error).__name__})")

        # Sin efectos aunque la ACL los permitiera: solo leen.
        for orden in (("GET", clave), ("SCAN", 0), ("CONFIG", "GET", "dir"), ("TTL", "fuera:arranque")):
            try:
                await self._cliente.execute_command(*orden)
                fallos.append(f"la ACL permite {orden[0]}" + (" fuera de limite:*" if orden[0] == "TTL" else ""))
            except NoPermissionError:
                pass
            except (RedisError, OSError) as error:
                fallos.append(f"{orden[0]}: se esperaba NoPermissionError ({type(error).__name__})")
        return fallos


class FronteraLimitador:
    """Middleware ASGI. Va por dentro de ErroresInternos y por fuera de
    LimiteCuerpo (app/frontera_http.py): rechaza antes de leer el cuerpo y
    antes de validar, así que también cuentan los cuerpos inválidos.

    Usa el Limitador de app.state, que crea el arranque (app/principal.py).
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        regla = regla_de(scope["path"])
        if regla is None:
            await self.app(scope, receive, send)
            return
        cliente = scope.get("client")
        try:
            if not cliente:
                raise ValueError("sin cliente")
            permitida, segundos = await scope["app"].state.limitador.consumir(regla, cliente[0])
        except NoDisponible as error:
            registro.error("EVENTO limitador_no_disponible: %s", error.clase)
            await responder(send, 503, [(b"retry-after", REINTENTAR_TRAS.encode("ascii"))])
            return
        except ValueError:
            # uvicorn siempre da la dirección del socket o la del proxy de
            # confianza; si no es una IP, se rechaza sin registrar su valor.
            registro.error("EVENTO limitador_cliente_invalido")
            await responder(send, 503, [(b"retry-after", REINTENTAR_TRAS.encode("ascii"))])
            return
        if not permitida:
            await responder(send, 429, [(b"retry-after", str(segundos).encode("ascii"))])
            return
        await self.app(scope, receive, send)
