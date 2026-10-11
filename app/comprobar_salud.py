"""Healthcheck del contenedor de la API, sin curl.

Sale con 0 solo si GET /salud responde 200 con el cuerpo exacto esperado.
Cualquier otra cosa (otro código, otro cuerpo, conexión rechazada o tiempo
agotado) sale con 1. Un 200 con un cuerpo distinto no basta: podría ser otro
proceso escuchando en el puerto.

Uso: python -m app.comprobar_salud [host] [puerto]
"""
import http.client
import sys

HOST_POR_DEFECTO = "127.0.0.1"
PUERTO_POR_DEFECTO = 8000
CUERPO_ESPERADO = b'{"estado":"ok"}'


def main(argv):
    host = argv[1] if len(argv) > 1 else HOST_POR_DEFECTO
    puerto = int(argv[2]) if len(argv) > 2 else PUERTO_POR_DEFECTO
    conexion = http.client.HTTPConnection(host, puerto, timeout=3)
    try:
        conexion.request("GET", "/salud")
        respuesta = conexion.getresponse()
        # Se lee un byte más de lo esperado para detectar cuerpos más largos.
        cuerpo = respuesta.read(len(CUERPO_ESPERADO) + 1)
    except (OSError, http.client.HTTPException) as error:
        # El fallo queda visible en el historial del healthcheck.
        print(f"no sano: {type(error).__name__}", file=sys.stderr)
        return 1
    finally:
        conexion.close()
    if respuesta.status == 200 and cuerpo == CUERPO_ESPERADO:
        return 0
    print(f"no sano: codigo {respuesta.status}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
