"""Gestión de Canario: alta de empresas, claves de cifrado y supresión legal.

Operación de administración, fuera de la API pública: corre en el servicio
gestion de docker-compose.yml (perfil propio, solo en la red data), nunca en
el contenedor de la API, que no tiene ni el secreto de plataforma ni forma de
dar de alta empresas ni de borrar nada.

Uso (PowerShell, desde la raíz del repositorio, con postgres en marcha):

    docker compose run --rm gestion alta-empresa --nombre "Empresa S.L." --zona Europe/Madrid
    docker compose run --rm gestion nueva-clave --empresa-id <uuid>
    docker compose run --rm gestion suprimir-caducadas

suprimir-caducadas aplica los arts. 32.4 y 26.2 de la Ley 2/2023 con
canal.suprimir_denuncias_caducadas() (db/init/04_supresion.sql), el único
camino de borrado. Hay que ejecutarla periódicamente (por ejemplo, cada día).
Repite lotes, cada uno en su transacción, hasta que uno vuelve vacío. Las
denuncias que estaban en uso se saltan: al terminar se cuentan las que siguen
cumpliendo el criterio y, si queda alguna, la orden lo dice y sale con código
1, para que una ejecución programada no lo pase por alto. No verifica la base
de datos como el arranque de la API: esas comprobaciones son las del rol
aplicacion, y plataforma solo puede ejecutar la función, cuyo criterio está
fijo en la base de datos.

La zona horaria es obligatoria: fija el calendario con el que se fechan las
denuncias de la empresa (docs/threat-model.md, 6.5).

alta-empresa hace dos pasos con dos roles distintos, a propósito:
1. Con plataforma, canal.alta_empresa(): empresa y entrada del directorio.
   plataforma no puede tocar claves ni denuncias.
2. Con aplicacion y el contexto de la empresa nueva: genera su clave de
   datos, la envuelve con la clave maestra y la guarda como versión 1.

Son dos sesiones, así que no hay una transacción común. Si el paso 2 falla, la
empresa queda sin clave: no acepta denuncias (la API responde 503 y lo
registra) y el mensaje de error indica el comando exacto para completarla
(nueva-clave). nueva-clave sirve también para rotar: crea la versión
siguiente sin tocar las anteriores.

Antes de escribir una clave:
* Se verifica la base de datos con las mismas comprobaciones literales que el
  arranque de la API (app/verificacion_arranque.py). Una clave no se guarda en
  una base de datos que no es la esperada.
* Se desenvuelven todas las claves anteriores de la empresa con la clave
  maestra montada. Si alguna falla (otra clave maestra, o una clave alterada),
  se aborta: una clave nueva envuelta con otra maestra dejaría a la empresa
  con claves que no se pueden usar juntas.

Límite asumido: en el alta no hay claves anteriores con las que contrastar la
clave maestra. Si la del servicio gestion fuera distinta de la de la API (los
dos montan el mismo fichero de secrets/, así que exige un error manual), la
empresa nueva tendría una clave que la API no puede desenvolver. No pasa en
silencio: la primera denuncia falla con un evento de integridad visible.

Nunca imprime claves, envueltas o no. Solo identificadores y versiones.
"""
import argparse
import sys
import uuid

import psycopg

from app import bd, claves, cripto, verificacion_arranque

SQL_ALTA = "select empresa_id, identificador_publico from canal.alta_empresa(%s, %s)"
# Misma lista que el CHECK de canal.empresa.zona_horaria. La autoridad es la
# base de datos; esta copia solo da un error claro antes de conectar.
ZONAS_HORARIAS = ("Europe/Madrid", "Atlantic/Canary", "Africa/Ceuta")
SQL_EMPRESA_VISIBLE = "select count(*) from canal.empresa"
SQL_CLAVES = "select version, clave_envuelta from canal.clave_empresa order by version"
SQL_INSERTAR_CLAVE = (
    "insert into canal.clave_empresa (empresa_id, version, clave_envuelta) values (%s, %s, %s)"
)
SQL_SUPRIMIR = "select empresa_id, articulo, suprimidas from canal.suprimir_denuncias_caducadas(%s)"
SQL_CONTAR_CADUCADAS = "select canal.contar_denuncias_caducadas()"
# Mismo intervalo que acepta la función (1 a 500). Un lote pequeño retiene
# pocos bloqueos y cabe de sobra en el statement_timeout de la sesión.
LOTE_POR_DEFECTO = 100


class ErrorGestion(Exception):
    """Fallo de una operación de gestión, con un motivo sin datos sensibles."""


def _verificar_base_datos(conexion):
    """Mismas comprobaciones que el arranque de la API, en solo lectura."""
    with conexion.transaction():
        conexion.execute("set transaction read only")
        fallos = verificacion_arranque.comprobar(conexion)
    if fallos:
        detalle = "; ".join(f"{identificador}: {texto}" for identificador, texto in fallos)
        raise ErrorGestion(f"la base de datos no es la esperada ({detalle})")


def nueva_clave(empresa_id, maestra):
    """Crea la versión siguiente de la clave de la empresa. Devuelve la versión."""
    with bd.conectar("aplicacion", bd.FICHERO_CONTRASENA) as conexion:
        _verificar_base_datos(conexion)
        with conexion.transaction():
            bd.fijar_contexto(conexion, empresa_id)
            # Con RLS, la tabla empresa solo muestra la del contexto: 0 filas
            # si no existe o el id es de otra cosa.
            if conexion.execute(SQL_EMPRESA_VISIBLE).fetchone()[0] != 1:
                raise ErrorGestion("la empresa no existe")
            anteriores = conexion.execute(SQL_CLAVES).fetchall()
            for version, envuelta in anteriores:
                try:
                    cripto.desenvolver_clave(maestra, bytes(envuelta), empresa_id, version)
                except cripto.ErrorIntegridad:
                    raise ErrorGestion(
                        f"la clave maestra montada no desenvuelve la version {version} de esta "
                        "empresa (o la clave maestra no es la que la envolvio, o la clave "
                        "guardada esta alterada): no se crea ninguna clave nueva"
                    ) from None
            version = (anteriores[-1][0] if anteriores else 0) + 1
            envuelta = cripto.envolver_clave(maestra, cripto.nueva_clave_empresa(), empresa_id, version)
            # Dos ejecuciones simultáneas calcularían la misma versión: la
            # clave primaria (empresa_id, version) rechaza la segunda.
            conexion.execute(SQL_INSERTAR_CLAVE, [empresa_id, version, envuelta])
    return version


def alta_empresa(nombre, zona_horaria, maestra):
    with (bd.conectar("plataforma", bd.FICHERO_CONTRASENA_PLATAFORMA) as conexion,
          conexion.transaction()):
        empresa_id, identificador = conexion.execute(SQL_ALTA, [nombre, zona_horaria]).fetchone()
    print(f"empresa creada: empresa_id={empresa_id} identificador_publico={identificador}")
    try:
        version = nueva_clave(empresa_id, maestra)
    except (ErrorGestion, psycopg.Error, bd.ErrorConfiguracion) as error:
        raise ErrorGestion(
            f"la empresa {empresa_id} se ha creado pero NO tiene clave ({_motivo(error)}). "
            f"No acepta denuncias hasta completar: nueva-clave --empresa-id {empresa_id}"
        ) from None
    print(f"clave creada: empresa_id={empresa_id} version={version}")


def suprimir_caducadas(lote):
    """Suprime las denuncias caducadas por lotes. Devuelve (totales, pendientes).

    totales: {(empresa_id, articulo): suprimidas}. pendientes: las que siguen
    cumpliendo el criterio al terminar (estaban en uso y se saltaron).
    """
    totales = {}
    with bd.conectar("plataforma", bd.FICHERO_CONTRASENA_PLATAFORMA) as conexion:
        while True:
            # Una transacción por lote, en READ COMMITTED (el nivel por defecto,
            # que la función exige): los bloqueos de un lote se liberan antes
            # del siguiente.
            with conexion.transaction():
                filas = conexion.execute(SQL_SUPRIMIR, [lote]).fetchall()
            if not filas:
                break
            for empresa_id, articulo, suprimidas in filas:
                totales[(empresa_id, articulo)] = totales.get((empresa_id, articulo), 0) + suprimidas
        with conexion.transaction():
            # El recuento solo lee: en solo lectura no puede escribir nada.
            conexion.execute(bd.SQL_SOLO_LECTURA)
            pendientes = conexion.execute(SQL_CONTAR_CADUCADAS).fetchone()[0]
    return totales, pendientes


def _motivo(error):
    # Los errores de psycopg se resumen en su clase y su SQLSTATE: su texto
    # puede incluir valores de la fila (por ejemplo en DETAIL).
    if isinstance(error, psycopg.Error):
        return f"{type(error).__name__} {error.sqlstate or ''}".strip()
    return str(error)


def _uuid(texto):
    try:
        return uuid.UUID(texto)
    except ValueError:
        raise argparse.ArgumentTypeError("no es un uuid") from None


def construir_parser():
    parser = argparse.ArgumentParser(prog="gestion", description="Gestion de empresas de Canario.")
    ordenes = parser.add_subparsers(dest="orden", required=True)
    alta = ordenes.add_parser("alta-empresa", help="da de alta una empresa con su clave version 1")
    alta.add_argument("--nombre", required=True)
    alta.add_argument("--zona", required=True, choices=ZONAS_HORARIAS,
                      help="zona horaria de la empresa: fija el calendario de sus fechas")
    clave = ordenes.add_parser("nueva-clave", help="crea la version siguiente de la clave de una empresa")
    clave.add_argument("--empresa-id", required=True, type=_uuid)
    supresion = ordenes.add_parser(
        "suprimir-caducadas",
        help="suprime las denuncias caducadas (arts. 32.4 y 26.2 de la Ley 2/2023)")
    supresion.add_argument("--lote", type=_lote, default=LOTE_POR_DEFECTO,
                           help="denuncias por transaccion, de 1 a 500")
    return parser


def _lote(texto):
    try:
        valor = int(texto)
    except ValueError:
        raise argparse.ArgumentTypeError("no es un entero") from None
    if not 1 <= valor <= 500:
        raise argparse.ArgumentTypeError("debe estar entre 1 y 500")
    return valor


def _informar_supresion(totales, pendientes):
    """Imprime solo recuentos por empresa y artículo. Devuelve el código de salida."""
    for (empresa_id, articulo), suprimidas in sorted(totales.items(), key=lambda e: (str(e[0][0]), e[0][1])):
        print(f"suprimidas: empresa_id={empresa_id} articulo={articulo} denuncias={suprimidas}")
    print(f"total suprimidas: {sum(totales.values())}")
    if pendientes:
        print(f"AVISO: quedan {pendientes} denuncias caducadas que estaban en uso; "
              "vuelva a ejecutar suprimir-caducadas", file=sys.stderr)
        return 1
    return 0


def main(argv=None):
    args = construir_parser().parse_args(argv)
    try:
        # La supresión no toca claves: no necesita cargar la clave maestra.
        if args.orden == "suprimir-caducadas":
            return _informar_supresion(*suprimir_caducadas(args.lote))
        maestra = claves.cargar_maestra()
        if args.orden == "alta-empresa":
            alta_empresa(args.nombre, args.zona, maestra)
        else:
            version = nueva_clave(args.empresa_id, maestra)
            print(f"clave creada: empresa_id={args.empresa_id} version={version}")
    except (ErrorGestion, claves.ErrorClaves, bd.ErrorConfiguracion) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    except psycopg.Error as error:
        print(f"ERROR: base de datos: {_motivo(error)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
