"""Pruebas unitarias de la lógica pura de app/denuncias.py: el formato exacto
del contenido cifrado y el descifrado de un expediente con varias versiones
de clave.

El expediente se construye con app/cripto.py, cifrando cada pieza con su
AAD: así se comprueba que una fila movida o con el autor cambiado no se
descifra, sin base de datos.
"""
import datetime
import types
import unittest
import uuid

from app import cripto, denuncias

MAESTRA = bytes(range(32))
EMPRESA = uuid.UUID(int=1)
DENUNCIA = uuid.UUID(int=2)
PERSONA = uuid.UUID(int=7)
FECHA = datetime.date(2026, 10, 13)


class Serializar(unittest.TestCase):
    def test_forma_exacta(self):
        self.assertEqual(denuncias.serializar(texto="a", categoria="acoso"),
                         b'{"categoria":"acoso","texto":"a","v":1}')
        # UTF-8 sin escapar: la eñe son sus dos bytes UTF-8, no un escape JSON de seis caracteres.
        self.assertEqual(denuncias.serializar(texto="ñ"), b'{"texto":"\xc3\xb1","v":1}')

    def test_ida_y_vuelta(self):
        datos = denuncias.serializar(categoria="fraude", texto="línea 1\nlínea 2")
        self.assertEqual(denuncias.deserializar(datos, ("categoria", "texto")),
                         {"v": 1, "categoria": "fraude", "texto": "línea 1\nlínea 2"})


class Deserializar(unittest.TestCase):
    CAMPOS = ("texto",)

    def test_control_valido(self):
        self.assertEqual(denuncias.deserializar(b'{"texto":"x","v":1}', self.CAMPOS), {"texto": "x", "v": 1})

    def test_formato_invalido(self):
        for datos in (b"\xff", b"{", b""):
            with self.subTest(datos=datos):
                with self.assertRaises(cripto.ErrorIntegridad) as error:
                    denuncias.deserializar(datos, self.CAMPOS)
                self.assertEqual(str(error.exception), "contenido descifrado con formato invalido")

    def test_formato_desconocido(self):
        casos = {
            "lista": b'["x"]',
            "null": b"null",
            "falta v": b'{"texto":"x"}',
            "sobra un campo": b'{"texto":"x","v":1,"otro":"y"}',
            "falta texto": b'{"v":1}',
            "version 2": b'{"texto":"x","v":2}',
            "texto no str": b'{"texto":5,"v":1}',
            "texto null": b'{"texto":null,"v":1}',
            # True == 1 y 1.0 == 1 en Python: la versión debe ser el entero exacto.
            "v true": b'{"texto":"x","v":true}',
            "v 1.0": b'{"texto":"x","v":1.0}',
            "v texto": b'{"texto":"x","v":"1"}',
        }
        for motivo, datos in casos.items():
            with self.subTest(motivo=motivo):
                with self.assertRaises(cripto.ErrorIntegridad) as error:
                    denuncias.deserializar(datos, self.CAMPOS)
                self.assertEqual(str(error.exception), "contenido descifrado con formato desconocido")


class Expediente(unittest.TestCase):
    """Denuncia cifrada con la versión 1 de la clave y un mensaje de cada
    autor, uno con la versión 1 y otro con la 2 (tras una rotación)."""

    def setUp(self):
        self.clave = {1: bytes([1]) * 32, 2: bytes([2]) * 32}
        self.envueltas = {v: cripto.envolver_clave(MAESTRA, k, EMPRESA, v) for v, k in self.clave.items()}
        self.claves = types.SimpleNamespace(maestra=MAESTRA)
        self.cifrado = cripto.cifrar_contenido(self.clave[1], denuncias.serializar(categoria="acoso", texto="hechos"),
                                               cripto.aad_denuncia(EMPRESA, DENUNCIA))
        self.filas = [self.fila(1, uuid.UUID(int=11), "denunciante", None, "dato nuevo", 1),
                      self.fila(2, uuid.UUID(int=12), "personal", PERSONA, "respuesta", 2)]

    def fila(self, secuencia, mensaje_id, autor, autor_id, texto, version):
        aad = cripto.aad_mensaje(EMPRESA, DENUNCIA, mensaje_id, autor, autor_id)
        cifrado = cripto.cifrar_contenido(self.clave[version], denuncias.serializar(texto=texto), aad)
        return (secuencia, FECHA, mensaje_id, autor, autor_id, cifrado, version)

    def descifrar(self, filas=None, denuncia=DENUNCIA, envueltas=None):
        return denuncias.descifrar_expediente(self.claves, EMPRESA, denuncia, self.cifrado, 1,
                                              self.filas if filas is None else filas,
                                              self.envueltas if envueltas is None else envueltas)

    def test_dos_versiones_y_dos_autores(self):
        contenido, mensajes = self.descifrar()
        self.assertEqual(contenido, {"v": 1, "categoria": "acoso", "texto": "hechos"})
        self.assertEqual([(m.secuencia, m.autor, m.autor_id, m.texto) for m in mensajes],
                         [(1, "denunciante", None, "dato nuevo"), (2, "personal", PERSONA, "respuesta")])

    def test_otra_denuncia_no_descifra(self):
        with self.assertRaises(cripto.ErrorIntegridad):
            self.descifrar(denuncia=uuid.UUID(int=99))

    def test_fila_alterada_no_descifra(self):
        secuencia, fecha, mensaje_id, autor, autor_id, cifrado, version = self.filas[1]
        alteradas = {
            "otro mensaje_id": (secuencia, fecha, uuid.UUID(int=13), autor, autor_id, cifrado, version),
            "otra persona": (secuencia, fecha, mensaje_id, autor, uuid.UUID(int=8), cifrado, version),
            "otra version": (secuencia, fecha, mensaje_id, autor, autor_id, cifrado, 1),
        }
        for motivo, alterada in alteradas.items():
            with self.subTest(motivo=motivo), self.assertRaises(cripto.ErrorIntegridad):
                self.descifrar(filas=[self.filas[0], alterada])

    def test_mensaje_del_personal_no_pasa_por_del_denunciante(self):
        # Mismo cifrado presentado como si lo hubiera escrito el denunciante.
        secuencia, fecha, mensaje_id, _, _, cifrado, version = self.filas[1]
        with self.assertRaises(cripto.ErrorIntegridad):
            self.descifrar(filas=[(secuencia, fecha, mensaje_id, "denunciante", None, cifrado, version)])

    def test_version_sin_clave_envuelta(self):
        with self.assertRaises(KeyError):
            self.descifrar(envueltas={1: self.envueltas[1]})
