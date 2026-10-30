"""Pruebas unitarias de los avisos de seguridad (app/avisos.py): a quién van
y qué dicen. El envío real a Mailpit, a través del cartero, con quién lo
recibe y quién no, lo prueba tests/security/verificar_registro.py.
"""
import unittest
import uuid
from unittest import mock

from app import avisos, cartero, personal

EMAILS = ("auditora@empresa.es", "otro.admin@empresa.es")


def componer(uno):
    """Lo compone el cartero, como en producción: el tipo es uno de
    correo.TIPOS y el asunto es de una línea."""
    return cartero.componer("no-responder@canario.test", uno.tipo, uno.destinatario, uno.asunto, uno.cuerpo)


class Destinatarios(unittest.TestCase):
    def test_los_roles_que_leen_la_auditoria(self):
        # Quien recibe los avisos es quien puede comprobarlos en la auditoría.
        self.assertEqual(personal.ROLES_AUDITORIA, ("admin", "auditor"))
        self.assertIn("rol in ('admin', 'auditor') and activo and totp_activo and id <> %s", avisos.SQL_DESTINATARIOS)

    def test_excluye_la_cuenta_de_la_que_se_avisa(self):
        conexion = mock.Mock()
        conexion.execute.return_value.fetchall.return_value = [(e,) for e in EMAILS]
        conexion.execute.return_value.fetchone.return_value = ("Empresa",)
        excluida = uuid.UUID(int=5)
        self.assertEqual(avisos.destinatarios(conexion, excluida), ("Empresa", EMAILS))
        self.assertEqual(conexion.execute.call_args_list[0].args, (avisos.SQL_DESTINATARIOS, [excluida]))


class Correos(unittest.TestCase):
    def test_lecturas_aviso_y_tope(self):
        aviso = avisos.correos_lecturas("Empresa", EMAILS, "lectora@empresa.es", 20, 50)
        tope = avisos.correos_lecturas("Empresa", EMAILS, "lectora@empresa.es", 50, 50)
        for correos in (aviso, tope):
            self.assertEqual([c.destinatario for c in correos], list(EMAILS))
            self.assertTrue(all(c.tipo == "aviso_lecturas" and "lectora@empresa.es" in c.cuerpo for c in correos))
            componer(correos[0])
        self.assertIn("ha abierto hoy 20 denuncias distintas", aviso[0].cuerpo)
        self.assertNotIn("Ha llegado al tope", aviso[0].cuerpo)
        self.assertIn("Ha llegado al tope de 50", tope[0].cuerpo)

    def test_activacion(self):
        correos = avisos.correos_activacion("Empresa", EMAILS, "nueva@empresa.es", "instructor")
        self.assertEqual([c.destinatario for c in correos], list(EMAILS))
        self.assertTrue(all(c.tipo == "aviso_activacion" for c in correos))
        self.assertIn("La cuenta nueva@empresa.es de Empresa se ha activado en Canario con el rol instructor",
                      correos[0].cuerpo)
        componer(correos[0])

    def test_vinculo_primero_al_titular(self):
        # NIST SP 800-63B-4, 4.1.2.1 y 4.5: el titular se entera de que se ha
        # añadido o quitado una forma de entrar en su cuenta.
        for vinculado, asunto in ((True, "Aviso de Canario: se ha vinculado una cuenta de Google"),
                                  (False, "Aviso de Canario: se ha desvinculado la cuenta de Google")):
            with self.subTest(vinculado=vinculado):
                correos = avisos.correos_vinculo("Empresa", EMAILS, "titular@empresa.es", "google", vinculado)
                self.assertEqual([c.destinatario for c in correos], ["titular@empresa.es", *EMAILS])
                self.assertTrue(all(c.tipo == "aviso_vinculo" and c.asunto == asunto for c in correos))
                self.assertIn("En su cuenta titular@empresa.es de Empresa en Canario", correos[0].cuerpo)
                self.assertIn("Si no ha sido usted, alguien ha usado su sesión", correos[0].cuerpo)
                self.assertIn("En la cuenta titular@empresa.es de Empresa en Canario", correos[1].cuerpo)
                self.assertNotIn("Si no ha sido usted", correos[1].cuerpo)
                componer(correos[0])
        # Sin nadie que vigile, el titular lo recibe igual.
        solo = avisos.correos_vinculo("Empresa", (), "titular@empresa.es", "google", True)
        self.assertEqual([c.destinatario for c in solo], ["titular@empresa.es"])

    def test_sin_destinatarios_no_hay_correos(self):
        self.assertEqual(avisos.correos_lecturas("Empresa", (), "x@empresa.es", 20, 50), ())
        self.assertEqual(avisos.correos_activacion("Empresa", (), "x@empresa.es", "admin"), ())
