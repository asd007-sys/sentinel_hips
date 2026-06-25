"""
Mailer del HIPS - sentinel_hips
--------------------------------
STUB TEMPORAL: por ahora solo imprime el email en pantalla.
Mas adelante se reemplaza por el envio real con smtplib.
La interfaz (la funcion enviar_email) ya queda definida para que
los modulos la usen y no haya que cambiarlos despues.
"""


def enviar_email(asunto, cuerpo):
    """
    Envia un email al administrador.
    Por ahora solo lo imprime en consola (stub).
    """
    print("=" * 50)
    print("[EMAIL AL ADMIN]")
    print("Asunto:", asunto)
    print("Cuerpo:", cuerpo)
    print("=" * 50)
