"""
Mailer del HIPS - sentinel_hips
--------------------------------
Envia emails al administrador usando el Postfix local (localhost:25).
La direccion del admin y el remitente se leen de la configuracion,
nunca estan hardcodeados con datos sensibles.

Reemplaza al stub anterior. La funcion enviar_email() mantiene la
misma firma, asi que los modulos que ya la usan no cambian.
"""

import smtplib
from email.message import EmailMessage

import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config_loader import obtener_parametro


def enviar_email(asunto, cuerpo):
    """
    Envia un email al administrador a traves del Postfix local.
    Devuelve True si se envio, False si hubo error (no corta el modulo).
    """
    # Datos de correo desde la config (con valores por defecto razonables)
    remitente = obtener_parametro("email", "email_remitente", "hips@localhost")
    destinatario = obtener_parametro("email", "email_admin", "asd@localhost")

    mensaje = EmailMessage()
    mensaje["From"] = remitente
    mensaje["To"] = destinatario
    mensaje["Subject"] = asunto
    mensaje.set_content(cuerpo)

    try:
        # Postfix local escucha en el puerto 25 sin autenticacion
        with smtplib.SMTP("localhost", 25) as servidor:
            servidor.send_message(mensaje)
        print("[mailer] Email enviado a", destinatario)
        return True
    except Exception as e:
        # Si falla el correo, no debe frenar la deteccion/prevencion
        print("[mailer] Error al enviar email:", e)
        return False


# Prueba rapida
if __name__ == "__main__":
    enviar_email(
        "[HIPS ALERTA] Prueba de correo",
        "Este es un email de prueba del sistema HIPS. Si lo recibis, el mailer funciona.",
    )
