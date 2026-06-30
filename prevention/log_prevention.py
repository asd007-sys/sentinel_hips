"""
Prevencion del modulo iv - sentinel_hips
-----------------------------------------
Acciones para el analisis de logs:
  - banear una IP con iptables (scanner, fuerza bruta)
  - cambiar la contrasena de un usuario por una aleatoria
  - bloquear una cuenta con passwd -l
  - bajar temporalmente el servicio de correo (postfix)
"""

import subprocess
import secrets
import string


def banear_ip(ip):
    """Banea una IP con iptables."""
    try:
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        return "exito"
    except subprocess.CalledProcessError:
        return "error"


def cambiar_password(usuario):
    """
    Cambia la contrasena del usuario por una aleatoria.
    Es lo que pide el enunciado para usuarios con multiples accesos
    o envio masivo de mails. El admin debe resetearla manualmente despues.
    """
    # Generar una contrasena aleatoria de 16 caracteres
    alfabeto = string.ascii_letters + string.digits
    nueva = "".join(secrets.choice(alfabeto) for _ in range(16))
    try:
        # 'chpasswd' recibe usuario:password por entrada estandar
        subprocess.run(
            ["chpasswd"], input=usuario + ":" + nueva,
            text=True, check=True,
        )
        return "exito"
    except subprocess.CalledProcessError:
        return "error"


def bloquear_cuenta(usuario):
    """Bloquea una cuenta con passwd -l."""
    try:
        subprocess.run(["passwd", "-l", usuario], check=True)
        return "exito"
    except subprocess.CalledProcessError:
        return "error"


def bajar_correo():
    """Baja temporalmente el servicio de correo (postfix)."""
    try:
        subprocess.run(["systemctl", "stop", "postfix"], check=True)
        return "exito"
    except subprocess.CalledProcessError:
        return "error"
