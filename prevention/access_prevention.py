"""
Prevencion de accesos invalidos - sentinel_hips
------------------------------------------------
Acciones cuando se detecta fuerza bruta o credential stuffing:
  - banear una IP con iptables
  - cambiar la contrasena de un usuario por una aleatoria
  - bloquear una cuenta con passwd -l

El enunciado pide, para usuarios con multiples accesos, "cambiar
contrasena generada aleatoriamente". Por eso la accion principal
para ataques por usuario es cambiar_password.

Cada accion devuelve "exito" o "error".
"""

import subprocess
import secrets
import string


def banear_ip(ip):
    """Banea una IP con iptables (para ataques con IP identificada)."""
    try:
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        return "exito"
    except subprocess.CalledProcessError:
        return "error"


def cambiar_password(usuario):
    """
    Cambia la contrasena del usuario por una aleatoria de 16 caracteres.
    Es la accion que pide el enunciado para usuarios atacados: en vez de
    bloquear la cuenta, se le pone una contrasena nueva aleatoria (el
    atacante ya no puede entrar, y el admin la resetea despues).
    """
    alfabeto = string.ascii_letters + string.digits
    nueva = "".join(secrets.choice(alfabeto) for _ in range(16))
    try:
        # chpasswd recibe "usuario:password" por entrada estandar
        subprocess.run(["chpasswd"], input=usuario + ":" + nueva,
                       text=True, check=True)
        return "exito"
    except subprocess.CalledProcessError:
        return "error"


def bloquear_cuenta(usuario):
    """Bloquea la cuenta del usuario (passwd -l). Alternativa a cambiar_password."""
    try:
        subprocess.run(["passwd", "-l", usuario], check=True)
        return "exito"
    except subprocess.CalledProcessError:
        return "error"
