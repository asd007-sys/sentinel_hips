"""
Prevencion de accesos invalidos - sentinel_hips
------------------------------------------------
Acciones cuando se detecta fuerza bruta o credential stuffing:
  - banear una IP con iptables
  - bloquear una cuenta de usuario con passwd -l

Cada accion devuelve "exito" o "error".
"""

import subprocess


def banear_ip(ip):
    """Agrega una regla iptables que descarta todo el trafico de esa IP."""
    try:
        subprocess.run(
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            check=True,
        )
        return "exito"
    except subprocess.CalledProcessError:
        return "error"


def bloquear_cuenta(usuario):
    """Bloquea la cuenta del usuario indicado (passwd -l)."""
    try:
        subprocess.run(["passwd", "-l", usuario], check=True)
        return "exito"
    except subprocess.CalledProcessError:
        return "error"
