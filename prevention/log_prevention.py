"""
Prevencion del modulo iv - sentinel_hips
-----------------------------------------
Acciones para el analisis de logs:
  - banear una IP (scanner HTTP) con iptables
  - bloquear una cuenta (correo masivo) con passwd -l
"""

import subprocess


def banear_ip(ip):
    """Banea una IP con iptables."""
    try:
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        return "exito"
    except subprocess.CalledProcessError:
        return "error"


def bloquear_cuenta(usuario):
    """Bloquea una cuenta de usuario con passwd -l."""
    try:
        subprocess.run(["passwd", "-l", usuario], check=True)
        return "exito"
    except subprocess.CalledProcessError:
        return "error"
