"""
Prevencion de DDoS - sentinel_hips
-----------------------------------
Cuando se detecta un ataque DDoS, se banea la IP atacante con iptables.
Devuelve "exito" o "error".
"""

import subprocess


def banear_ip(ip):
    """Agrega una regla iptables que descarta el trafico de la IP atacante."""
    try:
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        return "exito"
    except subprocess.CalledProcessError:
        return "error"
