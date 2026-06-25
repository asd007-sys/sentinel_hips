"""
Test del modulo x - sentinel_hips
----------------------------------
Simula el ataque de fuerza bruta inyectando lineas en /var/log/secure
para verificar que el modulo x detecta y previene.

USO (en dos terminales):
  Terminal 1:  sudo venv/bin/python detection/access_monitor.py
  Terminal 2:  sudo venv/bin/python tests/test_access.py

El script escribe lineas tipo ataque al final de /var/log/secure,
imitando el formato del dataset del profesor (ataque a 'condorito').
Tambien incluye un ataque con IP para probar el ban con iptables.
"""

import time
from datetime import datetime

RUTA_LOG = "/var/log/secure"


def linea_smtp(usuario):
    """Genera una linea de fallo SMTP (sin IP), como el dataset condorito."""
    ts = datetime.now().strftime("%b %e %H:%M:%S")
    return (ts + " tera saslauthd[754]: pam_unix(smtp:auth): "
            "authentication failure; logname= uid=0 euid=0 tty= ruser= "
            "rhost=  user=" + usuario + "\n")


def linea_ssh(usuario, ip):
    """Genera una linea de fallo SSH (con IP), para probar el ban."""
    ts = datetime.now().strftime("%b %e %H:%M:%S")
    return (ts + " tera sshd[999]: Failed password for " + usuario +
            " from " + ip + " port 22 ssh2\n")


def main():
    print("Inyectando ataque de prueba en", RUTA_LOG)

    with open(RUTA_LOG, "a") as f:
        # Ataque 1: fuerza bruta SMTP contra 'condorito' (sin IP)
        print("Ataque 1: 6 fallos SMTP contra 'condorito'...")
        for i in range(6):
            f.write(linea_smtp("condorito"))
            f.flush()
            time.sleep(0.5)

        time.sleep(2)

        # Ataque 2: fuerza bruta SSH desde una IP (con ban)
        print("Ataque 2: 6 fallos SSH desde 203.0.113.50...")
        for i in range(6):
            f.write(linea_ssh("root", "203.0.113.50"))
            f.flush()
            time.sleep(0.5)

    print("Listo. Revisa la terminal del modulo x.")


if __name__ == "__main__":
    main()
