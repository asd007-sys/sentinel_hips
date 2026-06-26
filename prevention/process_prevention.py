"""
Prevencion de procesos - sentinel_hips
---------------------------------------
Accion opcional para el modulo vi: matar un proceso.
Por defecto el modulo vi solo alarma, pero si el admin activa
accion_matar en la config, se usa esta funcion.
"""

import subprocess


def matar_proceso(pid):
    """Termina el proceso con el PID indicado."""
    try:
        subprocess.run(["kill", "-9", str(pid)], check=True)
        return "exito"
    except subprocess.CalledProcessError:
        return "error"
