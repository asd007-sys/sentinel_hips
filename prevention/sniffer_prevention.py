"""
Prevencion de sniffers - sentinel_hips
---------------------------------------
Acciones que toma el sistema cuando se detecta un sniffer:
  - apagar el modo promiscuo de una interfaz
  - terminar (kill) una herramienta de captura en ejecucion

Cada accion devuelve "exito" o "error" para que el modulo
que la llama lo registre con el logger.
"""

import subprocess


def apagar_promiscuo(interfaz):
    """Desactiva el modo promiscuo de la interfaz indicada."""
    try:
        subprocess.run(
            ["ip", "link", "set", "dev", interfaz, "promisc", "off"],
            check=True,
        )
        return "exito"
    except subprocess.CalledProcessError:
        return "error"


def matar_proceso(pid):
    """Termina el proceso con el PID indicado (herramienta de captura)."""
    try:
        subprocess.run(["kill", "-9", str(pid)], check=True)
        return "exito"
    except subprocess.CalledProcessError:
        return "error"
