"""
Prevencion de /tmp - sentinel_hips
-----------------------------------
Accion del modulo vii: eliminar un archivo sospechoso de /tmp.
Devuelve "exito" o "error".
"""

import os


def eliminar_archivo(ruta):
    """Elimina el archivo indicado."""
    try:
        os.remove(ruta)
        return "exito"
    except OSError:
        return "error"
