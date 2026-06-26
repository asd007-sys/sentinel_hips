"""
Modulo vii - Directorio /tmp - sentinel_hips
---------------------------------------------
Detecta archivos ejecutables sospechosos en /tmp.

/tmp normalmente tiene archivos temporales inofensivos. Lo sospechoso
es un archivo con permiso de ejecucion (scripts o binarios), patron
clasico de malware que se deja en /tmp para correr.

Cuando encuentra uno: alarma + eliminar el archivo + email.
Corre en loop cada check_interval segundos.
"""

import os
import time
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from alerts.logger import registrar_alarma, registrar_prevencion
from alerts.mailer import enviar_email
from prevention.tmp_prevention import eliminar_archivo
from config_loader import obtener_parametro

CARPETA = "/tmp"


def buscar_ejecutables():
    """Devuelve la lista de archivos en /tmp que tienen permiso de ejecucion."""
    sospechosos = []
    for nombre in os.listdir(CARPETA):
        ruta = os.path.join(CARPETA, nombre)
        # Solo archivos (no carpetas) con permiso de ejecucion
        if os.path.isfile(ruta) and os.access(ruta, os.X_OK):
            sospechosos.append(ruta)
    return sospechosos


def main():
    intervalo = int(obtener_parametro("tmp", "check_interval", "15"))
    ya_vistos = []

    print("Modulo vii (/tmp) iniciado. Intervalo:", intervalo, "segundos.")
    print("Ctrl+C para detener.")

    while True:
        for ruta in buscar_ejecutables():
            if ruta in ya_vistos:
                continue
            ya_vistos.append(ruta)
            print("[!] ARCHIVO_TMP_SOSPECHOSO ->", ruta)

            alarma_id = registrar_alarma("ARCHIVO_TMP_SOSPECHOSO", "tmp", None)
            resultado = eliminar_archivo(ruta)
            registrar_prevencion(alarma_id, "eliminar " + ruta, resultado)
            enviar_email(
                "[HIPS ALERTA] Archivo ejecutable sospechoso en /tmp",
                "Se encontro el archivo ejecutable " + ruta + " en /tmp. " +
                "Accion tomada: archivo eliminado (" + resultado + ").",
            )

        time.sleep(intervalo)


if __name__ == "__main__":
    main()
