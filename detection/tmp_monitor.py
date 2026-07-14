"""
Modulo vii - Directorio /tmp - sentinel_hips
---------------------------------------------
Detecta archivos ejecutables sospechosos en /tmp.

/tmp normalmente tiene archivos temporales inofensivos. Lo sospechoso
es un archivo con permiso de ejecucion (scripts o binarios), patron
clasico de malware que se deja en /tmp para correr.

Cuando encuentra uno: alarma + eliminar el archivo + email.
Corre en loop cada check_interval segundos.

NOTA: se revisa el BIT de permiso de ejecucion directamente (con stat),
no os.access(X_OK). Esto es importante porque /tmp esta montado con
noexec (control de hardening), y os.access(X_OK) devuelve False en /tmp
aunque el archivo tenga el bit de ejecucion puesto. El bit en los
metadatos si se puede leer, y es lo que delata al archivo sospechoso.
"""

import os
import stat
import time
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from alerts.logger import registrar_alarma, registrar_prevencion
from alerts.mailer import enviar_email
from prevention.tmp_prevention import eliminar_archivo
from config_loader import obtener_parametro

CARPETA = "/tmp"


def tiene_permiso_ejecucion(ruta):
    """
    Devuelve True si el archivo tiene el bit de ejecucion puesto
    (para el dueno, el grupo o todos). Lee el bit directamente con
    stat, asi funciona aunque /tmp este montado noexec.
    """
    try:
        modo = os.stat(ruta).st_mode
        # Bits de ejecucion: dueno (USR), grupo (GRP) y otros (OTH)
        bits_ejecucion = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
        return bool(modo & bits_ejecucion)
    except OSError:
        return False


def buscar_ejecutables():
    """Devuelve la lista de archivos en /tmp con el bit de ejecucion puesto."""
    sospechosos = []
    for nombre in os.listdir(CARPETA):
        ruta = os.path.join(CARPETA, nombre)
        if os.path.isfile(ruta) and tiene_permiso_ejecucion(ruta):
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
