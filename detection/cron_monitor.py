"""
Modulo ix - Cron Sospechoso - sentinel_hips
--------------------------------------------
Revisa los archivos de cron buscando tareas con comandos o rutas
sospechosas (tipicas de malware): descargas con wget/curl, netcat,
ejecucion desde /tmp, decodificacion base64, etc.

Lee /etc/crontab, los archivos de /etc/cron.d/ y los crontabs de
usuario en /var/spool/cron/.
Prevencion: solo alarma y avisa (no modifica los crontabs).
"""

import os
import time
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from alerts.logger import registrar_alarma
from alerts.mailer import enviar_email
from config_loader import obtener_parametro

# Lugares donde viven las tareas de cron
ARCHIVOS_CRON = ["/etc/crontab"]
CARPETAS_CRON = ["/etc/cron.d", "/var/spool/cron"]


def leer_lineas_cron():
    """
    Junta todas las lineas de cron del sistema.
    Devuelve una lista de (archivo, linea).
    """
    lineas = []

    # Archivos sueltos
    for ruta in ARCHIVOS_CRON:
        if os.path.isfile(ruta):
            for linea in abrir_archivo(ruta):
                lineas.append((ruta, linea))

    # Carpetas con varios archivos
    for carpeta in CARPETAS_CRON:
        if os.path.isdir(carpeta):
            for nombre in os.listdir(carpeta):
                ruta = os.path.join(carpeta, nombre)
                if os.path.isfile(ruta):
                    for linea in abrir_archivo(ruta):
                        lineas.append((ruta, linea))

    return lineas


def abrir_archivo(ruta):
    """Devuelve las lineas no vacias y no comentadas de un archivo."""
    resultado = []
    try:
        with open(ruta, "r") as f:
            for linea in f:
                linea = linea.strip()
                if linea and not linea.startswith("#"):
                    resultado.append(linea)
    except OSError:
        pass
    return resultado


def main():
    patrones = obtener_parametro(
        "cron", "patrones_sospechosos",
        "/tmp,/dev/shm,wget,curl,nc ,netcat,base64",
    )
    lista_patrones = patrones.split(",")
    intervalo = int(obtener_parametro("cron", "check_interval", "60"))

    ya_alarmadas = []

    print("Modulo ix (cron sospechoso) iniciado. Intervalo:", intervalo, "segundos.")
    print("Ctrl+C para detener.")

    while True:
        for archivo, linea in leer_lineas_cron():
            # Buscar si la linea contiene algun patron sospechoso
            for patron in lista_patrones:
                if patron in linea and linea not in ya_alarmadas:
                    ya_alarmadas.append(linea)
                    print("[!] CRON_SOSPECHOSO ->", archivo, ":", linea)

                    registrar_alarma("CRON_SOSPECHOSO", "cron", None)
                    enviar_email(
                        "[HIPS ALERTA] Tarea cron sospechosa",
                        "Se encontro una tarea cron sospechosa en " + archivo +
                        " (patron '" + patron + "'):\n" + linea,
                    )
                    break

        time.sleep(intervalo)


if __name__ == "__main__":
    main()
