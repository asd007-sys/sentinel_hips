"""
Modulo vi - Procesos con Alto Consumo - sentinel_hips
------------------------------------------------------
Detecta procesos que consumen demasiada CPU o RAM de forma sostenida.

Para no alarmar por un pico normal, un proceso tiene que superar el
umbral durante varias lecturas seguidas (lecturas_sostenidas) antes
de generar la alarma. Cuando se confirma, se mata el proceso (kill).

Lee los procesos con el comando 'ps'.
"""

import subprocess
import time
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from alerts.logger import registrar_alarma, registrar_prevencion
from alerts.mailer import enviar_email
from prevention.process_prevention import matar_proceso
from config_loader import obtener_parametro


def leer_procesos():
    """
    Devuelve una lista de (pid, nombre, cpu, ram) usando 'ps'.
    cpu y ram son porcentajes (float).

    Se ponen pid, cpu y mem PRIMERO y el nombre (comm) AL FINAL, porque
    el nombre puede tener espacios y romperia el split si estuviera en
    el medio. Asi, los 3 primeros campos son numeros y el resto es el nombre.
    """
    resultado = subprocess.run(
        ["ps", "-eo", "pid,%cpu,%mem,comm", "--no-headers"],
        capture_output=True, text=True,
    )
    procesos = []
    for linea in resultado.stdout.splitlines():
        partes = linea.split(None, 3)   # dividir en 4 partes como maximo
        if len(partes) < 4:
            continue
        try:
            pid = partes[0]
            cpu = float(partes[1])
            ram = float(partes[2])
            nombre = partes[3]
        except ValueError:
            # Si alguna linea no tiene el formato esperado, se salta
            continue
        procesos.append((pid, nombre, cpu, ram))
    return procesos


def main():
    umbral = float(obtener_parametro("procesos", "umbral_consumo", "90"))
    intervalo = int(obtener_parametro("procesos", "check_interval", "10"))
    sostenidas = int(obtener_parametro("procesos", "lecturas_sostenidas", "3"))

    # Cuenta cuantas lecturas seguidas lleva cada pid por encima del umbral
    contador = {}
    ya_alarmados = []

    print("Modulo vi (procesos) iniciado.")
    print("Umbral:", umbral, "% sostenido por", sostenidas, "lecturas.")
    print("Ctrl+C para detener.")

    while True:
        pids_altos = []
        for pid, nombre, cpu, ram in leer_procesos():
            if cpu >= umbral or ram >= umbral:
                pids_altos.append(pid)
                contador[pid] = contador.get(pid, 0) + 1

                if contador[pid] >= sostenidas and pid not in ya_alarmados:
                    ya_alarmados.append(pid)
                    print("[!] PROCESO_ALTO_CONSUMO ->", nombre, "PID", pid,
                          "(CPU", cpu, "% RAM", ram, "%)")

                    alarma_id = registrar_alarma("PROCESO_ALTO_CONSUMO", "procesos", None)
                    resultado = matar_proceso(pid)
                    registrar_prevencion(alarma_id,
                                         "matar " + nombre + " PID " + pid, resultado)
                    enviar_email(
                        "[HIPS ALERTA] Proceso con alto consumo: " + nombre,
                        "El proceso " + nombre + " (PID " + pid + ") consumio mas de " +
                        str(umbral) + "% de CPU/RAM durante " + str(sostenidas) +
                        " lecturas seguidas. Accion tomada: proceso terminado (" +
                        resultado + ").",
                    )

        # Resetear el contador de los pids que ya no estan altos
        for pid in list(contador.keys()):
            if pid not in pids_altos:
                contador[pid] = 0

        time.sleep(intervalo)


if __name__ == "__main__":
    main()
