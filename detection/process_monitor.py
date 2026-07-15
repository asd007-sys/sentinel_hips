"""
Modulo vi - Procesos con Alto Consumo - sentinel_hips
------------------------------------------------------
Detecta procesos que consumen demasiada CPU o RAM de forma sostenida.

Para no alarmar por un pico normal, un proceso tiene que superar el
umbral durante varias lecturas seguidas (lecturas_sostenidas) antes
de generar la alarma. Cuando se confirma, se mata el proceso (kill).

MEDICION DE CPU (importante):
Antes se usaba 'ps -o %cpu', pero ese valor es el promedio de CPU sobre
TODA la vida del proceso, no el uso instantaneo. Para un proceso que
fluctua o recien arranca, ese promedio es inestable y engañoso (un
proceso saturando un core podia leerse 86% en una lectura y 91% en la
siguiente, sin nunca sostener el umbral).

Ahora medimos CPU INSTANTANEO leyendo /proc/[pid]/stat dos veces
separadas por un intervalo corto: la diferencia de tiempo de CPU
consumido (utime+stime, en jiffies) sobre el tiempo real transcurrido
da el uso real en ese intervalo. Es el mismo metodo que usa 'top'.
El porcentaje es relativo a UN core (igual que el %cpu de ps), asi que
el umbral conserva el mismo significado: 100% = un core saturado.
La RAM se sigue leyendo como % del total fisico (campo rss).
"""

import time
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from alerts.logger import registrar_alarma, registrar_prevencion
from alerts.mailer import enviar_email
from prevention.process_prevention import matar_proceso
from config_loader import obtener_parametro

# Ticks del reloj por segundo (jiffies). Normalmente 100 en Linux.
TICKS_POR_SEG = os.sysconf("SC_CLK_TCK")
# Memoria fisica total en KB, para calcular el % de RAM.
try:
    _PAGINAS = os.sysconf("SC_PHYS_PAGES")
    _TAM_PAGINA = os.sysconf("SC_PAGE_SIZE")
    RAM_TOTAL_KB = (_PAGINAS * _TAM_PAGINA) / 1024.0
except (ValueError, OSError):
    RAM_TOTAL_KB = 0.0


def _leer_stat(pid):
    """
    Lee /proc/[pid]/stat y devuelve (nombre, jiffies_cpu, rss_kb).
    Devuelve None si el proceso ya no existe o no se puede leer.

    El nombre (comm) va entre parentesis y puede contener espacios o
    parentesis, por eso se parsea buscando el ULTIMO ')'.
    """
    try:
        with open("/proc/" + pid + "/stat", "r") as f:
            contenido = f.read()
    except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
        return None

    # comm esta entre el primer '(' y el ultimo ')'.
    ini = contenido.find("(")
    fin = contenido.rfind(")")
    if ini == -1 or fin == -1:
        return None
    nombre = contenido[ini + 1:fin]
    resto = contenido[fin + 2:].split()

    # Campos despues de comm (indices relativos a 'resto', 0-based):
    #   utime = campo 11, stime = campo 12, rss = campo 21 (en paginas)
    try:
        utime = int(resto[11])
        stime = int(resto[12])
        rss_paginas = int(resto[21])
    except (IndexError, ValueError):
        return None

    jiffies_cpu = utime + stime
    rss_kb = rss_paginas * (os.sysconf("SC_PAGE_SIZE") / 1024.0)
    return (nombre, jiffies_cpu, rss_kb)


def _pids_actuales():
    """Lista de PIDs (como strings) actualmente en /proc."""
    return [d for d in os.listdir("/proc") if d.isdigit()]


def leer_procesos(delta_seg=0.5):
    """
    Devuelve una lista de (pid, nombre, cpu, ram) con CPU INSTANTANEO.
    cpu y ram son porcentajes (float).

    Toma dos muestras de /proc/[pid]/stat separadas por delta_seg y
    calcula el uso de CPU en ese intervalo. Mantiene la misma firma que
    la version anterior, asi que el resto del modulo no cambia.
    """
    # Muestra 1
    muestra1 = {}
    for pid in _pids_actuales():
        datos = _leer_stat(pid)
        if datos is not None:
            muestra1[pid] = datos  # (nombre, jiffies, rss_kb)

    time.sleep(delta_seg)

    # Muestra 2 y calculo del delta (solo para los PIDs que ya vimos)
    procesos = []
    jiffies_posibles = delta_seg * TICKS_POR_SEG
    for pid in muestra1:
        datos2 = _leer_stat(pid)
        if datos2 is None:
            continue  # el proceso murio entre las dos muestras
        nombre2, jiffies2, rss_kb = datos2
        _nombre1, jiffies1, _rss1 = muestra1[pid]

        # CPU % = jiffies consumidos en el intervalo / jiffies posibles * 100
        delta_jiffies = jiffies2 - jiffies1
        cpu = (delta_jiffies / jiffies_posibles) * 100.0 if jiffies_posibles > 0 else 0.0

        ram = (rss_kb / RAM_TOTAL_KB) * 100.0 if RAM_TOTAL_KB > 0 else 0.0

        procesos.append((pid, nombre2, cpu, ram))

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
                          "(CPU", round(cpu, 1), "% RAM", round(ram, 1), "%)")

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
