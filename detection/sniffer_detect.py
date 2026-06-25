"""
Modulo iii - Deteccion de Sniffers - sentinel_hips
---------------------------------------------------
Detecta dos cosas (segun el enunciado):
  1. Interfaces de red en modo promiscuo no autorizadas.
  2. Herramientas de captura de paquetes en ejecucion
     (tcpdump, wireshark, ethereal, tshark).

Cuando detecta algo:
  - registra la alarma (logger -> log + base de datos)
  - ejecuta la prevencion (apagar promiscuo / matar el proceso)
  - registra la prevencion
  - manda email al admin

Pensado para correr en loop cada cierto intervalo (sniffer_check_interval).
"""

import subprocess
import time
import sys
import os

# Permite importar los modulos de las otras carpetas del proyecto
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from alerts.logger import registrar_alarma, registrar_prevencion
from alerts.mailer import enviar_email
from prevention.sniffer_prevention import apagar_promiscuo, matar_proceso
from config_loader import obtener_parametro

# Herramientas de captura que no deberian estar corriendo
HERRAMIENTAS_CAPTURA = ["tcpdump", "wireshark", "ethereal", "tshark"]


def interfaces_en_promiscuo():
    """
    Devuelve la lista de interfaces que estan en modo promiscuo.
    Usa 'ip link show' y busca el flag PROMISC.
    """
    resultado = subprocess.run(
        ["ip", "link", "show"], capture_output=True, text=True
    )
    interfaces = []
    for linea in resultado.stdout.splitlines():
        # Las lineas de interfaz tienen el formato "2: eth0: <...,PROMISC,...>"
        if "PROMISC" in linea and ": " in linea:
            # El nombre de la interfaz es el segundo campo
            partes = linea.split(": ")
            if len(partes) >= 2:
                nombre = partes[1].strip()
                interfaces.append(nombre)
    return interfaces


def herramientas_corriendo():
    """
    Devuelve una lista de (nombre_herramienta, pid) de las herramientas
    de captura que esten en ejecucion.
    """
    encontradas = []
    for herramienta in HERRAMIENTAS_CAPTURA:
        # pgrep devuelve los PIDs de los procesos con ese nombre
        resultado = subprocess.run(
            ["pgrep", herramienta], capture_output=True, text=True
        )
        if resultado.stdout.strip():
            for pid in resultado.stdout.strip().splitlines():
                encontradas.append((herramienta, pid))
    return encontradas


def revisar():
    """Hace una pasada de deteccion. Se llama en cada ciclo."""

    # Interfaces autorizadas a estar en promiscuo (de la config)
    autorizadas = obtener_parametro(
        "sniffer", "sniffer_authorized_interfaces", "lo"
    )
    lista_autorizadas = [i.strip() for i in autorizadas.split(",")]

    # --- 1. Modo promiscuo ---
    for interfaz in interfaces_en_promiscuo():
        if interfaz not in lista_autorizadas:
            print("[!] Interfaz en promiscuo no autorizada:", interfaz)

            alarma_id = registrar_alarma("SNIFFER_DETECTADO", "sniffer", None)

            resultado = apagar_promiscuo(interfaz)
            accion = "apagar modo promiscuo en " + interfaz
            registrar_prevencion(alarma_id, accion, resultado)

            enviar_email(
                "[HIPS ALERTA] Sniffer detectado en interfaz " + interfaz,
                "Se detecto la interfaz " + interfaz + " en modo promiscuo "
                "no autorizado. Accion tomada: modo promiscuo desactivado "
                "(" + resultado + ").",
            )

    # --- 2. Herramientas de captura ---
    for herramienta, pid in herramientas_corriendo():
        print("[!] Herramienta de captura corriendo:", herramienta, "PID", pid)

        alarma_id = registrar_alarma("SNIFFER_DETECTADO", "sniffer", None)

        resultado = matar_proceso(pid)
        accion = "terminar proceso " + herramienta + " (PID " + pid + ")"
        registrar_prevencion(alarma_id, accion, resultado)

        enviar_email(
            "[HIPS ALERTA] Herramienta de captura detectada: " + herramienta,
            "Se detecto la herramienta " + herramienta + " (PID " + pid + ") "
            "en ejecucion. Accion tomada: proceso terminado (" + resultado + ").",
        )


def main():
    """Corre la deteccion en loop segun el intervalo configurado."""
    intervalo = int(obtener_parametro("sniffer", "sniffer_check_interval", "60"))
    print("Modulo iii (sniffers) iniciado. Intervalo:", intervalo, "segundos.")
    print("Ctrl+C para detener.")
    while True:
        revisar()
        time.sleep(intervalo)


if __name__ == "__main__":
    main()
