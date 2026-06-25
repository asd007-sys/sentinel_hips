"""
Modulo iii - Deteccion de Sniffers - sentinel_hips
---------------------------------------------------
Detecta dos cosas:
  1. Interfaces de red en modo promiscuo no autorizadas.
  2. Herramientas de captura corriendo (tcpdump, wireshark, ethereal, tshark).

Cuando detecta algo: registra la alarma, aplica la prevencion
(apagar promiscuo o matar el proceso), y manda email al admin.
Corre en loop cada sniffer_check_interval segundos.
"""

import subprocess
import time
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from alerts.logger import registrar_alarma, registrar_prevencion
from alerts.mailer import enviar_email
from prevention.sniffer_prevention import apagar_promiscuo, matar_proceso
from config_loader import obtener_parametro

HERRAMIENTAS_CAPTURA = ["tcpdump", "wireshark", "ethereal", "tshark"]


def buscar_promiscuo():
    """Devuelve la lista de interfaces que estan en modo promiscuo."""
    resultado = subprocess.run(["ip", "link", "show"], capture_output=True, text=True)
    interfaces = []
    for linea in resultado.stdout.splitlines():
        if "PROMISC" in linea and ": " in linea:
            nombre = linea.split(": ")[1].strip()
            interfaces.append(nombre)
    return interfaces


def buscar_herramientas():
    """Devuelve una lista de (herramienta, pid) de las que esten corriendo."""
    encontradas = []
    for herramienta in HERRAMIENTAS_CAPTURA:
        resultado = subprocess.run(["pgrep", herramienta], capture_output=True, text=True)
        if resultado.stdout.strip():
            for pid in resultado.stdout.strip().splitlines():
                encontradas.append((herramienta, pid))
    return encontradas


def revisar():
    """Hace una pasada de deteccion."""
    autorizadas = obtener_parametro("sniffer", "sniffer_authorized_interfaces", "lo")
    lista_autorizadas = autorizadas.split(",")

    # 1. Interfaces en modo promiscuo
    for interfaz in buscar_promiscuo():
        if interfaz not in lista_autorizadas:
            print("[!] Interfaz en promiscuo no autorizada:", interfaz)
            alarma_id = registrar_alarma("SNIFFER_DETECTADO", "sniffer", None)
            resultado = apagar_promiscuo(interfaz)
            registrar_prevencion(alarma_id, "apagar promiscuo en " + interfaz, resultado)
            enviar_email(
                "[HIPS ALERTA] Sniffer detectado en " + interfaz,
                "La interfaz " + interfaz + " estaba en modo promiscuo. " +
                "Accion tomada: promiscuo desactivado (" + resultado + ").",
            )

    # 2. Herramientas de captura corriendo
    for herramienta, pid in buscar_herramientas():
        print("[!] Herramienta de captura corriendo:", herramienta, "PID", pid)
        alarma_id = registrar_alarma("SNIFFER_DETECTADO", "sniffer", None)
        resultado = matar_proceso(pid)
        registrar_prevencion(alarma_id, "matar " + herramienta + " PID " + pid, resultado)
        enviar_email(
            "[HIPS ALERTA] Herramienta de captura: " + herramienta,
            "Se detecto " + herramienta + " (PID " + pid + ") corriendo. " +
            "Accion tomada: proceso terminado (" + resultado + ").",
        )


def main():
    intervalo = int(obtener_parametro("sniffer", "sniffer_check_interval", "60"))
    print("Modulo iii (sniffers) iniciado. Intervalo:", intervalo, "segundos.")
    print("Ctrl+C para detener.")
    while True:
        revisar()
        time.sleep(intervalo)


if __name__ == "__main__":
    main()
