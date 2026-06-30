"""
Orquestador del HIPS - sentinel_hips
-------------------------------------
Arranca todos los modulos del HIPS juntos, cada uno en su propio hilo.

  - Modulos en vivo (vigilan continuamente): se lanzan una vez y corren
    en loop para siempre (i, ii, iii, v, vi, vii, ix, x).
  - Modulos de analisis (leen un archivo): iv y viii. Se corren cada
    cierto tiempo sobre sus logs (intervalo_analisis).

USO:
  sudo venv/bin/python orquestador.py
  Ctrl+C para detener todo.
"""

import threading
import time
import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Modulos en vivo: importamos el main() de cada uno
from detection.file_integrity import main as main_integridad
from detection.users_monitor import main as main_usuarios
from detection.sniffer_detect import main as main_sniffer
from detection.mail_queue import main as main_correo
from detection.process_monitor import main as main_procesos
from detection.tmp_monitor import main as main_tmp
from detection.cron_monitor import main as main_cron
from detection.access_monitor import main as main_accesos

# Modulos de analisis: importamos el modulo entero para llamar su main()
import detection.ddos_detect as ddos
import detection.log_analyzer as logs

from config_loader import obtener_parametro

# Lista de los modulos en vivo: (nombre, funcion)
MODULOS_EN_VIVO = [
    ("integridad", main_integridad),
    ("usuarios", main_usuarios),
    ("sniffer", main_sniffer),
    ("correo", main_correo),
    ("procesos", main_procesos),
    ("tmp", main_tmp),
    ("cron", main_cron),
    ("accesos", main_accesos),
]

# Rutas de los logs que analizan iv y viii.
# Por defecto apuntan a los datasets de prueba en tests/.
# Para usar logs reales del sistema, cambiar estas rutas.
CARPETA_BASE = os.path.dirname(os.path.abspath(__file__))
RUTA_CAPTURA_DNS = os.path.join(CARPETA_BASE, "tests", "Ataque_DNS_-_tcpdump.txt")
RUTA_ACCESS_LOG = os.path.join(CARPETA_BASE, "tests", "access_log")
RUTA_MAILLOG = os.path.join(CARPETA_BASE, "tests", "Ataques_SMTP_-_Maillog.txt")


def correr_en_vivo(nombre, funcion):
    """Corre un modulo en vivo. Si falla, lo avisa pero no tira todo abajo."""
    try:
        funcion()
    except Exception as e:
        print("[orquestador] El modulo", nombre, "fallo:", e)


def correr_analisis():
    """Corre los modulos de analisis (iv y viii) cada cierto intervalo."""
    intervalo = int(obtener_parametro("orquestador", "intervalo_analisis", "60"))
    while True:
        # Modulo viii (DDoS): analiza la captura si existe
        if os.path.isfile(RUTA_CAPTURA_DNS):
            sys.argv = ["ddos_detect", RUTA_CAPTURA_DNS]
            correr_en_vivo("ddos", ddos.main)

        # Modulo iv (logs): analiza access.log y maillog
        sys.argv = ["log_analyzer", RUTA_ACCESS_LOG, RUTA_MAILLOG]
        correr_en_vivo("logs", logs.main)

        time.sleep(intervalo)


def main():
    print("=" * 50)
    print(" HIPS sentinel_hips - Orquestador")
    print(" Arrancando todos los modulos...")
    print("=" * 50)

    hilos = []

    # Lanzar cada modulo en vivo en su propio hilo
    for nombre, funcion in MODULOS_EN_VIVO:
        h = threading.Thread(target=correr_en_vivo, args=(nombre, funcion), daemon=True)
        h.start()
        hilos.append(h)
        print(" [OK] Modulo en vivo:", nombre)

    # Lanzar el hilo de los modulos de analisis
    h = threading.Thread(target=correr_analisis, daemon=True)
    h.start()
    hilos.append(h)
    print(" [OK] Modulos de analisis: iv (logs) y viii (ddos)")

    print("=" * 50)
    print(" Todos los modulos corriendo. Ctrl+C para detener.")
    print("=" * 50)

    # Mantener el programa principal vivo
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nDeteniendo el HIPS...")


if __name__ == "__main__":
    main()
