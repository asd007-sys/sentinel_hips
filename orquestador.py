"""
Orquestador del HIPS - sentinel_hips
-------------------------------------
Arranca los 10 modulos del HIPS juntos, cada uno en su propio hilo.
Todos los modulos ahora corren en loop continuo (vigilancia en vivo).

USO:
  sudo venv/bin/python orquestador.py
  Ctrl+C para detener todo.
"""

import threading
import time
import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Importamos el main() de cada modulo
from detection.file_integrity import main as main_integridad
from detection.users_monitor import main as main_usuarios
from detection.sniffer_detect import main as main_sniffer
from detection.mail_queue import main as main_correo
from detection.process_monitor import main as main_procesos
from detection.tmp_monitor import main as main_tmp
from detection.cron_monitor import main as main_cron
from detection.access_monitor import main as main_accesos
from detection.log_analyzer import main as main_logs
from detection.ddos_detect import main as main_ddos

# Lista de los 10 modulos: (nombre, funcion)
MODULOS = [
    ("i - integridad", main_integridad),
    ("ii - usuarios", main_usuarios),
    ("iii - sniffer", main_sniffer),
    ("iv - logs", main_logs),
    ("v - correo", main_correo),
    ("vi - procesos", main_procesos),
    ("vii - tmp", main_tmp),
    ("viii - ddos", main_ddos),
    ("ix - cron", main_cron),
    ("x - accesos", main_accesos),
]


def correr_modulo(nombre, funcion):
    """Corre un modulo. Si falla, lo avisa pero no tira todo abajo."""
    try:
        funcion()
    except Exception as e:
        print("[orquestador] El modulo", nombre, "fallo:", e)


def main():
    print("=" * 50)
    print(" HIPS sentinel_hips - Orquestador")
    print(" Arrancando los 10 modulos...")
    print("=" * 50)

    # Lanzar cada modulo en su propio hilo
    for nombre, funcion in MODULOS:
        h = threading.Thread(target=correr_modulo, args=(nombre, funcion), daemon=True)
        h.start()
        print(" [OK] Modulo", nombre)
        time.sleep(0.3)  # pequena pausa para que los prints no se mezclen tanto

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
