"""
Modulo ii - Usuarios Conectados - sentinel_hips
------------------------------------------------
Detecta sesiones sospechosas de dos formas:
  1. Origen inusual: la IP desde donde se conecta el usuario no esta
     en la lista de origenes conocidos (ip_whitelist).
  2. Horario inusual: la conexion ocurre fuera del horario esperado
     (entre hora_fin y hora_inicio).

Lee las sesiones activas con el comando 'who'.
Prevencion: solo alarma y avisa al admin (no cierra sesiones).
"""

import subprocess
import time
import sys
import os
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from alerts.logger import registrar_alarma
from alerts.mailer import enviar_email
from config_loader import obtener_parametro


def leer_sesiones():
    """
    Devuelve una lista de (usuario, origen) de las sesiones activas.
    Usa 'who'. El origen es la IP entre parentesis, o 'local' si no hay.
    """
    resultado = subprocess.run(["who"], capture_output=True, text=True)
    sesiones = []
    for linea in resultado.stdout.splitlines():
        partes = linea.split()
        if not partes:
            continue
        usuario = partes[0]
        # El origen aparece entre parentesis al final, ej. (192.168.1.10)
        origen = "local"
        if "(" in linea and ")" in linea:
            origen = linea[linea.find("(") + 1:linea.find(")")]
        sesiones.append((usuario, origen))
    return sesiones


def horario_sospechoso(hora_inicio, hora_fin):
    """Devuelve True si la hora actual esta fuera del rango permitido."""
    hora_actual = datetime.now().hour
    return hora_actual < hora_inicio or hora_actual >= hora_fin


def main():
    whitelist = obtener_parametro("usuarios", "ip_whitelist", "local,127.0.0.1")
    lista_blanca = whitelist.split(",")
    hora_inicio = int(obtener_parametro("usuarios", "hora_inicio", "8"))
    hora_fin = int(obtener_parametro("usuarios", "hora_fin", "20"))
    intervalo = int(obtener_parametro("usuarios", "check_interval", "30"))

    ya_alarmadas = []

    print("Modulo ii (usuarios conectados) iniciado.")
    print("Horario permitido:", hora_inicio, "a", hora_fin, "hs.")
    print("Ctrl+C para detener.")

    while True:
        for usuario, origen in leer_sesiones():
            # Clave para no alarmar la misma sesion repetidamente
            clave = usuario + "@" + origen

            origen_malo = origen not in lista_blanca
            horario_malo = horario_sospechoso(hora_inicio, hora_fin)

            if (origen_malo or horario_malo) and clave not in ya_alarmadas:
                ya_alarmadas.append(clave)

                # Armar el motivo de la alarma
                motivos = []
                if origen_malo:
                    motivos.append("origen no conocido (" + origen + ")")
                if horario_malo:
                    motivos.append("fuera de horario")
                motivo = " y ".join(motivos)

                print("[!] USUARIO_SOSPECHOSO ->", clave, "-", motivo)

                ip = origen if origen != "local" else None
                registrar_alarma("USUARIO_SOSPECHOSO", "usuarios", ip)
                enviar_email(
                    "[HIPS ALERTA] Usuario sospechoso: " + usuario,
                    "El usuario " + usuario + " tiene una sesion sospechosa: " +
                    motivo + ". Origen: " + origen + ".",
                )

        time.sleep(intervalo)


if __name__ == "__main__":
    main()
