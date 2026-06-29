"""
Modulo v - Cola de Correo - sentinel_hips
------------------------------------------
Vigila el tamano de la cola de correo del sistema. Una cola que crece
mucho indica spam saliente (correo masivo acumulandose por salir).

Se diferencia del modulo iv en el momento que mira:
  - modulo iv: cuantos mails YA se enviaron (historial en maillog).
  - modulo v : cuantos mails estan esperando AHORA en la cola (mailq).

Lee la cola con 'mailq'. Si la cantidad supera umbral_cola -> alarma.
Prevencion: solo alarma y avisa al admin (no baja el servicio).
Corre en loop cada check_interval segundos.
"""

import subprocess
import time
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from alerts.logger import registrar_alarma
from alerts.mailer import enviar_email
from config_loader import obtener_parametro


def contar_cola():
    """
    Devuelve cuantos mensajes hay en la cola de correo.
    Usa 'mailq'. Si la cola esta vacia o el comando falla, devuelve 0.
    """
    try:
        resultado = subprocess.run(["mailq"], capture_output=True, text=True)
    except FileNotFoundError:
        return 0

    salida = resultado.stdout.strip()

    # Si la cola esta vacia, mailq dice "Mail queue is empty"
    if "empty" in salida.lower() or not salida:
        return 0

    # Cada mensaje en la cola empieza con un ID al principio de una linea.
    # Una forma simple y confiable: contar las lineas que separan mensajes.
    # mailq suele terminar con "-- N Kbytes in M Request(s)."
    for linea in salida.splitlines():
        if "Request" in linea:
            # linea tipo: "-- 5 Kbytes in 53 Requests."
            partes = linea.split()
            for i, palabra in enumerate(partes):
                if palabra.startswith("Request"):
                    return int(partes[i - 1])

    # Si no encontramos el resumen, contamos los bloques de mensaje
    # (separados por lineas en blanco), descartando la cabecera.
    bloques = salida.split("\n\n")
    return max(0, len(bloques) - 1)


def main():
    umbral = int(obtener_parametro("correo", "umbral_cola", "50"))
    intervalo = int(obtener_parametro("correo", "check_interval", "30"))

    ya_alarmado = False

    print("Modulo v (cola de correo) iniciado.")
    print("Umbral:", umbral, "mails en cola. Intervalo:", intervalo, "segundos.")
    print("Ctrl+C para detener.")

    while True:
        cantidad = contar_cola()

        if cantidad >= umbral and not ya_alarmado:
            ya_alarmado = True
            print("[!] MAIL_QUEUE_ALTA -> cola con", cantidad, "mensajes")

            registrar_alarma("MAIL_QUEUE_ALTA", "correo", None)
            enviar_email(
                "[HIPS ALERTA] Cola de correo alta",
                "La cola de correo tiene " + str(cantidad) + " mensajes esperando "
                "(umbral: " + str(umbral) + "). Posible spam saliente. "
                "Revisar la cola con mailq.",
            )

        # Si la cola baja del umbral, resetear para poder alarmar de nuevo
        if cantidad < umbral:
            ya_alarmado = False

        time.sleep(intervalo)


if __name__ == "__main__":
    main()
