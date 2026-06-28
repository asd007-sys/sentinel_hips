"""
Modulo iv - Analisis de Logs - sentinel_hips
---------------------------------------------
Analiza dos tipos de log buscando patrones de ataque:

  1. Scanner HTTP (/var/log/httpd/access.log):
     Una IP que genera muchos errores 404 esta escaneando el servidor
     buscando rutas vulnerables. Si supera scanner_404_threshold -> alarma + ban IP.

  2. Correo masivo (/var/log/maillog):
     Una cuenta que envia muchos mails (from=) esta haciendo spam,
     probablemente porque fue comprometida. Si supera mail_threshold ->
     alarma + bloquear cuenta.

Este modulo analiza los archivos completos (modo analisis), igual que
el de DDoS. Se le puede pasar la ruta de cada log por argumento.

USO:
  sudo venv/bin/python detection/log_analyzer.py <access_log> <maillog>
"""

import re
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from alerts.logger import registrar_alarma, registrar_prevencion
from alerts.mailer import enviar_email
from prevention.log_prevention import banear_ip, bloquear_cuenta
from config_loader import obtener_parametro

# Rutas por defecto (se pueden pasar otras por argumento)
RUTA_ACCESS = "/var/log/httpd/access.log"
RUTA_MAILLOG = "/var/log/maillog"


def analizar_scanner(ruta, umbral):
    """
    Cuenta errores 404 por IP en el access.log.
    Por cada IP que supere el umbral, alarma y banea.
    """
    if not os.path.isfile(ruta):
        print("No existe el access.log:", ruta)
        return

    # Contar 404 por IP
    contador = {}
    with open(ruta, "r") as f:
        for linea in f:
            # Formato: IP - - [fecha] "GET ..." 404 ...
            if " 404 " not in linea:
                continue
            ip = linea.split()[0]
            contador[ip] = contador.get(ip, 0) + 1

    # Revisar cuales superan el umbral
    for ip, cantidad in contador.items():
        if cantidad >= umbral:
            print("[!] SCANNER_HTTP ->", ip, "(" + str(cantidad), "errores 404)")
            alarma_id = registrar_alarma("SCANNER_HTTP", "logs", ip)
            resultado = banear_ip(ip)
            registrar_prevencion(alarma_id, "banear IP " + ip, resultado)
            enviar_email(
                "[HIPS ALERTA] Scanner HTTP desde " + ip,
                "La IP " + ip + " genero " + str(cantidad) + " errores 404 "
                "(escaneo de rutas). Accion tomada: IP baneada (" + resultado + ").",
            )


def analizar_correo(ruta, umbral):
    """
    Cuenta mails enviados (from=) por cuenta en el maillog.
    Por cada cuenta que supere el umbral, alarma y bloquea.
    """
    if not os.path.isfile(ruta):
        print("No existe el maillog:", ruta)
        return

    # Contar envios por cuenta
    contador = {}
    with open(ruta, "r") as f:
        for linea in f:
            # Buscar el patron from=<cuenta>
            m = re.search(r"from=<([^>]+)>", linea)
            if not m:
                continue
            cuenta = m.group(1)
            contador[cuenta] = contador.get(cuenta, 0) + 1

    # Revisar cuales superan el umbral
    for cuenta, cantidad in contador.items():
        if cantidad >= umbral:
            print("[!] MAIL_QUEUE_ALTA ->", cuenta, "(" + str(cantidad), "envios)")
            alarma_id = registrar_alarma("MAIL_QUEUE_ALTA", "logs", None)
            # El usuario del sistema es la parte antes del @
            usuario = cuenta.split("@")[0]
            resultado = bloquear_cuenta(usuario)
            registrar_prevencion(alarma_id, "bloquear cuenta " + usuario, resultado)
            enviar_email(
                "[HIPS ALERTA] Correo masivo desde " + cuenta,
                "La cuenta " + cuenta + " envio " + str(cantidad) + " mails "
                "(posible spam / cuenta comprometida). Accion tomada: cuenta "
                "bloqueada (" + resultado + ").",
            )


def main():
    # Rutas por argumento o por defecto
    ruta_access = sys.argv[1] if len(sys.argv) > 1 else RUTA_ACCESS
    ruta_maillog = sys.argv[2] if len(sys.argv) > 2 else RUTA_MAILLOG

    umbral_scanner = int(obtener_parametro("logs", "scanner_404_threshold", "20"))
    umbral_mail = int(obtener_parametro("logs", "mail_threshold", "15"))

    print("Modulo iv (analisis de logs) iniciado.")
    print("Umbral scanner:", umbral_scanner, "errores 404 |",
          "Umbral correo:", umbral_mail, "mails.")
    print("")

    print("--- Analizando access.log ---")
    analizar_scanner(ruta_access, umbral_scanner)

    print("--- Analizando maillog ---")
    analizar_correo(ruta_maillog, umbral_mail)

    print("")
    print("Analisis terminado.")


if __name__ == "__main__":
    main()
