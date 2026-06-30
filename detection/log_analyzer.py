"""
Modulo iv - Analisis de Logs - sentinel_hips
---------------------------------------------
Vigila en loop continuo los logs del sistema buscando 3 patrones de ataque:

  1. Failed Password / authentication failure en /var/log/secure y
     /var/log/messages. (Solo alarma por defecto; la prevencion de
     fuerza bruta la maneja el modulo x con su ventana de tiempo.)

  2. Scanner HTTP: muchos errores 404 desde una misma IP en
     /var/log/httpd/access.log -> alarma + banear IP.

  3. Correo masivo: una cuenta que envia muchos mails (from=) en
     /var/log/maillog -> alarma + bajar el servicio de correo.

Lee los logs de forma incremental (solo lineas nuevas) y cuenta por
ventana de tiempo, igual que el modulo x. Corre en loop.

Las cuentas/IPs en lista blanca nunca se bloquean.
"""

import re
import time
import sys
import os
from datetime import datetime, timedelta

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from alerts.logger import registrar_alarma, registrar_prevencion
from alerts.mailer import enviar_email
from prevention.log_prevention import banear_ip, bajar_correo
from config_loader import obtener_parametro

# Logs que vigila el modulo
RUTA_SECURE = "/var/log/secure"
RUTA_MESSAGES = "/var/log/messages"
RUTA_ACCESS = "/var/log/httpd/access.log"
RUTA_MAILLOG = "/var/log/maillog"


def abrir_al_final(ruta):
    """Abre un log y se posiciona al final (para leer solo lo nuevo).
    Devuelve el archivo abierto, o None si no existe."""
    if not os.path.isfile(ruta):
        return None
    f = open(ruta, "r")
    f.seek(0, os.SEEK_END)
    return f


def main():
    umbral_scanner = int(obtener_parametro("logs", "scanner_404_threshold", "20"))
    umbral_mail = int(obtener_parametro("logs", "mail_threshold", "15"))
    ventana_min = int(obtener_parametro("logs", "ventana_minutos", "10"))
    intervalo = int(obtener_parametro("logs", "check_interval", "10"))
    protegidas = obtener_parametro("logs", "cuentas_protegidas", "asd,root,hips,postfix")
    cuentas_protegidas = protegidas.split(",")
    ventana = timedelta(minutes=ventana_min)

    # Abrir los logs disponibles, posicionados al final
    archivos = {
        "secure": abrir_al_final(RUTA_SECURE),
        "messages": abrir_al_final(RUTA_MESSAGES),
        "access": abrir_al_final(RUTA_ACCESS),
        "maillog": abrir_al_final(RUTA_MAILLOG),
    }

    # Contadores por ventana de tiempo
    fallos_login = {}   # ip -> lista de horas
    scanner_404 = {}    # ip -> lista de horas
    correo = {}         # cuenta -> lista de horas
    ya_alarmadas = []

    print("Modulo iv (analisis de logs) iniciado.")
    print("Vigilando: secure, messages, access.log, maillog.")
    print("Ctrl+C para detener.")

    while True:
        ahora = datetime.now()

        # --- Frente 1: Failed Password en secure y messages ---
        for clave in ["secure", "messages"]:
            f = archivos[clave]
            if f is None:
                continue
            for linea in f.readlines():
                if "Failed password" in linea or "authentication failure" in linea:
                    m = re.search(r"from (\d+\.\d+\.\d+\.\d+)", linea)
                    ip = m.group(1) if m else "N/A"
                    fallos_login.setdefault(ip, []).append(ahora)
                    fallos_login[ip] = [t for t in fallos_login[ip] if t >= ahora - ventana]
                    # Solo alarma (la prevencion la maneja el modulo x)
                    nombre = "FAILED_LOGIN_MULTIPLE"
                    if len(fallos_login[ip]) >= 5 and (nombre + ip) not in ya_alarmadas:
                        ya_alarmadas.append(nombre + ip)
                        print("[!] FAILED_LOGIN_MULTIPLE ->", ip)
                        ip_db = ip if ip != "N/A" else None
                        registrar_alarma("FAILED_LOGIN_MULTIPLE", "logs", ip_db)

        # --- Frente 2: Scanner HTTP en access.log ---
        f = archivos["access"]
        if f is not None:
            for linea in f.readlines():
                if " 404 " not in linea:
                    continue
                ip = linea.split()[0]
                scanner_404.setdefault(ip, []).append(ahora)
                scanner_404[ip] = [t for t in scanner_404[ip] if t >= ahora - ventana]
                if len(scanner_404[ip]) >= umbral_scanner and ("scan" + ip) not in ya_alarmadas:
                    ya_alarmadas.append("scan" + ip)
                    print("[!] SCANNER_HTTP ->", ip, "(" + str(len(scanner_404[ip])), "404)")
                    alarma_id = registrar_alarma("SCANNER_HTTP", "logs", ip)
                    resultado = banear_ip(ip)
                    registrar_prevencion(alarma_id, "banear IP " + ip, resultado)
                    enviar_email(
                        "[HIPS ALERTA] Scanner HTTP desde " + ip,
                        "La IP " + ip + " genero muchos errores 404 (escaneo). "
                        "Accion: IP baneada (" + resultado + ").",
                    )

        # --- Frente 3: Correo masivo en maillog ---
        f = archivos["maillog"]
        if f is not None:
            for linea in f.readlines():
                m = re.search(r"from=<([^>]+)>", linea)
                if not m:
                    continue
                cuenta = m.group(1)
                correo.setdefault(cuenta, []).append(ahora)
                correo[cuenta] = [t for t in correo[cuenta] if t >= ahora - ventana]
                if len(correo[cuenta]) >= umbral_mail and ("mail" + cuenta) not in ya_alarmadas:
                    usuario = cuenta.split("@")[0]
                    if usuario in cuentas_protegidas:
                        continue
                    ya_alarmadas.append("mail" + cuenta)
                    print("[!] MAIL_QUEUE_ALTA ->", cuenta)
                    alarma_id = registrar_alarma("MAIL_QUEUE_ALTA", "logs", None)
                    # Prevencion del enunciado: bajar el servicio de correo
                    resultado = bajar_correo()
                    registrar_prevencion(alarma_id, "bajar servicio de correo", resultado)
                    enviar_email(
                        "[HIPS ALERTA] Correo masivo desde " + cuenta,
                        "La cuenta " + cuenta + " envio muchos mails (spam). "
                        "Accion: servicio de correo detenido (" + resultado + ").",
                    )

        time.sleep(intervalo)


if __name__ == "__main__":
    main()
