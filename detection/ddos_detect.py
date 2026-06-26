"""
Modulo viii - Deteccion de DDoS - sentinel_hips
------------------------------------------------
Detecta ataques DDoS de amplificacion DNS analizando una captura tcpdump.

Lee un archivo de captura (como el que provee el profesor) y cuenta
cuantas queries DNS manda cada IP de origen al puerto 53. Si una IP
supera ddos_dns_threshold queries dentro de ddos_dns_window_seconds,
se considera un ataque: se genera la alarma y se banea la IP.

Patron del ataque: queries tipo "ANY?" repetidas en rafaga desde la
misma IP (firma clasica de amplificacion DNS).

USO:
  sudo venv/bin/python detection/ddos_detect.py <archivo_captura>
  Si no se pasa archivo, usa la ruta por defecto RUTA_CAPTURA.
"""

import re
import sys
import os
from datetime import datetime, timedelta

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from alerts.logger import registrar_alarma, registrar_prevencion
from alerts.mailer import enviar_email
from prevention.ddos_prevention import banear_ip
from config_loader import obtener_parametro

# Ruta por defecto de la captura a analizar (se puede pasar otra por argumento)
RUTA_CAPTURA = "/var/log/hips/captura_dns.txt"


def analizar_linea(linea):
    """
    Si la linea es una query DNS (puerto 53, tipo ANY), devuelve (ip, hora).
    Sino, devuelve None.
    Formato tcpdump: '11:00:14.627392 IP 1.2.3.4.38254 > 5.6.7.8.53: ... ANY? ...'
    """
    if ".53:" not in linea or "ANY?" not in linea:
        return None
    m = re.match(r"^(\d+):(\d+):(\d+)\.(\d+) IP (\d+\.\d+\.\d+\.\d+)\.\d+ >", linea)
    if not m:
        return None
    hora, minuto, seg, micro, ip = m.groups()
    momento = datetime(2026, 1, 1, int(hora), int(minuto), int(seg),
                       int(micro[:6].ljust(6, "0")))
    return (ip, momento)


def main():
    # Permitir pasar el archivo de captura por argumento
    if len(sys.argv) > 1:
        ruta = sys.argv[1]
    else:
        ruta = RUTA_CAPTURA

    umbral = int(obtener_parametro("ddos", "ddos_dns_threshold", "30"))
    ventana_seg = int(obtener_parametro("ddos", "ddos_dns_window_seconds", "1"))
    ventana = timedelta(seconds=ventana_seg)

    print("Modulo viii (DDoS) - analizando:", ruta)
    print("Umbral:", umbral, "queries en", ventana_seg, "segundo(s).")

    # Por cada IP guardamos las horas de sus queries
    queries = {}
    ya_alarmadas = []

    f = open(ruta, "r")
    for linea in f:
        datos = analizar_linea(linea)
        if datos is None:
            continue
        ip, momento = datos

        # Agregar la query y quedarnos solo con las de la ventana
        if ip not in queries:
            queries[ip] = []
        queries[ip].append(momento)
        limite = momento - ventana
        queries[ip] = [t for t in queries[ip] if t >= limite]

        # Si supera el umbral -> ataque
        if len(queries[ip]) >= umbral and ip not in ya_alarmadas:
            ya_alarmadas.append(ip)
            cantidad = len(queries[ip])
            print("[!] DDOS_DETECTADO ->", ip, "(" + str(cantidad), "queries/seg)")

            alarma_id = registrar_alarma("DDOS_DETECTADO", "ddos", ip)
            resultado = banear_ip(ip)
            registrar_prevencion(alarma_id, "banear IP " + ip, resultado)
            enviar_email(
                "[HIPS ALERTA] Ataque DDoS desde " + ip,
                "Se detecto un ataque DDoS (amplificacion DNS) desde " + ip +
                " con " + str(cantidad) + " queries en " + str(ventana_seg) +
                " segundo(s). Accion tomada: IP baneada (" + resultado + ").",
            )

    f.close()

    if not ya_alarmadas:
        print("No se detectaron ataques DDoS en la captura.")
    else:
        print("Analisis terminado. IPs baneadas:", ", ".join(ya_alarmadas))


if __name__ == "__main__":
    main()
