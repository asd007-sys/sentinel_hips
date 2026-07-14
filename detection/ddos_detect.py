"""
Modulo viii - Deteccion de DDoS - sentinel_hips
------------------------------------------------
Vigila en vivo el trafico DNS buscando ataques de amplificacion (DDoS).

Al arrancar, lanza un tcpdump que captura las queries DNS (puerto 53)
y las escribe a un archivo. Despues, en loop, lee ese archivo y cuenta
cuantas queries manda cada IP dentro de una ventana de tiempo corta.
Si una IP supera ddos_dns_threshold queries -> alarma + banear IP.

Para la demo tambien se puede alimentar el archivo de captura con la
muestra del profesor (copiandola a RUTA_CAPTURA), y el modulo la detecta
igual que trafico real.

Requiere permisos de root (por tcpdump y iptables).
"""

import re
import time
import subprocess
import sys
import os
from datetime import datetime, timedelta

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from alerts.logger import registrar_alarma, registrar_prevencion
from alerts.mailer import enviar_email
from prevention.ddos_prevention import banear_ip
from config_loader import obtener_parametro

# Archivo donde tcpdump escribe la captura de trafico DNS
RUTA_CAPTURA = "/var/log/hips/captura_dns.txt"


def lanzar_tcpdump():
    """
    Lanza tcpdump en segundo plano capturando trafico DNS (puerto 53)
    y escribiendolo a RUTA_CAPTURA. Devuelve el proceso, o None si falla.
    """
    try:
        f = open(RUTA_CAPTURA, "w")
        proceso = subprocess.Popen(
            ["tcpdump", "-l", "-nn", "-p", "port", "53"],
            stdout=f, stderr=subprocess.DEVNULL,
        )
        print("tcpdump lanzado, capturando trafico DNS...")
        return proceso
    except FileNotFoundError:
        print("No se encontro tcpdump. El modulo leera solo el archivo de captura.")
        return None


def analizar_linea(linea):
    """
    Si la linea es una query DNS hacia el servidor (puerto 53), devuelve
    la IP de origen. Sino, devuelve None.

    Acepta el puerto como ".53:" (numero) o ".domain:" (nombre), porque
    tcpdump puede escribirlo de las dos formas segun la opcion -n/-nn.

    Formato tcpdump: '11:00:14.627392 IP 1.2.3.4.38254 > 5.6.7.8.53: ...'
    """
    # Debe ser trafico hacia el puerto DNS (53 o "domain")
    if ".53:" not in linea and ".domain:" not in linea:
        return None
    # Sacar la IP de origen (la que esta antes del ">")
    m = re.match(r"^\d+:\d+:\d+\.\d+ IP (\d+\.\d+\.\d+\.\d+)\.\S+ >", linea)
    if not m:
        return None
    return m.group(1)


def main():
    umbral = int(obtener_parametro("ddos", "ddos_dns_threshold", "30"))
    ventana_seg = int(obtener_parametro("ddos", "ddos_dns_window_seconds", "1"))
    intervalo = int(obtener_parametro("ddos", "check_interval", "5"))
    ventana = timedelta(seconds=ventana_seg)

    print("Modulo viii (DDoS) iniciado.")
    print("Umbral:", umbral, "queries en", ventana_seg, "segundo(s).")
    print("Ctrl+C para detener.")

    # Lanzar la captura en vivo
    proceso_tcpdump = lanzar_tcpdump()
    time.sleep(1)  # darle un momento a tcpdump para crear el archivo

    # Abrir el archivo de captura para leer solo lo nuevo
    if not os.path.isfile(RUTA_CAPTURA):
        open(RUTA_CAPTURA, "w").close()
    f = open(RUTA_CAPTURA, "r")

    queries = {}        # ip -> lista de horas
    ya_alarmadas = []

    try:
        while True:
            for linea in f.readlines():
                ip = analizar_linea(linea)
                if ip is None:
                    continue
                ahora = datetime.now()
                queries.setdefault(ip, []).append(ahora)
                queries[ip] = [t for t in queries[ip] if t >= ahora - ventana]

                if len(queries[ip]) >= umbral and ip not in ya_alarmadas:
                    ya_alarmadas.append(ip)
                    cantidad = len(queries[ip])
                    print("[!] DDOS_DETECTADO ->", ip, "(" + str(cantidad), "queries)")
                    alarma_id = registrar_alarma("DDOS_DETECTADO", "ddos", ip)
                    resultado = banear_ip(ip)
                    registrar_prevencion(alarma_id, "banear IP " + ip, resultado)
                    enviar_email(
                        "[HIPS ALERTA] Ataque DDoS desde " + ip,
                        "Se detecto un ataque DDoS (amplificacion DNS) desde " + ip +
                        " con " + str(cantidad) + " queries. Accion: IP baneada (" +
                        resultado + ").",
                    )

            time.sleep(intervalo)
    except KeyboardInterrupt:
        print("\nDeteniendo modulo viii...")
        if proceso_tcpdump is not None:
            proceso_tcpdump.terminate()


if __name__ == "__main__":
    main()
