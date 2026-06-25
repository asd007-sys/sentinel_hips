"""
Modulo x - Accesos Invalidos - sentinel_hips
---------------------------------------------
Detecta fuerza bruta y credential stuffing analizando /var/log/secure.

Maneja dos formatos de linea de fallo de autenticacion:
  1. Con IP de origen (ej. SSH):
     "Failed password for root from 10.0.0.8 port 22 ssh2"
     -> se cuenta por IP, prevencion = banear IP.
  2. Sin IP, con usuario (ej. SMTP/saslauthd):
     "pam_unix(smtp:auth): authentication failure; ... user=condorito"
     -> se cuenta por usuario, prevencion = bloquear cuenta.

Logica de ventana de tiempo:
  Si una IP (o usuario) supera max_failed_attempts dentro de
  time_window_minutes -> alarma + prevencion.

Credential stuffing:
  Si una misma IP falla contra muchos usuarios distintos -> CREDENTIAL_STUFFING.

Lee /var/log/secure de forma incremental (solo lineas nuevas).
"""

import re
import time
import sys
import os
from datetime import datetime, timedelta
from collections import defaultdict, deque

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from alerts.logger import registrar_alarma, registrar_prevencion
from alerts.mailer import enviar_email
from prevention.access_prevention import banear_ip, bloquear_cuenta
from config_loader import obtener_parametro

RUTA_LOG = "/var/log/secure"

# Patrones para extraer la informacion de cada tipo de linea
# Caso 1: fallo con IP (SSH y similares)
RE_FALLO_IP = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)")
# Caso 2: fallo sin IP, con user= (SMTP/saslauthd)
RE_FALLO_USER = re.compile(r"authentication failure;.*user=(\S+)")

# El timestamp del log es tipo "Jun  2 10:43:45" (sin anio)
RE_TIMESTAMP = re.compile(r"^(\w{3})\s+(\d+)\s+(\d+):(\d+):(\d+)")

MESES = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def parsear_timestamp(linea):
    """Convierte el timestamp de la linea a un objeto datetime."""
    m = RE_TIMESTAMP.match(linea)
    if not m:
        return None
    mes, dia, hora, minuto, segundo = m.groups()
    # El log no trae anio, usamos el anio actual
    anio = datetime.now().year
    return datetime(anio, MESES[mes], int(dia), int(hora), int(minuto), int(segundo))


def parsear_linea(linea):
    """
    Devuelve una tupla (clave, tipo, usuario, ip, timestamp) si la linea
    es un fallo de autenticacion, o None si no lo es.

    tipo es "ip" o "usuario" segun como se va a contar.
    """
    ts = parsear_timestamp(linea)
    if ts is None:
        return None

    # Caso 1: fallo con IP
    m = RE_FALLO_IP.search(linea)
    if m:
        usuario, ip = m.group(1), m.group(2)
        return (ip, "ip", usuario, ip, ts)

    # Caso 2: fallo sin IP, con usuario
    m = RE_FALLO_USER.search(linea)
    if m:
        usuario = m.group(1)
        return (usuario, "usuario", usuario, None, ts)

    return None


def main():
    max_intentos = int(obtener_parametro("accesos", "max_failed_attempts", "5"))
    ventana_min = int(obtener_parametro("accesos", "time_window_minutes", "10"))
    # Lista blanca de IPs que nunca se banean (ej. la IP de administracion)
    whitelist = obtener_parametro("accesos", "ip_whitelist", "127.0.0.1")
    lista_blanca = [i.strip() for i in whitelist.split(",")]

    ventana = timedelta(minutes=ventana_min)

    # Por cada clave (ip o usuario) guardamos los timestamps de los fallos
    fallos = defaultdict(deque)
    # Para credential stuffing: por IP, que usuarios distintos fallaron
    usuarios_por_ip = defaultdict(set)
    # Claves ya alarmadas, para no alarmar repetido
    ya_alarmadas = set()

    print("Modulo x (accesos invalidos) iniciado.")
    print("Umbral:", max_intentos, "intentos en", ventana_min, "minutos.")
    print("Ctrl+C para detener.")

    # Abrimos el log y nos posicionamos al final (solo lineas nuevas)
    with open(RUTA_LOG, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            linea = f.readline()
            if not linea:
                time.sleep(1)
                continue

            datos = parsear_linea(linea)
            if datos is None:
                continue

            clave, tipo, usuario, ip, ts = datos

            # Registrar el fallo en la ventana
            fallos[clave].append(ts)
            if ip:
                usuarios_por_ip[ip].add(usuario)

            # Sacar de la cola los fallos viejos (fuera de la ventana)
            limite = ts - ventana
            while fallos[clave] and fallos[clave][0] < limite:
                fallos[clave].popleft()

            # Evaluar si supera el umbral
            if len(fallos[clave]) >= max_intentos and clave not in ya_alarmadas:
                ya_alarmadas.add(clave)

                # Decidir tipo de alarma: credential stuffing si una IP
                # ataco muchos usuarios distintos
                es_stuffing = ip and len(usuarios_por_ip[ip]) >= max_intentos
                tipo_alarma = "CREDENTIAL_STUFFING" if es_stuffing else "ACCESO_INVALIDO_REPETIDO"

                print("[!]", tipo_alarma, "->", clave,
                      "(" + str(len(fallos[clave])), "fallos)")

                alarma_id = registrar_alarma(tipo_alarma, "accesos", ip)

                # Prevencion segun el tipo de dato disponible
                if tipo == "ip":
                    if ip in lista_blanca:
                        accion = "IP " + ip + " en lista blanca, no se banea"
                        resultado = "exito"
                    else:
                        resultado = banear_ip(ip)
                        accion = "banear IP " + ip
                else:
                    resultado = bloquear_cuenta(usuario)
                    accion = "bloquear cuenta " + usuario

                registrar_prevencion(alarma_id, accion, resultado)

                origen = ip if ip else ("usuario " + usuario)
                enviar_email(
                    "[HIPS ALERTA] " + tipo_alarma + " desde " + origen,
                    "Se detectaron " + str(len(fallos[clave])) + " intentos de "
                    "acceso fallidos desde " + origen + " en los ultimos " +
                    str(ventana_min) + " minutos. Accion tomada: " + accion +
                    " (" + resultado + ").",
                )


if __name__ == "__main__":
    main()
