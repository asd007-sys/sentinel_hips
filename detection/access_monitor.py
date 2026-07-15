"""
Modulo x - Accesos Invalidos - sentinel_hips
---------------------------------------------
Detecta fuerza bruta analizando /var/log/secure.

Maneja dos tipos de fallo de autenticacion:
  1. Con IP (ej. SSH): "Failed password for root from 10.0.0.8"
     -> cuenta por IP, prevencion = banear IP.
  2. Sin IP, con usuario (ej. SMTP): "authentication failure; ... user=condorito"
     -> cuenta por usuario, prevencion = cambiar la contrasena por una aleatoria
        (es lo que pide el enunciado para usuarios atacados).

Si una IP o un usuario supera max_failed_attempts dentro de
time_window_minutes, se genera la alarma y se aplica la prevencion.
"""

import re
import time
import sys
import os
from datetime import datetime, timedelta

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from alerts.logger import registrar_alarma, registrar_prevencion
from alerts.mailer import enviar_email
from prevention.access_prevention import banear_ip, cambiar_password
from config_loader import obtener_parametro

RUTA_LOG = "/var/log/secure"

MESES = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
         "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}


def sacar_fecha(linea):
    """Lee la fecha del inicio de la linea (ej. 'Jun  2 10:43:45')."""
    m = re.match(r"^(\w{3})\s+(\d+)\s+(\d+):(\d+):(\d+)", linea)
    if not m:
        return None
    mes, dia, hora, minuto, seg = m.groups()
    anio = datetime.now().year
    return datetime(anio, MESES[mes], int(dia), int(hora), int(minuto), int(seg))


def analizar_linea(linea):
    """
    Revisa si la linea es un fallo de login.
    Devuelve (clave, ip, usuario) o None si no es un fallo.
    La clave es la IP si la hay, sino el usuario.
    """
    # Caso 1: fallo con IP
    m = re.search(r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)", linea)
    if m:
        usuario = m.group(1)
        ip = m.group(2)
        return (ip, ip, usuario)

    # Caso 2: fallo sin IP, con usuario
    m = re.search(r"authentication failure;.*user=(\S+)", linea)
    if m:
        usuario = m.group(1)
        return (usuario, None, usuario)

    return None


def main():
    max_intentos = int(obtener_parametro("accesos", "max_failed_attempts", "5"))
    ventana_min = int(obtener_parametro("accesos", "time_window_minutes", "10"))
    whitelist = obtener_parametro("accesos", "ip_whitelist", "127.0.0.1")
    lista_blanca = whitelist.split(",")
    # Usuarios protegidos: nunca se les cambia la contrasena (admin, root, etc.)
    protegidos = obtener_parametro("accesos", "usuarios_protegidos", "asd,root,hips")
    usuarios_protegidos = protegidos.split(",")

    # Por cada clave (ip o usuario) guardamos la lista de fechas de sus fallos
    intentos = {}
    ya_alarmadas = []

    print("Modulo x (accesos invalidos) iniciado.")
    print("Umbral:", max_intentos, "intentos en", ventana_min, "minutos.")
    print("Ctrl+C para detener.")

    f = open(RUTA_LOG, "r")
    f.seek(0, os.SEEK_END)   # empezar a leer desde el final (solo lineas nuevas)

    while True:
        linea = f.readline()
        if not linea:
            time.sleep(1)
            continue

        fecha = sacar_fecha(linea)
        if fecha is None:
            continue

        datos = analizar_linea(linea)
        if datos is None:
            continue

        clave, ip, usuario = datos

        # Agregar este fallo a la lista de la clave
        if clave not in intentos:
            intentos[clave] = []
        intentos[clave].append(fecha)

        # Quedarnos solo con los fallos dentro de la ventana de tiempo
        limite = fecha - timedelta(minutes=ventana_min)
        intentos[clave] = [f for f in intentos[clave] if f >= limite]

        # Si supera el umbral y no la alarmamos antes -> actuar
        if len(intentos[clave]) >= max_intentos and clave not in ya_alarmadas:
            ya_alarmadas.append(clave)
            cantidad = len(intentos[clave])
            print("[!] ACCESO_INVALIDO_REPETIDO ->", clave, "(" + str(cantidad), "fallos)")

            alarma_id = registrar_alarma("ACCESO_INVALIDO_REPETIDO", "accesos", ip)

            # Elegir la prevencion segun tengamos IP o solo usuario
            if ip is not None:
                if ip in lista_blanca:
                    accion = "IP " + ip + " en lista blanca, no se banea"
                    resultado = "exito"
                else:
                    resultado = banear_ip(ip)
                    accion = "banear IP " + ip
            else:
                # Ataque por usuario: cambiar su contrasena por una aleatoria
                if usuario in usuarios_protegidos:
                    accion = "usuario " + usuario + " protegido, no se cambia password"
                    resultado = "exito"
                else:
                    resultado = cambiar_password(usuario)
                    accion = "cambiar password aleatoria de " + usuario

            registrar_prevencion(alarma_id, accion, resultado)

            origen = ip if ip else ("usuario " + usuario)
            enviar_email(
                "[HIPS ALERTA] Acceso invalido repetido desde " + origen,
                "Se detectaron " + str(cantidad) + " intentos fallidos desde " +
                origen + " en " + str(ventana_min) + " minutos. " +
                "Accion tomada: " + accion + " (" + resultado + ").",
            )


if __name__ == "__main__":
    main()
"""
Modulo x - Accesos Invalidos - sentinel_hips
---------------------------------------------
Detecta fuerza bruta analizando /var/log/secure.

Maneja dos tipos de fallo de autenticacion:
  1. Con IP (ej. SSH): "Failed password for root from 10.0.0.8"
     -> cuenta por IP, prevencion = banear IP.
  2. Sin IP, con usuario (ej. SMTP): "authentication failure; ... user=condorito"
     -> cuenta por usuario, prevencion = cambiar la contrasena por una aleatoria
        (es lo que pide el enunciado para usuarios atacados).

Si una IP o un usuario supera max_failed_attempts dentro de
time_window_minutes, se genera la alarma y se aplica la prevencion.
"""

import re
import time
import sys
import os
from datetime import datetime, timedelta

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from alerts.logger import registrar_alarma, registrar_prevencion
from alerts.mailer import enviar_email
from prevention.access_prevention import banear_ip, cambiar_password
from config_loader import obtener_parametro

RUTA_LOG = "/var/log/secure"

MESES = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
         "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}


def sacar_fecha(linea):
    """Lee la fecha del inicio de la linea (ej. 'Jun  2 10:43:45')."""
    m = re.match(r"^(\w{3})\s+(\d+)\s+(\d+):(\d+):(\d+)", linea)
    if not m:
        return None
    mes, dia, hora, minuto, seg = m.groups()
    anio = datetime.now().year
    return datetime(anio, MESES[mes], int(dia), int(hora), int(minuto), int(seg))


def analizar_linea(linea):
    """
    Revisa si la linea es un fallo de login.
    Devuelve (clave, ip, usuario) o None si no es un fallo.
    La clave es la IP si la hay, sino el usuario.
    """
    # Caso 1: fallo con IP
    m = re.search(r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)", linea)
    if m:
        usuario = m.group(1)
        ip = m.group(2)
        return (ip, ip, usuario)

    # Caso 2: fallo sin IP, con usuario
    m = re.search(r"authentication failure;.*user=(\S+)", linea)
    if m:
        usuario = m.group(1)
        return (usuario, None, usuario)

    return None


def main():
    max_intentos = int(obtener_parametro("accesos", "max_failed_attempts", "5"))
    ventana_min = int(obtener_parametro("accesos", "time_window_minutes", "10"))
    whitelist = obtener_parametro("accesos", "ip_whitelist", "127.0.0.1")
    lista_blanca = whitelist.split(",")
    # Usuarios protegidos: nunca se les cambia la contrasena (admin, root, etc.)
    protegidos = obtener_parametro("accesos", "usuarios_protegidos", "asd,root,hips")
    usuarios_protegidos = protegidos.split(",")

    # Por cada clave (ip o usuario) guardamos la lista de fechas de sus fallos
    intentos = {}
    ya_alarmadas = []

    print("Modulo x (accesos invalidos) iniciado.")
    print("Umbral:", max_intentos, "intentos en", ventana_min, "minutos.")
    print("Ctrl+C para detener.")

    def abrir_al_final():
        """Abre el log posicionado al final. Devuelve None si aun no existe."""
        if not os.path.isfile(RUTA_LOG):
            return None
        fh = open(RUTA_LOG, "r")
        fh.seek(0, os.SEEK_END)   # solo lineas nuevas
        return fh

    # El log puede no existir todavia cuando arranca el orquestador.
    # En vez de crashear con FileNotFoundError, esperamos a que aparezca.
    f = abrir_al_final()

    while True:
        if f is None:
            time.sleep(1)
            f = abrir_al_final()
            continue

        linea = f.readline()
        if not linea:
            time.sleep(1)
            continue

        fecha = sacar_fecha(linea)
        if fecha is None:
            continue

        datos = analizar_linea(linea)
        if datos is None:
            continue

        clave, ip, usuario = datos

        # Agregar este fallo a la lista de la clave
        if clave not in intentos:
            intentos[clave] = []
        intentos[clave].append(fecha)

        # Quedarnos solo con los fallos dentro de la ventana de tiempo
        limite = fecha - timedelta(minutes=ventana_min)
        intentos[clave] = [f for f in intentos[clave] if f >= limite]

        # Si supera el umbral y no la alarmamos antes -> actuar
        if len(intentos[clave]) >= max_intentos and clave not in ya_alarmadas:
            ya_alarmadas.append(clave)
            cantidad = len(intentos[clave])
            print("[!] ACCESO_INVALIDO_REPETIDO ->", clave, "(" + str(cantidad), "fallos)")

            alarma_id = registrar_alarma("ACCESO_INVALIDO_REPETIDO", "accesos", ip)

            # Elegir la prevencion segun tengamos IP o solo usuario
            if ip is not None:
                if ip in lista_blanca:
                    accion = "IP " + ip + " en lista blanca, no se banea"
                    resultado = "exito"
                else:
                    resultado = banear_ip(ip)
                    accion = "banear IP " + ip
            else:
                # Ataque por usuario: cambiar su contrasena por una aleatoria
                if usuario in usuarios_protegidos:
                    accion = "usuario " + usuario + " protegido, no se cambia password"
                    resultado = "exito"
                else:
                    resultado = cambiar_password(usuario)
                    accion = "cambiar password aleatoria de " + usuario

            registrar_prevencion(alarma_id, accion, resultado)

            origen = ip if ip else ("usuario " + usuario)
            enviar_email(
                "[HIPS ALERTA] Acceso invalido repetido desde " + origen,
                "Se detectaron " + str(cantidad) + " intentos fallidos desde " +
                origen + " en " + str(ventana_min) + " minutos. " +
                "Accion tomada: " + accion + " (" + resultado + ").",
            )


if __name__ == "__main__":
    main()
