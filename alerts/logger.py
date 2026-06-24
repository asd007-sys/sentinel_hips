"""
Logger central del HIPS - sentinel_hips
----------------------------------------
Escribe las alarmas y las acciones de prevencion en dos lugares a la vez:
  1. Los archivos de log en /var/log/hips/ (formato obligatorio del enunciado)
  2. Las tablas de PostgreSQL (para que el dashboard web las muestre)

Lo usan todos los modulos de deteccion y el modulo de prevencion.

Funciones principales:
  registrar_alarma(tipo_alarma, modulo, ip_origen)  -> devuelve el id de la alarma
  registrar_prevencion(alarma_id, accion, resultado)
"""

import os
from datetime import datetime

import psycopg2
from dotenv import load_dotenv

# Carga las variables del .env (credenciales de la base)
load_dotenv()

# Rutas obligatorias de los logs segun el enunciado (punto 4.4)
LOG_DIR = "/var/log/hips"
LOG_ALARMAS = os.path.join(LOG_DIR, "alarmas.log")
LOG_PREVENCION = os.path.join(LOG_DIR, "prevención.log")


def _conectar():
    """Abre una conexion a la base usando las credenciales del .env."""
    return psycopg2.connect(
        dbname=os.getenv("HIPS_DB_NAME"),
        user=os.getenv("HIPS_DB_USER"),
        password=os.getenv("HIPS_DB_PASSWORD"),
        host=os.getenv("HIPS_DB_HOST"),
        port=os.getenv("HIPS_DB_PORT"),
    )


def _timestamp():
    """Devuelve la fecha en el formato del enunciado: dd/mm/yyyy."""
    return datetime.now().strftime("%d/%m/%Y")


def registrar_alarma(tipo_alarma, modulo, ip_origen=None):
    """
    Registra una alarma en el log y en la base de datos.

    tipo_alarma : nombre del tipo segun el protocolo (ej. SNIFFER_DETECTADO)
    modulo      : nombre del modulo que la genera (ej. sniffer)
    ip_origen   : IP de origen si esta disponible, sino None

    Devuelve el id de la alarma insertada (sirve para el modulo de prevencion).
    """
    # IP que se muestra en el log: N/A si no hay
    ip_log = ip_origen if ip_origen else "N/A"

    # 1. Escribir en el archivo de log con el formato obligatorio
    linea = "{} :: {} :: {}\n".format(_timestamp(), tipo_alarma, ip_log)
    with open(LOG_ALARMAS, "a") as f:
        f.write(linea)

    # 2. Guardar en la tabla alarmas y obtener el id generado
    conn = _conectar()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO alarmas (tipo_alarma, ip_origen, modulo) "
        "VALUES (%s, %s, %s) RETURNING id;",
        (tipo_alarma, ip_origen, modulo),
    )
    alarma_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()

    return alarma_id


def registrar_prevencion(alarma_id, accion, resultado):
    """
    Registra una accion del modulo de prevencion en el log y en la base.

    alarma_id : id de la alarma que disparo la accion
    accion    : descripcion de la accion (ej. "bloqueo IP en firewall")
    resultado : "exito" o "error"
    """
    # 1. Escribir en prevención.log
    linea = "{} :: {} :: {}\n".format(_timestamp(), accion, resultado)
    with open(LOG_PREVENCION, "a") as f:
        f.write(linea)

    # 2. Guardar en la tabla acciones_prevencion
    conn = _conectar()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO acciones_prevencion (alarma_id, accion, resultado) "
        "VALUES (%s, %s, %s);",
        (alarma_id, accion, resultado),
    )
    conn.commit()
    cur.close()
    conn.close()


# Prueba rapida: si se ejecuta el archivo directamente, genera una alarma de test
if __name__ == "__main__":
    print("Probando el logger...")
    nuevo_id = registrar_alarma("SNIFFER_DETECTADO", "sniffer", None)
    print("Alarma registrada con id:", nuevo_id)
    registrar_prevencion(nuevo_id, "prueba de prevencion", "exito")
    print("Accion de prevencion registrada.")
    print("Revisa /var/log/hips/alarmas.log y /var/log/hips/prevención.log")
