"""
Modulo i - Integridad de Archivos - sentinel_hips
--------------------------------------------------
Detecta modificaciones en archivos criticos del sistema
(/etc/passwd, /etc/shadow y binarios clave).

Compara el hash actual de cada archivo contra el hash de referencia
guardado en la tabla baseline_integridad. Si no coinciden, el archivo
fue modificado -> alarma.

IMPORTANTE: antes de usar este modulo hay que crear el baseline una vez
con: sudo venv/bin/python detection/crear_baseline.py

Prevencion: solo alarma y avisa al admin (no modifica los archivos).
Corre en loop cada check_interval segundos.
"""

import hashlib
import time
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import psycopg2
from dotenv import load_dotenv

from alerts.logger import registrar_alarma
from alerts.mailer import enviar_email
from config_loader import obtener_parametro

load_dotenv()


def tipo_alarma_para(ruta):
    """
    Devuelve el nombre de alarma especifico segun el archivo modificado.
    Alinea con el ejemplo del enunciado (ej. MODIFICACION_PASSWD).
    """
    if ruta == "/etc/passwd":
        return "MODIFICACION_PASSWD"
    if ruta == "/etc/shadow":
        return "MODIFICACION_SHADOW"
    # El resto son binarios del sistema
    return "MODIFICACION_BINARIO"


def calcular_hash(ruta):
    """Devuelve el hash SHA-256 actual del archivo, o None si no se puede leer."""
    try:
        h = hashlib.sha256()
        with open(ruta, "rb") as f:
            h.update(f.read())
        return h.hexdigest()
    except OSError:
        return None


def conectar():
    return psycopg2.connect(
        dbname=os.getenv("HIPS_DB_NAME"),
        user=os.getenv("HIPS_DB_USER"),
        password=os.getenv("HIPS_DB_PASSWORD"),
        host=os.getenv("HIPS_DB_HOST"),
        port=os.getenv("HIPS_DB_PORT"),
    )


def leer_baseline():
    """Devuelve un diccionario {ruta: hash_guardado} desde la base."""
    conn = conectar()
    cur = conn.cursor()
    cur.execute("SELECT ruta_archivo, hash_sha256 FROM baseline_integridad;")
    filas = cur.fetchall()
    cur.close()
    conn.close()
    baseline = {}
    for ruta, h in filas:
        baseline[ruta] = h
    return baseline


def main():
    intervalo = int(obtener_parametro("integridad", "check_interval", "30"))

    baseline = leer_baseline()
    if not baseline:
        print("ERROR: el baseline esta vacio.")
        print("Primero corre: sudo venv/bin/python detection/crear_baseline.py")
        return

    ya_alarmados = []

    print("Modulo i (integridad de archivos) iniciado.")
    print("Vigilando", len(baseline), "archivos. Intervalo:", intervalo, "segundos.")
    print("Ctrl+C para detener.")

    while True:
        for ruta, hash_guardado in baseline.items():
            hash_actual = calcular_hash(ruta)

            # Si el hash cambio (y el archivo se pudo leer) -> modificacion
            if hash_actual is not None and hash_actual != hash_guardado:
                if ruta not in ya_alarmados:
                    ya_alarmados.append(ruta)
                    tipo = tipo_alarma_para(ruta)
                    print("[!]", tipo, "->", ruta)

                    registrar_alarma(tipo, "integridad", None)
                    enviar_email(
                        "[HIPS ALERTA] Archivo critico modificado: " + ruta,
                        "Se detecto una modificacion en el archivo critico " + ruta +
                        ". El hash actual no coincide con el baseline. "
                        "Revisar si el cambio es legitimo.",
                    )

        time.sleep(intervalo)


if __name__ == "__main__":
    main()
