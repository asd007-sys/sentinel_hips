"""
Crear baseline de integridad - sentinel_hips (modulo i)
--------------------------------------------------------
Calcula el hash SHA-256 de cada archivo critico y lo guarda en la
tabla baseline_integridad. Hay que correrlo UNA VEZ con el sistema
limpio, antes de usar el modulo de deteccion.

Si se corre de nuevo, actualiza los hashes (sirve cuando hubo un
cambio legitimo, ej. agregaste un usuario a proposito).

USO:
  sudo venv/bin/python detection/crear_baseline.py
"""

import hashlib
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import psycopg2
from dotenv import load_dotenv

load_dotenv()

# Archivos criticos a vigilar
ARCHIVOS = [
    "/etc/passwd",
    "/etc/shadow",
    "/bin/ls",
    "/bin/ps",
    "/usr/bin/netstat",
]


def calcular_hash(ruta):
    """Devuelve el hash SHA-256 del archivo, o None si no se puede leer."""
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


def main():
    conn = conectar()
    cur = conn.cursor()

    print("Creando baseline de integridad...")
    for ruta in ARCHIVOS:
        h = calcular_hash(ruta)
        if h is None:
            print("  No se pudo leer:", ruta, "(se omite)")
            continue

        # Insertar o actualizar el hash de este archivo
        cur.execute(
            "INSERT INTO baseline_integridad (ruta_archivo, hash_sha256) "
            "VALUES (%s, %s) "
            "ON CONFLICT (ruta_archivo) "
            "DO UPDATE SET hash_sha256 = %s, actualizado = now();",
            (ruta, h, h),
        )
        print("  Guardado:", ruta)

    conn.commit()
    cur.close()
    conn.close()
    print("Baseline creado. Ya se puede usar el modulo de deteccion.")


if __name__ == "__main__":
    main()
