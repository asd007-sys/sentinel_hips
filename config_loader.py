"""
Helper de configuracion - sentinel_hips
----------------------------------------
Lee los parametros de cada modulo desde la tabla configuracion_modulos.
Asi los umbrales se pueden cambiar desde la web sin tocar el codigo.
"""

import os

import psycopg2
from dotenv import load_dotenv

load_dotenv()


def _conectar():
    return psycopg2.connect(
        dbname=os.getenv("HIPS_DB_NAME"),
        user=os.getenv("HIPS_DB_USER"),
        password=os.getenv("HIPS_DB_PASSWORD"),
        host=os.getenv("HIPS_DB_HOST"),
        port=os.getenv("HIPS_DB_PORT"),
    )


def obtener_parametro(modulo, parametro, por_defecto=None):
    """
    Devuelve el valor de un parametro de configuracion (como texto).
    Si no lo encuentra, devuelve por_defecto.
    """
    conn = _conectar()
    cur = conn.cursor()
    cur.execute(
        "SELECT valor FROM configuracion_modulos "
        "WHERE modulo = %s AND parametro = %s AND activo = true;",
        (modulo, parametro),
    )
    fila = cur.fetchone()
    cur.close()
    conn.close()

    if fila:
        return fila[0]
    return por_defecto
