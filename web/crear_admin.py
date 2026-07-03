"""
Crear usuario admin de la web - sentinel_hips
----------------------------------------------
Crea un usuario para entrar a la interfaz web, guardando la contrasena
hasheada (nunca en texto plano) en la tabla usuarios_web.

USO:
  python web/crear_admin.py <usuario> <contrasena>
  ej: python web/crear_admin.py admin miclave123
"""

import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import psycopg2
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv

load_dotenv()


def main():
    if len(sys.argv) != 3:
        print("Uso: python web/crear_admin.py <usuario> <contrasena>")
        return

    usuario = sys.argv[1]
    password = sys.argv[2]
    hash_pw = generate_password_hash(password)

    conn = psycopg2.connect(
        dbname=os.getenv("HIPS_DB_NAME"),
        user=os.getenv("HIPS_DB_USER"),
        password=os.getenv("HIPS_DB_PASSWORD"),
        host=os.getenv("HIPS_DB_HOST"),
        port=os.getenv("HIPS_DB_PORT"),
    )
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO usuarios_web (username, password_hash, rol) "
        "VALUES (%s, %s, 'admin');",
        (usuario, hash_pw),
    )
    conn.commit()
    cur.close()
    conn.close()
    print("Usuario", usuario, "creado.")


if __name__ == "__main__":
    main()
