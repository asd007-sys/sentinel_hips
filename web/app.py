"""
Interfaz web del HIPS - sentinel_hips
--------------------------------------
Web basica con Flask. Permite (lo que pide el enunciado):
  - Login con usuario y contrasena.
  - Ver las alarmas detectadas (dashboard).
  - Configurar los umbrales de los modulos.

USO:
  sudo venv/bin/python web/app.py
  Despues abrir en el navegador: http://localhost:5000
"""

import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, request, redirect, url_for, session
import psycopg2
from werkzeug.security import check_password_hash
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
# Clave para las sesiones (en un proyecto real iria en el .env)
app.secret_key = os.getenv("HIPS_WEB_SECRET", "cambiar_esta_clave")


def conectar():
    return psycopg2.connect(
        dbname=os.getenv("HIPS_DB_NAME"),
        user=os.getenv("HIPS_DB_USER"),
        password=os.getenv("HIPS_DB_PASSWORD"),
        host=os.getenv("HIPS_DB_HOST"),
        port=os.getenv("HIPS_DB_PORT"),
    )


@app.route("/", methods=["GET", "POST"])
def login():
    """Pagina de login."""
    error = None
    if request.method == "POST":
        usuario = request.form["usuario"]
        password = request.form["password"]

        conn = conectar()
        cur = conn.cursor()
        cur.execute(
            "SELECT password_hash FROM usuarios_web WHERE username = %s;",
            (usuario,),
        )
        fila = cur.fetchone()
        cur.close()
        conn.close()

        # Verificar usuario y contrasena
        if fila and check_password_hash(fila[0], password):
            session["usuario"] = usuario
            return redirect(url_for("dashboard"))
        else:
            error = "Usuario o contrasena incorrectos."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.pop("usuario", None)
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    """Muestra las alarmas detectadas."""
    if "usuario" not in session:
        return redirect(url_for("login"))

    conn = conectar()
    cur = conn.cursor()
    cur.execute(
        "SELECT timestamp, tipo_alarma, ip_origen, modulo, resuelta "
        "FROM alarmas ORDER BY timestamp DESC LIMIT 100;"
    )
    alarmas = cur.fetchall()
    cur.close()
    conn.close()

    return render_template("dashboard.html", alarmas=alarmas, usuario=session["usuario"])


@app.route("/config", methods=["GET", "POST"])
def config():
    """Ver y editar los umbrales de los modulos."""
    if "usuario" not in session:
        return redirect(url_for("login"))

    conn = conectar()
    cur = conn.cursor()

    # Si se envio el formulario, actualizar el valor
    if request.method == "POST":
        id_param = request.form["id"]
        nuevo_valor = request.form["valor"]
        cur.execute(
            "UPDATE configuracion_modulos SET valor = %s WHERE id = %s;",
            (nuevo_valor, id_param),
        )
        conn.commit()

    # Traer toda la configuracion
    cur.execute(
        "SELECT id, modulo, parametro, valor FROM configuracion_modulos "
        "ORDER BY modulo, parametro;"
    )
    parametros = cur.fetchall()
    cur.close()
    conn.close()

    return render_template("config.html", parametros=parametros, usuario=session["usuario"])


if __name__ == "__main__":
    # host 0.0.0.0 para poder acceder desde fuera de la VM si hace falta
    app.run(host="0.0.0.0", port=5000, debug=True)
