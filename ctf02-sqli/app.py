"""CTF 02 - SQLi Login.

Aplicação intencionalmente vulnerável, usada apenas em laboratório.
A falha está na montagem da consulta SQL por concatenação de strings.
"""

import os
import secrets
import sqlite3

from flask import Flask, redirect, render_template, request, session, url_for

app = Flask(__name__)
# Um único worker: o segredo aleatório permanece consistente durante o processo.
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

FLAG = os.environ.get("FLAG", "flag{sq1_1nj3ct10n_b4s1c4}")
DATABASE = os.environ.get("DATABASE_PATH", "/tmp/ctf.db")


def init_db() -> None:
    with sqlite3.connect(DATABASE) as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            # A senha do admin é aleatória: o caminho esperado é a SQL Injection.
            db.executemany(
                "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
                [
                    ("admin", secrets.token_urlsafe(32), 1),
                    ("guest", "guest", 0),
                ],
            )


@app.get("/")
def index():
    if session.get("user") == "admin":
        return redirect(url_for("admin"))
    return render_template("login.html")


@app.post("/login")
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # VULNERÁVEL POR DESIGN: entrada do usuário concatenada diretamente na query.
    query = (
        f"SELECT id, username, is_admin FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )

    try:
        with sqlite3.connect(DATABASE) as db:
            db.row_factory = sqlite3.Row
            user = db.execute(query).fetchone()
    except sqlite3.Error as exc:
        return render_template(
            "login.html",
            error=f"Erro ao consultar o banco: {exc}",
        ), 500

    if user is None:
        return render_template("login.html", error="Usuário ou senha inválidos."), 401

    if not user["is_admin"]:
        return render_template(
            "login.html",
            error="Login válido, mas esta conta não é administradora.",
        ), 403

    session["user"] = user["username"]
    return redirect(url_for("admin"))


@app.get("/admin")
def admin():
    if session.get("user") != "admin":
        return redirect(url_for("index"))
    return render_template("admin.html", flag=FLAG)


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


init_db()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
