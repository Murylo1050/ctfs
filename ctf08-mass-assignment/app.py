"""CTF 08 - ProfileHub (Mass Assignment).

Aplicação intencionalmente vulnerável, usada apenas em laboratório.
A falha está em copiar todos os campos enviados pelo cliente para o registro
do usuário, incluindo campos que o cliente não deveria controlar (role).
"""

import os
import secrets

from flask import Flask, redirect, render_template, request, session, url_for

app = Flask(__name__)
# Um único worker: o segredo aleatório permanece consistente durante o processo.
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

FLAG = os.environ.get("FLAG", "flag{m4ss_4ss1gnm3nt_adm1n}")

USERS = {
    "guest": {
        "username": "guest",
        "password": "guest",
        "name": "Visitante",
        "email": "guest@example.com",
        "role": "user",
    }
}


def current_user():
    username = session.get("user")
    if not username:
        return None
    return USERS.get(username)


@app.get("/")
def index():
    if current_user():
        return redirect(url_for("profile"))
    return render_template("login.html")


@app.post("/login")
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    user = USERS.get(username)
    if user is None or user["password"] != password:
        return render_template("login.html", error="Usuário ou senha inválidos."), 401

    session["user"] = username
    return redirect(url_for("profile"))


@app.get("/profile")
def profile():
    user = current_user()
    if user is None:
        return redirect(url_for("index"))

    return render_template("profile.html", user=user)


@app.post("/profile")
def update_profile():
    user = current_user()
    if user is None:
        return redirect(url_for("index"))

    # VULNERÁVEL POR DESIGN: mass assignment. Todos os campos enviados são
    # copiados para o registro, inclusive "role".
    updates = request.form.to_dict()
    updates.pop("username", None)
    user.update(updates)

    return redirect(url_for("profile"))


@app.get("/admin")
def admin():
    user = current_user()
    if user is None:
        return redirect(url_for("index"))
    if user.get("role") != "admin":
        return render_template("profile.html", user=user, error="Acesso restrito a administradores."), 403

    return render_template("admin.html", user=user, flag=FLAG)


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
