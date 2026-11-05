"""CTF 03 - NotasWeb (IDOR).

Aplicação intencionalmente vulnerável, usada apenas em laboratório.
A falha está na ausência de verificação de autorização ao acessar uma nota.
"""

import os
import secrets

from flask import Flask, abort, redirect, render_template, request, session, url_for

app = Flask(__name__)
# Um único worker: o segredo aleatório permanece consistente durante o processo.
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

FLAG = os.environ.get("FLAG", "flag{1d0r_n0t4s_d0_adm1n}")

USERS = {"guest": "guest"}

NOTES = {
    1: {
        "owner": "guest",
        "title": "Minha primeira nota",
        "body": "Bem-vindo ao NotasWeb!\n\nUse o menu para acessar suas anotações.",
    },
    2: {
        "owner": "admin",
        "title": "Nota privada do administrador",
        "body": f"Parabéns! Você acessou uma nota que não é sua.\n\n{FLAG}",
    },
    3: {
        "owner": "admin",
        "title": "Rascunho",
        "body": "Não esqueça de revisar as permissões antes do deploy.",
    },
}


@app.get("/")
def index():
    if session.get("user"):
        return redirect(url_for("notes"))
    return render_template("login.html")


@app.post("/login")
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if username not in USERS or USERS[username] != password:
        return render_template("login.html", error="Usuário ou senha inválidos."), 401

    session["user"] = username
    return redirect(url_for("notes"))


@app.get("/notes")
def notes():
    user = session.get("user")
    if not user:
        return redirect(url_for("index"))

    user_notes = [
        {"id": note_id, **note}
        for note_id, note in NOTES.items()
        if note["owner"] == user
    ]
    return render_template("notes.html", user=user, notes=user_notes)


@app.get("/notes/<int:note_id>")
def note(note_id):
    user = session.get("user")
    if not user:
        return redirect(url_for("index"))

    selected_note = NOTES.get(note_id)
    if selected_note is None:
        abort(404)

    # VULNERÁVEL POR DESIGN: não verifica se a nota pertence ao usuário logado.
    return render_template(
        "note.html",
        user=user,
        note_id=note_id,
        note=selected_note,
    )


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
