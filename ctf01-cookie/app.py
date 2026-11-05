"""CTF 01 - Cookie Monsters.

Aplicação intencionalmente vulnerável, usada apenas em laboratório.
A falha está no cookie de sessão: ele é apenas base64(JSON) e não é assinado.
"""

import base64
import json
import os

from flask import Flask, make_response, redirect, render_template, request, url_for

app = Flask(__name__)
FLAG = os.environ.get("FLAG", "flag{c00k13s_s4o_cr0c4nt3s}")

# Conta de demonstração. O administrador não possui login válido.
USERS = {"guest": "guest"}


def encode_session(data: dict) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def decode_session(value: str) -> dict:
    try:
        raw = base64.b64decode(value, validate=True)
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except (ValueError, json.JSONDecodeError):
        return {}


def current_session() -> dict:
    return decode_session(request.cookies.get("session", ""))


@app.get("/")
def index():
    if current_session().get("role") == "admin":
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.post("/login")
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if USERS.get(username) != password or username not in USERS:
        return render_template("login.html", error="Usuário ou senha inválidos."), 401

    response = make_response(redirect(url_for("dashboard")))
    response.set_cookie(
        "session",
        encode_session({"user": username, "role": "user"}),
        httponly=True,
        samesite="Lax",
    )
    return response


@app.get("/dashboard")
def dashboard():
    session_data = current_session()
    if not session_data:
        return redirect(url_for("index"))

    if session_data.get("role") == "admin":
        return render_template(
            "dashboard.html",
            user=session_data.get("user", "desconhecido"),
            flag=FLAG,
        )

    return render_template(
        "dashboard.html",
        user=session_data.get("user", "desconhecido"),
        flag=None,
        cookie=request.cookies.get("session", ""),
        session_json=json.dumps(session_data, indent=2, ensure_ascii=False),
    )


@app.get("/logout")
def logout():
    response = make_response(redirect(url_for("index")))
    response.delete_cookie("session")
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
