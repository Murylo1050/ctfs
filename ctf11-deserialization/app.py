"""CTF 11 - Session Store (Insecure Deserialization).

Aplicação intencionalmente vulnerável, usada apenas em laboratório.
A falha está em desserializar com pickle um valor controlado pelo cliente.
"""

import base64
import os
import pickle
from pathlib import Path

from flask import Flask, make_response, render_template, request

app = Flask(__name__)

FLAG = os.environ.get("FLAG", "flag{p1ckl3_d3s3r14l1z4t10n}")
FLAG_PATH = Path("/tmp/flag.txt")
FLAG_PATH.write_text(FLAG + "\n", encoding="utf-8")

DEFAULT_PROFILE = {"name": "visitante", "theme": "escuro"}


def load_profile(raw: str):
    # VULNERÁVEL POR DESIGN: pickle.loads executa código arbitrário durante a
    # desserialização de dados controlados pelo cliente.
    return pickle.loads(base64.b64decode(raw))


def dump_profile(profile: dict) -> str:
    return base64.b64encode(pickle.dumps(profile)).decode("ascii")


def display(profile):
    return profile if isinstance(profile, dict) else repr(profile)


def render_profile(raw: str, profile, error: str | None = None, restored: bool = False):
    response = make_response(
        render_template(
            "index.html",
            raw=raw,
            profile=display(profile),
            error=error,
            restored=restored,
        )
    )
    response.set_cookie("profile", raw, httponly=False, samesite="Lax")
    return response


@app.get("/")
def index():
    raw = request.cookies.get("profile", "")

    if not raw:
        raw = dump_profile(DEFAULT_PROFILE)
        return render_profile(raw, DEFAULT_PROFILE)

    try:
        profile = load_profile(raw)
    except Exception as exc:
        return render_profile(raw, None, error=f"Perfil inválido: {exc}")

    return render_profile(raw, profile)


@app.post("/restore")
def restore():
    raw = request.form.get("profile", "").strip()
    if not raw:
        return render_profile(
            request.cookies.get("profile", ""),
            None,
            error="Informe o backup em base64.",
        )

    try:
        profile = load_profile(raw)
    except Exception as exc:
        return render_profile(raw, None, error=f"Falha ao restaurar o backup: {exc}")

    return render_profile(raw, profile, restored=True)


@app.get("/health")
def health():
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
