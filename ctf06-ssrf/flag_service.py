"""Serviço interno do CTF 06.

Não é publicado no host: só pode ser alcançado pela rede Docker.
"""

import os

from flask import Flask, Response

app = Flask(__name__)
FLAG = os.environ.get("FLAG", "flag{ssrf_r3d3_1nt3rn4}")


@app.get("/health")
def health():
    return "ok"


@app.get("/flag")
def flag():
    return Response(FLAG + "\n", mimetype="text/plain")


@app.get("/")
def index():
    return "Serviço interno de flags. Recurso protegido em /flag.\n", 200, {
        "Content-Type": "text/plain; charset=utf-8"
    }


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
