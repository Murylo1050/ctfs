"""CTF 05 - TemplateLab (SSTI).

Aplicação intencionalmente vulnerável, usada apenas em laboratório.
A falha está no uso de render_template_string com entrada do usuário.
"""

import os
from pathlib import Path

from flask import Flask, render_template, render_template_string, request
from jinja2 import TemplateSyntaxError

app = Flask(__name__)

FLAG = os.environ.get("FLAG", "flag{sst1_j1nj4_rce}")
FLAG_PATH = Path("/tmp/flag.txt")
FLAG_PATH.write_text(FLAG + "\n", encoding="utf-8")


@app.route("/", methods=["GET", "POST"])
def index():
    name = ""
    preview = None
    error = None

    if request.method == "POST":
        name = request.form.get("name", "")
        if name.strip():
            # VULNERÁVEL POR DESIGN: entrada do usuário interpretada como template Jinja.
            try:
                preview = render_template_string(
                    "Olá, " + name + "! Este é o seu cartão personalizado."
                )
            except TemplateSyntaxError as exc:
                error = f"Erro no template: {exc}"

    return render_template("index.html", name=name, preview=preview, error=error)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
