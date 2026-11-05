"""CTF 04 - NetCheck (Command Injection).

Aplicação intencionalmente vulnerável, usada apenas em laboratório.
A falha está no uso de shell=True com entrada não validada do usuário.
"""

import os
import subprocess

from flask import Flask, render_template, request

app = Flask(__name__)

FLAG = os.environ.get("FLAG", "flag{c0mm4nd_1nj3ct10n_b4s1c4}")
FLAG_PATH = "/tmp/flag.txt"
with open(FLAG_PATH, "w", encoding="utf-8") as flag_file:
    flag_file.write(FLAG + "\n")


@app.route("/", methods=["GET", "POST"])
def index():
    host = ""
    output = None
    error = None

    if request.method == "POST":
        host = request.form.get("host", "").strip()
        if not host:
            error = "Informe um host ou endereço IP."
        else:
            # VULNERÁVEL POR DESIGN: entrada concatenada em um comando executado pelo shell.
            command = f"getent hosts {host}"
            try:
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                output = result.stdout + result.stderr
                if not output.strip():
                    output = "(sem saída)"
            except subprocess.TimeoutExpired:
                error = "O comando excedeu o tempo limite de 5 segundos."

    return render_template("index.html", host=host, output=output, error=error)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
