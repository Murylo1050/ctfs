"""Serviço interno de cálculo de frete da VulnShop.

VULNERÁVEL POR DESIGN: o CEP e o peso recebidos pela API principal são
concatenados em um comando executado com shell=True. A flag de Command
Injection fica somente neste container, separada do banco da loja.

O serviço não publica porta no host; só é alcançável pela rede Docker.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from flask import Flask, jsonify, request

FLAG = os.environ.get("FLAG_CMDI", "flag{cmdi_fr3t3_c4lc}")
FLAG_PATH = Path("/tmp/flag.txt")
FLAG_PATH.write_text(FLAG + "\n", encoding="utf-8")

app = Flask(__name__)


@app.post("/quote")
def quote():
    data = request.get_json(silent=True) or {}
    cep = str(data.get("cep", "")).strip()
    weight = str(data.get("weight", "1")).strip() or "1"

    if not cep:
        return jsonify(error="Informe um CEP."), 400

    # VULNERÁVEL POR DESIGN: entrada do usuário concatenada em um comando de
    # shell. Metacaracteres como ;, && e | permitem executar outros comandos.
    command = f"bash /app/scripts/frete.sh {cep} {weight}"

    try:
        proc = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        return jsonify(error="O cálculo demorou demais para responder."), 504

    output = (proc.stdout or "") + (proc.stderr or "")
    return jsonify(
        output=output.strip(),
        exit_code=proc.returncode,
        weight=weight,
    )


@app.get("/health")
def health():
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
