"""CTF 07 - DocViewer (Path Traversal / LFI).

Aplicação intencionalmente vulnerável, usada apenas em laboratório.
A falha está em montar o caminho do arquivo com a entrada do usuário sem
normalizar nem restringir o diretório de documentos.
"""

import os
from pathlib import Path

from flask import Flask, render_template, request

app = Flask(__name__)

FLAG = os.environ.get("FLAG", "flag{p4th_tr4v3rs4l_b4s1c4}")
FLAG_PATH = Path("/tmp/flag.txt")
FLAG_PATH.write_text(FLAG + "\n", encoding="utf-8")

DOCS_DIR = Path(__file__).resolve().parent / "documents"

DOCUMENTS = [
    {"name": "readme.txt", "title": "Leia-me", "size": "1 KB"},
    {"name": "contrato.txt", "title": "Contrato de prestação de serviços", "size": "2 KB"},
    {"name": "relatorio.txt", "title": "Relatório financeiro", "size": "3 KB"},
]


@app.get("/")
def index():
    return render_template("index.html", documents=DOCUMENTS)


@app.get("/download")
def download():
    filename = request.args.get("file", "").strip()
    if not filename:
        return render_template(
            "index.html",
            documents=DOCUMENTS,
            error="Informe o arquivo que deseja baixar.",
        ), 400

    # VULNERÁVEL POR DESIGN: o nome informado é concatenado ao diretório de
    # documentos sem normalização. Sequências como ../ saem do diretório.
    path = os.path.join(DOCS_DIR, filename)

    try:
        content = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return render_template(
            "index.html",
            documents=DOCUMENTS,
            error=f"Não foi possível ler {filename}: {exc}",
        ), 404

    return render_template(
        "index.html",
        documents=DOCUMENTS,
        selected=filename,
        content=content,
    )


@app.get("/health")
def health():
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
