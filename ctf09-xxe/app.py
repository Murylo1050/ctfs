"""CTF 09 - ImportaXML (XXE).

Aplicação intencionalmente vulnerável, usada apenas em laboratório.
A falha está em processar XML com resolução de entidades externas habilitada.
"""

import os
from pathlib import Path

from flask import Flask, render_template, request
from lxml import etree

app = Flask(__name__)

FLAG = os.environ.get("FLAG", "flag{xxe_f1l3_r34d}")
FLAG_PATH = Path("/tmp/flag.txt")
FLAG_PATH.write_text(FLAG + "\n", encoding="utf-8")

SAMPLE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<produto>
  <nome>Caneca personalizada</nome>
  <preco>29.90</preco>
  <descricao>Caneca de cerâmica com estampa</descricao>
</produto>"""


def parse_product(xml_text: str) -> dict:
    # VULNERÁVEL POR DESIGN: resolve_entities e load_dtd habilitados.
    parser = etree.XMLParser(
        resolve_entities=True,
        load_dtd=True,
        no_network=True,
        huge_tree=False,
    )
    root = etree.fromstring(xml_text.encode("utf-8"), parser=parser)

    fields = {}
    for field in ("nome", "preco", "descricao"):
        node = root.find(field)
        fields[field] = node.text if node is not None and node.text else ""

    return fields


@app.route("/", methods=["GET", "POST"])
def index():
    xml = SAMPLE_XML
    result = None
    error = None

    if request.method == "POST":
        xml = request.form.get("xml", "")
        if not xml.strip():
            error = "Envie um documento XML."
        else:
            try:
                result = parse_product(xml)
            except etree.XMLSyntaxError as exc:
                error = f"XML inválido: {exc}"

    return render_template("index.html", xml=xml, result=result, error=error)


@app.get("/health")
def health():
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
