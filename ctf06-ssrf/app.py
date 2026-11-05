"""CTF 06 - URL Preview (SSRF).

Aplicação intencionalmente vulnerável, usada apenas em laboratório.
A falha está em permitir que o servidor faça requisições para a rede interna.
"""

import requests
from flask import Flask, render_template, request

app = Flask(__name__)

BLOCKED = ("localhost", "127.0.0.1", "0.0.0.0", "::1")


@app.route("/", methods=["GET", "POST"])
def index():
    url = ""
    result = None
    error = None

    if request.method == "POST":
        url = request.form.get("url", "").strip()

        if not url.startswith(("http://", "https://")):
            error = "A URL deve começar com http:// ou https://."
        elif any(blocked in url.lower() for blocked in BLOCKED):
            error = "Acesso a endereços locais bloqueado."
        else:
            try:
                response = requests.get(url, timeout=5, allow_redirects=True)
                result = {
                    "status": response.status_code,
                    "url": response.url,
                    "content_type": response.headers.get("Content-Type", "desconhecido"),
                    "body": response.text[:3000],
                }
            except requests.RequestException as exc:
                error = f"Falha ao buscar a URL: {exc}"

    return render_template("index.html", url=url, result=result, error=error)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
