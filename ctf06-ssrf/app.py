"""CTF 06 - URL Preview (SSRF).

Aplicação intencionalmente vulnerável, usada apenas em laboratório.
A falha está em permitir que o servidor faça requisições para a rede interna.
"""

import requests
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

BLOCKED = ("localhost", "127.0.0.1", "0.0.0.0", "::1")

# Histórico de exemplo. A entrada interna é uma pista deixada pela "equipe".
PREVIEW_HISTORY = [
    {"url": "https://example.com", "status": 200, "when": "02/10 09:14"},
    {"url": "https://httpbin.org/get", "status": 200, "when": "02/10 09:20"},
    {"url": "http://flag-service:8000/health", "status": 200, "when": "02/10 09:31"},
]

# Catálogo de dependências internas exposto por um endpoint de diagnóstico esquecido.
INTERNAL_SERVICES = {
    "flag-service": {
        "url": "http://flag-service:8000",
        "health": "http://flag-service:8000/health",
    }
}


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

    return render_template(
        "index.html",
        url=url,
        result=result,
        error=error,
        history=PREVIEW_HISTORY,
    )


@app.get("/debug")
def debug():
    """Endpoint de diagnóstico deixado no ambiente de produção."""
    return jsonify(
        {
            "app": "url-preview",
            "version": "1.3.2",
            "environment": "production",
            "fetch": {"timeout": 5, "allow_redirects": True},
            "blocked_hosts": list(BLOCKED),
            "internal_services": INTERNAL_SERVICES,
        }
    )


@app.get("/robots.txt")
def robots():
    return (
        "User-agent: *\n"
        "Disallow: /debug\n",
        200,
        {"Content-Type": "text/plain; charset=utf-8"},
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
