"""CTF 10 - Admin API (JWT algorithm confusion).

Aplicação intencionalmente vulnerável, usada apenas em laboratório.
A falha está em aceitar RS256 e HS256 com a mesma chave (a chave pública),
permitindo que um atacante assine um token HS256 usando a chave pública.
"""

import base64
import hashlib
import hmac
import json
import os
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from flask import Flask, Response, redirect, render_template, request, session, url_for

app = Flask(__name__)
# Um único worker: a chave aleatória permanece consistente durante o processo.
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(32)

FLAG = os.environ.get("FLAG", "flag{jwt_4lg0r1thm_c0nfus10n}")
USERS = {"guest": "guest"}


class TokenError(Exception):
    pass


def generate_keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return key, public_pem


PRIVATE_KEY, PUBLIC_PEM = generate_keypair()
PUBLIC_KEY = PRIVATE_KEY.public_key()


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def create_token(payload: dict) -> str:
    header = {"alg": "RS256", "typ": "JWT"}
    segments = [
        b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8")),
        b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8")),
    ]
    signing_input = ".".join(segments).encode("ascii")
    signature = PRIVATE_KEY.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return ".".join(segments + [b64url_encode(signature)])


def decode_token(token: str) -> dict:
    # VULNERÁVEL POR DESIGN: a verificação escolhe o algoritmo pelo header e
    # usa a mesma chave pública tanto para RS256 quanto para HS256.
    try:
        header_segment, payload_segment, signature_segment = token.split(".")
        header = json.loads(b64url_decode(header_segment))
        payload = json.loads(b64url_decode(payload_segment))
        signature = b64url_decode(signature_segment)
        signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
        algorithm = header.get("alg")

        if algorithm == "RS256":
            PUBLIC_KEY.verify(
                signature, signing_input, padding.PKCS1v15(), hashes.SHA256()
            )
        elif algorithm == "HS256":
            expected = hmac.new(
                PUBLIC_PEM.encode("ascii"), signing_input, hashlib.sha256
            ).digest()
            if not hmac.compare_digest(signature, expected):
                raise TokenError("assinatura inválida")
        else:
            raise TokenError("algoritmo não suportado")

        expires = payload.get("exp")
        if expires is not None and int(expires) < int(time.time()):
            raise TokenError("token expirado")

        return payload
    except TokenError:
        raise
    except (ValueError, TypeError, KeyError, json.JSONDecodeError, InvalidSignature) as exc:
        raise TokenError(f"token inválido: {exc}") from exc


def current_token() -> str:
    authorization = request.headers.get("Authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return request.cookies.get("token", "")


@app.get("/")
def index():
    return render_template("login.html")


@app.post("/login")
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if USERS.get(username) != password:
        return render_template("login.html", error="Usuário ou senha inválidos."), 401

    token = create_token(
        {
            "sub": username,
            "role": "user",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        }
    )

    response = redirect(url_for("dashboard"))
    response.set_cookie("token", token, httponly=True, samesite="Lax")
    return response


@app.get("/dashboard")
def dashboard():
    token = current_token()
    if not token:
        return redirect(url_for("index"))

    try:
        payload = decode_token(token)
    except TokenError as exc:
        return render_template("login.html", error=f"Token inválido: {exc}"), 401

    return render_template("dashboard.html", token=token, payload=payload)


@app.get("/admin")
def admin():
    token = current_token()
    if not token:
        return render_template("login.html", error="Envie um token JWT."), 401

    try:
        payload = decode_token(token)
    except TokenError as exc:
        return render_template("login.html", error=f"Token inválido: {exc}"), 401

    if payload.get("role") != "admin":
        return render_template(
            "dashboard.html",
            token=token,
            payload=payload,
            error="Acesso restrito a administradores.",
        ), 403

    return render_template("admin.html", payload=payload, flag=FLAG)


@app.get("/pubkey")
def pubkey():
    return Response(PUBLIC_PEM, mimetype="application/x-pem-file")


@app.get("/logout")
def logout():
    session.clear()
    response = redirect(url_for("index"))
    response.delete_cookie("token")
    return response


@app.get("/health")
def health():
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
