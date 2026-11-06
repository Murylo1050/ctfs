"""VulnShop — mini e-commerce intencionalmente vulnerável.

Aplicação didática para o minicurso de segurança da informação.
Contém falhas propositais de SQL Injection, Command Injection, confiança em
cookie, IDOR, BOLA, path traversal, XSS refletido, open redirect, mass
assignment e ausência de CSRF. Execute apenas em laboratório.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import sqlite3
import urllib.error
import urllib.request
from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    Response,
    abort,
    g,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)

import db

FLAGS = {
    "sqli": os.environ.get("FLAG_SQLI", "flag{sql1_s3arch_h1dd3n}"),
    "admin": os.environ.get("FLAG_ADMIN", "flag{c00k13s_r0l3_adm1n}"),
    "idor": os.environ.get("FLAG_IDOR", "flag{1d0r_0rd3r_1001}"),
    "bola": os.environ.get("FLAG_BOLA", "flag{b0l4_4p1_0rd3r_1003}"),
    "traversal": os.environ.get("FLAG_TRAVERSAL", "flag{p4th_tr4v3rs4l_1nv01c3}"),
}

SHIPPING_URL = os.environ.get(
    "SHIPPING_URL", "http://shipping-service:8000/quote"
)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

db.init_db(FLAGS)
db.prepare_invoices(FLAGS)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def fetch_all(sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    conn = db.get_db()
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def fetch_one(sql: str, params: tuple = ()) -> sqlite3.Row | None:
    conn = db.get_db()
    try:
        return conn.execute(sql, params).fetchone()
    finally:
        conn.close()


def encode_session(data: dict) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode_session(value: str | None) -> dict | None:
    if not value:
        return None
    try:
        padding = "=" * (-len(value) % 4)
        raw = base64.urlsafe_b64decode(value + padding)
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    try:
        uid = int(data.get("uid", 0))
    except (TypeError, ValueError):
        uid = 0
    return {
        "uid": uid,
        "username": str(data.get("username", "")),
        "role": str(data.get("role", "customer")),
    }


def set_session_cookie(response, user: sqlite3.Row):
    payload = {
        "uid": user["id"],
        "username": user["username"],
        "role": user["role"],
    }
    # VULNERÁVEL POR DESIGN: cookie apenas codificado em base64, sem
    # assinatura. O conteúdo é totalmente controlado pelo cliente.
    response.set_cookie(
        "shop_session",
        encode_session(payload),
        max_age=60 * 60 * 24,
        httponly=False,
        samesite="Lax",
        path="/",
    )
    return response


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not getattr(g, "user", None):
            next_url = request.full_path if request.query_string else request.path
            return redirect(url_for("login", next=next_url))
        return view(*args, **kwargs)

    return wrapped


def current_cart_count() -> int:
    if not getattr(g, "user", None):
        return 0
    row = fetch_one(
        "SELECT COALESCE(SUM(quantity), 0) AS n FROM cart_items WHERE user_id = ?",
        (g.user["uid"],),
    )
    return int(row["n"]) if row else 0


@app.before_request
def load_cookie_session():
    g.user = decode_session(request.cookies.get("shop_session"))


@app.context_processor
def inject_globals():
    return {
        "cart_count": current_cart_count(),
        "is_admin": bool(getattr(g, "user", None) and g.user["role"] == "admin"),
    }


@app.template_filter("brl")
def brl(value) -> str:
    try:
        text = f"{float(value):,.2f}"
    except (TypeError, ValueError):
        return "R$ 0,00"
    return "R$ " + text.replace(",", "X").replace(".", ",").replace("X", ".")


# ---------------------------------------------------------------------------
# Vitrine e catálogo
# ---------------------------------------------------------------------------


@app.get("/")
def index():
    products = fetch_all(
        "SELECT * FROM products WHERE visible = 1 ORDER BY id LIMIT 6"
    )
    return render_template("index.html", products=products, title="Início")


@app.get("/products")
def products():
    category = request.args.get("category", "").strip()
    if category:
        rows = fetch_all(
            "SELECT * FROM products WHERE visible = 1 AND category = ? ORDER BY id",
            (category,),
        )
    else:
        rows = fetch_all("SELECT * FROM products WHERE visible = 1 ORDER BY id")
    categories = fetch_all(
        "SELECT DISTINCT category FROM products WHERE visible = 1 ORDER BY category"
    )
    return render_template(
        "products.html",
        products=rows,
        categories=categories,
        selected_category=category,
        title="Produtos",
    )


@app.get("/search")
def search():
    query = request.args.get("q", "")
    results = []
    error = None
    if query:
        # VULNERÁVEL POR DESIGN: a entrada é interpolada diretamente na
        # consulta SQL. O produto interno (visible = 0) guarda a flag.
        sql = (
            "SELECT id, name, description, price, stock, icon FROM products "
            "WHERE visible = 1 AND (name LIKE '%"
            + query
            + "%' OR description LIKE '%"
            + query
            + "%') ORDER BY id"
        )
        try:
            results = fetch_all(sql)
        except sqlite3.Error as exc:
            error = f"Erro ao consultar o catálogo: {exc}"
    return render_template(
        "search.html",
        query=query,
        results=results,
        error=error,
        title="Busca",
    )


@app.get("/product/<int:product_id>")
def product(product_id: int):
    item = fetch_one(
        "SELECT * FROM products WHERE id = ? AND visible = 1", (product_id,)
    )
    if item is None:
        abort(404)
    related = fetch_all(
        "SELECT * FROM products WHERE visible = 1 AND category = ? AND id <> ? LIMIT 3",
        (item["category"], product_id),
    )
    return render_template("product.html", product=item, related=related)


# ---------------------------------------------------------------------------
# Autenticação e conta
# ---------------------------------------------------------------------------


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template(
            "login.html",
            next_url=request.args.get("next", ""),
            title="Entrar",
        )

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    next_url = request.form.get("next", "").strip()
    user = fetch_one(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username, password),
    )
    if user is None:
        return (
            render_template(
                "login.html",
                error="Usuário ou senha inválidos.",
                next_url=next_url,
                title="Entrar",
            ),
            401,
        )

    # VULNERÁVEL POR DESIGN: o parâmetro next é usado como destino sem
    # validar se pertence ao mesmo domínio (open redirect).
    destination = next_url or url_for("index")
    response = make_response(redirect(destination))
    return set_session_cookie(response, user)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html", title="Criar conta")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    email = request.form.get("email", "").strip()
    full_name = request.form.get("full_name", "").strip() or username
    # VULNERÁVEL POR DESIGN: mass assignment. O papel vem do formulário e é
    # aceito sem allowlist, embora a interface envie role=customer.
    role = request.form.get("role", "customer").strip().lower()
    if role not in {"customer", "admin"}:
        role = "customer"

    if not username or not password or not email:
        return (
            render_template(
                "register.html",
                error="Preencha usuário, e-mail e senha.",
                title="Criar conta",
            ),
            400,
        )
    if len(password) < 4:
        return (
            render_template(
                "register.html",
                error="A senha deve ter pelo menos 4 caracteres.",
                title="Criar conta",
            ),
            400,
        )

    conn = db.get_db()
    try:
        cur = conn.execute(
            """
            INSERT INTO users
                (username, password, email, full_name, role, api_key, created_at)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
            """,
            (
                username,
                password,
                email,
                full_name,
                role,
                "vulnshop-" + secrets.token_urlsafe(12),
            ),
        )
        conn.commit()
        user = conn.execute(
            "SELECT * FROM users WHERE id = ?", (cur.lastrowid,)
        ).fetchone()
    except sqlite3.IntegrityError:
        conn.rollback()
        return (
            render_template(
                "register.html",
                error="Este nome de usuário já está em uso.",
                title="Criar conta",
            ),
            409,
        )
    finally:
        conn.close()

    response = make_response(redirect(url_for("index")))
    return set_session_cookie(response, user)


@app.get("/logout")
def logout():
    response = make_response(redirect(url_for("index")))
    response.delete_cookie("shop_session", path="/")
    return response


@app.get("/profile")
@login_required
def profile():
    user = fetch_one("SELECT * FROM users WHERE id = ?", (g.user["uid"],))
    if user is None:
        response = make_response(redirect(url_for("logout")))
        return response
    order_count = fetch_one(
        "SELECT COUNT(*) AS n FROM orders WHERE user_id = ?", (user["id"],)
    )
    return render_template(
        "profile.html",
        user=user,
        order_count=order_count["n"] if order_count else 0,
        title="Minha conta",
    )


# ---------------------------------------------------------------------------
# Carrinho e checkout
# ---------------------------------------------------------------------------


@app.get("/cart")
@login_required
def cart():
    items = fetch_all(
        """
        SELECT c.product_id, c.quantity, p.name, p.price, p.icon, p.stock, p.category
        FROM cart_items c
        JOIN products p ON p.id = c.product_id
        WHERE c.user_id = ?
        ORDER BY c.id
        """,
        (g.user["uid"],),
    )
    total = sum(item["price"] * item["quantity"] for item in items)
    return render_template("cart.html", items=items, total=total, title="Carrinho")


@app.post("/cart/add")
@login_required
def cart_add():
    try:
        product_id = int(request.form.get("product_id", "0"))
        quantity = int(request.form.get("quantity", "1"))
    except ValueError:
        abort(400)
    quantity = max(1, min(quantity, 99))
    item = fetch_one(
        "SELECT * FROM products WHERE id = ? AND visible = 1", (product_id,)
    )
    if item is None:
        abort(404)

    conn = db.get_db()
    try:
        conn.execute(
            """
            INSERT INTO cart_items (user_id, product_id, quantity)
            VALUES (?, ?, ?)
            ON CONFLICT (user_id, product_id)
            DO UPDATE SET quantity = MIN(cart_items.quantity + excluded.quantity, 99)
            """,
            (g.user["uid"], product_id, quantity),
        )
        conn.commit()
    finally:
        conn.close()
    return redirect(url_for("cart"))


@app.post("/cart/update")
@login_required
def cart_update():
    try:
        product_id = int(request.form.get("product_id", "0"))
        quantity = int(request.form.get("quantity", "1"))
    except ValueError:
        abort(400)
    conn = db.get_db()
    try:
        if quantity <= 0:
            conn.execute(
                "DELETE FROM cart_items WHERE user_id = ? AND product_id = ?",
                (g.user["uid"], product_id),
            )
        else:
            conn.execute(
                "UPDATE cart_items SET quantity = ? WHERE user_id = ? AND product_id = ?",
                (min(quantity, 99), g.user["uid"], product_id),
            )
        conn.commit()
    finally:
        conn.close()
    return redirect(url_for("cart"))


@app.post("/cart/remove")
@login_required
def cart_remove():
    try:
        product_id = int(request.form.get("product_id", "0"))
    except ValueError:
        abort(400)
    conn = db.get_db()
    try:
        conn.execute(
            "DELETE FROM cart_items WHERE user_id = ? AND product_id = ?",
            (g.user["uid"], product_id),
        )
        conn.commit()
    finally:
        conn.close()
    return redirect(url_for("cart"))


@app.route("/checkout", methods=["GET", "POST"])
@login_required
def checkout():
    items = fetch_all(
        """
        SELECT c.product_id, c.quantity, p.name, p.price, p.stock
        FROM cart_items c
        JOIN products p ON p.id = c.product_id
        WHERE c.user_id = ?
        ORDER BY c.id
        """,
        (g.user["uid"],),
    )
    total = sum(item["price"] * item["quantity"] for item in items)

    if request.method == "GET":
        return render_template(
            "checkout.html", items=items, total=total, title="Finalizar compra"
        )

    if not items:
        return redirect(url_for("cart"))

    shipping_name = request.form.get("shipping_name", "").strip()
    shipping_address = request.form.get("shipping_address", "").strip()
    shipping_city = request.form.get("shipping_city", "").strip()
    shipping_zip = request.form.get("shipping_zip", "").strip()
    payment_method = request.form.get("payment_method", "PIX").strip()
    customer_note = request.form.get("customer_note", "").strip()

    if not all([shipping_name, shipping_address, shipping_city, shipping_zip]):
        return (
            render_template(
                "checkout.html",
                items=items,
                total=total,
                error="Preencha todos os dados de entrega.",
                title="Finalizar compra",
            ),
            400,
        )

    conn = db.get_db()
    try:
        cur = conn.execute(
            """
            INSERT INTO orders
                (user_id, status, total, shipping_name, shipping_address,
                 shipping_city, shipping_zip, payment_method, customer_note,
                 internal_note, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
            """,
            (
                g.user["uid"],
                "Pago",
                total,
                shipping_name,
                shipping_address,
                shipping_city,
                shipping_zip,
                payment_method,
                customer_note,
                "",
            ),
        )
        order_id = cur.lastrowid
        for item in items:
            conn.execute(
                """
                INSERT INTO order_items
                    (order_id, product_id, name, unit_price, quantity)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    order_id,
                    item["product_id"],
                    item["name"],
                    item["price"],
                    item["quantity"],
                ),
            )
            conn.execute(
                "UPDATE products SET stock = MAX(0, stock - ?) WHERE id = ?",
                (item["quantity"], item["product_id"]),
            )
        conn.execute("DELETE FROM cart_items WHERE user_id = ?", (g.user["uid"],))
        conn.commit()
    except sqlite3.Error:
        conn.rollback()
        raise
    finally:
        conn.close()

    db.prepare_invoices(FLAGS)
    return redirect(url_for("order_detail", order_id=order_id))


# ---------------------------------------------------------------------------
# Pedidos, notas fiscais e IDOR
# ---------------------------------------------------------------------------


@app.get("/orders")
@login_required
def orders():
    rows = fetch_all(
        "SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC", (g.user["uid"],)
    )
    return render_template("orders.html", orders=rows, title="Meus pedidos")


@app.get("/orders/<int:order_id>")
@login_required
def order_detail(order_id: int):
    order = fetch_one("SELECT * FROM orders WHERE id = ?", (order_id,))
    if order is None:
        abort(404)
    items = fetch_all(
        "SELECT * FROM order_items WHERE order_id = ? ORDER BY id", (order_id,)
    )
    owner = fetch_one(
        "SELECT username, email, full_name FROM users WHERE id = ?",
        (order["user_id"],),
    )
    # VULNERÁVEL POR DESIGN (IDOR): não verificamos se o pedido pertence ao
    # usuário autenticado antes de exibir os dados e a observação do cliente.
    return render_template(
        "order_detail.html",
        order=order,
        items=items,
        owner=owner,
        invoice_file=f"invoice-{order_id}.txt",
        is_own=order["user_id"] == g.user["uid"],
        title=f"Pedido #{order_id}",
    )


@app.get("/invoices/download")
@login_required
def invoice_download():
    filename = request.args.get("file", "").strip()
    if not filename:
        return "Informe o arquivo da nota fiscal.", 400
    # VULNERÁVEL POR DESIGN: só valida a extensão. O caminho é montado por
    # concatenação, permitindo ../ e leitura de outros arquivos .txt.
    if not filename.endswith(".txt"):
        return "Somente arquivos .txt são permitidos.", 400

    path = Path(os.path.join(str(db.INVOICE_DIR), filename))
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        abort(404)

    response = Response(content, mimetype="text/plain")
    response.headers["Content-Disposition"] = (
        f"inline; filename={os.path.basename(filename) or 'nota.txt'}"
    )
    return response


# ---------------------------------------------------------------------------
# Serviço de frete (Command Injection)
# ---------------------------------------------------------------------------


@app.route("/shipping", methods=["GET", "POST"])
@login_required
def shipping():
    output = None
    error = None
    cep = request.form.get("cep", "").strip() if request.method == "POST" else ""
    weight = request.form.get("weight", "1").strip() if request.method == "POST" else "1"

    if request.method == "POST":
        if not cep:
            error = "Informe um CEP para calcular o frete."
        else:
            payload = json.dumps({"cep": cep, "weight": weight}).encode("utf-8")
            req = urllib.request.Request(
                SHIPPING_URL,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=12) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    output = data.get("output", "")
            except urllib.error.HTTPError as exc:
                body = exc.read().decode("utf-8", errors="replace")
                try:
                    output = json.loads(body).get("error", body)
                except json.JSONDecodeError:
                    output = body
                error = "O serviço de frete recusou a consulta."
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
                error = "Não foi possível consultar o serviço de frete agora."

    return render_template(
        "shipping.html",
        output=output,
        error=error,
        cep=cep,
        weight=weight,
        title="Calcular frete",
    )


# ---------------------------------------------------------------------------
# Administração e API
# ---------------------------------------------------------------------------


@app.get("/admin")
@login_required
def admin():
    # VULNERÁVEL POR DESIGN: a autorização confia apenas no papel gravado no
    # cookie shop_session, que não é assinado.
    if g.user["role"] != "admin":
        return (
            render_template(
                "admin.html",
                denied=True,
                flag=None,
                title="Painel administrativo",
            ),
            403,
        )

    stats = fetch_one(
        """
        SELECT
            (SELECT COUNT(*) FROM users) AS users,
            (SELECT COUNT(*) FROM orders) AS orders,
            (SELECT COUNT(*) FROM products WHERE visible = 1) AS products
        """
    )
    users = fetch_all(
        "SELECT id, username, email, role, created_at FROM users ORDER BY id"
    )
    return render_template(
        "admin.html",
        denied=False,
        flag=FLAGS["admin"],
        stats=stats,
        users=users,
        title="Painel administrativo",
    )


@app.get("/api")
def api_docs():
    demo = fetch_one("SELECT api_key FROM users WHERE username = 'demo'")
    return render_template(
        "api_docs.html",
        demo_key=demo["api_key"] if demo else "",
        title="API da loja",
    )


@app.get("/api/v1/orders/<int:order_id>")
def api_order(order_id: int):
    api_key = request.headers.get("X-API-Key") or request.args.get("api_key", "")
    user = fetch_one("SELECT * FROM users WHERE api_key = ?", (api_key,))
    if user is None:
        return jsonify(error="API key ausente ou inválida."), 401

    order = fetch_one("SELECT * FROM orders WHERE id = ?", (order_id,))
    if order is None:
        return jsonify(error="Pedido não encontrado."), 404

    owner = fetch_one("SELECT username, email FROM users WHERE id = ?", (order["user_id"],))
    items = fetch_all(
        "SELECT product_id, name, unit_price, quantity FROM order_items WHERE order_id = ?",
        (order_id,),
    )

    # VULNERÁVEL POR DESIGN (BOLA): a API autentica a chave, mas não verifica
    # se o pedido pertence ao dono da chave. internal_note é exposto.
    return jsonify(
        {
            "id": order["id"],
            "status": order["status"],
            "total": round(order["total"], 2),
            "created_at": order["created_at"],
            "owner": {
                "username": owner["username"] if owner else None,
                "email": owner["email"] if owner else None,
            },
            "shipping": {
                "name": order["shipping_name"],
                "address": order["shipping_address"],
                "city": order["shipping_city"],
                "zip": order["shipping_zip"],
            },
            "payment_method": order["payment_method"],
            "items": [dict(item) for item in items],
            "customer_note": order["customer_note"],
            "internal_note": order["internal_note"],
        }
    )


@app.get("/health")
def health():
    return "ok"


@app.get("/robots.txt")
def robots():
    return Response("User-agent: *\nDisallow: /admin\n", mimetype="text/plain")


@app.errorhandler(404)
def not_found(_error):
    return (
        render_template(
            "error.html",
            code=404,
            message="A página ou o recurso solicitado não existe.",
            title="Não encontrado",
        ),
        404,
    )


@app.errorhandler(500)
def server_error(_error):
    return (
        render_template(
            "error.html",
            code=500,
            message="Ocorreu um erro inesperado no servidor.",
            title="Erro interno",
        ),
        500,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
