"""Camada de dados da VulnShop.

Aplicação intencionalmente vulnerável, usada apenas em laboratório.
O banco SQLite e os arquivos de runtime ficam em /tmp (tmpfs no container),
portanto são recriados a cada recriação do container.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

DB_PATH = os.environ.get("VULNSHOP_DB", "/tmp/vulnshop.db")
INVOICE_DIR = Path("/tmp/invoices")
INVOICE_FLAG_PATH = Path("/tmp/invoice-flag.txt")

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY,
    username    TEXT NOT NULL UNIQUE,
    password    TEXT NOT NULL,
    email       TEXT NOT NULL,
    full_name   TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'customer',
    api_key     TEXT NOT NULL UNIQUE,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS products (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL,
    price       REAL NOT NULL,
    stock       INTEGER NOT NULL DEFAULT 0,
    visible     INTEGER NOT NULL DEFAULT 1,
    category    TEXT NOT NULL DEFAULT 'Geral',
    icon        TEXT NOT NULL DEFAULT '📦'
);

CREATE TABLE IF NOT EXISTS cart_items (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    product_id  INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    quantity    INTEGER NOT NULL CHECK (quantity > 0),
    UNIQUE (user_id, product_id)
);

CREATE TABLE IF NOT EXISTS orders (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id          INTEGER NOT NULL REFERENCES users(id),
    status           TEXT NOT NULL,
    total            REAL NOT NULL,
    shipping_name    TEXT NOT NULL,
    shipping_address TEXT NOT NULL,
    shipping_city    TEXT NOT NULL,
    shipping_zip     TEXT NOT NULL,
    payment_method   TEXT NOT NULL,
    customer_note    TEXT NOT NULL DEFAULT '',
    internal_note    TEXT NOT NULL DEFAULT '',
    created_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS order_items (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id    INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    product_id  INTEGER NOT NULL REFERENCES products(id),
    name        TEXT NOT NULL,
    unit_price  REAL NOT NULL,
    quantity    INTEGER NOT NULL
);
"""


def get_db() -> sqlite3.Connection:
    """Abre uma conexão nova por operação (seguro com threads do Gunicorn)."""
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _created(days_ago: int = 0, hours_ago: int = 0) -> str:
    moment = datetime.now(timezone.utc) - timedelta(days=days_ago, hours=hours_ago)
    return moment.strftime("%Y-%m-%d %H:%M")


def init_db(flags: dict[str, str]) -> None:
    """Cria o schema e insere os dados de demonstração de forma idempotente."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    try:
        conn.executescript(SCHEMA)

        # Credenciais de demonstração. A senha do admin não é divulgada aos
        # alunos; o caminho didático é a adulteração do cookie ou o mass
        # assignment no cadastro.
        if conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"] == 0:
            conn.executemany(
                """
                INSERT INTO users
                    (id, username, password, email, full_name, role, api_key, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        1,
                        "admin",
                        "Adm1n!VulnShop#2026-9f42c1",
                        "admin@vulnshop.local",
                        "Administrador da Loja",
                        "admin",
                        "vulnshop-admin-9f42c1e7",
                        _created(days_ago=400),
                    ),
                    (
                        2,
                        "demo",
                        "demo123",
                        "demo@vulnshop.local",
                        "Cliente Demonstração",
                        "customer",
                        "vulnshop-demo-7a3f9c21",
                        _created(days_ago=90),
                    ),
                    (
                        3,
                        "alice",
                        "alice123",
                        "alice@vulnshop.local",
                        "Alice Souza",
                        "customer",
                        "vulnshop-alice-4b8d2e10",
                        _created(days_ago=120),
                    ),
                    (
                        4,
                        "bruno",
                        "bruno123",
                        "bruno@vulnshop.local",
                        "Bruno Lima",
                        "customer",
                        "vulnshop-bruno-6c1a0f33",
                        _created(days_ago=60),
                    ),
                ],
            )

        if conn.execute("SELECT COUNT(*) AS n FROM products").fetchone()["n"] == 0:
            conn.executemany(
                """
                INSERT INTO products
                    (id, name, description, price, stock, visible, category, icon)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        1,
                        "Fone de Ouvido Aurora",
                        "Fone Bluetooth com cancelamento de ruído, até 30 horas de bateria e estojo de viagem.",
                        249.90,
                        25,
                        1,
                        "Áudio",
                        "🎧",
                    ),
                    (
                        2,
                        "Teclado Mecânico K2",
                        "Teclado compacto com switches táteis, iluminação branca e conexão USB-C.",
                        329.90,
                        18,
                        1,
                        "Periféricos",
                        "⌨️",
                    ),
                    (
                        3,
                        "Mouse Sem Fio Lite",
                        "Mouse ergonômico de 2.4 GHz, sensor de 1600 DPI e autonomia de 12 meses.",
                        129.90,
                        40,
                        1,
                        "Periféricos",
                        "🖱️",
                    ),
                    (
                        4,
                        "Monitor UltraWide 29\"",
                        "Monitor de 29 polegadas, resolução 2560 × 1080 e entrada HDMI/DisplayPort.",
                        1299.00,
                        7,
                        1,
                        "Monitores",
                        "🖥️",
                    ),
                    (
                        5,
                        "Mochila Urbana 20L",
                        "Mochila resistente à água, com compartimento acolchoado para notebook de até 15,6\".",
                        189.90,
                        30,
                        1,
                        "Acessórios",
                        "🎒",
                    ),
                    (
                        6,
                        "Cafeteira Compacta",
                        "Cafeteira para até 12 xícaras, com filtro permanente e desligamento automático.",
                        219.90,
                        12,
                        1,
                        "Casa",
                        "☕",
                    ),
                    (
                        7,
                        "Relatório interno — Auditoria",
                        "Documento interno da equipe de auditoria. Não deve aparecer na vitrine. "
                        + flags["sqli"],
                        0.00,
                        0,
                        0,
                        "Interno",
                        "🔒",
                    ),
                ],
            )

        if conn.execute("SELECT COUNT(*) AS n FROM orders").fetchone()["n"] == 0:
            conn.executemany(
                """
                INSERT INTO orders
                    (id, user_id, status, total, shipping_name, shipping_address,
                     shipping_city, shipping_zip, payment_method, customer_note,
                     internal_note, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        1001,
                        3,
                        "Entregue",
                        579.80,
                        "Alice Souza",
                        "Rua das Acácias, 120",
                        "São Paulo",
                        "01310-100",
                        "Cartão de crédito",
                        "Cliente relata que o fone apresenta ruído no lado direito. "
                        "Atendimento registrado sob o protocolo SG-1001.\n\n"
                        + flags["idor"],
                        "Pedido entregue em 3 dias úteis.",
                        _created(days_ago=32),
                    ),
                    (
                        1002,
                        2,
                        "Em trânsito",
                        329.90,
                        "Cliente Demonstração",
                        "Avenida Central, 45",
                        "Campinas",
                        "13010-200",
                        "PIX",
                        "Pedido de demonstração criado pela equipe de suporte.",
                        "",
                        _created(days_ago=4),
                    ),
                    (
                        1003,
                        1,
                        "Processando",
                        1299.00,
                        "Administrador da Loja",
                        "Praça da Matriz, 1",
                        "Rio de Janeiro",
                        "20010-000",
                        "Boleto",
                        "Solicito entrega no período da tarde.",
                        flags["bola"]
                        + " — Nota interna restrita ao time de operações. Não divulgar.",
                        _created(days_ago=2),
                    ),
                    (
                        1004,
                        4,
                        "Pago",
                        189.90,
                        "Bruno Lima",
                        "Rua do Comércio, 88",
                        "Belo Horizonte",
                        "30110-300",
                        "Cartão de crédito",
                        "Embalar para presente, por favor.",
                        "",
                        _created(days_ago=1),
                    ),
                ],
            )

            conn.executemany(
                """
                INSERT INTO order_items
                    (order_id, product_id, name, unit_price, quantity)
                VALUES (?, ?, ?, ?, ?)
                """,
                [
                    (1001, 1, "Fone de Ouvido Aurora", 249.90, 1),
                    (1001, 2, "Teclado Mecânico K2", 329.90, 1),
                    (1002, 2, "Teclado Mecânico K2", 329.90, 1),
                    (1003, 4, "Monitor UltraWide 29\"", 1299.00, 1),
                    (1004, 5, "Mochila Urbana 20L", 189.90, 1),
                ],
            )

        # Mantém as flags sincronizadas com o ambiente em restarts do container.
        conn.execute(
            "UPDATE products SET description = ? WHERE id = 7",
            (
                "Documento interno da equipe de auditoria. Não deve aparecer na vitrine. "
                + flags["sqli"],
            ),
        )
        conn.execute(
            "UPDATE orders SET customer_note = ? WHERE id = 1001",
            (
                "Cliente relata que o fone apresenta ruído no lado direito. "
                "Atendimento registrado sob o protocolo SG-1001.\n\n"
                + flags["idor"],
            ),
        )
        conn.execute(
            "UPDATE orders SET internal_note = ? WHERE id = 1003",
            (
                flags["bola"]
                + " — Nota interna restrita ao time de operações. Não divulgar.",
            ),
        )
        conn.commit()
    finally:
        conn.close()


def prepare_invoices(flags: dict[str, str]) -> None:
    """Gera as notas fiscais de exemplo em /tmp/invoices."""
    INVOICE_DIR.mkdir(parents=True, exist_ok=True)
    INVOICE_FLAG_PATH.write_text(flags["traversal"] + "\n", encoding="utf-8")

    conn = get_db()
    try:
        orders = conn.execute(
            """
            SELECT o.*, u.username
            FROM orders o
            JOIN users u ON u.id = o.user_id
            ORDER BY o.id
            """
        ).fetchall()
        for order in orders:
            items = conn.execute(
                "SELECT name, unit_price, quantity FROM order_items WHERE order_id = ?",
                (order["id"],),
            ).fetchall()
            lines = [
                "VULNSHOP COMÉRCIO DIGITAL LTDA.",
                "CNPJ 12.345.678/0001-90",
                "",
                f"NOTA FISCAL SIMPLIFICADA Nº {order['id']}",
                f"Data: {order['created_at']}",
                f"Cliente: {order['shipping_name']} ({order['username']})",
                f"Endereço: {order['shipping_address']} — {order['shipping_city']} — {order['shipping_zip']}",
                f"Pagamento: {order['payment_method']}",
                f"Status: {order['status']}",
                "",
                "ITENS",
                "-" * 64,
            ]
            for item in items:
                subtotal = item["unit_price"] * item["quantity"]
                lines.append(
                    f"{item['name']}  {item['quantity']} × R$ {item['unit_price']:.2f}"
                    f"  = R$ {subtotal:.2f}"
                )
            lines.extend(
                [
                    "-" * 64,
                    f"TOTAL: R$ {order['total']:.2f}",
                    "",
                    "Documento gerado automaticamente pela VulnShop.",
                    "Este arquivo não possui validade fiscal.",
                ]
            )
            (INVOICE_DIR / f"invoice-{order['id']}.txt").write_text(
                "\n".join(lines) + "\n", encoding="utf-8"
            )
    finally:
        conn.close()
