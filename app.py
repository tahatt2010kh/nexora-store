import os
import sqlite3
from functools import wraps
from flask import Flask, request, jsonify, session, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "nexora.db")

app = Flask(__name__, static_folder=".", static_url_path="")
app.secret_key = os.environ.get("SECRET_KEY", "replace-this-secret-before-public-launch")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "0") == "1"

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "NEXORA-ChangeMe-2026")

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        price TEXT NOT NULL,
        image_url TEXT DEFAULT '',
        description TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        product_id INTEGER NOT NULL,
        customer_name TEXT NOT NULL,
        phone TEXT NOT NULL,
        country TEXT NOT NULL,
        address TEXT NOT NULL,
        postal_code TEXT DEFAULT '',
        shipping_method TEXT NOT NULL,
        customer_note TEXT DEFAULT '',
        status TEXT DEFAULT 'new',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(product_id) REFERENCES products(id)
    );
    """)
    admin = conn.execute(
        "SELECT id FROM admins WHERE username=?", (ADMIN_USERNAME,)
    ).fetchone()
    if not admin:
        conn.execute(
            "INSERT INTO admins(username, password_hash) VALUES (?, ?)",
            (ADMIN_USERNAME, generate_password_hash(ADMIN_PASSWORD))
        )
    conn.commit()
    conn.close()

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin_id"):
            return jsonify({"error": "Admin login required"}), 401
        return fn(*args, **kwargs)
    return wrapper

@app.get("/")
def home():
    return send_from_directory(app.static_folder, "index.html")

@app.get("/api/products")
def get_products():
    conn = db()
    rows = conn.execute("SELECT * FROM products ORDER BY id DESC").fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])

@app.post("/api/admin/login")
def admin_login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    conn = db()
    admin = conn.execute(
        "SELECT * FROM admins WHERE username=?", (username,)
    ).fetchone()
    conn.close()
    if not admin or not check_password_hash(admin["password_hash"], password):
        return jsonify({"error": "Username or password is incorrect"}), 401
    session.clear()
    session["admin_id"] = admin["id"]
    session["admin_username"] = admin["username"]
    return jsonify({"message": "Logged in"})

@app.post("/api/admin/logout")
def admin_logout():
    session.clear()
    return jsonify({"message": "Logged out"})

@app.get("/api/admin/me")
@admin_required
def admin_me():
    return jsonify({"username": session.get("admin_username")})

@app.post("/api/admin/products")
@admin_required
def create_product():
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    price = str(data.get("price", "")).strip()
    if not name or not price:
        return jsonify({"error": "Product name and price are required"}), 400
    conn = db()
    cur = conn.execute(
        """INSERT INTO products(name, price, image_url, description)
           VALUES (?, ?, ?, ?)""",
        (
            name,
            price,
            str(data.get("image_url", "")).strip(),
            str(data.get("description", "")).strip()
        )
    )
    conn.commit()
    product_id = cur.lastrowid
    conn.close()
    return jsonify({"id": product_id}), 201

@app.delete("/api/admin/products/<int:product_id>")
@admin_required
def delete_product(product_id):
    conn = db()
    conn.execute("DELETE FROM products WHERE id=?", (product_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Deleted"})

@app.post("/api/orders")
def create_order():
    data = request.get_json(silent=True) or {}
    required = ["product_id", "customer_name", "phone", "country", "address", "shipping_method"]
    if any(not str(data.get(field, "")).strip() for field in required):
        return jsonify({"error": "Please complete all required fields"}), 400

    conn = db()
    product = conn.execute(
        "SELECT id FROM products WHERE id=?", (data["product_id"],)
    ).fetchone()
    if not product:
        conn.close()
        return jsonify({"error": "Product not found"}), 404

    cur = conn.execute(
        """INSERT INTO orders
           (product_id, customer_name, phone, country, address, postal_code,
            shipping_method, customer_note)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            data["product_id"],
            str(data["customer_name"]).strip(),
            str(data["phone"]).strip(),
            str(data["country"]).strip(),
            str(data["address"]).strip(),
            str(data.get("postal_code", "")).strip(),
            str(data["shipping_method"]).strip(),
            str(data.get("customer_note", "")).strip()
        )
    )
    conn.commit()
    order_id = cur.lastrowid
    conn.close()
    return jsonify({"message": "Order received", "order_id": order_id}), 201

@app.get("/api/admin/orders")
@admin_required
def get_orders():
    conn = db()
    rows = conn.execute("""
        SELECT orders.*, products.name AS product_name
        FROM orders
        JOIN products ON products.id = orders.product_id
        ORDER BY orders.id DESC
    """).fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])

@app.patch("/api/admin/orders/<int:order_id>")
@admin_required
def update_order(order_id):
    data = request.get_json(silent=True) or {}
    status = str(data.get("status", "")).strip()
    allowed = {"new", "confirmed", "packing", "shipped", "delivered", "cancelled"}
    if status not in allowed:
        return jsonify({"error": "Invalid status"}), 400
    conn = db()
    conn.execute("UPDATE orders SET status=? WHERE id=?", (status, order_id))
    conn.commit()
    conn.close()
    return jsonify({"message": "Updated"})

init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
