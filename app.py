```python
from flask import Flask, request, jsonify
import sqlite3
import os
import datetime
import hashlib
import secrets
import json

app = Flask(__name__)

# =========================================================
# CONFIG
# =========================================================

app.config['SECRET_KEY'] = secrets.token_hex(32)

# Base SQLite temporaire compatible Vercel
DB_PATH = "/tmp/itsc.db"

# =========================================================
# DATABASE
# =========================================================

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        260000
    )
    return pwd_hash.hex(), salt.hex()

def init_db():
    db = get_db()

    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'admin',
        created_at TIMESTAMP NOT NULL
    );

    CREATE TABLE IF NOT EXISTS submissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TIMESTAMP NOT NULL,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        message TEXT NOT NULL
    );
    """)

    cur = db.execute("SELECT COUNT(*) as total FROM users")
    total = cur.fetchone()["total"]

    if total == 0:
        pwd_hash, salt = hash_password("Admin@2024!")

        db.execute("""
        INSERT INTO users
        (username, email, password_hash, salt, role, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (
            "admin",
            "admin@example.com",
            pwd_hash,
            salt,
            "admin",
            datetime.datetime.utcnow()
        ))

    db.commit()
    db.close()

# Initialisation DB
with app.app_context():
    init_db()

# =========================================================
# ROUTES
# =========================================================

@app.route("/")
def home():
    return """
    <h1>Bienvenue chez ITSC</h1>

    <form method="POST" action="/submit">
        <input type="text" name="name" placeholder="Nom"><br><br>

        <input type="email" name="email" placeholder="Email"><br><br>

        <textarea name="message" placeholder="Message"></textarea><br><br>

        <button type="submit">Envoyer</button>
    </form>
    """

@app.route("/submit", methods=["POST"])
def submit():

    name = request.form.get("name", "")
    email = request.form.get("email", "")
    message = request.form.get("message", "")

    if not name or not email or not message:
        return jsonify({
            "success": False,
            "message": "Tous les champs sont requis"
        }), 400

    db = get_db()

    db.execute("""
    INSERT INTO submissions
    (created_at, name, email, message)
    VALUES (?, ?, ?, ?)
    """, (
        datetime.datetime.utcnow(),
        name,
        email,
        message
    ))

    db.commit()
    db.close()

    return jsonify({
        "success": True,
        "message": "Message envoyé avec succès"
    })

@app.route("/api/messages")
def messages():

    db = get_db()

    rows = db.execute("""
    SELECT * FROM submissions
    ORDER BY created_at DESC
    """).fetchall()

    data = []

    for row in rows:
        data.append({
            "id": row["id"],
            "name": row["name"],
            "email": row["email"],
            "message": row["message"],
            "created_at": row["created_at"]
        })

    db.close()

    return jsonify(data)

# =========================================================
# VERCEL FIX
# =========================================================

application = app
```
