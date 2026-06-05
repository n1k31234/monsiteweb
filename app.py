#!/usr/bin/env python3
import os
import re
import json
import secrets
import hashlib
import sqlite3
import html
import datetime
from collections import defaultdict
from flask import (
    Flask, request, session, g, jsonify,
    redirect, url_for, abort, make_response
)

# ---------------------------------------------------------
# Configuration & Security
# ---------------------------------------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['DEBUG'] = False
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False

# ---------------------------------------------------------
# Database helpers
# ---------------------------------------------------------
DB_PATH = os.path.join(app.instance_path, 'itsc.db')
os.makedirs(app.instance_path, exist_ok=True)

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

@app.teardown_appcontext
def teardown_db(exception):
    close_db(exception)

def init_db():
    db = get_db()
    with app.open_resource('schema.sql', mode='r') as f:
        db.executescript(f.read())

    cur = db.execute('SELECT COUNT(*) FROM users')
    if cur.fetchone()[0] == 0:
        pwd_hash, salt = hash_password('Admin@2024!')
        db.execute('''
            INSERT INTO users (username,email,password_hash,salt,role,is_active,created_at)
            VALUES (?,?,?,?,?, ?, ?)
        ''', ('admin', 'admin@example.com', pwd_hash, salt, 'admin', 1,
              datetime.datetime.utcnow()))
        db.commit()

# ---------------------------------------------------------
# Password handling
# ---------------------------------------------------------
def hash_password(pwd: str, salt_hex: str = None):
    if salt_hex:
        salt = bytes.fromhex(salt_hex)
    else:
        salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', pwd.encode(), salt, 260000)
    return pwd_hash.hex(), salt.hex()

def verify_password(pwd: str, pwd_hash_hex: str, salt_hex: str):
    pwd_hash, _ = hash_password(pwd, salt_hex)
    return secrets.compare_digest(pwd_hash, pwd_hash_hex)

# ---------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------
RATE_LIMIT = 5
RATE_WINDOW = datetime.timedelta(hours=1)
_ip_requests = defaultdict(list)

def clean_ip_requests():
    now = datetime.datetime.utcnow()
    for ip, times in list(_ip_requests.items()):
        _ip_requests[ip] = [t for t in times if now - t < RATE_WINDOW]
        if not _ip_requests[ip]:
            del _ip_requests[ip]

def rate_limit():
    ip = request.remote_addr
    now = datetime.datetime.utcnow()
    clean_ip_requests()
    _ip_requests[ip].append(now)
    if len(_ip_requests[ip]) > RATE_LIMIT:
        abort(make_response(jsonify({
            'success': False,
            'message': 'Trop de requêtes, réessayez plus tard.'
        }), 429))

@app.before_request
def before_any_request():
    rate_limit()

# ---------------------------------------------------------
# CSRF protection
# ---------------------------------------------------------
def generate_csrf():
    token = secrets.token_urlsafe(32)
    session['csrf_token'] = token
    return token

def validate_csrf():
    token = session.get('csrf_token')
    form_token = request.form.get('csrf_token') or request.args.get('csrf_token')
    if not token or not form_token or not secrets.compare_digest(token, form_token):
        abort(make_response(jsonify({'success': False,'message': 'Token CSRF invalide.'}), 400))

# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------
def sanitize_string(s: str) -> str:
    return html.escape(s.strip())

def is_valid_email(email: str) -> bool:
    regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(regex, email) is not None

def ip_hash(ip: str) -> str:
    return hashlib.sha256(ip.encode()).hexdigest()

# ---------------------------------------------------------
# Headers sécurité
# ---------------------------------------------------------
@app.after_request
def set_secure_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response

# =========================
# ROUTES (inchangées)
# =========================
# (Tout ton code routes reste IDENTIQUE ici)
# 👉 Je ne le répète pas pour éviter une réponse inutilisable,
# MAIS tu n’as rien à changer dans cette partie.

# ---------------------------------------------------------
# INIT & RUN (IMPORTANT FIX VERCEL)
# ---------------------------------------------------------
if __name__ == '__main__':
    if not os.path.isfile(DB_PATH):
        with open('schema.sql', 'w', encoding='utf-8') as f:
            f.write('''CREATE TABLE users (...);''')  # ton schema complet ici
    init_db()
    app.run(host='0.0.0.0', port=5000, threaded=True)

# =========================================================
# ✅ FIX VERCEL IMPORTANT
# =========================================================

application = app   # 👈 IMPORTANT POUR GUNICORN / VERCEL
