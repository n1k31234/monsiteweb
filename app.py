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
    # create admin if none exists
    cur = db.execute('SELECT COUNT(*) FROM users')
    if cur.fetchone()[0] == 0:
        pwd_hash, salt = hash_password('Admin@2024!')
        db.execute('''
            INSERT INTO users (username,email,password_hash,salt,role,is_active,created_at)
            VALUES (?,?,?,?,?, ?, ?)
        ''', ('admin', 'admin@example.com', pwd_hash, salt, 'admin', 1,
              datetime.datetime.utcnow()))
        db.commit()
        print('>>> Admin user created : login=admin / password=Admin@2024!')

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
# Rate limiting (5 req / IP / hour)
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
        abort(make_response(jsonify({'success': False,
                                     'message': 'Trop de requêtes, réessayez plus tard.'}), 429))

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
        abort(make_response(jsonify({'success': False,
                                     'message': 'Token CSRF invalide.'}), 400))

# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------
def sanitize_string(s: str) -> str:
    """Basic sanitisation – escape HTML."""
    return html.escape(s.strip())

def is_valid_email(email: str) -> bool:
    regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(regex, email) is not None

def ip_hash(ip: str) -> str:
    return hashlib.sha256(ip.encode()).hexdigest()

# ---------------------------------------------------------
# HTTP security headers
# ---------------------------------------------------------
@app.after_request
def set_secure_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response

# ---------------------------------------------------------
# Public routes
# ---------------------------------------------------------
INDEX_HTML = """
<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>ITSC – Agence de communication</title>
</head>
<body>
<h1>Bienvenue chez ITSC</h1>
<form action="/submit" method="post" id="contactForm">
    CSRF_TOKEN_PLACEHOLDER
    <label>Nom :</label><br>
    <input type="text" name="name" required><br>
    <label>E‑mail :</label><br>
    <input type="email" name="email" required><br>
    <label>Message :</label><br>
    <textarea name="message" required></textarea><br>
    <!-- Honeypot -->
    <input type="text" name="website" style="display:none">
    <button type="submit">Envoyer</button>
</form>
</body>
</html>
"""

@app.route('/', methods=['GET'])
def index():
    if 'csrf_token' not in session:
        generate_csrf()
    html_page = INDEX_HTML.replace(
        'CSRF_TOKEN_PLACEHOLDER',
        f'<input type="hidden" name="csrf_token" value="{session["csrf_token"]}">'
    )
    return html_page

@app.route('/submit', methods=['POST'])
def submit():
    validate_csrf()
    # Honeypot check
    if request.form.get('website'):
        # silent discard
        return jsonify({'success': True, 'message': 'Merci.'})
    name = sanitize_string(request.form.get('name', ''))
    email = request.form.get('email', '').strip()
    message = sanitize_string(request.form.get('message', ''))

    if not name or not email or not message:
        return jsonify({'success': False, 'message': 'Tous les champs sont requis.'}), 400
    if not is_valid_email(email):
        return jsonify({'success': False, 'message': 'E‑mail invalide.'}), 400

    db = get_db()
    db.execute('''
        INSERT INTO submissions (created_at, ip_hash, form_type, data_json, status)
        VALUES (?, ?, ?, ?, ?)
    ''', (datetime.datetime.utcnow(),
          ip_hash(request.remote_addr),
          'contact',
          json.dumps({'name': name, 'email': email, 'message': message}),
          'new'))
    db.commit()
    return jsonify({'success': True, 'message': 'Message reçu, merci.'})

@app.route('/api/services', methods=['GET'])
def api_services():
    db = get_db()
    cats = db.execute('SELECT id, name, icon, description, order_index FROM service_categories WHERE is_active=1 ORDER BY order_index')
    res = []
    for cat in cats:
        subs = db.execute('''
            SELECT id, title, description, image_url, image_url_2, price, order_index
            FROM service_subcategories
            WHERE category_id=? AND is_active=1 ORDER BY order_index
        ''', (cat['id'],)).fetchall()
        sublist = [dict(sub) for sub in subs]
        res.append({
            'id': cat['id'],
            'name': cat['name'],
            'icon': cat['icon'],
            'description': cat['description'],
            'order_index': cat['order_index'],
            'subcategories': sublist
        })
    return jsonify({'categories': res})

@app.route('/api/articles', methods=['GET'])
def api_articles():
    db = get_db()
    rows = db.execute('''
        SELECT id, title, slug, excerpt, image_url, published_at
        FROM articles
        WHERE status='published'
        ORDER BY published_at DESC
    ''').fetchall()
    articles = [dict(row) for row in rows]
    return jsonify({'articles': articles})

@app.route('/api/gallery', methods=['GET'])
def api_gallery():
    db = get_db()
    rows = db.execute('''
        SELECT id, title, image_url, alt_text, category, order_index
        FROM gallery
        WHERE 1 ORDER BY order_index
    ''').fetchall()
    gallery = [dict(row) for row in rows]
    return jsonify({'gallery': gallery})

# ---------------------------------------------------------
# Admin helpers & decorators
# ---------------------------------------------------------
def login_required(f):
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

def require_admin(f):
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('admin_login'))
        db = get_db()
        cur = db.execute('SELECT role FROM users WHERE id=?', (session['user_id'],))
        row = cur.fetchone()
        if not row or row['role'] != 'admin':
            abort(403)
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

# ---------------------------------------------------------
# Admin routes
# ---------------------------------------------------------
ADMIN_BASE = """
<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>ITSC – Admin</title>
<style>
body {{ background:#0f1117; color:#cfd0d1; margin:0; font-family:Arial,Helvetica,sans-serif; }}
#sidebar {{ width:200px; background:#15171c; position:fixed; top:0; left:0; bottom:0; padding:20px; }}
#sidebar a {{ color:#cfd0d1; text-decoration:none; display:block; margin:10px 0; }}
#content {{ margin-left:220px; padding:20px; }}
button {{ background:#333; color:#cfd0d1; border:none; padding:5px 10px; cursor:pointer; }}
button:hover {{ background:#555; }}
input, textarea {{ background:#222; color:#cfd0d1; border:1px solid #444; padding:5px; width:100%; }}
</style>
{extra_head}
</head>
<body>
<div id="sidebar">
<h2>Admin</h2>
<a href="{dashboard_url}">Tableau de bord</a>
<a href="{services_url}">Services</a>
<a href="{articles_url}">Articles</a>
<a href="{gallery_url}">Galerie</a>
<a href="{users_url}">Utilisateurs</a>
<a href="{messages_url}">Messages</a>
<a href="{logout_url}">Déconnexion</a>
</div>
<div id="content">
{content}
</div>
</body>
</html>
"""

def render_admin(content: str, extra_head: str = ''):
    return ADMIN_BASE.format(
        extra_head=extra_head,
        dashboard_url=url_for('admin_dashboard'),
        services_url=url_for('admin_services'),
        articles_url=url_for('admin_articles'),
        gallery_url=url_for('admin_gallery'),
        users_url=url_for('admin_users'),
        messages_url=url_for('admin_messages'),
        logout_url=url_for('admin_logout'),
        content=content
    )

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        db = get_db()
        cur = db.execute('SELECT id, password_hash, salt, role, is_active FROM users WHERE username=?', (username,))
        user = cur.fetchone()
        if user and user['is_active'] and verify_password(password, user['password_hash'], user['salt']):
            session.clear()
            session['user_id'] = user['id']
            session['role'] = user['role']
            generate_csrf()
            return redirect(url_for('admin_dashboard'))
        error = 'Identifiants invalides.'
    else:
        error = ''
    html_form = f'''
    <h2>Connexion admin</h2>
    <form method="post">
        <label>Identifiant :</label><br>
        <input type="text" name="username" required><br>
        <label>Mot de passe :</label><br>
        <input type="password" name="password" required><br>
        <button type="submit">Se connecter</button>
    </form>
    <p style="color:red">{html.escape(error)}</p>
    '''
    return render_admin(html_form)

@app.route('/admin/logout')
@login_required
def admin_logout():
    session.clear()
    return redirect(url_for('admin_login'))

@app.route('/admin/dashboard')
@require_admin
def admin_dashboard():
    content = '<h2>Tableau de bord</h2><p>Bienvenue, administrateur.</p>'
    return render_admin(content)

# ---------------------------------------------------------
# Service management (Categories & Sub‑categories)
# ---------------------------------------------------------
@app.route('/admin/services')
@require_admin
def admin_services():
    db = get_db()
    rows = db.execute('SELECT id, name, is_active FROM service_categories ORDER BY order_index')
    rows = rows.fetchall()
    items = ''
    for r in rows:
        items += f'''
        <tr>
            <td>{html.escape(r["name"])}</td>
            <td>{"Actif" if r["is_active"] else "Inactif"}</td>
            <td>
                <a href="{url_for('admin_edit_category', cat_id=r['id'])}">Éditer</a> |
                <a href="{url_for('admin_delete_category', cat_id=r['id'])}"
                   onclick="return confirm('Voulez‑vous supprimer «{html.escape(r["name"])}» ?');">Supprimer</a>
            </td>
        </tr>
        '''
    content = f'''
    <h2>Catégories de services</h2>
    <a href="{url_for('admin_new_category')}">+ Nouvelle catégorie</a>
    <table border="1" cellpadding="5" cellspacing="0">
        <tr><th>Nom</th><th>Statut</th><th>Actions</th></tr>
        {items}
    </table>
    '''
    return render_admin(content)

@app.route('/admin/services/categories/new', methods=['GET', 'POST'])
@require_admin
def admin_new_category():
    if request.method == 'POST':
        validate_csrf()
        name = sanitize_string(request.form.get('name', ''))
        icon = sanitize_string(request.form.get('icon', ''))
        description = sanitize_string(request.form.get('description', ''))
        order_index = int(request.form.get('order_index', 0))
        db = get_db()
        db.execute('''
            INSERT INTO service_categories (name, icon, description, order_index, is_active, created_at, updated_at)
            VALUES (?,?,?,?,1,?,?)
        ''', (name, icon, description, order_index,
              datetime.datetime.utcnow(), datetime.datetime.utcnow()))
        db.commit()
        return redirect(url_for('admin_services'))
    token = generate_csrf()
    form = f'''
    <h2>Nouvelle catégorie</h2>
    <form method="post">
        <input type="hidden" name="csrf_token" value="{token}">
        <label>Nom :</label><br><input type="text" name="name" required><br>
        <label>Icône (fa‑class) :</label><br><input type="text" name="icon"><br>
        <label>Description :</label><br><textarea name="description"></textarea><br>
        <label>Ordre :</label><br><input type="number" name="order_index" value="0"><br>
        <button type="submit">Créer</button>
    </form>
    '''
    return render_admin(form)

@app.route('/admin/services/categories/edit/<int:cat_id>', methods=['GET', 'POST'])
@require_admin
def admin_edit_category(cat_id):
    db = get_db()
    cur = db.execute('SELECT * FROM service_categories WHERE id=?', (cat_id,))
    cat = cur.fetchone()
    if not cat:
        abort(404)
    if request.method == 'POST':
        validate_csrf()
        name = sanitize_string(request.form.get('name', ''))
        icon = sanitize_string(request.form.get('icon', ''))
        description = sanitize_string(request.form.get('description', ''))
        order_index = int(request.form.get('order_index', 0))
        is_active = 1 if request.form.get('is_active') == 'on' else 0
        db.execute('''
            UPDATE service_categories
            SET name=?, icon=?, description=?, order_index=?, is_active=?, updated_at=?
            WHERE id=?
        ''', (name, icon, description, order_index, is_active,
              datetime.datetime.utcnow(), cat_id))
        db.commit()
        return redirect(url_for('admin_services'))
    token = generate_csrf()
    checked = 'checked' if cat['is_active'] else ''
    form = f'''
    <h2>Éditer catégorie</h2>
    <form method="post">
        <input type="hidden" name="csrf_token" value="{token}">
        <label>Nom :</label><br><input type="text" name="name" value="{html.escape(cat["name"])}" required><br>
        <label>Icône :</label><br><input type="text" name="icon" value="{html.escape(cat["icon"])}"><br>
        <label>Description :</label><br><textarea name="description">{html.escape(cat["description"])}</textarea><br>
        <label>Ordre :</label><br><input type="number" name="order_index" value="{cat["order_index"]}"><br>
        <label>Actif :</label><input type="checkbox" name="is_active" {checked}><br>
        <button type="submit">Enregistrer</button>
    </form>
    '''
    return render_admin(form)

@app.route('/admin/services/categories/delete/<int:cat_id>', methods=['GET'])
@require_admin
def admin_delete_category(cat_id):
    db = get_db()
    db.execute('DELETE FROM service_categories WHERE id=?', (cat_id,))
    db.commit()
    return redirect(url_for('admin_services'))

# ---------------------------------------------------------
# Sub‑category CRUD (similar pattern – only new/edit/delete shown)
# ---------------------------------------------------------
@app.route('/admin/services/<int:cat_id>')
@require_admin
def admin_subcategories(cat_id):
    db = get_db()
    cat = db.execute('SELECT name FROM service_categories WHERE id=?', (cat_id,)).fetchone()
    if not cat:
        abort(404)
    subs = db.execute('''
        SELECT id, title, price, is_active FROM service_subcategories
        WHERE category_id=? ORDER BY order_index
    ''', (cat_id,)).fetchall()
    rows = ''
    for s in subs:
        rows += f'''
        <tr>
            <td>{html.escape(s["title"])}</td>
            <td>{s["price"]}</td>
            <td>{"Actif" if s["is_active"] else "Inactif"}</td>
            <td>
                <a href="{url_for('admin_edit_sub', sub_id=s['id'])}">Éditer</a> |
                <a href="{url_for('admin_delete_sub', sub_id=s['id'])}"
                   onclick="return confirm('Voulez‑vous supprimer «{html.escape(s["title"])}» ?');">Supprimer</a>
            </td>
        </tr>
        '''
    content = f'''
    <h2>Sous‑catégories de «{html.escape(cat["name"])}»</h2>
    <a href="{url_for('admin_new_sub', cat_id=cat_id)}">+ Nouvelle sous‑catégorie</a>
    <table border="1" cellpadding="5" cellspacing="0">
        <tr><th>Titre</th><th>Prix</th><th>Statut</th><th>Actions</th></tr>
        {rows}
    </table>
    '''
    return render_admin(content)

@app.route('/admin/services/sub/new/<int:cat_id>', methods=['GET', 'POST'])
@require_admin
def admin_new_sub(cat_id):
    if request.method == 'POST':
        validate_csrf()
        title = sanitize_string(request.form.get('title', ''))
        description = sanitize_string(request.form.get('description', ''))
        image_url = sanitize_string(request.form.get('image_url', ''))
        image_url_2 = sanitize_string(request.form.get('image_url_2', ''))
        price = float(request.form.get('price', 0))
        order_index = int(request.form.get('order_index', 0))
        db = get_db()
        db.execute('''
            INSERT INTO service_subcategories
            (category_id, title, description, image_url, image_url_2, price, order_index, is_active, created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        ''', (cat_id, title, description, image_url, image_url_2, price,
              order_index, 1, datetime.datetime.utcnow(), datetime.datetime.utcnow()))
        db.commit()
        return redirect(url_for('admin_subcategories', cat_id=cat_id))
    token = generate_csrf()
    form = f'''
    <h2>Nouvelle sous‑catégorie</h2>
    <form method="post">
        <input type="hidden" name="csrf_token" value="{token}">
        <label>Titre :</label><br><input type="text" name="title" required><br>
        <label>Description :</label><br><textarea name="description"></textarea><br>
        <label>Photo du service (URL) :</label><br>
        <input type="url" name="image_url" id="img1" onchange="preview(this,'preview1')"><br>
        <img id="preview1" style="max-width:200px;margin-top:5px;"><br>
        <label>Photo du service (URL) – deuxième image :</label><br>
        <input type="url" name="image_url_2" id="img2" onchange="preview(this,'preview2')"><br>
        <img id="preview2" style="max-width:200px;margin-top:5px;"><br>
        <label>Prix (€) :</label><br><input type="number" step="0.01" name="price" required><br>
        <label>Ordre :</label><br><input type="number" name="order_index" value="0"><br>
        <button type="submit">Créer</button>
    </form>
    <script>
        function preview(inp, imgId){\n
            var url = inp.value;\n
            document.getElementById(imgId).src = url;\n
        }
    </script>
    '''
    return render_admin(form)

@app.route('/admin/services/sub/edit/<int:sub_id>', methods=['GET', 'POST'])
@require_admin
def admin_edit_sub(sub_id):
    db = get_db()
    cur = db.execute('SELECT * FROM service_subcategories WHERE id=?', (sub_id,))
    sub = cur.fetchone()
    if not sub:
        abort(404)
    if request.method == 'POST':
        validate_csrf()
        title = sanitize_string(request.form.get('title', ''))
        description = sanitize_string(request.form.get('description', ''))
        image_url = sanitize_string(request.form.get('image_url', ''))
        image_url_2 = sanitize_string(request.form.get('image_url_2', ''))
        price = float(request.form.get('price', 0))
        order_index = int(request.form.get('order_index', 0))
        is_active = 1 if request.form.get('is_active') == 'on' else 0
        db.execute('''
            UPDATE service_subcategories
            SET title=?, description=?, image_url=?, image_url_2=?, price=?,
                order_index=?, is_active=?, updated_at=?
            WHERE id=?
        ''', (title, description, image_url, image_url_2, price,
              order_index, is_active, datetime.datetime.utcnow(), sub_id))
        db.commit()
        return redirect(url_for('admin_subcategories', cat_id=sub['category_id']))
    token = generate_csrf()
    checked = 'checked' if sub['is_active'] else ''
    form = f'''
    <h2>Éditer sous‑catégorie</h2>
    <form method="post">
        <input type="hidden" name="csrf_token" value="{token}">
        <label>Titre :</label><br><input type="text" name="title" value="{html.escape(sub["title"])}" required><br>
        <label>Description :</label><br><textarea name="description">{html.escape(sub["description"])}</textarea><br>
        <label>Photo du service (URL) :</label><br>
        <input type="url" name="image_url" id="img1" value="{html.escape(sub["image_url"])}"
               onchange="preview(this,'preview1')"><br>
        <img id="preview1" src="{html.escape(sub["image_url"])}" style="max-width:200px;margin-top:5px;"><br>
        <label>Photo du service (URL) – deuxième image :</label><br>
        <input type="url" name="image_url_2" id="img2" value="{html.escape(sub["image_url_2"])}"
               onchange="preview(this,'preview2')"><br>
        <img id="preview2" src="{html.escape(sub["image_url_2"])}" style="max-width:200px;margin-top:5px;"><br>
        <label>Prix (€) :</label><br><input type="number" step="0.01" name="price" value="{sub["price"]}" required><br>
        <label>Ordre :</label><br><input type="number" name="order_index" value="{sub["order_index"]}"><br>
        <label>Actif :</label><input type="checkbox" name="is_active" {checked}><br>
        <button type="submit">Sauvegarder</button>
    </form>
    <script>
        function preview(inp, imgId){\n
            var url = inp.value;\n
            document.getElementById(imgId).src = url;\n
        }
    </script>
    '''
    return render_admin(form)

@app.route('/admin/services/sub/delete/<int:sub_id>', methods=['GET'])
@require_admin
def admin_delete_sub(sub_id):
    db = get_db()
    db.execute('DELETE FROM service_subcategories WHERE id=?', (sub_id,))
    db.commit()
    return redirect(url_for('admin_services'))

# ---------------------------------------------------------
# Articles CRUD
# ---------------------------------------------------------
@app.route('/admin/articles')
@require_admin
def admin_articles():
    db = get_db()
    rows = db.execute('SELECT id, title, status, created_at FROM articles ORDER BY created_at DESC')
    rows = rows.fetchall()
    items = ''
    for r in rows:
        items += f'''
        <tr>
            <td>{html.escape(r["title"])}</td>
            <td>{r["status"]}</td>
            <td>{r["created_at"]}</td>
            <td>
                <a href="{url_for('admin_edit_article', article_id=r['id'])}">Éditer</a> |
                <a href="{url_for('admin_delete_article', article_id=r['id'])}"
                   onclick="return confirm('Voulez‑vous supprimer «{html.escape(r["title"])}» ?');">Supprimer</a>
            </td>
        </tr>
        '''
    content = f'''
    <h2>Articles</h2>
    <a href="{url_for('admin_new_article')}">+ Nouvel article</a>
    <table border="1" cellpadding="5" cellspacing="0">
        <tr><th>Titre</th><th>Statut</th><th>Créé le</th><th>Actions</th></tr>
        {items}
    </table>
    '''
    return render_admin(content)

@app.route('/admin/articles/new', methods=['GET', 'POST'])
@require_admin
def admin_new_article():
    if request.method == 'POST':
        validate_csrf()
        title = sanitize_string(request.form.get('title', ''))
        slug = sanitize_string(request.form.get('slug', ''))
        content = sanitize_string(request.form.get('content', ''))
        excerpt = sanitize_string(request.form.get('excerpt', ''))
        image_url = sanitize_string(request.form.get('image_url', ''))
        author_id = session['user_id']
        status = request.form.get('status', 'draft')
        db = get_db()
        db.execute('''
            INSERT INTO articles (title, slug, content, excerpt, image_url, author_id, status,
                                  created_at, updated_at)
            VALUES (?,?,?,?,?,?,?, ?, ?)
        ''', (title, slug, content, excerpt, image_url, author_id, status,
              datetime.datetime.utcnow(), datetime.datetime.utcnow()))
        db.commit()
        return redirect(url_for('admin_articles'))
    token = generate_csrf()
    form = f'''
    <h2>Nouvel article</h2>
    <form method="post">
        <input type="hidden" name="csrf_token" value="{token}">
        <label>Titre :</label><br><input type="text" name="title" required><br>
        <label>Slug (URL) :</label><br><input type="text" name="slug" required><br>
        <label>Extrait :</label><br><textarea name="excerpt"></textarea><br>
        <label>Contenu :</label><br><textarea name="content" rows="10"></textarea><br>
        <label>Image (URL) :</label><br><input type="url" name="image_url"><br>
        <label>Statut :</label><br>
        <select name="status">
            <option value="draft">Brouillon</option>
            <option value="published">Publié</option>
        </select><br>
        <button type="submit">Créer</button>
    </form>
    '''
    return render_admin(form)

@app.route('/admin/articles/edit/<int:article_id>', methods=['GET', 'POST'])
@require_admin
def admin_edit_article(article_id):
    db = get_db()
    cur = db.execute('SELECT * FROM articles WHERE id=?', (article_id,))
    article = cur.fetchone()
    if not article:
        abort(404)
    if request.method == 'POST':
        validate_csrf()
        title = sanitize_string(request.form.get('title', ''))
        slug = sanitize_string(request.form.get('slug', ''))
        content = sanitize_string(request.form.get('content', ''))
        excerpt = sanitize_string(request.form.get('excerpt', ''))
        image_url = sanitize_string(request.form.get('image_url', ''))
        status = request.form.get('status', article['status'])
        db.execute('''
            UPDATE articles
            SET title=?, slug=?, content=?, excerpt=?, image_url=?, status=?, updated_at=?
            WHERE id=?
        ''', (title, slug, content, excerpt, image_url, status,
              datetime.datetime.utcnow(), article_id))
        db.commit()
        return redirect(url_for('admin_articles'))
    token = generate_csrf()
    form = f'''
    <h2>Éditer article</h2>
    <form method="post">
        <input type="hidden" name="csrf_token" value="{token}">
        <label>Titre :</label><br><input type="text" name="title" value="{html.escape(article["title"])}" required><br>
        <label>Slug :</label><br><input type="text" name="slug" value="{html.escape(article["slug"])}" required><br>
        <label>Extrait :</label><br><textarea name="excerpt">{html.escape(article["excerpt"])}</textarea><br>
        <label>Contenu :</label><br><textarea name="content" rows="10">{html.escape(article["content"])}</textarea><br>
        <label>Image (URL) :</label><br><input type="url" name="image_url" value="{html.escape(article["image_url"])}"><br>
        <label>Statut :</label><br>
        <select name="status">
            <option value="draft" {"selected" if article["status"]=="draft" else ""}>Brouillon</option>
            <option value="published" {"selected" if article["status"]=="published" else ""}>Publié</option>
        </select><br>
        <button type="submit">Sauvegarder</button>
    </form>
    '''
    return render_admin(form)

@app.route('/admin/articles/delete/<int:article_id>', methods=['GET'])
@require_admin
def admin_delete_article(article_id):
    db = get_db()
    db.execute('DELETE FROM articles WHERE id=?', (article_id,))
    db.commit()
    return redirect(url_for('admin_articles'))

# ---------------------------------------------------------
# Gallery CRUD
# ---------------------------------------------------------
@app.route('/admin/gallery')
@require_admin
def admin_gallery():
    db = get_db()
    rows = db.execute('SELECT id, title, image_url, is_active FROM gallery ORDER BY order_index')
    rows = rows.fetchall()
    items = ''
    for r in rows:
        items += f'''
        <tr>
            <td>{html.escape(r["title"])}</td>
            <td><img src="{html.escape(r["image_url"])}" style="max-width:100px;"></td>
            <td>{"Actif" if r["is_active"] else "Inactif"}</td>
            <td>
                <a href="{url_for('admin_edit_gallery', img_id=r['id'])}">Éditer</a> |
                <a href="{url_for('admin_delete_gallery', img_id=r['id'])}"
                   onclick="return confirm('Voulez‑vous supprimer «{html.escape(r["title"])}» ?');">Supprimer</a>
            </td>
        </tr>
        '''
    content = f'''
    <h2>Galerie</h2>
    <a href="{url_for('admin_new_gallery')}">+ Nouvelle image</a>
    <table border="1" cellpadding="5" cellspacing="0">
        <tr><th>Titre</th><th>Image</th><th>Statut</th><th>Actions</th></tr>
        {items}
    </table>
    '''
    return render_admin(content)

@app.route('/admin/gallery/new', methods=['GET', 'POST'])
@require_admin
def admin_new_gallery():
    if request.method == 'POST':
        validate_csrf()
        title = sanitize_string(request.form.get('title', ''))
        image_url = sanitize_string(request.form.get('image_url', ''))
        alt_text = sanitize_string(request.form.get('alt_text', ''))
        category = sanitize_string(request.form.get('category', ''))
        order_index = int(request.form.get('order_index', 0))
        db = get_db()
        db.execute('''
            INSERT INTO gallery (title, image_url, alt_text, category, order_index, is_active, created_at)
            VALUES (?,?,?,?,?,1,?)
        ''', (title, image_url, alt_text, category, order_index,
              datetime.datetime.utcnow()))
        db.commit()
        return redirect(url_for('admin_gallery'))
    token = generate_csrf()
    form = f'''
    <h2>Nouvelle image de galerie</h2>
    <form method="post">
        <input type="hidden" name="csrf_token" value="{token}">
        <label>Titre :</label><br><input type="text" name="title" required><br>
        <label>Image (URL) :</label><br>
        <input type="url" name="image_url" id="img" onchange="preview(this,'preview')"><br>
        <img id="preview" style="max-width:200px;margin-top:5px;"><br>
        <label>Texte alternatif :</label><br><input type="text" name="alt_text"><br>
        <label>Catégorie :</label><br><input type="text" name="category"><br>
        <label>Ordre :</label><br><input type="number" name="order_index" value="0"><br>
        <button type="submit">Créer</button>
    </form>
    <script>
        function preview(inp, imgId){\n
            document.getElementById(imgId).src = inp.value;\n
        }
    </script>
    '''
    return render_admin(form)

@app.route('/admin/gallery/edit/<int:img_id>', methods=['GET', 'POST'])
@require_admin
def admin_edit_gallery(img_id):
    db = get_db()
    cur = db.execute('SELECT * FROM gallery WHERE id=?', (img_id,))
    img = cur.fetchone()
    if not img:
        abort(404)
    if request.method == 'POST':
        validate_csrf()
        title = sanitize_string(request.form.get('title', ''))
        image_url = sanitize_string(request.form.get('image_url', ''))
        alt_text = sanitize_string(request.form.get('alt_text', ''))
        category = sanitize_string(request.form.get('category', ''))
        order_index = int(request.form.get('order_index', 0))
        is_active = 1 if request.form.get('is_active') == 'on' else 0
        db.execute('''
            UPDATE gallery
            SET title=?, image_url=?, alt_text=?, category=?, order_index=?, is_active=?
            WHERE id=?
        ''', (title, image_url, alt_text, category, order_index, is_active, img_id))
        db.commit()
        return redirect(url_for('admin_gallery'))
    token = generate_csrf()
    checked = 'checked' if img['is_active'] else ''
    form = f'''
    <h2>Éditer image de galerie</h2>
    <form method="post">
        <input type="hidden" name="csrf_token" value="{token}">
        <label>Titre :</label><br><input type="text" name="title" value="{html.escape(img["title"])}" required><br>
        <label>Image (URL) :</label><br>
        <input type="url" name="image_url" id="img" value="{html.escape(img["image_url"])}"
               onchange="preview(this,'preview')"><br>
        <img id="preview" src="{html.escape(img["image_url"])}" style="max-width:200px;margin-top:5px;"><br>
        <label>Texte alternatif :</label><br><input type="text" name="alt_text" value="{html.escape(img["alt_text"])}"><br>
        <label>Catégorie :</label><br><input type="text" name="category" value="{html.escape(img["category"])}"><br>
        <label>Ordre :</label><br><input type="number" name="order_index" value="{img["order_index"]}"><br>
        <label>Actif :</label><input type="checkbox" name="is_active" {checked}><br>
        <button type="submit">Sauvegarder</button>
    </form>
    <script>
        function preview(inp, imgId){\n
            document.getElementById(imgId).src = inp.value;\n
        }
    </script>
    '''
    return render_admin(form)

@app.route('/admin/gallery/delete/<int:img_id>', methods=['GET'])
@require_admin
def admin_delete_gallery(img_id):
    db = get_db()
    db.execute('DELETE FROM gallery WHERE id=?', (img_id,))
    db.commit()
    return redirect(url_for('admin_gallery'))

# ---------------------------------------------------------
# Messages (submissions) view
# ---------------------------------------------------------
@app.route('/admin/messages')
@require_admin
def admin_messages():
    db = get_db()
    rows = db.execute('SELECT id, created_at, form_type, data_json, status FROM submissions ORDER BY created_at DESC')
    rows = rows.fetchall()
    items = ''
    for r in rows:
        data = json.loads(r['data_json'])
        preview = html.escape(data.get('message', ''))[:50]
        items += f'''
        <tr>
            <td>{r["id"]}</td>
            <td>{r["created_at"]}</td>
            <td>{r["form_type"]}</td>
            <td>{preview}…</td>
            <td>{r["status"]}</td>
            <td>
                <a href="{url_for('admin_view_message', msg_id=r['id'])}">Voir</a> |
                <a href="{url_for('admin_mark_message', msg_id=r['id'])}"
                   onclick="return confirm('Marquer comme lu ?');">Marquer lu</a>
            </td>
        </tr>
        '''
    content = f'''
    <h2>Messages reçus</h2>
    <table border="1" cellpadding="5" cellspacing="0">
        <tr><th>ID</th><th>Date</th><th>Formulaire</th><th>Message</th><th>Statut</th><th>Actions</th></tr>
        {items}
    </table>
    '''
    return render_admin(content)

@app.route('/admin/messages/view/<int:msg_id>')
@require_admin
def admin_view_message(msg_id):
    db = get_db()
    cur = db.execute('SELECT data_json, created_at, ip_hash, status FROM submissions WHERE id=?', (msg_id,))
    msg = cur.fetchone()
    if not msg:
        abort(404)
    data = json.loads(msg['data_json'])
    content = f'''
    <h2>Détails du message #{msg_id}</h2>
    <p><strong>Date :</strong> {msg["created_at"]}</p>
    <p><strong>IP hash :</strong> {msg["ip_hash"]}</p>
    <p><strong>Nom :</strong> {html.escape(data.get("name",""))}</p>
    <p><strong>E‑mail :</strong> {html.escape(data.get("email",""))}</p>
    <p><strong>Message :</strong><br>{html.escape(data.get("message","")).replace("\\n","<br>")}</p>
    <p><strong>Statut :</strong> {msg["status"]}</p>
    <a href="{url_for('admin_messages')}">← Retour</a>
    '''
    return render_admin(content)

@app.route('/admin/messages/mark/<int:msg_id>')
@require_admin
def admin_mark_message(msg_id):
    db = get_db()
    db.execute('UPDATE submissions SET status=? WHERE id=?', ('read', msg_id))
    db.commit()
    return redirect(url_for('admin_messages'))

# ---------------------------------------------------------
# Users CRUD (admin only)
# ---------------------------------------------------------
@app.route('/admin/users')
@require_admin
def admin_users():
    db = get_db()
    rows = db.execute('SELECT id, username, email, role, is_active, created_at FROM users')
    rows = rows.fetchall()
    items = ''
    for r in rows:
        items += f'''
        <tr>
            <td>{html.escape(r["username"])}</td>
            <td>{html.escape(r["email"])}</td>
            <td>{r["role"]}</td>
            <td>{"Actif" if r["is_active"] else "Inactif"}</td>
            <td>{r["created_at"]}</td>
            <td>
                <a href="{url_for('admin_edit_user', user_id=r['id'])}">Éditer</a> |
                <a href="{url_for('admin_delete_user', user_id=r['id'])}"
                   onclick="return confirm('Voulez‑vous supprimer l’utilisateur «{html.escape(r["username"])}» ?');">Supprimer</a>
            </td>
        </tr>
        '''
    content = f'''
    <h2>Utilisateurs</h2>
    <a href="{url_for('admin_new_user')}">+ Nouvel utilisateur</a>
    <table border="1" cellpadding="5" cellspacing="0">
        <tr><th>Pseudo</th><th>E‑mail</th><th>Rôle</th><th>Statut</th><th>Créé le</th><th>Actions</th></tr>
        {items}
    </table>
    '''
    return render_admin(content)

@app.route('/admin/users/new', methods=['GET', 'POST'])
@require_admin
def admin_new_user():
    if request.method == 'POST':
        validate_csrf()
        username = sanitize_string(request.form.get('username', ''))
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        role = request.form.get('role', 'editeur')
        is_active = 1 if request.form.get('is_active') == 'on' else 0
        if not is_valid_email(email):
            abort(400)
        pwd_hash, salt = hash_password(password)
        db = get_db()
        db.execute('''
            INSERT INTO users (username, email, password_hash, salt, role, is_active, created_at)
            VALUES (?,?,?,?,?, ?, ?)
        ''', (username, email, pwd_hash, salt, role, is_active,
              datetime.datetime.utcnow()))
        db.commit()
        return redirect(url_for('admin_users'))
    token = generate_csrf()
    form = f'''
    <h2>Nouvel utilisateur</h2>
    <form method="post">
        <input type="hidden" name="csrf_token" value="{token}">
        <label>Pseudo :</label><br><input type="text" name="username" required><br>
        <label>E‑mail :</label><br><input type="email" name="email" required><br>
        <label>Mot de passe :</label><br><input type="password" name="password" required><br>
        <label>Rôle :</label><br>
        <select name="role">
            <option value="editeur">Éditeur</option>
            <option value="admin">Admin</option>
        </select><br>
        <label>Actif :</label><input type="checkbox" name="is_active" checked><br>
        <button type="submit">Créer</button>
    </form>
    '''
    return render_admin(form)

@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@require_admin
def admin_edit_user(user_id):
    db = get_db()
    cur = db.execute('SELECT * FROM users WHERE id=?', (user_id,))
    user = cur.fetchone()
    if not user:
        abort(404)
    if request.method == 'POST':
        validate_csrf()
        username = sanitize_string(request.form.get('username', ''))
        email = request.form.get('email', '').strip()
        role = request.form.get('role', user['role'])
        is_active = 1 if request.form.get('is_active') == 'on' else 0
        db.execute('''
            UPDATE users SET username=?, email=?, role=?, is_active=?
            WHERE id=?
        ''', (username, email, role, is_active, user_id))
        db.commit()
        return redirect(url_for('admin_users'))
    token = generate_csrf()
    checked = 'checked' if user['is_active'] else ''
    form = f'''
    <h2>Éditer utilisateur</h2>
    <form method="post">
        <input type="hidden" name="csrf_token" value="{token}">
        <label>Pseudo :</label><br><input type="text" name="username" value="{html.escape(user["username"])}" required><br>
        <label>E‑mail :</label><br><input type="email" name="email" value="{html.escape(user["email"])}" required><br>
        <label>Rôle :</label><br>
        <select name="role">
            <option value="editeur" {"selected" if user["role"]=="editeur" else ""}>Éditeur</option>
            <option value="admin" {"selected" if user["role"]=="admin" else ""}>Admin</option>
        </select><br>
        <label>Actif :</label><input type="checkbox" name="is_active" {checked}><br>
        <button type="submit">Sauvegarder</button>
    </form>
    '''
    return render_admin(form)

@app.route('/admin/users/delete/<int:user_id>', methods=['GET'])
@require_admin
def admin_delete_user(user_id):
    db = get_db()
    db.execute('DELETE FROM users WHERE id=?', (user_id,))
    db.commit()
    return redirect(url_for('admin_users'))

# ---------------------------------------------------------
# Init & run
# ---------------------------------------------------------
if __name__ == '__main__':
    # create schema if missing
    if not os.path.isfile(DB_PATH):
        schema_sql = '''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'editeur',
            created_at TIMESTAMP NOT NULL,
            last_login TIMESTAMP,
            is_active INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE service_categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            icon TEXT,
            description TEXT,
            order_index INTEGER NOT NULL DEFAULT 0,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMP NOT NULL,
            updated_at TIMESTAMP NOT NULL
        );
        CREATE TABLE service_subcategories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            image_url TEXT,
            image_url_2 TEXT,
            price REAL NOT NULL DEFAULT 0,
            order_index INTEGER NOT NULL DEFAULT 0,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMP NOT NULL,
            updated_at TIMESTAMP NOT NULL,
            FOREIGN KEY(category_id) REFERENCES service_categories(id) ON DELETE CASCADE
        );
        CREATE TABLE articles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            slug TEXT NOT NULL UNIQUE,
            content TEXT,
            excerpt TEXT,
            image_url TEXT,
            author_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'draft',
            created_at TIMESTAMP NOT NULL,
            updated_at TIMESTAMP NOT NULL,
            published_at TIMESTAMP,
            FOREIGN KEY(author_id) REFERENCES users(id)
        );
        CREATE TABLE gallery (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            image_url TEXT NOT NULL,
            alt_text TEXT,
            category TEXT,
            order_index INTEGER NOT NULL DEFAULT 0,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMP NOT NULL
        );
        CREATE TABLE submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TIMESTAMP NOT NULL,
            ip_hash TEXT NOT NULL,
            form_type TEXT NOT NULL,
            data_json TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'new'
        );
        '''
        with open('schema.sql', 'w', encoding='utf-8') as f:
            f.write(schema_sql)
    init_db()
    app.run(host='0.0.0.0', port=5000, threaded=True)