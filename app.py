import sqlite3
import os
import socket
import secrets
from datetime import datetime
from functools import wraps
from flask import Flask, request, render_template, jsonify, g, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
DATABASE = os.environ.get("EZKOPY_DB", "clipboard.db")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    with sqlite3.connect(DATABASE) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                pin TEXT,
                whitelisted_ips TEXT,
                is_admin INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS clipboards (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                content TEXT NOT NULL DEFAULT '',
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                ip TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)
        db.commit()


def get_user_by_username(username):
    return get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def get_user_by_id(user_id):
    return get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def get_clipboard(user_id):
    row = get_db().execute("SELECT content FROM clipboards WHERE user_id = ?", (user_id,)).fetchone()
    return row["content"] if row else ""


def set_clipboard(user_id, text):
    db = get_db()
    existing = db.execute("SELECT id FROM clipboards WHERE user_id = ?", (user_id,)).fetchone()
    if existing:
        db.execute("UPDATE clipboards SET content = ?, updated_at = ? WHERE user_id = ?", 
                   (text, datetime.now().isoformat(), user_id))
    else:
        db.execute("INSERT INTO clipboards (user_id, content) VALUES (?, ?)", (user_id, text))
    db.commit()


def log_action(user_id, action, ip=None):
    db = get_db()
    db.execute("INSERT INTO logs (user_id, action, ip) VALUES (?, ?, ?)", (user_id, action, ip))
    db.commit()


def get_client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()


def check_terminal_auth(username, pin=None):
    """Check if terminal request is authorized via PIN or IP whitelist"""
    user = get_user_by_username(username)
    if not user:
        return None
    
    client_ip = get_client_ip()
    user_pin = user["pin"]
    whitelisted_ips = user["whitelisted_ips"] or ""
    ip_list = [ip.strip() for ip in whitelisted_ips.split(",") if ip.strip()]
    
    # Check PIN
    if pin and user_pin and pin == user_pin:
        return user
    
    # Check IP whitelist
    if client_ip in ip_list:
        return user
    
    return None


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        user = get_user_by_id(session["user_id"])
        if not user or not user["is_admin"]:
            flash("Admin access required", "error")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated


def get_host_info():
    hostname = socket.gethostname()
    try:
        ip = socket.gethostbyname(hostname)
    except:
        ip = "127.0.0.1"
    return hostname, ip


# ============ Auth Routes ============

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        
        if not username or not password:
            flash("Username and password required", "error")
            return render_template("register.html")
        
        if len(username) < 3:
            flash("Username must be at least 3 characters", "error")
            return render_template("register.html")
        
        if get_user_by_username(username):
            flash("Username already taken", "error")
            return render_template("register.html")
        
        db = get_db()
        # First user becomes admin
        is_admin = 1 if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0 else 0
        
        db.execute(
            "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), is_admin)
        )
        db.commit()
        
        user = get_user_by_username(username)
        log_action(user["id"], "register", get_client_ip())
        
        flash("Registration successful! Please login.", "success")
        return redirect(url_for("login"))
    
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        
        user = get_user_by_username(username)
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            log_action(user["id"], "login", get_client_ip())
            return redirect(url_for("index"))
        
        flash("Invalid username or password", "error")
    
    return render_template("login.html")


@app.route("/logout")
def logout():
    if "user_id" in session:
        log_action(session["user_id"], "logout", get_client_ip())
    session.clear()
    return redirect(url_for("login"))


# ============ Main Routes ============

@app.route("/")
@login_required
def index():
    user = get_user_by_id(session["user_id"])
    hostname, ip = get_host_info()
    host = request.host
    return render_template("index.html", 
                           user=user,
                           clipboard=get_clipboard(user["id"]), 
                           hostname=hostname, 
                           ip=ip, 
                           host=host)


@app.route("/raw", methods=["GET", "POST"])
@login_required
def raw():
    user_id = session["user_id"]
    if request.method == "POST":
        set_clipboard(user_id, request.get_data(as_text=True))
        log_action(user_id, "clipboard_set_web", get_client_ip())
        return "OK"
    return get_clipboard(user_id)


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    user = get_user_by_id(session["user_id"])
    
    if request.method == "POST":
        pin = request.form.get("pin", "").strip()
        whitelisted_ips = request.form.get("whitelisted_ips", "").strip()
        
        # Validate: at least one must be set
        if not pin and not whitelisted_ips:
            flash("At least PIN or IP whitelist must be set", "error")
            return render_template("settings.html", user=user, client_ip=get_client_ip())
        
        db = get_db()
        db.execute("UPDATE users SET pin = ?, whitelisted_ips = ? WHERE id = ?",
                   (pin or None, whitelisted_ips or None, user["id"]))
        db.commit()
        
        log_action(user["id"], "settings_update", get_client_ip())
        flash("Settings saved!", "success")
        return redirect(url_for("settings"))
    
    return render_template("settings.html", user=user, client_ip=get_client_ip())


# ============ Terminal API Routes ============

@app.route("/u/<username>/<pin>/raw", methods=["GET", "POST"])
def terminal_raw_with_pin(username, pin):
    user = check_terminal_auth(username, pin)
    if not user:
        return "Unauthorized", 401
    
    if request.method == "POST":
        set_clipboard(user["id"], request.get_data(as_text=True))
        log_action(user["id"], "clipboard_set_terminal", get_client_ip())
        return "OK"
    
    log_action(user["id"], "clipboard_get_terminal", get_client_ip())
    return get_clipboard(user["id"])


@app.route("/u/<username>/raw", methods=["GET", "POST"])
def terminal_raw_ip_only(username):
    user = check_terminal_auth(username)
    if not user:
        return "Unauthorized - IP not whitelisted", 401
    
    if request.method == "POST":
        set_clipboard(user["id"], request.get_data(as_text=True))
        log_action(user["id"], "clipboard_set_terminal_ip", get_client_ip())
        return "OK"
    
    log_action(user["id"], "clipboard_get_terminal_ip", get_client_ip())
    return get_clipboard(user["id"])


# ============ Admin Routes ============

@app.route("/admin")
@admin_required
def admin():
    db = get_db()
    users = db.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    logs = db.execute("""
        SELECT logs.*, users.username 
        FROM logs 
        LEFT JOIN users ON logs.user_id = users.id 
        ORDER BY logs.created_at DESC 
        LIMIT 100
    """).fetchall()
    return render_template("admin.html", users=users, logs=logs)


@app.route("/admin/user/<int:user_id>/toggle-admin", methods=["POST"])
@admin_required
def toggle_admin(user_id):
    if user_id == session["user_id"]:
        flash("Cannot modify your own admin status", "error")
        return redirect(url_for("admin"))
    
    db = get_db()
    user = get_user_by_id(user_id)
    if user:
        new_status = 0 if user["is_admin"] else 1
        db.execute("UPDATE users SET is_admin = ? WHERE id = ?", (new_status, user_id))
        db.commit()
        log_action(session["user_id"], f"toggle_admin_{user['username']}_{new_status}", get_client_ip())
    
    return redirect(url_for("admin"))


@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@admin_required
def delete_user(user_id):
    if user_id == session["user_id"]:
        flash("Cannot delete yourself", "error")
        return redirect(url_for("admin"))
    
    db = get_db()
    user = get_user_by_id(user_id)
    if user:
        db.execute("DELETE FROM clipboards WHERE user_id = ?", (user_id,))
        db.execute("DELETE FROM logs WHERE user_id = ?", (user_id,))
        db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        db.commit()
        log_action(session["user_id"], f"delete_user_{user['username']}", get_client_ip())
        flash(f"User {user['username']} deleted", "success")
    
    return redirect(url_for("admin"))


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
