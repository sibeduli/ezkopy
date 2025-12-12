import sqlite3
import os
import socket
from flask import Flask, request, render_template, jsonify, g

app = Flask(__name__)
DATABASE = os.environ.get("EZKOPY_DB", "clipboard.db")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
    return g.db


@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    with sqlite3.connect(DATABASE) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS clipboard (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                content TEXT NOT NULL DEFAULT ''
            )
        """)
        db.execute("INSERT OR IGNORE INTO clipboard (id, content) VALUES (1, '')")
        db.commit()


def get_clipboard():
    row = get_db().execute("SELECT content FROM clipboard WHERE id = 1").fetchone()
    return row[0] if row else ""


def set_clipboard(text):
    db = get_db()
    db.execute("UPDATE clipboard SET content = ? WHERE id = 1", (text,))
    db.commit()


def get_host_info():
    """Get server hostname and IP for display"""
    hostname = socket.gethostname()
    try:
        ip = socket.gethostbyname(hostname)
    except:
        ip = "127.0.0.1"
    return hostname, ip


@app.route("/")
def index():
    hostname, ip = get_host_info()
    port = request.host.split(":")[-1] if ":" in request.host else "5000"
    return render_template("index.html", clipboard=get_clipboard(), hostname=hostname, ip=ip, port=port)


@app.route("/raw", methods=["GET", "POST"])
def raw():
    if request.method == "POST":
        set_clipboard(request.get_data(as_text=True))
        return "OK"
    return get_clipboard()


@app.route("/api", methods=["GET", "POST"])
def api():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        text = data.get("text", request.get_data(as_text=True))
        set_clipboard(text)
        return jsonify({"status": "ok", "length": len(text)})
    text = get_clipboard()
    return jsonify({"text": text, "length": len(text)})


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
