import os
import sqlite3
import threading
from urllib.parse import urlparse

from flask import (
    Flask, request, render_template, redirect, url_for,
    session, g, abort
)
from werkzeug.security import generate_password_hash, check_password_hash

from bot import run_bot

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("DATA_DIR", os.path.join(BASE_DIR, "data"))
os.makedirs(DATA_DIR, exist_ok=True)
DATABASE = os.path.join(DATA_DIR, "lab.db")

FLAG = os.environ.get("FLAG", "FLAG{stored_xss_owns_the_admin}")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "insecure-dev-secret")
# HttpOnly: JS cannot read the session cookie. XSS must use fetch() instead. set to False to enable one to escalate to admin via STEALING ADMIN session cooking using stored xss.
app.config["SESSION_COOKIE_HTTPONLY"] = False
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# --------------------------------------------------------------------------
# DB
# --------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_):
    db = g.pop("db", None)
    if db:
        db.close()

def init_db():
    conn = sqlite3.connect(DATABASE)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author TEXT NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            reported_by TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS exfil (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            data TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
    """)
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        for u, p, a in [("admin", "admin", 1), ("alice", "alice", 0), ("bob", "bob", 0)]:
            conn.execute(
                "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
                (u, generate_password_hash(p), a),
            )
        conn.execute(
            "INSERT INTO posts (author, title, body) VALUES (?, ?, ?)",
            ("admin", "Welcome to MiniBoard", "Please be nice. Report suspicious URLs to me."),
        )
    conn.commit()
    conn.close()

init_db()

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def current_user():
    if "user_id" not in session:
        return None
    return get_db().execute(
        "SELECT id, username, is_admin FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()

@app.context_processor
def inject_user():
    return {"user": current_user()}

# --------------------------------------------------------------------------
# Auth
# --------------------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u = (request.form.get("username") or "").strip()
        p = request.form.get("password") or ""
        if not u or not p:
            return render_template("auth.html", mode="register", error="Username and password are required")
        try:
            db = get_db()
            db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (u, generate_password_hash(p)),
            )
            db.commit()
        except sqlite3.IntegrityError:
            return render_template("auth.html", mode="register", error="Username taken")
        return redirect(url_for("login"))
    return render_template("auth.html", mode="register")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username") or ""
        p = request.form.get("password") or ""
        row = get_db().execute("SELECT * FROM users WHERE username = ?", (u,)).fetchone()
        if row and check_password_hash(row["password_hash"], p):
            session["user_id"] = row["id"]
            return redirect(url_for("index"))
        return render_template("auth.html", mode="login", error="Invalid credentials")
    return render_template("auth.html", mode="login")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# --------------------------------------------------------------------------
# Posts
# --------------------------------------------------------------------------
@app.route("/")
def index():
    posts = get_db().execute(
        "SELECT id, author, title, created_at FROM posts ORDER BY id DESC"
    ).fetchall()
    return render_template("index.html", posts=posts)

@app.route("/posts/new", methods=["GET", "POST"])
def new_post():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        body = request.form.get("body") or ""
        if not title:
            return render_template("new_post.html", error="Title is required")
        db = get_db()
        db.execute(
            "INSERT INTO posts (author, title, body) VALUES (?, ?, ?)",
            (current_user()["username"], title, body),
        )
        db.commit()
        return redirect(url_for("index"))
    return render_template("new_post.html")

@app.route("/posts/<int:post_id>")
def view_post(post_id):
    post = get_db().execute("SELECT * FROM posts WHERE id = ?", (post_id,)).fetchone()
    if not post:
        abort(404)
    return render_template("post.html", post=post)

# --------------------------------------------------------------------------
# Reflected XSS endpoint
# --------------------------------------------------------------------------
@app.route("/search")
def search():
    q = request.args.get("q", "")
    results = []
    if q:
        # Note: parameterized SQL — SQL injection is NOT the bug here.
        # The bug is in search.html where `q` is rendered with |safe.
        results = get_db().execute(
            "SELECT id, author, title FROM posts WHERE title LIKE ? OR body LIKE ?",
            (f"%{q}%", f"%{q}%"),
        ).fetchall()
    return render_template("search.html", q=q, results=results)

# --------------------------------------------------------------------------
# DOM XSS endpoint — reads location.hash into innerHTML
# --------------------------------------------------------------------------
@app.route("/messages")
def messages():
    # Server only ships a static shell. Everything happens client-side.
    return render_template("messages.html")

# --------------------------------------------------------------------------
# Report → spawn admin bot
# --------------------------------------------------------------------------
_bot_lock = threading.Lock()

@app.route("/report", methods=["GET", "POST"])
def report():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if request.method == "POST":
        url = (request.form.get("url") or "").strip()
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or parsed.hostname not in ("127.0.0.1", "localhost"):
            return render_template("report.html",
                error="URL must point at 127.0.0.1 or localhost (the lab itself).")
        db = get_db()
        db.execute(
            "INSERT INTO reports (url, reported_by) VALUES (?, ?)",
            (url, current_user()["username"]),
        )
        db.commit()

        def _dispatch():
            if not _bot_lock.acquire(blocking=False):
                print("[report] bot busy, skipping", flush=True)
                return
            try:
                run_bot(url)
            finally:
                _bot_lock.release()

        threading.Thread(target=_dispatch, daemon=True).start()
        return render_template("report.html",
            success="Admin bot is reviewing the URL. Check /exfil/log in ~10-15 seconds.")
    return render_template("report.html")

# --------------------------------------------------------------------------
# Admin panel — where the flag lives (only admin can see it)
# --------------------------------------------------------------------------
@app.route("/admin")
def admin():
    user = current_user()
    if not user or not user["is_admin"]:
        abort(403)
    reports = get_db().execute(
        "SELECT * FROM reports ORDER BY id DESC LIMIT 20"
    ).fetchall()
    return render_template("admin.html", flag=FLAG, reports=reports)

# --------------------------------------------------------------------------
# Exfil endpoint — attacker-controlled. XSS sends stolen data here.
# --------------------------------------------------------------------------
@app.route("/exfil", methods=["GET", "POST"])
def exfil():
    data = request.args.get("data") or (request.form.get("data") if request.method == "POST" else "")
    if data:
        db = get_db()
        db.execute("INSERT INTO exfil (data) VALUES (?)", (data,))
        db.commit()
    return "OK", 200

@app.route("/exfil/log")
def exfil_log():
    if "user_id" not in session:
        return redirect(url_for("login"))
    rows = get_db().execute(
        "SELECT id, data, created_at FROM exfil ORDER BY id DESC LIMIT 50"
    ).fetchall()
    return render_template("exfil.html", rows=rows)

# --------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True, debug=False)