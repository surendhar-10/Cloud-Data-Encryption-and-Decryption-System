import os, sqlite3, uuid, hashlib
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from io import BytesIO

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "database.db")
STORAGE_DIR = os.path.join(APP_DIR, "cloud_storage")
os.makedirs(STORAGE_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-this-development-secret-before-deployment")
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25 MB

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            salt BLOB NOT NULL,
            nonce BLOB NOT NULL,
            sha256 TEXT NOT NULL,
            size INTEGER NOT NULL,
            uploaded_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )""")

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode("utf-8"))

@app.route("/")
def index():
    return redirect(url_for("dashboard") if session.get("user_id") else url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if len(username) < 3 or len(password) < 8:
            flash("Username must be 3+ characters and password must be at least 8 characters.")
            return render_template("register.html")
        try:
            with db() as conn:
                conn.execute("INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?)",
                             (username, generate_password_hash(password), datetime.now().isoformat(timespec="seconds")))
            flash("Account created. Please log in.")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("That username is already taken.")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with db() as conn:
            user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
def dashboard():
    if not session.get("user_id"):
        return redirect(url_for("login"))
    with db() as conn:
        files = conn.execute("SELECT * FROM files WHERE user_id=? ORDER BY uploaded_at DESC",
                             (session["user_id"],)).fetchall()
    return render_template("dashboard.html", files=files)

@app.route("/upload", methods=["POST"])
def upload():
    if not session.get("user_id"):
        return redirect(url_for("login"))
    uploaded = request.files.get("file")
    password = request.form.get("encryption_password", "")
    if not uploaded or not uploaded.filename:
        flash("Choose a file to upload.")
        return redirect(url_for("dashboard"))
    if len(password) < 8:
        flash("Use an encryption password with at least 8 characters.")
        return redirect(url_for("dashboard"))
    raw = uploaded.read()
    if not raw:
        flash("The selected file is empty.")
        return redirect(url_for("dashboard"))
    salt, nonce = os.urandom(16), os.urandom(12)
    key = derive_key(password, salt)
    encrypted = AESGCM(key).encrypt(nonce, raw, None)
    file_id = uuid.uuid4().hex
    stored_name = file_id + ".enc"
    with open(os.path.join(STORAGE_DIR, stored_name), "wb") as f:
        f.write(encrypted)
    with db() as conn:
        conn.execute("""INSERT INTO files
            (id,user_id,original_name,stored_name,salt,nonce,sha256,size,uploaded_at)
            VALUES(?,?,?,?,?,?,?,?,?)""",
            (file_id, session["user_id"], secure_filename(uploaded.filename) or "download",
             stored_name, salt, nonce, hashlib.sha256(raw).hexdigest(), len(raw),
             datetime.now().isoformat(timespec="seconds")))
    flash("File encrypted with AES-256-GCM and stored successfully.")
    return redirect(url_for("dashboard"))

@app.route("/download/<file_id>", methods=["POST"])
def download(file_id):
    if not session.get("user_id"):
        return redirect(url_for("login"))
    password = request.form.get("decryption_password", "")
    with db() as conn:
        record = conn.execute("SELECT * FROM files WHERE id=? AND user_id=?",
                              (file_id, session["user_id"])).fetchone()
    if not record:
        flash("File not found.")
        return redirect(url_for("dashboard"))
    try:
        key = derive_key(password, record["salt"])
        path = os.path.join(STORAGE_DIR, record["stored_name"])
        with open(path, "rb") as f:
            ciphertext = f.read()
        plaintext = AESGCM(key).decrypt(record["nonce"], ciphertext, None)
        if hashlib.sha256(plaintext).hexdigest() != record["sha256"]:
            raise ValueError("Integrity check failed")
        return send_file(BytesIO(plaintext), as_attachment=True,
                         download_name=record["original_name"],
                         mimetype="application/octet-stream")
    except Exception:
        flash("Decryption failed. Check your encryption password; the file may be damaged.")
        return redirect(url_for("dashboard"))

@app.errorhandler(413)
def too_large(_):
    flash("File is too large. Maximum upload size is 25 MB.")
    return redirect(url_for("dashboard"))

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
