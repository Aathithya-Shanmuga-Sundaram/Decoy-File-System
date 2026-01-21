from flask import Flask, render_template, request, redirect, url_for, session
import os
import sqlite3
import hashlib
import time
from faker import Faker

app = Flask(__name__)
app.secret_key = "super_secret_key_change_this"

# ---------------- CONFIG ----------------
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "SecureAdmin@123"  # Change this
DB_PATH = "logs/activity_logs.db"
REAL_DIR = "real_data"
DECOY_DIR = "decoy_data"

fake = Faker()

# ---------------- SETUP ----------------
def setup_environment():
    os.makedirs(REAL_DIR, exist_ok=True)
    os.makedirs(DECOY_DIR, exist_ok=True)
    os.makedirs("logs", exist_ok=True)
    init_db()
    generate_decoy_files()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password_hash TEXT,
            access_type TEXT,
            event TEXT,
            timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()

def log_event(username, password, access_type, event):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    cursor.execute("""
        INSERT INTO logs (username, password_hash, access_type, event, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (username, password_hash, access_type, event, time.ctime()))
    conn.commit()
    conn.close()

# ---------------- DECOY ENGINE ----------------
def generate_decoy_files():
    files = [
        "employee_salaries.txt",
        "bank_accounts.txt",
        "passwords.txt",
        "confidential_report.txt",
        "client_database.txt"
    ]

    for file in files:
        path = os.path.join(DECOY_DIR, file)
        if not os.path.exists(path):
            with open(path, "w") as f:
                for _ in range(20):
                    f.write(f"{fake.name()} | {fake.email()} | {fake.credit_card_number()}\n")

# ---------------- FILE MANAGER ----------------
def get_files(directory):
    return os.listdir(directory)

def read_file(directory, filename):
    with open(os.path.join(directory, filename), "r") as f:
        return f.read()

# ---------------- ROUTES ----------------
@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Only admin gets real access
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            access_type = "REAL"
            session["username"] = username
            session["access_type"] = access_type
            log_event(username, password, access_type, "Admin logged in with real access.")
            return redirect(url_for("dashboard"))
        else:
            access_type = "DECOY"
            session["username"] = username
            session["access_type"] = access_type
            log_event(username, password, access_type, "User granted decoy access.")
            return redirect(url_for("dashboard"))

    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]
    access_type = session["access_type"]

    directory = REAL_DIR if access_type == "REAL" else DECOY_DIR
    files = get_files(directory)

    return render_template("dashboard.html", username=username, access_type=access_type, files=files)

@app.route("/open/<filename>")
def open_file(filename):
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]
    access_type = session["access_type"]
    directory = REAL_DIR if access_type == "REAL" else DECOY_DIR

    file_path = os.path.join(directory, filename)

    # Log file access
    log_event(username, "N/A", access_type, f"Opened file: {filename}")

    # Alert if decoy accessed
    if access_type == "DECOY":
        log_event(username, "N/A", access_type, f"SECURITY ALERT: Decoy file accessed -> {filename}")

    # If it's a text file, display it
    if filename.lower().endswith((".txt", ".log", ".csv", ".md")):
        with open(file_path, "r", errors="ignore") as f:
            content = f.read()
        return render_template(
            "dashboard.html",
            username=username,
            access_type=access_type,
            files=get_files(directory),
            file_content=content,
            opened_file=filename
        )
    else:
        # Otherwise, force download (PDF, DOCX, XLSX, images, etc.)
        from flask import send_from_directory
        return send_from_directory(directory, filename, as_attachment=True)


@app.route("/admin/logs")
def admin_logs():
    if "username" not in session or session["username"] != ADMIN_USERNAME:
        return redirect(url_for("login"))

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM logs ORDER BY id DESC")
    logs = cursor.fetchall()
    conn.close()

    return render_template("admin_logs.html", logs=logs)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------------- RUN ----------------
if __name__ == "__main__":
    setup_environment()
    app.run(debug=True)
