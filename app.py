from flask import Flask, render_template, request, jsonify
import sqlite3
import hashlib
import os
import re

app = Flask(__name__)
DB_NAME = "web_users.db"


def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash BLOB NOT NULL,
                salt BLOB NOT NULL
            )
        """)
        conn.commit()


def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return pwd_hash, salt


# Serve the main webpage
@app.route('/')
def home():
    return render_template('index.html')


# API Route: Register
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    name = data.get('name', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({"success": False, "message": "Invalid email format."}), 400
    if len(password) < 6:
        return jsonify({"success": False, "message": "Password must be at least 6 characters long."}), 400
    if not name:
        return jsonify({"success": False, "message": "Name cannot be empty."}), 400

    pwd_hash, salt = hash_password(password)
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (name, email, password_hash, salt) VALUES (?, ?, ?, ?)",
                           (name, email, pwd_hash, salt))
            conn.commit()
        return jsonify({"success": True, "message": "Registration successful!"})
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "message": "An account with this email already exists."}), 400


# API Route: Login
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash, salt, name FROM users WHERE email = ?", (email,))
        row = cursor.fetchone()

    if row:
        stored_hash, salt, name = row
        computed_hash, _ = hash_password(password, salt)
        if hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000) == stored_hash:
            return jsonify({"success": True, "message": f"Welcome back, {name}!"})

    return jsonify({"success": False, "message": "Invalid email or password."}), 401


if __name__ == '__main__':
    init_db()
    # Check if we are in the cloud; default to port 5000 and local debug mode if not
    port = int(os.environ.get("PORT", 5000))
    is_cloud = "PORT" in os.environ

    app.run(host="0.0.0.0", port=port, debug=not is_cloud)