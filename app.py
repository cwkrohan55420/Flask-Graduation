from flask import Flask, render_template, request, redirect, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "secretkey"  # For session management

DB_FILE = "myapp.db"  # SQLite database file

# -------------------------------
# Helper function to get DB connection
# -------------------------------
def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

# -------------------------------
# Create users table if it doesn't exist
# -------------------------------
with get_db_connection() as conn:
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()

# -------------------------------
# Home page
# -------------------------------
@app.route('/')
def index():
    if 'user' in session:
        return render_template('index.html', username=session['user'])
    return redirect('/login')

# -------------------------------
# Login page
# -------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user'] = username
            return redirect('/')
        else:
            return render_template('login.html', error="Invalid username or password")

    return render_template('login.html')

# -------------------------------
# Register page
# -------------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm = request.form['confirm']

        if password != confirm:
            return render_template('register.html', error="Passwords do not match")

        hashed_password = generate_password_hash(password)

        try:
            conn = get_db_connection()
            conn.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hashed_password)
            )
            conn.commit()
            conn.close()

            session['user'] = username
            return redirect('/')

        except sqlite3.IntegrityError:
            return render_template('register.html', error="Username already exists")

    return render_template('register.html')

# -------------------------------
# Logout
# -------------------------------
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/login')

# -------------------------------
# Run the Flask app
# -------------------------------
if __name__ == '__main__':
    app.run(debug=True)