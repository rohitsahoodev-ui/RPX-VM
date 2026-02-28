import os
import random
import string
import datetime
import sqlite3
import bcrypt
import jwt
import psutil
from functools import wraps
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_socketio import SocketIO, emit
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Set absolute path for templates to prevent TemplateNotFound
base_dir = os.path.abspath(os.path.dirname(__file__))
template_dir = os.path.join(base_dir, 'templates')
static_dir = os.path.join(base_dir, 'static')

app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
app.config['SECRET_KEY'] = os.getenv('JWT_SECRET', 'rpx_panel_secret_python_777')
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

DB_PATH = os.getenv('DB_PATH', 'rpx_panel.db')
LOG_FILE = 'rpx_panel.log'

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# --- Database Initialization ---
def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'client',
            balance REAL DEFAULT 0,
            referral_code TEXT UNIQUE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS nodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            ip TEXT NOT NULL,
            location TEXT,
            status TEXT DEFAULT 'online',
            max_ram INTEGER DEFAULT 16384,
            max_cpu INTEGER DEFAULT 8
        );

        CREATE TABLE IF NOT EXISTS containers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            user_id INTEGER NOT NULL,
            node_id INTEGER NOT NULL,
            status TEXT DEFAULT 'stopped',
            ipv4 TEXT,
            cpu INTEGER DEFAULT 1,
            ram INTEGER DEFAULT 512,
            disk INTEGER DEFAULT 10,
            os TEXT DEFAULT 'ubuntu-22.04',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(node_id) REFERENCES nodes(id)
        );

        INSERT OR IGNORE INTO nodes (id, name, ip, location) VALUES (1, 'Python Node - US', '127.0.0.1', 'New York');
    """)
    db.commit()
    db.close()

init_db()

# --- Middleware ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token') or request.headers.get('Authorization')
        if not token:
            # Check session for token if not in headers/args
            token = session.get('token')
            
        if not token:
            return redirect(url_for('login'))
            
        try:
            if 'Bearer ' in token:
                token = token.split(' ')[1]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            db = get_db()
            current_user = db.execute("SELECT * FROM users WHERE id = ?", (data['id'],)).fetchone()
            db.close()
            if not current_user:
                return redirect(url_for('login'))
        except:
            return redirect(url_for('login'))
        return f(current_user, *args, **kwargs)
    return decorated

# --- Routes ---

@app.route('/')
def index():
    return redirect(url_for('dashboard'))

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/dashboard')
@token_required
def dashboard(current_user):
    db = get_db()
    containers = db.execute("SELECT * FROM containers WHERE user_id = ?", (current_user['id'],)).fetchall()
    db.close()
    return render_template('dashboard.html', user=current_user, containers=containers)

@app.route('/vps/create')
@token_required
def create_vps(current_user):
    db = get_db()
    nodes = db.execute("SELECT * FROM nodes WHERE status = 'online'").fetchall()
    db.close()
    return render_template('create_vps.html', user=current_user, nodes=nodes)

@app.route('/vps/<int:id>')
@token_required
def vps_details(current_user, id):
    db = get_db()
    container = db.execute("SELECT * FROM containers WHERE id = ? AND user_id = ?", (id, current_user['id'])).fetchone()
    db.close()
    if not container:
        return "Not Found", 404
    return render_template('vps_details.html', user=current_user, container=container)

@app.route('/billing')
@token_required
def billing(current_user):
    return render_template('billing.html', user=current_user)

@app.route('/admin')
@token_required
def admin(current_user):
    if current_user['role'] != 'admin':
        return redirect(url_for('dashboard'))
    db = get_db()
    nodes = db.execute("SELECT * FROM nodes").fetchall()
    db.close()
    return render_template('admin.html', user=current_user, nodes=nodes)

@app.route('/referral')
@token_required
def referral(current_user):
    return render_template('referral.html', user=current_user)

# --- API ---

@app.route('/api/auth/register', methods=['POST'])
def api_register():
    data = request.json
    hashed_pw = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    ref_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    try:
        db = get_db()
        db.execute("INSERT INTO users (email, password, referral_code) VALUES (?, ?, ?)", (data['email'], hashed_pw, ref_code))
        db.commit()
        db.close()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    data = request.json
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email = ?", (data['email'],)).fetchone()
    db.close()
    if user and bcrypt.checkpw(data['password'].encode('utf-8'), user['password'].encode('utf-8')):
        token = jwt.encode({
            'id': user['id'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'])
        return jsonify({"token": token, "user": dict(user)})
    return jsonify({"error": "Invalid credentials"}), 401

@app.route('/api/containers', methods=['POST'])
@token_required
def api_create_container(current_user):
    data = request.json
    ipv4 = f"10.0.0.{random.randint(2, 254)}"
    db = get_db()
    try:
        cursor = db.execute("""
            INSERT INTO containers (name, user_id, node_id, ipv4, cpu, ram, disk, os, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'running')
        """, (data['name'], current_user['id'], data['node_id'], ipv4, data['cpu'], data['ram'], data['disk'], data['os']))
        db.commit()
        new_id = cursor.lastrowid
        db.close()
        return jsonify({"id": new_id})
    except Exception as e:
        db.close()
        return jsonify({"error": str(e)}), 400

@app.route('/api/system/stats')
@token_required
def get_system_stats(current_user):
    if current_user['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 403
    
    stats = {
        "cpu_usage": psutil.cpu_percent(interval=None),
        "ram_usage": psutil.virtual_memory().percent,
        "disk_usage": psutil.disk_usage('/').percent,
        "uptime": datetime.datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S"),
        "containers_count": 0,
        "users_count": 0
    }
    
    db = get_db()
    stats["containers_count"] = db.execute("SELECT COUNT(*) FROM containers").fetchone()[0]
    stats["users_count"] = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    db.close()
    
    return jsonify(stats)

@app.route('/api/vps/<int:id>/action', methods=['POST'])
@token_required
def vps_action(current_user, id):
    data = request.json
    action = data.get('action')
    
    db = get_db()
    container = db.execute("SELECT * FROM containers WHERE id = ? AND user_id = ?", (id, current_user['id'])).fetchone()
    
    if not container:
        db.close()
        return jsonify({"error": "VPS not found"}), 404
    
    new_status = 'running' if action in ['start', 'restart'] else 'stopped'
    db.execute("UPDATE containers SET status = ? WHERE id = ?", (new_status, id))
    db.commit()
    db.close()
    
    with open(LOG_FILE, 'a') as f:
        f.write(f"[{datetime.datetime.now()}] User {current_user['email']} performed {action} on VPS {container['name']}\n")
        
    return jsonify({"success": True, "status": new_status})

@app.route('/api/user/add-balance', methods=['POST'])
@token_required
def add_balance(current_user):
    data = request.json
    amount = float(data.get('amount', 0))
    
    if amount <= 0:
        return jsonify({"error": "Invalid amount"}), 400
        
    db = get_db()
    db.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, current_user['id']))
    db.commit()
    db.close()
    
    return jsonify({"success": True})

# --- Socket.io ---
@socketio.on('get_vps_stats')
def handle_stats(vps_id):
    def emit_stats():
        while True:
            socketio.emit(f'vps_stats_{vps_id}', {
                'cpu': round(random.uniform(1, 15), 2),
                'ram': round(random.uniform(10, 80), 2),
                'net': round(random.uniform(0.1, 5), 2)
            })
            socketio.sleep(2)
    socketio.start_background_task(emit_stats)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=3000, debug=True)
