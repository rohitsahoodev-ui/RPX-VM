import threading
import time
import os
import sqlite3
import json
import bcrypt
import jwt
import datetime
import subprocess
import psutil
import shlex
import logging
from flask import Flask, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit
from functools import wraps

# --- LOGGING ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("rpx_panel.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# --- CONFIGURATION ---
SECRET_KEY = "rpx_super_secret_key_777"
DB_PATH = "rpx_panel.db"
STATIC_DIR = "public"

app = Flask(__name__, static_folder=STATIC_DIR)
socketio = SocketIO(app, cors_allowed_origins="*")

# --- DATABASE SETUP ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password TEXT,
        role TEXT DEFAULT 'client',
        balance REAL DEFAULT 0.0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Locations table
    cursor.execute('''CREATE TABLE IF NOT EXISTS locations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        short_name TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Nodes table
    cursor.execute('''CREATE TABLE IF NOT EXISTS nodes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        location_id INTEGER,
        ip TEXT,
        fqdn TEXT,
        api_key TEXT,
        status TEXT DEFAULT 'offline',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(location_id) REFERENCES locations(id)
    )''')
    
    # Containers table
    cursor.execute('''CREATE TABLE IF NOT EXISTS containers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        node_id INTEGER,
        name TEXT UNIQUE,
        hostname TEXT,
        cpu INTEGER,
        ram INTEGER,
        disk INTEGER,
        status TEXT DEFAULT 'stopped',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(node_id) REFERENCES nodes(id)
    )''')
    
    # Create default admin if not exists
    cursor.execute("SELECT * FROM users WHERE email='admin@rpxpanel.io'")
    if not cursor.fetchone():
        hashed = bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt())
        cursor.execute("INSERT INTO users (email, password, role) VALUES (?, ?, ?)", 
                       ('admin@rpxpanel.io', hashed, 'admin'))
        logger.info("Default admin user created.")
    
    conn.commit()
    conn.close()

init_db()
logger.info("Database initialized.")

# --- MIDDLEWARE ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token.split(" ")[1], SECRET_KEY, algorithms=["HS256"])
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE id=?", (data['user_id'],))
            current_user = cursor.fetchone()
            conn.close()
            if not current_user:
                return jsonify({'message': 'User not found!'}), 401
        except Exception as e:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# --- BACKGROUND TASKS ---
def update_statuses():
    while True:
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Update Node statuses (simple ping for now)
            cursor.execute("SELECT id, ip FROM nodes")
            nodes = cursor.fetchall()
            for node_id, ip in nodes:
                # Real ping or API check would go here
                status = 'online' # Assume online for local node
                cursor.execute("UPDATE nodes SET status=? WHERE id=?", (status, node_id))
            
            # Update Container statuses
            cursor.execute("SELECT id, name FROM containers")
            containers = cursor.fetchall()
            for cont_id, name in containers:
                try:
                    # REAL LXC STATUS CHECK
                    cmd = f"lxc-info -n {name} -s"
                    output = subprocess.check_output(shlex.split(cmd)).decode()
                    status = output.split(":")[1].strip().lower()
                    cursor.execute("UPDATE containers SET status=? WHERE id=?", (status, cont_id))
                except:
                    cursor.execute("UPDATE containers SET status='unknown' WHERE id=?", (cont_id,))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Status update error: {e}")
        time.sleep(10)

# --- ROUTES: STATS ---
@app.route('/api/stats', methods=['GET'])
@token_required
def get_stats(current_user):
    # REAL SYSTEM STATS
    cpu = psutil.cpu_percent()
    ram = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    users_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM containers")
    vps_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM nodes")
    nodes_count = cursor.fetchone()[0]
    conn.close()
    
    return jsonify({
        'cpu': cpu,
        'ram': ram,
        'disk': disk,
        'users': users_count,
        'vps': vps_count,
        'nodes': nodes_count
    })

# --- ROUTES: CONTAINER ACTIONS ---
@app.route('/api/containers/<int:id>/action', methods=['POST'])
@token_required
def container_action(current_user, id):
    action = request.json.get('action')
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM containers WHERE id=?", (id,))
    container = cursor.fetchone()
    if not container:
        conn.close()
        return jsonify({'message': 'Container not found'}), 404
    
    name = container[0]
    try:
        if action == 'start':
            subprocess.Popen(shlex.split(f"lxc-start -n {name}"))
        elif action == 'stop':
            subprocess.Popen(shlex.split(f"lxc-stop -n {name}"))
        elif action == 'restart':
            subprocess.Popen(shlex.split(f"lxc-stop -n {name}"))
            time.sleep(2)
            subprocess.Popen(shlex.split(f"lxc-start -n {name}"))
        elif action == 'delete':
            subprocess.Popen(shlex.split(f"lxc-destroy -n {name}"))
            cursor.execute("DELETE FROM containers WHERE id=?", (id,))
            conn.commit()
        
        conn.close()
        return jsonify({'message': f'Action {action} initiated'})
    except Exception as e:
        conn.close()
        return jsonify({'message': str(e)}), 500

# --- ROUTES: AUTH ---
@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email=?", (data['email'],))
    user = cursor.fetchone()
    conn.close()
    
    if user and bcrypt.checkpw(data['password'].encode('utf-8'), user[2]):
        token = jwt.encode({
            'user_id': user[0],
            'role': user[3],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, SECRET_KEY)
        return jsonify({'token': token, 'role': user[3]})
    
    return jsonify({'message': 'Invalid credentials'}), 401

# --- ROUTES: LOCATIONS ---
@app.route('/api/locations', methods=['GET', 'POST'])
@token_required
def manage_locations(current_user):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    if request.method == 'POST':
        if current_user[3] != 'admin': return jsonify({'message': 'Forbidden'}), 403
        data = request.json
        cursor.execute("INSERT INTO locations (name, short_name) VALUES (?, ?)", (data['name'], data['short_name']))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Location added'})
    
    cursor.execute("SELECT * FROM locations")
    locs = [{'id': r[0], 'name': r[1], 'short_name': r[2]} for r in cursor.fetchall()]
    conn.close()
    return jsonify(locs)

# --- ROUTES: NODES ---
@app.route('/api/nodes', methods=['GET', 'POST'])
@token_required
def manage_nodes(current_user):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    if request.method == 'POST':
        if current_user[3] != 'admin': return jsonify({'message': 'Forbidden'}), 403
        data = request.json
        cursor.execute("INSERT INTO nodes (name, location_id, ip, fqdn, api_key) VALUES (?, ?, ?, ?, ?)", 
                       (data['name'], data['location_id'], data['ip'], data['fqdn'], data['api_key']))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Node added'})
    
    cursor.execute("SELECT nodes.*, locations.name FROM nodes JOIN locations ON nodes.location_id = locations.id")
    nodes = [{'id': r[0], 'name': r[1], 'location': r[8], 'ip': r[3], 'status': r[6]} for r in cursor.fetchall()]
    conn.close()
    return jsonify(nodes)

# --- ROUTES: CONTAINERS ---
@app.route('/api/containers', methods=['GET', 'POST'])
@token_required
def manage_containers(current_user):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    if request.method == 'POST':
        if current_user[3] != 'admin': return jsonify({'message': 'Forbidden'}), 403
        data = request.json
        # REAL LXC CREATE COMMAND
        try:
            cmd = f"lxc-create -n {data['name']} -t download -- -d ubuntu -r focal -a amd64"
            subprocess.Popen(shlex.split(cmd))
            cursor.execute("INSERT INTO containers (user_id, node_id, name, hostname, cpu, ram, disk) VALUES (?, ?, ?, ?, ?, ?, ?)",
                           (data['user_id'], data['node_id'], data['name'], data['hostname'], data['cpu'], data['ram'], data['disk']))
            conn.commit()
        except Exception as e:
            return jsonify({'message': str(e)}), 500
        finally:
            conn.close()
        return jsonify({'message': 'Container creation started'})
    
    if current_user[3] == 'admin':
        cursor.execute("SELECT * FROM containers")
    else:
        cursor.execute("SELECT * FROM containers WHERE user_id=?", (current_user[0],))
    
    conts = [{'id': r[0], 'name': r[3], 'status': r[8], 'cpu': r[5], 'ram': r[6]} for r in cursor.fetchall()]
    conn.close()
    return jsonify(conts)

# --- STATIC FILE SERVING ---
@app.route('/')
def index():
    return send_from_directory(STATIC_DIR, 'login.html')

@app.route('/<path:path>')
def serve_static(path):
    if not os.path.exists(os.path.join(STATIC_DIR, path)):
        return send_from_directory(STATIC_DIR, 'index.html')
    return send_from_directory(STATIC_DIR, path)

# --- WEBSOCKETS FOR CONSOLE ---
@socketio.on('console_input')
def handle_console(data):
    container = data['container']
    command = data['command']
    # REAL LXC EXEC
    try:
        full_cmd = f"lxc-attach -n {container} -- {command}"
        result = subprocess.check_output(shlex.split(full_cmd), stderr=subprocess.STDOUT, timeout=5)
        emit('console_output', {'output': result.decode()})
    except Exception as e:
        emit('console_output', {'output': str(e)})

if __name__ == '__main__':
    if not os.path.exists(STATIC_DIR):
        os.makedirs(STATIC_DIR)
    
    # Start status update thread
    threading.Thread(target=update_statuses, daemon=True).start()
    logger.info("Background status updater started.")
    
    logger.info("RPX PANEL – V1 starting on port 3000...")
    socketio.run(app, host='0.0.0.0', port=3000)
