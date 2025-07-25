from flask import Flask, request, jsonify, session, redirect, url_for
import flask_hashing  # type: ignore
import secrets
import cfg
import os
import wg
import base64
import sqlite3
import hashlib

app = Flask(__name__)

app.secret_key = secrets.token_hex(32)

hashing = flask_hashing.Hashing(app)

config = cfg.load_config(os.getenv('WGWEB_CONFIG_FILE', 'config.ini'))

wgconfig = config['WireGuard']


@app.route('/')
def index():
    if 'username' in session:
        # return f"Hello, {session['username']}! Welcome back."
        return app.send_static_file('index.html')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    with sqlite3.connect(config['WebServer'].get('UsersDatabase', 'users.db')) as db:
        cursor = db.cursor()
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            app.logger.info(f"Login attempt for user: {username}")
            if username and password:
            # hashed_password = hashing.hash_value(password, salt=f'{hashlib.sha256(username.encode()).hexdigest()[8:16]}')
                try:
                    app.logger.info(f"SQL Query: SELECT passwdhash FROM auth WHERE username='{username}'")
                    hashed_password = cursor.execute(f"SELECT passwdhash FROM auth WHERE username='{username}'").fetchone()[0]
                except TypeError as e:
                    app.logger.error(f"Error fetching user: {e}")
                    return "Error occurred", 400
                if hashing.check_value(hashed_password, password, salt=f'{hashlib.sha256(username.encode()).hexdigest()[8:16]}'):
                    session['username'] = username
                    return redirect(url_for('index'))
                    # return jsonify({"message": "Login successful", "username": username, "hashed_password": hashed_password})
                return "Invalid credentials", 400
            return "Username and password are required", 400

    # Render a simple login form
    if request.method == 'GET':
        return app.send_static_file('login.html')

# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
#         if not username or not password:
#             return "Username and password are required", 400
        
#         hashed_password = hashing.hash_value(password, salt=f'{hashlib.sha256(username.encode()).hexdigest()[8:16]}')
        
#         with sqlite3.connect(config['WebServer'].get('UsersDatabase', 'users.db')) as db:
#             cursor = db.cursor()
#             try:
#                 cursor.execute("INSERT INTO auth (username, passwdhash) VALUES (?, ?)", (username, hashed_password))
#                 db.commit()
#                 return "User registered successfully", 201
#             except sqlite3.IntegrityError:
#                 return "Username already exists", 400

#     return '''
#         <form method="post">
#             Username: <input type="text" name="username"><br>
#             Password: <input type="password" name="password"><br>
#             <input type="submit" value="Register">
#         </form>
#     '''

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/peers', methods=['POST', 'GET'])
def get_peers():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        
        try:
            peers = wg.get_peers_comment(wgconfig)
            peers = [{"public_key": peer[0], "IP": peer[1], "comment": peer[2]} for peer in peers]
            peers = sorted(peers, key=lambda x: x['comment'].lower())
            # Filter peers based on the session username
            if session['username'] != 'admin':
                # Assuming the comment contains the username
                peers = [peer for peer in peers if peer['comment'].startswith(f'# {session["username"]}')]
            return jsonify(peers)
        except ValueError as ve:
            return jsonify({"error": str(ve)}), 400
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    if request.method == 'GET':
        return app.send_static_file('peers.html')
    
@app.route('/add_peer', methods=['GET'])
def add_peer_form():
    if 'username' not in session:
        return redirect(url_for('login'))
    return app.send_static_file('add_peer.html')

@app.route('/add_peer', methods=['POST'])
def add_peer():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.content_type == 'application/json':
        clientaddr = request.json.get('clientaddr')
        comment = request.json.get('comment', 'None')
    elif request.content_type == 'application/x-www-form-urlencoded':
        clientaddr = request.form.get('clientaddr')
        comment = request.form.get('comment', 'None')

    comment = f'# {session.get("username", "admin")} {comment}'

    try:
        client_config = wg.add_peer(wgconfig, clientaddr, comment)
        return jsonify({"message": "Configuration updated successfully", "client_config": base64.b64encode(client_config.encode()).decode()})
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500
        raise e
    
@app.route('/del_peer', methods=['POST'])
def del_peer():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.content_type == 'application/json':
        public_key = request.json.get('public_key')
    elif request.content_type == 'application/x-www-form-urlencoded':
        public_key = request.form.get('public_key')

    try:
        wg.del_peer(wgconfig, public_key)
        return jsonify({"message": "Peer deleted successfully"})
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500
