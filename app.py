from flask import Flask, request, jsonify, session, redirect, url_for
import flask_hashing
import secrets

app = Flask(__name__)

app.secret_key = secrets.token_hex(32)

hashing = flask_hashing.Hashing(app)

@app.route('/')
def index():
    if 'username' in session:
        return f"Hello, {session['username']}! Welcome back."
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username and password:
            hashed_password = hashing.hash_value(password, salt='my_salt')
            # TODO: Check hashed_password against stored hash
            session['username'] = username
            return redirect(url_for('index'))

