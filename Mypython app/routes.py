from flask import render_template, redirect, url_for, request, flash
from app import app, db
from app.models import User
from werkzeug.security import generate_password_hash, check_password_hash
import random
import string

@app.route('/')
def index():
    return render_template('index.html')

from flask import Flask, render_template, request, redirect, url_for, session, flash
import hashlib
import sqlite3

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

# Function to hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Function to connect to the SQLite database
def connect_db():
    conn = sqlite3.connect('database.db')
    return conn

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if not username or not email or not password or not confirm_password:
            flash('All fields are required', 'error')
            return redirect(url_for('signup'))

        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('signup'))

        session['signup_data'] = {
            'username': username,
            'email': email,
            'password': password
        }

        verification_token = ''.join(random.choices(string.ascii_letters + string.digits, k=6))

        session['verification_token'] = verification_token

        return redirect(url_for('verify_data'))

    return render_template('signup.html')

@app.route('/verify_data', methods=['GET', 'POST'])
def verify_data():
    if request.method == 'POST':
        user_token = request.form['token']
        verification_token = session.get('verification_token')

        if user_token == verification_token:
            signup_data = session.get('signup_data')

            # Storing user data in the database
            new_user = User(username=signup_data['username'], email=signup_data['email'], password=signup_data['password'])
            db.session.add(new_user)
            db.session.commit()

            session.pop('signup_data')
            session.pop('verification_token')

            flash('Signup successful, please login', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid token', 'error')

    return render_template('verify_data.html')
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')



# app/models.py







