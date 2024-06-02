from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mail import Mail, Message
import hashlib
import sqlite3
import os
import random
import string
import logging

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configuration for Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.hostinger.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'arnav@voezz.com'
app.config['MAIL_PASSWORD'] = 'RmitUniversity0403@'
mail = Mail(app)

# Set up logging
logging.basicConfig(level=logging.DEBUG)

# Function to hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Function to connect to the SQLite database
def connect_db():
    conn = sqlite3.connect('database.db')
    return conn

# Generate a random token
def generate_token(length=32):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

# Send verification email
def send_verification_email(email, token):
    try:
        msg = Message(
            'Password Reset Verification',
            sender='arnav@voezz.com',
            recipients=[email]
        )

        # HTML template for the email
        msg.html = f"""
        <html>
            <head>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        background-color: #f4f4f4;
                        color: #333;
                        line-height: 1.6;
                    }}
                    .container {{
                        max-width: 600px;
                        margin: 20px auto;
                        padding: 20px;
                        background-color: #fff;
                        border: 1px solid #ddd;
                        border-radius: 4px;
                    }}
                    .header {{
                        background-color: #673de6;
                        color: #fff;
                        padding: 10px 0;
                        text-align: center;
                        border-radius: 4px 4px 0 0;
                    }}
                    .content {{
                        padding: 20px;
                    }}
                    .footer {{
                        text-align: center;
                        padding: 10px 0;
                        color: #aaa;
                        font-size: 12px;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>Password Reset Verification</h1>
                    </div>
                    <div class="content">
                        <p>Dear Customer,</p>
                        <p>Greetings from LMS. Below is the OTP for LMS WebApp Registration.</p>
                        <p><strong>OTP: {token}</strong></p>
                        <p>Please note that this One Time Password is valid for 30 minutes.</p>
                        <p>Sincerely,</p>
                        <p>Team LMS</p>
                    </div>
                    <div class="footer">
                        <p>&copy; 2024 LMS. All rights reserved.</p>
                    </div>
                </div>
            </body>
        </html>
        """

        logging.debug('Sending email to: %s', email)
        mail.send(msg)
        logging.debug('Verification email sent successfully')
    except Exception as e:
        logging.error(f'Error sending email: {e}')
        flash('There was an error sending the verification email. Please try again later.', 'error')
# Root route redirects to login
@app.route('/')
def home():
    return redirect(url_for('login'))

# User sign up route
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

        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        if user:
            flash('Username already taken', 'error')
            conn.close()
            return redirect(url_for('signup'))

        hashed_password = hash_password(password)
        cursor.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', (username, email, hashed_password))
        conn.commit()
        conn.close()

        flash('Signup successful, please login', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')



# User login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if not username or not password:
            flash('Username and password cannot be empty', 'error')
            return redirect(url_for('login'))

        hashed_password = hash_password(password)

        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, hashed_password))
        user = cursor.fetchone()
        conn.close()

        if user:
            session['username'] = user[0]
            flash('Login successful', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html')

# Dashboard route (accessible only after login)
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html')
    else:
        flash('You need to login first', 'error')
        return redirect(url_for('login'))


store= ""
# Logout route
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))

# Forgot password route (Step 1: Enter username/email)
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        username = request.form['username']

        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            token = generate_token()
            session['reset_username'] = username  # Store the username in session
            session['verification_token'] = token
            send_verification_email(user[1], token)  # Sending email to user's email
            flash('Verification token sent to your email', 'success')
            return redirect(url_for('verify_token'))
        else:
            flash('Username not found', 'error')
            return redirect(url_for('reset_password'))
    return render_template('reset_password.html')



# Route to verify token
@app.route('/verify_token', methods=['GET', 'POST'])
def verify_token():
    if 'reset_username' not in session:
        flash('You need to provide your username first', 'error')
        return redirect(url_for('reset_password'))

    if request.method == 'POST':
        token = request.form['token']
        if token == session.get('verification_token'):
            return redirect(url_for('reset_password_step2'))
        else:
            flash('Invalid token', 'error')
            return redirect(url_for('verify_token'))
    return render_template('verify_token.html')


@app.route('/reset_password_step2', methods=['GET', 'POST'])
def reset_password_step2():
    if 'reset_username' not in session:
        flash('You need to provide your username or email first', 'error')
        return redirect(url_for('reset_password'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if not new_password or not confirm_password:
            flash('All fields are required', 'error')
            return redirect(url_for('reset_password_step2'))

        if new_password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('reset_password_step2'))

        # Hash the new password
        hashed_password = hash_password(new_password)
        logging.debug(f'Hashed new password: {hashed_password}')

        try:
            # Update the password in the database
            conn = connect_db()
            cursor = conn.cursor()
            username = session["reset_username"]
            logging.debug(f'Username to update: {username}')
            cursor.execute('UPDATE users SET password = ? WHERE username = ?', (hashed_password, username))
            conn.commit()
            
            if cursor.rowcount == 0:
                logging.debug('No rows were updated.')
                flash('Failed to reset password. User not found.', 'error')
                return redirect(url_for('reset_password_step2'))
            else:
                logging.debug('Password updated successfully.')

            conn.close()

            session.pop('reset_username', None)
            session.pop('verification_token', None)

            flash('Password reset successful, please login', 'success')
            return redirect(url_for('login'))
        except sqlite3.Error as e:
            logging.error(f'SQLite error: {e}')
            flash('An error occurred while resetting the password. Please try again later.', 'error')
            return redirect(url_for('reset_password_step2'))

    return render_template('reset_password_step2.html')




@app.route('/debug/users')
def list_users():
    try:
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute('SELECT username FROM users')
        users = cursor.fetchall()
        conn.close()
        
        user_list = [user[0] for user in users]
        logging.debug(f'Users in database: {user_list}')
        return f'Users: {user_list}'
    except sqlite3.Error as e:
        logging.error(f'SQLite error: {e}')
        return 'Error accessing database'
    


if __name__ == '__main__':
    app.run(debug=True)

