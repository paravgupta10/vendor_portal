from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.permanent_session_lifetime = timedelta(days=1)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:TM16SKJZ18pg!!@db.ryfwobovbxrkypiqoscm.supabase.co:5432/postgres'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# -----------------------------
# Database Model
# -----------------------------
class Vendor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company_name = db.Column(db.String(100), nullable=False)
    contact_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    business_type = db.Column(db.String(50))
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(10), default='vendor')  # or 'admin'
    status = db.Column(db.String(20), default='pending')

# -----------------------------
# Routes
# -----------------------------

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        data = request.form
        if data['password'] != data['confirm_password']:
            flash("Passwords do not match", "error")
            return redirect(url_for('signup'))

        existing_user = Vendor.query.filter_by(email=data['email']).first()
        if existing_user:
            flash("Email already registered", "error")
            return redirect(url_for('signup'))

        new_vendor = Vendor(
            company_name=data['company_name'],
            contact_name=data['contact_name'],
            email=data['email'],
            phone=data['phone'],
            business_type=data['business_type'],
            password_hash=generate_password_hash(data['password']),
            role='vendor'
        )
        db.session.add(new_vendor)
        db.session.commit()
        flash("Signup successful! Please log in.", "success")
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.form
        user = Vendor.query.filter_by(email=data['email'], role=data['role']).first()
        if user and check_password_hash(user.password_hash, data['password']):
            session['user_id'] = user.id
            session['user_role'] = user.role
            session['company'] = user.company_name
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials", "error")
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        return f"Welcome, {session['company']}! You are logged in as {session['user_role']}."
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out", "info")
    return redirect(url_for('login'))

# -----------------------------
# Run
# -----------------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
