import os
from dotenv import load_dotenv
from flask import Flask, request, render_template, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from supabase import create_client, Client
from functools import wraps

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev_key")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.Text, nullable=False)
    role = db.Column(db.String(20), nullable=False)

class VendorDetails(db.Model):
    __tablename__ = 'vendor_details'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True)
    company_name = db.Column(db.String(150), nullable=False)
    ownership_type = db.Column(db.String(50), nullable=False)
    registered_address = db.Column(db.Text)
    branch_addresses = db.Column(db.Text)
    email = db.Column(db.String(120))
    phone = db.Column(db.String(20))
    website = db.Column(db.String(200))
    turnover = db.Column(db.String(10))
    tan_number = db.Column(db.String(20))
    gst_number = db.Column(db.String(20))
    product_services = db.Column(db.Text)
    tan_proof_path = db.Column(db.String(200))
    gst_proof_path = db.Column(db.String(200))
    bs_year1_path = db.Column(db.String(200))
    bs_year2_path = db.Column(db.String(200))
    bs_year3_path = db.Column(db.String(200))

class SoleOwner(db.Model):
    __tablename__ = 'sole_owners'
    id = db.Column(db.Integer, primary_key=True)
    vendor_id = db.Column(db.Integer, db.ForeignKey('vendor_details.id'))
    name = db.Column(db.String(100))
    email = db.Column(db.String(120))
    phone = db.Column(db.String(20))
    pan_number = db.Column(db.String(20))

class Partner(db.Model):
    __tablename__ = 'partners'
    id = db.Column(db.Integer, primary_key=True)
    vendor_id = db.Column(db.Integer, db.ForeignKey('vendor_details.id'))
    name = db.Column(db.String(100))
    email = db.Column(db.String(120))
    phone = db.Column(db.String(20))
    pan_number = db.Column(db.String(20))

class PvtLtdDirector(db.Model):
    __tablename__ = 'pvtltd_directors'
    id = db.Column(db.Integer, primary_key=True)
    vendor_id = db.Column(db.Integer, db.ForeignKey('vendor_details.id'))
    name = db.Column(db.String(100))
    email = db.Column(db.String(120))
    phone = db.Column(db.String(20))
    pan_number = db.Column(db.String(20))

class PublicLtdDirector(db.Model):
    __tablename__ = 'publicltd_directors'
    id = db.Column(db.Integer, primary_key=True)
    vendor_id = db.Column(db.Integer, db.ForeignKey('vendor_details.id'))
    name = db.Column(db.String(100))
    email = db.Column(db.String(120))
    phone = db.Column(db.String(20))
    pan_number = db.Column(db.String(20))




# Decorators
def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapped

def role_required(required_role):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if session.get('role') != required_role:
                abort(403)
            return f(*args, **kwargs)
        return wrapped
    return decorator


@app.route('/')
def home():
    return redirect(url_for('login'))

# Signup Route
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form.get('email')                  
        raw_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if raw_password != confirm_password:
            flash("Passwords do not match.")
            return redirect(url_for('signup'))

        if User.query.filter_by(email=email).first():
            flash("Email already registered.")
            return redirect(url_for('signup'))

        # Step 1: Create User
        password_hash = generate_password_hash(raw_password)
        user = User(email=email, password_hash=password_hash, role='vendor')
        db.session.add(user)
        db.session.flush()  # ✅ Ensure user.id is available without committing

        # Step 2: Prepare Vendor
        vendor = VendorDetails(
            user_id=user.id,  # ✅ Explicitly set user_id
            company_name=request.form.get('company_name'),
            ownership_type=request.form.get('ownership'),
            registered_address=request.form.get('address'),
            branch_addresses="\n\n".join(request.form.getlist('baddress[]')),
            email=email,
            phone=request.form.get('phone'),
            website=request.form.get('website'),
            tan_number=request.form.get('tan_number'),
            gst_number=request.form.get('gst_number'),
            turnover=request.form.get('turnover'),
            product_services=", ".join(request.form.getlist('products[]'))
        )
        db.session.add(vendor)
        db.session.flush()  # ✅ Ensure vendor.id is available for ownership tables

        # Step 3: Ownership-Specific
        ownership = request.form.get('ownership')
        if ownership == "sole":
            db.session.add(SoleOwner(
                vendor_id=vendor.id,  # ✅ Use vendor_id, not model object
                name=request.form.get('sole_name'),
                email=request.form.get('sole_email'),
                phone=request.form.get('sole_phone'),
                pan_number=request.form.get('sole_pan')
            ))
        elif ownership == "partnership":
            for i in [1, 2]:
                db.session.add(Partner(
                    vendor_id=vendor.id,
                    name=request.form.get(f'partner{i}_name'),
                    email=request.form.get(f'partner{i}_email'),
                    phone=request.form.get(f'partner{i}_phone'),
                    pan_number=request.form.get(f'partner{i}_pan')
                ))
        elif ownership == "pvtltd":
            for i in [1, 2]:
                db.session.add(PvtLtdDirector(
                    vendor_id=vendor.id,
                    name=request.form.get(f'director{i}_name'),
                    email=request.form.get(f'director{i}_email'),
                    phone=request.form.get(f'director{i}_phone'),
                    pan_number=request.form.get(f'director{i}_pan')
                ))
        elif ownership == "publicltd":
            for i in [1, 2, 3]:
                db.session.add(PublicLtdDirector(
                    vendor_id=vendor.id,
                    name=request.form.get(f'dir{i}_name'),
                    email=request.form.get(f'dir{i}_email'),
                    phone=request.form.get(f'dir{i}_phone'),
                    pan_number=request.form.get(f'dir{i}_pan')
                ))

        # Step 4: Upload files & store Supabase paths
        upload_fields = {
            'tan_proof': 'tan_proof_path',
            'gst_proof': 'gst_proof_path',
            'bs_year1': 'bs_year1_path',
            'bs_year2': 'bs_year2_path',
            'bs_year3': 'bs_year3_path'
        }

        for field_name, attr in upload_fields.items():
            file = request.files.get(field_name)
            if file and file.filename:
                from uuid import uuid4
                filename = f"{uuid4()}_{secure_filename(file.filename)}"
                path = f"{user.id}/{field_name}/{filename}"
                supabase.storage.from_("vendor-uploads").upload(
                    path=path,
                    file=file.read(),
                    file_options={"cache-control": "3600", "upsert": "false"}
                )
                setattr(vendor, attr, path)

        # ✅ Final Commit
        db.session.commit()

        flash("Signup successful! Please log in.")
        return redirect(url_for('login'))

    return render_template("signup.html")


# Login Route
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        raw_password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, raw_password):
            session['user_id'] = user.id
            session['role'] = user.role
            session['email'] = user.email
            flash("Logged in successfully.")

            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('vendor_dashboard'))
        else:
            flash("Invalid credentials.")
    return render_template("login.html")

# Logout
@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for('login'))

# Dashboards
@app.route("/vendor-dashboard")
@login_required
@role_required('vendor')
def vendor_dashboard():
    return render_template("vendor_dashboard.html")

@app.route("/admin-dashboard")
@login_required
@role_required('admin')
def admin_dashboard():
    return render_template("admin_dashboard.html")

# Run App
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)