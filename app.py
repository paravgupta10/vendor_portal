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
    city = db.Column(db.String(30))
    state = db.Column(db.String(30))
    country = db.Column(db.String(30))
    status = db.Column(db.String(20), default='Pending')  

class BranchOffice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vendor_id = db.Column(db.Integer, db.ForeignKey('vendor_details.id'))
    address = db.Column(db.Text, nullable=False)
    city = db.Column(db.String(30))
    state = db.Column(db.String(30))
    country = db.Column(db.String(30))

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

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        raw_password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, raw_password):
            session['user_id'] = user.id
            session['email'] = user.email

            flash("Logged in successfully.")

            if user.email == "admin1@example.com":
                return redirect(url_for('admin_dashboard'))

            vendor_record = VendorDetails.query.filter_by(user_id=user.id).first()
            if vendor_record:
                return redirect(url_for('vendor_dashboard'))
            else:
                return redirect(url_for('signup'))

        else:
            flash("Invalid credentials.")
    return render_template("login.html")

@app.route("/register_user", methods=["POST"])
def register_user():
    email = request.form.get("email")
    password = request.form.get("password")
    confirm_password = request.form.get("confirm_password")

    if password != confirm_password:
        flash("Passwords do not match.")
        return redirect(url_for('login'))

    if User.query.filter_by(email=email).first():
        flash("Email already registered.")
        return redirect(url_for('login'))

    password_hash = generate_password_hash(password)
    new_user = User(email=email, password_hash=password_hash, role='vendor')
    db.session.add(new_user)
    db.session.commit()

    flash("Registration successful! Please log in.")
    return redirect(url_for('login'))

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if 'user_id' not in session:
        flash("Please log in to complete your registration.")
        return redirect(url_for('login'))

    user_id = session['user_id']
    email = session['email']

    existing_vendor = VendorDetails.query.filter_by(user_id=user_id).first()
    if existing_vendor:
        return redirect(url_for('vendor_dashboard'))

    if request.method == "POST":
        vendor = VendorDetails(
            user_id=user_id,
            company_name=request.form.get('company_name'),
            ownership_type=request.form.get('ownership'),
            registered_address=request.form.get('address'),
            branch_addresses="\n\n".join(request.form.getlist('baddress[]')),
            city=request.form.get('city'),
            state=request.form.get('state'),
            country=request.form.get('country'),
            status="Pending",
            email=email,
            phone=request.form.get('phone'),
            website=request.form.get('website'),
            tan_number=request.form.get('tan_number'),
            gst_number=request.form.get('gst_number'),
            turnover=request.form.get('turnover'),
            product_services=", ".join(request.form.getlist('products[]'))
        )

        db.session.add(vendor)
        db.session.flush()

        ownership = request.form.get('ownership')
        if ownership == "sole":
            db.session.add(SoleOwner(
                vendor_id=vendor.id,
                name=request.form.get('sole_name'),
                email=request.form.get('sole_email'),
                phone=request.form.get('sole_phone'),
                pan_number=request.form.get('sole_pan')
            ))
        elif ownership in ["partnership", "llp"]:
            i = 1
            while True:
                name = request.form.get(f'partner{i}_name')
                if not name:
                    break
                db.session.add(Partner(
                    vendor_id=vendor.id,
                    name=name,
                    email=request.form.get(f'partner{i}_email'),
                    phone=request.form.get(f'partner{i}_phone'),
                    pan_number=request.form.get(f'partner{i}_pan'),
                    ownership_type=ownership
                ))
                i += 1
        elif ownership == "pvtltd":
            i = 1
            while True:
                name = request.form.get(f'director{i}_name')
                if not name:
                    break
                db.session.add(PvtLtdDirector(
                    vendor_id=vendor.id,
                    name=name,
                    email=request.form.get(f'director{i}_email'),
                    phone=request.form.get(f'director{i}_phone'),
                    pan_number=request.form.get(f'director{i}_pan')
                ))
                i += 1
        elif ownership == "publicltd":
            i = 1
            while True:
                name = request.form.get(f'dir{i}_name')
                if not name:
                    break
                db.session.add(PublicLtdDirector(
                    vendor_id=vendor.id,
                    name=name,
                    email=request.form.get(f'dir{i}_email'),
                    phone=request.form.get(f'dir{i}_phone'),
                    pan_number=request.form.get(f'dir{i}_pan')
                ))
                i += 1

        branch_addresses = request.form.getlist('baddress[]')
        branch_cities = request.form.getlist('bcity[]')
        branch_states = request.form.getlist('bstate[]')
        branch_countries = request.form.getlist('bcountry[]')

        for addr, city, state, country in zip(branch_addresses, branch_cities, branch_states, branch_countries):
            if addr.strip():
                db.session.add(BranchOffice(
                    vendor_id=vendor.id,
                    address=addr.strip(),
                    city=city.strip(),
                    state=state.strip(),
                    country=country.strip()
                ))

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
                path = f"{user_id}/{field_name}/{filename}"
                supabase.storage.from_("vendor-uploads").upload(
                    path=path,
                    file=file.read(),
                    file_options={"cache-control": "3600", "upsert": "false"}
                )
                setattr(vendor, attr, path)

        db.session.commit()

        flash("Signup successful!")
        return redirect(url_for('vendor_dashboard'))

    return render_template("signup.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for('login'))

@app.route("/vendor-dashboard")
@login_required
def vendor_dashboard():
    if session.get('email') == "admin1@example.com":
        return redirect(url_for('admin_dashboard'))

    vendor = VendorDetails.query.filter_by(user_id=session['user_id']).first()
    if not vendor:
        flash("Vendor details not found.")
        return redirect(url_for('logout'))
    return render_template("vendor_dashboard.html", company=vendor.company_name)

@app.route("/admin-dashboard")
@login_required
def admin_dashboard():
    if session.get('email') != "admin1@example.com":
        flash("Unauthorized access.")
        return redirect(url_for('vendor_dashboard'))

    return render_template("admin_dashboard.html")

@app.route("/admin/view-registrations")
@login_required
def view_registrations():
    if session.get('email') != "admin1@example.com":
        flash("Unauthorized access.")
        return redirect(url_for('vendor_dashboard'))

    vendors = VendorDetails.query.all()
    return render_template("view_registrations.html", vendors=vendors)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
