import os, random
from dotenv import load_dotenv
from flask import Flask, request, render_template, redirect, url_for, flash, session, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from supabase import create_client, Client
from functools import wraps
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer

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


app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")  # your email
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")  # app password
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_USERNAME")

mail = Mail(app)
s = URLSafeTimedSerializer(app.secret_key)  # for generating tokens

#ROUTES

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

@app.route("/register", methods=["POST"])
def register():
    email = request.form.get("email")
    password = request.form.get("password")
    confirm_password = request.form.get("confirm_password")

    if password != confirm_password:
        flash("Passwords do not match.")
        return redirect(url_for('login'))
    
    if len(password) < 6:
        flash("Password must be at least 6 characters long.")
        return redirect(url_for('login'))


    if User.query.filter_by(email=email).first():
        flash("Email already registered.")
        return redirect(url_for('login'))

    code = str(random.randint(100000, 999999))
    session['email_verification'] = {
        'email': email,
        'password': password,
        'code': code
    }

    msg = Message("Your Verification Code", recipients=[email], sender="your_email@gmail.com")
    msg.body = f"Your verification code is {code}"
    mail.send(msg)

    return redirect(url_for('verify_code'))

@app.route("/verify_code", methods=["GET", "POST"])
def verify_code():
    if request.method == "POST":
        entered_code = request.form.get("code")
        data = session.get('email_verification')

        if data and entered_code == data['code']:
            email = data['email']
            password_hash = generate_password_hash(data['password'])
            new_user = User(email=email, password_hash=password_hash, role='vendor')
            db.session.add(new_user)
            db.session.commit()
            session.pop('email_verification', None)
            flash("Registration successful!")
            return redirect(url_for('login'))
        else:
            flash("Invalid verification code.")
            return redirect(url_for('verify_code'))

    return render_template("verify_code.html")

@app.route('/resend_code', methods=['POST'])
def resend_code():
    session_data = session.get('email_verification')
    if not session_data:
        flash("No verification session found. Please register again.")
        return redirect(url_for('login'))

    code = str(random.randint(100000, 999999))
    session_data['code'] = code
    session['email_verification'] = session_data

    msg = Message("Your New Verification Code", recipients=[session_data['email']], sender="your_email@gmail.com")
    msg.body = f"Your new verification code is {code}"
    mail.send(msg)

    flash("A new verification code has been sent to your email.")
    return redirect(url_for('verify_code'))



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

@app.route('/admin/review-vendors')
def review_vendors():
    if session.get("email") != "admin1@example.com":
        return redirect(url_for('login'))
    
    vendors = VendorDetails.query.all()  # assuming your signup table model is called Signup
    return render_template('review_vendors.html', vendors=vendors)

@app.route('/admin/update-vendor-status', methods=['POST'])
def update_vendor_status():
    if session.get("email") != "admin1@example.com":
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    data = request.get_json()
    vendor_id = data.get('id')
    new_status = data.get('status')

    vendor = VendorDetails.query.get(vendor_id)
    if not vendor:
        return jsonify({'success': False, 'message': 'Vendor not found'}), 404

    vendor.status = new_status
    db.session.commit()

    return jsonify({'success': True, 'message': f'Status updated to {new_status}'})

@app.route('/admin/vendor-details/<int:vendor_id>')
@login_required
def get_vendor_details(vendor_id):
    if session.get("email") != "admin1@example.com":
        return jsonify({'error': 'Unauthorized'}), 403

    vendor = VendorDetails.query.get_or_404(vendor_id)

    details = {
        "company_name": vendor.company_name,
        "email": vendor.email,
        "phone": vendor.phone,
        "status": vendor.status,
        "ownership_type": vendor.ownership_type,
        "registered_address": vendor.registered_address,
        "branch_addresses": vendor.branch_addresses,
        "tan_number": vendor.tan_number,
        "gst_number": vendor.gst_number,
        "product_services": vendor.product_services,
    }

    ownership = vendor.ownership_type.lower()

    if ownership == 'sole':
        sole_owner = SoleOwner.query.filter_by(vendor_id=vendor.id).first()
        if sole_owner:
            details['sole_owner'] = {
                "name": sole_owner.name,
                "email": sole_owner.email,
                "phone": sole_owner.phone,
                "pan_number": sole_owner.pan_number
            }

    elif ownership == 'partnership':
        partners = Partner.query.filter_by(vendor_id=vendor.id).all()
        if partners:
            details['partners'] = [{
                "name": p.name,
                "email": p.email,
                "phone": p.phone,
                "pan_number": p.pan_number
            } for p in partners]

    elif ownership == 'private limited':
        directors = PvtLtdDirector.query.filter_by(vendor_id=vendor.id).all()
        if directors:
            details['directors'] = [{
                "name": d.name,
                "email": d.email,
                "phone": d.phone,
                "pan_number": d.pan_number
            } for d in directors]

    elif ownership == 'public limited':
        directors = PublicLtdDirector.query.filter_by(vendor_id=vendor.id).all()
        if directors:
            details['directors'] = [{
                "name": d.name,
                "email": d.email,
                "phone": d.phone,
                "pan_number": d.pan_number
            } for d in directors]

    return jsonify(details)


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")
        user = User.query.filter_by(email=email).first()
        if user:
            token = s.dumps(email, salt='password-reset')
            reset_url = url_for('reset_password', token=token, _external=True)

            msg = Message("Password Reset Request", recipients=[email])
            msg.body = f"Click the link to reset your password: {reset_url}"
            mail.send(msg)

            flash("Reset link sent to your email.", "info")
            return redirect(url_for("login"))
        else:
            flash("Email not found.", "danger")
    return render_template("forgot_password.html")

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        email = s.loads(token, salt="password-reset", max_age=3600)  # 1 hour expiry
    except Exception:
        flash("The reset link is invalid or expired.", "danger")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        if len(new_password) < 6:
            flash("Password must be at least 6 characters long.")
            return render_template("reset_password.html")
        
        if new_password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("reset_password.html")

        user = User.query.filter_by(email=email).first()
        if user:
            user.password_hash = generate_password_hash(new_password)
            db.session.commit()
            flash("Password reset successful. Please log in.", "success")
            return redirect(url_for("login"))
        else:
            flash("User not found.", "danger")

    return render_template("reset_password.html")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
