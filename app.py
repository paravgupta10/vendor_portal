import os, random
from dotenv import load_dotenv
from flask import Flask, request, render_template, redirect, url_for, flash, session, abort, jsonify, render_template_string
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from supabase import create_client, Client
from functools import wraps
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy import text
from sqlalchemy.sql import text
import re

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
    status = db.Column(db.String(20), default='pending')  

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

class Invoice(db.Model):
    __tablename__ = 'invoices'
    id = db.Column(db.Integer, primary_key=True)
    vendor_id = db.Column(db.Integer, db.ForeignKey('vendor_details.id'))
    file_name = db.Column(db.String(200))
    file_url = db.Column(db.String(300))
    status = db.Column(db.String(20), default='pending')  
    uploaded_at = db.Column(db.DateTime, server_default=db.func.now())


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
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")  
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD") 
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_DEFAULT_SENDER") 

mail = Mail(app)
s = URLSafeTimedSerializer(app.secret_key)  

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
            flash("Invalid email or password.")
            return redirect(url_for('login'))  

    return render_template("login.html")

@app.route("/register", methods=["POST"])
def register():
    email = request.form.get("email")
    password = request.form.get("password")
    confirm_password = request.form.get("confirm_password")

    # Check if passwords match
    if password != confirm_password:
        flash("Passwords do not match.")
        return redirect(url_for('login'))

    # Check password length
    if len(password) < 8:
        flash("Password must be at least 8 characters long.")
        return redirect(url_for('login'))

    # Check password strength: one uppercase, one digit, one special character
    if not re.search(r"[A-Z]", password):
        flash("Password must contain at least one uppercase letter.")
        return redirect(url_for('login'))

    if not re.search(r"[0-9]", password):
        flash("Password must contain at least one number.")
        return redirect(url_for('login'))

    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        flash("Password must contain at least one special character.")
        return redirect(url_for('login'))

    # Check if email already exists
    if User.query.filter_by(email=email).first():
        flash("Email already registered.")
        return redirect(url_for('login'))

    # Store temporarily for verification
    code = str(random.randint(100000, 999999))
    session['email_verification'] = {
        'email': email,
        'password': password,
        'code': code
    }

    # Send verification code via email
    msg = Message("Your Verification Code", recipients=[email])
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

    msg = Message("Your New Verification Code", recipients=[session_data['email']])
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
            ownership_type=request.form.get('ownership').lower(),
            registered_address=request.form.get('address'),
            branch_addresses="\n\n".join(request.form.getlist('baddress[]')),
            city=request.form.get('city'),
            state=request.form.get('state'),
            country=request.form.get('country'),
            status="pending",
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

    invoices = Invoice.query.filter_by(vendor_id=vendor.id).order_by(Invoice.uploaded_at.desc()).all()

    return render_template("vendor_dashboard.html", 
                           company=vendor.company_name, 
                           vendor=vendor,
                           invoices=invoices)


@app.route("/admin-dashboard")
@login_required
def admin_dashboard():
    if session.get('email') != "admin1@example.com":
        flash("Unauthorized access.")
        return redirect(url_for('vendor_dashboard'))
    total_vendors = VendorDetails.query.count()
    approved_count = VendorDetails.query.filter_by(status='approved').count()
    pending_count = VendorDetails.query.filter_by(status='pending').count()
    hold_count = VendorDetails.query.filter_by(status='hold').count()
    rejected_count = VendorDetails.query.filter_by(status='rejected').count()

    return render_template(
        'admin_dashboard.html',
        total_vendors=total_vendors,
        approved_count=approved_count,
        pending_count=pending_count,
        hold_count=hold_count,
        rejected_count=rejected_count
    )

@app.route("/admin/view-registrations")
@login_required
def view_registrations():
    if session.get('email') != "admin1@example.com":
        flash("Unauthorized access.")
        return redirect(url_for('vendor_dashboard'))

    vendors = VendorDetails.query.all()
    return render_template("view_registrations.html", vendors=vendors)

@app.route('/admin/review-vendors')
@login_required
def review_vendors():
    if session.get("email") != "admin1@example.com":
        flash("Unauthorized access.")
        return redirect(url_for('vendor_dashboard'))

    vendors = VendorDetails.query.with_entities(
        VendorDetails.id,
        VendorDetails.company_name,
        VendorDetails.email,
        VendorDetails.phone,
        VendorDetails.status
    ).all()

    # Count vendors by status
    counts = {
    'all': len(vendors),
    'approved': VendorDetails.query.filter_by(status='approved').count(),
    'pending': VendorDetails.query.filter_by(status='pending').count(),
    'hold': VendorDetails.query.filter_by(status='hold').count(),
    'rejected': VendorDetails.query.filter_by(status='rejected').count()
}

    return render_template('review_vendors.html', vendors=vendors, counts=counts)


@app.route('/admin/update-vendor-status', methods=['POST'])
@login_required
def update_vendor_status():
    if session.get("email") != "admin1@example.com":
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    data = request.get_json()
    vendor_id = data.get('id')
    new_status = data.get('status')

    vendor = VendorDetails.query.get(vendor_id)
    if not vendor:
        return jsonify({'success': False, 'message': 'Vendor not found'}), 404

    vendor.status = new_status.lower()
    db.session.commit()

    # Send email notification
    try:
        msg = Message(
            subject="Vendor Registration Status Update",
            sender=app.config['MAIL_USERNAME'],
            recipients=[vendor.email]
        )
        msg.body = f"""Dear {vendor.company_name},

Your vendor registration status has been updated to: {new_status.title()}.

Please login to the vendor portal to check further details.

Regards,
Vendor Portal Admin Team
"""
        mail.send(msg)
    except Exception as e:
        print("Email failed:", str(e))

    return jsonify({'success': True, 'message': f'Status updated to {new_status}'})


@app.route('/admin/vendor-details/<int:vendor_id>')
@login_required
def get_vendor_details(vendor_id):
    sql = text("SELECT * FROM vendor_full_info WHERE id = :id")
    result = db.session.execute(sql, {'id': vendor_id}).mappings().fetchone()

    if not result:
        return jsonify({'error': 'Vendor not found'}), 404

    data = dict(result)
    ownership = data.get("ownership_type", "").lower()

    response = {
        "company_name": data["company_name"],
        "email": data["email"],
        "phone": data["phone"],
        "status": data["status"],
        "ownership_type": data.get("ownership_type", ""),
        "tan_number": data.get("tan_number", ""),
        "gst_number": data.get("gst_number", ""),
        "product_services": data.get("product_services", ""),
        "registered_address": data.get("registered_address", ""),
        "branch_addresses": data.get("branch_addresses", ""),
    }

    # Sole Owner
    if ownership == "sole":
        response.update({
            "owner_name": data.get("sole_owner_name", ""),
            "owner_email": data.get("sole_owner_email", ""),
            "owner_phone": data.get("sole_owner_phone", ""),
            "owner_pan": data.get("sole_owner_pan", "")
        })

    # Partnership or LLP — multiple partners
    elif ownership in ["partnership", "llp"]:
        partners = db.session.execute(
            text("SELECT name, email, phone FROM partners WHERE vendor_id = :id"),
            {"id": vendor_id}
        ).mappings().all()

        response["partners"] = [dict(p) for p in partners]

    # Pvt/Public Ltd — multiple directors
    elif ownership in ["pvtltd", "publicltd"]:
        directors = []

        if ownership == "pvtltd":
            rows = db.session.execute(
                text("SELECT name, email, phone FROM pvtltd_directors WHERE vendor_id = :id"),
                {"id": vendor_id}
            ).mappings().all()
            directors = [dict(d) for d in rows]
        elif ownership == "publicltd":
            rows = db.session.execute(
                text("SELECT name, email, phone FROM publicltd_directors WHERE vendor_id = :id"),
                {"id": vendor_id}
            ).mappings().all()
            directors = [dict(d) for d in rows]

        response["directors"] = directors

    return jsonify(response)



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

            # Use alert with redirect
            return render_template("forgot_password.html", alert="Reset link sent to your email!", redirect_to=url_for("login"))
        else:
            return render_template("forgot_password.html", alert="Email not found.")
    return render_template("forgot_password.html")



@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        email = s.loads(token, salt="password-reset", max_age=3600)
    except Exception:
        return render_template("reset_password.html", alert="The reset link is invalid or expired.")

    if request.method == "POST":
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        if len(new_password) < 8 or not any(c.isdigit() for c in new_password) or not any(c.isupper() for c in new_password):
            return render_template("reset_password.html", alert="Password must be at least 8 characters long and contain at least one digit and one uppercase letter.")

        if new_password != confirm_password:
            return render_template("reset_password.html", alert="Passwords do not match.")

        user = User.query.filter_by(email=email).first()
        if user:
            user.password_hash = generate_password_hash(new_password)
            db.session.commit()
            return render_template("reset_password.html", alert="Password reset successful!", redirect_to=url_for("login"))
        else:
            return render_template("reset_password.html", alert="User not found.")

    return render_template("reset_password.html")

@app.route('/upload-invoice', methods=['POST'])
@login_required
def upload_invoice():
    vendor = VendorDetails.query.filter_by(user_id=session['user_id']).first()
    if not vendor or vendor.status != 'approved':
        abort(403)

    file = request.files.get('invoice')
    if not file:
        flash("No file selected.")
        return redirect(url_for('vendor_dashboard'))

    file_bytes = file.read()

    # Validate file
    if file.filename.endswith(('.jpeg', '.jpg')) and len(file_bytes) <= 2 * 1024 * 1024:
        from uuid import uuid4
        filename = f"{uuid4()}_{secure_filename(file.filename)}"
        path = f"{vendor.id}/invoices/{filename}"

        # Upload to Supabase Storage (using correct bucket name: 'vendor-invoices')
        supabase.storage.from_("vendor-invoices").upload(
            path=path,
            file=file_bytes,
            file_options={"cache-control": "3600", "upsert": False}
        )
        public_url = f"{SUPABASE_URL}/storage/v1/object/public/vendor-invoices/{path}"

        invoice = Invoice(
            vendor_id=vendor.id,
            file_name=filename,
            file_url=public_url,
            status='Pending'
        )
        db.session.add(invoice)
        db.session.commit()

        flash("Invoice uploaded successfully.")
    else:
        flash("Invalid file type or size exceeds 2MB.")

    return redirect(url_for('vendor_dashboard'))


@app.route('/admin/invoices')
@login_required
def admin_invoices():
    if session.get('email') != 'admin1@example.com':
        abort(403)

    invoices = db.session.execute(text("""
        SELECT invoices.*, vendor_details.company_name
        FROM invoices
        JOIN vendor_details ON invoices.vendor_id = vendor_details.id
        ORDER BY invoices.uploaded_at DESC
    """)).fetchall()

    return render_template('admin_invoices.html', invoices=invoices)

@app.route('/admin/invoice/status/<int:invoice_id>', methods=['POST'])
@login_required
def update_invoice_status(invoice_id):
    if session.get('email') != 'admin1@example.com':
        abort(403)

    new_status = request.json.get('status')
    if not new_status:
        return jsonify({'success': False, 'message': 'No status provided'}), 400

    # Fetch current status
    current_status_result = db.session.execute(
        text("SELECT status FROM invoices WHERE id = :id"),
        {'id': invoice_id}
    ).fetchone()

    if not current_status_result:
        return jsonify({'success': False, 'message': 'Invoice not found'}), 404

    current_status = current_status_result.status.lower()
    if current_status in ['approved', 'rejected']:
        return jsonify({'success': False, 'message': 'Invoice status already finalized'}), 400

    # Update status
    db.session.execute(
        text("UPDATE invoices SET status = :status WHERE id = :id"),
        {'status': new_status.lower(), 'id': invoice_id}
    )
    db.session.commit()
    return jsonify({'success': True, 'message': f'Status updated to {new_status}'})


if __name__ == "__main__":
    with app.app_context():
        db.create_all()

        # Create vendor_full_info view once at startup
        view_sql = """
        create or replace view vendor_full_info as
        select
            vd.id,
            vd.company_name,
            vd.email,
            vd.phone,
            vd.status,
            vd.ownership_type,
            vd.registered_address,
            vd.branch_addresses,
            vd.tan_number,
            vd.gst_number,
            vd.product_services,
            so.name as sole_owner_name,
            so.email as sole_owner_email,
            so.phone as sole_owner_phone,
            so.pan_number as sole_owner_pan,
            p.name as partner_name,
            p.email as partner_email,
            p.phone as partner_phone,
            p.pan_number as partner_pan,
            pvt.name as pvt_director_name,
            pvt.email as pvt_director_email,
            pvt.phone as pvt_director_phone,
            pvt.pan_number as pvt_director_pan,
            pub.name as pub_director_name,
            pub.email as pub_director_email,
            pub.phone as pub_director_phone,
            pub.pan_number as pub_director_pan
        from vendor_details vd
        left join sole_owners so on vd.id = so.vendor_id and lower(vd.ownership_type) = 'sole'
        left join partners p on vd.id = p.vendor_id and lower(vd.ownership_type) in ('partnership', 'llp')
        left join pvtltd_directors pvt on vd.id = pvt.vendor_id and lower(vd.ownership_type) = 'pvtltd'
        left join publicltd_directors pub on vd.id = pub.vendor_id and lower(vd.ownership_type) = 'publicltd';
        """
        db.session.execute(text(view_sql))
        db.session.commit()

    app.run(debug=True)

