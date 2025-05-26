import os
from flask import Flask, request, render_template_string, redirect, url_for, flash, jsonify, render_template, session, abort
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from verify_utils import verify_signature  # Your signature verification function
from datetime import datetime

app = Flask(__name__)
app.secret_key = "your_strong_secret_key_here_CHANGE_THIS_IN_PRODUCTION"  # IMPORTANT: Change this to a strong, random key in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Ecochainapp.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
CORS(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Default login view for regular users

# ---- User model with UserMixin and 'role' column ----
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    wallet_address = db.Column(db.String(42), unique=True, nullable=True)
    password_hash = db.Column(db.String(128), nullable=True)
    role = db.Column(db.String(50), default='user', nullable=False) # 'user' or 'investor'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<User {self.email} ({self.role})>"

# Flask-Login user loader callback
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Help(db.Model):
    __tablename__ = 'help'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    issue_type = db.Column(db.String(100), nullable=False)
    other_issue = db.Column(db.String(200), nullable=True)
    description = db.Column(db.Text, nullable=False)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='help_requests')

with app.app_context():
    # This will create the 'role' column if the table already exists,
    # or create the table with the 'role' column if it's new.
    # For existing databases, you might need a migration tool like Flask-Migrate.
    db.create_all()

@app.route('/home' , methods=['GET', 'POST'])
def home():
    return render_template('index.html')

# ---- Route: Create Account (for regular users) ----
@app.route('/create-account', methods=['GET', 'POST'])
def create_account():
    if request.method == 'POST':
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        password_confirm = request.form.get('password_confirm', '')

        full_name = f"{first_name} {last_name}"

        if not all([first_name, last_name, email, password, password_confirm]):
            flash("Please fill in all required fields.", "danger")
            return redirect(url_for('create_account'))

        if password != password_confirm:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('create_account'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email already registered. Please use the appropriate login.", "danger")
            return redirect(url_for('create_account'))

        password_hash = generate_password_hash(password)

        new_user = User(
            full_name=full_name,
            email=email,
            wallet_address=None,
            password_hash=password_hash,
            role='user' # Explicitly set role for regular users
        )
        db.session.add(new_user)
        db.session.commit()

        flash("Account created successfully! Please link your wallet and log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

# ---- Route: Investor Sign Up ----
@app.route('/investor-signup', methods=['GET', 'POST'])
def investor_signup():
    if current_user.is_authenticated:
        flash("You are already logged in.", "info")
        if current_user.role == 'investor':
            return redirect(url_for('investor_dashboard'))
        else:
            return redirect(url_for('dashboard'))

    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        password_confirm = request.form.get('password_confirm', '')

        if not all([full_name, email, password, password_confirm]):
            flash("Please fill in all required fields.", "danger")
            return redirect(url_for('investor_signup'))

        if password != password_confirm:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('investor_signup'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            if existing_user.role == 'investor':
                flash("This email is already registered as an investor.", "danger")
            else:
                flash("This email is already registered as a regular user. Please use a different email or log in to your existing account.", "danger")
            return redirect(url_for('investor_signup'))

        password_hash = generate_password_hash(password)

        new_investor = User(
            full_name=full_name,
            email=email,
            wallet_address=None, # Wallet linking will happen separately
            password_hash=password_hash,
            role='investor' # Explicitly set role for investors
        )
        db.session.add(new_investor)
        db.session.commit()

        flash("Investor account created successfully! Please log in.", "success")
        return redirect(url_for('investor_login'))

    return render_template('investor_signup.html')


# ---- Route: Investor Login ----
@app.route('/investor-login', methods=['GET', 'POST'])
def investor_login():
    if current_user.is_authenticated:
        flash("You are already logged in.", "info")
        if current_user.role == 'investor':
            return redirect(url_for('investor_dashboard'))
        else:
            return redirect(url_for('dashboard')) # Redirect to regular dashboard if not an investor

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        remember_me = request.form.get('remember')

        if not email or not password:
            flash('Please enter both email and password.', 'danger')
            return redirect(url_for('investor_login'))

        user = User.query.filter_by(email=email).first()

        if not user:
            flash('No investor account found with that email.', 'danger')
            return redirect(url_for('investor_login'))

        if not check_password_hash(user.password_hash, password):
            flash('Incorrect password.', 'danger')
            return redirect(url_for('investor_login'))

        # Crucial: Check if the user has the 'investor' role
        if user.role != 'investor':
            flash('This login is for investors only. Please use the regular login.', 'warning')
            return redirect(url_for('login')) # Redirect to regular login if not an investor

        login_user(user, remember=bool(remember_me))
        flash('Logged in as investor successfully!', 'success')
        return redirect(url_for('investor_dashboard')) # Redirect to investor dashboard

    return render_template('investor_login.html')

# ---- Protected Investor Dashboard Route ----
@app.route('/investor-dashboard', methods=["GET"])
@login_required
def investor_dashboard():
    # Ensure only investors can access this dashboard
    if current_user.role != 'investor':
        flash("Access denied. This page is for investors only.", "danger")
        abort(403) # Or redirect to a general error page or the regular dashboard

    # Render a placeholder investor dashboard template
    return render_template('investor_dashboard.html', user=current_user)


# ---- Route: Wallet Signature Verification API ----
@app.route("/api/verify", methods=["POST", "GET"])
def verify():
    data = request.get_json()
    address = data.get("address")
    signature = data.get("signature")
    message = data.get("message", "Login to Celo Protected App")

    if not address or not signature:
        return jsonify({"status": "error", "message": "Missing address or signature"}), 400

    if verify_signature(address, signature, message):
        user = User.query.filter_by(wallet_address=address).first()

        if not user:
            # If a user doesn't exist with this wallet, create a new 'user' role by default
            user = User(wallet_address=address, full_name="Wallet User", email=f"{address}@ecochain.com", role='user')
            db.session.add(user)
        else:
            user.last_login = datetime.utcnow()

        db.session.commit()
        login_user(user)
        # Redirect based on the user's role after wallet verification
        if user.role == 'investor':
            return jsonify({"status": "success", "message": "Wallet verified and stored successfully!", "redirect_url": url_for('investor_dashboard')})
        else:
            return jsonify({"status": "success", "message": "Wallet verified and stored successfully!", "redirect_url": url_for('dashboard')})
    else:
        return jsonify({"status": "error", "message": "Signature verification failed"}), 401

@app.route('/wallet')
def wallet():
    return render_template('wallet.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        flash("You are already logged in.", "info")
        if current_user.role == 'investor':
            return redirect(url_for('investor_dashboard'))
        else:
            return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        remember_me = request.form.get('remember')

        if not email or not password:
            flash('Please enter both email and password.', 'danger')
            return redirect(url_for('login'))

        user = User.query.filter_by(email=email).first()

        if not user:
            flash('Email not found. Please create an account.', 'danger')
            return redirect(url_for('login'))

        if not check_password_hash(user.password_hash, password):
            flash('Incorrect password.', 'danger')
            return redirect(url_for('login'))

        # Crucial: Check if the user has the 'user' role for this login page
        if user.role != 'user':
            flash('This login is for regular users. Please use the investor login.', 'warning')
            return redirect(url_for('investor_login')) # Redirect to investor login if not a regular user

        if not user.wallet_address:
            flash('Please link your wallet before logging in.', 'warning')
            return redirect(url_for('wallet'))

        login_user(user, remember=bool(remember_me))
        flash('Logged in successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('login.html')

# ---- Protected Regular User Dashboard Route ----
@app.route('/dashboard', methods=["POST", "GET"])
@login_required
def dashboard():
    # Ensure only regular users can access this dashboard
    if current_user.role != 'user':
        flash("Access denied. This page is for regular users only.", "danger")
        abort(403) # Or redirect to investor dashboard

    return render_template('dashboard.html', user=current_user)


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        message = request.form.get('message', '').strip()

        if not all([name, email, phone, message]):
            flash('All fields are required!', 'danger')
            return redirect(url_for('contact'))

        new_contact = Contact(name=name, email=email, phone=phone, message=message)
        db.session.add(new_contact)
        db.session.commit()

        flash('Your message has been sent successfully!', 'success')
        return redirect(url_for('contact'))

    return render_template('index.html')

@app.route('/report-issue', methods=['GET', 'POST'])
@login_required
def report_issue():
    if request.method == 'POST':
        issue_type = request.form.get('issue_type')
        other_issue = request.form.get('other_issue', '').strip()
        description = request.form.get('description', '').strip()

        if not issue_type or not description:
            flash("Please fill in all required fields.", "danger")
            return redirect(url_for('report_issue'))

        if issue_type == 'other' and not other_issue:
            flash("Please specify your issue.", "danger")
            return redirect(url_for('report_issue'))

        new_help = Help(
            user_id=current_user.id,
            issue_type=issue_type,
            other_issue=other_issue if issue_type == 'other' else None,
            description=description
        )
        db.session.add(new_help)
        db.session.commit()

        flash("Your issue has been submitted successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template('help.html', user=current_user)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(401)
def unauthorized(e):
    return render_template('401.html'), 401

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)
