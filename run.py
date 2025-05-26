import os
from flask import Flask, request, render_template_string, redirect, url_for, flash, jsonify,render_template
from flask_login import login_required, current_user

from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash
from verify_utils import verify_signature  # Your signature verification function
from datetime import datetime

app = Flask(__name__)
app.secret_key = "your_secret_key_here"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Ecochain.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
CORS(app)

# ---- Your User model ----
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    wallet_address = db.Column(db.String(42), unique=True, nullable=True)
    password_hash = db.Column(db.String(128), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<User {self.email}>"



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
    db.create_all()




@app.route('/home' , methods=['GET', 'POST'])
def home():
    return render_template('index.html')




# ---- Route: Create Account ----
@app.route('/create-account', methods=['GET', 'POST'])
def create_account():
    if request.method == 'POST':
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        password_confirm = request.form.get('password_confirm', '')

        full_name = f"{first_name} {last_name}"

        # Basic validations
        if not first_name or not last_name or not email or not password or not password_confirm:
            flash("Please fill in all required fields.", "danger")
            return redirect(url_for('create_account'))

        if password != password_confirm:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('create_account'))

        # Check if email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email already registered.", "danger")
            return redirect(url_for('create_account'))

        # Hash password
        password_hash = generate_password_hash(password)

        # Create new user (wallet_address=None since this is normal signup)
        new_user = User(
            full_name=full_name,
            email=email,
            wallet_address=None,
            password_hash=password_hash
        )
        db.session.add(new_user)
        db.session.commit()

        flash("Account created successfully! Please link your wallet.", "success")
        return redirect(url_for('login'))  # Implement login route/page

    return render_template('register.html')


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
        # Check if user already exists with this wallet address
        user = User.query.filter_by(wallet_address=address).first()
        
        if not user:
            # Optionally, create a new user or update an existing one
            user = User(wallet_address=address)
            db.session.add(user)
        else:
            # Update last login time
            user.last_login = datetime.utcnow()

        db.session.commit()

        return jsonify({"status": "success", "message": "Wallet verified and stored successfully!"})
    else:
        return jsonify({"status": "error", "message": "Signature verification failed"}), 401

@app.route('/wallet')
def wallet():
    return render_template('wallet.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        user = User.query.filter_by(email=email).first()

        if not user:
            flash('Email not found. Please create an account.', 'danger')
            return redirect(url_for('login'))

        if not check_password_hash(user.password_hash, password):
            flash('Incorrect password.', 'danger')
            return redirect(url_for('login'))

        if not user.wallet_address:
            flash('Please link your wallet before logging in.', 'warning')
            return redirect(url_for('wallet'))

        # Successful login
        session['user_id'] = user.id
        flash('Logged in successfully!', 'success')
        return redirect(url_for('dashboard'))  # Replace with your dashboard route

    return render_template('login.html')




@app.route('/dashboard', methods=["POST", "GET"])
def dashboard():
    return render_template('dashboard.html')


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        message = request.form.get('message', '').strip()

        # Basic validation
        if not name or not email or not phone or not message:
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
def page_not_found(e):
    return render_template('401.html'), 401




@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))



if __name__ == "__main__":
    app.run(debug=True)
