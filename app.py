from flask import Flask, request, jsonify, abort, render_template, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_restful import Api, Resource
from werkzeug.security import generate_password_hash, check_password_hash
import secrets 
from flask_wtf import FlaskForm, CSRFProtect
from flask_admin import Admin
from flask_admin.base import BaseView, expose
from flask_admin.contrib.sqla import ModelView
from wtforms import StringField, PasswordField, TextAreaField, DateField, SubmitField, SelectField, IntegerField, TimeField
from wtforms.validators import DataRequired, Email, EqualTo, Length, NumberRange, Regexp, ValidationError
from werkzeug.exceptions import HTTPException
from flask_bcrypt import Bcrypt

from datetime import datetime
import logging
from werkzeug.utils import secure_filename
import os
from flask_wtf.file import FileField, FileAllowed


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = secrets.token_hex(24)
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

db = SQLAlchemy(app)
login_manager = LoginManager(app)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
api = Api(app)

login_manager.login_message_category = 'info'
login_manager.login_view = 'login'


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # Ensure this line is present
    role = db.Column(db.String(50), nullable=False, default='user')  # Add this line

    def __repr__(self):
        return f'<User {self.username}>'


class Record(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    value = db.Column(db.String(120), nullable=False)

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    subject = db.Column(db.String(150), nullable=False)
    message = db.Column(db.Text, nullable=False)

class InsuranceClaim(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    dln = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    dob = db.Column(db.Date, nullable=False)
    address = db.Column(db.String(255), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    postcode = db.Column(db.String(10), nullable=False)
    country = db.Column(db.String(100), nullable=False)
    car_model = db.Column(db.String(100), nullable=False)
    car_reg = db.Column(db.String(20), nullable=False)
    policy_number = db.Column(db.String(50), unique=True, nullable=False)
    insurance_type = db.Column(db.String(50), nullable=False)
    policy_start_date = db.Column(db.Date, nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    card_name = db.Column(db.String(100), nullable=False)
    card_number = db.Column(db.String(19), nullable=False)
    exp_date = db.Column(db.Date, nullable=False)
    cvc = db.Column(db.String(4), nullable=False)
    additional_info = db.Column(db.String(500))
    date_submitted = db.Column(db.DateTime, default=datetime.utcnow)

    # Added user_id for relationship management
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'<InsuranceClaim {self.id}>'

class IncidentReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    incident_date = db.Column(db.Date, nullable=False)
    incident_time = db.Column(db.Time, nullable=False)
    location = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    attachments = db.Column(db.String(255))  # Store file paths or URLs to the attachments
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<IncidentReport {self.id}>'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Insurance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    insurance_type = db.Column(db.String(50), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    premium_amount = db.Column(db.Integer, nullable=False)
    
    # Foreign key to link back to InsuranceClaim
    claim_id = db.Column(db.Integer, db.ForeignKey('insurance_claim.id'), nullable=False)
    claim = db.relationship('InsuranceClaim', backref='insurances', lazy=True)

    def __repr__(self):
        return f'<Insurance {self.id}>'
    
    def post(self):
        data = request.get_json()
        hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
        new_user = User(username=data['username'], email=data['email'], password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({
            'id': new_user.id,
            'username': new_user.username,
            'email': new_user.email,
            'is_admin': new_user.is_admin
        })

    def put(self, user_id):
        data = request.get_json()
        user = User.query.get_or_404(user_id)
        if 'username' in data:
            user.username = data['username']
        if 'email' in data:
            user.email = data['email']
        if 'password' in data:
            user.password = generate_password_hash(data['password'], method='pbkdf2:sha256')
        if 'is_admin' in data:
            user.is_admin = data['is_admin']
        db.session.commit()
        return jsonify({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'is_admin': user.is_admin
        })

    def delete(self, user_id):
        user = User.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': 'User deleted successfully'})
    
# API Resources
class UserResource(Resource):
    def get(self, user_id):
        user = User.query.get_or_404(user_id)
        return jsonify({'id': user.id, 'username': user.username, 'email': user.email, 'role': user.role})

    def delete(self, user_id):
        user = User.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        return '', 204

class UserListResource(Resource):
    def get(self):
        users = User.query.all()
        return jsonify([{'id': user.id, 'username': user.username, 'email': user.email, 'role': user.role} for user in users])

    def post(self):
        data = request.get_json()
        print(f"Received data: {data}")  # Log received data

        if 'username' not in data or 'email' not in data or 'password' not in data:
            abort(400, "Must include username, email, and password fields")

        try:
            hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
            new_user = User(username=data['username'], email=data['email'], password=hashed_password, role=data.get('role', 'user'))
            db.session.add(new_user)
            db.session.commit()
            return jsonify({'id': new_user.id, 'username': new_user.username, 'email': new_user.email, 'role': new_user.role}), 201
        except Exception as e:
            print(f"Error: {e}")  # Log the error
            abort(500, "Internal Server Error")


class InsuranceClaimResource(Resource):
    def get(self, claim_id):
        claim = InsuranceClaim.query.get_or_404(claim_id)
        return jsonify({
            'id': claim.id,
            'name': claim.name,
            'dln': claim.dln,
            'email': claim.email,
            'phone': claim.phone,
            'dob': claim.dob.strftime('%Y-%m-%d'),
            'address': claim.address,
            'city': claim.city,
            'postcode': claim.postcode,
            'country': claim.country,
            'car_model': claim.car_model,
            'car_reg': claim.car_reg,
            'policy_number': claim.policy_number,
            'insurance_type': claim.insurance_type,
            'policy_start_date': claim.policy_start_date.strftime('%Y-%m-%d'),
            'amount': claim.amount,
            'card_name': claim.card_name,
            'card_number': claim.card_number,
            'exp_date': claim.exp_date.strftime('%Y-%m-%d'),
            'cvc': claim.cvc,
            'additional_info': claim.additional_info,
            'date_submitted': claim.date_submitted.strftime('%Y-%m-%d %H:%M:%S'),
            'user_id': claim.user_id
        })

    def delete(self, claim_id):
        claim = InsuranceClaim.query.get_or_404(claim_id)
        db.session.delete(claim)
        db.session.commit()
        return '', 204

class InsuranceClaimListResource(Resource):
    def get(self):
        claims = InsuranceClaim.query.all()
        return jsonify([{
            'id': claim.id,
            'name': claim.name,
            'dln': claim.dln,
            'email': claim.email,
            'phone': claim.phone,
            'dob': claim.dob.strftime('%Y-%m-%d'),
            'address': claim.address,
            'city': claim.city,
            'postcode': claim.postcode,
            'country': claim.country,
            'car_model': claim.car_model,
            'car_reg': claim.car_reg,
            'policy_number': claim.policy_number,
            'insurance_type': claim.insurance_type,
            'policy_start_date': claim.policy_start_date.strftime('%Y-%m-%d'),
            'amount': claim.amount,
            'card_name': claim.card_name,
            'card_number': claim.card_number,
            'exp_date': claim.exp_date.strftime('%Y-%m-%d'),
            'cvc': claim.cvc,
            'additional_info': claim.additional_info,
            'date_submitted': claim.date_submitted.strftime('%Y-%m-%d %H:%M:%S'),
            'user_id': claim.user_id
        } for claim in claims])

    def post(self):
        data = request.get_json()
        required_fields = ['name', 'dln', 'email', 'phone', 'dob', 'address', 'city', 'postcode', 'country', 'car_model', 'car_reg', 'policy_number', 'insurance_type', 'policy_start_date', 'amount', 'card_name', 'card_number', 'exp_date', 'cvc', 'user_id']
        if not all(field in data for field in required_fields):
            abort(400, "Must include all required fields")
        
        new_claim = InsuranceClaim(
            name=data['name'],
            dln=data['dln'],
            email=data['email'],
            phone=data['phone'],
            dob=datetime.strptime(data['dob'], '%Y-%m-%d'),
            address=data['address'],
            city=data['city'],
            postcode=data['postcode'],
            country=data['country'],
            car_model=data['car_model'],
            car_reg=data['car_reg'],
            policy_number=data['policy_number'],
            insurance_type=data['insurance_type'],
            policy_start_date=datetime.strptime(data['policy_start_date'], '%Y-%m-%d'),
            amount=data['amount'],
            card_name=data['card_name'],
            card_number=data['card_number'],
            exp_date=datetime.strptime(data['exp_date'], '%Y-%m-%d'),
            cvc=data['cvc'],
            additional_info=data.get('additional_info', ''),
            user_id=data['user_id']
        )
        db.session.add(new_claim)
        db.session.commit()
        return jsonify({
            'id': new_claim.id,
            'name': new_claim.name,
            'dln': new_claim.dln,
            'email': new_claim.email,
            'phone': new_claim.phone,
            'dob': new_claim.dob.strftime('%Y-%m-%d'),
            'address': new_claim.address,
            'city': new_claim.city,
            'postcode': new_claim.postcode,
            'country': new_claim.country,
            'car_model': new_claim.car_model,
            'car_reg': new_claim.car_reg,
            'policy_number': new_claim.policy_number,
            'insurance_type': new_claim.insurance_type,
            'policy_start_date': new_claim.policy_start_date.strftime('%Y-%m-%d'),
            'amount': new_claim.amount,
            'card_name': new_claim.card_name,
            'card_number': new_claim.card_number,
            'exp_date': new_claim.exp_date.strftime('%Y-%m-%d'),
            'cvc': new_claim.cvc,
            'additional_info': new_claim.additional_info,
            'date_submitted': new_claim.date_submitted.strftime('%Y-%m-%d %H:%M:%S'),
            'user_id': new_claim.user_id
        }), 201

class IncidentReportResource(Resource):
    def get(self, report_id):
        report = IncidentReport.query.get_or_404(report_id)
        return jsonify({
            'id': report.id,
            'user_id': report.user_id,
            'incident_date': report.incident_date.strftime('%Y-%m-%d'),
            'incident_time': report.incident_time.strftime('%H:%M:%S'),
            'location': report.location,
            'description': report.description,
            'attachments': report.attachments,
            'created_at': report.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })

    def delete(self, report_id):
        report = IncidentReport.query.get_or_404(report_id)
        db.session.delete(report)
        db.session.commit()
        return '', 204

class IncidentReportListResource(Resource):
    def get(self):
        reports = IncidentReport.query.all()
        return jsonify([{
            'id': report.id,
            'user_id': report.user_id,
            'incident_date': report.incident_date.strftime('%Y-%m-%d'),
            'incident_time': report.incident_time.strftime('%H:%M:%S'),
            'location': report.location,
            'description': report.description,
            'attachments': report.attachments,
            'created_at': report.created_at.strftime('%Y-%m-%d %H:%M:%S')
        } for report in reports])

    def post(self):
        data = request.get_json()
        required_fields = ['user_id', 'incident_date', 'incident_time', 'location', 'description']
        if not all(field in data for field in required_fields):
            abort(400, "Must include all required fields")
        
        new_report = IncidentReport(
            user_id=data['user_id'],
            incident_date=datetime.strptime(data['incident_date'], '%Y-%m-%d'),
            incident_time=datetime.strptime(data['incident_time'], '%H:%M:%S').time(),
            location=data['location'],
            description=data['description'],
            attachments=data.get('attachments', '')
        )
        db.session.add(new_report)
        db.session.commit()
        return jsonify({
            'id': new_report.id,
            'user_id': new_report.user_id,
            'incident_date': new_report.incident_date.strftime('%Y-%m-%d'),
            'incident_time': new_report.incident_time.strftime('%H:%M:%S'),
            'location': new_report.location,
            'description': new_report.description,
            'attachments': new_report.attachments,
            'created_at': new_report.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }), 201

class ContactResource(Resource):
    def get(self, contact_id):
        contact = Contact.query.get_or_404(contact_id)
        return jsonify({
            'id': contact.id,
            'first_name': contact.first_name,
            'last_name': contact.last_name,
            'email': contact.email,
            'subject': contact.subject,
            'message': contact.message
        })

    def delete(self, contact_id):
        contact = Contact.query.get_or_404(contact_id)
        db.session.delete(contact)
        db.session.commit()
        return '', 204

class ContactListResource(Resource):
    def get(self):
        contacts = Contact.query.all()
        return jsonify([{
            'id': contact.id,
            'first_name': contact.first_name,
            'last_name': contact.last_name,
            'email': contact.email,
            'subject': contact.subject,
            'message': contact.message
        } for contact in contacts])

    def post(self):
        data = request.get_json()
        required_fields = ['first_name', 'last_name', 'email', 'subject', 'message']
        if not all(field in data for field in required_fields):
            abort(400, "Must include all required fields")
        
        new_contact = Contact(
            first_name=data['first_name'],
            last_name=data['last_name'],
            email=data['email'],
            subject=data['subject'],
            message=data['message']
        )
        db.session.add(new_contact)
        db.session.commit()
        return jsonify({
            'id': new_contact.id,
            'first_name': new_contact.first_name,
            'last_name': new_contact.last_name,
            'email': new_contact.email,
            'subject': new_contact.subject,
            'message': new_contact.message
        }), 201

# Adding resources to API
api.add_resource(UserListResource, '/users')
api.add_resource(UserResource, '/users/<int:user_id>')
api.add_resource(InsuranceClaimListResource, '/insurance-claims')
api.add_resource(InsuranceClaimResource, '/insurance-claims/<int:claim_id>')
api.add_resource(IncidentReportListResource, '/incident-reports')
api.add_resource(IncidentReportResource, '/incident-reports/<int:report_id>')
api.add_resource(ContactListResource, '/contacts')
api.add_resource(ContactResource, '/contacts/<int:contact_id>')
    
class InsuranceForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=100)])
    dln = StringField('DLN', validators=[DataRequired(), Length(min=5, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone', validators=[DataRequired(), Length(min=10, max=15)])
    dob = DateField('Date of Birth', format='%Y-%m-%d', validators=[DataRequired()])
    address = StringField('Address', validators=[DataRequired(), Length(max=255)])
    city = StringField('City', validators=[DataRequired(), Length(max=100)])
    postcode = StringField('Postcode', validators=[DataRequired(), Length(max=10)])
    country = StringField('Country', validators=[DataRequired(), Length(max=100)])
    car_model = StringField('Car Model', validators=[DataRequired(), Length(max=100)])
    car_reg = StringField('Car Registration', validators=[DataRequired(), Length(max=20)])
    policy_number = StringField('Policy Number', validators=[DataRequired(), Length(max=50)])
    insurance_type = SelectField('Insurance Type', choices=[('Comprehensive', 'Comprehensive'), ('Third-Party', 'Third-Party'), ('Third-Party, Fire and Theft', 'Third-Party, Fire and Theft')], validators=[DataRequired()])
    policy_start_date = DateField('Policy Start Date', format='%Y-%m-%d', validators=[DataRequired()])
    amount = IntegerField('Amount', validators=[DataRequired(), NumberRange(min=0)])
    card_name = StringField('Card Name', validators=[DataRequired(), Length(max=100)])
    card_number = StringField('Card Number', validators=[DataRequired(), Length(min=13, max=19)])
    exp_date = StringField('Expiration Date', validators=[DataRequired(), Length(min=5, max=5)])
    cvc = StringField('CVC', validators=[DataRequired(), Length(min=3, max=4)])
    additional_info = StringField('Additional Information', validators=[Length(max=500)])
    submit = SubmitField('Submit')

class IncidentReportForm(FlaskForm):
    incident_date = DateField('Date of Incident', format='%Y-%m-%d', validators=[DataRequired()])
    incident_time = TimeField('Time of Incident', format='%H:%M', validators=[DataRequired()])
    incident_location = StringField('Location of Incident', validators=[DataRequired()])
    incident_description = TextAreaField('Description of Incident', validators=[DataRequired()])
    attachments = FileField('Attachments', validators=[FileAllowed(['jpg', 'png', 'pdf'], 'Images and PDFs only!')])

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), EqualTo('confirm_password', message='Passwords must match')])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Register')

class ContactForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    subject = StringField('Subject', validators=[DataRequired()])
    message = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Submit')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        print(f"Attempting login for: {username}")  # Debugging line

        user = User.query.filter_by(username=username).first()
        if user:
            print(f"User found: {user.username}")  # Debugging line
            if check_password_hash(user.password, password):
                print("Password matches")  # Debugging line
                login_user(user)
                flash('Login successful!', 'success')

                if user.role == 'admin':
                    return redirect(url_for('admin_dashboard'))
                else:
                    return redirect(url_for('customer_dashboard'))
            else:
                print("Password does not match")  # Debugging line
        else:
            print("User not found")  # Debugging line

        flash('Login unsuccessful. Check username and/or password.', 'danger')

    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Check if the username or email already exists
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))
        email_check = User.query.filter_by(email=email).first()
        if email_check:
            flash('Email already registered.', 'danger')
            return redirect(url_for('register'))

        new_user = User(username=username, email=email, password=hashed_password)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html', form=form)


@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied!', 'danger')
        return redirect(url_for('login'))
    total_claims = InsuranceClaim.query.count()
    recent_claims = InsuranceClaim.query.order_by(InsuranceClaim.date_submitted.desc()).limit(5).all()
    return render_template('admin_dashboard.html', total_claims=total_claims, claims=recent_claims)

@app.route('/manage_claims')
@login_required
def manage_claims():
    if current_user.role != 'admin':
        flash('Access denied!', 'danger')
        return redirect(url_for('login'))
    # Logic to display/manage claims
    return render_template('manage_claims.html')

@app.route('/manage_users')
@login_required
def manage_users():
    if current_user.role != 'admin':
        flash('Access denied!', 'danger')
        return redirect(url_for('login'))
    # Logic to manage users
    return render_template('manage_users.html')

@app.route('/view_reports')
@login_required
def view_reports():
    if current_user.role != 'admin':
        flash('Access denied!', 'danger')
        return redirect(url_for('login'))
    # Logic to view reports
    return render_template('view_reports.html')

@app.route('/view_claim/<int:claim_id>')
@login_required
def view_claim(claim_id):
    if current_user.role != 'admin':
        flash('Access denied!', 'danger')
        return redirect(url_for('login'))
    claim = InsuranceClaim.query.get_or_404(claim_id)
    return render_template('view_claim.html', claim=claim)

@app.route('/customer_dashboard')
@login_required
def customer_dashboard():
    if current_user.role == 'admin':
        flash('Access denied! Admins cannot access the customer dashboard.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Fetch the latest insurance claim for the current user
    insurance_claim = InsuranceClaim.query.filter_by(user_id=current_user.id).order_by(InsuranceClaim.id.desc()).first()
    claims = InsuranceClaim.query.filter_by(user_id=current_user.id).all()
    incident_report = IncidentReport.query.filter_by(user_id=current_user.id).all()

    # Check if the user has an insurance claim
    if not insurance_claim:
        flash('No insurance data available.', 'warning')
        insurance_claim = None

    form = InsuranceForm()

    return render_template('customer_dashboard.html', user=current_user, insurance_claim=insurance_claim, claims=claims, form=form, incident_report=incident_report)


class MyModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.role == 'admin'

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login'))
    
admin = Admin(app, name='SLAYS Admin Dashboard', template_mode='bootstrap3')
admin.add_view(MyModelView(Record, db.session))
admin.add_view(MyModelView(Contact, db.session))
admin.add_view(MyModelView(User, db.session))
admin.add_view(MyModelView(InsuranceClaim, db.session))
admin.add_view(MyModelView(IncidentReport, db.session))

@app.route('/users', methods=['POST'])
def create_user():
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Missing data'}), 400
    
    hashed_password = generate_password_hash(data['password'], method='sha256')
    
    new_user = User(
        username=data['username'],
        email=data['email'],
        password=hashed_password
    )
    
    try:
        db.session.add(new_user)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
    
    return jsonify({
        'message': 'User created successfully',
        'user': {
            'id': new_user.id,
            'username': new_user.username,
            'email': new_user.email,
            'is_admin': new_user.is_admin,
            'role': new_user.role
        }
    }), 201

@app.route('/', methods=['GET', 'POST'])
def index():
    form = ContactForm()
    if form.validate_on_submit():
        new_contact = Contact(
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            email=form.email.data,
            subject=form.subject.data,
            message=form.message.data
        )
        db.session.add(new_contact)
        db.session.commit()
        flash('Form submitted successfully!', 'success')
        return redirect(url_for('index'))
    records = Record.query.all()
    return render_template('index.html', form=form, records=records)


@app.route('/claim_policy')
def claim_policy():
    return render_template('claim_policy.html')

@app.route('/insurance/new', methods=['GET', 'POST'])
@login_required
def new_insurance():
    form = InsuranceForm()
    if form.validate_on_submit():
        exp_date_str = form.exp_date.data
        exp_date = datetime.strptime(exp_date_str, '%m/%y')
        new_claim = InsuranceClaim(
            user_id=current_user.id,
            name=form.name.data,
            dln=form.dln.data,
            email=form.email.data,
            phone=form.phone.data,
            dob=form.dob.data,
            address=form.address.data,
            city=form.city.data,
            postcode=form.postcode.data,
            country=form.country.data,
            car_model=form.car_model.data,
            car_reg=form.car_reg.data,
            policy_number=form.policy_number.data,
            insurance_type=form.insurance_type.data,
            policy_start_date=form.policy_start_date.data,
            amount=form.amount.data,
            card_name=form.card_name.data,
            card_number=form.card_number.data,
            exp_date=exp_date,
            cvc=form.cvc.data,
            additional_info=form.additional_info.data
        )
        try:
            db.session.add(new_claim)
            db.session.commit()
            flash('Insurance form submitted successfully!', 'success')
            return redirect(url_for('view_insurance'))
        except Exception as e:
            db.session.rollback()
            logging.error(f'Error submitting form: {e}', exc_info=True)
            flash(f'Error submitting form: {e}', 'danger')
    else:
        # Log and flash detailed form errors
        error_messages = [f"{getattr(form, field).label.text}: {error}" for field, errors in form.errors.items() for error in errors]
        for message in error_messages:
            flash(message, 'danger')
        logging.error(f'Form validation errors: {form.errors}')

    return render_template('add_insurance.html', form=form)

@app.route('/insurance')
@login_required
def view_insurance():
    claims = InsuranceClaim.query.filter_by(user_id=current_user.id).all()
    return render_template('view_insurance.html', claims=claims)

@app.route('/insurance/<int:form_id>')
@login_required
def insurance_detail(form_id):
    insurance_form = InsuranceClaim.query.get_or_404(form_id)
    return render_template('insurance_detail.html', form=insurance_form)

@app.route('/update_insurance/<int:insurance_id>', methods=['GET', 'POST'])
@login_required
def update_insurance(insurance_id):
    insurance = InsuranceClaim.query.get_or_404(insurance_id)
    
    if insurance.user_id != current_user.id and not current_user.is_admin:
        flash('You are not authorized to update this insurance.', 'danger')
        return redirect(url_for('customer_dashboard'))

    form = InsuranceForm(obj=insurance)

    if form.validate_on_submit():
        # Check for unique policy number
        if InsuranceClaim.query.filter_by(policy_number=form.policy_number.data).first() and \
           InsuranceClaim.query.filter_by(policy_number=form.policy_number.data).first().id != insurance_id:
            flash('Policy number already exists.', 'danger')
            return render_template('update_insurance.html', form=form, insurance=insurance)

        try:
            insurance.name = form.name.data
            insurance.dln = form.dln.data
            insurance.email = form.email.data
            insurance.phone = form.phone.data
            insurance.dob = form.dob.data
            insurance.address = form.address.data
            insurance.city = form.city.data
            insurance.postcode = form.postcode.data
            insurance.country = form.country.data
            insurance.car_model = form.car_model.data
            insurance.car_reg = form.car_reg.data
            insurance.policy_number = form.policy_number.data
            insurance.insurance_type = form.insurance_type.data
            insurance.policy_start_date = form.policy_start_date.data
            insurance.amount = form.amount.data
            insurance.card_name = form.card_name.data
            insurance.card_number = form.card_number.data

            # Parse expiry date
            exp_date_str = form.exp_date.data
            try:
                exp_date = datetime.strptime(exp_date_str, '%m/%y').date()
                insurance.exp_date = exp_date
            except ValueError:
                flash('Expiry date must be in the format MM/YY.', 'danger')
                return render_template('update_insurance.html', form=form, insurance=insurance)

            insurance.cvc = form.cvc.data
            insurance.additional_info = form.additional_info.data

            db.session.commit()
            flash('Insurance updated successfully!', 'success')
            return redirect(url_for('customer_dashboard'))
        except Exception as e:
            db.session.rollback()
            logging.error(f'Error updating insurance: {e}', exc_info=True)
            flash('An error occurred while updating the insurance. Please try again.', 'danger')
    else:
        # Log and flash detailed form errors
        error_messages = [f"{getattr(form, field).label.text}: {error}" for field, errors in form.errors.items() for error in errors]
        for message in error_messages:
            flash(message, 'danger')
        logging.error(f'Form validation errors: {form.errors}')

    return render_template('update_insurance.html', form=form, insurance=insurance)

@app.route('/delete_insurance/<int:insurance_id>', methods=['POST'])
@login_required
def delete_insurance(insurance_id):
    insurance = InsuranceClaim.query.get_or_404(insurance_id)

    # Check if the user is authorized
    if insurance.user_id != current_user.id and not current_user.is_admin:
        flash('You are not authorized to delete this insurance.', 'danger')
        return redirect(url_for('customer_dashboard'))
    
    try:
        db.session.delete(insurance)
        db.session.commit()
        flash('Insurance deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        logging.error(f'Error deleting insurance: {e}', exc_info=True)
        flash('An error occurred. Please try again.', 'danger')

    return redirect(url_for('customer_dashboard'))

@app.route('/policy_claim')
def policy_claim():
    return render_template('policy_claim.html')

@app.route('/report_incident', methods=['GET', 'POST'])
@login_required
def report_incident():
    form = IncidentReportForm()
    if form.validate_on_submit():
        incident_date = form.incident_date.data
        incident_time = form.incident_time.data
        location = form.incident_location.data
        description = form.incident_description.data
        
        # Handle file uploads
        files = request.files.getlist('attachments')
        file_paths = []
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                
                # Debugging line
                print(f"File saved: {filename}")
                
                file_paths.append(filename)  # Store only the filename

        # Debugging line
        print(f"Attachments list: {file_paths}")
        
        attachments = ','.join(file_paths)  # Join filenames with comma

        # Create a new incident report
        new_incident = IncidentReport(
            user_id=current_user.id,
            incident_date=incident_date,
            incident_time=incident_time,
            location=location,
            description=description,
            attachments=attachments
        )
        
        db.session.add(new_incident)
        db.session.commit()
        
        flash('Incident reported successfully!', 'success')
        return redirect(url_for('customer_dashboard'))

    return render_template('report_incident.html', form=form)


# Helper function to check file type
def allowed_file(filename):
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

@app.route('/update_profile', methods=['GET', 'POST'])
@login_required
def update_profile():
    if request.method == 'POST':
        # Fetching form data
        name = request.form.get('name')
        dln = request.form.get('dln')
        email = request.form.get('email')
        phone = request.form.get('phone')
        dob = request.form.get('dob')
        address = request.form.get('address')
        city = request.form.get('city')
        postcode = request.form.get('postcode')
        country = request.form.get('country')
        
        # Update the user's personal details
        user = User.query.filter_by(id=current_user.id).first()
        if user:
            user.username = name  # Update as needed
            user.email = email
            # Handle other fields if necessary
            db.session.commit()
            flash('Profile updated successfully!', 'success')
        else:
            flash('Profile not found.', 'error')

        return redirect(url_for('customer_dashboard'))

    # GET request: Render the update profile form
    user = User.query.filter_by(id=current_user.id).first()
    return render_template('update_profile.html', user=user)


vehicles = [
    {
        "id": 1,
        "make": "Ford",
        "model": "Fiesta",
        "year": 2018,
        "owner_name": "John Doe",
        "insurance_provider": "Direct Line",
        "policy_number": "DL123456789",
        "coverage_type": "Third-Party",
        "premium": 450.00,
        "start_date": "2023-01-15",
        "end_date": "2024-01-14",
        "image_url": "https://www.thecarexpert.co.uk/wp-content/uploads/2023/05/Ford-Fiesta-ST-2013-to-2017-1920x960.jpg"
    },
    {
        "id": 2,
        "make": "Toyota",
        "model": "Camry",
        "year": 2019,
        "owner_name": "Jane Smith",
        "insurance_provider": "GEICO",
        "policy_number": "GEO987654321",
        "coverage_type": "Third-Party, Fire and Theft",
        "premium": 500.00,
        "start_date": "2023-03-10",
        "end_date": "2024-03-09",
        "image_url": "https://scene7.toyota.eu/is/image/toyotaeurope/exterior-1_tcm-3060-1592401"
    },
    {
        "id": 3,
        "make": "BMW",
        "model": "X5",
        "year": 2020,
        "owner_name": "Robert Johnson",
        "insurance_provider": "State Farm",
        "policy_number": "SF123654789",
        "coverage_type": "Third-Party",
        "premium": 600.00,
        "start_date": "2023-05-05",
        "end_date": "2024-05-04",
        "image_url": "https://stimg.cardekho.com/images/carexteriorimages/930x620/BMW/X5-2023/10452/1688992642182/front-left-side-47.jpg?impolicy=resize&imwidth=420"
    },
    {
        "id": 4,
        "make": "Audi",
        "model": "A4",
        "year": 2021,
        "owner_name": "Emily Davis",
        "insurance_provider": "Allianz",
        "policy_number": "ALZ456789123",
        "coverage_type": "Comprehensive",
        "premium": 700.00,
        "start_date": "2023-06-20",
        "end_date": "2024-06-19",
        "image_url": "https://www.autocar.co.uk/sites/autocar.co.uk/files/audi-a4-rt-2015-0024_0.jpg"
    },
    {
        "id": 5,
        "make": "Mercedes-Benz",
        "model": "C-Class",
        "year": 2022,
        "owner_name": "Michael Brown",
        "insurance_provider": "AXA",
        "policy_number": "AXA123456789",
        "coverage_type": "Third-Party, Fire and Theft",
        "premium": 750.00,
        "start_date": "2023-08-15",
        "end_date": "2024-08-14",
        "image_url": "https://upload.wikimedia.org/wikipedia/commons/5/52/Mercedes-Benz_C_200_Avantgarde_%28W_205%29_%E2%80%93_Frontansicht%2C_26._April_2014%2C_D%C3%BCsseldorf.jpg"
    },
    {
        "id": 6,
        "make": "Honda",
        "model": "Civic",
        "year": 2018,
        "owner_name": "Sarah Wilson",
        "insurance_provider": "Liberty Mutual",
        "policy_number": "LM123456789",
        "coverage_type": "Comprehensive",
        "premium": 400.00,
        "start_date": "2023-07-10",
        "end_date": "2024-07-09",
        "image_url": "https://media.gq-magazine.co.uk/photos/5d13a3199fa6017e488394f8/16:9/w_2560%2Cc_limit/Honda-Civic-01GQ-6Mar17_b.jpg"
    },
    {
        "id": 7,
        "make": "Nissan",
        "model": "Altima",
        "year": 2019,
        "owner_name": "David Miller",
        "insurance_provider": "Zurich",
        "policy_number": "ZUR987654321",
        "coverage_type": "Third-Party, Fire and Theft",
        "premium": 480.00,
        "start_date": "2023-02-25",
        "end_date": "2024-02-24",
        "image_url": "https://www.cnet.com/a/img/resize/0ff95e5b630fa622eab78a6610643c48488cebd5/hub/2012/11/03/25b52d67-bb76-11e2-8a8e-0291187978f3/35524770-5.jpg?auto=webp&width=768"
    },
    {
        "id": 8,
        "make": "Tesla",
        "model": "Model 3",
        "year": 2020,
        "owner_name": "Laura Martinez",
        "insurance_provider": "Progressive",
        "policy_number": "PRO123654789",
        "coverage_type": "Third-Party",
        "premium": 850.00,
        "start_date": "2023-09-15",
        "end_date": "2024-09-14",
        "image_url": "https://ev-database.org/img/auto/Tesla_Model_3_2024/Tesla_Model_3_2024-01@2x.jpg"
    },
    {
        "id": 9,
        "make": "Hyundai",
        "model": "Elantra",
        "year": 2018,
        "owner_name": "Daniel Anderson",
        "insurance_provider": "Nationwide",
        "policy_number": "NW123456789",
        "coverage_type": "Third-Party",
        "premium": 430.00,
        "start_date": "2023-11-01",
        "end_date": "2024-10-31",
        "image_url": "https://hips.hearstapps.com/hmg-prod/images/2024-hyundai-elantra-limited-106-64ef85e2044f5.jpg"
    },
    {
        "id": 10,
        "make": "Volkswagen",
        "model": "Passat",
        "year": 2021,
        "owner_name": "Emma Thomas",
        "insurance_provider": "Farmers",
        "policy_number": "FAR123456789",
        "coverage_type": "Comprehensive",
        "premium": 570.00,
        "start_date": "2023-12-20",
        "end_date": "2024-12-19",
        "image_url": "https://upload.wikimedia.org/wikipedia/commons/thumb/c/c4/VW_Passat_CC_2.0_TDI_DSG_Reflexsilber.JPG/800px-VW_Passat_CC_2.0_TDI_DSG_Reflexsilber.JPG"
    }
    
]


@app.route('/vehicles', methods=['GET'])
def get_vehicles():
    return jsonify(vehicles)

@app.route('/vehicles/<int:vehicle_id>', methods=['GET'])
def get_vehicle(vehicle_id):
    vehicle = next((v for v in vehicles if v['id'] == vehicle_id), None)
    if vehicle is None:
        abort(404, description="Vehicle not found")
    return jsonify(vehicle)

@app.route('/vehicles', methods=['POST'])
def add_vehicle():
    if not request.json or 'make' not in request.json:
        abort(400, description="Bad request: 'make' is required")
    new_vehicle = {
        "id": vehicles[-1]['id'] + 1 if vehicles else 1,
        "make": request.json['make'],
        "model": request.json.get('model', ""),
        "year": request.json.get('year', 0),
        "owner_name": request.json.get('owner_name', ""),
        "insurance_provider": request.json.get('insurance_provider', ""),
        "policy_number": request.json.get('policy_number', ""),
        "coverage_type": request.json.get('coverage_type', ""),
        "premium": request.json.get('premium', 0.0),
        "start_date": request.json.get('start_date', ""),
        "end_date": request.json.get('end_date', ""),
        "image_url": request.json.get('image_url', "")
    }
    vehicles.append(new_vehicle)
    return jsonify(new_vehicle), 201

@app.route('/vehicles/<int:vehicle_id>', methods=['PUT'])
def update_vehicle(vehicle_id):
    vehicle = next((v for v in vehicles if v['id'] == vehicle_id), None)
    if not vehicle:
        return jsonify({"error": "Vehicle not found"}), 404
    if not request.json:
        abort(400, description="Bad request: JSON body required")
    data = request.json
    for key, value in data.items():
        if key in vehicle:
            vehicle[key] = value
    return jsonify(vehicle), 200

@app.route('/vehicles/<int:vehicle_id>', methods=['DELETE'])
def delete_vehicle(vehicle_id):
    global vehicles
    vehicles = [v for v in vehicles if v['id'] != vehicle_id]
    return jsonify({"message": "Vehicle deleted"}), 200

if __name__ == '__main__':
    app.run(debug=True)