from flask import Flask, request, jsonify, abort, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_restful import Api, Resource
from werkzeug.security import generate_password_hash, check_password_hash
import secrets 
from flask_wtf import FlaskForm, CSRFProtect
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from wtforms import StringField, PasswordField, TextAreaField, DateField, SubmitField, SelectField, IntegerField
from wtforms.validators import DataRequired, Email, EqualTo, Length, NumberRange, Regexp, ValidationError
from werkzeug.exceptions import HTTPException
from flask_bcrypt import Bcrypt

from datetime import datetime
import logging



app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = secrets.token_hex(24)

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

    # Added user_id for relationship management
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'<InsuranceClaim {self.id}>'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Flask-RESTful Resource for Users
class UserResource(Resource):
    def get(self, user_id=None):
        if user_id:
            user = User.query.get_or_404(user_id)
            return jsonify({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_admin': user.is_admin
            })
        else:
            users = User.query.all()
            return jsonify([{
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_admin': user.is_admin
            } for user in users])

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

class InsuranceClaimResource(Resource):
    @login_required
    def get(self, claim_id=None):
        if claim_id:
            claim = InsuranceClaim.query.get_or_404(claim_id)
            return jsonify({
                'id': claim.id,
                'user_id': claim.user_id,
                'name': claim.name,
                'dln': claim.dln,
                'email': claim.email,
                'phone': claim.phone,
                'dob': claim.dob,
                'address': claim.address,
                'city': claim.city,
                'postcode': claim.postcode,
                'country': claim.country,
                'car_model': claim.car_model,
                'car_reg': claim.car_reg,
                'policy_number': claim.policy_number,
                'insurance_type': claim.insurance_type,
                'policy_start_date': claim.policy_start_date,
                'amount': claim.amount,
                'card_name': claim.card_name,
                'card_number': claim.card_number,
                'exp_date': claim.exp_date,
                'cvc': claim.cvc,
                'additional_info': claim.additional_info
            })
        else:
            claims = InsuranceClaim.query.filter_by(user_id=current_user.id).all()
            return jsonify([{
                'id': claim.id,
                'user_id': claim.user_id,
                'name': claim.name,
                'dln': claim.dln,
                'email': claim.email,
                'phone': claim.phone,
                'dob': claim.dob,
                'address': claim.address,
                'city': claim.city,
                'postcode': claim.postcode,
                'country': claim.country,
                'car_model': claim.car_model,
                'car_reg': claim.car_reg,
                'policy_number': claim.policy_number,
                'insurance_type': claim.insurance_type,
                'policy_start_date': claim.policy_start_date,
                'amount': claim.amount,
                'card_name': claim.card_name,
                'card_number': claim.card_number,
                'exp_date': claim.exp_date,
                'cvc': claim.cvc,
                'additional_info': claim.additional_info
            } for claim in claims])

    def post(self):
        data = request.get_json()
        new_claim = InsuranceClaim(
            user_id=current_user.id,
            name=data['name'],
            dln=data['dln'],
            email=data['email'],
            phone=data['phone'],
            dob=data['dob'],
            address=data['address'],
            city=data['city'],
            postcode=data['postcode'],
            country=data['country'],
            car_model=data['car_model'],
            car_reg=data['car_reg'],
            policy_number=data['policy_number'],
            insurance_type=data['insurance_type'],
            policy_start_date=data['policy_start_date'],
            amount=data['amount'],
            card_name=data['card_name'],
            card_number=data['card_number'],
            exp_date=data['exp_date'],
            cvc=data['cvc'],
            additional_info=data.get('additional_info')
        )
        db.session.add(new_claim)
        db.session.commit()
        return jsonify({
            'id': new_claim.id,
            'user_id': new_claim.user_id,
            'name': new_claim.name,
            'dln': new_claim.dln,
            'email': new_claim.email,
            'phone': new_claim.phone,
            'dob': new_claim.dob,
            'address': new_claim.address,
            'city': new_claim.city,
            'postcode': new_claim.postcode,
            'country': new_claim.country,
            'car_model': new_claim.car_model,
            'car_reg': new_claim.car_reg,
            'policy_number': new_claim.policy_number,
            'insurance_type': new_claim.insurance_type,
            'policy_start_date': new_claim.policy_start_date,
            'amount': new_claim.amount,
            'card_name': new_claim.card_name,
            'card_number': new_claim.card_number,
            'exp_date': new_claim.exp_date,
            'cvc': new_claim.cvc,
            'additional_info': new_claim.additional_info
        })

    def put(self, claim_id):
        data = request.get_json()
        claim = InsuranceClaim.query.get_or_404(claim_id)
        if claim.user_id != current_user.id and not current_user.is_admin:
            abort(403)
        if 'name' in data:
            claim.name = data['name']
        if 'dln' in data:
            claim.dln = data['dln']
        if 'email' in data:
            claim.email = data['email']
        if 'phone' in data:
            claim.phone = data['phone']
        if 'dob' in data:
            claim.dob = data['dob']
        if 'address' in data:
            claim.address = data['address']
        if 'city' in data:
            claim.city = data['city']
        if 'postcode' in data:
            claim.postcode = data['postcode']
        if 'country' in data:
            claim.country = data['country']
        if 'car_model' in data:
            claim.car_model = data['car_model']
        if 'car_reg' in data:
            claim.car_reg = data['car_reg']
        if 'policy_number' in data:
            claim.policy_number = data['policy_number']
        if 'insurance_type' in data:
            claim.insurance_type = data['insurance_type']
        if 'policy_start_date' in data:
            claim.policy_start_date = data['policy_start_date']
        if 'amount' in data:
            claim.amount = data['amount']
        if 'card_name' in data:
            claim.card_name = data['card_name']
        if 'card_number' in data:
            claim.card_number = data['card_number']
        if 'exp_date' in data:
            claim.exp_date = data['exp_date']
        if 'cvc' in data:
            claim.cvc = data['cvc']
        if 'additional_info' in data:
            claim.additional_info = data['additional_info']
        db.session.commit()
        return jsonify({
            'id': claim.id,
            'user_id': claim.user_id,
            'name': claim.name,
            'dln': claim.dln,
            'email': claim.email,
            'phone': claim.phone,
            'dob': claim.dob,
            'address': claim.address,
            'city': claim.city,
            'postcode': claim.postcode,
            'country': claim.country,
            'car_model': claim.car_model,
            'car_reg': claim.car_reg,
            'policy_number': claim.policy_number,
            'insurance_type': claim.insurance_type,
            'policy_start_date': claim.policy_start_date,
            'amount': claim.amount,
            'card_name': claim.card_name,
            'card_number': claim.card_number,
            'exp_date': claim.exp_date,
            'cvc': claim.cvc,
            'additional_info': claim.additional_info
        })

    def delete(self, claim_id):
        claim = InsuranceClaim.query.get_or_404(claim_id)
        if claim.user_id != current_user.id and not current_user.is_admin:
            abort(403)
        db.session.delete(claim)
        db.session.commit()
        return jsonify({'message': 'Insurance claim deleted successfully'})

class ContactResource(Resource):
    def get(self, contact_id=None):
        if contact_id:
            contact = Contact.query.get_or_404(contact_id)
            return jsonify({
                'id': contact.id,
                'first_name': contact.first_name,
                'last_name': contact.last_name,
                'email': contact.email,
                'subject': contact.subject,
                'message': contact.message
            })
        else:
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
        })

    def put(self, contact_id):
        data = request.get_json()
        contact = Contact.query.get_or_404(contact_id)
        if 'first_name' in data:
            contact.first_name = data['first_name']
        if 'last_name' in data:
            contact.last_name = data['last_name']
        if 'email' in data:
            contact.email = data['email']
        if 'subject' in data:
            contact.subject = data['subject']
        if 'message' in data:
            contact.message = data['message']
        db.session.commit()
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
        return jsonify({'message': 'Contact deleted successfully'})
    
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
    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)

@app.route('/customer_dashboard')
@login_required
def customer_dashboard():
    if current_user.role == 'admin':
        flash('Access denied! Admins cannot access the customer dashboard.', 'danger')
        return redirect(url_for('admin_dashboard'))

    claims = InsuranceClaim.query.filter_by(user_id=current_user.id).all()
    form = InsuranceForm()  # Instantiate the form

    return render_template('customer_dashboard.html', user=current_user, claims=claims, form=form)


class MyModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.role == 'admin'

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login'))

admin = Admin(app, name='Admin Panel', template_mode='bootstrap3')
admin.add_view(MyModelView(Record, db.session))
admin.add_view(MyModelView(Contact, db.session))
admin.add_view(MyModelView(User, db.session))  # Added User model to the admin view
admin.add_view(MyModelView(InsuranceClaim, db.session))  # Updated to InsuranceClaim

# Adding Resources to API
api.add_resource(UserResource, '/users', '/users/<int:user_id>')
api.add_resource(InsuranceClaimResource, '/insurance_claims', '/insurance_claims/<int:claim_id>')
api.add_resource(ContactResource, '/contacts', '/contacts/<int:contact_id>')



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

@app.route('/faq')
def faq():
    return render_template('faq.html')


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


from datetime import datetime

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
        claim = InsuranceClaim.query.filter_by(id=current_user.id).first()
        if claim:
            claim.name = name
            claim.dln = dln
            claim.email = email
            claim.phone = phone
            claim.dob = dob
            claim.address = address
            claim.city = city
            claim.postcode = postcode
            claim.country = country
            db.session.commit()
            flash('Profile updated successfully!', 'success')
        else:
            flash('Profile not found.', 'error')

        return redirect(url_for('customer_dashboard'))

    # GET request: Render the update profile form
    claim = InsuranceClaim.query.filter_by(id=current_user.id).first()
    return render_template('update_profile.html', claim=claim)

if __name__ == '__main__':
    app.run(debug=True)