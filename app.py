from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, DateField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = secrets.token_hex(24)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

# Record model
class Record(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    value = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return f'<Record {self.name}>'

# Contact model
class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    subject = db.Column(db.String(150), nullable=False)
    message = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return f'<Contact {self.email}>'

# InsuranceClaim model
class InsuranceClaim(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    car_model = db.Column(db.String(100), nullable=False)
    license_plate = db.Column(db.String(50), nullable=False)
    insurance_type = db.Column(db.String(50), nullable=False)
    policy_number = db.Column(db.String(50), nullable=False)
    policy_start_date = db.Column(db.Date, nullable=False)
    additional_info = db.Column(db.Text, nullable=True)

    user = db.relationship('User', backref=db.backref('insurance_claims', lazy=True))

    def __repr__(self):
        return f'<InsuranceClaim {self.full_name}>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class InsuranceForm(FlaskForm):
    full_name = StringField('Full Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone_number = StringField('Phone Number', validators=[DataRequired()])
    address = StringField('Address', validators=[DataRequired()])
    car_model = StringField('Car Model', validators=[DataRequired()])
    license_plate = StringField('License Plate', validators=[DataRequired()])
    insurance_type = SelectField('Type of Insurance', choices=[
        ('comprehensive', 'Comprehensive'),
        ('third-party', 'Third-Party'),
        ('third-party-fire-theft', 'Third-Party, Fire and Theft')
    ], validators=[DataRequired()])
    policy_number = StringField('Policy Number', validators=[DataRequired()])
    policy_start_date = DateField('Policy Start Date', format='%Y-%m-%d', validators=[DataRequired()])
    additional_info = TextAreaField('Additional Information')
    submit = SubmitField('Submit')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), EqualTo('confirm_password', message='Passwords must match')])
    confirm_password = PasswordField('Confirm Password')
    submit = SubmitField('Register')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('customer_dashboard'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
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
        new_user = User(username=username, email=email, password=hashed_password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('Username or Email already exists', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html', form=form)

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied: Admins only!', 'danger')
        return redirect(url_for('customer_dashboard'))
    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)

@app.route('/customer_dashboard')
@login_required
def customer_dashboard():
    if current_user.is_admin:
        flash('Access denied: Customers only!', 'danger')
        return redirect(url_for('admin_dashboard'))
    return render_template('customer_dashboard.html', user=current_user)

class MyModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login'))

admin = Admin(app, name='Admin Panel', template_mode='bootstrap3')
admin.add_view(MyModelView(Record, db.session))
admin.add_view(MyModelView(Contact, db.session))
admin.add_view(MyModelView(User, db.session))  # Added User model to the admin view
admin.add_view(MyModelView(InsuranceClaim, db.session))  # Updated to InsuranceClaim

class ContactForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    subject = StringField('Subject', validators=[DataRequired()])
    message = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Submit')

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

@app.route('/add', methods=['POST'])
def add_record():
    name = request.form['name']
    value = request.form['value']
    new_record = Record(name=name, value=value)
    db.session.add(new_record)
    db.session.commit()
    return redirect(url_for('index'))

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
        # Creating a new insurance claim object with form data
        new_claim = InsuranceClaim(
            user_id=current_user.id,
            full_name=current_user.username,
            email=current_user.email,
            phone_number=request.form['phone'],
            address=request.form['address'],
            car_model=request.form['car_model'],
            license_plate=request.form['car_reg'],
            insurance_type=form.insurance_type.data,
            policy_number=request.form['policy_number'],
            policy_start_date=form.start_date.data,
            additional_info=request.form.get('additional_info', '')  # Handle optional fields safely
        )
        try:
            db.session.add(new_claim)
            db.session.commit()
            flash('Insurance form submitted successfully!', 'success')
            return redirect(url_for('view_insurance'))  # Redirect to another view upon success
        except Exception as e:
            db.session.rollback()  # Rollback the transaction on error
            flash(f'Error submitting form: {e}', 'danger')
            print(f'Error submitting form: {e}')
    else:
        # Print validation errors for debugging
        print(form.errors)
        flash('Error in form submission', 'danger')
    
    return render_template('add_insurance.html', form=form)  # Render the form template



@app.route('/insurance')
@login_required
def view_insurance():
    if current_user.is_admin:
        forms = InsuranceClaim.query.all()
    else:
        forms = InsuranceClaim.query.filter_by(user_id=current_user.id).all()
    return render_template('view_insurance.html', forms=forms)

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

    form = InsuranceForm()
    if form.validate_on_submit():
        insurance.insurance_type = form.insurance_type.data
        insurance.policy_start_date = form.start_date.data
        db.session.commit()
        flash('Insurance updated successfully!', 'success')
        return redirect(url_for('customer_dashboard'))

    form.insurance_type.data = insurance.insurance_type
    form.start_date.data = insurance.policy_start_date
    return render_template('update_insurance.html', form=form, insurance=insurance)

@app.route('/delete_insurance/<int:insurance_id>', methods=['POST'])
@login_required
def delete_insurance(insurance_id):
    insurance = InsuranceClaim.query.get_or_404(insurance_id)
    if insurance.user_id != current_user.id and not current_user.is_admin:
        flash('You are not authorized to delete this insurance.', 'danger')
        return redirect(url_for('customer_dashboard'))
    db.session.delete(insurance)
    db.session.commit()
    flash('Insurance deleted successfully!', 'success')
    return redirect(url_for('customer_dashboard'))

@app.route('/policy_claim')
def policy_claim():
    return render_template('policy_claim.html')


if __name__ == '__main__':
    app.run(debug=True)