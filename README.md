# Car Insurance Company Web Application

**Overview**

This project is a full-featured web application designed for a Car Insurance Company, built using a modern tech stack focusing on robust functionality and user experience.

**Tech Stack**

- Frontend: HTML, CSS, Bootstrap, Javascript
- Backend: Python, Flask
-  Database: SQLAlchemy
-  API: RESTful

**Features**

+ User Authentication and Authorization: Secure login and registration system with role-based access control.
+ Admin Dashboard: Easily manage insurance claims, incident reports, and user accounts.
+ Customer Dashboard: Users can manage insurance policies, report incidents, and update profiles.
+ Payment Integration: Secure payment processing and data encryption.
+ Forms and Validation: Comprehensive forms for insurance claims, incident reports, and contact messages, with robust validation.
+ File Uploads: Secure handling of file uploads for incident report attachments.

**Libraries and Tools**

```
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
```

**Initial Configuration**

```
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
```

**Database Models**

```
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(50), nullable=False, default='user')

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
    attachments = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<IncidentReport {self.id}>'

class Insurance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    insurance_type = db.Column(db.String(50), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    premium_amount = db.Column(db.Integer, nullable=False)
    
    claim_id = db.Column(db.Integer, db.ForeignKey('insurance_claim.id'), nullable=False)
    claim = db.relationship('InsuranceClaim', backref='insurances', lazy=True)

    def __repr__(self):
        return f'<Insurance {self.id}>'

```

**Flask Forms**

```
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
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class ContactForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(max=50)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    subject = StringField('Subject', validators=[DataRequired(), Length(max=150)])
    message = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Submit')
```

**Routes**

+ Authentication: `/login`, `/logout`, `/register`
+ Admin and Customer Dashboards: `/admin_dashboard`, `/customer_dashboard`
+ Insurance Management: `/insurance/new`, `/insurance`, `/update_insurance/<int:insurance_id>`, `/delete_insurance/<int:insurance_id>`
+ Incident Reporting: `/report_incident`
+ Profile Management: `/update_profile`
+ RESTful API: `/vehicles`, `/insurance`, `/users`, `/contact`, `/incident_report`

**RESTful API Endpoints**

+ Vehicles: CRUD operations for vehicle information.
+ Insurance: Manage insurance details.
+ Users: User management endpoints.
+ Contact Form: Handle contact form submissions.
+ Incident Report: Manage incident reports.

**Setup and Installation**

+ Clone the repository.
+ Install dependencies: `pip install -r requirements.txt`
+ Initialize the database: `flask db init && flask db migrate && flask db upgrade`
+ Run the application: `flask run`


## Interface

**Home Page**

![127 0 0 1_5000_ (1)](https://github.com/user-attachments/assets/48e003a8-f135-48cc-9e5e-aabce2a2d2f2)

**Login Page**

![127 0 0 1_5000_login](https://github.com/user-attachments/assets/7bb8eb5d-16b2-4df7-9561-178aa1c4bd73)

**Register Page**

![127 0 0 1_5000_register](https://github.com/user-attachments/assets/6a2d9ba0-ca19-45e4-810c-8eea5d53e520)

**Customer Dashboard**

![127 0 0 1_5000_customer_dashboard (1)](https://github.com/user-attachments/assets/8365c338-864c-42b1-bc9d-63589a3ed0eb)

**Add Insurance**

![127 0 0 1_5000_insurance_new](https://github.com/user-attachments/assets/6de4f8ae-eb5e-4cc3-8d6b-16bdb6ca226c)

**Update Insurance**

![127 0 0 1_5000_update_insurance_3](https://github.com/user-attachments/assets/c98a0a5d-a530-46d3-addb-541d9f6bb9ff)

**Report Incident**

![127 0 0 1_5000_report_incident (2)](https://github.com/user-attachments/assets/d351a43e-18ad-4310-8a41-b814d10d2483)

**Claim Policy**

![127 0 0 1_5000_claim_policy (2)](https://github.com/user-attachments/assets/e8948097-cb1d-48a3-a3c9-67b538330f90)

**View All Registered Insurance**

![127 0 0 1_5000_insurance (1)](https://github.com/user-attachments/assets/8d78a264-c2e3-40bc-9b28-823bd944680f)

**Admin Panel**

![127 0 0 1_5000_admin_dashboard (1)](https://github.com/user-attachments/assets/6fa70f5b-db6e-4077-b194-0bc49ab0b1d1)

### Manage Database Record

**Report Incident Table**

![image](https://github.com/user-attachments/assets/7075894b-db05-46e2-9014-95f1004d1a8e)

**Insurance Claim Table**

![image](https://github.com/user-attachments/assets/b96d20d9-8c0c-473a-b334-94d0dce8de09)

**Users Table**

![image](https://github.com/user-attachments/assets/249c8e89-f3ce-4422-b593-6fc53b1733a8)

**Contact Form Table**

![image](https://github.com/user-attachments/assets/9b5ea52b-a107-402b-8212-64b15f4e09d3)

## RESTful API

**Users API**

![image](https://github.com/user-attachments/assets/566dfa88-d145-4526-8ed1-d68f21dd11aa)

**Contacts API**

![image](https://github.com/user-attachments/assets/8342e84e-a429-4c73-baa6-3e290a855f45)

**Vehicles API**

![127 0 0 1_5000_vehicles](https://github.com/user-attachments/assets/a0107490-42d4-4b28-9ac4-a57875925699)

**Insurance Claims API**

![127 0 0 1_5000_insurance-claims](https://github.com/user-attachments/assets/818f0204-09da-4ea4-99be-87eb474d6ef5)

**Report Incident API**

![image](https://github.com/user-attachments/assets/4358e032-9cca-4262-af8c-e11a6e109506)


## Video

https://github.com/user-attachments/assets/53b16c97-148a-4fbd-b354-d917421f7a41


**Contributions**

Feel free to fork the repository and submit pull requests. Contributions are welcome!
