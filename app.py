from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField, TextAreaField
from wtforms.validators import DataRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash
import os
import pandas as pd
from cryptography.fernet import Fernet
from ping3 import ping
import paramiko  # For SSH functionality

# Initialize the Flask app
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///devices.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'supersecretkey'  # Required for session management
app.config['UPLOAD_FOLDER'] = 'uploads'  # For handling file uploads
app.config['ENCRYPTION_KEY'] = Fernet.generate_key()  # Fernet Key generation
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)  # Create folder if not exists

db = SQLAlchemy(app)

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Upload Form
class UploadForm(FlaskForm):
    file = FileField('Upload CSV', validators=[DataRequired()])
    submit = SubmitField('Upload')

# Device model
class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(100), nullable=False)
    site = db.Column(db.String(100), nullable=False)
    serial_number = db.Column(db.String(100), unique=True, nullable=False)
    division = db.Column(db.String(100), nullable=False)
    instrument_type = db.Column(db.String(100), nullable=False)
    lab_number = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(100), nullable=False)
    ssh_username = db.Column(db.String(100), nullable=False)
    ssh_password = db.Column(db.String(200), nullable=False)  # Store encrypted password
    source_location = db.Column(db.String(200), nullable=False)  # Share drive path
    owner_name = db.Column(db.String(100), nullable=False)
    owner_contact = db.Column(db.String(100), nullable=False)  # Email address
    configuration_details = db.Column(db.Text, nullable=True)

    def encrypt_password(self, password):
        cipher_suite = Fernet(app.config['ENCRYPTION_KEY'])
        self.ssh_password = cipher_suite.encrypt(password.encode()).decode()

    def decrypt_password(self):
        cipher_suite = Fernet(app.config['ENCRYPTION_KEY'])
        return cipher_suite.decrypt(self.ssh_password.encode()).decode()

# Flask-WTF forms for user authentication
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=150)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=4, max=150)])
    submit = SubmitField('Register')

# AddDeviceForm
class AddDeviceForm(FlaskForm):
    hostname = StringField('Hostname', validators=[DataRequired()])
    site = StringField('Site', validators=[DataRequired()])
    serial_number = StringField('Serial Number', validators=[DataRequired()])
    division = StringField('Division', validators=[DataRequired()])
    instrument_type = StringField('Instrument Type', validators=[DataRequired()])
    lab_number = StringField('Lab Number', validators=[DataRequired()])
    ip_address = StringField('IP Address', validators=[DataRequired()])
    ssh_username = StringField('SSH Username', validators=[DataRequired()])
    ssh_password = StringField('SSH Password', validators=[DataRequired()])
    shared_service = StringField('Shared Service')
    owner_name = StringField('Owner Name', validators=[DataRequired()])
    owner_contact = StringField('Owner Contact', validators=[DataRequired()])
    configuration_details = TextAreaField('Configuration Details')

# Function to SSH and check device status
def check_device_status(device):
    try:
        # Set up Paramiko SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Decrypt the password and connect
        decrypted_password = device.decrypt_password()
        ssh.connect(device.ip_address, username=device.ssh_username, password=decrypted_password)

        # Check if the source location exists (using 'ls' or similar command)
        command = f'ls {device.source_location}'
        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode()
        error = stderr.read().decode()

        ssh.close()

        if error:
            return False, f"Error accessing source location: {error}"
        else:
            return True, f"Source location accessible: {output}"

    except Exception as e:
        return False, f"SSH failed: {str(e)}"

# Route to ping a device and check its status via SSH
@app.route('/ping/<int:id>', methods=['GET'])
@login_required
def ping_device(id):
    device = Device.query.get_or_404(id)

    # Check the device's status via SSH
    is_online, message = check_device_status(device)

    return render_template('device_status.html', device=device, is_online=is_online, message=message)

# Routes for user authentication
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('list_devices'))

    form = RegisterForm()
    if form.validate_on_submit():
        user = User(username=form.username.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('list_devices'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('list_devices'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Route to list all devices
@app.route('/')
@login_required
def list_devices():
    devices = Device.query.all()
    return render_template('list_devices.html', devices=devices)

# Route to Upload CSV
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_csv():
    form = UploadForm()  # Create an instance of the form

    if form.validate_on_submit():
        file = form.file.data  # Access the uploaded file

        if not file:
            flash('No file uploaded', 'danger')
            return redirect(request.url)

        # Save the file temporarily
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filepath)

        # Process CSV file
        try:
            data = pd.read_csv(filepath)
            for _, row in data.iterrows():
                new_device = Device(
                    hostname=row['hostname'],
                    site=row['site'],
                    serial_number=row['serial_number'],
                    division=row['division'],
                    instrument_type=row['instrument_type'],
                    lab_number=row['lab_number'],
                    ip_address=row['ip_address'],
                    ssh_username=row['ssh_username'],
                    ssh_password=row['ssh_password'],
                    source_location=row['source_location'],
                    owner_name=row['owner_name'],
                    owner_contact=row['owner_contact'],
                    configuration_details=row['configuration_details']
                )
                db.session.add(new_device)
            db.session.commit()
            flash('CSV file successfully uploaded and data inserted!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error processing file: {e}', 'danger')
        finally:
            # Optionally delete the uploaded file after processing
            os.remove(filepath)

        return redirect(url_for('list_devices'))

    return render_template('upload.html', form=form)  # Pass the form to the template

#Route Edit Device
@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_device(id):
    device = Device.query.get_or_404(id)


# Route to add a new device manually
@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_device():
    form = AddDeviceForm()

    if form.validate_on_submit():
        new_device = Device(
            hostname=form.hostname.data,
            site=form.site.data,
            serial_number=form.serial_number.data,
            division=form.division.data,
            instrument_type=form.instrument_type.data,
            lab_number=form.lab_number.data,
            ip_address=form.ip_address.data,
            ssh_username=form.ssh_username.data,
            ssh_password=form.ssh_password.data,
            source_location=form.shared_service.data,
            owner_name=form.owner_name.data,
            owner_contact=form.owner_contact.data,
            configuration_details=form.configuration_details.data
        )

        new_device.encrypt_password(form.ssh_password.data)

        try:
            db.session.add(new_device)
            db.session.commit()
            flash('Device added successfully!', 'success')
            return redirect(url_for('list_devices'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding device: {e}', 'danger')

    return render_template('add_device.html', form=form)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
