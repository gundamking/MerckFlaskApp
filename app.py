from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///devices.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'supersecretkey'  # Required for session management
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

app = Flask(__name__)

# Make sure you set a secret key for CSRF protection
app.config['SECRET_KEY'] = 'supersecretkey'  # Ensure this is set and kept secret in production

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Database setup
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///devices.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Device model
class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(100), nullable=False)
    site = db.Column(db.String(100), nullable=False)
    serial_number = db.Column(db.String(100), unique=True, nullable=False)
    division = db.Column(db.String(100), nullable=False)
    instrument_type = db.Column(db.String(100), nullable=False)
    lab_number = db.Column(db.String(100), nullable=False)
    ip_subnet = db.Column(db.String(100), nullable=False)
    owner_name = db.Column(db.String(100), nullable=False)
    owner_contact = db.Column(db.String(100), nullable=False)
    configuration_details = db.Column(db.Text, nullable=True)

# Flask-WTF forms for user authentication
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=150)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=4, max=150)])
    submit = SubmitField('Register')

# Routes for Logging in 
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
        if user is not None and user.check_password(form.password.data):
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
def list_devices():
    devices = Device.query.all()
    return render_template('list_devices.html', devices=devices)

# Route to edit a device
@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit_device(id):
    device = Device.query.get_or_404(id)

    if request.method == 'POST':
        device.hostname = request.form['hostname']
        device.site = request.form['site']
        device.serial_number = request.form['serial_number']
        device.division = request.form['division']
        device.instrument_type = request.form['instrument_type']
        device.lab_number = request.form['lab_number']
        device.ip_subnet = request.form['ip_subnet']
        device.owner_name = request.form['owner_name']
        device.owner_contact = request.form['owner_contact']
        device.configuration_details = request.form['configuration_details']

        try:
            db.session.commit()
            flash('Device updated successfully!', 'success')
            return redirect(url_for('list_devices'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating device: {e}', 'danger')

    return render_template('edit_device.html', device=device)

# Route to add a new device manually
@app.route('/add', methods=['GET', 'POST'])
def add_device():
    if request.method == 'POST':
        hostname = request.form['hostname']
        site = request.form['site']
        serial_number = request.form['serial_number']
        division = request.form['division']
        instrument_type = request.form['instrument_type']
        lab_number = request.form['lab_number']
        ip_subnet = request.form['ip_subnet']
        owner_name = request.form['owner_name']
        owner_contact = request.form['owner_contact']
        configuration_details = request.form['configuration_details']

        new_device = Device(
            hostname=hostname, site=site, serial_number=serial_number, division=division,
            instrument_type=instrument_type, lab_number=lab_number, ip_subnet=ip_subnet,
            owner_name=owner_name, owner_contact=owner_contact, configuration_details=configuration_details
        )

        try:
            db.session.add(new_device)
            db.session.commit()
            flash('Device added successfully!', 'success')
            return redirect(url_for('list_devices'))
        except:
            db.session.rollback()
            flash('Error adding device. Please try again.', 'danger')

    return render_template('add_device.html')

# Route to upload devices via CSV
@app.route('/upload', methods=['GET', 'POST'])
def upload_csv():
    if request.method == 'POST':
        file = request.files['file']
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
                    ip_subnet=row['ip_subnet'],
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

    return render_template('upload.html')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
