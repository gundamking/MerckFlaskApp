from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
import os
import pandas as pd

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///devices.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.secret_key = 'supersecretkey'
db = SQLAlchemy(app)

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

    def __repr__(self):
        return f'<Device {self.hostname}>'

# Home route to list all devices
@app.route('/')
def list_devices():
    devices = Device.query.all()
    return render_template('list_devices.html', devices=devices)

# Route to add new device manually
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

# Route to upload CSV and insert devices from CSV
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

        return redirect(url_for('upload_csv'))

    return render_template('upload.html')


@app.route('/ping/<string:ip_subnet>', methods=['GET'])
def ping_device(ip_subnet):
    try:
        response_time = ping(ip_subnet)  # Ping the device's IP address
        if response_time:
            flash(f'Device at {ip_subnet} is reachable (Response Time: {response_time:.2f}ms)', 'success')
        else:
            flash(f'Device at {ip_subnet} is unreachable', 'danger')
    except Exception as e:
        flash(f"An error occurred while pinging: {e}", 'danger')

    return redirect(url_for('list_devices'))


if __name__ == '__main__':
    # Ensure uploads folder exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Initialize the database
    with app.app_context():
        db.create_all()

    # Run the Flask app
    app.run(debug=True)
