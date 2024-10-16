from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from ping3 import ping

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///devices.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'supersecretkey'
db = SQLAlchemy(app)

# Model for IoT Device
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

# Route to add new device
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
            hostname=hostname, site=site, serial_number=serial_number,
            division=division, instrument_type=instrument_type, lab_number=lab_number,
            ip_subnet=ip_subnet, owner_name=owner_name, owner_contact=owner_contact,
            configuration_details=configuration_details
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

# Route to list and search devices
@app.route('/')
def list_devices():
    search = request.args.get('search', '')
    if search:
        devices = Device.query.filter(Device.hostname.contains(search) | 
                                      Device.serial_number.contains(search)).all()
    else:
        devices = Device.query.all()
    return render_template('list_devices.html', devices=devices)

# Route to ping a device
@app.route('/ping/<string:ip_subnet>', methods=['GET'])
def ping_device(ip_subnet):
    response_time = ping(ip_subnet)
    if response_time:
        flash(f'Device at {ip_subnet} is reachable (Response Time: {response_time:.2f}ms)', 'success')
    else:
        flash(f'Device at {ip_subnet} is unreachable', 'danger')
    return redirect(url_for('list_devices'))

if __name__ == '__main__':
    db.create_all()  # Create database and tables
    app.run(debug=True)
