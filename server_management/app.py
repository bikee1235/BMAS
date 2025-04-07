from flask import Flask, render_template, redirect, url_for, flash, request, abort, send_file
from flask_login import login_user, logout_user, login_required, current_user
from models import db, login_manager, migrate
from models.user import User
from models.machine import Machine
from config import Config
from datetime import datetime
from io import BytesIO, StringIO
import csv
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.config.from_object(Config)

# Make min function available in templates
app.jinja_env.globals.update(min=min)

# Initialize extensions
db.init_app(app)
login_manager.init_app(app)
migrate.init_app(app, db)

# Create database tables and initialize database
with app.app_context():
    db.create_all()
    
    # Create default admin user if it doesn't exist
    admin = User.query.filter_by(username='scoot').first()
    if not admin:
        admin = User(
            username='scoot',
            email='admin@example.com',
            password='tiger',
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()
    
    # Create default regular user if it doesn't exist
    regular_user = User.query.filter_by(username='user').first()
    if not regular_user:
        regular_user = User(
            username='user',
            email='user@example.com',
            password='user123',
            is_admin=False
        )
        db.session.add(regular_user)
        db.session.commit()

@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            user.update_last_login()
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        
        flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 10
    os_filter = request.args.get('os')
    search = request.args.get('search')
    
    query = Machine.query
    
    if os_filter:
        query = query.filter_by(os_type=os_filter)
    if search:
        search_term = f"%{search.strip()}%"
        query = query.filter(
            db.or_(
                db.func.coalesce(Machine.hostname, '').ilike(search_term),
                db.func.coalesce(Machine.username, '').ilike(search_term),
                db.func.coalesce(Machine.private_ip, '').ilike(search_term),
                db.func.coalesce(Machine.public_ip, '').ilike(search_term),
                db.func.coalesce(Machine.installed_os, '').ilike(search_term),
                db.func.coalesce(Machine.os_type, '').ilike(search_term),
                db.func.coalesce(Machine.cpu_details, '').ilike(search_term),
                db.func.coalesce(Machine.ram_details, '').ilike(search_term),
                db.func.coalesce(Machine.cloud_provider_url, '').ilike(search_term),
                db.func.coalesce(Machine.physical_location, '').ilike(search_term),  # Add this line
                db.func.coalesce(Machine.remarks, '').ilike(search_term),
                db.cast(Machine.vnc_port, db.String).ilike(search_term),
                db.cast(Machine.ssh_port, db.String).ilike(search_term)
            )
        )
    
    pagination = query.order_by(Machine.hostname).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('admin/dashboard.html', 
                         machines=pagination.items,
                         pagination=pagination)

@app.route('/user/dashboard')
@login_required
def user_dashboard():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    os_filter = request.args.get('os')
    search = request.args.get('search')
    
    query = Machine.query
    
    if os_filter:
        query = query.filter_by(os_type=os_filter)
    if search:
        search_term = f"%{search.strip()}%"
        query = query.filter(
            db.or_(
                db.func.coalesce(Machine.hostname, '').ilike(search_term),
                db.func.coalesce(Machine.username, '').ilike(search_term),
                db.func.coalesce(Machine.private_ip, '').ilike(search_term),
                db.func.coalesce(Machine.public_ip, '').ilike(search_term),
                db.func.coalesce(Machine.installed_os, '').ilike(search_term),
                db.func.coalesce(Machine.os_type, '').ilike(search_term),
                db.func.coalesce(Machine.cpu_details, '').ilike(search_term),
                db.func.coalesce(Machine.ram_details, '').ilike(search_term),
                db.func.coalesce(Machine.cloud_provider_url, '').ilike(search_term),
                db.func.coalesce(Machine.physical_location, '').ilike(search_term),  # Add this line
                db.func.coalesce(Machine.remarks, '').ilike(search_term),
                db.cast(Machine.vnc_port, db.String).ilike(search_term),
                db.cast(Machine.ssh_port, db.String).ilike(search_term)
            )
        )
    
    pagination = query.order_by(Machine.hostname).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('admin/dashboard.html',
                         machines=pagination.items,
                         pagination=pagination)

@app.route('/admin/machine/add', methods=['GET', 'POST'])
@login_required
def add_machine():
    if not current_user.is_admin:
        abort(403)
    
    if request.method == 'POST':
        machine = Machine(
            hostname=request.form['hostname'],
            username=request.form['username'],
            os_type=request.form['os_type'],
            installed_os=request.form['installed_os'],
            cpu_details=request.form['cpu_details'],
            ram_details=request.form['ram_details'],
            private_ip=request.form['private_ip'],
            public_ip=request.form['public_ip'],
            cloud_provider_url=request.form['cloud_provider_url'],
            physical_location=request.form['physical_location'],  # Add this line
            vnc_port=request.form['vnc_port'] or None,
            ssh_port=request.form['ssh_port'] or None,
            outside_accessible=request.form['outside_accessible'] == 'Yes',
            remarks=request.form['remarks']
        )
        db.session.add(machine)
        db.session.commit()
        flash('Machine added successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin/add_machine.html')

@app.route('/admin/machine/<int:machine_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_machine(machine_id):
    if not current_user.is_admin:
        abort(403)
    
    try:
        machine = Machine.query.get_or_404(machine_id)
        
        if request.method == 'POST':
            try:
                # Validate hostname uniqueness
                new_hostname = request.form['hostname']
                if new_hostname != machine.hostname and Machine.query.filter_by(hostname=new_hostname).first():
                    flash('Hostname already exists', 'danger')
                    return render_template('admin/edit_machine.html', machine=machine)
                
                # Validate IP addresses
                private_ip = request.form['private_ip']
                public_ip = request.form['public_ip']
                if private_ip and not is_valid_ip(private_ip):
                    flash('Invalid private IP address format', 'danger')
                    return render_template('admin/edit_machine.html', machine=machine)
                if public_ip and not is_valid_ip(public_ip):
                    flash('Invalid public IP address format', 'danger')
                    return render_template('admin/edit_machine.html', machine=machine)
                
                # Validate ports
                vnc_port = request.form['vnc_port']
                ssh_port = request.form['ssh_port']
                if vnc_port and not is_valid_port(vnc_port):
                    flash('Invalid VNC port number (must be between 1-65535)', 'danger')
                    return render_template('admin/edit_machine.html', machine=machine)
                if ssh_port and not is_valid_port(ssh_port):
                    flash('Invalid SSH port number (must be between 1-65535)', 'danger')
                    return render_template('admin/edit_machine.html', machine=machine)
                
                # Update machine details
                machine.hostname = new_hostname
                machine.username = request.form['username']
                machine.os_type = request.form['os_type']
                machine.installed_os = request.form['installed_os']
                machine.cpu_details = request.form['cpu_details']
                machine.ram_details = request.form['ram_details']
                machine.private_ip = private_ip
                machine.public_ip = public_ip
                machine.cloud_provider_url = request.form['cloud_provider_url']
                machine.physical_location = request.form['physical_location']  # Add this line
                machine.vnc_port = int(vnc_port) if vnc_port else None
                machine.ssh_port = int(ssh_port) if ssh_port else None
                machine.outside_accessible = request.form['outside_accessible'] == 'Yes'
                machine.remarks = request.form['remarks']
                machine.updated_at = datetime.utcnow()
                
                db.session.commit()
                flash('Machine updated successfully!', 'success')
                return redirect(url_for('admin_dashboard'))
                
            except ValueError as e:
                flash(f'Invalid input: {str(e)}', 'danger')
                return render_template('admin/edit_machine.html', machine=machine)
            except Exception as e:
                db.session.rollback()
                flash(f'Error updating machine: {str(e)}', 'danger')
                return render_template('admin/edit_machine.html', machine=machine)
        
        return render_template('admin/edit_machine.html', machine=machine)
        
    except Exception as e:
        flash(f'Error loading machine: {str(e)}', 'danger')
        return redirect(url_for('admin_dashboard'))

# Add helper functions for validation
def is_valid_ip(ip):
    try:
        parts = ip.split('.')
        return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
    except (AttributeError, TypeError, ValueError):
        return False

def is_valid_port(port):
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (TypeError, ValueError):
        return False

@app.route('/admin/machine/<int:machine_id>/delete', methods=['POST'])
@login_required
def delete_machine(machine_id):
    if not current_user.is_admin:
        abort(403)
    
    machine = Machine.query.get_or_404(machine_id)
    db.session.delete(machine)
    db.session.commit()
    
    flash('Machine deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/export-machines')
@login_required
def export_machines():
    if not current_user.is_admin:
        abort(403)
    
    try:
        output = StringIO()
        writer = csv.writer(output)
        
        # Update header with physical_location
        writer.writerow(['Hostname', 'Username', 'OS Type', 'Installed OS', 'Private IP', 
                        'Public IP', 'CPU Details', 'RAM Details', 'VNC Port', 'SSH Port',
                        'Outside Accessible', 'Cloud Provider URL', 'Physical Location', 'Remarks'])
        
        machines = Machine.query.all()
        for machine in machines:
            writer.writerow([
                machine.hostname,
                machine.username,
                machine.os_type,
                machine.installed_os,
                machine.private_ip or '',
                machine.public_ip or '',
                machine.cpu_details,
                machine.ram_details,
                machine.vnc_port or '',
                machine.ssh_port or '',
                'Yes' if machine.outside_accessible else 'No',
                machine.cloud_provider_url or '',
                machine.physical_location or '',  # Add physical location to export
                machine.remarks or ''
            ])
        
        # Convert to bytes
        output_str = output.getvalue()
        output.close()
        bytes_output = BytesIO()
        bytes_output.write(output_str.encode('utf-8-sig'))
        bytes_output.seek(0)
        
        return send_file(
            bytes_output,
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'machines_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        )
        
    except Exception as e:
        print(f"Export error: {str(e)}")
        flash('Error exporting data. Please try again.', 'danger')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/import-machines', methods=['POST'])
@login_required
def import_machines():
    if not current_user.is_admin:
        abort(403)
    
    try:
        if 'file' not in request.files:
            flash('No file selected', 'danger')
            return redirect(url_for('admin_dashboard'))
        
        file = request.files['file']
        if file.filename == '' or not file.filename.endswith('.csv'):
            flash('Please select a valid CSV file', 'danger')
            return redirect(url_for('admin_dashboard'))
        
        # Read CSV file and handle BOM
        stream = StringIO(file.stream.read().decode("UTF8"), newline=None)
        csv_input = stream.read()
        if csv_input.startswith('\ufeff'):  # Remove BOM if present
            csv_input = csv_input[1:]
        stream = StringIO(csv_input)
        csv_reader = csv.DictReader(stream)
        
        success_count = 0
        error_count = 0
        errors = []
        
        for row in csv_reader:
            try:
                # Clean row keys by removing BOM if present
                cleaned_row = {k.replace('\ufeff', ''): v for k, v in row.items()}
                
                machine = Machine(
                    hostname=cleaned_row['Hostname'],
                    username=cleaned_row['Username'],
                    os_type=cleaned_row['OS Type'],
                    installed_os=cleaned_row['Installed OS'],
                    cpu_details=cleaned_row['CPU Details'],
                    ram_details=cleaned_row['RAM Details'],
                    private_ip=cleaned_row.get('Private IP'),
                    public_ip=cleaned_row.get('Public IP'),
                    cloud_provider_url=cleaned_row.get('Cloud Provider URL'),
                    physical_location=cleaned_row.get('Physical Location'),  # Add this line
                    vnc_port=int(cleaned_row['VNC Port']) if cleaned_row.get('VNC Port') else None,
                    ssh_port=int(cleaned_row['SSH Port']) if cleaned_row.get('SSH Port') else None,
                    outside_accessible=cleaned_row.get('Outside Accessible', 'No') == 'Yes',
                    remarks=cleaned_row.get('Remarks')
                )
                db.session.add(machine)
                success_count += 1
            except Exception as e:
                error_count += 1
                errors.append(f"Row {success_count + error_count}: {str(e)}")
                continue
        
        if success_count > 0:
            db.session.commit()
            
        if error_count > 0:
            flash(f'Import partially complete: {success_count} machines imported, {error_count} failed. Check console for details.', 'warning')
            for error in errors:
                print(error)
        else:
            flash(f'Successfully imported {success_count} machines!', 'success')
        
    except Exception as e:
        print(f"Import error: {str(e)}")
        flash('Error importing data. Please check the CSV format.', 'danger')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
def manage_users():
    if not current_user.is_admin:
        abort(403)
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('manage_users'))
        
        user = User(
            username=username,
            email=email,
            password=password,
            is_admin=False
        )
        db.session.add(user)
        db.session.commit()
        flash('User created successfully!', 'success')
        return redirect(url_for('manage_users'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 10
    pagination = User.query.filter_by(is_admin=False).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('admin/manage_users.html', 
                         users=pagination.items,
                         pagination=pagination)

@app.route('/admin/user/<int:user_id>/edit', methods=['POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin:
        abort(403)
    
    user = User.query.get_or_404(user_id)
    
    if user.is_admin:
        flash('Cannot edit admin user', 'danger')
        return redirect(url_for('manage_users'))
    
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    
    if User.query.filter(User.username == username, User.id != user_id).first():
        flash('Username already exists', 'danger')
        return redirect(url_for('manage_users'))
    
    user.username = username
    user.email = email
    if password:
        user.set_password(password)
    
    db.session.commit()
    flash('User updated successfully!', 'success')
    return redirect(url_for('manage_users'))

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        abort(403)
    
    user = User.query.get_or_404(user_id)
    
    if user.is_admin:
        flash('Cannot delete admin user', 'danger')
        return redirect(url_for('manage_users'))
    
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('manage_users'))

if __name__ == '__main__':
     app.run(host='0.0.0.0', port=5005, debug=True)
