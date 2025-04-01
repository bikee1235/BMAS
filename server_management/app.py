from flask import Flask, render_template, redirect, url_for, flash, request, abort, send_file
from flask_login import login_user, logout_user, login_required, current_user
from models import db, login_manager
from models.user import User
from models.machine import Machine
from config import Config
from datetime import datetime
from io import BytesIO, StringIO
import csv

app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db.init_app(app)
login_manager.init_app(app)

# Create database tables and initialize database
with app.app_context():
    db.create_all()
    
    # Create default admin user if it doesn't exist
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(
            username='admin',
            email='admin@example.com',
            password='admin123',
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
        search_term = f"%{search}%"
        query = query.filter(
            db.or_(
                Machine.hostname.ilike(search_term),
                Machine.username.ilike(search_term),
                Machine.private_ip.ilike(search_term),
                Machine.public_ip.ilike(search_term),
                Machine.installed_os.ilike(search_term),
                Machine.os_type.ilike(search_term),
                Machine.cpu_details.ilike(search_term),
                Machine.ram_details.ilike(search_term),
                Machine.cloud_provider_url.ilike(search_term),
                Machine.remarks.ilike(search_term)
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
        search_term = f"%{search}%"
        query = query.filter(
            db.or_(
                Machine.hostname.ilike(search_term),
                Machine.username.ilike(search_term),
                Machine.private_ip.ilike(search_term),
                Machine.public_ip.ilike(search_term),
                Machine.installed_os.ilike(search_term),
                Machine.os_type.ilike(search_term),
                Machine.cpu_details.ilike(search_term),
                Machine.ram_details.ilike(search_term),
                Machine.cloud_provider_url.ilike(search_term),
                Machine.remarks.ilike(search_term)
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
            vnc_port=request.form['vnc_port'] or None,
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
    
    machine = Machine.query.get_or_404(machine_id)
    
    if request.method == 'POST':
        machine.hostname = request.form['hostname']
        machine.username = request.form['username']
        machine.os_type = request.form['os_type']
        machine.installed_os = request.form['installed_os']
        machine.cpu_details = request.form['cpu_details']
        machine.ram_details = request.form['ram_details']
        machine.private_ip = request.form['private_ip']
        machine.public_ip = request.form['public_ip']
        machine.cloud_provider_url = request.form['cloud_provider_url']
        machine.vnc_port = request.form['vnc_port'] or None
        machine.outside_accessible = request.form['outside_accessible'] == 'Yes'
        machine.remarks = request.form['remarks']
        machine.updated_at = datetime.utcnow()
        
        db.session.commit()
        flash('Machine updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin/edit_machine.html', machine=machine)

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
        # Create a string buffer for CSV data
        output = StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['Hostname', 'Username', 'OS Type', 'Installed OS', 'Private IP', 
                        'Public IP', 'CPU Details', 'RAM Details', 'VNC Port', 
                        'Outside Accessible', 'Cloud Provider URL', 'Remarks'])
        
        # Write machine data
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
                'Yes' if machine.outside_accessible else 'No',
                machine.cloud_provider_url or '',
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

if __name__ == '__main__':
    app.run(debug=True)
