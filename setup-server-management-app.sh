#!/bin/bash

# Server Management System Setup Script
# This script sets up a Flask web application for managing server details

set -e  # Exit on any error

echo "==========================================================="
echo "Setting up Server Management Web Application"
echo "==========================================================="

# Create project directory
PROJECT_DIR="server_management"
echo "[1/10] Creating project structure..."
mkdir -p "$PROJECT_DIR"/{static/{css,js},templates/{admin,user},models}

# Move to project directory
cd "$PROJECT_DIR"

# Create virtual environment
echo "[2/10] Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Create requirements.txt
echo "[3/10] Creating requirements.txt..."
cat > requirements.txt << 'EOF'
Flask==2.3.3
Flask-SQLAlchemy==3.1.1
Flask-Login==0.6.2
Flask-WTF==1.2.1
Werkzeug==2.3.7
email-validator==2.0.0
python-dotenv==1.0.0
EOF

# Install dependencies
echo "[4/10] Installing dependencies..."
pip install -r requirements.txt

# Create config.py
echo "[5/10] Creating configuration file..."
cat > config.py << 'EOF'
import os
from datetime import timedelta

class Config:
    # Security settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard-to-guess-string'
    
    # SQLite database settings
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///server_management.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session settings
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    
    # Application settings
    APP_NAME = "Machine Management System"
EOF

# Create models
echo "[6/10] Creating database models..."

# models/__init__.py
cat > models/__init__.py << 'EOF'
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
EOF

# models/user.py
cat > models/user.py << 'EOF'
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from . import db, login_manager

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True, nullable=False)
    email = db.Column(db.String(120), unique=True, index=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    
    def __init__(self, username, email, password, is_admin=False):
        self.username = username
        self.email = email
        self.password_hash = generate_password_hash(password)
        self.is_admin = is_admin
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def update_last_login(self):
        self.last_login = datetime.utcnow()
        db.session.commit()
    
    def __repr__(self):
        return f'<User {self.username}>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
EOF

# models/machine.py
cat > models/machine.py << 'EOF'
from datetime import datetime
from . import db

class Machine(db.Model):
    __tablename__ = 'machines'
    
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(64), unique=True, nullable=False, index=True)
    username = db.Column(db.String(64), nullable=False)
    os_type = db.Column(db.String(20), nullable=False)  # Linux, Windows, Mac
    installed_os = db.Column(db.String(64), nullable=False)
    cpu_details = db.Column(db.String(128), nullable=False)
    ram_details = db.Column(db.String(64), nullable=False)
    private_ip = db.Column(db.String(15), nullable=True)
    public_ip = db.Column(db.String(15), nullable=True)
    cloud_provider_url = db.Column(db.String(128), nullable=True)
    vnc_port = db.Column(db.Integer, nullable=True)
    outside_accessible = db.Column(db.Boolean, default=False)
    remarks = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __init__(self, hostname, username, os_type, installed_os, cpu_details, ram_details, 
                 private_ip=None, public_ip=None, cloud_provider_url=None, vnc_port=None, 
                 outside_accessible=False, remarks=None):
        self.hostname = hostname
        self.username = username
        self.os_type = os_type
        self.installed_os = installed_os
        self.cpu_details = cpu_details
        self.ram_details = ram_details
        self.private_ip = private_ip
        self.public_ip = public_ip
        self.cloud_provider_url = cloud_provider_url
        self.vnc_port = vnc_port
        self.outside_accessible = outside_accessible
        self.remarks = remarks
    
    def update(self, **kwargs):
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
        
        self.updated_at = datetime.utcnow()
        db.session.commit()
    
    def to_dict(self):
        return {
            'id': self.id,
            'hostname': self.hostname,
            'username': self.username,
            'os_type': self.os_type,
            'installed_os': self.installed_os,
            'cpu_details': self.cpu_details,
            'ram_details': self.ram_details,
            'private_ip': self.private_ip,
            'public_ip': self.public_ip,
            'cloud_provider_url': self.cloud_provider_url,
            'vnc_port': self.vnc_port,
            'outside_accessible': self.outside_accessible,
            'remarks': self.remarks
        }
    
    def __repr__(self):
        return f'<Machine {self.hostname}>'
EOF

# Create templates
echo "[7/10] Creating HTML templates..."

# Base template
cat > templates/base.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Machine Management System{% endblock %}</title>
    
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    
    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    
    <!-- Custom CSS -->
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
    
    {% block extra_css %}{% endblock %}
</head>
<body>
    {% if current_user.is_authenticated %}
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="{{ url_for('index') }}">Machine Management System</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto">
                    {% if current_user.is_admin %}
                    <li class="nav-item">
                        <a class="nav-link {% if request.endpoint == 'admin_dashboard' %}active{% endif %}" href="{{ url_for('admin_dashboard') }}">
                            <i class="fas fa-tachometer-alt"></i> Dashboard
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link {% if request.endpoint == 'add_machine' %}active{% endif %}" href="{{ url_for('add_machine') }}">
                            <i class="fas fa-plus"></i> Add Machine
                        </a>
                    </li>
                    {% else %}
                    <li class="nav-item">
                        <a class="nav-link {% if request.endpoint == 'user_dashboard' %}active{% endif %}" href="{{ url_for('user_dashboard') }}">
                            <i class="fas fa-tachometer-alt"></i> Dashboard
                        </a>
                    </li>
                    {% endif %}
                </ul>
                <div class="d-flex">
                    <span class="navbar-text me-3">
                        {% if current_user.is_admin %}
                        <span class="badge bg-success">Admin</span>
                        {% else %}
                        <span class="badge bg-info">User</span>
                        {% endif %}
                        {{ current_user.username }}
                    </span>
                    <a href="{{ url_for('logout') }}" class="btn btn-outline-light btn-sm">
                        <i class="fas fa-sign-out-alt"></i> Logout
                    </a>
                </div>
            </div>
        </div>
    </nav>
    {% endif %}
    
    <div class="container mt-4">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category if category != 'message' else 'info' }} alert-dismissible fade show" role="alert">
                        {{ message }}
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        {% block content %}{% endblock %}
    </div>
    
    <footer class="mt-5 py-3 bg-light text-center">
        <div class="container">
            <p class="mb-0">&copy; 2025 Machine Management System</p>
        </div>
    </footer>
    
    <!-- Bootstrap JS Bundle -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    
    <!-- jQuery -->
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    
    <!-- Custom JS -->
    <script src="{{ url_for('static', filename='js/script.js') }}"></script>
    
    {% block extra_js %}{% endblock %}
</body>
</html>
EOF

# Login template
cat > templates/login.html << 'EOF'
{% extends "base.html" %}

{% block title %}Login - Machine Management System{% endblock %}

{% block content %}
<div class="row justify-content-center mt-5">
    <div class="col-md-6 col-lg-4">
        <div class="card shadow">
            <div class="card-body p-5">
                <h2 class="text-center mb-4">Machine Management System</h2>
                
                <form method="POST" action="{{ url_for('login') }}">
                    <div class="mb-3">
                        <label for="username" class="form-label">Username</label>
                        <input type="text" class="form-control" id="username" name="username" required>
                    </div>
                    <div class="mb-3">
                        <label for="password" class="form-label">Password</label>
                        <input type="password" class="form-control" id="password" name="password" required>
                    </div>
                    <div class="d-grid gap-2">
                        <button type="submit" class="btn btn-primary">Sign In</button>
                    </div>
                </form>
                
                <div class="text-center text-muted mt-4">
                    <small>Demo Accounts:</small><br>
                    <small>Admin: username=admin, password=admin123</small><br>
                    <small>User: username=user, password=user123</small>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
EOF

# Admin Dashboard
cat > templates/admin/dashboard.html << 'EOF'
{% extends "base.html" %}

{% block title %}Admin Dashboard - Machine Management System{% endblock %}

{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h2>Machine Management System</h2>
    <a href="{{ url_for('add_machine') }}" class="btn btn-primary">
        <i class="fas fa-plus"></i> Add Machine
    </a>
</div>

<div class="card shadow-sm mb-4">
    <div class="card-body">
        <div class="row mb-3">
            <div class="col-md-6">
                <div class="btn-group" role="group">
                    <a href="{{ url_for('admin_dashboard') }}" class="btn btn-outline-primary {{ 'active' if not request.args.get('os') }}">All</a>
                    <a href="{{ url_for('admin_dashboard', os='Linux') }}" class="btn btn-outline-primary {{ 'active' if request.args.get('os') == 'Linux' }}">Linux</a>
                    <a href="{{ url_for('admin_dashboard', os='Windows') }}" class="btn btn-outline-primary {{ 'active' if request.args.get('os') == 'Windows' }}">Windows</a>
                    <a href="{{ url_for('admin_dashboard', os='Mac') }}" class="btn btn-outline-primary {{ 'active' if request.args.get('os') == 'Mac' }}">Mac</a>
                </div>
            </div>
            <div class="col-md-6">
                <form method="GET" action="{{ url_for('admin_dashboard') }}" class="d-flex">
                    {% if request.args.get('os') %}
                    <input type="hidden" name="os" value="{{ request.args.get('os') }}">
                    {% endif %}
                    <input type="text" name="search" class="form-control me-2" placeholder="Search machines..." value="{{ request.args.get('search', '') }}">
                    <button type="submit" class="btn btn-outline-primary">Search</button>
                </form>
            </div>
        </div>

        <div class="table-responsive">
            <table class="table table-hover">
                <thead>
                    <tr>
                        <th>HOSTNAME</th>
                        <th>OS / TYPE</th>
                        <th>IP ADDRESS</th>
                        <th>RESOURCES</th>
                        <th>ACCESS</th>
                        <th>REMARKS</th>
                        <th>ACTIONS</th>
                    </tr>
                </thead>
                <tbody>
                    {% for machine in machines %}
                    <tr>
                        <td>
                            <strong>{{ machine.hostname }}</strong><br>
                            <small class="text-muted">{{ machine.username }}</small>
                        </td>
                        <td>
                            <strong>{{ machine.installed_os }}</strong><br>
                            <small class="text-muted">{{ machine.os_type }}</small>
                        </td>
                        <td>
                            {% if machine.private_ip %}
                            <span>{{ machine.private_ip }}</span><br>
                            {% endif %}
                            {% if machine.public_ip %}
                            <small class="text-muted">{{ machine.public_ip }}</small>
                            {% endif %}
                        </td>
                        <td>
                            <span>{{ machine.cpu_details }}</span><br>
                            <small class="text-muted">{{ machine.ram_details }}</small>
                        </td>
                        <td>
                            {% if machine.vnc_port %}
                            <span>VNC: {{ machine.vnc_port }}</span><br>
                            {% endif %}
                            <span class="badge {% if machine.outside_accessible %}bg-success{% elif machine.outside_accessible == false %}bg-danger{% else %}bg-warning{% endif %}">
                                {{ 'Yes' if machine.outside_accessible else 'No' }}
                            </span>
                        </td>
                        <td>{{ machine.remarks }}</td>
                        <td>
                            <a href="{{ url_for('edit_machine', machine_id=machine.id) }}" class="btn btn-sm btn-outline-primary">
                                <i class="fas fa-edit"></i>
                            </a>
                            <button type="button" class="btn btn-sm btn-outline-danger" data-bs-toggle="modal" data-bs-target="#deleteModal{{ machine.id }}">
                                <i class="fas fa-trash"></i>
                            </button>
                            
                            <!-- Delete Modal -->
                            <div class="modal fade" id="deleteModal{{ machine.id }}" tabindex="-1" aria-labelledby="deleteModalLabel{{ machine.id }}" aria-hidden="true">
                                <div class="modal-dialog">
                                    <div class="modal-content">
                                        <div class="modal-header">
                                            <h5 class="modal-title" id="deleteModalLabel{{ machine.id }}">Confirm Delete</h5>
                                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                                        </div>
                                        <div class="modal-body">
                                            Are you sure you want to delete the machine <strong>{{ machine.hostname }}</strong>?
                                        </div>
                                        <div class="modal-footer">
                                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                            <form action="{{ url_for('delete_machine', machine_id=machine.id) }}" method="POST">
                                                <button type="submit" class="btn btn-danger">Delete</button>
                                            </form>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        
        {% if pagination.pages > 1 %}
        <nav aria-label="Page navigation">
            <ul class="pagination justify-content-center">
                <li class="page-item {{ 'disabled' if pagination.page == 1 }}">
                    <a class="page-link" href="{{ url_for('admin_dashboard', page=pagination.prev_num, os=request.args.get('os'), search=request.args.get('search')) }}">Previous</a>
                </li>
                
                {% for page_num in pagination.iter_pages() %}
                    {% if page_num %}
                        <li class="page-item {{ 'active' if pagination.page == page_num }}">
                            <a class="page-link" href="{{ url_for('admin_dashboard', page=page_num, os=request.args.get('os'), search=request.args.get('search')) }}">{{ page_num }}</a>
                        </li>
                    {% else %}
                        <li class="page-item disabled">
                            <span class="page-link">...</span>
                        </li>
                    {% endif %}
                {% endfor %}
                
                <li class="page-item {{ 'disabled' if pagination.page == pagination.pages }}">
                    <a class="page-link" href="{{ url_for('admin_dashboard', page=pagination.next_num, os=request.args.get('os'), search=request.args.get('search')) }}">Next</a>
                </li>
            </ul>
        </nav>
        {% endif %}
    </div>
</div>
{% endblock %}
EOF

# Add Machine template
cat > templates/admin/add_machine.html << 'EOF'
{% extends "base.html" %}

{% block title %}Add Machine - Machine Management System{% endblock %}

{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h2>Add New Machine</h2>
    <a href="{{ url_for('admin_dashboard') }}" class="btn btn-outline-secondary">
        <i class="fas fa-arrow-left"></i> Back to Dashboard
    </a>
</div>

<div class="card shadow">
    <div class="card-body p-4">
        <form method="POST" action="{{ url_for('add_machine') }}">
            <div class="row">
                <div class="col-md-6 mb-3">
                    <label for="hostname" class="form-label">Hostname*</label>
                    <input type="text" class="form-control" id="hostname" name="hostname" required>
                </div>
                <div class="col-md-6 mb-3">
                    <label for="username" class="form-label">Username*</label>
                    <input type="text" class="form-control" id="username" name="username" required>
                </div>
            </div>
            
            <div class="row">
                <div class="col-md-4 mb-3">
                    <label for="os_type" class="form-label">OS Type*</label>
                    <select class="form-select" id="os_type" name="os_type" required>
                        <option value="Linux">Linux</option>
                        <option value="Windows">Windows</option>
                        <option value="Mac">Mac</option>
                    </select>
                </div>
                <div class="col-md-8 mb-3">
                    <label for="installed_os" class="form-label">Installed OS*</label>
                    <input type="text" class="form-control" id="installed_os" name="installed_os" required>
                </div>
            </div>
            
            <div class="row">
                <div class="col-md-6 mb-3">
                    <label for="private_ip" class="form-label">Private IP Address</label>
                    <input type="text" class="form-control" id="private_ip" name="private_ip">
                </div>
                <div class="col-md-6 mb-3">
                    <label for="public_ip" class="form-label">Public IP Address</label>
                    <input type="text" class="form-control" id="public_ip" name="public_ip">
                </div>
            </div>
            
            <div class="row">
                <div class="col-md-6 mb-3">
                    <label for="cloud_provider_url" class="form-label">Cloud Provider/URL</label>
                    <input type="text" class="form-control" id="cloud_provider_url" name="cloud_provider_url">
                </div>
                <div class="col-md-3 mb-3">
                    <label for="vnc_port" class="form-label">VNC Port</label>
                    <input type="number" class="form-control" id="vnc_port" name="vnc_port">
                </div>
                <div class="col-md-3 mb-3">
                    <label for="outside_accessible" class="form-label">Outside Accessible</label>
                    <select class="form-select" id="outside_accessible" name="outside_accessible">
                        <option value="No">No</option>
                        <option value="Yes">Yes</option>
                    </select>
                </div>
            </div>
            
            <div class="row">
                <div class="col-md-6 mb-3">
                    <label for="cpu_details" class="form-label">CPU Details*</label>
                    <input type="text" class="form-control" id="cpu_details" name="cpu_details" required>
                </div>
                <div class="col-md-6 mb-3">
                    <label for="ram_details" class="form-label">RAM Details*</label>
                    <input type="text" class="form-control" id="ram_details" name="ram_details" required>
                </div>
            </div>
            
            <div class="mb-3">
                <label for="remarks" class="form-label">Remarks</label>
                <textarea class="form-control" id="remarks" name="remarks" rows="3"></textarea>
            </div>
            
            <div class="d-flex justify-content-end mt-4">
                <a href="{{ url_for('admin_dashboard') }}" class="btn btn-outline-secondary me-2">Cancel</a>
                <button type="submit" class="btn btn-primary">Save Machine</button>
            </div>
        </form>
    </div>
</div>
{% endblock %}
EOF

# Edit Machine template
cat > templates/admin/edit_machine.html << 'EOF'
{% extends "base.html" %}

{% block title %}Edit Machine - Machine Management System{% endblock %}

{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h2>Edit Machine: {{ machine.hostname }}</h2>
    <a href="{{ url_for('admin_dashboard') }}" class="btn btn-outline-secondary">
        <i class="fas fa-arrow-left"></i> Back to Dashboard
    </a>
</div>

<div class="card shadow">
    <div class="card-body p-4">
        <form method="POST" action="{{ url_for('edit_machine', machine_id=machine.id) }}">
            <div class="row">
                <div class="col-md-6 mb-3">
                    <label for="hostname" class="form-label">Hostname*</label>
                    <input type="text" class="form-control" id="hostname" name="hostname" value="{{ machine.hostname }}" required>
                </div>
                <div class="col-md-6 mb-3">
                    <label for="username" class="form-label">Username*</label>
                    <input type="text" class="form-control" id="username" name="username" value="{{ machine.username }}" required>
                </div>
            </div>
            
            <div class="row">
                <div class="col-md-4 mb-3">
                    <label for="os_type" class="form-label">OS Type*</label>
                    <select class="form-select" id="os_type" name="os_type" required>
                        <option value="Linux" {{ 'selected' if machine.os_type == 'Linux' }}>Linux</option>
                        <option value="Windows" {{ 'selected' if machine.os_type == 'Windows' }}>Windows</option>
                        <option value="Mac" {{ 'selected' if machine.os_type == 'Mac' }}>Mac</option>
                    </select>
                </div>
                <div class="col-md-8 mb-3">
                    <label for="installed_os" class="form-label">Installed OS*</label>
                    <input type="text" class="form-control" id="installed_os" name="installed_os" value="{{ machine.installed_os }}" required>
                </div>
            </div>
            
            <div class="row">
                <div class="col-md-6 mb-3">
                    <label for="private_ip" class="form-label">Private IP Address</label>
                    <input type="text" class="form-control" id="private_ip" name="private_ip" value="{{ machine.private_ip }}">
                </div>
                <div class="col-md-6 mb-3">
                    <label for="public_ip" class="form-label">Public IP Address</label>
                    <input type="text" class="form-control" id="public_ip" name="public_ip" value="{{ machine.public_ip }}">
                </div>
            </div>
            
            <div class="row">
                <div class="col-md-6 mb-3">
                    <label for="cloud_provider_url" class="form-label">Cloud Provider/URL</label>
                    <input type="text" class="form-control" id="cloud_provider_url" name="cloud_provider_url" value="{{ machine.cloud_provider_url }}">
                </div>
                <div class="col-md-3 mb-3">
                    <label for="vnc_port" class="form-label">VNC Port</label>
                    <input type="number" class="form-control" id="vnc_port" name="vnc_port" value="{{ machine.vnc_port }}">
                </div>
                <div class="col-md-3 mb-3">
                    <label for="outside_accessible" class="form-label">Outside Accessible</label>
                    <select class="form-select" id="outside_accessible" name="outside_accessible">
                        <option value="No" {{ 'selected' if not machine.outside_accessible }}>No</option>
                        <option value="Yes" {{ 'selected' if machine.outside_accessible }}>Yes</option>
                    </select>
                </div>
            </div>
            
            <div class="row">
                <div class="col-md-6 mb-3">
                    <label for="cpu_details" class="form-label">CPU Details*</label>
                    <input type="text" class="form-control" id="cpu_details" name="cpu_details" value="{{ machine.cpu_details }}" required>
                </div>
                <div class="col-md-6 mb-3">
                    <label for="ram_details" class="form-label">RAM Details*</label>
                    <input type="text" class="form-control" id="ram_details" name="ram_details" value="{{ machine.ram_details }}" required>
                </div>