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
    physical_location = db.Column(db.String(128), nullable=True)  # Add this line
    vnc_port = db.Column(db.Integer, nullable=True)
    ssh_port = db.Column(db.Integer, nullable=True)  # Add this line
    outside_accessible = db.Column(db.Boolean, default=False)
    remarks = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __init__(self, hostname, username, os_type, installed_os, cpu_details, ram_details, 
                 private_ip=None, public_ip=None, cloud_provider_url=None, physical_location=None,  # Add parameter
                 vnc_port=None, ssh_port=None, outside_accessible=False, remarks=None):
        self.hostname = hostname
        self.username = username
        self.os_type = os_type
        self.installed_os = installed_os
        self.cpu_details = cpu_details
        self.ram_details = ram_details
        self.private_ip = private_ip
        self.public_ip = public_ip
        self.cloud_provider_url = cloud_provider_url
        self.physical_location = physical_location  # Add this line
        self.vnc_port = vnc_port
        self.ssh_port = ssh_port  # Add this line
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
            'physical_location': self.physical_location,  # Add this line
            'vnc_port': self.vnc_port,
            'ssh_port': self.ssh_port,  # Add this line
            'outside_accessible': self.outside_accessible,
            'remarks': self.remarks
        }
    
    def __repr__(self):
        return f'<Machine {self.hostname}>'
