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
