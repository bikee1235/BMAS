from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
migrate = Migrate()

# Import models after db initialization to avoid circular imports
from .user import User
from .machine import Machine

# Make models available at package level
__all__ = ['db', 'login_manager', 'User', 'Machine']
