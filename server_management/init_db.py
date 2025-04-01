from models.user import User
from models import db
from flask import Flask
from config import Config

def init_db():
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    
    with app.app_context():
        # Create all database tables
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
            
        # Create default regular user if it doesn't exist
        user = User.query.filter_by(username='user').first()
        if not user:
            user = User(
                username='user',
                email='user@example.com',
                password='user123',
                is_admin=False
            )
            db.session.add(user)
            
        db.session.commit()

if __name__ == '__main__':
    init_db()
    print("Database initialized successfully!")
