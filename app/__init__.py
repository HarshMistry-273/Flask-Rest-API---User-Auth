import logging
from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_mail import Mail
# from .models import User -- Creates a circular dependency

db = SQLAlchemy()
migrate = Migrate()
mail = Mail()

def create_app():
    
    # Create Flask Application
    app = Flask(__name__)
    app.config.from_object(Config)
    
    from app.api import bp
    app.register_blueprint(bp)
    
    # Initialize extensions with Flask
    db.init_app(app)
    migrate.init_app(app, db)
    mail.init_app(app)
    
    # Setup Logging
    handler = logging.FileHandler('app.log')
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    app.logger.addHandler(handler)
    
    # Provide context variables to flask shell 
    @app.shell_context_processor
    def make_shell_context():
        from .models import User  # Import here to avoid circular dependency
        return {'db': db, 'User': User}

    return app

    
    
    