import os
from dotenv import load_dotenv

# Config class to handle Secret data

load_dotenv()
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY') or 'you-will-never-guess'
    SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI') or 'sqlite:///' + os.path.join(BASE_DIR, 'app.db')
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')
    JWT_ACCESS_TOKEN_EXPIRES = int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES')) or 10
    JWT_REFRESH_TOKEN_EXPIRES = int(os.getenv('JWT_REFRESH_TOKEN_EXPIRES')) or 30
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    MAIL_SERVER = os.getenv('MAIL_SERVER')
    MAIL_PORT = int(os.getenv('MAIL_PORT'))
    MAIL_USE_SSL = bool(os.getenv('MAIL_USE_SSL')) or True 
    # MAX_ATTEMPTS = int(os.getenv('MAX_ATTEMPTS')) 
    # LOCKOUT_TIME = int(os.getenv('LOCKOUT_TIME'))
    

# -- SECRET KEY SCRIPT --
# >>> import secrets
# >>> secrets.token_hex(16) -- FOR JWT hex(32)