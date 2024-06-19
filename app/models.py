from datetime import datetime, timedelta, timezone
import sqlalchemy as sa
from sqlalchemy.sql import func
import sqlalchemy.orm as so
from app import db
from flask import current_app
from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model):
    # User model for handling user data
    __tablename__ = 'users'

    id: so.Mapped[int] = so.mapped_column(sa.Integer, primary_key=True)
    username: so.Mapped[str] = so.mapped_column(sa.String(64), unique=True, index=True, nullable=False)
    email: so.Mapped[str] = so.mapped_column(sa.String(120), unique=True, index=True, nullable=False)
    password_hash: so.Mapped[str] = so.mapped_column(sa.String(256), nullable=False)
    is_verified: so.Mapped[bool] = so.mapped_column(sa.Boolean, nullable=True, default=False)
    login_attempts: so.Mapped[int] = so.mapped_column(sa.Integer, nullable=True,default=0)
    last_attempt: so.Mapped[datetime] = so.mapped_column(sa.DateTime, nullable=True, default=None)
    otps = so.relationship("OTP", back_populates="user")
    
    def set_password(self, password):
        # Sets user's password.
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        # Checks user's password.
        return check_password_hash(self.password_hash, password)


    def to_dict(self):
        data = {
            'id': self.id,
            'username': self.username,
            'email': self.email
        }
        
        return data

    def reset_login_attempts(self):
        # Resets user's Login attempts
        self.login_attempts = 0
        self.last_attempt = None
        db.session.commit()
    
        
    def __repr__(self):
        return f'<User {self.username}>'

class OTP(db.Model):
    # OTP model for handling user's OTP
    __tablename__ = 'otp_verification'
    
    id: so.Mapped[int] = so.mapped_column(sa.Integer, primary_key=True)
    code: so.Mapped[int] = so.mapped_column(sa.Integer)
    user_id: so.Mapped[User] = so.mapped_column(sa.Integer, sa.ForeignKey(User.id))
    time: so.Mapped[datetime] = so.mapped_column(sa.DateTime(timezone=True), server_default=func.now())
    
    user = so.relationship("User", back_populates="otps")
    
    def check_otp(self, code):
        # Checks OTP code
        return self.code == code
    
    def is_expired(self):
        # Checks if OTP code is expired
        expiry_time = self.time + timedelta(seconds=120)
        # current_app.logger.info(f'Server Time: {self.time} ')
        # current_app.logger.info(f'Current Time: {func.now()} ')
        # current_app.logger.info(f'Expiry Time: {expiry_time} ')
        return datetime.utcnow() > expiry_time
    
    def __repr__(self):
        return f'<OTP {self.code}>'

class BlackList(db.Model):
    # Blacklist Token model for revoking user's Access token
    __tablename__ = 'blacklist_token'
    
    id: so.Mapped[int] = so.mapped_column(sa.Integer, primary_key=True)
    token: so.Mapped[str] = so.mapped_column(sa.String(500), unique=True)
    token_type: so.Mapped[str] = so.mapped_column(sa.String(20))
    blacklisted_on: so.Mapped[datetime] = so.mapped_column(sa.DateTime(timezone=True), server_default=func.now())
    
    def __repr__(self):
        return f'<Token {self.token} - {self.token_type}>'