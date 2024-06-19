import random
import jwt
from datetime import timezone, timedelta, datetime
from sqlalchemy.sql import func
from flask import current_app, request, jsonify
from functools import wraps
from app.models import User, OTP, BlackList
from flask_mail import Message
from app import mail, db

# Module for utility functions -- Auth related functions can be made in a seperate file auth.py  

def create_jwt(identity, token_type="access"): # Default type is access
    # Method to create jwt access or refresh token
    if token_type == 'access':
        expires_in = current_app.config["JWT_ACCESS_TOKEN_EXPIRES"]
    elif token_type == 'refresh':
        expires_in = current_app.config["JWT_REFRESH_TOKEN_EXPIRES"]
    else:
        raise ValueError("Invalid Token Type")
    
    payload = {
        'identity': identity, # Identification of user such as id, email etc.
        'type': token_type,
        'exp': datetime.now(timezone.utc) + timedelta(minutes=expires_in)
    }
    
    return jwt.encode(payload, current_app.config["JWT_SECRET_KEY"], algorithm='HS256')
    
def decode_jwt(token):
    # Decodes the token to readable form
    try:
        payload = jwt.decode(token, current_app.config["JWT_SECRET_KEY"], algorithms='HS256')
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def access_token_required(f):
    # Decorator which checks if access token and valid and returns current user 
    @wraps(f)
    
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization').split()[1] if 'Authorization' in request.headers else None
        
        if not token:
            return jsonify({
                "Err": "Token is missing"
            }, 401)
            
        blacklist_token = BlackList.query.filter_by(token=token).first()
        
        if blacklist_token: # Checks for blacklisted token
            return jsonify({
                'err': 'Token is revoked!'
            })
            
        decoded_token = decode_jwt(token) 
        
        if not decoded_token or decoded_token.get('type') != 'access': # Checks for access token
            return jsonify({
                "err": "Invalid Token!"
            }, 401)
            
        u_id = decoded_token['identity']
        current_user = User.query.get(u_id)
        
        if not current_user:
            return jsonify({
                "Err": "User not found!"
            }, 401)
            
        return f(current_user, *args, **kwargs)
    
    return decorated

def refresh_token_required(f):
    @wraps(f)
    
    # Decorator which checks if refresh token and valid and returns current user 

    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization').split()[1] if 'Authorization' in request.headers else None
        
        if not token:
            return jsonify({
                "Err": "Token is missing"
            }, 401)
        
        decoded_token = decode_jwt(token)
        
        if not decoded_token or decoded_token.get('type') != 'refresh':
            return jsonify({
                "err": "Invalid Token!"
            }, 401)
            
        u_id = decoded_token['identity']
        current_user = User.query.get(u_id)
        
        if not current_user:
            return jsonify({
                "Err": "User not found!"
            }, 401)
            
        return f(current_user, *args, **kwargs)
    
    return decorated

def send_mail_for_verification(email, user_id):
    # Method to send OTP mail to given email
    try:
        subject = 'OTP VERIFICATION'
        recipient = email
        otp = random.randint(100000, 999999) # Returns Random 6-Digit INT
        body = f"Your OTP for verification is {otp}."
        
        if not email:
            return False

        msg = Message(subject=subject, sender=current_app.config["MAIL_USERNAME"], recipients=[recipient])
        msg.body = body
        mail.send(msg) # Send mail

        user_otp = OTP.query.filter_by(user_id=user_id).first()
        
        if user_otp: # Checks for already exting OTP
            user_otp.code = otp
            user_otp.time = datetime.now(timezone.utc) 
            db.session.commit() # Updates OTP model
            current_app.logger.info(f'Existing OTP updated for email {email} with OTP {otp}')
            
        else:
            user_otp = OTP(user_id=user_id, code=otp, time=func.now())
            db.session.add(user_otp)
            db.session.commit() # Creates new entry
            current_app.logger.info(f'New OTP created for email {email} with OTP {otp}')
        
        return True # Returns true if mail sent
    
    except Exception as e:
        current_app.logger.error(f"INTERNAL SERVER ERROR : {str(e)}")
        return False # Returns False in case of error