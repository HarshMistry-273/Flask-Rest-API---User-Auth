from datetime import datetime, timedelta, timezone
from app.api import bp
from flask import request, jsonify, url_for
from app import db
from app.models import OTP, User, BlackList
from .utils import  create_jwt, access_token_required, send_mail_for_verification, refresh_token_required, decode_jwt
from flask import current_app

# Route for User Registration
@bp.route('/users/register', methods=['POST'])
def register():
    try:
        data = request.json # Get data from request
        
        if not data or not all(k in data for k in ("username", "email", "password")): # Checks for required values
            current_app.logger.info("Empty data received in registration request.")
            return jsonify({'msg':"Username, Email or Password can't be empty."}), 401

        if User.query.filter_by(username = data["username"]).first(): # Checks for if username is already in use 
            current_app.logger.info(f"Username '{data['username']}' already taken in registration request.")
            return jsonify({'msg':"Username already taken."}), 400
        
        if User.query.filter_by(email = data["email"]).first(): # Checks for if email is already in use 
            current_app.logger.info(f"Email '{data['email']}' already taken in registration request.")
            return jsonify({'msg':"Email already taken."}), 400
        
        user = User(username=data["username"], email=data["email"])
        user.set_password(data["password"])
        current_app.logger.info(f"User ID {user.id} registered successfully.")
        
        db.session.add(user)
        db.session.commit()
        # Adds user in User model
        email = send_mail_for_verification(user.email, user.id)
        
        if not email: # Checks if email is sent or not
            current_app.logger.error(f"Failed to send email to User ID {user.id}.")
            return jsonify({'err': 'Failed to send OTP.'})
        
        current_app.logger.info(f"OTP sent to email for User ID {user.id}.")
        return jsonify({
            'msg': 'User registered and OTP sent.',
            '_links': {
                'resend': url_for('api.send_mail', id=user.id),
                'check': url_for('api.check_otp_for_verification', id=user.id)
            }
        }), 201

    except Exception as e:
        current_app.logger.error(f"Internal server error: {e}")
        return jsonify({
            "err": "INTERNAL SERVER ERROR",
            # "msg": str(e)
        }), 500

# Login Variables
MAX_ATTEMPTS = 3 # current_app.config["MAX_ATTEMPTS"]
LOCKOUT_TIME = timedelta(minutes=1)  # current_app.config["LOCKOUT_TIME"]

# Login route to handle user login
@bp.route('/users/login', methods=['POST'])
def login():
    try:
        data = request.json # Get data from request
        
        if not data or not all(k in data for k in ("username", "password")): # Checks for required values
            current_app.logger.info("Received empty data in login request.")
            return jsonify({'msg':"Username or Password can't be empty."}), 400
        
        user = User.query.filter_by(username=data["username"]).first()
        
        if not user: # Checks if user exists or not
            current_app.logger.info(f"Username '{data['username']}' not found in login request.")
            return jsonify({'err': 'User not found!'}), 404
        
        if not user.is_verified: # Checks if user is verified or not
            current_app.logger.error(f"User ID {user.id} not verified.")
            return jsonify({'err': 'Please verify your email first to login!'}), 401
        
        if user.login_attempts >= MAX_ATTEMPTS and user.last_attempt: # Checks for failed login attempts and last failed login time
            time_since_last_attempt = datetime.utcnow() -  user.last_attempt # Gets time since last failed login attempt by user
            
            if time_since_last_attempt <  LOCKOUT_TIME: # Checks for LockOut time
                current_app.logger.info(f"User ID {user.id} is locked out due to too many login attempts.")
                return jsonify({'msg': f'Too many login attempts try again later in few seconds!'})  
                 
        if user and user.check_password(data["password"]): # Checks if user exists and if the provided password matches the actual password
            user.reset_login_attempts()
            access_token = create_jwt(user.id, "access") # Create access token
            refresh_token = create_jwt(user.id, "refresh") # Create refresh token
            current_app.logger.info(f"User ID {user.id} logged in.")
            return jsonify(access_token=access_token, refresh_token=refresh_token), 201 # Returns access and refresh tokens
        
        else:
            user.login_attempts += 1 # If failed login attempt increases the value by 1
            user.last_attempt = datetime.now(timezone.utc) # Stores last login attempt's time
            db.session.commit()
            current_app.logger.info(f"Failed log in attempt for User ID {user.id}. Attempt {user.login_attempts}")
            return jsonify({"msg":"Invalid username or password"}), 401
        
    except Exception as e:
        current_app.logger.error(f"Internal server error: {e}")
        return jsonify({
            "err": "INTERNAL SERVER ERROR",
            # "msg": str(e)
        }), 500

@bp.route('/send-otp')
def send_mail():
    try:
        id = request.args.get('id') # Gets id from query params
        
        if not id: # If not found in query params, it checks for request's body
            data = request.json  
             
            if not data: # Checks if no data is received
                current_app.logger.info("Received empty data in send OTP request.")
                return jsonify({'err': 'Please enter the user id!'}), 400
            id = data["id"]
            
        user = User.query.filter_by(id=id).first()
        
        if not user: # Checks if user is there or not
            current_app.logger.info('No user found in send OTP request')
            return jsonify({'err': 'User not found!'}), 404
        
        if user.is_verified: # Checks if user is already verified
            current_app.logger.info(f"User {user.id} already verified in send OTP request.")
            return jsonify({'msg': 'User already verified!'})
         
        email_sent = send_mail_for_verification(user.email, user.id) # Sends OTP to user's mail
        
        if not email_sent: # Checks if mail sent or not
            current_app.logger.error(f"INTERNAL SERVER ERROR : {str(e)} ")
            return jsonify({'err': 'Failed to send OTP'})
        
        current_app.logger.info(f'OTP sent for username {user.username}')
        return jsonify({'msg': 'OTP re-sent!'})
    
    except Exception as e:
        current_app.logger.error(f"Internal server error: {e}")
        return jsonify({
            "err": "INTERNAL SERVER ERROR",
            # "msg": str(e)
        }), 500
    
@bp.route('/check-otp', methods=['POST'])
def check_otp_for_verification():
    try:
        id = request.args.get('id') # Gets id from query params
        
        if not id:
            data = request.json  # If not found in query params, it checks for request's body
            
            if not data or not all(k in data for k in ("id", "code")): # Checks for required data
                current_app.logger.info("Received empty data in check OTP request.")
                return jsonify({'err': 'Please provide the user id and OTP code!'}), 400
            
            id = data["id"]
            code = data["code"]
            
        data = request.json
        
        if not data or "code" not in data:  # Checks for required data
                current_app.logger.info("Received empty data in check OTP request.")
                return jsonify({'err': 'Please provide the user id and OTP code!'}), 400
            
        code = data["code"]
        user_otp = OTP.query.filter_by(user_id=id).first()
        user = User.query.filter_by(id=id).first()
        
        if not user_otp: # Checks if OTP is there or not
            current_app.logger.info(f'No OTP found for User {user.id} in check OTP request')
            return jsonify({'err': 'OTP not found!'}), 404
        
        if user_otp.is_expired(): # Checks if OTP is expired
            current_app.logger.info(f'OTP expired for {user.id} in check OTP request')
            return jsonify({'err': 'OTP has expired!'}), 400
        
        if not user_otp.check_otp(code):  # Checks if actual OTP is == provided OTP
            current_app.logger.info(f'User {user.id} passed invalid OTP in check OTP request')
            return jsonify({'err':'Invalid OTP!'}), 400
        
        if not user: # Checks if user is there or not
            current_app.logger.info(f'User {user.id} not found in check OTP request')
            return jsonify({'err': 'User not found!'}), 404
        
        user.is_verified = True # Verifies user if OTP matches
        current_app.logger.info(f'User {user.username} verified')
        db.session.commit() 
        return jsonify({'msg': 'User Verified'}), 200       
    
    except Exception as e:
        current_app.logger.error(f"Internal server error: {e}")
        return jsonify({
            "err": "INTERNAL SERVER ERROR",
            # "msg": str(e)
        }), 500

@bp.route('/index')
@access_token_required 
# Sample protected route
def index(current_user):
    current_app.logger.info(f"User ID {current_user.id} visited /index.")
    return jsonify({'msg': f'Welcome {current_user.username}'})

@bp.route('/auth/refresh')
# Route to generate access tokens
@refresh_token_required
def get_refresh_token(current_user): 
    try:
        current_app.logger.info(f"User ID {current_user.id} requested access token.") # Fetches current user and returns access token based on the provided refresh token
        access_token = create_jwt(current_user.id, "access")
        return jsonify({'access': access_token}), 201
    
    except Exception as e:
        current_app.logger.error(f"Internal server error: {e}")
        return jsonify({
            "err": "INTERNAL SERVER ERROR",
            # "msg": str(e)
        }), 500
    
@bp.route('/logout', methods=['POST'])
# Route to blacklist access token
@access_token_required
@refresh_token_required
def logout(current_user):
    try:
        token = request.headers.get('Authorization').split()[1] # Gets authorization token
        decoded_token = decode_jwt(token) # Decoded token
        token_type = decoded_token.get('type') # Gets token type i.e Access or Refresh
        blacklisted_token = BlackList(token=token, token_type=token_type) #Blacklists the given token
        db.session.add(blacklisted_token)
        db.session.commit()
        current_app.logger.info(f"User ID {current_user.id} requested access token revoke.")
        return jsonify({'msg': 'Token Revoked!'})
    
    except Exception as e:
            current_app.logger.error(f"Internal server error: {e}")
            return jsonify({
            "err": "INTERNAL SERVER ERROR",
            # "msg": str(e)
        }), 500
