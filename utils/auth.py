import os
import jwt
import uuid
import datetime
import logging
import hashlib
import secrets
from functools import wraps
from flask import request, jsonify, session, g
from werkzeug.security import check_password_hash

logger = logging.getLogger(__name__)

def verify_owner(username, password, biometric_data=None):
    """
    Verify that the user is the owner of the system
    
    Args:
        username: Username of the alleged owner
        password: Password to verify
        biometric_data: Optional biometric data for additional verification
        
    Returns:
        bool: True if verified as owner, False otherwise
    """
    from app import db
    from models import User
    
    # Get the user from the database
    user = User.query.filter_by(username=username).first()
    
    if not user or not user.is_owner:
        logger.warning(f"Owner verification failed: User not found or not owner: {username}")
        return False
    
    # Verify password
    if not check_password_hash(user.password_hash, password):
        logger.warning(f"Owner verification failed: Invalid password for {username}")
        return False
    
    # Check biometric data if provided and enabled
    if biometric_data and user.biometric_data:
        # Simplified biometric verification - in a real system, this would use proper biometric algorithms
        if hashlib.sha256(biometric_data.encode()).hexdigest() != user.biometric_data:
            logger.warning(f"Owner verification failed: Invalid biometric data for {username}")
            return False
    
    # Update last login time
    user.last_login = datetime.datetime.utcnow()
    db.session.commit()
    
    logger.info(f"Owner verified successfully: {username}")
    return True

def generate_auth_token(user_id, expiration=24*60*60):
    """
    Generate a JWT token for API authentication
    
    Args:
        user_id: ID of the user (owner)
        expiration: Token expiration time in seconds (default: 24 hours)
        
    Returns:
        str: JWT token
    """
    from app import app
    
    # Create token payload
    payload = {
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=expiration),
        'iat': datetime.datetime.utcnow(),
        'sub': user_id,
        'jti': str(uuid.uuid4())  # JWT ID for token uniqueness
    }
    
    # Create the token
    token = jwt.encode(
        payload,
        app.secret_key,
        algorithm='HS256'
    )
    
    logger.debug(f"Generated auth token for user {user_id}")
    return token

def verify_auth_token(token):
    """
    Verify a JWT authentication token
    
    Args:
        token: JWT token to verify
        
    Returns:
        int or None: User ID if token is valid, None otherwise
    """
    from app import app
    
    try:
        # Decode and verify the token
        payload = jwt.decode(
            token,
            app.secret_key,
            algorithms=['HS256']
        )
        return payload['sub']  # User ID
    except jwt.ExpiredSignatureError:
        logger.warning("Auth token expired")
        return None
    except jwt.InvalidTokenError:
        logger.warning("Invalid auth token")
        return None

def owner_required(f):
    """
    Decorator to require owner authentication for an endpoint
    
    Usage:
        @app.route('/protected')
        @owner_required
        def protected_route():
            return 'This is a protected route'
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from app import db
        from models import User
        
        # Check session authentication
        if 'user_id' in session:
            user = User.query.get(session['user_id'])
            if user and user.is_owner:
                g.user = user
                return f(*args, **kwargs)
        
        # Check token authentication
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                token = auth_header.split(" ")[1]
                user_id = verify_auth_token(token)
                if user_id:
                    user = User.query.get(user_id)
                    if user and user.is_owner:
                        g.user = user
                        return f(*args, **kwargs)
            except IndexError:
                pass
        
        return jsonify({'error': 'Owner authentication required'}), 401
    
    return decorated_function

def generate_secure_key(length=32):
    """
    Generate a secure random key
    
    Args:
        length: Length of the key in bytes
        
    Returns:
        str: Secure random key in hexadecimal
    """
    return secrets.token_hex(length)
