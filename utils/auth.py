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
    import config
    
    # Use fixed credentials from config
    FIXED_USERNAME = config.DEFAULT_OWNER_USERNAME
    FIXED_PASSWORD = config.DEFAULT_OWNER_PASSWORD
    
    # Only allow authentication with fixed credentials
    if username != FIXED_USERNAME or password != FIXED_PASSWORD:
        logger.warning(f"Owner verification failed: Invalid credentials for username: {username}")
        return False
    
    # Get the owner from the database (for logging purposes)
    user = User.query.filter_by(is_owner=True).first()
    
    # If we have an owner in the database, update their last login time
    if user:
        user.last_login = datetime.datetime.utcnow()
        db.session.commit()
    
    logger.info(f"Owner verified successfully with fixed credentials")
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
        import config
        
        # Use fixed credentials from config
        FIXED_USERNAME = config.DEFAULT_OWNER_USERNAME
        
        # Check session authentication
        if 'user_id' in session:
            user = User.query.get(session['user_id'])
            # If user exists and is owner, proceed
            if user and user.is_owner:
                # Additional verification check that this is a properly authenticated owner
                # even if session exists, the user must match fixed credentials
                if user.username == FIXED_USERNAME:
                    g.user = user
                    return f(*args, **kwargs)
        
        # Check token authentication - only used for API calls
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                token = auth_header.split(" ")[1]
                user_id = verify_auth_token(token)
                if user_id:
                    user = User.query.get(user_id)
                    if user and user.is_owner and user.username == FIXED_USERNAME:
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
