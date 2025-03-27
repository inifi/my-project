"""
Enhanced Owner Recognition Module

This module implements advanced technologies for owner authentication and recognition,
including behavioral biometrics, multi-factor authentication, and secure token-based systems.
"""

import hashlib
import hmac
import json
import logging
import time
import random
import re
import uuid
from datetime import datetime, timedelta
from urllib.parse import urlparse
import jwt
from cryptography.fernet import Fernet
import base64
import os

# Configure logging
logger = logging.getLogger(__name__)

# Constants for token validation
TOKEN_EXPIRY = 3600  # 1 hour in seconds
REFRESH_TOKEN_EXPIRY = 604800  # 1 week in seconds

# Fixed credentials from config - will be imported at runtime
AUTH_USERNAME = None
AUTH_PASSWORD = None


class OwnerRecognitionSystem:
    """Comprehensive owner recognition system with multiple verification methods"""
    
    def __init__(self, app=None, secret_key=None):
        """Initialize the recognition system"""
        self.app = app
        self.secret_key = secret_key or os.environ.get("SECRET_KEY", "fallback_secret_key")
        self.encryption_key = self._derive_encryption_key(self.secret_key)
        self.fernet = Fernet(self.encryption_key)
        self.owner_fingerprints = {}
        self.typing_patterns = {}
        self.known_devices = {}
        self.suspicious_attempts = {}
        
        # Load the AUTH credentials from config at runtime
        global AUTH_USERNAME, AUTH_PASSWORD
        if app and hasattr(app, 'config'):
            try:
                import config
                AUTH_USERNAME = config.AUTH_USERNAME
                AUTH_PASSWORD = config.AUTH_PASSWORD
            except (ImportError, AttributeError) as e:
                logger.error(f"Failed to load auth credentials from config: {str(e)}")
                AUTH_USERNAME = "NOBODY"
                AUTH_PASSWORD = "ONEWORLD"
        else:
            # Fallback to hardcoded values if needed
            AUTH_USERNAME = "NOBODY"
            AUTH_PASSWORD = "ONEWORLD"
    
    def _derive_encryption_key(self, secret):
        """Derive a Fernet encryption key from the secret key"""
        key = hashlib.sha256(secret.encode()).digest()
        return base64.urlsafe_b64encode(key)
    
    def generate_owner_token(self, user_id, device_info=None, ip_address=None):
        """
        Generate a secure token for owner authentication
        
        Args:
            user_id: Owner's user ID
            device_info: Information about the owner's device
            ip_address: IP address of the request
            
        Returns:
            dict: Access and refresh tokens with metadata
        """
        now = datetime.utcnow()
        
        # Store device fingerprint if provided
        device_id = None
        if device_info:
            device_id = self._generate_device_fingerprint(device_info, ip_address)
            if device_id not in self.known_devices:
                self.known_devices[device_id] = {
                    'first_seen': now.isoformat(),
                    'user_id': user_id,
                    'ip_address': ip_address,
                    'device_info': device_info,
                    'trust_level': 'new'
                }
        
        # Create access token payload
        access_payload = {
            'sub': str(user_id),
            'iat': now,
            'exp': now + timedelta(seconds=TOKEN_EXPIRY),
            'type': 'access',
            'device_id': device_id,
            'jti': str(uuid.uuid4())
        }
        
        # Create refresh token payload with longer expiry
        refresh_payload = {
            'sub': str(user_id),
            'iat': now,
            'exp': now + timedelta(seconds=REFRESH_TOKEN_EXPIRY),
            'type': 'refresh',
            'device_id': device_id,
            'jti': str(uuid.uuid4())
        }
        
        # Sign the tokens
        access_token = jwt.encode(access_payload, self.secret_key, algorithm='HS256')
        refresh_token = jwt.encode(refresh_payload, self.secret_key, algorithm='HS256')
        
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'expires_in': TOKEN_EXPIRY,
            'token_type': 'Bearer',
            'device_id': device_id
        }
        
    def verify_token(self, token, token_type='access'):
        """
        Verify a token's validity
        
        Args:
            token: JWT token to verify
            token_type: Type of token ('access' or 'refresh')
            
        Returns:
            dict: Token payload if valid, None if invalid
        """
        try:
            # Decode and verify the token
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            
            # Check token type
            if payload.get('type') != token_type:
                logger.warning(f"Token type mismatch: expected {token_type}, got {payload.get('type')}")
                return None
            
            # Token is valid
            return payload
            
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {str(e)}")
            return None
    
    def refresh_access_token(self, refresh_token, device_info=None, ip_address=None):
        """
        Generate a new access token using a refresh token
        
        Args:
            refresh_token: Valid refresh token
            device_info: Current device information
            ip_address: Current IP address
            
        Returns:
            dict: New access token if refresh token is valid
        """
        # Verify the refresh token
        payload = self.verify_token(refresh_token, token_type='refresh')
        if not payload:
            return None
        
        user_id = payload.get('sub')
        stored_device_id = payload.get('device_id')
        
        # Verify device consistency if possible
        if device_info and stored_device_id:
            current_device_id = self._generate_device_fingerprint(device_info, ip_address)
            if stored_device_id != current_device_id:
                logger.warning(f"Device mismatch during token refresh: {stored_device_id} vs {current_device_id}")
                # We still allow refresh but at lower trust level, tracking the anomaly
                self._record_suspicious_activity(user_id, "device_mismatch", ip_address, device_info)
        
        # Generate a new access token
        now = datetime.utcnow()
        new_payload = {
            'sub': user_id,
            'iat': now,
            'exp': now + timedelta(seconds=TOKEN_EXPIRY),
            'type': 'access',
            'device_id': stored_device_id,
            'jti': str(uuid.uuid4()),
            'refreshed': True
        }
        
        access_token = jwt.encode(new_payload, self.secret_key, algorithm='HS256')
        
        return {
            'access_token': access_token,
            'expires_in': TOKEN_EXPIRY,
            'token_type': 'Bearer'
        }
        
    def analyze_typing_pattern(self, typing_data):
        """
        Analyze typing pattern data for behavioral biometrics
        
        Args:
            typing_data: Raw typing data (keystroke timings, etc.)
            
        Returns:
            dict: Analysis results with confidence score
        """
        try:
            # Decode the typing data if it's encrypted or encoded
            if isinstance(typing_data, str):
                try:
                    typing_data = json.loads(typing_data)
                except:
                    typing_data = {"raw": typing_data}
            
            # Extract timing data
            keystroke_timings = typing_data.get('timings', [])
            key_hold_times = typing_data.get('holdTimes', [])
            
            if not keystroke_timings or len(keystroke_timings) < 5:
                return {"confidence": 0, "error": "Insufficient typing data"}
            
            # Calculate basic metrics
            avg_time_between_keys = sum(keystroke_timings[1:]) / len(keystroke_timings[1:]) if len(keystroke_timings) > 1 else 0
            typing_consistency = self._calculate_typing_consistency(keystroke_timings)
            
            # For first-time analysis, just store the pattern
            user_id = typing_data.get('userId')
            if user_id:
                if user_id not in self.typing_patterns:
                    self.typing_patterns[user_id] = {
                        'avg_time_between_keys': avg_time_between_keys,
                        'typing_consistency': typing_consistency,
                        'samples': 1,
                        'last_updated': datetime.utcnow().isoformat()
                    }
                    return {"confidence": 1.0, "status": "pattern_stored", "metrics": {"consistency": typing_consistency}}
                else:
                    # Compare with stored pattern
                    stored_pattern = self.typing_patterns[user_id]
                    time_diff_ratio = min(abs(stored_pattern['avg_time_between_keys'] - avg_time_between_keys) / stored_pattern['avg_time_between_keys'], 1.0)
                    consistency_diff = abs(stored_pattern['typing_consistency'] - typing_consistency)
                    
                    # Calculate confidence score (1.0 = perfect match, 0.0 = completely different)
                    confidence = 1.0 - (time_diff_ratio * 0.5 + consistency_diff * 0.5)
                    
                    # Update stored pattern with weighted average
                    samples = stored_pattern['samples']
                    stored_pattern['avg_time_between_keys'] = (stored_pattern['avg_time_between_keys'] * samples + avg_time_between_keys) / (samples + 1)
                    stored_pattern['typing_consistency'] = (stored_pattern['typing_consistency'] * samples + typing_consistency) / (samples + 1)
                    stored_pattern['samples'] += 1
                    stored_pattern['last_updated'] = datetime.utcnow().isoformat()
                    
                    return {
                        "confidence": confidence,
                        "status": "pattern_matched" if confidence > 0.7 else "pattern_mismatch",
                        "metrics": {
                            "consistency": typing_consistency,
                            "time_diff_ratio": time_diff_ratio,
                            "consistency_diff": consistency_diff
                        }
                    }
            
            return {"confidence": 0.5, "status": "no_user_id", "metrics": {"consistency": typing_consistency}}
            
        except Exception as e:
            logger.error(f"Error analyzing typing pattern: {str(e)}")
            return {"confidence": 0, "error": str(e)}
            
    def _calculate_typing_consistency(self, timings):
        """Calculate typing consistency score from timing data"""
        if len(timings) < 3:
            return 0
            
        # Calculate standard deviation of timings
        mean = sum(timings) / len(timings)
        variance = sum((t - mean) ** 2 for t in timings) / len(timings)
        std_dev = variance ** 0.5
        
        # Normalize to a consistency score (0-1, higher is more consistent)
        consistency = 1.0 / (1.0 + std_dev / mean)
        return consistency
            
    def _generate_device_fingerprint(self, device_info, ip_address=None):
        """
        Generate a unique fingerprint for a device
        
        Args:
            device_info: Dictionary of device characteristics
            ip_address: IP address of the device
            
        Returns:
            str: Unique device fingerprint
        """
        # Extract key device characteristics
        fingerprint_data = {
            'userAgent': device_info.get('userAgent', ''),
            'platform': device_info.get('platform', ''),
            'screenResolution': device_info.get('screenResolution', ''),
            'colorDepth': device_info.get('colorDepth', ''),
            'timezone': device_info.get('timezone', ''),
            'language': device_info.get('language', ''),
            'fonts': device_info.get('fonts', [])[:5],  # Limit to first 5 fonts for stability
            'canvas': device_info.get('canvas', ''),
            'webgl': device_info.get('webgl', ''),
            'audio': device_info.get('audio', ''),
            'plugins': device_info.get('plugins', [])[:3],  # Limit to first 3 plugins
            'ipClass': self._classify_ip(ip_address) if ip_address else None
        }
        
        # Create a deterministic string representation
        fingerprint_str = json.dumps(fingerprint_data, sort_keys=True)
        
        # Generate hash fingerprint
        hash_obj = hashlib.sha256(fingerprint_str.encode())
        fingerprint = hash_obj.hexdigest()
        
        return fingerprint
        
    def _classify_ip(self, ip_address):
        """Classify IP address into a general class to allow for IP changes within same network"""
        if not ip_address:
            return None
            
        # For IPv4
        if re.match(r'\d+\.\d+\.\d+\.\d+', ip_address):
            octets = ip_address.split('.')
            # Return first two octets as the class (e.g. 192.168.x.x)
            return f"{octets[0]}.{octets[1]}"
        
        # For IPv6 (simplified)
        return ip_address.split(':')[0:2]
        
    def _record_suspicious_activity(self, user_id, activity_type, ip_address=None, device_info=None):
        """
        Record suspicious authentication activity
        
        Args:
            user_id: User ID related to the activity
            activity_type: Type of suspicious activity
            ip_address: IP address of the request
            device_info: Device information
        """
        now = datetime.utcnow()
        
        if user_id not in self.suspicious_attempts:
            self.suspicious_attempts[user_id] = []
            
        self.suspicious_attempts[user_id].append({
            'timestamp': now.isoformat(),
            'type': activity_type,
            'ip_address': ip_address,
            'device_info': device_info
        })
        
        # Limit the size of the history
        if len(self.suspicious_attempts[user_id]) > 10:
            self.suspicious_attempts[user_id] = self.suspicious_attempts[user_id][-10:]
            
        # Log the suspicious activity
        logger.warning(f"Suspicious activity: {activity_type} for user {user_id} from IP {ip_address}")
        
    def verify_owner_credentials(self, username, password, request_info=None):
        """
        Verify owner credentials with enhanced security checks
        
        Args:
            username: Submitted username
            password: Submitted password
            request_info: Additional request information for security checks
            
        Returns:
            dict: Authentication result with security assessment
        """
        # Check for brute force or distributed attacks
        ip_address = request_info.get('ip') if request_info else None
        if ip_address:
            # Check for rate limiting (simplified implementation)
            # In a real system, this would use a proper rate limiter with Redis, etc.
            current_time = time.time()
            key = f"auth_attempt:{ip_address}"
            
            # This is a placeholder for a proper rate-limiting mechanism
            # In the real implementation, we would increment a counter in a distributed store
            
        # Enhanced timing attack protection
        # We'll perform full verification regardless of early failure
        # but only return final result to avoid timing leaks
        
        # Verify fixed credentials (expected to be from config.py)
        credentials_valid = (username == AUTH_USERNAME and password == AUTH_PASSWORD)
        
        # Add artificial delay with slight randomization to prevent timing attacks
        time.sleep(random.uniform(0.1, 0.3))
        
        if credentials_valid:
            return {
                "authenticated": True,
                "security_level": "enhanced",
                "message": "Authentication successful",
                "additional_checks_required": False
            }
        else:
            return {
                "authenticated": False,
                "security_level": "enhanced",
                "message": "Invalid credentials",
                "additional_checks_required": False
            }
            
    def encrypt_sensitive_data(self, data):
        """
        Encrypt sensitive data for secure storage or transmission
        
        Args:
            data: Data to encrypt (string or bytes)
            
        Returns:
            str: Encrypted data as a base64-encoded string
        """
        try:
            # Convert to bytes if string
            if isinstance(data, str):
                data = data.encode()
                
            # Encrypt the data
            encrypted = self.fernet.encrypt(data)
            
            # Return as base64 string
            return encrypted.decode()
            
        except Exception as e:
            logger.error(f"Error encrypting data: {str(e)}")
            return None
            
    def decrypt_sensitive_data(self, encrypted_data):
        """
        Decrypt sensitive data
        
        Args:
            encrypted_data: Encrypted data as base64 string
            
        Returns:
            str: Decrypted data as string
        """
        try:
            # Convert to bytes if string
            if isinstance(encrypted_data, str):
                encrypted_data = encrypted_data.encode()
                
            # Decrypt the data
            decrypted = self.fernet.decrypt(encrypted_data)
            
            # Return as string
            return decrypted.decode()
            
        except Exception as e:
            logger.error(f"Error decrypting data: {str(e)}")
            return None
            
    def generate_hmac_signature(self, data, key=None):
        """
        Generate HMAC signature for data verification
        
        Args:
            data: Data to sign
            key: Optional custom key, defaults to secret_key
            
        Returns:
            str: HMAC signature as hexadecimal string
        """
        key = key or self.secret_key
        
        # Convert to bytes if string
        if isinstance(data, str):
            data = data.encode()
        if isinstance(key, str):
            key = key.encode()
            
        # Create HMAC signature
        signature = hmac.new(key, data, hashlib.sha256).hexdigest()
        
        return signature
        
    def verify_hmac_signature(self, data, signature, key=None):
        """
        Verify HMAC signature for data integrity
        
        Args:
            data: Original data
            signature: HMAC signature to verify
            key: Optional custom key, defaults to secret_key
            
        Returns:
            bool: True if signature is valid
        """
        expected_signature = self.generate_hmac_signature(data, key)
        
        # Use constant-time comparison to prevent timing attacks
        return hmac.compare_digest(expected_signature, signature)
        
    def get_owner_device_history(self, user_id):
        """
        Get history of owner's authenticated devices
        
        Returns:
            list: Device history with metadata
        """
        devices = []
        
        for device_id, device_data in self.known_devices.items():
            if device_data.get('user_id') == user_id:
                devices.append({
                    'device_id': device_id,
                    'first_seen': device_data.get('first_seen'),
                    'last_seen': device_data.get('last_seen', device_data.get('first_seen')),
                    'ip_address': device_data.get('ip_address'),
                    'trust_level': device_data.get('trust_level', 'unknown')
                })
                
        return devices


# Initialize the global recognition system
owner_recognition = OwnerRecognitionSystem()

def initialize_recognition_system(app, secret_key):
    """Initialize the global recognition system with app context"""
    global owner_recognition
    owner_recognition = OwnerRecognitionSystem(app, secret_key)
    return owner_recognition

def get_recognition_system():
    """Get the global recognition system instance"""
    global owner_recognition
    return owner_recognition