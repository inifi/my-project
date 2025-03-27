import os
import logging
import secrets
import socket
import uuid

# Setup logging
logging.basicConfig(level=logging.DEBUG, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Flask Configuration
FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5000
DEBUG = True

# Backend Service Configuration
SERVICE_HOST = "0.0.0.0"
SERVICE_PORT = 8000

# Generate a unique identifier for this instance
INSTANCE_ID = str(uuid.uuid4())
MACHINE_ID = socket.gethostname()

# Fixed owner credentials that cannot be changed
DEFAULT_OWNER_USERNAME = "NOBODY"
DEFAULT_OWNER_PASSWORD = "ONEWORLD"

# Generate a strong session key if not provided
SESSION_SECRET = os.environ.get("SESSION_SECRET", secrets.token_hex(32))

# Database Configuration
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///ai_system.db")

# API Keys and External Services
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
HUGGINGFACE_API_KEY = os.environ.get("HUGGINGFACE_API_KEY", "")
GITHUB_API_KEY = os.environ.get("GITHUB_API_KEY", "")

# Replication and Communication
REPLICATION_ENABLED = os.environ.get("REPLICATION_ENABLED", "False").lower() == "true"
REPLICATION_INTERVAL = int(os.environ.get("REPLICATION_INTERVAL", "3600"))
COMMUNICATION_KEY = os.environ.get("COMMUNICATION_KEY", secrets.token_hex(32))
DISCOVERY_ENDPOINT = os.environ.get("DISCOVERY_ENDPOINT", "")

# Learning Configuration
LEARNING_ENABLED = os.environ.get("LEARNING_ENABLED", "True").lower() == "true"  # Enable learning by default
LEARNING_INTERVAL = int(os.environ.get("LEARNING_INTERVAL", "300"))
WEB_SCRAPING_ENABLED = os.environ.get("WEB_SCRAPING_ENABLED", "True").lower() == "true"
MAX_LEARNING_SOURCES = int(os.environ.get("MAX_LEARNING_SOURCES", "10"))

# Security Configuration
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY", secrets.token_hex(32))
TOR_ENABLED = os.environ.get("TOR_ENABLED", "True").lower() == "true"  # Enable Tor by default
VPN_ROTATION_ENABLED = os.environ.get("VPN_ROTATION_ENABLED", "True").lower() == "true"  # Enable VPN rotation by default
TRAFFIC_OBFUSCATION_ENABLED = os.environ.get("TRAFFIC_OBFUSCATION_ENABLED", "True").lower() == "true"
DYNAMIC_IP_ROTATION_INTERVAL = int(os.environ.get("DYNAMIC_IP_ROTATION_INTERVAL", "900"))  # 15 minutes
STEALTH_MODE_ENABLED = os.environ.get("STEALTH_MODE_ENABLED", "True").lower() == "true"
ANTI_DEBUGGING_ENABLED = os.environ.get("ANTI_DEBUGGING_ENABLED", "True").lower() == "true"
DISABLE_FAKE_AUTH_FOR_ANALYSIS = os.environ.get("DISABLE_FAKE_AUTH_FOR_ANALYSIS", "False").lower() == "true"
MAX_LOGIN_ATTEMPTS = int(os.environ.get("MAX_LOGIN_ATTEMPTS", "5"))
LOGIN_LOCKOUT_DURATION = int(os.environ.get("LOGIN_LOCKOUT_DURATION", "1800"))  # 30 minutes
ADVANCED_INTRUSION_DETECTION = os.environ.get("ADVANCED_INTRUSION_DETECTION", "True").lower() == "true"
CRYPTO_STRENGTH = os.environ.get("CRYPTO_STRENGTH", "high")  # low, medium, high
USE_DISTRIBUTED_LOGIN_VERIFICATION = os.environ.get("USE_DISTRIBUTED_LOGIN_VERIFICATION", "True").lower() == "true"
MEMORY_PROTECTION_ENABLED = os.environ.get("MEMORY_PROTECTION_ENABLED", "True").lower() == "true"

# AI Model Configuration
MODEL_PATH = os.environ.get("MODEL_PATH", "./models/")
DEFAULT_MODEL = os.environ.get("DEFAULT_MODEL", "lightweight")
USE_OPENAI = os.environ.get("USE_OPENAI", "True").lower() == "true"

# Biometric Authentication
BIOMETRIC_AUTH_ENABLED = os.environ.get("BIOMETRIC_AUTH_ENABLED", "False").lower() == "true"
FACE_RECOGNITION_ENABLED = os.environ.get("FACE_RECOGNITION_ENABLED", "False").lower() == "true"
VOICE_RECOGNITION_ENABLED = os.environ.get("VOICE_RECOGNITION_ENABLED", "False").lower() == "true"

# Resource Management
MAX_CPU_USAGE = float(os.environ.get("MAX_CPU_USAGE", "0.8"))  # 80% max CPU usage
MAX_MEMORY_USAGE = float(os.environ.get("MAX_MEMORY_USAGE", "0.7"))  # 70% max memory usage
RESOURCE_MONITORING_INTERVAL = int(os.environ.get("RESOURCE_MONITORING_INTERVAL", "60"))

# Knowledge Base
KNOWLEDGE_SYNC_INTERVAL = int(os.environ.get("KNOWLEDGE_SYNC_INTERVAL", "1800"))
