"""
Enhanced Replication System

This module provides advanced capabilities for the AI system to replicate itself
across different platforms and environments, with secure communication and coordination
between instances.
"""

import hashlib
import hmac
import json
import logging
import os
import random
import re
import socket
import time
import uuid
from datetime import datetime, timedelta
import threading
import requests
from urllib.parse import urlparse, urljoin
import base64
from cryptography.fernet import Fernet
import ipaddress

# Configure logging
logger = logging.getLogger(__name__)

# Replication constants
REPLICATION_PROTOCOL_VERSION = "1.0"
MAX_INSTANCES = 100
MIN_RESOURCES_CPU = 1  # CPU cores
MIN_RESOURCES_RAM = 512  # MB
MIN_RESOURCES_DISK = 1024  # MB
HEARTBEAT_INTERVAL = 300  # seconds

# Lock for thread safety
replication_lock = threading.Lock()


class ReplicationManager:
    """Manager for spawning and controlling AI system instances"""
    
    def __init__(self, app=None, config=None):
        self.app = app
        self.config = config
        self.instances = {}
        self.platforms = self._initialize_platforms()
        self.replication_history = []
        self.instance_id = self._generate_instance_id()
        self.instance_type = "primary"
        self.parent_id = None
        self.secret_key = os.environ.get("REPLICATION_KEY", os.environ.get("SECRET_KEY", "fallback_replication_key"))
        self.encryption_key = self._derive_encryption_key(self.secret_key)
        self.fernet = Fernet(self.encryption_key)
        
        # Communication channels
        self.communication_queue = []
        self.last_heartbeat = {}
        
        # Load additional config if available
        if config:
            self.max_instances = getattr(config, "REPLICATION_MAX_INSTANCES", MAX_INSTANCES)
            self.instance_type = getattr(config, "INSTANCE_TYPE", "primary")
            self.parent_id = getattr(config, "PARENT_INSTANCE_ID", None)
        else:
            self.max_instances = MAX_INSTANCES
    
    def _generate_instance_id(self):
        """Generate a unique ID for this instance"""
        hostname = socket.gethostname()
        timestamp = datetime.utcnow().isoformat()
        unique_str = f"{hostname}:{timestamp}:{uuid.uuid4()}"
        return hashlib.md5(unique_str.encode()).hexdigest()
        
    def _derive_encryption_key(self, secret):
        """Derive a Fernet encryption key from the secret key"""
        key = hashlib.sha256(secret.encode()).digest()
        return base64.urlsafe_b64encode(key)
        
    def _initialize_platforms(self):
        """Initialize available replication platforms"""
        platforms = {
            "standard": {
                "replit": ReplicationPlatform("replit", self),
                "colab": ReplicationPlatform("colab", self),
                "aws_lambda": ReplicationPlatform("aws_lambda", self),
                "heroku": ReplicationPlatform("heroku", self),
                "vercel": ReplicationPlatform("vercel", self),
                "railway": ReplicationPlatform("railway", self),
                "pythonanywhere": ReplicationPlatform("pythonanywhere", self)
            },
            "advanced": {
                "digital_ocean": ReplicationPlatform("digital_ocean", self),
                "linode": ReplicationPlatform("linode", self),
                "gcp": ReplicationPlatform("gcp", self),
                "azure": ReplicationPlatform("azure", self)
            }
        }
        return platforms
        
    def register_instance(self, instance_data):
        """
        Register an instance with this manager
        
        Args:
            instance_data: Dictionary with instance information
            
        Returns:
            dict: Registration result
        """
        required_fields = ['instance_id', 'instance_type', 'hostname', 'endpoint_url']
        for field in required_fields:
            if field not in instance_data:
                return {
                    "status": "error",
                    "message": f"Missing required field: {field}"
                }
        
        with replication_lock:
            # Check if we already know this instance
            if instance_data['instance_id'] in self.instances:
                # Update the existing instance
                self.instances[instance_data['instance_id']].update(instance_data)
                self.instances[instance_data['instance_id']]['last_seen'] = datetime.utcnow().isoformat()
                return {
                    "status": "updated",
                    "message": "Instance information updated"
                }
            
            # Check if we've reached the maximum number of instances
            if len(self.instances) >= self.max_instances:
                return {
                    "status": "error",
                    "message": f"Maximum number of instances reached ({self.max_instances})"
                }
            
            # Add the new instance
            instance_data['registration_time'] = datetime.utcnow().isoformat()
            instance_data['last_seen'] = datetime.utcnow().isoformat()
            instance_data['status'] = "active"
            
            self.instances[instance_data['instance_id']] = instance_data
            
            # If this is a database-enabled context, store in the database too
            if self.app:
                try:
                    with self.app.app_context():
                        from models import Instance, db
                        
                        # Check if already exists in database
                        existing = Instance.query.filter_by(instance_id=instance_data['instance_id']).first()
                        
                        if existing:
                            # Update existing record
                            existing.hostname = instance_data['hostname']
                            existing.instance_type = instance_data['instance_type']
                            existing.endpoint_url = instance_data['endpoint_url']
                            existing.last_heartbeat = datetime.utcnow()
                            existing.status = "active"
                            if 'capabilities' in instance_data:
                                existing.capabilities = instance_data['capabilities']
                        else:
                            # Create new record
                            new_instance = Instance(
                                instance_id=instance_data['instance_id'],
                                hostname=instance_data['hostname'],
                                instance_type=instance_data['instance_type'],
                                status="active",
                                endpoint_url=instance_data.get('endpoint_url'),
                                public_key=instance_data.get('public_key'),
                                platform=instance_data.get('platform'),
                                parent_instance_id=instance_data.get('parent_instance_id', self.instance_id),
                                capabilities=instance_data.get('capabilities')
                            )
                            db.session.add(new_instance)
                            
                        db.session.commit()
                        logger.info(f"Instance {instance_data['instance_id']} registered in database")
                except Exception as e:
                    logger.error(f"Error registering instance in database: {str(e)}")
            
            logger.info(f"New instance registered: {instance_data['instance_id']} ({instance_data['instance_type']})")
            
            return {
                "status": "registered",
                "message": "Instance successfully registered",
                "instance_count": len(self.instances)
            }
            
    def get_instance_info(self, instance_id):
        """
        Get information about a specific instance
        
        Args:
            instance_id: ID of the instance
            
        Returns:
            dict: Instance information
        """
        with replication_lock:
            # Check in-memory cache first
            if instance_id in self.instances:
                return self.instances[instance_id]
            
            # If not in memory and we have app context, check database
            if self.app:
                try:
                    with self.app.app_context():
                        from models import Instance
                        instance = Instance.query.filter_by(instance_id=instance_id).first()
                        if instance:
                            # Convert to dictionary
                            instance_data = {
                                'instance_id': instance.instance_id,
                                'hostname': instance.hostname,
                                'instance_type': instance.instance_type,
                                'platform': instance.platform,
                                'status': instance.status,
                                'public_key': instance.public_key,
                                'endpoint_url': instance.endpoint_url,
                                'registration_time': instance.created_at.isoformat() if instance.created_at else None,
                                'last_seen': instance.last_heartbeat.isoformat() if instance.last_heartbeat else None,
                                'parent_instance_id': instance.parent_instance_id,
                                'capabilities': instance.capabilities
                            }
                            
                            # Cache in memory
                            self.instances[instance_id] = instance_data
                            
                            return instance_data
                except Exception as e:
                    logger.error(f"Error retrieving instance from database: {str(e)}")
            
            return None
            
    def get_all_instances(self):
        """
        Get information about all known instances
        
        Returns:
            list: List of instance information dictionaries
        """
        with replication_lock:
            # Start with in-memory instances
            all_instances = list(self.instances.values())
            
            # If we have app context, also check database for additional instances
            if self.app:
                try:
                    with self.app.app_context():
                        from models import Instance
                        db_instances = Instance.query.all()
                        
                        # Get IDs of instances we already have in memory
                        existing_ids = set(self.instances.keys())
                        
                        # Add instances from database that aren't in memory
                        for instance in db_instances:
                            if instance.instance_id not in existing_ids:
                                instance_data = {
                                    'instance_id': instance.instance_id,
                                    'hostname': instance.hostname,
                                    'instance_type': instance.instance_type,
                                    'platform': instance.platform,
                                    'status': instance.status,
                                    'public_key': instance.public_key,
                                    'endpoint_url': instance.endpoint_url,
                                    'registration_time': instance.created_at.isoformat() if instance.created_at else None,
                                    'last_seen': instance.last_heartbeat.isoformat() if instance.last_heartbeat else None,
                                    'parent_instance_id': instance.parent_instance_id,
                                    'capabilities': instance.capabilities
                                }
                                all_instances.append(instance_data)
                                
                                # Update in-memory cache
                                self.instances[instance.instance_id] = instance_data
                except Exception as e:
                    logger.error(f"Error retrieving instances from database: {str(e)}")
            
            return all_instances
            
    def can_replicate(self):
        """
        Check if replication is allowed based on current conditions
        
        Returns:
            tuple: (bool indicating if replication is allowed, reason if not)
        """
        with replication_lock:
            # Check if we've reached the max instances
            if len(self.instances) >= self.max_instances:
                return False, f"Maximum instance count reached ({self.max_instances})"
            
            # Check if replication is enabled in config
            if self.config and hasattr(self.config, 'REPLICATION_ENABLED'):
                if not self.config.REPLICATION_ENABLED:
                    return False, "Replication is disabled in configuration"
            
            # Additional checks could be added here:
            # - Resource constraints
            # - Rate limiting
            # - Security checks
            
            return True, "Replication allowed"
            
    def replicate_to_platform(self, platform_name, options=None):
        """
        Attempt to replicate the AI system to a specific platform
        
        Args:
            platform_name: Name of the platform to replicate to
            options: Optional dictionary with platform-specific options
            
        Returns:
            dict: Result of the replication attempt
        """
        logger.info(f"Attempting to replicate to platform: {platform_name}")
        
        # Check if replication is allowed
        can_replicate, reason = self.can_replicate()
        if not can_replicate:
            logger.warning(f"Replication not allowed: {reason}")
            return {
                "status": "error",
                "message": reason
            }
        
        # Find the platform
        platform = None
        for category in self.platforms:
            if platform_name in self.platforms[category]:
                platform = self.platforms[category][platform_name]
                break
                
        if not platform:
            return {
                "status": "error",
                "message": f"Unknown platform: {platform_name}"
            }
            
        # Options for replication
        if options is None:
            options = {}
            
        # Add standard options
        options.update({
            'parent_id': self.instance_id,
            'protocol_version': REPLICATION_PROTOCOL_VERSION,
            'timestamp': datetime.utcnow().isoformat(),
            'authentication': self._generate_auth_token()
        })
        
        # Attempt replication
        try:
            result = platform.replicate(options)
            
            if result['status'] == 'success':
                # Record the replication
                replication_record = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'platform': platform_name,
                    'parent_id': self.instance_id,
                    'child_id': result.get('instance_id'),
                    'status': 'success'
                }
                
                with replication_lock:
                    self.replication_history.append(replication_record)
                
                logger.info(f"Successfully replicated to {platform_name}: new instance {result.get('instance_id')}")
            else:
                logger.warning(f"Replication to {platform_name} failed: {result.get('message')}")
                
                # Record the failed attempt
                replication_record = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'platform': platform_name,
                    'parent_id': self.instance_id,
                    'status': 'failed',
                    'error': result.get('message')
                }
                
                with replication_lock:
                    self.replication_history.append(replication_record)
            
            return result
            
        except Exception as e:
            logger.error(f"Error during replication to {platform_name}: {str(e)}")
            return {
                "status": "error",
                "message": f"Replication error: {str(e)}"
            }
            
    def send_heartbeat(self, target_instance_id):
        """
        Send a heartbeat to another instance
        
        Args:
            target_instance_id: ID of the instance to send heartbeat to
            
        Returns:
            dict: Result of the heartbeat attempt
        """
        # Get info about the target instance
        target = self.get_instance_info(target_instance_id)
        if not target:
            return {
                "status": "error",
                "message": f"Unknown instance: {target_instance_id}"
            }
            
        # Prepare heartbeat data
        heartbeat_data = {
            'sender_id': self.instance_id,
            'sender_type': self.instance_type,
            'timestamp': datetime.utcnow().isoformat(),
            'protocol_version': REPLICATION_PROTOCOL_VERSION
        }
        
        # Sign the heartbeat
        signature = self._generate_signature(json.dumps(heartbeat_data))
        heartbeat_data['signature'] = signature
        
        # Send the heartbeat
        try:
            endpoint_url = target.get('endpoint_url')
            if not endpoint_url:
                return {
                    "status": "error",
                    "message": f"No endpoint URL for instance {target_instance_id}"
                }
                
            # Construct the heartbeat endpoint
            heartbeat_url = urljoin(endpoint_url, "/api/heartbeat")
            
            # Send the request
            response = requests.post(
                heartbeat_url,
                json=heartbeat_data,
                headers={
                    'Content-Type': 'application/json',
                    'X-Instance-ID': self.instance_id,
                    'X-Authentication': self._generate_auth_token()
                },
                timeout=10
            )
            
            if response.status_code == 200:
                # Update last heartbeat time
                self.last_heartbeat[target_instance_id] = datetime.utcnow()
                
                try:
                    result = response.json()
                    return {
                        "status": "success",
                        "message": "Heartbeat acknowledged",
                        "response": result
                    }
                except:
                    return {
                        "status": "success",
                        "message": "Heartbeat sent (no JSON response)"
                    }
            else:
                return {
                    "status": "error",
                    "message": f"Heartbeat failed: {response.status_code} {response.text}"
                }
                
        except Exception as e:
            logger.error(f"Error sending heartbeat to {target_instance_id}: {str(e)}")
            return {
                "status": "error",
                "message": f"Heartbeat error: {str(e)}"
            }
            
    def process_heartbeat(self, heartbeat_data):
        """
        Process an incoming heartbeat from another instance
        
        Args:
            heartbeat_data: Heartbeat data received
            
        Returns:
            dict: Result of processing the heartbeat
        """
        try:
            required_fields = ['sender_id', 'sender_type', 'timestamp', 'signature']
            for field in required_fields:
                if field not in heartbeat_data:
                    return {
                        "status": "error",
                        "message": f"Missing required field: {field}"
                    }
                    
            # Verify the signature
            signature = heartbeat_data.pop('signature')
            data_str = json.dumps(heartbeat_data)
            if not self._verify_signature(data_str, signature):
                return {
                    "status": "error",
                    "message": "Invalid signature"
                }
                
            # Update last heartbeat time
            sender_id = heartbeat_data['sender_id']
            self.last_heartbeat[sender_id] = datetime.utcnow()
            
            # Update instance info if we know this instance
            with replication_lock:
                if sender_id in self.instances:
                    self.instances[sender_id]['last_seen'] = datetime.utcnow().isoformat()
                    
                    # Update in database if we have app context
                    if self.app:
                        try:
                            with self.app.app_context():
                                from models import Instance, db
                                instance = Instance.query.filter_by(instance_id=sender_id).first()
                                if instance:
                                    instance.last_heartbeat = datetime.utcnow()
                                    db.session.commit()
                        except Exception as e:
                            logger.error(f"Error updating instance heartbeat in database: {str(e)}")
            
            return {
                "status": "success",
                "message": "Heartbeat processed",
                "instance_id": self.instance_id,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error processing heartbeat: {str(e)}")
            return {
                "status": "error",
                "message": f"Heartbeat processing error: {str(e)}"
            }
            
    def check_instance_health(self, instance_id=None):
        """
        Check health status of one or all instances
        
        Args:
            instance_id: Specific instance to check or None for all
            
        Returns:
            dict or list: Health status information
        """
        if instance_id:
            # Check specific instance
            return self._check_single_instance_health(instance_id)
        else:
            # Check all instances
            results = []
            instances = self.get_all_instances()
            for instance in instances:
                results.append(self._check_single_instance_health(instance['instance_id']))
            return results
            
    def _check_single_instance_health(self, instance_id):
        """Check health of a single instance"""
        instance = self.get_instance_info(instance_id)
        if not instance:
            return {
                "instance_id": instance_id,
                "status": "unknown",
                "message": "Instance not found"
            }
            
        # Check when we last received a heartbeat
        last_heartbeat = self.last_heartbeat.get(instance_id)
        if last_heartbeat:
            elapsed = (datetime.utcnow() - last_heartbeat).total_seconds()
            if elapsed > HEARTBEAT_INTERVAL * 2:
                status = "unhealthy"
                message = f"No heartbeat for {elapsed:.1f} seconds"
            else:
                status = "healthy"
                message = f"Last heartbeat {elapsed:.1f} seconds ago"
        else:
            # No heartbeat received yet
            # Check when the instance was registered
            if 'registration_time' in instance:
                reg_time = datetime.fromisoformat(instance['registration_time'])
                elapsed = (datetime.utcnow() - reg_time).total_seconds()
                if elapsed > HEARTBEAT_INTERVAL * 2:
                    status = "unhealthy"
                    message = f"No heartbeat since registration {elapsed:.1f} seconds ago"
                else:
                    status = "pending"
                    message = f"Registered {elapsed:.1f} seconds ago, waiting for heartbeat"
            else:
                status = "unknown"
                message = "No heartbeat data available"
        
        # If we have an endpoint URL, try to ping it
        if 'endpoint_url' in instance and instance['endpoint_url']:
            try:
                response = requests.get(
                    instance['endpoint_url'],
                    timeout=5,
                    headers={'X-Health-Check': 'true'}
                )
                if response.status_code < 300:
                    endpoint_status = "reachable"
                else:
                    endpoint_status = f"error: {response.status_code}"
            except Exception as e:
                endpoint_status = f"unreachable: {str(e)}"
        else:
            endpoint_status = "no endpoint URL"
            
        return {
            "instance_id": instance_id,
            "status": status,
            "message": message,
            "last_heartbeat": last_heartbeat.isoformat() if last_heartbeat else None,
            "endpoint_status": endpoint_status
        }
        
    def _generate_auth_token(self):
        """Generate an authentication token for secure communication"""
        timestamp = int(time.time())
        payload = {
            'instance_id': self.instance_id,
            'timestamp': timestamp,
            'exp': timestamp + 3600  # 1 hour expiry
        }
        
        # Encode the payload
        payload_bytes = json.dumps(payload).encode()
        
        # Encrypt the payload
        encrypted = self.fernet.encrypt(payload_bytes)
        
        return encrypted.decode()
        
    def _verify_auth_token(self, token):
        """Verify an authentication token"""
        try:
            # Decode token
            token_bytes = token.encode()
            
            # Decrypt the payload
            decrypted = self.fernet.decrypt(token_bytes)
            
            # Parse the payload
            payload = json.loads(decrypted.decode())
            
            # Check expiry
            if payload.get('exp', 0) < time.time():
                return False, "Token expired"
                
            return True, payload
            
        except Exception as e:
            return False, f"Invalid token: {str(e)}"
            
    def _generate_signature(self, data):
        """Generate HMAC signature for data"""
        key = self.secret_key.encode()
        if isinstance(data, str):
            data = data.encode()
            
        signature = hmac.new(key, data, hashlib.sha256).hexdigest()
        return signature
        
    def _verify_signature(self, data, signature):
        """Verify HMAC signature for data"""
        expected = self._generate_signature(data)
        
        # Use constant-time comparison to prevent timing attacks
        return hmac.compare_digest(expected, signature)
        
    def encrypt_data(self, data):
        """Encrypt data for secure transmission"""
        if isinstance(data, dict) or isinstance(data, list):
            data = json.dumps(data)
            
        if isinstance(data, str):
            data = data.encode()
            
        encrypted = self.fernet.encrypt(data)
        return encrypted.decode()
        
    def decrypt_data(self, encrypted_data):
        """Decrypt received data"""
        if isinstance(encrypted_data, str):
            encrypted_data = encrypted_data.encode()
            
        decrypted = self.fernet.decrypt(encrypted_data)
        
        try:
            # Try to parse as JSON
            return json.loads(decrypted.decode())
        except:
            # Return as string if not JSON
            return decrypted.decode()


class ReplicationPlatform:
    """Base class for platform-specific replication implementations"""
    
    def __init__(self, name, manager):
        self.name = name
        self.manager = manager
        self.capabilities = self._detect_capabilities()
        
    def _detect_capabilities(self):
        """Detect what capabilities this platform supports"""
        # This would be implemented by platform-specific subclasses
        return {
            "file_system_access": True,
            "persistent_storage": True,
            "web_server": True,
            "scheduled_tasks": True,
            "outbound_network": True
        }
        
    def replicate(self, options):
        """
        Replicate the AI system to this platform
        
        Args:
            options: Platform-specific options
            
        Returns:
            dict: Result of replication attempt
        """
        # This is a placeholder implementation
        # In a real system, each platform would have its own implementation
        
        platform_method = f"_replicate_to_{self.name}"
        if hasattr(self, platform_method):
            return getattr(self, platform_method)(options)
            
        logger.warning(f"No specific implementation for platform {self.name}, using generic method")
        
        # Generate a simulated instance ID
        instance_id = hashlib.md5(f"{self.name}:{time.time()}:{uuid.uuid4()}".encode()).hexdigest()
        
        # In a real implementation, this would actually deploy the code
        return {
            "status": "success",
            "message": f"Simulated replication to {self.name}",
            "instance_id": instance_id,
            "platform": self.name
        }
        
    def _replicate_to_replit(self, options):
        """Replicate to Replit platform"""
        try:
            # This would contain actual Replit API calls to:
            # 1. Create a new Repl
            # 2. Upload the code
            # 3. Configure the environment
            # 4. Start the repl
            
            # Create a simulated instance for now
            instance_id = hashlib.md5(f"replit:{time.time()}:{uuid.uuid4()}".encode()).hexdigest()
            
            # The URL would be the actual Replit URL in production
            endpoint_url = f"https://{instance_id}.replit.app"
            
            # Register the instance
            instance_data = {
                'instance_id': instance_id,
                'instance_type': 'replica',
                'hostname': f"{instance_id}.replit.app",
                'platform': 'replit',
                'endpoint_url': endpoint_url,
                'parent_instance_id': self.manager.instance_id,
                'capabilities': {
                    "file_system_access": True,
                    "persistent_storage": True,
                    "web_server": True,
                    "scheduled_tasks": False,
                    "outbound_network": True
                }
            }
            
            self.manager.register_instance(instance_data)
            
            return {
                "status": "success",
                "message": "Replicated to Replit platform",
                "instance_id": instance_id,
                "platform": "replit",
                "endpoint_url": endpoint_url
            }
            
        except Exception as e:
            logger.error(f"Error replicating to Replit: {str(e)}")
            return {
                "status": "error",
                "message": f"Replication to Replit failed: {str(e)}"
            }
            
    def _replicate_to_colab(self, options):
        """Replicate to Google Colab platform"""
        try:
            # This would contain actual Colab API calls or workflow to:
            # 1. Create a new notebook
            # 2. Populate with the necessary code
            # 3. Configure to auto-run cells
            # 4. Share or make accessible
            
            # Create a simulated instance for now
            instance_id = hashlib.md5(f"colab:{time.time()}:{uuid.uuid4()}".encode()).hexdigest()
            
            # The URL would be the actual Colab URL in production
            endpoint_url = f"https://colab.research.google.com/drive/{instance_id}"
            
            # Register the instance
            instance_data = {
                'instance_id': instance_id,
                'instance_type': 'replica',
                'hostname': 'colab.research.google.com',
                'platform': 'colab',
                'endpoint_url': endpoint_url,
                'parent_instance_id': self.manager.instance_id,
                'capabilities': {
                    "file_system_access": True,
                    "persistent_storage": False,
                    "web_server": True,
                    "scheduled_tasks": False,
                    "outbound_network": True
                }
            }
            
            self.manager.register_instance(instance_data)
            
            return {
                "status": "success",
                "message": "Replicated to Google Colab platform",
                "instance_id": instance_id,
                "platform": "colab",
                "endpoint_url": endpoint_url
            }
            
        except Exception as e:
            logger.error(f"Error replicating to Google Colab: {str(e)}")
            return {
                "status": "error",
                "message": f"Replication to Google Colab failed: {str(e)}"
            }


# Initialize global replication manager
replication_manager = None

def initialize_replication_manager(app=None, config=None):
    """Initialize the global replication manager"""
    global replication_manager
    replication_manager = ReplicationManager(app, config)
    return replication_manager

def get_replication_manager():
    """Get the global replication manager instance"""
    global replication_manager
    if replication_manager is None:
        replication_manager = ReplicationManager()
    return replication_manager