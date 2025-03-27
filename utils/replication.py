import logging
import requests
import json
import uuid
import os
import base64
import time
import random
from datetime import datetime, timedelta
import socket
import shutil
import hashlib
import importlib
import sys
import inspect

from utils.security import encrypt_data, decrypt_data, obfuscate_traffic

logger = logging.getLogger(__name__)

def check_for_instances(app):
    """
    Check for other instances of the AI system
    
    Args:
        app: Flask application context
    
    Returns:
        list: Available instances
    """
    with app.app_context():
        from models import Instance
        from config import INSTANCE_ID, DISCOVERY_ENDPOINT, COMMUNICATION_KEY
        
        logger.info("Checking for other system instances")
        
        # Get all known instances from database
        instances = Instance.query.filter(
            Instance.instance_id != INSTANCE_ID,
            Instance.status == 'active'
        ).all()
        
        active_instances = []
        
        # Check connectivity with each instance
        for instance in instances:
            if instance.endpoint_url:
                try:
                    # Ping the instance with authentication
                    headers = {
                        'Authorization': f'Bearer {COMMUNICATION_KEY}',
                        'X-Sender-ID': INSTANCE_ID
                    }
                    
                    # Obfuscate the request
                    ping_data = {
                        'action': 'ping',
                        'timestamp': datetime.utcnow().isoformat(),
                        'sender': INSTANCE_ID
                    }
                    
                    # Encrypt and encode the payload
                    encrypted_data = encrypt_data(json.dumps(ping_data), COMMUNICATION_KEY)
                    encoded_data = base64.b64encode(encrypted_data).decode('utf-8')
                    
                    # Send the request
                    response = requests.post(
                        f"{instance.endpoint_url}/api/system/ping",
                        headers=headers,
                        json={'data': encoded_data},
                        timeout=5
                    )
                    
                    if response.status_code == 200:
                        # Instance is active
                        active_instances.append(instance)
                        logger.info(f"Instance {instance.instance_id} is active")
                        
                        # Update last heartbeat
                        instance.last_heartbeat = datetime.utcnow()
                        instance.status = 'active'
                    else:
                        logger.warning(f"Instance {instance.instance_id} returned code {response.status_code}")
                        
                        # Mark as inactive if not reached for over a day
                        if instance.last_heartbeat and (datetime.utcnow() - instance.last_heartbeat > timedelta(days=1)):
                            instance.status = 'inactive'
                
                except Exception as e:
                    logger.error(f"Error connecting to instance {instance.instance_id}: {str(e)}")
                    
                    # Mark as inactive if not reached for over a day
                    if instance.last_heartbeat and (datetime.utcnow() - instance.last_heartbeat > timedelta(days=1)):
                        instance.status = 'inactive'
        
        # Try to discover new instances if discovery endpoint is configured
        if DISCOVERY_ENDPOINT:
            try:
                logger.info(f"Checking discovery endpoint: {DISCOVERY_ENDPOINT}")
                
                # Create authentication headers
                headers = {
                    'Authorization': f'Bearer {COMMUNICATION_KEY}',
                    'X-Sender-ID': INSTANCE_ID
                }
                
                # Send discovery request
                response = requests.get(
                    DISCOVERY_ENDPOINT,
                    headers=headers,
                    timeout=10
                )
                
                if response.status_code == 200:
                    # Process discovered instances
                    discovered = response.json().get('instances', [])
                    
                    for instance_data in discovered:
                        instance_id = instance_data.get('instance_id')
                        
                        if instance_id and instance_id != INSTANCE_ID:
                            # Check if instance is already known
                            existing = Instance.query.filter_by(instance_id=instance_id).first()
                            
                            if not existing:
                                # Add new instance
                                new_instance = Instance(
                                    instance_id=instance_id,
                                    hostname=instance_data.get('hostname', 'unknown'),
                                    instance_type=instance_data.get('instance_type', 'discovered'),
                                    platform=instance_data.get('platform', 'unknown'),
                                    status='active',
                                    endpoint_url=instance_data.get('endpoint_url'),
                                    public_key=instance_data.get('public_key'),
                                    created_at=datetime.utcnow(),
                                    last_heartbeat=datetime.utcnow()
                                )
                                
                                from app import db
                                db.session.add(new_instance)
                                logger.info(f"Discovered new instance: {instance_id}")
                                
                                # Add to active instances
                                active_instances.append(new_instance)
            
            except Exception as e:
                logger.error(f"Error during instance discovery: {str(e)}")
        
        # Commit all changes
        from app import db
        db.session.commit()
        
        return active_instances

def replicate_to_new_platform(app, platform_type='colab'):
    """
    Replicate the AI system to a new platform
    
    Args:
        app: Flask application context
        platform_type: Type of platform to replicate to
        
    Returns:
        bool: Success status
    """
    with app.app_context():
        from models import Instance, SecurityLog
        from app import db
        from config import INSTANCE_ID
        
        logger.info(f"Attempting to replicate to new platform: {platform_type}")
        
        # Log the replication attempt
        log_entry = SecurityLog(
            event_type='replication_attempt',
            description=f"Attempting to replicate to {platform_type}",
            severity='info',
            timestamp=datetime.utcnow()
        )
        db.session.add(log_entry)
        db.session.commit()
        
        # Generate new instance ID
        new_instance_id = str(uuid.uuid4())
        
        try:
            # Prepare replication payload
            current_files = get_current_codebase()
            system_config = get_system_config()
            
            # Combine into a replication package
            replication_package = {
                'instance_id': new_instance_id,
                'parent_instance_id': INSTANCE_ID,
                'files': current_files,
                'config': system_config,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # The replication method depends on the platform
            if platform_type == 'colab':
                success = replicate_to_colab(replication_package)
            else:
                logger.error(f"Unsupported platform type: {platform_type}")
                return False
            
            if success:
                # Register the new instance
                new_instance = Instance(
                    instance_id=new_instance_id,
                    hostname=f"replica-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                    instance_type='replica',
                    platform=platform_type,
                    status='initializing',
                    created_at=datetime.utcnow(),
                    parent_instance_id=INSTANCE_ID
                )
                
                db.session.add(new_instance)
                
                # Log success
                log_entry = SecurityLog(
                    event_type='replication_success',
                    description=f"Successfully replicated to {platform_type} with ID {new_instance_id}",
                    severity='info',
                    timestamp=datetime.utcnow()
                )
                db.session.add(log_entry)
                db.session.commit()
                
                logger.info(f"Replication successful: {new_instance_id}")
                return True
            else:
                # Log failure
                log_entry = SecurityLog(
                    event_type='replication_failure',
                    description=f"Failed to replicate to {platform_type}",
                    severity='warning',
                    timestamp=datetime.utcnow()
                )
                db.session.add(log_entry)
                db.session.commit()
                
                logger.error(f"Replication failed")
                return False
        
        except Exception as e:
            logger.error(f"Error during replication: {str(e)}")
            
            # Log the error
            log_entry = SecurityLog(
                event_type='replication_error',
                description=f"Error replicating to {platform_type}: {str(e)}",
                severity='error',
                timestamp=datetime.utcnow()
            )
            db.session.add(log_entry)
            db.session.commit()
            
            return False

def get_current_codebase():
    """
    Get a dictionary of all current code files
    
    Returns:
        dict: Dictionary of file paths and contents
    """
    files = {}
    
    # Get directory of current file
    current_dir = os.path.dirname(os.path.abspath(__file__))
    # Go up one level to project root
    project_root = os.path.dirname(current_dir)
    
    # Walk the directory and collect Python files
    for root, dirs, filenames in os.walk(project_root):
        # Skip __pycache__ directories
        if '__pycache__' in root:
            continue
        
        for filename in filenames:
            # Only collect Python files, HTML, CSS, JS
            if filename.endswith(('.py', '.html', '.css', '.js')):
                file_path = os.path.join(root, filename)
                relative_path = os.path.relpath(file_path, project_root)
                
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        
                        # Add to files dictionary
                        files[relative_path] = content
                except Exception as e:
                    logger.error(f"Error reading file {file_path}: {str(e)}")
    
    return files

def get_system_config():
    """
    Get the current system configuration
    
    Returns:
        dict: System configuration
    """
    import config
    
    # Get all uppercase variables from config module (these are the settings)
    config_vars = {key: value for key, value in vars(config).items() 
                  if key.isupper() and not key.startswith('_')}
    
    # Convert to a serializable dictionary
    # Remove any sensitive information like keys and passwords
    sensitive_keys = ['API_KEY', 'SECRET', 'PASSWORD', 'KEY', 'TOKEN']
    
    for key in list(config_vars.keys()):
        # Check if any sensitive key is part of this config key
        if any(sensitive in key for sensitive in sensitive_keys):
            # Replace with a placeholder or remove
            config_vars[key] = "[REDACTED]"
    
    return config_vars

def replicate_to_colab(replication_package):
    """
    Replicate the system to Google Colab
    
    Args:
        replication_package: Replication package with files and config
        
    Returns:
        bool: Success status
    """
    # In a real implementation, this would:
    # 1. Create a new Colab notebook or use a template
    # 2. Push the code to GitHub or another accessible location
    # 3. Configure the notebook to clone/download the code
    # 4. Start the new instance
    
    # For this implementation, we'll simulate the process
    logger.info("Simulating replication to Google Colab")
    
    # Ensure we have a colab_launcher.ipynb
    if 'colab_launcher.ipynb' not in replication_package['files']:
        logger.error("No Colab launcher notebook found in code base")
        return False
    
    # In a real implementation, we would use the Google Drive API
    # or GitHub API to create a new notebook with our code
    
    # Simulate a delay for the replication process
    time.sleep(2)
    
    # Return success
    return True

def sync_knowledge_with_instance(app, instance):
    """
    Synchronize knowledge with another instance
    
    Args:
        app: Flask application context
        instance: Instance to sync with
        
    Returns:
        bool: Success status
    """
    with app.app_context():
        from models import KnowledgeBase, SecurityLog
        from app import db
        from config import INSTANCE_ID, COMMUNICATION_KEY
        
        logger.info(f"Synchronizing knowledge with instance {instance.instance_id}")
        
        if not instance.endpoint_url:
            logger.error(f"No endpoint URL for instance {instance.instance_id}")
            return False
        
        try:
            # Get our most recent knowledge timestamp
            latest_knowledge = KnowledgeBase.query.order_by(
                KnowledgeBase.updated_at.desc()
            ).first()
            
            latest_timestamp = latest_knowledge.updated_at if latest_knowledge else datetime.min
            
            # Request new knowledge from the other instance
            headers = {
                'Authorization': f'Bearer {COMMUNICATION_KEY}',
                'X-Sender-ID': INSTANCE_ID
            }
            
            # Create sync request data
            sync_data = {
                'action': 'knowledge_sync',
                'last_sync': latest_timestamp.isoformat(),
                'sender': INSTANCE_ID
            }
            
            # Encrypt and encode the payload
            encrypted_data = encrypt_data(json.dumps(sync_data), COMMUNICATION_KEY)
            encoded_data = base64.b64encode(encrypted_data).decode('utf-8')
            
            # Send the request
            response = requests.post(
                f"{instance.endpoint_url}/api/system/sync_knowledge",
                headers=headers,
                json={'data': encoded_data},
                timeout=30
            )
            
            if response.status_code == 200:
                # Process the response
                try:
                    response_data = response.json()
                    
                    if 'data' in response_data:
                        # Decode and decrypt the response
                        decoded_data = base64.b64decode(response_data['data'])
                        decrypted_data = decrypt_data(decoded_data, COMMUNICATION_KEY)
                        
                        knowledge_data = json.loads(decrypted_data)
                        
                        # Process new knowledge items
                        new_items = knowledge_data.get('knowledge_items', [])
                        
                        for item in new_items:
                            # Check if we already have this knowledge
                            existing = KnowledgeBase.query.filter_by(
                                source_url=item['source_url'],
                                content=item['content']
                            ).first()
                            
                            if not existing:
                                # Add new knowledge
                                new_knowledge = KnowledgeBase(
                                    content=item['content'],
                                    source_url=item['source_url'],
                                    source_type=item['source_type'],
                                    confidence=item['confidence'],
                                    verified=item['verified'],
                                    created_at=datetime.fromisoformat(item['created_at']),
                                    updated_at=datetime.utcnow(),
                                    instance_id=instance.instance_id  # Track where this came from
                                )
                                
                                db.session.add(new_knowledge)
                        
                        # Commit all changes
                        db.session.commit()
                        
                        logger.info(f"Synced {len(new_items)} knowledge items from {instance.instance_id}")
                        
                        # Log the sync
                        log_entry = SecurityLog(
                            event_type='knowledge_sync',
                            description=f"Synchronized {len(new_items)} knowledge items from {instance.instance_id}",
                            severity='info',
                            timestamp=datetime.utcnow()
                        )
                        db.session.add(log_entry)
                        db.session.commit()
                        
                        return True
                    else:
                        logger.warning(f"Invalid response format from {instance.instance_id}")
                        return False
                
                except Exception as e:
                    logger.error(f"Error processing knowledge sync response: {str(e)}")
                    return False
            else:
                logger.warning(f"Knowledge sync request failed with code {response.status_code}")
                return False
        
        except Exception as e:
            logger.error(f"Error during knowledge sync: {str(e)}")
            return False
