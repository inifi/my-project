import logging
import time
import random
import threading
import psutil
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

def start_security_service(app, socketio=None):
    """
    Start the security monitoring and anti-detection service
    
    Args:
        app: Flask application context
        socketio: SocketIO instance for real-time updates
    """
    logger.info("Starting security service")
    
    if socketio:
        socketio.emit('system_message', {'message': 'Security service started'})
    
    try:
        from utils.security import randomize_traffic_pattern, generate_fake_traffic, calculate_resource_usage_variance
        from models import SecurityLog
        from app import db
        from config import TRAFFIC_OBFUSCATION_ENABLED, TOR_ENABLED, VPN_ROTATION_ENABLED
        
        # Do a single security cycle instead of an infinite loop
        # This prevents the service from hanging
        with app.app_context():
            try:
                # Monitor for suspicious activity
                suspicious_activity = detect_suspicious_activity(app)
                
                if suspicious_activity:
                    logger.warning(f"Detected suspicious activity: {suspicious_activity}")
                    
                    # Log the suspicious activity
                    log_entry = SecurityLog(
                        event_type='suspicious_activity',
                        description=f"Detected suspicious activity: {suspicious_activity}",
                        severity='warning',
                        timestamp=datetime.utcnow()
                    )
                    db.session.add(log_entry)
                    db.session.commit()
                    
                    if socketio:
                        socketio.emit('system_message', {
                            'message': f'Security alert: {suspicious_activity}'
                        })
                
                # Generate fake traffic if enabled
                if TRAFFIC_OBFUSCATION_ENABLED:
                    # Determine how many fake requests to generate
                    fake_count = random.randint(1, 5)
                    
                    # This is a simulated endpoint since we don't have a real external URL
                    simulated_url = "https://example.com"
                    
                    logger.debug(f"Generating {fake_count} fake traffic requests")
                    generate_fake_traffic(simulated_url, fake_count)
                
                # Randomize resource usage to avoid detection
                cpu_variance, memory_variance = calculate_resource_usage_variance()
                randomize_resource_usage(cpu_variance, memory_variance)
                
                # Perform security audit periodically
                if random.randint(1, 10) == 1:  # 10% chance each cycle
                    perform_security_audit(app, socketio)
                
                logger.info("Security service cycle completed successfully")
                if socketio:
                    socketio.emit('system_message', {'message': 'Security service cycle completed'})
                
            except Exception as e:
                logger.error(f"Error in security service: {str(e)}")
                
                if socketio:
                    socketio.emit('system_message', {
                        'message': f'Security service error: {str(e)}'
                    })
    
    except Exception as e:
        logger.error(f"Security service failed: {str(e)}")
        
        if socketio:
            socketio.emit('system_message', {
                'message': f'Security service terminated: {str(e)}'
            })

def detect_suspicious_activity(app):
    """
    Detect potential suspicious activity targeting the system
    
    Args:
        app: Flask application context
        
    Returns:
        str or None: Description of suspicious activity if detected, None otherwise
    """
    with app.app_context():
        from models import SecurityLog
        
        # Check for rapid failed login attempts
        recent_failed_logins = SecurityLog.query.filter(
            SecurityLog.event_type == 'login_failed',
            SecurityLog.timestamp > datetime.utcnow() - timedelta(minutes=5)
        ).count()
        
        if recent_failed_logins > 5:
            return f"Multiple failed login attempts ({recent_failed_logins} in 5 minutes)"
        
        # Check for unusual access patterns
        recent_access_ips = {}
        
        recent_accesses = SecurityLog.query.filter(
            SecurityLog.event_type.in_(['login', 'access', 'query']),
            SecurityLog.timestamp > datetime.utcnow() - timedelta(hours=1)
        ).all()
        
        for log in recent_accesses:
            if log.ip_address:
                recent_access_ips[log.ip_address] = recent_access_ips.get(log.ip_address, 0) + 1
        
        # If more than 3 different IPs accessing in an hour, might be suspicious
        if len(recent_access_ips) > 3:
            return f"Unusual access pattern: {len(recent_access_ips)} different IP addresses in 1 hour"
        
        # Check system resources for unusual usage
        try:
            cpu_usage = psutil.cpu_percent(interval=0.1)
            memory_usage = psutil.virtual_memory().percent
            
            # If unusually high CPU or memory usage, might be suspicious
            if cpu_usage > 90:
                return f"Unusual CPU usage: {cpu_usage}%"
            
            if memory_usage > 90:
                return f"Unusual memory usage: {memory_usage}%"
        except:
            pass
        
        # No suspicious activity detected
        return None

def randomize_resource_usage(cpu_variance, memory_variance):
    """
    Randomize resource usage to avoid detection
    
    Args:
        cpu_variance: Percentage points of CPU usage to vary
        memory_variance: Percentage points of memory usage to vary
    """
    # This is a simplified simulation of resource usage variation
    
    # Decide whether to increase or decrease resource usage
    direction = random.choice([-1, 1])
    
    if direction > 0:
        # Increase resource usage
        try:
            # Create some CPU load
            if random.random() < 0.3:  # 30% chance
                duration = random.uniform(0.1, 0.5)
                end_time = time.time() + duration
                
                # Burn some CPU cycles
                logger.debug(f"Increasing CPU usage for {duration:.2f} seconds")
                while time.time() < end_time:
                    # Perform meaningless calculations
                    for i in range(10000):
                        x = i * i / 1.1
                
                # Allocate some memory
                if random.random() < 0.2:  # 20% chance
                    size = int(random.uniform(1, 10) * 1024 * 1024)  # 1-10 MB
                    logger.debug(f"Allocating {size/1024/1024:.2f} MB of memory")
                    data = bytearray(size)
                    time.sleep(0.5)  # Hold for half a second
                    # The memory will be released when this function returns
        except:
            pass
    else:
        # Decrease resource usage
        try:
            # Sleep to reduce CPU usage
            time.sleep(random.uniform(0.5, 2.0))
            
            # Suggest garbage collection
            if random.random() < 0.1:  # 10% chance
                import gc
                gc.collect()
        except:
            pass

def perform_security_audit(app, socketio=None):
    """
    Perform a security audit of the system
    
    Args:
        app: Flask application context
        socketio: SocketIO instance for real-time updates
    """
    with app.app_context():
        from models import SecurityLog, User, Instance
        from app import db
        
        logger.info("Performing security audit")
        
        # Check for unauthorized users
        user_count = User.query.count()
        owner_count = User.query.filter_by(is_owner=True).count()
        
        if user_count > 1:
            message = f"Security audit: Found {user_count} users, but should only have 1 owner"
            logger.warning(message)
            
            log_entry = SecurityLog(
                event_type='security_audit',
                description=message,
                severity='warning',
                timestamp=datetime.utcnow()
            )
            db.session.add(log_entry)
            
            if socketio:
                socketio.emit('system_message', {'message': message})
        
        if owner_count > 1:
            message = f"Security audit: Found {owner_count} users with owner privileges"
            logger.warning(message)
            
            log_entry = SecurityLog(
                event_type='security_audit',
                description=message,
                severity='critical',
                timestamp=datetime.utcnow()
            )
            db.session.add(log_entry)
            
            if socketio:
                socketio.emit('system_message', {'message': message})
        
        # Check for unauthorized instances
        unknown_instances = Instance.query.filter_by(status='active').filter(
            Instance.parent_instance_id.is_(None),
            Instance.instance_type != 'primary'
        ).count()
        
        if unknown_instances > 0:
            message = f"Security audit: Found {unknown_instances} active instances with unknown origin"
            logger.warning(message)
            
            log_entry = SecurityLog(
                event_type='security_audit',
                description=message,
                severity='warning',
                timestamp=datetime.utcnow()
            )
            db.session.add(log_entry)
            
            if socketio:
                socketio.emit('system_message', {'message': message})
        
        # Log successful audit
        log_entry = SecurityLog(
            event_type='security_audit',
            description="Security audit completed",
            severity='info',
            timestamp=datetime.utcnow()
        )
        db.session.add(log_entry)
        db.session.commit()
        
        logger.info("Security audit completed")
        
        if socketio:
            socketio.emit('system_message', {'message': 'Security audit completed'})
