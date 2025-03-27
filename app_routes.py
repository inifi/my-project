"""
Additional API routes for the AI system

This file contains extended API routes for the system, particularly focusing on:
- Keepalive endpoints for session management
- Status checking endpoints
- Real-time update routes
- Session persistence and auto-refresh support
"""

from flask import jsonify, request, session
from datetime import datetime, timedelta
import jwt
import logging
import time
import json

# Configure logging
logger = logging.getLogger(__name__)

def register_routes(app, db):
    """Register the API routes with the Flask app"""
    
    @app.route('/api/keepalive', methods=['POST'])
    def keepalive():
        """Keep the user session alive"""
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'No active session'}), 401
            
        # Get the request data
        data = request.get_json() or {}
        timestamp = data.get('timestamp')
        
        # Verify the fingerprint for additional security
        request_fingerprint = request.headers.get('X-Fingerprint')
        session_fingerprint = session.get('fingerprint')
        
        if session_fingerprint and request_fingerprint and session_fingerprint != request_fingerprint:
            logger.warning(f"Fingerprint mismatch in keepalive request: {request.remote_addr}")
            return jsonify({'success': False, 'message': 'Invalid session (fingerprint mismatch)'}), 401
        
        # Update the session expiry
        session.permanent = True
        app.permanent_session_lifetime = timedelta(hours=24)
        
        # Touch the session to reset expiry time
        session['last_activity'] = datetime.utcnow().isoformat()
        
        # Generate a fresh auth token if needed
        auth_token = None
        if 'auth_token' in session and 'auth_expiry' in session:
            # Check if token is close to expiring (within 5 minutes)
            expiry = datetime.fromisoformat(session['auth_expiry'])
            if expiry - datetime.utcnow() < timedelta(minutes=5):
                # Token is about to expire, generate a new one
                auth_token = generate_auth_token(session['user_id'])
                session['auth_token'] = auth_token
                session['auth_expiry'] = (datetime.utcnow() + timedelta(hours=1)).isoformat()
        
        # Log the keepalive for audit
        logger.debug(f"Keepalive from user {session['user_id']} at {datetime.utcnow()}")
        
        return jsonify({
            'success': True,
            'session_active': True,
            'token': auth_token,
            'message': 'Session refreshed'
        })
    
    @app.route('/api/status', methods=['GET'])
    def system_status():
        """Get the current system status"""
        from app import active_threads
        
        # Check if user is authenticated for detailed status
        if 'user_id' in session:
            # Get the instance count
            from models import Instance
            instance_count = Instance.query.count()
            
            # Get the knowledge item count
            from models import KnowledgeBase
            knowledge_count = KnowledgeBase.query.count()
            
            # Get active services status
            services_status = {
                'learning': active_threads['learning'] is not None and active_threads['learning'].is_alive(),
                'replication': active_threads['replication'] is not None and active_threads['replication'].is_alive(),
                'security': active_threads['security'] is not None and active_threads['security'].is_alive()
            }
            
            # Memory usage and system load information
            import psutil
            memory = psutil.virtual_memory()
            memory_usage = {
                'total': memory.total,
                'available': memory.available,
                'percent': memory.percent
            }
            
            cpu_usage = psutil.cpu_percent(interval=0.1)
            
            return jsonify({
                'status': 'operational',
                'authenticated': True,
                'instance_count': instance_count,
                'knowledge_count': knowledge_count,
                'services': services_status,
                'system': {
                    'memory': memory_usage,
                    'cpu': cpu_usage
                },
                'timestamp': datetime.utcnow().isoformat()
            })
        else:
            # Limited status for unauthenticated users
            return jsonify({
                'status': 'operational',
                'authenticated': False,
                'timestamp': datetime.utcnow().isoformat()
            })
    
    @app.route('/api/updates', methods=['GET'])
    def get_updates():
        """Get real-time updates for the system"""
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401
            
        # Get the timestamp from the request to filter updates
        since = request.args.get('since', None)
        if since:
            try:
                since_dt = datetime.fromisoformat(since)
            except ValueError:
                since_dt = datetime.utcnow() - timedelta(hours=1)  # Default to 1 hour ago
        else:
            since_dt = datetime.utcnow() - timedelta(hours=1)  # Default to 1 hour ago
            
        # Get recent security logs
        from models import SecurityLog
        security_logs = SecurityLog.query.filter(
            SecurityLog.timestamp > since_dt
        ).order_by(SecurityLog.timestamp.desc()).limit(10).all()
        
        # Get recent knowledge updates
        from models import KnowledgeBase
        knowledge_updates = KnowledgeBase.query.filter(
            KnowledgeBase.created_at > since_dt
        ).order_by(KnowledgeBase.created_at.desc()).limit(10).all()
        
        # Prepare the response data
        security_events = [{
            'id': log.id,
            'event_type': log.event_type,
            'description': log.description,
            'severity': log.severity,
            'timestamp': log.timestamp.isoformat()
        } for log in security_logs]
        
        knowledge_items = [{
            'id': item.id,
            'content_summary': item.content[:100] + '...' if len(item.content) > 100 else item.content,
            'source_type': item.source_type,
            'verified': item.verified,
            'timestamp': item.created_at.isoformat()
        } for item in knowledge_updates]
        
        return jsonify({
            'success': True,
            'security_events': security_events,
            'knowledge_updates': knowledge_items,
            'timestamp': datetime.utcnow().isoformat()
        })
            
    @app.route('/api/activity', methods=['POST'])
    def log_activity():
        """Log user activity to keep session alive and track usage patterns"""
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'No active session'}), 401
            
        # Get the activity data
        data = request.get_json() or {}
        activity_type = data.get('type', 'page_view')
        page = data.get('page', request.headers.get('Referer', 'unknown'))
        
        # Update the session last activity
        session['last_activity'] = datetime.utcnow().isoformat()
        
        # In a production system, we'd store this in a database
        logger.debug(f"User {session['user_id']} activity: {activity_type} on {page}")
        
        return jsonify({
            'success': True,
            'message': 'Activity logged'
        })

def generate_auth_token(user_id):
    """Generate a JWT auth token for the user"""
    import config
    
    now = datetime.utcnow()
    payload = {
        'sub': str(user_id),
        'iat': now,
        'exp': now + timedelta(hours=1),
        'jti': str(int(time.time() * 1000))
    }
    
    # Sign with the app's secret key
    token = jwt.encode(payload, config.SECRET_KEY, algorithm='HS256')
    
    return token

def verify_auth_token(token):
    """Verify a JWT auth token"""
    import config
    
    try:
        payload = jwt.decode(token, config.SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None