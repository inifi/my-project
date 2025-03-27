import os
import logging
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from flask_socketio import SocketIO
import threading
import config
from werkzeug.security import check_password_hash, generate_password_hash


class Base(DeclarativeBase):
    pass


# Initialize Flask application and extensions
app = Flask(__name__)
app.secret_key = config.SESSION_SECRET
app.config["SQLALCHEMY_DATABASE_URI"] = config.DATABASE_URL
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Initialize SQLAlchemy with the application
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# Initialize SocketIO for real-time communication
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# Import models (after db initialization)
with app.app_context():
    from models import User, Instance, KnowledgeBase, LearningSource, SecurityLog
    db.create_all()

# Import utility modules after db is initialized
from utils.auth import verify_owner, generate_auth_token, verify_auth_token
from utils.scraper import scrape_website
from utils.learning import update_knowledge_base
from utils.replication import check_for_instances, replicate_to_new_platform
from utils.security import encrypt_data, decrypt_data, obfuscate_traffic
from utils.api_connector import query_openai_api, get_github_data

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
    """Authentication page for owner verification"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Username and password are required', 'danger')
            return render_template('auth.html')
        
        # Check if this is the first login (setup)
        with app.app_context():
            user_count = User.query.count()
            
            if user_count == 0 and username == config.DEFAULT_OWNER_USERNAME:
                # First-time setup - create the owner account
                new_owner = User(
                    username=username,
                    email=f"{username}@aiowner.local",
                    password_hash=generate_password_hash(password),
                    is_owner=True,
                    biometric_data="",  # Will be populated later if biometrics enabled
                    created_at=datetime.utcnow()
                )
                db.session.add(new_owner)
                db.session.commit()
                
                session['user_id'] = new_owner.id
                flash('Owner account created successfully!', 'success')
                return redirect(url_for('dashboard'))
            
            # Regular login
            user = User.query.filter_by(username=username).first()
            
            if user and check_password_hash(user.password_hash, password):
                if user.is_owner:
                    session['user_id'] = user.id
                    return redirect(url_for('dashboard'))
                else:
                    flash('Only the owner can access this system', 'danger')
            else:
                flash('Invalid credentials', 'danger')
                
    return render_template('auth.html')

@app.route('/dashboard')
def dashboard():
    """Main dashboard for the AI system"""
    if 'user_id' not in session:
        return redirect(url_for('auth'))
    
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
    source_type = request.form.get('type')
    
    if not url or not source_type:
        return jsonify({'success': False, 'message': 'URL and type are required'}), 400
    
    try:
        new_source = LearningSource(
            url=url,
            source_type=source_type,
            last_accessed=None,
            added_by_user_id=user.id,
            created_at=datetime.utcnow()
        )
        db.session.add(new_source)
        db.session.commit()
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
        if config.USE_OPENAI and config.OPENAI_API_KEY:
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
                    response = "I don't have specific knowledge about that query yet. I'm continuously learning and improving."
        
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
    
    if command == 'self_improve':
        # Trigger self-improvement process
        socketio.emit('system_message', {'message': 'Starting self-improvement process...'})
        # In a real implementation, this would trigger code analysis and optimization
    
    elif command == 'sync_knowledge':
        # Trigger knowledge sync with other instances
        socketio.emit('system_message', {'message': 'Synchronizing knowledge across instances...'})
        # This would communicate with other instances to share knowledge
    
    elif command == 'security_scan':
        # Run security audit
        socketio.emit('system_message', {'message': 'Running security scan...'})
        # This would check for security vulnerabilities or detection attempts

# Initialize the owner in the database if not present
def initialize_system():
    with app.app_context():
        # Check if any users exist, if not, system needs setup
        user_count = User.query.count()
        if user_count == 0:
            logger.info("No users found. System needs initial setup.")
        
        # Register this instance in the database
        existing_instance = Instance.query.filter_by(
            instance_id=config.INSTANCE_ID
        ).first()
        
        if not existing_instance:
            new_instance = Instance(
                instance_id=config.INSTANCE_ID,
                hostname=config.MACHINE_ID,
                instance_type="primary" if user_count == 0 else "secondary",
                status="active",
                created_at=datetime.utcnow(),
                last_heartbeat=datetime.utcnow()
            )
            db.session.add(new_instance)
            db.session.commit()
            logger.info(f"Registered new instance: {config.INSTANCE_ID}")

# Run initialization when the app starts
with app.app_context():
    initialize_system()
