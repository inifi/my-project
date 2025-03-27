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
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="gevent", ping_timeout=120, ping_interval=25)

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
    # Use the fixed credentials from config
    FIXED_USERNAME = config.DEFAULT_OWNER_USERNAME
    FIXED_PASSWORD = config.DEFAULT_OWNER_PASSWORD
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Username and password are required', 'danger')
            return render_template('auth.html')
        
        # Check if this is the first login (setup)
        with app.app_context():
            user_count = User.query.count()
            
            if user_count == 0:
                # First-time setup - create the owner account with fixed credentials
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
            
            # Always verify against fixed credentials, regardless of what's in database
            if username == FIXED_USERNAME and password == FIXED_PASSWORD:
                # Find the owner user
                owner = User.query.filter_by(is_owner=True).first()
                if owner:
                    session['user_id'] = owner.id
                    return redirect(url_for('dashboard'))
                else:
                    flash('System error: Owner account not found', 'danger')
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
        # Check if any users exist, if not, create the owner with fixed credentials
        user_count = User.query.count()
        if user_count == 0:
            logger.info("No users found. Creating owner account with fixed credentials.")
            
            # Create the owner with the fixed credentials: NOBODY/ONEWORLD
            owner = User(
                username="NOBODY",
                email="owner@example.com",  # Placeholder email
                password_hash=generate_password_hash("ONEWORLD"),
                is_owner=True,
                created_at=datetime.utcnow()
            )
            db.session.add(owner)
            db.session.commit()
            logger.info("Owner account created with fixed credentials.")
        
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
    
    # Add a default learning source for demonstration
    if LearningSource.query.count() == 0:
        # Find the owner user
        owner = User.query.filter_by(is_owner=True).first()
        if owner:
            # Add a few starter learning sources
            starter_sources = [
                {"url": "https://en.wikipedia.org/wiki/Artificial_intelligence", "source_type": "website"},
                {"url": "https://en.wikipedia.org/wiki/Machine_learning", "source_type": "website"},
                {"url": "https://news.ycombinator.com/rss", "source_type": "rss"}
            ]
            
            for source in starter_sources:
                new_source = LearningSource(
                    url=source["url"],
                    source_type=source["source_type"],
                    schedule="daily",
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
