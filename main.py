import os
import logging
import threading
import time
from app import app, socketio
import config

# Setup logging
logging.basicConfig(level=logging.DEBUG, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def start_services():
    """
    Start the background services after a delay
    """
    logger.info("Waiting to start background services...")
    time.sleep(10)  # Give the web server time to start
    
    try:
        # Import service modules
        from services.learning_service import start_learning_service
        from services.replication_service import start_replication_service
        from services.security_service import start_security_service
        
        # Start learning service if enabled
        if config.LEARNING_ENABLED:
            logger.info("Starting learning service thread")
            learning_thread = threading.Thread(
                target=start_learning_service,
                args=(app, socketio),
                daemon=True
            )
            learning_thread.start()
        
        # Start replication service if enabled
        if config.REPLICATION_ENABLED:
            logger.info("Starting replication service thread")
            replication_thread = threading.Thread(
                target=start_replication_service,
                args=(app, socketio),
                daemon=True
            )
            replication_thread.start()
        
        # Always start security service
        logger.info("Starting security service thread")
        security_thread = threading.Thread(
            target=start_security_service,
            args=(app, socketio),
            daemon=True
        )
        security_thread.start()
        
        logger.info("All background services started")
    
    except Exception as e:
        logger.error(f"Error starting background services: {str(e)}")

if __name__ == "__main__":
    # Log startup information
    logger.info(f"Starting AI system with instance ID: {config.INSTANCE_ID}")
    logger.info(f"Host: {config.FLASK_HOST}, Port: {config.FLASK_PORT}")
    
    # Start background services in a separate thread
    services_thread = threading.Thread(target=start_services, daemon=True)
    services_thread.start()
    
    # Start the Flask application with SocketIO
    socketio.run(
        app, 
        host=config.FLASK_HOST, 
        port=config.FLASK_PORT, 
        debug=config.DEBUG,
        allow_unsafe_werkzeug=True  # For development only
    )
