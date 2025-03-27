import os
import logging
import threading
import time
from app import app, socketio
import config
from utils.enhanced_security import initialize_enhanced_security

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
        
        # Start decentralized network if available
        try:
            from utils.decentralized_network import start_network, find_master_node, get_web_endpoint
            
            logger.info("Starting decentralized network...")
            start_network()
            
            # Find master node
            master_info = find_master_node()
            if master_info:
                logger.info(f"Found master node: {master_info.get('node_id', 'unknown')}")
                
                # Get web endpoint for browser interaction
                web_endpoint = get_web_endpoint()
                if web_endpoint:
                    logger.info(f"Web interface available at: {web_endpoint}")
            else:
                logger.warning("No master node found, operating in standalone mode")
        except ImportError:
            logger.info("Decentralized network module not available")
        except Exception as e:
            logger.error(f"Error starting decentralized network: {str(e)}")
        
        # Start auto-improvement system if available
        try:
            from utils.auto_improvement import start_auto_improvement
            
            logger.info("Starting automatic improvement system...")
            start_auto_improvement()
            logger.info("Automatic improvement system is now actively searching for resources to improve")
        except ImportError:
            logger.info("Automatic improvement module not available")
        except Exception as e:
            logger.error(f"Error starting automatic improvement system: {str(e)}")
        
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
    logger.info(f"Host: {config.WEB_HOST}, Port: {config.WEB_PORT}")
    
    # Initialize enhanced security features
    try:
        logger.info("Initializing enhanced security features...")
        security_features = initialize_enhanced_security()
        logger.info(f"Enhanced security enabled with features: {security_features}")
    except Exception as e:
        logger.error(f"Error initializing enhanced security: {str(e)}")
    
    # Register additional API routes
    try:
        from app_routes import register_routes
        from app import db
        register_routes(app, db)
        logger.info("Additional API routes registered successfully")
    except Exception as e:
        logger.error(f"Error registering additional routes: {str(e)}")
    
    # Start background services in a separate thread
    services_thread = threading.Thread(target=start_services, daemon=True)
    services_thread.start()
    
    # Start the Flask application (standard mode for Replit compatibility)
    # In production with Replit, gunicorn will handle this
    app.run(
        host=config.WEB_HOST, 
        port=config.WEB_PORT, 
        debug=config.DEBUG
    )
