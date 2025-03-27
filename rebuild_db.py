import os
import sys
from app import app, db, initialize_learning_data
import logging

def rebuild_database():
    """
    Rebuild the database from scratch.
    This should only be used during development.
    """
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    logger.info("Starting database rebuild...")
    
    try:
        # Check if database exists
        db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
        if os.path.exists(db_path):
            logger.info(f"Removing existing database: {db_path}")
            os.remove(db_path)
        
        with app.app_context():
            # Import all models to ensure they are registered
            from models import User, Instance, KnowledgeBase, LearningSource, SecurityLog, ModelVersion, CodeImprovement
            
            # Create all tables
            logger.info("Creating database tables...")
            db.create_all()
            
            # Create default user (owner) if not exists
            existing_owner = User.query.filter_by(username="NOBODY").first()
            if not existing_owner:
                logger.info("Creating default owner account...")
                from werkzeug.security import generate_password_hash
                
                # Fixed credentials as requested
                admin = User(
                    username="NOBODY",
                    email="owner@system.local",
                    password_hash=generate_password_hash("ONEWORLD"),
                    is_owner=True
                )
                db.session.add(admin)
            else:
                logger.info("Owner account already exists, skipping creation")
            
            # Create system instance
            logger.info("Creating primary system instance...")
            import uuid
            hostname = "primary"
            try:
                import socket
                hostname = socket.gethostname()
            except:
                pass
                
            instance = Instance(
                instance_id=str(uuid.uuid4()),
                hostname=hostname,
                instance_type="primary",
                platform="replit",
                status="active",
                endpoint_url="http://localhost:5000"
            )
            db.session.add(instance)
            
            # Commit changes
            db.session.commit()
            
            # Initialize learning data
            logger.info("Adding initial learning sources and knowledge items...")
            initialize_learning_data()
            
            logger.info("Database rebuild completed successfully!")
            
            return True
            
    except Exception as e:
        logger.error(f"Error rebuilding database: {str(e)}")
        return False

if __name__ == "__main__":
    success = rebuild_database()
    sys.exit(0 if success else 1)