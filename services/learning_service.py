import logging
import time
import threading
import random
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

def start_learning_service(app, socketio=None):
    """
    Start the continuous learning service
    
    Args:
        app: Flask application context
        socketio: SocketIO instance for real-time updates
    """
    logger.info("Starting learning service")
    
    if socketio:
        socketio.emit('system_message', {'message': 'Learning service started'})
    
    try:
        from utils.learning import update_knowledge_base
        from config import LEARNING_INTERVAL, LEARNING_ENABLED
        
        # Check if learning is enabled
        if not LEARNING_ENABLED:
            logger.warning("Learning service disabled in configuration")
            if socketio:
                socketio.emit('system_message', {'message': 'Learning service is disabled in configuration'})
            return
        
        # Main learning loop
        while True:
            with app.app_context():
                try:
                    # Update the knowledge base
                    update_knowledge_base(app, socketio)
                    
                    # Analyze existing knowledge for patterns
                    analyze_existing_knowledge(app, socketio)
                    
                    # Report learning progress
                    report_learning_progress(app, socketio)
                
                except Exception as e:
                    logger.error(f"Error in learning service loop: {str(e)}")
                    
                    if socketio:
                        socketio.emit('system_message', {
                            'message': f'Learning service error: {str(e)}'
                        })
            
            # Randomize the learning interval slightly to avoid detection patterns
            sleep_time = LEARNING_INTERVAL + random.randint(-30, 30)
            sleep_time = max(60, sleep_time)  # Ensure minimum 60 seconds
            
            logger.info(f"Learning service sleeping for {sleep_time} seconds")
            
            # Sleep in small increments to be more responsive to shutdown
            for _ in range(sleep_time // 5):
                time.sleep(5)
                # Check for termination signal (future use)
    
    except Exception as e:
        logger.error(f"Learning service failed: {str(e)}")
        
        if socketio:
            socketio.emit('system_message', {
                'message': f'Learning service terminated: {str(e)}'
            })

def analyze_existing_knowledge(app, socketio=None):
    """
    Analyze existing knowledge for patterns and insights
    
    Args:
        app: Flask application context
        socketio: SocketIO instance for real-time updates
    """
    with app.app_context():
        from models import KnowledgeBase
        from app import db
        
        logger.info("Analyzing existing knowledge")
        
        try:
            # Get knowledge items for analysis
            recent_items = KnowledgeBase.query.order_by(
                KnowledgeBase.created_at.desc()
            ).limit(100).all()
            
            if not recent_items:
                logger.info("No knowledge items to analyze")
                return
            
            # Count knowledge by source type
            source_types = {}
            for item in recent_items:
                source_type = item.source_type
                source_types[source_type] = source_types.get(source_type, 0) + 1
            
            # Calculate average confidence
            avg_confidence = sum(item.confidence for item in recent_items) / len(recent_items)
            
            # Find verified vs unverified ratio
            verified_count = sum(1 for item in recent_items if item.verified)
            unverified_count = len(recent_items) - verified_count
            
            # Send analysis results
            if socketio:
                socketio.emit('system_message', {
                    'message': f'Knowledge analysis: {len(recent_items)} items analyzed, '
                               f'avg confidence: {avg_confidence:.2f}, '
                               f'verified: {verified_count}, unverified: {unverified_count}'
                })
            
            logger.info(f"Knowledge analysis complete: {len(recent_items)} items, "
                       f"avg confidence: {avg_confidence:.2f}, "
                       f"verified: {verified_count}, unverified: {unverified_count}")
        
        except Exception as e:
            logger.error(f"Error analyzing knowledge: {str(e)}")

def report_learning_progress(app, socketio=None):
    """
    Report on learning progress and status
    
    Args:
        app: Flask application context
        socketio: SocketIO instance for real-time updates
    """
    with app.app_context():
        from models import KnowledgeBase, LearningSource
        from app import db
        
        try:
            # Get counts
            total_knowledge = KnowledgeBase.query.count()
            recent_knowledge = KnowledgeBase.query.filter(
                KnowledgeBase.created_at > datetime.utcnow() - timedelta(days=1)
            ).count()
            active_sources = LearningSource.query.filter_by(status='active').count()
            
            # Report stats
            if socketio:
                socketio.emit('learning_stats', {
                    'total_knowledge': total_knowledge,
                    'recent_knowledge': recent_knowledge,
                    'active_sources': active_sources,
                    'timestamp': datetime.utcnow().isoformat()
                })
            
            logger.info(f"Learning stats: {total_knowledge} total items, "
                       f"{recent_knowledge} recent items, {active_sources} active sources")
        
        except Exception as e:
            logger.error(f"Error reporting learning progress: {str(e)}")
