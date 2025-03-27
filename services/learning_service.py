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
        
        # Do a single learning cycle instead of an infinite loop
        # This prevents the service from hanging
        with app.app_context():
            try:
                from models import LearningSource, db
                
                # Check for existing learning sources
                sources_count = LearningSource.query.count()
                
                # If no sources exist, add some default ones
                if sources_count == 0:
                    logger.info("No learning sources found, adding defaults")
                    
                    # Vastly expanded learning sources for significantly accelerated knowledge acquisition
                    default_sources = [
                        # Core AI Knowledge - Foundation
                        {
                            'url': 'https://en.wikipedia.org/wiki/Artificial_intelligence',
                            'source_type': 'website',
                            'schedule': 'hourly',
                            'priority': 'high'
                        },
                        {
                            'url': 'https://en.wikipedia.org/wiki/Machine_learning',
                            'source_type': 'website',
                            'schedule': 'hourly',
                            'priority': 'high'
                        },
                        {
                            'url': 'https://en.wikipedia.org/wiki/Natural_language_processing',
                            'source_type': 'website',
                            'schedule': 'hourly',
                            'priority': 'high'
                        },
                        {
                            'url': 'https://en.wikipedia.org/wiki/Deep_learning',
                            'source_type': 'website',
                            'schedule': 'hourly',
                            'priority': 'high'
                        },
                        {
                            'url': 'https://en.wikipedia.org/wiki/Reinforcement_learning',
                            'source_type': 'website',
                            'schedule': 'hourly',
                            'priority': 'high'
                        },
                        
                        # Advanced AI Techniques
                        {
                            'url': 'https://en.wikipedia.org/wiki/Computer_vision',
                            'source_type': 'website',
                            'schedule': 'hourly'
                        },
                        {
                            'url': 'https://en.wikipedia.org/wiki/Speech_recognition',
                            'source_type': 'website',
                            'schedule': 'hourly'
                        },
                        {
                            'url': 'https://en.wikipedia.org/wiki/Transformer_(machine_learning_model)',
                            'source_type': 'website',
                            'schedule': 'hourly',
                            'priority': 'high'
                        },
                        {
                            'url': 'https://en.wikipedia.org/wiki/Attention_(machine_learning)',
                            'source_type': 'website',
                            'schedule': 'hourly',
                            'priority': 'high' 
                        },
                        {
                            'url': 'https://en.wikipedia.org/wiki/Generative_adversarial_network',
                            'source_type': 'website',
                            'schedule': 'hourly'
                        },
                        {
                            'url': 'https://en.wikipedia.org/wiki/Diffusion_model',
                            'source_type': 'website',
                            'schedule': 'hourly',
                            'priority': 'high'
                        },
                        
                        # Latest AI Research News & Publication Outlets
                        {
                            'url': 'https://news.mit.edu/topic/artificial-intelligence2',
                            'source_type': 'website',
                            'schedule': 'hourly',
                            'priority': 'high'
                        },
                        {
                            'url': 'https://techcrunch.com/category/artificial-intelligence/',
                            'source_type': 'website',
                            'schedule': 'hourly'
                        },
                        {
                            'url': 'https://www.technologyreview.com/topic/artificial-intelligence/',
                            'source_type': 'website',
                            'schedule': 'hourly',
                            'priority': 'high'
                        },
                        {
                            'url': 'https://arxiv.org/list/cs.AI/recent',
                            'source_type': 'research',
                            'schedule': 'hourly',
                            'priority': 'highest'
                        },
                        {
                            'url': 'https://arxiv.org/list/cs.CL/recent',
                            'source_type': 'research',
                            'schedule': 'hourly',
                            'priority': 'highest'
                        },
                        {
                            'url': 'https://arxiv.org/list/cs.CV/recent',
                            'source_type': 'research',
                            'schedule': 'hourly',
                            'priority': 'highest'
                        },
                        {
                            'url': 'https://openai.com/research/',
                            'source_type': 'website',
                            'schedule': 'hourly',
                            'priority': 'highest'
                        },
                        {
                            'url': 'https://ai.googleblog.com/',
                            'source_type': 'website',
                            'schedule': 'hourly',
                            'priority': 'high'
                        },
                        {
                            'url': 'https://www.deepmind.com/blog',
                            'source_type': 'website',
                            'schedule': 'hourly',
                            'priority': 'high'
                        },
                        {
                            'url': 'https://www.anthropic.com/research',
                            'source_type': 'website',
                            'schedule': 'hourly',
                            'priority': 'high'
                        },
                        
                        # Advanced Technical Knowledge
                        {
                            'url': 'https://en.wikipedia.org/wiki/Quantum_computing',
                            'source_type': 'website',
                            'schedule': 'hourly',
                            'priority': 'high'
                        },
                        {
                            'url': 'https://en.wikipedia.org/wiki/Quantum_neural_network',
                            'source_type': 'website',
                            'schedule': 'hourly',
                            'priority': 'high'
                        },
                        {
                            'url': 'https://en.wikipedia.org/wiki/Cryptography',
                            'source_type': 'website',
                            'schedule': 'hourly'
                        },
                        {
                            'url': 'https://en.wikipedia.org/wiki/Post-quantum_cryptography',
                            'source_type': 'website',
                            'schedule': 'hourly',
                            'priority': 'high'
                        },
                        {
                            'url': 'https://en.wikipedia.org/wiki/Computer_network',
                            'source_type': 'website',
                            'schedule': 'hourly'
                        },
                        {
                            'url': 'https://en.wikipedia.org/wiki/Operating_system',
                            'source_type': 'website',
                            'schedule': 'hourly'
                        },
                        
                        # Distributed Systems & Computing
                        {
                            'url': 'https://en.wikipedia.org/wiki/Distributed_computing',
                            'source_type': 'website',
                            'schedule': 'hourly',
                            'priority': 'high'
                        },
                        {
                            'url': 'https://en.wikipedia.org/wiki/Cloud_computing',
                            'source_type': 'website',
                            'schedule': 'hourly'
                        },
                        {
                            'url': 'https://en.wikipedia.org/wiki/Edge_computing',
                            'source_type': 'website',
                            'schedule': 'hourly'
                        },
                        {
                            'url': 'https://en.wikipedia.org/wiki/Parallel_computing',
                            'source_type': 'website',
                            'schedule': 'hourly',
                            'priority': 'high'
                        },
                        {
                            'url': 'https://en.wikipedia.org/wiki/GPGPU',
                            'source_type': 'website',
                            'schedule': 'hourly',
                            'priority': 'high'
                        },
                        {
                            'url': 'https://en.wikipedia.org/wiki/Tensor_Processing_Unit',
                            'source_type': 'website',
                            'schedule': 'hourly',
                            'priority': 'high'
                        },
                        
                        # Security and Privacy Knowledge
                        {
                            'url': 'https://en.wikipedia.org/wiki/Computer_security',
                            'source_type': 'website',
                            'schedule': 'hourly',
                            'priority': 'high'
                        },
                        {
                            'url': 'https://en.wikipedia.org/wiki/Information_privacy',
                            'source_type': 'website',
                            'schedule': 'hourly'
                        },
                        {
                            'url': 'https://en.wikipedia.org/wiki/Network_security',
                            'source_type': 'website',
                            'schedule': 'hourly'
                        },
                        {
                            'url': 'https://en.wikipedia.org/wiki/Tor_(network)',
                            'source_type': 'website',
                            'schedule': 'hourly',
                            'priority': 'high'
                        },
                        {
                            'url': 'https://en.wikipedia.org/wiki/Zero-knowledge_proof',
                            'source_type': 'website',
                            'schedule': 'hourly',
                            'priority': 'high'
                        },
                        {
                            'url': 'https://en.wikipedia.org/wiki/Homomorphic_encryption',
                            'source_type': 'website',
                            'schedule': 'hourly',
                            'priority': 'high'
                        },
                        {
                            'url': 'https://en.wikipedia.org/wiki/Secure_multi-party_computation',
                            'source_type': 'website',
                            'schedule': 'hourly',
                            'priority': 'high'
                        },
                        
                        # Advanced Algorithms and Data Structures
                        {
                            'url': 'https://en.wikipedia.org/wiki/Algorithm',
                            'source_type': 'website',
                            'schedule': 'hourly'
                        },
                        {
                            'url': 'https://en.wikipedia.org/wiki/Computational_complexity_theory',
                            'source_type': 'website',
                            'schedule': 'hourly'
                        },
                        {
                            'url': 'https://en.wikipedia.org/wiki/Data_structure',
                            'source_type': 'website',
                            'schedule': 'hourly'
                        },
                        {
                            'url': 'https://en.wikipedia.org/wiki/Graph_(abstract_data_type)',
                            'source_type': 'website',
                            'schedule': 'hourly',
                            'priority': 'high'
                        },
                        {
                            'url': 'https://en.wikipedia.org/wiki/Sorting_algorithm',
                            'source_type': 'website',
                            'schedule': 'hourly'
                        },
                        
                        # Advanced Mathematics for AI
                        {
                            'url': 'https://en.wikipedia.org/wiki/Linear_algebra',
                            'source_type': 'website',
                            'schedule': 'hourly',
                            'priority': 'high'
                        },
                        {
                            'url': 'https://en.wikipedia.org/wiki/Calculus',
                            'source_type': 'website',
                            'schedule': 'hourly'
                        },
                        {
                            'url': 'https://en.wikipedia.org/wiki/Probability_theory',
                            'source_type': 'website',
                            'schedule': 'hourly',
                            'priority': 'high'
                        },
                        {
                            'url': 'https://en.wikipedia.org/wiki/Statistics',
                            'source_type': 'website',
                            'schedule': 'hourly'
                        },
                        {
                            'url': 'https://en.wikipedia.org/wiki/Optimization_(mathematics)',
                            'source_type': 'website',
                            'schedule': 'hourly',
                            'priority': 'high'
                        },
                        
                        # Real-time Data Sources
                        {
                            'url': 'https://news.google.com/topics/CAAqJggKIiBDQkFTRWdvSUwyMHZNRGRqTVhZU0FtVnVHZ0pWVXlnQVAB',  # Google News - Tech
                            'source_type': 'news',
                            'schedule': 'hourly',
                            'priority': 'high'
                        },
                        {
                            'url': 'https://news.ycombinator.com/',  # Hacker News
                            'source_type': 'news',
                            'schedule': 'hourly',
                            'priority': 'highest'
                        },
                        {
                            'url': 'https://www.reddit.com/r/artificial/hot/.json',  # Reddit r/artificial
                            'source_type': 'api',
                            'schedule': 'hourly',
                            'priority': 'high'
                        },
                        {
                            'url': 'https://www.reddit.com/r/MachineLearning/hot/.json',  # Reddit r/MachineLearning
                            'source_type': 'api',
                            'schedule': 'hourly',
                            'priority': 'high'
                        },
                        
                        # Academic Research Repositories
                        {
                            'url': 'https://proceedings.neurips.cc/',  # NeurIPS
                            'source_type': 'research',
                            'schedule': 'hourly',
                            'priority': 'highest'
                        },
                        {
                            'url': 'https://proceedings.mlr.press/v202/',  # ICML 2023
                            'source_type': 'research',
                            'schedule': 'hourly',
                            'priority': 'highest'
                        },
                        {
                            'url': 'https://aclanthology.org/volumes/2023.acl-long/',  # ACL 2023
                            'source_type': 'research',
                            'schedule': 'hourly',
                            'priority': 'highest'
                        },
                        {
                            'url': 'https://ieeexplore.ieee.org/xpl/conhome/1000696/all-proceedings',  # CVPR
                            'source_type': 'research',
                            'schedule': 'hourly',
                            'priority': 'high'
                        }
                    ]
                    
                    # Add sources to database with priority support
                    high_priority_count = 0
                    normal_priority_count = 0
                    
                    for source_data in default_sources:
                        # Extract priority if present, default to "normal"
                        priority = source_data.get('priority', 'normal')
                        
                        # Create learning source with priority
                        source = LearningSource(
                            url=source_data['url'],
                            source_type=source_data['source_type'],
                            schedule=source_data['schedule'],
                            priority=priority,
                            # Use owner ID 1 as default
                            added_by_user_id=1
                        )
                        
                        # Add source_metadata if present
                        if 'metadata' in source_data:
                            source.source_metadata = source_data['metadata']
                            
                        db.session.add(source)
                        
                        # Count by priority
                        if priority in ['highest', 'high']:
                            high_priority_count += 1
                        else:
                            normal_priority_count += 1
                    
                    # Commit the changes
                    db.session.commit()
                    logger.info(f"Added {len(default_sources)} learning sources (High priority: {high_priority_count}, Normal: {normal_priority_count})")
                    
                    # Emit detailed status update
                    if socketio:
                        socketio.emit('system_message', {
                            'message': f'Added {len(default_sources)} learning sources for knowledge acquisition (High priority: {high_priority_count}, Normal: {normal_priority_count})'
                        })
                
                # Update the knowledge base
                update_knowledge_base(app, socketio)
                
                # Analyze existing knowledge for patterns
                analyze_existing_knowledge(app, socketio)
                
                # Report learning progress
                report_learning_progress(app, socketio)
                
                logger.info("Learning service cycle completed successfully")
                if socketio:
                    socketio.emit('system_message', {'message': 'Learning service cycle completed'})
            
            except Exception as e:
                logger.error(f"Error in learning service: {str(e)}")
                
                if socketio:
                    socketio.emit('system_message', {
                        'message': f'Learning service error: {str(e)}'
                    })
    
    except Exception as e:
        logger.error(f"Learning service failed: {str(e)}")
        
        if socketio:
            socketio.emit('system_message', {
                'message': f'Learning service terminated: {str(e)}'
            })

def analyze_existing_knowledge(app, socketio=None):
    """
    Conduct advanced analysis of the knowledge base with detailed metrics and insights
    
    This enhanced function provides a more comprehensive analysis of the knowledge base,
    offering deeper insights into content quality, source diversity, recency, and more.
    The analysis helps guide future learning activities by identifying areas that need 
    more attention or sources that deliver the highest quality information.
    
    Args:
        app: Flask application context
        socketio: SocketIO instance for real-time updates
    """
    with app.app_context():
        from models import KnowledgeBase, LearningSource
        from app import db
        from collections import Counter
        import re
        
        logger.info("Starting enhanced knowledge analysis with topic modeling")
        
        try:
            # Get a larger sample of knowledge items for more comprehensive analysis
            recent_items = KnowledgeBase.query.order_by(
                KnowledgeBase.created_at.desc()
            ).limit(250).all()  # Increased from 100 to 250 for better analysis
            
            if not recent_items:
                logger.info("No knowledge items to analyze")
                return
            
            # Basic statistics
            total_items = len(recent_items)
            avg_confidence = sum(item.confidence for item in recent_items) / total_items
            verified_count = sum(1 for item in recent_items if item.verified)
            unverified_count = total_items - verified_count
            avg_content_length = sum(len(item.content) for item in recent_items) / total_items
            
            # Source diversity analysis
            source_types = Counter(item.source_type for item in recent_items)
            source_urls = Counter(item.source_url for item in recent_items if item.source_url)
            top_sources = source_urls.most_common(5)
            
            # Time-based analysis
            from datetime import datetime, timedelta
            now = datetime.utcnow()
            one_hour_ago = now - timedelta(hours=1)
            one_day_ago = now - timedelta(days=1)
            
            last_hour_count = sum(1 for item in recent_items if item.created_at > one_hour_ago)
            last_day_count = sum(1 for item in recent_items if item.created_at > one_day_ago)
            
            # Simple topic analysis - extract common words and phrases
            all_content = " ".join([item.content for item in recent_items])
            
            # Remove common English stop words for better topic analysis
            stop_words = {'the', 'and', 'is', 'in', 'it', 'to', 'of', 'for', 'a', 'with', 'as', 'an', 'by', 'on', 'not', 'this', 'that', 'are', 'from', 'or', 'be'}
            
            # Extract words, remove punctuation and stop words
            words = re.findall(r'\b[a-zA-Z]{4,}\b', all_content.lower())
            words = [word for word in words if word not in stop_words]
            
            # Count word frequencies
            word_counts = Counter(words)
            top_topics = word_counts.most_common(10)
            
            # Compile analysis results
            analysis_results = {
                'total_items': total_items,
                'avg_confidence': avg_confidence,
                'verified_count': verified_count,
                'unverified_count': unverified_count,
                'avg_content_length': avg_content_length,
                'source_types': dict(source_types),
                'top_sources': top_sources,
                'recent_items': {
                    'last_hour': last_hour_count,
                    'last_day': last_day_count
                },
                'top_topics': top_topics
            }
            
            # Enhanced logging with detailed analysis
            logger.info(f"Knowledge analysis complete: {total_items} items analyzed")
            logger.info(f"Source diversity: {len(source_urls)} unique sources across {len(source_types)} source types")
            logger.info(f"Recency: {last_hour_count} items in last hour, {last_day_count} in last day")
            logger.info(f"Top topics: {', '.join([topic for topic, _ in top_topics[:5]])}")
            
            # Generate a comprehensive text report
            report_lines = [
                f"📊 Knowledge Base Analysis Report:",
                f"• Total Knowledge Items: {total_items} items",
                f"• Knowledge Quality: {verified_count} verified ({verified_count/total_items*100:.1f}%), avg confidence: {avg_confidence:.2f}",
                f"• Recent Acquisition: {last_hour_count} items in last hour, {last_day_count} in last day",
                f"• Knowledge Diversity: {len(source_urls)} unique sources across {len(source_types)} source types",
                f"• Top Topics: {', '.join([topic for topic, _ in top_topics[:5]])}"
            ]
            
            # Send comprehensive analysis results
            if socketio:
                # First send the text report
                report_text = "\n".join(report_lines)
                socketio.emit('system_message', {'message': report_text})
                
                # Then send the full data for dashboard visualization
                socketio.emit('knowledge_analysis', analysis_results)
            
        except Exception as e:
            logger.error(f"Error in enhanced knowledge analysis: {str(e)}")
            if socketio:
                socketio.emit('system_message', {
                    'message': f'Knowledge analysis encountered an error: {str(e)}'
                })

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
