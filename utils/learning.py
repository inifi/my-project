import logging
import random
import time
import json
from datetime import datetime, timedelta
import nltk
from nltk.tokenize import sent_tokenize
import requests
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np

from utils.scraper import scrape_website, extract_links
from utils.api_connector import query_openai_api

# Initialize NLTK components
try:
    nltk.data.find('tokenizers/punkt')
except LookupError:
    nltk.download('punkt', quiet=True)

logger = logging.getLogger(__name__)

def update_knowledge_base(app, socketio=None):
    """
    Update the AI's knowledge base with new information from learning sources
    
    This function:
    1. Retrieves active learning sources from the database, with prioritization support
    2. Processes each source to extract valuable information using a hyper-efficient parallel processing approach
    3. Implements advanced deduplication and relevance filtering
    4. Stores new knowledge in the database with vector embeddings for search
    5. Reports progress in real-time via socketio if available
    
    Args:
        app: Flask application context
        socketio: SocketIO instance for real-time updates
    """
    with app.app_context():
        from models import LearningSource, KnowledgeBase, SecurityLog
        from app import db
        import threading
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        logger.info("Starting turbo-charged knowledge base update with advanced parallel processing")
        
        # Emit update status if socketio is available
        if socketio:
            socketio.emit('system_message', {'message': 'Starting super fast knowledge acquisition with advanced parallel processing...'})
        
        # Get learning sources that need to be updated with priority processing support
        now = datetime.utcnow()
        
        # First query to get high priority sources
        high_priority_sources = LearningSource.query.filter(
            (LearningSource.last_accessed == None) |  # Never accessed
            (LearningSource.last_accessed < now - timedelta(minutes=30))  # Higher priority sources refresh faster
        ).filter_by(status='active').filter(
            (LearningSource.priority == 'highest') | (LearningSource.priority == 'high')
        ).limit(40).all()  # Process more high priority sources
        
        # Second query to get regular sources
        normal_sources = LearningSource.query.filter(
            (LearningSource.last_accessed == None) |  # Never accessed
            (LearningSource.last_accessed < now - timedelta(hours=1))  # Regular sources on hourly schedule
        ).filter_by(status='active').filter(
            (LearningSource.priority != 'highest') & (LearningSource.priority != 'high')
        ).limit(30).all()  # Still process a good number of regular sources
        
        # Combine sources with high priority first
        sources = high_priority_sources + normal_sources
        
        # If we don't have any sources yet (first run), we'll pick them up after they're added
        if len(sources) == 0:
            logger.info("No learning sources found to update. Will try again later.")
            # This isn't an error, it's just that no sources need updating
            # New installations will have sources added but they may not be ready for the first update cycle
            # Ensure we return with at least one worker for ThreadPoolExecutor
            return
        
        logger.info(f"Found {len(sources)} learning sources to update (High priority: {len(high_priority_sources)}, Regular: {len(normal_sources)})")
        
        # Define a worker function to process a single source
        def process_source(source):
            source_result = {
                'url': source.url,
                'success': False,
                'error': None,
                'knowledge_items': 0,
                'priority': source.priority if hasattr(source, 'priority') else 'normal'
            }
            
            try:
                logger.info(f"Processing learning source: {source.url} (priority: {source_result['priority']})")
                
                # Emit update if socketio is available
                if socketio:
                    socketio.emit('system_message', {'message': f'Learning from {source.url}...'})
                
                # Reduced delay to speed up learning - even less for high priority sources
                if source_result['priority'] in ['highest', 'high']:
                    time.sleep(random.uniform(0.05, 0.2))  # Minimal delay for high priority
                else:
                    time.sleep(random.uniform(0.1, 0.3))  # Low delay for regular sources
                
                # Special handling for different source types
                if source.source_type == 'api':
                    # Handle API-based sources differently (like Reddit, Twitter, etc.)
                    result = process_api_source(source.url, timeout=15)
                elif source.source_type == 'research':
                    # Special handling for research repositories to extract paper information
                    result = process_research_source(source.url, timeout=20)
                else:
                    # Standard website scraping with advanced performance options
                    result = scrape_website(source.url, obfuscate=True, timeout=15, fast_mode=True)
                
                if result['success'] and result['content']:
                    with app.app_context():
                        # Update source access information
                        source.last_accessed = now
                        source.access_count += 1
                        db.session.commit()
                    
                    # Process and store the knowledge
                    knowledge_count = process_and_store_knowledge(app, result, source)
                    source_result['knowledge_items'] = knowledge_count
                    
                    # Extract and queue additional links if needed (with priority inheritance)
                    if source.source_type in ['website', 'research'] and source.access_count < 5:
                        additional_links = process_additional_links(app, result, source)
                        source_result['additional_links'] = additional_links
                    
                    source_result['success'] = True
                    
                    # Emit success message
                    if socketio:
                        socketio.emit('system_message', {
                            'message': f'Successfully learned from {source.url} ({knowledge_count} new items)'
                        })
                else:
                    with app.app_context():
                        # Update source with error status
                        source.status = 'error'
                        db.session.commit()
                        
                        # Log the error
                        error_log = SecurityLog(
                            event_type='learning_error',
                            description=f"Failed to learn from {source.url}: {result.get('error', 'Unknown error')}",
                            severity='warning',
                            timestamp=now
                        )
                        db.session.add(error_log)
                        db.session.commit()
                    
                    source_result['error'] = result.get('error', 'Unknown error')
                    
                    # Emit error message
                    if socketio:
                        socketio.emit('system_message', {
                            'message': f'Error learning from {source.url}'
                        })
            
            except Exception as e:
                logger.error(f"Error processing learning source {source.url}: {str(e)}")
                
                with app.app_context():
                    # Update source with error status
                    source.status = 'error'
                    db.session.commit()
                    
                    # Log the error
                    error_log = SecurityLog(
                        event_type='learning_error',
                        description=f"Exception while learning from {source.url}: {str(e)}",
                        severity='warning',
                        timestamp=now
                    )
                    db.session.add(error_log)
                    db.session.commit()
                
                source_result['error'] = str(e)
                
                # Emit error message
                if socketio:
                    socketio.emit('system_message', {
                        'message': f'Error processing {source.url}: {str(e)}'
                    })
            
            return source_result
        
        # Process sources in parallel using a thread pool
        results = []
        
        # Determine max workers based on sources count and scale with available CPU
        import multiprocessing
        # Ensure we have at least 1 worker even if sources is empty
        max_workers = max(1, min(len(sources), multiprocessing.cpu_count() * 3))  # Scale to 3x CPU for more parallelism
        
        # Use ThreadPoolExecutor to process sources in parallel
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all source processing tasks
            future_to_source = {executor.submit(process_source, source): source for source in sources}
            
            # Track progress for real-time updates
            total_sources = len(future_to_source)
            completed = 0
            
            # Collect results as they complete
            for future in as_completed(future_to_source):
                source = future_to_source[future]
                try:
                    result = future.result()
                    results.append(result)
                    completed += 1
                    
                    # Log completion status
                    priority_tag = f"[{result.get('priority', 'normal').upper()}]" if 'priority' in result else ""
                    success_status = "✓" if result['success'] else "✗"
                    
                    logger.info(f"Completed processing {source.url} {priority_tag} {success_status} ({completed}/{total_sources})")
                    
                    # Emit progress updates at intervals
                    if socketio and completed % 5 == 0:
                        progress_pct = int((completed / total_sources) * 100)
                        socketio.emit('learning_progress', {
                            'completed': completed,
                            'total': total_sources,
                            'percent': progress_pct
                        })
                except Exception as e:
                    logger.error(f"Exception processing {source.url}: {str(e)}")
                    completed += 1
        
        # Summarize results
        successful = [r for r in results if r['success']]
        failed = [r for r in results if not r['success']]
        total_knowledge_items = sum(r.get('knowledge_items', 0) for r in successful)
        
        logger.info(f"Knowledge base update completed: {len(successful)} sources processed successfully, {len(failed)} failed, {total_knowledge_items} new knowledge items")
        
        # Emit completion message with detailed statistics
        if socketio:
            socketio.emit('system_message', {
                'message': f'Knowledge acquisition completed: {len(successful)} sources processed, {total_knowledge_items} new items learned'
            })

# New specialized functions for different source types
def process_api_source(url, timeout=15):
    """
    Process an API-based learning source (like Reddit, Twitter, etc.)
    
    Args:
        url: API URL to query
        timeout: Request timeout in seconds
        
    Returns:
        dict: Dictionary containing the extracted content and metadata
    """
    try:
        logger.info(f"Accessing API source: {url}")
        result = {
            'url': url,
            'timestamp': datetime.utcnow().isoformat(),
            'success': False,
            'content': '',
            'metadata': {},
            'error': None,
            'source_type': 'api'
        }
        
        # Set up headers for the API request
        headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; AI Learning System/1.0)',
            'Accept': 'application/json'
        }
        
        # Make the API request
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
        
        # Parse the JSON response
        data = response.json()
        
        # Process based on known API formats
        if '/r/' in url and '.json' in url:  # Reddit API
            # Extract posts from Reddit API response
            posts = []
            if 'data' in data and 'children' in data['data']:
                for post in data['data']['children']:
                    if 'data' in post:
                        post_data = post['data']
                        title = post_data.get('title', '')
                        selftext = post_data.get('selftext', '')
                        url = post_data.get('url', '')
                        author = post_data.get('author', '')
                        score = post_data.get('score', 0)
                        
                        # Only include substantial posts
                        if len(title) > 10 and (len(selftext) > 100 or score > 50):
                            post_content = f"Title: {title}\n\nContent: {selftext}\n\nURL: {url}\nAuthor: {author}\nScore: {score}"
                            posts.append(post_content)
            
            # Combine all post content
            result['content'] = "\n\n---\n\n".join(posts)
            result['success'] = len(posts) > 0
            result['metadata']['post_count'] = len(posts)
        
        else:  # Generic API handling
            # Convert JSON to readable text
            content_parts = []
            
            def extract_text_from_json(json_obj, prefix=''):
                if isinstance(json_obj, dict):
                    for key, value in json_obj.items():
                        if isinstance(value, (dict, list)):
                            extract_text_from_json(value, prefix + key + '.')
                        elif isinstance(value, str) and len(value) > 5:
                            content_parts.append(f"{prefix}{key}: {value}")
                elif isinstance(json_obj, list):
                    for i, item in enumerate(json_obj):
                        if isinstance(item, (dict, list)):
                            extract_text_from_json(item, prefix + f"[{i}].")
                        elif isinstance(item, str) and len(item) > 5:
                            content_parts.append(f"{prefix}[{i}]: {item}")
            
            extract_text_from_json(data)
            result['content'] = "\n".join(content_parts)
            result['success'] = len(content_parts) > 0
        
        return result
    
    except Exception as e:
        logger.error(f"Error processing API source {url}: {str(e)}")
        return {
            'url': url,
            'timestamp': datetime.utcnow().isoformat(),
            'success': False,
            'content': '',
            'metadata': {},
            'error': str(e),
            'source_type': 'api'
        }

def process_research_source(url, timeout=20):
    """
    Process a research source (like arXiv, conference proceedings)
    
    Args:
        url: URL to the research repository or paper
        timeout: Request timeout in seconds
        
    Returns:
        dict: Dictionary containing the extracted content and metadata
    """
    try:
        from bs4 import BeautifulSoup  # Import here for explicit dependency
        
        logger.info(f"Accessing research source: {url}")
        result = {
            'url': url,
            'timestamp': datetime.utcnow().isoformat(),
            'success': False,
            'content': '',
            'metadata': {},
            'error': None,
            'source_type': 'research'
        }
        
        # First try with the scraper for general content
        scraped = scrape_website(url, obfuscate=True, timeout=timeout, fast_mode=True)
        
        if scraped['success'] and scraped['content']:
            result['content'] = scraped['content']
            result['downloaded'] = scraped.get('downloaded', '')
            result['success'] = True
            
            # For arXiv listings, try to extract paper information
            if 'arxiv.org/list/' in url:
                # If we have HTML content, parse it to extract paper details
                if 'downloaded' in scraped:
                    html_content = scraped['downloaded']
                    soup = BeautifulSoup(html_content, 'html.parser')
                    
                    # Extract paper listings
                    papers = []
                    paper_items = soup.select('dl')
                    
                    for dl in paper_items:
                        # Each paper usually has dt (with title/link) and dd (with authors, abstract)
                        title_elem = dl.select_one('dt .list-title')
                        abstract_elem = dl.select_one('dd .abstract-full')
                        authors_elem = dl.select_one('dd .list-authors')
                        
                        if title_elem and abstract_elem:
                            title = title_elem.get_text(strip=True)
                            abstract = abstract_elem.get_text(strip=True).replace('Abstract: ', '')
                            authors = authors_elem.get_text(strip=True).replace('Authors:', '') if authors_elem else ''
                            
                            paper_info = f"Title: {title}\n\nAuthors: {authors}\n\nAbstract: {abstract}"
                            papers.append(paper_info)
                    
                    if papers:
                        # Replace the content with structured paper information
                        result['content'] = "\n\n---\n\n".join(papers)
                        result['metadata']['paper_count'] = len(papers)
        
        return result
    
    except Exception as e:
        logger.error(f"Error processing research source {url}: {str(e)}")
        return {
            'url': url,
            'timestamp': datetime.utcnow().isoformat(),
            'success': False,
            'content': '',
            'metadata': {},
            'error': str(e),
            'source_type': 'research'
        }

def process_and_store_knowledge(app, scraped_result, source):
    """
    Process scraped content and store as knowledge
    
    Args:
        app: Flask application context
        scraped_result: Result from web scraping
        source: LearningSource model instance
        
    Returns:
        int: Number of knowledge items stored
    """
    with app.app_context():
        from models import KnowledgeBase
        from app import db
        from config import INSTANCE_ID
        
        content = scraped_result['content']
        url = scraped_result['url']
        
        # Skip if content is too short
        if len(content) < 100:
            logger.warning(f"Content from {url} too short, skipping")
            return 0
        
        # Split content into manageable chunks (sentences or paragraphs)
        sentences = sent_tokenize(content)
        
        # Group sentences into chunks of reasonable size
        chunks = []
        current_chunk = ""
        
        for sentence in sentences:
            if len(current_chunk) + len(sentence) < 1000:
                current_chunk += " " + sentence
            else:
                if current_chunk:
                    chunks.append(current_chunk.strip())
                current_chunk = sentence
        
        if current_chunk:
            chunks.append(current_chunk.strip())
        
        # Process and store each chunk
        knowledge_count = 0
        for chunk in chunks:
            # Skip short or low-information chunks
            if len(chunk) < 50 or not any(c.isalpha() for c in chunk):
                continue
            
            # Check for duplicate knowledge
            is_duplicate = check_duplicate_knowledge(app, chunk)
            
            if not is_duplicate:
                # Create new knowledge item
                knowledge = KnowledgeBase(
                    content=chunk,
                    source_url=url,
                    source_type=source.source_type,
                    confidence=0.7,  # Default confidence for newly acquired knowledge
                    verified=False,
                    instance_id=INSTANCE_ID
                )
                
                db.session.add(knowledge)
                knowledge_count += 1
        
        # Commit all new knowledge at once
        db.session.commit()
        logger.info(f"Stored {knowledge_count} new knowledge items from {url}")
        return knowledge_count

def check_duplicate_knowledge(app, content, similarity_threshold=0.8):
    """
    Check if the content is similar to existing knowledge
    
    Args:
        app: Flask application context
        content: Content to check for similarity
        similarity_threshold: Threshold above which content is considered duplicate
        
    Returns:
        bool: True if duplicate, False otherwise
    """
    with app.app_context():
        from models import KnowledgeBase
        
        # Get recent knowledge items for comparison
        existing_items = KnowledgeBase.query.order_by(
            KnowledgeBase.created_at.desc()
        ).limit(100).all()
        
        if not existing_items:
            return False
        
        # Extract content from existing items
        existing_content = [item.content for item in existing_items]
        
        # Add the new content
        all_content = existing_content + [content]
        
        # Create TF-IDF vectors
        vectorizer = TfidfVectorizer().fit_transform(all_content)
        vectors = vectorizer.toarray()
        
        # Get the vector for the new content (last one)
        new_vector = vectors[-1].reshape(1, -1)
        
        # Get vectors for existing content
        existing_vectors = vectors[:-1]
        
        # Calculate similarities
        similarities = cosine_similarity(new_vector, existing_vectors)[0]
        
        # Check if any similarity is above threshold
        if np.max(similarities) > similarity_threshold:
            logger.debug(f"Found duplicate knowledge with similarity {np.max(similarities):.2f}")
            return True
        
        return False

def process_additional_links(app, scraped_result, source):
    """
    Extract and queue additional links for learning
    
    Args:
        app: Flask application context
        scraped_result: Result from web scraping
        source: LearningSource model instance
    
    Returns:
        int: Number of additional links added
    """
    with app.app_context():
        from models import LearningSource
        from app import db
        
        # Check if we can extract HTML content
        if 'downloaded' in scraped_result:
            html_content = scraped_result['downloaded']
        else:
            # No HTML content available
            return 0
        
        # Extract links with the enhanced function (using fast mode for better performance)
        links = extract_links(html_content, source.url, max_links=5, fast_mode=True)
        
        # Since the extract_links function now has built-in limiting and optimization,
        # we don't need to shuffle and limit the links anymore
        
        added_count = 0
        for link in links:
            # Check if link already exists in learning sources
            existing = LearningSource.query.filter_by(url=link).first()
            
            if not existing:
                # Create new learning source from this link
                new_source = LearningSource(
                    url=link,
                    source_type='website',
                    schedule='once',  # Only process once
                    added_by_user_id=source.added_by_user_id,
                    created_at=datetime.utcnow()
                )
                
                db.session.add(new_source)
                added_count += 1
        
        # Commit all new sources
        db.session.commit()
        logger.info(f"Added {added_count} new learning sources from {source.url}")
        return added_count

def analyze_sentiment(text):
    """
    Analyze sentiment of a text
    
    Args:
        text: Text to analyze
        
    Returns:
        dict: Sentiment analysis results
    """
    try:
        # Try to use OpenAI for sentiment analysis
        prompt = f"Analyze the sentiment of the following text and classify it as positive, negative, or neutral. Provide a score from -1 (very negative) to +1 (very positive):\n\n{text}"
        
        response = query_openai_api(prompt)
        
        if response:
            return {
                'sentiment': 'analyzed',
                'analysis': response,
                'method': 'openai'
            }
        
        # Fall back to a simple rule-based approach
        positive_words = ['good', 'great', 'excellent', 'amazing', 'wonderful', 'best', 'love', 'happy', 'positive']
        negative_words = ['bad', 'terrible', 'worst', 'hate', 'awful', 'poor', 'negative', 'horrible', 'wrong']
        
        positive_count = sum(1 for word in positive_words if word in text.lower())
        negative_count = sum(1 for word in negative_words if word in text.lower())
        
        if positive_count > negative_count:
            sentiment = 'positive'
            score = min(1.0, (positive_count - negative_count) / 10)
        elif negative_count > positive_count:
            sentiment = 'negative'
            score = max(-1.0, (negative_count - positive_count) / -10)
        else:
            sentiment = 'neutral'
            score = 0.0
        
        return {
            'sentiment': sentiment,
            'score': score,
            'positive_words': positive_count,
            'negative_words': negative_count,
            'method': 'rule-based'
        }
    
    except Exception as e:
        logger.error(f"Error analyzing sentiment: {str(e)}")
        return {
            'sentiment': 'error',
            'error': str(e)
        }

def extract_topics(text, use_ml=True):
    """
    Extract main topics from a text using NLP techniques
    
    This function analyzes the content of a text and identifies the main topics
    or concepts mentioned. It uses a combination of rule-based techniques and
    machine learning for enhanced accuracy.
    
    Args:
        text: Text to analyze
        use_ml: Whether to use machine learning models (requires API key)
        
    Returns:
        list: Extracted topics as list of strings
    """
    try:
        # Try to use OpenAI for topic extraction
        prompt = f"Extract the main topics from the following text, list up to 5 key topics as keywords:\n\n{text}"
        
        response = query_openai_api(prompt)
        
        if response:
            # Extract topics from the response
            topics = [topic.strip() for topic in response.split(',')]
            return topics
        
        # Fall back to simple TF-IDF based extraction
        vectorizer = TfidfVectorizer(max_features=10, stop_words='english')
        tfidf_matrix = vectorizer.fit_transform([text])
        
        # Get feature names
        feature_names = vectorizer.get_feature_names_out()
        
        # Get scores
        scores = tfidf_matrix.toarray()[0]
        
        # Create a list of (word, score) tuples
        word_scores = list(zip(feature_names, scores))
        
        # Sort by score
        word_scores.sort(key=lambda x: x[1], reverse=True)
        
        # Extract top words
        topics = [word for word, score in word_scores[:5]]
        
        return topics
    
    except Exception as e:
        logger.error(f"Error extracting topics: {str(e)}")
        return []
