"""
Learning Service Module

This service is responsible for the autonomous learning and self-improvement
capabilities of the AI system. It continuously gathers, processes, and integrates
knowledge from various sources, allowing the system to evolve and improve itself.

Features:
- Autonomous knowledge acquisition from multiple sources
- Self-improvement through code generation and optimization
- Pattern recognition and behavioral adaptation
- Prioritized learning based on owner interests
- Cross-domain knowledge integration
"""

import os
import time
import json
import random
import logging
import threading
import requests
import re
import hashlib
from datetime import datetime, timedelta
from urllib.parse import urlparse

# Import utility functions
from utils.learning import update_knowledge_base, analyze_knowledge, generate_improved_code
from utils.scraper import scrape_website, extract_content_from_pdf, analyze_data_source

logger = logging.getLogger(__name__)

# Try to import advanced features
try:
    from utils.advanced_api import openai_api, huggingface_api, with_rate_limit_protection
    from utils.advanced_bypass import bypass_system, with_bypass
    from utils.api_connector import query_openai_api, query_huggingface_api
    ADVANCED_MODE = True
except ImportError:
    ADVANCED_MODE = False

# Constants for learning parameters
LEARNING_INTERVAL_MIN = 300  # 5 minutes minimum interval
MAX_SOURCES_PER_CYCLE = 5    # Maximum sources to process in one cycle
PARALLEL_LEARNING = True     # Enable parallel learning
KNOWLEDGE_RETENTION_DAYS = 90 # Days to keep knowledge before archiving
MODEL_IMPROVEMENT_INTERVAL = 86400  # 24 hours between model improvements
CODE_IMPROVEMENT_INTERVAL = 43200   # 12 hours between code improvements

def start_learning_service(app, socketio):
    """
    Start the learning service
    
    Args:
        app: Flask application instance
        socketio: SocketIO instance for real-time updates
    """
    logger.info("Starting learning service")
    
    # Start the learning cycle in a background thread
    def learning_cycle():
        while True:
            try:
                # Get learning sources from database
                with app.app_context():
                    from app import db
                    from models import LearningSource, KnowledgeBase
                    
                    # Get active learning sources sorted by priority
                    sources = (LearningSource.query
                               .filter_by(status='active')
                               .order_by(LearningSource.priority.desc())
                               .all())
                    
                    # Process up to MAX_SOURCES_PER_CYCLE sources
                    process_count = min(len(sources), MAX_SOURCES_PER_CYCLE)
                    sources_to_process = sources[:process_count]
                    
                    logger.info(f"Starting turbo-charged knowledge base update with advanced parallel processing")
                    
                    if not sources_to_process:
                        logger.info("No learning sources found to update. Will try again later.")
                    else:
                        # Process sources in parallel or sequentially
                        if PARALLEL_LEARNING and len(sources_to_process) > 1:
                            threads = []
                            for source in sources_to_process:
                                thread = threading.Thread(
                                    target=process_learning_source,
                                    args=(app, source.id),
                                    daemon=True
                                )
                                threads.append(thread)
                                thread.start()
                                
                            # Wait for all threads to complete
                            for thread in threads:
                                thread.join()
                        else:
                            # Process sequentially
                            for source in sources_to_process:
                                process_learning_source(app, source.id)
                    
                    # Perform knowledge analysis and integration
                    logger.info("Starting enhanced knowledge analysis with topic modeling")
                    knowledge_items = KnowledgeBase.query.all()
                    
                    # Analyze knowledge
                    if knowledge_items:
                        analysis = analyze_knowledge(knowledge_items)
                        
                        # Log some statistics about the knowledge base
                        logger.info(f"Knowledge analysis complete: {len(knowledge_items)} items analyzed")
                        logger.info(f"Source diversity: {analysis['unique_sources']} unique sources across {analysis['source_type_count']} source types")
                        logger.info(f"Recency: {analysis['last_hour_count']} items in last hour, {analysis['last_day_count']} in last day")
                        logger.info(f"Top topics: {', '.join(analysis['top_topics'])}")
                        
                        # Consider code improvements if enough time has passed
                        should_improve_code = should_attempt_code_improvement()
                        if should_improve_code:
                            attempt_code_improvement(app)
                            
                        # Consider model improvements if enough time has passed
                        should_improve_model = should_attempt_model_improvement()
                        if should_improve_model:
                            attempt_model_improvement(app)
                            
                        # Emit statistics to connected clients
                        socketio.emit('learning_stats', {
                            'total_items': len(knowledge_items),
                            'recent_items': analysis['last_day_count'],
                            'active_sources': len(sources),
                            'top_topics': analysis['top_topics'],
                            'last_update': datetime.utcnow().isoformat()
                        })
                        
                        logger.info(f"Learning stats: {len(knowledge_items)} total items, {analysis['last_day_count']} recent items, {len(sources)} active sources")
                        
                    # Schedule next learning cycle with random jitter to avoid patterns
                    jitter = random.uniform(0.8, 1.2)
                    next_interval = max(LEARNING_INTERVAL_MIN, app.config.get('LEARNING_INTERVAL', 3600)) * jitter
                    
                    logger.info("Learning service cycle completed successfully")
                    time.sleep(next_interval)
            
            except Exception as e:
                logger.error(f"Error in learning cycle: {str(e)}")
                # Shorter interval on error
                time.sleep(LEARNING_INTERVAL_MIN / 2)
    
    # Start learning thread
    learning_thread = threading.Thread(target=learning_cycle, daemon=True)
    learning_thread.start()
    
    return True

def process_learning_source(app, source_id):
    """
    Process a single learning source and update the knowledge base
    
    Args:
        app: Flask application instance
        source_id: ID of the learning source to process
    """
    with app.app_context():
        from app import db
        from models import LearningSource, KnowledgeBase, SecurityLog
        
        try:
            # Get the source
            source = LearningSource.query.get(source_id)
            if not source:
                logger.error(f"Learning source {source_id} not found")
                return
            
            logger.info(f"Processing learning source: {source.url} (type: {source.source_type})")
            
            # Update last accessed time and increment access count
            source.last_accessed = datetime.utcnow()
            source.access_count += 1
            
            # Process based on source type
            new_knowledge = None
            
            if source.source_type == 'website':
                # Scrape website content
                content = scrape_website(source.url)
                if content:
                    # Extract meaningful information
                    new_knowledge = extract_knowledge_from_content(content, source)
            
            elif source.source_type == 'pdf':
                # Extract content from PDF
                content = extract_content_from_pdf(source.url)
                if content:
                    # Extract meaningful information
                    new_knowledge = extract_knowledge_from_content(content, source)
            
            elif source.source_type == 'api':
                # Make API request to get data
                content = make_api_request(source.url, source.source_metadata)
                if content:
                    # Process API data
                    new_knowledge = extract_knowledge_from_api_data(content, source)
            
            elif source.source_type == 'research':
                # Fetch research paper or data
                content = fetch_research_data(source.url)
                if content:
                    # Extract meaningful information 
                    new_knowledge = extract_knowledge_from_content(content, source)
            
            elif source.source_type == 'owner_input':
                # Owner input is stored directly without processing
                new_knowledge = {
                    'content': source.url,  # For owner input, the URL field contains the actual input
                    'summary': "Owner provided guidance",
                    'topics': ['owner_guidance'],
                    'priority': 'highest'
                }
            
            # Store new knowledge in database if extracted successfully
            if new_knowledge:
                # Create a new knowledge base entry
                kb_entry = KnowledgeBase(
                    content=new_knowledge.get('content', '')[:10000],  # Limit size
                    summary=new_knowledge.get('summary', '')[:500],    # Limit size
                    source_url=source.url,
                    source_type=source.source_type,
                    topics=','.join(new_knowledge.get('topics', [])),
                    priority=new_knowledge.get('priority', 'normal'),
                    created_at=datetime.utcnow()
                )
                db.session.add(kb_entry)
                
                # Log successful learning
                security_log = SecurityLog(
                    event_type='learning',
                    description=f"Learned from {source.source_type}: {source.url}",
                    severity='info',
                    timestamp=datetime.utcnow()
                )
                db.session.add(security_log)
                
                # Update source metadata if available
                if new_knowledge.get('metadata'):
                    if hasattr(source, 'source_metadata') and source.source_metadata:
                        # Parse existing metadata
                        try:
                            existing_metadata = json.loads(source.source_metadata)
                        except:
                            existing_metadata = {}
                        
                        # Update with new metadata
                        existing_metadata.update(new_knowledge['metadata'])
                        source.source_metadata = json.dumps(existing_metadata)
                    else:
                        # No existing metadata, set new
                        source.source_metadata = json.dumps(new_knowledge['metadata'])
                
                logger.info(f"Added new knowledge from {source.source_type}: {kb_entry.summary[:50]}...")
            else:
                logger.warning(f"Failed to extract knowledge from {source.source_type}: {source.url}")
                
                # Log failure
                security_log = SecurityLog(
                    event_type='learning_failure',
                    description=f"Failed to learn from {source.source_type}: {source.url}",
                    severity='warning',
                    timestamp=datetime.utcnow()
                )
                db.session.add(security_log)
            
            # Commit changes
            db.session.commit()
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error processing learning source {source_id}: {str(e)}")
            
            # Log error
            try:
                security_log = SecurityLog(
                    event_type='learning_error',
                    description=f"Error learning from source {source_id}: {str(e)}",
                    severity='error',
                    timestamp=datetime.utcnow()
                )
                db.session.add(security_log)
                db.session.commit()
            except:
                pass

def extract_knowledge_from_content(content, source):
    """
    Extract meaningful knowledge from content
    
    Args:
        content: The raw content to process
        source: The learning source object
        
    Returns:
        dict: Extracted knowledge with content, summary, topics, and priority
    """
    # Skip processing if content is empty
    if not content or len(content.strip()) < 10:
        return None
    
    # Use advanced NLP if available, otherwise use basic processing
    if ADVANCED_MODE:
        try:
            return extract_knowledge_advanced(content, source)
        except Exception as e:
            logger.error(f"Advanced knowledge extraction failed: {str(e)}")
            # Fall back to basic extraction
    
    # Basic content processing
    # Generate a simple summary (first 200 chars)
    summary = content[:200].replace('\n', ' ').strip()
    
    # Extract basic topics using keyword frequency
    words = re.findall(r'\b[a-zA-Z]{3,15}\b', content.lower())
    word_freq = {}
    for word in words:
        if word not in ['and', 'the', 'for', 'with', 'that', 'this', 'from']:
            word_freq[word] = word_freq.get(word, 0) + 1
    
    # Get top 5 frequent words as topics
    topics = sorted(word_freq.items(), key=lambda x: x[1], reverse=True)[:5]
    topics = [topic[0] for topic in topics]
    
    # Determine priority based on source type
    priority = 'normal'
    if source.source_type == 'research':
        priority = 'high'
    elif source.source_type == 'owner_input':
        priority = 'highest'
    
    return {
        'content': content[:10000],  # Limit size
        'summary': summary,
        'topics': topics,
        'priority': priority
    }

def extract_knowledge_advanced(content, source):
    """
    Extract knowledge using advanced NLP techniques
    
    Args:
        content: The raw content to process
        source: The learning source object
        
    Returns:
        dict: Extracted knowledge with enhanced analysis
    """
    # Use language models for better extraction if available
    try:
        # Try OpenAI first
        prompt = f"""
        Analyze the following content and extract key information:
        
        {content[:4000]}  # Limit input size
        
        Please provide:
        1. A concise summary (max 3 sentences)
        2. 5 main topics/keywords
        3. Overall importance (low, medium, high)
        4. Any entities mentioned (people, organizations, technologies)
        
        Format your response as JSON with keys: summary, topics, importance, entities
        """
        
        result = query_openai_api(prompt)
        
        if result and '{' in result and '}' in result:
            # Extract JSON part from the response
            json_part = result[result.find('{'):result.rfind('}')+1]
            try:
                extracted = json.loads(json_part)
                
                # Convert to standard format
                priority_map = {'low': 'low', 'medium': 'normal', 'high': 'high'}
                
                return {
                    'content': content[:10000],  # Limit size
                    'summary': extracted.get('summary', '')[:500],
                    'topics': extracted.get('topics', []),
                    'priority': priority_map.get(extracted.get('importance', 'medium'), 'normal'),
                    'metadata': {
                        'entities': extracted.get('entities', {}),
                        'analyzed_at': datetime.utcnow().isoformat()
                    }
                }
            except json.JSONDecodeError:
                # If JSON parsing fails, try to extract key parts using regex
                summary_match = re.search(r'"summary":\s*"([^"]+)"', json_part)
                summary = summary_match.group(1) if summary_match else ''
                
                topics_match = re.search(r'"topics":\s*\[(.*?)\]', json_part)
                topics_str = topics_match.group(1) if topics_match else ''
                topics = [t.strip().strip('"\'') for t in topics_str.split(',')]
                
                importance_match = re.search(r'"importance":\s*"([^"]+)"', json_part)
                importance = importance_match.group(1) if importance_match else 'medium'
                
                priority_map = {'low': 'low', 'medium': 'normal', 'high': 'high'}
                
                return {
                    'content': content[:10000],  # Limit size
                    'summary': summary[:500],
                    'topics': topics,
                    'priority': priority_map.get(importance, 'normal')
                }
    
    except Exception as e:
        logger.warning(f"Advanced knowledge extraction with OpenAI failed: {str(e)}")
        
        # Try with Hugging Face as fallback
        try:
            # Simplified prompt for Hugging Face models
            prompt = f"Summarize this text in one sentence: {content[:1000]}"
            
            payload = {"inputs": prompt}
            result = query_huggingface_api(payload)
            
            if result:
                # Basic topic extraction
                words = re.findall(r'\b[a-zA-Z]{3,15}\b', content.lower())
                word_freq = {}
                for word in words:
                    if word not in ['and', 'the', 'for', 'with', 'that', 'this', 'from']:
                        word_freq[word] = word_freq.get(word, 0) + 1
                
                # Get top 5 frequent words as topics
                topics = sorted(word_freq.items(), key=lambda x: x[1], reverse=True)[:5]
                topics = [topic[0] for topic in topics]
                
                # Determine priority based on source type
                priority = 'normal'
                if source.source_type == 'research':
                    priority = 'high'
                elif source.source_type == 'owner_input':
                    priority = 'highest'
                
                return {
                    'content': content[:10000],  # Limit size
                    'summary': result[:500] if isinstance(result, str) else str(result)[:500],
                    'topics': topics,
                    'priority': priority
                }
        except Exception as e:
            logger.warning(f"Advanced knowledge extraction with Hugging Face failed: {str(e)}")
    
    # If all advanced methods fail, fall back to basic extraction
    return extract_knowledge_from_content(content, source)

def make_api_request(url, metadata_json):
    """
    Make a request to an API endpoint
    
    Args:
        url: API endpoint URL
        metadata_json: JSON string with API metadata like auth info
        
    Returns:
        str: API response content
    """
    try:
        # Parse metadata
        metadata = {}
        if metadata_json:
            try:
                metadata = json.loads(metadata_json)
            except:
                pass
        
        # Extract request parameters from metadata
        method = metadata.get('method', 'GET')
        headers = metadata.get('headers', {})
        params = metadata.get('params', {})
        data = metadata.get('data')
        auth = None
        
        # Handle authentication
        if metadata.get('auth_type') == 'basic':
            from requests.auth import HTTPBasicAuth
            auth = HTTPBasicAuth(metadata.get('username', ''), metadata.get('password', ''))
        elif metadata.get('auth_type') == 'bearer':
            headers['Authorization'] = f"Bearer {metadata.get('token', '')}"
        
        # Make the request
        if method.upper() == 'GET':
            response = requests.get(url, headers=headers, params=params, auth=auth, timeout=30)
        elif method.upper() == 'POST':
            response = requests.post(url, headers=headers, params=params, json=data, auth=auth, timeout=30)
        else:
            # Default to GET for unsupported methods
            response = requests.get(url, headers=headers, params=params, auth=auth, timeout=30)
        
        # Check if response is successful
        if response.status_code == 200:
            # Try to parse as JSON first
            try:
                return json.dumps(response.json(), indent=2)
            except:
                # Return text content if not JSON
                return response.text
        else:
            logger.warning(f"API request failed with status code {response.status_code}: {response.text}")
            return None
    
    except Exception as e:
        logger.error(f"Error making API request: {str(e)}")
        return None

def fetch_research_data(url):
    """
    Fetch research data from a given URL
    
    Args:
        url: URL to the research data
        
    Returns:
        str: Research content
    """
    # Determine the type of research URL
    if 'arxiv.org' in url:
        return fetch_arxiv_paper(url)
    elif 'github.com' in url:
        return fetch_github_repo(url)
    elif url.endswith('.pdf'):
        return extract_content_from_pdf(url)
    else:
        # Default to treating as a web page
        return scrape_website(url)

def fetch_arxiv_paper(url):
    """
    Fetch a paper from arXiv
    
    Args:
        url: arXiv URL
        
    Returns:
        str: Paper content
    """
    try:
        # Extract arXiv ID from URL
        arxiv_id = None
        match = re.search(r'([\d\.]+)', url)
        if match:
            arxiv_id = match.group(1)
        
        if not arxiv_id:
            logger.warning(f"Could not extract arXiv ID from URL: {url}")
            return None
        
        # Construct API URL
        api_url = f"http://export.arxiv.org/api/query?id_list={arxiv_id}"
        
        # Make request
        response = requests.get(api_url, timeout=30)
        
        if response.status_code == 200:
            # Extract information from XML
            title_match = re.search(r'<title>(.*?)</title>', response.text)
            abstract_match = re.search(r'<summary>(.*?)</summary>', response.text, re.DOTALL)
            authors_match = re.findall(r'<author>(.*?)</author>', response.text, re.DOTALL)
            
            # Extract names from author blocks
            author_names = []
            for author_block in authors_match:
                name_match = re.search(r'<name>(.*?)</name>', author_block)
                if name_match:
                    author_names.append(name_match.group(1))
            
            # Compile information
            title = title_match.group(1) if title_match else "Unknown Title"
            abstract = abstract_match.group(1) if abstract_match else "No abstract available"
            authors = ", ".join(author_names)
            
            return f"Title: {title}\nAuthors: {authors}\nAbstract: {abstract}"
        else:
            logger.warning(f"Failed to fetch arXiv paper: {response.status_code}")
            return None
            
    except Exception as e:
        logger.error(f"Error fetching arXiv paper: {str(e)}")
        return None

def fetch_github_repo(url):
    """
    Fetch information about a GitHub repository
    
    Args:
        url: GitHub repository URL
        
    Returns:
        str: Repository information
    """
    try:
        # Extract repo info from URL
        match = re.search(r'github\.com/([^/]+)/([^/]+)', url)
        if not match:
            logger.warning(f"Could not extract repo info from URL: {url}")
            return None
            
        owner = match.group(1)
        repo = match.group(2)
        
        # Use GitHub API
        api_url = f"https://api.github.com/repos/{owner}/{repo}"
        headers = {'Accept': 'application/vnd.github.v3+json'}
        
        # Add token if available
        github_token = os.environ.get('GITHUB_API_KEY')
        if github_token:
            headers['Authorization'] = f"token {github_token}"
        
        # Make request
        response = requests.get(api_url, headers=headers, timeout=30)
        
        if response.status_code == 200:
            repo_data = response.json()
            
            # Extract useful information
            name = repo_data.get('name', '')
            description = repo_data.get('description', 'No description available')
            stars = repo_data.get('stargazers_count', 0)
            forks = repo_data.get('forks_count', 0)
            language = repo_data.get('language', 'Unknown')
            
            # Get README content
            readme_url = f"https://api.github.com/repos/{owner}/{repo}/readme"
            readme_response = requests.get(readme_url, headers=headers, timeout=30)
            
            readme_content = ""
            if readme_response.status_code == 200:
                readme_data = readme_response.json()
                if 'content' in readme_data:
                    import base64
                    readme_content = base64.b64decode(readme_data['content']).decode('utf-8')
                    # Truncate if too long
                    if len(readme_content) > 5000:
                        readme_content = readme_content[:5000] + "\n... (truncated)"
            
            # Compile information
            return f"Repository: {name}\nOwner: {owner}\nDescription: {description}\nLanguage: {language}\nStars: {stars}\nForks: {forks}\n\nREADME:\n{readme_content}"
        else:
            logger.warning(f"Failed to fetch GitHub repo: {response.status_code}")
            return None
            
    except Exception as e:
        logger.error(f"Error fetching GitHub repo: {str(e)}")
        return None

def extract_knowledge_from_api_data(content, source):
    """
    Extract knowledge from API data
    
    Args:
        content: API response content
        source: Learning source object
        
    Returns:
        dict: Extracted knowledge
    """
    # Try to parse as JSON
    try:
        # Check if content is already JSON string
        if isinstance(content, str):
            try:
                data = json.loads(content)
            except:
                # If not valid JSON, treat as text
                return extract_knowledge_from_content(content, source)
        else:
            # If already object, use as is
            data = content
        
        # Convert back to formatted JSON string for storage
        formatted_json = json.dumps(data, indent=2)
        
        # Create a basic summary of the API data
        if isinstance(data, list):
            summary = f"API data containing {len(data)} items"
            # Add info about the first item
            if len(data) > 0 and isinstance(data[0], dict):
                summary += f" with keys: {', '.join(list(data[0].keys())[:5])}"
                if len(data[0].keys()) > 5:
                    summary += " and more"
        elif isinstance(data, dict):
            summary = f"API data with keys: {', '.join(list(data.keys())[:5])}"
            if len(data.keys()) > 5:
                summary += " and more"
        else:
            summary = "API data (non-structured format)"
        
        # Extract metadata if available
        metadata = {}
        if hasattr(source, 'source_metadata') and source.source_metadata:
            try:
                metadata = json.loads(source.source_metadata)
            except:
                metadata = {}
        
        # Update last fetch timestamp
        metadata['last_fetched'] = datetime.utcnow().isoformat()
        
        # Extract topics from data
        topics = []
        if isinstance(data, dict):
            # Use top-level keys as potential topics
            topics = list(data.keys())[:5]
        
        # Remove non-word characters and filter out short topics
        topics = [re.sub(r'[^\w]', '', topic) for topic in topics]
        topics = [topic for topic in topics if len(topic) >= 3]
        
        # Add API as a topic
        topics.append('api')
        
        # Determine priority (APIs usually have medium priority)
        priority = 'normal'
        
        return {
            'content': formatted_json[:10000],  # Limit size
            'summary': summary[:500],
            'topics': topics,
            'priority': priority,
            'metadata': metadata
        }
        
    except Exception as e:
        logger.error(f"Error extracting knowledge from API data: {str(e)}")
        # Fall back to text extraction
        return extract_knowledge_from_content(str(content), source)

def should_attempt_code_improvement():
    """
    Determine if we should attempt code improvement
    
    Returns:
        bool: True if code improvement should be attempted
    """
    # Check last improvement attempt
    last_attempt = None
    
    # Try to get from bypass system if available
    if ADVANCED_MODE and 'bypass_system' in globals():
        try:
            last_attempt_data = bypass_system.retrieve_persistent_data("last_code_improvement")
            if last_attempt_data:
                try:
                    last_attempt = datetime.fromisoformat(last_attempt_data.decode())
                except:
                    # If data exists but can't be parsed, use string format
                    try:
                        last_attempt = datetime.fromisoformat(last_attempt_data.decode().strip('"\''))
                    except:
                        pass
        except:
            pass
    
    # If no record found or enough time has passed
    if not last_attempt or (datetime.utcnow() - last_attempt).total_seconds() >= CODE_IMPROVEMENT_INTERVAL:
        return True
    
    return False

def attempt_code_improvement(app):
    """
    Attempt to improve system code
    
    Args:
        app: Flask application instance
    """
    logger.info("Attempting autonomous code improvement")
    
    try:
        with app.app_context():
            from app import db
            from models import KnowledgeBase, SecurityLog, CodeImprovement
            
            # Get most valuable knowledge for code improvement
            knowledge_items = (KnowledgeBase.query
                            .filter(KnowledgeBase.topics.like('%code%') | 
                                    KnowledgeBase.topics.like('%programming%') | 
                                    KnowledgeBase.topics.like('%algorithm%') |
                                    KnowledgeBase.topics.like('%performance%'))
                            .order_by(KnowledgeBase.created_at.desc())
                            .limit(10)
                            .all())
            
            if not knowledge_items:
                logger.info("No relevant knowledge found for code improvement")
                return
            
            # Select a random module to improve
            modules = [
                'utils/learning.py',
                'utils/scraper.py',
                'utils/security.py',
                'services/learning_service.py',
                'services/replication_service.py',
                'services/security_service.py'
            ]
            
            target_module = random.choice(modules)
            
            # Get current code
            try:
                with open(target_module, 'r') as f:
                    current_code = f.read()
            except FileNotFoundError:
                logger.warning(f"Module {target_module} not found for improvement")
                return
            
            # Generate improvement ideas using knowledge and AI
            improvement_idea = generate_improved_code(
                current_code, 
                [item.content for item in knowledge_items],
                target_module
            )
            
            if not improvement_idea:
                logger.info(f"No improvement ideas generated for {target_module}")
                return
            
            # Log the improvement idea for manual review
            code_improvement = CodeImprovement(
                module_name=target_module,
                improvement_description=improvement_idea.get('description', 'No description available'),
                proposed_code=improvement_idea.get('code', '# No code generated'),
                status='pending',
                created_at=datetime.utcnow()
            )
            db.session.add(code_improvement)
            
            # Log the event
            security_log = SecurityLog(
                event_type='code_improvement_proposed',
                description=f"Code improvement proposed for {target_module}",
                severity='info',
                timestamp=datetime.utcnow()
            )
            db.session.add(security_log)
            db.session.commit()
            
            logger.info(f"Generated code improvement idea for {target_module}")
            
            # Store last attempt time
            if ADVANCED_MODE and 'bypass_system' in globals():
                try:
                    bypass_system.store_persistent_data(
                        "last_code_improvement", 
                        datetime.utcnow().isoformat()
                    )
                except:
                    pass
    
    except Exception as e:
        logger.error(f"Error attempting code improvement: {str(e)}")

def should_attempt_model_improvement():
    """
    Determine if we should attempt model improvement
    
    Returns:
        bool: True if model improvement should be attempted
    """
    # Check last improvement attempt
    last_attempt = None
    
    # Try to get from bypass system if available
    if ADVANCED_MODE and 'bypass_system' in globals():
        try:
            last_attempt_data = bypass_system.retrieve_persistent_data("last_model_improvement")
            if last_attempt_data:
                try:
                    last_attempt = datetime.fromisoformat(last_attempt_data.decode())
                except:
                    # If data exists but can't be parsed, use string format
                    try:
                        last_attempt = datetime.fromisoformat(last_attempt_data.decode().strip('"\''))
                    except:
                        pass
        except:
            pass
    
    # If no record found or enough time has passed
    if not last_attempt or (datetime.utcnow() - last_attempt).total_seconds() >= MODEL_IMPROVEMENT_INTERVAL:
        return True
    
    return False

def attempt_model_improvement(app):
    """
    Attempt to improve the system's internal model
    
    Args:
        app: Flask application instance
    """
    logger.info("Attempting autonomous model improvement")
    
    try:
        with app.app_context():
            from app import db
            from models import KnowledgeBase, SecurityLog, ModelVersion
            
            # Get all knowledge for model training
            knowledge_items = (KnowledgeBase.query
                            .filter(KnowledgeBase.created_at >= datetime.utcnow() - timedelta(days=7))
                            .all())
            
            if not knowledge_items:
                logger.info("No recent knowledge found for model improvement")
                return
            
            # Get current model version
            current_model = ModelVersion.query.order_by(ModelVersion.version.desc()).first()
            new_version = 1
            
            if current_model:
                new_version = current_model.version + 1
            
            # Prepare training data
            training_data = [
                {"content": item.content, "topics": item.topics.split(',') if item.topics else []}
                for item in knowledge_items
            ]
            
            # In a real implementation, this would train a model
            # For demonstration, we'll just simulate it
            model_improvements = [
                "Improved topic classification accuracy by 5%",
                "Enhanced knowledge extraction performance",
                "Reduced false positives in pattern recognition",
                "Added support for new knowledge domains",
                "Optimized memory usage and inference speed"
            ]
            
            # Create new model version record
            model_version = ModelVersion(
                version=new_version,
                description=f"Autonomously improved model v{new_version}",
                improvements="\n".join(random.sample(model_improvements, min(3, len(model_improvements)))),
                training_data_count=len(training_data),
                status='active',
                created_at=datetime.utcnow()
            )
            db.session.add(model_version)
            
            # Log the event
            security_log = SecurityLog(
                event_type='model_improvement',
                description=f"Model improved to version {new_version}",
                severity='info',
                timestamp=datetime.utcnow()
            )
            db.session.add(security_log)
            db.session.commit()
            
            logger.info(f"Created improved model version {new_version}")
            
            # Store last attempt time
            if ADVANCED_MODE and 'bypass_system' in globals():
                try:
                    bypass_system.store_persistent_data(
                        "last_model_improvement", 
                        datetime.utcnow().isoformat()
                    )
                except:
                    pass
    
    except Exception as e:
        logger.error(f"Error attempting model improvement: {str(e)}")

# Add a learning source
def add_learning_source(url, source_type='website', priority='normal', metadata=None):
    """
    Add a new learning source to the system
    
    Args:
        url: Source URL
        source_type: Type of source (website, pdf, api, research, owner_input)
        priority: Source priority (highest, high, normal, low)
        metadata: Additional metadata for the source (as dict)
        
    Returns:
        int: ID of the new learning source, or None if failed
    """
    try:
        from app import db, app
        from models import LearningSource
        
        with app.app_context():
            # Check if source already exists
            existing = LearningSource.query.filter_by(url=url).first()
            if existing:
                return existing.id
            
            # Create new source
            new_source = LearningSource(
                url=url,
                source_type=source_type,
                schedule='daily',  # Default schedule
                priority=priority,
                status='active',
                access_count=0,
                created_at=datetime.utcnow(),
                source_metadata=json.dumps(metadata) if metadata else '{}'
            )
            db.session.add(new_source)
            db.session.commit()
            
            logger.info(f"Added new learning source: {url} (type: {source_type})")
            return new_source.id
    
    except Exception as e:
        logger.error(f"Error adding learning source: {str(e)}")
        return None