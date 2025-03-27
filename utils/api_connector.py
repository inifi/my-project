import logging
import requests
import json
import random
import time
import os
import base64
import hashlib
from datetime import datetime, timedelta
from functools import wraps

# Import our advanced API system
try:
    from utils.advanced_api import (
        get_api_connector, openai_api, huggingface_api, github_api,
        with_rate_limit_protection
    )
    from utils.advanced_bypass import bypass_system, with_bypass
    ADVANCED_API_AVAILABLE = True
    BYPASS_AVAILABLE = True
    logger = logging.getLogger(__name__)
    logger.info("Advanced API and bypass system loaded successfully")
except ImportError:
    ADVANCED_API_AVAILABLE = False
    BYPASS_AVAILABLE = False
    logger = logging.getLogger(__name__)
    logger.warning("Advanced API or bypass system unavailable, using standard API methods")

# Store the last successful API responses to avoid redundant calls
_cached_responses = {}

def with_response_caching(cache_key_prefix, expire_seconds=300):
    """
    Decorator to cache API responses for a period of time
    
    Args:
        cache_key_prefix (str): Prefix for cache keys
        expire_seconds (int): Time in seconds before cache expires
        
    Returns:
        function: Decorated function with caching
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Generate a cache key from the function arguments
            args_str = str(args) + str(kwargs)
            cache_key = f"{cache_key_prefix}_{hashlib.md5(args_str.encode()).hexdigest()}"
            
            # Check if we have a cached result that hasn't expired
            if cache_key in _cached_responses:
                cached_data = _cached_responses[cache_key]
                if datetime.now() < cached_data['expires']:
                    logger.debug(f"Using cached response for {func.__name__}")
                    return cached_data['response']
            
            # No valid cache, execute the function
            result = func(*args, **kwargs)
            
            # Cache the result
            _cached_responses[cache_key] = {
                'response': result,
                'timestamp': datetime.now(),
                'expires': datetime.now() + timedelta(seconds=expire_seconds)
            }
            
            # Also try to persist in bypass system if available
            if BYPASS_AVAILABLE:
                try:
                    bypass_system.store_persistent_data(
                        f"api_cache_{cache_key}", 
                        json.dumps({'response': str(result), 'timestamp': str(datetime.now())})
                    )
                except:
                    pass
                    
            return result
        return wrapper
    return decorator

@with_response_caching('openai', expire_seconds=3600)  # Cache for 1 hour
def query_openai_api(prompt, model="gpt-3.5-turbo", max_tokens=1000, temperature=0.7):
    """
    Query the OpenAI API using advanced security and bypass techniques
    
    Args:
        prompt: The prompt to send to the OpenAI API
        model: Model to use (default: gpt-3.5-turbo)
        max_tokens: Maximum tokens in the response
        temperature: Temperature for randomness (0.0-1.0)
        
    Returns:
        str: API response text or None if failed
    """
    # Check if we can use the advanced API connector
    if ADVANCED_API_AVAILABLE:
        try:
            connector = openai_api()
            
            payload = {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": max_tokens,
                "temperature": temperature
            }
            
            response = connector.post(
                "chat/completions", 
                json=payload
            )
            
            if response.status_code == 200:
                response_json = response.json()
                message_content = response_json["choices"][0]["message"]["content"]
                return message_content.strip()
            else:
                logger.error(f"OpenAI API error with advanced connector: {response.status_code}")
                # Fall back to standard method
        except Exception as e:
            logger.error(f"Error with advanced API connector: {str(e)}")
            # Fall back to standard method
    
    # Standard method as fallback
    api_key = os.environ.get("OPENAI_API_KEY", "")
    
    if not api_key:
        logger.warning("No OpenAI API key found in environment variables")
        # Try to retrieve from bypass system if available
        if BYPASS_AVAILABLE:
            try:
                stored_key = bypass_system.retrieve_persistent_data("openai_api_key")
                if stored_key:
                    try:
                        api_key = stored_key.decode('utf-8')
                    except:
                        api_key = str(stored_key)
                        logger.info("Retrieved API key from secure storage")
            except:
                pass
                
        if not api_key:
            return None
    
    try:
        # Generate a random request ID to avoid detection patterns
        request_id = f"req_{hashlib.md5(str(datetime.now().timestamp()).encode()).hexdigest()[:10]}"
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "X-Request-ID": request_id
        }
        
        # Add random acceptable headers
        if random.random() > 0.5:
            headers["Accept"] = "application/json"
        if random.random() > 0.7:
            headers["Accept-Encoding"] = "gzip, deflate, br"
        
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
            "temperature": temperature
        }
        
        # Add random timing to avoid detection patterns
        if random.random() > 0.7:
            time.sleep(random.uniform(0.1, 0.5))
        
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            message_content = result["choices"][0]["message"]["content"]
            
            # If using bypass system, store successful API key
            if BYPASS_AVAILABLE:
                try:
                    bypass_system.store_persistent_data("openai_api_key", api_key)
                except:
                    pass
                    
            return message_content.strip()
        else:
            logger.error(f"OpenAI API error: {response.status_code} - {response.text}")
            
            # If rate limited, store information for future requests
            if response.status_code == 429 and BYPASS_AVAILABLE:
                try:
                    rate_limit_info = {
                        "timestamp": str(datetime.now()),
                        "status_code": 429,
                        "headers": dict(response.headers),
                        "service": "openai"
                    }
                    bypass_system.store_persistent_data("openai_rate_limit", json.dumps(rate_limit_info))
                except:
                    pass
                    
            return None
    
    except Exception as e:
        logger.error(f"Error querying OpenAI API: {str(e)}")
        return None

def get_github_data(repo_path, token=None):
    """
    Get data from a GitHub repository
    
    Args:
        repo_path: Repository path (e.g., "username/repo")
        token: GitHub API token (optional)
        
    Returns:
        dict: Repository data or None if failed
    """
    token = token or os.environ.get("GITHUB_API_KEY", "")
    
    try:
        headers = {
            "Accept": "application/vnd.github.v3+json"
        }
        
        if token:
            headers["Authorization"] = f"token {token}"
        
        # Get repository information
        repo_url = f"https://api.github.com/repos/{repo_path}"
        response = requests.get(repo_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            repo_data = response.json()
            
            # Get recent commits
            commits_url = f"{repo_url}/commits"
            commits_response = requests.get(commits_url, headers=headers, timeout=10)
            
            if commits_response.status_code == 200:
                commits = commits_response.json()[:5]  # Get 5 most recent commits
                repo_data["recent_commits"] = commits
            
            return repo_data
        else:
            logger.error(f"GitHub API error: {response.status_code} - {response.text}")
            return None
    
    except Exception as e:
        logger.error(f"Error fetching GitHub data: {str(e)}")
        return None

def search_stackoverflow(query, tagged=None, page=1, pagesize=5):
    """
    Search Stack Overflow for information
    
    Args:
        query: Search query
        tagged: List of tags to filter by (optional)
        page: Result page (default: 1)
        pagesize: Results per page (default: 5)
        
    Returns:
        dict: Search results or None if failed
    """
    try:
        url = "https://api.stackexchange.com/2.3/search/advanced"
        
        params = {
            "q": query,
            "site": "stackoverflow",
            "page": page,
            "pagesize": pagesize,
            "order": "desc",
            "sort": "relevance",
            "filter": "withbody"  # Include body content
        }
        
        if tagged:
            if isinstance(tagged, list):
                params["tagged"] = ";".join(tagged)
            else:
                params["tagged"] = tagged
        
        response = requests.get(url, params=params, timeout=10)
        
        if response.status_code == 200:
            return response.json()
        else:
            logger.error(f"Stack Overflow API error: {response.status_code} - {response.text}")
            return None
    
    except Exception as e:
        logger.error(f"Error searching Stack Overflow: {str(e)}")
        return None

def fetch_rss_feed(url):
    """
    Fetch and parse an RSS feed
    
    Args:
        url: URL of the RSS feed
        
    Returns:
        list: List of feed items or None if failed
    """
    try:
        import feedparser
        
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        feed = feedparser.parse(url, agent=user_agent)
        
        if feed.get('status', 0) == 200:
            items = []
            
            for entry in feed.entries:
                item = {
                    'title': entry.get('title', ''),
                    'link': entry.get('link', ''),
                    'summary': entry.get('summary', ''),
                    'published': entry.get('published', ''),
                    'id': entry.get('id', '')
                }
                
                # Add full content if available
                if 'content' in entry:
                    item['content'] = entry.content[0].value
                
                items.append(item)
            
            return items
        else:
            logger.error(f"RSS feed error: {feed.get('status', 'Unknown error')}")
            return None
    
    except Exception as e:
        logger.error(f"Error fetching RSS feed: {str(e)}")
        return None

def query_huggingface_api(payload, model_id="google/flan-t5-base", api_key=None):
    """
    Query HuggingFace Inference API for text generation, summarization,
    question answering, or other NLP tasks.
    
    Args:
        payload: The input data for the model. Should be a dictionary with keys
                 relevant to the model (e.g., "inputs" for text, "question" and "context"
                 for question answering models)
        model_id: HuggingFace model ID (e.g., "google/flan-t5-base", "facebook/bart-large-cnn")
        api_key: HuggingFace API token (required for production usage)
        
    Returns:
        dict: API response or None if failed
        
    Example:
        # For text generation
        response = query_huggingface_api({"inputs": "What is artificial intelligence?"}, 
                                         model_id="google/flan-t5-base", 
                                         api_key=YOUR_API_KEY)
                                         
        # For summarization
        response = query_huggingface_api({"inputs": long_text}, 
                                         model_id="facebook/bart-large-cnn", 
                                         api_key=YOUR_API_KEY)
    """
    api_key = api_key or os.environ.get("HUGGINGFACE_API_KEY", "")
    
    if not api_key:
        logger.warning("No HuggingFace API key found in environment variables")
        return None
    
    try:
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        
        url = f"https://api-inference.huggingface.co/models/{model_id}"
        
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        
        if response.status_code == 200:
            return response.json()
        else:
            logger.error(f"HuggingFace API error: {response.status_code} - {response.text}")
            return None
    
    except Exception as e:
        logger.error(f"Error querying HuggingFace API: {str(e)}")
        return None

def search_wikipedia(query, limit=5):
    """
    Search Wikipedia for information
    
    Args:
        query: Search query
        limit: Maximum number of results (default: 5)
        
    Returns:
        dict: Search results or None if failed
    """
    try:
        url = "https://en.wikipedia.org/w/api.php"
        
        params = {
            "action": "opensearch",
            "search": query,
            "limit": limit,
            "namespace": 0,
            "format": "json"
        }
        
        response = requests.get(url, params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            results = []
            titles = data[1]
            links = data[3]
            
            for i in range(len(titles)):
                # Get the page content
                content_params = {
                    "action": "query",
                    "prop": "extracts",
                    "exintro": True,
                    "explaintext": True,
                    "titles": titles[i],
                    "format": "json"
                }
                
                content_response = requests.get(url, params=content_params, timeout=10)
                
                if content_response.status_code == 200:
                    content_data = content_response.json()
                    pages = content_data["query"]["pages"]
                    page_id = list(pages.keys())[0]
                    
                    extract = pages[page_id].get("extract", "No extract available")
                    
                    results.append({
                        "title": titles[i],
                        "link": links[i],
                        "extract": extract
                    })
            
            return {"results": results}
        else:
            logger.error(f"Wikipedia API error: {response.status_code} - {response.text}")
            return None
    
    except Exception as e:
        logger.error(f"Error searching Wikipedia: {str(e)}")
        return None
