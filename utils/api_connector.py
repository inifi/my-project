import logging
import requests
import json
import random
import time
import os
from datetime import datetime

logger = logging.getLogger(__name__)

def query_openai_api(prompt, model="gpt-3.5-turbo", max_tokens=1000):
    """
    Query the OpenAI API
    
    Args:
        prompt: The prompt to send to the OpenAI API
        model: Model to use (default: gpt-3.5-turbo)
        max_tokens: Maximum tokens in the response
        
    Returns:
        str: API response text or None if failed
    """
    api_key = os.environ.get("OPENAI_API_KEY", "")
    
    if not api_key:
        logger.warning("No OpenAI API key found in environment variables")
        return None
    
    try:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
        
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
            "temperature": 0.7
        }
        
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            message_content = result["choices"][0]["message"]["content"]
            return message_content.strip()
        else:
            logger.error(f"OpenAI API error: {response.status_code} - {response.text}")
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
    Query HuggingFace Inference API
    
    Args:
        payload: The input data for the model
        model_id: HuggingFace model ID
        api_key: HuggingFace API token (optional)
        
    Returns:
        dict: API response or None if failed
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
