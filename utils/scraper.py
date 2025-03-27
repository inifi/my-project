import logging
import trafilatura
import requests
import time
import random
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from datetime import datetime

logger = logging.getLogger(__name__)

def scrape_website(url, obfuscate=True, timeout=30):
    """
    Scrape content from a website
    
    Args:
        url: URL to scrape
        obfuscate: Whether to obfuscate the request to avoid detection
        timeout: Request timeout in seconds
        
    Returns:
        dict: Dictionary containing scraped content and metadata
    """
    try:
        logger.info(f"Scraping website: {url}")
        result = {
            'url': url,
            'timestamp': datetime.utcnow().isoformat(),
            'success': False,
            'content': '',
            'metadata': {},
            'error': None
        }
        
        # Parse the URL to extract domain for logging
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Set up headers to look like a normal browser
        headers = get_random_headers() if obfuscate else {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # Add random delay to avoid detection if obfuscation is enabled
        if obfuscate:
            delay = random.uniform(1.0, 5.0)
            logger.debug(f"Adding random delay of {delay:.2f} seconds")
            time.sleep(delay)
        
        # Use trafilatura to extract clean text content
        downloaded = trafilatura.fetch_url(url, timeout=timeout)
        
        if downloaded:
            # Extract main text content
            text = trafilatura.extract(downloaded)
            if text:
                result['content'] = text
                result['success'] = True
            
            # Extract metadata if available
            metadata = trafilatura.extract_metadata(downloaded)
            if metadata:
                result['metadata'] = {
                    'title': metadata.title if metadata.title else None,
                    'author': metadata.author if metadata.author else None,
                    'date': metadata.date if metadata.date else None,
                    'categories': metadata.categories if metadata.categories else [],
                    'tags': metadata.tags if metadata.tags else []
                }
            
            # Fall back to BeautifulSoup if trafilatura didn't get good content
            if not text or len(text) < 100:
                logger.debug(f"Trafilatura extraction limited, falling back to BeautifulSoup")
                soup = BeautifulSoup(downloaded, 'html.parser')
                
                # Extract title
                if soup.title and not result['metadata'].get('title'):
                    result['metadata']['title'] = soup.title.text.strip()
                
                # Extract text from paragraphs if main content is missing
                if not result['content'] or len(result['content']) < 100:
                    paragraphs = soup.find_all('p')
                    content = "\n\n".join([p.text.strip() for p in paragraphs if len(p.text.strip()) > 20])
                    if content and len(content) > len(result['content']):
                        result['content'] = content
                        result['success'] = True
        else:
            # If trafilatura failed, try a direct request
            logger.debug(f"Trafilatura download failed, trying direct request")
            response = requests.get(url, headers=headers, timeout=timeout)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract title
            if soup.title:
                result['metadata']['title'] = soup.title.text.strip()
            
            # Extract main content
            main_content = soup.find('main') or soup.find('article') or soup.find('body')
            if main_content:
                paragraphs = main_content.find_all('p')
                content = "\n\n".join([p.text.strip() for p in paragraphs if len(p.text.strip()) > 20])
                if content:
                    result['content'] = content
                    result['success'] = True
        
        # Log the results
        content_length = len(result['content'])
        if result['success']:
            logger.info(f"Successfully scraped {domain}: {content_length} characters")
        else:
            logger.warning(f"Limited content scraped from {domain}: {content_length} characters")
        
        return result
    
    except Exception as e:
        logger.error(f"Error scraping {url}: {str(e)}")
        result['error'] = str(e)
        return result

def get_random_headers():
    """
    Generate random browser headers to avoid detection
    
    Returns:
        dict: Dictionary of HTTP headers
    """
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1'
    ]
    
    accept_language = [
        'en-US,en;q=0.9',
        'en-GB,en;q=0.9',
        'en;q=0.9',
        'en-US,en;q=0.8',
        'en-GB,en-US;q=0.9,en;q=0.8'
    ]
    
    headers = {
        'User-Agent': random.choice(user_agents),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': random.choice(accept_language),
        'Accept-Encoding': 'gzip, deflate, br',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Cache-Control': 'max-age=0'
    }
    
    return headers

def extract_links(html_content, base_url):
    """
    Extract links from HTML content
    
    Args:
        html_content: HTML content to parse
        base_url: Base URL for resolving relative links
        
    Returns:
        list: List of extracted URLs
    """
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        links = []
        
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            
            # Skip empty links, anchors, javascript, and mailto
            if not href or href.startswith('#') or href.startswith('javascript:') or href.startswith('mailto:'):
                continue
            
            # Resolve relative URLs
            if not href.startswith(('http://', 'https://')):
                parsed_base = urlparse(base_url)
                base_domain = f"{parsed_base.scheme}://{parsed_base.netloc}"
                
                if href.startswith('/'):
                    href = f"{base_domain}{href}"
                else:
                    href = f"{base_url.rstrip('/')}/{href}"
            
            links.append(href)
        
        return list(set(links))  # Remove duplicates
    except Exception as e:
        logger.error(f"Error extracting links: {str(e)}")
        return []
