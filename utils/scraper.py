import logging
import trafilatura
import requests
import time
import random
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from datetime import datetime

logger = logging.getLogger(__name__)

def scrape_website(url, obfuscate=True, timeout=20, fast_mode=True):
    """
    Scrape content from a website with enhanced performance options
    
    Args:
        url: URL to scrape
        obfuscate: Whether to obfuscate the request to avoid detection
        timeout: Request timeout in seconds
        fast_mode: If True, uses optimized settings for faster scraping
        
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
        if obfuscate and not fast_mode:
            # Standard delay for normal mode
            delay = random.uniform(1.0, 5.0)
            logger.debug(f"Adding random delay of {delay:.2f} seconds")
            time.sleep(delay)
        elif obfuscate and fast_mode:
            # Shorter delay for fast mode
            delay = random.uniform(0.1, 0.5)
            logger.debug(f"Adding minimal delay of {delay:.2f} seconds (fast mode)")
            time.sleep(delay)
        
        # Use trafilatura to extract clean text content
        downloaded = trafilatura.fetch_url(url, timeout=timeout)
        
        if downloaded:
            # Extract main text content
            text = trafilatura.extract(downloaded)
            if text:
                result['content'] = text
                result['success'] = True
                
                # Store the downloaded content for link extraction later
                result['downloaded'] = downloaded
            
            # Extract metadata if available (skip in fast mode to improve speed)
            if not fast_mode:
                metadata = trafilatura.extract_metadata(downloaded)
                if metadata:
                    result['metadata'] = {
                        'title': metadata.title if metadata.title else None,
                        'author': metadata.author if metadata.author else None,
                        'date': metadata.date if metadata.date else None,
                        'categories': metadata.categories if metadata.categories else [],
                        'tags': metadata.tags if metadata.tags else []
                    }
            else:
                # In fast mode, just try to get the title
                soup = BeautifulSoup(downloaded, 'html.parser')
                if soup.title:
                    result['metadata']['title'] = soup.title.text.strip()
                result['downloaded'] = downloaded
            
            # Fall back to BeautifulSoup if trafilatura didn't get good content
            if not text or len(text) < 100:
                logger.debug(f"Trafilatura extraction limited, falling back to BeautifulSoup")
                soup = BeautifulSoup(downloaded, 'html.parser')
                
                # Extract title if not already done
                if soup.title and not result['metadata'].get('title'):
                    result['metadata']['title'] = soup.title.text.strip()
                
                # In fast mode, use a more efficient approach to extract content
                if fast_mode:
                    # Just get main content areas and paragraphs quickly
                    main_tags = ['main', 'article', 'div', 'section']
                    for tag in main_tags:
                        if result['content'] and len(result['content']) > 300:
                            break
                        for element in soup.find_all(tag, class_=lambda c: c and any(x in str(c).lower() for x in ['content', 'main', 'article', 'text', 'body'])):
                            paragraphs = element.find_all('p')
                            if paragraphs:
                                content = "\n\n".join([p.text.strip() for p in paragraphs if len(p.text.strip()) > 15])
                                if content and len(content) > len(result['content']):
                                    result['content'] = content
                                    result['success'] = True
                else:
                    # Standard approach for regular mode
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
            
            # Save the raw HTML content for link extraction
            result['downloaded'] = response.text
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract title
            if soup.title:
                result['metadata']['title'] = soup.title.text.strip()
            
            # Use different extraction methods based on mode
            if fast_mode:
                # Quick targeted approach for fast mode
                # Try to find content in the most common containers first
                content_containers = []
                
                # Look for common content containers
                for tag_name in ['main', 'article', 'div', 'section']:
                    # Look for content classes
                    for element in soup.find_all(tag_name, class_=lambda c: c and any(x in str(c).lower() for x in ['content', 'main', 'article', 'text', 'body'])):
                        content_containers.append(element)
                    
                    # If we found enough containers, stop looking
                    if len(content_containers) >= 3:
                        break
                
                # If no containers found, use body as fallback
                if not content_containers and soup.body:
                    content_containers = [soup.body]
                
                # Extract paragraphs from containers
                all_paragraphs = []
                for container in content_containers:
                    paragraphs = container.find_all('p')
                    # Only add paragraphs with meaningful content
                    for p in paragraphs:
                        p_text = p.text.strip()
                        if len(p_text) > 15 and p_text not in all_paragraphs:
                            all_paragraphs.append(p_text)
                
                # Combine paragraphs into content
                if all_paragraphs:
                    content = "\n\n".join(all_paragraphs)
                    result['content'] = content
                    result['success'] = True
            else:
                # Standard approach for regular mode
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

def extract_links(html_content, base_url, max_links=10, fast_mode=True):
    """
    Extract links from HTML content with enhanced performance options
    
    Args:
        html_content: HTML content to parse
        base_url: Base URL for resolving relative links
        max_links: Maximum number of links to return
        fast_mode: If True, uses optimized settings for faster extraction
        
    Returns:
        list: List of extracted URLs
    """
    try:
        # Parse the base URL to get the domain
        parsed_base = urlparse(base_url)
        base_domain = f"{parsed_base.scheme}://{parsed_base.netloc}"
        
        # Create a set to avoid duplicates from the beginning (more efficient)
        links = set()
        
        # Parse HTML
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Get all links
        a_tags = soup.find_all('a', href=True, limit=100 if fast_mode else None)
        
        # Process each link
        for a_tag in a_tags:
            href = a_tag['href']
            
            # Skip empty links, anchors, javascript, and mailto
            if not href or href.startswith(('#', 'javascript:', 'mailto:')):
                continue
            
            # In fast mode, prioritize same-domain links
            if fast_mode and not href.startswith(('http://', 'https://')):
                # For relative URLs, resolve them
                if href.startswith('/'):
                    href = f"{base_domain}{href}"
                else:
                    href = f"{base_url.rstrip('/')}/{href}"
                links.add(href)
                
                # If we have enough links, return early
                if len(links) >= max_links:
                    return list(links)
            elif not fast_mode:
                # For standard mode, process all links
                if not href.startswith(('http://', 'https://')):
                    # Resolve relative URLs
                    if href.startswith('/'):
                        href = f"{base_domain}{href}"
                    else:
                        href = f"{base_url.rstrip('/')}/{href}"
                links.add(href)
        
        # If in fast mode but we don't have enough same-domain links, add other links too
        if fast_mode and len(links) < max_links:
            for a_tag in a_tags:
                href = a_tag['href']
                
                # Process external links now
                if href and href.startswith(('http://', 'https://')):
                    links.add(href)
                    
                    # If we have enough links, stop
                    if len(links) >= max_links:
                        break
        
        # Convert to list and return
        return list(links)[:max_links]
        
    except Exception as e:
        logger.error(f"Error extracting links: {str(e)}")
        return []
