"""
Enhanced Web Scraper Module

This module provides advanced web scraping capabilities with multiple strategies
for content extraction, stealth access, and structured data extraction.
"""

import random
import time
import re
import logging
import json
from datetime import datetime
from urllib.parse import urlparse, urljoin
import trafilatura
from bs4 import BeautifulSoup
import requests

# Configure logging
logger = logging.getLogger(__name__)

# List of common user agents for rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36"
]


def get_website_text_content(url, extraction_method="trafilatura", stealth_mode=True, use_proxies=False):
    """
    Enhanced function to extract text content from a website with multiple extraction methods.
    
    Args:
        url: URL to scrape
        extraction_method: Method to use for extraction ('trafilatura', 'beautifulsoup', 'hybrid')
        stealth_mode: Whether to use stealth techniques to avoid detection
        use_proxies: Whether to route request through proxy servers
        
    Returns:
        dict: Extracted content with metadata
    """
    try:
        # Create a session for consistent headers
        session = requests.Session()
        
        # Apply stealth techniques if enabled
        if stealth_mode:
            session.headers.update({
                'User-Agent': random.choice(USER_AGENTS),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Cache-Control': 'max-age=0',
                'TE': 'Trailers',
            })
            
            # Add a random delay to mimic human behavior
            time.sleep(random.uniform(1.0, 3.0))
        
        # Setup proxies if enabled
        proxies = None
        if use_proxies:
            # Import dynamically to avoid dependency issues
            try:
                from utils.enhanced_security import get_proxy_server
                proxy_server = get_proxy_server()
                if proxy_server:
                    proxies = {
                        'http': proxy_server,
                        'https': proxy_server
                    }
            except ImportError:
                logger.warning("Enhanced security module not available for proxy support")
        
        # Make the request
        response = session.get(url, timeout=10, proxies=proxies)
        response.raise_for_status()
        
        # Extract domain for metadata
        domain = urlparse(url).netloc
        
        # Get content based on the specified method
        if extraction_method == "trafilatura":
            content = extract_with_trafilatura(response.text, url)
        elif extraction_method == "beautifulsoup":
            content = extract_with_beautifulsoup(response.text, url)
        elif extraction_method == "hybrid":
            # Try trafilatura first, fall back to beautifulsoup
            content = extract_with_trafilatura(response.text, url)
            if not content or len(content.get('text', '')) < 100:
                content = extract_with_beautifulsoup(response.text, url)
        else:
            # Default to trafilatura
            content = extract_with_trafilatura(response.text, url)
        
        # Enhance metadata
        content['url'] = url
        content['domain'] = domain
        content['scraped_at'] = datetime.utcnow().isoformat()
        content['extraction_method'] = extraction_method
        
        return content
        
    except Exception as e:
        logger.error(f"Error scraping {url}: {str(e)}")
        return {
            'url': url,
            'domain': urlparse(url).netloc if url else None,
            'scraped_at': datetime.utcnow().isoformat(),
            'error': str(e),
            'text': None,
            'title': None,
            'extraction_method': extraction_method
        }


def extract_with_trafilatura(html_content, url):
    """
    Extract content using trafilatura - good for article content
    """
    try:
        # Extract with trafilatura
        extracted = trafilatura.extract(html_content, output_format='json', url=url, include_links=True, 
                                       include_tables=True, include_images=True)
        
        if extracted:
            extracted_dict = json.loads(extracted)
            
            # Additional processing
            text_content = extracted_dict.get('text', '')
            title = extracted_dict.get('title', '')
            
            # Process any extracted data like links, tables, etc.
            return {
                'text': text_content,
                'title': title,
                'metadata': {
                    'author': extracted_dict.get('author', ''),
                    'date': extracted_dict.get('date', ''),
                    'categories': extracted_dict.get('categories', []),
                    'tags': extracted_dict.get('tags', []),
                    'sitename': extracted_dict.get('sitename', '')
                },
                'links': extracted_dict.get('links', []),
                'source': 'trafilatura'
            }
        else:
            return {'text': '', 'title': '', 'metadata': {}, 'source': 'trafilatura', 'error': 'No content extracted'}
            
    except Exception as e:
        logger.error(f"Trafilatura extraction error: {str(e)}")
        return {'text': '', 'title': '', 'metadata': {}, 'source': 'trafilatura', 'error': str(e)}


def extract_with_beautifulsoup(html_content, url):
    """
    Extract content using BeautifulSoup - more flexible for various page structures
    """
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Extract title
        title = ''
        title_tag = soup.find('title')
        if title_tag:
            title = title_tag.text.strip()
            
        # Remove script and style tags
        for script_or_style in soup(['script', 'style', 'header', 'footer', 'nav']):
            script_or_style.decompose()
            
        # Extract main content
        main_content = ''
        
        # Try to find main content area
        main_tags = ['article', 'main', 'div[role="main"]', '.content', '.main', '#content', '#main']
        content_area = None
        
        for tag in main_tags:
            if '[' in tag and ']' in tag:
                tag_name, attr = tag.split('[')
                attr_name, attr_value = attr.rstrip(']').split('=')
                attr_value = attr_value.strip('"\'')
                elements = soup.find_all(tag_name, {attr_name.strip(): attr_value})
            elif tag.startswith('.'):
                elements = soup.find_all(class_=tag[1:])
            elif tag.startswith('#'):
                elements = soup.find_all(id=tag[1:])
            else:
                elements = soup.find_all(tag)
                
            if elements:
                # Use the largest content area
                content_area = max(elements, key=lambda x: len(x.get_text()))
                break
                
        if content_area:
            main_content = content_area.get_text(separator='\n', strip=True)
        else:
            # Fall back to body if no specific content area found
            body = soup.find('body')
            if body:
                main_content = body.get_text(separator='\n', strip=True)
            else:
                main_content = soup.get_text(separator='\n', strip=True)
        
        # Process text: remove excessive whitespace
        main_content = re.sub(r'\n\s*\n', '\n\n', main_content)
        main_content = re.sub(r' +', ' ', main_content)
        
        # Extract links
        links = []
        for link in soup.find_all('a', href=True):
            href = link['href']
            text = link.get_text(strip=True)
            if href and href != '#' and not href.startswith('javascript:'):
                # Convert relative links to absolute
                if not href.startswith(('http://', 'https://')):
                    href = urljoin(url, href)
                links.append({'url': href, 'text': text})
        
        # Extract metadata
        meta_tags = {}
        for meta in soup.find_all('meta'):
            name = meta.get('name', meta.get('property', ''))
            content = meta.get('content', '')
            if name and content:
                meta_tags[name] = content
        
        return {
            'text': main_content,
            'title': title,
            'metadata': meta_tags,
            'links': links,
            'source': 'beautifulsoup'
        }
        
    except Exception as e:
        logger.error(f"BeautifulSoup extraction error: {str(e)}")
        return {'text': '', 'title': '', 'metadata': {}, 'source': 'beautifulsoup', 'error': str(e)}


def scrape_structured_data(url, data_type="all"):
    """
    Extract structured data like JSON-LD, RDFa, Microdata from a webpage
    
    Args:
        url: URL to scrape
        data_type: Type of structured data to extract ('json-ld', 'rdfa', 'microdata', 'all')
        
    Returns:
        dict: Extracted structured data
    """
    try:
        session = requests.Session()
        session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
        response = session.get(url, timeout=10)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        structured_data = {}
        
        # Extract JSON-LD
        if data_type in ["json-ld", "all"]:
            json_ld_data = []
            for script in soup.find_all('script', type='application/ld+json'):
                try:
                    json_ld_data.append(json.loads(script.string))
                except (json.JSONDecodeError, TypeError) as e:
                    logger.error(f"Error parsing JSON-LD: {str(e)}")
            structured_data['json_ld'] = json_ld_data
            
        # Extract RDFa (simplified)
        if data_type in ["rdfa", "all"]:
            rdfa_elements = soup.find_all(attrs={"property": True})
            rdfa_data = {}
            for element in rdfa_elements:
                property_name = element.get('property')
                content = element.get('content', element.text.strip())
                if property_name not in rdfa_data:
                    rdfa_data[property_name] = []
                rdfa_data[property_name].append(content)
            structured_data['rdfa'] = rdfa_data
            
        # Extract OpenGraph and Twitter card data
        if data_type in ["meta", "all"]:
            meta_data = {}
            # OpenGraph
            og_tags = soup.find_all('meta', property=re.compile(r'^og:'))
            for tag in og_tags:
                property_name = tag.get('property', '')[3:]  # Remove 'og:' prefix
                content = tag.get('content', '')
                meta_data[f'og_{property_name}'] = content
                
            # Twitter Card
            twitter_tags = soup.find_all('meta', name=re.compile(r'^twitter:'))
            for tag in twitter_tags:
                property_name = tag.get('name', '')[8:]  # Remove 'twitter:' prefix
                content = tag.get('content', '')
                meta_data[f'twitter_{property_name}'] = content
                
            structured_data['meta'] = meta_data
            
        return structured_data
        
    except Exception as e:
        logger.error(f"Error scraping structured data from {url}: {str(e)}")
        return {"error": str(e)}


def crawl_website(base_url, max_pages=10, same_domain_only=True, extraction_method="trafilatura"):
    """
    Crawl a website to extract content from multiple pages
    
    Args:
        base_url: Starting URL for crawling
        max_pages: Maximum number of pages to crawl
        same_domain_only: Whether to stay on the same domain
        extraction_method: Content extraction method
        
    Returns:
        list: Extracted content from crawled pages
    """
    try:
        base_domain = urlparse(base_url).netloc
        crawled_urls = set()
        to_crawl = [base_url]
        results = []
        
        while to_crawl and len(crawled_urls) < max_pages:
            current_url = to_crawl.pop(0)
            
            if current_url in crawled_urls:
                continue
                
            logger.info(f"Crawling: {current_url}")
            
            # Extract content
            content = get_website_text_content(current_url, extraction_method=extraction_method)
            if content and not content.get('error'):
                results.append(content)
                
                # Extract links for further crawling
                for link in content.get('links', []):
                    link_url = link.get('url')
                    
                    if not link_url:
                        continue
                        
                    # Ensure it's an absolute URL
                    if not link_url.startswith(('http://', 'https://')):
                        link_url = urljoin(current_url, link_url)
                        
                    # Check if we should follow this link
                    link_domain = urlparse(link_url).netloc
                    if same_domain_only and link_domain != base_domain:
                        continue
                        
                    # Check if we've seen this URL
                    if link_url not in crawled_urls and link_url not in to_crawl:
                        to_crawl.append(link_url)
            
            # Mark as crawled
            crawled_urls.add(current_url)
            
            # Respect robots.txt with a delay
            time.sleep(random.uniform(1.0, 3.0))
            
        return results
        
    except Exception as e:
        logger.error(f"Error during website crawling: {str(e)}")
        return []