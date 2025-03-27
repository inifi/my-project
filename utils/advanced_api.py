"""
Advanced API Integration Module

This module provides enhanced API capabilities with built-in security,
rate limit bypassing, error handling, and advanced request management.

Key features:
- Automatic rate limit detection and adaptive delay
- Request signature rotation and obfuscation
- Distributed API key management
- Request fingerprint randomization
- Fallback patterns and alternative endpoints
"""

import os
import time
import random
import hashlib
import logging
import requests
import json
import base64
import threading
from datetime import datetime, timedelta
from urllib.parse import urlparse
from functools import wraps

# Configure logging
logger = logging.getLogger(__name__)

# Import the bypass system for additional capabilities
try:
    from utils.advanced_bypass import bypass_system
    BYPASS_AVAILABLE = True
except ImportError:
    BYPASS_AVAILABLE = False
    logger.warning("Advanced bypass system not available, using limited API capabilities")

# Global API state tracking
API_STATE = {
    'calls': {},
    'rate_limits': {},
    'backoff_times': {},
    'last_rotation': datetime.utcnow(),
    'active_session': None
}

class AdvancedAPIConnector:
    """Main class for advanced API connectivity with security features"""
    
    def __init__(self, service_name, api_key=None, base_url=None):
        """
        Initialize API connector for a specific service
        
        Args:
            service_name (str): Name of the API service (e.g., 'openai', 'huggingface')
            api_key (str, optional): API key for the service. If None, will attempt to load from environment
            base_url (str, optional): Base URL for API endpoints. If None, will use default for the service
        """
        self.service = service_name.lower()
        self.api_key = api_key or self._get_api_key()
        self.base_url = base_url or self._get_default_base_url()
        self.session = self._create_secure_session()
        self.call_history = []
        self.error_count = 0
        self.success_count = 0
        self._last_call_time = None
        self._rate_limit_detected = False
        self._concurrent_calls = 0
        self._backup_keys = self._load_backup_keys()
        
        # Fingerprint randomization
        self.fingerprints = self._generate_fingerprints()
        
        # Register this API connector in global state
        if self.service not in API_STATE['calls']:
            API_STATE['calls'][self.service] = 0
            API_STATE['rate_limits'][self.service] = {
                'limit': None,
                'remaining': None,
                'reset': None,
                'detected_limit': 0
            }
            API_STATE['backoff_times'][self.service] = 0.5  # Default backoff time in seconds
        
    def _get_api_key(self):
        """Get API key from environment with fallback strategies"""
        # Common environment variable patterns for different services
        env_patterns = [
            f"{self.service.upper()}_API_KEY",
            f"{self.service.upper()}_KEY",
            f"{self.service.upper()}_TOKEN",
            f"{self.service}_api_key",
            f"{self.service}_key",
            f"{self.service}_token",
            "API_KEY" if self.service == "default" else None
        ]
        
        # Try each pattern
        for pattern in env_patterns:
            if not pattern:
                continue
            key = os.environ.get(pattern)
            if key:
                logger.debug(f"Found API key for {self.service} using environment variable {pattern}")
                return key
                
        # Try to retrieve from bypass system if available
        if BYPASS_AVAILABLE:
            stored_key = bypass_system.retrieve_persistent_data(f"{self.service}_api_key")
            if stored_key:
                try:
                    return stored_key.decode('utf-8')
                except:
                    return stored_key
                    
        logger.warning(f"No API key found for {self.service}")
        return None
        
    def _get_default_base_url(self):
        """Get the default base URL for the service"""
        defaults = {
            'openai': 'https://api.openai.com/v1',
            'huggingface': 'https://api-inference.huggingface.co/models',
            'github': 'https://api.github.com',
            'reddit': 'https://oauth.reddit.com/api/v1',
            'twitter': 'https://api.twitter.com/2',
            'stackexchange': 'https://api.stackexchange.com/2.3',
            'arxiv': 'http://export.arxiv.org/api'
        }
        
        return defaults.get(self.service, f"https://api.{self.service}.com")
        
    def _create_secure_session(self):
        """Create a secure session with randomized attributes"""
        session = requests.Session()
        
        # Randomize user agent
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36'
        ]
        session.headers.update({
            'User-Agent': random.choice(user_agents),
            'Accept': 'application/json',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive'
        })
        
        # Set default timeout
        session.timeout = (5, 30)  # (connect, read) timeouts
        
        return session
        
    def _load_backup_keys(self):
        """Load any backup API keys from various storage locations"""
        backup_keys = []
        
        # Try to load from bypass system
        if BYPASS_AVAILABLE:
            for i in range(5):  # Try different key positions
                key_data = bypass_system.retrieve_persistent_data(f"{self.service}_api_key_{i}")
                if key_data:
                    try:
                        backup_keys.append(key_data.decode('utf-8'))
                    except:
                        backup_keys.append(str(key_data))
        
        return backup_keys
        
    def _generate_fingerprints(self):
        """Generate multiple request fingerprints for rotation"""
        fingerprints = []
        
        # Create several fingerprint patterns
        for i in range(5):
            fp = {
                'headers': {
                    'Accept-Encoding': random.choice(['gzip, deflate, br', 'gzip, deflate', 'br, gzip']),
                    'Cache-Control': random.choice(['no-cache', 'max-age=0', None]),
                    'Pragma': random.choice(['no-cache', None])
                },
                'cookies': {},
                'query_params': {}
            }
            
            # Randomize some additional headers based on patterns
            if random.random() > 0.5:
                fp['headers']['Sec-Fetch-Site'] = random.choice(['same-origin', 'same-site', 'cross-site'])
            
            if random.random() > 0.6:
                fp['headers']['Sec-Fetch-Mode'] = random.choice(['cors', 'navigate'])
                
            if random.random() > 0.7:
                fp['headers']['Sec-Fetch-Dest'] = random.choice(['empty', 'document', 'image'])
                
            # Generate a random client ID as a query parameter for some requests
            if random.random() > 0.6:
                client_id = f"client-{hashlib.md5(os.urandom(8)).hexdigest()[:8]}"
                fp['query_params']['client'] = client_id
                
            fingerprints.append(fp)
            
        return fingerprints
        
    def _apply_fingerprint(self, request_kwargs):
        """Apply a random fingerprint to the request"""
        if not self.fingerprints:
            return request_kwargs
            
        # Select a random fingerprint
        fp = random.choice(self.fingerprints)
        
        # Apply headers
        if 'headers' not in request_kwargs:
            request_kwargs['headers'] = {}
            
        for header, value in fp['headers'].items():
            if value is not None:
                request_kwargs['headers'][header] = value
                
        # Apply query parameters if any
        if fp['query_params'] and ('params' not in request_kwargs or not request_kwargs['params']):
            request_kwargs['params'] = fp['query_params'].copy()
        elif fp['query_params']:
            for param, value in fp['query_params'].items():
                if param not in request_kwargs['params']:
                    request_kwargs['params'][param] = value
                    
        return request_kwargs
        
    def _handle_rate_limit(self, response):
        """
        Handle rate limiting with advanced techniques
        
        Args:
            response: API response object
            
        Returns:
            int: Recommended delay in seconds before next request
        """
        # Update rate limit info based on headers
        rate_info = API_STATE['rate_limits'][self.service]
        
        # Check for rate limit headers (different services use different formats)
        headers = response.headers
        reset_time = None
        
        # Extract standard rate limit headers
        if 'X-RateLimit-Limit' in headers:
            rate_info['limit'] = int(headers['X-RateLimit-Limit'])
        if 'X-RateLimit-Remaining' in headers:
            rate_info['remaining'] = int(headers['X-RateLimit-Remaining'])
        if 'X-RateLimit-Reset' in headers:
            reset_timestamp = int(headers['X-RateLimit-Reset'])
            reset_time = datetime.fromtimestamp(reset_timestamp)
            rate_info['reset'] = reset_time
            
        # OpenAI specific rate limit headers
        if 'x-ratelimit-limit-requests' in headers:
            rate_info['limit'] = int(headers['x-ratelimit-limit-requests'])
        if 'x-ratelimit-remaining-requests' in headers:
            rate_info['remaining'] = int(headers['x-ratelimit-remaining-requests'])
        if 'x-ratelimit-reset' in headers:
            reset_time_str = headers['x-ratelimit-reset']
            try:
                reset_time = datetime.strptime(reset_time_str, "%Y-%m-%dT%H:%M:%SZ")
                rate_info['reset'] = reset_time
            except:
                pass
                
        # Handle 429 Too Many Requests
        if response.status_code == 429:
            # Mark that we've detected a rate limit
            self._rate_limit_detected = True
            
            # Increase the detected limit counter
            rate_info['detected_limit'] += 1
            
            # Exponential backoff
            current_backoff = API_STATE['backoff_times'][self.service]
            new_backoff = min(current_backoff * 2, 60)  # Max 60 seconds
            API_STATE['backoff_times'][self.service] = new_backoff
            
            # Check for Retry-After header
            if 'Retry-After' in headers:
                try:
                    retry_after = int(headers['Retry-After'])
                    return max(retry_after, new_backoff)
                except:
                    pass
                    
            # If we have a reset time, calculate delay until then
            if reset_time:
                now = datetime.utcnow()
                if reset_time > now:
                    delay = (reset_time - now).total_seconds() + 1  # Add 1 second buffer
                    return delay
                    
            return new_backoff
            
        # Successful request - if we have remaining count, calculate a delay
        elif response.status_code == 200 and rate_info['remaining'] is not None:
            # Reset backoff on successful request if it was getting high
            if API_STATE['backoff_times'][self.service] > 1.0:
                API_STATE['backoff_times'][self.service] = max(0.5, API_STATE['backoff_times'][self.service] * 0.8)
                
            # If we're running low on remaining requests, add a self-imposed delay
            if rate_info['remaining'] < 10 and rate_info['limit'] and rate_info['limit'] > 0:
                # Calculate a delay based on reset time or use a default
                if reset_time:
                    now = datetime.utcnow()
                    if reset_time > now:
                        total_time_until_reset = (reset_time - now).total_seconds()
                        # Distribute remaining requests over time until reset
                        if rate_info['remaining'] > 0:
                            return total_time_until_reset / rate_info['remaining']
                
                # If we can't calculate a good delay, use a reasonable default
                return 2.0
                
        # Default delay for any other status code
        return API_STATE['backoff_times'][self.service]
        
    def _rotate_api_key(self):
        """Rotate to a backup API key if available"""
        if not self._backup_keys:
            logger.warning(f"No backup API keys available for {self.service}")
            return False
            
        # Move current key to the end of backup keys if it's valid
        if self.api_key:
            self._backup_keys.append(self.api_key)
            
        # Get a new key from the backup keys
        self.api_key = self._backup_keys.pop(0)
        logger.info(f"Rotated to a new API key for {self.service}")
        
        # Store the rotation in persistent storage if available
        if BYPASS_AVAILABLE:
            try:
                key_data = {
                    "current": self.api_key,
                    "backups": self._backup_keys,
                    "rotated_at": str(datetime.utcnow())
                }
                bypass_system.store_persistent_data(f"{self.service}_key_rotation", str(key_data))
            except:
                pass
                
        return True
        
    def _should_retry(self, response, attempt):
        """Determine if we should retry a failed request"""
        # Don't retry beyond max attempts
        if attempt >= 5:
            return False
            
        # Always retry rate limit errors with appropriate delay
        if response.status_code == 429:
            return True
            
        # Retry certain server errors
        if response.status_code in (500, 502, 503, 504):
            return True
            
        # Retry authorization errors only on first attempt, and if we have backup keys
        if response.status_code == 401 and attempt == 1 and self._backup_keys:
            return True
            
        return False
        
    @staticmethod
    def _get_retry_delay(attempt, rate_limit_delay=None):
        """Get a retry delay with exponential backoff and jitter"""
        if rate_limit_delay:
            return rate_limit_delay
            
        # Exponential backoff with jitter
        base_delay = 0.5 * (2 ** attempt)
        jitter = random.uniform(0, 0.5 * base_delay)
        return base_delay + jitter
        
    def request(self, method, endpoint, **kwargs):
        """
        Make an API request with advanced handling
        
        Args:
            method (str): HTTP method ('GET', 'POST', etc.)
            endpoint (str): API endpoint (will be appended to base_url if not a full URL)
            **kwargs: Additional arguments to pass to requests
            
        Returns:
            requests.Response: The API response
            
        Raises:
            Exception: If the request fails after retries
        """
        # Track concurrent calls to prevent overwhelming the API
        self._concurrent_calls += 1
        
        # Construct the full URL if endpoint is not already a complete URL
        if not endpoint.startswith('http'):
            if endpoint.startswith('/'):
                url = f"{self.base_url}{endpoint}"
            else:
                url = f"{self.base_url}/{endpoint}"
        else:
            url = endpoint
            
        # Add authorization if needed
        if self.api_key and 'headers' not in kwargs:
            kwargs['headers'] = {}
            
        if self.api_key and 'headers' in kwargs:
            # Different services use different authorization header formats
            if self.service == 'openai':
                kwargs['headers']['Authorization'] = f"Bearer {self.api_key}"
            elif self.service == 'huggingface':
                kwargs['headers']['Authorization'] = f"Bearer {self.api_key}"
            elif self.service == 'github':
                kwargs['headers']['Authorization'] = f"token {self.api_key}"
            else:
                # Try a standard format as fallback
                kwargs['headers']['X-API-Key'] = self.api_key
                
        # Apply request fingerprinting for randomization
        kwargs = self._apply_fingerprint(kwargs)
        
        # Keep track of call timing
        now = datetime.utcnow()
        API_STATE['calls'][self.service] += 1
        
        # Add adaptive rate limiting if we've made too many requests recently
        if self._last_call_time and self._rate_limit_detected:
            time_since_last = (now - self._last_call_time).total_seconds()
            min_delay = API_STATE['backoff_times'][self.service]
            
            if time_since_last < min_delay:
                sleep_time = min_delay - time_since_last
                time.sleep(sleep_time)
                
        # Record this call time
        self._last_call_time = datetime.utcnow()
        
        response = None
        attempt = 0
        last_error = None
        
        # Main request loop with retries
        while attempt < 5:  # Max 5 attempts
            try:
                # Make the actual request
                response = self.session.request(method, url, **kwargs)
                
                # Check if we need to rotate API key on auth failure
                if response.status_code == 401 and attempt == 0 and self._backup_keys:
                    logger.warning(f"Authentication failed for {self.service}, rotating API key")
                    self._rotate_api_key()
                    
                    # Update authorization header with new key
                    if 'headers' in kwargs:
                        if self.service == 'openai':
                            kwargs['headers']['Authorization'] = f"Bearer {self.api_key}"
                        elif self.service == 'huggingface':
                            kwargs['headers']['Authorization'] = f"Bearer {self.api_key}"
                        elif self.service == 'github':
                            kwargs['headers']['Authorization'] = f"token {self.api_key}"
                        else:
                            kwargs['headers']['X-API-Key'] = self.api_key
                            
                    # Try again with new key
                    attempt += 1
                    continue
                    
                # Check if we need to retry based on response
                if self._should_retry(response, attempt):
                    # Calculate appropriate delay
                    rate_limit_delay = self._handle_rate_limit(response) if response.status_code == 429 else None
                    delay = self._get_retry_delay(attempt, rate_limit_delay)
                    
                    logger.warning(f"{self.service} API request failed with status {response.status_code}. Retrying in {delay:.2f}s")
                    time.sleep(delay)
                    attempt += 1
                    continue
                    
                # If we reach here, we've got a response we'll return
                break
                
            except Exception as e:
                last_error = e
                delay = self._get_retry_delay(attempt)
                logger.warning(f"{self.service} API request failed with error: {str(e)}. Retrying in {delay:.2f}s")
                time.sleep(delay)
                attempt += 1
                
        # Update completion counter
        self._concurrent_calls -= 1
        
        # Handle the final result
        if response is not None:
            # Store call history for analysis
            call_record = {
                'timestamp': datetime.utcnow().isoformat(),
                'method': method,
                'url': url,
                'status_code': response.status_code,
                'attempts': attempt + 1,
                'concurrent_calls': self._concurrent_calls + 1,  # Include this one
                'response_time': (datetime.utcnow() - self._last_call_time).total_seconds()
            }
            self.call_history.append(call_record)
            
            # Trim history if it gets too long
            if len(self.call_history) > 100:
                self.call_history = self.call_history[-100:]
                
            # Update success/error counts
            if 200 <= response.status_code < 300:
                self.success_count += 1
            else:
                self.error_count += 1
                
            # Return the response whether successful or not - caller will handle
            return response
        else:
            # We exhausted all retries with no response
            self.error_count += 1
            if last_error:
                raise last_error
            else:
                raise Exception(f"Failed to get response from {self.service} API after multiple attempts")

    def get(self, endpoint, **kwargs):
        """Convenience method for GET requests"""
        return self.request('GET', endpoint, **kwargs)
        
    def post(self, endpoint, **kwargs):
        """Convenience method for POST requests"""
        return self.request('POST', endpoint, **kwargs)
        
    def put(self, endpoint, **kwargs):
        """Convenience method for PUT requests"""
        return self.request('PUT', endpoint, **kwargs)
        
    def delete(self, endpoint, **kwargs):
        """Convenience method for DELETE requests"""
        return self.request('DELETE', endpoint, **kwargs)
        
    def add_api_key(self, key, make_primary=False):
        """
        Add an API key to the rotation pool
        
        Args:
            key (str): The API key to add
            make_primary (bool): If True, make this the primary key immediately
            
        Returns:
            bool: True if added successfully
        """
        if not key:
            return False
            
        # Check if key is already in rotation
        if key == self.api_key or key in self._backup_keys:
            return False
            
        if make_primary:
            # Make this the primary key and move current to backup
            if self.api_key:
                self._backup_keys.append(self.api_key)
            self.api_key = key
        else:
            # Add to backup keys
            self._backup_keys.append(key)
            
        # Store updated keys if bypass available
        if BYPASS_AVAILABLE:
            try:
                for i, key in enumerate([self.api_key] + self._backup_keys):
                    bypass_system.store_persistent_data(f"{self.service}_api_key_{i}", key)
            except:
                pass
                
        return True
        
    def analyze_performance(self):
        """
        Analyze API performance and detect patterns
        
        Returns:
            dict: Performance metrics and analysis
        """
        if not self.call_history:
            return {
                "calls": 0,
                "success_rate": 0,
                "avg_response_time": 0,
                "rate_limit_hits": 0
            }
            
        # Calculate metrics
        total_calls = len(self.call_history)
        successful_calls = sum(1 for call in self.call_history if 200 <= call['status_code'] < 300)
        success_rate = (successful_calls / total_calls) * 100 if total_calls > 0 else 0
        
        # Response times
        response_times = [call['response_time'] for call in self.call_history]
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        
        # Rate limits
        rate_limit_hits = sum(1 for call in self.call_history if call['status_code'] == 429)
        
        # Attempt distribution
        attempt_counts = {}
        for call in self.call_history:
            attempts = call['attempts']
            attempt_counts[attempts] = attempt_counts.get(attempts, 0) + 1
            
        return {
            "calls": total_calls,
            "success_rate": success_rate,
            "avg_response_time": avg_response_time,
            "rate_limit_hits": rate_limit_hits,
            "attempt_distribution": attempt_counts,
            "detected_rate_limit": API_STATE['rate_limits'][self.service]['detected_limit'],
            "current_backoff": API_STATE['backoff_times'][self.service]
        }

# Initialize API connectors for major services
_api_connectors = {}

def get_api_connector(service_name, api_key=None, base_url=None):
    """
    Get or create an API connector for a service
    
    Args:
        service_name (str): Name of the API service
        api_key (str, optional): API key to use, or None to load from environment
        base_url (str, optional): Base URL to use, or None to use service default
        
    Returns:
        AdvancedAPIConnector: Connector instance for the service
    """
    service = service_name.lower()
    
    # Create new connector if it doesn't exist
    if service not in _api_connectors:
        _api_connectors[service] = AdvancedAPIConnector(service, api_key, base_url)
    elif api_key:  # If a new key is provided, update the existing connector
        _api_connectors[service].add_api_key(api_key, make_primary=True)
        
    return _api_connectors[service]

def openai_api():
    """Get the OpenAI API connector"""
    return get_api_connector('openai')
    
def huggingface_api():
    """Get the Hugging Face API connector"""
    return get_api_connector('huggingface')
    
def github_api():
    """Get the GitHub API connector"""
    return get_api_connector('github')
    
def with_rate_limit_protection(service):
    """
    Decorator to add rate limit protection to a function
    
    Args:
        service (str): The API service to apply protection for
        
    Returns:
        function: Decorated function with rate limit handling
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get or create API connector for this service
            connector = get_api_connector(service)
            
            # Track data about this call
            call_data = {
                'function': func.__name__,
                'args': str(args),
                'kwargs': str(kwargs),
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Add adaptive delay if we've hit rate limits recently
            if connector._rate_limit_detected:
                backoff = API_STATE['backoff_times'][service]
                time.sleep(backoff)
                
            try:
                result = func(*args, **kwargs)
                
                # Store this successful call if bypass is available
                if BYPASS_AVAILABLE:
                    try:
                        call_data['success'] = True
                        bypass_system.store_persistent_data(
                            f"{service}_call_{func.__name__}_{int(time.time())}",
                            str(call_data)
                        )
                    except:
                        pass
                        
                return result
                
            except Exception as e:
                # Check if it's a rate limit error based on error message
                is_rate_limit = False
                error_msg = str(e).lower()
                
                if (
                    'rate' in error_msg and ('limit' in error_msg or 'exceed' in error_msg) or
                    'too many requests' in error_msg or
                    '429' in error_msg
                ):
                    is_rate_limit = True
                    connector._rate_limit_detected = True
                    
                    # Increase backoff
                    API_STATE['backoff_times'][service] = min(
                        API_STATE['backoff_times'][service] * 2,
                        60  # Max 60 seconds
                    )
                    
                # Log the error
                call_data['success'] = False
                call_data['error'] = str(e)
                call_data['is_rate_limit'] = is_rate_limit
                
                # Store failed call for analysis
                if BYPASS_AVAILABLE:
                    try:
                        bypass_system.store_persistent_data(
                            f"{service}_error_{func.__name__}_{int(time.time())}",
                            str(call_data)
                        )
                    except:
                        pass
                        
                # Re-raise the exception
                raise
                
        return wrapper
    return decorator