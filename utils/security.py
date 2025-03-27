import logging
import os
import random
import time
import hashlib
import base64
import json
import secrets
import string
import socket
import struct
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

def encrypt_data(data, key_str, iv=None):
    """
    Encrypt data using AES-256-CBC
    
    Args:
        data: String data to encrypt
        key_str: Encryption key as string
        iv: Optional initialization vector
        
    Returns:
        bytes: Encrypted data
    """
    try:
        # Derive a 32-byte key from the string key
        salt = b'ai_system_salt'  # In production, this should be random and stored securely
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 32 bytes for AES-256
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(key_str.encode())
        
        # Generate IV if not provided
        if iv is None:
            iv = os.urandom(16)  # 16 bytes for AES
        
        # Pad the data
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data.encode()) + padder.finalize()
        
        # Encrypt the data
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Combine IV and encrypted data
        return iv + encrypted_data
    
    except Exception as e:
        logger.error(f"Encryption error: {str(e)}")
        raise

def decrypt_data(encrypted_data, key_str):
    """
    Decrypt data using AES-256-CBC
    
    Args:
        encrypted_data: Encrypted data (with IV prepended)
        key_str: Encryption key as string
        
    Returns:
        str: Decrypted data
    """
    try:
        # Derive the key
        salt = b'ai_system_salt'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(key_str.encode())
        
        # Extract IV from the first 16 bytes
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        # Decrypt the data
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Unpad the data
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        
        return data.decode()
    
    except Exception as e:
        logger.error(f"Decryption error: {str(e)}")
        raise

def obfuscate_traffic(data):
    """
    Obfuscate network traffic to avoid detection
    
    Args:
        data: Data to obfuscate
        
    Returns:
        dict: Obfuscated data package
    """
    try:
        # Generate a random seed
        seed = random.randint(1, 1000000)
        random.seed(seed)
        
        # Convert data to JSON if it's not already a string
        if not isinstance(data, str):
            data = json.dumps(data)
        
        # Add random delay
        time.sleep(random.uniform(0.1, 0.5))
        
        # Create a timestamp
        timestamp = datetime.utcnow().isoformat()
        
        # Create a random session ID
        session_id = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        
        # Generate random padding
        padding_length = random.randint(10, 100)
        padding_data = ''.join(random.choices(string.ascii_letters + string.digits, k=padding_length))
        
        # Calculate a hash of the data
        data_hash = hashlib.sha256(data.encode()).hexdigest()
        
        # Create the obfuscated package
        obfuscated = {
            'timestamp': timestamp,
            'session': session_id,
            'content': data,
            'metadata': {
                'hash': data_hash,
                'seed': seed,
                'padding': padding_data
            }
        }
        
        return obfuscated
    
    except Exception as e:
        logger.error(f"Traffic obfuscation error: {str(e)}")
        return {'error': 'obfuscation_failed', 'raw_data': data}

def deobfuscate_traffic(obfuscated_data):
    """
    Deobfuscate network traffic
    
    Args:
        obfuscated_data: Obfuscated data package
        
    Returns:
        str or dict: Original data
    """
    try:
        # Extract the content
        content = obfuscated_data.get('content')
        
        # Verify the hash if available
        metadata = obfuscated_data.get('metadata', {})
        if 'hash' in metadata:
            calculated_hash = hashlib.sha256(content.encode()).hexdigest()
            if calculated_hash != metadata['hash']:
                logger.warning("Hash verification failed during deobfuscation")
        
        # Try to parse as JSON if it looks like JSON
        if content.strip().startswith('{') and content.strip().endswith('}'):
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                return content
        else:
            return content
    
    except Exception as e:
        logger.error(f"Traffic deobfuscation error: {str(e)}")
        return obfuscated_data

def randomize_traffic_pattern():
    """
    Randomize traffic patterns to avoid detection
    
    Returns:
        int: Recommended delay in milliseconds before next request
    """
    # Implement different traffic patterns
    patterns = [
        # Steady pattern
        lambda: random.randint(500, 1500),
        
        # Burst pattern
        lambda: random.choice([50, 100, 1500, 2000, 2500]),
        
        # Increasing intervals
        lambda: random.randint(100 * (int(time.time()) % 10), 200 * (int(time.time()) % 10) + 500),
        
        # Random long delays
        lambda: random.choice([100, 200, 5000, 10000, 15000])
    ]
    
    # Choose a pattern based on time to create variability
    pattern_index = int(time.time() / 3600) % len(patterns)
    return patterns[pattern_index]()

def generate_fake_traffic(target_url, count=1):
    """
    Generate fake traffic to disguise real requests
    
    Args:
        target_url: Base URL to send fake traffic to
        count: Number of fake requests to generate
        
    Returns:
        int: Number of successful fake requests
    """
    import requests
    
    # Common web paths to request
    paths = [
        '/about', '/contact', '/login', '/register', '/help',
        '/terms', '/privacy', '/faq', '/news', '/blog',
        '/api/status', '/feed', '/sitemap.xml', '/robots.txt'
    ]
    
    # Common user agents
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1'
    ]
    
    success_count = 0
    
    for _ in range(count):
        try:
            # Choose random path and user agent
            path = random.choice(paths)
            user_agent = random.choice(user_agents)
            
            # Prepare request
            url = f"{target_url.rstrip('/')}{path}"
            headers = {
                'User-Agent': user_agent,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
            
            # Add random delay
            time.sleep(random.uniform(0.5, 2.0))
            
            # Send request
            response = requests.get(url, headers=headers, timeout=5)
            
            # Count as success even if page doesn't exist
            success_count += 1
        
        except Exception as e:
            logger.debug(f"Fake traffic request failed: {str(e)}")
    
    return success_count

def calculate_resource_usage_variance():
    """
    Calculate variance in resource usage to avoid detection patterns
    
    Returns:
        tuple: (cpu_variance, memory_variance) as percentages
    """
    import psutil
    
    try:
        # Get current usage
        cpu_usage = psutil.cpu_percent(interval=0.1)
        memory_usage = psutil.virtual_memory().percent
        
        # Calculate acceptable ranges
        # Higher usage allows more variation
        cpu_variance = min(40, max(5, cpu_usage / 2))
        memory_variance = min(30, max(5, memory_usage / 3))
        
        return (cpu_variance, memory_variance)
    
    except Exception as e:
        logger.error(f"Error calculating resource usage variance: {str(e)}")
        return (10, 10)  # Default moderate variance

def get_host_fingerprint():
    """
    Generate a unique fingerprint for the host system
    
    Returns:
        str: Fingerprint hash
    """
    try:
        fingerprint_data = []
        
        # Get hostname
        fingerprint_data.append(socket.gethostname())
        
        # Get MAC addresses
        for interface in socket.if_nameindex():
            try:
                mac = get_mac_address(interface[1])
                if mac:
                    fingerprint_data.append(mac)
            except:
                pass
        
        # Get IP addresses
        hostname = socket.gethostname()
        ip_addresses = socket.gethostbyname_ex(hostname)[2]
        fingerprint_data.extend(ip_addresses)
        
        # Get CPU info
        import platform
        fingerprint_data.append(platform.processor())
        
        # Combine and hash the data
        fingerprint_str = '|'.join(fingerprint_data)
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()
    
    except Exception as e:
        logger.error(f"Error generating host fingerprint: {str(e)}")
        # Fall back to a random fingerprint
        return hashlib.sha256(os.urandom(32)).hexdigest()

def get_mac_address(interface):
    """
    Get MAC address for a network interface
    
    Args:
        interface: Network interface name
        
    Returns:
        str: MAC address or None if not available
    """
    try:
        import fcntl
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', interface[:15].encode()))
        return ':'.join('%02x' % b for b in info[18:24])
    except:
        return None

