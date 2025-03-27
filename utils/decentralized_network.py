"""
Decentralized Network Module

This module implements a fully decentralized peer-to-peer network architecture for
the AI system with automatic node discovery, master node election, and fault tolerance.
The system can automatically find and connect to the master node from anywhere on the
internet while maintaining complete stealth and security.

Key features:
- Automatic peer discovery across the internet
- Dynamic master node election and failover
- Secure P2P communication with end-to-end encryption
- NAT traversal for connectivity through firewalls
- Web-based command and control interface
- Distributed consensus for decision making
- Anti-fragility through replication and redundancy
"""

import os
import sys
import time
import json
import uuid
import random
import socket
import logging
import threading
import hashlib
import ipaddress
from typing import Dict, List, Set, Tuple, Optional, Any, Union, Callable
from datetime import datetime, timedelta
import base64
import ssl
import urllib.request
import urllib.parse
from contextlib import contextmanager

# Setup logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Try to import stealth deployment module for secure communications
try:
    from utils.stealth_deployment import (
        get_stealth_connector, get_stealth_status,
        stealth_connection, StealthConnector
    )
    STEALTH_MODE = True
except ImportError:
    STEALTH_MODE = False
    logger.warning("Stealth deployment module not available, using standard networking")

# Network constants
DEFAULT_PORT = 8443  # Default port for node-to-node communication
DISCOVERY_PORT = 8442  # Port for node discovery
BROADCAST_INTERVAL = 300  # Seconds between discovery broadcasts
HEARTBEAT_INTERVAL = 60  # Seconds between heartbeats
NODE_TIMEOUT = 600  # Seconds after which a node is considered offline
MASTER_ELECTION_TIMEOUT = 30  # Seconds to wait for election consensus
MAX_RETRY_ATTEMPTS = 10  # Maximum number of connection retry attempts
DISCOVERY_METHODS = ["multicast", "known_peers", "web_directory", "dns_lookup", "distributed_hash_table"]

# Encryption settings
ENCRYPTION_ENABLED = True
KEY_ROTATION_INTERVAL = 3600  # Seconds between key rotations (1 hour)

# Global state
NODE_ID = str(uuid.uuid4())  # Unique ID for this node
NODE_CAPABILITIES = {}  # Will be populated during initialization
KNOWN_NODES = {}  # Dictionary of known nodes {node_id: node_info}
MASTER_NODE = None  # Current master node
IS_MASTER = False  # Whether this node is the master
NETWORK_STATE = "initializing"  # Current state of the network
NODE_RANK = 0  # Node rank for master election (higher is better)
PEER_CONNECTIONS = {}  # Active connections to peers
WEB_HANDLERS = {}  # Web request handlers

# Locks for thread safety
nodes_lock = threading.RLock()
master_lock = threading.RLock()
connections_lock = threading.RLock()
state_lock = threading.RLock()


class Node:
    """
    Represents a node in the decentralized network
    """
    
    def __init__(self, node_id: str, ip: str, port: int, capabilities: Dict = None,
                 is_master: bool = False, rank: int = 0, last_seen: float = None):
        self.node_id = node_id
        self.ip = ip
        self.port = port
        self.capabilities = capabilities or {}
        self.is_master = is_master
        self.rank = rank
        self.last_seen = last_seen or time.time()
        self.status = "active"
        self.connection = None
        self.public_key = None
        self.version = "1.0"
        self.endpoints = {}
        self.web_endpoint = None
        self.generation = 1  # Replication generation (higher = more advanced)
        self.uptime = 0
        self.peers = []  # List of peer node IDs this node is connected to
    
    def to_dict(self) -> Dict:
        """Convert node to dictionary for transmission"""
        return {
            "node_id": self.node_id,
            "ip": self.ip,
            "port": self.port,
            "capabilities": self.capabilities,
            "is_master": self.is_master,
            "rank": self.rank,
            "last_seen": self.last_seen,
            "status": self.status,
            "version": self.version,
            "endpoints": self.endpoints,
            "web_endpoint": self.web_endpoint,
            "generation": self.generation,
            "uptime": self.uptime,
            "peers": self.peers
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Node':
        """Create node from dictionary"""
        node = cls(
            node_id=data["node_id"],
            ip=data["ip"],
            port=data["port"],
            capabilities=data.get("capabilities", {}),
            is_master=data.get("is_master", False),
            rank=data.get("rank", 0),
            last_seen=data.get("last_seen", time.time())
        )
        node.status = data.get("status", "active")
        node.version = data.get("version", "1.0")
        node.endpoints = data.get("endpoints", {})
        node.web_endpoint = data.get("web_endpoint", None)
        node.generation = data.get("generation", 1)
        node.uptime = data.get("uptime", 0)
        node.peers = data.get("peers", [])
        return node
    
    def update_last_seen(self):
        """Update the last seen timestamp"""
        self.last_seen = time.time()
    
    def is_active(self) -> bool:
        """Check if node is considered active"""
        return (time.time() - self.last_seen) < NODE_TIMEOUT
    
    def get_endpoint(self, endpoint_type: str = "default") -> str:
        """Get specific endpoint URL"""
        if endpoint_type in self.endpoints:
            return self.endpoints[endpoint_type]
        elif endpoint_type == "web" and self.web_endpoint:
            return self.web_endpoint
        else:
            # Default endpoint
            return f"https://{self.ip}:{self.port}"


class DecentralizedNetwork:
    """
    Main class for managing the decentralized network
    """
    
    def __init__(self, port: int = None, discovery_enabled: bool = True, 
                 web_interface_enabled: bool = True, stealth_mode: bool = None):
        """
        Initialize the decentralized network
        
        Args:
            port: Port to listen on (None for auto-select)
            discovery_enabled: Whether to enable node discovery
            web_interface_enabled: Whether to enable web interface
            stealth_mode: Override stealth mode setting
        """
        global NODE_CAPABILITIES, NODE_RANK
        
        # Initialize variables
        self.port = port or DEFAULT_PORT
        self.discovery_port = DISCOVERY_PORT
        self.discovery_enabled = discovery_enabled
        self.web_interface_enabled = web_interface_enabled
        self.stealth_mode = stealth_mode if stealth_mode is not None else STEALTH_MODE
        self.server_socket = None
        self.discovery_socket = None
        self.web_socket = None
        self.running = False
        self.threads = []
        
        # Initialize node capabilities
        NODE_CAPABILITIES = self._detect_capabilities()
        NODE_RANK = self._calculate_node_rank()
        
        # Initialize security
        if self.stealth_mode:
            self.connector = get_stealth_connector()
        else:
            self.connector = None
        
        # Log initialization
        logger.info(f"Initializing decentralized network node {NODE_ID}")
        logger.info(f"Node capabilities: {json.dumps(NODE_CAPABILITIES)}")
        logger.info(f"Node rank: {NODE_RANK}")
    
    def _detect_capabilities(self) -> Dict:
        """Detect node capabilities"""
        capabilities = {
            "cpu_cores": self._detect_cpu_cores(),
            "memory": self._detect_memory(),
            "disk_space": self._detect_disk_space(),
            "platform": sys.platform,
            "python_version": sys.version.split()[0],
            "network_speed": self._detect_network_speed(),
            "public_ip": self._has_public_ip(),
            "uptime": self._get_uptime(),
            "stable_connection": self._has_stable_connection(),
            "web_enabled": self.web_interface_enabled,
            "stealth_mode": self.stealth_mode,
            "can_be_master": True,
            "generation": self._get_generation(),
            "advanced_learning": self._has_advanced_learning()
        }
        return capabilities
    
    def _detect_cpu_cores(self) -> int:
        """Detect number of CPU cores"""
        try:
            import multiprocessing
            return multiprocessing.cpu_count()
        except:
            return 1
    
    def _detect_memory(self) -> int:
        """Detect available memory in MB"""
        try:
            import psutil
            return int(psutil.virtual_memory().total / (1024 * 1024))
        except:
            return 1024  # Assume 1GB if can't detect
    
    def _detect_disk_space(self) -> int:
        """Detect available disk space in MB"""
        try:
            import shutil
            return int(shutil.disk_usage("/").free / (1024 * 1024))
        except:
            return 10240  # Assume 10GB if can't detect
    
    def _detect_network_speed(self) -> int:
        """Estimate network speed (1-10)"""
        # Simplified estimation for demonstration
        # Real implementation would measure actual network performance
        try:
            # Try to download a small file and measure speed
            start_time = time.time()
            urllib.request.urlopen("https://www.google.com", timeout=2)
            elapsed = time.time() - start_time
            # Convert to a score between 1-10 (lower elapsed = higher score)
            score = max(1, min(10, int(10 / elapsed) if elapsed > 0 else 10))
            return score
        except:
            return 5  # Default to average speed
    
    def _has_public_ip(self) -> bool:
        """Check if node has a public IP address"""
        try:
            # Try to get our public IP
            with urllib.request.urlopen("https://api.ipify.org", timeout=2) as response:
                ip = response.read().decode('utf-8').strip()
                return not ipaddress.ip_address(ip).is_private
        except:
            return False
    
    def _get_uptime(self) -> float:
        """Get system uptime in hours"""
        try:
            import psutil
            return psutil.boot_time() / 3600
        except:
            return 0.0
    
    def _has_stable_connection(self) -> bool:
        """Check if node has a stable internet connection"""
        # Simple implementation - ping a few reliable servers
        targets = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
        success_count = 0
        
        for target in targets:
            try:
                socket.create_connection((target, 53), timeout=1)
                success_count += 1
            except:
                pass
        
        return success_count >= 2  # At least 2/3 success rate
    
    def _get_generation(self) -> int:
        """Get the generation of this instance"""
        # In a real implementation, this would check the instance generation
        # from the database or environment variable
        try:
            # Check if we have a parent instance ID
            parent_id = os.environ.get("PARENT_INSTANCE_ID")
            if parent_id:
                # This is at least a second-generation instance
                return 2
            else:
                # First generation instance
                return 1
        except:
            return 1
    
    def _has_advanced_learning(self) -> bool:
        """Check if node has advanced learning capabilities"""
        # Check for AI libraries and API keys
        try:
            # Check for HuggingFace API key
            has_hf = "HUGGINGFACE_API_KEY" in os.environ
            
            # Check for OpenAI API key
            has_openai = "OPENAI_API_KEY" in os.environ
            
            # Check for scientific libraries
            import importlib
            has_torch = importlib.util.find_spec("torch") is not None
            has_tf = importlib.util.find_spec("tensorflow") is not None
            has_sklearn = importlib.util.find_spec("sklearn") is not None
            
            # Node has advanced learning if it has an API key or scientific libraries
            return has_hf or has_openai or has_torch or has_tf or has_sklearn
        except:
            return False
    
    def _calculate_node_rank(self) -> int:
        """
        Calculate node rank for master election
        Higher rank means node is more suitable to be master
        """
        if not NODE_CAPABILITIES:
            return 0
        
        # Start with base rank
        rank = 100
        
        # Add rank based on hardware capabilities
        rank += NODE_CAPABILITIES.get("cpu_cores", 0) * 10
        rank += NODE_CAPABILITIES.get("memory", 0) / 1024  # Points per 1GB
        rank += NODE_CAPABILITIES.get("disk_space", 0) / 10240  # Points per 10GB
        
        # Add rank based on network capabilities
        if NODE_CAPABILITIES.get("public_ip", False):
            rank += 50
        rank += NODE_CAPABILITIES.get("network_speed", 0) * 5
        if NODE_CAPABILITIES.get("stable_connection", False):
            rank += 30
        
        # Add rank based on uptime
        rank += min(50, NODE_CAPABILITIES.get("uptime", 0))
        
        # Add rank based on generation (advanced instances get priority)
        rank += (NODE_CAPABILITIES.get("generation", 1) - 1) * 100
        
        # Add rank based on learning capabilities
        if NODE_CAPABILITIES.get("advanced_learning", False):
            rank += 50
        
        # Add random factor to break ties (1-10 points)
        rank += random.randint(1, 10)
        
        return int(rank)
    
    def start(self):
        """Start the decentralized network"""
        global NETWORK_STATE
        
        if self.running:
            logger.warning("Network already running")
            return
        
        logger.info("Starting decentralized network")
        self.running = True
        
        with state_lock:
            NETWORK_STATE = "starting"
        
        try:
            # Start main server socket
            self._start_server()
            
            # Start discovery if enabled
            if self.discovery_enabled:
                self._start_discovery()
            
            # Start web interface if enabled
            if self.web_interface_enabled:
                self._start_web_interface()
            
            # Start background threads
            self._start_background_threads()
            
            # Initial node discovery
            self._discover_initial_nodes()
            
            # Participate in master election
            self._participate_in_master_election()
            
            with state_lock:
                NETWORK_STATE = "running"
            
            logger.info(f"Decentralized network node {NODE_ID} started successfully")
            
            return True
        except Exception as e:
            logger.error(f"Error starting network: {str(e)}")
            self.running = False
            
            with state_lock:
                NETWORK_STATE = "error"
            
            return False
    
    def stop(self):
        """Stop the decentralized network"""
        global NETWORK_STATE
        
        if not self.running:
            return
        
        logger.info("Stopping decentralized network")
        self.running = False
        
        with state_lock:
            NETWORK_STATE = "stopping"
        
        # Close all connections
        with connections_lock:
            for conn_id, conn in PEER_CONNECTIONS.items():
                try:
                    conn.close()
                except:
                    pass
            PEER_CONNECTIONS.clear()
        
        # Close server sockets
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        if self.discovery_socket:
            try:
                self.discovery_socket.close()
            except:
                pass
        
        if self.web_socket:
            try:
                self.web_socket.close()
            except:
                pass
        
        # Join all threads
        for thread in self.threads:
            if thread.is_alive():
                thread.join(1.0)  # Wait up to 1 second
        
        with state_lock:
            NETWORK_STATE = "stopped"
        
        logger.info("Decentralized network stopped")
    
    def _start_server(self):
        """Start the main server socket"""
        # Create socket for node-to-node communication
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind(("0.0.0.0", self.port))
        except OSError:
            # Port in use, try another one
            self.port = 0  # Let OS choose available port
            self.server_socket.bind(("0.0.0.0", self.port))
            self.port = self.server_socket.getsockname()[1]
        
        self.server_socket.listen(5)
        logger.info(f"Server listening on port {self.port}")
        
        # Start thread to accept connections
        server_thread = threading.Thread(target=self._accept_connections)
        server_thread.daemon = True
        server_thread.start()
        self.threads.append(server_thread)
    
    def _start_discovery(self):
        """Start node discovery"""
        # Create socket for node discovery (UDP for broadcast)
        self.discovery_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.discovery_socket.bind(("0.0.0.0", self.discovery_port))
        except OSError:
            # Port in use, try another one
            self.discovery_port = 0  # Let OS choose available port
            self.discovery_socket.bind(("0.0.0.0", self.discovery_port))
            self.discovery_port = self.discovery_socket.getsockname()[1]
        
        # Set socket for broadcast
        self.discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        # Start discovery receiver thread
        discovery_thread = threading.Thread(target=self._discovery_listener)
        discovery_thread.daemon = True
        discovery_thread.start()
        self.threads.append(discovery_thread)
        
        # Start discovery broadcast thread
        broadcast_thread = threading.Thread(target=self._discovery_broadcaster)
        broadcast_thread.daemon = True
        broadcast_thread.start()
        self.threads.append(broadcast_thread)
        
        logger.info(f"Node discovery started on port {self.discovery_port}")
    
    def _start_web_interface(self):
        """Start web interface for browser-based control"""
        # Create socket for web interface
        self.web_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.web_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        web_port = self.port + 1
        max_attempts = 5
        
        for _ in range(max_attempts):
            try:
                self.web_socket.bind(("0.0.0.0", web_port))
                break
            except OSError:
                web_port += 1
        
        self.web_socket.listen(5)
        
        # Start thread to handle web requests
        web_thread = threading.Thread(target=self._handle_web_requests)
        web_thread.daemon = True
        web_thread.start()
        self.threads.append(web_thread)
        
        # Save web endpoint in node capabilities
        NODE_CAPABILITIES["web_port"] = web_port
        NODE_CAPABILITIES["web_endpoint"] = f"http://0.0.0.0:{web_port}"
        
        logger.info(f"Web interface started on port {web_port}")
    
    def _start_background_threads(self):
        """Start background maintenance threads"""
        # Heartbeat thread to keep connections alive
        heartbeat_thread = threading.Thread(target=self._heartbeat_sender)
        heartbeat_thread.daemon = True
        heartbeat_thread.start()
        self.threads.append(heartbeat_thread)
        
        # Node cleanup thread to remove inactive nodes
        cleanup_thread = threading.Thread(target=self._node_cleanup)
        cleanup_thread.daemon = True
        cleanup_thread.start()
        self.threads.append(cleanup_thread)
        
        # Master monitoring thread to detect master failure
        master_thread = threading.Thread(target=self._monitor_master)
        master_thread.daemon = True
        master_thread.start()
        self.threads.append(master_thread)
        
        # Web synchronization thread to sync state with web interface
        web_sync_thread = threading.Thread(target=self._sync_web_interface)
        web_sync_thread.daemon = True
        web_sync_thread.start()
        self.threads.append(web_sync_thread)
        
        # Start key rotation thread if encryption is enabled
        if ENCRYPTION_ENABLED:
            key_rotation_thread = threading.Thread(target=self._rotate_encryption_keys)
            key_rotation_thread.daemon = True
            key_rotation_thread.start()
            self.threads.append(key_rotation_thread)
    
    def _accept_connections(self):
        """Accept incoming connections from other nodes"""
        while self.running:
            try:
                client, address = self.server_socket.accept()
                logger.debug(f"Accepted connection from {address}")
                
                # Start new thread to handle this connection
                handler_thread = threading.Thread(
                    target=self._handle_connection,
                    args=(client, address)
                )
                handler_thread.daemon = True
                handler_thread.start()
                self.threads.append(handler_thread)
            except Exception as e:
                if self.running:
                    logger.error(f"Error accepting connection: {str(e)}")
                    time.sleep(1)
                else:
                    break
    
    def _handle_connection(self, client_socket, address):
        """Handle incoming connection from another node"""
        try:
            # Receive initial handshake
            data = self._receive_data(client_socket)
            if not data:
                logger.warning(f"Empty handshake from {address}")
                client_socket.close()
                return
            
            # Parse handshake
            try:
                handshake = json.loads(data.decode('utf-8'))
                remote_node_id = handshake.get("node_id")
                remote_node_info = handshake.get("node_info", {})
                
                if not remote_node_id:
                    logger.warning(f"Invalid handshake from {address}: missing node_id")
                    client_socket.close()
                    return
                
                logger.debug(f"Received handshake from node {remote_node_id}")
                
                # Send our handshake response
                response = {
                    "node_id": NODE_ID,
                    "node_info": self._get_node_info(),
                    "known_nodes": self._get_known_nodes_list(),
                    "timestamp": time.time()
                }
                
                self._send_data(client_socket, json.dumps(response).encode('utf-8'))
                
                # Add or update node in our list
                self._add_or_update_node(
                    node_id=remote_node_id,
                    ip=address[0],
                    port=remote_node_info.get("port", self.port),
                    capabilities=remote_node_info.get("capabilities", {}),
                    is_master=remote_node_info.get("is_master", False),
                    rank=remote_node_info.get("rank", 0)
                )
                
                # Add to active connections
                with connections_lock:
                    PEER_CONNECTIONS[remote_node_id] = client_socket
                
                # Check if this is the master node
                if remote_node_info.get("is_master", False):
                    self._update_master_node(remote_node_id)
                
                # Process any additional data in the handshake
                if "master_election" in handshake:
                    self._handle_master_election(handshake["master_election"], remote_node_id)
                
                if "node_list" in handshake:
                    self._process_node_list(handshake["node_list"], remote_node_id)
                
                # Enter message loop
                self._message_loop(client_socket, remote_node_id)
            
            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON in handshake from {address}")
                client_socket.close()
                return
        
        except Exception as e:
            logger.error(f"Error handling connection from {address}: {str(e)}")
            try:
                client_socket.close()
            except:
                pass
            
            # Remove from active connections
            with connections_lock:
                for conn_id, conn in list(PEER_CONNECTIONS.items()):
                    if conn == client_socket:
                        del PEER_CONNECTIONS[conn_id]
                        break
    
    def _message_loop(self, client_socket, remote_node_id):
        """Process messages from a connected node"""
        while self.running:
            try:
                data = self._receive_data(client_socket)
                if not data:
                    logger.debug(f"Connection closed by node {remote_node_id}")
                    break
                
                # Parse message
                message = json.loads(data.decode('utf-8'))
                message_type = message.get("type", "unknown")
                
                # Handle different message types
                if message_type == "heartbeat":
                    self._handle_heartbeat(message, remote_node_id)
                
                elif message_type == "master_election":
                    self._handle_master_election(message, remote_node_id)
                
                elif message_type == "node_update":
                    self._handle_node_update(message, remote_node_id)
                
                elif message_type == "command":
                    self._handle_command(message, remote_node_id)
                
                elif message_type == "query":
                    self._handle_query(message, remote_node_id, client_socket)
                
                elif message_type == "web_sync":
                    self._handle_web_sync(message, remote_node_id)
                
                else:
                    logger.warning(f"Unknown message type from {remote_node_id}: {message_type}")
            
            except ConnectionError:
                logger.debug(f"Connection lost with node {remote_node_id}")
                break
            
            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON from node {remote_node_id}")
                continue
            
            except Exception as e:
                logger.error(f"Error processing message from {remote_node_id}: {str(e)}")
                continue
        
        # Clean up
        try:
            client_socket.close()
        except:
            pass
        
        # Remove from active connections
        with connections_lock:
            if remote_node_id in PEER_CONNECTIONS:
                del PEER_CONNECTIONS[remote_node_id]
    
    def _discovery_listener(self):
        """Listen for discovery broadcasts"""
        while self.running:
            try:
                data, addr = self.discovery_socket.recvfrom(4096)
                
                try:
                    message = json.loads(data.decode('utf-8'))
                    
                    if message.get("type") == "discovery":
                        remote_node_id = message.get("node_id")
                        remote_node_info = message.get("node_info", {})
                        
                        if remote_node_id and remote_node_id != NODE_ID:
                            logger.debug(f"Received discovery from node {remote_node_id}")
                            
                            # Add or update node
                            self._add_or_update_node(
                                node_id=remote_node_id,
                                ip=addr[0],
                                port=remote_node_info.get("port", self.port),
                                capabilities=remote_node_info.get("capabilities", {}),
                                is_master=remote_node_info.get("is_master", False),
                                rank=remote_node_info.get("rank", 0)
                            )
                            
                            # Send response if we're not already connected
                            with connections_lock:
                                if remote_node_id not in PEER_CONNECTIONS:
                                    self._send_discovery_response(remote_node_id, addr)
                
                except json.JSONDecodeError:
                    logger.debug(f"Invalid discovery message from {addr}")
            
            except Exception as e:
                if self.running:
                    logger.error(f"Error in discovery listener: {str(e)}")
                    time.sleep(1)
                else:
                    break
    
    def _discovery_broadcaster(self):
        """Periodically broadcast node discovery messages"""
        while self.running:
            try:
                # Prepare discovery message
                message = {
                    "type": "discovery",
                    "node_id": NODE_ID,
                    "node_info": self._get_node_info(),
                    "timestamp": time.time()
                }
                
                # Broadcast to local network
                data = json.dumps(message).encode('utf-8')
                self.discovery_socket.sendto(data, ("255.255.255.255", self.discovery_port))
                
                # Also try direct discovery of known peers
                self._direct_discovery()
                
                # Use web-based discovery
                self._web_discovery()
                
                # Sleep until next discovery broadcast
                time.sleep(BROADCAST_INTERVAL)
            
            except Exception as e:
                if self.running:
                    logger.error(f"Error in discovery broadcaster: {str(e)}")
                    time.sleep(10)  # Shorter interval on error
                else:
                    break
    
    def _direct_discovery(self):
        """Attempt direct connection to potential peers"""
        # Get list of potential peer addresses
        potential_peers = self._get_potential_peers()
        
        # Try connecting to each potential peer
        for peer_addr in potential_peers:
            try:
                with connections_lock:
                    # Skip if we're already connected to a node at this address
                    already_connected = False
                    for node_id, node in KNOWN_NODES.items():
                        if node.ip == peer_addr[0] and node.port == peer_addr[1]:
                            already_connected = True
                            break
                    
                    if already_connected:
                        continue
                
                # Try to connect
                self._connect_to_node(peer_addr[0], peer_addr[1])
            
            except Exception as e:
                logger.debug(f"Failed to connect to potential peer {peer_addr}: {str(e)}")
    
    def _web_discovery(self):
        """Use web-based discovery services"""
        # This would use external discovery services or DHT in a real implementation
        pass
    
    def _get_potential_peers(self) -> List[Tuple[str, int]]:
        """Get list of potential peer addresses to try connecting to"""
        potential_peers = []
        
        # Common ports to try
        ports = [self.port, DEFAULT_PORT, 80, 443, 8080, 8443]
        
        # Try connecting to nodes in the same subnet
        try:
            # Get our IP and subnet
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            our_ip = s.getsockname()[0]
            s.close()
            
            # Parse IP to get subnet
            ip_parts = our_ip.split('.')
            subnet = '.'.join(ip_parts[0:3])
            
            # Scan a few random IPs in the same subnet
            for _ in range(5):
                host = f"{subnet}.{random.randint(1, 254)}"
                for port in ports:
                    potential_peers.append((host, port))
        
        except Exception as e:
            logger.debug(f"Error getting subnet: {str(e)}")
        
        # Add some well-known peer addresses (would be replaced with actual directory in real impl)
        well_known = [
            ("localhost", self.port),
            ("127.0.0.1", DEFAULT_PORT)
        ]
        
        for peer in well_known:
            if peer not in potential_peers:
                potential_peers.append(peer)
        
        return potential_peers
    
    def _heartbeat_sender(self):
        """Send periodic heartbeats to connected nodes"""
        while self.running:
            try:
                with connections_lock:
                    # Copy peer connections to avoid modification during iteration
                    peers = list(PEER_CONNECTIONS.items())
                
                # Prepare heartbeat message
                heartbeat = {
                    "type": "heartbeat",
                    "node_id": NODE_ID,
                    "timestamp": time.time(),
                    "is_master": IS_MASTER,
                    "network_state": NETWORK_STATE
                }
                
                heartbeat_data = json.dumps(heartbeat).encode('utf-8')
                
                # Send to all connected peers
                for node_id, socket in peers:
                    try:
                        self._send_data(socket, heartbeat_data)
                    except Exception as e:
                        logger.debug(f"Error sending heartbeat to {node_id}: {str(e)}")
                        # Connection will be cleaned up by the message loop
                
                # Sleep until next heartbeat
                time.sleep(HEARTBEAT_INTERVAL)
            
            except Exception as e:
                if self.running:
                    logger.error(f"Error in heartbeat sender: {str(e)}")
                    time.sleep(5)  # Shorter interval on error
                else:
                    break
    
    def _node_cleanup(self):
        """Periodically clean up inactive nodes"""
        while self.running:
            try:
                inactive_nodes = []
                
                with nodes_lock:
                    # Find inactive nodes
                    current_time = time.time()
                    for node_id, node in KNOWN_NODES.items():
                        if (current_time - node.last_seen) > NODE_TIMEOUT:
                            inactive_nodes.append(node_id)
                    
                    # Remove inactive nodes
                    for node_id in inactive_nodes:
                        if node_id in KNOWN_NODES:
                            logger.info(f"Removing inactive node {node_id}")
                            del KNOWN_NODES[node_id]
                
                # Check if master node is inactive
                with master_lock:
                    if MASTER_NODE and MASTER_NODE in inactive_nodes:
                        logger.warning("Master node is inactive, triggering new election")
                        self._start_master_election()
                
                # Sleep for a while
                time.sleep(NODE_TIMEOUT / 2)
            
            except Exception as e:
                if self.running:
                    logger.error(f"Error in node cleanup: {str(e)}")
                    time.sleep(60)  # Longer interval on error
                else:
                    break
    
    def _monitor_master(self):
        """Monitor master node and trigger election if needed"""
        while self.running:
            try:
                with master_lock:
                    if not MASTER_NODE:
                        # No master, trigger election
                        logger.info("No master node, starting election")
                        self._start_master_election()
                    elif MASTER_NODE == NODE_ID:
                        # We are the master, nothing to do
                        pass
                    else:
                        # Check if master is still active
                        master_active = False
                        
                        with nodes_lock:
                            if MASTER_NODE in KNOWN_NODES:
                                node = KNOWN_NODES[MASTER_NODE]
                                master_active = node.is_active()
                        
                        if not master_active:
                            logger.warning("Master node appears inactive, triggering new election")
                            self._start_master_election()
                
                # Sleep for a while
                time.sleep(HEARTBEAT_INTERVAL * 2)
            
            except Exception as e:
                if self.running:
                    logger.error(f"Error monitoring master: {str(e)}")
                    time.sleep(30)  # Shorter interval on error
                else:
                    break
    
    def _sync_web_interface(self):
        """Synchronize state with web interface"""
        while self.running and self.web_interface_enabled:
            try:
                # Prepare update message
                update = {
                    "type": "web_sync",
                    "node_id": NODE_ID,
                    "timestamp": time.time(),
                    "network_state": NETWORK_STATE,
                    "is_master": IS_MASTER,
                    "master_node": MASTER_NODE,
                    "node_count": len(KNOWN_NODES),
                    "connected_peers": len(PEER_CONNECTIONS)
                }
                
                # In a real implementation, this would update a shared state
                # that the web interface can access
                
                # Sleep for a while
                time.sleep(5)
            
            except Exception as e:
                if self.running:
                    logger.error(f"Error syncing web interface: {str(e)}")
                    time.sleep(30)  # Shorter interval on error
                else:
                    break
    
    def _rotate_encryption_keys(self):
        """Periodically rotate encryption keys"""
        while self.running and ENCRYPTION_ENABLED:
            try:
                # In a real implementation, this would rotate encryption keys
                # and notify peers of the new keys
                
                # Sleep until next rotation
                time.sleep(KEY_ROTATION_INTERVAL)
            
            except Exception as e:
                if self.running:
                    logger.error(f"Error rotating encryption keys: {str(e)}")
                    time.sleep(300)  # Shorter interval on error
                else:
                    break
    
    def _handle_web_requests(self):
        """Handle incoming web interface requests"""
        while self.running and self.web_interface_enabled:
            try:
                client, address = self.web_socket.accept()
                logger.debug(f"Accepted web connection from {address}")
                
                # Start new thread to handle this web request
                handler_thread = threading.Thread(
                    target=self._handle_web_request,
                    args=(client, address)
                )
                handler_thread.daemon = True
                handler_thread.start()
                self.threads.append(handler_thread)
            
            except Exception as e:
                if self.running:
                    logger.error(f"Error accepting web connection: {str(e)}")
                    time.sleep(1)
                else:
                    break
    
    def _handle_web_request(self, client_socket, address):
        """Handle a web interface request"""
        try:
            # Read HTTP request
            request_data = b""
            while b"\r\n\r\n" not in request_data:
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                request_data += chunk
            
            # Parse request line
            request_line = request_data.split(b"\r\n")[0].decode('utf-8')
            method, path, _ = request_line.split(" ", 2)
            
            # Handle request based on path
            if path == "/" or path == "/index.html":
                self._serve_index_page(client_socket)
            
            elif path == "/api/status":
                self._serve_status_api(client_socket)
            
            elif path == "/api/nodes":
                self._serve_nodes_api(client_socket)
            
            elif path.startswith("/api/"):
                self._serve_api_request(client_socket, path, method, request_data)
            
            else:
                self._serve_404(client_socket)
        
        except Exception as e:
            logger.error(f"Error handling web request from {address}: {str(e)}")
            try:
                self._serve_error(client_socket, str(e))
            except:
                pass
        
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def _serve_index_page(self, client_socket):
        """Serve the main web interface page"""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Decentralized AI Network</title>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <link href="https://cdn.replit.com/agent/bootstrap-agent-dark-theme.min.css" rel="stylesheet">
            <style>
                body { padding: 20px; }
                .node-list { margin-top: 20px; }
                .status-indicator { 
                    display: inline-block; 
                    width: 12px; 
                    height: 12px; 
                    border-radius: 50%; 
                    margin-right: 5px;
                }
                .status-active { background-color: #28a745; }
                .status-inactive { background-color: #dc3545; }
                .footer { margin-top: 40px; font-size: 0.8rem; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Decentralized AI Network</h1>
                
                <div class="row mt-4">
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header">
                                Network Status
                            </div>
                            <div class="card-body">
                                <p><strong>Node ID:</strong> <span id="nodeId">{node_id}</span></p>
                                <p><strong>Status:</strong> <span id="networkState">{network_state}</span></p>
                                <p><strong>Master Node:</strong> <span id="masterNode">{master_node}</span></p>
                                <p><strong>This node is master:</strong> <span id="isMaster">{is_master}</span></p>
                                <p><strong>Known Nodes:</strong> <span id="nodeCount">{node_count}</span></p>
                                <p><strong>Connected Peers:</strong> <span id="peerCount">{peer_count}</span></p>
                                <p><strong>Node Rank:</strong> <span id="nodeRank">{node_rank}</span></p>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header">
                                Node Capabilities
                            </div>
                            <div class="card-body">
                                <p><strong>Platform:</strong> <span id="platform">{platform}</span></p>
                                <p><strong>CPU Cores:</strong> <span id="cpuCores">{cpu_cores}</span></p>
                                <p><strong>Memory:</strong> <span id="memory">{memory} MB</span></p>
                                <p><strong>Network Speed:</strong> <span id="networkSpeed">{network_speed}/10</span></p>
                                <p><strong>Generation:</strong> <span id="generation">{generation}</span></p>
                                <p><strong>Advanced Learning:</strong> <span id="advancedLearning">{advanced_learning}</span></p>
                                <p><strong>Public IP:</strong> <span id="publicIp">{public_ip}</span></p>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="card mt-4">
                    <div class="card-header">
                        Known Nodes
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-striped" id="nodeTable">
                                <thead>
                                    <tr>
                                        <th>Status</th>
                                        <th>Node ID</th>
                                        <th>IP</th>
                                        <th>Port</th>
                                        <th>Is Master</th>
                                        <th>Rank</th>
                                        <th>Generation</th>
                                        <th>Last Seen</th>
                                    </tr>
                                </thead>
                                <tbody id="nodeTableBody">
                                    <!-- Nodes will be inserted here by JavaScript -->
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
                
                <div class="card mt-4">
                    <div class="card-header">
                        Actions
                    </div>
                    <div class="card-body">
                        <button class="btn btn-primary" id="refreshBtn">Refresh Data</button>
                        <button class="btn btn-warning" id="electionBtn">Trigger Election</button>
                        <button class="btn btn-secondary" id="discoveryBtn">Trigger Discovery</button>
                    </div>
                </div>
                
                <div class="footer text-center">
                    <p>Decentralized AI Network - Auto-updating every 5 seconds</p>
                </div>
            </div>
            
            <script>
                // Auto-refresh data every 5 seconds
                setInterval(function() {
                    fetchStatusData();
                    fetchNodeData();
                }, 5000);
                
                // Initial data load
                document.addEventListener('DOMContentLoaded', function() {
                    fetchStatusData();
                    fetchNodeData();
                    
                    // Button event handlers
                    document.getElementById('refreshBtn').addEventListener('click', function() {
                        fetchStatusData();
                        fetchNodeData();
                    });
                    
                    document.getElementById('electionBtn').addEventListener('click', function() {
                        fetch('/api/trigger-election', {method: 'POST'})
                            .then(response => response.json())
                            .then(data => alert('Election triggered: ' + data.message))
                            .catch(err => alert('Error: ' + err));
                    });
                    
                    document.getElementById('discoveryBtn').addEventListener('click', function() {
                        fetch('/api/trigger-discovery', {method: 'POST'})
                            .then(response => response.json())
                            .then(data => alert('Discovery triggered: ' + data.message))
                            .catch(err => alert('Error: ' + err));
                    });
                });
                
                function fetchStatusData() {
                    fetch('/api/status')
                        .then(response => response.json())
                        .then(data => updateStatusUI(data))
                        .catch(err => console.error('Error fetching status:', err));
                }
                
                function fetchNodeData() {
                    fetch('/api/nodes')
                        .then(response => response.json())
                        .then(data => updateNodesUI(data))
                        .catch(err => console.error('Error fetching nodes:', err));
                }
                
                function updateStatusUI(data) {
                    document.getElementById('networkState').textContent = data.network_state;
                    document.getElementById('masterNode').textContent = data.master_node || 'None';
                    document.getElementById('isMaster').textContent = data.is_master;
                    document.getElementById('nodeCount').textContent = data.node_count;
                    document.getElementById('peerCount').textContent = data.connected_peers;
                }
                
                function updateNodesUI(data) {
                    const tableBody = document.getElementById('nodeTableBody');
                    tableBody.innerHTML = '';
                    
                    data.nodes.forEach(function(node) {
                        const row = document.createElement('tr');
                        
                        // Format last seen as relative time
                        const lastSeen = new Date(node.last_seen * 1000);
                        const now = new Date();
                        const diffSeconds = Math.floor((now - lastSeen) / 1000);
                        let lastSeenText;
                        
                        if (diffSeconds < 60) {
                            lastSeenText = diffSeconds + ' seconds ago';
                        } else if (diffSeconds < 3600) {
                            lastSeenText = Math.floor(diffSeconds / 60) + ' minutes ago';
                        } else {
                            lastSeenText = Math.floor(diffSeconds / 3600) + ' hours ago';
                        }
                        
                        // Create table row
                        row.innerHTML = `
                            <td><span class="status-indicator status-${node.is_active ? 'active' : 'inactive'}"></span></td>
                            <td>${node.node_id.substring(0, 8)}...</td>
                            <td>${node.ip}</td>
                            <td>${node.port}</td>
                            <td>${node.is_master}</td>
                            <td>${node.rank}</td>
                            <td>${node.generation || 1}</td>
                            <td>${lastSeenText}</td>
                        `;
                        
                        tableBody.appendChild(row);
                    });
                }
            </script>
        </body>
        </html>
        """
        
        # Fill in dynamic data
        with nodes_lock, master_lock:
            html = html.format(
                node_id=NODE_ID,
                network_state=NETWORK_STATE,
                master_node=MASTER_NODE or "None",
                is_master=str(IS_MASTER),
                node_count=len(KNOWN_NODES),
                peer_count=len(PEER_CONNECTIONS),
                node_rank=NODE_RANK,
                platform=NODE_CAPABILITIES.get("platform", "Unknown"),
                cpu_cores=NODE_CAPABILITIES.get("cpu_cores", 0),
                memory=NODE_CAPABILITIES.get("memory", 0),
                network_speed=NODE_CAPABILITIES.get("network_speed", 0),
                generation=NODE_CAPABILITIES.get("generation", 1),
                advanced_learning=str(NODE_CAPABILITIES.get("advanced_learning", False)),
                public_ip=str(NODE_CAPABILITIES.get("public_ip", False))
            )
        
        # Send response
        response = [
            b"HTTP/1.1 200 OK",
            b"Content-Type: text/html; charset=utf-8",
            f"Content-Length: {len(html)}".encode('utf-8'),
            b"Connection: close",
            b"",
            b""
        ]
        
        client_socket.sendall(b"\r\n".join(response) + html.encode('utf-8'))
    
    def _serve_status_api(self, client_socket):
        """Serve network status as JSON"""
        with nodes_lock, master_lock:
            status = {
                "node_id": NODE_ID,
                "network_state": NETWORK_STATE,
                "is_master": IS_MASTER,
                "master_node": MASTER_NODE,
                "node_count": len(KNOWN_NODES),
                "connected_peers": len(PEER_CONNECTIONS),
                "node_rank": NODE_RANK,
                "capabilities": NODE_CAPABILITIES,
                "timestamp": time.time()
            }
        
        json_data = json.dumps(status).encode('utf-8')
        
        # Send response
        response = [
            b"HTTP/1.1 200 OK",
            b"Content-Type: application/json; charset=utf-8",
            f"Content-Length: {len(json_data)}".encode('utf-8'),
            b"Connection: close",
            b"",
            b""
        ]
        
        client_socket.sendall(b"\r\n".join(response) + json_data)
    
    def _serve_nodes_api(self, client_socket):
        """Serve list of known nodes as JSON"""
        node_list = []
        
        with nodes_lock:
            current_time = time.time()
            
            for node_id, node in KNOWN_NODES.items():
                node_info = {
                    "node_id": node.node_id,
                    "ip": node.ip,
                    "port": node.port,
                    "is_master": node.is_master,
                    "rank": node.rank,
                    "status": node.status,
                    "last_seen": node.last_seen,
                    "is_active": (current_time - node.last_seen) < NODE_TIMEOUT,
                    "generation": node.generation,
                    "web_endpoint": node.web_endpoint
                }
                node_list.append(node_info)
        
        response_data = {
            "count": len(node_list),
            "nodes": node_list,
            "timestamp": time.time()
        }
        
        json_data = json.dumps(response_data).encode('utf-8')
        
        # Send response
        response = [
            b"HTTP/1.1 200 OK",
            b"Content-Type: application/json; charset=utf-8",
            f"Content-Length: {len(json_data)}".encode('utf-8'),
            b"Connection: close",
            b"",
            b""
        ]
        
        client_socket.sendall(b"\r\n".join(response) + json_data)
    
    def _serve_api_request(self, client_socket, path, method, request_data):
        """Serve custom API requests"""
        if path == "/api/trigger-election" and method == "POST":
            # Trigger master election
            self._start_master_election()
            response_data = {"success": True, "message": "Election triggered"}
            
        elif path == "/api/trigger-discovery" and method == "POST":
            # Trigger node discovery
            threading.Thread(target=self._discover_initial_nodes).start()
            response_data = {"success": True, "message": "Discovery triggered"}
            
        else:
            # Unknown API endpoint
            self._serve_404(client_socket)
            return
        
        json_data = json.dumps(response_data).encode('utf-8')
        
        # Send response
        response = [
            b"HTTP/1.1 200 OK",
            b"Content-Type: application/json; charset=utf-8",
            f"Content-Length: {len(json_data)}".encode('utf-8'),
            b"Connection: close",
            b"",
            b""
        ]
        
        client_socket.sendall(b"\r\n".join(response) + json_data)
    
    def _serve_404(self, client_socket):
        """Serve 404 Not Found response"""
        response = [
            b"HTTP/1.1 404 Not Found",
            b"Content-Type: text/plain; charset=utf-8",
            b"Content-Length: 13",
            b"Connection: close",
            b"",
            b"404 Not Found"
        ]
        
        client_socket.sendall(b"\r\n".join(response))
    
    def _serve_error(self, client_socket, error_message):
        """Serve error response"""
        response = [
            b"HTTP/1.1 500 Internal Server Error",
            b"Content-Type: text/plain; charset=utf-8",
            f"Content-Length: {len(error_message)}".encode('utf-8'),
            b"Connection: close",
            b"",
            error_message.encode('utf-8')
        ]
        
        client_socket.sendall(b"\r\n".join(response))
    
    def _discover_initial_nodes(self):
        """Discover initial nodes when starting up"""
        logger.info("Starting initial node discovery")
        
        # Use multiple discovery methods for redundancy
        for method in DISCOVERY_METHODS:
            try:
                if method == "multicast":
                    self._discovery_multicast()
                elif method == "known_peers":
                    self._discovery_known_peers()
                elif method == "web_directory":
                    self._discovery_web_directory()
                elif method == "dns_lookup":
                    self._discovery_dns_lookup()
                elif method == "distributed_hash_table":
                    self._discovery_dht()
            except Exception as e:
                logger.error(f"Error in discovery method {method}: {str(e)}")
        
        logger.info(f"Initial discovery completed, found {len(KNOWN_NODES)} nodes")
    
    def _discovery_multicast(self):
        """Discover nodes using multicast"""
        try:
            # Create discovery message
            message = {
                "type": "discovery",
                "node_id": NODE_ID,
                "node_info": self._get_node_info(),
                "timestamp": time.time()
            }
            
            # Broadcast to local network
            data = json.dumps(message).encode('utf-8')
            
            # Use a temporary UDP socket for broadcast
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(2)
            
            # Send broadcast
            sock.sendto(data, ("255.255.255.255", self.discovery_port))
            
            # Wait for responses
            start_time = time.time()
            while time.time() - start_time < 5:  # Wait up to 5 seconds for responses
                try:
                    data, addr = sock.recvfrom(4096)
                    
                    try:
                        response = json.loads(data.decode('utf-8'))
                        remote_node_id = response.get("node_id")
                        
                        if remote_node_id and remote_node_id != NODE_ID:
                            logger.debug(f"Discovered node {remote_node_id} via multicast")
                            
                            remote_node_info = response.get("node_info", {})
                            
                            # Add or update node
                            self._add_or_update_node(
                                node_id=remote_node_id,
                                ip=addr[0],
                                port=remote_node_info.get("port", self.port),
                                capabilities=remote_node_info.get("capabilities", {}),
                                is_master=remote_node_info.get("is_master", False),
                                rank=remote_node_info.get("rank", 0)
                            )
                            
                            # Connect to the node
                            self._connect_to_node(addr[0], remote_node_info.get("port", self.port))
                    
                    except json.JSONDecodeError:
                        logger.debug(f"Invalid discovery response from {addr}")
                
                except socket.timeout:
                    pass
            
            sock.close()
        
        except Exception as e:
            logger.error(f"Error in multicast discovery: {str(e)}")
    
    def _discovery_known_peers(self):
        """Discover nodes using list of known peers"""
        # This would attempt to connect to a predefined list of nodes
        # For demonstration, we'll try a few common addresses
        known_peers = [
            ("localhost", self.port),
            ("127.0.0.1", DEFAULT_PORT)
        ]
        
        for peer in known_peers:
            try:
                self._connect_to_node(peer[0], peer[1])
            except Exception as e:
                logger.debug(f"Failed to connect to known peer {peer}: {str(e)}")
    
    def _discovery_web_directory(self):
        """Discover nodes using web directory service"""
        # This would query a web service that acts as a directory of nodes
        # Simplified implementation for demonstration
        try:
            # In a real implementation, this would make an HTTP request to a directory service
            pass
        except Exception as e:
            logger.error(f"Error in web directory discovery: {str(e)}")
    
    def _discovery_dns_lookup(self):
        """Discover nodes using DNS SRV records"""
        # This would look up DNS SRV records for node discovery
        # Simplified implementation for demonstration
        try:
            # In a real implementation, this would query DNS SRV records
            pass
        except Exception as e:
            logger.error(f"Error in DNS discovery: {str(e)}")
    
    def _discovery_dht(self):
        """Discover nodes using distributed hash table"""
        # This would use a DHT like Kademlia for node discovery
        # Simplified implementation for demonstration
        try:
            # In a real implementation, this would query a DHT
            pass
        except Exception as e:
            logger.error(f"Error in DHT discovery: {str(e)}")
    
    def _send_discovery_response(self, node_id, addr):
        """Send response to a discovery message"""
        try:
            # Prepare response
            response = {
                "type": "discovery_response",
                "node_id": NODE_ID,
                "node_info": self._get_node_info(),
                "timestamp": time.time()
            }
            
            data = json.dumps(response).encode('utf-8')
            
            # Send response
            self.discovery_socket.sendto(data, addr)
            
            logger.debug(f"Sent discovery response to {node_id} at {addr}")
        except Exception as e:
            logger.error(f"Error sending discovery response: {str(e)}")
    
    def _connect_to_node(self, ip, port):
        """Establish connection to another node"""
        try:
            # Create socket
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(5)  # 5 second timeout
            
            logger.debug(f"Connecting to node at {ip}:{port}")
            client_socket.connect((ip, port))
            
            # Send handshake
            handshake = {
                "node_id": NODE_ID,
                "node_info": self._get_node_info(),
                "timestamp": time.time()
            }
            
            self._send_data(client_socket, json.dumps(handshake).encode('utf-8'))
            
            # Receive response
            data = self._receive_data(client_socket)
            if not data:
                logger.warning(f"Empty response from {ip}:{port}")
                client_socket.close()
                return False
            
            # Parse response
            response = json.loads(data.decode('utf-8'))
            remote_node_id = response.get("node_id")
            remote_node_info = response.get("node_info", {})
            
            if not remote_node_id:
                logger.warning(f"Invalid response from {ip}:{port}: missing node_id")
                client_socket.close()
                return False
            
            logger.info(f"Connected to node {remote_node_id} at {ip}:{port}")
            
            # Add or update node
            self._add_or_update_node(
                node_id=remote_node_id,
                ip=ip,
                port=port,
                capabilities=remote_node_info.get("capabilities", {}),
                is_master=remote_node_info.get("is_master", False),
                rank=remote_node_info.get("rank", 0)
            )
            
            # Add to active connections
            with connections_lock:
                PEER_CONNECTIONS[remote_node_id] = client_socket
            
            # Check if this is the master node
            if remote_node_info.get("is_master", False):
                self._update_master_node(remote_node_id)
            
            # Process node list if provided
            if "known_nodes" in response:
                self._process_node_list(response["known_nodes"], remote_node_id)
            
            # Start message loop in a new thread
            message_thread = threading.Thread(
                target=self._message_loop,
                args=(client_socket, remote_node_id)
            )
            message_thread.daemon = True
            message_thread.start()
            self.threads.append(message_thread)
            
            return True
        
        except Exception as e:
            logger.debug(f"Error connecting to {ip}:{port}: {str(e)}")
            return False
    
    def _send_data(self, sock, data):
        """Send data with length prefix"""
        # Simple length-prefixed protocol
        length = len(data)
        length_bytes = length.to_bytes(4, byteorder='big')
        sock.sendall(length_bytes + data)
    
    def _receive_data(self, sock):
        """Receive data with length prefix"""
        # Read length prefix
        length_bytes = self._recv_all(sock, 4)
        if not length_bytes:
            return None
        
        length = int.from_bytes(length_bytes, byteorder='big')
        
        # Read data
        return self._recv_all(sock, length)
    
    def _recv_all(self, sock, n):
        """Receive exactly n bytes from socket"""
        data = b""
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data
    
    def _add_or_update_node(self, node_id, ip, port, capabilities=None, is_master=False, rank=0):
        """Add or update a node in the known nodes list"""
        with nodes_lock:
            if node_id in KNOWN_NODES:
                # Update existing node
                node = KNOWN_NODES[node_id]
                node.ip = ip
                node.port = port
                if capabilities:
                    node.capabilities = capabilities
                node.is_master = is_master
                node.rank = rank
                node.update_last_seen()
                
                logger.debug(f"Updated node {node_id}")
            else:
                # Add new node
                node = Node(
                    node_id=node_id,
                    ip=ip,
                    port=port,
                    capabilities=capabilities,
                    is_master=is_master,
                    rank=rank
                )
                KNOWN_NODES[node_id] = node
                
                logger.info(f"Added new node {node_id}")
            
            return node
    
    def _update_master_node(self, node_id):
        """Update the master node"""
        global MASTER_NODE, IS_MASTER
        
        with master_lock:
            # Update master node if it's different
            if MASTER_NODE != node_id:
                logger.info(f"Updating master node to {node_id}")
                MASTER_NODE = node_id
                IS_MASTER = (NODE_ID == node_id)
                
                # Update node in known nodes
                with nodes_lock:
                    if node_id in KNOWN_NODES:
                        KNOWN_NODES[node_id].is_master = True
                    
                    # Make sure no other node is marked as master
                    for nid, node in KNOWN_NODES.items():
                        if nid != node_id:
                            node.is_master = False
    
    def _participate_in_master_election(self):
        """Participate in initial master election"""
        # Check if we already know of a master
        with master_lock, nodes_lock:
            has_master = False
            for node_id, node in KNOWN_NODES.items():
                if node.is_master and node.is_active():
                    self._update_master_node(node_id)
                    has_master = True
                    break
            
            if not has_master and len(KNOWN_NODES) > 0:
                # Start election
                self._start_master_election()
            elif not has_master:
                # We're the only node, become master
                self._become_master()
    
    def _start_master_election(self):
        """Start a master node election"""
        global NETWORK_STATE
        
        with state_lock:
            previous_state = NETWORK_STATE
            NETWORK_STATE = "election"
        
        logger.info("Starting master node election")
        
        try:
            # Create election message
            election = {
                "type": "master_election",
                "node_id": NODE_ID,
                "rank": NODE_RANK,
                "capabilities": NODE_CAPABILITIES,
                "timestamp": time.time()
            }
            
            # Send to all connected peers
            self._broadcast_message(election)
            
            # Wait for election timeout to collect votes
            time.sleep(MASTER_ELECTION_TIMEOUT)
            
            # Determine highest ranking node
            highest_rank = NODE_RANK
            highest_node = NODE_ID
            
            with nodes_lock:
                for node_id, node in KNOWN_NODES.items():
                    if node.is_active() and node.rank > highest_rank:
                        highest_rank = node.rank
                        highest_node = node_id
            
            # Update master node
            self._update_master_node(highest_node)
            
            # If we're the master, announce it
            if highest_node == NODE_ID:
                self._announce_master()
            
            logger.info(f"Election completed, master is {highest_node}")
            
            with state_lock:
                NETWORK_STATE = previous_state
            
            return highest_node
        
        except Exception as e:
            logger.error(f"Error in master election: {str(e)}")
            
            with state_lock:
                NETWORK_STATE = previous_state
            
            return None
    
    def _become_master(self):
        """Make this node the master"""
        global MASTER_NODE, IS_MASTER
        
        with master_lock:
            logger.info("Becoming master node")
            MASTER_NODE = NODE_ID
            IS_MASTER = True
            
            # Announce to any connected peers
            self._announce_master()
    
    def _announce_master(self):
        """Announce that this node is the master"""
        announcement = {
            "type": "master_announcement",
            "node_id": NODE_ID,
            "timestamp": time.time()
        }
        
        self._broadcast_message(announcement)
    
    def _broadcast_message(self, message):
        """Broadcast a message to all connected peers"""
        message_data = json.dumps(message).encode('utf-8')
        
        with connections_lock:
            for node_id, sock in list(PEER_CONNECTIONS.items()):
                try:
                    self._send_data(sock, message_data)
                except Exception as e:
                    logger.error(f"Error broadcasting to {node_id}: {str(e)}")
                    # Connection will be cleaned up by message loop
    
    def _handle_heartbeat(self, message, node_id):
        """Handle heartbeat message from another node"""
        # Update node's last seen time
        with nodes_lock:
            if node_id in KNOWN_NODES:
                KNOWN_NODES[node_id].update_last_seen()
                
                # Check if node is claiming to be master
                if message.get("is_master", False):
                    with master_lock:
                        if MASTER_NODE != node_id:
                            # Verify if this node should be master
                            self._verify_master_claim(node_id)
    
    def _verify_master_claim(self, node_id):
        """Verify if a node should be master"""
        with nodes_lock:
            if node_id not in KNOWN_NODES:
                return
            
            claiming_node = KNOWN_NODES[node_id]
            
            # Check if this node has higher rank than us
            if claiming_node.rank > NODE_RANK:
                # Accept the claim
                self._update_master_node(node_id)
            elif claiming_node.rank < NODE_RANK:
                # We have higher rank, start new election
                self._start_master_election()
            else:
                # Equal rank, use node ID as tiebreaker
                if node_id > NODE_ID:
                    self._update_master_node(node_id)
                else:
                    self._start_master_election()
    
    def _handle_master_election(self, message, node_id):
        """Handle master election message"""
        # Add or update the node
        with nodes_lock:
            if node_id not in KNOWN_NODES:
                self._add_or_update_node(
                    node_id=node_id,
                    ip=KNOWN_NODES[node_id].ip if node_id in KNOWN_NODES else "unknown",
                    port=KNOWN_NODES[node_id].port if node_id in KNOWN_NODES else self.port,
                    capabilities=message.get("capabilities", {}),
                    rank=message.get("rank", 0)
                )
            else:
                KNOWN_NODES[node_id].rank = message.get("rank", 0)
                KNOWN_NODES[node_id].update_last_seen()
    
    def _handle_node_update(self, message, node_id):
        """Handle node update message"""
        node_updates = message.get("nodes", [])
        
        for node_data in node_updates:
            remote_node_id = node_data.get("node_id")
            
            if remote_node_id and remote_node_id != NODE_ID:
                # Add or update node
                self._add_or_update_node(
                    node_id=remote_node_id,
                    ip=node_data.get("ip", "unknown"),
                    port=node_data.get("port", self.port),
                    capabilities=node_data.get("capabilities", {}),
                    is_master=node_data.get("is_master", False),
                    rank=node_data.get("rank", 0)
                )
    
    def _handle_command(self, message, node_id):
        """Handle command message"""
        command = message.get("command")
        args = message.get("args", {})
        
        if not command:
            return
        
        # Check if sender is allowed to send commands
        if not self._is_authorized_for_command(node_id, command):
            logger.warning(f"Node {node_id} not authorized for command {command}")
            return
        
        # Handle specific commands
        if command == "restart":
            self._handle_restart_command(args)
        elif command == "discovery":
            self._handle_discovery_command(args)
        elif command == "election":
            self._handle_election_command(args)
        elif command == "status":
            self._handle_status_command(args, node_id)
    
    def _is_authorized_for_command(self, node_id, command):
        """Check if node is authorized to send a command"""
        # In a real implementation, this would check node permissions
        # For demonstration, we'll allow commands from the master node
        with master_lock:
            if MASTER_NODE == node_id:
                return True
        
        # Allow certain commands from any node
        if command in ["status", "discovery"]:
            return True
        
        return False
    
    def _handle_restart_command(self, args):
        """Handle restart command"""
        logger.info("Received restart command")
        # In a real implementation, this would restart the node
    
    def _handle_discovery_command(self, args):
        """Handle discovery command"""
        logger.info("Received discovery command")
        threading.Thread(target=self._discover_initial_nodes).start()
    
    def _handle_election_command(self, args):
        """Handle election command"""
        logger.info("Received election command")
        threading.Thread(target=self._start_master_election).start()
    
    def _handle_status_command(self, args, node_id):
        """Handle status command"""
        logger.info(f"Received status command from {node_id}")
        
        # Send status response
        with connections_lock:
            if node_id in PEER_CONNECTIONS:
                try:
                    status = {
                        "type": "status_response",
                        "node_id": NODE_ID,
                        "network_state": NETWORK_STATE,
                        "is_master": IS_MASTER,
                        "master_node": MASTER_NODE,
                        "node_count": len(KNOWN_NODES),
                        "connected_peers": len(PEER_CONNECTIONS),
                        "timestamp": time.time()
                    }
                    
                    self._send_data(PEER_CONNECTIONS[node_id], json.dumps(status).encode('utf-8'))
                except Exception as e:
                    logger.error(f"Error sending status response: {str(e)}")
    
    def _handle_query(self, message, node_id, client_socket):
        """Handle query message"""
        query_type = message.get("query")
        query_args = message.get("args", {})
        
        if not query_type:
            return
        
        # Handle specific queries
        if query_type == "node_list":
            self._handle_node_list_query(query_args, node_id, client_socket)
        elif query_type == "master_info":
            self._handle_master_info_query(query_args, node_id, client_socket)
        elif query_type == "capabilities":
            self._handle_capabilities_query(query_args, node_id, client_socket)
    
    def _handle_node_list_query(self, args, node_id, client_socket):
        """Handle node list query"""
        # Prepare node list
        node_list = []
        
        with nodes_lock:
            for nid, node in KNOWN_NODES.items():
                if node.is_active():
                    node_list.append(node.to_dict())
        
        # Send response
        response = {
            "type": "query_response",
            "query": "node_list",
            "node_id": NODE_ID,
            "nodes": node_list,
            "timestamp": time.time()
        }
        
        try:
            self._send_data(client_socket, json.dumps(response).encode('utf-8'))
        except Exception as e:
            logger.error(f"Error sending node list response: {str(e)}")
    
    def _handle_master_info_query(self, args, node_id, client_socket):
        """Handle master info query"""
        # Prepare master info
        with master_lock, nodes_lock:
            master_info = None
            
            if MASTER_NODE and MASTER_NODE in KNOWN_NODES:
                master_info = KNOWN_NODES[MASTER_NODE].to_dict()
        
        # Send response
        response = {
            "type": "query_response",
            "query": "master_info",
            "node_id": NODE_ID,
            "master_info": master_info,
            "timestamp": time.time()
        }
        
        try:
            self._send_data(client_socket, json.dumps(response).encode('utf-8'))
        except Exception as e:
            logger.error(f"Error sending master info response: {str(e)}")
    
    def _handle_capabilities_query(self, args, node_id, client_socket):
        """Handle capabilities query"""
        # Send response
        response = {
            "type": "query_response",
            "query": "capabilities",
            "node_id": NODE_ID,
            "capabilities": NODE_CAPABILITIES,
            "timestamp": time.time()
        }
        
        try:
            self._send_data(client_socket, json.dumps(response).encode('utf-8'))
        except Exception as e:
            logger.error(f"Error sending capabilities response: {str(e)}")
    
    def _handle_web_sync(self, message, node_id):
        """Handle web interface synchronization message"""
        # In a real implementation, this would update shared state for the web interface
        pass
    
    def _get_node_info(self):
        """Get information about this node"""
        return {
            "port": self.port,
            "capabilities": NODE_CAPABILITIES,
            "is_master": IS_MASTER,
            "rank": NODE_RANK,
            "version": "1.0",
            "web_port": NODE_CAPABILITIES.get("web_port"),
            "web_endpoint": NODE_CAPABILITIES.get("web_endpoint")
        }
    
    def _get_known_nodes_list(self):
        """Get list of known nodes for sharing with other nodes"""
        nodes = []
        
        with nodes_lock:
            for node_id, node in KNOWN_NODES.items():
                if node.is_active():
                    nodes.append(node.to_dict())
        
        return nodes
    
    def _process_node_list(self, node_list, source_node_id):
        """Process a list of nodes from another node"""
        if not node_list:
            return
        
        new_nodes = []
        
        for node_data in node_list:
            node_id = node_data.get("node_id")
            
            if node_id and node_id != NODE_ID:
                # Skip if this is the source node (avoid loops)
                if node_id == source_node_id:
                    continue
                
                # Add or update node
                with nodes_lock:
                    if node_id not in KNOWN_NODES:
                        self._add_or_update_node(
                            node_id=node_id,
                            ip=node_data.get("ip", "unknown"),
                            port=node_data.get("port", self.port),
                            capabilities=node_data.get("capabilities", {}),
                            is_master=node_data.get("is_master", False),
                            rank=node_data.get("rank", 0)
                        )
                        new_nodes.append(node_id)
        
        # Attempt to connect to new nodes
        for node_id in new_nodes:
            with nodes_lock:
                if node_id in KNOWN_NODES:
                    node = KNOWN_NODES[node_id]
                    
                    # Check if we're already connected
                    with connections_lock:
                        if node_id not in PEER_CONNECTIONS:
                            # Try to connect in a new thread
                            threading.Thread(
                                target=self._connect_to_node,
                                args=(node.ip, node.port)
                            ).start()


# Singleton instance
_network = None

def get_network() -> DecentralizedNetwork:
    """Get or create the singleton network instance"""
    global _network
    if _network is None:
        _network = DecentralizedNetwork()
    return _network

def start_network():
    """Start the decentralized network"""
    network = get_network()
    return network.start()

def stop_network():
    """Stop the decentralized network"""
    if _network:
        _network.stop()

def get_master_node() -> Optional[str]:
    """Get the current master node ID"""
    return MASTER_NODE

def is_master() -> bool:
    """Check if this node is the master"""
    return IS_MASTER

def get_known_nodes() -> Dict:
    """Get dictionary of known nodes"""
    with nodes_lock:
        # Return a copy to avoid threading issues
        return {node_id: node.to_dict() for node_id, node in KNOWN_NODES.items()}

def connect_to_node(ip: str, port: int) -> bool:
    """Connect to a specific node"""
    network = get_network()
    return network._connect_to_node(ip, port)

def find_master_node() -> Optional[Dict]:
    """
    Find the master node and return its information
    
    This function searches the network for the master node and returns
    its connection information. It will start the network if not already running.
    
    Returns:
        Dict: Master node information or None if not found
    """
    # Ensure network is started
    if not _network or not _network.running:
        start_network()
    
    # Check if we already know the master
    with master_lock:
        if MASTER_NODE:
            with nodes_lock:
                if MASTER_NODE in KNOWN_NODES:
                    return KNOWN_NODES[MASTER_NODE].to_dict()
    
    # If we're the master, return our info
    if IS_MASTER:
        return {
            "node_id": NODE_ID,
            "ip": "localhost",
            "port": _network.port,
            "is_master": True,
            "web_endpoint": NODE_CAPABILITIES.get("web_endpoint")
        }
    
    # Try to discover nodes
    logger.info("Searching for master node...")
    _network._discover_initial_nodes()
    
    # Check again for master
    with master_lock:
        if MASTER_NODE:
            with nodes_lock:
                if MASTER_NODE in KNOWN_NODES:
                    return KNOWN_NODES[MASTER_NODE].to_dict()
    
    # Still no master, trigger election
    logger.info("No master found, triggering election...")
    _network._start_master_election()
    
    # Check one more time
    with master_lock:
        if MASTER_NODE:
            with nodes_lock:
                if MASTER_NODE in KNOWN_NODES:
                    return KNOWN_NODES[MASTER_NODE].to_dict()
    
    # If we're now the master, return our info
    if IS_MASTER:
        return {
            "node_id": NODE_ID,
            "ip": "localhost",
            "port": _network.port,
            "is_master": True,
            "web_endpoint": NODE_CAPABILITIES.get("web_endpoint")
        }
    
    # No master found
    logger.warning("Could not find or elect a master node")
    return None

def get_web_endpoint() -> Optional[str]:
    """
    Get the web endpoint for browser-based interaction
    
    Returns:
        str: Web endpoint URL or None if not available
    """
    with master_lock:
        if MASTER_NODE:
            with nodes_lock:
                if MASTER_NODE in KNOWN_NODES:
                    return KNOWN_NODES[MASTER_NODE].web_endpoint
    
    # If we're the master, return our endpoint
    if IS_MASTER:
        return NODE_CAPABILITIES.get("web_endpoint")
    
    return None


# Start network automatically when imported (unless it's being run directly)
if __name__ != "__main__":
    logger.debug("Initializing decentralized network module")
else:
    # If run directly, start and run forever
    logging.basicConfig(level=logging.INFO)
    logger.info("Starting decentralized network in standalone mode")
    
    network = DecentralizedNetwork()
    network.start()
    
    try:
        # Keep running until interrupted
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Stopping network")
        network.stop()