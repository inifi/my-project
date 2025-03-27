"""
Platform Adapter Module

This module provides a cross-platform abstraction layer that allows the AI system
to adapt to different runtime environments and deploy without errors. It handles
platform-specific differences and provides graceful degradation of features when
necessary.

Features:
- Runtime environment detection
- Resource availability checking
- Feature degradation management
- Cross-platform compatibility layer
- Deployment health monitoring
- Recovery mechanisms
"""

import os
import sys
import platform
import json
import logging
import tempfile
import shutil
import socket
import subprocess
import importlib
import inspect
import traceback
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union, Callable

# Setup logging
logger = logging.getLogger(__name__)

# Import configuration
try:
    from config import (
        PLATFORM_COMPATIBILITY,
        DEPLOYMENT_SETTINGS,
        ENVIRONMENT,
        INSTANCE_ID,
        INSTANCE_TYPE
    )
except ImportError:
    # Default values if config unavailable
    logger.warning("Could not import configuration, using defaults")
    PLATFORM_COMPATIBILITY = {
        "auto_detect_platform": True,
        "graceful_degradation": True,
        "cross_platform_abstraction": True,
        "health_monitoring": True,
        "auto_provisioning": True,
        "zero_config_networking": True,
        "platform_optimizations": True,
        "auto_recovery": True,
        "container_support": True,
        "cloud_integration": True
    }
    DEPLOYMENT_SETTINGS = {
        "fallbacks": {
            "database": ["sqlite", "json_file", "memory"],
            "networking": ["direct", "proxy", "p2p"],
            "storage": ["local", "memory", "distributed"],
            "compute": ["local", "distributed", "offload"]
        },
        "required_resources": {
            "container": {
                "min_memory": "256MB",
                "min_cpu": 0.25,
                "storage": "50MB"
            },
            "cloud": {
                "min_memory": "512MB",
                "min_cpu": 0.5,
                "storage": "100MB"
            },
            "server": {
                "min_memory": "1GB",
                "min_cpu": 1,
                "storage": "200MB"
            },
            "notebook": {
                "min_memory": "512MB",
                "min_cpu": 0.5,
                "storage": "50MB"
            }
        }
    }
    ENVIRONMENT = "development"
    INSTANCE_ID = "unknown"
    INSTANCE_TYPE = "unknown"

# Global variable to track platform adaptation status
PLATFORM_STATUS = {
    "platform": "unknown",
    "detected_features": {},
    "available_resources": {},
    "degraded_features": [],
    "optimized_features": [],
    "deployment_issues": [],
    "recovery_attempts": 0,
    "health_status": "unknown",
    "adaptation_level": 0,  # 0: none, 1: minimal, 2: partial, 3: full
    "last_health_check": None,
    "initialization_time": datetime.utcnow().isoformat()
}

# Registry for feature implementations with fallbacks
FEATURE_REGISTRY = {}

class PlatformAdapter:
    """
    Main adapter class for platform-specific functionality
    """
    
    def __init__(self):
        """Initialize the platform adapter"""
        self.platform = detect_platform()
        self.resources = check_available_resources()
        self.compatibility = check_compatibility()
        self.health_monitor = HealthMonitor() if PLATFORM_COMPATIBILITY.get("health_monitoring") else None
        
        # Update global status
        global PLATFORM_STATUS
        PLATFORM_STATUS["platform"] = self.platform
        PLATFORM_STATUS["available_resources"] = self.resources
        PLATFORM_STATUS["adaptation_level"] = 1
        
        logger.info(f"Platform adapter initialized for: {self.platform}")
        
        # Start health monitoring if enabled
        if self.health_monitor:
            self.health_monitor.start()
            
        # Apply automatic platform optimizations if enabled
        if PLATFORM_COMPATIBILITY.get("platform_optimizations"):
            self.apply_optimizations()
    
    def adapt_feature(self, feature_name: str, *args, **kwargs) -> Any:
        """
        Adapt a feature to the current platform with graceful degradation
        
        Args:
            feature_name: The name of the feature
            *args: Arguments to pass to the feature implementation
            **kwargs: Keyword arguments to pass to the feature implementation
            
        Returns:
            Feature result or fallback result
        """
        if feature_name not in FEATURE_REGISTRY:
            logger.warning(f"Feature {feature_name} not registered")
            return None
            
        implementations = FEATURE_REGISTRY[feature_name]
        
        # Try implementations in order until one works
        errors = []
        for impl_name, impl_func in implementations:
            try:
                logger.debug(f"Trying implementation: {impl_name} for feature: {feature_name}")
                return impl_func(*args, **kwargs)
            except Exception as e:
                error_info = {
                    "implementation": impl_name,
                    "error": str(e),
                    "traceback": traceback.format_exc()
                }
                errors.append(error_info)
                logger.debug(f"Implementation {impl_name} failed: {str(e)}")
                continue
        
        # If we got here, all implementations failed
        if PLATFORM_COMPATIBILITY.get("graceful_degradation"):
            # Record degraded feature
            if feature_name not in PLATFORM_STATUS["degraded_features"]:
                PLATFORM_STATUS["degraded_features"].append(feature_name)
                
            # Try to recover if auto-recovery is enabled
            if PLATFORM_COMPATIBILITY.get("auto_recovery"):
                recovery_result = self.attempt_recovery(feature_name, errors)
                if recovery_result:
                    return recovery_result
            
            logger.warning(f"All implementations of feature {feature_name} failed, returning degraded result")
            return self.generate_degraded_response(feature_name)
        else:
            # Just raise the last error if graceful degradation is disabled
            raise RuntimeError(f"Feature {feature_name} failed on all implementations: {errors[-1]['error']}")
    
    def apply_optimizations(self) -> None:
        """Apply platform-specific optimizations"""
        logger.info(f"Applying platform-specific optimizations for: {self.platform}")
        
        optimizations = []
        
        # Apply different optimizations based on platform
        if self.platform == "container":
            # Optimize for containerized environment
            optimizations.append("memory_conservation")
            optimizations.append("reduced_disk_io")
            optimizations.append("container_networking")
            
        elif self.platform == "cloud":
            # Optimize for cloud environment
            optimizations.append("elastic_scaling")
            optimizations.append("distributed_state")
            optimizations.append("cloud_native_apis")
            
        elif self.platform == "notebook":
            # Optimize for notebook environment
            optimizations.append("interactive_response")
            optimizations.append("visualization_support")
            optimizations.append("cell_execution")
            
        elif self.platform == "server":
            # Optimize for server environment
            optimizations.append("daemon_mode")
            optimizations.append("service_integration")
            optimizations.append("persistent_storage")
            
        # Apply common optimizations
        optimizations.append("error_recovery")
        optimizations.append("adaptive_logging")
        
        # Record optimized features
        PLATFORM_STATUS["optimized_features"] = optimizations
        PLATFORM_STATUS["adaptation_level"] = 3
        
        logger.info(f"Applied {len(optimizations)} platform-specific optimizations")
    
    def attempt_recovery(self, feature_name: str, errors: List[Dict]) -> Any:
        """
        Attempt to recover from feature failures
        
        Args:
            feature_name: The name of the failed feature
            errors: List of errors encountered
            
        Returns:
            Recovery result or None if recovery failed
        """
        logger.info(f"Attempting recovery for feature: {feature_name}")
        PLATFORM_STATUS["recovery_attempts"] += 1
        
        # Add recovery logic here based on the feature and errors
        # This is a simplified example
        
        recovery_strategies = {
            "database_access": self._recover_database,
            "network_connection": self._recover_network,
            "file_access": self._recover_filesystem,
            "api_call": self._recover_api,
            "resource_allocation": self._recover_resources
        }
        
        # Determine if we have a recovery strategy for this feature
        feature_category = feature_name.split('_')[0] if '_' in feature_name else feature_name
        recovery_func = recovery_strategies.get(feature_category)
        
        if recovery_func:
            try:
                return recovery_func(feature_name, errors)
            except Exception as e:
                logger.error(f"Recovery attempt failed: {str(e)}")
                return None
        
        return None
    
    def _recover_database(self, feature_name: str, errors: List[Dict]) -> Any:
        """Recover from database access failures"""
        # Example: try alternative database connection methods
        for fallback in DEPLOYMENT_SETTINGS["fallbacks"]["database"]:
            if fallback == "sqlite":
                # Try creating a SQLite connection in a writable location
                try:
                    import sqlite3
                    temp_path = os.path.join(tempfile.gettempdir(), f"recovery_{INSTANCE_ID}.db")
                    conn = sqlite3.connect(temp_path)
                    logger.info(f"Recovered with SQLite fallback at {temp_path}")
                    return conn
                except:
                    pass
            elif fallback == "json_file":
                # Try using a JSON file for simple data storage
                try:
                    temp_path = os.path.join(tempfile.gettempdir(), f"recovery_{INSTANCE_ID}.json")
                    return {"_file_path": temp_path, "_type": "json_file_fallback"}
                except:
                    pass
            elif fallback == "memory":
                # Last resort - in-memory storage
                return {"_type": "memory_storage_fallback", "data": {}}
        
        return None
    
    def _recover_network(self, feature_name: str, errors: List[Dict]) -> Any:
        """Recover from network connection failures"""
        # Try fallback networking methods
        for fallback in DEPLOYMENT_SETTINGS["fallbacks"]["networking"]:
            if fallback == "proxy":
                # Try setting up a proxy connection
                try:
                    # Logic to establish proxy connection would go here
                    return {"_type": "proxy_connection", "status": "fallback"}
                except:
                    pass
            elif fallback == "p2p":
                # Try using P2P communication
                try:
                    # Logic for P2P communication would go here
                    return {"_type": "p2p_connection", "status": "fallback"}
                except:
                    pass
        
        return None
    
    def _recover_filesystem(self, feature_name: str, errors: List[Dict]) -> Any:
        """Recover from filesystem access failures"""
        # Try alternative storage locations
        for fallback in DEPLOYMENT_SETTINGS["fallbacks"]["storage"]:
            if fallback == "memory":
                # Use in-memory storage
                return {"_type": "memory_storage", "data": {}}
            elif fallback == "distributed":
                # Try distributed storage if available
                try:
                    # Logic for distributed storage would go here
                    return {"_type": "distributed_storage", "status": "fallback"}
                except:
                    pass
        
        return None
    
    def _recover_api(self, feature_name: str, errors: List[Dict]) -> Any:
        """Recover from API call failures"""
        # Could implement retries, alternative endpoints, etc.
        return None
    
    def _recover_resources(self, feature_name: str, errors: List[Dict]) -> Any:
        """Recover from resource allocation failures"""
        # Implement reduced functionality mode with minimal resources
        return {"_type": "minimal_resources", "status": "degraded"}
    
    def generate_degraded_response(self, feature_name: str) -> Any:
        """
        Generate a degraded response for a failed feature
        
        Args:
            feature_name: The name of the failed feature
            
        Returns:
            A degraded response appropriate for the feature
        """
        # Feature-specific degraded responses
        if "database" in feature_name:
            return {"status": "degraded", "error": "Database access unavailable", "_type": "memory_fallback"}
        elif "network" in feature_name:
            return {"status": "degraded", "error": "Network unavailable", "_type": "offline_mode"}
        elif "file" in feature_name or "storage" in feature_name:
            return {"status": "degraded", "error": "File access unavailable", "_type": "volatile_storage"}
        elif "api" in feature_name:
            return {"status": "degraded", "error": "API access unavailable", "_type": "mock_response"}
        else:
            # Generic degraded response
            return {"status": "degraded", "feature": feature_name, "_type": "generic_fallback"}


class HealthMonitor:
    """
    Monitors the health of the deployment and triggers recovery when needed
    """
    
    def __init__(self):
        """Initialize the health monitor"""
        self.running = False
        self.check_interval = 60  # seconds
        self.thread = None
        self.health_metrics = {
            "cpu_usage": 0,
            "memory_usage": 0,
            "disk_usage": 0,
            "network_latency": 0,
            "error_rate": 0,
            "last_update": datetime.utcnow().isoformat()
        }
    
    def start(self):
        """Start the health monitoring thread"""
        if self.running:
            return
            
        self.running = True
        self.thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.thread.start()
        logger.info("Health monitoring started")
    
    def stop(self):
        """Stop the health monitoring thread"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
            self.thread = None
        logger.info("Health monitoring stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                self._check_health()
                time.sleep(self.check_interval)
            except Exception as e:
                logger.error(f"Error in health monitoring: {str(e)}")
                time.sleep(self.check_interval * 2)  # Longer sleep on error
    
    def _check_health(self):
        """Check system health metrics"""
        try:
            import psutil
            
            # Update metrics
            self.health_metrics["cpu_usage"] = psutil.cpu_percent(interval=0.5)
            self.health_metrics["memory_usage"] = psutil.virtual_memory().percent
            self.health_metrics["disk_usage"] = psutil.disk_usage('/').percent
            
            # Network check
            start_time = time.time()
            try:
                socket.create_connection(("8.8.8.8", 53), timeout=2)
                latency = (time.time() - start_time) * 1000  # ms
                self.health_metrics["network_latency"] = latency
            except:
                self.health_metrics["network_latency"] = -1  # Error
            
            # Update status
            self.health_metrics["last_update"] = datetime.utcnow().isoformat()
            
            # Update global status
            global PLATFORM_STATUS
            PLATFORM_STATUS["health_status"] = "healthy" if self._is_healthy() else "degraded"
            PLATFORM_STATUS["last_health_check"] = self.health_metrics["last_update"]
            
            # Log status periodically
            logger.debug(f"Health check: CPU {self.health_metrics['cpu_usage']}%, Memory {self.health_metrics['memory_usage']}%, Status: {PLATFORM_STATUS['health_status']}")
            
            # Take action if unhealthy
            if not self._is_healthy():
                self._handle_unhealthy_state()
                
        except ImportError:
            # psutil not available, use simplified metrics
            self.health_metrics["last_update"] = datetime.utcnow().isoformat()
            PLATFORM_STATUS["health_status"] = "unknown"
            PLATFORM_STATUS["last_health_check"] = self.health_metrics["last_update"]
    
    def _is_healthy(self) -> bool:
        """Check if the system is healthy based on metrics"""
        # Define thresholds
        cpu_threshold = 90
        memory_threshold = 90
        disk_threshold = 95
        
        # Check against thresholds
        if (self.health_metrics["cpu_usage"] > cpu_threshold or
            self.health_metrics["memory_usage"] > memory_threshold or
            self.health_metrics["disk_usage"] > disk_threshold):
            return False
            
        # Check network
        if self.health_metrics["network_latency"] == -1:
            # Network error, but not necessarily unhealthy
            pass
            
        return True
    
    def _handle_unhealthy_state(self):
        """Handle unhealthy system state"""
        logger.warning("System health check indicates unhealthy state")
        
        # Identify issues
        issues = []
        if self.health_metrics["cpu_usage"] > 90:
            issues.append("high_cpu_usage")
        if self.health_metrics["memory_usage"] > 90:
            issues.append("high_memory_usage")
        if self.health_metrics["disk_usage"] > 95:
            issues.append("high_disk_usage")
        if self.health_metrics["network_latency"] == -1:
            issues.append("network_error")
            
        # Update global status
        global PLATFORM_STATUS
        PLATFORM_STATUS["deployment_issues"] = issues
        
        # Take corrective actions
        for issue in issues:
            if issue == "high_memory_usage":
                self._reduce_memory_usage()
            elif issue == "high_disk_usage":
                self._clean_temporary_files()
            elif issue == "network_error":
                self._reset_network_connections()
    
    def _reduce_memory_usage(self):
        """Attempt to reduce memory usage"""
        logger.info("Attempting to reduce memory usage")
        # Implementation would depend on the specific application
        # This could involve clearing caches, reducing batch sizes, etc.
        
    def _clean_temporary_files(self):
        """Clean temporary files to free disk space"""
        logger.info("Cleaning temporary files")
        try:
            temp_dir = tempfile.gettempdir()
            # Only remove temp files related to our application
            for filename in os.listdir(temp_dir):
                if filename.startswith(f"recovery_{INSTANCE_ID}"):
                    file_path = os.path.join(temp_dir, filename)
                    try:
                        if os.path.isfile(file_path):
                            os.unlink(file_path)
                        elif os.path.isdir(file_path):
                            shutil.rmtree(file_path)
                    except Exception as e:
                        logger.error(f"Error removing {file_path}: {str(e)}")
        except Exception as e:
            logger.error(f"Error cleaning temporary files: {str(e)}")
    
    def _reset_network_connections(self):
        """Reset network connections"""
        logger.info("Resetting network connections")
        # Implementation would depend on the specific application
        # This could involve closing and reopening sockets, etc.


def detect_platform() -> str:
    """
    Detect the current platform
    
    Returns:
        str: Platform identifier ("container", "cloud", "notebook", "server", etc.)
    """
    if not PLATFORM_COMPATIBILITY.get("auto_detect_platform", True):
        # Default to server if auto-detection is disabled
        return "server"
        
    # Check for container environment
    if os.path.exists('/.dockerenv') or os.path.exists('/var/run/docker.sock'):
        return "container"
        
    # Check for cloud environment
    if any(key.startswith(prefix) for prefix in ['AWS_', 'AZURE_', 'GOOGLE_CLOUD_'] 
           for key in os.environ):
        return "cloud"
        
    # Check for notebook environment
    if 'ipykernel' in sys.modules or 'google.colab' in sys.modules:
        return "notebook"
        
    # Check for Replit
    if any(key in os.environ for key in ['REPL_ID', 'REPL_OWNER', 'REPL_SLUG']):
        return "replit"
        
    # Default to server for desktop/server environments
    return "server"


def check_available_resources() -> Dict[str, Any]:
    """
    Check available system resources
    
    Returns:
        Dict with resource information
    """
    resources = {
        "memory": {
            "total": "unknown",
            "available": "unknown",
            "percent": 0
        },
        "cpu": {
            "count": 1,
            "available": True
        },
        "disk": {
            "total": "unknown",
            "available": "unknown",
            "percent": 0
        },
        "network": {
            "available": False,
            "internet_access": False
        }
    }
    
    # Try to get detailed resource information
    try:
        import psutil
        
        # Memory
        mem = psutil.virtual_memory()
        resources["memory"]["total"] = _format_bytes(mem.total)
        resources["memory"]["available"] = _format_bytes(mem.available)
        resources["memory"]["percent"] = mem.percent
        
        # CPU
        resources["cpu"]["count"] = psutil.cpu_count() or 1
        resources["cpu"]["percent"] = psutil.cpu_percent(interval=0.1)
        
        # Disk
        disk = psutil.disk_usage('/')
        resources["disk"]["total"] = _format_bytes(disk.total)
        resources["disk"]["available"] = _format_bytes(disk.free)
        resources["disk"]["percent"] = disk.percent
    except ImportError:
        logger.warning("psutil not available, using limited resource detection")
        
        # Fallback memory detection
        try:
            with open('/proc/meminfo', 'r') as f:
                meminfo = f.read()
                mem_total = int(meminfo.split('MemTotal:')[1].split('kB')[0].strip()) * 1024
                mem_free = int(meminfo.split('MemAvailable:')[1].split('kB')[0].strip()) * 1024
                resources["memory"]["total"] = _format_bytes(mem_total)
                resources["memory"]["available"] = _format_bytes(mem_free)
                resources["memory"]["percent"] = 100 - (mem_free / mem_total * 100)
        except:
            pass
            
        # Fallback CPU detection
        try:
            resources["cpu"]["count"] = os.cpu_count() or 1
        except:
            pass
            
        # Fallback disk detection
        try:
            stat = os.statvfs('/')
            disk_total = stat.f_blocks * stat.f_frsize
            disk_free = stat.f_bfree * stat.f_frsize
            resources["disk"]["total"] = _format_bytes(disk_total)
            resources["disk"]["available"] = _format_bytes(disk_free)
            resources["disk"]["percent"] = 100 - (disk_free / disk_total * 100)
        except:
            pass
    
    # Check network
    try:
        # Check basic network connectivity
        socket.create_connection(("8.8.8.8", 53), timeout=2)
        resources["network"]["available"] = True
        resources["network"]["internet_access"] = True
    except:
        # Try an alternative check
        try:
            socket.gethostbyname("google.com")
            resources["network"]["available"] = True
            resources["network"]["internet_access"] = True
        except:
            pass
    
    return resources


def check_compatibility() -> Dict[str, bool]:
    """
    Check compatibility with the current platform
    
    Returns:
        Dict with compatibility information
    """
    current_platform = detect_platform()
    resources = check_available_resources()
    
    # Check if we meet the minimum requirements
    required = DEPLOYMENT_SETTINGS.get("required_resources", {}).get(current_platform, {})
    
    compatibility = {
        "meets_memory_requirements": True,
        "meets_cpu_requirements": True,
        "meets_storage_requirements": True,
        "has_network_access": resources["network"]["available"],
        "has_internet_access": resources["network"]["internet_access"],
        "overall_compatible": True
    }
    
    # Check memory requirements
    if required and "min_memory" in required:
        min_memory = _parse_size(required["min_memory"])
        if min_memory > 0:
            current_memory = _parse_size(resources["memory"]["total"])
            compatibility["meets_memory_requirements"] = current_memory >= min_memory
    
    # Check CPU requirements
    if required and "min_cpu" in required:
        min_cpu = float(required["min_cpu"])
        if min_cpu > 0:
            current_cpu = resources["cpu"]["count"]
            compatibility["meets_cpu_requirements"] = current_cpu >= min_cpu
    
    # Check storage requirements
    if required and "storage" in required:
        min_storage = _parse_size(required["storage"])
        if min_storage > 0:
            current_storage = _parse_size(resources["disk"]["available"])
            compatibility["meets_storage_requirements"] = current_storage >= min_storage
    
    # Calculate overall compatibility
    compatibility["overall_compatible"] = all([
        compatibility["meets_memory_requirements"],
        compatibility["meets_cpu_requirements"],
        compatibility["meets_storage_requirements"]
    ])
    
    return compatibility


def register_feature(feature_name: str, implementation: Callable, impl_name: str, priority: int = 0) -> None:
    """
    Register a feature implementation with the platform adapter
    
    Args:
        feature_name: The name of the feature
        implementation: The function implementing the feature
        impl_name: A name for this implementation
        priority: Priority (higher number = higher priority)
    """
    if feature_name not in FEATURE_REGISTRY:
        FEATURE_REGISTRY[feature_name] = []
    
    # Add implementation to the registry
    FEATURE_REGISTRY[feature_name].append((impl_name, implementation))
    
    # Sort implementations by priority (higher priority first)
    FEATURE_REGISTRY[feature_name].sort(key=lambda x: _get_implementation_priority(x[0], priority), reverse=True)
    
    logger.debug(f"Registered feature implementation: {feature_name} -> {impl_name}")


def _get_implementation_priority(impl_name: str, default_priority: int) -> int:
    """Get the priority for an implementation"""
    # Some implementations have inherent priorities
    if impl_name.startswith("primary_"):
        return max(100, default_priority)
    elif impl_name.startswith("fallback_"):
        return min(-100, default_priority)
    else:
        return default_priority


def _format_bytes(bytes_value: int) -> str:
    """Format bytes as human-readable string"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024 or unit == 'TB':
            return f"{bytes_value:.2f}{unit}"
        bytes_value /= 1024


def _parse_size(size_str: str) -> int:
    """Parse size string (like "1GB") to bytes"""
    if not size_str or not isinstance(size_str, str):
        return 0
        
    size_str = size_str.upper()
    
    # Extract number and unit
    import re
    match = re.match(r"([\d.]+)([KMGT]?B)", size_str)
    if not match:
        return 0
        
    value, unit = match.groups()
    value = float(value)
    
    # Convert to bytes
    multipliers = {
        'B': 1,
        'KB': 1024,
        'MB': 1024**2,
        'GB': 1024**3,
        'TB': 1024**4
    }
    
    return int(value * multipliers.get(unit, 1))


def get_adapter() -> PlatformAdapter:
    """
    Get or create a PlatformAdapter instance
    
    Returns:
        PlatformAdapter instance
    """
    global _adapter_instance
    
    if not '_adapter_instance' in globals():
        _adapter_instance = PlatformAdapter()
        
    return _adapter_instance


# Initialize adapter on module import
try:
    _adapter_instance = PlatformAdapter()
except Exception as e:
    logger.error(f"Error initializing platform adapter: {str(e)}")
    _adapter_instance = None