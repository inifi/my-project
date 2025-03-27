/**
 * Communication Module for AI System
 * 
 * This module manages real-time communication and data fetching
 * between the client browser and the server. It works with auto_refresh.js
 * to maintain a persistent session and provide real-time updates.
 */

// Configuration
const COMMUNICATION = {
    updateInterval: 15000,  // 15 seconds for real-time updates
    reconnectDelay: 5000,   // 5 seconds between reconnection attempts
    maxReconnectAttempts: 5,
    wsEnabled: true,        // WebSocket for real-time communication
    pollingEnabled: true,   // Fallback to polling if WebSocket fails
};

// Communication state
let comState = {
    socket: null,
    connected: false,
    reconnectAttempts: 0,
    lastUpdateTime: Date.now(),
    updateTimer: null,
    pollingFallback: false
};

/**
 * Initialize the communication system
 */
function initCommunication() {
    console.log("Self-Improving AI System - Communication module initialized");
    
    // Check if we're on a page that needs real-time updates
    if (!document.querySelector('.dashboard-content, .system-stats, #knowledgeList')) {
        console.log("Not on a page requiring real-time updates");
        return;
    }
    
    // Only initialize for authenticated users
    if (!userSession || !userSession.isLoggedIn) {
        console.log("User not logged in, communication features disabled");
        return;
    }
    
    // Set up WebSocket if enabled
    if (COMMUNICATION.wsEnabled) {
        setupWebSocket();
    }
    
    // Set up polling fallback for updates
    if (COMMUNICATION.pollingEnabled) {
        startUpdatePolling();
    }
    
    // Setup event listeners
    document.addEventListener('visibilitychange', handleVisibilityChange);
}

/**
 * Set up WebSocket connection for real-time updates
 */
function setupWebSocket() {
    // Check if SocketIO or native WebSocket is available
    if (typeof io !== 'undefined') {
        // Socket.IO is available
        console.log("Setting up Socket.IO connection");
        comState.socket = io.connect(window.location.origin);
        
        // Set up event handlers
        comState.socket.on('connect', () => {
            console.log("WebSocket connected");
            comState.connected = true;
            comState.reconnectAttempts = 0;
            
            // Send authentication data
            comState.socket.emit('authenticate', {
                token: userSession.authToken,
                fingerprint: userSession.fingerprint
            });
        });
        
        comState.socket.on('disconnect', () => {
            console.log("WebSocket disconnected");
            comState.connected = false;
            attemptReconnect();
        });
        
        // Handle different types of real-time updates
        comState.socket.on('update', handleUpdate);
        comState.socket.on('security_alert', handleSecurityAlert);
        comState.socket.on('knowledge_update', handleKnowledgeUpdate);
        
    } else if ('WebSocket' in window) {
        // Native WebSocket fallback
        console.log("Setting up native WebSocket");
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws`;
        
        try {
            comState.socket = new WebSocket(wsUrl);
            
            comState.socket.onopen = () => {
                console.log("WebSocket connected");
                comState.connected = true;
                comState.reconnectAttempts = 0;
                
                // Send authentication
                comState.socket.send(JSON.stringify({
                    type: 'authenticate',
                    token: userSession.authToken,
                    fingerprint: userSession.fingerprint
                }));
            };
            
            comState.socket.onclose = () => {
                console.log("WebSocket disconnected");
                comState.connected = false;
                attemptReconnect();
            };
            
            comState.socket.onmessage = (event) => {
                const data = JSON.parse(event.data);
                switch (data.type) {
                    case 'update':
                        handleUpdate(data);
                        break;
                    case 'security_alert':
                        handleSecurityAlert(data);
                        break;
                    case 'knowledge_update':
                        handleKnowledgeUpdate(data);
                        break;
                }
            };
            
        } catch (e) {
            console.warn("WebSocket connection failed:", e);
            comState.connected = false;
            comState.pollingFallback = true;
        }
    } else {
        console.warn("WebSocket not supported by browser, using polling");
        comState.pollingFallback = true;
    }
}

/**
 * Attempt to reconnect WebSocket after disconnection
 */
function attemptReconnect() {
    if (comState.reconnectAttempts < COMMUNICATION.maxReconnectAttempts) {
        comState.reconnectAttempts++;
        console.log(`Attempting to reconnect (${comState.reconnectAttempts}/${COMMUNICATION.maxReconnectAttempts})...`);
        
        setTimeout(() => {
            setupWebSocket();
        }, COMMUNICATION.reconnectDelay);
    } else {
        console.warn("Max reconnection attempts reached, falling back to polling");
        comState.pollingFallback = true;
    }
}

/**
 * Start periodic polling for updates when WebSocket isn't available
 */
function startUpdatePolling() {
    // Clear any existing timers
    if (comState.updateTimer) {
        clearInterval(comState.updateTimer);
    }
    
    // Set up new interval for updates
    comState.updateTimer = setInterval(() => {
        if (document.visibilityState === 'visible') {
            fetchUpdates();
        }
    }, COMMUNICATION.updateInterval);
    
    // Fetch immediately
    fetchUpdates();
}

/**
 * Fetch updates via REST API
 */
function fetchUpdates() {
    fetch('/api/updates?since=' + new Date(comState.lastUpdateTime).toISOString(), {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            'X-Auth-Token': userSession.authToken || '',
            'X-Fingerprint': userSession.fingerprint || ''
        }
    })
    .then(response => {
        if (response.ok) {
            return response.json();
        } else {
            throw new Error('Failed to fetch updates');
        }
    })
    .then(data => {
        if (data.success) {
            // Process the updates
            if (data.security_events && data.security_events.length > 0) {
                data.security_events.forEach(event => handleSecurityAlert(event));
            }
            
            if (data.knowledge_updates && data.knowledge_updates.length > 0) {
                data.knowledge_updates.forEach(update => handleKnowledgeUpdate(update));
            }
            
            // Update last update time
            comState.lastUpdateTime = new Date(data.timestamp);
        }
    })
    .catch(error => {
        console.warn("Error fetching updates:", error);
    });
}

/**
 * Handle system-wide updates
 */
function handleUpdate(data) {
    console.log("Received system update:", data);
    
    // Update any relevant UI elements
    updateSystemStatistics(data);
    
    // Check for system alerts
    if (data.alerts && data.alerts.length > 0) {
        data.alerts.forEach(alert => {
            showNotification(alert.title, alert.message, alert.type);
        });
    }
}

/**
 * Handle security alerts
 */
function handleSecurityAlert(data) {
    console.log("Received security alert:", data);
    
    // Update security log display if present
    const securityLogElement = document.getElementById('securityLog');
    if (securityLogElement) {
        const alertHtml = `
            <div class="alert alert-${getSeverityClass(data.severity)} alert-dismissible fade show" role="alert">
                <strong>${data.event_type}:</strong> ${data.description}
                <small class="text-muted">${formatTimestamp(data.timestamp)}</small>
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
        `;
        securityLogElement.innerHTML = alertHtml + securityLogElement.innerHTML;
    }
    
    // Show a notification for high-severity alerts
    if (data.severity === 'critical' || data.severity === 'warning') {
        showNotification('Security Alert', data.description, 'danger');
    }
}

/**
 * Handle knowledge base updates
 */
function handleKnowledgeUpdate(data) {
    console.log("Received knowledge update:", data);
    
    // Update knowledge list if present
    const knowledgeList = document.getElementById('knowledgeList');
    if (knowledgeList) {
        const itemHtml = `
            <div class="card mb-2 knowledge-item ${data.verified ? 'border-success' : 'border-warning'}">
                <div class="card-body">
                    <p class="card-text">${data.content_summary}</p>
                    <div class="d-flex justify-content-between">
                        <span class="badge bg-${data.verified ? 'success' : 'warning'}">${data.verified ? 'Verified' : 'Unverified'}</span>
                        <small class="text-muted">${formatTimestamp(data.timestamp)}</small>
                    </div>
                </div>
            </div>
        `;
        
        // Add to the beginning of the list
        const fragment = document.createRange().createContextualFragment(itemHtml);
        knowledgeList.insertBefore(fragment, knowledgeList.firstChild);
        
        // If we have more than 50 items, remove the oldest ones
        while (knowledgeList.children.length > 50) {
            knowledgeList.removeChild(knowledgeList.lastChild);
        }
    }
}

/**
 * Update system statistics display
 */
function updateSystemStatistics(data) {
    // Update instance count
    const instanceCountElement = document.getElementById('instanceCount');
    if (instanceCountElement && data.instance_count) {
        instanceCountElement.textContent = data.instance_count;
    }
    
    // Update knowledge count
    const knowledgeCountElement = document.getElementById('knowledgeCount');
    if (knowledgeCountElement && data.knowledge_count) {
        knowledgeCountElement.textContent = data.knowledge_count;
    }
    
    // Update service status indicators
    if (data.services) {
        for (const [service, status] of Object.entries(data.services)) {
            const statusElement = document.getElementById(`${service}Status`);
            if (statusElement) {
                statusElement.className = `badge bg-${status ? 'success' : 'danger'}`;
                statusElement.textContent = status ? 'Active' : 'Inactive';
            }
        }
    }
    
    // Update system resource gauges
    if (data.system) {
        // Update memory usage
        const memoryGauge = document.getElementById('memoryGauge');
        if (memoryGauge && data.system.memory) {
            memoryGauge.style.width = `${data.system.memory.percent}%`;
            memoryGauge.textContent = `${data.system.memory.percent}%`;
        }
        
        // Update CPU usage
        const cpuGauge = document.getElementById('cpuGauge');
        if (cpuGauge && data.system.cpu) {
            cpuGauge.style.width = `${data.system.cpu}%`;
            cpuGauge.textContent = `${data.system.cpu}%`;
        }
    }
}

/**
 * Get Bootstrap alert class based on severity
 */
function getSeverityClass(severity) {
    switch (severity) {
        case 'critical':
            return 'danger';
        case 'warning':
            return 'warning';
        case 'info':
            return 'info';
        default:
            return 'secondary';
    }
}

/**
 * Format timestamp for display
 */
function formatTimestamp(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString();
}

/**
 * Show a notification to the user
 */
function showNotification(title, message, type = 'info') {
    // Check if the browser supports notifications
    if (!("Notification" in window)) {
        console.warn("This browser does not support desktop notification");
        
        // Fallback to toast notification
        showToast(title, message, type);
        return;
    }
    
    // Check if permission is already granted
    if (Notification.permission === "granted") {
        createNotification(title, message);
    } 
    // Otherwise, request permission
    else if (Notification.permission !== 'denied') {
        Notification.requestPermission().then(permission => {
            if (permission === "granted") {
                createNotification(title, message);
            } else {
                // Fallback to toast notification
                showToast(title, message, type);
            }
        });
    } else {
        // Permission denied, use toast
        showToast(title, message, type);
    }
}

/**
 * Create a browser notification
 */
function createNotification(title, message) {
    const notification = new Notification(title, {
        body: message,
        icon: '/static/img/ai-icon.png'
    });
    
    notification.onclick = function() {
        window.focus();
        this.close();
    };
    
    // Auto-close after 5 seconds
    setTimeout(() => {
        notification.close();
    }, 5000);
}

/**
 * Show a toast notification in the UI
 */
function showToast(title, message, type = 'info') {
    // Create toast container if it doesn't exist
    let toastContainer = document.getElementById('toast-container');
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.id = 'toast-container';
        toastContainer.className = 'toast-container position-fixed top-0 end-0 p-3';
        document.body.appendChild(toastContainer);
    }
    
    // Create toast element
    const toastId = 'toast-' + Date.now();
    const toastHtml = `
        <div id="${toastId}" class="toast" role="alert" aria-live="assertive" aria-atomic="true">
            <div class="toast-header bg-${type} text-white">
                <strong class="me-auto">${title}</strong>
                <small>${new Date().toLocaleTimeString()}</small>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="toast" aria-label="Close"></button>
            </div>
            <div class="toast-body">
                ${message}
            </div>
        </div>
    `;
    
    // Add toast to container
    toastContainer.innerHTML += toastHtml;
    
    // Initialize and show the toast
    const toastElement = document.getElementById(toastId);
    const toast = new bootstrap.Toast(toastElement, {
        autohide: true,
        delay: 5000
    });
    toast.show();
    
    // Remove after hiding
    toastElement.addEventListener('hidden.bs.toast', () => {
        toastElement.remove();
    });
}

/**
 * Handle tab visibility changes
 */
function handleVisibilityChange() {
    if (document.visibilityState === 'visible') {
        // Tab is now visible, fetch updates immediately
        fetchUpdates();
    }
}

// Initialize when DOM is fully loaded
document.addEventListener('DOMContentLoaded', initCommunication);

// Re-initialize on AJAX navigation (if applicable)
document.addEventListener('turbolinks:load', initCommunication);

/**
 * Send a command to the AI system
 * 
 * This function ensures backward compatibility with all commands from previous versions
 * while supporting enhanced functionality in newer versions.
 */
function sendCommand(command, args = {}) {
    if (!comState.socket) {
        console.warn("Cannot send command: socket not initialized");
        showToast("Command Failed", "Not connected to server. Please try again.", "warning");
        return false;
    }
    
    try {
        // First check if the command is in the legacy format (simple string)
        // If so, adapt it to the new format while maintaining backward compatibility
        let commandData = {
            command: command,
            args: args,
            timestamp: new Date().toISOString(),
            clientVersion: "2.0", // Indicate the client version supports enhanced features
            compatibility: true // Always maintain backward compatibility
        };
        
        console.log(`Sending command: ${command}`, args);
        
        // Send the command through the socket
        comState.socket.emit('command', commandData);
        
        // Show feedback that command was sent
        showToast("Command Sent", `Executing: ${command}`, "info");
        
        return true;
    } catch (e) {
        console.error("Error sending command:", e);
        showToast("Command Failed", `Error: ${e.message}`, "danger");
        return false;
    }
}

// Export functions for use in other modules
window.Communication = {
    fetchUpdates: fetchUpdates,
    showNotification: showNotification,
    sendCommand: sendCommand
};