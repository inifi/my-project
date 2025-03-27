// WebSocket communication for real-time updates

let socket;
let reconnectAttempts = 0;
const maxReconnectAttempts = 5;
const reconnectDelay = 5000; // 5 seconds

function initializeSocket() {
    // Initialize Socket.IO connection
    socket = io();

    // Connection opened
    socket.on('connect', function() {
        console.log('WebSocket connected');
        reconnectAttempts = 0;
        if (document.getElementById('connectionStatus')) {
            document.getElementById('connectionStatus').textContent = 'Connected';
            document.getElementById('connectionStatus').className = 'badge bg-success';
        }
        addConsoleMessage('Connected to AI system', 'success');
    });

    // Connection closed
    socket.on('disconnect', function() {
        console.log('WebSocket disconnected');
        if (document.getElementById('connectionStatus')) {
            document.getElementById('connectionStatus').textContent = 'Disconnected';
            document.getElementById('connectionStatus').className = 'badge bg-danger';
        }
        addConsoleMessage('Disconnected from AI system', 'danger');
        
        // Try to reconnect
        if (reconnectAttempts < maxReconnectAttempts) {
            reconnectAttempts++;
            setTimeout(function() {
                addConsoleMessage(`Attempting to reconnect (${reconnectAttempts}/${maxReconnectAttempts})...`, 'warning');
                socket.connect();
            }, reconnectDelay);
        }
    });

    // Listen for system messages
    socket.on('system_message', function(data) {
        console.log('System message received:', data);
        showToast(data.message);
        addConsoleMessage(data.message);
    });

    // Listen for learning stats updates
    socket.on('learning_stats', function(data) {
        console.log('Learning stats received:', data);
        
        // Update UI elements if they exist
        if (document.getElementById('totalKnowledge')) {
            document.getElementById('totalKnowledge').textContent = data.total_knowledge;
        }
        
        if (document.getElementById('recentKnowledge')) {
            document.getElementById('recentKnowledge').textContent = data.recent_knowledge;
        }
        
        if (document.getElementById('activeSources')) {
            document.getElementById('activeSources').textContent = data.active_sources;
        }
        
        // Update the activity chart if it exists and is defined
        if (typeof activityChart !== 'undefined') {
            // Add new data point
            const now = new Date();
            const timeString = now.getHours() + ':' + now.getMinutes().toString().padStart(2, '0');
            
            // Update chart data
            activityChart.data.labels.push(timeString);
            activityChart.data.datasets[0].data.push(data.recent_knowledge);
            
            // Remove oldest data point if we have more than 12
            if (activityChart.data.labels.length > 12) {
                activityChart.data.labels.shift();
                activityChart.data.datasets[0].data.shift();
            }
            
            // Update chart
            activityChart.update();
        }
    });

    // Listen for security alerts
    socket.on('security_alert', function(data) {
        console.log('Security alert received:', data);
        showToast(data.message, 'warning');
        addConsoleMessage('SECURITY ALERT: ' + data.message, 'danger');
        
        // Play alert sound if enabled
        const alertSound = document.getElementById('alertSound');
        if (alertSound) {
            alertSound.play().catch(e => console.error('Error playing alert sound:', e));
        }
    });

    // Listen for replication updates
    socket.on('replication_update', function(data) {
        console.log('Replication update received:', data);
        showToast(data.message);
        addConsoleMessage('Replication: ' + data.message);
        
        // Update instance count if element exists
        if (document.getElementById('instanceCount') && data.instance_count) {
            document.getElementById('instanceCount').textContent = data.instance_count;
        }
    });

    // Listen for knowledge updates
    socket.on('knowledge_update', function(data) {
        console.log('Knowledge update received:', data);
        addConsoleMessage('Knowledge base updated: ' + data.message);
        
        // Update knowledge count if element exists
        if (document.getElementById('knowledgeCount') && data.knowledge_count) {
            document.getElementById('knowledgeCount').textContent = data.knowledge_count;
        }
    });
}

// Initialize WebSocket connection when the document is ready
document.addEventListener('DOMContentLoaded', function() {
    // Initialize WebSocket
    initializeSocket();
    
    // Send heartbeat to keep connection alive
    setInterval(function() {
        if (socket && socket.connected) {
            socket.emit('heartbeat', { timestamp: new Date().toISOString() });
        }
    }, 30000); // every 30 seconds
});

// Function to send a query to the AI system
function queryAI(query) {
    return new Promise((resolve, reject) => {
        // If socket is not connected, use regular AJAX
        if (!socket || !socket.connected) {
            fetch('/api/query', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams({
                    'query': query
                })
            })
            .then(response => response.json())
            .then(data => resolve(data))
            .catch(error => reject(error));
            return;
        }
        
        // Use socket for real-time response
        const timeout = setTimeout(() => {
            socket.off('query_response');
            reject(new Error('Query timed out'));
        }, 30000); // 30 second timeout
        
        socket.once('query_response', function(data) {
            clearTimeout(timeout);
            resolve(data);
        });
        
        socket.emit('query', { query: query });
    });
}
