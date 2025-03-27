// Main JavaScript for the AI System

document.addEventListener('DOMContentLoaded', function() {
    console.log("AI System UI Initialized");

    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize popovers
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });

    // Toggle sidebar on mobile
    const sidebarToggle = document.getElementById('sidebarToggle');
    if (sidebarToggle) {
        sidebarToggle.addEventListener('click', function() {
            document.querySelector('#sidebar').classList.toggle('active');
            document.querySelector('#content').classList.toggle('active');
        });
    }

    // Security Audit Button
    const securityAuditBtn = document.getElementById('securityAuditBtn');
    if (securityAuditBtn) {
        securityAuditBtn.addEventListener('click', function() {
            // Send command to server
            sendCommand('security_scan');
            
            // Show toast message
            showToast('Security audit initiated');
        });
    }

    // Sync Knowledge Button
    const syncKnowledgeBtn = document.getElementById('syncKnowledgeBtn');
    if (syncKnowledgeBtn) {
        syncKnowledgeBtn.addEventListener('click', function() {
            // Send command to server
            sendCommand('sync_knowledge');
            
            // Show toast message
            showToast('Knowledge synchronization started');
        });
    }

    // Create Instance Button
    const createInstanceBtn = document.getElementById('createInstanceBtn');
    if (createInstanceBtn) {
        createInstanceBtn.addEventListener('click', function() {
            // Show confirmation dialog
            if (confirm('Are you sure you want to create a new AI instance? This will attempt to replicate the system to a new platform.')) {
                // Send command to server to start replication
                fetch('/api/start_replication', {
                    method: 'POST'
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        showToast('Replication process started');
                    } else {
                        showToast('Failed to start replication: ' + data.message, 'error');
                    }
                })
                .catch(error => {
                    showToast('Error: ' + error.message, 'error');
                });
            }
        });
    }

    // Self-Improve Button (if exists)
    const selfImproveBtn = document.getElementById('selfImproveBtn');
    if (selfImproveBtn) {
        selfImproveBtn.addEventListener('click', function() {
            // Send command to server
            sendCommand('self_improve');
            
            // Show toast message
            showToast('Self-improvement process initiated');
        });
    }

    // Monitor system resources periodically
    function updateSystemResources() {
        fetch('/api/system/resources')
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Update resource displays if elements exist
                    if (document.getElementById('cpuUsage')) {
                        document.getElementById('cpuUsage').style.width = data.cpu_usage + '%';
                        document.getElementById('cpuUsage').textContent = data.cpu_usage + '%';
                    }
                    
                    if (document.getElementById('memoryUsage')) {
                        document.getElementById('memoryUsage').style.width = data.memory_usage + '%';
                        document.getElementById('memoryUsage').textContent = data.memory_usage + '%';
                    }
                }
            })
            .catch(error => console.error('Error fetching system resources:', error));
    }

    // Call once on load and then set interval (if on dashboard)
    if (document.getElementById('dashboard')) {
        updateSystemResources();
        setInterval(updateSystemResources, 30000); // Update every 30 seconds
    }
});

// Helper function to show toast messages
function showToast(message, type = 'info') {
    const toast = document.getElementById('systemMessageToast');
    if (!toast) return;
    
    const toastBody = toast.querySelector('.toast-body');
    toastBody.textContent = message;
    
    // Set appropriate toast class based on message type
    toast.classList.remove('bg-success', 'bg-danger', 'bg-warning', 'bg-info');
    
    switch (type) {
        case 'success':
            toast.classList.add('bg-success');
            break;
        case 'error':
            toast.classList.add('bg-danger');
            break;
        case 'warning':
            toast.classList.add('bg-warning');
            toast.classList.add('text-dark');
            break;
        default:
            toast.classList.add('bg-info');
    }
    
    // Update timestamp
    const toastTime = toast.querySelector('.toast-time');
    if (toastTime) {
        toastTime.textContent = 'just now';
    }
    
    // Show the toast
    const bsToast = new bootstrap.Toast(toast);
    bsToast.show();
}

// Send command to server via WebSocket
function sendCommand(command, data = {}) {
    if (typeof socket !== 'undefined' && socket.connected) {
        socket.emit('command', {
            command: command,
            data: data,
            timestamp: new Date().toISOString()
        });
        return true;
    } else {
        console.error('WebSocket not connected');
        return false;
    }
}

// Add a console message to the system console if it exists
function addConsoleMessage(message, type = 'info') {
    const console = document.getElementById('systemConsole');
    if (!console) return;
    
    const line = document.createElement('div');
    line.className = 'console-line';
    
    const dot = document.createElement('span');
    dot.className = `text-${type}`;
    dot.textContent = '●';
    
    line.appendChild(dot);
    line.appendChild(document.createTextNode(' ' + message));
    
    console.appendChild(line);
    console.scrollTop = console.scrollHeight;
}
