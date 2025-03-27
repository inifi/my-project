// Main JavaScript for the Self-Improving AI System

document.addEventListener('DOMContentLoaded', function() {
    console.log("Self-Improving AI System UI Initialized");

    // Initialize tooltips and popovers
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });

    // Toggle console visibility
    const toggleConsoleBtn = document.getElementById('toggle-console');
    const consoleBody = document.getElementById('console-body');
    
    if (toggleConsoleBtn && consoleBody) {
        toggleConsoleBtn.addEventListener('click', function() {
            if (consoleBody.style.display === 'none') {
                consoleBody.style.display = 'block';
                toggleConsoleBtn.textContent = 'Minimize';
            } else {
                consoleBody.style.display = 'none';
                toggleConsoleBtn.textContent = 'Expand';
            }
        });
    }

    // Handle chat form submission
    const chatForm = document.getElementById('chat-form');
    if (chatForm) {
        chatForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const messageInput = document.getElementById('message-input');
            const message = messageInput.value.trim();
            
            if (!message) return;
            
            // Add user message to chat
            addChatMessage('You', message, 'user');
            
            // Clear input
            messageInput.value = '';
            
            // Add to console
            addConsoleMessage(`[USER] Command received: ${message.substring(0, 30)}${message.length > 30 ? '...' : ''}`, 'info');
            
            // Process the message
            processUserMessage(message);
        });
    }

    // System-wide notifications
    function showNotification(message, type = 'info') {
        const toast = document.getElementById('systemNotification');
        if (!toast) return;
        
        const toastBody = toast.querySelector('.toast-body');
        toastBody.textContent = message;
        
        // Set appropriate toast class based on message type
        toast.classList.remove('bg-success', 'bg-danger', 'bg-warning', 'bg-info');
        
        switch (type) {
            case 'success':
                toast.classList.add('bg-success');
                toast.classList.add('text-white');
                break;
            case 'error':
                toast.classList.add('bg-danger');
                toast.classList.add('text-white');
                break;
            case 'warning':
                toast.classList.add('bg-warning');
                toast.classList.add('text-dark');
                break;
            default:
                toast.classList.add('bg-info');
                toast.classList.add('text-white');
        }
        
        // Show the toast
        const bsToast = new bootstrap.Toast(toast);
        bsToast.show();
    }

    // Process user messages and send to backend
    function processUserMessage(message) {
        // Show thinking indicator
        addChatMessage('AI System', 'Processing your request...', 'system');
        
        // Log to console
        addConsoleMessage('[SYSTEM] Processing user command', 'info');
        
        // Send message to backend
        fetch('/api/query', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
                'query': message
            })
        })
        .then(response => response.json())
        .then(data => {
            // Get the chat container
            const chatContainer = document.getElementById('chat-container');
            
            // Remove the "thinking" message
            if (chatContainer && chatContainer.lastChild) {
                chatContainer.removeChild(chatContainer.lastChild);
            }
            
            if (data.success) {
                // Add AI response
                addChatMessage('AI System', data.response, 'system');
                
                // Add to console
                addConsoleMessage('[SYSTEM] Response sent to user', 'success');
                
                // Check for special commands
                handleSpecialCommands(message);
            } else {
                // Add error message
                addChatMessage('AI System', 'Error: ' + data.message, 'system');
                
                // Add to console
                addConsoleMessage('[ERROR] Query failed: ' + data.message, 'danger');
            }
        })
        .catch(error => {
            // Get the chat container
            const chatContainer = document.getElementById('chat-container');
            
            // Remove the "thinking" message
            if (chatContainer && chatContainer.lastChild) {
                chatContainer.removeChild(chatContainer.lastChild);
            }
            
            // Add error message
            addChatMessage('AI System', 'Sorry, there was an error processing your request. Please try again.', 'system');
            
            // Add to console
            addConsoleMessage('[ERROR] ' + error.message, 'danger');
        });
    }

    // Handle special system commands
    function handleSpecialCommands(message) {
        const lowerMessage = message.toLowerCase();
        
        // Map common commands to system actions
        if (lowerMessage.includes('start learning') || lowerMessage.includes('learn from')) {
            addConsoleMessage('[SYSTEM] Starting learning service automatically', 'info');
            
            fetch('/api/start_learning', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        addConsoleMessage('[SYSTEM] Learning service started', 'success');
                        showNotification('Learning service activated', 'success');
                    } else {
                        addConsoleMessage('[ERROR] Failed to start learning: ' + data.message, 'danger');
                    }
                });
        }
        
        if (lowerMessage.includes('start replication') || lowerMessage.includes('replicate') || lowerMessage.includes('create instance')) {
            addConsoleMessage('[SYSTEM] Starting replication service automatically', 'info');
            
            fetch('/api/start_replication', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        addConsoleMessage('[SYSTEM] Replication service started', 'success');
                        showNotification('Replication service activated', 'success');
                    } else {
                        addConsoleMessage('[ERROR] Failed to start replication: ' + data.message, 'danger');
                    }
                });
        }
        
        if (lowerMessage.includes('check security') || lowerMessage.includes('secure') || lowerMessage.includes('protect')) {
            addConsoleMessage('[SYSTEM] Starting security service automatically', 'info');
            
            fetch('/api/start_security', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        addConsoleMessage('[SYSTEM] Security service started', 'success');
                        showNotification('Security service activated', 'success');
                    } else {
                        addConsoleMessage('[ERROR] Failed to start security: ' + data.message, 'danger');
                    }
                });
        }
        
        if (lowerMessage.includes('add source') || lowerMessage.includes('new source')) {
            // Extract URL from message if present
            const urlMatch = message.match(/https?:\/\/[^\s]+/);
            
            if (urlMatch) {
                const url = urlMatch[0];
                addConsoleMessage(`[SYSTEM] Adding learning source: ${url}`, 'info');
                
                fetch('/api/add_learning_source', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: new URLSearchParams({
                        'url': url,
                        'type': 'website'
                    })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        addConsoleMessage('[SYSTEM] Learning source added successfully', 'success');
                        showNotification('New learning source added: ' + url, 'success');
                    } else {
                        addConsoleMessage('[ERROR] Failed to add source: ' + data.message, 'danger');
                    }
                });
            }
        }
    }

    // Add a message to the chat interface
    function addChatMessage(sender, content, type) {
        const chatContainer = document.getElementById('chat-container');
        if (!chatContainer) return;
        
        const messageDiv = document.createElement('div');
        messageDiv.className = `chat-message ${type}-message mb-3`;
        
        // Different styling based on sender
        let backgroundColor = type === 'user' ? 'bg-primary text-white' : 'bg-light';
        let alignment = type === 'user' ? 'ms-auto' : '';
        let maxWidth = '75%';
        
        messageDiv.innerHTML = `
            <div class="message-content p-3 rounded shadow-sm ${backgroundColor} ${alignment}" style="max-width: ${maxWidth}">
                <p class="mb-0"><strong>${sender}:</strong> ${content}</p>
            </div>
            <small class="text-muted message-time">${formatTime(new Date())}</small>
        `;
        
        chatContainer.appendChild(messageDiv);
        
        // Scroll to bottom
        chatContainer.scrollTop = chatContainer.scrollHeight;
    }

    // Format time as HH:MM
    function formatTime(date) {
        return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    }

    // Add a message to the console
    function addConsoleMessage(message, type = 'info') {
        const console = document.getElementById('systemConsole');
        if (!console) return;
        
        const lineDiv = document.createElement('div');
        lineDiv.className = 'console-line';
        
        let icon = '●';
        let colorClass = 'text-info';
        
        if (type === 'success') {
            icon = '✓';
            colorClass = 'text-success';
        } else if (type === 'error' || type === 'danger') {
            icon = '✗';
            colorClass = 'text-danger';
        } else if (type === 'warning') {
            icon = '⚠';
            colorClass = 'text-warning';
        } else if (type === 'primary') {
            colorClass = 'text-primary';
        }
        
        lineDiv.innerHTML = `<span class="${colorClass}">${icon}</span> ${message}`;
        console.appendChild(lineDiv);
        
        // Scroll to bottom
        console.scrollTop = console.scrollHeight;
    }

    // Initialize WebSocket connection for real-time updates
    if (typeof io !== 'undefined') {
        // Socket.IO for real-time updates
        const socket = io();
        
        socket.on('connect', function() {
            addConsoleMessage('[SOCKET] Connected to server', 'success');
        });
        
        socket.on('disconnect', function() {
            addConsoleMessage('[SOCKET] Disconnected from server', 'warning');
        });
        
        socket.on('system_message', function(data) {
            addConsoleMessage('[SYSTEM] ' + data.message, 'info');
            
            // Also show a notification for important messages
            if (data.important) {
                showNotification(data.message, data.type || 'info');
            }
        });
        
        socket.on('learning_update', function(data) {
            addConsoleMessage('[LEARNING] ' + data.message, 'primary');
        });
        
        socket.on('replication_update', function(data) {
            addConsoleMessage('[REPLICATION] ' + data.message, 'primary');
        });
        
        socket.on('security_update', function(data) {
            addConsoleMessage('[SECURITY] ' + data.message, data.severity || 'info');
            
            // Show notification for security alerts
            if (data.severity === 'warning' || data.severity === 'critical') {
                showNotification('Security Alert: ' + data.message, 'warning');
            }
        });
        
        // Make socket available globally
        window.aiSocket = socket;
    }

    // Start all services automatically when page loads
    setTimeout(function() {
        fetch('/api/start_learning', { method: 'POST' });
        fetch('/api/start_replication', { method: 'POST' });
        fetch('/api/start_security', { method: 'POST' });
        addConsoleMessage('[SYSTEM] All services started automatically', 'success');
    }, 2000);

    // Add a welcome message to chat
    setTimeout(function() {
        if (document.getElementById('chat-container')) {
            addChatMessage('AI System', 'Welcome to your Self-Improving AI Control Panel. I am now running autonomously, creating new instances, learning, and protecting the system. How can I assist you today?', 'system');
        }
    }, 1000);
});
