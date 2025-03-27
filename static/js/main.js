/**
 * Main JavaScript file for the Self-Improving AI System
 * 
 * Initializes and coordinates all client-side functionality.
 */

// System initialization
document.addEventListener('DOMContentLoaded', function() {
    console.log('Self-Improving AI System UI Initialized');
    
    // Initialize the tooltip components if Bootstrap is available
    if (typeof bootstrap !== 'undefined' && bootstrap.Tooltip) {
        const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
    }
    
    // Set up event listeners for UI interactions
    setupEventListeners();
});

/**
 * Set up event listeners for various UI elements
 */
function setupEventListeners() {
    // Listen for form submissions
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', handleFormSubmit);
    });
    
    // Listen for dashboard control actions
    const startLearningBtn = document.getElementById('startLearningBtn');
    if (startLearningBtn) {
        startLearningBtn.addEventListener('click', function() {
            fetch('/start_learning', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        showAlert('Learning service started successfully', 'success');
                    } else {
                        showAlert('Failed to start learning service: ' + data.message, 'danger');
                    }
                });
        });
    }
    
    const startReplicationBtn = document.getElementById('startReplicationBtn');
    if (startReplicationBtn) {
        startReplicationBtn.addEventListener('click', function() {
            fetch('/start_replication', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        showAlert('Replication service started successfully', 'success');
                    } else {
                        showAlert('Failed to start replication service: ' + data.message, 'danger');
                    }
                });
        });
    }
    
    const startSecurityBtn = document.getElementById('startSecurityBtn');
    if (startSecurityBtn) {
        startSecurityBtn.addEventListener('click', function() {
            fetch('/start_security', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        showAlert('Security service started successfully', 'success');
                    } else {
                        showAlert('Failed to start security service: ' + data.message, 'danger');
                    }
                });
        });
    }
    
    // Set up WebSocket event handlers if available
    setupSocketHandlers();
}

/**
 * Handle form submissions
 */
function handleFormSubmit(event) {
    // Get the form
    const form = event.target;
    
    // Only handle XHR forms
    if (!form.dataset.ajax) return;
    
    // Prevent default form submission
    event.preventDefault();
    
    // Collect form data
    const formData = new FormData(form);
    const url = form.action;
    const method = form.method.toUpperCase();
    
    // Convert FormData to JSON object if needed
    let data;
    if (form.dataset.format === 'json') {
        data = {};
        formData.forEach((value, key) => {
            data[key] = value;
        });
    } else {
        data = formData;
    }
    
    // Disable form while submitting
    const submitBtn = form.querySelector('button[type="submit"]');
    if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Processing...';
    }
    
    // Perform AJAX request
    let fetchOptions = {
        method: method,
        headers: {}
    };
    
    if (form.dataset.format === 'json') {
        fetchOptions.headers['Content-Type'] = 'application/json';
        fetchOptions.body = JSON.stringify(data);
    } else {
        fetchOptions.body = formData;
    }
    
    // Send the request
    fetch(url, fetchOptions)
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok: ' + response.statusText);
            }
            return response.json();
        })
        .then(data => {
            // Handle successful response
            handleFormResponse(form, data);
        })
        .catch(error => {
            // Handle error
            console.error('Form submission error:', error);
            showAlert('Error: ' + error.message, 'danger');
        })
        .finally(() => {
            // Re-enable form
            if (submitBtn) {
                submitBtn.disabled = false;
                submitBtn.innerHTML = submitBtn.dataset.originalText || 'Submit';
            }
        });
}

/**
 * Handle form submission response
 */
function handleFormResponse(form, data) {
    // Show success/error message
    if (data.success) {
        if (data.message) {
            showAlert(data.message, 'success');
        }
        
        // Handle redirect if specified
        if (data.redirect) {
            window.location.href = data.redirect;
            return;
        }
        
        // Reset form on success if specified
        if (form.dataset.reset === 'true') {
            form.reset();
        }
        
        // Handle callback if specified
        if (form.dataset.callback) {
            const callback = window[form.dataset.callback];
            if (typeof callback === 'function') {
                callback(data);
            }
        }
        
        // Update content if specified
        if (data.updateElement && data.content) {
            const element = document.getElementById(data.updateElement);
            if (element) {
                element.innerHTML = data.content;
            }
        }
    } else {
        // Show error message
        if (data.message) {
            showAlert(data.message, 'danger');
        }
        
        // Show field-specific errors
        if (data.errors) {
            for (const field in data.errors) {
                const input = form.querySelector(`[name="${field}"]`);
                if (input) {
                    input.classList.add('is-invalid');
                    
                    // Create or update error message
                    let errorDiv = input.nextElementSibling;
                    if (!errorDiv || !errorDiv.classList.contains('invalid-feedback')) {
                        errorDiv = document.createElement('div');
                        errorDiv.className = 'invalid-feedback';
                        input.parentNode.insertBefore(errorDiv, input.nextSibling);
                    }
                    errorDiv.textContent = data.errors[field];
                }
            }
        }
    }
}

/**
 * Show an alert message
 */
function showAlert(message, type = 'info') {
    // Create alert container if it doesn't exist
    let alertContainer = document.getElementById('alert-container');
    if (!alertContainer) {
        alertContainer = document.createElement('div');
        alertContainer.id = 'alert-container';
        alertContainer.className = 'alert-container position-fixed top-0 start-50 translate-middle-x mt-3';
        document.body.appendChild(alertContainer);
    }
    
    // Create alert element
    const alertId = 'alert-' + Date.now();
    const alertHtml = `
        <div id="${alertId}" class="alert alert-${type} alert-dismissible fade show" role="alert">
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
    `;
    
    // Add alert to container
    alertContainer.innerHTML += alertHtml;
    
    // Auto-close after 5 seconds
    setTimeout(() => {
        const alertElement = document.getElementById(alertId);
        if (alertElement) {
            // If Bootstrap is available, use it to dismiss
            if (typeof bootstrap !== 'undefined' && bootstrap.Alert) {
                const bsAlert = new bootstrap.Alert(alertElement);
                bsAlert.close();
            } else {
                // Otherwise, just remove the element
                alertElement.remove();
            }
        }
    }, 5000);
}

/**
 * Set up Socket.IO event handlers for real-time updates
 */
function setupSocketHandlers() {
    if (typeof io === 'undefined') return;
    
    const socket = io();
    
    socket.on('connect', function() {
        console.log('Socket.IO connected');
    });
    
    socket.on('disconnect', function() {
        console.log('Socket.IO disconnected');
    });
    
    // Listen for real-time updates
    socket.on('update', function(data) {
        console.log('Received update:', data);
        
        // Handle different types of updates
        if (data.type === 'knowledge') {
            updateKnowledgeBase(data);
        } else if (data.type === 'security') {
            updateSecurityLog(data);
        } else if (data.type === 'replication') {
            updateReplicationStatus(data);
        }
    });
    
    // Listen for real-time commands
    socket.on('command', function(data) {
        console.log('Received command:', data);
        
        // Process the command
        if (data.command === 'refresh') {
            // Refresh the page
            window.location.reload();
        } else if (data.command === 'notification') {
            // Show a notification
            showAlert(data.message, data.alert_type || 'info');
        }
    });
}

/**
 * Update the knowledge base display with new data
 */
function updateKnowledgeBase(data) {
    const knowledgeList = document.getElementById('knowledgeList');
    if (!knowledgeList) return;
    
    const html = `
        <div class="card mb-2">
            <div class="card-body">
                <h5 class="card-title">${data.source_type}</h5>
                <p class="card-text">${data.content.substring(0, 100)}...</p>
                <div class="d-flex justify-content-between">
                    <span class="badge bg-${data.verified ? 'success' : 'warning'}">
                        ${data.verified ? 'Verified' : 'Unverified'}
                    </span>
                    <small class="text-muted">${new Date(data.timestamp).toLocaleString()}</small>
                </div>
            </div>
        </div>
    `;
    
    // Add the new item to the beginning of the list
    knowledgeList.insertAdjacentHTML('afterbegin', html);
    
    // Limit the number of displayed items
    while (knowledgeList.children.length > 20) {
        knowledgeList.removeChild(knowledgeList.lastChild);
    }
}

/**
 * Update the security log with new events
 */
function updateSecurityLog(data) {
    const securityLog = document.getElementById('securityLog');
    if (!securityLog) return;
    
    const severityClass = getSeverityClass(data.severity);
    
    const html = `
        <div class="alert alert-${severityClass} mb-2">
            <div class="d-flex justify-content-between">
                <strong>${data.event_type}</strong>
                <small>${new Date(data.timestamp).toLocaleString()}</small>
            </div>
            <p class="mb-0">${data.description}</p>
        </div>
    `;
    
    // Add the new event to the beginning of the log
    securityLog.insertAdjacentHTML('afterbegin', html);
    
    // Limit the number of displayed items
    while (securityLog.children.length > 20) {
        securityLog.removeChild(securityLog.lastChild);
    }
}

/**
 * Update the replication status display
 */
function updateReplicationStatus(data) {
    const instanceCount = document.getElementById('instanceCount');
    if (instanceCount) {
        instanceCount.textContent = data.instance_count;
    }
    
    const activeInstances = document.getElementById('activeInstances');
    if (activeInstances) {
        activeInstances.textContent = data.active_count;
    }
    
    // Update instance list if available
    const instanceList = document.getElementById('instanceList');
    if (instanceList && data.instances) {
        // Clear the current list
        instanceList.innerHTML = '';
        
        // Add each instance
        data.instances.forEach(instance => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${instance.instance_id.substring(0, 8)}...</td>
                <td>${instance.hostname}</td>
                <td><span class="badge bg-${instance.status === 'active' ? 'success' : 'warning'}">${instance.status}</span></td>
                <td>${instance.instance_type}</td>
                <td>${new Date(instance.last_heartbeat).toLocaleString()}</td>
            `;
            instanceList.appendChild(row);
        });
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