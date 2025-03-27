// Auto-refresh functionality
document.addEventListener('DOMContentLoaded', function() {
    console.log('Auto-refresh script loaded');
    
    // Check if authentication token exists
    const authToken = document.querySelector('meta[name="auth-token"]')?.getAttribute('content');
    
    if (authToken) {
        console.log('Auth token found, setting up auto-refresh');
        setupAutoRefresh(authToken);
    } else {
        console.log('No auth token found, skipping auto-refresh setup');
    }
});

/**
 * Setup auto-refresh mechanism for persistent sessions
 */
function setupAutoRefresh(authToken) {
    // Set up periodic keepalive to maintain session
    const KEEPALIVE_INTERVAL = 5 * 60 * 1000; // 5 minutes in milliseconds
    
    // Function to send keepalive request
    function sendKeepalive() {
        fetch('/api/keepalive', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({ timestamp: new Date().toISOString() })
        })
        .then(response => response.json())
        .then(data => {
            console.log('Keepalive response:', data);
            if (data.refresh_token) {
                // Update the token if a new one is provided
                const metaTag = document.querySelector('meta[name="auth-token"]');
                if (metaTag) {
                    metaTag.setAttribute('content', data.refresh_token);
                }
            }
        })
        .catch(error => {
            console.error('Keepalive error:', error);
        });
    }
    
    // Set up tracking for user activity
    let lastActivity = Date.now();
    const activityEvents = ['mousedown', 'keydown', 'scroll', 'touchstart'];
    
    // Function to update last activity timestamp
    function updateActivity() {
        lastActivity = Date.now();
        // Optionally log activity to the server
        logActivity();
    }
    
    // Add event listeners for user activity
    activityEvents.forEach(event => {
        document.addEventListener(event, updateActivity, { passive: true });
    });
    
    // Function to log activity to the server
    function logActivity() {
        fetch('/api/log-activity', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({ 
                timestamp: new Date().toISOString(),
                path: window.location.pathname
            })
        }).catch(error => {
            console.error('Activity logging error:', error);
        });
    }
    
    // Start the keepalive timer
    setInterval(() => {
        // Only send keepalive if there's been activity in the last hour
        const inactiveTime = Date.now() - lastActivity;
        if (inactiveTime < 60 * 60 * 1000) { // 1 hour
            sendKeepalive();
        } else {
            console.log('No recent activity, skipping keepalive');
        }
    }, KEEPALIVE_INTERVAL);
    
    // Initial keepalive
    sendKeepalive();
}