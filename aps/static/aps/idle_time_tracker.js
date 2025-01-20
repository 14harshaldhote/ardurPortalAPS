let idleTime = 0;
const idleThreshold = 1 * 60 * 1000;  // 1 minute in milliseconds
const activityEvents = ['mousemove', 'keydown', 'click', 'scroll'];

function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

function resetIdleTime() {
    idleTime = 0;
    fetch('/update-last-activity/', {
        method: 'POST',
        body: JSON.stringify({ timestamp: new Date().toISOString() }),
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCookie('csrftoken')
        },
    })
    .then(response => response.json())
    .catch(error => console.error('Error updating activity:', error));
}

// Listen for user activity events
activityEvents.forEach(event => {
    document.addEventListener(event, resetIdleTime);
});

// Check idle time every second
setInterval(() => {
    idleTime += 1000;
    if (idleTime >= idleThreshold) {
        console.log('User is idle for 1 minute');
        // Optionally reload page or redirect to logout
        window.location.reload();
    }
}, 1000);