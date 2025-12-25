const SESSION_TIMEOUT = 60000; // 1 minute in milliseconds
let sessionTimer;

function handleLogin(event) {
    event.preventDefault();
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const errorDiv = document.getElementById('error-message');

    fetch('/api/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, password })
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            throw new Error(data.error);
        }
        if (data.token) {
            localStorage.setItem('token', data.token);
            window.location.replace('/index.html');
        } else {
            throw new Error('No token received');
        }
    })
    .catch(error => {
        errorDiv.textContent = error.message;
        errorDiv.style.display = 'block';
    });

    return false;
}

// Auto logout after 1 minute of inactivity
let inactivityTimer;

function resetInactivityTimer() {
    clearTimeout(inactivityTimer);
    inactivityTimer = setTimeout(() => {
        localStorage.removeItem('token');
        window.location.href = '/login.html';
    }, 60000); // 1 minute
}

// Reset timer on user activity
document.addEventListener('mousemove', resetInactivityTimer);
document.addEventListener('keypress', resetInactivityTimer);

// Initial timer start
resetInactivityTimer();