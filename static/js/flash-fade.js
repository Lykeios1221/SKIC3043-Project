document.addEventListener('DOMContentLoaded', function() {
    // Add a script to fade out flash messages after a few seconds
    var flashMessages = document.querySelectorAll('.flash-message');
    flashMessages.forEach(function(message) {
        setTimeout(function() {
            message.style.opacity = '0';
            message.style.transition = 'opacity 1s ease-in-out';
            setTimeout(function() {
                message.style.display = 'none';
            }, 1000);
        }, 3000); // Adjust the time (in milliseconds) the message should stay visible
    });
});
