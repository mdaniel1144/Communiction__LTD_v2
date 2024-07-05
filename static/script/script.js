
// Select the element you want to remove
// After 3 second
document.addEventListener("DOMContentLoaded", function() {

    const messageElement = document.querySelector(".message-success");
        setTimeout(function() {
            if(messageElement)
                messageElement.remove();
        },  3000); 
});