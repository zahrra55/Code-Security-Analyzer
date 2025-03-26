document.addEventListener("DOMContentLoaded", () => {
    // Create a toggle button for light/dark mode
    const toggleButton = document.createElement("button");
    toggleButton.classList.add("toggle-button");
    toggleButton.innerHTML = `
        <div class="icon sun"></div>
        <div class="icon moon"></div>
    `;
    document.body.insertBefore(toggleButton, document.body.firstChild);

    // Check localStorage for dark mode state
    const isDarkMode = localStorage.getItem("dark-mode") === "true";
    if (isDarkMode) {
        document.body.classList.add("dark-mode");
        toggleButton.classList.add("active");
    }

    // Toggle light/dark mode
    toggleButton.addEventListener("click", () => {
        const isDarkMode = document.body.classList.toggle("dark-mode");
        toggleButton.classList.toggle("active");

        // Save the current state to localStorage
        localStorage.setItem("dark-mode", isDarkMode);
    });
});