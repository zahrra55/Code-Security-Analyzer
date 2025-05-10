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

document.addEventListener('DOMContentLoaded', function() {
    const uploadForm = document.getElementById('upload-form');
    const resultsSection = document.getElementById('results');
    const vulnerabilitiesList = document.getElementById('vulnerabilities-list');
    const fixedCode = document.getElementById('fixed-code');

    uploadForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const formData = new FormData(uploadForm);
        
        try {
            const response = await fetch('/api/analyze', {
                method: 'POST',
                body: formData
            });
            
            if (!response.ok) {
                throw new Error('Analysis failed');
            }
            
            const data = await response.json();
            
            // Display vulnerabilities
            vulnerabilitiesList.innerHTML = '';
            if (data.vulnerabilities && data.vulnerabilities.length > 0) {
                data.vulnerabilities.forEach(vuln => {
                    const vulnElement = document.createElement('div');
                    vulnElement.className = 'vulnerability';
                    vulnElement.innerHTML = `
                        <h4>${vuln.type}</h4>
                        <p>${vuln.description}</p>
                        <p>Severity: ${vuln.severity}</p>
                    `;
                    vulnerabilitiesList.appendChild(vulnElement);
                });
            } else {
                vulnerabilitiesList.innerHTML = '<p>No vulnerabilities found.</p>';
            }
            
            // Display fixed code
            if (data.fixed_code) {
                fixedCode.textContent = data.fixed_code;
            } else {
                fixedCode.textContent = 'No fixes available.';
            }
            
            // Show results section
            resultsSection.style.display = 'block';
            
        } catch (error) {
            alert('Error analyzing code: ' + error.message);
        }
    });
});