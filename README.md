# Code Security Analyzer

Code Security Analyzer is a tool designed to analyze code files for potential vulnerabilities. It offers both a **web-based interface** and a **command-line interface (CLI)**, making it accessible for developers with different workflows. The project leverages a **pre-trained machine learning model** to detect vulnerabilities and provide actionable recommendations for fixing them. Additionally, it generates detailed security reports in PDF format.

[![Demo Video](https://img.shields.io/badge/Demo-Video-blue)](https://youtu.be/-d10O9g7cP0?si=Zke_5oUPLDyBEfUp)

---

## Table of Contents

- [Features](#features)
- [How It Works](#how-it-works)
  - [Pre-trained Model](#pre-trained-model)
  - [Capabilities and Limitations](#capabilities-and-limitations)
- [Technologies Used](#technologies-used)
- [Installation](#installation)
- [Project Structure](#project-structure)
- [Usage](#usage)
  - [Web Mode](#web-mode)
  - [CLI Mode](#cli-mode)
  - [REST API](#rest-api)
- [Testing](#testing)
- [Future Enhancements](#future-enhancements)
- [Contributing](#contributing)
- [Acknowledgments](#acknowledgments)

---

## Features

- **Web Mode**:
  - Upload code files via a user-friendly web interface.
  - Analyze code for vulnerabilities and display results dynamically.
  - Dark mode support for better user experience.
  - Displays recommended fixes for detected vulnerabilities.
  - Responsive design optimized for various devices.

- **CLI Mode**:
  - Analyze code files directly from the command line.
  - Output results in a structured format (e.g., JSON or plain text).
  - Ideal for developers who prefer terminal-based workflows.

- **REST API**:
  - Exposes an API endpoint for programmatic analysis of code.
  - Accepts JSON payloads with code and language information.
  - Returns predictions and recommended fixes.

- **Pre-trained Model**:
  - Utilizes a machine learning model trained on a dataset of secure and insecure code patterns.
  - Capable of detecting common vulnerabilities like SQL injection, XSS, and insecure file handling.

- **Dynamic Results**:
  - Provides detailed analysis results, including:
    - Vulnerability type.
    - Code snippet causing the issue.
    - Recommended fixes.

- **File Type Support**:
  - Supports multiple programming languages, including Python, JavaScript, C, Java, and PHP.

- **Security Report Generation**:
  - Generates a PDF report summarizing the analysis results.

---

## How It Works

### Pre-trained Model

The project uses a **pre-trained machine learning model** based on the `CodeBERTa` architecture. The model was fine-tuned on a dataset of secure and insecure code snippets, annotated with vulnerability types. Here's how it works:

1. **Input Processing**:
   - The uploaded or provided code file is tokenized and preprocessed into a format suitable for the model.
   
2. **Vulnerability Detection**:
   - The model analyzes the code for patterns associated with vulnerabilities.
   - It assigns a probability score to each detected issue.

3. **Recommendation Generation**:
   - Based on the detected vulnerabilities, the system generates recommendations for fixing the issues.

#### Model Details:
- **Architecture**: CodeBERTa (based on RoBERTa).
- **Training Dataset**: A curated dataset of 50,000+ secure and insecure code snippets.
- **Framework**: Hugging Face Transformers (PyTorch).
- **Limitations**:
  - The model is not perfect and may produce false positives or miss certain vulnerabilities.
  - It works best with common programming languages like Python, JavaScript, C, Java, and PHP.

---

### Capabilities and Limitations

#### What the Project Can Do:
- Detect common vulnerabilities in code files.
- Provide recommendations for fixing detected issues.
- Support both web and CLI modes for flexibility.
- Analyze multiple programming languages.
- Generate PDF reports summarizing the analysis.

#### What the Project Cannot Do:
- Detect highly complex or obscure vulnerabilities.
- Guarantee 100% accuracy in analysis.
- Replace manual code reviews by security experts.

---

## Technologies Used

- **Backend**: Flask (Python)
- **Frontend**: HTML, CSS, JavaScript
- **Machine Learning**: Hugging Face Transformers (CodeBERTa)
- **Database**: SQLite
- **PDF Generation**: ReportLab
- **Template Engine**: Jinja2
- **Styling**: Custom CSS
- **JavaScript Features**: LocalStorage for dark mode, dynamic animations
- **Testing**: Pytest (for backend testing)

---

## Installation

Follow these steps to set up the project locally:

1. **Clone the Repository**:
   ```bash
   https://github.com/zahrra55/security-analyzer.git
   cd code-security-analyzer
   ```

2. **Set Up a Virtual Environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the Application**:
   ```bash
   flask --app analyze run
   ```

5. Open your browser and navigate to `http://127.0.0.1:5000`.

---

## Project Structure

```
security_analyze/
├── __pycache__/
│   └── analyze.cpython-312.pyc 
├── Outputs/
│   └── Screen_Shoots.pdf 
├── static/
│   ├── css/
│   │   └── style.css          
│   ├── js/
│   │   └── script.js          
├── templates/
│   └── index.html             
├── testing/
│   ├── __pycache__/
│   │   ├── __init__.cpython-312.pyc 
│   │   ├── test_analyze.cpython-312-pytest-8.3.5.pyc              
│   ├── .pytest_cache/
│   │   ├── v/cache/
│   │    │   ├── lastfailed
│   │    │   ├── nodeids
│   │    │   ├── stepwise
│   │   ├── CACHEDIR.TAG 
│   │   ├── README.md     
│   ├── __init__.py               
│   ├── example.c              
│   ├── example.py     
│   ├── test_analyze.py        # Test suite for the application  
├── analyze.py                 # Main application script
├── analysis_results.db        # SQLite database for storing analysis results
├── Code Citations.md
├── requirements.txt           # Python dependencies
├── LICENSE
└── README.md                  # Project documentation
```

---

## Usage

### Web Mode

1.Run the web app with the following command:
   ```bash
   python analyze.py --web
   ```
2. Open the application in your browser.
3. Upload a code file using the provided form.
4. Click the "Analyze" button to start the security analysis.
5. View the results, including any detected vulnerabilities and recommended fixes.

### CLI Mode

1.Run the CLI tool with the following command:
   ```bash
   python analyze.py --cli
   ```
2. Follow the interactive prompts to analyze code snippets or files.

### REST API

1. Use the `/api/analyze` endpoint to analyze code programmatically.
2. Send a POST request with the following JSON payload:
   ```json
   {
       "code": "your code snippet here",
       "language": "python"
   }
   ```
3. Receive a response with the prediction and recommended fixes.

---

## Testing

To ensure the project is functioning correctly, run the test suite using `pytest`:

```bash
pytest test_analyze.py
```

This will execute all test cases in the `test_analyze.py` file, including:
- `analyze_code_vulnerability`: Tests for detecting vulnerabilities in code.
- `suggest_fix`: Tests for generating fixes for vulnerable code.
- `generate_security_report`: Tests for generating PDF reports.

---

## Future Enhancements

- **Support for Additional Languages**: Extend support to analyze more programming languages.
- **Detailed Reports**: Generate downloadable reports for the analysis results.
- **Real-Time Analysis**: Provide real-time feedback as the user uploads the file.
- **User Authentication**: Add user accounts to save analysis history.
- **Improved Model Accuracy**: Train the model on a larger and more diverse dataset.

---

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Commit your changes and push them to your fork.
4. Submit a pull request with a detailed description of your changes.

---

## Acknowledgments

- **CS50**: For inspiring this project.
- **Flask Documentation**: For providing excellent resources.
- **Hugging Face**: For enabling the use of CodeBERTa.
- **Open Source Libraries**: For making development easier.

---
