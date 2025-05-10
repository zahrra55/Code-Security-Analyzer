# Code Security Analyzer

A comprehensive code security analysis tool that helps developers identify and fix security vulnerabilities in their code.

## Features

- **Multi-language Support**: Analyzes Python, JavaScript, Java, C, and PHP code
- **Real-time Analysis**: Get instant feedback on code security
- **Vulnerability Detection**: Identifies common security vulnerabilities
- **Fix Suggestions**: Provides detailed fix suggestions for identified issues
- **PDF Reports**: Generates comprehensive security reports
- **API Access**: RESTful API for integration with other tools
- **Web Interface**: Modern, responsive web UI with dark mode support
- **Dependency Analysis**: Checks for vulnerable dependencies
- **Performance Metrics**: Prometheus metrics for monitoring
- **Rate Limiting**: API rate limiting for production use
- **Caching**: Efficient caching for improved performance
- **Async Support**: Asynchronous processing for better scalability

## Project Structure

```
code-security-analyzer/
├── app/
│   ├── __init__.py
│   ├── api/
│   │   ├── __init__.py
│   │   ├── routes.py
│   │   └── validators.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── analyzer.py
│   │   ├── security.py
│   │   └── dependencies.py
│   ├── models/
│   │   ├── __init__.py
│   │   └── database.py
│   ├── services/
│   │   ├── __init__.py
│   │   ├── report.py
│   │   └── cache.py
│   └── utils/
│       ├── __init__.py
│       └── helpers.py
├── static/
│   ├── css/
│   │   └── styles.css
│   └── js/
│       └── main.js
├── templates/
│   └── index.html
├── tests/
│   ├── __init__.py
│   ├── test_analyzer.py
│   └── test_security.py
├── config/
│   ├── __init__.py
│   └── settings.py
├── requirements.txt
├── setup.py
└── README.md
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/code-security-analyzer.git
cd code-security-analyzer
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Web Interface

Start the web server:
```bash
python -m app
```

Visit `http://localhost:5000` in your browser.

### API

The API is available at `http://localhost:5000/api/analyze`:

```bash
curl -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"code": "your code here", "language": "python"}'
```

### CLI

Analyze files from the command line:
```bash
python -m app --cli
```

## Development

1. Install development dependencies:
```bash
pip install -r requirements-dev.txt
```

2. Run tests:
```bash
pytest
```

3. Run linting:
```bash
flake8
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
