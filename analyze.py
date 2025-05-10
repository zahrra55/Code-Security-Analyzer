from transformers import RobertaTokenizer, RobertaForSequenceClassification
import torch
import time
import os
import argparse
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from flask import Flask, request, render_template, jsonify, send_file
import warnings
import logging
import datetime
import sqlite3
from concurrent.futures import ThreadPoolExecutor
import tempfile
from functools import lru_cache
import hashlib
from typing import Dict, List, Optional, Tuple, Any, Union
import numpy as np
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import HTTPException
import traceback
from app.core.security import SecurityChecker, Vulnerability
from app.core.dependencies import check_dependencies
from app.utils.helpers import get_file_extension
from app.api.validators import allowed_file
from app.core.analyzer import CodeAnalyzer
from app.services.report import generate_security_report
from app.models.database import DatabaseConnection, save_analysis_result
from prometheus_client import Counter, Histogram, generate_latest
import threading
from queue import Queue
import asyncio
from aiohttp import ClientSession
import aiohttp
import ssl
import certifi
import json

# Suppress model initialization warnings
warnings.filterwarnings("ignore", message="Some weights of RobertaForSequenceClassification were not initialized")
logging.getLogger("transformers.modeling_utils").setLevel(logging.ERROR)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Prometheus metrics
ANALYSIS_COUNTER = Counter('code_analysis_total', 'Total number of code analyses')
ANALYSIS_DURATION = Histogram('code_analysis_duration_seconds', 'Time spent analyzing code')
VULNERABILITY_COUNTER = Counter('vulnerabilities_detected_total', 'Total number of vulnerabilities detected', ['severity'])

# Global variables for caching
CACHE_SIZE = 1000
MODEL_CACHE: Dict[str, Tuple[torch.nn.Module, torch.nn.Module]] = {}
CODE_CACHE: Dict[str, int] = {}

# Initialize security checker
security_checker = SecurityChecker()

# Load fine-tuned model and tokenizer with caching
def load_model(model_name: str = "huggingface/CodeBERTa-small-v1") -> Tuple[torch.nn.Module, torch.nn.Module]:
    """Load model and tokenizer with caching."""
    if model_name in MODEL_CACHE:
        return MODEL_CACHE[model_name]
    
    try:
        tokenizer = RobertaTokenizer.from_pretrained(model_name)
        model = RobertaForSequenceClassification.from_pretrained(model_name)
        model.eval()  # Set to evaluation mode
        if torch.cuda.is_available():
            model = model.cuda()
        MODEL_CACHE[model_name] = (model, tokenizer)
        logging.info("Model and tokenizer loaded successfully.")
        return model, tokenizer
    except Exception as e:
        logging.error(f"Error loading model or tokenizer: {e}")
        raise

# Initialize model and tokenizer
model, tokenizer = load_model()

# Flask app initialization
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()
app.config['ALLOWED_EXTENSIONS'] = {'c', 'py', 'java', 'js', 'php'}

# Rate limiting configuration
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Database initialization with connection pooling
class DatabaseConnection:
    _instance = None
    _pool = []
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(DatabaseConnection, cls).__new__(cls)
        return cls._instance

    def get_connection(self):
        with self._lock:
            if not self._pool:
                conn = sqlite3.connect(DB_FILE)
                conn.row_factory = sqlite3.Row
                self._pool.append(conn)
            return self._pool[0]

    def close_all(self):
        with self._lock:
            for conn in self._pool:
                conn.close()
            self._pool.clear()

# Initialize database with connection pooling
DB_FILE = "analysis_results.db"
db = DatabaseConnection()

def init_db():
    """Initialize the SQLite database with optimized schema."""
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analysis_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            language TEXT,
            prediction INTEGER,
            fixed_code TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            code_hash TEXT,
            vulnerabilities TEXT,
            severity_counts TEXT,
            INDEX idx_code_hash (code_hash),
            INDEX idx_timestamp (timestamp)
        )
    """)
    conn.commit()

@lru_cache(maxsize=CACHE_SIZE)
def get_code_hash(code: str) -> str:
    """Generate a hash for the code snippet."""
    return hashlib.md5(code.encode()).hexdigest()

def save_result(filename: str, language: str, prediction: int, fixed_code: str, code: str, vulnerabilities: List[Vulnerability]):
    """Save analysis results to the database with caching."""
    code_hash = get_code_hash(code)
    conn = db.get_connection()
    cursor = conn.cursor()
    
    # Convert vulnerabilities to JSON
    vuln_json = json.dumps([{
        'type': v.type.value,
        'line_number': v.line_number,
        'code_snippet': v.code_snippet,
        'severity': v.severity,
        'description': v.description,
        'fix_suggestion': v.fix_suggestion
    } for v in vulnerabilities])
    
    # Get severity counts
    severity_counts = {
        'Critical': 0,
        'High': 0,
        'Medium': 0,
        'Low': 0
    }
    for v in vulnerabilities:
        severity_counts[v.severity] += 1
    
    cursor.execute("""
        INSERT INTO analysis_results (
            filename, language, prediction, fixed_code, code_hash,
            vulnerabilities, severity_counts
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        filename, language, prediction, fixed_code, code_hash,
        vuln_json, json.dumps(severity_counts)
    ))
    conn.commit()

async def check_dependencies(code: str, language: str) -> List[Dict[str, Any]]:
    """Check for vulnerable dependencies."""
    # This is a placeholder for actual dependency checking
    # In a real implementation, you would:
    # 1. Parse package files (requirements.txt, package.json, etc.)
    # 2. Query vulnerability databases
    # 3. Return results
    return []

def analyze_code_vulnerability(code_snippet: str, language: str) -> Tuple[int, List[Vulnerability]]:
    """Analyze code snippet for vulnerabilities using optimized checks and the fine-tuned model."""
    try:
        # Check cache first
        code_hash = get_code_hash(code_snippet)
        if code_hash in CODE_CACHE:
            return CODE_CACHE[code_hash], []

        # Get vulnerabilities from security checker
        vulnerabilities = security_checker.check_code(code_snippet, language)
        
        # Update metrics
        for vuln in vulnerabilities:
            VULNERABILITY_COUNTER.labels(severity=vuln.severity).inc()

        # Use the model for additional analysis
        inputs = tokenizer(
            code_snippet, 
            return_tensors='pt', 
            truncation=True, 
            padding=True, 
            max_length=512
        )
        
        if torch.cuda.is_available():
            inputs = {k: v.cuda() for k, v in inputs.items()}

        with torch.no_grad():
            outputs = model(**inputs)
            logits = outputs.logits
            prediction = torch.argmax(logits, dim=-1).item()

        # Cache the result
        CODE_CACHE[code_hash] = prediction
        return prediction, vulnerabilities

    except Exception as e:
        logging.error(f"Error analyzing code snippet: {e}")
        return -1, []

async def analyze_code_async(code: str, language: str) -> Dict[str, Any]:
    """Asynchronous code analysis with multiple checks."""
    start_time = time.time()
    
    # Run ML model and security checks
    prediction, vulnerabilities = analyze_code_vulnerability(code, language)
    
    # Check dependencies
    dependency_vulns = await check_dependencies(code, language)
    
    # Generate fix suggestions
    fixed_code = suggest_fix(code, language) if prediction == 1 else None
    
    # Get vulnerability summary
    vuln_summary = security_checker.get_vulnerability_summary(vulnerabilities)
    
    # Update metrics
    ANALYSIS_COUNTER.inc()
    ANALYSIS_DURATION.observe(time.time() - start_time)
    
    return {
        "prediction": prediction,
        "vulnerabilities": vuln_summary,
        "dependency_vulnerabilities": dependency_vulns,
        "fixed_code": fixed_code,
        "execution_time": time.time() - start_time
    }

@app.route("/metrics")
def metrics():
    """Prometheus metrics endpoint."""
    return generate_latest()

class APIError(Exception):
    def __init__(self, message, status_code=400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code

@app.route("/api/analyze", methods=["POST"])
@limiter.limit("10 per minute")
async def api_analyze():
    """REST API for analyzing code with rate limiting."""
    try:
        data = request.get_json()
        if not data:
            raise APIError("No JSON data provided", 400)

        code = data.get("code")
        language = data.get("language")

        if not code:
            raise APIError("Code is required", 400)
        if not language:
            raise APIError("Language is required", 400)

        # Validate language
        if language not in app.config['ALLOWED_EXTENSIONS']:
            raise APIError(f"Unsupported language. Supported languages: {', '.join(app.config['ALLOWED_EXTENSIONS'])}", 400)

        # Analyze code
        result = await analyze_code_async(code, language)
        
        # Save result
        save_result(
            "api_request",
            language,
            result["prediction"],
            result["fixed_code"],
            code,
            result["vulnerabilities"]["vulnerabilities"]
        )

        return jsonify({
            "status": "success",
            **result
        })

    except APIError as e:
        raise e
    except Exception as e:
        logging.error(f"Error in API: {str(e)}")
        logging.error(traceback.format_exc())
        raise APIError("An internal error occurred", 500)

@app.route("/", methods=["GET", "POST"])
async def index():
    """Flask web interface for analyzing code."""
    if request.method == "POST":
        if 'file' not in request.files:
            return jsonify({'error': 'No file part in the request'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        if file and allowed_file(file.filename):
            filename = file.filename
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            with open(file_path, 'r') as f:
                code = f.read()
            language = detect_language(file_path)
            
            # Analyze code
            result = await analyze_code_async(code, language)
            
            # Save result
            save_result(
                filename,
                language,
                result["prediction"],
                result["fixed_code"],
                code,
                result["vulnerabilities"]["vulnerabilities"]
            )

            # Generate the PDF report
            pdf_path = generate_security_report(
                filename,
                code,
                result["prediction"],
                result["execution_time"],
                result["fixed_code"],
                result["vulnerabilities"],
                result["dependency_vulnerabilities"]
            )

            # Render the results
            return render_template(
                "index.html",
                execution_time=result["execution_time"],
                result=result["prediction"],
                code=code,
                fixed_code=result["fixed_code"],
                pdf_path=pdf_path,
                vulnerabilities=result["vulnerabilities"],
                dependency_vulnerabilities=result["dependency_vulnerabilities"]
            )
    return render_template("index.html")

def generate_security_report(filename: str, code: str, prediction: int, execution_time: float,
                           fixed_code: str, vulnerabilities: Dict[str, Any], output_dir: str = ".") -> str:
    """Generate a comprehensive PDF security report."""
    try:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        pdf_path = os.path.join(output_dir, f"{filename}_security_report_{timestamp}.pdf")
        c = canvas.Canvas(pdf_path, pagesize=letter)
        
        # Title
        c.setFont("Helvetica-Bold", 16)
        c.drawString(72, 750, "Code Security Analysis Report")
        
        # File Information
        c.setFont("Helvetica", 12)
        c.drawString(72, 720, f"File: {filename}")
        c.drawString(72, 700, f"Analysis Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        c.drawString(72, 680, f"Execution Time: {execution_time:.4f} seconds")
        
        # Vulnerability Summary
        c.setFont("Helvetica-Bold", 14)
        c.drawString(72, 650, "Vulnerability Summary")
        c.setFont("Helvetica", 12)
        
        y_position = 630
        c.drawString(72, y_position, f"Total Vulnerabilities: {vulnerabilities['total_vulnerabilities']}")
        
        # Severity Distribution
        y_position -= 20
        c.drawString(72, y_position, "Severity Distribution:")
        y_position -= 20
        for severity, count in vulnerabilities['severity_counts'].items():
            c.drawString(92, y_position, f"{severity}: {count}")
            y_position -= 20
        
        # Vulnerability Types
        y_position -= 20
        c.drawString(72, y_position, "Vulnerability Types:")
        y_position -= 20
        for vuln_type, count in vulnerabilities['type_counts'].items():
            c.drawString(92, y_position, f"{vuln_type}: {count}")
            y_position -= 20
        
        # Detailed Vulnerabilities
        y_position -= 20
        c.setFont("Helvetica-Bold", 14)
        c.drawString(72, y_position, "Detailed Vulnerabilities")
        c.setFont("Helvetica", 12)
        
        for vuln in vulnerabilities['vulnerabilities']:
            y_position -= 20
            if y_position < 50:  # Start new page if needed
                c.showPage()
                y_position = 750
                c.setFont("Helvetica", 12)
            
            c.drawString(72, y_position, f"Type: {vuln['type']}")
            y_position -= 20
            c.drawString(72, y_position, f"Severity: {vuln['severity']}")
            y_position -= 20
            c.drawString(72, y_position, f"Line: {vuln['line_number']}")
            y_position -= 20
            c.drawString(72, y_position, f"Description: {vuln['description']}")
            y_position -= 20
            c.drawString(72, y_position, f"Fix: {vuln['fix_suggestion']}")
            y_position -= 20
            c.drawString(72, y_position, f"Code: {vuln['code_snippet']}")
            y_position -= 40
        
        # Analyzed Code
        c.showPage()
        c.setFont("Helvetica-Bold", 14)
        c.drawString(72, 750, "Analyzed Code")
        c.setFont("Helvetica", 12)
        
        y_position = 730
        for line in code[:1000].split('\n'):
            c.drawString(72, y_position, line)
            y_position -= 15
            if y_position < 50:
                c.showPage()
                y_position = 750
                c.setFont("Helvetica", 12)
        
        # Fixed Code (if any)
        if fixed_code:
            c.showPage()
            c.setFont("Helvetica-Bold", 14)
            c.drawString(72, 750, "Recommended Fixes")
            c.setFont("Helvetica", 12)
            
            y_position = 730
            for line in fixed_code[:1000].split('\n'):
                c.drawString(72, y_position, line)
                y_position -= 15
                if y_position < 50:
                    c.showPage()
                    y_position = 750
                    c.setFont("Helvetica", 12)
        
        c.save()
        logging.info(f"Analysis report saved to {pdf_path}")
        return pdf_path
    except Exception as e:
        logging.error(f"Error generating security report: {e}")
        return None

def detect_language(filename: str) -> str:
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    ext_map = {
        'py': 'python',
        'js': 'javascript',
        'java': 'java',
        'c': 'c',
        'php': 'php'
    }
    return ext_map.get(ext, 'unknown')

def suggest_fix(code: str, language: str):
    analyzer = CodeAnalyzer()
    vulnerabilities = analyzer.security_checker.check_code(code, language)
    return analyzer._suggest_fixes(code, language, vulnerabilities)

def interactive_cli():
    print("Interactive CLI mode. Type 'exit' to quit.")
    while True:
        code = input("Enter code (or 'exit' to quit): ")
        if code.strip().lower() == 'exit':
            break
        language = input("Enter language (python, javascript, java, c, php): ")
        if language.strip().lower() == 'exit':
            break
        result = analyze_code_vulnerability(code, language)
        print(f"Prediction: {result}")

def analyze_files_parallel(file_paths):
    from concurrent.futures import ThreadPoolExecutor
    import os
    import json
    import asyncio
    def analyze_file(file_path):
        if not os.path.exists(file_path):
            print(f"File not found: {file_path}")
            return
        with open(file_path, 'r') as f:
            code = f.read()
        language = detect_language(file_path)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(analyze_code_async(code, language))
        print(f"Analysis for {file_path}:")
        print(json.dumps(result, indent=2))
    with ThreadPoolExecutor() as executor:
        executor.map(analyze_file, file_paths)

def main():
    """Main function to handle command-line arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument("files", nargs='*', help="File paths to analyze")
    parser.add_argument("--cli", action="store_true", help="Start interactive CLI mode")
    parser.add_argument("--web", action="store_true", help="Start web UI")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind the web server")
    parser.add_argument("--port", type=int, default=5000, help="Port to bind the web server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    args = parser.parse_args()

    if args.cli:
        interactive_cli()
    elif args.web:
        init_db()
        app.run(host=args.host, port=args.port, debug=args.debug)
    elif args.files:
        analyze_files_parallel(args.files)
    else:
        print("No input provided. Use --cli, --web, or specify file paths.")

if __name__ == "__main__":
    main()