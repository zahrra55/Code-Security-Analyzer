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

# Suppress model initialization warnings
warnings.filterwarnings("ignore", message="Some weights of RobertaForSequenceClassification were not initialized")
logging.getLogger("transformers.modeling_utils").setLevel(logging.ERROR)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load fine-tuned model and tokenizer
MODEL_NAME = "huggingface/CodeBERTa-small-v1"
try:
    tokenizer = RobertaTokenizer.from_pretrained(MODEL_NAME)
    model = RobertaForSequenceClassification.from_pretrained(MODEL_NAME)
    logging.info("Model and tokenizer loaded successfully.")
except Exception as e:
    logging.error(f"Error loading model or tokenizer: {e}")
    raise

# Flask app initialization
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'c', 'py', 'java', 'js', 'php'}

# Database initialization
DB_FILE = "analysis_results.db"

def init_db():
    """Initialize the SQLite database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analysis_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            language TEXT,
            prediction INTEGER,
            fixed_code TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def save_result(filename, language, prediction, fixed_code):
    """Save analysis results to the database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO analysis_results (filename, language, prediction, fixed_code)
        VALUES (?, ?, ?, ?)
    """, (filename, language, prediction, fixed_code))
    conn.commit()
    conn.close()

# Helper functions
def allowed_file(filename):
    """Check if the uploaded file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def detect_language(file_path):
    """Detect the programming language based on the file extension."""
    _, ext = os.path.splitext(file_path)
    language_map = {
        '.c': 'c',
        '.h': 'c',
        '.py': 'python',
        '.java': 'java',
        '.js': 'javascript',
        '.php': 'php'
    }
    return language_map.get(ext, 'unknown')

def analyze_code_vulnerability(code_snippet, language):
    """Analyze code snippet for vulnerabilities using explicit checks and the fine-tuned model."""
    try:
        # Explicitly check for known vulnerabilities
        vulnerabilities = {
            'c': ["gets(", "strcpy("],
            'python': ["eval(", "exec("],
            'java': ["System.exec(", "Runtime.getRuntime().exec("],
            'javascript': ["eval(", "Function("],
            'php': ["eval(", "exec("]
        }
        if language in vulnerabilities:
            for vuln in vulnerabilities[language]:
                if vuln in code_snippet:
                    logging.info(f"Detected explicit vulnerability: {vuln}")
                    return 1  # Vulnerability detected

        # Use the model to analyze the code snippet
        inputs = tokenizer(code_snippet, return_tensors='pt', truncation=True, padding=True, max_length=512)
        with torch.no_grad():
            outputs = model(**inputs)
        logits = outputs.logits
        prediction = torch.argmax(logits, dim=-1).item()
        logging.info(f"Model logits: {logits}")
        logging.info(f"Model prediction: {prediction} (1 = Vulnerable, 0 = Secure)")
        return prediction
    except Exception as e:
        logging.error(f"Error analyzing code snippet: {e}")
        return -1  # Return -1 for errors
    
def suggest_fix(code_snippet, language):
    """Suggest fixes for common vulnerabilities based on the language."""
    fixes = {
        'c': {
            "gets(": "fgets(input, sizeof(input), stdin);",
            "strcpy(": "strncpy(buffer, input, sizeof(buffer) - 1); buffer[sizeof(buffer) - 1] = '\\0';"
        },
        'python': {
            "eval(": "# Avoid using eval; consider safer alternatives like ast.literal_eval\n",
            "exec(": "# Avoid using exec; consider safer alternatives\n"
        },
        'java': {
            "System.exec(": "// Avoid using System.exec; consider safer alternatives\n",
            "Runtime.getRuntime().exec(": "// Avoid using Runtime.exec; consider safer alternatives\n"
        },
        'javascript': {
            "eval(": "// Avoid using eval; consider safer alternatives\n",
            "Function(": "// Avoid using Function constructor; consider safer alternatives\n"
        },
        'php': {
            "eval(": "// Avoid using eval; consider safer alternatives\n",
            "exec(": "// Avoid using exec; consider safer alternatives\n"
        }
    }

    # Check for vulnerabilities and suggest fixes
    if language in fixes:
        fixed_code = code_snippet
        found_vulnerability = False
        for vuln, fix in fixes[language].items():
            if vuln in code_snippet:
                logging.info(f"Detected vulnerability: {vuln}. Suggesting fix: {fix}")
                fixed_code = fixed_code.replace(vuln, fix)
                found_vulnerability = True
        return fixed_code if found_vulnerability else None
    else:
        logging.info(f"No fixes available for language: {language}")
        return None
    
def generate_security_report(filename, code, prediction, execution_time, fixed_code=None, output_dir="."):
    """Generate a PDF security report using reportlab."""
    try:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        pdf_path = os.path.join(output_dir, f"{filename}_security_report_{timestamp}.pdf")
        c = canvas.Canvas(pdf_path, pagesize=letter)
        c.setFont("Helvetica", 12)
        c.drawString(72, 750, "Code Security Analysis Report")
        c.drawString(72, 730, f"File: {filename}")
        c.drawString(72, 710, f"Execution Time: {execution_time:.4f} seconds")
        c.drawString(72, 690, "Analyzed Code:")
        
        # Adjust the starting position for the code block
        y_position = 670
        line_height = 14  # Adjust line height as needed
        
        # Split the code into lines and draw each line
        for line in code[:1000].split('\n'):  # Truncate long code
            c.drawString(72, y_position, line)
            y_position -= line_height
        
        if prediction == 1:
            c.setFillColorRGB(1, 0, 0)  # Red
            c.drawString(72, y_position - line_height, "⚠️  Vulnerabilities detected!")
            c.setFillColorRGB(0, 0, 0)  # Black
            c.drawString(72, y_position - 2 * line_height, "🔴 Vulnerability detected in the code.")
            if fixed_code:
                c.drawString(72, y_position - 3 * line_height, "✅ Recommended Fix:")
                y_position -= 4 * line_height
                for line in fixed_code[:1000].split('\n'):  # Truncate long code
                    c.drawString(72, y_position, line)
                    y_position -= line_height
        else:
            c.setFillColorRGB(0, 0.5, 0)  # Green
            c.drawString(72, y_position - line_height, "✅ Code is secure!")
        
        c.save()
        logging.info(f"Analysis report saved to {pdf_path}")
        return pdf_path  # Return the path of the generated PDF
    except Exception as e:
        logging.error(f"Error generating security report: {e}")
        return None

def interactive_cli():
    """Interactive CLI for analyzing code."""
    print("Welcome to the Code Security Analyzer CLI!")
    print("Type 'exit' to quit.")
    while True:
        print("\nOptions:")
        print("1. Analyze a code snippet")
        print("2. Analyze a file")
        choice = input("Enter your choice (1/2): ").strip()
        if choice == "exit":
            print("Exiting CLI. Goodbye!")
            break
        elif choice == "1":
            code = input("Enter the code snippet to analyze:\n")
            language = input("Enter the programming language (e.g., python, c, java): ").strip().lower()
            start_time = time.time()
            prediction = analyze_code_vulnerability(code, language)
            execution_time = time.time() - start_time
            fixed_code = suggest_fix(code, language) if prediction == 1 else None
            print("\nAnalysis Result:")
            if prediction == 1:
                print("⚠️ Vulnerabilities detected!")
                print("Recommended Fix:\n", fixed_code)
            else:
                print("✅ Code is secure!")

            # Generate the PDF report
            generate_security_report("snippet", code, prediction, execution_time, fixed_code)
        elif choice == "2":
            file_path = input("Enter the file path to analyze: ").strip()
            if not os.path.exists(file_path):
                print("Error: File not found!")
                continue
            with open(file_path, 'r') as f:
                code = f.read()
            language = detect_language(file_path)
            start_time = time.time()
            prediction = analyze_code_vulnerability(code, language)
            execution_time = time.time() - start_time
            fixed_code = suggest_fix(code, language) if prediction == 1 else None
            print("\nAnalysis Result:")
            if prediction == 1:
                print("⚠️ Vulnerabilities detected!")
                print("Recommended Fix:\n", fixed_code)
            else:
                print("✅ Code is secure!")

            # Generate the PDF report
            generate_security_report(file_path, code, prediction, execution_time, fixed_code)
        else:
            print("Invalid choice. Please try again.")

def analyze_files_parallel(file_paths):
    """Analyze multiple files in parallel."""
    def analyze_file(file_path):
        if not os.path.exists(file_path):
            return {"file": file_path, "error": "File not found"}
        with open(file_path, 'r') as f:
            code = f.read()
        language = detect_language(file_path)
        prediction = analyze_code_vulnerability(code, language)
        fixed_code = suggest_fix(code, language) if prediction == 1 else None
        return {
            "file": file_path,
            "prediction": prediction,
            "fixed_code": fixed_code
        }

    results = []
    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(analyze_file, file_path): file_path for file_path in file_paths}
        for future in futures:
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                results.append({"file": futures[future], "error": str(e)})

    # Print results
    for result in results:
        print(f"\nFile: {result['file']}")
        if "error" in result:
            print(f"Error: {result['error']}")
        else:
            if result["prediction"] == 1:
                print("⚠️ Vulnerabilities detected!")
                print("Recommended Fix:\n", result["fixed_code"])
            else:
                print("✅ Code is secure!")

                
# Flask routes
from flask import send_file

@app.route("/", methods=["GET", "POST"])
def index():
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
            start_time = time.time()
            prediction = analyze_code_vulnerability(code, language)
            execution_time = time.time() - start_time
            fixed_code = suggest_fix(code, language) if prediction == 1 else None
            save_result(filename, language, prediction, fixed_code)

            # Generate the PDF report
            pdf_path = generate_security_report(filename, code, prediction, execution_time, fixed_code)

            # Render the results and provide a link to download the PDF
            return render_template(
                "index.html",
                execution_time=execution_time,
                result=prediction,
                code=code,
                fixed_code=fixed_code,
                pdf_path=pdf_path
            )
    return render_template("index.html")

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """REST API for analyzing code."""
    try:
        data = request.get_json()
        code = data.get("code")
        language = data.get("language")
        if not code or not language:
            return jsonify({"error": "Code and language are required"}), 400
        prediction = analyze_code_vulnerability(code, language)
        fixed_code = suggest_fix(code, language) if prediction == 1 else None
        return jsonify({
            "prediction": prediction,
            "fixed_code": fixed_code
        })
    except Exception as e:
        logging.error(f"Error in API: {e}")
        return jsonify({"error": "An internal error occurred"}), 500

@app.route("/download/<path:pdf_path>")
def download_pdf(pdf_path):
    """Serve the generated PDF report for download."""
    try:
        return send_file(pdf_path, as_attachment=True)
    except Exception as e:
        logging.error(f"Error serving PDF file: {e}")
        return jsonify({"error": "File not found"}), 404
    
def main():
    """Main function to handle command-line arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument("files", nargs='*', help="File paths to analyze")
    parser.add_argument("--cli", action="store_true", help="Start interactive CLI mode")
    parser.add_argument("--web", action="store_true", help="Start web UI")
    args = parser.parse_args()

    if args.cli:
        interactive_cli()
    elif args.web:
        init_db()
        app.run(debug=True)
    elif args.files:
        analyze_files_parallel(args.files)
    else:
        print("No input provided. Use --cli, --web, or specify file paths.")

        
if __name__ == "__main__":
    main()