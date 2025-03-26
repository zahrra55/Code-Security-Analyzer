import pytest
from analyze import analyze_code_vulnerability, suggest_fix, generate_security_report
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from analyze import analyze_code_vulnerability, suggest_fix, generate_security_report
def test_analyze_code_vulnerability():
    """Test the analyze_code_vulnerability function."""
    # Test with vulnerable code
    code = "eval('print(1)')"
    language = "python"
    prediction = analyze_code_vulnerability(code, language)
    assert prediction == 1  # Vulnerability detected

    # Test with secure code
    code = "print('Hello, World!')"
    prediction = analyze_code_vulnerability(code, language)
    assert prediction == 0  # No vulnerability detected

def test_suggest_fix():
    """Test the suggest_fix function."""
    # Test with vulnerable code
    code = "eval('print(1)')"
    language = "python"
    fixed_code = suggest_fix(code, language)
    assert "Avoid using eval" in fixed_code  # Ensure the fix recommendation is correct

    # Test with secure code
    code = "print('Hello, World!')"
    language = "python"
    fixed_code = suggest_fix(code, language)
    assert fixed_code is None  # No fix needed for secure code

def test_generate_security_report(tmp_path):
    """Test the generate_security_report function."""
    # Create a temporary directory for the test
    temp_dir = tmp_path / "reports"
    temp_dir.mkdir()

    # Define test inputs
    filename = "test_file.py"
    code = "eval('print(1)')"
    prediction = 1  # Vulnerability detected
    execution_time = 0.1234
    fixed_code = "Avoid using eval and use safer alternatives."

    # Generate the report
    pdf_path = generate_security_report(filename, code, prediction, execution_time, fixed_code, output_dir=temp_dir)

    # Check if the PDF file was created
    assert os.path.exists(pdf_path)

def test_generate_security_report_no_vulnerability(tmp_path):
    """Test generate_security_report when no vulnerabilities are detected."""
    # Create a temporary directory for the test
    temp_dir = tmp_path / "reports"
    temp_dir.mkdir()

    # Define test inputs
    filename = "secure_file.py"
    code = "print('Hello, World!')"
    prediction = 0  # No vulnerability detected
    execution_time = 0.0456
    fixed_code = None

    # Generate the report
    pdf_path = generate_security_report(filename, code, prediction, execution_time, fixed_code, output_dir=temp_dir)

    # Check if the PDF file was created
    assert os.path.exists(pdf_path)