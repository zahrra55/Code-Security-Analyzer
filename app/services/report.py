from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import os
import datetime
import logging
from typing import Dict, Any, List
from flask import current_app

logger = logging.getLogger(__name__)

def generate_security_report(
    filename: str,
    code: str,
    prediction: int,
    execution_time: float,
    fixed_code: str,
    vulnerabilities: Dict[str, Any],
    dependency_vulnerabilities: List[Dict[str, Any]]
) -> str:
    """Generate a comprehensive PDF security report."""
    try:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = current_app.config['REPORT_OUTPUT_DIR']
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
        
        # Dependency Vulnerabilities
        if dependency_vulnerabilities:
            c.showPage()
            c.setFont("Helvetica-Bold", 14)
            c.drawString(72, 750, "Dependency Vulnerabilities")
            c.setFont("Helvetica", 12)
            
            y_position = 730
            for dep_vuln in dependency_vulnerabilities:
                c.drawString(72, y_position, f"Package: {dep_vuln['package']}")
                y_position -= 20
                c.drawString(72, y_position, f"Version: {dep_vuln['version']}")
                y_position -= 20
                c.drawString(72, y_position, f"Vulnerability: {dep_vuln['vulnerability']}")
                y_position -= 20
                c.drawString(72, y_position, f"Fix: {dep_vuln['fix']}")
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
        logger.info(f"Analysis report saved to {pdf_path}")
        return pdf_path
        
    except Exception as e:
        logger.error(f"Error generating security report: {e}")
        return None 