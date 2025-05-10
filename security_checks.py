from typing import Dict, List, Set, Tuple, Any
import re
from dataclasses import dataclass
from enum import Enum

class VulnerabilityType(Enum):
    SQL_INJECTION = "SQL Injection"
    XSS = "Cross-Site Scripting"
    COMMAND_INJECTION = "Command Injection"
    PATH_TRAVERSAL = "Path Traversal"
    INSECURE_DESERIALIZATION = "Insecure Deserialization"
    INSECURE_FILE_HANDLING = "Insecure File Handling"
    HARDCODED_CREDENTIALS = "Hardcoded Credentials"
    INSECURE_CRYPTO = "Insecure Cryptography"
    INSECURE_DEPENDENCIES = "Insecure Dependencies"
    RACE_CONDITION = "Race Condition"

@dataclass
class Vulnerability:
    type: VulnerabilityType
    line_number: int
    code_snippet: str
    severity: str
    description: str
    fix_suggestion: str

class SecurityChecker:
    def __init__(self):
        self.patterns: Dict[str, Dict[VulnerabilityType, List[Tuple[str, str]]]] = {
            'python': {
                VulnerabilityType.SQL_INJECTION: [
                    (r"execute\s*\(\s*[\"'].*?\+.*?[\"']", "String concatenation in SQL query"),
                    (r"cursor\.execute\s*\(\s*[\"'].*?\+.*?[\"']", "String concatenation in SQL query")
                ],
                VulnerabilityType.XSS: [
                    (r"print\s*\(\s*request\.form\s*\[.*?\]\s*\)", "Direct output of user input"),
                    (r"response\.write\s*\(\s*request\.form\s*\[.*?\]\s*\)", "Direct output of user input")
                ],
                VulnerabilityType.COMMAND_INJECTION: [
                    (r"os\.system\s*\(\s*.*?\+.*?\s*\)", "Command injection through os.system"),
                    (r"subprocess\.call\s*\(\s*.*?\+.*?\s*\)", "Command injection through subprocess")
                ],
                VulnerabilityType.PATH_TRAVERSAL: [
                    (r"open\s*\(\s*.*?\+.*?\s*\)", "Path traversal in file open"),
                    (r"os\.path\.join\s*\(\s*.*?\+.*?\s*\)", "Path traversal in path join")
                ],
                VulnerabilityType.INSECURE_DESERIALIZATION: [
                    (r"pickle\.loads\s*\(\s*.*?\s*\)", "Insecure deserialization with pickle"),
                    (r"yaml\.load\s*\(\s*.*?\s*\)", "Insecure deserialization with yaml")
                ],
                VulnerabilityType.HARDCODED_CREDENTIALS: [
                    (r"password\s*=\s*[\"'].*?[\"']", "Hardcoded password"),
                    (r"api_key\s*=\s*[\"'].*?[\"']", "Hardcoded API key")
                ],
                VulnerabilityType.INSECURE_CRYPTO: [
                    (r"hashlib\.md5\s*\(\s*.*?\s*\)", "Insecure hashing algorithm (MD5)"),
                    (r"hashlib\.sha1\s*\(\s*.*?\s*\)", "Insecure hashing algorithm (SHA1)")
                ]
            },
            'javascript': {
                VulnerabilityType.SQL_INJECTION: [
                    (r"query\s*\(\s*[\"'].*?\+.*?[\"']", "String concatenation in SQL query"),
                    (r"execute\s*\(\s*[\"'].*?\+.*?[\"']", "String concatenation in SQL query")
                ],
                VulnerabilityType.XSS: [
                    (r"innerHTML\s*=\s*.*?\+.*?", "Direct assignment to innerHTML"),
                    (r"document\.write\s*\(\s*.*?\+.*?\s*\)", "Direct document.write with user input")
                ],
                VulnerabilityType.COMMAND_INJECTION: [
                    (r"exec\s*\(\s*.*?\+.*?\s*\)", "Command injection through exec"),
                    (r"eval\s*\(\s*.*?\+.*?\s*\)", "Command injection through eval")
                ],
                VulnerabilityType.INSECURE_DESERIALIZATION: [
                    (r"JSON\.parse\s*\(\s*.*?\s*\)", "Insecure deserialization with JSON.parse"),
                    (r"eval\s*\(\s*.*?\s*\)", "Insecure deserialization with eval")
                ],
                VulnerabilityType.HARDCODED_CREDENTIALS: [
                    (r"password\s*:\s*[\"'].*?[\"']", "Hardcoded password"),
                    (r"apiKey\s*:\s*[\"'].*?[\"']", "Hardcoded API key")
                ]
            },
            'java': {
                VulnerabilityType.SQL_INJECTION: [
                    (r"executeQuery\s*\(\s*[\"'].*?\+.*?[\"']", "String concatenation in SQL query"),
                    (r"createStatement\s*\(\s*[\"'].*?\+.*?[\"']", "String concatenation in SQL query")
                ],
                VulnerabilityType.XSS: [
                    (r"response\.getWriter\(\)\.write\s*\(\s*.*?\+.*?\s*\)", "Direct output of user input"),
                    (r"out\.println\s*\(\s*.*?\+.*?\s*\)", "Direct output of user input")
                ],
                VulnerabilityType.COMMAND_INJECTION: [
                    (r"Runtime\.getRuntime\(\)\.exec\s*\(\s*.*?\+.*?\s*\)", "Command injection through Runtime.exec"),
                    (r"ProcessBuilder\s*\(\s*.*?\+.*?\s*\)", "Command injection through ProcessBuilder")
                ],
                VulnerabilityType.INSECURE_DESERIALIZATION: [
                    (r"ObjectInputStream\s*\(\s*.*?\s*\)", "Insecure deserialization with ObjectInputStream"),
                    (r"XMLDecoder\s*\(\s*.*?\s*\)", "Insecure deserialization with XMLDecoder")
                ],
                VulnerabilityType.HARDCODED_CREDENTIALS: [
                    (r"password\s*=\s*[\"'].*?[\"']", "Hardcoded password"),
                    (r"apiKey\s*=\s*[\"'].*?[\"']", "Hardcoded API key")
                ]
            }
        }

        self.fix_suggestions: Dict[VulnerabilityType, str] = {
            VulnerabilityType.SQL_INJECTION: "Use parameterized queries or prepared statements",
            VulnerabilityType.XSS: "Use proper output encoding and sanitization",
            VulnerabilityType.COMMAND_INJECTION: "Use safe APIs and input validation",
            VulnerabilityType.PATH_TRAVERSAL: "Use proper path validation and sanitization",
            VulnerabilityType.INSECURE_DESERIALIZATION: "Use safe deserialization methods",
            VulnerabilityType.INSECURE_FILE_HANDLING: "Use proper file handling with validation",
            VulnerabilityType.HARDCODED_CREDENTIALS: "Use environment variables or secure configuration",
            VulnerabilityType.INSECURE_CRYPTO: "Use strong cryptographic algorithms",
            VulnerabilityType.INSECURE_DEPENDENCIES: "Update dependencies to secure versions",
            VulnerabilityType.RACE_CONDITION: "Implement proper synchronization"
        }

    def check_code(self, code: str, language: str) -> List[Vulnerability]:
        """Check code for security vulnerabilities."""
        vulnerabilities = []
        
        if language not in self.patterns:
            return vulnerabilities

        lines = code.split('\n')
        for line_number, line in enumerate(lines, 1):
            for vuln_type, patterns in self.patterns[language].items():
                for pattern, description in patterns:
                    if re.search(pattern, line):
                        vulnerabilities.append(Vulnerability(
                            type=vuln_type,
                            line_number=line_number,
                            code_snippet=line.strip(),
                            severity=self._get_severity(vuln_type),
                            description=description,
                            fix_suggestion=self.fix_suggestions[vuln_type]
                        ))

        return vulnerabilities

    def _get_severity(self, vuln_type: VulnerabilityType) -> str:
        """Get severity level for vulnerability type."""
        severity_map = {
            VulnerabilityType.SQL_INJECTION: "High",
            VulnerabilityType.XSS: "Medium",
            VulnerabilityType.COMMAND_INJECTION: "Critical",
            VulnerabilityType.PATH_TRAVERSAL: "High",
            VulnerabilityType.INSECURE_DESERIALIZATION: "High",
            VulnerabilityType.INSECURE_FILE_HANDLING: "Medium",
            VulnerabilityType.HARDCODED_CREDENTIALS: "High",
            VulnerabilityType.INSECURE_CRYPTO: "High",
            VulnerabilityType.INSECURE_DEPENDENCIES: "Medium",
            VulnerabilityType.RACE_CONDITION: "Medium"
        }
        return severity_map.get(vuln_type, "Low")

    def get_vulnerability_summary(self, vulnerabilities: List[Vulnerability]) -> Dict[str, Any]:
        """Generate a summary of vulnerabilities."""
        summary = {
            "total_vulnerabilities": len(vulnerabilities),
            "severity_counts": {
                "Critical": 0,
                "High": 0,
                "Medium": 0,
                "Low": 0
            },
            "type_counts": {},
            "vulnerabilities": []
        }

        for vuln in vulnerabilities:
            # Update severity counts
            summary["severity_counts"][vuln.severity] += 1
            
            # Update type counts
            vuln_type = vuln.type.value
            summary["type_counts"][vuln_type] = summary["type_counts"].get(vuln_type, 0) + 1
            
            # Add vulnerability details
            summary["vulnerabilities"].append({
                "type": vuln_type,
                "line_number": vuln.line_number,
                "code_snippet": vuln.code_snippet,
                "severity": vuln.severity,
                "description": vuln.description,
                "fix_suggestion": vuln.fix_suggestion
            })

        return summary 