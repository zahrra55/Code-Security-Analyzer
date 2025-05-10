import pytest
from app.models.database import (
    DatabaseConnection,
    save_analysis_result,
    save_dependency_vulnerabilities,
    get_analysis_result,
    get_dependency_vulnerabilities
)
from app.services.cache import get_code_hash

def test_database_connection(app):
    """Test database connection."""
    conn = DatabaseConnection()
    assert conn is not None

    with app.app_context():
        with conn.get_connection() as db:
            assert db is not None

def test_save_analysis_result(app):
    """Test saving analysis results."""
    with app.app_context():
        code = "print('Hello, World!')"
        code_hash = get_code_hash(code)
        
        analysis_id = save_analysis_result(
            filename="test.py",
            language="python",
            prediction=1,
            fixed_code="print('Hello, World!')  # Fixed",
            code_hash=code_hash,
            vulnerabilities=[
                {
                    "type": "command_injection",
                    "severity": "high",
                    "line_number": 1,
                    "description": "Potential command injection",
                    "fix_suggestion": "Use subprocess.run with shell=False"
                }
            ],
            severity_counts={"high": 1},
            execution_time=0.1
        )
        
        assert analysis_id is not None
        
        # Verify saved result
        result = get_analysis_result(code_hash)
        assert result is not None
        assert result['filename'] == "test.py"
        assert result['language'] == "python"
        assert result['prediction'] == 1

def test_save_dependency_vulnerabilities(app):
    """Test saving dependency vulnerabilities."""
    with app.app_context():
        # First save an analysis result
        code = "import requests"
        code_hash = get_code_hash(code)
        
        analysis_id = save_analysis_result(
            filename="test.py",
            language="python",
            prediction=1,
            fixed_code="import requests  # Fixed",
            code_hash=code_hash,
            vulnerabilities=[],
            severity_counts={},
            execution_time=0.1
        )
        
        # Save dependency vulnerabilities
        vulnerabilities = [
            {
                "package": "requests",
                "version": "2.25.1",
                "vulnerability": "CVE-2021-1234: Remote code execution",
                "severity": "high",
                "fix": "Update to version 2.26.0"
            }
        ]
        
        save_dependency_vulnerabilities(analysis_id, vulnerabilities)
        
        # Verify saved vulnerabilities
        saved_vulns = get_dependency_vulnerabilities(analysis_id)
        assert len(saved_vulns) == 1
        assert saved_vulns[0]['package'] == "requests"
        assert saved_vulns[0]['version'] == "2.25.1"
        assert saved_vulns[0]['severity'] == "high"

def test_database_cleanup(app):
    """Test database cleanup."""
    with app.app_context():
        conn = DatabaseConnection()
        conn.close_all()
        
        # Try to get a new connection
        with conn.get_connection() as db:
            cursor = db.cursor()
            cursor.execute("SELECT 1")
            result = cursor.fetchone()
            assert result[0] == 1

def test_concurrent_connections(app):
    """Test concurrent database connections."""
    with app.app_context():
        conn = DatabaseConnection()
        
        # Create multiple connections
        connections = []
        for _ in range(5):
            with conn.get_connection() as db:
                cursor = db.cursor()
                cursor.execute("SELECT 1")
                result = cursor.fetchone()
                assert result[0] == 1
                connections.append(db)
        
        # Verify all connections work
        for db in connections:
            cursor = db.cursor()
            cursor.execute("SELECT 1")
            result = cursor.fetchone()
            assert result[0] == 1

def test_transaction_rollback(app):
    """Test transaction rollback."""
    with app.app_context():
        conn = DatabaseConnection()
        
        with conn.get_connection() as db:
            cursor = db.cursor()
            
            # Start transaction
            cursor.execute("BEGIN TRANSACTION")
            
            # Insert test data
            cursor.execute("""
                INSERT INTO analysis_results (
                    filename, language, prediction, code_hash
                ) VALUES (?, ?, ?, ?)
            """, ("test.py", "python", 1, "test_hash"))
            
            # Rollback transaction
            db.rollback()
            
            # Verify data was not saved
            cursor.execute("SELECT * FROM analysis_results WHERE code_hash = ?", ("test_hash",))
            result = cursor.fetchone()
            assert result is None 