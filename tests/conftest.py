import pytest
from app import create_app
from app.models.database import DatabaseConnection, init_db
import os
import tempfile
import shutil
from app.core.analyzer import CodeAnalyzer

@pytest.fixture
def app():
    """Create and configure a Flask app for testing."""
    # Create a temporary directory for test files
    test_dir = tempfile.mkdtemp()
    
    # Create test configuration
    class TestConfig:
        TESTING = True
        DATABASE_URL = 'sqlite:///test.db'
        UPLOAD_FOLDER = os.path.join(test_dir, 'uploads')
        REPORT_OUTPUT_DIR = os.path.join(test_dir, 'reports')
        RATE_LIMIT_STORAGE_URL = "memory://"
        RATE_LIMIT_STRATEGY = "fixed-window"
        ALLOWED_EXTENSIONS = {'py', 'js', 'java', 'c', 'php'}
    
    # Create the app with test configuration
    app = create_app(TestConfig)
    
    # Create test directories
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['REPORT_OUTPUT_DIR'], exist_ok=True)
    
    # Initialize test database
    with app.app_context():
        init_db()
    
    yield app
    
    # Cleanup
    shutil.rmtree(test_dir)
    if os.path.exists('test.db'):
        os.remove('test.db')

@pytest.fixture
def client(app):
    """Create a test client for the app."""
    return app.test_client()

@pytest.fixture
def runner(app):
    """Create a test CLI runner for the app."""
    return app.test_cli_runner()

@pytest.fixture
def sample_python_code():
    """Return a sample Python code with vulnerabilities."""
    return """
import os
import subprocess

def execute_command(command):
    os.system(command)  # Security vulnerability: command injection

def read_file(filename):
    with open(filename, 'r') as f:
        return f.read()  # Security vulnerability: path traversal

def connect_to_db():
    password = "hardcoded_password"  # Security vulnerability: hardcoded credentials
    return password
"""

@pytest.fixture
def sample_requirements():
    """Return a sample requirements.txt with vulnerable dependencies."""
    return """
requests==2.25.1  # Known vulnerability
django==2.2.0  # Known vulnerability
flask==0.12.0  # Known vulnerability
"""

@pytest.fixture
def analyzer():
    return CodeAnalyzer()

@pytest.fixture
def limiter(app):
    """Provide the limiter instance for tests."""
    return app.extensions['limiter'] 