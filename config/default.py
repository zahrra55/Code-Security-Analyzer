import os

class Config:
    """Default configuration for the application."""
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev')
    DEBUG = False
    TESTING = False
    
    # Database settings
    DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///app.db')
    
    # File upload settings
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    ALLOWED_EXTENSIONS = {'py', 'js', 'java', 'cpp', 'c', 'h', 'hpp', 'cs', 'go', 'rs', 'php', 'rb', 'swift', 'kt', 'ts'}
    
    # Report settings
    REPORT_OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'reports')
    
    # Rate limiting settings
    RATE_LIMIT_STORAGE_URL = "memory://"
    RATE_LIMIT_STRATEGY = "fixed-window"
    RATE_LIMIT_DEFAULT = "200 per day, 50 per hour"
    
    # Model settings
    MODEL_PATH = "huggingface/CodeBERTa-small-v1"
    MAX_SEQUENCE_LENGTH = 512
    
    # Logging settings
    LOG_LEVEL = "INFO"
    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs', 'app.log') 