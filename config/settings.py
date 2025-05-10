import os
from datetime import timedelta

class Config:
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    
    # Allowed file extensions
    ALLOWED_EXTENSIONS = {'py', 'js', 'java', 'c', 'php'}
    
    # Database settings
    DATABASE_URL = os.environ.get('DATABASE_URL') or 'sqlite:///analysis_results.db'
    
    # Cache settings
    CACHE_TYPE = 'simple'
    CACHE_DEFAULT_TIMEOUT = 300
    
    # Model settings
    MODEL_NAME = "huggingface/CodeBERTa-small-v1"
    MODEL_CACHE_SIZE = 1000
    
    # Security settings
    RATE_LIMIT_STORAGE_URL = "memory://"
    RATE_LIMIT_STRATEGY = "fixed-window"
    
    # API settings
    API_TITLE = 'Code Security Analyzer API'
    API_VERSION = 'v1'
    OPENAPI_VERSION = '3.0.2'
    OPENAPI_URL_PREFIX = '/'
    OPENAPI_SWAGGER_UI_PATH = '/swagger-ui'
    OPENAPI_SWAGGER_UI_URL = 'https://cdn.jsdelivr.net/npm/swagger-ui-dist/'
    
    # Monitoring settings
    ENABLE_METRICS = True
    METRICS_PORT = 9090
    
    # Logging settings
    LOG_LEVEL = 'INFO'
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    LOG_FILE = 'app.log'
    
    # Report settings
    REPORT_OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'reports')
    REPORT_TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates')
    
    @staticmethod
    def init_app(app):
        # Create necessary directories
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        os.makedirs(app.config['REPORT_OUTPUT_DIR'], exist_ok=True) 