from flask import Flask, jsonify, render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from prometheus_client import Counter, Histogram
import logging
from logging.handlers import RotatingFileHandler
import os
from config.settings import Config
from app.models.database import DatabaseConnection

# Configure logging
def setup_logging(app):
    """Setup logging configuration."""
    log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
    os.makedirs(log_dir, exist_ok=True)
    
    log_file = os.path.join(log_dir, 'app.log')
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    ))
    
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

# Prometheus metrics
ANALYSIS_COUNTER = Counter('code_analysis_total', 'Total number of code analyses')
ANALYSIS_DURATION = Histogram('code_analysis_duration_seconds', 'Time spent analyzing code')
VULNERABILITY_COUNTER = Counter('vulnerabilities_detected_total', 'Total number of vulnerabilities detected', ['severity'])
API_ERROR_COUNTER = Counter('api_errors_total', 'Total number of API errors', ['endpoint', 'error_type'])

def create_app(config=None):
    """Create and configure the Flask application."""
    app = Flask(__name__)
    
    # Load configuration
    if config is None:
        from config.default import Config
        app.config.from_object(Config)
    else:
        app.config.from_object(config)
    
    # Setup logging
    setup_logging(app)
    logger = logging.getLogger(__name__)
    
    # Initialize extensions
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        storage_uri=app.config['RATE_LIMIT_STORAGE_URL'],
        strategy=app.config['RATE_LIMIT_STRATEGY']
    )
    app.extensions['limiter'] = limiter
    
    # Initialize database
    db = DatabaseConnection()
    db.init_app(app)
    
    # Register blueprints
    from app.api.routes import api_bp
    app.register_blueprint(api_bp)
    
    # Add root route
    @app.route('/')
    def index():
        return render_template('index.html')
    
    # Add favicon route
    @app.route('/favicon.ico')
    def favicon():
        return app.send_static_file('favicon.ico')
    
    # Initialize database within app context
    with app.app_context():
        try:
            from app.models.database import init_db
            init_db()
            logger.info("Database initialized successfully")
        except Exception as e:
            logger.error(f"Error initializing database: {e}")
            raise
    
    # Create necessary directories
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['REPORT_OUTPUT_DIR'], exist_ok=True)
    
    # Register error handlers
    @app.errorhandler(404)
    def not_found_error(error):
        API_ERROR_COUNTER.labels(endpoint='404', error_type='not_found').inc()
        return jsonify({'error': 'Not found'}), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        API_ERROR_COUNTER.labels(endpoint='500', error_type='internal').inc()
        return jsonify({'error': 'Internal server error'}), 500
    
    @app.errorhandler(429)
    def ratelimit_error(error):
        API_ERROR_COUNTER.labels(endpoint='429', error_type='ratelimit').inc()
        return jsonify({'error': 'Rate limit exceeded'}), 429
    
    # Register cleanup function
    @app.teardown_appcontext
    def cleanup(exception=None):
        """Cleanup resources when the application context is torn down."""
        try:
            DatabaseConnection().close_all()
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
    
    return app 

__all__ = ["limiter"] 