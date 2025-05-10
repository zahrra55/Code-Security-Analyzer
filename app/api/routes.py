from flask import Blueprint, request, jsonify, current_app
from app.core.analyzer import CodeAnalyzer
from app.api.validators import validate_analysis_request
from app.services.report import generate_security_report
from app.services.cache import get_cached_result, cache_result
import logging
import os
from app import limiter  # Import the limiter instance from app/__init__.py

api_bp = Blueprint('api', __name__)
logger = logging.getLogger(__name__)

# Initialize analyzer
analyzer = CodeAnalyzer()

@api_bp.route('/analyze', methods=['POST'])
@limiter.limit("10 per minute")
def analyze_code():
    """Analyze code for security vulnerabilities."""
    try:
        # Validate request
        data = validate_analysis_request(request)
        if not data:
            return jsonify({'error': 'Invalid request data'}), 400

        code = data.get('code')
        language = data.get('language')

        # Check cache first
        cached_result = get_cached_result(code)
        if cached_result:
            return jsonify({
                'status': 'success',
                'cached': True,
                **cached_result
            })

        # Analyze code
        result = analyzer.analyze_code(code, language)

        # Cache the result
        cache_result(code, result)

        # Generate report if requested
        if request.args.get('generate_report', 'false').lower() == 'true':
            report_path = generate_security_report(
                filename="api_request",
                code=code,
                prediction=result['prediction'],
                execution_time=result['execution_time'],
                fixed_code=result['fixed_code'],
                vulnerabilities=result['vulnerabilities'],
                dependency_vulnerabilities=result['dependency_vulnerabilities']
            )
            if report_path:
                result['report_path'] = report_path
            else:
                logger.warning("Failed to generate security report")

        return jsonify({
            'status': 'success',
            'cached': False,
            **result
        })

    except Exception as e:
        logger.error(f"Error in API: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@api_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    try:
        # Check database connection
        from app.models.database import DatabaseConnection
        conn = DatabaseConnection().get_connection()
        conn.execute("SELECT 1")
        
        return jsonify({
            'status': 'healthy',
            'version': '1.0.0',
            'database': 'connected'
        })
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            'status': 'unhealthy',
            'version': '1.0.0',
            'error': str(e)
        }), 500

@api_bp.route('/metrics', methods=['GET'])
def metrics():
    """Prometheus metrics endpoint."""
    try:
        from prometheus_client import generate_latest
        return generate_latest()
    except Exception as e:
        logger.error(f"Metrics generation failed: {str(e)}")
        return jsonify({'error': 'Failed to generate metrics'}), 500

@api_bp.route('/supported-languages', methods=['GET'])
def supported_languages():
    """Get list of supported programming languages."""
    try:
        return jsonify({
            'languages': list(current_app.config['ALLOWED_EXTENSIONS'])
        })
    except Exception as e:
        logger.error(f"Failed to get supported languages: {str(e)}")
        return jsonify({'error': 'Failed to get supported languages'}), 500 