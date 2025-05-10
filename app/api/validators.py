from flask import request, current_app
from typing import Dict, Any, Optional

def validate_analysis_request(request) -> Optional[Dict[str, Any]]:
    """Validate the analysis request data."""
    try:
        data = request.get_json()
        if not data:
            return None

        # Check required fields
        if 'code' not in data or not data['code']:
            return None
        if 'language' not in data or not data['language']:
            return None

        # Validate language
        if data['language'] not in current_app.config['ALLOWED_EXTENSIONS']:
            return None

        # Validate code length
        if len(data['code']) > current_app.config['MAX_CONTENT_LENGTH']:
            return None

        return data

    except Exception:
        return None

def validate_file_upload(request) -> Optional[Dict[str, Any]]:
    """Validate file upload request."""
    try:
        if 'file' not in request.files:
            return None

        file = request.files['file']
        if file.filename == '':
            return None

        # Check file extension
        if not allowed_file(file.filename):
            return None

        return {'file': file}

    except Exception:
        return None

def allowed_file(filename: str) -> bool:
    """Check if the file extension is allowed."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS'] 