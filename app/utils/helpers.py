import os
import logging
from typing import Optional
from flask import current_app

logger = logging.getLogger(__name__)

def get_file_extension(filename: str) -> Optional[str]:
    """Get file extension from filename."""
    try:
        return filename.rsplit('.', 1)[1].lower()
    except IndexError:
        return None

def is_allowed_file(filename: str) -> bool:
    """Check if file extension is allowed."""
    extension = get_file_extension(filename)
    return extension in current_app.config['ALLOWED_EXTENSIONS']

def get_language_from_extension(extension: str) -> Optional[str]:
    """Get programming language from file extension."""
    extension_map = {
        'py': 'python',
        'js': 'javascript',
        'java': 'java',
        'c': 'c',
        'php': 'php'
    }
    return extension_map.get(extension)

def ensure_directory(directory: str) -> None:
    """Ensure directory exists, create if it doesn't."""
    try:
        if not os.path.exists(directory):
            os.makedirs(directory)
    except Exception as e:
        logger.error(f"Error creating directory {directory}: {e}")

def format_code(code: str) -> str:
    """Format code for display."""
    try:
        # Remove extra whitespace
        code = '\n'.join(line.rstrip() for line in code.split('\n'))
        
        # Ensure proper line endings
        code = code.replace('\r\n', '\n').replace('\r', '\n')
        
        return code
    except Exception as e:
        logger.error(f"Error formatting code: {e}")
        return code

def get_file_size(file_path: str) -> int:
    """Get file size in bytes."""
    try:
        return os.path.getsize(file_path)
    except Exception as e:
        logger.error(f"Error getting file size: {e}")
        return 0

def is_file_too_large(file_path: str) -> bool:
    """Check if file is too large for processing."""
    try:
        size = get_file_size(file_path)
        return size > current_app.config['MAX_CONTENT_LENGTH']
    except Exception as e:
        logger.error(f"Error checking file size: {e}")
        return True 