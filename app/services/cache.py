import hashlib
from functools import lru_cache
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)

# Cache for code analysis results
CODE_CACHE: Dict[str, Dict[str, Any]] = {}

@lru_cache(maxsize=1000)
def get_code_hash(code: str) -> str:
    """Generate a hash for the code snippet."""
    return hashlib.md5(code.encode()).hexdigest()

def get_cached_result(code: str) -> Dict[str, Any]:
    """Get cached analysis result for code."""
    code_hash = get_code_hash(code)
    return CODE_CACHE.get(code_hash)

def cache_result(code: str, result: Dict[str, Any]) -> None:
    """Cache analysis result for code."""
    try:
        code_hash = get_code_hash(code)
        CODE_CACHE[code_hash] = result
    except Exception as e:
        logger.error(f"Error caching result: {e}")

def clear_cache() -> None:
    """Clear the code analysis cache."""
    CODE_CACHE.clear()
    get_code_hash.cache_clear() 