import pytest
import json
from app.models.database import DatabaseConnection

def test_analyze_code(client, sample_python_code):
    """Test code analysis endpoint."""
    response = client.post('/api/analyze',
        json={
            'code': sample_python_code,
            'language': 'python'
        }
    )
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'vulnerabilities' in data
    assert 'prediction' in data
    assert 'fixed_code' in data
    assert data['cached'] is False

def test_analyze_code_cached(client, sample_python_code):
    """Test code analysis caching."""
    # First request
    response1 = client.post('/api/analyze',
        json={
            'code': sample_python_code,
            'language': 'python'
        }
    )
    assert response1.status_code == 200
    
    # Second request (should be cached)
    response2 = client.post('/api/analyze',
        json={
            'code': sample_python_code,
            'language': 'python'
        }
    )
    assert response2.status_code == 200
    data = json.loads(response2.data)
    assert data['cached'] is True

def test_analyze_code_invalid_request(client):
    """Test code analysis with invalid request."""
    response = client.post('/api/analyze',
        json={
            'code': '',  # Empty code
            'language': 'python'
        }
    )
    assert response.status_code == 400

def test_analyze_code_invalid_language(client, sample_python_code):
    """Test code analysis with invalid language."""
    response = client.post('/api/analyze',
        json={
            'code': sample_python_code,
            'language': 'invalid_language'
        }
    )
    assert response.status_code == 400

def test_health_check(client):
    """Test health check endpoint."""
    response = client.get('/api/health')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['status'] == 'healthy'
    assert 'version' in data
    assert data['database'] == 'connected'

def test_metrics(client):
    """Test metrics endpoint."""
    response = client.get('/api/metrics')
    assert response.status_code == 200
    assert b'code_analysis_total' in response.data
    assert b'vulnerabilities_detected_total' in response.data

def test_supported_languages(client):
    """Test supported languages endpoint."""
    response = client.get('/api/supported-languages')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'languages' in data
    assert isinstance(data['languages'], list)
    assert 'python' in data['languages']

def test_rate_limiting(client, sample_python_code):
    """Test rate limiting."""
    # Make multiple requests quickly
    for _ in range(11):  # Should be limited at 10 per minute
        response = client.post('/api/analyze',
            json={
                'code': sample_python_code,
                'language': 'python'
            }
        )
    
    assert response.status_code == 429  # Too Many Requests

def test_generate_report(client, sample_python_code):
    """Test report generation."""
    response = client.post('/api/analyze?generate_report=true',
        json={
            'code': sample_python_code,
            'language': 'python'
        }
    )
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'report_path' in data
    assert data['report_path'].endswith('.pdf') 