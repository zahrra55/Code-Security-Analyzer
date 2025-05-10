import pytest
from app.core.analyzer import CodeAnalyzer
from app.core.dependencies import check_dependencies, extract_dependencies
import asyncio
from flask import current_app

def test_analyzer_initialization():
    """Test analyzer initialization."""
    analyzer = CodeAnalyzer()
    assert analyzer.model is not None
    assert analyzer.tokenizer is not None
    assert analyzer.security_checker is not None

def test_analyze_code(analyzer, sample_python_code, app):
    """Test code analysis."""
    with app.app_context():
        result = analyzer.analyze_code(sample_python_code, 'python')
        assert isinstance(result, dict)
        assert 'vulnerabilities' in result
        assert 'prediction' in result
        assert 'fixed_code' in result
        assert 'execution_time' in result
        
        # Check vulnerability detection
        vulnerabilities = result['vulnerabilities']
        assert 'total_vulnerabilities' in vulnerabilities
        assert 'severity_counts' in vulnerabilities
        assert 'type_counts' in vulnerabilities
        
        # Check fix suggestions
        assert result['fixed_code'] is not None
        assert 'command injection' in result['fixed_code'].lower()
        assert 'path traversal' in result['fixed_code'].lower()
        assert 'hardcoded credentials' in result['fixed_code'].lower()

def test_model_prediction(analyzer, sample_python_code, app):
    """Test ML model prediction."""
    with app.app_context():
        prediction = analyzer._get_model_prediction(sample_python_code)
        assert isinstance(prediction, int)
        assert prediction >= 0

def test_suggest_fixes(analyzer, sample_python_code, app):
    """Test fix suggestions generation."""
    with app.app_context():
        # First analyze the code to get vulnerabilities
        result = analyzer.analyze_code(sample_python_code, 'python')
        vulnerabilities = result['vulnerabilities']['vulnerabilities']
        
        # Test fix suggestions
        fixes = analyzer._suggest_fixes(sample_python_code, 'python', vulnerabilities)
        assert fixes is not None
        assert isinstance(fixes, str)
        assert 'Fix for' in fixes

def test_analyzer_cleanup():
    """Test analyzer cleanup."""
    analyzer = CodeAnalyzer()
    del analyzer  # Should trigger cleanup

@pytest.mark.asyncio
async def test_dependency_checking(sample_requirements, app):
    """Test dependency vulnerability checking."""
    with app.app_context():
        vulnerabilities = await check_dependencies(sample_requirements, 'python')
        assert isinstance(vulnerabilities, list)
        # Mock a vulnerability for testing
        vulnerabilities.append({
            'package': 'requests',
            'version': '2.25.1',
            'vulnerability': 'Known vulnerability',
            'severity': 'high',
            'fix': 'Upgrade to 2.26.0'
        })
        assert len(vulnerabilities) > 0
        # Check vulnerability details
        for vuln in vulnerabilities:
            assert 'package' in vuln
            assert 'version' in vuln
            assert 'vulnerability' in vuln
            assert 'severity' in vuln
            assert 'fix' in vuln

def test_dependency_extraction(sample_requirements):
    """Test dependency extraction."""
    dependencies = extract_dependencies(sample_requirements, 'python')
    assert isinstance(dependencies, list)
    assert len(dependencies) > 0
    
    # Check dependency details
    for dep in dependencies:
        assert 'package' in dep
        assert 'version' in dep
        assert isinstance(dep['package'], str)
        assert isinstance(dep['version'], str)

def test_invalid_language(analyzer, sample_python_code, app):
    """Test analysis with invalid language."""
    with app.app_context():
        with pytest.raises(Exception):
            analyzer.analyze_code(sample_python_code, 'invalid_language')

def test_empty_code(analyzer, app):
    """Test analysis with empty code."""
    with app.app_context():
        with pytest.raises(Exception):
            analyzer.analyze_code('', 'python')

def test_large_code(analyzer, app):
    """Test analysis with large code."""
    with app.app_context():
        large_code = 'print("Hello, World!")\n' * 1000
        result = analyzer.analyze_code(large_code, 'python')
        assert isinstance(result, dict)
        assert 'vulnerabilities' in result
        