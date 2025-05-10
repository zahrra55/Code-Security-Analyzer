from transformers import RobertaTokenizer, RobertaForSequenceClassification
import torch
import time
from typing import Dict, List, Tuple, Any, Optional
import logging
from functools import lru_cache
from app import ANALYSIS_COUNTER, ANALYSIS_DURATION, VULNERABILITY_COUNTER
from app.core.security import SecurityChecker
from app.services.cache import get_code_hash, get_cached_result, cache_result
from app.core.dependencies import check_dependencies
from app.models.database import save_analysis_result, save_dependency_vulnerabilities
import gc

logger = logging.getLogger(__name__)

class CodeAnalyzer:
    def __init__(self, model_name: str = "huggingface/CodeBERTa-small-v1"):
        self.model_name = model_name
        self.model = None
        self.tokenizer = None
        self.security_checker = SecurityChecker()
        self._load_model()

    def _load_model(self) -> None:
        """Load and cache the model and tokenizer."""
        try:
            if self.model is None or self.tokenizer is None:
                self.tokenizer = RobertaTokenizer.from_pretrained(self.model_name)
                self.model = RobertaForSequenceClassification.from_pretrained(self.model_name)
                self.model.eval()
                if torch.cuda.is_available():
                    self.model = self.model.cuda()
                logger.info("Model and tokenizer loaded successfully")
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            raise

    def analyze_code(self, code: str, language: str) -> Dict[str, Any]:
        """Analyze code for vulnerabilities."""
        start_time = time.time()
        
        try:
            # Check cache first
            cached_result = get_cached_result(code)
            if cached_result:
                logger.info("Using cached analysis result")
                return cached_result

            # Get security vulnerabilities
            vulnerabilities = self.security_checker.check_code(code, language)
            
            # Update vulnerability metrics
            for vuln in vulnerabilities:
                VULNERABILITY_COUNTER.labels(severity=vuln.severity).inc()
            
            # Get ML model prediction
            prediction = self._get_model_prediction(code)
            
            # Check dependencies
            dependency_vulns = check_dependencies(code, language)
            
            # Generate fix suggestions
            fixed_code = self._suggest_fixes(code, language, vulnerabilities)
            
            # Get vulnerability summary
            vuln_summary = self.security_checker.get_vulnerability_summary(vulnerabilities)
            
            # Prepare result
            result = {
                "prediction": prediction,
                "vulnerabilities": vuln_summary,
                "dependency_vulnerabilities": dependency_vulns,
                "fixed_code": fixed_code,
                "execution_time": time.time() - start_time
            }
            
            # Cache the result
            cache_result(code, result)
            
            # Save to database
            code_hash = get_code_hash(code)
            analysis_id = save_analysis_result(
                filename="api_request",
                language=language,
                prediction=prediction,
                fixed_code=fixed_code,
                code_hash=code_hash,
                vulnerabilities=vulnerabilities,
                severity_counts=vuln_summary['severity_counts'],
                execution_time=result['execution_time']
            )
            
            if analysis_id and dependency_vulns:
                save_dependency_vulnerabilities(analysis_id, dependency_vulns)
            
            # Update metrics
            ANALYSIS_COUNTER.inc()
            ANALYSIS_DURATION.observe(time.time() - start_time)
            
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing code: {e}")
            raise
        finally:
            # Clean up GPU memory if available
            if torch.cuda.is_available():
                torch.cuda.empty_cache()
            gc.collect()

    def _get_model_prediction(self, code: str) -> int:
        """Get prediction from the ML model."""
        try:
            inputs = self.tokenizer(
                code,
                return_tensors='pt',
                truncation=True,
                padding=True,
                max_length=512
            )
            
            if torch.cuda.is_available():
                inputs = {k: v.cuda() for k, v in inputs.items()}
            
            with torch.no_grad():
                outputs = self.model(**inputs)
                prediction = torch.argmax(outputs.logits, dim=-1).item()
            
            return prediction
            
        except Exception as e:
            logger.error(f"Error getting model prediction: {e}")
            return -1

    def _suggest_fixes(self, code: str, language: str, vulnerabilities: List[Any]) -> Optional[str]:
        """Generate fix suggestions for identified vulnerabilities."""
        if not vulnerabilities:
            return None
            
        try:
            fixes = []
            for vuln in vulnerabilities:
                fixes.append(f"# Fix for {vuln.type.value} at line {vuln.line_number}")
                fixes.append(f"# {vuln.fix_suggestion}")
                fixes.append("")
            
            return "\n".join(fixes)
        except Exception as e:
            logger.error(f"Error generating fix suggestions: {e}")
            return None

    def __del__(self):
        """Cleanup when the analyzer is destroyed."""
        try:
            if self.model is not None:
                del self.model
            if self.tokenizer is not None:
                del self.tokenizer
            if torch.cuda.is_available():
                torch.cuda.empty_cache()
            gc.collect()
        except Exception as e:
            logger.error(f"Error during cleanup: {e}") 