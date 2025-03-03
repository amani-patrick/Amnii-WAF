import re
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from .config import settings
import logging

logger = logging.getLogger(__name__)

@dataclass
class RuleMatch:
    rule_name: str
    pattern: str
    matched_content: str
    severity: str
    confidence: float

class RulesEngine:
    def __init__(self):
        self.rules = settings.CUSTOM_RULES
        self._compile_rules()
    
    def _compile_rules(self):
        """Pre-compile regex patterns for better performance"""
        self.compiled_rules = {}
        for rule_type, rule_config in self.rules.items():
            if rule_config["enabled"]:
                self.compiled_rules[rule_type] = [
                    re.compile(pattern, re.IGNORECASE) 
                    for pattern in rule_config["patterns"]
                ]
    
    def _check_xss(self, content: str) -> List[RuleMatch]:
        """Check for XSS attacks in content"""
        matches = []
        if not settings.ENABLE_XSS_PROTECTION:
            return matches
            
        for pattern in self.compiled_rules.get("xss_patterns", []):
            if found := pattern.findall(content):
                matches.append(RuleMatch(
                    rule_name="XSS Detection",
                    pattern=pattern.pattern,
                    matched_content=found[0],
                    severity="HIGH",
                    confidence=0.9
                ))
        return matches

    def _check_sql_injection(self, content: str) -> List[RuleMatch]:
        """Check for SQL injection attempts"""
        matches = []
        if not settings.ENABLE_SQL_INJECTION_PROTECTION:
            return matches
            
        for pattern in self.compiled_rules.get("sql_injection_patterns", []):
            if found := pattern.findall(content):
                matches.append(RuleMatch(
                    rule_name="SQL Injection Detection",
                    pattern=pattern.pattern,
                    matched_content=found[0],
                    severity="CRITICAL",
                    confidence=0.95
                ))
        return matches

    def _check_path_traversal(self, content: str) -> List[RuleMatch]:
        """Check for path traversal attempts"""
        matches = []
        if not settings.ENABLE_PATH_TRAVERSAL_PROTECTION:
            return matches
            
        for pattern in self.compiled_rules.get("path_traversal_patterns", []):
            if found := pattern.findall(content):
                matches.append(RuleMatch(
                    rule_name="Path Traversal Detection",
                    pattern=pattern.pattern,
                    matched_content=found[0],
                    severity="HIGH",
                    confidence=0.85
                ))
        return matches

    def analyze_request(self, request_data: Dict) -> Tuple[bool, List[RuleMatch]]:
        """
        Analyze an HTTP request for potential security threats
        Returns: (is_threat, matches)
        """
        matches = []
        
        # Check URL path
        path = request_data.get("path", "")
        if path in settings.PATH_WHITELIST:
            return False, []
            
        # Check request method
        method = request_data.get("method", "").upper()
        if method not in settings.ALLOWED_HTTP_METHODS:
            matches.append(RuleMatch(
                rule_name="Invalid HTTP Method",
                pattern=method,
                matched_content=method,
                severity="MEDIUM",
                confidence=1.0
            ))
            
        # Analyze headers
        headers = request_data.get("headers", {})
        for header_name, header_value in headers.items():
            matches.extend(self._check_xss(header_value))
            matches.extend(self._check_sql_injection(header_value))
            
        # Analyze query parameters
        query_params = request_data.get("query_params", {})
        for param_name, param_value in query_params.items():
            matches.extend(self._check_xss(param_value))
            matches.extend(self._check_sql_injection(param_value))
            matches.extend(self._check_path_traversal(param_value))
            
        # Analyze body content
        body = request_data.get("body", "")
        if isinstance(body, str):
            matches.extend(self._check_xss(body))
            matches.extend(self._check_sql_injection(body))
            matches.extend(self._check_path_traversal(body))
            
        # Log findings
        if matches:
            logger.warning(f"Security threats detected: {len(matches)} matches found")
            for match in matches:
                logger.info(f"Rule match: {match}")
                
        return bool(matches), matches

    def should_block_request(self, matches: List[RuleMatch]) -> Tuple[bool, Optional[str]]:
        """Determine if request should be blocked based on rule matches"""
        if not matches:
            return False, None
            
        # Block if any critical severity matches
        critical_matches = [m for m in matches if m.severity == "CRITICAL"]
        if critical_matches:
            return True, "Critical security threat detected"
            
        # Block if multiple high severity matches
        high_matches = [m for m in matches if m.severity == "HIGH"]
        if len(high_matches) >= 2:
            return True, "Multiple high severity threats detected"
            
        # Block if high confidence match
        high_confidence_matches = [m for m in matches if m.confidence >= 0.9]
        if high_confidence_matches:
            return True, "High confidence security threat detected"
            
        return False, None
