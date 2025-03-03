import logging
import json
from datetime import datetime
from typing import Dict, Optional
import os
from pathlib import Path
from logging.handlers import RotatingFileHandler
from pythonjsonlogger import jsonlogger
from .config import settings

class RequestLogger:
    def __init__(self):
        self.setup_logging()
        
    def setup_logging(self):
        """Setup logging configuration"""
        # Create logs directory if it doesn't exist
        log_dir = Path(settings.LOG_DIR)
        log_dir.mkdir(exist_ok=True)
        
        # Setup access logger
        self.access_logger = logging.getLogger('waf.access')
        self.access_logger.setLevel(logging.INFO)
        
        # Setup error logger
        self.error_logger = logging.getLogger('waf.error')
        self.error_logger.setLevel(logging.ERROR)
        
        if settings.ENABLE_ACCESS_LOG:
            self._setup_access_handler()
            
        if settings.ENABLE_ERROR_LOG:
            self._setup_error_handler()
            
    def _setup_access_handler(self):
        """Setup handler for access logs"""
        access_file = Path(settings.LOG_DIR) / 'access.log'
        handler = RotatingFileHandler(
            access_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5
        )
        
        if settings.LOG_FORMAT.lower() == 'json':
            formatter = jsonlogger.JsonFormatter(
                '%(asctime)s %(name)s %(levelname)s %(message)s'
            )
        else:
            formatter = logging.Formatter(
                '[%(asctime)s] %(levelname)s: %(message)s'
            )
            
        handler.setFormatter(formatter)
        self.access_logger.addHandler(handler)
        
    def _setup_error_handler(self):
        """Setup handler for error logs"""
        error_file = Path(settings.LOG_DIR) / 'error.log'
        handler = RotatingFileHandler(
            error_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5
        )
        
        if settings.LOG_FORMAT.lower() == 'json':
            formatter = jsonlogger.JsonFormatter(
                '%(asctime)s %(name)s %(levelname)s %(message)s %(exc_info)s'
            )
        else:
            formatter = logging.Formatter(
                '[%(asctime)s] %(levelname)s: %(message)s'
            )
            
        handler.setFormatter(formatter)
        self.error_logger.addHandler(handler)
        
    def _sanitize_headers(self, headers: Dict) -> Dict:
        """Remove sensitive information from headers"""
        sanitized = headers.copy()
        sensitive_headers = [
            'authorization',
            'cookie',
            'x-api-key',
            'api-key',
            'password',
        ]
        
        for header in sensitive_headers:
            if header in sanitized:
                sanitized[header] = '[REDACTED]'
                
        return sanitized
        
    def log_request(
        self,
        request_data: Dict,
        status_code: int,
        response_time: float
    ):
        """Log a processed request"""
        try:
            log_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'client_ip': request_data.get('client_ip'),
                'method': request_data.get('method'),
                'path': request_data.get('path'),
                'status_code': status_code,
                'response_time': f"{response_time:.3f}s",
                'headers': self._sanitize_headers(request_data.get('headers', {})),
                'query_params': request_data.get('query_params'),
            }
            
            if settings.LOG_FORMAT.lower() == 'json':
                self.access_logger.info(json.dumps(log_data))
            else:
                self.access_logger.info(
                    f"{log_data['client_ip']} - {log_data['method']} "
                    f"{log_data['path']} {status_code} {log_data['response_time']}"
                )
                
        except Exception as e:
            self.error_logger.error(
                f"Error logging request: {str(e)}",
                exc_info=True
            )
            
    def log_blocked_request(
        self,
        request_data: Dict,
        status_code: int,
        reason: Optional[str] = None
    ):
        """Log a blocked request"""
        try:
            log_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'client_ip': request_data.get('client_ip'),
                'method': request_data.get('method'),
                'path': request_data.get('path'),
                'status_code': status_code,
                'reason': reason or 'Request blocked by WAF',
                'headers': self._sanitize_headers(request_data.get('headers', {})),
                'query_params': request_data.get('query_params'),
            }
            
            if settings.LOG_FORMAT.lower() == 'json':
                self.error_logger.warning(json.dumps(log_data))
            else:
                self.error_logger.warning(
                    f"Blocked request from {log_data['client_ip']} - "
                    f"{log_data['method']} {log_data['path']} "
                    f"{status_code} - {log_data['reason']}"
                )
                
        except Exception as e:
            self.error_logger.error(
                f"Error logging blocked request: {str(e)}",
                exc_info=True
            )
            
    def log_error(self, error: Exception, request_data: Optional[Dict] = None):
        """Log an error"""
        try:
            log_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'error': str(error),
                'error_type': error.__class__.__name__,
            }
            
            if request_data:
                log_data.update({
                    'client_ip': request_data.get('client_ip'),
                    'method': request_data.get('method'),
                    'path': request_data.get('path'),
                    'headers': self._sanitize_headers(
                        request_data.get('headers', {})
                    ),
                })
                
            if settings.LOG_FORMAT.lower() == 'json':
                self.error_logger.error(json.dumps(log_data), exc_info=True)
            else:
                self.error_logger.error(
                    f"Error: {log_data['error']} ({log_data['error_type']})",
                    exc_info=True
                )
                
        except Exception as e:
            self.error_logger.error(
                f"Error logging error: {str(e)}",
                exc_info=True
            )
