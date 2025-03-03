from fastapi import Request, Response
from fastapi.responses import JSONResponse
from typing import Callable, Dict, Optional
import time
import logging
from .config import settings
from .rules_engine import RulesEngine
from .ml_model import WAFMLModel
from .rate_limiter import RateLimiter
from .logger import RequestLogger

logger = logging.getLogger(__name__)

class WAFMiddleware:
    def __init__(self):
        self.rules_engine = RulesEngine()
        self.ml_model = WAFMLModel()
        self.rate_limiter = RateLimiter()
        self.request_logger = RequestLogger()
        
    async def _extract_request_data(self, request: Request) -> Dict:
        """Extract relevant data from the request"""
        # Get client IP
        client_ip = request.client.host if request.client else None
        
        # Get request body
        try:
            body = await request.body()
            body = body.decode() if body else ""
        except:
            body = ""
            
        # Build request data dictionary
        request_data = {
            "method": request.method,
            "path": request.url.path,
            "headers": dict(request.headers),
            "query_params": dict(request.query_params),
            "body": body,
            "client_ip": client_ip,
            "timestamp": time.time()
        }
        
        return request_data
        
    def _check_ip_whitelist(self, client_ip: str) -> bool:
        """Check if IP is whitelisted"""
        return client_ip in settings.IP_WHITELIST
        
    def _check_path_whitelist(self, path: str) -> bool:
        """Check if path is whitelisted"""
        return path in settings.PATH_WHITELIST
        
    async def _process_request(self, request_data: Dict) -> Optional[Response]:
        """Process request and return response if request should be blocked"""
        # Check whitelists
        if self._check_ip_whitelist(request_data["client_ip"]):
            return None
            
        if self._check_path_whitelist(request_data["path"]):
            return None
            
        # Check rate limit
        if self.rate_limiter.is_rate_limited(request_data["client_ip"]):
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests"}
            )
            
        # Check rules
        is_threat, matches = self.rules_engine.analyze_request(request_data)
        if is_threat:
            should_block, reason = self.rules_engine.should_block_request(matches)
            if should_block:
                return JSONResponse(
                    status_code=403,
                    content={"detail": reason or "Request blocked by WAF"}
                )
                
        # Check ML model
        if settings.ENABLE_ML_DETECTION:
            is_malicious, confidence = self.ml_model.predict(request_data)
            if is_malicious:
                return JSONResponse(
                    status_code=403,
                    content={
                        "detail": f"Request blocked by ML model (confidence: {confidence:.2%})"
                    }
                )
                
        return None
        
    async def __call__(
        self,
        request: Request,
        call_next: Callable
    ) -> Response:
        """Process request through WAF middleware"""
        start_time = time.time()
        
        try:
            # Extract request data
            request_data = await self._extract_request_data(request)
            
            # Process request through WAF
            blocked_response = await self._process_request(request_data)
            if blocked_response:
                # Log blocked request
                self.request_logger.log_blocked_request(
                    request_data,
                    blocked_response.status_code
                )
                return blocked_response
                
            # Process request normally
            response = await call_next(request)
            
            # Log successful request
            self.request_logger.log_request(
                request_data,
                response.status_code,
                time.time() - start_time
            )
            
            return response
            
        except Exception as e:
            logger.error(f"Error in WAF middleware: {str(e)}")
            return JSONResponse(
                status_code=500,
                content={"detail": "Internal server error"}
            )
