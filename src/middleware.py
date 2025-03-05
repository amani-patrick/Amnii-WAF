from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import JSONResponse
from typing import Callable, Dict, Optional
import time
import logging
import redis
import requests
from .config import settings
from .rules_engine import RulesEngine
from .ml_model import WAFMLModel
from .rate_limiter import RateLimiter
from .logger import RequestLogger

logger = logging.getLogger(__name__)

# Redis setup for rate limiting
redis_client = redis.Redis(host="localhost", port=6379, db=0)

class WAFMiddleware(BaseHTTPMiddleware):
    ML_CONFIDENCE_THRESHOLD = 0.85  # Block only if confidence is 85%+

    def __init__(self, app):
        super().__init__(app)
        self.rules_engine = RulesEngine()
        self.ml_model = WAFMLModel()
        self.rate_limiter = RateLimiter(redis_client)
        self.request_logger = RequestLogger()

    async def _extract_request_data(self, request: Request) -> Dict:
        """Extract relevant data from the request"""
        client_ip = request.client.host if request.client else None

        try:
            body = await request.body()
            body = body.decode() if body else ""
        except:
            body = ""

        request_data = {
            "method": request.method,
            "path": request.url.path,
            "headers": dict(request.headers),
            "query_params": dict(request.query_params),
            "body": body,
            "client_ip": client_ip,
            "timestamp": time.time(),
        }

        return request_data

    def _check_ip_whitelist(self, client_ip: str) -> bool:
        """Check if IP is whitelisted"""
        return client_ip in settings.IP_WHITELIST

    def _check_path_whitelist(self, path: str) -> bool:
        """Check if path is whitelisted"""
        return path in settings.PATH_WHITELIST

    def _send_alert(self, message: str):
        """Send alert to security team via Slack"""
        if settings.SLACK_WEBHOOK_URL:
            requests.post(settings.SLACK_WEBHOOK_URL, json={"text": message})

    async def _process_request(self, request_data: Dict) -> Optional[Response]:
        """Process request and return response if it should be blocked"""

        if self._check_ip_whitelist(request_data["client_ip"]):
            return None

        if self._check_path_whitelist(request_data["path"]):
            return None

        if self.rate_limiter.is_rate_limited(request_data["client_ip"]):
            return JSONResponse(status_code=429, content={"detail": "Too many requests"})

        is_threat, matches = self.rules_engine.analyze_request(request_data)
        if is_threat:
            should_block, reason = self.rules_engine.should_block_request(matches)
            if should_block:
                self._send_alert(f"🚨 WAF blocked request from {request_data['client_ip']} to {request_data['path']}")
                return JSONResponse(status_code=403, content={"detail": reason or "Request blocked by WAF"})

        if settings.ENABLE_ML_DETECTION:
            is_malicious, confidence = self.ml_model.predict(request_data)
            if is_malicious and confidence >= self.ML_CONFIDENCE_THRESHOLD:
                self._send_alert(f"🚨 ML Model blocked request (Confidence: {confidence:.2%}) from {request_data['client_ip']}")
                return JSONResponse(status_code=403, content={"detail": f"Blocked by ML model (Confidence: {confidence:.2%})"})

        return None

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request through WAF middleware"""
        start_time = time.time()

        try:
            request_data = await self._extract_request_data(request)
            blocked_response = await self._process_request(request_data)

            if blocked_response:
                self.request_logger.log_blocked_request(request_data, blocked_response.status_code)
                return blocked_response

            response = await call_next(request)
            self.request_logger.log_request(request_data, response.status_code, time.time() - start_time)
            return response

        except Exception as e:
            logger.error(f"Error in WAF middleware: {str(e)}")
            return JSONResponse(status_code=500, content={"detail": "Internal server error"})
