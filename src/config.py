from pydantic import BaseSettings
from typing import List, Dict, Optional

class WAFSettings(BaseSettings):
    # Application Settings
    APP_NAME: str = "Amnii-WAF"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # Server Settings
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    WORKERS: int = 4
    
    # Security Settings
    MAX_REQUEST_SIZE: int = 10 * 1024 * 1024  # 10MB
    RATE_LIMIT: int = 100  # requests per minute
    RATE_LIMIT_BURST: int = 20
    
    # ML Model Settings
    ML_MODEL_PATH: str = "models/waf_model.h5"
    ENABLE_ML_DETECTION: bool = True
    PREDICTION_THRESHOLD: float = 0.85
    
    # Rule Settings
    BLOCK_SUSPICIOUS_IPS: bool = True
    BLOCK_TOR_IPS: bool = True
    ENABLE_XSS_PROTECTION: bool = True
    ENABLE_SQL_INJECTION_PROTECTION: bool = True
    ENABLE_PATH_TRAVERSAL_PROTECTION: bool = True
    
    # Allowed HTTP Methods
    ALLOWED_HTTP_METHODS: List[str] = ["GET", "POST", "PUT", "DELETE", "PATCH"]
    
    # Custom Rules
    CUSTOM_RULES: Dict[str, Dict] = {
        "xss_patterns": {
            "enabled": True,
            "patterns": [
                r"<script.*?>",
                r"javascript:",
                r"onload=",
                r"onerror=",
                r"eval\(",
            ]
        },
        "sql_injection_patterns": {
            "enabled": True,
            "patterns": [
                r"UNION.*?SELECT",
                r"DROP.*?TABLE",
                r"--.*?",
                r";.*?",
                r"'.*?OR.*?'.*?=.*?'",
            ]
        },
        "path_traversal_patterns": {
            "enabled": True,
            "patterns": [
                r"\.\.\/",
                r"\.\.\\",
                r"%2e%2e%2f",
                r"%252e%252e%252f",
            ]
        }
    }
    
    # Whitelist Settings
    IP_WHITELIST: List[str] = ["127.0.0.1"]
    PATH_WHITELIST: List[str] = ["/health", "/metrics"]
    
    # Logging Settings
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"
    ENABLE_ACCESS_LOG: bool = True
    ENABLE_ERROR_LOG: bool = True
    LOG_DIR: str = "logs"
    
    # Database Settings
    DB_URL: str = "postgresql://user:password@localhost:5432/waf_db"
    
    # Monitoring Settings
    ENABLE_PROMETHEUS: bool = True
    ENABLE_APM: bool = True
    APM_SERVER_URL: Optional[str] = None
    
    class Config:
        env_file = ".env"
        case_sensitive = True

# Initialize settings
settings = WAFSettings()
