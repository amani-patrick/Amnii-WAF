from pydantic_settings import BaseSettings
from pydantic import SecretStr
from typing import List, Dict, Optional
import os

class WAFSettings(BaseSettings):
    # Application Settings
    APP_NAME: str = "Amnii-WAF"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # Server Settings
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    WORKERS: int = os.cpu_count() or 4  # Dynamically set workers based on CPU
    
    # Security Settings
    MAX_REQUEST_SIZE: int = 10 * 1024 * 1024  # 10MB
    RATE_LIMIT: int = 100  # requests per minute
    RATE_LIMIT_BURST: int = 20
    
    # ML Model Settings
    ML_MODEL_PATH: str = "models/waf_model.h5"
    ENABLE_ML_DETECTION: bool = True
    PREDICTION_THRESHOLD: float = 0.85

    BLOCK_SUSPICIOUS_IPS: bool = True
    BLOCK_TOR_IPS: bool = True
    ENABLE_XSS_PROTECTION: bool = True
    ENABLE_SQL_INJECTION_PROTECTION: bool = True
    ENABLE_PATH_TRAVERSAL_PROTECTION: bool = True
    
    # Allowed HTTP Methods
    ALLOWED_HTTP_METHODS: List[str] = ["GET", "POST", "PUT", "DELETE", "PATCH"]
    
    # Custom Rules with enhanced regex
    CUSTOM_RULES: Dict[str, Dict] = {
        "xss_patterns": {
            "enabled": True,
            "patterns": [
                r"(?i)<script.*?>.*?</script.*?>",  # Case-insensitive XSS detection
                r"(?i)javascript\s*:",
                r"(?i)on\w+\s*=",
                r"(?i)eval\s*\(",
            ]
        },
        "sql_injection_patterns": {
            "enabled": True,
            "patterns": [
                r"(?i)UNION\s+SELECT",
                r"(?i)DROP\s+TABLE",
                r"(?i)INSERT\s+INTO",
                r"(?i)UPDATE\s+\w+\s+SET",
                r"(?i)--\s",
                r"(?i)OR\s+\d+=\d+",
                r"(?i)'.*?OR.*?=.*?'",
            ]
        },
        "path_traversal_patterns": {
            "enabled": True,
            "patterns": [
                r"\.\./",  # Classic traversal
                r"\.\.\\",
                r"%2e%2e%2f",  # Encoded traversal
                r"%252e%252e%252f",
                r"(?i)/etc/passwd",  # Targeting UNIX paths
                r"(?i)C:\\Windows",  # Targeting Windows paths
            ]
        }
    }

    # Whitelist Configurations
    IP_WHITELIST: List[str] = ["127.0.0.1"]
    PATH_WHITELIST: List[str] = ["/health", "/metrics"]

    # Logging Configuration
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"
    ENABLE_ACCESS_LOG: bool = True
    ENABLE_ERROR_LOG: bool = True
    LOG_DIR: str = os.getenv("LOG_DIR", "logs")  # Allow log dir to be set dynamically
    
    # Database Settings (Use SecretStr to prevent accidental logging)
    DB_URL: SecretStr = SecretStr("mysql+pymysql://root:@localhost:3306/waf_db")

    # Monitoring Settings
    ENABLE_PROMETHEUS: bool = True
    ENABLE_APM: bool = True
    APM_SERVER_URL: Optional[str] = None

    class Config:
        env_file = ".env"
        case_sensitive = True

    def get_db_url(self) -> str:
        """Return the database URL without exposing the secret."""
        return self.DB_URL.get_secret_value()

# Initialize settings
settings = WAFSettings()

# Example of using the settings
print(f"Application Name: {settings.APP_NAME}")
print(f"Database URL: {settings.get_db_url()}")
