from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import logging
from .config import settings
from .middleware import WAFMiddleware
from prometheus_client import make_asgi_app
from elastic_apm.contrib.starlette import ElasticAPM
import elastic_apm

# Setup logging
logging.basicConfig(level=settings.LOG_LEVEL)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add WAF middleware
app.add_middleware(WAFMiddleware)

# Add Prometheus metrics if enabled
if settings.ENABLE_PROMETHEUS:
    metrics_app = make_asgi_app()
    app.mount("/metrics", metrics_app)
    
# Add Elastic APM if enabled
if settings.ENABLE_APM and settings.APM_SERVER_URL:
    app.add_middleware(ElasticAPM, client=elastic_apm.Client(
        service_name=settings.APP_NAME,
        server_url=settings.APM_SERVER_URL
    ))

@app.get("/")
async def root():
    return {"message": "WAF is running"}

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "version": settings.APP_VERSION
    }

@app.get("/test/xss")
async def test_xss_protection(payload: str):
    """Test endpoint for XSS protection"""
    return {"message": f"Received payload: {payload}"}

@app.get("/test/sqli")
async def test_sql_injection(query: str):
    """Test endpoint for SQL injection protection"""
    return {"message": f"Received query: {query}"}

@app.get("/test/path-traversal")
async def test_path_traversal(path: str):
    """Test endpoint for path traversal protection"""
    return {"message": f"Received path: {path}"}

if __name__ == "__main__":
    # Run the application
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        workers=settings.WORKERS,
        reload=settings.DEBUG
    )
