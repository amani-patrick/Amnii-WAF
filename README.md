# Amnii-WAF

A modern Web Application Firewall (WAF) built with Python, featuring machine learning-based threat detection and comprehensive security rules.

## Features

- **Rule-Based Protection**
  - XSS (Cross-Site Scripting) Detection
  - SQL Injection Protection
  - Path Traversal Prevention
  - Custom Rule Support

- **Machine Learning Integration**
  - TensorFlow-based Anomaly Detection
  - Request Pattern Analysis
  - Adaptive Threat Detection

- **Rate Limiting**
  - IP-based Rate Limiting
  - Burst Protection
  - Configurable Thresholds

- **Monitoring & Logging**
  - Prometheus Metrics Integration
  - Elastic APM Support
  - JSON/Text Log Formats
  - Rotating Log Files

- **Advanced Features**
  - IP Whitelisting
  - Path Whitelisting
  - Configurable Security Rules
  - CORS Support

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/Amnii-WAF.git
cd Amnii-WAF
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Configuration

1. Copy the example environment file:
```bash
cp .env.example .env
```

2. Edit the `.env` file with your settings:
```env
APP_NAME=Amnii-WAF
DEBUG=False
HOST=0.0.0.0
PORT=8000
WORKERS=4
```

## Usage

1. Start the WAF:
```bash
python -m src.main
```

2. The WAF will be available at `http://localhost:8000`

3. Access the API documentation at:
   - Swagger UI: `http://localhost:8000/api/docs`
   - ReDoc: `http://localhost:8000/api/redoc`

## Testing

1. Run the test suite:
```bash
pytest
```

2. Test specific security features:
```bash
# Test XSS Protection
curl "http://localhost:8000/test/xss?payload=<script>alert('test')</script>"

# Test SQL Injection Protection
curl "http://localhost:8000/test/sqli?query=SELECT * FROM users"

# Test Path Traversal Protection
curl "http://localhost:8000/test/path-traversal?path=../../../etc/passwd"
```

## Project Structure

```
waf_project/
│── src/
│   ├── __init__.py
│   ├── main.py         # Main entry point
│   ├── config.py       # Configuration settings
│   ├── middleware.py   # Request inspection
│   ├── rules_engine.py # Attack detection logic
│   ├── logger.py       # Logging system
│   ├── rate_limiter.py # Prevent DDoS
│   ├── database.py     # DB operations
│   ├── ml_model.py     # AI-based anomaly detection
│── dashboard/
│   ├── frontend/       # React/Vue UI for logs & reports
│   ├── backend/        # API for dashboard
│── tests/              # Unit & integration tests
│── docs/              # Documentation
│── requirements.txt   # Dependencies
│── README.md         # Project description
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## Security

For security issues, please email security@yourdomain.com instead of using the issue tracker.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- FastAPI for the excellent web framework
- TensorFlow for machine learning capabilities
- The Python security community for inspiration and guidance
