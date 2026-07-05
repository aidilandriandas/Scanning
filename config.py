import os
from dotenv import load_dotenv

load_dotenv()

# ===========================
# Telegram Bot Configuration
# ===========================
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN', '')
ALLOWED_USERS = os.getenv('ALLOWED_USERS', '8392806634').split(',')  # Comma-separated list of Telegram user IDs

# ===========================
# Redis Configuration (for Celery)
# ===========================
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')

# ===========================
# Database Configuration
# ===========================
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///scanner.db')

# ===========================
# Security Settings
# ===========================
MAX_SCAN_TIMEOUT = 300  # Maximum scan timeout in seconds
WHITELIST_ONLY = True   # Only allow users in ALLOWED_USERS
SAFE_MODE_DEFAULT = True  # Default to safe scanning mode
RATE_LIMIT_DELAY = 1.0  # Delay between requests in seconds
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'

# ===========================
# AI Configuration
# ===========================
AI_ENABLED = os.getenv('AI_ENABLED', 'False').lower() == 'true'
AI_API_KEY = os.getenv('AI_API_KEY', '')  # OpenAI API Key or other LLM provider
AI_MODEL_NAME = os.getenv('AI_MODEL_NAME', 'gpt-3.5-turbo')
AI_API_BASE_URL = os.getenv('AI_API_BASE_URL', 'https://api.openai.com/v1')

# ===========================
# Compliance Standards
# ===========================
COMPLIANCE_STANDARDS = {
    'OWASP_TOP_10': 'OWASP Top 10 2021',
    'PCI_DSS': 'PCI-DSS v4.0',
    'GDPR': 'General Data Protection Regulation',
    'ALL': 'All Standards'
}

# ===========================
# Scan Profiles
# ===========================
SCAN_PROFILES = {
    'safe': {
        'name': 'Safe Mode',
        'description': 'Passive checks only, minimal impact on target',
        'active_tests': False,
        'rate_limit': 2.0,
        'max_depth': 3
    },
    'deep': {
        'name': 'Deep Scan',
        'description': 'Active testing with JS rendering, higher impact',
        'active_tests': True,
        'rate_limit': 0.5,
        'max_depth': 10,
        'enable_browser': True
    }
}

# ===========================
# CVSS Scoring Configuration
# ===========================
CVSS_ENABLED = True
SEVERITY_THRESHOLDS = {
    'CRITICAL': 9.0,
    'HIGH': 7.0,
    'MEDIUM': 4.0,
    'LOW': 0.1
}

# ===========================
# Logging Configuration
# ===========================
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
LOG_FILE = os.getenv('LOG_FILE', 'scanner.log')

# ===========================
# Dashboard Settings
# ===========================
SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
DEBUG_MODE = os.getenv('DEBUG_MODE', 'False').lower() == 'true'
DASHBOARD_HOST = os.getenv('DASHBOARD_HOST', '0.0.0.0')
DASHBOARD_PORT = int(os.getenv('DASHBOARD_PORT', '5000'))
