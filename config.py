import os

# Telegram Bot Configuration
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN', 'YOUR_TELEGRAM_BOT_TOKEN_HERE')
ALLOWED_USERS = os.getenv('ALLOWED_USERS', '').split(',')  # Comma-separated list of Telegram user IDs

# Redis Configuration (for Celery)
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')

# Database Configuration (SQLite for simplicity, change to PostgreSQL for production)
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///scanner.db')

# Security Settings
MAX_SCAN_TIMEOUT = 300  # Maximum scan timeout in seconds
SAFE_MODE_DEFAULT = True  # Default to safe mode scanning
WHITELIST_ONLY = True  # Only allow whitelisted users to use the bot

# CVSS Scoring Configuration
CVSS_ENABLED = True
SEVERITY_THRESHOLDS = {
    'CRITICAL': 9.0,
    'HIGH': 7.0,
    'MEDIUM': 4.0,
    'LOW': 0.1
}

# Dashboard Configuration
DASHBOARD_HOST = os.getenv('DASHBOARD_HOST', '0.0.0.0')
DASHBOARD_PORT = int(os.getenv('DASHBOARD_PORT', '5000'))
SECRET_KEY = os.getenv('SECRET_KEY', 'change-this-to-a-random-secret-key-in-production')

# Logging Configuration
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
LOG_FILE = os.getenv('LOG_FILE', 'scanner.log')
