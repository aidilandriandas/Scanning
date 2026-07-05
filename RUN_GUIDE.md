# 🚀 Quick Start Guide - Vulnerability Scanner

## Step-by-Step Setup (5 Minutes)

### 1. Install Dependencies
```bash
cd /workspace
pip install -r requirements.txt
```

### 2. Start Redis
```bash
# Option A: System service
sudo systemctl start redis

# Option B: Docker
docker run -d -p 6379:6379 --name redis redis:latest

# Option C: Direct (if installed)
redis-server
```

### 3. Get Telegram Bot Token
1. Open Telegram, search `@BotFather`
2. Send `/newbot`
3. Name your bot
4. Copy the token

### 4. Configure Environment
```bash
export TELEGRAM_BOT_TOKEN="paste_your_token_here"
export ALLOWED_USERS="your_telegram_id"  # Get from @userinfobot
export REDIS_URL="redis://localhost:6379/0"
```

### 5. Initialize Database
```bash
python app.py &
sleep 2
kill %1  # Stop after DB is created
```

### 6. Run Components

**Terminal 1 - Celery Worker:**
```bash
celery -A celery_config worker --loglevel=info
```

**Terminal 2 - Web Dashboard:**
```bash
python app.py
```

**Terminal 3 - Telegram Bot:**
```bash
python telegram_bot.py
```

### 7. Access

- **Web Dashboard**: http://localhost:5000
- **Telegram**: Find your bot and send `/start`
- **CLI**: `python scanner.py -u https://your-target.com`

---

## 🎯 First Scan

### Via Telegram:
```
/scan https://example.com safe
```

### Via Web:
1. Login with Telegram ID
2. Enter URL
3. Click "Start Scan"
4. Watch real-time progress

### Via CLI:
```bash
python scanner.py -u https://example.com -o report.html
```

---

## ✅ Verify Everything Works

```bash
# Test Redis
redis-cli ping  # Should return: PONG

# Test Python imports
python -c "from flask import Flask; from celery import Celery; print('OK')"

# Test database
python -c "from models import db, User; print('DB OK')"
```

---

## 🆘 Common Issues

| Problem | Solution |
|---------|----------|
| Redis connection error | `sudo systemctl start redis` |
| Bot not responding | Check token, ensure internet |
| Database locked | Delete `scanner.db`, restart |
| Port 5000 in use | Change `DASHBOARD_PORT` in config |

---

**Need help?** Check logs: `tail -f scanner.log`
