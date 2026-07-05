# 🔒 Advanced Web Vulnerability Scanner System

Sistem keamanan siber terpadu untuk mendeteksi kerentanan web dengan fitur canggih: **SCA (Software Composition Analysis)**, **AI-Powered Analysis**, **Subdomain Enumeration**, **Compliance Checking (OWASP/PCI-DSS/GDPR)**, **Attack Path Visualization**, dashboard web real-time, antrean Celery, dan integrasi Telegram.

---

## ⚠️ DISCLAIMER PENTING

**Alat ini HANYA untuk tujuan edukasi dan pengujian keamanan pada sistem yang Anda miliki sendiri atau memiliki izin tertulis dari pemiliknya.**

- Penggunaan tanpa izin adalah **ILEGAL** dan dapat dikenai sanksi pidana.
- Penulis tidak bertanggung jawab atas penyalahgunaan alat ini.
- Selalu patuhi hukum yang berlaku (UU ITE di Indonesia, CFAA di AS, Computer Misuse Act di UK, dll).

---

## 🚀 Fitur Utama

### 1. Mesin Scanning Canggih
- **Deteksi Kerentanan**: SQL Injection, XSS, Directory Traversal, Open Redirect, SSRF
- **Security Headers**: Missing HSTS, CSP, X-Frame-Options, dll.
- **File Sensitif**: Deteksi .env, .git/config, backup files
- **Crawler Otomatis**: Menemukan halaman dan form secara rekursif

### 2. Software Composition Analysis (SCA) 🆕
- Deteksi library/framework usang dari `package.json`, `requirements.txt`
- Pencocokan dengan database CVE
- Rekomendasi versi aman

### 3. AI-Powered Context Analysis 🆕
- Validasi temuan dengan AI untuk mengurangi false positive
- Confidence score dan analisis konteks otomatis
- Integrasi dengan OpenAI API (opsional)

### 4. Subdomain Enumeration 🆕
- Penemuan subdomain otomatis via DNS & Certificate Transparency
- Asset mapping hierarkis
- Deteksi subdomain takeover

### 5. Compliance Check Mode 🆕
- **OWASP Top 10 2021**: Kontrol keamanan aplikasi web
- **PCI-DSS v4.0**: Kepatuhan industri pembayaran
- **GDPR**: Perlindungan data pribadi
- Skor kepatuhan otomatis Pass/Fail

### 6. Attack Path Visualization 🆕
- Grafik interaktif alur serangan potensial
- Menghubungkan kerentanan kecil ke kritis
- Visualisasi eskalasi privilege

### 7. Analisis Risiko & Edukasi
- **Skor CVSS Otomatis** (0.0 - 10.0)
- **Panduan Eksploitasi**: Contoh payload spesifik
- **Remediasi Detail**: Contoh kode perbaikan (Python, PHP, Node.js, Java)
- **Referensi**: Link ke OWASP, CWE, NVD

### 8. Dashboard Web Real-Time
- UI modern dengan grafik statistik
- Manajemen tugas scan (Pending, Running, Completed)
- **Asset Map**: Visualisasi subdomain dan aset
- **Tren Keamanan**: Grafik historis kerentanan
- **False Positive Management**: Tandai dan filter temuan

### 9. Sistem Antrean & Performa
- **Celery Worker**: Proses scan di background
- **Redis Broker**: Manajemen antrean cepat
- **Mode Scan**: Safe (minimal impact) vs Deep (agresif)
- Rate limiting otomatis

### 10. Integrasi Telegram
- Kontrol penuh via chat (start scan, status, download report)
- Notifikasi otomatis saat selesai
- Whitelist ID untuk keamanan

### 11. Logging & Audit Trail
- Pencatatan lengkap aktivitas pengguna
- Jejak audit: siapa, kapan, target apa
- Monitoring perubahan file & konten

### 12. Mode Simulasi Serangan
- Generator skrip PoC otomatis (Python/cURL)
- Download script verifikasi
- Tombol "Verify" untuk testing manual

---

## 📋 Prasyarat

- **Python 3.8+**
- **Redis Server** (untuk Celery)
- **Node.js** (opsional, untuk beberapa fitur frontend)
- **wkhtmltopdf** (opsional, untuk export PDF)
- Akses internet (untuk AI dan CVE lookup)

---

## 🛠️ Instalasi

### Langkah 1: Clone & Setup Environment

```bash
cd /workspace
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
```

### Langkah 2: Install Dependensi

```bash
pip install -r requirements.txt
playwright install  # Install browser untuk headless scanning
```

### Langkah 3: Konfigurasi

Edit file `config.py` atau buat `.env`:

```bash
# Telegram Bot
TELEGRAM_BOT_TOKEN=your_bot_token_here
ALLOWED_USERS=8392806634,1234567890  # ID Telegram yang diizinkan

# AI Configuration (Opsional)
AI_ENABLED=True
AI_API_KEY=sk-your-openai-api-key
AI_MODEL_NAME=gpt-3.5-turbo
AI_API_BASE_URL=https://api.openai.com/v1

# Redis
REDIS_URL=redis://localhost:6379/0

# Database
DATABASE_URL=sqlite:///scanner.db

# Security
SECRET_KEY=your-random-secret-key-change-in-production
WHITELIST_ONLY=True
SAFE_MODE_DEFAULT=True

# Compliance
COMPLIANCE_STANDARDS=OWASP_TOP_10,PCI_DSS,GDPR
```

### Langkah 4: Setup Redis

**Linux/Mac:**
```bash
sudo apt-get install redis-server  # Debian/Ubuntu
brew install redis  # macOS
redis-server --daemonize yes
```

**Windows:** Download dari https://github.com/microsoftarchive/redis/releases

---

## 🚀 Cara Menjalankan

Jalankan dalam **4 terminal terpisah**:

### Terminal 1: Redis Server
```bash
redis-server
# Atau jika sudah running sebagai service:
sudo systemctl start redis
```

### Terminal 2: Celery Worker
```bash
source venv/bin/activate
celery -A tasks.celery_app worker --loglevel=info --pool=solo
```

### Terminal 3: Flask Web Dashboard
```bash
source venv/bin/activate
export FLASK_APP=app.py
export FLASK_ENV=production
python app.py
```

### Terminal 4: Telegram Bot (Opsional)
```bash
source venv/bin/activate
python telegram_bot.py
```

---

## 🌐 Akses Dashboard

Buka browser dan akses:
```
http://localhost:5000
```

**Login:**
- Masukkan **Telegram ID** Anda (harus ada di `ALLOWED_USERS`)
- Username opsional untuk tampilan

**Fitur Dashboard:**
1. **New Scan**: Input URL, pilih mode (Safe/Deep), compliance standard, enable AI
2. **Asset Map**: Lihat semua subdomain yang ditemukan
3. **History & Trends**: Grafik tren kerentanan dari waktu ke waktu
4. **Reports**: Download laporan HTML/JSON/PDF
5. **Settings**: Kelola whitelist user dan konfigurasi

---

## 📱 Menggunakan Telegram Bot

### Dapatkan Token Bot
1. Chat dengan `@BotFather` di Telegram
2. Kirim `/newbot`
3. Ikuti instruksi, simpan token

### Dapatkan Telegram ID Anda
1. Chat dengan `@userinfobot`
2. Bot akan reply dengan ID Anda (contoh: `8392806634`)
3. Tambahkan ID ke `ALLOWED_USERS` di `config.py`

### Perintah Bot
```
/start          - Mulai bot dan lihat menu
/scan [URL]     - Jalankan scan (contoh: /scan https://example.com)
/status         - Cek status scan terakhir
/report         - Download laporan scan
/help           - Lihat bantuan lengkap
/settings       - Atur preferensi scan
```

---

## 🔍 Panduan Penggunaan Fitur Lanjutan

### 1. Software Composition Analysis (SCA)
Saat scan, sistem otomatis:
- Deteksi `package.json` → cek versi npm packages
- Deteksi `requirements.txt` → cek versi Python packages
- Cocokkan dengan database CVE internal
- Tampilkan versi rentan vs versi aman

**Output Example:**
```
Type: Outdated Dependency
Package: lodash@4.17.15
CVE: CVE-2021-23337
Severity: HIGH (CVSS 7.5)
Recommendation: Upgrade to >=4.17.21
```

### 2. AI-Powered Analysis
Aktifkan dengan:
- Centang "Enable AI Analysis" di dashboard
- Atau set `AI_ENABLED=True` dan isi `AI_API_KEY`

AI akan memberikan:
- Confidence score (0-1)
- False positive likelihood
- Konteks temuan
- Prioritas remediasi

### 3. Subdomain Enumeration
Centang "Discover Subdomains" saat scan:
- DNS brute-force (common subdomains)
- Certificate Transparency logs
- DNS record lookup

Hasil ditampilkan di **Asset Map** dengan hierarki:
```
example.com
├── www.example.com
├── api.example.com
├── dev.example.com
└── admin.example.com
```

### 4. Compliance Check
Pilih standard saat scan:
- **OWASP Top 10**: Fokus pada kerentanan aplikasi web umum
- **PCI-DSS**: Untuk sistem pembayaran (kartu kredit)
- **GDPR**: Untuk perlindungan data pribadi EU

Dashboard menampilkan:
- Controls yang Pass/Fail
- Skor kepatuhan (%)
- Detail temuan per control

### 5. Attack Path Visualization
Setelah scan selesai:
- Buka detail vulnerability
- Tab "Attack Path" menampilkan grafik
- Node = vulnerability, Edge = hubungan eskalasi

Contoh alur:
```
Missing Header (LOW) → XSS (MEDIUM) → Session Hijack (HIGH) → Data Breach (CRITICAL)
```

### 6. False Positive Management
Di dashboard:
1. Buka detail vulnerability
2. Klik "Mark as False Positive"
3. Tambahkan alasan (opsional)
4. Temuan akan di-filter di scan berikutnya

### 7. Simulation Mode (PoC Generator)
Untuk setiap vulnerability:
- Tab "Simulation" berisi script Python/cURL
- Copy-paste atau download
- Jalankan untuk verifikasi manual

Example PoC:
```python
# SQL Injection PoC
import requests
url = "https://target.com/search"
params = {'q': "' OR '1'='1"}
response = requests.get(url, params=params)
print("[+] SQL Injection confirmed!" if 'error' in response.text else "[-]")
```

---

## 📊 Struktur Proyek

```
/workspace
├── app.py                  # Flask web dashboard
├── tasks.py                # Celery tasks untuk scanning
├── telegram_bot.py         # Bot Telegram
├── config.py               # Konfigurasi utama
├── requirements.txt        # Dependensi Python
├── scanner.db              # Database SQLite
├── scanner.log             # Log file
├── modules/
│   └── scanner.py          # Core scanning engine
├── templates/
│   ├── dashboard.html      # UI dashboard
│   ├── login.html          # Halaman login
│   ├── scan_detail.html    # Detail hasil scan
│   └── asset_map.html      # Peta aset subdomain
└── static/
    ├── css/style.css       # Styling
    └── js/main.js          # Frontend logic
```

---

## 🧪 Testing & Troubleshooting

###常见问题

**1. Login gagal "Not Authorized"**
- Pastikan Telegram ID ada di `ALLOWED_USERS`
- Restart Flask app setelah edit config

**2. Celery worker tidak jalan**
- Pastikan Redis running: `redis-cli ping` → harus reply `PONG`
- Cek log Celery untuk error

**3. Scan timeout**
- Increase `MAX_SCAN_TIMEOUT` di `config.py`
- Gunakan Safe Mode untuk website besar

**4. AI tidak berfungsi**
- Cek `AI_API_KEY` valid
- Pastikan `AI_ENABLED=True`
- Cek koneksi internet

**5. Subdomain tidak ketemu**
- Beberapa domain memblok DNS lookup
- Coba manual dengan tools seperti `sublist3r`

### Test Scan Lokal

Gunakan DVWA (Damn Vulnerable Web App) untuk testing:
```bash
docker run --rm -it -p 8080:80 vulnerables/web-dvwa
```
Scan target: `http://localhost:8080`

---

## 📈 Roadmap Fitur Mendatang

- [ ] Integrasi CI/CD (GitHub Actions, GitLab CI)
- [ ] Export laporan PDF/SARIF
- [ ] Plugin scanner eksternal (Nuclei, Nikto)
- [ ] User management & RBAC
- [ ] Dark web monitoring integration
- [ ] Auto-ticket creation (Jira, GitHub Issues)
- [ ] Multi-target batch scanning
- [ ] REST API dengan autentikasi

---

## 📚 Referensi

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CVSS Calculator](https://www.first.org/cvss/calculator/3.1)
- [CWE Database](https://cwe.mitre.org/)
- [NVD NIST](https://nvd.nist.gov/)
- [Telegram Bot API](https://core.telegram.org/bots/api)
- [Celery Documentation](https://docs.celeryq.dev/)

---

## 📄 Lisensi

MIT License - Bebas digunakan untuk tujuan edukasi dan research.

**Ingat: Dengan kekuatan besar datang tanggung jawab besar. Gunakan dengan bijak!**

---

## 🆘 Dukungan

Untuk pertanyaan atau issue, buat ticket di repository ini atau hubungi developer.

**Happy (Ethical) Hacking! 🔐**
