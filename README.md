# Advanced Web Vulnerability Scanner System

Sistem keamanan siber terpadu untuk mendeteksi kerentanan web (SQL Injection, XSS, dll) lengkap dengan analisis risiko otomatis (CVSS), panduan eksploitasi edukatif, remediasi kode, dashboard web real-time, antrean tugas (Celery), logging audit, dan integrasi Telegram.

## ⚠️ DISCLAIMER PENTING

**Alat ini hanya untuk tujuan edukasi dan pengujian keamanan pada sistem yang Anda miliki sendiri atau memiliki izin tertulis dari pemiliknya.**

- Penggunaan tanpa izin adalah **ILEGAL** dan dapat dikenai sanksi pidana.
- Penulis tidak bertanggung jawab atas penyalahgunaan alat ini.
- Selalu patuhi hukum yang berlaku di negara Anda (UU ITE di Indonesia, CFAA di AS, dll).

---

## 🚀 Fitur Utama

### 1. Mesin Scanning Canggih
- **Deteksi Kerentanan**: SQL Injection, XSS (Reflected/Stored), Directory Traversal (LFI/RFI), Open Redirect, SSRF dasar.
- **Analisis Header**: Missing HSTS, CSP, X-Frame-Options, X-Content-Type-Options, dll.
- **Eksposur File Sensitif**: Deteksi .env, .git/config, backup files, database dumps.
- **Crawler Otomatis**: Menemukan halaman dan form tersembunyi secara rekursif.

### 2. Analisis Risiko & Edukasi (New!)
- **Skor CVSS Otomatis**: Perhitungan skor risiko (0.0 - 10.0) dengan kategorisasi (Critical, High, Medium, Low).
- **Panduan Eksploitasi**: Langkah-langkah reproduksi dan contoh payload spesifik untuk verifikasi manual.
- **Remediasi Detail**: Panduan perbaikan langkah demi langkah dengan contoh kode (Python, PHP, Node.js, Java).
- **Referensi Terpercaya**: Link langsung ke OWASP Top 10, CWE, dan artikel mitigasi.

### 3. Dashboard Web Real-Time (New!)
- **Antarmuka Modern**: UI responsif dengan grafik statistik dan pemetaan risiko.
- **Manajemen Tugas**: Pantau status scan (Pending, Running, Completed) secara live.
- **Riwayat & Audit**: Lihat log aktivitas pengguna dan hasil scan sebelumnya.
- **Mode Scan**: Pilihan antara "Safe Mode" (produktif) dan "Deep Mode" (agresif).

### 4. Sistem Antrean & Performa (New!)
- **Celery Worker**: Memproses scan berat di latar belakang tanpa memblokir aplikasi utama.
- **Redis Broker**: Manajemen antrean tugas yang cepat dan andal.
- **Skalabilitas**: Siap dijalankan dengan multiple worker untuk scan paralel.

### 5. Integrasi Telegram
- **Kontrol Penuh**: Jalankan scan, cek status, dan download laporan langsung dari chat.
- **Notifikasi Otomatis**: Alert real-time saat scan selesai atau menemukan bug kritis.
- **Keamanan Akses**: Whitelist ID Telegram untuk mencegah akses tidak sah.

### 6. Logging & Audit Trail (New!)
- **Pencatatan Lengkap**: Log setiap permintaan scan, pengguna, dan hasil deteksi.
- **Jejak Audit**: Melacak siapa yang menjalankan scan, kapan, dan terhadap target apa.

---

## 📋 Prasyarat Sistem

- **OS**: Linux (Ubuntu/Debian/Kali), macOS, atau Windows (WSL disarankan).
- **Python**: Versi 3.8 atau lebih baru.
- **Redis Server**: Wajib untuk sistem antrean Celery.
- **Telegram Bot**: Token bot dari @BotFather.
- **Browser**: Untuk mengakses Dashboard Web.

---

## 🛠️ Instalasi

### 1. Clone & Persiapan Direktori
```bash
cd /workspace
# Pastikan semua file sumber (app.py, scanner.py, celery_worker.py, dll) sudah ada
```

### 2. Install Dependensi Python
Buat file `requirements.txt` jika belum ada, lalu install:
```bash
pip install -r requirements.txt
```
*Isi `requirements.txt` harus mencakup:*
```text
flask
flask-login
flask-sqlalchemy
celery
redis
requests
beautifulsoup4
python-telegram-bot
cryptography
```

### 3. Setup Redis Server
**Linux (Ubuntu/Debian):**
```bash
sudo apt-get update
sudo apt-get install redis-server
sudo systemctl start redis
sudo systemctl enable redis
```
**Cek Status:** `redis-cli ping` (Harus merespon `PONG`).

**Windows/macOS:** Gunakan Docker atau installer resmi Redis.

---

## ⚙️ Konfigurasi

Buat file `config.py` di direktori utama dan sesuaikan nilai berikut:

```python
import os

# --- Konfigurasi Telegram ---
TELEGRAM_BOT_TOKEN = 'MASUKKAN_TOKEN_BOT_ANDA_DISINI'
WHITELIST_ONLY = True  # Set True untuk produksi, False untuk testing
ALLOWED_TELEGRAM_USERS = [123456789, 987654321]  # Ganti dengan Chat ID Telegram Anda

# --- Konfigurasi Database ---
DATABASE_URI = 'sqlite:///vuln_scanner.db'

# --- Konfigurasi Redis (Untuk Celery) ---
CELERY_BROKER_URL = 'redis://localhost:6379/0'
CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'

# --- Konfigurasi Keamanan ---
SECRET_KEY = os.urandom(24).hex()  # Ganti dengan string random aman untuk produksi
SCAN_TIMEOUT = 300  # Timeout scan dalam detik
```

**Cara Mendapatkan Telegram Token & Chat ID:**
1. Buka Telegram, cari **@BotFather**, kirim `/newbot`, ikuti instruksi untuk mendapatkan **Token**.
2. Cari **@userinfobot**, kirim pesan apapun, bot akan membalas dengan **Chat ID** Anda.
3. Masukkan Token dan Chat ID ke `config.py`.

---

## ▶️ Cara Menjalankan Sistem

Sistem ini terdiri dari 4 komponen yang harus berjalan bersamaan. Buka 4 terminal terpisah:

### Terminal 1: Jalankan Redis
```bash
redis-server
# Atau jika sudah sebagai service: sudo systemctl start redis
```

### Terminal 2: Jalankan Celery Worker (Proses Background)
```bash
celery -A celery_worker.celery worker --loglevel=info --pool=solo
```
*(Catatan: `--pool=solo` diperlukan jika menggunakan Windows)*

### Terminal 3: Jalankan Web Dashboard
```bash
python app.py
```
Dashboard akan berjalan di `http://127.0.0.1:5000`.

### Terminal 4: Jalankan Bot Telegram
```bash
python telegram_bot.py
```
Bot akan aktif dan siap menerima perintah.

---

## 📖 Panduan Penggunaan

### A. Melalui Web Dashboard
1. Buka browser dan akses `http://127.0.0.1:5000/login`.
2. Login menggunakan **Telegram Chat ID** Anda (sesuai konfigurasi whitelist).
3. Di Dashboard, masukkan **Target URL** (misal: `http://testphp.vulnweb.com`).
4. Pilih **Scan Mode**:
   - **Safe Mode**: Cepat, aman untuk production, cek header & file umum.
   - **Deep Mode**: Lambat, agresif, cek injeksi mendalam (HANYA untuk lab/testing).
5. Klik **Start Scan**.
6. Pantau progres di tab "Active Scans". Setelah selesai, klik hasil untuk melihat detail kerentanan, skor CVSS, dan cara perbaikan.
7. Download laporan (HTML/JSON) jika diperlukan.

### B. Melalui Telegram Bot
1. Start bot Anda di Telegram.
2. Kirim perintah:
   - `/start`: Menu utama.
   - `/scan <url>`: Mulai scan (misal: `/scan http://target.com`).
   - `/status`: Cek status scan yang sedang berjalan.
   - `/help`: Bantuan perintah.
3. Bot akan mengirimkan notifikasi progres dan hasil akhir berupa ringkasan serta file laporan.

---

## 📂 Struktur Proyek

```
/workspace
├── README.md           # Dokumentasi ini
├── config.py           # Konfigurasi sensitif (Token, DB, Redis)
├── requirements.txt    # Daftar library Python
├── app.py              # Aplikasi Web Dashboard (Flask)
├── celery_worker.py    # Worker untuk proses scanning background
├── telegram_bot.py     # Bot Telegram handler
├── scanner.py          # Inti mesin scanning & logika deteksi
├── models.py           # Model database (User, ScanResult, Logs)
├── templates/          # Folder HTML Dashboard
│   ├── login.html
│   ├── dashboard.html
│   └── report.html
├── static/             # CSS, JS, Gambar untuk Dashboard
│   ├── css/style.css
│   └── js/main.js
└── logs/               # Folder penyimpanan log audit
    └── audit.log
```

---

## 🔍 Troubleshooting

| Masalah | Solusi |
| :--- | :--- |
| **Redis Connection Error** | Pastikan service Redis berjalan (`redis-cli ping`). Cek URL di `config.py`. |
| **Task Pending Selamanya** | Pastikan Celery Worker berjalan di terminal terpisah. Cek log worker untuk error. |
| **Bot Telegram Tidak Respon** | Cek apakah Token benar di `config.py`. Pastikan ID Anda ada di `ALLOWED_TELEGRAM_USERS`. |
| **Login Dashboard Gagal** | Pastikan memasukkan Chat ID yang tepat. Cek `SECRET_KEY` konsisten. |
| **Import Error** | Jalankan `pip install -r requirements.txt` ulang di environment yang benar. |

---

## 📚 Referensi Keamanan
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CVE Details](https://www.cvedetails.com/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)

*Dibuat untuk tujuan edukasi dan pertahanan siber.*

---

## 🛠️ Instalasi

### 1. Clone Repository atau Siapkan Folder
Buat folder baru dan masuk ke dalamnya:
```bash
mkdir vuln-scanner
cd vuln-scanner
```

### 2. Install Dependensi
Buat virtual environment (opsional tapi disarankan) dan install library yang dibutuhkan:

```bash
python3 -m venv venv
source venv/bin/activate  # Untuk Windows: venv\Scripts\activate

pip install -r requirements.txt
```

*Catatan: Pastikan Anda telah membuat file `requirements.txt` (lihat bagian File Struktur di bawah).*

### 3. Setup Bot Telegram

1.  Buka Telegram dan cari user **@BotFather**.
2.  Kirim perintah `/newbot`.
3.  Ikuti instruksi:
    - Beri nama bot (misal: `MySecurityScanner`).
    - Beri username bot (harus berakhiran `bot`, misal: `my_sec_scanner_bot`).
4.  BotFather akan memberikan **API TOKEN**. Simpan token ini (berbentuk string panjang seperti `123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11`).
5.  Cari bot yang baru dibuat di Telegram, klik **Start**, dan dapatkan **Chat ID** Anda:
    - Kirim pesan `/start` ke bot Anda.
    - Buka browser dan akses: `https://api.telegram.org/bot<TOKEN_ANDA>/getUpdates`
    - Cari bagian `"chat":{"id": <ANGKA_INI_ADALAH_CHAT_ID>}`.

---

## 📂 Struktur File

Pastikan struktur folder Anda seperti ini:

```text
vuln-scanner/
├── scanner.py            # Inti logika scanning
├── telegram_bot.py       # Kode bot Telegram
├── requirements.txt      # Daftar library python
├── config.py             # Konfigurasi (Token, Chat ID)
└── reports/              # Folder otomatis untuk menyimpan laporan
```

### Isi File `requirements.txt`
```text
requests
beautifulsoup4
python-telegram-bot==20.7
aiohttp
jinja2
```

### Isi File `config.py`
Ganti nilai di bawah dengan data Anda:
```python
# Konfigurasi Telegram
TELEGRAM_BOT_TOKEN = "GANTI_DENGAN_TOKEN_BOT_ANDA"
ALLOWED_CHAT_IDS = [123456789]  # Ganti dengan Chat ID Anda (bisa lebih dari satu)

# Konfigurasi Scanner
USER_AGENT = "Mozilla/5.0 (Advanced Vuln Scanner)"
TIMEOUT = 10
MAX_PAGES_TO_SCAN = 50
```

---

## 🚀 Cara Menggunakan

### Mode 1: Command Line Interface (CLI)
Jalankan scan langsung dari terminal komputer/server Anda.

```bash
# Scan dasar
python scanner.py -u https://target-anda.com

# Scan dengan output HTML
python scanner.py -u https://target-anda.com -o laporan.html

# Scan dengan output JSON
python scanner.py -u https://target-anda.com -f json -o hasil.json

# Mode verbose (detail)
python scanner.py -u https://target-anda.com -v
```

### Mode 2: Telegram Bot
Jalankan bot untuk mengontrol scanning dari HP.

1.  Jalankan script bot:
    ```bash
    python telegram_bot.py
    ```
2.  Buka Telegram dan kirim perintah ke bot Anda:
    - `/start`: Menampilkan menu bantuan.
    - `/scan https://target-anda.com`: Memulai proses scanning.
    - `/status`: Mengecek status scan yang sedang berjalan.
    - `/help`: Panduan penggunaan.

3.  Bot akan mengirimkan progres scanning dan mengirimkan file laporan (HTML) setelah selesai.

---

## 🔍 Detail Kerentanan & Output

Setiap kerentanan yang ditemukan akan menyertakan:
1.  **Nama & Tipe**: Misal "SQL Injection (Error Based)".
2.  **Severity**: Critical, High, Medium, Low.
3.  **Lokasi**: URL dan parameter yang rentan.
4.  **Risiko**: Penjelasan dampak jika dieksploitasi.
5.  **Proof of Concept (Exploit)**:
    - Contoh payload yang digunakan.
    - Langkah-langkah mereproduksi bug (untuk validasi).
6.  **Remediation (Perbaikan)**:
    - Penjelasan teknis cara memperbaiki.
    - Contoh kode sebelum (vulnerable) dan sesudah (secure) dalam bahasa populer (PHP, Python, Node.js, Java).
7.  **Referensi**: Link ke OWASP Top 10, CWE, dan tutorial mitigasi.

---

## 🤖 Alur Kerja Telegram Bot

1.  User mengirim `/scan <url>`.
2.  Bot memvalidasi apakah user diizinkan (berdasarkan `ALLOWED_CHAT_IDS`).
3.  Bot menjalankan proses scanning di background (async).
4.  Bot mengirimkan update berkala ("Sedang scanning...", "Menemukan XSS!", dll).
5.  Setelah selesai, bot mengirimkan file laporan `.html` dan ringkasan teks.

---

## 🛡️ Keamanan Penggunaan Bot

- **Whitelist Chat ID**: Hanya Chat ID yang terdaftar di `config.py` yang bisa menggunakan bot.
- **Private Bot**: Jangan publikasikan token bot Anda.
- **Rate Limiting**: Bot dibatasi agar tidak melakukan spam request ke target.

---

## 📄 Lisensi

Gunakan dengan bijak dan bertanggung jawab. Alat ini dirilis di bawah lisensi MIT untuk tujuan edukasi.

## 🙏 Kontribusi

Silakan fork dan submit pull request jika ingin menambahkan fitur deteksi kerentanan baru atau meningkatkan akurasi scanner.

---

**Dibuat untuk Edukasi Keamanan Siber.**
