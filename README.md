# Advanced Web Vulnerability Scanner with Telegram Integration

Scanner kerentanan web canggih yang mendeteksi berbagai jenis celah keamanan (SQL Injection, XSS, Directory Traversal, dll) lengkap dengan analisis risiko, cara eksploitasi (untuk edukasi), dan panduan perbaikan. Dilengkapi dengan bot Telegram untuk kontrol jarak jauh.

## ⚠️ DISCLAIMER PENTING

**Alat ini hanya untuk tujuan edukasi dan pengujian keamanan pada sistem yang Anda miliki sendiri atau memiliki izin tertulis dari pemiliknya.**

- Penggunaan tanpa izin adalah **ILEGAL**.
- Penulis tidak bertanggung jawab atas penyalahgunaan alat ini.
- Selalu patuhi hukum yang berlaku di negara Anda.

---

## 🚀 Fitur Utama

### 1. Deteksi Kerentanan
- **SQL Injection** (Error-based, Boolean-based)
- **Cross-Site Scripting (XSS)** (Reflected)
- **Directory Traversal** (LFI/RFI)
- **Open Redirect**
- **Missing Security Headers** (HSTS, CSP, X-Frame-Options, dll)
- **Sensitive Files Exposure** (.env, .git/config, backup files)

### 2. Analisis Mendalam
- **Risk Score & Severity**: Penilaian tingkat bahaya (Low, Medium, High, Critical).
- **Dampak**: Penjelasan potensi kerusakan.
- **Cara Eksploitasi**: Contoh payload dan langkah-langkah reproduksi (untuk verifikasi manual).
- **Remediasi**: Panduan langkah demi langkah untuk memperbaiki celah, termasuk contoh kode.
- **Referensi**: Link ke OWASP, CVE, dan artikel keamanan terkait.

### 3. Pelaporan (Reporting)
- **HTML Report**: Laporan interaktif dengan dashboard, grafik, dan detail lengkap.
- **JSON Report**: Data terstruktur untuk integrasi API atau analisis lebih lanjut.
- **Console Output**: Log real-time saat scanning berlangsung.

### 4. Integrasi Telegram
- Jalankan scan langsung dari chat Telegram.
- Terima notifikasi otomatis saat scan selesai.
- Download laporan HTML/JSON langsung ke Telegram.
- Perintah sederhana: `/scan <url>`, `/status`, `/help`.

---

## 📋 Prasyarat

- Python 3.8 atau lebih baru
- Akun Telegram dan Token Bot (lihat panduan di bawah)
- Koneksi internet stabil

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
