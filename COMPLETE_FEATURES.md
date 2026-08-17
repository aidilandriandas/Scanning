# 🚀 Advanced Web Security Scanner - Fitur Lengkap

Sistem scanning keamanan web enterprise-grade dengan kemampuan deteksi dan remediasi otomatis.

## ✅ Modul yang Tersedia

### 1. **Core Vulnerability Scanner** (`modules/scanner.py`)
Deteksi kerentanan web standar (SQLi, XSS, File Sensitif, Security Headers).

### 2. **API Security Scanner** (`modules/api_scanner.py`)
- OWASP API Top 10 detection (BOLA, Broken Auth, Mass Assignment, dll)
- OpenAPI/Swagger specification validation
- Endpoint discovery & testing

### 3. **Auto Remediation** (`modules/auto_remediation.py`)
- **Auto-fix** untuk vulnerability umum
- Safe mode dengan backup otomatis
- Support: SQLi patching, XSS sanitization, Security Headers, Dependency updates

### 4. **Dynamic Web Scanner** (`modules/dynamic_scanner.py`) ⭐ BARU
Menggunakan **Playwright Headless Browser** untuk:
- ✅ DOM-based XSS detection
- ✅ JavaScript-heavy app analysis (SPA, React, Vue, Angular)
- ✅ Client-side route discovery
- ✅ Sensitive data exposure di LocalStorage/SessionStorage
- ✅ Network traffic analysis untuk credential leakage

### 5. **Asset Discovery & Reconnaissance** (`modules/asset_discovery.py`) ⭐ BARU
Fitur complete reconnaissance:
- ✅ **Subdomain Enumeration** - Brute-force subdomain aktif
- ✅ **Technology Fingerprinting** - Deteksi CMS, Framework, Server, CDN
- ✅ **Port Scanning** - Scan port umum (SSH, DB, Redis, Elasticsearch)
- ✅ **Cloud Bucket Detection** - Cek exposed AWS S3, DigitalOcean Spaces, Google Cloud Storage

### 6. **Business Logic & PII Scanner** (`modules/logic_pii_scanner.py`) ⭐ BARU
Deteksi advanced vulnerabilities:
- ✅ **IDOR (Insecure Direct Object Reference)** - Test akses resource user lain
- ✅ **Race Condition** - Deteksi bypass limit, double spending, coupon reuse
- ✅ **PII Leakage** - Scan kebocoran data pribadi:
  - Email, Phone, SSN
  - Credit Card Numbers
  - AWS Keys, Private Keys
  - Date of Birth, IP Addresses

---

## 📊 Ringkasan Fitur Lengkap

| Kategori | Fitur | Status |
|----------|-------|--------|
| **Web Vuln** | SQLi, XSS, LFI, RCE, Security Headers | ✅ |
| **API Security** | OWASP API Top 10, BOLA, Auth Testing | ✅ |
| **Dynamic Analysis** | Headless Browser, DOM XSS, JS Routes | ✅ |
| **Asset Discovery** | Subdomain, Tech Stack, Ports, Cloud Buckets | ✅ |
| **Business Logic** | IDOR, Race Condition | ✅ |
| **Privacy** | PII Leakage Detection (GDPR Compliance) | ✅ |
| **Remediation** | Auto-fix, Backup, Patch Generation | ✅ |
| **Dependencies** | SCA, CVE Detection, Auto Update | ✅ |

---

## 🔧 Cara Penggunaan

### Quick Start - Full Scan

```python
from modules.scanner import run_full_scan
from modules.api_scanner import scan_api
from modules.dynamic_scanner import scan_dynamic_web
from modules.asset_discovery import discover_assets
from modules.logic_pii_scanner import scan_business_logic, scan_pii

target = "https://example.com"

# 1. Traditional Web Scan
web_results = run_full_scan(target)

# 2. API Scan (jika ada endpoint API)
api_results = scan_api(f"{target}/api")

# 3. Dynamic Scan (untuk SPA/JS-heavy apps)
dynamic_results = asyncio.run(scan_dynamic_web(target))

# 4. Asset Discovery
asset_results = discover_assets("example.com")

# 5. Business Logic & PII (butuh auth token)
token = "your_jwt_token_here"
idor_results = scan_business_logic(f"{target}/api/users/123", "id", "123", token)
pii_results = scan_pii(f"{target}/api/profile", token)
```

### Auto Remediation

```python
from modules.auto_remediation import AutoRemediation

remediator = AutoRemediation()

# Dry run mode (preview perubahan tanpa eksekusi)
report = remediator.generate_fix_plan("path/to/vulnerable/code.py", dry_run=True)
print(report)

# Eksekusi fix dengan backup otomatis
result = remediator.apply_all_fixes("path/to/project/", auto_backup=True)
print(result)
```

---

## 🎯 Use Cases

### 1. **Security Researcher**
- Complete reconnaissance dengan Asset Discovery
- Deteksi vulnerability tradisional + advanced (IDOR, Race Condition)
- Validasi temuan dengan Dynamic Scanner

### 2. **DevSecOps / CI/CD**
- Integrasi scanning dalam pipeline
- Auto-remediation untuk vulnerability umum
- Compliance check (OWASP, GDPR, PCI-DSS)

### 3. **Developer**
- Scan lokal sebelum deploy
- Auto-fix suggestions dengan code patch
- PII leakage prevention

### 4. **Compliance Officer**
- Laporan compliance GDPR (PII detection)
- PCI-DSS check (credit card leakage)
- Audit trail lengkap

---

## 📦 Dependencies

Install semua requirements:

```bash
pip install requests playwright aiohttp dnspython python-nmap
playwright install chromium
```

---

## ⚠️ Disclaimer

**HANYA gunakan pada sistem yang Anda miliki atau memiliki izin tertulis.**
Penggunaan tanpa izin adalah tindakan ilegal dan dapat dikenakan sanksi hukum.

---

## 📈 Roadmap Fitur Selanjutnya

- [ ] CI/CD Integration (GitHub Actions, GitLab CI)
- [ ] Scheduled Monitoring & Alerting
- [ ] Multi-user RBAC & Audit Trail
- [ ] Dark Web Monitoring
- [ ] Mobile App Scanner (APK/IPA analysis)
- [ ] Phishing Simulation Module

---

**Version:** 2.0 Enterprise  
**Last Updated:** 2025  
**License:** MIT (Educational & Authorized Use Only)
