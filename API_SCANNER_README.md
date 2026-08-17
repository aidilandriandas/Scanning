# API Security Scanner Module

## 📋 Overview
Modul **API Security Scanner** yang mendeteksi kerentanan berdasarkan **OWASP API Top 10 2023**. Fitur ini melengkapi vulnerability scanner utama dengan kemampuan khusus untuk menguji keamanan API (REST, GraphQL).

## ✨ Fitur Utama

### Deteksi OWASP API Top 10:
1. **API1: Broken Object Level Authorization (BOLA/IDOR)**
   - Menguji akses tidak sah ke objek user lain
   - Deteksi ekspos data sensitif tanpa authorization

2. **API2: Broken Authentication**
   - Test bypass authentication
   - Deteksi invalid token yang diterima
   - Header injection testing

3. **API3: Excessive Data Exposure**
   - Identifikasi field sensitif yang terekspos
   - Check password, token, credit card, dll

4. **API4: Lack of Resources & Rate Limiting**
   - Test rapid requests untuk deteksi rate limiting
   - Analisis response headers

5. **API6: Mass Assignment**
   - Test privileged field manipulation
   - Deteksi prototype pollution

6. **API7: Security Misconfiguration**
   - Check missing security headers
   - CORS misconfiguration detection

7. **API8: Injection**
   - SQL Injection testing
   - NoSQL Injection testing
   - Command Injection testing

## 🚀 Cara Penggunaan

### 1. Import Module
```python
from modules.api_scanner import APISecurityScanner, scan_api
```

### 2. Quick Scan (Simple)
```python
# Scan API dengan konfigurasi otomatis
report = scan_api(
    target_url="https://api.example.com",
    auth_token="your_bearer_token_here"  # Optional
)

print(f"Total vulnerabilities: {report['total_vulnerabilities']}")
```

### 3. Advanced Usage
```python
# Inisialisasi scanner dengan parameter lengkap
scanner = APISecurityScanner(
    base_url="https://api.example.com",
    endpoints=[  # Optional: specific endpoints to scan
        "/api/users",
        "/api/products",
        "/api/orders/{id}"
    ],
    auth_token="eyJhbGciOiJIUzI1NiIs...",  # Optional
    openapi_spec="https://api.example.com/swagger.json"  # Optional
)

# Load OpenAPI/Swagger specification
scanner.load_openapi_spec()

# Discover endpoints automatically
endpoints = scanner.discover_endpoints()
print(f"Discovered {len(endpoints)} endpoints")

# Run all security checks
vulnerabilities = scanner.scan_all_endpoints()

# Generate comprehensive report
report = scanner.generate_report()

# Print summary
print(f"\n=== API Security Report ===")
print(f"Target: {report['target']}")
print(f"Endpoints scanned: {report['total_endpoints']}")
print(f"Total vulnerabilities: {report['total_vulnerabilities']}")
print(f"\nBy Severity:")
for severity, count in report['vulnerabilities_by_severity'].items():
    print(f"  {severity}: {count}")
```

### 4. Scan Specific Endpoint
```python
scanner = APISecurityScanner(base_url="https://api.example.com")

# Check BOLA on specific endpoint
bola_vulns = scanner.check_bola("/api/users/123", method="GET")

# Check authentication
auth_vulns = scanner.check_broken_authentication("/api/admin")

# Check rate limiting
rate_vulns = scanner.check_rate_limiting("/api/login", method="POST")

# Check for injection
inj_vulns = scanner.check_injection("/api/search", method="POST")
```

## 📊 Output Report Structure

```json
{
  "scan_timestamp": "2024-01-15T10:30:00",
  "target": "https://api.example.com",
  "total_endpoints": 15,
  "discovered_endpoints": [...],
  "rate_limit_info": {...},
  "total_vulnerabilities": 5,
  "vulnerabilities_by_severity": {
    "CRITICAL": 1,
    "HIGH": 2,
    "MEDIUM": 2,
    "LOW": 0
  },
  "vulnerabilities_by_category": {
    "API1:2023 Broken Object Level Authorization": [...],
    "API2:2023 Broken Authentication": [...]
  },
  "vulnerabilities": [
    {
      "type": "API1: Broken Object Level Authorization (BOLA)",
      "url": "https://api.example.com/api/users/123",
      "method": "GET",
      "details": "Endpoint returns sensitive data...",
      "severity": "HIGH",
      "cvss": 8.6,
      "owasp_category": "API1:2023 Broken Object Level Authorization",
      "remediation": "...",
      "impact": "...",
      "compliance": ["GDPR", "PCI-DSS", "OWASP_API_TOP_10"]
    }
  ],
  "compliance_status": {
    "OWASP_API_TOP_10": {
      "violations": [...],
      "compliant": false,
      "violation_count": 5
    }
  }
}
```

## 🔧 Integrasi dengan Main Scanner

Untuk mengintegrasikan API scanner ke dalam main application:

```python
# In app.py or tasks.py
from modules.api_scanner import scan_api

@app.route('/scan_api', methods=['POST'])
def run_api_scan():
    data = request.json
    target_url = data.get('url')
    auth_token = data.get('auth_token')
    
    # Run API scan
    report = scan_api(target_url, auth_token=auth_token)
    
    # Save to database or return
    return jsonify(report)
```

## ⚠️ Peringatan Penting

> **HANYA gunakan pada sistem yang Anda miliki atau memiliki izin tertulis!**
> 
> Unauthorized scanning adalah ilegal dan dapat menyebabkan:
> - Tuntutan hukum
> - Terminasi service
> - Kriminal charges

## 📚 Referensi

- [OWASP API Security Top 10 2023](https://owasp.org/www-project-api-security/)
- [API1: Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [API2: Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/)

## 🎯 Best Practices

1. **Selalu gunakan auth_token** untuk API yang memerlukan authentication
2. **Provide OpenAPI spec** untuk coverage lebih baik
3. **Run di staging environment** sebelum production
4. **Review manual** semua temuan critical/high
5. **Schedule regular scans** untuk continuous monitoring

## 🔄 Next Steps

Setelah menemukan vulnerabilities:
1. Prioritize berdasarkan severity (CRITICAL > HIGH > MEDIUM > LOW)
2. Assign ke development team untuk remediation
3. Re-scan setelah fix untuk verifikasi
4. Document lessons learned
5. Update security policies

---

**Created**: 2024
**Version**: 1.0
**Author**: Security Team
