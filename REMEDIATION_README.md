# 🔧 Auto-Remediation Engine

Modul otomatis untuk **memperbaiki celah keamanan** yang terdeteksi oleh vulnerability scanner.

## 🎯 Fitur Utama

### 1. **Code Patching Otomatis**
- ✅ SQL Injection → Parameterized Queries
- ✅ XSS → Output Escaping
- ✅ Command Injection → Input Sanitization

### 2. **Configuration Hardening**
- Generate security headers untuk Nginx/Apache/Express
- SSL/TLS configuration recommendations
- CORS policy setup

### 3. **Dependency Updates**
- Auto-generate commands untuk update package vulnerable
- Support: pip, npm, yarn, composer, maven

### 4. **Safety Features**
- 🛡️ **Dry Run Mode** (default) - Simulasi tanpa mengubah file
- 📦 **Auto Backup** - Backup file sebelum modifikasi
- 📝 **Detailed Logging** - Track semua perubahan

---

## 📖 Cara Penggunaan

### Quick Start

```python
from modules.remediation_engine import auto_fix

# Contoh 1: Fix Missing Security Headers
vuln = {
    "type": "MISSING_SECURITY_HEADERS",
    "target": "nginx",
    "details": {"server": "nginx"}
}
result = auto_fix(vuln, dry_run=True)  # dry_run=True untuk simulasi
print(result)

# Contoh 2: Fix Vulnerable Dependency
vuln_dep = {
    "type": "VULNERABLE_DEPENDENCY",
    "target": "requirements.txt",
    "details": {
        "package_manager": "pip",
        "package": "requests",
        "safe_version": "2.31.0"
    }
}
result = auto_fix(vuln_dep, dry_run=True)
print(result["commands"])  # ['pip install requests==2.31.0']
```

### Advanced Usage

```python
from modules.remediation_engine import RemediationEngine

# Initialize engine
engine = RemediationEngine(dry_run=False)  # False = apply changes

# Fix SQL Injection in file
with open("vulnerable.py", "r") as f:
    code = f.read()

fixed_code, changes = engine.fix_sql_injection(code, language="python")
print(f"Changes: {changes}")

# Apply to file (if not dry_run)
# engine.apply_remediation({...})
```

---

## 📋 Supported Vulnerabilities

| Vulnerability | Auto-Fix | Manual Review |
|--------------|----------|---------------|
| SQL Injection | ✅ (Parameterized) | ⚠️ Complex queries |
| XSS | ✅ (Escaping) | ⚠️ Dynamic content |
| Missing Headers | ✅ (Config gen) | ❌ |
| Vulnerable Deps | ✅ (Commands) | ❌ |
| CSRF | ❌ | ⚠️ Token implementation |
| IDOR/BOLA | ❌ | ⚠️ Logic fixes |
| Auth Issues | ❌ | ⚠️ Business logic |

---

## 🔒 Safety Modes

### Dry Run Mode (Recommended)
```python
auto_fix(vulnerability, dry_run=True)
```
- Hanya simulasi
- Tidak ada file yang diubah
- Output menunjukkan apa yang AKAN dilakukan

### Production Mode
```python
engine = RemediationEngine(dry_run=False)
```
- Backup otomatis dibuat di `remediation_backups/`
- File dimodifikasi langsung
- Log lengkap tersedia

---

## 📁 Output Structure

```json
{
  "fixed_files": [
    {
      "file": "app.py",
      "changes": ["Replaced f-string with parameterized query"],
      "applied": true
    }
  ],
  "generated_configs": ["security_headers_nginx.conf"],
  "commands": ["pip install requests==2.31.0"],
  "manual_steps": ["Review complex SQL in line 45"],
  "status": "success"
}
```

---

## 🧪 Testing

Jalankan demo:
```bash
python modules/remediation_engine.py
```

Test import:
```bash
python -c "from modules.remediation_engine import RemediationEngine; print('OK')"
```

---

## ⚠️ Disclaimer

- **Selalu gunakan Dry Run terlebih dahulu**
- **Review semua perubahan sebelum apply ke production**
- **Backup manual tetap recommended**
- Module ini adalah **assistant**, bukan pengganti security audit manual

---

## 🔗 Integration dengan Scanner

```python
from modules.scanner import scan_website
from modules.remediation_engine import auto_fix

# Scan
results = scan_website("https://target.com")

# Auto-fix setiap vulnerability
for vuln in results["vulnerabilities"]:
    fix_result = auto_fix(vuln, dry_run=True)
    print(f"Fix for {vuln['type']}: {fix_result['status']}")
```

---

## 🚀 Roadmap

- [ ] AST-based code analysis untuk akurasi lebih tinggi
- [ ] Support lebih banyak framework (Laravel, Django, Spring)
- [ ] Auto Pull Request creation ke GitHub/GitLab
- [ ] Integration dengan CI/CD pipelines
- [ ] Machine Learning untuk pattern recognition
