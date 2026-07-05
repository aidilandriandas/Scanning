#!/usr/bin/env python3
"""
Advanced Web Vulnerability Scanner
Dengan Reporting, Risiko, Eksploitasi, dan Remediasi

PENTING: Gunakan HANYA pada sistem yang Anda miliki atau dengan izin eksplisit.
Scanning tanpa izin adalah ilegal.
"""

import argparse
import requests
from urllib.parse import urlparse, urljoin, urlencode
from bs4 import BeautifulSoup
import json
import html
import re
from datetime import datetime
from typing import Dict, List, Any
import os

# Database kerentanan dengan info lengkap
VULNERABILITY_DB = {
    "sql_injection": {
        "name": "SQL Injection",
        "severity": "CRITICAL",
        "risk_score": 9.8,
        "description": "SQL Injection memungkinkan penyerang untuk memanipulasi query database, mengakses data sensitif, memodifikasi atau menghapus data, bahkan mengambil alih server database.",
        "impact": "Kehilangan data, akses tidak sah, kompromi seluruh sistem",
        "references": [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://portswigger.net/web-security/sql-injection"
        ],
        "exploitation": {
            "method": "Manual Testing",
            "steps": [
                "1. Identifikasi parameter input (GET/POST)",
                "2. Inject payload: ' OR '1'='1",
                "3. Coba payload: ' UNION SELECT NULL--",
                "4. Jika error muncul atau data berubah, kemungkinan rentan",
                "5. Gunakan tools seperti sqlmap untuk automasi (dengan izin)"
            ],
            "example_payloads": [
                "' OR '1'='1",
                "1; DROP TABLE users--",
                "' UNION SELECT username, password FROM users--",
                "admin'--",
                "1' AND '1'='1"
            ],
            "warning": "JANGAN lakukan eksploitasi tanpa izin tertulis. Ini hanya untuk tujuan edukasi dan testing sistem sendiri."
        },
        "remediation": {
            "short": "Gunakan Prepared Statements/Parameterized Queries",
            "detailed": [
                "1. GUNAKAN PREPARED STATEMENTS/PARAMETERIZED QUERIES",
                "   Contoh PHP: $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');",
                "   $stmt->execute([$id]);",
                "",
                "2. Gunakan ORM (Object-Relational Mapping)",
                "   Contoh: SQLAlchemy (Python), Eloquent (Laravel), Hibernate (Java)",
                "",
                "3. Validasi dan sanitasi semua input user",
                "   - Whitelist karakter yang diperbolehkan",
                "   - Gunakan filter_var() di PHP",
                "",
                "4. Implementasi Least Privilege",
                "   - Database user tidak boleh punya akses root/admin",
                "",
                "5. Gunakan Web Application Firewall (WAF)",
                "   - ModSecurity, Cloudflare, AWS WAF",
                "",
                "6. Disable error messages di production",
                "   - Tampilkan custom error page"
            ],
            "code_examples": {
                "php": """
// BURUK - Rentan SQL Injection
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];

// BAIK - Prepared Statement
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET['id']]);
$user = $stmt->fetch();
                """,
                "python": """
# BURUK - Rentan SQL Injection
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# BAIK - Parameterized Query
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
                """,
                "nodejs": """
// BURUK - Rentan SQL Injection
const query = `SELECT * FROM users WHERE id = ${userId}`;

// BAIK - Parameterized Query
const query = 'SELECT * FROM users WHERE id = $1';
await pool.query(query, [userId]);
                """
            }
        }
    },
    
    "xss": {
        "name": "Cross-Site Scripting (XSS)",
        "severity": "HIGH",
        "risk_score": 7.5,
        "description": "XSS memungkinkan penyerang menyisipkan script malicious ke halaman web yang dilihat pengguna lain, mencuri session, redirect ke phishing, atau deface website.",
        "impact": "Pencurian cookie/session, deface, phishing, malware distribution",
        "references": [
            "https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            "https://portswigger.net/web-security/cross-site-scripting"
        ],
        "exploitation": {
            "method": "Manual Testing",
            "steps": [
                "1. Identifikasi titik input (form, URL params, headers)",
                "2. Inject payload: <script>alert('XSS')</script>",
                "3. Coba bypass filter: <img src=x onerror=alert(1)>",
                "4. Test berbagai konteks (HTML, attribute, JavaScript)",
                "5. Gunakan encoder untuk bypass filter sederhana"
            ],
            "example_payloads": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert(document.cookie)>",
                "<svg onload=alert(1)>",
                "javascript:alert(1)",
                "<body onload=alert('XSS')>",
                "\"><script>alert(String.fromCharCode(88,83,83))</script>"
            ],
            "warning": "JANGAN lakukan eksploitasi tanpa izin tertulis. Ini hanya untuk tujuan edukasi dan testing sistem sendiri."
        },
        "remediation": {
            "short": "Output Encoding & Content Security Policy",
            "detailed": [
                "1. OUTPUT ENCODING sesuai konteks",
                "   - HTML Context: htmlspecialchars() di PHP",
                "   - Attribute Context: Encode quotes dan special chars",
                "   - JavaScript Context: JSON.encode()",
                "   - URL Context: urlencode()",
                "",
                "2. Implementasi Content Security Policy (CSP)",
                "   Header: Content-Security-Policy: default-src 'self'",
                "",
                "3. Gunakan HTTPOnly flag pada cookies",
                "   Set-Cookie: session=xxx; HttpOnly; Secure",
                "",
                "4. Input Validation",
                "   - Whitelist karakter yang diperbolehkan",
                "   - Sanitize HTML jika perlu (gunakan library seperti HTMLPurifier)",
                "",
                "5. Framework modern sudah auto-escape",
                "   - React, Vue, Angular (tapi tetap waspada dengan dangerouslySetInnerHTML)"
            ],
            "code_examples": {
                "php": """
// BURUK - Rentan XSS
echo $_GET['name'];

// BAIK - Output Encoding
echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');

// Untuk CSP, tambahkan header:
header("Content-Security-Policy: default-src 'self'");
                """,
                "python_flask": """
# BURUK - Rentan XSS
return render_template_string('<h1>{{ name }}</h1>')

# BAIK - Flask auto-escape dengan Jinja2
return render_template('page.html', name=name)
# Di template: {{ name }} (auto escaped)
                """,
                "nodejs_express": """
// BURUK - Rentan XSS
res.send(`<h1>${req.query.name}</h1>`);

// BAIK - Template engine auto-escape
res.render('page', { name: req.query.name });
// Atau manual encoding:
const escapeHtml = require('escape-html');
res.send(`<h1>${escapeHtml(req.query.name)}</h1>`);
                """
            }
        }
    },
    
    "directory_traversal": {
        "name": "Directory Traversal / Path Traversal",
        "severity": "HIGH",
        "risk_score": 7.5,
        "description": "Memungkinkan penyerang mengakses file di luar direktori web root, membaca file konfigurasi, source code, atau data sensitif sistem.",
        "impact": "Pembacaan file sensitif (/etc/passwd, .env, config files), informasi disclosure",
        "references": [
            "https://owasp.org/www-community/attacks/Path_Traversal",
            "https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Prevention_Cheat_Sheet.html",
            "https://portswigger.net/web-security/file-path-traversal"
        ],
        "exploitation": {
            "method": "Manual Testing",
            "steps": [
                "1. Identifikasi parameter yang menerima file path",
                "2. Inject: ../../../etc/passwd",
                "3. Coba variasi: ....//....//etc/passwd",
                "4. Test URL encoding: %2e%2e%2f",
                "5. Coba akses file Windows: ..\\..\\windows\\system32\\config\\SAM"
            ],
            "example_payloads": [
                "../../../etc/passwd",
                "....//....//etc/passwd",
                "..%2f..%2f..%2fetc%2fpasswd",
                "..\\\\..\\\\windows\\\\system32\\\\config\\\\SAM",
                "/etc/shadow",
                "../../../../../../var/log/auth.log"
            ],
            "warning": "JANGAN lakukan eksploitasi tanpa izin tertulis. Ini hanya untuk tujuan edukasi dan testing sistem sendiri."
        },
        "remediation": {
            "short": "Input Validation & Chroot Jail",
            "detailed": [
                "1. JANGAN pernah trust user input untuk file path",
                "",
                "2. Gunakan whitelist untuk file yang diperbolehkan",
                "   $allowed_files = ['home.html', 'about.html'];",
                "   if in_array($file, $allowed_files): ...",
                "",
                "3. Implementasi chroot jail atau sandbox",
                "   Batasi akses ke direktori tertentu saja",
                "",
                "4. Remove/../dari input",
                "   Tapi ini BUKAN solusi lengkap (bisa di-bypass)",
                "",
                "5. Gunakan realpath() dan validasi prefix",
                "   $real_path = realpath($base_dir . '/' . $file);",
                "   if strpos($real_path, $base_dir) !== 0: deny",
                "",
                "6. Set proper file permissions",
                "   File sensitif tidak boleh readable oleh web server"
            ],
            "code_examples": {
                "php": """
// BURUK - Rentan Path Traversal
$file = $_GET['file'];
include($file);

// BAIK - Whitelist + realpath validation
$base_dir = '/var/www/html/pages/';
$file = basename($_GET['file']); // Hanya filename
$allowed = ['home.php', 'about.php', 'contact.php'];

if (in_array($file, $allowed)) {
    $real_path = realpath($base_dir . $file);
    if (strpos($real_path, $base_dir) === 0) {
        include($real_path);
    }
}
                """,
                "python": """
# BURUK - Rentan Path Traversal
file_path = request.args.get('file')
with open(file_path, 'r') as f:
    return f.read()

# BAIK - Validation dengan pathlib
from pathlib import Path
base_dir = Path('/var/www/files').resolve()
requested = Path(request.args.get('file'))
full_path = (base_dir / requested).resolve()

if base_dir in full_path.parents or full_path == base_dir:
    with open(full_path, 'r') as f:
        return f.read()
else:
    abort(403)
                """
            }
        }
    },
    
    "missing_security_headers": {
        "name": "Missing Security Headers",
        "severity": "MEDIUM",
        "risk_score": 5.0,
        "description": "Tidak adanya security headers membuat aplikasi rentan terhadap berbagai serangan seperti clickjacking, XSS, MIME sniffing, dan information disclosure.",
        "impact": "Clickjacking, XSS, MIME confusion, caching sensitive data",
        "references": [
            "https://owasp.org/www-project-secure-headers/",
            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers"
        ],
        "exploitation": {
            "method": "Analysis & Exploitation",
            "steps": [
                "1. Cek headers dengan browser dev tools atau curl",
                "2. Jika X-Frame-Options hilang: buat iframe untuk clickjacking",
                "3. Jika CSP hilang: coba inject XSS lebih mudah",
                "4. Jika HSTS hilang: coba SSL stripping attack",
                "5. Gunakan tools seperti securityheaders.com untuk scoring"
            ],
            "example_attack_scenarios": [
                "Clickjacking: Embed site dalam iframe transparan untuk trick user klik",
                "MIME Sniffing: Upload file HTML sebagai gambar untuk execute script",
                "Cache Poisoning: Sensitive data ter-cache di browser/proxy",
                "SSL Stripping: Downgrade HTTPS ke HTTP untuk intercept data"
            ],
            "warning": "JANGAN lakukan eksploitasi tanpa izin tertulis. Ini hanya untuk tujuan edukasi dan testing sistem sendiri."
        },
        "remediation": {
            "short": "Implementasi Semua Security Headers",
            "detailed": [
                "1. X-Frame-Options: DENY atau SAMEORIGIN",
                "   Mencegah clickjacking",
                "",
                "2. Content-Security-Policy (CSP)",
                "   default-src 'self'; script-src 'self'; object-src 'none'",
                "",
                "3. X-Content-Type-Options: nosniff",
                "   Mencegah MIME sniffing",
                "",
                "4. Strict-Transport-Security (HSTS)",
                "   max-age=31536000; includeSubDomains; preload",
                "",
                "5. X-XSS-Protection: 1; mode=block",
                "   (Legacy, tapi masih berguna untuk browser lama)",
                "",
                "6. Referrer-Policy: strict-origin-when-cross-origin",
                "   Kontrol informasi referrer",
                "",
                "7. Permissions-Policy (Feature-Policy)",
                "   camera=(), microphone=(), geolocation=()"
            ],
            "code_examples": {
                "apache": """
# .htaccess atau httpd.conf
Header always set X-Frame-Options "DENY"
Header always set X-Content-Type-Options "nosniff"
Header always set X-XSS-Protection "1; mode=block"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
                """,
                "nginx": """
# nginx.conf
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
                """,
                "nodejs_express": """
const helmet = require('helmet');
app.use(helmet());

// Atau manual:
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  next();
});
                """,
                "php": """
<?php
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Strict-Transport-Security: max-age=31536000; includeSubDomains");
header("Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'");
header("Referrer-Policy: strict-origin-when-cross-origin");
?>
                """
            }
        }
    },
    
    "open_redirect": {
        "name": "Open Redirect",
        "severity": "MEDIUM",
        "risk_score": 4.5,
        "description": "Open Redirect memungkinkan penyerang mengarahkan user dari website terpercaya ke website malicious untuk phishing atau malware distribution.",
        "impact": "Phishing attacks, malware distribution, reputation damage",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
            "https://portswigger.net/kb/issues/00500e00_open-redirection-reflected",
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect"
        ],
        "exploitation": {
            "method": "Manual Testing",
            "steps": [
                "1. Cari parameter redirect: ?url=, ?next=, ?redirect=",
                "2. Inject URL eksternal: https://evil.com",
                "3. Coba bypass: //evil.com, /\\/evil.com",
                "4. Test URL encoding: %2f%2fevil.com",
                "5. Coba domain relatif: evil.com"
            ],
            "example_payloads": [
                "https://evil.com",
                "//evil.com",
                "/\\/evil.com",
                "///evil.com",
                "https://google.com@evil.com",
                "%2f%2fevil.com",
                "javascript:alert(1)"
            ],
            "warning": "JANGAN lakukan eksploitasi tanpa izin tertulis. Ini hanya untuk tujuan edukasi dan testing sistem sendiri."
        },
        "remediation": {
            "short": "Validasi Redirect URL",
            "detailed": [
                "1. JANGAN gunakan URL dari user input langsung",
                "",
                "2. Gunakan whitelist untuk URL yang diperbolehkan",
                "   allowed_urls = ['/home', '/dashboard', '/profile']",
                "",
                "3. Jika harus external, gunakan mapping ID",
                "   ?redirect_id=1 -> lookup di database",
                "",
                "4. Validasi URL scheme dan domain",
                "   Pastikan hanya http/https dan domain sendiri",
                "",
                "5. Gunakan relative path saja",
                "   redirect('/dashboard') bukan redirect(url)",
                "",
                "6. Warning page sebelum redirect ke external",
                "   'Anda akan diarahkan ke situs eksternal...'"
            ],
            "code_examples": {
                "php": """
// BURUK - Open Redirect
$redirect = $_GET['url'];
header("Location: " . $redirect);

// BAIK - Whitelist validation
$allowed = ['/home', '/dashboard', '/profile'];
$redirect = $_GET['url'] ?? '/home';

if (in_array($redirect, $allowed)) {
    header("Location: " . $redirect);
} else {
    header("Location: /home"); // Default safe
}

// BAIK - Validasi domain sendiri
$parsed = parse_url($redirect);
if (isset($parsed['host']) && $parsed['host'] === $_SERVER['HTTP_HOST']) {
    header("Location: " . $redirect);
} else {
    header("Location: /home");
}
                """,
                "python_flask": """
# BURUK - Open Redirect
from flask import redirect, request
return redirect(request.args.get('next'))

# BAIK - Validasi dengan is_safe_url
from werkzeug.urls import url_parse

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

next_page = request.args.get('next')
if not is_safe_url(next_page):
    next_page = url_for('index')
return redirect(next_page)
                """,
                "nodejs_express": """
// BURUK - Open Redirect
app.get('/redirect', (req, res) => {
  res.redirect(req.query.url);
});

// BAIK - Validasi
const { URL } = require('url');

app.get('/redirect', (req, res) => {
  const target = req.query.url || '/';
  try {
    const parsed = new URL(target, 'http://' + req.get('host'));
    if (parsed.hostname === req.get('host')) {
      res.redirect(target);
    } else {
      res.redirect('/');
    }
  } catch {
    res.redirect('/');
  }
});
                """
            }
        }
    },
    
    "sensitive_files": {
        "name": "Sensitive Files Exposure",
        "severity": "CRITICAL",
        "risk_score": 8.5,
        "description": "File sensitif seperti .env, .git/config, backup files, atau config files terekspos publik, mengandung credentials, API keys, atau informasi kritis lainnya.",
        "impact": "Credential theft, API key compromise, source code disclosure, full system compromise",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/",
            "https://github.com/random-robbie/My-Shodan-Scripts"
        ],
        "exploitation": {
            "method": "Direct Access",
            "steps": [
                "1. Scan common sensitive files dengan directory scanner",
                "2. Akses langsung: /.env, /.git/config, /backup.sql",
                "3. Gunakan tools: dirb, gobuster, ffuf",
                "4. Check robots.txt untuk hint directories",
                "5. Try variations: .env.bak, config.php.old, db.sql.gz"
            ],
            "common_files": [
                ".env",
                ".git/config",
                ".gitignore",
                "wp-config.php",
                "config.php",
                "database.yml",
                "settings.py",
                ".aws/credentials",
                "id_rsa",
                "backup.sql",
                "dump.sql",
                "*.bak",
                "*.old",
                "*.tmp"
            ],
            "warning": "JANGAN lakukan eksploitasi tanpa izin tertulis. Ini hanya untuk tujuan edukasi dan testing sistem sendiri."
        },
        "remediation": {
            "short": "Block Access & Remove Sensitive Files",
            "detailed": [
                "1. HAPUS semua file sensitif dari web root",
                "   Pindahkan ke luar document root",
                "",
                "2. Block access dengan .htaccess atau nginx config",
                "   Deny all untuk .env, .git, .svn, dll",
                "",
                "3. Gunakan .gitignore yang proper",
                "   Jangan commit .env, credentials, keys",
                "",
                "4. Environment variables untuk secrets",
                "   Jangan hardcode credentials di code",
                "",
                "5. Regular audit dengan scanning tools",
                "   Cek exposed files secara berkala",
                "",
                "6. Rotate semua credentials jika sudah terekspos",
                "   Anggap semua secrets sudah compromised"
            ],
            "code_examples": {
                "apache": """
# .htaccess - Block sensitive files
<FilesMatch "^\\.">
    Order allow,deny
    Deny from all
</FilesMatch>

<FilesMatch "\\.(env|git|svn|htaccess|htpasswd|ini|log|sh|sql|conf|bak|old|tmp)$">
    Order allow,deny
    Deny from all
</FilesMatch>

# Block directories
RedirectMatch 403 /\\.git
RedirectMatch 403 /\\.svn
                """,
                "nginx": """
# nginx.conf - Block sensitive files
location ~ /\\. {
    deny all;
    return 404;
}

location ~* \\.(env|git|svn|htaccess|htpasswd|ini|log|sh|sql|conf|bak|old|tmp)$ {
    deny all;
    return 404;
}

location ~ ^/(wp-config|config|settings|database) {
    deny all;
    return 404;
}
                """,
                "gitignore": """
# .gitignore - Jangan commit ini
.env
.env.*
*.pem
*.key
id_rsa
id_rsa.pub
.aws/
.azure/
config.local.php
*.sql
*.sql.gz
backup/
uploads/
vendor/
node_modules/
.DS_Store
Thumbs.db
                """
            }
        }
    }
}

class VulnerabilityScanner:
    def __init__(self, target_url: str, verbose: bool = False):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.vulnerabilities = []
        self.verbose = verbose
        self.crawled_urls = set()
        self.forms = []
        
    def log(self, message: str, level: str = "INFO"):
        """Logging dengan warna"""
        colors = {
            "INFO": "\033[94m",
            "SUCCESS": "\033[92m",
            "WARNING": "\033[93m",
            "ERROR": "\033[91m",
            "CRITICAL": "\033[95m"
        }
        reset = "\033[0m"
        color = colors.get(level, "")
        print(f"{color}[{level}] {reset}{message}")
    
    def get_domain(self) -> str:
        """Extract domain dari URL"""
        parsed = urlparse(self.target_url)
        return parsed.netloc
    
    def is_same_domain(self, url: str) -> bool:
        """Cek apakah URL masih dalam domain yang sama"""
        parsed = urlparse(url)
        return parsed.netloc == '' or parsed.netloc == self.get_domain()
    
    def crawl(self, max_pages: int = 50) -> List[str]:
        """Crawl website untuk menemukan semua halaman"""
        self.log(f"Starting crawl from {self.target_url}", "INFO")
        to_visit = [self.target_url]
        visited = set()
        
        while to_visit and len(visited) < max_pages:
            current_url = to_visit.pop(0)
            
            if current_url in visited:
                continue
                
            try:
                response = self.session.get(current_url, timeout=10)
                visited.add(current_url)
                self.crawled_urls.add(current_url)
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Extract links
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        full_url = urljoin(current_url, href)
                        
                        if self.is_same_domain(full_url) and full_url not in visited:
                            if '#' in full_url:
                                full_url = full_url.split('#')[0]
                            to_visit.append(full_url)
                    
                    # Extract forms
                    for form in soup.find_all('form'):
                        form_data = self.extract_form(form, current_url)
                        if form_data:
                            self.forms.append(form_data)
                
                if self.verbose:
                    self.log(f"Crawled: {current_url}", "SUCCESS")
                    
            except Exception as e:
                if self.verbose:
                    self.log(f"Error crawling {current_url}: {str(e)}", "ERROR")
        
        self.log(f"Crawl completed. Found {len(visited)} pages and {len(self.forms)} forms", "SUCCESS")
        return list(visited)
    
    def extract_form(self, form, page_url: str) -> Dict:
        """Extract form information"""
        action = form.get('action', '')
        if not action or action.startswith('#'):
            action = page_url
        else:
            action = urljoin(page_url, action)
        
        method = form.get('method', 'get').lower()
        inputs = []
        
        for inp in form.find_all(['input', 'textarea', 'select']):
            name = inp.get('name')
            if name:
                inp_type = inp.get('type', 'text')
                inputs.append({
                    'name': name,
                    'type': inp_type,
                    'value': inp.get('value', '')
                })
        
        if inputs:
            return {
                'action': action,
                'method': method,
                'inputs': inputs,
                'page': page_url
            }
        return None
    
    def check_sql_injection(self):
        """Check SQL Injection vulnerabilities"""
        self.log("Checking for SQL Injection...", "INFO")
        
        sql_payloads = [
            "' OR '1'='1",
            "1' OR '1'='1' --",
            "1' AND '1'='1",
            "' UNION SELECT NULL --",
            "admin'--",
            "1; DROP TABLE users--"
        ]
        
        # Test URL parameters
        parsed = urlparse(self.target_url)
        params = {}
        
        for key, value in urlparse(self.target_url).query.split('&'):
            if '=' in key:
                k, v = key.split('=', 1)
                params[k] = v
        
        for param, original_value in params.items():
            for payload in sql_payloads:
                test_params = params.copy()
                test_params[param] = payload
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if test_params:
                    test_url += "?" + urlencode(test_params)
                
                try:
                    response = self.session.get(test_url, timeout=10)
                    
                    # Detect SQL injection based on errors
                    error_patterns = [
                        r"SQL syntax.*MySQL",
                        r"Warning.*mysql_",
                        r"unclosed quotation mark",
                        r"ODBC Microsoft Access",
                        r"PostgreSQL.*ERROR",
                        r"Oracle.*ORA-",
                        r"SQLite.*error",
                        r"Microsoft SQL Server.*Error",
                        r"DB2.*SQLCODE"
                    ]
                    
                    for pattern in error_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            vuln = {
                                "type": "sql_injection",
                                "location": "URL Parameter",
                                "parameter": param,
                                "payload_tested": payload,
                                "url": test_url,
                                "evidence": f"Error pattern detected: {pattern}",
                                "response_snippet": response.text[:500]
                            }
                            self.vulnerabilities.append(vuln)
                            self.log(f"SQL Injection found in parameter '{param}'", "CRITICAL")
                            break
                            
                except Exception as e:
                    if self.verbose:
                        self.log(f"Error testing {param}: {str(e)}", "ERROR")
        
        # Test form inputs
        for form in self.forms:
            for inp in form['inputs']:
                if inp['type'] in ['text', 'password', 'email', 'search', 'number']:
                    for payload in sql_payloads:
                        test_data = {}
                        for field in form['inputs']:
                            if field['name'] == inp['name']:
                                test_data[field['name']] = payload
                            else:
                                test_data[field['name']] = field.get('value', 'test')
                        
                        try:
                            if form['method'] == 'post':
                                response = self.session.post(form['action'], data=test_data, timeout=10)
                            else:
                                response = self.session.get(form['action'], params=test_data, timeout=10)
                            
                            error_patterns = [
                                r"SQL syntax.*MySQL",
                                r"Warning.*mysql_",
                                r"unclosed quotation mark",
                                r"ODBC Microsoft Access",
                                r"PostgreSQL.*ERROR",
                                r"Oracle.*ORA-"
                            ]
                            
                            for pattern in error_patterns:
                                if re.search(pattern, response.text, re.IGNORECASE):
                                    vuln = {
                                        "type": "sql_injection",
                                        "location": "Form Input",
                                        "parameter": inp['name'],
                                        "form_action": form['action'],
                                        "payload_tested": payload,
                                        "evidence": f"Error pattern detected: {pattern}",
                                        "response_snippet": response.text[:500]
                                    }
                                    self.vulnerabilities.append(vuln)
                                    self.log(f"SQL Injection found in form field '{inp['name']}'", "CRITICAL")
                                    break
                                    
                        except Exception as e:
                            if self.verbose:
                                self.log(f"Error testing form field {inp['name']}: {str(e)}", "ERROR")
    
    def check_xss(self):
        """Check Cross-Site Scripting vulnerabilities"""
        self.log("Checking for XSS...", "INFO")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>",
            "<body onload=alert('XSS')>",
            "javascript:alert(1)"
        ]
        
        # Test URL parameters
        parsed = urlparse(self.target_url)
        params = {}
        
        query_parts = parsed.query.split('&')
        for part in query_parts:
            if '=' in part:
                k, v = part.split('=', 1)
                params[k] = v
        
        for param, original_value in params.items():
            for payload in xss_payloads:
                test_params = params.copy()
                test_params[param] = payload
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if test_params:
                    test_url += "?" + urlencode(test_params)
                
                try:
                    response = self.session.get(test_url, timeout=10)
                    
                    # Check if payload is reflected without proper encoding
                    if payload in response.text or html.escape(payload) not in response.text:
                        # Additional check: see if script tags are present
                        if '<script>' in response.text.lower() or 'onerror=' in response.text.lower():
                            vuln = {
                                "type": "xss",
                                "location": "URL Parameter",
                                "parameter": param,
                                "payload_tested": payload,
                                "url": test_url,
                                "evidence": "Payload reflected in response without proper encoding",
                                "response_snippet": response.text[:500]
                            }
                            self.vulnerabilities.append(vuln)
                            self.log(f"XSS found in parameter '{param}'", "WARNING")
                            break
                            
                except Exception as e:
                    if self.verbose:
                        self.log(f"Error testing {param} for XSS: {str(e)}", "ERROR")
        
        # Test form inputs
        for form in self.forms:
            for inp in form['inputs']:
                if inp['type'] in ['text', 'search', 'email']:
                    for payload in xss_payloads:
                        test_data = {}
                        for field in form['inputs']:
                            if field['name'] == inp['name']:
                                test_data[field['name']] = payload
                            else:
                                test_data[field['name']] = field.get('value', 'test')
                        
                        try:
                            if form['method'] == 'post':
                                response = self.session.post(form['action'], data=test_data, timeout=10)
                            else:
                                response = self.session.get(form['action'], params=test_data, timeout=10)
                            
                            if '<script>' in response.text.lower() or 'onerror=' in response.text.lower():
                                vuln = {
                                    "type": "xss",
                                    "location": "Form Input",
                                    "parameter": inp['name'],
                                    "form_action": form['action'],
                                    "payload_tested": payload,
                                    "evidence": "XSS payload executed/reflected in response",
                                    "response_snippet": response.text[:500]
                                }
                                self.vulnerabilities.append(vuln)
                                self.log(f"XSS found in form field '{inp['name']}'", "WARNING")
                                break
                                
                        except Exception as e:
                            if self.verbose:
                                self.log(f"Error testing form field {inp['name']} for XSS: {str(e)}", "ERROR")
    
    def check_directory_traversal(self):
        """Check Directory Traversal vulnerabilities"""
        self.log("Checking for Directory Traversal...", "INFO")
        
        traversal_payloads = [
            "../../../etc/passwd",
            "....//....//etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "/etc/passwd",
            "../../../../../../var/log/auth.log"
        ]
        
        # Test URL parameters that might accept file paths
        parsed = urlparse(self.target_url)
        params = {}
        
        query_parts = parsed.query.split('&')
        for part in query_parts:
            if '=' in part:
                k, v = part.split('=', 1)
                # Check if parameter name suggests file handling
                if any(keyword in k.lower() for keyword in ['file', 'path', 'dir', 'doc', 'page', 'template']):
                    params[k] = v
        
        for param, original_value in params.items():
            for payload in traversal_payloads:
                test_params = params.copy()
                test_params[param] = payload
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if test_params:
                    test_url += "?" + urlencode(test_params)
                
                try:
                    response = self.session.get(test_url, timeout=10)
                    
                    # Check for passwd file patterns
                    if 'root:' in response.text and ':/bin/bash' in response.text:
                        vuln = {
                            "type": "directory_traversal",
                            "location": "URL Parameter",
                            "parameter": param,
                            "payload_tested": payload,
                            "url": test_url,
                            "evidence": "System file content (/etc/passwd) returned in response",
                            "response_snippet": response.text[:500]
                        }
                        self.vulnerabilities.append(vuln)
                        self.log(f"Directory Traversal found in parameter '{param}'", "CRITICAL")
                        break
                    
                    # Check for log files or other sensitive content
                    if 'sshd' in response.text or 'auth' in response.text.lower():
                        vuln = {
                            "type": "directory_traversal",
                            "location": "URL Parameter",
                            "parameter": param,
                            "payload_tested": payload,
                            "url": test_url,
                            "evidence": "Log file content detected in response",
                            "response_snippet": response.text[:500]
                        }
                        self.vulnerabilities.append(vuln)
                        self.log(f"Directory Traversal found in parameter '{param}'", "CRITICAL")
                        break
                        
                except Exception as e:
                    if self.verbose:
                        self.log(f"Error testing {param} for traversal: {str(e)}", "ERROR")
    
    def check_security_headers(self):
        """Check for missing security headers"""
        self.log("Checking Security Headers...", "INFO")
        
        required_headers = {
            'X-Frame-Options': 'Missing X-Frame-Options (Clickjacking protection)',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options (MIME sniffing protection)',
            'X-XSS-Protection': 'Missing X-XSS-Protection',
            'Strict-Transport-Security': 'Missing HSTS (HTTPS enforcement)',
            'Content-Security-Policy': 'Missing CSP (XSS and injection protection)',
            'Referrer-Policy': 'Missing Referrer-Policy'
        }
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            headers = response.headers
            
            missing = []
            for header, description in required_headers.items():
                if header not in headers:
                    missing.append({
                        'header': header,
                        'description': description
                    })
            
            if missing:
                vuln = {
                    "type": "missing_security_headers",
                    "location": "HTTP Response Headers",
                    "url": self.target_url,
                    "missing_headers": missing,
                    "evidence": f"Missing {len(missing)} critical security headers",
                    "all_headers": dict(headers)
                }
                self.vulnerabilities.append(vuln)
                self.log(f"Missing {len(missing)} security headers", "WARNING")
                
        except Exception as e:
            self.log(f"Error checking headers: {str(e)}", "ERROR")
    
    def check_open_redirect(self):
        """Check for Open Redirect vulnerabilities"""
        self.log("Checking for Open Redirect...", "INFO")
        
        redirect_payloads = [
            "https://evil.com",
            "//evil.com",
            "///evil.com",
            "/\\/evil.com",
            "https://google.com@evil.com"
        ]
        
        # Test URL parameters
        parsed = urlparse(self.target_url)
        params = {}
        
        query_parts = parsed.query.split('&')
        for part in query_parts:
            if '=' in part:
                k, v = part.split('=', 1)
                # Check if parameter name suggests redirect
                if any(keyword in k.lower() for keyword in ['url', 'redirect', 'next', 'return', 'goto', 'dest', 'target']):
                    params[k] = v
        
        for param, original_value in params.items():
            for payload in redirect_payloads:
                test_params = params.copy()
                test_params[param] = payload
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if test_params:
                    test_url += "?" + urlencode(test_params)
                
                try:
                    response = self.session.get(test_url, timeout=10, allow_redirects=False)
                    
                    # Check Location header
                    location = response.headers.get('Location', '')
                    if location and ('evil.com' in location or 'google.com' in location):
                        vuln = {
                            "type": "open_redirect",
                            "location": "URL Parameter",
                            "parameter": param,
                            "payload_tested": payload,
                            "url": test_url,
                            "redirect_location": location,
                            "evidence": f"Unvalidated redirect to: {location}",
                            "status_code": response.status_code
                        }
                        self.vulnerabilities.append(vuln)
                        self.log(f"Open Redirect found in parameter '{param}'", "WARNING")
                        break
                    
                    # Follow redirects and check final URL
                    response_follow = self.session.get(test_url, timeout=10, allow_redirects=True)
                    if response_follow.url != test_url:
                        if 'evil.com' in response_follow.url or 'google.com' in response_follow.url:
                            vuln = {
                                "type": "open_redirect",
                                "location": "URL Parameter",
                                "parameter": param,
                                "payload_tested": payload,
                                "url": test_url,
                                "redirect_location": response_follow.url,
                                "evidence": f"Redirected to external URL: {response_follow.url}",
                                "status_code": response.status_code
                            }
                            self.vulnerabilities.append(vuln)
                            self.log(f"Open Redirect found in parameter '{param}'", "WARNING")
                            break
                            
                except Exception as e:
                    if self.verbose:
                        self.log(f"Error testing {param} for redirect: {str(e)}", "ERROR")
    
    def check_sensitive_files(self):
        """Check for exposed sensitive files"""
        self.log("Checking for Sensitive Files...", "INFO")
        
        sensitive_files = [
            '.env',
            '.git/config',
            '.gitignore',
            'wp-config.php',
            'config.php',
            'database.yml',
            'settings.py',
            '.aws/credentials',
            'backup.sql',
            'dump.sql',
            'db.sql',
            'config.bak',
            '.htaccess',
            '.htpasswd',
            'web.config',
            'phpinfo.php',
            'info.php',
            'test.php'
        ]
        
        for file_path in sensitive_files:
            test_url = f"{self.target_url}/{file_path}"
            
            try:
                response = self.session.get(test_url, timeout=10)
                
                if response.status_code == 200:
                    # Check for sensitive content
                    is_sensitive = False
                    evidence = ""
                    
                    if file_path.endswith('.env'):
                        if 'DB_' in response.text or 'API_' in response.text or '=' in response.text:
                            is_sensitive = True
                            evidence = "Environment variables detected"
                    
                    elif file_path.endswith('.git/config'):
                        if '[core]' in response.text and 'repositoryformatversion' in response.text:
                            is_sensitive = True
                            evidence = "Git configuration file exposed"
                    
                    elif file_path.endswith('.sql'):
                        if 'CREATE TABLE' in response.text or 'INSERT INTO' in response.text:
                            is_sensitive = True
                            evidence = "Database dump file exposed"
                    
                    elif file_path in ['phpinfo.php', 'info.php']:
                        if 'PHP Version' in response.text and 'phpinfo()' in response.text:
                            is_sensitive = True
                            evidence = "PHPInfo page exposed - reveals server configuration"
                    
                    elif file_path == '.htaccess':
                        if 'RewriteEngine' in response.text or 'Deny' in response.text:
                            is_sensitive = True
                            evidence = "Apache configuration exposed"
                    
                    # Generic check for code/config files
                    if not is_sensitive and response.status_code == 200:
                        if '<?php' in response.text or 'password' in response.text.lower() or 'secret' in response.text.lower():
                            is_sensitive = True
                            evidence = "Potentially sensitive content detected"
                    
                    if is_sensitive:
                        vuln = {
                            "type": "sensitive_files",
                            "location": "Public URL",
                            "file_path": file_path,
                            "url": test_url,
                            "evidence": evidence,
                            "status_code": response.status_code,
                            "content_snippet": response.text[:500]
                        }
                        self.vulnerabilities.append(vuln)
                        self.log(f"Sensitive file exposed: {file_path}", "CRITICAL")
                        
            except Exception as e:
                if self.verbose:
                    self.log(f"Error checking {file_path}: {str(e)}", "ERROR")
    
    def scan(self):
        """Run all security checks"""
        self.log(f"Starting scan on {self.target_url}", "INFO")
        self.log("=" * 60, "INFO")
        
        # Crawl first
        self.crawl(max_pages=30)
        
        # Run all checks
        self.check_sql_injection()
        self.check_xss()
        self.check_directory_traversal()
        self.check_security_headers()
        self.check_open_redirect()
        self.check_sensitive_files()
        
        self.log("=" * 60, "INFO")
        self.log(f"Scan completed. Found {len(self.vulnerabilities)} potential vulnerabilities", 
                "SUCCESS" if len(self.vulnerabilities) == 0 else "WARNING")
        
        return self.vulnerabilities
    
    def generate_report(self, output_format: str = 'html') -> str:
        """Generate detailed report with remediation and exploitation info"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if output_format == 'json':
            report_data = {
                "scan_info": {
                    "target": self.target_url,
                    "timestamp": timestamp,
                    "total_vulnerabilities": len(self.vulnerabilities)
                },
                "vulnerabilities": []
            }
            
            for vuln in self.vulnerabilities:
                vuln_type = vuln['type']
                if vuln_type in VULNERABILITY_DB:
                    db_entry = VULNERABILITY_DB[vuln_type]
                    report_data["vulnerabilities"].append({
                        **vuln,
                        "name": db_entry['name'],
                        "severity": db_entry['severity'],
                        "risk_score": db_entry['risk_score'],
                        "description": db_entry['description'],
                        "impact": db_entry['impact'],
                        "references": db_entry['references'],
                        "exploitation": db_entry['exploitation'],
                        "remediation": db_entry['remediation']
                    })
                else:
                    report_data["vulnerabilities"].append(vuln)
            
            return json.dumps(report_data, indent=2)
        
        elif output_format == 'html':
            html_report = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Report - {self.target_url}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        h3 {{ color: #7f8c8d; }}
        .summary {{ background: #ecf0f1; padding: 20px; border-radius: 5px; margin: 20px 0; }}
        .vuln-card {{ border-left: 4px solid #e74c3c; background: #fdf2f2; padding: 20px; margin: 20px 0; border-radius: 0 5px 5px 0; }}
        .vuln-card.HIGH {{ border-left-color: #e67e22; background: #fef5e7; }}
        .vuln-card.MEDIUM {{ border-left-color: #f39c12; background: #fef9e7; }}
        .vuln-card.LOW {{ border-left-color: #27ae60; background: #e8f8f5; }}
        .severity-badge {{ display: inline-block; padding: 5px 15px; border-radius: 20px; color: white; font-weight: bold; font-size: 12px; }}
        .CRITICAL {{ background: #c0392b; }}
        .HIGH {{ background: #e67e22; }}
        .MEDIUM {{ background: #f39c12; }}
        .LOW {{ background: #27ae60; }}
        .section {{ margin: 15px 0; }}
        .section-title {{ font-weight: bold; color: #2c3e50; margin-bottom: 10px; }}
        .code-block {{ background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 5px; overflow-x: auto; font-family: 'Courier New', monospace; font-size: 13px; }}
        .reference-link {{ display: block; color: #3498db; text-decoration: none; margin: 5px 0; }}
        .reference-link:hover {{ text-decoration: underline; }}
        .warning {{ background: #fff3cd; border: 1px solid #ffc107; padding: 15px; border-radius: 5px; margin: 15px 0; }}
        .step {{ margin: 10px 0; padding-left: 20px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #3498db; color: white; }}
        .risk-score {{ font-size: 24px; font-weight: bold; color: #e74c3c; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Vulnerability Assessment Report</h1>
        
        <div class="summary">
            <h2>📊 Scan Summary</h2>
            <table>
                <tr>
                    <th>Target URL</th>
                    <td>{self.target_url}</td>
                </tr>
                <tr>
                    <th>Scan Date</th>
                    <td>{timestamp}</td>
                </tr>
                <tr>
                    <th>Total Vulnerabilities</th>
                    <td style="font-size: 20px; font-weight: bold; color: {'#e74c3c' if len(self.vulnerabilities) > 0 else '#27ae60'}">{len(self.vulnerabilities)}</td>
                </tr>
                <tr>
                    <th>Critical</th>
                    <td>{sum(1 for v in self.vulnerabilities if VULNERABILITY_DB.get(v['type'], {}).get('severity') == 'CRITICAL')}</td>
                </tr>
                <tr>
                    <th>High</th>
                    <td>{sum(1 for v in self.vulnerabilities if VULNERABILITY_DB.get(v['type'], {}).get('severity') == 'HIGH')}</td>
                </tr>
                <tr>
                    <th>Medium</th>
                    <td>{sum(1 for v in self.vulnerabilities if VULNERABILITY_DB.get(v['type'], {}).get('severity') == 'MEDIUM')}</td>
                </tr>
            </table>
        </div>
"""
            
            if not self.vulnerabilities:
                html_report += """
        <div class="summary" style="background: #d4edda; border: 1px solid #c3e6cb;">
            <h2 style="color: #155724;">✅ No Vulnerabilities Detected</h2>
            <p style="color: #155724;">Great! No common vulnerabilities were found during this scan. However, this does not guarantee complete security. Regular testing and manual review are still recommended.</p>
        </div>
"""
            else:
                for i, vuln in enumerate(self.vulnerabilities, 1):
                    vuln_type = vuln['type']
                    db_entry = VULNERABILITY_DB.get(vuln_type, {})
                    severity = db_entry.get('severity', 'UNKNOWN')
                    risk_score = db_entry.get('risk_score', 0)
                    
                    html_report += f"""
        <div class="vuln-card {severity}">
            <h2>#{i} - {db_entry.get('name', vuln_type)}</h2>
            <span class="severity-badge {severity}">{severity}</span>
            <span class="risk-score">Risk Score: {risk_score}/10</span>
            
            <div class="section">
                <div class="section-title">📍 Location</div>
                <p><strong>Type:</strong> {vuln.get('location', 'N/A')}</p>
                {f"<p><strong>Parameter:</strong> {vuln.get('parameter', 'N/A')}</p>" if vuln.get('parameter') else ''}
                {f"<p><strong>URL:</strong> <code>{vuln.get('url', 'N/A')}</code></p>" if vuln.get('url') else ''}
                {f"<p><strong>Form Action:</strong> <code>{vuln.get('form_action', 'N/A')}</code></p>" if vuln.get('form_action') else ''}
                {f"<p><strong>File:</strong> <code>{vuln.get('file_path', 'N/A')}</code></p>" if vuln.get('file_path') else ''}
            </div>
            
            <div class="section">
                <div class="section-title">⚠️ Description</div>
                <p>{db_entry.get('description', 'No description available')}</p>
            </div>
            
            <div class="section">
                <div class="section-title">💥 Impact</div>
                <p>{db_entry.get('impact', 'Potential security impact')}</p>
            </div>
            
            <div class="section">
                <div class="section-title">🔍 Evidence</div>
                <p>{vuln.get('evidence', 'No specific evidence captured')}</p>
                {f"<p><strong>Payload Tested:</strong> <code>{html.escape(vuln.get('payload_tested', ''))}</code></p>" if vuln.get('payload_tested') else ''}
            </div>
            
            <div class="section">
                <div class="section-title">🎯 How to Exploit (For Educational Purposes Only)</div>
                <div class="warning">
                    <strong>⚠️ WARNING:</strong> This information is for educational purposes and testing your own systems only. 
                    Unauthorized exploitation is illegal and unethical.
                </div>
                <p><strong>Method:</strong> {db_entry.get('exploitation', {}).get('method', 'Manual Testing')}</p>
                <div class="section-title">Steps:</div>
                <ol>
"""
                    for step in db_entry.get('exploitation', {}).get('steps', []):
                        html_report += f"                    <li class='step'>{step}</li>\n"
                    
                    html_report += """
                </ol>
                <div class="section-title">Example Payloads:</div>
                <div class="code-block">
"""
                    for payload in db_entry.get('exploitation', {}).get('example_payloads', []):
                        html_report += f"{html.escape(payload)}\n"
                    
                    html_report += f"""
                </div>
            </div>
            
            <div class="section">
                <div class="section-title">🛡️ How to Fix (Remediation)</div>
                <p><strong>Quick Fix:</strong> {db_entry.get('remediation', {}).get('short', 'Implement proper security measures')}</p>
                <div class="section-title">Detailed Steps:</div>
                <pre>
"""
                    for line in db_entry.get('remediation', {}).get('detailed', []):
                        html_report += f"{html.escape(line)}\n"
                    
                    html_report += """
                </pre>
            </div>
"""
                    
                    # Code examples
                    code_examples = db_entry.get('remediation', {}).get('code_examples', {})
                    if code_examples:
                        html_report += """
            <div class="section">
                <div class="section-title">💻 Code Examples (Before & After)</div>
"""
                        for lang, code in code_examples.items():
                            lang_name = lang.replace('_', ' ').title()
                            html_report += f"""
                <h3>{lang_name}</h3>
                <div class="code-block">{html.escape(code.strip())}</div>
"""
                        html_report += """
            </div>
"""
                    
                    # References
                    references = db_entry.get('references', [])
                    if references:
                        html_report += """
            <div class="section">
                <div class="section-title">📚 References & Further Reading</div>
"""
                        for ref in references:
                            html_report += f'                <a href="{ref}" class="reference-link" target="_blank">🔗 {ref}</a>\n'
                        html_report += """
            </div>
"""
                    
                    html_report += """
        </div>
"""
            
            html_report += """
        <div class="summary" style="margin-top: 40px; background: #e8f4f8; border: 1px solid #bee5eb;">
            <h2>ℹ️ Disclaimer</h2>
            <p>This report was generated by an automated vulnerability scanner. While it identifies potential security issues, it may produce false positives or miss complex vulnerabilities.</p>
            <p><strong>Recommendations:</strong></p>
            <ul>
                <li>Manually verify all reported vulnerabilities</li>
                <li>Conduct regular security assessments</li>
                <li>Keep all software and dependencies up to date</li>
                <li>Implement a bug bounty program for responsible disclosure</li>
                <li>Consider hiring professional security auditors for critical systems</li>
            </ul>
            <p style="margin-top: 20px; font-style: italic; color: #7f8c8d;">
                Generated by Advanced Web Vulnerability Scanner<br>
                Use responsibly and only on systems you own or have explicit permission to test.
            </p>
        </div>
    </div>
</body>
</html>
"""
            return html_report
        
        return ""

def main():
    parser = argparse.ArgumentParser(description='Advanced Web Vulnerability Scanner')
    parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
    parser.add_argument('-o', '--output', help='Output file (report.html or report.json)')
    parser.add_argument('-f', '--format', choices=['html', 'json'], default='html', help='Report format')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        print("Error: URL must start with http:// or https://")
        return
    
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║     ADVANCED WEB VULNERABILITY SCANNER                    ║
    ║     With Exploitation & Remediation Guide                 ║
    ╠═══════════════════════════════════════════════════════════╣
    ║  ⚠️  USE ONLY ON SYSTEMS YOU OWN OR HAVE PERMISSION      ║
    ║      UNAUTHORIZED SCANNING IS ILLEGAL                     ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    scanner = VulnerabilityScanner(args.url, args.verbose)
    vulnerabilities = scanner.scan()
    
    # Generate report
    if args.output:
        report_format = args.format
        if args.output.endswith('.json'):
            report_format = 'json'
        elif args.output.endswith('.html'):
            report_format = 'html'
        
        report_content = scanner.generate_report(report_format)
        
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        print(f"\n✅ Report saved to: {args.output}")
    else:
        # Print summary to console
        print("\n" + "=" * 60)
        print("VULNERABILITY SUMMARY")
        print("=" * 60)
        
        if not vulnerabilities:
            print("✅ No vulnerabilities detected!")
        else:
            for i, vuln in enumerate(vulnerabilities, 1):
                vuln_type = vuln['type']
                db_entry = VULNERABILITY_DB.get(vuln_type, {})
                severity = db_entry.get('severity', 'UNKNOWN')
                print(f"\n{i}. {db_entry.get('name', vuln_type)} [{severity}]")
                print(f"   Location: {vuln.get('location', 'N/A')}")
                if vuln.get('parameter'):
                    print(f"   Parameter: {vuln.get('parameter')}")
                print(f"   Risk Score: {db_entry.get('risk_score', 0)}/10")
                print(f"   Quick Fix: {db_entry.get('remediation', {}).get('short', 'N/A')}")
        
        print("\n💡 Tip: Use -o report.html to generate detailed report with exploitation and remediation guides")

if __name__ == "__main__":
    main()
