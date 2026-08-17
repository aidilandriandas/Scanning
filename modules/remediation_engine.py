"""
Auto-Remediation Engine Module
Generates patches, fixes configurations, and provides actionable remediation steps.
Supports: Code Patching, Config Hardening, Dependency Updates, and Safe Mode (Dry Run).
"""

import os
import re
import json
import shutil
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path

class RemediationEngine:
    def __init__(self, dry_run: bool = True):
        """
        Initialize the engine.
        :param dry_run: If True, only simulates changes without writing files.
        """
        self.dry_run = dry_run
        self.logs = []
        self.backup_dir = "remediation_backups"
        
    def _log(self, message: str, level: str = "INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"
        self.logs.append(log_entry)
        if not self.dry_run:
            print(log_entry)
        else:
            print(f"[DRY RUN] {message}")

    def create_backup(self, file_path: str) -> Optional[str]:
        """Create a backup of the file before modifying."""
        if not os.path.exists(file_path):
            return None
        
        if not os.path.exists(self.backup_dir):
            if not self.dry_run:
                os.makedirs(self.backup_dir)
            else:
                self._log(f"Would create backup directory: {self.backup_dir}")
                return None

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.basename(file_path)
        backup_path = os.path.join(self.backup_dir, f"{filename}.{timestamp}.bak")

        if not self.dry_run:
            shutil.copy2(file_path, backup_path)
            self._log(f"Backup created: {backup_path}")
            return backup_path
        else:
            self._log(f"Would backup {file_path} to {backup_path}")
            return None

    def fix_sql_injection(self, code_content: str, language: str = "python") -> Tuple[str, List[str]]:
        """
        Attempts to fix basic SQL Injection patterns by suggesting parameterized queries.
        Returns fixed code and list of changes made.
        """
        changes = []
        fixed_code = code_content

        if language == "python":
            # Pattern for string formatting in SQL (e.g., f"SELECT * FROM users WHERE id = {user_id}")
            patterns = [
                (r'execute\s*\(\s*f["\'].*?WHERE.*?=.*?\{.*?\}.*?["\']', "Parameterized Query"),
                (r'cursor\.execute\s*\(\s*["\']SELECT.*?\+.*?["\']', "String Concatenation in SQL"),
            ]
            
            # Simple heuristic replacement examples (Real-world needs AST parsing)
            # Example: cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
            # This is a simplified regex demo. Production should use `sqlparse` or AST.
            if "cursor.execute(f\"" in code_content or "cursor.execute('" in code_content and "+" in code_content:
                changes.append("Detected potential string formatting in SQL. Recommend using parameterized queries.")
                # Mocking a fix structure for demonstration
                fixed_code = code_content.replace(
                    'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
                    'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'
                )
                if fixed_code != code_content:
                    changes.append("Replaced f-string with parameterized query placeholder.")

        elif language == "php":
            if "mysqli_query" in code_content and ("$_GET" in code_content or "$_" in code_content):
                changes.append("Detected direct variable interpolation in SQL. Recommend prepared statements.")
        
        return fixed_code, changes

    def fix_xss(self, code_content: str, framework: str = "generic") -> Tuple[str, List[str]]:
        """
        Suggests escaping output to prevent XSS.
        """
        changes = []
        fixed_code = code_content

        if framework == "django":
            # Django templates auto-escape by default, but if |safe is used incorrectly
            if "|safe" in code_content:
                changes.append("Review usage of '|safe' filter. Ensure content is trusted.")
        
        elif framework == "react":
            if "dangerouslySetInnerHTML" in code_content:
                changes.append("CRITICAL: 'dangerouslySetInnerHTML' detected. Replace with standard JSX interpolation if possible.")
                fixed_code = code_content.replace(
                    "dangerouslySetInnerHTML={{__html: content}}",
                    "{content} /* Replaced dangerouslySetInnerHTML */"
                )
                if fixed_code != code_content:
                    changes.append("Removed dangerouslySetInnerHTML (Manual review required).")

        elif framework == "generic":
            # Generic HTML escape suggestion
            if re.search(r'innerHTML\s*=', code_content):
                changes.append("Use textContent instead of innerHTML to prevent XSS.")
        
        return fixed_code, changes

    def generate_security_headers_config(self, server_type: str = "nginx") -> str:
        """
        Generates secure configuration snippets for web servers.
        """
        headers = {
            "nginx": """
# Security Headers Configuration for Nginx
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
""",
            "apache": """
# Security Headers Configuration for Apache (.htaccess)
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-Content-Type-Options "nosniff"
Header always set X-XSS-Protection "1; mode=block"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline';"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
""",
            "express": """
// Security Headers for Node.js Express (using helmet)
const helmet = require('helmet');
app.use(helmet());
// Specific CSP configuration
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'"],
  },
}));
"""
        }
        return headers.get(server_type, "# Server type not supported")

    def fix_dependency(self, package_manager: str, vulnerable_package: str, safe_version: str) -> str:
        """
        Generates the command to update a vulnerable dependency.
        """
        commands = {
            "pip": f"pip install {vulnerable_package}=={safe_version}",
            "npm": f"npm install {vulnerable_package}@{safe_version}",
            "yarn": f"yarn add {vulnerable_package}@{safe_version}",
            "composer": f"composer require {vulnerable_package}:{safe_version}",
            "maven": f"Update version in pom.xml to {safe_version}"
        }
        return commands.get(package_manager, f"Manually update {vulnerable_package} to {safe_version}")

    def apply_remediation(self, vulnerability_report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main entry point to process a vulnerability report and generate fixes.
        """
        results = {
            "fixed_files": [],
            "generated_configs": [],
            "commands": [],
            "manual_steps": [],
            "status": "success"
        }

        vuln_type = vulnerability_report.get("type", "").upper()
        target = vulnerability_report.get("target", "")
        details = vulnerability_report.get("details", {})

        self._log(f"Processing remediation for {vuln_type} at {target}")

        try:
            # 1. Code Patching
            if vuln_type in ["SQL_INJECTION", "XSS", "COMMAND_INJECTION"]:
                if os.path.exists(target):
                    self.create_backup(target)
                    with open(target, 'r') as f:
                        content = f.read()
                    
                    new_content = content
                    changes = []
                    
                    if vuln_type == "SQL_INJECTION":
                        lang = "python" if target.endswith(".py") else "php" if target.endswith(".php") else "generic"
                        new_content, changes = self.fix_sql_injection(content, lang)
                    
                    elif vuln_type == "XSS":
                        fw = "react" if "jsx" in target or "react" in content.lower() else "django" if "template" in target else "generic"
                        new_content, changes = self.fix_xss(content, fw)

                    if new_content != content:
                        if not self.dry_run:
                            with open(target, 'w') as f:
                                f.write(new_content)
                            self._log(f"Applied patch to {target}")
                            results["fixed_files"].append({"file": target, "changes": changes})
                        else:
                            self._log(f"Would apply patch to {target}: {changes}")
                            results["fixed_files"].append({"file": target, "changes": changes, "applied": False})
                    else:
                        results["manual_steps"].append(f"Review {target} for {vuln_type}. Automated fix pattern not matched.")
                else:
                    results["manual_steps"].append(f"File {target} not found. Cannot apply code patch.")

            # 2. Configuration Hardening
            elif vuln_type == "MISSING_SECURITY_HEADERS":
                server = details.get("server", "nginx")
                config_content = self.generate_security_headers_config(server)
                config_filename = f"security_headers_{server}.conf"
                
                if not self.dry_run:
                    with open(config_filename, 'w') as f:
                        f.write(config_content)
                    self._log(f"Generated config file: {config_filename}")
                    results["generated_configs"].append(config_filename)
                else:
                    self._log(f"Would generate config file: {config_filename}")
                    results["generated_configs"].append({"filename": config_filename, "content": config_content, "applied": False})

            # 3. Dependency Updates
            elif vuln_type == "VULNERABLE_DEPENDENCY":
                pkg_mgr = details.get("package_manager", "pip")
                pkg_name = details.get("package", "unknown")
                safe_ver = details.get("safe_version", "latest")
                
                cmd = self.fix_dependency(pkg_mgr, pkg_name, safe_ver)
                self._log(f"Generated dependency fix command: {cmd}")
                results["commands"].append(cmd)

            else:
                results["manual_steps"].append(f"No automated fix available for {vuln_type}. Manual review required.")

        except Exception as e:
            self._log(f"Error during remediation: {str(e)}", "ERROR")
            results["status"] = "failed"
            results["error"] = str(e)

        return results

def auto_fix(vulnerability: Dict[str, Any], dry_run: bool = True) -> Dict[str, Any]:
    """
    Convenience function to run remediation on a single vulnerability.
    :param vulnerability: Dict containing 'type', 'target', and 'details'.
    :param dry_run: If True, simulate changes only.
    """
    engine = RemediationEngine(dry_run=dry_run)
    return engine.apply_remediation(vulnerability)

if __name__ == "__main__":
    # Demo Usage
    print("=== Auto-Remediation Engine Demo ===")
    
    # Case 1: Missing Headers
    vuln_headers = {
        "type": "MISSING_SECURITY_HEADERS",
        "target": "nginx",
        "details": {"server": "nginx"}
    }
    res1 = auto_fix(vuln_headers, dry_run=True)
    print(f"Headers Result: {json.dumps(res1, indent=2)}")

    # Case 2: Vulnerable Dependency
    vuln_dep = {
        "type": "VULNERABLE_DEPENDENCY",
        "target": "requirements.txt",
        "details": {"package_manager": "pip", "package": "requests", "safe_version": "2.31.0"}
    }
    res2 = auto_fix(vuln_dep, dry_run=True)
    print(f"Dependency Result: {json.dumps(res2, indent=2)}")
