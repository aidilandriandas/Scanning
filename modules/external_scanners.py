"""
External Scanner Plugins Module
Supports: Nuclei, Nikto, and custom scanner plugins
Real-time progress tracking with WebSocket support
"""

import subprocess
import json
import os
import tempfile
import shutil
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
import threading
import queue


class ExternalScannerPlugin:
    """Base class for external scanner plugins"""
    
    def __init__(self, name: str, command: str, output_format: str = 'json'):
        self.name = name
        self.command = command
        self.output_format = output_format
        self.is_available = self._check_availability()
        
    def _check_availability(self) -> bool:
        """Check if the scanner tool is installed"""
        try:
            result = subprocess.run(
                [self.command, '-version' if self.command != 'nikto' else '-Version'],
                capture_output=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False
    
    def scan(self, target_url: str, output_dir: str, 
             progress_callback: Optional[Callable] = None) -> Dict[str, Any]:
        """
        Run external scanner on target
        Returns scan results in standardized format
        """
        if not self.is_available:
            return {
                'error': f"{self.name} is not installed",
                'scanner': self.name,
                'target': target_url,
                'status': 'unavailable'
            }
        
        try:
            return self._execute_scan(target_url, output_dir, progress_callback)
        except Exception as e:
            return {
                'error': str(e),
                'scanner': self.name,
                'target': target_url,
                'status': 'failed'
            }
    
    def _execute_scan(self, target_url: str, output_dir: str,
                      progress_callback: Optional[Callable] = None) -> Dict[str, Any]:
        """Execute the scan - to be implemented by subclasses"""
        raise NotImplementedError


class NucleiPlugin(ExternalScannerPlugin):
    """Nuclei vulnerability scanner plugin"""
    
    def __init__(self):
        super().__init__(
            name='Nuclei',
            command='nuclei',
            output_format='json'
        )
        self.templates = []
        self.severity_filter = []
    
    def set_templates(self, templates: List[str]):
        """Set specific nuclei templates to use"""
        self.templates = templates
    
    def set_severity_filter(self, severities: List[str]):
        """Filter by severity (critical, high, medium, low, info)"""
        self.severity_filter = severities
    
    def _execute_scan(self, target_url: str, output_dir: str,
                      progress_callback: Optional[Callable] = None) -> Dict[str, Any]:
        """Execute Nuclei scan"""
        start_time = datetime.now()
        
        # Build command
        cmd = [
            'nuclei',
            '-target', target_url,
            '-json-export', os.path.join(output_dir, 'nuclei_results.json'),
            '-silent'
        ]
        
        # Add template filter if specified
        if self.templates:
            for template in self.templates:
                cmd.extend(['-t', template])
        
        # Add severity filter if specified
        if self.severity_filter:
            cmd.extend(['-severity', ','.join(self.severity_filter)])
        
        # Execute scan
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Monitor progress
        output_lines = []
        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
            if line:
                output_lines.append(line.strip())
                # Send progress update
                if progress_callback:
                    progress_callback({
                        'scanner': 'Nuclei',
                        'activity': line.strip(),
                        'percentage': min(95, len(output_lines) * 2),  # Rough estimate
                        'timestamp': datetime.now().isoformat()
                    })
        
        # Get return code
        return_code = process.wait(timeout=300)
        end_time = datetime.now()
        
        # Parse results
        results_file = os.path.join(output_dir, 'nuclei_results.json')
        findings = []
        
        if os.path.exists(results_file):
            with open(results_file, 'r') as f:
                for line in f:
                    try:
                        finding = json.loads(line.strip())
                        findings.append(self._normalize_finding(finding))
                    except json.JSONDecodeError:
                        continue
        
        duration = (end_time - start_time).total_seconds()
        
        return {
            'scanner': 'Nuclei',
            'target': target_url,
            'status': 'completed' if return_code == 0 else 'failed',
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'duration_seconds': duration,
            'findings_count': len(findings),
            'findings': findings,
            'raw_output': '\n'.join(output_lines)
        }
    
    def _normalize_finding(self, finding: Dict) -> Dict:
        """Normalize Nuclei finding to standard format"""
        return {
            'type': finding.get('info', {}).get('name', 'Unknown'),
            'url': finding.get('host', '') + finding.get('matched-at', ''),
            'parameter': finding.get('extracted-results', ['N/A'])[0] if finding.get('extracted-results') else 'N/A',
            'details': finding.get('info', {}).get('description', ''),
            'severity': finding.get('info', {}).get('severity', 'INFO').upper(),
            'cvss': self._severity_to_cvss(finding.get('info', {}).get('severity', 'info')),
            'scanner': 'Nuclei',
            'template_id': finding.get('template-id', ''),
            'tags': finding.get('info', {}).get('tags', []),
            'reference': finding.get('info', {}).get('reference', [])
        }
    
    def _severity_to_cvss(self, severity: str) -> float:
        """Convert severity string to CVSS score"""
        mapping = {
            'critical': 9.8,
            'high': 7.5,
            'medium': 5.0,
            'low': 3.0,
            'info': 1.0
        }
        return mapping.get(severity.lower(), 5.0)


class NiktoPlugin(ExternalScannerPlugin):
    """Nikto web scanner plugin"""
    
    def __init__(self):
        super().__init__(
            name='Nikto',
            command='nikto',
            output_format='json'
        )
        self.tuning = ''
        self.plugins = []
    
    def set_tuning(self, tuning: str):
        """Set Nikto tuning options (e.g., '123456789abc')"""
        self.tuning = tuning
    
    def set_plugins(self, plugins: List[str]):
        """Set specific Nikto plugins to use"""
        self.plugins = plugins
    
    def _execute_scan(self, target_url: str, output_dir: str,
                      progress_callback: Optional[Callable] = None) -> Dict[str, Any]:
        """Execute Nikto scan"""
        start_time = datetime.now()
        
        # Build command
        cmd = [
            'nikto',
            '-host', target_url,
            '-Format', 'json',
            '-output', os.path.join(output_dir, 'nikto_results.json'),
            '-no404'
        ]
        
        # Add tuning if specified
        if self.tuning:
            cmd.extend(['-Tuning', self.tuning])
        
        # Add plugins if specified
        if self.plugins:
            for plugin in self.plugins:
                cmd.extend(['-Plugins', plugin])
        
        # Execute scan
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        
        # Monitor progress
        output_lines = []
        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
            if line:
                output_lines.append(line.strip())
                # Send progress update
                if progress_callback:
                    progress_callback({
                        'scanner': 'Nikto',
                        'activity': line.strip(),
                        'percentage': min(95, len(output_lines)),
                        'timestamp': datetime.now().isoformat()
                    })
        
        # Get return code
        return_code = process.wait(timeout=600)
        end_time = datetime.now()
        
        # Parse results
        results_file = os.path.join(output_dir, 'nikto_results.json')
        findings = []
        
        if os.path.exists(results_file):
            try:
                with open(results_file, 'r') as f:
                    data = json.load(f)
                    vulnerabilities = data.get('vulnerabilities', [])
                    for vuln in vulnerabilities:
                        findings.append(self._normalize_finding(vuln))
            except (json.JSONDecodeError, IOError):
                pass
        
        duration = (end_time - start_time).total_seconds()
        
        return {
            'scanner': 'Nikto',
            'target': target_url,
            'status': 'completed' if return_code == 0 else 'failed',
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'duration_seconds': duration,
            'findings_count': len(findings),
            'findings': findings,
            'raw_output': '\n'.join(output_lines)
        }
    
    def _normalize_finding(self, finding: Dict) -> Dict:
        """Normalize Nikto finding to standard format"""
        return {
            'type': finding.get('id', 'Unknown'),
            'url': finding.get('host', '') + finding.get('uri', ''),
            'parameter': 'N/A',
            'details': finding.get('method', '') + ': ' + finding.get('evidence', ''),
            'severity': self._estimate_severity(finding.get('id', '')),
            'cvss': self._estimate_cvss(finding.get('id', '')),
            'scanner': 'Nikto',
            'osvdb_id': finding.get('osvdbid', ''),
            'reference': [finding.get('references', '')] if finding.get('references') else []
        }
    
    def _estimate_severity(self, nikto_id: str) -> str:
        """Estimate severity from Nikto ID"""
        critical_ids = ['000001', '000002']  # Example critical IDs
        high_ids = ['000101', '000102']  # Example high IDs
        
        if any(nikto_id.startswith(cid) for cid in critical_ids):
            return 'CRITICAL'
        elif any(nikto_id.startswith(hid) for hid in high_ids):
            return 'HIGH'
        elif 'ssl' in nikto_id.lower() or 'password' in nikto_id.lower():
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _estimate_cvss(self, nikto_id: str) -> float:
        """Estimate CVSS from Nikto ID"""
        severity = self._estimate_severity(nikto_id)
        mapping = {
            'CRITICAL': 9.0,
            'HIGH': 7.5,
            'MEDIUM': 5.0,
            'LOW': 3.0
        }
        return mapping.get(severity, 5.0)


class PluginManager:
    """Manages external scanner plugins"""
    
    def __init__(self):
        self.plugins: Dict[str, ExternalScannerPlugin] = {}
        self.register_default_plugins()
    
    def register_default_plugins(self):
        """Register default scanner plugins"""
        self.register_plugin(NucleiPlugin())
        self.register_plugin(NiktoPlugin())
    
    def register_plugin(self, plugin: ExternalScannerPlugin):
        """Register a scanner plugin"""
        self.plugins[plugin.name] = plugin
    
    def get_plugin(self, name: str) -> Optional[ExternalScannerPlugin]:
        """Get a registered plugin by name"""
        return self.plugins.get(name)
    
    def get_available_plugins(self) -> List[str]:
        """Get list of available plugins"""
        return [name for name, plugin in self.plugins.items() if plugin.is_available]
    
    def run_all_scanners(self, target_url: str, output_dir: str,
                         progress_callback: Optional[Callable] = None) -> Dict[str, Any]:
        """Run all available scanners on target"""
        start_time = datetime.now()
        all_results = {}
        
        for name, plugin in self.plugins.items():
            if plugin.is_available:
                print(f"Running {name} scanner...")
                
                def wrapped_progress(data):
                    data['plugin'] = name
                    if progress_callback:
                        progress_callback(data)
                
                results = plugin.scan(target_url, output_dir, wrapped_progress)
                all_results[name] = results
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # Aggregate findings
        all_findings = []
        for name, results in all_results.items():
            if 'findings' in results:
                all_findings.extend(results['findings'])
        
        return {
            'status': 'completed',
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'duration_seconds': duration,
            'scanners_used': list(all_results.keys()),
            'total_findings': len(all_findings),
            'findings': all_findings,
            'individual_results': all_results
        }


# Singleton instance
plugin_manager = PluginManager()


def get_plugin_manager() -> PluginManager:
    """Get the plugin manager singleton"""
    return plugin_manager
