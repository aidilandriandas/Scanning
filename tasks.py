from celery_config import celery_app
from scanner import VulnerabilityScanner
from models import ScanJob, db
from modules.external_scanners import get_plugin_manager
import config
import logging
import os
import tempfile
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@celery_app.task(bind=True, max_retries=0)
def run_scan_task(self, target_url, user_id, scan_mode='safe', use_external_scanners=False):
    """
    Celery task to run vulnerability scan in background
    Supports both internal and external scanners with real-time progress
    """
    job_id = self.request.id
    
    try:
        # Create database record
        scan_job = ScanJob(
            id=job_id,
            target_url=target_url,
            user_id=user_id,
            scan_mode=scan_mode,
            status='RUNNING',
            started_at=datetime.utcnow(),
            external_scanners_used=[] if use_external_scanners else None
        )
        db.session.add(scan_job)
        db.session.commit()
        
        # Initialize scanner
        scanner = VulnerabilityScanner(target_url, safe_mode=(scan_mode == 'safe'))
        
        # Run internal scan with progress updates
        def internal_progress(progress_data):
            update_progress(job_id, progress_data)
            add_realtime_log(job_id, progress_data)
        
        results = scanner.run_scan(progress_callback=internal_progress)
        
        # Run external scanners if enabled
        if use_external_scanners:
            external_results = run_external_scanners(
                job_id, target_url, 
                progress_callback=lambda data: add_realtime_log(job_id, data)
            )
            
            # Merge external findings into results
            if 'external_findings' not in results:
                results['external_findings'] = []
            results['external_findings'].extend(external_results.get('findings', []))
            results['external_scanners'] = external_results.get('scanners_used', [])
            
            # Update total vulnerability count
            total_vulns = len(results.get('vulnerabilities', [])) + len(results.get('external_findings', []))
            results['total_findings'] = total_vulns
        
        # Calculate CVSS scores
        if config.CVSS_ENABLED:
            results = calculate_cvss_scores(results)
        
        # Update job status
        scan_job.status = 'COMPLETED'
        scan_job.completed_at = datetime.utcnow()
        scan_job.results = results
        scan_job.vulnerability_count = len(results.get('vulnerabilities', [])) + len(results.get('external_findings', []))
        scan_job.risk_score = results.get('overall_risk_score', 0)
        
        db.session.commit()
        
        logger.info(f"Scan completed for {target_url} - Job ID: {job_id}")
        return {
            'status': 'success',
            'job_id': job_id,
            'results': results
        }
        
    except Exception as e:
        logger.error(f"Scan failed for {target_url}: {str(e)}")
        
        # Update job status to failed
        scan_job = ScanJob.query.get(job_id)
        if scan_job:
            scan_job.status = 'FAILED'
            scan_job.error_message = str(e)
            scan_job.completed_at = datetime.utcnow()
            db.session.commit()
        
        return {
            'status': 'failed',
            'job_id': job_id,
            'error': str(e)
        }


def run_external_scanners(job_id, target_url, progress_callback=None):
    """Run external scanners (Nuclei, Nikto) on target"""
    output_dir = tempfile.mkdtemp(prefix='scanner_')
    
    try:
        plugin_manager = get_plugin_manager()
        
        def wrapped_progress(data):
            data['timestamp'] = datetime.now().isoformat()
            if progress_callback:
                progress_callback(data)
            # Also update job progress
            update_progress(job_id, {
                'percentage': data.get('percentage', 50),
                'activity': f"[{data.get('scanner', 'External')}] {data.get('activity', 'Scanning...')}"
            })
        
        results = plugin_manager.run_all_scanners(
            target_url=target_url,
            output_dir=output_dir,
            progress_callback=wrapped_progress
        )
        
        # Update job with scanners used
        scan_job = ScanJob.query.get(job_id)
        if scan_job:
            scan_job.external_scanners_used = results.get('scanners_used', [])
            db.session.commit()
        
        return results
    
    finally:
        # Cleanup temp directory
        import shutil
        try:
            shutil.rmtree(output_dir)
        except:
            pass


def update_progress(job_id, progress_data):
    """Update scan progress in database"""
    scan_job = ScanJob.query.get(job_id)
    if scan_job:
        scan_job.progress = progress_data.get('percentage', 0)
        scan_job.current_activity = progress_data.get('activity', '')
        db.session.commit()


def add_realtime_log(job_id, log_entry):
    """Add entry to realtime log"""
    scan_job = ScanJob.query.get(job_id)
    if scan_job:
        if not scan_job.realtime_log:
            scan_job.realtime_log = []
        
        # Add timestamp if not present
        if 'timestamp' not in log_entry:
            log_entry['timestamp'] = datetime.now().isoformat()
        
        # Append to log (keep last 100 entries to avoid bloat)
        scan_job.realtime_log.append(log_entry)
        if len(scan_job.realtime_log) > 100:
            scan_job.realtime_log = scan_job.realtime_log[-100:]
        
        db.session.commit()


def calculate_cvss_scores(results):
    """
    Calculate CVSS scores for found vulnerabilities
    This is a simplified implementation - in production, use proper CVSS calculator
    """
    for vuln in results.get('vulnerabilities', []):
        base_score = vuln.get('risk_score', 5.0)
        
        # Adjust based on severity
        if base_score >= 9.0:
            vuln['cvss_severity'] = 'CRITICAL'
        elif base_score >= 7.0:
            vuln['cvss_severity'] = 'HIGH'
        elif base_score >= 4.0:
            vuln['cvss_severity'] = 'MEDIUM'
        else:
            vuln['cvss_severity'] = 'LOW'
            
        vuln['cvss_score'] = min(10.0, base_score)
    
    # Also calculate for external findings
    for vuln in results.get('external_findings', []):
        if 'cvss' in vuln:
            cvss = vuln['cvss']
            if cvss >= 9.0:
                vuln['cvss_severity'] = 'CRITICAL'
            elif cvss >= 7.0:
                vuln['cvss_severity'] = 'HIGH'
            elif cvss >= 4.0:
                vuln['cvss_severity'] = 'MEDIUM'
            else:
                vuln['cvss_severity'] = 'LOW'
    
    return results
