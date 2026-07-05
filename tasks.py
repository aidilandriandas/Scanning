from celery_config import celery_app
from scanner import VulnerabilityScanner
from models import ScanJob, db
import config
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@celery_app.task(bind=True, max_retries=0)
def run_scan_task(self, target_url, user_id, scan_mode='safe'):
    """
    Celery task to run vulnerability scan in background
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
            started_at=datetime.utcnow()
        )
        db.session.add(scan_job)
        db.session.commit()
        
        # Initialize scanner
        scanner = VulnerabilityScanner(target_url, safe_mode=(scan_mode == 'safe'))
        
        # Run scan with progress updates
        results = scanner.run_scan(progress_callback=lambda progress: update_progress(job_id, progress))
        
        # Calculate CVSS scores
        if config.CVSS_ENABLED:
            results = calculate_cvss_scores(results)
        
        # Update job status
        scan_job.status = 'COMPLETED'
        scan_job.completed_at = datetime.utcnow()
        scan_job.results = results
        scan_job.vulnerability_count = len(results.get('vulnerabilities', []))
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


def update_progress(job_id, progress_data):
    """Update scan progress in database"""
    scan_job = ScanJob.query.get(job_id)
    if scan_job:
        scan_job.progress = progress_data.get('percentage', 0)
        scan_job.current_activity = progress_data.get('activity', '')
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
    
    return results
