from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json

db = SQLAlchemy()


class User(db.Model):
    """User model for authentication and authorization"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    telegram_id = db.Column(db.String(50), unique=True, nullable=False)
    username = db.Column(db.String(100))
    is_whitelisted = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    scans = db.relationship('ScanJob', backref='user', lazy=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'telegram_id': self.telegram_id,
            'username': self.username,
            'is_whitelisted': self.is_whitelisted,
            'created_at': self.created_at.isoformat()
        }


class ScanJob(db.Model):
    """Scan job model to track scan progress and results"""
    __tablename__ = 'scan_jobs'
    
    id = db.Column(db.String(100), primary_key=True)  # Celery task ID
    target_url = db.Column(db.String(500), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    scan_mode = db.Column(db.String(20), default='safe')  # 'safe' or 'deep'
    
    status = db.Column(db.String(20), default='PENDING')  # PENDING, RUNNING, COMPLETED, FAILED
    progress = db.Column(db.Integer, default=0)  # 0-100
    current_activity = db.Column(db.String(200))
    
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    
    results = db.Column(db.JSON)  # Store full scan results
    vulnerability_count = db.Column(db.Integer, default=0)
    risk_score = db.Column(db.Float, default=0.0)
    error_message = db.Column(db.Text)
    
    def to_dict(self):
        return {
            'id': self.id,
            'target_url': self.target_url,
            'user_id': self.user_id,
            'scan_mode': self.scan_mode,
            'status': self.status,
            'progress': self.progress,
            'current_activity': self.current_activity,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'vulnerability_count': self.vulnerability_count,
            'risk_score': self.risk_score,
            'error_message': self.error_message,
            'summary': self.get_summary()
        }
    
    def get_summary(self):
        """Get a summary of vulnerabilities found"""
        if not self.results or 'vulnerabilities' not in self.results:
            return []
        
        summary = []
        for vuln in self.results['vulnerabilities']:
            summary.append({
                'name': vuln.get('name', 'Unknown'),
                'severity': vuln.get('cvss_severity', 'MEDIUM'),
                'cvss_score': vuln.get('cvss_score', 5.0),
                'url': vuln.get('url', ''),
                'parameter': vuln.get('parameter', '')
            })
        return summary


class AuditLog(db.Model):
    """Audit log for tracking all actions"""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    action = db.Column(db.String(100), nullable=False)
    target = db.Column(db.String(500))
    details = db.Column(db.JSON)
    ip_address = db.Column(db.String(45))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'action': self.action,
            'target': self.target,
            'details': self.details,
            'ip_address': self.ip_address,
            'timestamp': self.timestamp.isoformat()
        }


def init_db(app):
    """Initialize database with app context"""
    db.init_app(app)
    with app.app_context():
        db.create_all()
