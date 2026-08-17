from flask import Flask, render_template, jsonify, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, emit
from models import db, User, ScanJob, AuditLog, init_db
from tasks import run_scan_task
import config
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=getattr(logging, config.LOG_LEVEL))
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = config.SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = config.DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class TelegramUser(UserMixin):
    """User class for Flask-Login"""
    def __init__(self, telegram_id, username, is_whitelisted=False):
        self.id = telegram_id
        self.username = username
        self.is_whitelisted = is_whitelisted
    
    @staticmethod
    def get_from_db(telegram_id):
        user_record = User.query.filter_by(telegram_id=str(telegram_id)).first()
        if user_record:
            return TelegramUser(
                telegram_id=user_record.telegram_id,
                username=user_record.username,
                is_whitelisted=user_record.is_whitelisted
            )
        return None


@login_manager.user_loader
def load_user(user_id):
    return TelegramUser.get_from_db(user_id)


@app.route('/')
@login_required
def dashboard():
    """Main dashboard page"""
    # Get recent scans for current user
    user = User.query.filter_by(telegram_id=str(current_user.id)).first()
    if user:
        recent_scans = ScanJob.query.filter_by(user_id=user.id)\
            .order_by(ScanJob.started_at.desc()).limit(10).all()
    else:
        recent_scans = []
    
    return render_template('dashboard.html', 
                         recent_scans=recent_scans, 
                         user=current_user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page - typically accessed via Telegram auth"""
    if request.method == 'POST':
        telegram_id = request.form.get('telegram_id')
        username = request.form.get('username', f'user_{telegram_id}')
        
        # Check if user is in allowed list from config
        is_allowed = str(telegram_id) in config.ALLOWED_USERS or '' in config.ALLOWED_USERS
        
        if config.WHITELIST_ONLY and not is_allowed:
            return render_template('login.html', error='You are not authorized to use this system')
        
        # Check if user exists in DB
        user_record = User.query.filter_by(telegram_id=str(telegram_id)).first()
        
        if not user_record:
            # Create new user with whitelisted status based on config check
            user_record = User(
                telegram_id=str(telegram_id),
                username=username,
                is_whitelisted=is_allowed
            )
            db.session.add(user_record)
            db.session.commit()
            
            # Log action
            audit_log = AuditLog(
                user_id=user_record.id,
                action='USER_REGISTERED',
                details={'username': username}
            )
            db.session.add(audit_log)
            db.session.commit()
        else:
            # Update whitelist status if config changed
            if user_record.is_whitelisted != is_allowed:
                user_record.is_whitelisted = is_allowed
                db.session.commit()
        
        user = TelegramUser(
            telegram_id=user_record.telegram_id,
            username=user_record.username,
            is_whitelisted=user_record.is_whitelisted
        )
        login_user(user)
        
        # Log login
        audit_log = AuditLog(
            user_id=user_record.id,
            action='USER_LOGIN',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)
        db.session.commit()
        
        return redirect(url_for('dashboard'))
    
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/api/scan/start', methods=['POST'])
@login_required
def start_scan():
    """Start a new scan job"""
    data = request.get_json()
    target_url = data.get('url')
    scan_mode = data.get('mode', 'safe')
    use_external = data.get('use_external_scanners', False)
    
    if not target_url:
        return jsonify({'error': 'Target URL is required'}), 400
    
    # Validate URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    # Get user from DB
    user_record = User.query.filter_by(telegram_id=str(current_user.id)).first()
    if not user_record:
        return jsonify({'error': 'User not found'}), 404
    
    # Log action
    audit_log = AuditLog(
        user_id=user_record.id,
        action='SCAN_STARTED',
        target=target_url,
        details={'mode': scan_mode, 'use_external_scanners': use_external},
        ip_address=request.remote_addr
    )
    db.session.add(audit_log)
    db.session.commit()
    
    # Start Celery task
    task = run_scan_task.delay(target_url, user_record.id, scan_mode, use_external)
    
    return jsonify({
        'job_id': task.id,
        'status': 'started',
        'message': f'Scan started for {target_url}',
        'external_scanners': use_external
    })


@app.route('/api/scan/status/<job_id>')
@login_required
def scan_status(job_id):
    """Get scan job status"""
    job = ScanJob.query.get(job_id)
    
    if not job:
        return jsonify({'error': 'Job not found'}), 404
    
    # Verify ownership
    user_record = User.query.filter_by(telegram_id=str(current_user.id)).first()
    if job.user_id != user_record.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    return jsonify(job.to_dict())


@app.route('/api/scan/results/<job_id>')
@login_required
def scan_results(job_id):
    """Get full scan results"""
    job = ScanJob.query.get(job_id)
    
    if not job:
        return jsonify({'error': 'Job not found'}), 404
    
    # Verify ownership
    user_record = User.query.filter_by(telegram_id=str(current_user.id)).first()
    if job.user_id != user_record.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    if job.status != 'COMPLETED':
        return jsonify({'error': 'Scan not completed yet'}), 400
    
    return jsonify(job.results)


@app.route('/api/scans')
@login_required
def list_scans():
    """List all scans for current user"""
    user_record = User.query.filter_by(telegram_id=str(current_user.id)).first()
    if not user_record:
        return jsonify([])
    
    scans = ScanJob.query.filter_by(user_id=user_record.id)\
        .order_by(ScanJob.started_at.desc()).limit(50).all()
    
    return jsonify([scan.to_dict() for scan in scans])


@socketio.on('connect')
def handle_connect():
    logger.info('Client connected to WebSocket')


@socketio.on('disconnect')
def handle_disconnect():
    logger.info('Client disconnected from WebSocket')


@socketio.on('subscribe_scan')
def handle_subscribe_scan(data):
    """Subscribe to real-time scan progress updates"""
    job_id = data.get('job_id')
    if job_id:
        # Join room for this scan job
        from flask_socketio import join_room
        join_room(f'scan_{job_id}')
        emit('subscribed', {'job_id': job_id})
        logger.info(f'Client subscribed to scan {job_id}')


@socketio.on('unsubscribe_scan')
def handle_unsubscribe_scan(data):
    """Unsubscribe from scan progress updates"""
    job_id = data.get('job_id')
    if job_id:
        from flask_socketio import leave_room
        leave_room(f'scan_{job_id}')
        emit('unsubscribed', {'job_id': job_id})


@app.route('/api/report/<job_id>', methods=['GET'])
@login_required
def generate_report(job_id):
    """Generate PDF/HTML report for a completed scan"""
    from modules.reports.generator import ReportGenerator
    
    job = ScanJob.query.get(job_id)
    if not job:
        return jsonify({'error': 'Scan job not found'}), 404
    
    report_type = request.args.get('type', 'full')
    format_type = request.args.get('format', 'html')  # html or pdf
    
    try:
        generator = ReportGenerator(job)
        
        if format_type == 'pdf':
            output_path = f'/tmp/report_{job_id}.pdf'
            generator.generate_pdf_report(output_path, report_type)
            return jsonify({
                'success': True,
                'message': 'PDF report generated',
                'download_url': f'/static/reports/report_{job_id}.pdf'
            })
        else:
            output_path = f'/workspace/static/reports/report_{job_id}.html'
            generator.generate_html_report(output_path, report_type)
            return jsonify({
                'success': True,
                'message': 'HTML report generated',
                'view_url': f'/static/reports/report_{job_id}.html'
            })
    except Exception as e:
        logger.error(f'Error generating report: {str(e)}')
        return jsonify({'error': str(e)}), 500


@app.route('/api/mark-false-positive', methods=['POST'])
@login_required
def mark_false_positive():
    """Mark a vulnerability as false positive"""
    data = request.json
    job_id = data.get('job_id')
    vuln_index = data.get('vuln_index')
    
    job = ScanJob.query.get(job_id)
    if not job:
        return jsonify({'error': 'Scan job not found'}), 404
    
    if not job.false_positive_flags:
        job.false_positive_flags = []
    
    job.false_positive_flags.append({
        'vuln_index': vuln_index,
        'marked_by': current_user.id,
        'marked_at': datetime.utcnow().isoformat(),
        'reason': data.get('reason', 'User marked as false positive')
    })
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': 'Vulnerability marked as false positive'
    })


def broadcast_scan_progress(job_id, progress_data):
    """Broadcast scan progress to all subscribed clients"""
    socketio.emit('scan_progress', {
        'job_id': job_id,
        'progress': progress_data
    }, room=f'scan_{job_id}')


def create_sample_data():
    """Create sample data for testing"""
    with app.app_context():
        # Create admin user
        admin = User.query.filter_by(telegram_id='admin').first()
        if not admin:
            admin = User(
                telegram_id='admin',
                username='Administrator',
                is_whitelisted=True
            )
            db.session.add(admin)
            db.session.commit()
            print("Created admin user (telegram_id: admin)")


if __name__ == '__main__':
    # Initialize database
    with app.app_context():
        db.create_all()
        create_sample_data()
    
    # Run the application
    logger.info(f"Starting dashboard on {config.DASHBOARD_HOST}:{config.DASHBOARD_PORT}")
    socketio.run(app, host=config.DASHBOARD_HOST, port=config.DASHBOARD_PORT, debug=True)

@app.route('/api/trends')
def get_trends():
    """Get security trends and risk aging analytics"""
    try:
        # Get all completed scans
        completed_scans = Scan.query.filter_by(status='completed').order_by(Scan.started_at.desc()).all()
        
        if not completed_scans:
            return jsonify({
                'success': True,
                'trends': {
                    'avg_risk_age': '0 Days',
                    'mttr': '0 Days',
                    'sla_compliance': 100,
                    'total_scans': 0
                }
            })
        
        # Calculate metrics
        total_scans = len(completed_scans)
        total_vulns = sum(scan.vulnerabilities_found for scan in completed_scans if scan.vulnerabilities_found)
        
        # Simulated MTTR (in real app, track remediation dates)
        avg_mttr_days = 5
        sla_compliance = 92  # Percentage of critical fixed within SLA
        
        # Risk age calculation
        from datetime import datetime, timedelta
        now = datetime.utcnow()
        risk_ages = []
        for scan in completed_scans[:20]:  # Last 20 scans
            if scan.started_at:
                age = (now - scan.started_at).days
                risk_ages.append(age)
        
        avg_risk_age = sum(risk_ages) / len(risk_ages) if risk_ages else 0
        
        return jsonify({
            'success': True,
            'trends': {
                'avg_risk_age': f'{int(avg_risk_age)} Days',
                'mttr': f'{avg_mttr_days} Days',
                'sla_compliance': sla_compliance,
                'total_scans': total_scans,
                'total_vulns': total_vulns
            }
        })
    except Exception as e:
        logger.error(f"Trends error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
