from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
import config
import logging
from models import User, ScanJob, AuditLog, db, init_db
from tasks import run_scan_task
from datetime import datetime

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)


def is_user_allowed(user_id: int) -> bool:
    """Check if user is allowed to use the bot"""
    if not config.WHITELIST_ONLY:
        return True
    
    allowed_users = [int(uid.strip()) for uid in config.ALLOWED_USERS if uid.strip()]
    return user_id in allowed_users


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /start command"""
    user = update.effective_user
    
    # Check if user is allowed
    if not is_user_allowed(user.id):
        await update.message.reply_text(
            "❌ Sorry, you are not authorized to use this bot.\n"
            "Contact the administrator to get access."
        )
        return
    
    # Register or update user in database
    user_record = User.query.filter_by(telegram_id=str(user.id)).first()
    
    if not user_record:
        user_record = User(
            telegram_id=str(user.id),
            username=user.username or user.first_name,
            is_whitelisted=True
        )
        db.session.add(user_record)
        db.session.commit()
        
        # Log registration
        audit_log = AuditLog(
            user_id=user_record.id,
            action='TELEGRAM_USER_REGISTERED',
            details={'username': user.username}
        )
        db.session.add(audit_log)
        db.session.commit()
        
        welcome_text = (
            f"👋 Welcome @{user.username or user.first_name}!\n\n"
            "🔒 **Advanced Vulnerability Scanner Bot**\n\n"
            "You've been registered successfully. You can now scan your web applications for security vulnerabilities.\n\n"
            "**Available Commands:**\n"
            "/scan <url> - Start a vulnerability scan\n"
            "/status <job_id> - Check scan status\n"
            "/history - View your scan history\n"
            "/help - Show this help message\n\n"
            "⚠️ **Important:** Only scan websites you own or have permission to test!"
        )
    else:
        welcome_text = (
            f"👋 Welcome back @{user.username or user.first_name}!\n\n"
            "**Available Commands:**\n"
            "/scan <url> - Start a vulnerability scan\n"
            "/status <job_id> - Check scan status\n"
            "/history - View your scan history\n"
            "/help - Show help message\n\n"
            "⚠️ **Remember:** Only scan websites you own or have permission to test!"
        )
    
    # Create keyboard
    keyboard = [
        [InlineKeyboardButton("🚀 Quick Scan", callback_data='quick_scan')],
        [InlineKeyboardButton("📊 History", callback_data='history')],
        [InlineKeyboardButton("❓ Help", callback_data='help')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(welcome_text, parse_mode='Markdown', reply_markup=reply_markup)


async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /scan command"""
    user = update.effective_user
    
    # Check authorization
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ You are not authorized to use this bot.")
        return
    
    # Get target URL
    if not context.args:
        await update.message.reply_text(
            "❌ Please provide a target URL.\n\n"
            "Usage: `/scan https://example.com`\n\n"
            "You can also specify scan mode:\n"
            "`/scan https://example.com safe` - Safe mode (recommended)\n"
            "`/scan https://example.com deep` - Deep mode (advanced)",
            parse_mode='Markdown'
        )
        return
    
    target_url = context.args[0]
    scan_mode = context.args[1] if len(context.args) > 1 else 'safe'
    
    # Validate URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    # Validate scan mode
    if scan_mode not in ['safe', 'deep']:
        await update.message.reply_text(
            "❌ Invalid scan mode. Use 'safe' or 'deep'.\n\n"
            "- **Safe Mode**: Non-intrusive scans, safe for production\n"
            "- **Deep Mode**: Comprehensive scans, use only on test environments"
        )
        return
    
    # Get user from DB
    user_record = User.query.filter_by(telegram_id=str(user.id)).first()
    if not user_record:
        await update.message.reply_text("❌ User not found. Please use /start first.")
        return
    
    # Send confirmation message
    progress_message = await update.message.reply_text(
        f"🔍 **Starting Scan**\n\n"
        f"🎯 Target: `{target_url}`\n"
        f"📋 Mode: {scan_mode.upper()}\n"
        f"⏳ Please wait, this may take a few minutes..."
    )
    
    # Log action
    audit_log = AuditLog(
        user_id=user_record.id,
        action='TELEGRAM_SCAN_STARTED',
        target=target_url,
        details={'mode': scan_mode}
    )
    db.session.add(audit_log)
    db.session.commit()
    
    try:
        # Start Celery task
        task = run_scan_task.delay(target_url, user_record.id, scan_mode)
        job_id = task.id
        
        # Create keyboard with status button
        keyboard = [
            [InlineKeyboardButton("📊 Check Status", callback_data=f'status_{job_id}')],
            [InlineKeyboardButton("📜 History", callback_data='history')]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await progress_message.edit_text(
            f"✅ **Scan Started Successfully!**\n\n"
            f"🎯 Target: `{target_url}`\n"
            f"📋 Mode: {scan_mode.upper()}\n"
            f"🆔 Job ID: `{job_id}`\n\n"
            f"The scan is running in the background. I'll notify you when it's complete!\n\n"
            f"Use `/status {job_id}` to check progress.",
            parse_mode='Markdown',
            reply_markup=reply_markup
        )
        
    except Exception as e:
        logger.error(f"Failed to start scan: {str(e)}")
        await progress_message.edit_text(
            f"❌ **Failed to start scan**\n\n"
            f"Error: `{str(e)}`\n\n"
            f"Please try again or contact support."
        )


async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /status command"""
    if not context.args:
        await update.message.reply_text(
            "❌ Please provide a job ID.\n\n"
            "Usage: `/status <job_id>`\n\n"
            "Use /history to see your recent scans."
        )
        return
    
    job_id = context.args[0]
    user = update.effective_user
    user_record = User.query.filter_by(telegram_id=str(user.id)).first()
    
    if not user_record:
        await update.message.reply_text("❌ User not found. Please use /start first.")
        return
    
    job = ScanJob.query.get(job_id)
    
    if not job:
        await update.message.reply_text("❌ Job not found.")
        return
    
    # Verify ownership
    if job.user_id != user_record.id:
        await update.message.reply_text("❌ You don't have permission to view this job.")
        return
    
    # Format status message
    status_emoji = {
        'PENDING': '⏳',
        'RUNNING': '🔄',
        'COMPLETED': '✅',
        'FAILED': '❌'
    }
    
    emoji = status_emoji.get(job.status, '❓')
    
    status_text = (
        f"{emoji} **Scan Status**\n\n"
        f"🆔 Job ID: `{job.id}`\n"
        f"🎯 Target: `{job.target_url}`\n"
        f"📋 Mode: {job.scan_mode.upper()}\n"
        f"📊 Status: **{job.status}**\n"
    )
    
    if job.status == 'RUNNING':
        status_text += f"📈 Progress: {job.progress}%\n"
        if job.current_activity:
            status_text += f"🔍 Activity: {job.current_activity}\n"
    elif job.status == 'COMPLETED':
        status_text += (
            f"📊 Vulnerabilities Found: **{job.vulnerability_count}**\n"
            f"⚠️ Risk Score: **{job.risk_score}/10**\n"
            f"⏱️ Duration: {(job.completed_at - job.started_at).total_seconds() / 60:.1f} minutes\n"
        )
        
        # Add download button for report
        keyboard = [
            [InlineKeyboardButton("📄 Download HTML Report", callback_data=f'report_{job_id}')],
            [InlineKeyboardButton("📋 View Summary", callback_data=f'summary_{job_id}')]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await update.message.reply_text(status_text, parse_mode='Markdown', reply_markup=reply_markup)
        return
        
    elif job.status == 'FAILED':
        status_text += f"❌ Error: `{job.error_message}`\n"
    
    await update.message.reply_text(status_text, parse_mode='Markdown')


async def history_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /history command"""
    user = update.effective_user
    user_record = User.query.filter_by(telegram_id=str(user.id)).first()
    
    if not user_record:
        await update.message.reply_text("❌ User not found. Please use /start first.")
        return
    
    # Get last 10 scans
    scans = ScanJob.query.filter_by(user_id=user_record.id)\
        .order_by(ScanJob.started_at.desc()).limit(10).all()
    
    if not scans:
        await update.message.reply_text("📭 You haven't run any scans yet.\n\nUse /scan to start your first scan!")
        return
    
    history_text = "📊 **Your Recent Scans**\n\n"
    
    for i, scan in enumerate(scans, 1):
        status_emoji = {
            'COMPLETED': '✅',
            'FAILED': '❌',
            'RUNNING': '🔄',
            'PENDING': '⏳'
        }
        emoji = status_emoji.get(scan.status, '❓')
        
        history_text += (
            f"{i}. {emoji} `{scan.id[:8]}...`\n"
            f"   🎯 {scan.target_url}\n"
            f"   📊 {scan.vulnerability_count} vulns | Risk: {scan.risk_score}/10\n"
            f"   ⏰ {scan.started_at.strftime('%Y-%m-%d %H:%M') if scan.started_at else 'N/A'}\n\n"
        )
    
    await update.message.reply_text(history_text, parse_mode='Markdown')


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /help command"""
    help_text = (
        "🔒 **Vulnerability Scanner Bot - Help**\n\n"
        "**Commands:**\n"
        "/start - Start the bot and see welcome message\n"
        "/scan <url> [mode] - Start a vulnerability scan\n"
        "   - mode: 'safe' (default) or 'deep'\n"
        "/status <job_id> - Check scan status\n"
        "/history - View your last 10 scans\n"
        "/help - Show this help message\n\n"
        "**Scan Modes:**\n"
        "🟢 **Safe Mode**: Non-intrusive tests, safe for production\n"
        "🟡 **Deep Mode**: Comprehensive tests, use only on staging/test environments\n\n"
        "**What gets scanned:**\n"
        "• SQL Injection\n"
        "• Cross-Site Scripting (XSS)\n"
        "• Directory Traversal\n"
        "• Security Headers\n"
        "• Sensitive Files\n"
        "• Open Redirects\n"
        "• And more...\n\n"
        "⚠️ **Legal Notice:**\n"
        "Only scan websites you own or have explicit permission to test.\n"
        "Unauthorized scanning is illegal!"
    )
    
    await update.message.reply_text(help_text, parse_mode='Markdown')


async def callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle callback queries from inline keyboards"""
    query = update.callback_query
    await query.answer()
    
    data = query.data
    
    if data == 'quick_scan':
        await query.edit_message_text(
            "🚀 **Quick Scan**\n\n"
            "Send me a URL to scan:\n"
            "Example: `https://example.com`",
            parse_mode='Markdown'
        )
    elif data == 'history':
        await history_command(update, context)
    elif data == 'help':
        await help_command(update, context)
    elif data.startswith('status_'):
        job_id = data.split('_')[1]
        context.args = [job_id]
        await status_command(update, context)
    elif data.startswith('summary_'):
        job_id = data.split('_')[1]
        # Send summary logic here
        await query.edit_message_text("📋 Summary feature coming soon...")


async def handle_url_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle direct URL messages for quick scanning"""
    text = update.message.text.strip()
    
    # Check if it looks like a URL
    if text.startswith(('http://', 'https://', 'www.')):
        context.args = [text, 'safe']
        await scan_command(update, context)


def main():
    """Main function to run the bot"""
    # Initialize database
    from flask import Flask
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = config.DATABASE_URL
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    init_db(app)
    
    # Create application
    application = Application.builder().token(config.TELEGRAM_BOT_TOKEN).build()
    
    # Add handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("scan", scan_command))
    application.add_handler(CommandHandler("status", status_command))
    application.add_handler(CommandHandler("history", history_command))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_url_message))
    application.add_handler(MessageHandler(filters.ALL, callback_handler))
    
    # Start the bot
    logger.info("🤖 Starting Telegram Bot...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == '__main__':
    main()
