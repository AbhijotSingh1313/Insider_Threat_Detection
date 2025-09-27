from flask import Flask, render_template, request, jsonify, make_response
import sqlite3
import threading
import time
from datetime import datetime, timedelta
import os
import psutil
import pdfkit
import smtplib
import platform
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

# Import your custom modules (with error handling)
try:
    from db_init_enhanced import create_database, get_db_connection
    from monitor_enhanced import EnhancedSecurityMonitor as SecurityMonitor
    from ftp_server_enhanced import FTPHoneypot
    from analyzer_enhanced import RealWorldThreatDetector as SuspiciousActivityDetector
except ImportError as e:
    print(f"Warning: Some modules not found: {e}")
    print("Using fallback imports...")
    try:
        from db_init_enhanced import create_database, get_db_connection
        from monitor_enhanced import SecurityMonitor
        from ftp_server_enhanced import FTPHoneypot
        from analyzer_enhanced import SuspiciousActivityDetector
    except ImportError:
        print("Error: Required modules not found!")

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

# Global monitoring services
security_monitor = None
ftp_honeypot = None
analyzer = None
monitoring_active = False

# Ngrok configuration
NGROK_ENABLED = True
NGROK_AUTH_TOKEN = ""  # Optional

def setup_ngrok():
    try:
        from pyngrok import ngrok
        tunnel = ngrok.connect(5000)
        print(f"🌍 PUBLIC URL: {tunnel.public_url}")
        return tunnel.public_url
    except Exception as e:
        print(f"Ngrok failed: {e}")
        return None
def get_wkhtmltopdf_path():
    system = platform.system().lower()
    if system == 'windows':
        for p in [
            r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe',
            r'C:\Program Files (x86)\wkhtmltopdf\bin\wkhtmltopdf.exe',
            r'C:\Users\lenovo\Desktop\wkhtmltox-0.12.6-1.msvc2015-win64.exe'#   Your custom path
        ]:
            if os.path.isfile(p):
                return p
    elif system == 'linux':
        for p in ['/usr/bin/wkhtmltopdf','/usr/local/bin/wkhtmltopdf']:
            if os.path.isfile(p):
                return p
    elif system == 'darwin':
        for p in ['/usr/local/bin/wkhtmltopdf','/opt/homebrew/bin/wkhtmltopdf']:
            if os.path.isfile(p):
                return p
    return None

WK_PATH = get_wkhtmltopdf_path()
if WK_PATH:
    PDFKIT_CONFIG = pdfkit.configuration(wkhtmltopdf=WK_PATH)
    print(f"✅ wkhtmltopdf found at: {WK_PATH}")
else:
    PDFKIT_CONFIG = None
    print("⚠️ wkhtmltopdf not found; using system PATH")
def get_wkhtmltopdf_path():
    """Get the correct wkhtmltopdf path for different OS"""
    system = platform.system().lower()
    
    if system == 'windows':
        # Common Windows installation paths (using your provided paths)
        possible_paths = [
            r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe',
            r'C:\Program Files (x86)\wkhtmltopdf\bin\wkhtmltopdf.exe',
            r'C:\Users\lenovo\Desktop\wkhtmltox-0.12.6-1.msvc2015-win64.exe'#   Your custom path
        ]
        
        for path in possible_paths:
            # Remove quotes if present and check if file exists
            clean_path = path.strip('"')
            if os.path.exists(clean_path):
                return clean_path
                
    elif system == 'linux':
        # Common Linux paths
        possible_paths = [
            '/usr/bin/wkhtmltopdf',
            '/usr/local/bin/wkhtmltopdf'
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
                
    elif system == 'darwin':  # macOS
        # Common macOS paths
        possible_paths = [
            '/usr/local/bin/wkhtmltopdf',
            '/opt/homebrew/bin/wkhtmltopdf'
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
    
    return None  # Let pdfkit find it automatically

# Configure pdfkit with the correct path
WKHTMLTOPDF_PATH = get_wkhtmltopdf_path()
if WKHTMLTOPDF_PATH:
    pdfkit_config = pdfkit.configuration(wkhtmltopdf=WKHTMLTOPDF_PATH)
    print(f"✅ Found wkhtmltopdf at: {WKHTMLTOPDF_PATH}")
else:
    pdfkit_config = None
    print("⚠️  wkhtmltopdf path not found, using system PATH")

def get_system_info():
    '''Get system information for enhanced monitoring'''
    try:
        return {
            'cpu_percent': psutil.cpu_percent(),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_percent': psutil.disk_usage('/').percent if os.name != 'nt' else psutil.disk_usage('C:').percent,
            'network_connections': len(psutil.net_connections()),
            'running_processes': len(psutil.pids())
        }
    except Exception as e:
        print(f"Error getting system info: {e}")
        return {}

def initialize_services():
    '''Initialize all monitoring services'''
    global security_monitor, ftp_honeypot, analyzer
    
    try:
        # Create database if it doesn't exist
        db_path = 'security_monitoring.db'
        if not os.path.exists(db_path):
            print("Creating database...")
            create_database()

        # Initialize services
        if security_monitor is None:
            security_monitor = SecurityMonitor()
            print("✅ Security monitor initialized")
        
        if ftp_honeypot is None:
            ftp_honeypot = FTPHoneypot()
            print("✅ FTP honeypot initialized")
        
        if analyzer is None:
            analyzer = SuspiciousActivityDetector()
            print("✅ ML analyzer initialized")
    
    except Exception as e:
        print(f"Error initializing services: {e}")

@app.before_request
def startup():
    '''Initialize services on first request'''
    initialize_services()

@app.route('/')
def dashboard():
    '''Main admin dashboard showing recent logs and alerts'''
    try:
        initialize_services()
        
        conn = get_db_connection()
        if not conn:
            return "Database connection failed", 500

        # Get visitor IP for tracking
        visitor_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        
        # Log dashboard access
        try:
            conn.execute('''
                INSERT INTO event_logs 
                (event_id, timestamp, source_ip, username, event_type, description, risk_score, is_suspicious, processed)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
            ''', (9001, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), visitor_ip, 
                  'dashboard_user', 'Dashboard Access', f'Dashboard accessed from {visitor_ip}', 0.1, 0))
            conn.commit()
        except Exception as e:
            print(f"Error logging dashboard access: {e}")

        # Get recent suspicious activities
        try:
            recent_suspicious = conn.execute('''
                SELECT id, timestamp, activity_type, source_ip, username, risk_level, details, status, 'report' as source_type
                FROM suspicious_reports 
                WHERE datetime(timestamp) >= datetime('now', '-1 day')
                ORDER BY timestamp DESC LIMIT 20
            ''').fetchall()
        except:
            recent_suspicious = []

        # Get system statistics
        try:
            stats = conn.execute('''
                SELECT 
                    (SELECT COUNT(*) FROM event_logs WHERE date(timestamp) = date('now')) as today_events,
                    (SELECT COUNT(*) FROM ftp_logs WHERE date(timestamp) = date('now')) as today_ftp,
                    (SELECT COUNT(*) FROM event_logs WHERE is_suspicious = 1 AND date(timestamp) = date('now')) as today_suspicious_events,
                    (SELECT COUNT(*) FROM ftp_logs WHERE is_suspicious = 1 AND date(timestamp) = date('now')) as today_suspicious_ftp,
                    (SELECT COUNT(*) FROM suspicious_reports WHERE status = 'new') as pending_reports
            ''').fetchone()
        except:
            stats = (0, 0, 0, 0, 0)

        # Get recent event logs
        try:
            recent_events = conn.execute('''
                SELECT * FROM event_logs ORDER BY timestamp DESC LIMIT 10
            ''').fetchall()
        except:
            recent_events = []

        # Get recent FTP logs
        try:
            recent_ftp = conn.execute('''
                SELECT * FROM ftp_logs ORDER BY timestamp DESC LIMIT 10
            ''').fetchall()
        except:
            recent_ftp = []

        conn.close()
        
        # Get system info
        system_info = get_system_info()

        return render_template('dashboard.html',
                               suspicious_activities=recent_suspicious,
                               stats=stats,
                               recent_events=recent_events,
                               recent_ftp=recent_ftp,
                               monitoring_status=monitoring_active,
                               system_info=system_info)
                               
    except Exception as e:
        print(f"Dashboard error: {e}")
        return f'''
        <!DOCTYPE html>
        <html><body>
        <h1>Security Dashboard</h1>
        <p><strong>Status:</strong> System running</p>
        <p><strong>Error:</strong> {str(e)}</p>
        <a href="/monitoring/start">Start Monitoring</a> | 
        <a href="/reports">View Reports</a>
        </body></html>
        '''

@app.route('/reports')
def reports():
    '''View all suspicious activity reports'''
    try:
        initialize_services()
        conn = get_db_connection()
        
        # Get filter parameters
        status_filter = request.args.get('status', 'all')
        risk_filter = request.args.get('risk', 'all')
        
        query = "SELECT * FROM suspicious_reports WHERE 1=1"
        params = []
        
        if status_filter != 'all':
            query += " AND status = ?"
            params.append(status_filter)
        
        if risk_filter != 'all':
            query += " AND risk_level = ?"
            params.append(risk_filter)
        
        query += " ORDER BY timestamp DESC"
        
        try:
            reports = conn.execute(query, params).fetchall()
        except:
            reports = []
        
        conn.close()
        
        return render_template('reports.html', 
                               reports=reports,
                               current_status=status_filter,
                               current_risk=risk_filter)
                               
    except Exception as e:
        return f'''
        <!DOCTYPE html>
        <html><body>
        <h1>Reports</h1>
        <p><strong>Error:</strong> {str(e)}</p>
        <a href="/">Back to Dashboard</a>
        </body></html>
        '''

@app.route('/report/<int:report_id>')
def view_report(report_id):
    '''View individual report details'''
    try:
        conn = get_db_connection()
        
        # Get the specific report
        report = conn.execute('''
            SELECT * FROM suspicious_reports WHERE id = ?
        ''', (report_id,)).fetchone()
        
        if not report:
            conn.close()
            return "Report not found", 404
        
        # Get related data
        try:
            related_events = conn.execute('''
                SELECT * FROM event_logs 
                WHERE username = ? AND date(timestamp) = date(?)
                ORDER BY timestamp DESC
            ''', (report[4], report[1])).fetchall()
        except:
            related_events = []
        
        try:
            related_ftp = conn.execute('''
                SELECT * FROM ftp_logs 
                WHERE username = ? AND date(timestamp) = date(?)
                ORDER BY timestamp DESC
            ''', (report[4], report[1])).fetchall()
        except:
            related_ftp = []
        
        conn.close()
        
        return render_template('report.html',
                               report=report,
                               related_events=related_events,
                               related_ftp=related_ftp)
                               
    except Exception as e:
        return f"Report Error: {str(e)}", 500

# ==================== PDF AND EMAIL ROUTES ====================

@app.route('/report/<int:report_id>/pdf')
def download_report_pdf(report_id):
    '''Download individual report as PDF'''
    try:
        conn = get_db_connection()
        
        # Get the specific report
        report = conn.execute('''
            SELECT * FROM suspicious_reports WHERE id = ?
        ''', (report_id,)).fetchone()
        
        if not report:
            conn.close()
            return "Report not found", 404
        
        # Get related data
        try:
            related_events = conn.execute('''
                SELECT * FROM event_logs 
                WHERE username = ? AND date(timestamp) = date(?)
                ORDER BY timestamp DESC
            ''', (report[4], report[1])).fetchall()
        except:
            related_events = []
        
        try:
            related_ftp = conn.execute('''
                SELECT * FROM ftp_logs 
                WHERE username = ? AND date(timestamp) = date(?)
                ORDER BY timestamp DESC
            ''', (report[4], report[1])).fetchall()
        except:
            related_ftp = []
        
        conn.close()
        
        # Render HTML template for PDF
        html_content = render_template('single_report_pdf.html',
                                     report=report,
                                     related_events=related_events,
                                     related_ftp=related_ftp,
                                     current_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        # Convert HTML to PDF
        options = {
            'page-size': 'A4',
            'margin-top': '0.75in',
            'margin-right': '0.75in',
            'margin-bottom': '0.75in',
            'margin-left': '0.75in',
            'encoding': "UTF-8",
            'no-outline': None
        }
        
        # Use configuration if available
        if pdfkit_config:
            pdf = pdfkit.from_string(html_content, False, options=options, configuration=pdfkit_config)
        else:
            pdf = pdfkit.from_string(html_content, False, options=options)
        
        # Create response
        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=security_report_{report_id}.pdf'
        
        return response
        
    except Exception as e:
        error_msg = str(e)
        if "wkhtmltopdf" in error_msg.lower():
            return f'''
            <h1>❌ PDF Generation Error</h1>
            <p><strong>Error:</strong> wkhtmltopdf not found or not configured properly.</p>
            <p><strong>Current paths checked:</strong></p>
            <ul>
                <li>C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe</li>
                <li>C:\\Program Files (x86)\\wkhtmltopdf\\bin\\wkhtmltopdf.exe</li>
                <li>C:\\Users\\lenovo\\Desktop\\wkhtmltox-0.12.6-1.msvc2015-win64.exe</li>
            </ul>
            <h3>🔧 Quick Fixes:</h3>
            <ol>
                <li>Make sure wkhtmltopdf is installed at one of the above paths</li>
                <li>If installed elsewhere, update the path in get_wkhtmltopdf_path() function</li>
                <li>Restart your Flask app after installation</li>
            </ol>
            <p><a href="/reports">← Back to Reports</a></p>
            ''', 500
        else:
            return f"Error generating PDF: {error_msg}", 500

@app.route('/report/<int:report_id>/email', methods=['POST'])
def email_report(report_id):
    '''Email individual report as PDF attachment'''
    try:
        # Get email from form data
        recipient_email = request.form.get('email')
        if not recipient_email:
            return jsonify({'success': False, 'error': 'Email address required'})
        
        conn = get_db_connection()
        
        # Get the specific report
        report = conn.execute('''
            SELECT * FROM suspicious_reports WHERE id = ?
        ''', (report_id,)).fetchone()
        
        if not report:
            conn.close()
            return jsonify({'success': False, 'error': 'Report not found'})
        
        # Get related data
        try:
            related_events = conn.execute('''
                SELECT * FROM event_logs 
                WHERE username = ? AND date(timestamp) = date(?)
                ORDER BY timestamp DESC
            ''', (report[4], report[1])).fetchall()
        except:
            related_events = []
        
        try:
            related_ftp = conn.execute('''
                SELECT * FROM ftp_logs 
                WHERE username = ? AND date(timestamp) = date(?)
                ORDER BY timestamp DESC
            ''', (report[4], report[1])).fetchall()
        except:
            related_ftp = []
        
        conn.close()
        
        # Generate PDF
        html_content = render_template('single_report_pdf.html',
                                     report=report,
                                     related_events=related_events,
                                     related_ftp=related_ftp,
                                     current_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        options = {
            'page-size': 'A4',
            'margin-top': '0.75in',
            'margin-right': '0.75in',
            'margin-bottom': '0.75in',
            'margin-left': '0.75in',
            'encoding': "UTF-8",
            'no-outline': None
        }
        
        # Use configuration if available
        if pdfkit_config:
            pdf_data = pdfkit.from_string(html_content, False, options=options, configuration=pdfkit_config)
        else:
            pdf_data = pdfkit.from_string(html_content, False, options=options)
        
        # Email configuration (UPDATE THESE WITH YOUR EMAIL SETTINGS)
        smtp_server = "smtp.gmail.com"
        smtp_port = 587
        sender_email = "Your Email"  # CHANGE THIS
        sender_password = "Your email password"  # CHANGE THIS
        
        # Create email message
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = recipient_email
        msg['Subject'] = f"🔒 Security Report #{report_id} - {report[2]}"
        
        # Email body
        body = f'''
        Dear Security Team,
        
        Please find attached the security report for suspicious activity.
        
        Report Details:
        - ID: {report[0]}
        - Timestamp: {report[1]}
        - Activity: {report[2]}
        - Username: {report[4]}
        - Risk Level: {report[5]}
        - Status: {report[7]}
        
        Details: {report[6]}
        
        This is an automated email from the Insider Threat Detection System.
        Please review the attached PDF report for complete details.
        
        Best regards,
        Security Monitoring System
        '''
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Attach PDF
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(pdf_data)
        encoders.encode_base64(part)
        part.add_header(
            'Content-Disposition',
            f'attachment; filename=security_report_{report_id}.pdf'
        )
        msg.attach(part)
        
        # Send email
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        text = msg.as_string()
        server.sendmail(sender_email, recipient_email, text)
        server.quit()
        
        return jsonify({
            'success': True, 
            'message': f'Report #{report_id} emailed successfully to {recipient_email}'
        })
        
    except Exception as e:
        error_msg = str(e)
        if "wkhtmltopdf" in error_msg.lower():
            return jsonify({
                'success': False, 
                'error': 'PDF generation failed. Please ensure wkhtmltopdf is installed and restart the application.'
            })
        else:
            print(f"Email error: {e}")
            return jsonify({'success': False, 'error': str(e)})

@app.route('/reports/pdf')
def download_all_reports_pdf():
    '''Download all reports as a single PDF'''
    try:
        conn = get_db_connection()
        
        # Get all reports
        reports = conn.execute('''
            SELECT * FROM suspicious_reports ORDER BY timestamp DESC
        ''').fetchall()
        
        if not reports:
            conn.close()
            return "No reports found", 404
        
        conn.close()
        
        # Render HTML template for all reports
        html_content = render_template('all_reports_pdf.html',
                                     reports=reports,
                                     current_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        # Convert HTML to PDF
        options = {
            'page-size': 'A4',
            'margin-top': '0.75in',
            'margin-right': '0.75in',
            'margin-bottom': '0.75in',
            'margin-left': '0.75in',
            'encoding': "UTF-8",
            'no-outline': None
        }
        
        # Use configuration if available
        if pdfkit_config:
            pdf = pdfkit.from_string(html_content, False, options=options, configuration=pdfkit_config)
        else:
            pdf = pdfkit.from_string(html_content, False, options=options)
        
        # Create response
        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=all_security_reports_{datetime.now().strftime("%Y%m%d")}.pdf'
        
        return response
        
    except Exception as e:
        error_msg = str(e)
        if "wkhtmltopdf" in error_msg.lower():
            return f'''
            <h1>❌ PDF Generation Error</h1>
            <p><strong>Error:</strong> wkhtmltopdf not found or not configured properly.</p>
            <p><strong>Current paths checked:</strong></p>
            <ul>
                <li>C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe</li>
                <li>C:\\Program Files (x86)\\wkhtmltopdf\\bin\\wkhtmltopdf.exe</li>
                <li>C:\\Users\\lenovo\\Desktop\\wkhtmltox-0.12.6-1.msvc2015-win64.exe</li>
            </ul>
            <h3>🔧 Quick Fixes:</h3>
            <ol>
                <li>Make sure wkhtmltopdf is installed at one of the above paths</li>
                <li>If you have it installed elsewhere, update the path in the code</li>
                <li>Restart your Flask app after installation</li>
            </ol>
            <p><a href="/reports">← Back to Reports</a></p>
            ''', 500
        else:
            return f"Error generating PDF: {error_msg}", 500

# ==================== EXISTING ROUTES (UNCHANGED) ====================

@app.route('/api/acknowledge/<int:report_id>', methods=['POST'])
def acknowledge_report(report_id):
    '''Mark report as acknowledged'''
    try:
        conn = get_db_connection()
        
        conn.execute('''
            UPDATE suspicious_reports SET status = 'acknowledged' WHERE id = ?
        ''', (report_id,))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Report acknowledged'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/stats')
def api_stats():
    '''API endpoint for real-time dashboard updates'''
    try:
        initialize_services()
        conn = get_db_connection()
        
        try:
            stats = conn.execute('''
                SELECT 
                    (SELECT COUNT(*) FROM event_logs WHERE datetime(timestamp) >= datetime('now', '-1 hour')) as last_hour_events,
                    (SELECT COUNT(*) FROM ftp_logs WHERE datetime(timestamp) >= datetime('now', '-1 hour')) as last_hour_ftp,
                    (SELECT COUNT(*) FROM event_logs WHERE is_suspicious = 1 AND datetime(timestamp) >= datetime('now', '-1 hour')) as last_hour_suspicious,
                    (SELECT COUNT(*) FROM suspicious_reports WHERE status = 'new') as new_alerts
            ''').fetchone()
        except:
            stats = (0, 0, 0, 0)
        
        conn.close()
        
        system_info = get_system_info()
        
        return jsonify({
            'last_hour_events': stats[0],
            'last_hour_ftp': stats[1],
            'last_hour_suspicious': stats[2],
            'new_alerts': stats[3],
            'monitoring_active': monitoring_active,
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'system_info': system_info
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/monitoring/start')
def start_monitoring():
    '''Start all monitoring services'''
    global monitoring_active, security_monitor, ftp_honeypot
    
    try:
        initialize_services()
        
        if not monitoring_active:
            # Start monitoring services
            if security_monitor:
                security_monitor.start_monitoring()
            
            if ftp_honeypot:
                ftp_honeypot.start_server()
            
            if analyzer:
                analyzer_thread = threading.Thread(target=run_periodic_analysis)
                analyzer_thread.daemon = True
                analyzer_thread.start()
            
            monitoring_active = True
            print("✅ All monitoring services started")
            
            return jsonify({
                'success': True,
                'message': 'Monitoring services started successfully'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Monitoring is already active'
            })
            
    except Exception as e:
        print(f"Start monitoring error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/monitoring/stop')
def stop_monitoring():
    '''Stop all monitoring services'''
    global monitoring_active, security_monitor, ftp_honeypot
    
    try:
        if monitoring_active:
            if security_monitor:
                security_monitor.stop_monitoring()
            
            if ftp_honeypot:
                ftp_honeypot.stop_server()
            
            monitoring_active = False
            print("🛑 All monitoring services stopped")
            
            return jsonify({
                'success': True,
                'message': 'Monitoring services stopped successfully'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Monitoring is not active'
            })
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def run_periodic_analysis():
    '''Background thread for periodic ML analysis'''
    global analyzer
    
    while monitoring_active:
        try:
            if not analyzer:
                break
            
            print("🧠 Running ML analysis...")
            
            conn = get_db_connection()
            if not conn:
                continue
            
            # Get unprocessed events
            try:
                unprocessed_events = conn.execute('''
                    SELECT * FROM event_logs WHERE processed = 0
                ''').fetchall()
            except:
                unprocessed_events = []
            
            try:
                unprocessed_ftp = conn.execute('''
                    SELECT * FROM ftp_logs WHERE processed = 0
                ''').fetchall()
            except:
                unprocessed_ftp = []
            
            # Train models if needed
            try:
                if not analyzer.model_trained:
                    analyzer.train_models()
            except:
                pass
            
            # Analyze events
            if unprocessed_events:
                try:
                    suspicious_events = analyzer.analyze_events(unprocessed_events)
                    for event_id, is_suspicious, risk_score in suspicious_events:
                        conn.execute('''
                            UPDATE event_logs 
                            SET is_suspicious = ?, risk_score = ?, processed = 1 
                            WHERE id = ?
                        ''', (is_suspicious, risk_score, event_id))
                        
                        if is_suspicious and risk_score >= 0.7:
                            event_data = conn.execute('SELECT * FROM event_logs WHERE id = ?', (event_id,)).fetchone()
                            if event_data:
                                create_suspicious_report(conn, event_data, 'event')
                
                except Exception as e:
                    print(f"Event analysis error: {e}")
            
            # Analyze FTP logs
            if unprocessed_ftp:
                try:
                    suspicious_ftp = analyzer.analyze_ftp_logs(unprocessed_ftp)
                    for log_id, is_suspicious, risk_score in suspicious_ftp:
                        conn.execute('''
                            UPDATE ftp_logs 
                            SET is_suspicious = ?, risk_score = ?, processed = 1 
                            WHERE id = ?
                        ''', (is_suspicious, risk_score, log_id))
                        
                        if is_suspicious and risk_score >= 0.7:
                            ftp_data = conn.execute('SELECT * FROM ftp_logs WHERE id = ?', (log_id,)).fetchone()
                            if ftp_data:
                                create_suspicious_report(conn, ftp_data, 'ftp')
                
                except Exception as e:
                    print(f"FTP analysis error: {e}")
            
            conn.commit()
            conn.close()
            
            print(f"✅ Analyzed {len(unprocessed_events)} events, {len(unprocessed_ftp)} FTP logs")
            
        except Exception as e:
            print(f"Analysis error: {e}")
        
        time.sleep(120)

def create_suspicious_report(conn, data, data_type):
    """Create a suspicious activity report"""
    try:
        if data_type == 'event':
            activity_type = f"Suspicious Event: {data[5]}"
            source_ip = data[3]
            username = data[4]
            details = f"Event ID: {data[1]}, Description: {data[6]}"
        else:  # ftp
            activity_type = f"Suspicious FTP: {data[4]}"
            source_ip = data[2]
            username = data[1]
            details = f"File: {data[5]}, Action: {data[4]}"
        
        risk_level = 'HIGH' if data[7] >= 0.8 else 'MEDIUM'
        
        conn.execute('''
            INSERT INTO suspicious_reports 
            (timestamp, activity_type, source_ip, username, risk_level, details, status)
            VALUES (datetime('now'), ?, ?, ?, ?, ?, 'new')
        ''', (activity_type, source_ip, username, risk_level, details))
        
        conn.commit()
        
    except Exception as e:
        print(f"❌ Error creating report: {e}")

if __name__ == '__main__':
    print("🚀 Starting Insider Threat Detection System...")
    print("📊 Dashboard will be available at: http://127.0.0.1:5000/")
    print("🍯 FTP Honeypot will run on port 2121")
    print("🔍 Event logs will be monitored continuously")
    
    # Setup ngrok if enabled
    if NGROK_ENABLED:
        setup_ngrok()
    
    # Run Flask app
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True, use_reloader=False)