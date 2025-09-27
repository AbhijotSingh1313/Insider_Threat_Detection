import os
import threading
import time
from datetime import datetime
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
import socket
from db_init_enhanced import get_db_connection

class EnhancedFTPHandler(FTPHandler):
    '''Enhanced FTP handler with detailed user tracking and threat detection'''

    def __init__(self, conn, server, ioloop=None):
        super().__init__(conn, server, ioloop)
        self.session_start = datetime.now()
        self.commands_executed = []
        self.files_accessed = []

    def on_connect(self):
        '''Called when client connects'''
        client_ip = self.remote_ip
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Get additional client info
        try:
            hostname = socket.gethostbyaddr(client_ip)[0]
        except:
            hostname = 'unknown'

        print(f"🔗 FTP Connection from {client_ip} ({hostname})")
        self.log_activity("connect", client_ip, "anonymous", "/", timestamp, 
                          extra_info={'hostname': hostname})

    def on_disconnect(self):
        '''Called when client disconnects'''
        client_ip = self.remote_ip
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        username = getattr(self, 'username', 'anonymous')

        # Calculate session duration
        session_duration = (datetime.now() - self.session_start).total_seconds()

        print(f"❌ FTP Disconnection from {client_ip} (session: {session_duration:.0f}s)")
        self.log_activity("disconnect", client_ip, username, "/", timestamp,
                          extra_info={
                              'session_duration': session_duration,
                              'commands_executed': len(self.commands_executed),
                              'files_accessed': len(self.files_accessed)
                          })

    def on_login(self, username):
        '''Called when user successfully logs in'''
        client_ip = self.remote_ip
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        print(f"✅ FTP Login: {username} from {client_ip}")
        self.log_activity("login", client_ip, username, "/", timestamp)

        # Check for suspicious login patterns
        self.check_suspicious_login(username, client_ip, timestamp)

    def on_login_failed(self, username, password):
        '''Called when login fails'''
        client_ip = self.remote_ip
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        print(f"🚨 FTP Failed Login: {username} from {client_ip}")
        self.log_activity("failed_login", client_ip, username, "/", timestamp, 
                          suspicious=True, extra_info={'attempted_password': password[:3] + '***'})

        # Check for brute force attempts
        self.check_brute_force_attempt(username, client_ip, timestamp)

    def on_logout(self, username):
        '''Called when user logs out'''
        client_ip = self.remote_ip
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        print(f"👋 FTP Logout: {username} from {client_ip}")
        self.log_activity("logout", client_ip, username, "/", timestamp)

    def on_file_sent(self, file):
        '''Called when a file is successfully sent (downloaded)'''
        client_ip = self.remote_ip
        username = getattr(self, 'username', 'anonymous')
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Get file size
        try:
            file_size = os.path.getsize(file)
        except:
            file_size = 0

        print(f"📥 FTP Download: {username} downloaded {file} ({file_size} bytes) from {client_ip}")
        self.log_activity("download", client_ip, username, file, timestamp,
                          extra_info={'file_size': file_size})

        self.files_accessed.append(file)
        self.check_suspicious_file_activity("download", username, client_ip, file, timestamp)

    def on_file_received(self, file):
        '''Called when a file is successfully received (uploaded)'''
        client_ip = self.remote_ip
        username = getattr(self, 'username', 'anonymous')
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Get file size
        try:
            file_size = os.path.getsize(file)
        except:
            file_size = 0

        print(f"📤 FTP Upload: {username} uploaded {file} ({file_size} bytes) from {client_ip}")
        self.log_activity("upload", client_ip, username, file, timestamp,
                          extra_info={'file_size': file_size})

        self.files_accessed.append(file)
        self.check_suspicious_file_activity("upload", username, client_ip, file, timestamp)

    def ftp_LIST(self, path):
        '''Override LIST command to log directory access'''
        client_ip = self.remote_ip
        username = getattr(self, 'username', 'anonymous')
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        self.log_activity("list_directory", client_ip, username, path, timestamp)
        self.commands_executed.append(f"LIST {path}")

        return super().ftp_LIST(path)

    def ftp_CWD(self, path):
        '''Override CWD (change directory) command'''
        client_ip = self.remote_ip
        username = getattr(self, 'username', 'anonymous')
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        self.log_activity("change_directory", client_ip, username, path, timestamp)
        self.commands_executed.append(f"CWD {path}")

        return super().ftp_CWD(path)

    def log_activity(self, action, client_ip, username, file_path, timestamp, suspicious=False, extra_info=None):
        '''Enhanced activity logging with additional metadata'''
        try:
            conn = get_db_connection()
            if not conn:
                return

            # Calculate risk score
            risk_score = self.calculate_risk_score(action, username, client_ip, file_path, timestamp, extra_info)

            # Override suspicious flag if risk is high
            if risk_score >= 0.6:
                suspicious = True

            # Prepare extra info JSON
            extra_info_json = str(extra_info) if extra_info else None

            # Insert into ftp_logs table with enhanced fields
            conn.execute('''
                INSERT INTO ftp_logs
                (username, client_ip, timestamp, action, file_path, risk_score, is_suspicious, processed, extra_info)
                VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
            ''', (username, client_ip, timestamp, action, file_path, risk_score, int(suspicious), extra_info_json))

            conn.commit()
            conn.close()

            if suspicious:
                print(f"🚨 Suspicious FTP Activity: {action} by {username} from {client_ip}")

        except Exception as e:
            print(f"Error logging FTP activity: {e}")

    def check_brute_force_attempt(self, username, client_ip, timestamp):
        '''Enhanced brute force detection'''
        try:
            conn = get_db_connection()
            if not conn:
                return

            # Check failed login attempts in last 10 minutes
            recent_failures = conn.execute('''
                SELECT COUNT(*) FROM ftp_logs 
                WHERE client_ip = ? 
                AND action = 'failed_login' 
                AND datetime(timestamp) >= datetime('now', '-10 minutes')
            ''', (client_ip,)).fetchone()[0]

            # Check attempts across different usernames (account enumeration)
            unique_users = conn.execute('''
                SELECT COUNT(DISTINCT username) FROM ftp_logs 
                WHERE client_ip = ? 
                AND action = 'failed_login' 
                AND datetime(timestamp) >= datetime('now', '-15 minutes')
            ''', (client_ip,)).fetchone()[0]

            conn.close()

            if recent_failures >= 3:
                print(f"🚨 Brute force attack detected: {recent_failures} failed logins from {client_ip}")
                return True

            if unique_users >= 5:
                print(f"🚨 Account enumeration detected: {unique_users} different usernames from {client_ip}")
                return True

            return False

        except Exception as e:
            print(f"Error checking brute force: {e}")
            return False

    def check_suspicious_login(self, username, client_ip, timestamp):
        '''Enhanced suspicious login detection'''
        try:
            # Time-based detection
            login_time = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
            if login_time.hour >= 23 or login_time.hour <= 6:
                print(f"🚨 After-hours FTP login: {username} at {timestamp}")
                return True

            # Geographic detection (basic)
            if not client_ip.startswith(('192.168.', '10.', '172.', '127.')):
                print(f"🚨 External FTP access: {username} from {client_ip}")
                return True

            # Anonymous access detection
            if username.lower() in ['anonymous', 'ftp', 'guest']:
                print(f"🚨 Anonymous FTP access: {username} from {client_ip}")
                return True

            # Check login frequency
            conn = get_db_connection()
            if conn:
                recent_logins = conn.execute('''
                    SELECT COUNT(*) FROM ftp_logs 
                    WHERE username = ? AND action = 'login' 
                    AND datetime(timestamp) >= datetime('now', '-1 hour')
                ''', (username,)).fetchone()[0]

                conn.close()

                if recent_logins > 10:  # More than 10 logins per hour
                    print(f"🚨 Excessive login frequency: {username} - {recent_logins} logins/hour")
                    return True

            return False

        except Exception as e:
            print(f"Error checking suspicious login: {e}")
            return False

    def check_suspicious_file_activity(self, action, username, client_ip, file_path, timestamp):
        '''Enhanced suspicious file activity detection'''
        try:
            suspicious_indicators = []

            # File type analysis
            file_lower = file_path.lower()

            # Executable files
            if any(ext in file_lower for ext in ['.exe', '.bat', '.cmd', '.scr', '.pif', '.vbs', '.ps1']):
                suspicious_indicators.append("executable_file")

            # Archive files (potential data exfiltration)
            if any(ext in file_lower for ext in ['.zip', '.rar', '.7z', '.tar', '.gz']):
                suspicious_indicators.append("archive_file")

            # Sensitive content keywords
            sensitive_keywords = ['password', 'credential', 'secret', 'backup', 'dump', 'export', 'database', 'config']
            if any(keyword in file_lower for keyword in sensitive_keywords):
                suspicious_indicators.append("sensitive_content")

            # System files
            if any(path in file_lower for path in ['/etc/', '/var/', '/sys/', 'system32', 'windows']):
                suspicious_indicators.append("system_file")

            # Hidden files
            if '/..' in file_path or file_path.startswith('.'):
                suspicious_indicators.append("hidden_file")

            # Check bulk transfer patterns
            conn = get_db_connection()
            if conn:
                # Recent transfers by same user
                recent_transfers = conn.execute('''
                    SELECT COUNT(*) FROM ftp_logs 
                    WHERE username = ? AND client_ip = ? 
                    AND action IN ('upload', 'download') 
                    AND datetime(timestamp) >= datetime('now', '-5 minutes')
                ''', (username, client_ip)).fetchone()[0]

                # Large file transfers
                large_files = conn.execute('''
                    SELECT COUNT(*) FROM ftp_logs 
                    WHERE username = ? 
                    AND action IN ('upload', 'download') 
                    AND datetime(timestamp) >= datetime('now', '-10 minutes')
                    AND extra_info LIKE '%file_size%'
                ''', (username,)).fetchone()[0]

                conn.close()

                if recent_transfers > 5:
                    suspicious_indicators.append("bulk_transfer")

                if large_files > 3:
                    suspicious_indicators.append("large_file_transfer")

            # Report findings
            if suspicious_indicators:
                print(f"🚨 Suspicious file activity: {action} - {file_path}")
                print(f"   Indicators: {', '.join(suspicious_indicators)}")
                return True

            return False

        except Exception as e:
            print(f"Error checking suspicious file activity: {e}")
            return False

    def calculate_risk_score(self, action, username, client_ip, file_path, timestamp, extra_info=None):
        '''Enhanced risk scoring algorithm'''
        try:
            risk = 0.0

            # Base risk by action type
            action_risks = {
                'connect': 0.05,
                'disconnect': 0.05,
                'login': 0.15,
                'failed_login': 0.85,
                'logout': 0.05,
                'upload': 0.45,
                'download': 0.35,
                'list_directory': 0.10,
                'change_directory': 0.10,
                'incomplete_upload': 0.65,
                'incomplete_download': 0.65
            }
            risk = action_risks.get(action, 0.25)

            # Time-based risk enhancement
            try:
                activity_time = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
                hour = activity_time.hour

                if hour >= 23 or hour <= 5:  # Late night/early morning
                    risk += 0.35
                elif hour <= 7 or hour >= 21:  # Extended hours
                    risk += 0.20

                # Weekend activity
                if activity_time.weekday() >= 5:
                    risk += 0.15

            except:
                pass

            # Username-based risk
            username_lower = username.lower()
            if username_lower in ['anonymous', 'ftp', 'guest']:
                risk += 0.25
            elif username_lower in ['admin', 'root', 'administrator']:
                risk += 0.30
            elif 'test' in username_lower or 'demo' in username_lower:
                risk += 0.20

            # IP-based risk assessment
            if not client_ip.startswith(('192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '127.')):
                risk += 0.40  # External IP

                # Known suspicious ranges
                if client_ip.startswith(('203.0.113.', '198.51.100.', '185.220.')):
                    risk += 0.30

            # File-based risk analysis
            if file_path and file_path != "/":
                file_lower = file_path.lower()

                # High-risk file extensions
                high_risk_exts = ['.exe', '.bat', '.cmd', '.scr', '.pif', '.vbs', '.ps1']
                if any(ext in file_lower for ext in high_risk_exts):
                    risk += 0.50

                # Medium-risk extensions
                medium_risk_exts = ['.zip', '.rar', '.7z', '.tar']
                if any(ext in file_lower for ext in medium_risk_exts):
                    risk += 0.25

                # Sensitive keywords
                sensitive_keywords = ['password', 'credential', 'secret', 'backup', 'dump', 'database', 'config']
                if any(keyword in file_lower for keyword in sensitive_keywords):
                    risk += 0.45

                # System paths
                if any(path in file_lower for path in ['/etc/', '/var/', 'system32', 'windows']):
                    risk += 0.35

                # Hidden or directory traversal
                if '/..' in file_path or file_path.startswith('.'):
                    risk += 0.40

            # Session-based risk (if extra_info available)
            if extra_info:
                if isinstance(extra_info, dict):
                    # Rapid-fire commands
                    if extra_info.get('commands_executed', 0) > 20:
                        risk += 0.20

                    # Large file transfers
                    file_size = extra_info.get('file_size', 0)
                    if file_size > 100 * 1024 * 1024:  # > 100MB
                        risk += 0.15

                    # Very short sessions (hit-and-run)
                    session_duration = extra_info.get('session_duration', 0)
                    if session_duration < 10 and extra_info.get('files_accessed', 0) > 0:
                        risk += 0.25

            # Cap at 1.0
            return min(1.0, risk)

        except Exception as e:
            print(f"Error calculating risk score: {e}")
            return 0.35  # Default moderate risk


class FTPHoneypot:
    '''Enhanced FTP Honeypot with advanced monitoring and user tracking'''

    def __init__(self, host='0.0.0.0', port=2121):
        self.host = host
        self.port = port
        self.server = None
        self.server_thread = None
        self.running = False

        # Create FTP directory structure
        self.ftp_root = self.setup_enhanced_ftp_directory()

        print(f"🍯 Enhanced FTP Honeypot initialized on {host}:{port}")
        print(f"📁 FTP Root Directory: {self.ftp_root}")

    def setup_enhanced_ftp_directory(self):
        '''Create enhanced FTP directory structure with realistic bait'''
        try:
            ftp_root = os.path.join(os.getcwd(), 'ftp_honeypot')

            # Create directory structure
            directories = [
                'public',
                'uploads',
                'downloads', 
                'documents',
                'temp',
                'backup',
                'logs',
                'config',
                'database',
                'reports'
            ]

            for directory in directories:
                dir_path = os.path.join(ftp_root, directory)
                os.makedirs(dir_path, exist_ok=True)

            # Create realistic bait files
            bait_files = {
                'readme.txt': 'FTP Server - Please follow company security policies.',
                'public/company_info.txt': 'Company Information - For internal use only.',
                'documents/employee_handbook.pdf': 'Employee Handbook - Confidential',
                'documents/financial_report_2024.xlsx': 'Financial Report Q3 2024',
                'backup/database_backup.sql': 'Database backup - DO NOT DELETE',
                'backup/system_backup.tar.gz': 'System backup archive',
                'logs/access.log': 'Access log file - monitoring enabled',
                'logs/error.log': 'Error log file',
                'config/database.conf': 'Database configuration - SENSITIVE',
                'config/server.conf': 'Server configuration file',
                'temp/upload_temp.txt': 'Temporary upload staging area',
                'reports/security_report.docx': 'Security Assessment Report - CONFIDENTIAL',
                'reports/audit_findings.pdf': 'Internal Audit Findings',
                '.env': 'DATABASE_URL=postgresql://user:password@localhost/prod\nAPI_KEY=sk-1234567890abcdef',
                '.htaccess': 'AuthType Basic\nAuthName "Restricted Area"',
                'passwords.txt': 'admin:Admin123\nroot:RootPass\nuser:Password1'
            }

            for file_path, content in bait_files.items():
                full_path = os.path.join(ftp_root, file_path)
                os.makedirs(os.path.dirname(full_path), exist_ok=True)

                if not os.path.exists(full_path):
                    with open(full_path, 'w') as f:
                        f.write(content)

            return ftp_root

        except Exception as e:
            print(f"Error setting up enhanced FTP directory: {e}")
            return os.getcwd()

    def start_server(self):
        '''Start the enhanced FTP honeypot server'''
        try:
            if self.running:
                print("⚠️ Enhanced FTP Honeypot is already running")
                return False

            # Set up authorizer with realistic accounts
            authorizer = DummyAuthorizer()

            # Add various user accounts (common in real environments)
            user_accounts = [
                ("admin", "admin123", "elradfmwMT"),
                ("administrator", "password", "elradfmwMT"),
                ("ftpuser", "ftp123", "elradfmwMT"),
                ("backup", "backup2024", "elradfmwMT"),
                ("service", "service123", "elr"),
                ("guest", "guest", "elr"),
                ("test", "test123", "elradfmwMT"),
                ("demo", "demo123", "elr"),
                ("upload", "upload123", "elradfmwMT"),
                ("user", "password123", "elr")
            ]

            for username, password, permissions in user_accounts:
                authorizer.add_user(username, password, self.ftp_root, perm=permissions)

            # Allow anonymous access (major attack vector)
            authorizer.add_anonymous(self.ftp_root, perm="elr")

            # Set up enhanced handler
            handler = EnhancedFTPHandler
            handler.authorizer = authorizer

            # Enhanced security settings
            handler.banner = "Corporate FTP Server v2.1 - Authorized Users Only"
            handler.max_cons = 500  # Allow more connections for monitoring
            handler.max_cons_per_ip = 15
            handler.timeout = 300
            handler.passive_ports = range(60000, 60200)

            # Create server
            self.server = FTPServer((self.host, self.port), handler)

            # Start in thread
            self.server_thread = threading.Thread(target=self._run_server)
            self.server_thread.daemon = True
            self.running = True
            self.server_thread.start()

            print(f"🚀 Enhanced FTP Honeypot started on {self.host}:{self.port}")
            print("👥 Available accounts:")
            for username, password, _ in user_accounts:
                print(f"   {username}/{password}")
            print("🌍 Anonymous access enabled")
            print("🎯 Monitoring all connections and activities...")

            return True

        except Exception as e:
            print(f"❌ Failed to start Enhanced FTP Honeypot: {e}")
            self.running = False
            return False

    def stop_server(self):
        '''Stop the enhanced FTP honeypot server'''
        try:
            if not self.running:
                print("⚠️ Enhanced FTP Honeypot is not running")
                return False

            self.running = False

            if self.server:
                self.server.close_all()

            if self.server_thread and self.server_thread.is_alive():
                self.server_thread.join(timeout=10)

            print("🛑 Enhanced FTP Honeypot stopped")
            return True

        except Exception as e:
            print(f"❌ Error stopping Enhanced FTP Honeypot: {e}")
            return False

    def _run_server(self):
        '''Internal method to run the FTP server'''
        try:
            print("🍯 Enhanced FTP Honeypot server loop started")
            self.server.serve_forever()
        except Exception as e:
            print(f"Enhanced FTP Server error: {e}")
        finally:
            self.running = False
            print("🍯 Enhanced FTP Honeypot server loop ended")

    def get_server_status(self):
        '''Get enhanced server status'''
        return {
            'running': self.running,
            'host': self.host,
            'port': self.port,
            'ftp_root': self.ftp_root,
            'thread_alive': self.server_thread.is_alive() if self.server_thread else False,
            'user_accounts': 10,
            'anonymous_enabled': True
        }

    def get_threat_summary(self):
        '''Get threat activity summary'''
        try:
            conn = get_db_connection()
            if not conn:
                return {}

            # Get threat statistics
            threat_stats = conn.execute('''
                SELECT 
                    COUNT(*) as total_connections,
                    COUNT(DISTINCT client_ip) as unique_ips,
                    SUM(CASE WHEN is_suspicious = 1 THEN 1 ELSE 0 END) as suspicious_activities,
                    SUM(CASE WHEN action = 'failed_login' THEN 1 ELSE 0 END) as failed_logins,
                    AVG(risk_score) as avg_risk_score
                FROM ftp_logs 
                WHERE datetime(timestamp) >= datetime('now', '-24 hours')
            ''').fetchone()

            # Get top attacking IPs
            top_ips = conn.execute('''
                SELECT client_ip, COUNT(*) as attempts 
                FROM ftp_logs 
                WHERE is_suspicious = 1 
                AND datetime(timestamp) >= datetime('now', '-24 hours')
                GROUP BY client_ip 
                ORDER BY attempts DESC 
                LIMIT 5
            ''').fetchall()

            conn.close()

            return {
                'total_connections': threat_stats[0] or 0,
                'unique_ips': threat_stats[1] or 0,
                'suspicious_activities': threat_stats[2] or 0,
                'failed_logins': threat_stats[3] or 0,
                'avg_risk_score': round(threat_stats[4] or 0, 2),
                'top_attacking_ips': [dict(ip) for ip in top_ips]
            }

        except Exception as e:
            print(f"Error getting threat summary: {e}")
            return {}

# Alias for backward compatibility
FTPHoneypot = FTPHoneypot

if __name__ == '__main__':
    honeypot = FTPHoneypot()

    if honeypot.start_server():
        try:
            print("✅ Enhanced FTP Honeypot is running")
            print(f"🔗 Connect: ftp://{honeypot.host}:{honeypot.port}")
            print("🔍 Monitoring enhanced threats and user behavior...")

            while honeypot.running:
                time.sleep(10)
                summary = honeypot.get_threat_summary()
                if summary.get('total_connections', 0) > 0:
                    print(f"📊 Threat Summary: {summary}")

        except KeyboardInterrupt:
            print("\n🛑 Stopping Enhanced FTP Honeypot...")
        finally:
            honeypot.stop_server()
    else:
        print("❌ Failed to start Enhanced FTP Honeypot")
