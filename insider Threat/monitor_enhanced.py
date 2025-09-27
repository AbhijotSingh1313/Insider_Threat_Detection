import sqlite3
import threading
import time
import os
import platform
import json
import hashlib
import psutil
import socket
from datetime import datetime, timedelta
from db_init_enhanced import get_db_connection
import logging
import subprocess
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Import OS-specific modules
if platform.system() == "Windows":
    try:
        import win32evtlog
        import win32con
        import win32security
        import win32api
        WINDOWS_AVAILABLE = True
        logger.info("Windows monitoring capabilities enabled")
    except ImportError:
        logger.warning("pywin32 not available. Windows event monitoring disabled.")
        WINDOWS_AVAILABLE = False
else:
    import re
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WINDOWS_AVAILABLE = False
    logger.info("Linux/Unix monitoring capabilities enabled")

class EnhancedSecurityMonitor:
    """Enhanced Security Monitor with real event detection only - NO SIMULATION"""

    def __init__(self):
        self.monitoring = False
        self.monitor_thread = None
        self.start_time = datetime.now()
        self.system_type = platform.system()
        self.access_denied = False
        self.error_message = ""
        self.event_cache = {}

        # Initialize baseline metrics
        self.baseline_metrics = self.collect_system_metrics()

        # Critical Windows Event IDs to monitor (no simulation)
        self.critical_event_ids = {
            4624: {"name": "Successful Logon", "category": "AUTHENTICATION", "risk": 0.2},
            4625: {"name": "Failed Logon", "category": "AUTHENTICATION", "risk": 0.8},
            4648: {"name": "Explicit Logon", "category": "AUTHENTICATION", "risk": 0.5},
            4720: {"name": "User Account Created", "category": "ACCOUNT_MANAGEMENT", "risk": 0.7},
            4722: {"name": "User Account Enabled", "category": "ACCOUNT_MANAGEMENT", "risk": 0.6},
            4724: {"name": "Password Reset", "category": "ACCOUNT_MANAGEMENT", "risk": 0.5},
            4728: {"name": "User Added to Global Group", "category": "ACCOUNT_MANAGEMENT", "risk": 0.6},
            4732: {"name": "User Added to Local Group", "category": "ACCOUNT_MANAGEMENT", "risk": 0.7},
            4740: {"name": "User Account Locked", "category": "AUTHENTICATION", "risk": 0.8},
            1102: {"name": "Audit Log Cleared", "category": "TAMPERING", "risk": 0.9},
            4656: {"name": "Object Access", "category": "OBJECT_ACCESS", "risk": 0.3},
            4663: {"name": "Object Access Attempt", "category": "OBJECT_ACCESS", "risk": 0.4},
            4688: {"name": "Process Creation", "category": "PROCESS_ACTIVITY", "risk": 0.3},
            4689: {"name": "Process Termination", "category": "PROCESS_ACTIVITY", "risk": 0.2}
        }

        # Linux log patterns (real log analysis only)
        self.linux_patterns = {
            "ssh_failed": {
                "pattern": r"Failed password for (\S+) from ([\d.]+)",
                "description": "SSH Failed Login",
                "category": "AUTHENTICATION",
                "risk": 0.8
            },
            "ssh_success": {
                "pattern": r"Accepted (?:password|publickey) for (\S+) from ([\d.]+)",
                "description": "SSH Successful Login",
                "category": "AUTHENTICATION", 
                "risk": 0.3
            },
            "sudo_command": {
                "pattern": r"sudo:\s*(\S+).*COMMAND=(.+)",
                "description": "Sudo Command Execution",
                "category": "PRIVILEGE_ESCALATION",
                "risk": 0.6
            }
        }

        # Threat indicators (real patterns only)
        self.threat_indicators = {
            "suspicious_processes": [
                "mimikatz", "psexec", "wmic", "powershell -enc", "rundll32", "regsvr32"
            ],
            "suspicious_commands": [
                "net user", "net group", "whoami", "systeminfo", "tasklist", "netstat"
            ]
        }

        # Resource thresholds for anomaly detection
        self.resource_thresholds = {
            "cpu_high": 85.0,
            "memory_high": 90.0,
            "disk_high": 95.0,
            "network_high": 1000
        }

        logger.info("Enhanced Security Monitor initialized")

    def start_monitoring(self):
        """Start enhanced monitoring services"""
        if self.monitoring:
            logger.warning("Monitoring is already active")
            return False

        try:
            self.monitoring = True
            self.monitor_thread = threading.Thread(target=self._enhanced_monitor_loop)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()

            logger.info("Enhanced Security Monitor started successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to start monitoring: {e}")
            self.monitoring = False
            return False

    def stop_monitoring(self):
        """Stop monitoring services"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5.0)
        logger.info("Enhanced Security Monitor stopped")

    # ADD THE AUTOMATIC REPORT CREATION FUNCTION HERE
    def create_suspicious_report(self, conn, event_data, data_type):
        """Create a suspicious activity report automatically"""
        try:
            if data_type == 'event':
                activity_type = f"Suspicious Event: {event_data.get('event_type', 'Unknown')}"
                source_ip = event_data.get('source_ip', 'Unknown')
                username = event_data.get('username', 'Unknown')
                details = f"Event ID: {event_data.get('event_id', 'N/A')}, Description: {event_data.get('description', 'No details')}"
            else:  # ftp
                activity_type = f"Suspicious FTP: {event_data.get('action', 'Unknown')}"
                source_ip = event_data.get('client_ip', 'Unknown')
                username = event_data.get('username', 'Unknown')
                details = f"File: {event_data.get('file_path', 'N/A')}, Action: {event_data.get('action', 'Unknown')}"

            # Determine risk level from the event data
            risk_score = event_data.get('risk_score', 0.5)
            risk_level = 'HIGH' if risk_score >= 0.8 else 'MEDIUM' if risk_score >= 0.5 else 'LOW'

            # Insert the report
            conn.execute('''
                INSERT INTO suspicious_reports 
                (timestamp, activity_type, source_ip, username, risk_level, details, status)
                VALUES (datetime('now'), ?, ?, ?, ?, ?, 'new')
            ''', (activity_type, source_ip, username, risk_level, details))

            # CRITICAL: COMMIT THE TRANSACTION
            conn.commit()
            logger.info(f"✅ Auto-created report: {activity_type} for {username}")

        except Exception as e:
            logger.error(f"❌ Error auto-creating report: {e}")

    def _enhanced_monitor_loop(self):
        """Main monitoring loop with OS detection"""
        logger.info(f"Starting enhanced monitoring for {self.system_type}")

        if self.system_type == "Windows":
            self._enhanced_windows_monitor()
        else:
            self._enhanced_linux_monitor()

    def _enhanced_windows_monitor(self):
        """Enhanced Windows event log monitoring with real events only"""
        if not WINDOWS_AVAILABLE:
            self.access_denied = True
            self.error_message = "Windows monitoring not available - pywin32 not installed"
            logger.error(self.error_message)
            return

        logger.info("Starting enhanced Windows event monitoring")

        try:
            # Open Security event log
            hand = win32evtlog.OpenEventLog(None, "Security")
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

            # Get initial position
            total = win32evtlog.GetNumberOfEventLogRecords(hand)
            last_processed = total

            logger.info(f"Windows Security log opened. Total events: {total}")

            while self.monitoring:
                try:
                    # Check for new events
                    current_total = win32evtlog.GetNumberOfEventLogRecords(hand)

                    if current_total > last_processed:
                        # Read new events
                        events = win32evtlog.ReadEventLog(
                            hand, 
                            win32evtlog.EVENTLOG_SEQUENTIAL_READ | win32evtlog.EVENTLOG_FORWARDS_READ, 
                            0
                        )

                        new_events_processed = 0
                        for event in events:
                            if event.RecordNumber <= last_processed:
                                continue

                            self._process_enhanced_windows_event(event)
                            new_events_processed += 1

                            # Prevent overwhelming the system
                            if new_events_processed % 10 == 0:
                                time.sleep(0.1)

                        last_processed = current_total

                        if new_events_processed > 0:
                            logger.info(f"Processed {new_events_processed} new Windows events")

                    time.sleep(5)  # Check for new events every 5 seconds

                except Exception as e:
                    logger.error(f"Error in Windows event monitoring loop: {e}")
                    time.sleep(10)

            win32evtlog.CloseEventLog(hand)

        except Exception as e:
            self.access_denied = True
            self.error_message = f"Critical error in Windows monitoring: {str(e)}"
            logger.error(f"Critical error in Windows monitoring: {e}")

    def _process_enhanced_windows_event(self, event):
        """Process Windows events with enhanced threat detection"""
        try:
            event_id = event.EventID & 0xFFFF  # Remove severity bits

            # Skip if not a monitored event type
            if event_id not in self.critical_event_ids:
                return

            event_info = self.critical_event_ids[event_id]

            # Extract enhanced event data
            event_data = {
                "event_id": event_id,
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "source_ip": self._extract_ip_from_event(event),
                "username": self._extract_username_from_event(event),
                "event_type": event_info["name"],
                "category": event_info["category"],
                "description": self._get_event_description(event),
                "risk_score": self._calculate_enhanced_risk(event_data, event_info)
            }

            # Determine if suspicious
            is_suspicious = event_data['risk_score'] >= 0.6

            if is_suspicious:
                logger.warning(f"🚨 Suspicious Windows event: {event_info['name']} - Risk: {event_data['risk_score']:.2f}")

            # Store enhanced event WITH AUTOMATIC REPORT CREATION
            self._store_enhanced_event(event_data, event_data['risk_score'], is_suspicious, [])

        except Exception as e:
            logger.error(f"Error processing Windows event {event.EventID}: {e}")

    def _store_enhanced_event(self, event_data, risk_score, is_suspicious, attack_indicators):
        """Store enhanced event data in database and AUTO-CREATE REPORTS"""
        try:
            conn = get_db_connection()
            if not conn:
                return

            # Store the event
            conn.execute('''
                INSERT INTO event_logs 
                (event_id, timestamp, source_ip, username, event_type, description, 
                 risk_score, is_suspicious, processed)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
            ''', (
                event_data["event_id"], 
                event_data["timestamp"],
                event_data.get("source_ip", ""),
                event_data.get("username", ""),
                event_data["event_type"],
                event_data.get("description", ""),
                risk_score,
                int(is_suspicious)
            ))

            # AUTO-CREATE REPORT IF SUSPICIOUS - THIS IS THE KEY ADDITION
            if is_suspicious and risk_score >= 0.6:
                # Add risk_score to event_data for report creation
                event_data_with_risk = event_data.copy()
                event_data_with_risk['risk_score'] = risk_score
                self.create_suspicious_report(conn, event_data_with_risk, 'event')

            conn.commit()
            conn.close()

        except Exception as e:
            logger.error(f"Error storing enhanced event: {e}")

    def _calculate_enhanced_risk(self, event_data, event_info):
        """Calculate enhanced risk score with multiple factors"""
        try:
            base_risk = event_info["risk"]

            # Time-based risk adjustment
            event_time = datetime.strptime(event_data["timestamp"], '%Y-%m-%d %H:%M:%S')
            if event_time.hour < 6 or event_time.hour > 22:
                base_risk += 0.2  # After hours activity

            # Username-based risk adjustment
            username = event_data.get("username", "").lower()
            if username in ["admin", "administrator", "root", "system"]:
                base_risk += 0.2

            return min(1.0, base_risk)

        except Exception as e:
            logger.error(f"Error calculating enhanced risk: {e}")
            return 0.5

    def _extract_ip_from_event(self, event):
        """Extract IP address from Windows event"""
        try:
            if hasattr(event, 'StringInserts') and event.StringInserts:
                for insert in event.StringInserts:
                    if insert and "." in insert:
                        # Simple IP pattern check
                        parts = insert.split(".")
                        if (len(parts) == 4 and 
                            all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)):
                            return insert
            return "unknown"
        except:
            return "unknown"

    def _get_event_description(self, event):
        """Get detailed event description"""
        try:
            description_parts = []
            if hasattr(event, 'StringInserts') and event.StringInserts:
                description_parts.extend([str(insert) for insert in event.StringInserts if insert])

            return "; ".join(description_parts) if description_parts else "No additional details"
        except:
            return "Error retrieving event details"

    def _extract_username_from_event(self, event):
        """Extract username from Windows event"""
        try:
            if hasattr(event, 'StringInserts') and event.StringInserts:
                # Username is typically in the first few string inserts
                for insert in event.StringInserts[:3]:
                    if insert and not "." in insert and insert.count(".") < 3:
                        # Avoid IPs, return first likely username
                        return insert
            return "unknown"
        except:
            return "unknown"

    def _enhanced_linux_monitor(self):
        """Enhanced Linux system monitoring with multiple log sources"""
        logger.info("Starting enhanced Linux system monitoring")

        # Multiple log files to monitor
        log_files = ["/var/log/auth.log", "/var/log/secure", "/var/log/messages"]

        # Find available log files
        available_logs = []
        for log_file in log_files:
            if os.path.exists(log_file):
                try:
                    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                        f.read(1)  # Try to read one character
                    available_logs.append(log_file)
                except PermissionError:
                    logger.warning(f"Permission denied for log file: {log_file}")

        if not available_logs:
            self.access_denied = True
            self.error_message = "No accessible Linux log files found"
            logger.error("No accessible log files found")
            return

        logger.info(f"Monitoring Linux logs: {', '.join(available_logs)}")

        # Track file positions
        file_positions = {log: self._get_file_size(log) for log in available_logs}

        while self.monitoring:
            try:
                for log_file in available_logs:
                    self._process_enhanced_linux_log(log_file, file_positions)

                time.sleep(3)  # Check logs every 3 seconds

            except Exception as e:
                logger.error(f"Error in Linux monitoring loop: {e}")
                time.sleep(10)

    def _process_enhanced_linux_log(self, log_file, file_positions):
        """Process Linux log files with enhanced pattern matching"""
        try:
            current_size = self._get_file_size(log_file)
            last_position = file_positions.get(log_file, 0)

            if current_size <= last_position:
                return  # No new data

            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(last_position)
                new_lines = f.readlines()
                file_positions[log_file] = f.tell()

            for line in new_lines:
                self._analyze_enhanced_linux_log_line(line.strip(), log_file)

        except Exception as e:
            logger.error(f"Error processing Linux log {log_file}: {e}")

    def _analyze_enhanced_linux_log_line(self, line, source_file):
        """Analyze Linux log lines with enhanced pattern detection"""
        try:
            if not line:
                return

            # Check against patterns
            for pattern_name, pattern_config in self.linux_patterns.items():
                match = re.search(pattern_config["pattern"], line, re.IGNORECASE)

                if match:
                    event_data = {
                        "event_id": hash(pattern_name) % 10000,
                        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        "source_ip": self._extract_ip_from_linux_log(line),
                        "username": match.group(1) if match.groups() else "unknown",
                        "event_type": pattern_config["description"],
                        "category": pattern_config["category"],
                        "description": line,
                        "risk_score": pattern_config["risk"]
                    }

                    is_suspicious = event_data['risk_score'] >= 0.6

                    if is_suspicious:
                        logger.warning(f"🚨 Suspicious Linux activity: {pattern_config['description']}")

                    self._store_enhanced_event(event_data, event_data['risk_score'], is_suspicious, [])
                    break

        except Exception as e:
            logger.error(f"Error analyzing Linux log line: {e}")

    def _extract_ip_from_linux_log(self, log_line):
        """Extract IP address from Linux log line"""
        try:
            # Find IP patterns in log line
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            matches = re.findall(ip_pattern, log_line)

            # Return the first non-localhost IP
            for ip in matches:
                if ip != "127.0.0.1" and not ip.startswith("0."):
                    return ip

            return matches[0] if matches else "unknown"

        except:
            return "unknown"

    def _get_file_size(self, file_path):
        """Get file size safely"""
        try:
            return os.path.getsize(file_path)
        except:
            return 0

    def collect_system_metrics(self):
        """Collect comprehensive system metrics"""
        try:
            cpu_percent = psutil.cpu_percent()
            memory = psutil.virtual_memory()

            if os.name == 'nt':
                disk = psutil.disk_usage('C:')
            else:
                disk = psutil.disk_usage('/')

            connections = psutil.net_connections()
            process_count = len(psutil.pids())

            return {
                "timestamp": datetime.now().isoformat(),
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "disk_percent": (disk.used / disk.total) * 100,
                "network_connections": len(connections),
                "running_processes": process_count
            }

        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
            return {}

# Alias for backward compatibility
SecurityMonitor = EnhancedSecurityMonitor

if __name__ == "__main__":
    print("Testing Enhanced Security Monitor with Auto Report Creation...")

    monitor = EnhancedSecurityMonitor()

    try:
        print("Starting monitoring test...")
        monitor.start_monitoring()

        time.sleep(30)  # Run for 30 seconds

    except KeyboardInterrupt:
        print("Test interrupted by user")
    finally:
        print("Stopping monitor...")
        monitor.stop_monitoring()
        print("Enhanced Security Monitor test completed")
